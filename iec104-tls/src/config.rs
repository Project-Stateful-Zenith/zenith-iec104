//! [`TlsConfig`]: one configuration for both ends of a connection.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::{Resumption, Tls12Resumption};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{CipherSuite, ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};

use crate::verify::{PeerClientVerifier, PeerServerVerifier};

/// A TLS protocol version.
///
/// Secondary sources (unverified against IEC 62351-3) describe TLS 1.2 as the
/// profile's minimum and TLS 1.3 as allowed; older versions are not offered
/// at all, and rustls implements neither.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Version {
    /// TLS 1.2 (RFC 5246).
    Tls12,
    /// TLS 1.3 (RFC 8446).
    Tls13,
}

impl Version {
    fn rustls(self) -> &'static SupportedProtocolVersion {
        match self {
            Self::Tls12 => &rustls::version::TLS12,
            Self::Tls13 => &rustls::version::TLS13,
        }
    }
}

/// This end's certificate chain (leaf first) and its private key.
pub struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("chain", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// A chain in DER, leaf first, and its key (PKCS#8, PKCS#1 or SEC1).
    #[must_use]
    pub const fn new(chain: Vec<CertificateDer<'static>>, key: PrivateKeyDer<'static>) -> Self {
        Self { chain, key }
    }

    /// A chain and a key in PEM. The key must not be encrypted.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Pem`] when the chain holds no certificate or either
    /// text is malformed.
    pub fn from_pem(chain: &[u8], key: &[u8]) -> Result<Self, ConfigError> {
        let chain = certificates_from_pem(chain)?;
        let key = PrivateKeyDer::from_pem_slice(key).map_err(|e| pem_error("private key", &e))?;
        Ok(Self { chain, key })
    }

    /// [`Identity::from_pem`] from two files.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Io`] when a file cannot be read, otherwise as
    /// [`Identity::from_pem`].
    pub fn from_pem_files(
        chain: impl AsRef<Path>,
        key: impl AsRef<Path>,
    ) -> Result<Self, ConfigError> {
        Self::from_pem(&read(chain.as_ref())?, &read(key.as_ref())?)
    }

    /// The chain, leaf first.
    #[must_use]
    pub fn chain(&self) -> &[CertificateDer<'static>] {
        &self.chain
    }
}

/// Every certificate in a PEM text, in order.
///
/// # Errors
///
/// [`ConfigError::Pem`] when the text holds no certificate or is malformed.
pub fn certificates_from_pem(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pem_error("certificate", &e))?;
    if certs.is_empty() {
        return Err(ConfigError::Pem("no certificate in the PEM text".into()));
    }
    Ok(certs)
}

/// [`certificates_from_pem`] from a file.
///
/// # Errors
///
/// [`ConfigError::Io`] when the file cannot be read, otherwise as
/// [`certificates_from_pem`].
pub fn certificates_from_pem_file(
    path: impl AsRef<Path>,
) -> Result<Vec<CertificateDer<'static>>, ConfigError> {
    certificates_from_pem(&read(path.as_ref())?)
}

/// Every certificate revocation list in a PEM text.
///
/// # Errors
///
/// [`ConfigError::Pem`] when the text holds no CRL or is malformed.
pub fn crls_from_pem(
    pem: &[u8],
) -> Result<Vec<CertificateRevocationListDer<'static>>, ConfigError> {
    let crls = CertificateRevocationListDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| pem_error("CRL", &e))?;
    if crls.is_empty() {
        return Err(ConfigError::Pem("no X509 CRL in the PEM text".into()));
    }
    Ok(crls)
}

/// [`crls_from_pem`] from a file.
///
/// # Errors
///
/// [`ConfigError::Io`] when the file cannot be read, otherwise as
/// [`crls_from_pem`].
pub fn crls_from_pem_file(
    path: impl AsRef<Path>,
) -> Result<Vec<CertificateRevocationListDer<'static>>, ConfigError> {
    crls_from_pem(&read(path.as_ref())?)
}

fn read(path: &Path) -> Result<Vec<u8>, ConfigError> {
    std::fs::read(path).map_err(|e| ConfigError::Io(format!("{}: {e}", path.display())))
}

fn pem_error(what: &str, e: &rustls::pki_types::pem::Error) -> ConfigError {
    ConfigError::Pem(format!("{what}: {e:?}"))
}

/// Why a [`TlsConfig`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// A file could not be read.
    Io(String),
    /// A PEM text held nothing usable, or was malformed.
    Pem(String),
    /// The minimum version is above the maximum.
    VersionRange {
        /// The minimum asked for.
        min: Version,
        /// The maximum asked for.
        max: Version,
    },
    /// A cipher suite the backend (rustls with the *ring* provider) does not
    /// implement: any CBC, RSA key exchange, DHE or NULL suite, for instance.
    UnsupportedCipherSuite(CipherSuite),
    /// Some enabled version has no cipher suite left to negotiate.
    NoCipherSuiteFor(Version),
    /// rustls refused the certificates, key, CRLs or trust anchors.
    Tls(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read {e}"),
            Self::Pem(e) => write!(f, "bad PEM: {e}"),
            Self::VersionRange { min, max } => {
                write!(f, "minimum version {min:?} is above the maximum {max:?}")
            }
            Self::UnsupportedCipherSuite(s) => {
                write!(f, "cipher suite {s:?} is not implemented by the backend")
            }
            Self::NoCipherSuiteFor(v) => write!(f, "no cipher suite enabled for {v:?}"),
            Self::Tls(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The TLS settings of one station, for both ends: the same value makes
/// client connections ([`connect`](crate::connect)) and serves accepted ones
/// ([`accept`](crate::accept)). Cheap to clone.
///
/// Every connection is **mutually authenticated**: this end presents its
/// [`Identity`], and the peer's chain must lead to one of the trusted roots
/// (secondary sources describe mutual authentication as mandatory in IEC
/// 62351-3; unverified). A server refuses a client without a certificate.
///
/// Build one with [`TlsConfig::builder`].
#[derive(Clone)]
pub struct TlsConfig {
    pub(crate) client: Arc<ClientConfig>,
    pub(crate) server: Arc<ServerConfig>,
    pub(crate) key_update_interval: Option<Duration>,
    pub(crate) handshake_timeout: Duration,
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("key_update_interval", &self.key_update_interval)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl TlsConfig {
    /// Starts a configuration from this end's identity and the certificate
    /// authorities whose certificates it accepts from peers.
    #[must_use]
    pub const fn builder(
        identity: Identity,
        roots: Vec<CertificateDer<'static>>,
    ) -> TlsConfigBuilder {
        TlsConfigBuilder {
            identity,
            roots,
            allowed: Vec::new(),
            min: Version::Tls12,
            max: Version::Tls13,
            suites: None,
            crls: Vec::new(),
            end_entity_only: false,
            allow_unknown_status: false,
            key_update_interval: None,
            resumption: false,
            verify_server_name: true,
            handshake_timeout: Duration::from_secs(10),
        }
    }

    /// The rustls client configuration, for use with rustls directly.
    #[must_use]
    pub fn client_config(&self) -> Arc<ClientConfig> {
        self.client.clone()
    }

    /// The rustls server configuration, for use with rustls directly.
    #[must_use]
    pub fn server_config(&self) -> Arc<ServerConfig> {
        self.server.clone()
    }
}

/// Builds a [`TlsConfig`]; see [`TlsConfig::builder`].
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent builder switches"
)]
pub struct TlsConfigBuilder {
    identity: Identity,
    roots: Vec<CertificateDer<'static>>,
    allowed: Vec<CertificateDer<'static>>,
    min: Version,
    max: Version,
    suites: Option<Vec<CipherSuite>>,
    crls: Vec<CertificateRevocationListDer<'static>>,
    end_entity_only: bool,
    allow_unknown_status: bool,
    key_update_interval: Option<Duration>,
    resumption: bool,
    verify_server_name: bool,
    handshake_timeout: Duration,
}

impl TlsConfigBuilder {
    /// Accepts only peers whose leaf certificate is, octet for octet, one of
    /// these. The list applies **in addition to** the chain validation, not
    /// instead of it.
    /// Empty (the default) accepts any peer the roots vouch for.
    ///
    /// c104's `add_allowed_remote_certificate` and lib60870's allow-list do
    /// the same (both can also skip chain validation, which this crate does
    /// not offer).
    #[must_use]
    pub fn allow_peers(mut self, certs: impl IntoIterator<Item = CertificateDer<'static>>) -> Self {
        self.allowed.extend(certs);
        self
    }

    /// The versions offered and accepted, `min..=max`. Default TLS 1.2 to 1.3.
    #[must_use]
    pub const fn versions(mut self, min: Version, max: Version) -> Self {
        self.min = min;
        self.max = max;
        self
    }

    /// The cipher suites offered and accepted, by IANA name, in preference
    /// order. Default: every suite rustls' *ring* provider implements
    /// (TLS 1.3 AES-GCM and ChaCha20-Poly1305; TLS 1.2 ECDHE with ECDSA or
    /// RSA and AES-GCM or ChaCha20-Poly1305).
    #[must_use]
    pub fn cipher_suites(mut self, suites: impl IntoIterator<Item = CipherSuite>) -> Self {
        self.suites = Some(suites.into_iter().collect());
        self
    }

    /// Checks the peer's chain against these certificate revocation lists.
    ///
    /// By default every certificate of the chain below the trust anchor must
    /// be covered by a list from its issuer, or it is refused as of unknown
    /// status; see [`only_check_end_entity_revocation`](Self::only_check_end_entity_revocation)
    /// and [`allow_unknown_revocation_status`](Self::allow_unknown_revocation_status).
    /// A list whose nextUpdate has passed is refused rather than trusted
    /// (RFC 5280 5.1.2.5), so an out-of-date list makes connections fail until
    /// a fresh one is configured. The lists are fixed when the configuration
    /// is built: to take up a new list, build a new configuration for the next
    /// connections. OCSP is not supported (rustls does not check it).
    #[must_use]
    pub fn crls(
        mut self,
        crls: impl IntoIterator<Item = CertificateRevocationListDer<'static>>,
    ) -> Self {
        self.crls.extend(crls);
        self
    }

    /// Checks revocation of the peer's leaf certificate only, not of the
    /// intermediates.
    #[must_use]
    pub const fn only_check_end_entity_revocation(mut self) -> Self {
        self.end_entity_only = true;
        self
    }

    /// Accepts a certificate for which no list from its issuer was given.
    #[must_use]
    pub const fn allow_unknown_revocation_status(mut self) -> Self {
        self.allow_unknown_status = true;
        self
    }

    /// On a TLS 1.3 connection, sends a `KeyUpdate` that also asks the peer to
    /// update (RFC 8446 4.6.3) once `interval` has passed since the handshake
    /// or the previous update, right ahead of the next write. Every `KeyUpdate`
    /// is so followed by data, and a peer that bounds `KeyUpdates` between data
    /// records (rustls allows 32) never sees a run of them. On
    /// an idle 104 link the next write comes at the latest with t3's test
    /// frames. `None` (the default) leaves it to rustls, which updates by
    /// itself only when a cipher's usage limit nears.
    ///
    /// This is the TLS 1.3 stand-in for the periodic session renegotiation
    /// that secondary sources describe for IEC 62351-3 (unverified). TLS 1.2
    /// renegotiation is not available: rustls does not implement it, so on a
    /// TLS 1.2 connection this setting does nothing.
    ///
    /// **Not with mbedTLS peers:** mbedTLS 3.6 (lib60870-C, c104) has no
    /// `KeyUpdate`, and ends the session at the first one (observed in this
    /// crate's interop tests).
    #[must_use]
    pub const fn key_update_interval(mut self, interval: Option<Duration>) -> Self {
        self.key_update_interval = interval;
        self
    }

    /// Lets a reconnecting client resume an earlier session. Default off:
    /// every connection is a full handshake, so each validates the peer's
    /// chain, its validity period, the allow-list and the CRLs again.
    ///
    /// When on, a resumed session is **not** validated again (not even
    /// the certificate's expiry) for as long as its ticket lives. Tickets are
    /// stateless and rotated by rustls (currently every 6 hours, each valid
    /// for two periods). Our client resumes TLS 1.3 sessions only; our server
    /// keeps no session cache, because rustls keeps TLS 1.2 sessions there
    /// with no time limit.
    #[must_use]
    pub const fn session_resumption(mut self, on: bool) -> Self {
        self.resumption = on;
        self
    }

    /// As a client, checks that the server's certificate names the host
    /// dialed (a DNS name or IP address in its subjectAltName). Default on.
    ///
    /// Stations addressed by IP whose certificates do not carry the address
    /// may turn it off; the chain, the allow-list and revocation are still
    /// checked, so any certificate from a trusted CA is then accepted for any
    /// address. Narrow it with [`allow_peers`](Self::allow_peers).
    #[must_use]
    pub const fn verify_server_name(mut self, on: bool) -> Self {
        self.verify_server_name = on;
        self
    }

    /// How long a handshake may take before the connection is dropped; the
    /// `connect` functions also allow the TCP connect this long. Default
    /// 10 s (this crate's choice, not a standard value).
    #[must_use]
    pub const fn handshake_timeout(mut self, timeout: Duration) -> Self {
        self.handshake_timeout = timeout;
        self
    }

    /// Checks the settings and builds the configuration.
    ///
    /// # Errors
    ///
    /// [`ConfigError::VersionRange`] when the minimum version is above the
    /// maximum, [`ConfigError::UnsupportedCipherSuite`] or
    /// [`ConfigError::NoCipherSuiteFor`] when the suites do not fit, and
    /// [`ConfigError::Tls`] when rustls refuses the certificates, key, CRLs
    /// or trust anchors.
    pub fn build(self) -> Result<TlsConfig, ConfigError> {
        if self.min > self.max {
            return Err(ConfigError::VersionRange {
                min: self.min,
                max: self.max,
            });
        }
        let versions: Vec<Version> = [Version::Tls12, Version::Tls13]
            .into_iter()
            .filter(|v| (self.min..=self.max).contains(v))
            .collect();
        let provider = Arc::new(provider(self.suites.as_deref(), &versions)?);
        let rustls_versions: Vec<&'static SupportedProtocolVersion> =
            versions.iter().map(|v| v.rustls()).collect();

        let mut roots = RootCertStore::empty();
        for root in self.roots {
            roots
                .add(root)
                .map_err(|e| ConfigError::Tls(format!("trust anchor: {e}")))?;
        }
        let roots = Arc::new(roots);
        let tls = |e: rustls::Error| ConfigError::Tls(e.to_string());

        // Verifying the server: rustls' WebPKI verifier, then the allow-list.
        let mut server_check = rustls::client::WebPkiServerVerifier::builder_with_provider(
            roots.clone(),
            provider.clone(),
        )
        .with_crls(self.crls.clone())
        // A list past its nextUpdate says nothing about today (RFC 5280
        // 5.1.2.5): refused, not trusted as "not revoked".
        .enforce_revocation_expiration();
        if self.end_entity_only {
            server_check = server_check.only_check_end_entity_revocation();
        }
        if self.allow_unknown_status {
            server_check = server_check.allow_unknown_revocation_status();
        }
        let server_check = server_check
            .build()
            .map_err(|e| ConfigError::Tls(e.to_string()))?;
        let server_verifier = Arc::new(PeerServerVerifier {
            inner: server_check,
            allowed: self.allowed.clone(),
            verify_name: self.verify_server_name,
        });

        let mut client = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&rustls_versions)
            .map_err(tls)?
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_client_auth_cert(self.identity.chain.clone(), self.identity.key.clone_key())
            .map_err(tls)?;
        client.resumption = if self.resumption {
            // TLS 1.3 tickets only: rustls keeps TLS 1.2 sessions with no
            // time limit.
            Resumption::default().tls12_resumption(Tls12Resumption::Disabled)
        } else {
            Resumption::disabled()
        };

        // Verifying the client: a certificate is mandatory.
        let mut client_check = WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
            .with_crls(self.crls)
            .enforce_revocation_expiration();
        if self.end_entity_only {
            client_check = client_check.only_check_end_entity_revocation();
        }
        if self.allow_unknown_status {
            client_check = client_check.allow_unknown_revocation_status();
        }
        let client_check = client_check
            .build()
            .map_err(|e| ConfigError::Tls(e.to_string()))?;
        let client_verifier = Arc::new(PeerClientVerifier {
            inner: client_check,
            allowed: self.allowed,
        });

        let mut server = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&rustls_versions)
            .map_err(tls)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(self.identity.chain, self.identity.key)
            .map_err(tls)?;
        // No server-side session cache: rustls keeps TLS 1.2 sessions in it
        // with no time limit. Resumption, when on, is by stateless tickets,
        // which rustls rotates and so expire.
        server.session_storage = Arc::new(NoServerSessionStorage {});
        if self.resumption {
            server.ticketer = rustls::crypto::ring::Ticketer::new().map_err(tls)?;
        } else {
            server.send_tls13_tickets = 0;
        }

        Ok(TlsConfig {
            client: Arc::new(client),
            server: Arc::new(server),
            key_update_interval: self.key_update_interval,
            handshake_timeout: self.handshake_timeout,
        })
    }
}

/// rustls' *ring* provider with only the chosen suites, in the chosen order.
fn provider(
    suites: Option<&[CipherSuite]>,
    versions: &[Version],
) -> Result<CryptoProvider, ConfigError> {
    let mut provider = ring::default_provider();
    if let Some(wanted) = suites {
        let mut chosen = Vec::with_capacity(wanted.len());
        for &name in wanted {
            let suite = provider
                .cipher_suites
                .iter()
                .find(|s| s.suite() == name)
                .ok_or(ConfigError::UnsupportedCipherSuite(name))?;
            chosen.push(*suite);
        }
        provider.cipher_suites = chosen;
    }
    for &version in versions {
        let usable = provider
            .cipher_suites
            .iter()
            .any(|s| s.version() == version.rustls());
        if !usable {
            return Err(ConfigError::NoCipherSuiteFor(version));
        }
    }
    Ok(provider)
}
