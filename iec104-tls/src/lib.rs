//! TLS for [`iec104`]: 104 over mutually authenticated TLS, with
//! [rustls](https://docs.rs/rustls) and its *ring* provider.
//!
//! 104 over TLS is the plain 104 byte stream inside a TLS session, so this
//! crate is only a transport: [`connect`] and [`accept`] hand back a
//! [`TlsStream`] that is `Read + Write`, and the sans-IO core and the drivers
//! use it as they use a `TcpStream`. With the `tokio` feature, the `tokio`
//! module does the same for [`iec104_tokio`](https://docs.rs/iec104-tokio):
//! a `TlsConnector` for the master, and `serve` / `serve_routed` for the
//! outstation. The same pieces serve `iec104_tokio`'s `Client` (built with the
//! `TlsConnector`) and `Server` (whose handle goes to `serve`). One
//! [`TlsConfig`] serves both sides.
//!
//! # What this is measured against
//!
//! IEC 62351-3 (the TLS profile for TCP/IP-based power-system protocols) and
//! IEC 62351-9 (key management) were **not available** when this crate was
//! written. Everything below comes from secondary sources (the TLS APIs,
//! documentation and source comments of lib60870-C and c104, and public
//! descriptions of the profile) and is **unverified** against the
//! standard's text; no clause is cited because none was read. This crate
//! does not claim conformance to IEC 62351.
//!
//! | Requirement, as secondary sources describe it | Here |
//! | --- | --- |
//! | Its own port for 104 over TLS, commonly 19998 | [`DEFAULT_TLS_PORT`] |
//! | Mutual authentication with X.509 certificates | always on; a server refuses a client without one |
//! | Chain validated against configured CA roots | rustls' `WebPKI` verifier (chain, validity period, key usage) |
//! | Optionally, only explicitly allowed peer certificates | [`TlsConfigBuilder::allow_peers`], on top of chain validation |
//! | Minimum TLS 1.2, TLS 1.3 allowed; both configurable | [`TlsConfigBuilder::versions`]; TLS 1.0/1.1 not implemented at all |
//! | A restricted, configurable cipher-suite list | [`TlsConfigBuilder::cipher_suites`]; only AEAD suites with (EC)DHE exist in rustls |
//! | Revocation checking with CRLs | [`TlsConfigBuilder::crls`], at each handshake |
//! | Revocation checking with OCSP | **not implemented** (rustls does not check OCSP) |
//! | A minimum key length (lib60870: 2048 bits) | partly: webpki refuses RSA keys under 2048 bits; P-256, P-384 and Ed25519 keys are accepted |
//! | Session key renewal, TLS 1.2: periodic renegotiation (lib60870 notes session resumption *within* a connection as required) | **not implemented** (rustls does not renegotiate) |
//! | Session key renewal, TLS 1.3 | `KeyUpdate`: [`TlsConfigBuilder::key_update_interval`], but mbedTLS peers end the session at a `KeyUpdate` (see below) |
//! | Session resumption on reconnect | opt-in, [`TlsConfigBuilder::session_resumption`]; off by default; the peer's certificate is validated again on every resumed session; our client offers TLS 1.3 tickets only |
//! | Re-validation of open sessions when a CRL changes (lib60870: renegotiation) | **not implemented**; build a new [`TlsConfig`] and reconnect |
//! | Security events on failures | every refused handshake is returned as an error carrying the [`rustls::Error`] ([`tls_error`]); the `tokio` accept loops pass them to a callback. Logging them is the application's |
//!
//! # Gaps that follow from rustls
//!
//! - **No TLS 1.2 renegotiation.** A peer that renegotiates a TLS 1.2 session
//!   is answered as rustls does, on either side: the first request is
//!   declined with a `no_renegotiation` warning alert, a second one ends the
//!   connection. Observed with lib60870 and c104 (mbedTLS): they ask again,
//!   so their renegotiation interval **ends the session**; a 104 master then
//!   reconnects at t0 with a full handshake. Configure such peers not to
//!   renegotiate, or use TLS 1.3.
//! - **No OCSP**, stapled or fetched. CRLs only, fixed per [`TlsConfig`].
//! - **No CBC, RSA-key-exchange, DHE or NULL cipher suites.** A peer that
//!   offers only such suites cannot connect.
//! - **No skipping chain validation.** lib60870 and c104 can accept a peer
//!   on the allow-list alone; here the chain must always validate.
//!
//! # Defaults while the standard is unavailable
//!
//! Until IEC 62351-3 and 62351-9 can be checked, the open questions are
//! settled conservatively and can change once they are:
//!
//! - **Key renewal is by reconnecting.** A new connection is a full
//!   handshake with fresh keys. Neither TLS 1.2 renegotiation nor, against
//!   mbedTLS peers, TLS 1.3 `KeyUpdate` is available (see below), so a long-lived
//!   connection that must renew its keys is closed and reopened; a 104 master
//!   does that at t0. No other TLS backend is used to get renegotiation.
//! - **Revocation is by CRL only.** OCSP is a known gap.
//! - **Long sessions end at the AES-GCM record limit** against mbedTLS peers
//!   (below), and the master reconnects. The ChaCha20-Poly1305 suites avoid
//!   the limit where the peer offers them.
//!
//! # Interoperability notes
//!
//! Tested against lib60870-C (mbedTLS 3.6.6) and c104 2.2.1 (see the
//! `lib60870` and `c104` test suites):
//!
//! - **mbedTLS 3.6 has no TLS 1.3 `KeyUpdate`**: lib60870 and c104 end the
//!   session at the first one. Leave
//!   [`key_update_interval`](TlsConfigBuilder::key_update_interval) off
//!   against them.
//! - **Long sessions end at the AES-GCM record limit.** After 2^24 records
//!   sent under one key with an AES-GCM suite (about 19 days at 10 frames a
//!   second), rustls sends a TLS 1.3 `KeyUpdate` by itself, on which an
//!   mbedTLS peer ends the session; under TLS 1.2 it closes the connection.
//!   The ChaCha20-Poly1305 suites have no such limit in rustls. A 104 master
//!   reconnects either way.
//! - lib60870 refuses peer keys under 2048 bits by default, **EC keys
//!   included**: use RSA 2048 (or larger) certificates with it, or lower its
//!   minimum.
//! - With TLS 1.3, a client learns that the server refused its certificate
//!   only on its first read; mbedTLS's refusal then arrives as a record
//!   rustls cannot decrypt (`DecryptError`) rather than a readable alert.
//! - c104 2.2.1's client cannot complete any TLS handshake (its mbedTLS
//!   wants a hostname that c104 never sets); c104's server works.
//!
//! # Example
//!
//! ```no_run
//! use iec104_tls::{Identity, TlsConfig, certificates_from_pem_file};
//!
//! # fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let identity = Identity::from_pem_files("master.crt", "master.key")?;
//! let roots = certificates_from_pem_file("ca.crt")?;
//! let config = TlsConfig::builder(identity, roots).build()?;
//! let stream = iec104_tls::connect("outstation.example:19998", &config)?;
//! println!("{:?} with {:?}", stream.protocol_version(), stream.cipher_suite());
//! // `stream` is Read + Write: hand it to the driver.
//! # Ok(())
//! # }
//! ```

mod blocking;
mod config;
#[cfg(feature = "tokio")]
pub mod tokio;
mod verify;

use std::io;
use std::time::{Duration, Instant};

pub use blocking::{TlsStream, accept, connect, connect_over};
pub use config::{
    ConfigError, Identity, TlsConfig, TlsConfigBuilder, Version, certificates_from_pem,
    certificates_from_pem_file, crls_from_pem, crls_from_pem_file,
};
pub use rustls;
pub use rustls::pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};
pub use rustls::{CipherSuite, ProtocolVersion};

/// The TCP port commonly used for IEC 60870-5-104 over TLS.
///
/// From secondary sources (lib60870 and c104 examples, vendor documentation);
/// **not verified** against IEC 62351-3. Plain 104 uses 2404
/// ([`iec104::params::PORT`]).
pub const DEFAULT_TLS_PORT: u16 = 19998;

/// The TLS error inside an I/O error from [`connect`], [`accept`] or a
/// [`TlsStream`], if the failure was TLS's: a certificate that did not
/// validate, a refused version or suite, an alert from the peer.
#[must_use]
pub fn tls_error(error: &io::Error) -> Option<&rustls::Error> {
    error.get_ref()?.downcast_ref::<rustls::Error>()
}

/// The host part of `host:port` (brackets stripped from an IPv6 address).
fn host(address: &str) -> io::Result<&str> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{address}: expected host:port"),
        )
    };
    let (host, _port) = address.rsplit_once(':').ok_or_else(invalid)?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return Err(invalid());
    }
    Ok(host)
}

/// When a TLS 1.3 session's keys are next updated.
#[derive(Debug)]
struct Renewal {
    interval: Option<Duration>,
    last: Instant,
}

impl Renewal {
    fn new(interval: Option<Duration>) -> Self {
        Self {
            interval,
            last: Instant::now(),
        }
    }

    fn due(&self, version: Option<ProtocolVersion>) -> bool {
        version == Some(ProtocolVersion::TLSv1_3)
            && self.interval.is_some_and(|i| self.last.elapsed() >= i)
    }

    fn done(&mut self) {
        self.last = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::host;

    #[test]
    fn the_host_of_an_address_is_what_the_server_certificate_must_name() {
        assert_eq!(host("127.0.0.1:19998").unwrap(), "127.0.0.1");
        assert_eq!(host("[::1]:19998").unwrap(), "::1");
        assert_eq!(host("rtu-7.example:19998").unwrap(), "rtu-7.example");
        assert!(host("no-port").is_err());
        assert!(host(":19998").is_err());
    }
}
