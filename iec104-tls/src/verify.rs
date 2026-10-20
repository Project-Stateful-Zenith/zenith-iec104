//! The peer checks on top of rustls' `WebPKI` verifiers: the allow-list, and
//! the optional server-name check. Chain, validity period, key usage and
//! revocation stay rustls' (webpki's) own. And the check of a resumed
//! session's peer, which rustls skips.

use std::io;
use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, CommonState, DigitallySignedStruct, DistinguishedName, Error, HandshakeKind,
    SignatureScheme,
};

use crate::TlsConfig;

/// Refuses a leaf that is not on a non-empty allow-list. The alert is
/// `access_denied` (rustls' mapping of `ApplicationVerificationFailure`).
fn allowed(list: &[CertificateDer<'static>], leaf: &CertificateDer<'_>) -> Result<(), Error> {
    if list.is_empty() || list.iter().any(|c| c.as_ref() == leaf.as_ref()) {
        Ok(())
    } else {
        Err(Error::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }
}

/// How a client checks the server.
#[derive(Debug)]
pub struct PeerServerVerifier {
    pub(crate) inner: Arc<WebPkiServerVerifier>,
    pub(crate) allowed: Vec<CertificateDer<'static>>,
    pub(crate) verify_name: bool,
}

impl ServerCertVerifier for PeerServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => {}
            // rustls checks the name last, after the chain and revocation
            // passed, so this error means only the name did not match.
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) if !self.verify_name => {}
            Err(e) => return Err(e),
        }
        allowed(&self.allowed, end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// How a server checks the client. A client certificate is mandatory.
#[derive(Debug)]
pub struct PeerClientVerifier {
    pub(crate) inner: Arc<dyn ClientCertVerifier>,
    pub(crate) allowed: Vec<CertificateDer<'static>>,
}

impl ClientCertVerifier for PeerClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        allowed(&self.allowed, end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Checks the peer of a resumed session again, as a full handshake would, at
/// the current time; a full handshake passes unchecked, its verifier ran.
///
/// rustls 0.23 accepts a resumed session (TLS 1.3 PSK, RFC 8446 2.2; TLS 1.2
/// ticket, RFC 5077) on the ticket alone: it takes the peer's chain from the
/// ticket and calls no verifier, on either side (`server/tls13.rs`,
/// `server/tls12.rs`, `client/tls13.rs`, `client/tls12.rs`). Every resumption
/// issues fresh tickets, so without this a certificate that expired, was
/// revoked or left the allow-list would stay accepted for as long as the peer
/// keeps reconnecting.
///
/// `server_name` is the name dialed when this end is the client, `None` when
/// it is the server. rustls offers no way to send an alert after the
/// handshake, so the caller drops the connection on an error.
pub fn check_resumed(
    common: &CommonState,
    config: &TlsConfig,
    server_name: Option<&ServerName<'_>>,
) -> io::Result<()> {
    if common.handshake_kind() != Some(HandshakeKind::Resumed) {
        return Ok(());
    }
    let refused = |e: Error| io::Error::new(io::ErrorKind::InvalidData, e);
    let (leaf, intermediates) = common
        .peer_certificates()
        .and_then(<[_]>::split_first)
        .ok_or_else(|| refused(Error::NoCertificatesPresented))?;
    let now = UnixTime::now();
    server_name
        .map_or_else(
            || {
                config
                    .client_verifier
                    .verify_client_cert(leaf, intermediates, now)
                    .map(drop)
            },
            |name| {
                config
                    .server_verifier
                    .verify_server_cert(leaf, intermediates, name, &[], now)
                    .map(drop)
            },
        )
        .map_err(refused)
}
