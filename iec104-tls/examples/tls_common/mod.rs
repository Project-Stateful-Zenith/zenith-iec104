//! The TLS configuration both examples build from their arguments.

use std::net::TcpStream;

use iec104_tls::{Identity, TlsConfig, TlsStream, certificates_from_pem_file, crls_from_pem_file};

#[path = "../../../examples/common/mod.rs"]
pub mod common;

impl common::Socket for TlsStream {
    fn tcp(&self) -> &TcpStream {
        self.get_ref()
    }
}

/// `cert key ca` from the arguments, and the optional environment:
///
/// - `IEC104_TLS_CRL=file.crl`: check the peer against this PEM CRL;
/// - `IEC104_TLS_PEER=peer.crt`: accept only this peer certificate;
/// - `IEC104_TLS_NO_NAME_CHECK=1`: as a client, accept a server certificate
///   that does not name the host dialed.
pub fn config(args: &mut impl Iterator<Item = String>) -> Result<TlsConfig, String> {
    let usage = "arguments: <address> <cert.pem> <key.pem> <ca.pem>";
    let (Some(cert), Some(key), Some(ca)) = (args.next(), args.next(), args.next()) else {
        return Err(usage.into());
    };
    let identity = Identity::from_pem_files(&cert, &key).map_err(|e| e.to_string())?;
    let roots = certificates_from_pem_file(&ca).map_err(|e| e.to_string())?;
    let mut builder = TlsConfig::builder(identity, roots);
    if let Ok(crl) = std::env::var("IEC104_TLS_CRL") {
        builder = builder.crls(crls_from_pem_file(crl).map_err(|e| e.to_string())?);
    }
    if let Ok(peer) = std::env::var("IEC104_TLS_PEER") {
        builder = builder.allow_peers(certificates_from_pem_file(peer).map_err(|e| e.to_string())?);
    }
    if std::env::var_os("IEC104_TLS_NO_NAME_CHECK").is_some() {
        builder = builder.verify_server_name(false);
    }
    builder.build().map_err(|e| e.to_string())
}

/// One line on who the peer is and what was negotiated.
pub fn describe(tls: &TlsStream) -> String {
    let peer = tls
        .peer_certificates()
        .and_then(|c| c.first())
        .map_or_else(|| "none".into(), |c| format!("{} octets", c.len()));
    format!(
        "TLS {:?}, {:?}, peer certificate {peer}",
        tls.protocol_version(),
        tls.cipher_suite()
    )
}
