//! Blocking TLS in-process over loopback: the mutual handshake carrying 104
//! through the examples' blocking driver, and every way a handshake must be
//! refused.
//!
//! The alerts asserted are the ones RFC 8446 (TLS 1.3) names for each
//! failure: `unknown_ca` (6.2), `certificate_required` (4.4.2.4),
//! `protocol_version` (4.2.1), `handshake_failure` (4.1.1),
//! `certificate_revoked` and `access_denied` (6.2). The ASDU carried is
//! 101's `C_IC_NA_1`, written out by hand; the APCIs (clause 5, figures 6–8)
//! come from the driver.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

#[path = "../../examples/common/mod.rs"]
#[allow(dead_code)]
mod common;
mod pki;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104_tls::rustls::{self, AlertDescription, CertificateError, PeerIncompatible};
use iec104_tls::{
    CipherSuite, ConfigError, ProtocolVersion, TlsConfig, TlsStream, Version, tls_error,
};
use pki::{Ca, station};

impl common::Socket for TlsStream {
    fn tcp(&self) -> &TcpStream {
        self.get_ref()
    }
}

/// `C_IC_NA_1`, cause 6 (activation), common address 1, IOA 0, QOI 20: a
/// station interrogation (101 cl.7.3.4.1).
const INTERROGATION: [u8; 10] = [0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14];

fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// The TLS error inside `result`'s I/O error.
fn tls<T>(result: io::Result<T>) -> rustls::Error {
    match result {
        Ok(_) => panic!("expected a TLS failure, the handshake succeeded"),
        Err(e) => tls_error(&e)
            .unwrap_or_else(|| panic!("not a TLS error: {e}"))
            .clone(),
    }
}

/// What each side saw of one connection.
struct Outcome {
    /// The client's handshake, then its read of the server's first octet.
    client: io::Result<TlsStream>,
    /// The server's handshake.
    server: io::Result<()>,
}

/// One connection from `client` to `server` at `host`: the server writes
/// one octet once its handshake is done and waits for the client to close.
fn connect(server: TlsConfig, client: &TlsConfig, host: &str) -> Outcome {
    let (listener, port) = listener();
    let server = thread::spawn(move || -> io::Result<()> {
        let (tcp, _) = listener.accept()?;
        let mut tls = iec104_tls::accept(tcp, &server)?;
        tls.write_all(b"!")?;
        let mut rest = Vec::new();
        let _ = tls.read_to_end(&mut rest);
        Ok(())
    });
    let client = iec104_tls::connect(&format!("{host}:{port}"), client).and_then(|mut tls| {
        tls.get_ref()
            .set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut octet = [0u8; 1];
        tls.read_exact(&mut octet)?;
        assert_eq!(&octet, b"!");
        Ok(tls)
    });
    if let Ok(tls) = &client {
        // Lets the server's read end.
        let _ = tls.get_ref().shutdown(std::net::Shutdown::Both);
    }
    let server = server.join().unwrap();
    Outcome { client, server }
}

/// STARTDT and one I-frame through the examples' blocking driver, over a
/// mutually authenticated TLS 1.3 session: the outstation receives the
/// station interrogation octet for octet, and each side sees the other's
/// certificate.
#[test]
fn a_mutual_tls_session_carries_startdt_and_an_i_frame_through_the_driver() {
    let ca = Ca::new("test CA");
    let master_leaf = ca.leaf(&["127.0.0.1"], 1);
    let outstation_leaf = ca.leaf(&["127.0.0.1"], 2);
    let master = TlsConfig::builder(master_leaf.identity(), vec![ca.cert.clone()])
        .build()
        .unwrap();
    let outstation = TlsConfig::builder(outstation_leaf.identity(), vec![ca.cert.clone()])
        .build()
        .unwrap();
    let (listener, port) = listener();
    let sizes = iec104::asdu::AddressSizes::CONVENTIONAL;
    let (done, received) = mpsc::channel();

    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let tls = iec104_tls::accept(tcp, &outstation).unwrap();
        let peer = tls.peer_certificates().unwrap()[0].clone();
        let version = tls.protocol_version();
        let mut manager = ConnectionManager::new(
            Role::Controlled,
            vec![StationConfig::new(LinkParams::default())],
        )
        .unwrap();
        let mut link = common::Link::new(sizes);
        link.attach(tls, &mut manager, Instant::now()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let now = Instant::now();
            let expired = manager.tick(now);
            link.perform(&mut manager, expired);
            if let Some(asdu) = link.receive(&mut manager, now).into_iter().next() {
                done.send(()).unwrap();
                return (asdu, peer, version);
            }
        }
        panic!("no ASDU arrived");
    });

    let tls = iec104_tls::connect(&format!("127.0.0.1:{port}"), &master).unwrap();
    assert_eq!(tls.peer_certificates().unwrap()[0], outstation_leaf.cert);
    assert_eq!(tls.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    let mut manager = ConnectionManager::new(
        Role::Controlling,
        vec![StationConfig::new(LinkParams::default())],
    )
    .unwrap();
    let mut link = common::Link::new(sizes);
    let now = Instant::now();
    link.attach(tls, &mut manager, now).unwrap();
    let start = manager.request_start(common::STATION, now).unwrap();
    link.perform(&mut manager, start);
    let mut sent = false;
    let deadline = Instant::now() + Duration::from_secs(10);
    while received.try_recv().is_err() {
        assert!(
            Instant::now() < deadline,
            "the outstation never got the ASDU"
        );
        let now = Instant::now();
        let expired = manager.tick(now);
        link.perform(&mut manager, expired);
        link.receive(&mut manager, now);
        let started = manager.station(common::STATION).unwrap().state() == State::Started;
        if started && !sent {
            link.send_asdu(&mut manager, &INTERROGATION, now);
            sent = true;
        }
    }
    let (asdu, peer, version) = server.join().unwrap();
    assert_eq!(asdu, INTERROGATION);
    assert_eq!(peer, master_leaf.cert);
    assert_eq!(version, Some(ProtocolVersion::TLSv1_3));
}

#[test]
fn a_server_certificate_from_an_untrusted_ca_is_refused_by_the_client() {
    let (ca, rogue) = (Ca::new("test CA"), Ca::new("rogue CA"));
    let server = station(&rogue, 2, &ca).build().unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    assert_eq!(
        tls(outcome.client),
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
    );
    assert_eq!(
        tls(outcome.server),
        rustls::Error::AlertReceived(AlertDescription::UnknownCA)
    );
}

#[test]
fn a_client_without_a_certificate_is_refused_by_the_server() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca).build().unwrap();
    let (listener, port) = listener();
    let accepted = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        iec104_tls::accept(tcp, &server).map(|_| ())
    });

    // A plain rustls client that offers no certificate.
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.cert.clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = "127.0.0.1".try_into().unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut stream = rustls::StreamOwned::new(conn, tcp);
    let mut octet = [0u8; 1];
    let read = stream.read(&mut octet);

    assert_eq!(
        tls(accepted.join().unwrap()),
        rustls::Error::NoCertificatesPresented
    );
    assert_eq!(
        tls(read),
        rustls::Error::AlertReceived(AlertDescription::CertificateRequired)
    );
}

/// With TLS 1.3 the client's own handshake completes before the server has
/// judged its certificate, so the refusal reaches it on its first read.
#[test]
fn a_client_certificate_from_an_untrusted_ca_is_refused_by_the_server() {
    let (ca, rogue) = (Ca::new("test CA"), Ca::new("rogue CA"));
    let server = station(&ca, 2, &ca).build().unwrap();
    let client = station(&rogue, 1, &ca).build().unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    assert_eq!(
        tls(outcome.server),
        rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)
    );
    assert_eq!(
        tls(outcome.client),
        rustls::Error::AlertReceived(AlertDescription::UnknownCA)
    );
}

#[test]
fn a_client_not_on_the_servers_allow_list_is_refused() {
    let ca = Ca::new("test CA");
    let allowed = ca.leaf(&["127.0.0.1"], 1);
    let other = ca.leaf(&["127.0.0.1"], 3);
    let server = station(&ca, 2, &ca)
        .allow_peers([allowed.cert.clone()])
        .build()
        .unwrap();

    let client = TlsConfig::builder(other.identity(), vec![ca.cert.clone()])
        .build()
        .unwrap();
    let outcome = connect(server.clone(), &client, "127.0.0.1");
    assert_eq!(
        tls(outcome.server),
        rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
    );
    assert_eq!(
        tls(outcome.client),
        rustls::Error::AlertReceived(AlertDescription::AccessDenied)
    );

    let client = TlsConfig::builder(allowed.identity(), vec![ca.cert.clone()])
        .build()
        .unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    outcome.server.unwrap();
    outcome.client.unwrap();
}

#[test]
fn a_server_not_on_the_clients_allow_list_is_refused() {
    let ca = Ca::new("test CA");
    let expected = ca.leaf(&["127.0.0.1"], 2);
    let server = station(&ca, 4, &ca).build().unwrap();
    let client = station(&ca, 1, &ca)
        .allow_peers([expected.cert.clone()])
        .build()
        .unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    assert_eq!(
        tls(outcome.client),
        rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
    );
    assert_eq!(
        tls(outcome.server),
        rustls::Error::AlertReceived(AlertDescription::AccessDenied)
    );
}

#[test]
fn a_version_outside_the_configured_range_is_refused() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls13, Version::Tls13)
        .build()
        .unwrap();
    let client = station(&ca, 1, &ca)
        .versions(Version::Tls12, Version::Tls12)
        .build()
        .unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    assert!(matches!(
        tls(outcome.server),
        rustls::Error::PeerIncompatible(PeerIncompatible::Tls12NotOfferedOrEnabled)
    ));
    assert_eq!(
        tls(outcome.client),
        rustls::Error::AlertReceived(AlertDescription::ProtocolVersion)
    );
}

#[test]
fn tls_1_2_is_negotiated_when_both_ends_are_limited_to_it() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls12, Version::Tls12)
        .build()
        .unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let tls = connect(server, &client, "127.0.0.1").client.unwrap();
    assert_eq!(tls.protocol_version(), Some(ProtocolVersion::TLSv1_2));
}

#[test]
fn a_cipher_suite_outside_the_configured_set_is_refused() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls13, Version::Tls13)
        .cipher_suites([CipherSuite::TLS13_AES_256_GCM_SHA384])
        .build()
        .unwrap();
    let client = station(&ca, 1, &ca)
        .versions(Version::Tls13, Version::Tls13)
        .cipher_suites([CipherSuite::TLS13_CHACHA20_POLY1305_SHA256])
        .build()
        .unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    assert_eq!(
        tls(outcome.server),
        rustls::Error::PeerIncompatible(PeerIncompatible::NoCipherSuitesInCommon)
    );
    assert_eq!(
        tls(outcome.client),
        rustls::Error::AlertReceived(AlertDescription::HandshakeFailure)
    );
}

#[test]
fn the_configured_cipher_suite_is_the_one_negotiated() {
    let ca = Ca::new("test CA");
    let suite = CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls12, Version::Tls12)
        .cipher_suites([suite])
        .build()
        .unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let tls = connect(server, &client, "127.0.0.1").client.unwrap();
    assert_eq!(tls.cipher_suite(), Some(suite));
}

#[test]
fn a_revoked_client_certificate_is_refused() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca).crls([ca.crl(&[1])]).build().unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    assert_eq!(
        tls(outcome.server),
        rustls::Error::InvalidCertificate(CertificateError::Revoked)
    );
    assert_eq!(
        tls(outcome.client),
        rustls::Error::AlertReceived(AlertDescription::CertificateRevoked)
    );
}

#[test]
fn a_revoked_server_certificate_is_refused() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca).build().unwrap();
    let client = station(&ca, 1, &ca).crls([ca.crl(&[2])]).build().unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    assert_eq!(
        tls(outcome.client),
        rustls::Error::InvalidCertificate(CertificateError::Revoked)
    );
}

#[test]
fn a_certificate_the_crl_does_not_list_is_accepted() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca).crls([ca.crl(&[7])]).build().unwrap();
    let client = station(&ca, 1, &ca).crls([ca.crl(&[7])]).build().unwrap();
    let outcome = connect(server, &client, "127.0.0.1");
    outcome.server.unwrap();
    outcome.client.unwrap();
}

#[test]
fn without_a_crl_from_the_issuer_the_status_is_unknown_and_refused_unless_allowed() {
    let (ca, other) = (Ca::new("test CA"), Ca::new("other CA"));
    let server = station(&ca, 2, &ca).build().unwrap();
    let client = station(&ca, 1, &ca).crls([other.crl(&[])]).build().unwrap();
    let outcome = connect(server.clone(), &client, "127.0.0.1");
    assert_eq!(
        tls(outcome.client),
        rustls::Error::InvalidCertificate(CertificateError::UnknownRevocationStatus)
    );

    let client = station(&ca, 1, &ca)
        .crls([other.crl(&[])])
        .allow_unknown_revocation_status()
        .build()
        .unwrap();
    connect(server, &client, "127.0.0.1").client.unwrap();
}

#[test]
fn a_server_certificate_for_another_host_is_refused_unless_the_name_check_is_off() {
    let ca = Ca::new("test CA");
    let leaf = ca.leaf(&["rtu-7.example"], 2);
    let server = TlsConfig::builder(leaf.identity(), vec![ca.cert.clone()])
        .build()
        .unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let outcome = connect(server.clone(), &client, "127.0.0.1");
    assert!(matches!(
        tls(outcome.client),
        rustls::Error::InvalidCertificate(
            CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. }
        )
    ));

    let client = station(&ca, 1, &ca)
        .verify_server_name(false)
        .build()
        .unwrap();
    connect(server, &client, "127.0.0.1").client.unwrap();
}

#[test]
fn a_handshake_the_peer_never_starts_times_out() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .handshake_timeout(Duration::from_millis(300))
        .build()
        .unwrap();
    let (listener, port) = listener();
    let _silent = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (tcp, _) = listener.accept().unwrap();
    let started = Instant::now();
    let error = iec104_tls::accept(tcp, &server).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(3));
}

/// RFC 8446 5.3: a record's sequence number restarts at 0 whenever its key
/// changes. With a zero interval, a `KeyUpdate` goes ahead of every write, so
/// the server reads the fifth message as record 0 of a fresh key: its read
/// sequence ends at 1, not 5.
#[test]
fn a_key_update_goes_ahead_of_each_write_once_the_interval_passed() {
    for (interval, expected) in [(None, 5), (Some(Duration::ZERO), 1)] {
        let ca = Ca::new("test CA");
        let server = station(&ca, 2, &ca)
            .versions(Version::Tls13, Version::Tls13)
            .build()
            .unwrap();
        let mut raw = (*server.server_config()).clone();
        raw.enable_secret_extraction = true;
        let (listener, port) = listener();
        let reader = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(raw)).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, tcp);
            let mut five = [0u8; 5];
            for octet in &mut five {
                stream.read_exact(std::slice::from_mut(octet)).unwrap();
            }
            assert_eq!(&five, b"abcde");
            let secrets = stream.conn.dangerous_extract_secrets().unwrap();
            secrets.rx.0
        });
        let client = station(&ca, 1, &ca)
            .key_update_interval(interval)
            .build()
            .unwrap();
        let mut tls = iec104_tls::connect(&format!("127.0.0.1:{port}"), &client).unwrap();
        for octet in b"abcde" {
            tls.write_all(std::slice::from_ref(octet)).unwrap();
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(reader.join().unwrap(), expected, "interval {interval:?}");
    }
}

#[test]
fn a_key_update_on_tls_1_2_is_refused_as_there_is_none() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls12, Version::Tls12)
        .build()
        .unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let mut stream = connect(server, &client, "127.0.0.1").client.unwrap();
    assert_eq!(
        tls(stream.update_keys()),
        rustls::Error::HandshakeNotComplete
    );
}

#[test]
fn inconsistent_settings_are_refused_when_the_config_is_built() {
    let ca = Ca::new("test CA");
    assert_eq!(
        station(&ca, 1, &ca)
            .versions(Version::Tls13, Version::Tls12)
            .build()
            .unwrap_err(),
        ConfigError::VersionRange {
            min: Version::Tls13,
            max: Version::Tls12
        }
    );
    // A CBC suite with RSA key exchange: rustls implements none.
    assert_eq!(
        station(&ca, 1, &ca)
            .cipher_suites([CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256])
            .build()
            .unwrap_err(),
        ConfigError::UnsupportedCipherSuite(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256)
    );
    assert_eq!(
        station(&ca, 1, &ca)
            .cipher_suites([CipherSuite::TLS13_AES_128_GCM_SHA256])
            .build()
            .unwrap_err(),
        ConfigError::NoCipherSuiteFor(Version::Tls12)
    );
}

#[test]
fn pem_files_load_as_an_identity_trust_anchors_and_crls() {
    let ca = Ca::new("test CA");
    let leaf = ca.leaf(&["127.0.0.1"], 1);
    let dir = std::env::temp_dir().join(format!("iec104-tls-pem-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ca.crt"), &ca.pem).unwrap();
    std::fs::write(dir.join("own.crt"), &leaf.cert_pem).unwrap();
    std::fs::write(dir.join("own.key"), &leaf.key_pem).unwrap();
    let crl = ca.crl(&[5]);
    let crl_pem = format!(
        "-----BEGIN X509 CRL-----\n{}\n-----END X509 CRL-----\n",
        base64(crl.as_ref())
    );
    std::fs::write(dir.join("ca.crl"), crl_pem).unwrap();

    let identity =
        iec104_tls::Identity::from_pem_files(dir.join("own.crt"), dir.join("own.key")).unwrap();
    assert_eq!(identity.chain(), std::slice::from_ref(&leaf.cert));
    let roots = iec104_tls::certificates_from_pem_file(dir.join("ca.crt")).unwrap();
    assert_eq!(roots, std::slice::from_ref(&ca.cert));
    let crls = iec104_tls::crls_from_pem_file(dir.join("ca.crl")).unwrap();
    assert_eq!(crls, [crl]);
    assert!(matches!(
        iec104_tls::certificates_from_pem(b"not PEM"),
        Err(ConfigError::Pem(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// RFC 4648 base64, for writing a PEM file by hand.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
