//! Hardening against misbehaving peers and stale credentials: a handshake
//! that never finishes, a trickled record, a lone `KeyUpdate`, descriptor
//! exhaustion, an out-of-date CRL, credentials that do not fit together, and
//! resumption past a certificate's expiry.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

mod pki;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use iec104_tls::{TlsConfig, Version};
use pki::{Ca, station};
use rcgen::{CertificateRevocationListParams, KeyIdMethod, SerialNumber, date_time_ymd};

fn listener() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    (l, p)
}

/// The handshake timeout bounds the whole handshake, not each read: a peer
/// that trickles one octet of a never-finished record every 100 ms is dropped
/// at the deadline.
#[test]
fn the_blocking_handshake_timeout_holds_against_a_trickling_peer() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .handshake_timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let (listener, port) = listener();
    let attacker = thread::spawn(move || {
        let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        // Handshake record header, TLS 1.0 legacy version, length 16000.
        tcp.write_all(&[0x16, 0x03, 0x01, 0x3e, 0x80]).unwrap();
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(4) {
            if tcp.write_all(&[0x00]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let (tcp, _) = listener.accept().unwrap();
    let started = Instant::now();
    let result = iec104_tls::accept(tcp, &server);
    let elapsed = started.elapsed();
    attacker.join().unwrap();
    assert!(result.is_err());
    assert!(
        elapsed < Duration::from_secs(2),
        "accept took {elapsed:?} with a 500 ms handshake timeout ({:?})",
        result.err()
    );
}

/// A `KeyUpdate` arriving on its own (RFC 8446 4.6.3) is no data: a blocking
/// read on a socket without a read timeout keeps waiting for the data.
#[test]
fn a_lone_key_update_does_not_end_a_blocking_read() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls13, Version::Tls13)
        .build()
        .unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let (listener, port) = listener();
    let srv = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut tls = iec104_tls::accept(tcp, &server).unwrap();
        tls.update_keys().unwrap();
        thread::sleep(Duration::from_millis(300));
        tls.write_all(b"x").unwrap();
        thread::sleep(Duration::from_millis(300));
    });
    let mut tls = iec104_tls::connect(&format!("127.0.0.1:{port}"), &client).unwrap();
    // No read timeout: a blocking read must block until "x" arrives.
    let mut buf = [0u8; 1];
    let r = tls.read(&mut buf);
    srv.join().unwrap();
    match r {
        Ok(1) => assert_eq!(&buf, b"x"),
        other => panic!("blocking read without timeout returned {other:?}"),
    }
}

/// The read timeout bounds the whole read, not each socket read: a peer
/// trickling one octet of a record every 20 ms does not hold a read with a
/// 50 ms timeout past a few timeouts.
#[test]
fn the_blocking_read_timeout_holds_against_a_trickling_record() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca).build().unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let (listener, port) = listener();
    let srv = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let tls = iec104_tls::accept(tcp, &server).unwrap();
        let mut raw = tls.get_ref();
        // Application data record header, length 100, then its body octet by octet.
        raw.write_all(&[0x17, 0x03, 0x03, 0x00, 0x64]).unwrap();
        for _ in 0..100 {
            if raw.write_all(&[0x00]).is_err() {
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
    });
    let mut tls = iec104_tls::connect(&format!("127.0.0.1:{port}"), &client).unwrap();
    tls.get_ref()
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let started = Instant::now();
    let r = tls.read(&mut [0u8; 1]);
    let elapsed = started.elapsed();
    srv.join().unwrap();
    assert!(
        elapsed < Duration::from_millis(500),
        "read took {elapsed:?} with a 50 ms read timeout ({r:?})"
    );
    let kind = r.unwrap_err().kind();
    assert!(
        matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
        "{kind:?}"
    );
}

/// A CRL whose nextUpdate has passed says nothing about today (RFC 5280
/// 5.1.2.5): the handshake is refused rather than trusting it.
#[test]
fn an_expired_crl_is_refused() {
    let ca = Ca::new("test CA");
    let params = CertificateRevocationListParams {
        this_update: date_time_ymd(2019, 1, 1),
        next_update: date_time_ymd(2020, 1, 1),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![],
        key_identifier_method: KeyIdMethod::Sha256,
    };
    let crl = ca.sign_crl(&params);
    let (listener, port) = listener();
    let server = station(&ca, 2, &ca).build().unwrap();
    let srv = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        iec104_tls::accept(tcp, &server).map(|_| ())
    });
    let client = station(&ca, 1, &ca).crls([crl]).build().unwrap();
    let r = iec104_tls::connect(&format!("127.0.0.1:{port}"), &client);
    let _ = srv.join();
    assert!(
        r.is_err(),
        "client accepted the server on a CRL that expired in 2020"
    );
}

/// A key that does not belong to the certificate, an empty chain, and no
/// trust anchors are all refused when the configuration is built.
#[test]
fn inconsistent_credentials_are_refused_at_build() {
    let ca = Ca::new("test CA");
    let a = ca.leaf(&["127.0.0.1"], 1);
    let b = ca.leaf(&["127.0.0.1"], 2);
    let id = iec104_tls::Identity::new(vec![a.cert.clone()], b.key());
    let e = TlsConfig::builder(id, vec![ca.cert.clone()]).build();
    assert!(e.is_err());
    let id = iec104_tls::Identity::new(vec![], a.key());
    let e = TlsConfig::builder(id, vec![ca.cert.clone()]).build();
    assert!(e.is_err());
    let e = TlsConfig::builder(a.identity(), vec![]).build();
    assert!(e.is_err());
}

/// Peers that open connections and never finish the handshake cannot stop
/// the accept loop: out of descriptors, it waits and accepts again instead of
/// returning. Needs a low descriptor limit, so it is ignored by default:
///
/// ```text
/// cargo test -p iec104-tls --features tokio --test hardening --no-run
/// prlimit --nofile=64:64 target/debug/deps/hardening-* serve_survives --ignored
/// ```
#[tokio::test]
#[ignore = "needs a low descriptor limit (see the doc comment)"]
async fn serve_survives_descriptor_exhaustion_by_unauthenticated_peers() {
    let ca = Ca::new("test CA");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let group = iec104::redundancy::RedundancyGroup::uniform(
        iec104::link::Role::Controlled,
        iec104::params::LinkParams::default(),
        1,
    )
    .unwrap();
    let (handle, _events) =
        iec104_tokio::outstation::spawn(group, iec104_tokio::Options::default()).unwrap();
    let config = station(&ca, 2, &ca)
        .handshake_timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let served = tokio::spawn(iec104_tls::tokio::serve(
        listener,
        config,
        handle,
        |_, _| {},
    ));
    // 100 silent connections from another process.
    let mut child = std::process::Command::new("bash")
        .arg("-c")
        .arg(format!(
            "for i in $(seq 100); do exec {{fd}}<>/dev/tcp/127.0.0.1/{port}; done; sleep 4"
        ))
        .spawn()
        .unwrap();
    let r = tokio::time::timeout(Duration::from_secs(3), served).await;
    let _ = child.kill();
    let _ = child.wait();
    if let Ok(ended) = r {
        panic!("serve returned: {:?}", ended.unwrap());
    }
}

/// With session resumption on, TLS 1.2 sessions are not resumed (rustls
/// would keep them with no time limit): a client whose certificate expired
/// since its first handshake gets a full handshake, which refuses it.
#[test]
fn an_expired_client_certificate_cannot_resume_a_tls12_session() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls12, Version::Tls12)
        .session_resumption(true)
        .build()
        .unwrap();
    let leaf = ca.leaf_expiring(&["127.0.0.1"], 1, 2);
    let client = TlsConfig::builder(leaf.identity(), vec![ca.cert.clone()])
        .session_resumption(true)
        .build()
        .unwrap();
    let (listener, port) = listener();
    let srv = thread::spawn(move || {
        let mut results = Vec::new();
        for _ in 0..3 {
            let (tcp, _) = listener.accept().unwrap();
            results.push(iec104_tls::accept(tcp, &server).map(|mut s| {
                let _ = s.write_all(b"!");
                let mut rest = Vec::new();
                let _ = s.read_to_end(&mut rest);
            }));
        }
        results
    });
    let once = |cfg: &TlsConfig| -> io::Result<()> {
        let mut tls = iec104_tls::connect(&format!("127.0.0.1:{port}"), cfg)?;
        let mut b = [0u8; 1];
        tls.read_exact(&mut b)?;
        tls.shutdown()
    };
    once(&client).unwrap();
    thread::sleep(Duration::from_secs(4));
    let resumed = once(&client);
    let fresh_client = TlsConfig::builder(leaf.identity(), vec![ca.cert.clone()])
        .build()
        .unwrap();
    let fresh = once(&fresh_client);
    let results = srv.join().unwrap();
    println!("resumed client: {resumed:?}; fresh client: {fresh:?}");
    println!("server: {results:?}");
    assert!(
        results[2].is_err(),
        "full handshake with the expired cert must fail"
    );
    assert!(
        results[1].is_err(),
        "server accepted a resumed session from a client whose certificate expired"
    );
}
