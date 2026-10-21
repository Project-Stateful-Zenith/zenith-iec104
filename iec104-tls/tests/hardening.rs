//! Hardening against misbehaving peers and stale credentials: a handshake
//! that never finishes, a trickled record, a lone `KeyUpdate`, descriptor
//! exhaustion, a peer that drains slowly or not at all, an out-of-date CRL,
//! credentials that do not fit together, and resumption past a certificate's
//! expiry.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

mod pki;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use iec104_tls::{TlsConfig, Version, rustls};
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

/// A listener whose connections have a small receive buffer, and so a small
/// TCP window.
fn narrow_listener() -> (TcpListener, u16) {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    socket
        .bind(
            &"127.0.0.1:0"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .into(),
        )
        .unwrap();
    socket.listen(1).unwrap();
    let l = TcpListener::from(socket);
    let p = l.local_addr().unwrap().port();
    (l, p)
}

/// A client over a small send buffer, with `timeout` for writes.
fn narrow_client(port: u16, client: &TlsConfig, timeout: Duration) -> iec104_tls::TlsStream {
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket2::SockRef::from(&tcp)
        .set_send_buffer_size(4096)
        .unwrap();
    let tls = iec104_tls::connect_over(tcp, "127.0.0.1", client).unwrap();
    tls.get_ref().set_write_timeout(Some(timeout)).unwrap();
    tls
}

/// Writes 64 KiB at a time until a flush stalls, and returns what the writes
/// took. A peer that reads slowly or not at all does not stall a single 64 KiB
/// write everywhere: Windows' loopback takes it in whole despite the small
/// socket buffers. Every write and flush must end well inside 900 ms, so the
/// write timeout (150 ms at most) bounds each one as a whole.
fn write_until_stalled(tls: &mut iec104_tls::TlsStream) -> Vec<u8> {
    let data: Vec<u8> = (0..=250u8).cycle().take(65536).collect();
    let mut written = Vec::new();
    loop {
        let started = Instant::now();
        let n = tls.write(&data).unwrap();
        assert!(n > 0);
        written.extend(data.iter().take(n));
        let r = tls.flush();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(900),
            "write and flush took {elapsed:?} ({r:?})"
        );
        match r {
            Ok(()) => assert!(
                written.len() < 64 << 20,
                "64 MiB went out without a flush stalling"
            ),
            Err(e) => {
                let kind = e.kind();
                assert!(
                    matches!(kind, io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut),
                    "{kind:?}"
                );
                return written;
            }
        }
    }
}

/// The write timeout bounds the whole flush, not each send: a peer draining
/// 2 KiB every 50 ms keeps every send moving, yet once the socket buffers are
/// full, a flush of 64 KiB with a 150 ms write timeout gives up after a few
/// timeouts.
#[test]
fn the_blocking_write_timeout_holds_against_a_slow_reader() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca).build().unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let (listener, port) = narrow_listener();
    let done = Arc::new(AtomicBool::new(false));
    let srv = thread::spawn({
        let done = Arc::clone(&done);
        move || {
            let (tcp, _) = listener.accept().unwrap();
            let tls = iec104_tls::accept(tcp, &server).unwrap();
            let mut raw = tls.get_ref();
            let started = Instant::now();
            let mut buf = [0u8; 2048];
            while !done.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(5) {
                if matches!(raw.read(&mut buf), Ok(0) | Err(_)) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
    });
    let mut tls = narrow_client(port, &client, Duration::from_millis(150));
    write_until_stalled(&mut tls);
    done.store(true, Ordering::Relaxed);
    srv.join().unwrap();
}

/// A write whose data is queued succeeds even when sending it times out, so
/// the caller does not write it again: once the peer reads, it gets the data
/// exactly once.
#[test]
fn a_queued_write_is_not_reported_as_failed() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca).build().unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let (listener, port) = narrow_listener();
    let (go, wait) = mpsc::channel::<()>();
    let srv = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut tls = iec104_tls::accept(tcp, &server).unwrap();
        // Not reading until the client's write has stalled.
        if wait.recv().is_err() {
            return Vec::new();
        }
        let mut got = Vec::new();
        tls.read_to_end(&mut got).unwrap();
        got
    });
    let mut tls = narrow_client(port, &client, Duration::from_millis(100));
    // The peer reads nothing yet: the rest of the data cannot go out.
    let data = write_until_stalled(&mut tls);
    go.send(()).unwrap();
    let started = Instant::now();
    loop {
        match tls.flush() {
            Ok(()) => break,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "flush never finished"
                );
            }
            Err(e) => panic!("{e}"),
        }
    }
    tls.shutdown().unwrap();
    assert_eq!(srv.join().unwrap(), data);
}

/// Data stuck on the way out does not stop the way in: a station whose own
/// send has stalled still reads what the peer sent, so two stations both stuck
/// writing can drain each other.
#[test]
fn a_stalled_send_does_not_stop_the_read() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca).build().unwrap();
    let client = station(&ca, 1, &ca).build().unwrap();
    let (listener, port) = narrow_listener();
    let (go, wait) = mpsc::channel::<()>();
    let srv = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut tls = iec104_tls::accept(tcp, &server).unwrap();
        tls.write_all(b"ping").unwrap();
        tls.flush().unwrap();
        // Reads nothing until the test is over.
        let _ = wait.recv();
    });
    let mut tls = narrow_client(port, &client, Duration::from_millis(100));
    write_until_stalled(&mut tls);
    let mut got = [0u8; 4];
    let started = Instant::now();
    let mut have = 0;
    while have < got.len() {
        match tls.read(&mut got[have..]) {
            Ok(0) => panic!("closed"),
            Ok(k) => have += k,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "the read never got past the stalled send"
                );
            }
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(&got, b"ping");
    go.send(()).unwrap();
    srv.join().unwrap();
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

/// Three connections to `server`, which has resumption on, from `client`,
/// whose certificate expires 2 s after issue: the second right after the
/// first, the third 4 s later, past the expiry. For each, the client's
/// handshake kind (`None` if its handshake failed) and the server's accept.
fn connect_thrice(
    server: TlsConfig,
    client: &Arc<rustls::ClientConfig>,
) -> [(Option<rustls::HandshakeKind>, io::Result<()>); 3] {
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
    let once = || {
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let conn = rustls::ClientConnection::new(client.clone(), name).unwrap();
        let mut tls =
            rustls::StreamOwned::new(conn, TcpStream::connect(("127.0.0.1", port)).unwrap());
        let mut b = [0u8; 1];
        let read = tls.read_exact(&mut b);
        let kind = tls.conn.handshake_kind();
        if read.is_ok() {
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
        kind
    };
    let mut kinds = vec![once(), once()];
    thread::sleep(Duration::from_secs(4));
    kinds.push(once());
    let results = srv.join().unwrap();
    println!("client: {kinds:?}; server: {results:?}");
    let both: Vec<_> = kinds.into_iter().zip(results).collect();
    both.try_into().unwrap()
}

/// The resumed session of a client whose certificate expired since is
/// refused: rustls resumes it without calling the verifier, and the server
/// checks the certificate from the ticket again.
fn assert_expiry_is_checked_on_resumption(
    [first, second, third]: &[(Option<rustls::HandshakeKind>, io::Result<()>); 3],
) {
    use rustls::HandshakeKind::{Full, Resumed};
    assert_eq!(first.0, Some(Full));
    assert!(first.1.is_ok(), "full handshake refused");
    assert_eq!(second.0, Some(Resumed));
    assert!(second.1.is_ok(), "resumed handshake refused");
    assert_eq!(third.0, Some(Resumed), "third connection not resumed");
    let e = third.1.as_ref().unwrap_err();
    assert!(
        matches!(
            iec104_tls::tls_error(e),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ))
        ),
        "server accepted a resumed session from a client whose certificate expired: {e:?}"
    );
}

/// TLS 1.3 (RFC 8446 2.2): our client resumes with a ticket from the resumed
/// second handshake, after its certificate expired.
#[test]
fn an_expired_client_certificate_cannot_resume_a_tls13_session() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls13, Version::Tls13)
        .session_resumption(true)
        .build()
        .unwrap();
    let leaf = ca.leaf_expiring(&["127.0.0.1"], 1, 2);
    let ours = TlsConfig::builder(leaf.identity(), vec![ca.cert.clone()])
        .versions(Version::Tls13, Version::Tls13)
        .session_resumption(true)
        .build()
        .unwrap();
    assert_expiry_is_checked_on_resumption(&connect_thrice(server, &ours.client_config()));
}

/// With session resumption on and TLS 1.2 allowed, the server resumes no
/// session: a client that does offer a TLS 1.2 ticket (rustls' default) gets
/// a full handshake, which refuses it once its certificate expired.
#[test]
fn an_expired_client_certificate_cannot_resume_a_tls12_session() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls12, Version::Tls12)
        .session_resumption(true)
        .build()
        .unwrap();
    let leaf = ca.leaf_expiring(&["127.0.0.1"], 1, 2);
    let ours = TlsConfig::builder(leaf.identity(), vec![ca.cert.clone()])
        .build()
        .unwrap();
    // Not our client, which offers no TLS 1.2 ticket: rustls' default resumption.
    let mut client = (*ours.client_config()).clone();
    client.resumption = rustls::client::Resumption::default();
    let [first, second, third] = connect_thrice(server, &Arc::new(client));
    assert_eq!(first.0, Some(rustls::HandshakeKind::Full));
    assert!(first.1.is_ok(), "full handshake refused");
    assert_eq!(
        second.0,
        Some(rustls::HandshakeKind::Full),
        "server resumed a TLS 1.2 session"
    );
    assert!(second.1.is_ok(), "second full handshake refused");
    let e = third.1.unwrap_err();
    assert!(
        matches!(
            iec104_tls::tls_error(&e),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ))
        ),
        "server accepted a client whose certificate expired: {e:?}"
    );
}

/// The mirror case: our client checks the server of a resumed session again,
/// and refuses one whose certificate expired since.
#[test]
fn a_server_certificate_that_expired_is_refused_on_resumption() {
    let ca = Ca::new("test CA");
    let leaf = ca.leaf_expiring(&["127.0.0.1"], 2, 2);
    let server = TlsConfig::builder(leaf.identity(), vec![ca.cert.clone()])
        .versions(Version::Tls13, Version::Tls13)
        .session_resumption(true)
        .build()
        .unwrap();
    let client = station(&ca, 1, &ca)
        .versions(Version::Tls13, Version::Tls13)
        .session_resumption(true)
        .build()
        .unwrap();
    let (listener, port) = listener();
    let srv = thread::spawn(move || {
        for _ in 0..3 {
            let (tcp, _) = listener.accept().unwrap();
            if let Ok(mut s) = iec104_tls::accept(tcp, &server) {
                let _ = s.write_all(b"!");
                let mut rest = Vec::new();
                let _ = s.read_to_end(&mut rest);
            }
        }
    });
    let once = || -> io::Result<()> {
        let mut tls = iec104_tls::connect(&format!("127.0.0.1:{port}"), &client)?;
        tls.read_exact(&mut [0u8; 1])?;
        tls.shutdown()
    };
    once().unwrap();
    once().unwrap();
    thread::sleep(Duration::from_secs(4));
    let e = once().unwrap_err();
    srv.join().unwrap();
    assert!(
        matches!(
            iec104_tls::tls_error(&e),
            Some(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ))
        ),
        "client accepted a resumed session from a server whose certificate expired: {e:?}"
    );
}

/// The positive control for the tests above: with TLS 1.3 only and resumption
/// on at both ends, our client's second connection is resumed.
#[test]
fn a_tls13_session_is_resumed_when_resumption_is_on() {
    let ca = Ca::new("test CA");
    let server = station(&ca, 2, &ca)
        .versions(Version::Tls13, Version::Tls13)
        .session_resumption(true)
        .build()
        .unwrap();
    let leaf = ca.leaf(&["127.0.0.1"], 1);
    let ours = TlsConfig::builder(leaf.identity(), vec![ca.cert.clone()])
        .versions(Version::Tls13, Version::Tls13)
        .session_resumption(true)
        .build()
        .unwrap();
    let client = ours.client_config();
    let (listener, port) = listener();
    let srv = thread::spawn(move || {
        for _ in 0..2 {
            let (tcp, _) = listener.accept().unwrap();
            let mut s = iec104_tls::accept(tcp, &server).unwrap();
            s.write_all(b"!").unwrap();
            let mut rest = Vec::new();
            let _ = s.read_to_end(&mut rest);
        }
    });
    let once = || -> rustls::HandshakeKind {
        let name = rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap();
        let conn = rustls::ClientConnection::new(client.clone(), name).unwrap();
        let mut tls =
            rustls::StreamOwned::new(conn, TcpStream::connect(("127.0.0.1", port)).unwrap());
        let mut b = [0u8; 1];
        tls.read_exact(&mut b).unwrap();
        let kind = tls.conn.handshake_kind().unwrap();
        tls.conn.send_close_notify();
        tls.flush().unwrap();
        kind
    };
    assert_eq!(once(), rustls::HandshakeKind::Full);
    assert_eq!(once(), rustls::HandshakeKind::Resumed);
    srv.join().unwrap();
}
