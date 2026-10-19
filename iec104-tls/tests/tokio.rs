//! Async TLS in-process over loopback: iec104-tokio's master and outstation
//! drivers over mutual TLS, and the refusals as the drivers and accept loops
//! report them. The ASDUs are written out by hand from 101; the APCIs come
//! from the drivers.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

mod pki;

use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104::redundancy::RedundancyGroup;
use iec104_tls::rustls::{self, CertificateError};
use iec104_tls::tokio::{TlsConnector, serve, serve_routed};
use iec104_tls::{CertificateDer, ProtocolVersion, TlsConfig, Version, tls_error};
use iec104_tokio::{Event, Events, Options, master, outstation};
use pki::{Ca, station};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

/// `C_IC_NA_1`, cause 6, common address 1, IOA 0, QOI 20 (101 cl.7.3.4.1).
const INTERROGATION: [u8; 10] = [0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14];

/// `M_ME_NB_1`, cause 3 (spontaneous), common address 1, IOA 100, value
/// 1000, QDS 0 (101 cl.7.3.1.11).
const MEASURAND: [u8; 12] = [
    0x0B, 0x01, 0x03, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0xE8, 0x03, 0x00,
];

async fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// The first event `wanted` picks, within five seconds.
async fn until<T>(events: &mut Events, mut wanted: impl FnMut(&Event) -> Option<T>) -> T {
    timeout(Duration::from_secs(5), async {
        loop {
            let event = events.recv().await.expect("the driver runs");
            if let Some(found) = wanted(&event) {
                return found;
            }
        }
    })
    .await
    .expect("the event never came")
}

fn master_manager() -> ConnectionManager {
    ConnectionManager::new(
        Role::Controlling,
        vec![StationConfig::new(LinkParams::default())],
    )
    .unwrap()
}

fn outstation_group() -> RedundancyGroup {
    RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 1).unwrap()
}

/// STARTDT (clause 5.3) and an I-frame each way through the async drivers,
/// over a mutually authenticated TLS session.
#[tokio::test]
async fn the_async_drivers_carry_startdt_and_i_frames_over_mutual_tls() {
    let ca = Ca::new("test CA");
    let (listener, port) = listener().await;
    let (os_handle, mut os_events) =
        outstation::spawn(outstation_group(), Options::default()).unwrap();
    let server = station(&ca, 2, &ca).build().unwrap();
    tokio::spawn(serve(listener, server, os_handle.clone(), |peer, e| {
        panic!("{peer} refused: {e}")
    }));

    let connector = TlsConnector::new(
        station(&ca, 1, &ca).build().unwrap(),
        vec![format!("127.0.0.1:{port}")],
    );
    let (handle, mut events) =
        master::spawn(master_manager(), connector, Options::default()).unwrap();
    until(&mut events, |e| {
        matches!(
            e,
            Event::State {
                conn: 0,
                state: State::Started
            }
        )
        .then_some(())
    })
    .await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    let asdu = until(&mut os_events, |e| match e {
        Event::Asdu { asdu, .. } => Some(asdu.clone()),
        _ => None,
    })
    .await;
    assert_eq!(asdu, INTERROGATION);

    os_handle.send_asdu(0, MEASURAND).await.unwrap();
    let asdu = until(&mut events, |e| match e {
        Event::Asdu { asdu, .. } => Some(asdu.clone()),
        _ => None,
    })
    .await;
    assert_eq!(asdu, MEASURAND);
    handle.shutdown().await;
    os_handle.shutdown().await;
}

#[tokio::test]
async fn the_master_reports_an_untrusted_server_as_a_failed_connect() {
    let (ca, rogue) = (Ca::new("test CA"), Ca::new("rogue CA"));
    let (listener, port) = listener().await;
    let (os_handle, _os_events) =
        outstation::spawn(outstation_group(), Options::default()).unwrap();
    let server = station(&rogue, 2, &ca).build().unwrap();
    tokio::spawn(serve(listener, server, os_handle, |_, _| {}));

    let connector = TlsConnector::new(
        station(&ca, 1, &ca).build().unwrap(),
        vec![format!("127.0.0.1:{port}")],
    );
    let (_handle, mut events) =
        master::spawn(master_manager(), connector, Options::default()).unwrap();
    let error = until(&mut events, |e| match e {
        Event::ConnectFailed { error, .. } => Some(error.clone()),
        Event::Connected { .. } => panic!("connected to an untrusted server"),
        _ => None,
    })
    .await;
    // rustls' text for InvalidCertificate(UnknownIssuer).
    assert!(error.contains("UnknownIssuer"), "{error}");
}

#[tokio::test]
async fn serve_reports_a_refused_client_and_attaches_nothing() {
    let (ca, rogue) = (Ca::new("test CA"), Ca::new("rogue CA"));
    let (listener, port) = listener().await;
    let (os_handle, mut os_events) =
        outstation::spawn(outstation_group(), Options::default()).unwrap();
    let (refusals, mut refused) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(serve(
        listener,
        station(&ca, 2, &ca).build().unwrap(),
        os_handle,
        move |peer: SocketAddr, e: io::Error| {
            let _ = refusals.send((peer, tls_error(&e).cloned()));
        },
    ));

    let client = station(&rogue, 1, &ca).build().unwrap();
    let mut stream = iec104_tls::tokio::connect(&format!("127.0.0.1:{port}"), &client)
        .await
        .unwrap();
    let local = stream.get_ref().local_addr().unwrap();
    // TLS 1.3: the refusal reaches the client on its first read.
    let mut octet = [0u8; 1];
    assert!(stream.read(&mut octet).await.is_err());

    let (peer, error) = timeout(Duration::from_secs(5), refused.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer, local);
    assert_eq!(
        error,
        Some(rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
    );
    assert!(
        timeout(
            Duration::from_millis(200),
            until(&mut os_events, |e| {
                matches!(e, Event::Connected { .. }).then_some(())
            })
        )
        .await
        .is_err(),
        "a refused client was attached"
    );
}

/// `serve_routed` hands the route the peer's authenticated certificate, so a
/// master is tied to its process image by identity.
#[tokio::test]
async fn serve_routed_routes_on_the_peer_certificate() {
    let ca = Ca::new("test CA");
    let known = ca.leaf(&["127.0.0.1"], 1);
    let stranger = ca.leaf(&["127.0.0.1"], 3);
    let (listener, port) = listener().await;
    let (os_handle, mut os_events) =
        outstation::spawn(outstation_group(), Options::default()).unwrap();
    let seen: Arc<Mutex<Vec<CertificateDer<'static>>>> = Arc::default();
    let (route_seen, route_known) = (seen.clone(), known.cert.clone());
    tokio::spawn(serve_routed(
        listener,
        station(&ca, 2, &ca).build().unwrap(),
        move |_peer, certs| {
            route_seen.lock().unwrap().push(certs[0].clone());
            (certs[0] == route_known).then(|| os_handle.clone())
        },
        |peer, e| panic!("{peer} refused: {e}"),
    ));

    let address = format!("127.0.0.1:{port}");
    let config = |leaf: &pki::Leaf| {
        TlsConfig::builder(leaf.identity(), vec![ca.cert.clone()])
            .build()
            .unwrap()
    };
    let mut refused = iec104_tls::tokio::connect(&address, &config(&stranger))
        .await
        .unwrap();
    let mut octet = [0u8; 1];
    // Not routed: the connection is dropped, which the client reads as EOF.
    let read = timeout(Duration::from_secs(5), refused.read(&mut octet))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");

    let _routed = iec104_tls::tokio::connect(&address, &config(&known))
        .await
        .unwrap();
    until(&mut os_events, |e| {
        matches!(e, Event::Connected { conn: 0 }).then_some(())
    })
    .await;
    assert_eq!(*seen.lock().unwrap(), [stranger.cert, known.cert]);
}

/// RFC 8446 5.3 (a record's sequence number restarts with every new key), as
/// in the blocking test: with a zero interval, a `KeyUpdate` goes ahead of each
/// write, so the peer's read sequence ends at 1 after five writes.
#[tokio::test]
async fn an_async_key_update_goes_ahead_of_each_write_once_the_interval_passed() {
    for (interval, expected) in [(None, 5), (Some(Duration::ZERO), 1)] {
        let ca = Ca::new("test CA");
        let server = station(&ca, 2, &ca)
            .versions(Version::Tls13, Version::Tls13)
            .build()
            .unwrap();
        let mut raw = (*server.server_config()).clone();
        raw.enable_secret_extraction = true;
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = std_listener.local_addr().unwrap().port();
        let (sequence, reader) = mpsc::channel();
        thread::spawn(move || {
            let (tcp, _) = std_listener.accept().unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(raw)).unwrap();
            let mut stream = rustls::StreamOwned::new(conn, tcp);
            let mut five = [0u8; 5];
            for octet in &mut five {
                stream.read_exact(std::slice::from_mut(octet)).unwrap();
            }
            assert_eq!(&five, b"abcde");
            let secrets = stream.conn.dangerous_extract_secrets().unwrap();
            sequence.send(secrets.rx.0).unwrap();
        });
        let client = station(&ca, 1, &ca)
            .key_update_interval(interval)
            .build()
            .unwrap();
        let mut tls = iec104_tls::tokio::connect(&format!("127.0.0.1:{port}"), &client)
            .await
            .unwrap();
        assert_eq!(tls.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        for octet in b"abcde" {
            tls.write_all(std::slice::from_ref(octet)).await.unwrap();
            tls.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let got = tokio::task::spawn_blocking(move || reader.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, expected, "interval {interval:?}");
    }
}

/// Peers that open TCP connections and never send a `ClientHello` hold
/// handshake slots for the whole handshake timeout. Those of one address are
/// capped, so they cannot take every slot and lock out the master, which
/// dials from another address (two loopback addresses, so Linux only).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn silent_peers_of_one_address_do_not_lock_out_another() {
    let ca = Ca::new("test CA");
    let (listener, port) = listener().await;
    let (os_handle, _os_events) =
        outstation::spawn(outstation_group(), Options::default()).unwrap();
    let server = station(&ca, 2, &ca)
        .handshake_timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    tokio::spawn(serve(listener, server, os_handle, |_, _| {}));

    let mut silent = Vec::new();
    for _ in 0..iec104_tls::tokio::MAX_HANDSHAKES {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        silent.push(
            socket
                .connect(format!("127.0.0.1:{port}").parse().unwrap())
                .await
                .unwrap(),
        );
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = station(&ca, 1, &ca)
        .handshake_timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    iec104_tls::tokio::connect(&format!("127.0.0.1:{port}"), &client)
        .await
        .expect("the master gets a handshake slot");
    drop(silent);
}
