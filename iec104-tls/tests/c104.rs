//! 104 over TLS against `c104` (iec104-python, Fraunhofer FIT, GPLv3; it
//! wraps lib60870-C with mbedTLS), run as an **external process**
//! (`tests/interop/c104_tls.py`). Nothing of it is linked or copied.
//!
//! Our blocking and async masters against c104's outstation, over TLS 1.3
//! and 1.2; then the refusals, each seen from both ends: a certificate from
//! a CA the other end does not trust, in either direction, and c104's
//! allow-list. Certificates are made with rcgen at test time.
//!
//! The other direction (c104's master against our outstation) cannot be
//! run: c104 2.2.1's client fails every TLS handshake, against c104's own
//! server too, because its mbedTLS refuses to verify a certificate without a
//! hostname and c104 sets none (see `c104_tls.py`). `lib60870.rs` covers
//! that direction with lib60870-C's own client.
//!
//! Ignored by default; it needs a Python with c104 2.2.1:
//!
//! ```text
//! python3 -m venv .venv && .venv/bin/pip install c104==2.2.1
//! cargo test -p iec104-tls --test c104 -- --ignored --nocapture --test-threads=1
//! ```
//!
//! The interpreter is `<repository>/.venv/bin/python`, or `IEC104_INTEROP_PYTHON`.
//! `scripts/interop.sh` sets the environment up and runs this with the rest.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod interop;

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104_tls::rustls::{self, CertificateError};
use iec104_tls::tokio::TlsConnector;
use iec104_tls::{ProtocolVersion, TlsConfig, tls_error};
use iec104_tokio::{Event, Options, master};
use interop::{INTERROGATION, Keys, Peer, Pki, blocking_master, dial, root};

/// The peer's interrogated point: IOA 0x1001, value 4242 (0x1092), in the
/// `M_ME_NB_1` it answers with (cause 20).
const PEER_POINT: [u8; 5] = [0x01, 0x10, 0x00, 0x92, 0x10];

fn interpreter() -> PathBuf {
    std::env::var("IEC104_INTEROP_PYTHON")
        .map_or_else(|_| root().join(".venv/bin/python"), PathBuf::from)
}

/// c104's outstation on `port` with the `outstation` certificate, trusting
/// `ca`, plus `extra` options; returns once it reports READY.
fn c104_outstation(pki: &Pki, port: u16, ca: &str, extra: &[&str]) -> Peer {
    let mut args = vec![
        root()
            .join("iec104-tls/tests/interop/c104_tls.py")
            .to_string_lossy()
            .into_owned(),
        "server".into(),
        "--port".into(),
        port.to_string(),
        "--cert".into(),
        pki.path("outstation.crt"),
        "--key".into(),
        pki.path("outstation.key"),
        "--ca".into(),
        pki.path(ca),
    ];
    args.extend(extra.iter().map(std::string::ToString::to_string));
    let mut peer = Peer::spawn(&interpreter(), &args);
    assert!(
        peer.wait_for(Duration::from_secs(30), |l| l == "READY"),
        "c104 never printed READY: {:?}",
        peer.log
    );
    if let Some(version) = peer.log.iter().find(|l| l.starts_with("VERSION")) {
        println!("{version}");
    }
    peer
}

/// ACTCON, the point, ACTTERM: 101 cl.7.4.5's interrogation as c104 answers.
fn assert_interrogated(asdus: &[Vec<u8>]) {
    let causes: Vec<(u8, u8)> = asdus.iter().map(|a| (a[0], a[2] & 0x3F)).collect();
    assert_eq!(
        causes,
        [(0x64, 7), (0x0B, 20), (0x64, 10)],
        "C_IC_NA_1 actcon, M_ME_NB_1 inrogen, C_IC_NA_1 actterm: {asdus:02X?}"
    );
    assert!(asdus[1].ends_with(&[0x00]), "QDS 0");
    assert!(
        asdus[1].windows(PEER_POINT.len()).any(|w| w == PEER_POINT),
        "IOA 0x1001 = 4242: {:02X?}",
        asdus[1]
    );
}

/// No APDU crossed: the peer logged none received or sent.
fn assert_silent(peer: &mut Peer) {
    std::thread::sleep(Duration::from_millis(500));
    let log = peer.drain();
    assert!(
        !log.iter()
            .any(|l| l.starts_with("RX") || l.starts_with("TX")),
        "{log:?}"
    );
}

#[test]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
fn our_blocking_master_against_a_c104_outstation_over_tls() {
    let pki = Pki::new("c104-blocking-master", Keys::P256);
    let ours = pki.leaf(&pki.ca, "master", 1);
    pki.leaf(&pki.ca, "outstation", 2);
    let mut peer = c104_outstation(&pki, 24401, "ca.crt", &[]);
    let tls = dial(24401, &pki.ours(&ours)).unwrap();
    assert_eq!(tls.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    println!("{:?}", tls.cipher_suite());
    let run = blocking_master(tls, Duration::from_secs(3));
    assert_interrogated(&run.asdus);
    assert!(!run.closed);
    assert!(peer.wait_for(Duration::from_secs(1), |l| l.starts_with("RX")));
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
async fn our_async_master_against_a_c104_outstation_over_tls() {
    let pki = Pki::new("c104-async-master", Keys::P256);
    let ours = pki.leaf(&pki.ca, "master", 1);
    pki.leaf(&pki.ca, "outstation", 2);
    let _peer = tokio::task::block_in_place(|| c104_outstation(&pki, 24402, "ca.crt", &[]));
    let params = LinkParams {
        t0: Duration::from_secs(1),
        ..LinkParams::default()
    };
    let manager =
        ConnectionManager::new(Role::Controlling, vec![StationConfig::new(params)]).unwrap();
    let connector = TlsConnector::new(pki.ours(&ours), vec!["127.0.0.1:24402".into()]);
    let (handle, mut events) = master::spawn(manager, connector, Options::default()).unwrap();
    let mut asdus = Vec::new();
    let run = tokio::time::sleep(Duration::from_secs(6));
    tokio::pin!(run);
    while asdus.len() < 3 {
        let event = tokio::select! {
            event = events.recv() => event.expect("the driver runs"),
            () = &mut run => break,
        };
        match event {
            Event::State {
                state: State::Started,
                ..
            } => handle.send_asdu(0, INTERROGATION).await.unwrap(),
            Event::Asdu { asdu, .. } => asdus.push(asdu),
            Event::Disconnected { reason, .. } => panic!("the connection closed: {reason}"),
            _ => {}
        }
    }
    handle.shutdown().await;
    assert_interrogated(&asdus);
}

/// c104 limited to TLS 1.2: the session is TLS 1.2 and carries 104 as well.
#[test]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
fn tls_1_2_against_c104() {
    let pki = Pki::new("c104-tls12", Keys::P256);
    let ours = pki.leaf(&pki.ca, "master", 1);
    pki.leaf(&pki.ca, "outstation", 2);
    let _peer = c104_outstation(&pki, 24409, "ca.crt", &["--tls", "1.2"]);
    let tls = dial(24409, &pki.ours(&ours)).unwrap();
    assert_eq!(tls.protocol_version(), Some(ProtocolVersion::TLSv1_2));
    println!("{:?}", tls.cipher_suite());
    assert_interrogated(&blocking_master(tls, Duration::from_secs(3)).asdus);
}

/// c104's outstation trusts only another CA: it refuses our certificate,
/// and not one APDU crosses, with TLS 1.3 and with TLS 1.2.
///
/// With TLS 1.3 our handshake completes before c104 has judged our
/// certificate, so the refusal reaches us on the first read. Observed with
/// c104 2.2.1: under TLS 1.3 the refusal arrives as a record we cannot
/// decrypt (`DecryptError`) rather than a readable alert; under TLS 1.2 as
/// the alert itself (`unknown_ca`).
#[test]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
fn a_c104_outstation_that_does_not_trust_our_ca_refuses_our_master() {
    for (port, version) in [(24404, "1.3"), (24410, "1.2")] {
        let pki = Pki::new(&format!("c104-untrusted-master-{version}"), Keys::P256);
        let ours = pki.leaf(&pki.ca, "master", 1);
        pki.leaf(&pki.ca, "outstation", 2);
        let mut peer = c104_outstation(&pki, port, "rogue.crt", &["--tls", version]);
        let refused = dial(port, &pki.ours(&ours)).and_then(|mut tls| {
            tls.get_ref()
                .set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut octet = [0u8; 1];
            tls.read(&mut octet)
        });
        let error = refused.expect_err("c104 accepted a certificate from a CA it does not trust");
        println!("TLS {version}, our side: {error}");
        let tls = tls_error(&error).unwrap_or_else(|| panic!("not a TLS error: {error}"));
        if version == "1.2" {
            assert_eq!(
                *tls,
                rustls::Error::AlertReceived(rustls::AlertDescription::UnknownCA)
            );
        }
        assert_silent(&mut peer);
    }
}

/// c104's outstation presents a certificate from a CA we do not trust: our
/// master refuses it, and not one APDU crosses.
#[test]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
fn our_master_refuses_a_c104_outstation_from_an_untrusted_ca() {
    let pki = Pki::new("c104-untrusted-outstation", Keys::P256);
    let ours = pki.leaf(&pki.ca, "master", 1);
    pki.leaf(&pki.rogue, "outstation", 2);
    let mut peer = c104_outstation(&pki, 24405, "ca.crt", &[]);
    let error = dial(24405, &pki.ours(&ours)).expect_err("accepted an untrusted server");
    assert_eq!(
        tls_error(&error),
        Some(&rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
    );
    assert_silent(&mut peer);
}

/// c104's allow-list (`only_known`): with another certificate allowed, our
/// valid certificate is refused; with ours allowed, the interrogation runs.
#[test]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
fn c104s_allow_list_admits_only_the_certificate_it_names() {
    let pki = Pki::new("c104-allow-list", Keys::P256);
    let ours = pki.leaf(&pki.ca, "master", 1);
    pki.leaf(&pki.ca, "other", 3);
    pki.leaf(&pki.ca, "outstation", 2);

    let mut peer = c104_outstation(&pki, 24407, "ca.crt", &["--allow", &pki.path("other.crt")]);
    let refused = dial(24407, &pki.ours(&ours)).and_then(|mut tls| {
        tls.get_ref()
            .set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut octet = [0u8; 1];
        tls.read(&mut octet)
    });
    let error = refused.expect_err("c104 accepted a certificate not on its allow-list");
    println!("not allowed: {error}");
    assert!(tls_error(&error).is_some(), "not a TLS error: {error}");
    assert_silent(&mut peer);
    drop(peer);

    let _peer = c104_outstation(&pki, 24408, "ca.crt", &["--allow", &pki.path("master.crt")]);
    let tls = dial(24408, &pki.ours(&ours)).unwrap();
    assert_interrogated(&blocking_master(tls, Duration::from_secs(3)).asdus);
}

/// Our TLS 1.3 `KeyUpdate` (RFC 8446 4.6.3) against c104: its mbedTLS 3.6
/// does not implement `KeyUpdate`, and c104 closes the connection at the
/// first one. Without key updates the same run keeps the session.
#[test]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
fn c104_closes_the_session_at_a_tls_1_3_key_update() {
    for (port, interval, survives) in [
        (24411, None, true),
        (24412, Some(Duration::from_secs(1)), false),
    ] {
        let pki = Pki::new(&format!("c104-key-update-{port}"), Keys::P256);
        let ours = pki.leaf(&pki.ca, "master", 1);
        pki.leaf(&pki.ca, "outstation", 2);
        let _peer = c104_outstation(&pki, port, "ca.crt", &[]);
        let config = TlsConfig::builder(ours.identity(), vec![pki.ca.cert.clone()])
            .key_update_interval(interval)
            .build()
            .unwrap();
        let tls = dial(port, &config).unwrap();
        assert_eq!(tls.protocol_version(), Some(ProtocolVersion::TLSv1_3));
        // c104's keep-alive is 2 s, so test frames go both ways; with the
        // interval, a KeyUpdate precedes our first write after a second.
        let run = blocking_master(tls, Duration::from_secs(6));
        assert!(!run.asdus.is_empty(), "the interrogation started");
        assert_eq!(!run.closed, survives, "key update interval {interval:?}");
    }
}
