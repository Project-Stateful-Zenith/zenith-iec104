//! 104 over TLS against lib60870-C (GPLv3) built with mbedTLS 3.6, run as
//! an **external process**: `tests/lib60870/tls_peer.c`, built by
//! `scripts/interop-setup.sh` into `target/interop/bin/tls_peer` (or
//! `IEC104_LIB60870_TLS_PEER`). Nothing of lib60870 is linked into the crate.
//!
//! Both directions: our blocking master against lib60870's outstation, and
//! lib60870's master against our async outstation. Then the refusals from
//! both ends (untrusted CAs, a revoked certificate), and what lib60870 does
//! that this crate cannot follow: its TLS 1.2 session renegotiation, and a
//! TLS 1.3 `KeyUpdate` from us. Certificates are made at test time: RSA 2048
//! (lib60870 refuses keys under 2048 bits by default, EC keys included),
//! except where P-256 is the point.
//!
//! ```text
//! scripts/interop-setup.sh
//! cargo test -p iec104-tls --test lib60870 -- --ignored --nocapture --test-threads=1
//! ```

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

mod interop;

use std::io::{self, Read};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use iec104::link::Role;
use iec104::params::LinkParams;
use iec104::redundancy::RedundancyGroup;
use iec104_tls::rustls::{self, CertificateError, PeerMisbehaved};
use iec104_tls::tokio::serve;
use iec104_tls::{ProtocolVersion, TlsConfig, TlsStream, tls_error};
use iec104_tokio::{Event, Options, outstation};
use interop::{INTERROGATION, Keys, Peer, Pki, blocking_master, dial, root};

#[path = "../../iec104-tokio/tests/station/mod.rs"]
mod station;

/// The peer's interrogated point: IOA 0x0102, value 1234 (0x04D2), QDS 0.
const PEER_POINT: [u8; 6] = [0x02, 0x01, 0x00, 0xD2, 0x04, 0x00];

/// lib60870's security event codes (`tls_config.h`).
const EVENT_CERT_VALIDATION_FAILED: &str = " 6 ";
const EVENT_CERT_REVOKED: &str = " 12 ";
const EVENT_INSUFFICIENT_KEY_LENGTH: &str = " 23 ";

fn program() -> PathBuf {
    std::env::var("IEC104_LIB60870_TLS_PEER").map_or_else(
        |_| root().join("target/interop/bin/tls_peer"),
        PathBuf::from,
    )
}

/// `tls_peer <mode> <port> <seconds> <name>.crt <name>.key <ca> <options>`.
fn tls_peer(pki: &Pki, mode: &str, port: u16, name: &str, ca: &str, options: &[&str]) -> Peer {
    let mut args = vec![
        mode.to_string(),
        port.to_string(),
        "15".into(),
        pki.path(&format!("{name}.crt")),
        pki.path(&format!("{name}.key")),
        pki.path(ca),
    ];
    args.extend(options.iter().map(std::string::ToString::to_string));
    let mut peer = Peer::spawn(&program(), &args);
    if mode == "server" {
        assert!(
            peer.wait_for(Duration::from_secs(10), |l| l == "peer: listening"),
            "lib60870 never listened: {:?}",
            peer.log
        );
    }
    peer
}

/// ACTCON, the point, ACTTERM: 101 cl.7.4.5's interrogation as lib60870
/// answers it.
fn assert_interrogated(asdus: &[Vec<u8>]) {
    let causes: Vec<(u8, u8)> = asdus.iter().map(|a| (a[0], a[2] & 0x3F)).collect();
    assert_eq!(
        causes,
        [(0x64, 7), (0x0B, 20), (0x64, 10)],
        "C_IC_NA_1 actcon, M_ME_NB_1 inrogen, C_IC_NA_1 actterm: {asdus:02X?}"
    );
    assert!(asdus[1].ends_with(&PEER_POINT), "{:02X?}", asdus[1]);
}

/// The first read on `tls` within five seconds: where a refusal that came
/// after our side of a TLS 1.3 handshake arrives.
fn first_read(tls: io::Result<TlsStream>) -> io::Result<usize> {
    tls.and_then(|mut tls| {
        tls.get_ref()
            .set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut octet = [0u8; 1];
        tls.read(&mut octet)
    })
}

#[test]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
fn our_blocking_master_against_a_lib60870_outstation_over_tls() {
    for (port, version, negotiated) in [
        (24501, "version=13", ProtocolVersion::TLSv1_3),
        (24502, "version=12", ProtocolVersion::TLSv1_2),
    ] {
        let pki = Pki::new(&format!("lib60870-master-{port}"), Keys::Rsa2048);
        let ours = pki.leaf(&pki.ca, "master", 1);
        pki.leaf(&pki.ca, "outstation", 2);
        let mut peer = tls_peer(&pki, "server", port, "outstation", "ca.crt", &[version]);
        let tls = dial(port, &pki.ours(&ours)).unwrap();
        assert_eq!(tls.protocol_version(), Some(negotiated));
        println!("{:?} {:?}", tls.protocol_version(), tls.cipher_suite());
        let run = blocking_master(tls, Duration::from_secs(3));
        assert_interrogated(&run.asdus);
        assert!(!run.closed);
        assert!(peer.wait_for(Duration::from_secs(1), |l| l
            == "peer: connection activated"));
    }
}

/// lib60870's master against our async outstation, served by
/// `iec104_tls::tokio::serve`: its interrogation reaches us octet for octet,
/// and our answer reaches it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
async fn a_lib60870_master_against_our_async_outstation_over_tls() {
    const PORT: u16 = 24503;
    let pki = Pki::new("lib60870-outstation", Keys::Rsa2048);
    pki.leaf(&pki.ca, "master", 1);
    let ours = pki.leaf(&pki.ca, "outstation", 2);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", PORT))
        .await
        .unwrap();
    let group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 1).unwrap();
    let (handle, mut events) = outstation::spawn(group, Options::default()).unwrap();
    tokio::spawn(serve(
        listener,
        pki.ours(&ours),
        handle.clone(),
        |peer, e| panic!("{peer} refused: {e}"),
    ));
    let mut peer = tls_peer(&pki, "client", PORT, "master", "ca.crt", &[]);
    let mut station = station::Station::new(iec104::ct::CommandMode::Direct);
    let mut requests = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        let Ok(Some(event)) = tokio::time::timeout_at(deadline, events.recv()).await else {
            break;
        };
        if let Event::Asdu { asdu, .. } = event {
            for answer in station.answer(&asdu) {
                handle.send_asdu(0, answer).await.unwrap();
            }
            requests.push(asdu);
        }
    }
    handle.shutdown().await;
    assert_eq!(requests.first(), Some(&INTERROGATION.to_vec()));
    let log = tokio::task::block_in_place(|| {
        peer.wait_for(Duration::from_secs(1), |_| false);
        peer.drain().to_vec()
    });
    // The station's GI answer (M_ME_NB_1 1234 at 0x0102), then ACTTERM.
    for line in [
        "got type=11 cot=20 ioa=258 value=1234",
        "got type=100 cot=10",
    ] {
        assert!(log.iter().any(|l| l == line), "missing `{line}`: {log:?}");
    }
}

/// lib60870 refuses keys under 2048 bits, P-256 included, unless told
/// otherwise: its event 23 (insufficient key length). Told `minkey=256`, it
/// takes the same certificates.
#[test]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
fn lib60870_refuses_a_p256_certificate_by_its_default_minimum_key_length() {
    for (port, options, accepted) in [(24504, &[][..], false), (24505, &["minkey=256"][..], true)] {
        let pki = Pki::new(&format!("lib60870-p256-{port}"), Keys::P256);
        let ours = pki.leaf(&pki.ca, "master", 1);
        pki.leaf(&pki.ca, "outstation", 2);
        let mut peer = tls_peer(&pki, "server", port, "outstation", "ca.crt", options);
        let read = first_read(dial(port, &pki.ours(&ours)));
        // Either way the read fails: nothing to read on an idle session, or the refusal.
        let error = read.unwrap_err();
        if accepted {
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "{error}"
            );
        } else {
            assert!(tls_error(&error).is_some(), "not a TLS error: {error}");
            assert!(
                peer.wait_for(Duration::from_secs(2), |l| l.starts_with("event:")
                    && l.contains(EVENT_INSUFFICIENT_KEY_LENGTH)),
                "{:?}",
                peer.log
            );
        }
    }
}

/// lib60870's outstation trusts only another CA: it refuses our certificate
/// (its event 6, validation failed) and we see a TLS failure.
#[test]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
fn a_lib60870_outstation_that_does_not_trust_our_ca_refuses_our_master() {
    for (port, version) in [(24506, "version=13"), (24507, "version=12")] {
        let pki = Pki::new(&format!("lib60870-untrusted-master-{port}"), Keys::Rsa2048);
        let ours = pki.leaf(&pki.ca, "master", 1);
        pki.leaf(&pki.ca, "outstation", 2);
        let mut peer = tls_peer(&pki, "server", port, "outstation", "rogue.crt", &[version]);
        let error = first_read(dial(port, &pki.ours(&ours))).unwrap_err();
        println!("{version}, our side: {error}");
        let tls = tls_error(&error).unwrap_or_else(|| panic!("not a TLS error: {error}"));
        if version == "version=12" {
            assert!(matches!(tls, rustls::Error::AlertReceived(_)), "{tls}");
        }
        assert!(
            peer.wait_for(Duration::from_secs(2), |l| l.starts_with("event:")
                && l.contains(EVENT_CERT_VALIDATION_FAILED)),
            "{:?}",
            peer.log
        );
        assert!(!peer.drain().iter().any(|l| l.contains("activated")));
    }
}

#[test]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
fn our_master_refuses_a_lib60870_outstation_from_an_untrusted_ca() {
    const PORT: u16 = 24508;
    let pki = Pki::new("lib60870-untrusted-outstation", Keys::Rsa2048);
    let ours = pki.leaf(&pki.ca, "master", 1);
    pki.leaf(&pki.rogue, "outstation", 2);
    let mut peer = tls_peer(&pki, "server", PORT, "outstation", "ca.crt", &[]);
    let error = dial(PORT, &pki.ours(&ours)).expect_err("accepted an untrusted server");
    assert_eq!(
        tls_error(&error),
        Some(&rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!peer.drain().iter().any(|l| l.contains("activated")));
}

/// lib60870's master presents a certificate from a CA we do not trust: our
/// outstation refuses it, reported through `serve`'s callback, and lib60870
/// never connects.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
async fn our_outstation_refuses_a_lib60870_master_from_an_untrusted_ca() {
    const PORT: u16 = 24509;
    let pki = Pki::new("lib60870-untrusted-client", Keys::Rsa2048);
    pki.leaf(&pki.rogue, "master", 1);
    let ours = pki.leaf(&pki.ca, "outstation", 2);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", PORT))
        .await
        .unwrap();
    let group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 1).unwrap();
    let (handle, mut events) = outstation::spawn(group, Options::default()).unwrap();
    let (refusals, mut refused) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(serve(
        listener,
        pki.ours(&ours),
        handle.clone(),
        move |_, e| {
            let _ = refusals.send(tls_error(&e).cloned());
        },
    ));
    let mut peer = tls_peer(&pki, "client", PORT, "master", "ca.crt", &[]);
    let error = tokio::time::timeout(Duration::from_secs(10), refused.recv())
        .await
        .expect("no refusal reported")
        .unwrap();
    assert_eq!(
        error,
        Some(rustls::Error::InvalidCertificate(
            CertificateError::UnknownIssuer
        ))
    );
    let connected = tokio::time::timeout(Duration::from_millis(300), async {
        while let Some(event) = events.recv().await {
            if matches!(event, Event::Connected { .. }) {
                return;
            }
        }
    })
    .await;
    assert!(connected.is_err(), "a refused client was attached");
    let log = tokio::task::block_in_place(|| {
        peer.wait_for(Duration::from_secs(1), |_| false);
        peer.drain().to_vec()
    });
    assert!(!log.iter().any(|l| l.starts_with("got")), "{log:?}");
    handle.shutdown().await;
}

/// lib60870 checks our certificate against its CRL (PEM, made by rcgen):
/// revoked, it is refused with lib60870's event 12.
#[test]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
fn a_lib60870_outstation_refuses_our_revoked_certificate() {
    const PORT: u16 = 24510;
    let pki = Pki::new("lib60870-revoked", Keys::Rsa2048);
    let ours = pki.leaf(&pki.ca, "master", 1);
    pki.leaf(&pki.ca, "outstation", 2);
    std::fs::write(pki.path("ca.crl"), pki.ca.crl_pem(&[1])).unwrap();
    let crl = format!("crl={}", pki.path("ca.crl"));
    let mut peer = tls_peer(&pki, "server", PORT, "outstation", "ca.crt", &[&crl]);
    let error = first_read(dial(PORT, &pki.ours(&ours))).unwrap_err();
    assert!(tls_error(&error).is_some(), "not a TLS error: {error}");
    assert!(
        peer.wait_for(Duration::from_secs(2), |l| l.starts_with("event:")
            && l.contains(EVENT_CERT_REVOKED)),
        "{:?}",
        peer.log
    );
}

/// lib60870 renegotiates a TLS 1.2 session after its interval (here 2 s).
/// rustls does not renegotiate: it declines the first request with a
/// `no_renegotiation` warning and ends the session at the second. Under
/// TLS 1.3 lib60870 does not renegotiate, and the session stays.
#[test]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
fn lib60870s_tls_1_2_renegotiation_ends_the_session() {
    for (port, version) in [(24511, "version=12"), (24512, "version=13")] {
        let pki = Pki::new(&format!("lib60870-renegotiation-{port}"), Keys::Rsa2048);
        let ours = pki.leaf(&pki.ca, "master", 1);
        pki.leaf(&pki.ca, "outstation", 2);
        let mut peer = tls_peer(
            &pki,
            "server",
            port,
            "outstation",
            "ca.crt",
            &[version, "renegotiate=2000"],
        );
        let mut tls = dial(port, &pki.ours(&ours)).unwrap();
        tls.get_ref()
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut ended = None;
        let mut octet = [0u8; 1];
        while Instant::now() < deadline && ended.is_none() {
            match tls.read(&mut octet) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                other => ended = Some(other),
            }
        }
        if version == "version=12" {
            let error = ended
                .expect("the session outlived renegotiation")
                .unwrap_err();
            println!("TLS 1.2: {error}");
            assert_eq!(
                tls_error(&error),
                Some(&rustls::Error::PeerMisbehaved(
                    PeerMisbehaved::TooManyRenegotiationRequests
                ))
            );
            assert!(peer.wait_for(Duration::from_secs(1), |l| l.contains("renegotiation")));
        } else {
            assert!(ended.is_none(), "TLS 1.3 session ended: {ended:?}");
        }
    }
}

/// Our TLS 1.3 `KeyUpdate` (RFC 8446 4.6.3) against lib60870: mbedTLS 3.6
/// does not implement `KeyUpdate`, and the session ends at the first one.
#[test]
#[ignore = "needs the lib60870 TLS peer (scripts/interop-setup.sh)"]
fn lib60870_ends_the_session_at_a_tls_1_3_key_update() {
    for (port, interval, survives) in [
        (24513, None, true),
        (24514, Some(Duration::from_secs(1)), false),
    ] {
        let pki = Pki::new(&format!("lib60870-key-update-{port}"), Keys::Rsa2048);
        let ours = pki.leaf(&pki.ca, "master", 1);
        pki.leaf(&pki.ca, "outstation", 2);
        let _peer = tls_peer(
            &pki,
            "server",
            port,
            "outstation",
            "ca.crt",
            &["version=13"],
        );
        let config = TlsConfig::builder(ours.identity(), vec![pki.ca.cert.clone()])
            .key_update_interval(interval)
            .build()
            .unwrap();
        let mut tls = dial(port, &config).unwrap();
        // A write every 0.6 s or so: with the 1 s interval, a KeyUpdate goes
        // ahead of the third.
        let mut ended = None;
        tls.get_ref()
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        for _ in 0..4 {
            // TESTFR act (clause 5, figure 8); lib60870 confirms it.
            let written = io::Write::write_all(&mut tls, &[0x68, 0x04, 0x43, 0x00, 0x00, 0x00]);
            let mut con = [0u8; 6];
            let read = written.and_then(|()| tls.read_exact(&mut con));
            if let Err(e) = read {
                ended = Some(e);
                break;
            }
            assert_eq!(con, [0x68, 0x04, 0x83, 0x00, 0x00, 0x00], "TESTFR con");
            std::thread::sleep(Duration::from_millis(600));
        }
        println!("key update {interval:?}: {ended:?}");
        assert_eq!(
            ended.is_none(),
            survives,
            "key update interval {interval:?}"
        );
    }
}
