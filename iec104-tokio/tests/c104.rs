//! The async drivers against `c104` (iec104-python, Fraunhofer FIT, GPLv3),
//! run as an **external process**. Nothing of it is linked or copied.
//!
//! - The async master against `tests/interop/peer.py`, c104's outstation. It
//!   has a 2 s keep-alive, so besides the station interrogation and its
//!   spontaneous event this checks that the driver answers the peer's own
//!   TESTFR acts while it runs (clause 5.2).
//! - The async outstation against `tests/interop/client.py`, c104's master,
//!   which sends one of each request its client offers.
//!
//! The tests run on Tokio's multi-threaded runtime, as an application would,
//! so the drivers' tasks run in parallel against a real peer. Most other
//! async tests run on one thread, which their paused clock needs.
//!
//! Ignored by default; it needs a Python with c104 (see the root
//! `tests/interop.rs`):
//!
//! ```text
//! python3 -m venv .venv && .venv/bin/pip install c104==2.2.1
//! cargo test -p iec104-tokio --test c104 -- --ignored --nocapture --test-threads=1
//! ```
//!
//! `scripts/interop.sh` sets the environment up and runs this with the rest.
//!
//! The interpreter is `<repository>/.venv/bin/python`, or `IEC104_INTEROP_PYTHON`.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use iec104::asdu::Known;
use iec104::gi::{Interrogation, Reaction, Scope, SecondActivation};
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104::redundancy::RedundancyGroup;
use iec104_tokio::{Event, Options, TcpConnector, master, outstation};

mod station;

const PORT: u16 = 24301;

/// Clause 5, figure 8: TESTFR act and con.
const TESTFR_ACT: [u8; 6] = [0x68, 0x04, 0x43, 0x00, 0x00, 0x00];
const TESTFR_CON: [u8; 6] = [0x68, 0x04, 0x83, 0x00, 0x00, 0x00];

struct Peer(Child);

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the workspace root")
}

fn interpreter() -> PathBuf {
    std::env::var("IEC104_INTEROP_PYTHON")
        .map_or_else(|_| root().join(".venv/bin/python"), PathBuf::from)
}

/// Starts the peer and waits for its `READY` line.
fn spawn() -> Peer {
    let python = interpreter();
    let mut child = Command::new(&python)
        .arg(root().join("tests/interop/peer.py"))
        .args(["--port", &PORT.to_string(), "--timeout", "60"])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", python.display()));
    let stdout = child.stdout.take().unwrap();
    let (lines, ready) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if line.starts_with("VERSION") {
                println!("{line}");
            }
            let _ = lines.send(line);
        }
    });
    loop {
        match ready.recv_timeout(Duration::from_secs(30)) {
            Ok(line) if line == "READY" => return Peer(child),
            Ok(_) => {}
            Err(e) => panic!("the peer never printed READY: {e}"),
        }
    }
}

/// Clause 7.1/5.3 (connect, STARTDT), 101 cl.7.4.5 (the station
/// interrogation: ACTCON, the measured value `4242` at IOA 0x1001, ACTTERM),
/// cl.7.4.4 (the peer's spontaneous `M_SP_NA_1`), and clause 5.2 (every TESTFR
/// act of the peer confirmed), against c104.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
async fn the_async_master_against_c104() {
    let _peer = spawn();
    let params = LinkParams {
        t0: Duration::from_secs(1),
        ..LinkParams::default()
    };
    let manager =
        ConnectionManager::new(Role::Controlling, vec![StationConfig::new(params)]).unwrap();
    let connector = TcpConnector::new(vec![format!("127.0.0.1:{PORT}")]);
    let options = Options {
        trace: true,
        ..Options::default()
    };
    let (handle, mut events) = master::spawn(manager, connector, options).unwrap();

    let mut gi = Interrogation::controlling(SecondActivation::Locked, 1, 0);
    let mut reactions = Vec::new();
    let mut spontaneous = false;
    let mut measured = false;
    let (mut tests_received, mut tests_confirmed) = (0, 0);
    let run = tokio::time::sleep(Duration::from_secs(7));
    tokio::pin!(run);
    loop {
        let event = tokio::select! {
            event = events.recv() => event.expect("the driver runs"),
            () = &mut run => break,
        };
        match event {
            Event::State {
                state: State::Started,
                ..
            } => handle
                .send_asdu(0, gi.request(Scope::Station).unwrap())
                .await
                .unwrap(),
            // Cause 3: the peer's spontaneous M_SP_NA_1, IOA 0x1002, SPI on.
            Event::Asdu { asdu, .. } if asdu[2] & 0x3F == 3 => {
                assert_eq!(asdu[0], 0x01, "spontaneous: {asdu:02X?}");
                assert_eq!(asdu[6..10], [0x02, 0x10, 0x00, 0x01]);
                spontaneous = true;
            }
            Event::Asdu { asdu, .. } => {
                let reaction = gi.on_response(&asdu, &Known::EVERYTHING).unwrap().reaction;
                if asdu[0] == 0x0B {
                    // M_ME_NB_1, cause 20, IOA 0x1001, value 4242.
                    assert_eq!(asdu[2] & 0x3F, 20);
                    assert_eq!(asdu[6..11], [0x01, 0x10, 0x00, 0x92, 0x10]);
                    measured = true;
                }
                reactions.push(reaction);
            }
            Event::Received { frame, .. } if frame == TESTFR_ACT => tests_received += 1,
            Event::Sent { frame, .. } if frame == TESTFR_CON => tests_confirmed += 1,
            Event::Disconnected { reason, .. } => panic!("the connection closed: {reason}"),
            _ => {}
        }
    }
    handle.shutdown().await;

    // ACTCON first, ACTTERM last, the peer's two points in between.
    assert_eq!(
        reactions.first(),
        Some(&Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: false
        })
    );
    assert!(matches!(
        reactions.last(),
        Some(Reaction::Terminated { .. })
    ));
    assert!(
        reactions[1..reactions.len() - 1]
            .iter()
            .all(|r| matches!(r, Reaction::Interrogated { .. }))
    );
    assert!(measured, "the measured value 4242 was interrogated");
    assert!(spontaneous, "cl.7.4: the spontaneous event arrived");
    assert!(tests_received >= 2, "the peer tested the idle link");
    assert_eq!(
        tests_confirmed, tests_received,
        "every TESTFR act confirmed"
    );
    println!("{tests_received} TESTFR acts from the peer, all confirmed");
}

/// Starts c104's master against our outstation on `port`; its stdout lines
/// arrive on the returned channel.
fn spawn_client(port: u16) -> (Peer, mpsc::Receiver<String>) {
    let python = interpreter();
    let mut child = Command::new(&python)
        .arg(root().join("tests/interop/client.py"))
        .args(["--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", python.display()));
    let stdout = child.stdout.take().unwrap();
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = lines.send(line);
        }
    });
    (Peer(child), received)
}

/// Every request c104's master offers, answered by the async outstation
/// behind `dispatch::route`. c104 reports each one accepted: STARTDT (clause
/// 5.3), interrogation (101 cl.7.4.5), counter interrogation (cl.7.4.8), read
/// (cl.7.4.14), a direct single command (cl.7.4.7), the test command
/// (cl.7.4.10) and clock synchronisation (cl.7.4.6). The read value is the
/// station's.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
async fn the_async_outstation_against_c104() {
    const OUTSTATION_PORT: u16 = 24302;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", OUTSTATION_PORT))
        .await
        .unwrap();
    let group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 1).unwrap();
    let (handle, mut events) = outstation::spawn(group, Options::default()).unwrap();
    tokio::spawn(outstation::serve(listener, handle.clone()));
    let (mut peer, lines) = spawn_client(OUTSTATION_PORT);
    let mut station = station::Station::new(iec104::ct::CommandMode::Direct);

    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    while tokio::time::Instant::now() < until {
        let event = tokio::select! {
            event = events.recv() => event.expect("the driver runs"),
            _ = poll.tick() => {
                if peer.0.try_wait().unwrap().is_some() {
                    break;
                }
                continue;
            }
        };
        if let Event::Asdu { asdu, .. } = event {
            for answer in station.answer(&asdu) {
                handle.send_asdu(0, answer).await.unwrap();
            }
        }
    }
    let status = peer.0.wait().unwrap();
    handle.shutdown().await;

    let log: Vec<String> = lines.try_iter().collect();
    let results: Vec<&str> = log
        .iter()
        .filter(|l| l.starts_with("RESULT") || l.starts_with("VALUE") || l.starts_with("VERSION"))
        .map(String::as_str)
        .collect();
    println!("{}", results.join("\n"));
    assert!(status.success(), "the c104 master failed: {status}");
    for request in [
        "startdt",
        "interrogation",
        "counter_interrogation",
        "read",
        "single_command",
        "test",
        "clock_sync",
    ] {
        let line = format!("RESULT {request} True");
        assert!(log.contains(&line), "missing `{line}`: {results:?}");
    }
    assert!(
        log.iter()
            .any(|l| l.starts_with("VALUE read") && l.contains("-77")),
        "the read answer: {results:?}"
    );
    assert!(log.contains(&"DONE".to_string()));
}
