//! The interoperability scenario against a real peer, `c104`.
//!
//! `c104` (iec104-python, Fraunhofer FIT, GPLv3) is run as an **external
//! process** and nothing else: never linked, never vendored, never copied from.
//! `tests/interop/peer.py` drives its public API; the octets that cross the
//! socket are wire traffic. The scenario step list and every clause citation
//! behind it live in `tests/interop/mod.rs` and are shared with the offline
//! entry point `tests/interop_mock.rs`: one step list, two peers.
//!
//! # Running it
//!
//! ```text
//! python3 -m venv .venv && .venv/bin/pip install c104==2.2.1
//! cargo test --test interop -- --ignored --nocapture
//! ```
//!
//! The interpreter is found at `<project>/.venv/bin/python`, or wherever
//! `IEC104_INTEROP_PYTHON` points. The test is `#[ignore]`d because it needs
//! that venv; when it is asked to run and the interpreter or the module is
//! missing it **fails loudly** with the reason: it never passes silently and
//! never skips quietly. Its output prints the c104 version it used.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::string_slice
)]

#[path = "interop/mod.rs"]
mod interop;

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// How long the peer gets to bind its port or finish the scenario. Every wait
/// is bounded, so a stuck peer fails the test instead of hanging it.
const PEER_DEADLINE: Duration = Duration::from_secs(60);

/// The interpreter that runs `peer.py`: the project venv by default, an
/// environment override for a box that keeps it elsewhere.
fn interpreter() -> PathBuf {
    std::env::var("IEC104_INTEROP_PYTHON").map_or_else(
        |_| Path::new(env!("CARGO_MANIFEST_DIR")).join(".venv/bin/python"),
        PathBuf::from,
    )
}

/// A loopback port nothing is listening on. The listener is dropped before the
/// peer binds, so the two cannot collide in practice; the window is a few
/// microseconds and a lost race shows up as the peer failing to start.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    listener.local_addr().expect("the bound address").port()
}

/// cl.7.1 (index 54), cl.5.3 (index 38), cl.7.5 (index 64), cl.7.4 (index 64),
/// cl.7.7 (index 68), cl.5.2 (index 34) and cl.7.1's active-close row
/// (index 56): the whole scripted scenario, against `c104`.
#[test]
#[ignore = "needs the project .venv with c104 (see this file's module doc)"]
fn the_scenario_passes_against_the_c104_peer() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let python = interpreter();
    assert!(
        python.exists(),
        "the interop peer needs a Python with c104: {} does not exist.\n\
         Create it with `python3 -m venv .venv && .venv/bin/pip install c104==2.2.1`, \
         or point IEC104_INTEROP_PYTHON at one that has it.",
        python.display()
    );

    // Fail loudly when the installed c104 cannot be imported, rather than
    // trusting the wheel's stub file to match it.
    let probe = Command::new(&python)
        .arg("-c")
        .arg("import c104, importlib.metadata; print(importlib.metadata.version('c104'))")
        .output()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", python.display()));
    assert!(
        probe.status.success(),
        "{} cannot `import c104`: {}",
        python.display(),
        String::from_utf8_lossy(&probe.stderr).trim()
    );
    let version = String::from_utf8_lossy(&probe.stdout).trim().to_string();
    println!("interop: c104 {version} via {}", python.display());

    let port = free_port();
    let log = Arc::new(Mutex::new(interop::PeerLog::default()));
    let mut child = Command::new(&python)
        .arg(manifest.join("tests/interop/peer.py"))
        .arg("--port")
        .arg(port.to_string())
        .current_dir(manifest)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot start peer.py: {e}"));

    let stdout = child.stdout.take().expect("piped stdout");
    let sink = Arc::clone(&log);
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => sink.lock().expect("the peer log").absorb(&line),
                Err(_) => break,
            }
        }
    });

    wait_for(&log, &mut child, "READY", |log| log.ready);

    let address = format!("127.0.0.1:{port}")
        .parse()
        .expect("a loopback socket address");
    let station = interop::Station::connect(address)
        .unwrap_or_else(|why| panic!("the controlling station connects: {why}"));
    let station = match interop::run(station, &interop::scenario()) {
        Ok(station) => station,
        Err(why) => panic!("the scenario failed against c104: {why}"),
    };

    // The peer reports the connection's state change and leaves (cl.7.1's
    // active-close row read from the other side).
    wait_for(&log, &mut child, "DONE", |log| log.done);
    wait_for_exit(&mut child);
    let _ = reader.join();

    let log = std::mem::take(&mut *log.lock().expect("the peer log"));
    println!(
        "interop: {version} — {} frames received, {} sent",
        log.rx.len(),
        log.tx.len()
    );
    for note in &log.notes {
        println!("interop note: {note}");
    }
    assert!(
        log.version.contains("c104") && log.version.contains(&version),
        "the peer printed the version it used: {:?}",
        log.version
    );
    assert!(log.closed, "cl.7.1: the peer reports the connection closed");
    // Step 1 of the scenario: the peer's `on_connect` accepted the client
    // (cl.7.1, index 54: the controlling station performs the connection
    // establishment, and the peer reports it from its own side).
    assert!(
        log.notes.iter().any(|note| note == "CONNECT 127.0.0.1"),
        "cl.7.1: the peer accepted the connection: {:?}",
        log.notes
    );

    cross_check(&log, &station);
}

/// The peer's captures against this side's own record of the run, and the wire
/// log printed.
fn cross_check(log: &interop::PeerLog, station: &interop::Station) {
    // ---------------------------------------------------- the cross-check
    // What the peer saw is what this side thinks it sent, re-parsed with **our**
    // codec: the one assertion a symmetric mock bug cannot satisfy by luck.
    let peer_rx = interop::decode_capture(&log.rx)
        .unwrap_or_else(|why| panic!("the peer's receive capture: {why}"));
    assert_eq!(
        peer_rx.len(),
        log.rx.len(),
        "every RX line is one whole APDU"
    );
    // cl.5.3: the first APDU the real peer received is the STARTDT act. No
    // user data crossed the wire before it.
    assert_eq!(
        peer_rx[0],
        interop::encode_action_bytes(&iec104::link::Action::Send(iec104::apci::Apci::U(
            iec104::apci::UFunction::StartDtAct
        )))
        .expect("the STARTDT act encodes"),
        "cl.5.3: STARTDT act is the first frame the peer saw"
    );
    assert_eq!(
        peer_rx, station.sent,
        "the peer received exactly the APDUs this side put on the wire"
    );

    let peer_tx = interop::decode_capture(&log.tx)
        .unwrap_or_else(|why| panic!("the peer's send capture: {why}"));
    assert_eq!(
        peer_tx.len(),
        log.tx.len(),
        "every TX line is one whole APDU"
    );
    assert!(
        peer_tx.len() >= station.received.len(),
        "this side read {} frames the peer never sent",
        station.received.len()
    );
    assert_eq!(
        &peer_tx[..station.received.len()],
        &station.received[..],
        "every APDU this side read is one the peer sent, in order"
    );

    // cl.5.1 (104 index 32, the NOTE under figure 11): the acknowledgement the
    // peer is owed goes out as an S-frame before the socket is closed, and it
    // acknowledges every I-frame the peer sent. The wire log below is the
    // evidence: `interop sent` must hold `68 04 01 00 0e 00` for 7 peer frames.
    let peer_i_frames = peer_tx
        .iter()
        .filter(|frame| {
            matches!(
                interop::parse_frame(frame),
                Ok((iec104::apci::Apci::I { .. }, _))
            )
        })
        .count();
    let s_frames: Vec<u16> = station
        .sent
        .iter()
        .filter_map(|frame| match interop::parse_frame(frame) {
            Ok((iec104::apci::Apci::S { nr }, _)) => Some(nr.get()),
            _ => None,
        })
        .collect();
    assert_eq!(
        s_frames,
        vec![peer_i_frames as u16],
        "cl.5.1: exactly one S-frame, acknowledging all {peer_i_frames} I-frames the peer sent"
    );

    // The wire log, printed so a run's real traffic can be read and quoted.
    for frame in &station.sent {
        println!("interop sent {}", interop::encode_hex(frame));
    }
    for frame in &log.tx {
        println!("interop peer-sent {}", interop::encode_hex(frame));
    }
}

/// Polls the peer's log until `ready`, or fails with the peer's own stderr.
fn wait_for(
    log: &Arc<Mutex<interop::PeerLog>>,
    child: &mut Child,
    what: &str,
    ready: impl Fn(&interop::PeerLog) -> bool,
) {
    let deadline = Instant::now() + PEER_DEADLINE;
    loop {
        if ready(&log.lock().expect("the peer log")) {
            return;
        }
        if let Some(status) = child.try_wait().expect("the peer's status") {
            panic!(
                "the peer exited with {status} before {what}: {}",
                stderr(child)
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("the peer never printed {what} within {PEER_DEADLINE:?}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Waits for the peer to leave on its own, then reaps it.
fn wait_for_exit(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if child.try_wait().expect("the peer's status").is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// The peer's stderr, for a loud failure message.
fn stderr(child: &mut Child) -> String {
    child.stderr.as_mut().map_or_else(
        || "(no stderr)".to_string(),
        |pipe| {
            let mut text = String::new();
            let _ = pipe.read_to_string(&mut text);
            text.trim().to_string()
        },
    )
}
