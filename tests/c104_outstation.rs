//! The core's controlled station over blocking TCP against `c104`'s master
//! (iec104-python, Fraunhofer FIT, GPLv3), run as an **external process**:
//! `tests/interop/client.py`, which sends one of each request c104's client
//! offers. Nothing of c104 is linked or copied.
//!
//! Ignored by default; it needs a Python with c104 (`scripts/interop-setup.sh`
//! makes one in `.venv`, or point `IEC104_INTEROP_PYTHON` at one):
//!
//! ```text
//! cargo test --test c104_outstation -- --ignored --nocapture
//! ```

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

mod station;

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

/// The Python that runs `client.py`: the project venv, or
/// `IEC104_INTEROP_PYTHON`.
fn interpreter() -> PathBuf {
    std::env::var("IEC104_INTEROP_PYTHON").map_or_else(
        |_| Path::new(env!("CARGO_MANIFEST_DIR")).join(".venv/bin/python"),
        PathBuf::from,
    )
}

/// Every request c104's master offers, answered by the core's controlled
/// station. c104 reports each one accepted: STARTDT (clause 5.3), station
/// interrogation (101 cl.7.4.5), counter interrogation (cl.7.4.8), read
/// (cl.7.4.14), a direct single command (cl.7.4.7), the test command
/// (cl.7.4.10) and clock synchronisation (cl.7.4.6). The value it reads is the
/// station's (-77, set in `tests/station/mod.rs`).
#[test]
#[ignore = "needs a Python with c104 (see this file's module doc)"]
fn the_blocking_outstation_serves_a_c104_master() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let python = interpreter();
    let mut peer = Command::new(&python)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/client.py"))
        .args(["--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", python.display()));
    let stdout = peer.stdout.take().unwrap();
    let lines = std::thread::spawn(move || {
        BufReader::new(stdout)
            .lines()
            .map_while(Result::ok)
            .collect::<Vec<String>>()
    });

    station::serve(
        &listener,
        &mut peer,
        iec104::ct::CommandMode::Direct,
        Duration::from_secs(30),
    );
    let status = peer.wait().unwrap();
    let log = lines.join().unwrap();
    let results: Vec<&String> = log
        .iter()
        .filter(|l| l.starts_with("RESULT") || l.starts_with("VALUE") || l.starts_with("VERSION"))
        .collect();
    println!("{results:#?}");
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
