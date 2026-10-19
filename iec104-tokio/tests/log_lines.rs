//! The `log` feature: the lines a STARTDT exchange writes through the `log`
//! crate, compared with the lines `docs/RUNBOOK.md` documents.
//!
//! The frames are clause 5's figure 8 U-format APDUs written out by hand
//! (`tests/common`). The expected lines are the runbook's: `diag::apdu`'s
//! text for those frames is figure 8's own names (`U STARTDT act`,
//! `U STARTDT con`), and the state names are figure 18's.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

mod common;

use std::sync::Mutex;

use common::*;
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104_tokio::{Event, Options, master};

/// The runbook, read at build time so that a line it no longer quotes fails
/// here.
const RUNBOOK: &str = include_str!("../../docs/RUNBOOK.md");

/// Every record of the driver's target, as `LEVEL message`.
static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.target() == "iec104_tokio"
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            let line = format!("{:<5} {}", record.level(), record.args());
            LINES.lock().unwrap().push(line);
        }
    }

    fn flush(&self) {}
}

/// Clause 5.3 / figure 18: the controlling station dials, sends STARTDT act,
/// and the peer's STARTDT con starts data transfer. One line per APDU and one
/// per connection state change, in the order they happened.
#[tokio::test(start_paused = true)]
async fn a_startdt_exchange_logs_the_lines_the_runbook_documents() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    let station = StationConfig::new(LinkParams::default());
    let manager = ConnectionManager::new(Role::Controlling, vec![station]).unwrap();
    let (connector, mut dials) = Dials::new();
    let (_handle, mut events) = master::spawn(manager, connector, Options::default()).unwrap();
    let mut peer = next_dial(&mut dials).await.accept();
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
    peer.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 0,
            state: State::Started,
        }
    })
    .await;

    let lines = LINES.lock().unwrap().clone();
    let expected = [
        "DEBUG conn=0 connecting",
        "INFO  conn=0 connected",
        "DEBUG conn=0 sent: U STARTDT act",
        "INFO  conn=0 state: PendingStarted",
        "DEBUG conn=0 received: U STARTDT con",
        "INFO  conn=0 state: Started",
    ];
    assert_eq!(lines, expected);
    let block = expected.join("\n");
    assert!(
        RUNBOOK.contains(&block),
        "docs/RUNBOOK.md no longer quotes the lines:\n{block}"
    );
}
