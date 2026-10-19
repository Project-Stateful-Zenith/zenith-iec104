//! The `tracing` feature: the events a STARTDT exchange emits through the
//! `tracing` crate, compared with the lines `docs/RUNBOOK.md` documents.
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

use std::fmt;
use std::sync::{Arc, Mutex};

use common::*;
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104_tokio::{Event, Options, master};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Metadata, Subscriber};

/// The runbook, read at build time so that a line it no longer quotes fails
/// here.
const RUNBOOK: &str = include_str!("../../docs/RUNBOOK.md");

/// A subscriber that keeps every event of the driver's target as
/// `LEVEL conn=<conn> message`, the shape the runbook prints them in.
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

#[derive(Default)]
struct Fields {
    conn: Option<u64>,
    message: String,
}

impl Visit for Fields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "conn" {
            self.conn = Some(value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

impl Subscriber for Capture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == "iec104_tokio"
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields::default();
        event.record(&mut fields);
        let conn = fields.conn.expect("every event names its connection");
        let line = format!(
            "{:<5} conn={conn} {}",
            event.metadata().level(),
            fields.message
        );
        self.0.lock().unwrap().push(line);
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Clause 5.3 / figure 18: the controlling station dials, sends STARTDT act,
/// and the peer's STARTDT con starts data transfer. One event per APDU and
/// one per connection state change, in the order they happened.
#[tokio::test(start_paused = true)]
async fn a_startdt_exchange_emits_the_lines_the_runbook_documents() {
    let capture = Capture::default();
    let _default = tracing::subscriber::set_default(capture.clone());

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

    let lines = capture.0.lock().unwrap().clone();
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
