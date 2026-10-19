//! The driver's log lines, through the `log` crate (feature `log`) and the
//! `tracing` crate (feature `tracing`). With neither feature every function
//! here is empty.
//!
//! Every line has the target [`TARGET`] and names its connection: `log`
//! records start with `conn=<n> `, `tracing` events carry a `conn` field. The
//! text is the same in both:
//!
//! | Text | Level | When |
//! | --- | --- | --- |
//! | `sent: <line>` | debug | an APDU handed to the connection's writer |
//! | `received: <line>` | debug | an APDU read from the connection |
//! | `connecting` | debug | [`Event::Connecting`] |
//! | `connect failed: <error>` | warn | [`Event::ConnectFailed`] |
//! | `connected` | info | [`Event::Connected`] |
//! | `disconnected: <reason>` | info | [`Event::Disconnected`] |
//! | `state: <state>` | info | [`Event::State`] |
//! | `frame refused: <error>` | warn | [`Event::FrameRefused`] |
//! | `switchover: <switchover>` | warn | [`Event::Switchover`] (the failed connection's) |
//! | `started connection failed, <n> unconfirmed` | warn | [`Event::StartedConnectionFailed`] |
//!
//! `<line>` is [`iec104::diag::apdu`] in the profile of
//! [`Options::sizes`](crate::Options::sizes). A frame it cannot format prints
//! its error and the octets in hex instead.

use iec104::asdu::AddressSizes;

use crate::Event;

/// The target of every line, for a logger's filter.
#[cfg(any(feature = "log", feature = "tracing"))]
pub const TARGET: &str = "iec104_tokio";

/// Which way an APDU went.
#[derive(Clone, Copy)]
pub enum Direction {
    Sent,
    Received,
}

/// One line for an APDU `conn` sent or received.
#[cfg_attr(not(any(feature = "log", feature = "tracing")), allow(unused))]
pub fn apdu(direction: Direction, conn: usize, frame: &[u8], sizes: AddressSizes) {
    #[cfg(any(feature = "log", feature = "tracing"))]
    if enabled(Level::Debug) {
        let line = match iec104::diag::apdu(frame, sizes) {
            Ok(line) => line,
            Err(error) => format!("{error}: {}", hex(frame)),
        };
        let direction = match direction {
            Direction::Sent => "sent",
            Direction::Received => "received",
        };
        emit(Level::Debug, conn, format_args!("{direction}: {line}"));
    }
}

/// One line for a driver event that changes a connection's state. APDUs and
/// delivered ASDUs have their own line ([`apdu`]) and none here.
#[cfg_attr(not(any(feature = "log", feature = "tracing")), allow(unused))]
pub fn event(event: &Event) {
    #[cfg(any(feature = "log", feature = "tracing"))]
    match event {
        Event::Connecting { conn } => emit(Level::Debug, *conn, format_args!("connecting")),
        Event::ConnectFailed { conn, error } => {
            emit(Level::Warn, *conn, format_args!("connect failed: {error}"));
        }
        Event::Connected { conn } => emit(Level::Info, *conn, format_args!("connected")),
        Event::Disconnected { conn, reason } => {
            emit(Level::Info, *conn, format_args!("disconnected: {reason}"));
        }
        Event::State { conn, state } => emit(Level::Info, *conn, format_args!("state: {state:?}")),
        Event::FrameRefused { conn, error } => {
            emit(Level::Warn, *conn, format_args!("frame refused: {error}"));
        }
        Event::Switchover(switchover) => {
            use iec104::redundancy::Switchover;
            let (Switchover::Automatic { failed, .. }
            | Switchover::NoStoppedConnection { failed, .. }
            | Switchover::LeftToTheControllingStation { failed, .. }) = switchover;
            emit(
                Level::Warn,
                *failed,
                format_args!("switchover: {switchover:?}"),
            );
        }
        Event::StartedConnectionFailed { conn, unconfirmed } => emit(
            Level::Warn,
            *conn,
            format_args!("started connection failed, {unconfirmed} unconfirmed"),
        ),
        Event::Asdu { .. }
        | Event::Acknowledged { .. }
        | Event::Sent { .. }
        | Event::Received { .. } => {}
    }
}

#[cfg(any(feature = "log", feature = "tracing"))]
#[derive(Clone, Copy)]
enum Level {
    Debug,
    Info,
    Warn,
}

/// Whether any sink takes a line at `level`, so a frame is formatted only
/// when someone reads it.
#[cfg(any(feature = "log", feature = "tracing"))]
fn enabled(level: Level) -> bool {
    #[cfg(feature = "log")]
    {
        let level = match level {
            Level::Debug => log::Level::Debug,
            Level::Info => log::Level::Info,
            Level::Warn => log::Level::Warn,
        };
        if log::log_enabled!(target: TARGET, level) {
            return true;
        }
    }
    #[cfg(feature = "tracing")]
    {
        let on = match level {
            Level::Debug => tracing::enabled!(target: TARGET, tracing::Level::DEBUG),
            Level::Info => tracing::enabled!(target: TARGET, tracing::Level::INFO),
            Level::Warn => tracing::enabled!(target: TARGET, tracing::Level::WARN),
        };
        if on {
            return true;
        }
    }
    false
}

#[cfg(any(feature = "log", feature = "tracing"))]
fn emit(level: Level, conn: usize, text: std::fmt::Arguments<'_>) {
    #[cfg(feature = "log")]
    {
        let level = match level {
            Level::Debug => log::Level::Debug,
            Level::Info => log::Level::Info,
            Level::Warn => log::Level::Warn,
        };
        log::log!(target: TARGET, level, "conn={conn} {text}");
    }
    #[cfg(feature = "tracing")]
    match level {
        Level::Debug => tracing::debug!(target: TARGET, conn, "{text}"),
        Level::Info => tracing::info!(target: TARGET, conn, "{text}"),
        Level::Warn => tracing::warn!(target: TARGET, conn, "{text}"),
    }
}

/// `68 04 07 00 00 00`.
#[cfg(any(feature = "log", feature = "tracing"))]
fn hex(octets: &[u8]) -> String {
    octets
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}
