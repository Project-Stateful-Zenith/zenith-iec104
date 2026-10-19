//! A Tokio transport for [`iec104`]: async drivers for the controlling station
//! (master) and the controlled station (outstation) of IEC 60870-5-104.
//!
//! # What this crate does
//!
//! The protocol lives in `iec104`'s sans-IO core, which decides what to send
//! and when but never touches a socket or a clock. This crate supplies the
//! I/O around it: it dials or accepts TCP connections, reads and writes the
//! sockets, and wakes the core when a timer is due. The application works
//! with ASDUs (the octets of the application layer) and leaves the APCI,
//! the sequence numbers and the timers to the core.
//!
//! # Choosing a driver
//!
//! | Driver | Core it runs | Connections |
//! | --- | --- | --- |
//! | [`master::spawn`] | `ConnectionManager` | one per station, redialed every t0 |
//! | [`master::spawn_redundant`] | `RedundancyGroup` | N to one station, one started (clause 10) |
//! | [`outstation::spawn`] + [`outstation::serve`] or [`outstation::serve_routed`] | `RedundancyGroup` | accepted, one per member; one driver per master |
//!
//! The cores are [`ConnectionManager`](iec104::manager::ConnectionManager)
//! and [`RedundancyGroup`](iec104::redundancy::RedundancyGroup). An
//! outstation with a single connection is a group of one member.
//!
//! # Talking to a driver
//!
//! Spawning a driver returns a [`Handle`] and an [`Events`] receiver.
//!
//! - The [`Handle`] sends requests: [`Handle::send_asdu`], [`Handle::start`]
//!   and [`Handle::stop`] (STARTDT and STOPDT, clause 5.3), [`Handle::close`],
//!   [`Handle::attach`] for a socket the application opened itself, and
//!   [`Handle::shutdown`]. It also asks for a connection's [`Handle::state`]
//!   and for the room left in its k window ([`Handle::window`]), and on a
//!   redundancy group decides what happens to a failed connection's
//!   unconfirmed data ([`Handle::retransmit_unconfirmed`]). Connections are
//!   named by index: the station of a manager, or the member of a group.
//! - The [`Event`]s report, in order, every ASDU the session accepted for the
//!   application ([`Event::Asdu`]), every state change of a connection, its
//!   dials, sockets and closes, and each acknowledgement that makes room in
//!   the k window ([`Event::Acknowledged`]). [`Options::trace`] adds every
//!   APDU sent and received. [`Event`] is `#[non_exhaustive]`: a `match` on
//!   it needs a wildcard arm.
//!
//! # Logging
//!
//! Two cargo features, both off by default, make the driver write its own
//! lines with the target `iec104_tokio`: `log` through the `log` crate and
//! `tracing` through the `tracing` crate. Each APDU sent or received gets one
//! debug line, formatted with [`iec104::diag::apdu`] in the profile of
//! [`Options::sizes`]; each connection event (dial, socket, state change,
//! refused frame, switchover, failed started connection) gets one more. The
//! lines do not depend on [`Options::trace`]. A [`client::Client`] and a
//! [`server::Server`] fill [`Options::sizes`] from
//! [`ClientConfig::sizes`](client::ClientConfig::sizes) and
//! [`ServerConfig::sizes`](server::ServerConfig::sizes).
//!
//! By default a controlling station sends STARTDT act as soon as a
//! connection is up ([`Options::auto_start`]). Answering an ASDU
//! ([`iec104::dispatch::route`] and the procedure modules such as
//! [`iec104::gi`]) stays application code, as in the core crate's blocking
//! examples.
//!
//! # Or let the client run the procedures
//!
//! For a controlling station, [`client::Client`] runs clause 7's procedures
//! on top of the master driver. Each call returns its result decoded:
//! `interrogate` and `stop_interrogation`, `counter_interrogate`, `command`
//! (or its steps `select`, `execute` and `cancel`), `sync_clock`, `read`,
//! `test`, `reset_process`, and `load_parameter`, `activate_parameter` and
//! `deactivate_parameter`. `subscribe` reports what the station sends, and
//! [`client::ProcessImage`] keeps the latest value of every address from
//! those reports.
//!
//! For a controlled station, [`server::Server`] runs them on top of the
//! outstation driver: it answers interrogations, counter interrogations,
//! reads, clock synchronisations and test commands from a process image the
//! application writes, sends the events the application reports, and hands
//! commands to the application.
//!
//! # How a driver runs
//!
//! - One task owns the core. It takes one event at a time (a request from a
//!   handle, received bytes, a finished dial, a due timer), feeds it to the
//!   core, and queues the resulting frames to the connection's writer before
//!   it takes the next event. It never waits for a write.
//! - Each socket has a reader task and a writer task. The writer puts frames
//!   on the wire in the order they were queued and flushes after every write,
//!   so a stream that buffers (TLS) does not hold a frame back. A peer that
//!   stops reading holds up only its own connection: a write it has not
//!   taken within t1 closes that connection.
//! - An active close (the application's, or the session's own on a t1
//!   expiry or a protocol error) first puts the frames queued before it on
//!   the wire, including the S-frame figures 10/11's NOTE asks for, then
//!   flushes and shuts the write half down.
//! - Each dial runs in its own task; the core's t0 decides when a new attempt
//!   replaces one still in flight.
//!
//! # Streams
//!
//! Every driver is generic over the byte stream ([`AsyncStream`]): plain TCP
//! through [`TcpConnector`] and the `serve` functions, anything else (TLS, an
//! in-memory pipe) through your own [`Connector`] or [`Handle::attach`].
//!
//! # Example
//!
//! ```no_run
//! use iec104::link::{Role, State};
//! use iec104::manager::{ConnectionManager, StationConfig};
//! use iec104::params::LinkParams;
//! use iec104_tokio::{master, Event, Options, TcpConnector};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let station = StationConfig::new(LinkParams::default());
//! let manager = ConnectionManager::new(Role::Controlling, vec![station])
//!     .expect("valid parameters");
//! let connector = TcpConnector::new(vec!["127.0.0.1:2404".into()]);
//! let (handle, mut events) = master::spawn(manager, connector, Options::default())?;
//! while let Some(event) = events.recv().await {
//!     match event {
//!         Event::State { conn, state: State::Started } => {
//!             // A station interrogation, C_IC_NA_1 to common address 1.
//!             let gi = [0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14];
//!             handle.send_asdu(conn, gi).await?;
//!         }
//!         Event::Asdu { asdu, .. } => println!("{asdu:02X?}"),
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod client;
mod connect;
mod core;
mod diagnostics;
mod engine;
mod error;
mod handle;
pub mod master;
pub mod outstation;
pub mod server;

pub use connect::{AsyncStream, Connector, NoConnector, TcpConnector};
pub use error::Error;
pub use handle::Handle;

use iec104::asdu::AddressSizes;
use iec104::link::State;
use iec104::redundancy::Switchover;
use tokio::sync::mpsc;

/// What a driver reports, in the order it happened.
///
/// More kinds of event may be added in later versions, so a `match` on it
/// needs a wildcard arm.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The driver is dialing `conn`.
    Connecting {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
    },
    /// The dial failed; the core asks again when the attempt's t0 expires.
    ConnectFailed {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
        /// The connector's error.
        error: String,
    },
    /// `conn` has a socket: a dial succeeded, or one was accepted or attached.
    Connected {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
    },
    /// `conn`'s socket is gone: the peer closed it, an I/O error, or an active
    /// close whose reason this is.
    Disconnected {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
        /// Why the socket is gone.
        reason: String,
    },
    /// `conn`'s session changed state (figures 17/18). [`State::Started`]
    /// means data transfer is on.
    State {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
        /// The state it is in now.
        state: State,
    },
    /// An ASDU the session accepted for the application, octet for octet.
    Asdu {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
        /// The ASDU's octets.
        asdu: Vec<u8>,
    },
    /// Redundancy group: a frame on `conn` that the group refused and did not
    /// act on. That is an I- or S-frame on a connection that is not the
    /// started one (10.5, 10.6: *"The controlled station shall only
    /// acknowledge user data received on the connection on which it last
    /// received a `STARTDT_ACT`"*), or a STARTDT act on a connection that is
    /// already over. Nothing was acknowledged or delivered; a peer that keeps
    /// doing this is misbehaving.
    FrameRefused {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
        /// Why the group refused it.
        error: Error,
    },
    /// Redundancy group: a failed started connection's switchover (10.5),
    /// after its t1 expired.
    Switchover(Switchover),
    /// Redundancy group: the started connection went down other than by its
    /// t1: the socket was lost, its session closed it (a sequence error), or,
    /// on a controlled station, the master started another connection (10.7).
    /// It is no longer the started one. `unconfirmed` ASDUs it held can go out
    /// again on the next started connection with
    /// [`Handle::retransmit_unconfirmed`] (10.5, 10.6), or be discarded with
    /// it; the group keeps them until then, also when `conn` is reopened or
    /// started again. The count includes earlier failures of `conn` not yet
    /// decided on, so an application that never decides holds more with every
    /// failure. A connection the master stopped before starting another
    /// (10.2's manual switchover) has not failed and is not reported, and
    /// neither is the application's own [`Handle::close`].
    StartedConnectionFailed {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
        /// How many ASDUs the group keeps for it, unconfirmed.
        unconfirmed: usize,
    },
    /// A received I- or S-frame confirmed I-frames sent on `conn` (clause
    /// 5.1), and [`Handle::window`] has more room than before it. An
    /// acknowledgement whose room the session's own queue fills at once is
    /// not reported.
    Acknowledged {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
    },
    /// With [`Options::trace`]: an APDU the driver handed to the connection's
    /// writer, in wire order.
    Sent {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
        /// The APDU's octets.
        frame: Vec<u8>,
    },
    /// With [`Options::trace`]: an APDU the driver read.
    Received {
        /// The connection: the station of a manager, or the member of a group.
        conn: usize,
        /// The APDU's octets.
        frame: Vec<u8>,
    },
}

/// The receiving end of a driver's [`Event`]s. Unbounded, so the driver never
/// waits for the application; read it steadily.
pub type Events = mpsc::UnboundedReceiver<Event>;

/// How a driver behaves beyond what the standard fixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Controlling station: send STARTDT act as soon as a connection is up
    /// (clause 5.3). For a redundancy group, start one connection whenever the
    /// group names none (10.3), which also covers a started connection that
    /// was lost. Default `true`.
    pub auto_start: bool,
    /// Report every APDU on the wire as [`Event::Sent`] / [`Event::Received`].
    /// Default `false`.
    pub trace: bool,
    /// The system's address sizes (104 cl.9.5). The driver treats ASDUs as
    /// octets and needs them only to format the log lines of the `log` and
    /// `tracing` features. Default [`AddressSizes::CONVENTIONAL`].
    pub sizes: AddressSizes,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            auto_start: true,
            trace: false,
            sizes: AddressSizes::CONVENTIONAL,
        }
    }
}

/// How many requests a [`Handle`] may have in flight before `send_asdu` and
/// the others wait.
const COMMAND_QUEUE: usize = 64;

fn spawn<C: core::Core, K: Connector>(
    core: C,
    connector: K,
    options: Options,
    group: bool,
) -> (Handle, Events) {
    let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE);
    let (events, event_rx) = mpsc::unbounded_channel();
    tokio::spawn(engine::run(
        core, connector, options, group, command_rx, events,
    ));
    (Handle { commands }, event_rx)
}
