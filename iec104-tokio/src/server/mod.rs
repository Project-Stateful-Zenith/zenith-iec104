//! A controlled station that answers from a process image.
//!
//! [`crate::outstation`] hands the application every ASDU as octets and leaves
//! the procedures of 104 clause 7 to it. A [`Server`] runs them: the
//! application writes its process values into the server's image, and the
//! server answers interrogations, counter interrogations, reads, clock
//! synchronisations and test commands from it without further application
//! code. Commands go to the application's [`Application`].
//!
//! ```no_run
//! use iec104::asdu::{DoublePointState, Quality, Value};
//! use iec104::ct::{Command, Family};
//! use iec104_tokio::server::{Application, PointConfig, Server, ServerConfig};
//! use tokio::net::TcpListener;
//!
//! struct Breaker;
//!
//! impl Application for Breaker {
//!     async fn operate(&self, command: Command) -> bool {
//!         println!("operating {command:?}");
//!         true
//!     }
//! }
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ServerConfig::new(1)
//!     .point(100, PointConfig::new(Value::Scaled(0)))
//!     .point(4001, PointConfig::new(Value::Double(DoublePointState::Off)))
//!     .command(4001, Family::Double);
//! let server = Server::spawn(config, Breaker)?;
//! tokio::spawn(server.clone().serve(TcpListener::bind("0.0.0.0:2404").await?));
//!
//! // A measured value changed: an event with cause 3.
//! server.report(100, Value::Scaled(1234), Quality::default(), None).await?;
//! // Written silently: sent only when asked for.
//! server.set(100, Value::Scaled(1235), Quality::default()).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # What is answered from the image
//!
//! | Request | Answer |
//! | --- | --- |
//! | `C_IC_NA_1` station or group interrogation (104 cl.7.5) | the points of the scope in their untagged types (5-101 cl.7.4.5), then the termination |
//! | `C_CI_NA_1` counter interrogation (104 cl.7.8) | the counters of the request, frozen where a freeze stored them; a freeze stores them; a reset calls [`Application::reset_counters`] |
//! | `C_RD_NA_1` read (104 cl.7.2) | the point in its untagged type with cause 5, or cause 47 |
//! | `C_CS_NA_1` clock synchronisation (104 cl.7.6) | the station's time before the synchronisation, then [`Application::synchronise`] |
//! | `C_TS_TA_1` test command (104 cl.7.10) | its confirmation |
//! | file transfer (5-101 cl.7.4.11), with files declared by [`ServerConfig::file`] | a call directory with the declared files; select and call file with the file, through [`iec104::ft::provide::Provider`]; another address with the cause 47 mirror |
//! | file transfer in the control direction (5-101 cl.7.4.11), with [`ServerConfig::accept_uploads`] | an offered file is called and acknowledged through [`iec104::ft::receive::Receiver`], then [`Application::received_file`] |
//! | parameter loading, reset process, file transfer in a direction not served and any other type | the cause 44 mirror (5-101 cl.7.2.3) |
//!
//! Every answer is decided by the core's procedure for the request
//! ([`iec104::gi`], [`iec104::ci`], [`iec104::rd`], [`iec104::cs`],
//! [`iec104::ts`], [`iec104::ct`]); the server adds the data.
//!
//! # Commands
//!
//! Only the addresses declared with [`ServerConfig::command`] take commands;
//! any other is answered with the cause 47 mirror (TS 60870-5-604 5.4.19.50:
//! the ASDU comes back unchanged with COT = 47, unknown information object
//! address), and a command of another family than the declared one with a
//! negative confirmation. [`Application::accept`] decides every select and
//! execute; a refusal is the negative confirmation. An accepted execute is
//! confirmed and handed to [`Application::operate`] in a task of its own, so
//! the station goes on answering meanwhile (TS 60870-5-604 Table 19: a
//! command arriving while a general interrogation runs is handled and
//! executed at once, not after the GI ends). Its termination goes out
//! when `operate` returns, positive or negative.
//!
//! # The order things are sent in
//!
//! The server keeps what it sends in its own queue, sorted into the rows of
//! 5-101 Table 16 ([`iec104::tx::respond_priority`]): the end of
//! initialisation, command mirrors, events and the clock synchronisation,
//! answers to reads and tests, interrogations, cyclic data. Within a row,
//! first in first out. It takes entries from the highest row first, one entry
//! for each ASDU the k window has room for ([`crate::Handle::window`]).
//!
//! Most entries are one ASDU. A pending interrogation, counter interrogation
//! or read is one entry too, which expands into every ASDU it owes (an
//! interrogation's data, a counter interrogation's totals and termination)
//! when it is taken. Only the first of them is handed over then; the rest
//! stay at the head of their row, in their order, and wait there for room.
//! An interrogation's termination is added once its last data ASDU is out.
//! So the server never hands
//! the driver more than the window takes, and a command's confirmation or
//! termination, an event or a clock synchronisation that comes up while a
//! large answer is being sent goes out before the rest of it (5-101 Table
//! 16 fixes the sending order by row, whichever data was produced first).
//! The termination still follows the last data ASDU
//! (5-101 cl.7.4.5).
//!
//! The same paragraph of 5-101 cl.7.4 keeps the chronological reporting
//! rules of 7.2.2.2 in force. Each ASDU of an
//! interrogation's or a counter interrogation's answer is therefore encoded
//! again from the image when it is handed over, and a read's answer is
//! encoded when its entry is taken. Every event queued before is then in the
//! driver already, so no answer carries a value older than an event already sent
//! (5-101 cl.7.2.2.2: successive values of one information object are
//! always sent in the order they were measured). One answer's ASDUs can therefore
//! carry values of different moments, each at least as new as the events
//! sent before it.
//!
//! An interrogation runs until its termination is taken, so the controlling
//! station can still stop it while the rest of its answer waits. TS
//! 60870-5-604 5.4.17.50: the controlled station confirms with the
//! interrogation command at COT = 9 (`C_IC_DEACTCON`), sends the controlling
//! station no more objects of that QOI's interrogation, and sends no COT = 10
//! (`ACTTERM`). The confirmation is positive, and the rest of the
//! answer is dropped with no termination. A second activation under
//! [`iec104::gi::ReActivation::Restart`] (5.4.17.30: the running GI is
//! abandoned and the second one begins) drops the rest the same way, and
//! the second answer starts from the beginning. Under
//! [`iec104::gi::ReActivation::Queue`] the second interrogation's data
//! follows the first's termination and its own confirmation. A counter
//! interrogation cannot be stopped: 5-101 cl.7.4.8 has no `C_CI` DEACT or
//! DEACTCON.
//!
//! # Connections
//!
//! Nothing is sent before the controlling station starts data transfer (104
//! cl.5.3: the controlled station holds back pending user data until the
//! STARTDT con); until then the queue waits. The image, the queue
//! and the state of every procedure belong to the server, not to a
//! connection, so they carry over to the next started connection, and the
//! ASDUs a failed connection left unconfirmed are sent again on it (104
//! cl.10.6: after a switchover, all user data still unconfirmed, any
//! unconfirmed ACTCONs or ACTTERMs among it, is sent again on the newly
//! started connection). Once no member
//! of the group has a socket the link is gone, and so is the controlling
//! station that asked: the queue keeps only the events and the end of
//! initialisation, and the running interrogations, selects and executes are
//! dropped, so the next one gets no answer it did not ask for.
//!
//! The end of initialisation ([`ServerConfig::end_of_initialisation`]) goes
//! out once, on the first started connection: TS 60870-5-604 5.4.12.30, after
//! re-establishment no `M_EI` (end of initialisation) is sent, nor is one
//! needed.
//!
//! One server is one redundancy group of [`ServerConfig::members`]
//! connections, and serves one controlling station (104 cl.10.2 rule 7). For
//! several, run one server each and route the connections with
//! [`crate::outstation::serve_routed`] and each server's [`Server::handle`].

mod image;
mod queue;
mod task;

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use iec104::asdu::{
    AddressSizes, AsduError, Cause, Coi, Cp56Time2a, LayoutError, Lof, MAX_IOA, Nof, Point,
    Quality, Value,
};
use iec104::ci::{self, CounterMode};
use iec104::ct::{Command, CommandMode, CommandSet, Family, Termination};
use iec104::gi::ReActivation;
use iec104::link::Role;
use iec104::params::LinkParams;
use iec104::redundancy::RedundancyGroup;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

use crate::{AsyncStream, Error, Handle, Options, outstation};

pub use crate::client::Clock;

/// The default select timeout: 10 s. TS 60870-5-604 5.4.19.1 requires the
/// execute to reach the controlled station within a configured delay and
/// leaves the delay to the system.
pub const DEFAULT_SELECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The default size of the event buffer: 1000 events.
pub const DEFAULT_EVENT_BUFFER: usize = 1000;

/// The default size of the request buffer: 1000 entries.
pub const DEFAULT_REQUEST_BUFFER: usize = 1000;

/// The default clock synchronisation interval: 24 hours. 104 cl.7.6 leaves
/// the interval to agreement between the parties and fixes none.
pub const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// What the application decides and does for a [`Server`].
///
/// Every method but [`Application::operate`] has a default.
pub trait Application: Send + Sync + 'static {
    /// Whether the station takes this select or execute. `false` is answered
    /// with a negative confirmation (TS 60870-5-604 5.4.19.30, 5.4.19.50).
    /// Called in the server's task: it must answer at once and must not
    /// block. Default: every command is taken.
    fn accept(&self, command: &Command) -> bool {
        let _ = command;
        true
    }

    /// Operates an accepted, confirmed execute and returns whether it
    /// succeeded: `true` is the positive termination, `false` the negative one
    /// (TS 60870-5-604 5.4.19.40: a positive `ACTCON` followed by a negative
    /// termination), where the family is
    /// terminated ([`ServerConfig::termination`]). It runs in its own task
    /// and may take its time.
    ///
    /// Past [`ServerConfig::operate_timeout`] the operation is reported
    /// failed to the master but is not cancelled. An application that needs
    /// cancellation times out inside `operate` and returns the equipment to
    /// a safe state.
    fn operate(&self, command: Command) -> impl Future<Output = bool> + Send;

    /// A valid clock synchronisation arrived with `time`: set the station's
    /// clock from it (5-101 cl.7.4.6: only the controlled station corrects
    /// its time). Called after the
    /// confirmation, which carries the time before the correction (104
    /// cl.7.6), is queued.
    /// Default: nothing.
    fn synchronise(&self, time: Cp56Time2a) {
        let _ = time;
    }

    /// A counter interrogation command asked for a reset (`FRZ` 2 or 3, 5-101
    /// cl.7.2.6.23) of `request`'s counters, after any freeze it asked for was
    /// stored. The counters are the application's; write them again with
    /// [`Server::set`]. Default: nothing.
    fn reset_counters(&self, request: ci::Request) {
        let _ = request;
    }

    /// The controlling station uploaded the file `nof` at `ioa` holding
    /// `content` (5-101 cl.7.4.11 in the control direction), and the
    /// section and file checksums added up (7.2.6.37). Called in the server's
    /// task after the positive file acknowledgement is queued: it must not
    /// block. Only with [`ServerConfig::accept_uploads`]. Default: nothing.
    fn received_file(&self, ioa: u32, nof: Nof, content: Vec<u8>) {
        let _ = (ioa, nof, content);
    }
}

/// One point of the image.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PointConfig {
    /// The initial value. Its kind is the point's for good: a write of
    /// another kind is refused.
    pub value: Value,
    /// The initial quality.
    pub quality: Quality,
    /// Answered in a station interrogation (and, for a counter, in the
    /// general counter request). 5-101 cl.7.4.5: a station interrogation
    /// returns only objects the controlled station stores.
    pub station: bool,
    /// The interrogation groups 1 to 16 it is also answered in, bit `n - 1`
    /// for group `n`; for a counter, the counter groups 1 to 4.
    pub groups: u16,
    /// Its events carry a `CP56Time2a` (the types `<30>` to `<40>`, 104 cl.9).
    /// A value with only one form (`M_PS_NA_1` untagged, the protection
    /// events tagged) ignores it.
    pub tagged: bool,
    /// A read (104 cl.7.2) returns it.
    pub readable: bool,
}

impl PointConfig {
    /// A point with `value`, a quality with every bit clear, answered in the
    /// station interrogation, in no group, with tagged events, readable.
    #[must_use]
    pub fn new(value: Value) -> Self {
        Self {
            value,
            quality: Quality::default(),
            station: true,
            groups: 0,
            tagged: true,
            readable: true,
        }
    }

    /// Also answered in interrogation group `n` (1 to 16; counter group 1 to
    /// 4 for a counter). Another `n` is ignored.
    #[must_use]
    pub fn group(mut self, n: u8) -> Self {
        if let Some(bit) = image::group_bit(n) {
            self.groups |= bit;
        }
        self
    }

    /// Events without a time tag.
    #[must_use]
    pub const fn untagged(mut self) -> Self {
        self.tagged = false;
        self
    }

    /// Not answered in the station interrogation.
    #[must_use]
    pub const fn not_in_station(mut self) -> Self {
        self.station = false;
        self
    }

    /// Not returned by a read.
    #[must_use]
    pub const fn not_readable(mut self) -> Self {
        self.readable = false;
        self
    }

    /// The initial quality.
    #[must_use]
    pub const fn with_quality(mut self, quality: Quality) -> Self {
        self.quality = quality;
        self
    }
}

/// What a server needs to know about its station.
#[derive(Clone)]
pub struct ServerConfig {
    /// The station's common address (5-101 cl.7.2.4).
    pub common_address: u16,
    /// The system's address sizes (104 cl.9.5).
    pub sizes: AddressSizes,
    /// The link parameters of each connection.
    pub link: LinkParams,
    /// How many connections the controlling station may open, one of which is
    /// started (104 clause 10). Default 1.
    pub members: usize,
    /// Direct execute, or select and execute (5-101 cl.7.4.7).
    pub command_mode: CommandMode,
    /// The untagged or the time-tagged command set (104 clause 9).
    pub command_set: CommandSet,
    /// Which command families are terminated (5-101 cl.7.4.7).
    pub termination: Termination,
    /// How long a select waits for its execute. Default
    /// [`DEFAULT_SELECT_TIMEOUT`], 10 s.
    pub select_timeout: Duration,
    /// The maximum delay of a time-tagged command (104 cl.8): an older one is
    /// neither answered nor operated. Default `None`: not supervised.
    pub max_command_delay: Option<Duration>,
    /// How long [`Application::operate`] may run before its execute is
    /// terminated negatively. The future is not cancelled: it runs on, and
    /// its object refuses every select and execute (negative ACTCON) until
    /// it really ends; its result is then discarded. Neither 104 nor TS
    /// 60870-5-604 fixes a limit. Default `None`: an operation runs for as
    /// long as it takes, and one that never ends holds its object until
    /// restart.
    pub operate_timeout: Option<Duration>,
    /// The station's counter mode (5-101 cl.7.4.8). Default mode C.
    pub counter_mode: CounterMode,
    /// What a second interrogation does while one runs (TS 60870-5-604
    /// 5.4.17). Default: the running one continues.
    pub reactivation: ReActivation,
    /// The end of initialisation sent on the first started connection, or
    /// `None` for none (104 cl.7.1 marks it optional). Default: local power
    /// on, local parameters unchanged.
    pub end_of_initialisation: Option<Coi>,
    /// The station's clock, for time tags and the clock synchronisation.
    /// Default: the system clock as UTC.
    pub clock: Clock,
    /// The agreed interval between clock synchronisations (104 cl.7.6).
    /// Default [`DEFAULT_SYNC_INTERVAL`], 24 hours.
    pub sync_interval: Duration,
    /// The station's clock is kept by other means than the clock
    /// synchronisation command (104 cl.7.6 names dedicated time receivers
    /// and the like; GPS or NTP, say). Time tags then
    /// carry no invalid mark for want of a `C_CS ACT`, neither before the
    /// first nor after [`ServerConfig::sync_interval`]. A clock
    /// synchronisation is still answered and handed to
    /// [`Application::synchronise`]. A [`Clock`] that knows its time is
    /// wrong marks it itself (`Cp56Time2a::invalid`); the mark is kept.
    /// Default `false`.
    pub external_clock: bool,
    /// How many reported events wait at most; beyond it the oldest is
    /// dropped and counted ([`Server::dropped`]). Default
    /// [`DEFAULT_EVENT_BUFFER`], 1000.
    pub event_buffer: usize,
    /// How many entries other than events (answers to reads, confirmations,
    /// mirrors, terminations, interrogations) wait at most. While they fill
    /// it, a received ASDU is dropped unanswered and counted
    /// ([`Server::dropped`]); the controlling station's own timeout covers
    /// it. What is owed for an ASDU already taken, such as the termination
    /// of a confirmed command, is never dropped. `0` is not "no limit": it
    /// drops every received ASDU, so the station answers nothing. Default
    /// [`DEFAULT_REQUEST_BUFFER`], 1000.
    pub request_buffer: usize,
    /// Report every APDU in the driver's events ([`Options::trace`]).
    pub trace: bool,
    /// Receive files in the control direction (104 cl.9.6's second
    /// checkbox, 604 5.4.23.10): a file the controlling station offers with
    /// a file ready, at any address, is called and handed to
    /// [`Application::received_file`]. Default `false`: the cause 44 mirror.
    pub accept_uploads: bool,
    points: BTreeMap<u32, PointConfig>,
    commands: BTreeMap<u32, Family>,
    files: BTreeMap<u32, ServedFile>,
}

/// A file a server provides in the monitor direction (5-104 cl.9.6's first
/// checkbox), declared with [`ServerConfig::file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServedFile {
    pub(crate) nof: Nof,
    pub(crate) content: Arc<[u8]>,
}

impl ServerConfig {
    /// A station at `common_address` with the defaults above, no points and
    /// no commands.
    pub fn new(common_address: u16) -> Self {
        Self {
            common_address,
            sizes: AddressSizes::CONVENTIONAL,
            link: LinkParams::default(),
            members: 1,
            command_mode: CommandMode::Direct,
            command_set: CommandSet::Untagged,
            termination: Termination::All,
            select_timeout: DEFAULT_SELECT_TIMEOUT,
            max_command_delay: None,
            operate_timeout: None,
            counter_mode: CounterMode::FreezeAndTransmit,
            reactivation: ReActivation::Continue,
            end_of_initialisation: Some(Coi {
                cause: Coi::LOCAL_POWER_ON,
                changed_local_parameters: false,
            }),
            clock: Arc::new(system_clock),
            sync_interval: DEFAULT_SYNC_INTERVAL,
            external_clock: false,
            event_buffer: DEFAULT_EVENT_BUFFER,
            request_buffer: DEFAULT_REQUEST_BUFFER,
            trace: false,
            accept_uploads: false,
            points: BTreeMap::new(),
            commands: BTreeMap::new(),
            files: BTreeMap::new(),
        }
    }

    /// Adds the point at `ioa` (replacing one there). `ioa` must not be `0`,
    /// which [`Server::spawn`] refuses.
    #[must_use]
    pub fn point(mut self, ioa: u32, point: PointConfig) -> Self {
        self.points.insert(ioa, point);
        self
    }

    /// Lets `ioa` take commands of `family`. `ioa` must not be `0`, which
    /// [`Server::spawn`] refuses.
    #[must_use]
    pub fn command(mut self, ioa: u32, family: Family) -> Self {
        self.commands.insert(ioa, family);
        self
    }

    /// Serves the file `nof` holding `content` at `ioa` (replacing one there):
    /// it is listed in the directory and transferred on request (5-101
    /// cl.7.4.11). `ioa` must not be `0`, which [`Server::spawn`] refuses, nor
    /// `content` longer than `LOF` can state ([`iec104::asdu::Lof::MAX`]).
    #[must_use]
    pub fn file(mut self, ioa: u32, nof: Nof, content: impl Into<Arc<[u8]>>) -> Self {
        self.files.insert(
            ioa,
            ServedFile {
                nof,
                content: content.into(),
            },
        );
        self
    }
}

fn system_clock() -> Cp56Time2a {
    Cp56Time2a::from_system_time(SystemTime::now()).unwrap_or_default()
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("common_address", &self.common_address)
            .field("sizes", &self.sizes)
            .field("link", &self.link)
            .field("members", &self.members)
            .field("command_mode", &self.command_mode)
            .field("command_set", &self.command_set)
            .field("termination", &self.termination)
            .field("select_timeout", &self.select_timeout)
            .field("max_command_delay", &self.max_command_delay)
            .field("operate_timeout", &self.operate_timeout)
            .field("counter_mode", &self.counter_mode)
            .field("reactivation", &self.reactivation)
            .field("end_of_initialisation", &self.end_of_initialisation)
            .field("sync_interval", &self.sync_interval)
            .field("external_clock", &self.external_clock)
            .field("event_buffer", &self.event_buffer)
            .field("request_buffer", &self.request_buffer)
            .field("trace", &self.trace)
            .field("accept_uploads", &self.accept_uploads)
            .field("points", &self.points)
            .field("commands", &self.commands)
            .finish_non_exhaustive()
    }
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerError {
    /// No point at this address.
    UnknownAddress(u32),
    /// The value is of another kind than the point's.
    WrongKind(u32),
    /// An event's cause must be 3, 11 or 12.
    NotAnEventCause(Cause),
    /// A point or a command at address `<0>`, which 5-101 cl.7.2.5 defines as
    /// irrelevant: it names no object, so a point there could never be read.
    IrrelevantAddress,
    /// The file at this address is longer than `LOF` can state (5-101
    /// cl.7.2.6.35).
    FileTooLong(u32),
    /// The value cannot be encoded.
    Layout(LayoutError),
    /// The driver refused or has stopped.
    Driver(Error),
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownAddress(ioa) => write!(f, "no point at address {ioa}"),
            Self::WrongKind(ioa) => {
                write!(f, "the value is not of the kind of the point at {ioa}")
            }
            Self::NotAnEventCause(cause) => {
                write!(f, "cause {} is not an event's (3, 11 or 12)", cause.to_u8())
            }
            Self::IrrelevantAddress => f.write_str("address 0 is irrelevant and names no object"),
            Self::FileTooLong(ioa) => write!(f, "the file at {ioa} is longer than LOF can state"),
            Self::Layout(e) => write!(f, "layout: {e:?}"),
            Self::Driver(e) => write!(f, "driver: {e}"),
        }
    }
}

impl std::error::Error for ServerError {}

impl From<Error> for ServerError {
    fn from(e: Error) -> Self {
        Self::Driver(e)
    }
}

type Reply<T> = oneshot::Sender<Result<T, ServerError>>;

/// A request from a [`Server`] to its task.
enum Request {
    Write {
        ioa: u32,
        value: Value,
        quality: Quality,
        time: Option<Cp56Time2a>,
        event: Option<Cause>,
        reply: Reply<()>,
    },
    Point(u32, Reply<Point>),
    Dropped(Reply<u64>),
}

/// A controlled station serving one controlling station. Cheap to clone; the
/// server stops when the last clone is dropped or [`Server::shutdown`] is
/// called.
#[derive(Clone)]
pub struct Server {
    requests: mpsc::Sender<Request>,
    handle: Handle,
}

impl Server {
    /// Starts the server on the current Tokio runtime. It has no connection
    /// yet: give it sockets with [`Server::serve`], [`Server::attach`] or
    /// through [`Server::handle`].
    ///
    /// # Errors
    ///
    /// [`ServerError::IrrelevantAddress`] when a point, a command or a file is
    /// at address `<0>`, [`ServerError::FileTooLong`] for a file longer than
    /// `LOF` can state, [`ServerError::Layout`] when the common address, or a
    /// point's or a command's address, does not fit [`ServerConfig::sizes`], and
    /// [`ServerError::Driver`] when the redundancy group cannot be built from
    /// the configuration (no member, say).
    pub fn spawn<A: Application>(config: ServerConfig, app: A) -> Result<Self, ServerError> {
        // 5-101 cl.7.2.4: every ASDU carries it, so one that does not fit
        // would leave each answer unencodable.
        let max = config.sizes.max_common_address();
        if config.common_address > max {
            return Err(ServerError::Layout(LayoutError::Asdu(
                AsduError::CommonAddressOutOfRange {
                    common_address: config.common_address,
                    max,
                },
            )));
        }
        // 5-101 cl.7.2.5: `<0>` is "irrelevant", so a point there could be
        // interrogated but never read.
        if config.points.contains_key(&0)
            || config.commands.contains_key(&0)
            || config.files.contains_key(&0)
        {
            return Err(ServerError::IrrelevantAddress);
        }
        if let Some((&ioa, _)) = config
            .files
            .iter()
            .find(|(_, file)| u32::try_from(file.content.len()).map_or(true, |l| l > Lof::MAX))
        {
            return Err(ServerError::FileTooLong(ioa));
        }
        let max = config.sizes.max_ioa();
        if let Some(&ioa) = config
            .points
            .keys()
            .chain(config.commands.keys())
            .chain(config.files.keys())
            .find(|&&ioa| ioa > max)
        {
            let e = if max == MAX_IOA {
                AsduError::IoaOutOfRange { ioa }
            } else {
                AsduError::IoaOutOfRangeForWidth { ioa, max }
            };
            return Err(ServerError::Layout(LayoutError::Asdu(e)));
        }
        let group = RedundancyGroup::new(Role::Controlled, vec![config.link; config.members])
            .map_err(|e| ServerError::Driver(Error::Group(e)))?;
        let options = Options {
            trace: config.trace,
            sizes: config.sizes,
            ..Options::default()
        };
        let (handle, events) = outstation::spawn(group, options)?;
        let (requests, receiver) = mpsc::channel(64);
        tokio::spawn(task::run(handle.clone(), events, receiver, config, app));
        Ok(Self { requests, handle })
    }

    /// Accepts TCP connections on `listener` for this server
    /// ([`outstation::serve`]). Returns when the server stops; accept errors
    /// are waited out. Every host that reaches the listener is accepted, so
    /// keep unknown peers out with a firewall, or accept them yourself and
    /// hand over only known ones with [`Server::attach`] (TLS, say).
    ///
    /// # Errors
    ///
    /// None: it returns `Ok` when the server stops, and handles every accept
    /// error itself.
    pub async fn serve(self, listener: TcpListener) -> io::Result<()> {
        outstation::serve(listener, self.handle).await
    }

    /// Hands the server a connection the application accepted itself (a TLS
    /// stream, say) and returns the member it took.
    ///
    /// # Errors
    ///
    /// [`ServerError::Driver`] with [`Error::NoFreeConnection`] when every
    /// member has a socket, or with [`Error::Stopped`] once the server has
    /// stopped.
    pub async fn attach<S: AsyncStream>(&self, stream: S) -> Result<usize, ServerError> {
        Ok(self.handle.attach(None, stream).await?)
    }

    /// The driver underneath.
    #[must_use]
    pub const fn handle(&self) -> &Handle {
        &self.handle
    }

    async fn call<T>(&self, request: impl FnOnce(Reply<T>) -> Request) -> Result<T, ServerError> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .send(request(reply))
            .await
            .map_err(|_| ServerError::Driver(Error::Stopped))?;
        answer
            .await
            .map_err(|_| ServerError::Driver(Error::Stopped))?
    }

    /// Writes a point without sending anything: the value goes out when it is
    /// asked for. A point with tagged events is stamped with the station's
    /// clock.
    ///
    /// # Errors
    ///
    /// [`ServerError::UnknownAddress`] for no point at `ioa`,
    /// [`ServerError::WrongKind`] for a value of another kind, and
    /// [`ServerError::Driver`] with [`Error::Stopped`] once the server has stopped.
    pub async fn set(&self, ioa: u32, value: Value, quality: Quality) -> Result<(), ServerError> {
        self.call(|reply| Request::Write {
            ioa,
            value,
            quality,
            time: None,
            event: None,
            reply,
        })
        .await
    }

    /// Writes a point and sends it as a spontaneous event (cause 3, 104
    /// cl.7.4). `time` is the event's time tag for a point with tagged
    /// events; `None` takes the station's clock now. The tag's invalid bit is
    /// set while the clock is not synchronised (104 cl.7.6: if no
    /// synchronisation command arrives within the interval, the controlled
    /// station marks every time-tagged object's tag as possibly inaccurate,
    /// that is invalid), unless
    /// [`ServerConfig::external_clock`] says something else keeps it.
    ///
    /// # Errors
    ///
    /// As [`Server::set`], and [`ServerError::Layout`] when the event cannot
    /// be encoded.
    pub async fn report(
        &self,
        ioa: u32,
        value: Value,
        quality: Quality,
        time: Option<Cp56Time2a>,
    ) -> Result<(), ServerError> {
        self.report_with(ioa, value, quality, time, Cause::Spontaneous)
            .await
    }

    /// [`Server::report`] with the cause given: 3 spontaneous, or the return
    /// information of a remote (11) or a local (12) command (5-101 cl.7.4.7:
    /// return information marks a completed control operation, where the
    /// station has it). It goes with the events of 5-101 Table 16.
    ///
    /// # Errors
    ///
    /// [`ServerError::NotAnEventCause`] for another cause, otherwise as
    /// [`Server::report`].
    pub async fn report_with(
        &self,
        ioa: u32,
        value: Value,
        quality: Quality,
        time: Option<Cp56Time2a>,
        cause: Cause,
    ) -> Result<(), ServerError> {
        if !matches!(
            cause,
            Cause::Spontaneous | Cause::ReturnInfoRemote | Cause::ReturnInfoLocal
        ) {
            return Err(ServerError::NotAnEventCause(cause));
        }
        self.call(|reply| Request::Write {
            ioa,
            value,
            quality,
            time,
            event: Some(cause),
            reply,
        })
        .await
    }

    /// The point at `ioa` as the image holds it.
    ///
    /// # Errors
    ///
    /// [`ServerError::UnknownAddress`] for no point at `ioa`, and
    /// [`ServerError::Driver`] with [`Error::Stopped`] once the server has stopped.
    pub async fn point(&self, ioa: u32) -> Result<Point, ServerError> {
        self.call(|reply| Request::Point(ioa, reply)).await
    }

    /// How many events and received requests were dropped because the event
    /// buffer or the request buffer was full.
    ///
    /// # Errors
    ///
    /// [`ServerError::Driver`] with [`Error::Stopped`] once the server has stopped.
    pub async fn dropped(&self) -> Result<u64, ServerError> {
        self.call(Request::Dropped).await
    }

    /// Closes every connection and stops the server.
    pub async fn shutdown(&self) {
        self.handle.shutdown().await;
    }
}
