//! A controlling station that speaks in procedures rather than frames.
//!
//! [`crate::master`] hands the application every ASDU as octets and leaves the
//! procedures of 104 clause 7 to it. A [`Client`] runs them: each call sends the
//! activation, waits for the answers that belong to it and returns the result,
//! already decoded with [`iec104::asdu::decode_with`].
//!
//! ```no_run
//! use iec104::asdu::DoubleCommandState;
//! use iec104::ct::Command;
//! use iec104::gi::Scope;
//! use iec104_tokio::TcpConnector;
//! use iec104_tokio::client::{Client, ClientConfig, Update};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let connector = TcpConnector::new(vec!["192.0.2.10:2404".into()]);
//! let client = Client::connect(connector, ClientConfig::new(1)).await?;
//!
//! let image = client.interrogate(Scope::Station).await?;
//! println!("{} ASDUs in the station's image", image.len());
//!
//! client.command(Command::double(4001, DoubleCommandState::On)).await?;
//!
//! let mut updates = client.subscribe().await?;
//! while let Some(update) = updates.recv().await {
//!     if let Update::Data(asdu) = update {
//!         println!("{:?}", asdu.objects);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # One client, one controlled station
//!
//! A client talks to one common address over one connection
//! ([`Client::connect`]) or over a redundancy group of several
//! ([`Client::connect_redundant`], 104 clause 10). For several stations, run
//! one client each.
//!
//! # What a call waits for
//!
//! | Call | Procedure | Returns at |
//! | --- | --- | --- |
//! | [`Client::interrogate`] | 104 cl.7.5, `C_IC_NA_1` | the `ACTTERM`, with every ASDU of the scope |
//! | [`Client::counter_interrogate`] | 104 cl.7.8, `C_CI_NA_1` | the `ACTTERM` of a collection, the `ACTCON` of a freeze or reset |
//! | [`Client::command`] | 104 cl.7.7, types 45–51 or 58–64 | the `ACTTERM`, or the `ACTCON` where the family is not terminated ([`iec104::ct::Termination`]) |
//! | [`Client::select`] | TS 60870-5-604 5.4.19.1, the select alone | the select's `ACTCON` |
//! | [`Client::execute`] | TS 60870-5-604 5.4.19.1, the execute of that select | as [`Client::command`] |
//! | [`Client::cancel`] | TS 60870-5-604 5.4.19.10, `DEACT` of that select | the `DEACTCON` |
//! | [`Client::stop_interrogation`] | TS 60870-5-604 5.4.17.50, `C_IC_NA_1` `DEACT` | the `DEACTCON` |
//! | [`Client::sync_clock`] | 104 cl.7.6, `C_CS_NA_1` | the `ACTCON` |
//! | [`Client::read`] | 104 cl.7.2, `C_RD_NA_1` | the object, cause 5 |
//! | [`Client::test`] | 104 cl.7.10, `C_TS_TA_1` | the `ACTCON`, which must echo the TSC and the time |
//! | [`Client::reset_process`] | 104 cl.7.1 figure 22, `C_RP_NA_1` | the `ACTCON` |
//! | [`Client::load_parameter`] | 104 cl.7.9, `P_ME_NA_1`–`P_ME_NC_1` | the `ACTCON`, with the parameter now in operation |
//! | [`Client::activate_parameter`], [`Client::deactivate_parameter`] | 104 cl.7.9, `P_AC_NA_1` | the `ACTCON` or `DEACTCON` |
//!
//! The standard gives no application-level time-outs, only the link's t1, so
//! each wait is bounded by the client's own [`Timeouts`].
//!
//! File transfer (104 cl.7.11) is not among the calls. The core's
//! [`iec104::ft`] leaves the whole session (which file and section is in
//! flight, the segments received, the checksums, the acknowledgements) to its
//! caller, and the client does not pass the file-transfer ASDUs it receives on
//! to [`Client::subscribe`]: an application that transfers files runs
//! [`crate::master`] and [`iec104::ft`] itself.
//!
//! # Nothing that acts on the station is sent twice
//!
//! A command whose execute went out but whose answer did not come back, by
//! time-out or because the connection was lost, ends with
//! [`ClientError::OutcomeUnknown`]: the controlled station may or may not have
//! operated, and the client does not resend it. A reset process and a
//! parameter load, activation or deactivation end the same way. A select that
//! got no answer operated nothing (TS 60870-5-604 5.4.19.1: without the
//! confirmed select there is no execute), so it ends with
//! [`ClientError::Timeout`] or [`ClientError::ConnectionLost`] like any other
//! request, and so does a cancel or a stopped interrogation. An interrogation,
//! a read, a clock synchronisation or a test command is safe to repeat and is
//! never retried either: call it again.
//!
//! # Concurrency
//!
//! Every call may run alongside the others. TS 60870-5-604 Table 19: *"Command
//! function during a running general interrogation is processed and executed
//! without waiting for the GI to finish."* A second call for what is already
//! outstanding (a command, select, execute or cancel for the same object
//! address, a counter interrogation of the same group with another qualifier,
//! a second clock synchronisation, test command, reset process or stop of the
//! same interrogation, a second request for the same parameter) is refused
//! with [`ClientError::Busy`]. A second interrogation of the same
//! scope, or a read of the same address, joins the one running and gets its
//! result: 5-101 cl.7.4.5 locks the identical interrogation, so no second
//! activation is sent.
//!
//! # Updates
//!
//! [`Client::subscribe`] returns every monitor-direction ASDU the station
//! sends (spontaneous, cyclic, interrogated, counted, read, return
//! information, end of initialisation), decoded, and the link's changes. Only
//! monitor-direction types are updates: the data the calls above bring back
//! (interrogation, counter interrogation and read results) is reported there,
//! so a process image kept from the updates alone misses no value, but the
//! confirmations and terminations of commands, clock synchronisations, tests,
//! resets and parameters are not.
//!
//! On each new started connection the client runs a station interrogation of
//! its own ([`ClientConfig::interrogate_on_start`]): TS 60870-5-604 5.4.13.10
//! *"begins the General Interrogation procedure"* after re-establishment. Its
//! data arrives as updates.
//!
//! # Process image
//!
//! [`ProcessImage`] keeps the latest value of every address the station sent
//! (a [`Point`](iec104::asdu::Point) with its cause and the instant it
//! arrived), merging interrogation data with spontaneous changes. The
//! application feeds it the updates with [`ProcessImage::apply`]; the client
//! does not keep one itself:
//!
//! - The updates already carry every monitor-direction ASDU, so the image is a
//!   plain fold over them and needs no second copy inside the client's task.
//! - The application owns it: it reads single entries by reference, without a
//!   round trip to the task or a copy of the whole image, decides when to
//!   clear it, and pays nothing when it keeps no image.
//! - Time is a parameter, as in the rest of the crate. The instant stored is
//!   the one the application passes, so it is when the update was taken from
//!   the channel: later than the reception by the time the update waited
//!   there, which is short for a channel read steadily. A subscriber that
//!   falls [`ClientConfig::update_buffer`] updates behind misses some
//!   ([`Update::Lagged`]); its image is then incomplete until the next
//!   interrogation.
//!
//! To see the interrogation run on the first start, subscribe before it:
//! [`Client::spawn`], then [`Client::subscribe`], then
//! [`Client::wait_started`].

mod image;
mod task;

pub use image::{ImageEntry, ProcessImage};

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use iec104::asdu::{AddressSizes, Asdu, Cause, Cp56Time2a, FreezeMode, LayoutError, Qrp, Tsc};
use iec104::ci::{self, CounterMode};
use iec104::ct::{Command, CommandMode, CommandSet, Termination};
use iec104::gi::Scope;
use iec104::link::Role;
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104::pm::Parameter;
use iec104::redundancy::{RedundancyGroup, Switchover};
use tokio::sync::{mpsc, oneshot};

use crate::{Connector, Error, Handle, Options, master};

/// How long a client waits for each answer.
///
/// The standard fixes the link's timers (104 clause 9, t0–t3) but no time-out
/// for an application procedure, so these are the system's own choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// From an activation to its confirmation (`ACTCON`), and from a read or
    /// a clock synchronisation to its answer. Default 10 s.
    pub confirmation: Duration,
    /// From a command's confirmation to its termination (`ACTTERM`). Default
    /// 30 s.
    pub termination: Duration,
    /// From an interrogation's activation to its termination, the data
    /// included. Default 60 s.
    pub interrogation: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            confirmation: Duration::from_secs(10),
            termination: Duration::from_secs(30),
            interrogation: Duration::from_secs(60),
        }
    }
}

/// The time source for the time tags of the 5-104 command set.
/// [`Cp56Time2a::from_system_time`] turns the system clock into a tag.
pub type Clock = Arc<dyn Fn() -> Cp56Time2a + Send + Sync>;

/// The default size of each subscriber's channel: 1000 updates.
pub const DEFAULT_UPDATE_BUFFER: usize = 1000;

/// What a client needs to know about its station.
#[derive(Clone)]
pub struct ClientConfig {
    /// The station's common address (5-101 cl.7.2.4).
    pub common_address: u16,
    /// The originator address this station sends (5-101 cl.7.2.3), 0 if the
    /// system does not use one.
    pub originator: u8,
    /// The system's address sizes (104 cl.9.5).
    pub sizes: AddressSizes,
    /// The link parameters of the connection, or of each member of a
    /// redundancy group.
    pub link: LinkParams,
    /// Direct execute, or select and execute (5-101 cl.7.4.7).
    pub command_mode: CommandMode,
    /// The untagged command set `<45>`–`<51>` or the time-tagged set
    /// `<58>`–`<64>` (104 clause 9: one or the other, not both).
    pub command_set: CommandSet,
    /// Which command families are terminated (5-101 cl.7.4.7).
    pub termination: Termination,
    /// The station's counter mode (104 cl.9.6, 5-101 cl.7.4.8).
    pub counter_mode: CounterMode,
    /// How long each answer may take.
    pub timeouts: Timeouts,
    /// Run a station interrogation on every new started connection. Default
    /// `true`.
    pub interrogate_on_start: bool,
    /// Redundancy group: replay a failed connection's unconfirmed ASDUs on the
    /// next started one (104 cl.10.5 leaves the choice *"to the
    /// application"*), and keep waiting for the answers they are owed. Default
    /// `false`: they are discarded, and what waited for them ends as on a lost
    /// connection ([`ClientError::OutcomeUnknown`] for an execute, a reset
    /// process or a parameter request, [`ClientError::ConnectionLost`] for the
    /// rest).
    pub retransmit_on_switchover: bool,
    /// How many updates wait at most in each subscriber's channel
    /// ([`Client::subscribe`]); beyond it the subscriber misses updates and
    /// is told how many ([`Update::Lagged`]). At least 1. Default
    /// [`DEFAULT_UPDATE_BUFFER`], 1000.
    pub update_buffer: usize,
    /// Report every APDU in the driver's events ([`Options::trace`]). The
    /// client itself does not print them.
    pub trace: bool,
    /// Where the time tags of the 5-104 command set come from. Required with
    /// [`CommandSet::Tagged`] unless every command carries its own.
    pub clock: Option<Clock>,
}

impl ClientConfig {
    /// A station at `common_address` with the conventional address sizes,
    /// clause 9's default link parameters, direct untagged commands with every
    /// family terminated, counter mode C and the default [`Timeouts`].
    #[must_use]
    pub fn new(common_address: u16) -> Self {
        Self {
            common_address,
            originator: 0,
            sizes: AddressSizes::CONVENTIONAL,
            link: LinkParams::default(),
            command_mode: CommandMode::Direct,
            command_set: CommandSet::Untagged,
            termination: Termination::All,
            counter_mode: CounterMode::FreezeAndTransmit,
            timeouts: Timeouts::default(),
            interrogate_on_start: true,
            retransmit_on_switchover: false,
            update_buffer: DEFAULT_UPDATE_BUFFER,
            trace: false,
            clock: None,
        }
    }
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("common_address", &self.common_address)
            .field("originator", &self.originator)
            .field("sizes", &self.sizes)
            .field("link", &self.link)
            .field("command_mode", &self.command_mode)
            .field("command_set", &self.command_set)
            .field("termination", &self.termination)
            .field("counter_mode", &self.counter_mode)
            .field("timeouts", &self.timeouts)
            .field("interrogate_on_start", &self.interrogate_on_start)
            .field("retransmit_on_switchover", &self.retransmit_on_switchover)
            .field("update_buffer", &self.update_buffer)
            .field("trace", &self.trace)
            .field("clock", &self.clock.as_ref().map(|_| "..."))
            .finish()
    }
}

/// How a command ended when it succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    /// The controlled station confirmed and then terminated it (`ACTTERM`).
    Terminated,
    /// The controlled station confirmed it, and the family is not terminated
    /// under the configured [`Termination`].
    Confirmed,
}

/// Something the station sent or the link did, for [`Client::subscribe`].
#[derive(Debug, Clone, PartialEq)]
pub enum Update {
    /// A monitor-direction ASDU, decoded.
    Data(Asdu),
    /// A monitor-direction ASDU that has no layout (a reserved or private type
    /// identification), as received.
    Undecodable {
        /// The ASDU's octets.
        asdu: Vec<u8>,
        /// Why it could not be decoded.
        error: LayoutError,
    },
    /// Data transfer runs: a connection is started (clause 5.3).
    Started,
    /// No connection is started any more.
    Stopped,
    /// Redundancy group: the started connection's t1 expired and the group
    /// moved on (104 cl.10.5).
    Switchover(Switchover),
    /// This many updates were dropped before this one because the
    /// subscriber's channel was full ([`ClientConfig::update_buffer`]): the
    /// subscriber read more slowly than the station sent.
    Lagged(u64),
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientError {
    /// No connection is started, so nothing was sent.
    NotStarted,
    /// The same thing is already outstanding; nothing was sent.
    Busy,
    /// The station confirmed negatively (`ACTCON` with `P/N = 1`). A refused
    /// command, select or execute, did not operate.
    Rejected,
    /// The station confirmed a command and then terminated it negatively
    /// (TS 60870-5-604 5.4.19.40: *"first accept the command with a Positive
    /// ACTCON and then send a Negative Termination"*).
    Failed,
    /// The station mirrored the request with one of the causes 44–47
    /// (5-101 cl.7.2.3): it has no such type, cause, common address or object.
    Refused {
        /// The cause of the mirror: 44, 45, 46 or 47.
        cause: Cause,
    },
    /// The station confirmed a select that is not the one sent. The execute
    /// was not sent (TS 60870-5-604 5.4.19.1).
    NotMirrored,
    /// [`Client::execute`] for an object whose confirmed select carries
    /// another command. TS 60870-5-604 Table 19: *"If the EXECUTE message
    /// from the Controlling does not contain exactly the same information as
    /// the SELECT message, then the Controlled mirrors the same ASDU with
    /// COT=7, `C_SC/DC/SE/RC_ACTCONneg`"*. Nothing was sent and the select is
    /// kept.
    SelectMismatch,
    /// No answer within the configured [`Timeouts`]. For a command, only a
    /// select ends this way; nothing operated.
    Timeout,
    /// The connection was lost before the answer. For a command, only a
    /// select ends this way; nothing operated.
    ConnectionLost,
    /// A command's execute, a reset process, or a parameter load, activation
    /// or deactivation was sent and its answer never came, by time-out or
    /// because the connection was lost. The station may or may not have
    /// acted on it; it was not sent again.
    OutcomeUnknown,
    /// [`CommandSet::Tagged`] with no [`ClientConfig::clock`] and a command
    /// without a time tag.
    NoClock,
    /// The interrogation was stopped by [`Client::stop_interrogation`] before
    /// its termination. TS 60870-5-604 5.4.17.50: after the `C_IC_DEACTCON`
    /// *"No further Information Objects that are part of the GI for that QOI
    /// are sent"* and no `ACTTERM` follows. What arrived before the stop was
    /// reported to the subscribers.
    Deactivated,
    /// The interrogation procedure refused the request.
    Interrogation(iec104::gi::GiError),
    /// The counter interrogation procedure refused the request.
    CounterInterrogation(ci::CiError),
    /// The command procedure refused the command.
    Command(iec104::ct::CtError),
    /// The clock synchronisation procedure refused the request.
    ClockSync(iec104::cs::CsError),
    /// The read procedure refused the request.
    Read(iec104::rd::RdError),
    /// The test procedure refused the request, or the confirmation did not
    /// echo it (`EchoMismatch`).
    Test(iec104::ts::TsError),
    /// The frame could not be built with the configured address sizes (a
    /// common address or originator they cannot carry).
    Layout(LayoutError),
    /// The parameter loading procedure refused the request.
    Parameter(iec104::pm::PmError),
    /// The station confirmed a parameter load negatively. `in_operation` is
    /// the parameter the confirmation carried: the old value, still in
    /// operation (5-101 cl.7.4.9, TS 60870-5-604 5.4.21.10).
    ParameterRejected {
        /// The parameter in operation, as the confirmation carried it.
        in_operation: Parameter,
    },
    /// The driver refused the frame or has stopped.
    Driver(Error),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => f.write_str("no connection is started"),
            Self::Busy => f.write_str("the same request is already outstanding"),
            Self::Rejected => f.write_str("the station confirmed negatively"),
            Self::Failed => f.write_str("the station terminated the command negatively"),
            Self::Refused { cause } => write!(
                f,
                "the station refused the request with cause {}",
                cause.to_u8()
            ),
            Self::NotMirrored => {
                f.write_str("the station confirmed a select other than the one sent")
            }
            Self::Timeout => f.write_str("no answer in time"),
            Self::ConnectionLost => f.write_str("the connection was lost"),
            Self::OutcomeUnknown => f.write_str(
                "the request was sent and not answered: it may or may not have taken effect",
            ),
            Self::SelectMismatch => f.write_str("the execute is not the command that was selected"),
            Self::NoClock => f.write_str("a time-tagged command needs a clock"),
            Self::Deactivated => f.write_str("the interrogation was stopped"),
            Self::Interrogation(e) => write!(f, "interrogation: {e:?}"),
            Self::CounterInterrogation(e) => write!(f, "counter interrogation: {e:?}"),
            Self::Command(e) => write!(f, "command: {e:?}"),
            Self::ClockSync(e) => write!(f, "clock synchronisation: {e:?}"),
            Self::Read(e) => write!(f, "read: {e:?}"),
            Self::Test(e) => write!(f, "test: {e:?}"),
            Self::Layout(e) => write!(f, "layout: {e:?}"),
            Self::Parameter(e) => write!(f, "parameter loading: {e:?}"),
            Self::ParameterRejected { in_operation } => write!(
                f,
                "the station refused the parameter; in operation: {in_operation:?}"
            ),
            Self::Driver(e) => write!(f, "driver: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<Error> for ClientError {
    fn from(e: Error) -> Self {
        Self::Driver(e)
    }
}

type Reply<T> = oneshot::Sender<Result<T, ClientError>>;

/// A request from a [`Client`] to its task.
enum Request {
    WaitStarted(Reply<()>),
    Subscribe(Reply<mpsc::Receiver<Update>>),
    Interrogate(Scope, Reply<Vec<Asdu>>),
    StopInterrogation(Scope, Reply<()>),
    Counter(ci::Request, FreezeMode, Reply<Vec<Asdu>>),
    Command(Command, Reply<CommandOutcome>),
    Select(Command, Reply<()>),
    Execute(Command, Reply<CommandOutcome>),
    Cancel(Command, Reply<()>),
    ClockSync(Cp56Time2a, Reply<()>),
    Read(u32, Reply<Asdu>),
    Test(Tsc, Cp56Time2a, Reply<()>),
    ResetProcess(Qrp, Reply<()>),
    /// The answer is the parameter now in operation for a load, `None` for
    /// an activation or a deactivation.
    Parameter(ParameterRequest, Parameter, Reply<Option<Parameter>>),
}

/// Which of the parameter requests of 104 cl.7.9 a call makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParameterRequest {
    /// `P_ME ACT`: load a parameter of measured values.
    Load,
    /// `P_AC ACT`: activate.
    Activate,
    /// `P_AC DEACT`: deactivate.
    Deactivate,
}

/// A controlling station for one controlled station. Cheap to clone; the
/// connection is closed when the last clone is dropped or
/// [`Client::shutdown`] is called.
#[derive(Clone)]
pub struct Client {
    requests: mpsc::Sender<Request>,
    handle: Handle,
}

impl Client {
    /// Dials the station through `connector` (connection 0), redialing every
    /// t0, and returns once data transfer runs. It waits as long as that
    /// takes: wrap it in [`tokio::time::timeout`] for a bound.
    ///
    /// # Errors
    ///
    /// As [`Client::spawn`], and [`ClientError::Driver`] when the client
    /// stops before a connection is started.
    pub async fn connect<K: Connector>(
        connector: K,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        let client = Self::spawn(connector, config)?;
        client.wait_started().await?;
        Ok(client)
    }

    /// [`Client::connect`] without the wait: the client dials in the
    /// background, and calls made before data transfer runs fail with
    /// [`ClientError::NotStarted`].
    ///
    /// # Errors
    ///
    /// [`ClientError::Driver`] when the link configuration builds no
    /// connection manager.
    pub fn spawn<K: Connector>(connector: K, config: ClientConfig) -> Result<Self, ClientError> {
        let manager =
            ConnectionManager::new(Role::Controlling, vec![StationConfig::new(config.link)])
                .map_err(|e| ClientError::Driver(Error::Manager(e)))?;
        let (handle, events) = master::spawn(manager, connector, options(&config))?;
        Ok(Self::start(handle, events, config, false, Vec::new()))
    }

    /// [`Client::spawn`] with a subscription that exists before the first
    /// dial, so no update is missed: not the start of the first connection,
    /// nor what the station sends at once, nor the answer to the
    /// interrogation on start ([`ClientConfig::interrogate_on_start`]).
    /// [`Client::subscribe`] after [`Client::spawn`] can miss them: the
    /// client dials as soon as it is spawned, and may be connected and
    /// answered before the subscription is in place.
    ///
    /// # Errors
    ///
    /// As [`Client::spawn`].
    pub fn spawn_subscribed<K: Connector>(
        connector: K,
        config: ClientConfig,
    ) -> Result<(Self, mpsc::Receiver<Update>), ClientError> {
        let manager =
            ConnectionManager::new(Role::Controlling, vec![StationConfig::new(config.link)])
                .map_err(|e| ClientError::Driver(Error::Manager(e)))?;
        let (handle, events) = master::spawn(manager, connector, options(&config))?;
        let (subscriber, receiver) = task::Subscriber::new(&config);
        Ok((
            Self::start(handle, events, config, false, vec![subscriber]),
            receiver,
        ))
    }

    /// Dials `members` connections to the one station through `connector`
    /// (connections `0..members`), as a redundancy group (104 clause 10), and
    /// returns once one of them is started.
    ///
    /// # Errors
    ///
    /// As [`Client::spawn_redundant`], and [`ClientError::Driver`] when the
    /// client stops before a connection is started.
    pub async fn connect_redundant<K: Connector>(
        connector: K,
        members: usize,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        let client = Self::spawn_redundant(connector, members, config)?;
        client.wait_started().await?;
        Ok(client)
    }

    /// [`Client::connect_redundant`] without the wait.
    ///
    /// # Errors
    ///
    /// [`ClientError::Driver`] when no redundancy group can be built of
    /// `members` connections (none, say).
    pub fn spawn_redundant<K: Connector>(
        connector: K,
        members: usize,
        config: ClientConfig,
    ) -> Result<Self, ClientError> {
        let group = RedundancyGroup::new(Role::Controlling, vec![config.link; members])
            .map_err(|e| ClientError::Driver(Error::Group(e)))?;
        let (handle, events) = master::spawn_redundant(group, connector, options(&config))?;
        Ok(Self::start(handle, events, config, true, Vec::new()))
    }

    fn start(
        handle: Handle,
        events: crate::Events,
        config: ClientConfig,
        group: bool,
        subscribers: Vec<task::Subscriber>,
    ) -> Self {
        let (requests, receiver) = mpsc::channel(64);
        tokio::spawn(task::run(
            handle.clone(),
            events,
            receiver,
            config,
            group,
            subscribers,
        ));
        Self { requests, handle }
    }

    async fn call<T>(&self, request: impl FnOnce(Reply<T>) -> Request) -> Result<T, ClientError> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .send(request(reply))
            .await
            .map_err(|_| ClientError::Driver(Error::Stopped))?;
        answer
            .await
            .map_err(|_| ClientError::Driver(Error::Stopped))?
    }

    /// Waits until a connection is started.
    ///
    /// # Errors
    ///
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn wait_started(&self) -> Result<(), ClientError> {
        self.call(Request::WaitStarted).await
    }

    /// Everything the station sends in the monitor direction, and the link's
    /// changes, from the moment this call returns: it returns once the
    /// client holds the subscription. The channel holds
    /// [`ClientConfig::update_buffer`] updates; the client never waits for a
    /// slow reader, so while the channel is full the updates for it are
    /// dropped and counted, and the next one that fits is preceded by
    /// [`Update::Lagged`] with the count. Read it steadily, or drop it. What
    /// happened before is not
    /// repeated; to see the client's first connection and its first answers,
    /// use [`Client::spawn_subscribed`].
    ///
    /// # Errors
    ///
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn subscribe(&self) -> Result<mpsc::Receiver<Update>, ClientError> {
        // Returns once the task holds the subscription, so whatever the
        // station sends after this call is in the channel.
        self.call(Request::Subscribe).await
    }

    /// A station or group interrogation (104 cl.7.5): every ASDU the station
    /// sent for `scope`, in order, once it terminated.
    ///
    /// # Errors
    ///
    /// The interrogation procedure's refusal ([`ClientError::Interrogation`]),
    /// the station's ([`ClientError::Rejected`], [`ClientError::Refused`]),
    /// [`ClientError::Deactivated`] after a stop, [`ClientError::Timeout`],
    /// [`ClientError::ConnectionLost`], [`ClientError::NotStarted`] when no
    /// connection is started, and
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn interrogate(&self, scope: Scope) -> Result<Vec<Asdu>, ClientError> {
        self.call(|reply| Request::Interrogate(scope, reply)).await
    }

    /// Stops the running interrogation of `scope` (TS 60870-5-604 5.4.17.50):
    /// *"The Controlling station sends an Interrogation Command with COT = 8,
    /// `C_IC_DEACT`"*, and the station answers with `C_IC_DEACTCON`. Returns at
    /// that answer; a negative one is [`ClientError::Rejected`]. Either way
    /// the waiting [`Client::interrogate`] calls end with
    /// [`ClientError::Deactivated`], since no termination follows.
    ///
    /// Only an interrogation this client runs can be stopped (its own on a new
    /// started connection included): another scope is
    /// [`ClientError::Interrogation`] (`NotRunning`), without sending. A stop
    /// that got no answer ends with [`ClientError::Timeout`] and leaves the
    /// interrogation running until its termination or its own time-out.
    ///
    /// # Errors
    ///
    /// As described above, [`ClientError::NotStarted`] when no connection is
    /// started, and [`ClientError::Driver`] once the client has stopped.
    pub async fn stop_interrogation(&self, scope: Scope) -> Result<(), ClientError> {
        self.call(|reply| Request::StopInterrogation(scope, reply))
            .await
    }

    /// A counter interrogation (104 cl.7.8). With [`FreezeMode::Read`], the
    /// integrated totals the station sent, once it terminated; with a freeze
    /// or reset, nothing, once it confirmed (5-101 figure 95: the memorize has
    /// no data and no termination).
    ///
    /// # Errors
    ///
    /// The procedure's refusal ([`ClientError::CounterInterrogation`],
    /// [`ClientError::Busy`]), the station's ([`ClientError::Rejected`],
    /// [`ClientError::Refused`]), [`ClientError::Timeout`], [`ClientError::ConnectionLost`],
    /// [`ClientError::NotStarted`] when no connection is started, and
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn counter_interrogate(
        &self,
        request: ci::Request,
        freeze: FreezeMode,
    ) -> Result<Vec<Asdu>, ClientError> {
        self.call(|reply| Request::Counter(request, freeze, reply))
            .await
    }

    /// A command (104 cl.7.7). With [`CommandMode::SelectAndExecute`] the
    /// client selects first and executes once the select is confirmed. See
    /// the module documentation for what a lost answer means.
    ///
    /// # Errors
    ///
    /// The procedure's refusal ([`ClientError::Command`],
    /// [`ClientError::NoClock`], [`ClientError::Busy`]), the station's
    /// ([`ClientError::Rejected`], [`ClientError::Refused`], [`ClientError::NotMirrored`],
    /// [`ClientError::Failed`]), an answer that did not come
    /// ([`ClientError::Timeout`], [`ClientError::ConnectionLost`],
    /// [`ClientError::OutcomeUnknown`]), [`ClientError::NotStarted`] when no
    /// connection is started, and
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn command(&self, command: Command) -> Result<CommandOutcome, ClientError> {
        self.call(|reply| Request::Command(command, reply)).await
    }

    /// Only the select of a command (TS 60870-5-604 5.4.19.1): returns once
    /// the station confirmed it, and sends nothing more. The operator then
    /// confirms with [`Client::execute`] or withdraws with [`Client::cancel`].
    ///
    /// Needs [`CommandMode::SelectAndExecute`]; under
    /// [`CommandMode::Direct`] it fails with [`ClientError::Command`]
    /// (`SelectNotAllowed`), as does a family without a select (the
    /// bitstring). A select that got no answer operated nothing and ends with
    /// [`ClientError::Timeout`] or [`ClientError::ConnectionLost`]. The
    /// confirmed select is kept until the execute, the cancel or the loss of
    /// the connection; the station's own select time-out (TS 60870-5-604
    /// 5.4.19.40) is not known to the client, and an execute after it is
    /// refused by the station ([`ClientError::Rejected`]).
    ///
    /// # Errors
    ///
    /// As described above, and as [`Client::command`].
    pub async fn select(&self, command: Command) -> Result<(), ClientError> {
        self.call(|reply| Request::Select(command, reply)).await
    }

    /// The execute of a command selected with [`Client::select`] (TS
    /// 60870-5-604 5.4.19.1), ending like [`Client::command`]: at the
    /// termination, or the confirmation where the family is not terminated.
    ///
    /// `command` must be the selected one: another value is refused with
    /// [`ClientError::SelectMismatch`] and an object with no confirmed select
    /// with [`ClientError::Command`] (`ExecuteWithoutSelect`), both without
    /// sending. Under [`CommandMode::Direct`], and for a family without a
    /// select, it is a direct execute. An execute that went out unanswered
    /// ends with [`ClientError::OutcomeUnknown`] and is not sent again.
    ///
    /// # Errors
    ///
    /// As described above, and as [`Client::command`].
    pub async fn execute(&self, command: Command) -> Result<CommandOutcome, ClientError> {
        self.call(|reply| Request::Execute(command, reply)).await
    }

    /// Withdraws a select confirmed by [`Client::select`]: the deactivation
    /// of TS 60870-5-604 5.4.19.10, *"The Controlling station sends the same
    /// Command message with COT=8, `C_SC/DC/SE/RC_DEACT`, and S/E=1 (SELECT)"*.
    /// Returns at the station's `DEACTCON`; a negative one is
    /// [`ClientError::Rejected`].
    ///
    /// Either way, and also when the answer does not come, the select is gone
    /// on this side: an execute after a cancel is refused without sending.
    ///
    /// # Errors
    ///
    /// A negative `DEACTCON` ([`ClientError::Rejected`]), and otherwise as
    /// [`Client::command`].
    pub async fn cancel(&self, command: Command) -> Result<(), ClientError> {
        self.call(|reply| Request::Cancel(command, reply)).await
    }

    /// A clock synchronisation (104 cl.7.6) with `time`, the controlling
    /// station's time now, for instance
    /// `Cp56Time2a::from_system_time(SystemTime::now())`.
    ///
    /// # Errors
    ///
    /// The procedure's refusal ([`ClientError::ClockSync`],
    /// [`ClientError::Busy`]), the station's
    /// ([`ClientError::Rejected`], [`ClientError::Refused`]),
    /// [`ClientError::Timeout`], [`ClientError::ConnectionLost`],
    /// [`ClientError::NotStarted`] when no connection is started, and
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn sync_clock(&self, time: Cp56Time2a) -> Result<(), ClientError> {
        self.call(|reply| Request::ClockSync(time, reply)).await
    }

    /// Reads one object (104 cl.7.2).
    ///
    /// # Errors
    ///
    /// The procedure's refusal ([`ClientError::Read`]), the station's
    /// ([`ClientError::Refused`]), [`ClientError::Timeout`],
    /// [`ClientError::ConnectionLost`], [`ClientError::NotStarted`] when no
    /// connection is started, and
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn read(&self, ioa: u32) -> Result<Asdu, ClientError> {
        self.call(|reply| Request::Read(ioa, reply)).await
    }

    /// The test procedure (104 cl.7.10) with `C_TS_TA_1` `<107>`, the form
    /// 104 Table 4 carries: `tsc` and `time` are the caller's (104 cl.8.8,
    /// *"The requesting station may choose any value of TSC"*). Returns at
    /// the `ACTCON`, which must echo both: *"The TSC in the response shall
    /// match the request, and the time in the response shall also exactly
    /// match the time in the request."* A confirmation that does not is
    /// [`ClientError::Test`] (`EchoMismatch`), TS 60870-5-604 5.4.22.1's
    /// *"Mismatching values of TSC are detected by the Primary station"*.
    ///
    /// One test runs at a time; a second is [`ClientError::Busy`].
    ///
    /// # Errors
    ///
    /// As described above, [`ClientError::Rejected`],
    /// [`ClientError::Timeout`], [`ClientError::ConnectionLost`],
    /// [`ClientError::NotStarted`] when no connection is started, and
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn test(&self, tsc: Tsc, time: Cp56Time2a) -> Result<(), ClientError> {
        self.call(|reply| Request::Test(tsc, time, reply)).await
    }

    /// The reset process command `C_RP_NA_1` `<105>` (5-101 cl.7.3.4.6,
    /// figure 77: address 0, the qualifier `QRP` of cl.7.2.6.27, cause 6).
    /// Returns at the `ACTCON`; a negative one is [`ClientError::Rejected`],
    /// a 44–47 mirror [`ClientError::Refused`]. The qualifier travels as
    /// given: `<1>` general reset of process, `<2>` reset of pending
    /// information with time tag.
    ///
    /// 104 cl.7.1, figure 22: the station *"confirms back the `Reset_Process`
    /// and gives an active close call to its TCP"*, and the controlling
    /// station *"tries to connect the controlled station by giving cyclic
    /// active opens"*. The client does that on its own (every t0) and, with
    /// [`ClientConfig::interrogate_on_start`], interrogates the station once
    /// it is started again. A reset that got no answer may or may not have
    /// happened: it ends with [`ClientError::OutcomeUnknown`] and is not sent
    /// again.
    ///
    /// # Errors
    ///
    /// As described above, [`ClientError::Layout`] when the frame cannot be
    /// built, [`ClientError::Busy`] while a reset is outstanding,
    /// [`ClientError::NotStarted`] when no connection is started, and
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn reset_process(&self, qrp: Qrp) -> Result<(), ClientError> {
        self.call(|reply| Request::ResetProcess(qrp, reply)).await
    }

    /// Loads a parameter of measured values (104 cl.7.9, `P_ME ACT`, types
    /// 110–112) and returns the parameter now in operation, read from the
    /// `P_ME ACTCON`. 5-101 cl.7.4.9: *"In either case (positive or negative
    /// acceptance), the parameter value returned in the ASDU `P_ME` ACTCON is
    /// the value (new or old) of the parameter now in operation."* A negative
    /// confirmation is therefore [`ClientError::ParameterRejected`] with the
    /// old value.
    ///
    /// The core refuses what the standard does not let a station send
    /// ([`ClientError::Parameter`]): a `QPM` with `LPC` or `POP` set or an
    /// unused `KPA` (cl.7.2.6.24), a `P_AC` value. One request per parameter
    /// at a time. A load that got no answer may or may not be in operation:
    /// it ends with [`ClientError::OutcomeUnknown`] and is not sent again.
    ///
    /// # Errors
    ///
    /// As described above, [`ClientError::Busy`] while the parameter has a
    /// request outstanding, [`ClientError::Refused`],
    /// [`ClientError::NotStarted`] when no connection is started, and
    /// [`ClientError::Driver`] once the client has stopped.
    pub async fn load_parameter(&self, parameter: Parameter) -> Result<Parameter, ClientError> {
        self.call(|reply| Request::Parameter(ParameterRequest::Load, parameter, reply))
            .await
            .map(|loaded| loaded.unwrap_or(parameter))
    }

    /// Activates a parameter (104 cl.7.9, `P_AC ACT`, `P_AC_NA_1` `<113>`
    /// with its `QPA`) and returns at the `ACTCON`; a negative one is
    /// [`ClientError::Rejected`]. 5-101 cl.7.4.9 selects `QPA` `<3>`
    /// (act/deact of persistent cyclic or periodic transmission of the
    /// addressed object); the core refuses `<0>`–`<2>` and `<4>`–`<127>`
    /// ([`ClientError::Parameter`]). An activation that got no answer ends
    /// with [`ClientError::OutcomeUnknown`] and is not sent again.
    ///
    /// # Errors
    ///
    /// As [`Client::load_parameter`], with [`ClientError::Rejected`] for a
    /// negative confirmation.
    pub async fn activate_parameter(&self, parameter: Parameter) -> Result<(), ClientError> {
        self.call(|reply| Request::Parameter(ParameterRequest::Activate, parameter, reply))
            .await
            .map(|_| ())
    }

    /// Deactivates a parameter (`P_AC_NA_1` with cause 8, 5-101 figure 82)
    /// and returns at the `DEACTCON` (cause 9); a negative one is
    /// [`ClientError::Rejected`]. Otherwise as [`Client::activate_parameter`].
    ///
    /// # Errors
    ///
    /// As [`Client::activate_parameter`].
    pub async fn deactivate_parameter(&self, parameter: Parameter) -> Result<(), ClientError> {
        self.call(|reply| Request::Parameter(ParameterRequest::Deactivate, parameter, reply))
            .await
            .map(|_| ())
    }

    /// The driver underneath, for what the client does not cover.
    #[must_use]
    pub const fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Closes every connection and stops the client. Outstanding calls end
    /// with [`ClientError::Driver`].
    pub async fn shutdown(&self) {
        self.handle.shutdown().await;
    }
}

const fn options(config: &ClientConfig) -> Options {
    Options {
        auto_start: true,
        trace: config.trace,
        sizes: config.sizes,
    }
}
