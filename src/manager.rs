//! The connection manager: several stations at once, each with its own
//! parameters, its own interoperability profile and its own connection, and
//! the t0-driven retry that keeps them connected.
//!
//! # What the standard says
//!
//! IEC 60870-5-104:2006 defines no connection manager; it defines where the
//! decisions live. Clause 7.1 (page index 54, printed page 53) is the
//! establishment sentence:
//!
//! > Connection establishment is performed by the controlling station in case of
//! > a controlled station as a partner; a fixed selection (parameter) in the case
//! > of two equivalent controlling stations or partners (see figure 1).
//!
//! The retry is on the same page, in figure 21's own description:
//!
//! > Figure 21 shows the controlling station repeatedly attempting to establish a
//! > connection with a controlled station. These attempts fail until the
//! > controlled station has performed a local initialization and given a passive
//! > open call to its TCP which has then acquired the listen status (status not
//! > shown in the figure).
//!
//! Its timer is clause 9's row (index 114, printed 113), `t0  30 s Time-out of
//! connection establishment`, and figure 33 (index 126, printed 125) draws
//! `Timeout t0` on each `active open`. Clause 10.5 (index 128, printed 127)
//! states that the retry never gives up:
//!
//! > The failed connection is eventually closed by both sides, and reopening is
//! > regularly retried by the controlling station until the error has been
//! > corrected and the connection is re-established.
//!
//! Clause 10.7 (index 136, printed 135) is why every station carries its own
//! scheduler:
//!
//! > It should be possible to set the values of the timers t0 to t3 individually
//! > for each connection within a redundancy group.
//!
//! # What this module adds
//!
//! [`ConnectionManager`] holds N [`Station`]s. A station is the label the caller
//! gave it, its [`LinkParams`], optionally its clause 9 [`InteropProfile`]
//! (carried, not consulted), and one connection: a [`Session`] and its
//! [`Timers`], the same pairing [`crate::redundancy::Member`] uses. A station of
//! this manager has exactly one connection. N redundant connections to one
//! station (clause 10) are a [`crate::redundancy::RedundancyGroup`], not a
//! manager.
//!
//! **The retry policy.** The standard gives the timer and the never-give-up
//! sentence and nothing about a queue, a backoff or a maximum, so the manager
//! uses the simplest policy faithful to those two: **one attempt per station
//! per t0 expiry, no backoff, no attempt limit, and no queue of pending user
//! data beyond the clause 5.3 queue each session already owns.** A station of a
//! controlling manager that has no TCP connection, and whose t0 has expired or
//! was never armed, is asked for a new connection on the next
//! [`ConnectionManager::tick`]. The attempt counter labels the directive and is
//! never a limit.
//!
//! Three consequences of that policy:
//!
//! - **Only a controlling manager dials.** Clause 7.1's other half (index 54,
//!   printed 53) is *"The controlling station is equivalent to the client
//!   (connector), the controlled station to the server (listener)."* A
//!   [`Role::Controlled`] manager therefore never emits [`Directive::Connect`]
//!   and never arms t0: its stations wait for the caller's own accept, reported
//!   through [`ConnectionManager::on_connection_established`].
//! - **A refused dial keeps the attempt's t0.** Figure 21's peer refuses *every*
//!   dial until it listens, so a caller that reports the refusal and polls
//!   faster than t0 still gets one attempt per t0 expiry.
//! - **A lost connection is dialed again when its attempt's t0 runs out.** A
//!   connection that lasted longer than t0 is dialed again at once (clause
//!   10.5's *"reopening is regularly retried"*); one lost sooner waits for the
//!   rest of that t0. A peer that takes every connection and closes it at once
//!   so gets one attempt per t0, as a peer that refuses them does, and not one
//!   per round trip.
//! - **`reason` tells the attempts apart.** [`ConnectReason::ConnectionLost`]
//!   marks only the first attempt after an established connection was lost
//!   (clause 10.5's reopening). The attempts after it are figure 21's repeats:
//!   [`ConnectReason::AttemptFailed`] after a reported refusal, or
//!   [`ConnectReason::AttemptTimedOut`] when the previous attempt was still
//!   unanswered at its t0 expiry.
//!
//! **The output is directives, never sockets.** A [`Directive`] names a station
//! and says what to do with it: [`Directive::Connect`] for an attempt (clause
//! 7.1's establishment is the caller's socket) and [`Directive::Actions`] for
//! the action list that station's own session produced. `tick` is where the
//! caller's clock enters; the other methods are where the caller's events
//! enter. Nothing here opens, reads or writes a socket, reads a clock, spawns a
//! thread or holds a `static`.
//!
//! # The timer wiring
//!
//! [`Session`] reacts to a [`Timer`] it is handed, and [`Timers`] decides when
//! that expiry is due. Keeping the two in step is otherwise the caller's job
//! (the event table in `crate::timers`' module doc), which is easy to get wrong
//! with several stations, so the manager applies those events itself, per
//! station, through [`Supervisor`]:
//!
//! | Event | Applied |
//! | --- | --- |
//! | an attempt is asked for (controlling only) | [`Timers::connection_attempt`] (arm t0) |
//! | the caller's socket came up | [`Session::on_connection_established`], then [`Timers::connection_lost`] and [`Timers::connection_established`] (cancel t0 to t3, arm t3) |
//! | an *established* connection went away | [`Session::on_connection_lost`] and [`Timers::connection_lost`] (cancel t0–t3) |
//! | any frame arrived | [`Timers::frame_received`] (clause 5.2's t3 retrigger) |
//! | an I-frame arrived | [`Timers::i_frame_received`] (arm t2) |
//! | a sent U-frame *act* or I-frame was handed out | [`Timers::frame_sent`] (arm t1) |
//! | an S-frame or an I-frame was handed out | [`Timers::acknowledgement_sent`] (cancel t2) |
//! | nothing awaits confirmation any more | [`Timers::confirmation_received`] (cancel t1) |
//! | an acknowledgement advanced the send buffer | [`Timers::confirmation_received`] then [`Timers::frame_sent`] (t1 moves to the frame that is now the oldest unconfirmed one) |
//! | the caller's clock advanced | [`Timers::expired`], then [`Session::on_timeout`] per due timer |
//!
//! The manager hands out exactly the action lists the session produced, and the
//! caller is expected to perform every one of them: that is what makes the
//! t1/t2 above honest. Three consequences of the table:
//!
//! - **A `con` is never supervised by t1.** STARTDT con, STOPDT con and TESTFR
//!   con confirm; nothing confirms them, so arming t1 for one would actively
//!   close a live peer ([`Timers::frame_sent`]'s own note). Only the three
//!   U-function *acts* and I-frames arm t1.
//! - **A station whose session reached [`State::Terminated`] produces no further
//!   expiry reactions**, because figures 17/18's `Connection terminated` is
//!   final. The caller closes its own socket and reports the loss with
//!   [`ConnectionManager::on_connection_lost`], which is what starts the next
//!   attempt.
//! - **t1 follows the *oldest* unconfirmed frame.** Figures 17/18 NOTE 2 make t1
//!   *"the timeout of a sent U-frame or I-frame"*, singular. An acknowledgement
//!   that advances the clause 5.1 send buffer while frames remain re-arms t1
//!   from the instant of the acknowledgement (or from when a still pending act
//!   was sent). A peer that confirms every frame shortly after it arrives is
//!   therefore never closed, while a peer that stops confirming is closed one
//!   t1 after the last progress.
//!
//! A caller that drives a station's session and scheduler by hand, through
//! [`Station::session_mut`] and [`Station::timers_mut`], owns the wiring again.
//!
//! # What the caller still owns
//!
//! The socket (this crate holds no TCP), the loop that decides when to call
//! `tick`, the process image, whether a station is used at all, and the use of
//! the [`InteropProfile`] in decisions: the manager carries the profile so that
//! the station table has one home, and consults nothing in it. The profile
//! reaches the receiver's decision through
//! [`crate::asdu::Known::for_profile`] and nowhere else.
//!
//! # Pairing the manager with a caller's loop
//!
//! ```
//! use iec104::link::Role;
//! use iec104::manager::{ConnectReason, ConnectionManager, Directive, StationConfig};
//! use iec104::params::LinkParams;
//! use std::time::Instant;
//!
//! let start = Instant::now();
//! let mut manager = ConnectionManager::new(
//!     Role::Controlling,
//!     vec![StationConfig::new(LinkParams::default()).with_label("station 1")],
//! )
//! .unwrap();
//!
//! // Nothing has tried to connect yet: the first tick asks for the socket.
//! match manager.tick(start).as_slice() {
//!     [Directive::Connect { station: 0, attempt: 1, reason: ConnectReason::FirstAttempt }] => {}
//!     other => panic!("unexpected directives: {other:?}"),
//! }
//!
//! // The caller's socket came up, and the caller starts the data transfer.
//! manager.on_connection_established(0, start).unwrap();
//! for directive in manager.request_start(0, start).unwrap() {
//!     let _ = directive; // ... and put the STARTDT act on the wire
//! }
//! ```

use std::time::Instant;

use crate::apci::{Apci, ParseError};
use crate::interop::InteropProfile;
use crate::link::{Action, QueueError, Role, Session, State, Timer};
use crate::params::{LinkParams, ParamError};
use crate::timers::{Supervision, Supervisor, Timers};

/// One station as the caller configures it, before its connection exists.
///
/// The `params` are the station's own [`LinkParams`] (clause 10.7 asks for t0
/// to t3 per connection), so a station that shares the defaults shares them
/// because the caller passed them. The `profile` is the station's clause 9
/// [`InteropProfile`], carried for the station's table entry and never
/// consulted by this module.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StationConfig {
    /// What the caller calls this station. `None` is the station's index.
    pub label: Option<String>,
    /// The station's link parameters: its port, its k/w and its t0–t3.
    pub params: LinkParams,
    /// The station's clause 9 interoperability profile, if it has one.
    pub profile: Option<InteropProfile>,
}

impl StationConfig {
    /// A station with these parameters, no label and no profile.
    #[must_use]
    pub const fn new(params: LinkParams) -> Self {
        Self {
            label: None,
            params,
            profile: None,
        }
    }

    /// The same station, labelled.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// The same station, carrying this clause 9 profile.
    #[must_use]
    pub const fn with_profile(mut self, profile: InteropProfile) -> Self {
        self.profile = Some(profile);
        self
    }
}

/// One station of a [`ConnectionManager`]: its configuration plus the one
/// connection it owns.
///
/// The connection is the crate's usual pair, a [`Session`] and the [`Timers`]
/// built from the same [`LinkParams`]. The station's own bookkeeping is what
/// the manager needs to name the next attempt: whether a TCP connection is up,
/// whether an established one was lost, whether an attempt is in flight, and
/// how many attempts have been started.
#[derive(Debug)]
pub struct Station {
    label: Option<String>,
    profile: Option<InteropProfile>,
    session: Session,
    timers: Timers,
    /// True between `on_connection_established` and `on_connection_lost`: the
    /// caller's socket is up. The manager never opens one, so this is what the
    /// caller told it ([`ConnectionManager::on_connection_established`]).
    connected: bool,
    /// True from the loss of an *established* connection until the next attempt is
    /// started. It tells clause 10.5's reopening after a real loss from figure
    /// 21's repeated attempt, which is what the retry's `reason` reports. A
    /// failed attempt reported by the caller never sets it.
    lost: bool,
    /// How many attempts have been started. A label, never a limit (the standard
    /// sets none: *"reopening is regularly retried by the controlling station
    /// until the error has been corrected"*, index 128).
    attempts: u32,
    /// True from the start of an attempt until the caller reports its outcome
    /// (established, or a refused dial): an attempt still unanswered when its
    /// t0 expires is still in flight, and the caller must abandon it
    /// ([`ConnectReason::AttemptTimedOut`]).
    dialing: bool,
    /// When the latest attempt began: a connection lost within its t0 is
    /// dialed again when that t0 runs out, not at once.
    attempt_began: Option<Instant>,
    /// The timer wiring of this station's connection.
    supervisor: Supervisor,
}

impl Station {
    /// Builds the station of a validated configuration. Private: the parameters
    /// are the manager's to validate once, so that a station cannot exist with a
    /// parameter set the standard's ranges reject.
    fn from_config(role: Role, config: StationConfig) -> Result<Self, ParamError> {
        Ok(Self {
            label: config.label,
            profile: config.profile,
            // One validation, two values: the session and its scheduler must come
            // from one parameter set (clauses 5.5 and 9, `LinkParams::validate`).
            session: Session::with_params(role, config.params)?,
            timers: Timers::new(config.params)?,
            connected: false,
            lost: false,
            attempts: 0,
            dialing: false,
            attempt_began: None,
            supervisor: Supervisor::default(),
        })
    }

    /// What the caller calls this station, or `None` for "the index".
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// The station's link parameters.
    #[must_use]
    pub const fn params(&self) -> &LinkParams {
        self.timers.params()
    }

    /// The station's clause 9 interoperability profile, if the caller gave it
    /// one. The manager reads nothing in it.
    #[must_use]
    pub const fn profile(&self) -> Option<&InteropProfile> {
        self.profile.as_ref()
    }

    /// This station's connection: clause 5.1/5.2/5.3's state machine.
    #[must_use]
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// The connection, for a caller that drives it by hand. Doing so bypasses
    /// the timer wiring of the module doc.
    pub const fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// This station's t0–t3 scheduler.
    #[must_use]
    pub const fn timers(&self) -> &Timers {
        &self.timers
    }

    /// The scheduler, for a caller that drives it by hand. Doing so bypasses
    /// the timer wiring of the module doc.
    pub const fn timers_mut(&mut self) -> &mut Timers {
        &mut self.timers
    }

    /// The connection state of this station (figures 17/18's boxes).
    #[must_use]
    pub const fn state(&self) -> State {
        self.session.state()
    }

    /// True while the caller says this station's TCP connection is up.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    /// How many connection attempts have been started for this station. The
    /// standard sets no maximum; the number is reported by
    /// [`Directive::Connect`] and read here.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Why the next attempt is being asked for: the first one, the first one
    /// after an established connection was lost (clause 10.5's reopening), or one
    /// of figure 21's repeated attempts, after a refusal or after an attempt
    /// that is still unanswered. Only the attempt right after a real loss
    /// reports [`ConnectReason::ConnectionLost`].
    const fn attempt_reason(&self) -> ConnectReason {
        if self.attempts == 0 {
            ConnectReason::FirstAttempt
        } else if self.lost {
            ConnectReason::ConnectionLost
        } else if self.dialing {
            ConnectReason::AttemptTimedOut
        } else {
            ConnectReason::AttemptFailed
        }
    }

    /// Starts one attempt: arm t0 (clause 9's *"Time-out of connection
    /// establishment"*, figure 33's per-`active open` `Timeout t0`) and count it.
    /// The attempt consumes the loss it answers: the *next* retry is figure 21's
    /// repeat again, not a second reopening.
    fn begin_attempt(&mut self, now: Instant) -> u32 {
        self.attempts = self.attempts.saturating_add(1);
        self.lost = false;
        self.dialing = true;
        self.attempt_began = Some(now);
        self.timers.connection_attempt(now);
        self.attempts
    }

    /// What t1 supervises for this station right now (the unconfirmed I-frames
    /// and a pending act of ours), and what an event's own acknowledgement
    /// progress is measured against.
    fn supervision(&self) -> Supervision {
        Supervision::of(&self.session)
    }

    /// Keeps this station's scheduler in step with an action list the caller is
    /// about to perform ([`Supervisor::apply`]).
    fn apply_timers(&mut self, now: Instant, actions: &[Action], before: Supervision) {
        self.supervisor
            .apply(&mut self.timers, &self.session, now, actions, before);
    }
}

/// What the caller must do, for one station.
///
/// A directive always names its station by index (the position in
/// [`ConnectionManager::stations`]), and the two variants are the module's whole
/// vocabulary: open a socket, or perform an action list on the connection that
/// socket carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    /// Open a TCP connection to this station (clause 7.1's establishment, which
    /// the caller's socket performs) and tell the manager with
    /// [`ConnectionManager::on_connection_established`] when it is up.
    ///
    /// An attempt that is never established is reported by the caller or is
    /// noticed when the attempt's t0 expires; either way a station without a
    /// connection produces another `Connect` on a later tick. Only a controlling
    /// manager emits this directive at all: clause 7.1 makes the controlled
    /// station the *listener*, so its connection is the caller's accept and never
    /// this request.
    Connect {
        /// The station's index in [`ConnectionManager::stations`].
        station: usize,
        /// Which attempt this is for that station, 1 for the first. A label, not
        /// a limit: the standard sets none.
        attempt: u32,
        /// Why the attempt is being asked for.
        reason: ConnectReason,
    },
    /// Perform these actions on this station's connection, in order: put the
    /// frames on the wire, hand `DeliverData`'s ASDU to the application, close
    /// the socket on an [`Action::ActiveClose`].
    Actions {
        /// The station's index in [`ConnectionManager::stations`].
        station: usize,
        /// Exactly what the station's session returned for the event, in order.
        actions: Vec<Action>,
    },
}

/// Why a station is being asked for a connection, as
/// [`Directive::Connect`] reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectReason {
    /// No attempt has been started for this station yet (clause 7.1's
    /// *"Connection establishment is performed by the controlling station"*).
    FirstAttempt,
    /// An earlier attempt was refused (reported through
    /// [`ConnectionManager::on_connection_lost`]) and its t0 has expired:
    /// figure 21's repeated attempts (index 54).
    AttemptFailed,
    /// The previous attempt is still unanswered when its t0 expired: the
    /// caller has reported neither a connection nor a refusal. **Abandon that
    /// attempt** (close the socket still connecting) before dialing this
    /// one, or a slow first dial can complete after the second has started
    /// and leave two connections to one station.
    AttemptTimedOut,
    /// A connection that had been established was lost, and clause 10.5's
    /// *"reopening is regularly retried"* applies (index 128). This is the first
    /// attempt after the loss only: the attempts after it are
    /// [`ConnectReason::AttemptFailed`] or [`ConnectReason::AttemptTimedOut`].
    ConnectionLost,
}

/// Why the manager refused a call. Every variant names the rule, and the
/// parameter refusal is the layers' own [`ParamError`] passed through rather
/// than re-invented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagerError {
    /// A manager of zero stations manages nothing: there is no station to ask
    /// for a connection. This is the crate's own refusal (the standard defines
    /// no manager at all) and the counterpart of
    /// [`crate::redundancy::GroupError::NoMembers`].
    NoStations,
    /// The index names no station of this manager.
    StationIndexOutOfRange {
        /// The index the caller used.
        index: usize,
        /// How many stations the manager has.
        stations: usize,
    },
    /// One station's parameters are not admissible: the same [`ParamError`]
    /// [`Session::with_params`] and [`Timers::new`] report, for the station whose
    /// configuration carried them.
    Params {
        /// The index of the station whose parameters were refused.
        station: usize,
        /// What was wrong with them.
        error: ParamError,
    },
    /// The connection refused the ASDU: see [`QueueError`]. A terminated station
    /// cannot carry one, a full queue takes no more ([`QueueError::Full`]), and
    /// the manager holds no queue of its own.
    Queue {
        /// The index of the station whose connection refused the data.
        station: usize,
        /// The session's own refusal.
        error: QueueError,
    },
}

/// Several stations, each with its own parameters, its own profile and its own
/// connection.
///
/// The manager owns its stations and the retry policy of the module doc. It holds
/// no socket, no clock, no thread and no `static`; the caller's socket state
/// arrives through [`ConnectionManager::on_connection_established`] and
/// [`ConnectionManager::on_connection_lost`], and its clock through
/// [`ConnectionManager::tick`].
#[derive(Debug)]
pub struct ConnectionManager {
    role: Role,
    stations: Vec<Station>,
}

impl ConnectionManager {
    /// A manager of one station per configuration, all in one role. Clause 7.1
    /// makes the role a property of the connection (client or server), so a
    /// manager is one role's station table, as a
    /// [`crate::redundancy::RedundancyGroup`] is.
    ///
    /// Every station's parameters are validated once, by
    /// [`Session::with_params`] and [`Timers::new`]: the first station whose set
    /// the standard's ranges reject is [`ManagerError::Params`], and no station
    /// exists with a parameter set nobody checked. An empty list is
    /// [`ManagerError::NoStations`].
    ///
    /// # Errors
    ///
    /// [`ManagerError::NoStations`] for an empty list, and
    /// [`ManagerError::Params`] for the first station whose parameters are
    /// inadmissible.
    pub fn new(role: Role, stations: Vec<StationConfig>) -> Result<Self, ManagerError> {
        if stations.is_empty() {
            return Err(ManagerError::NoStations);
        }
        let stations = stations
            .into_iter()
            .enumerate()
            .map(|(index, config)| {
                Station::from_config(role, config).map_err(|error| ManagerError::Params {
                    station: index,
                    error,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { role, stations })
    }

    /// A manager of `count` stations that share one configuration.
    ///
    /// # Errors
    ///
    /// As [`ConnectionManager::new`], so [`ManagerError::NoStations`] when
    /// `count` is zero.
    pub fn uniform(role: Role, config: StationConfig, count: usize) -> Result<Self, ManagerError> {
        Self::new(role, vec![config; count])
    }

    /// The role of every station of this manager.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// How many stations the manager holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.stations.len()
    }

    /// False for every constructed manager: an empty station list is refused by
    /// [`ConnectionManager::new`] rather than built.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.stations.is_empty()
    }

    /// The stations, in index order.
    #[must_use]
    pub fn stations(&self) -> &[Station] {
        &self.stations
    }

    /// One station, or [`ManagerError::StationIndexOutOfRange`].
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn station(&self, index: usize) -> Result<&Station, ManagerError> {
        let stations = self.stations.len();
        self.stations
            .get(index)
            .ok_or(ManagerError::StationIndexOutOfRange { index, stations })
    }

    /// One station, mutably, or [`ManagerError::StationIndexOutOfRange`].
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn station_mut(&mut self, index: usize) -> Result<&mut Station, ManagerError> {
        let stations = self.stations.len();
        self.stations
            .get_mut(index)
            .ok_or(ManagerError::StationIndexOutOfRange { index, stations })
    }

    /// What the caller must do now, in station order: the manager's clock.
    ///
    /// Two things happen here, per station:
    ///
    /// - **A station of a controlling manager whose TCP connection is down is
    ///   asked for one** when its t0 has expired or when nothing is armed at all:
    ///   the first attempt of clause 7.1, figure 21's repeated attempt after a
    ///   failure, or clause 10.5's reopening after a loss. One attempt per station
    ///   per tick, never two, and the retry has no limit. A manager of
    ///   [`Role::Controlled`] asks for nothing here: clause 7.1 makes that station
    ///   the *listener*, and its connection arrives through
    ///   [`ConnectionManager::on_connection_established`] only.
    /// - **A station with a TCP connection has its due timers reacted to**: each
    ///   expiry from [`Timers::expired`] goes to [`Session::on_timeout`] and its
    ///   action list out as one [`Directive::Actions`]. A connection whose session
    ///   already reached [`State::Terminated`] produces nothing: figures 17/18's
    ///   `Connection terminated` is final, and closing the caller's socket is what
    ///   the `ActiveClose` action already asked for.
    ///
    /// Call it as often as the caller likes with whatever `now` it has: the
    /// scheduler reports each expiry once, so a late poll reports one expiry and
    /// never a burst.
    pub fn tick(&mut self, now: Instant) -> Vec<Directive> {
        let mut directives = Vec::new();
        let controlling = self.role == Role::Controlling;
        for (index, station) in self.stations.iter_mut().enumerate() {
            if !station.connected {
                if !controlling {
                    // Clause 7.1: *"the controlled station to the server
                    // (listener)"*. Nothing to dial: its connection is the
                    // caller's accept, not this manager's request.
                    continue;
                }
                // One attempt at a time: while an attempt is in flight and its t0
                // has not expired there is nothing to ask for (figure 21's
                // attempts fail *until* the peer listens).
                let due = station
                    .timers
                    .deadline(Timer::T0)
                    .is_none_or(|deadline| deadline <= now);
                if due {
                    let reason = station.attempt_reason();
                    let attempt = station.begin_attempt(now);
                    directives.push(Directive::Connect {
                        station: index,
                        attempt,
                        reason,
                    });
                }
                continue;
            }
            if station.session.state() == State::Terminated {
                continue;
            }
            for timer in station.timers.expired(now) {
                let before = station.supervision();
                let actions = station.session.on_timeout(timer);
                station.apply_timers(now, &actions, before);
                if !actions.is_empty() {
                    directives.push(Directive::Actions {
                        station: index,
                        actions,
                    });
                }
            }
        }
        directives
    }

    /// The soonest instant [`ConnectionManager::tick`] has something to do, or
    /// `None` when nothing is armed: what an event loop sleeps until.
    ///
    /// Only the timers `tick` reacts to count: t0 of a station that is down
    /// (clause 9's *"Time-out of connection establishment"*), t0–t3 of one that
    /// is up and not yet [`State::Terminated`]. It is exact only right after a
    /// `tick`, which arms t0 for every attempt it asks for. A station that went
    /// down since (an established connection reported through
    /// [`ConnectionManager::on_connection_lost`]) or was never ticked has no t0
    /// armed: it is due at once and has no instant here, so tick again after
    /// such an event instead of sleeping.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        let controlling = self.role == Role::Controlling;
        self.stations
            .iter()
            .filter_map(|station| {
                if !station.connected {
                    controlling
                        .then(|| station.timers.deadline(Timer::T0))
                        .flatten()
                } else if station.session.state() == State::Terminated {
                    None
                } else {
                    station.timers.next_deadline()
                }
            })
            .min()
    }

    /// The caller's socket came up: clause 5.3 makes the fresh connection
    /// `STOPDT` (a [`State::Stopped`] session), clause 5.1 restarts its sequence
    /// numbers at zero, and t0 is cancelled in favour of t3.
    ///
    /// The attempt's t0 is gone with it, so the retry of
    /// [`ConnectionManager::tick`] has nothing left to report for this station
    /// until the connection is lost again.
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn on_connection_established(
        &mut self,
        index: usize,
        now: Instant,
    ) -> Result<(), ManagerError> {
        let station = self.station_mut(index)?;
        station.connected = true;
        station.dialing = false;
        station.lost = false;
        // A fresh connection has nothing outstanding: the counters restart at
        // zero (clause 5.1), so no t1 is armed for it (`Timers::connection_established`).
        // Nothing of an earlier connection is supervised on this one either,
        // also when that connection's own session closed it and the caller
        // never reported the loss that would have cleared its timers.
        station.session.on_connection_established();
        station.timers.connection_lost();
        station.timers.connection_established(now);
        station.supervisor = Supervisor::default();
        Ok(())
    }

    /// The caller lost its connection: the peer's FIN, an OS error, or a dial
    /// that was refused before it ever came up.
    ///
    /// The two cases do *not* leave the station in the same state:
    ///
    /// - **An established connection that was lost.** The session loses it
    ///   ([`Session::on_connection_lost`], which emits nothing: the peer is gone
    ///   and there is nobody left to confirm anything to) and its scheduler
    ///   cancels t0–t3. The next [`ConnectionManager::tick`] asks for a new
    ///   connection at once (clause 10.5's *"reopening is regularly retried by
    ///   the controlling station until the error has been corrected"*), and that
    ///   attempt's `reason` is [`ConnectReason::ConnectionLost`].
    /// - **A dial that was refused.** A session that was never established has no
    ///   connection to lose, so it is left alone, and the attempt's own t0
    ///   **stays armed**: the next dial comes at that expiry, not on every tick.
    ///   Figure 21's peer refuses *every* dial until it listens, and clause
    ///   10.5's *"regularly retried"* is one attempt per t0, not a busy loop.
    ///   The retry's `reason` is [`ConnectReason::AttemptFailed`].
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn on_connection_lost(&mut self, index: usize) -> Result<(), ManagerError> {
        let station = self.station_mut(index)?;
        if station.connected {
            station.session.on_connection_lost();
            station.connected = false;
            station.lost = true;
            station.timers.connection_lost();
            station.supervisor = Supervisor::default();
            // Clause 10.5's reopening is "regularly retried": one attempt per
            // t0 (clause 9's "Time-out of connection establishment"), also
            // when a peer takes every connection and closes it at once. t0 is
            // armed again from the attempt this connection came from, so a
            // connection that lasted longer than t0 is due at once and one
            // lost sooner when that t0 runs out.
            if let Some(began) = station.attempt_began {
                station.timers.connection_attempt(began);
            }
        } else {
            // A refused dial: the attempt is over, only its t0 still runs.
            station.dialing = false;
        }
        Ok(())
    }

    /// Feeds one received control field to a station's connection.
    ///
    /// Every frame retriggers that station's t3 (clause 5.2), and an I-frame
    /// arms its t2 (the time-out for acknowledges in case of no data
    /// messages); the session's own answers come back as directives. An
    /// N(R) in the frame acknowledges frames in the clause 5.1 send buffer, and
    /// t1 moves to the frame that is now the oldest unconfirmed one.
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn on_frame(
        &mut self,
        index: usize,
        apci: Apci,
        now: Instant,
    ) -> Result<Vec<Directive>, ManagerError> {
        let station = self.station_mut(index)?;
        station.timers.frame_received(now);
        if matches!(apci, Apci::I { .. }) {
            station.timers.i_frame_received(now);
        }
        let before = station.supervision();
        let actions = station.session.on_frame(apci);
        station.apply_timers(now, &actions, before);
        Ok(directives(index, actions))
    }

    /// Feeds one codec error to a station's connection, with the reactions of
    /// [`crate::link::reaction`]: a clause 5 violation closes that station's
    /// connection and the framing conditions produce nothing.
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn on_parse_error(
        &mut self,
        index: usize,
        error: ParseError,
        now: Instant,
    ) -> Result<Vec<Directive>, ManagerError> {
        let station = self.station_mut(index)?;
        let before = station.supervision();
        let actions = station.session.on_parse_error(error);
        station.apply_timers(now, &actions, before);
        Ok(directives(index, actions))
    }

    /// Asks a station's connection to start its data transfer: clause 5.3's
    /// `STARTDT act`, for a controlling station.
    ///
    /// The act is supervised by t1 (figures 15/16), so the manager arms it; the
    /// con that answers it cancels the supervision when it arrives through
    /// [`ConnectionManager::on_frame`].
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn request_start(
        &mut self,
        index: usize,
        now: Instant,
    ) -> Result<Vec<Directive>, ManagerError> {
        let station = self.station_mut(index)?;
        let before = station.supervision();
        let actions = station.session.request_start();
        station.apply_timers(now, &actions, before);
        Ok(directives(index, actions))
    }

    /// Asks a station's connection to stop its data transfer: clause 5.3's
    /// `STOPDT act`, for a controlling station. It is supervised by t1 like the
    /// start.
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn request_stop(
        &mut self,
        index: usize,
        now: Instant,
    ) -> Result<Vec<Directive>, ManagerError> {
        let station = self.station_mut(index)?;
        let before = station.supervision();
        let actions = station.session.request_stop();
        station.apply_timers(now, &actions, before);
        Ok(directives(index, actions))
    }

    /// Sends one user ASDU on a station's connection.
    ///
    /// `Some(directive)` is the I-frame for the caller to put on the wire, and
    /// its t1 is armed (clause 5.1 keeps it in the send buffer until its N(R)
    /// comes back). `None` means the connection refused it, because data
    /// transfer is not enabled in this state (clause 5.3) or the k window is
    /// full (clause 5.5), and the caller must queue the ASDU
    /// ([`ConnectionManager::queue_i_frame`]) and retry.
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn send_i_frame(
        &mut self,
        index: usize,
        asdu: &[u8],
        now: Instant,
    ) -> Result<Option<Directive>, ManagerError> {
        let station = self.station_mut(index)?;
        let before = station.supervision();
        Ok(station.session.send_i_frame(asdu).map(|action| {
            let actions = vec![action];
            station.apply_timers(now, &actions, before);
            Directive::Actions {
                station: index,
                actions,
            }
        }))
    }

    /// Hands one ASDU to a station's connection for it to hold until it may send
    /// it: clause 5.3's *"Any pending user data in the controlled station is
    /// sent only after the STARTDT con."*
    ///
    /// The queue is the session's, not a second one here: the session releases
    /// it itself when data transfer becomes enabled or the k window reopens
    /// ([`Session::flush_pending`]), and it is cleared with the connection
    /// (clause 5.1). Without a connection the ASDU is refused with
    /// [`ManagerError::Queue`].
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station,
    /// and [`ManagerError::Queue`] when that station has no connection or its
    /// queue is full ([`QueueError::Full`]).
    pub fn queue_i_frame(&mut self, index: usize, asdu: &[u8]) -> Result<(), ManagerError> {
        let station = self.station_mut(index)?;
        station
            .session
            .queue_i_frame(asdu)
            .map_err(|error| ManagerError::Queue {
                station: index,
                error,
            })
    }

    /// Puts as much of a station's pending queue on the wire as its state and k
    /// window allow, oldest first, as directives.
    ///
    /// The session calls this itself whenever data transfer becomes enabled; a
    /// caller needs it only for data queued into a session that is *already*
    /// allowed to send, where [`ConnectionManager::send_i_frame`] is the better
    /// call.
    ///
    /// # Errors
    ///
    /// [`ManagerError::StationIndexOutOfRange`] when `index` names no station.
    pub fn flush_pending(
        &mut self,
        index: usize,
        now: Instant,
    ) -> Result<Vec<Directive>, ManagerError> {
        let station = self.station_mut(index)?;
        let before = station.supervision();
        let actions = station.session.flush_pending();
        station.apply_timers(now, &actions, before);
        Ok(directives(index, actions))
    }
}

/// Wraps one station's action list in the directive the caller performs, or
/// nothing at all when the session produced no action.
fn directives(station: usize, actions: Vec<Action>) -> Vec<Directive> {
    if actions.is_empty() {
        Vec::new()
    } else {
        vec![Directive::Actions { station, actions }]
    }
}
