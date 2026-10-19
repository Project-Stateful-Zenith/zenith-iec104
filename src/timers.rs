//! The four link-layer time-outs t0–t3 of IEC 60870-5-104:2006, scheduled from
//! a caller-supplied clock.
//!
//! This module decides *when* a time-out is due; *what* happens then is in
//! [`crate::link`]. The session state machine owns no clock: it reacts to a
//! [`Timer`] expiry it is handed, and [`Timers`] decides when each expiry is
//! due. Nothing here reads the wall clock or opens a socket, so a whole
//! connection lifetime is testable without sleeping.
//!
//! # The four time-outs and where they come from
//!
//! | Timer | Default | Meaning (clause 9's interoperability list) | Clause |
//! | --- | --- | --- | --- |
//! | t0 | 30 s | "Time-out of connection establishment" | 104 cl.9, cl.10 |
//! | t1 | 15 s | "Time-out of send or test APDUs" | 104 cl.9, fig.17/18 note 2 |
//! | t2 | 10 s | "Time-out for acknowledges in case of no data messages t2 < t1" | 104 cl.9, cl.5.1 fig.10 |
//! | t3 | 20 s | "Time-out for sending test frames in case of a long idle state" | 104 cl.9, cl.5.2 |
//!
//! The defaults are [`LinkParams::default`]'s, and the admissible ranges are
//! the ones [`LinkParams::validate`] enforces. This type takes the same [`LinkParams`]
//! the session does, so a project selects its time-outs once, per connection.
//! Clause 10.7 states that requirement for redundant connections: "It should be
//! possible to set the values of the timers t0 to t3 individually for each
//! connection within a redundancy group."
//!
//! # Which event arms, retriggers and cancels which timer
//!
//! | Event | Method | Effect |
//! | --- | --- | --- |
//! | a connection attempt starts | [`Timers::connection_attempt`] | arm t0 |
//! | the TCP connection came up | [`Timers::connection_established`] | cancel t0, arm t3 |
//! | the TCP connection went away | [`Timers::connection_lost`] | cancel t0–t3 |
//! | a U-frame or I-frame went out | [`Timers::frame_sent`] | arm t1 if it is not armed |
//! | that frame was confirmed | [`Timers::confirmation_received`] | cancel t1 |
//! | any frame arrived | [`Timers::frame_received`] | retrigger t3 |
//! | an I-frame arrived | [`Timers::i_frame_received`] | arm t2 if it is not armed |
//! | an acknowledgement went out | [`Timers::acknowledgement_sent`] | cancel t2 |
//! | the clock advanced | [`Timers::expired`] | report what is due, once each |
//!
//! The rules those rows implement, in the standard's words:
//!
//! - **t1**: "t1 is the timeout of a sent U-frame or I-frame" (figures 17/18,
//!   NOTE 2). Figures 15 and 16 mark `Time-out t1` on the STARTDT act and STOPDT
//!   act, and figure 14 draws its expiry as `Time-out t1` → `Active close`. It is
//!   armed by the *oldest* unconfirmed frame: a further send does not push the
//!   deadline out, because that would let a peer that never confirms anything
//!   hold the connection open forever.
//! - **t2** covers the case where the w limit is never reached: clause 9's
//!   "Time-out for acknowledges in case of no data messages", drawn in figure 10.
//!   It measures from the first I-frame still unacknowledged, so a later
//!   arrival does not restart it either.
//! - **t3** is retriggered by activity: "The reception of every frame – I frame,
//!   S frame or U frame – retriggers timer t3" (clause 5.2). Its expiry sends the
//!   TESTFR act of figure 13, after which the station is idle again. So t3,
//!   unlike t0 to t2, is *periodic* and restarts itself on every expiry.
//! - **t0** covers the connection attempt, which is the caller's socket and not
//!   the session's: the expiry is reported so the caller can fail or retry the
//!   attempt (the connection figures of clauses 7.1 and 10 draw `Time-out t0`
//!   per attempt).
//!
//! # Reporting each expiry exactly once
//!
//! [`Timers::expired`] returns the timers whose instant has arrived, in the fixed
//! order t0, t1, t2, t3, and clears each of them. t3 is re-armed at `now + t3`,
//! so a poll that happens long after the deadline still reports one expiry and
//! never a burst. Call it after every event with the same `now`, or on a timer
//! of its own; the crate makes no assumption about how often.
//!
//! # Pairing with the session
//!
//! ```
//! use iec104::link::{Role, Session};
//! use iec104::params::LinkParams;
//! use iec104::timers::Timers;
//! use std::time::{Duration, Instant};
//!
//! let start = Instant::now();
//! let mut session = Session::new(Role::Controlling);
//! let mut timers = Timers::new(LinkParams::default()).unwrap();
//!
//! session.on_connection_established();
//! timers.connection_established(start);
//! for action in session.request_start() {
//!     let _ = action; // ... and put it on the wire
//!     timers.frame_sent(start); // figures 15/16: t1 supervises the act
//! }
//!
//! // The peer's STARTDT con arrives:
//! let now = start + Duration::from_secs(1);
//! session.on_frame(iec104::apci::Apci::U(iec104::apci::UFunction::StartDtCon));
//! timers.confirmation_received();
//! timers.frame_received(now);
//!
//! // 20 s of silence later, t3 is due and the session answers with TESTFR act:
//! let now = now + Duration::from_secs(20);
//! for timer in timers.expired(now) {
//!     for action in session.on_timeout(timer) {
//!         let _ = action;
//!         timers.frame_sent(now);
//!     }
//! }
//! ```

use std::time::Instant;

use crate::apci::{Apci, UFunction};
use crate::link::{Action, Session, State, Timer};
use crate::params::{LinkParams, ParamError};

/// The t0–t3 scheduler of one connection.
///
/// Cheap to clone and to keep beside a [`crate::link::Session`]; it holds four
/// optional instants and the parameter set they were computed from.
#[derive(Debug, Clone)]
pub struct Timers {
    params: LinkParams,
    t0: Option<Instant>,
    t1: Option<Instant>,
    t2: Option<Instant>,
    t3: Option<Instant>,
}

impl Timers {
    /// A scheduler with these link parameters.
    ///
    /// The parameters are validated (clauses 5.5 and 9), so an inadmissible set
    /// fails here, once. [`crate::link::Session::with_params`] performs the same
    /// check, because a project configures the two from one source.
    ///
    /// # Errors
    ///
    /// The [`ParamError`] of [`LinkParams::validate`] for an inadmissible set.
    pub fn new(params: LinkParams) -> Result<Self, ParamError> {
        params.validate()?;
        Ok(Self {
            params,
            t0: None,
            t1: None,
            t2: None,
            t3: None,
        })
    }

    /// The parameters this scheduler was built from.
    #[must_use]
    pub const fn params(&self) -> &LinkParams {
        &self.params
    }

    /// A connection attempt starts: arm t0 (clause 9, "Time-out of connection
    /// establishment").
    ///
    /// Clause 10 raises t0 per attempt on the redundant group's diagrams, so a
    /// retry simply calls this again.
    pub fn connection_attempt(&mut self, now: Instant) {
        self.t0 = now.checked_add(self.params.t0);
    }

    /// The TCP connection came up: the attempt succeeded (cancel t0) and the
    /// connection is idle until something happens (arm t3).
    ///
    /// Clause 5.3 makes STOPDT the default state of a fresh connection, so no
    /// other timer has a reason to run yet.
    pub fn connection_established(&mut self, now: Instant) {
        self.t0 = None;
        self.t3 = now.checked_add(self.params.t3);
    }

    /// The TCP connection went away: nothing is left to supervise.
    pub const fn connection_lost(&mut self) {
        self.t0 = None;
        self.t1 = None;
        self.t2 = None;
        self.t3 = None;
    }

    /// A U-frame or an I-frame went out: start supervising it with t1.
    ///
    /// Figures 17/18 NOTE 2: "t1 is the timeout of a sent U-frame or I-frame".
    /// Only the *first* unconfirmed frame arms it; the module doc explains why a
    /// later send must not move the deadline.
    ///
    /// Do **not** call this for a confirmation of your own (a `TESTFR con`,
    /// `STARTDT con` or `STOPDT con`). Nothing ever confirms a con, so t1 would
    /// expire and `on_timeout(Timer::T1)` would actively close a live peer.
    pub fn frame_sent(&mut self, now: Instant) {
        if self.t1.is_none() {
            self.t1 = now.checked_add(self.params.t1);
        }
    }

    /// The frame t1 supervises has been confirmed: its U-function con arrived,
    /// or its N(S) came back inside an N(R).
    ///
    /// Call this only when nothing is left awaiting confirmation; a frame still
    /// outstanding is supervised by calling [`Timers::frame_sent`] again.
    pub const fn confirmation_received(&mut self) {
        self.t1 = None;
    }

    /// Any frame arrived (I, S or U format, and whether or not it is acted on):
    /// retrigger t3.
    ///
    /// Clause 5.2: "The reception of every frame – I frame, S frame or U frame –
    /// retriggers timer t3."
    pub fn frame_received(&mut self, now: Instant) {
        self.t3 = now.checked_add(self.params.t3);
    }

    /// An I-frame arrived: arm t2 unless it is already running.
    ///
    /// t2 forces an acknowledgement when too few frames arrive to reach w
    /// (clauses 5.5 and 9), so it starts at the first unacknowledged frame.
    pub fn i_frame_received(&mut self, now: Instant) {
        if self.t2.is_none() {
            self.t2 = now.checked_add(self.params.t2);
        }
    }

    /// An acknowledgement went out (an S-frame, or an I-frame carrying the N(R)
    /// that acknowledges everything received): cancel t2.
    pub const fn acknowledgement_sent(&mut self) {
        self.t2 = None;
    }

    /// The instants due at `now`, in the order t0, t1, t2, t3.
    ///
    /// Each due timer is reported once and cleared; t3 is re-armed for the next
    /// idle interval (figure 13's expiry leaves the station idle again). A poll
    /// far past several deadlines therefore reports one expiry per timer, never a
    /// burst.
    pub fn expired(&mut self, now: Instant) -> Vec<Timer> {
        let mut due = Vec::new();
        for (timer, slot) in [
            (Timer::T0, &mut self.t0),
            (Timer::T1, &mut self.t1),
            (Timer::T2, &mut self.t2),
        ] {
            if slot.is_some_and(|deadline| deadline <= now) {
                *slot = None;
                due.push(timer);
            }
        }
        if self.t3.is_some_and(|deadline| deadline <= now) {
            self.t3 = now.checked_add(self.params.t3);
            due.push(Timer::T3);
        }
        due
    }

    /// The instant `timer` is due, or `None` when it is not armed.
    #[must_use]
    pub const fn deadline(&self, timer: Timer) -> Option<Instant> {
        match timer {
            Timer::T0 => self.t0,
            Timer::T1 => self.t1,
            Timer::T2 => self.t2,
            Timer::T3 => self.t3,
        }
    }

    /// The soonest instant any armed timer is due: what a caller with an event
    /// loop waits until.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        [self.t0, self.t1, self.t2, self.t3]
            .into_iter()
            .flatten()
            .min()
    }
}

/// Keeps one connection's [`Timers`] in step with its [`Session`].
///
/// This applies the event table of the module doc the way [`crate::manager`]
/// and [`crate::redundancy`] do. For a caller that drives a session by hand:
/// take [`Supervision::of`] the session before feeding it an event, then hand
/// the actions it returned to [`Supervisor::apply`]. On a received frame, call
/// [`Timers::frame_received`] (and [`Timers::i_frame_received`] for an
/// I-frame) first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Supervisor {
    /// When our pending `STARTDT`/`STOPDT`/`TESTFR` act went out, so that
    /// acknowledgement progress on I-frames cannot postpone that act's t1.
    act_sent: Option<Instant>,
    /// When the oldest I-frame still in the send buffer went out (or, after a
    /// partial acknowledgement, when that acknowledgement came), so that a
    /// confirmed act cannot postpone the I-frames' t1.
    frames_sent: Option<Instant>,
}

impl Supervisor {
    /// Applies an action list the caller is about to perform.
    ///
    /// A sent act or I-frame arms t1. A sent S-frame or I-frame is an
    /// acknowledgement and cancels t2. t1 follows the *oldest* unconfirmed
    /// frame: it is cancelled once nothing awaits confirmation, and re-armed
    /// when part of what it supervised was acknowledged and something remains.
    /// It is re-armed from `now` for I-frames left after an acknowledgement, and
    /// otherwise from the send time of what is still pending: acknowledgements
    /// of I-frames say nothing about an act, nor a confirmed act about I-frames
    /// (figures 17/18 NOTE 2). A con never arms t1, because nothing confirms a
    /// con ([`Timers::frame_sent`]).
    ///
    /// `before` is [`Supervision::of`] the session captured before it saw the
    /// event; the difference is the event's own acknowledgement progress.
    pub fn apply(
        &mut self,
        timers: &mut Timers,
        session: &Session,
        now: Instant,
        actions: &[Action],
        before: Supervision,
    ) {
        for action in actions {
            match action {
                Action::Send(Apci::U(
                    UFunction::StartDtAct | UFunction::StopDtAct | UFunction::TestFrAct,
                )) => {
                    timers.frame_sent(now);
                    self.act_sent.get_or_insert(now);
                }
                Action::SendI { .. } => timers.frame_sent(now),
                _ => {}
            }
            if matches!(action, Action::Send(Apci::S { .. }) | Action::SendI { .. }) {
                timers.acknowledgement_sent();
            }
        }
        let after = Supervision::of(session);
        if !after.act_pending {
            self.act_sent = None;
        }
        if after.outstanding == 0 {
            self.frames_sent = None;
        } else if self.frames_sent.is_none() || after.outstanding < before.outstanding {
            self.frames_sent = Some(now);
        }
        if !after.any() {
            timers.confirmation_received();
        } else if after.advanced_from(before) {
            let oldest = self
                .act_sent
                .into_iter()
                .chain(self.frames_sent)
                .min()
                .unwrap_or(now);
            timers.confirmation_received();
            timers.frame_sent(oldest);
        }
    }
}

/// What t1 supervises at one instant: the frames this station sent that the peer
/// has not confirmed, and whether one of its own U-frame *acts* is still waiting
/// for the con that ends that procedure.
///
/// Figures 17/18 NOTE 2: *"t1 is the timeout of a sent U-frame or I-frame"*.
/// The count and the flag are both needed to tell an event that made
/// acknowledgement progress from one that did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Supervision {
    /// I-frames held in the clause 5.1 send buffer. An N(R) that acknowledges one
    /// of them lowers this; that is the acknowledgement progress that moves t1.
    outstanding: u16,
    /// A `TESTFR act`, `STARTDT act` or `STOPDT act` of ours awaits the peer's
    /// con (figure 13, figures 15/16). A con of ours is never pending.
    act_pending: bool,
}

impl Supervision {
    /// What in `session` awaits confirmation from the peer right now.
    #[must_use]
    pub const fn of(session: &Session) -> Self {
        Self {
            outstanding: session.outstanding_i_frames(),
            act_pending: session.test_pending()
                || matches!(
                    session.state(),
                    State::PendingStarted
                        | State::PendingStopped
                        | State::PendingUnconfirmedStopped
                ),
        }
    }

    /// True while something this station sent awaits confirmation, the
    /// condition t1 exists for. Either half is enough to keep t1 armed, and both
    /// must be gone before it is cancelled.
    const fn any(self) -> bool {
        self.outstanding > 0 || self.act_pending
    }

    /// True when this station made acknowledgement progress relative to `before`:
    /// an outstanding frame was acknowledged, or an act of ours was confirmed.
    const fn advanced_from(self, before: Self) -> bool {
        self.outstanding < before.outstanding || (before.act_pending && !self.act_pending)
    }
}
