//! The t0–t3 timer layer.
//!
//! Every rule asserted here is read off IEC 60870-5-104:2006:
//!
//! - **t0**: clause 9 interoperability list ("t0 30 s — Time-out of connection
//!   establishment"); clause 10's connection diagrams raise it per connection
//!   attempt ("Timeout t0"), and clause 10 states "It should be possible to set
//!   the values of the timers t0 to t3 individually for each connection".
//! - **t1**: figures 17/18 NOTE 2: "t1 is the timer of a sent U-frame or
//!   I-frame"; figures 15/16 mark `Temporisateur t1` on the STARTDT act and
//!   STOPDT act, and figure 14 draws `Time-out t1` → `Active close`.
//! - **t2**: clause 5.2/5.5; figures 10/11 mark `Temporisateur t2`, and clause
//!   5.5's w is the other half of the same acknowledgement decision.
//! - **t3**: clause 5.2 verbatim: "The reception of every frame – I frame,
//!   S frame or U frame – retriggers timer t3"; figure 13 draws the expiry as
//!   `Time-out t3` → `U (TESTFR act)`.
//!
//! No wall-clock read happens anywhere in the crate: the scheduler is handed
//! `Instant` values by its caller, which is why every assertion below is
//! deterministic. `base()` exists only to give the durations something to be
//! added to.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::arithmetic_side_effects)]

use std::time::{Duration, Instant};

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::link::{Action, Role, Session, Timer};
use iec104::params::{LinkParams, ParamError};
use iec104::timers::Timers;

/// A scheduler with the standard's defaults: t0 30 s, t1 15 s, t2 10 s, t3 20 s
/// (clause 9).
fn scheduler() -> Timers {
    Timers::new(LinkParams::default()).expect("the standard's defaults are admissible")
}

/// The one instant a test works from. Each test reads it once, so nothing
/// depends on the wall clock.
fn base() -> Instant {
    Instant::now()
}

fn at(base: Instant, secs: u64) -> Instant {
    base + Duration::from_secs(secs)
}

const fn u(f: UFunction) -> Apci {
    Apci::U(f)
}

const fn i(ns: u16, nr: u16) -> Apci {
    Apci::I {
        ns: SeqNo::new(ns),
        nr: SeqNo::new(nr),
    }
}

// ---------------------------------------------------------------------------
// The scheduler on its own.
// ---------------------------------------------------------------------------

#[test]
fn nothing_is_armed_on_a_fresh_scheduler() {
    let b = base();
    let mut tm = scheduler();
    assert_eq!(tm.next_deadline(), None);
    for timer in [Timer::T0, Timer::T1, Timer::T2, Timer::T3] {
        assert_eq!(tm.deadline(timer), None, "{timer:?} must start unarmed");
    }
    assert_eq!(tm.expired(at(b, 1_000_000)), vec![]);
}

#[test]
fn t0_fires_at_the_connection_timeout_and_not_before() {
    // clause 9: "t0 30 s — Time-out of connection establishment".
    let b = base();
    let mut tm = scheduler();
    tm.connection_attempt(b);
    assert_eq!(tm.deadline(Timer::T0), Some(at(b, 30)));
    assert_eq!(tm.next_deadline(), Some(at(b, 30)));

    assert_eq!(tm.expired(at(b, 29)), vec![], "not before its instant");
    assert_eq!(tm.expired(at(b, 30)), vec![Timer::T0]);
    assert_eq!(tm.expired(at(b, 31)), vec![], "reported at most once");
}

#[test]
fn connection_established_cancels_t0_and_arms_t3() {
    // clause 5.2: the test procedure runs on an idle connection; clause 5.3: a
    // fresh connection carries no data transfer, so nothing else is armed.
    let b = base();
    let mut tm = scheduler();
    tm.connection_attempt(b);
    tm.connection_established(at(b, 5));

    assert_eq!(tm.deadline(Timer::T0), None, "the attempt succeeded");
    assert_eq!(tm.deadline(Timer::T3), Some(at(b, 25)));
    assert_eq!(tm.expired(at(b, 30)), vec![Timer::T3], "t0 is gone");
}

#[test]
fn t3_is_retriggered_by_every_received_frame() {
    // clause 5.2: "The reception of every frame – I frame, S frame or U frame –
    // retriggers timer t3."
    let b = base();
    let mut tm = scheduler();
    tm.connection_established(b);
    tm.frame_received(at(b, 19));
    assert_eq!(tm.deadline(Timer::T3), Some(at(b, 39)));
    assert_eq!(tm.expired(at(b, 20)), vec![], "the retrigger moved it");

    // The scheduler does not see the format: every received frame is one
    // `frame_received` call.
    tm.frame_received(at(b, 38));
    assert_eq!(tm.expired(at(b, 39)), vec![]);
    assert_eq!(tm.expired(at(b, 58)), vec![Timer::T3]);
}

#[test]
fn t3_restarts_after_it_fires() {
    // Figure 13: the expiry sends TESTFR act; the connection is still idle, so
    // the next interval starts from the expiry (t3 is periodic, unlike t0–t2).
    let b = base();
    let mut tm = scheduler();
    tm.connection_established(b);
    assert_eq!(tm.expired(at(b, 20)), vec![Timer::T3]);
    assert_eq!(tm.deadline(Timer::T3), Some(at(b, 40)));
    assert_eq!(tm.expired(at(b, 39)), vec![]);
    assert_eq!(tm.expired(at(b, 40)), vec![Timer::T3]);
}

#[test]
fn a_late_poll_reports_each_timer_once_and_does_not_burst() {
    let b = base();
    let mut tm = scheduler();
    tm.connection_attempt(b);
    tm.frame_sent(b);
    tm.i_frame_received(b);

    assert_eq!(
        tm.expired(at(b, 10_000)),
        vec![Timer::T0, Timer::T1, Timer::T2]
    );
    assert_eq!(tm.expired(at(b, 10_000)), vec![], "nothing repeats");
}

#[test]
fn every_due_timer_is_reported_in_a_fixed_order() {
    // All three of these are due by t = 20 s: t2 at 10, t1 at 15, t3 at 20. The
    // order reported is the fixed t0, t1, t2, t3 of `Timers::expired`, not the
    // chronological one. A caller dispatches each expiry on its own, and a fixed
    // order keeps the vector comparable. `next_deadline` is what answers "what is
    // due soonest".
    let b = base();
    let mut tm = scheduler();
    tm.connection_established(b);
    tm.frame_sent(b);
    tm.i_frame_received(b);
    assert_eq!(tm.next_deadline(), Some(at(b, 10)), "t2 is the soonest");
    assert_eq!(tm.expired(at(b, 20)), vec![Timer::T1, Timer::T2, Timer::T3]);
}

#[test]
fn t1_is_armed_by_a_sent_frame_and_cancelled_by_its_confirmation() {
    // figures 17/18 NOTE 2: "t1 is the timer of a sent U-frame or I-frame"; it
    // is cancelled the moment the frame it supervises is confirmed.
    let b = base();
    let mut tm = scheduler();
    tm.frame_sent(b);
    assert_eq!(tm.deadline(Timer::T1), Some(at(b, 15)));

    tm.confirmation_received();
    assert_eq!(tm.deadline(Timer::T1), None);
    assert_eq!(tm.expired(at(b, 60)), vec![], "it never fires");
}

#[test]
fn t1_fires_once_at_its_instant_when_nothing_confirms() {
    // Figure 14: an unconfirmed TESTFR act ends in `Time-out t1` → `Active close`.
    let b = base();
    let mut tm = scheduler();
    tm.frame_sent(b);
    assert_eq!(tm.expired(at(b, 14)), vec![]);
    assert_eq!(tm.expired(at(b, 15)), vec![Timer::T1]);
    assert_eq!(tm.expired(at(b, 16)), vec![]);
}

#[test]
fn a_second_send_does_not_postpone_the_t1_close() {
    // t1 supervises the outstanding frame, not the most recent one: letting a
    // chattering peer push the deadline out would mean never closing.
    let b = base();
    let mut tm = scheduler();
    tm.frame_sent(b);
    tm.frame_sent(at(b, 10));
    assert_eq!(tm.deadline(Timer::T1), Some(at(b, 15)));

    // Once that frame is confirmed the deadline is free for the next one.
    tm.confirmation_received();
    tm.frame_sent(at(b, 20));
    assert_eq!(tm.deadline(Timer::T1), Some(at(b, 35)));
}

#[test]
fn t2_is_armed_by_the_first_unacknowledged_frame_and_cancelled_by_the_ack() {
    // clause 5.2: t2 is the acknowledgement time-out; it measures from the first
    // frame that is still unacknowledged.
    let b = base();
    let mut tm = scheduler();
    tm.i_frame_received(b);
    assert_eq!(tm.deadline(Timer::T2), Some(at(b, 10)));
    tm.i_frame_received(at(b, 2));
    assert_eq!(
        tm.deadline(Timer::T2),
        Some(at(b, 10)),
        "a later frame does not restart the acknowledgement clock"
    );

    tm.acknowledgement_sent();
    assert_eq!(tm.deadline(Timer::T2), None);
    assert_eq!(tm.expired(at(b, 60)), vec![]);
}

#[test]
fn t2_fires_once_at_its_instant() {
    let b = base();
    let mut tm = scheduler();
    tm.i_frame_received(b);
    assert_eq!(tm.expired(at(b, 9)), vec![]);
    assert_eq!(tm.expired(at(b, 10)), vec![Timer::T2]);
    assert_eq!(tm.expired(at(b, 11)), vec![]);
}

#[test]
fn connection_lost_cancels_every_timer() {
    let b = base();
    let mut tm = scheduler();
    tm.connection_attempt(b);
    tm.connection_established(b);
    tm.frame_sent(b);
    tm.i_frame_received(b);
    tm.connection_lost();

    assert_eq!(tm.next_deadline(), None);
    for timer in [Timer::T0, Timer::T1, Timer::T2, Timer::T3] {
        assert_eq!(tm.deadline(timer), None, "{timer:?} must be cancelled");
    }
    assert_eq!(tm.expired(at(b, 100_000)), vec![]);
}

#[test]
fn a_lost_connection_may_be_attempted_again() {
    let b = base();
    let mut tm = scheduler();
    tm.connection_attempt(b);
    tm.connection_lost();
    tm.connection_attempt(at(b, 10));
    assert_eq!(tm.deadline(Timer::T0), Some(at(b, 40)));
}

#[test]
fn the_parameters_are_validated() {
    let bad = LinkParams {
        k: 0,
        ..LinkParams::default()
    };
    assert_eq!(Timers::new(bad).unwrap_err(), ParamError::KOutOfRange(0));
}

#[test]
fn the_time_outs_are_read_from_the_link_parameters() {
    // clause 10: "It should be possible to set the values of the timers t0 to t3
    // individually for each connection."
    let b = base();
    let params = LinkParams {
        t0: Duration::from_secs(5),
        t1: Duration::from_secs(3),
        t2: Duration::from_secs(2),
        t3: Duration::from_secs(7),
        ..LinkParams::default()
    };
    let mut tm = Timers::new(params).unwrap();
    tm.connection_attempt(b);
    assert_eq!(tm.deadline(Timer::T0), Some(at(b, 5)));
    tm.connection_established(b);
    assert_eq!(tm.deadline(Timer::T3), Some(at(b, 7)));
    tm.frame_sent(b);
    assert_eq!(tm.deadline(Timer::T1), Some(at(b, 3)));
    tm.i_frame_received(b);
    assert_eq!(tm.deadline(Timer::T2), Some(at(b, 2)));
}

// ---------------------------------------------------------------------------
// Composed with the session: each expiry produces the documented event.
// ---------------------------------------------------------------------------

#[test]
fn a_t0_expiry_is_the_failed_connection_attempt() {
    // The connection is the caller's socket, not the session's. Clauses 5.4 and
    // 9 make t0 the connection-establishment timeout, and clause 10's diagrams
    // react by trying again, so the scheduler reports the expiry and the caller
    // closes or reopens the socket.
    let b = base();
    let mut tm = scheduler();
    tm.connection_attempt(b);
    assert_eq!(tm.expired(at(b, 30)), vec![Timer::T0]);
}

#[test]
fn a_t1_expiry_produces_the_active_close() {
    // Figure 15: the STARTDT act is supervised by `Temporisateur t1`. Clause 5.3:
    // "If the STARTDT is not confirmed, the connection is closed by the
    // controlling station"; and figure 14's `Time-out t1` → `Active close`.
    let b = base();
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    assert_eq!(s.state(), iec104::link::State::PendingStarted);

    let mut tm = scheduler();
    tm.connection_established(b);
    tm.frame_sent(b);
    let expired = tm.expired(at(b, 15));
    assert_eq!(expired, vec![Timer::T1]);

    let actions: Vec<Action> = expired.iter().flat_map(|t| s.on_timeout(*t)).collect();
    assert!(
        actions.iter().any(|a| matches!(a, Action::ActiveClose(_))),
        "got {actions:?}"
    );
    assert_eq!(s.state(), iec104::link::State::Terminated);
}

#[test]
fn a_t2_expiry_produces_exactly_one_acknowledgement_s_frame() {
    // clause 5.5 acknowledges at the latest after w I-frames; t2 (clause 5.2) is
    // what acknowledges the single frame that never reaches w.
    let b = base();
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));
    s.on_frame(i(0, 0));
    assert!(s.ack_pending());

    let mut tm = scheduler();
    tm.connection_established(b);
    tm.i_frame_received(b);
    let expired = tm.expired(at(b, 10));
    assert_eq!(expired, vec![Timer::T2]);

    let actions: Vec<Action> = expired.iter().flat_map(|t| s.on_timeout(*t)).collect();
    assert_eq!(actions, vec![Action::Send(Apci::S { nr: SeqNo::new(1) })]);
    assert!(!s.ack_pending());

    // Exactly one: the ack cancels t2 and a second expiry does nothing.
    tm.acknowledgement_sent();
    assert_eq!(tm.expired(at(b, 11)), vec![]);
    assert_eq!(s.on_timeout(Timer::T2), vec![]);
}

#[test]
fn a_t3_expiry_produces_a_test_frame_and_restarts_the_idle_timer() {
    // clause 5.2 + figure 13: `Time-out t3` → `U (TESTFR act)`.
    let b = base();
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();

    let mut tm = scheduler();
    tm.connection_established(b);
    let expired = tm.expired(at(b, 20));
    assert_eq!(expired, vec![Timer::T3]);

    let actions: Vec<Action> = expired.iter().flat_map(|t| s.on_timeout(*t)).collect();
    assert_eq!(actions, vec![Action::Send(Apci::U(UFunction::TestFrAct))]);
    assert_eq!(tm.deadline(Timer::T3), Some(at(b, 40)), "idle again");
}

#[test]
fn a_confirmed_test_frame_cancels_t1_and_restarts_t3() {
    // The end-to-end shape of figure 13: t3 fires, TESTFR act goes out under t1,
    // the peer's TESTFR con both cancels t1 and retriggers t3.
    let b = base();
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();

    let mut tm = scheduler();
    tm.connection_established(b);
    assert_eq!(tm.expired(at(b, 20)), vec![Timer::T3]);

    let actions: Vec<Action> = s.on_timeout(Timer::T3);
    assert_eq!(actions, vec![Action::Send(Apci::U(UFunction::TestFrAct))]);
    assert!(
        s.test_pending(),
        "the act is supervised by t1 until its con"
    );
    // figure 13's `Time-out t3` → `U (TESTFR act)`: the act is a sent U-frame,
    // so the caller starts t1 (figures 17/18 NOTE 2).
    tm.frame_sent(at(b, 20));
    assert_eq!(tm.deadline(Timer::T1), Some(at(b, 35)));

    let con = s.on_frame(u(UFunction::TestFrCon));
    assert_eq!(con, vec![], "a confirmation carries no further action");
    assert!(!s.test_pending(), "the procedure is over");
    tm.confirmation_received();
    tm.frame_received(at(b, 25));
    assert_eq!(tm.deadline(Timer::T1), None);
    assert_eq!(tm.deadline(Timer::T3), Some(at(b, 45)));
}

#[test]
fn a_received_test_frame_keeps_our_own_idle_timer_alive() {
    // clause 5.2: "Station B has to supervise the connection independently.
    // However, as long as it receives test frames from station A, it will not
    // send test frames." The mechanism is the sentence before it ("The
    // reception of every frame ... retriggers timer t3"), so the peer's act both
    // gets its con and moves our own deadline: no act of ours is due at the
    // instant our own t3 would otherwise have fired.
    let b = base();
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();

    let mut tm = scheduler();
    tm.connection_established(b);

    // 19 s of silence, then the peer tests us.
    let actions = s.on_frame(u(UFunction::TestFrAct));
    assert_eq!(actions, vec![Action::Send(Apci::U(UFunction::TestFrCon))]);
    tm.frame_received(at(b, 19));

    assert_eq!(
        tm.expired(at(b, 20)),
        vec![],
        "the peer's test moved our t3"
    );
    assert_eq!(tm.deadline(Timer::T3), Some(at(b, 39)));
    assert!(
        !s.test_pending(),
        "we answered the peer's act; we did not start one of our own"
    );

    // Only after that interval, with the peer silent again, does our own test
    // procedure start.
    let expired = tm.expired(at(b, 39));
    assert_eq!(expired, vec![Timer::T3]);
    let actions: Vec<Action> = expired.iter().flat_map(|t| s.on_timeout(*t)).collect();
    assert_eq!(actions, vec![Action::Send(Apci::U(UFunction::TestFrAct))]);
    assert!(s.test_pending());
}
