//! The connection manager: several stations, each with its own parameters and
//! its own connection, and the t0-driven reconnect policy that keeps them
//! connected.
//!
//! Most tests name the clause they pin. The clause citations are 5-104 cl.7.1's
//! establishment sentence and figure 21 (PDF page index 54, printed page 53),
//! clause 9's `t0 30 s` row of the time-out table (index 114, printed 113),
//! clause 10.1's restatement (index 118, printed 117), clause 10.4's figure 33
//! (index 126, printed 125), clause 10.5's reopening sentence (index 128,
//! printed 127), clause 10.7's per-connection timers (index 136, printed 135),
//! and clauses 5.2/5.3 for the t1/t2/t3 supervision the manager keeps in step.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::as_conversions, clippy::cast_possible_truncation)]

use std::time::{Duration, Instant};

use iec104::apci::{Apci, ParseError, SeqNo, UFunction};
use iec104::interop::{Direction, Function, InteropProfile};
use iec104::link::{Action, Role, State, Timer};
use iec104::manager::{ConnectReason, ConnectionManager, Directive, ManagerError, StationConfig};
use iec104::params::{LinkParams, ParamError};

/// One station's configuration with the standard's default parameters.
fn station() -> StationConfig {
    StationConfig::new(LinkParams::default())
}

/// A `C_IC_NA_1` activation: cause 6, common address 12, information object
/// address 0, `QOI` 20.
fn asdu() -> Vec<u8> {
    vec![0x64, 0x01, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x14]
}

/// The `Connect` directives of a tick, as `(station, attempt, reason)`.
fn connects(directives: &[Directive]) -> Vec<(usize, u32, ConnectReason)> {
    directives
        .iter()
        .filter_map(|d| match d {
            Directive::Connect {
                station,
                attempt,
                reason,
            } => Some((*station, *attempt, *reason)),
            Directive::Actions { .. } => None,
        })
        .collect()
}

/// The stations the directives name, in order.
fn stations_of(directives: &[Directive]) -> Vec<usize> {
    directives
        .iter()
        .map(|d| match d {
            Directive::Connect { station, .. } | Directive::Actions { station, .. } => *station,
        })
        .collect()
}

/// The actions of the first `Actions` directive, or an empty list.
fn actions_of(directives: &[Directive]) -> Vec<Action> {
    directives
        .iter()
        .find_map(|d| match d {
            Directive::Actions { actions, .. } => Some(actions.clone()),
            Directive::Connect { .. } => None,
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// cl.7.1: who establishes the connection, and figure 21's repeated attempts
// ---------------------------------------------------------------------------

/// 5-104 cl.7.1 (index 54, printed 53): *"Connection establishment is performed
/// by the controlling station in case of a controlled station as a partner; a
/// fixed selection (parameter) in the case of two equivalent controlling
/// stations or partners (see figure 1)."* The manager performs no establishment
/// itself. The first tick asks the caller to, once per station, in station
/// order.
#[test]
fn clause_7_1_the_first_tick_asks_for_every_stations_connection() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(
        Role::Controlling,
        vec![
            station().with_label("station 1"),
            station().with_label("station 2"),
            station().with_label("station 3"),
        ],
    )
    .expect("the default parameters are admissible");

    let directives = manager.tick(start);
    assert_eq!(
        connects(&directives),
        vec![
            (0, 1, ConnectReason::FirstAttempt),
            (1, 1, ConnectReason::FirstAttempt),
            (2, 1, ConnectReason::FirstAttempt),
        ],
        "one attempt per station, in station order, and nothing else"
    );
    assert_eq!(directives.len(), 3, "a Connect carries no actions");
    assert_eq!(manager.station(0).unwrap().label(), Some("station 1"));
    assert!(!manager.station(0).unwrap().is_connected());
    assert_eq!(manager.station(0).unwrap().attempts(), 1);
    assert_eq!(manager.station(0).unwrap().state(), State::Stopped);
}

/// The same sentence from the other side: an attempt is not a connection. A
/// station whose dial failed is exactly the station that has no TCP connection.
/// The failed attempt keeps its own t0 (the retry comes at that expiry, not on
/// every tick), and the `reason` says which attempt it was.
#[test]
fn clause_7_1_an_attempt_is_not_a_connection() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();

    assert_eq!(
        connects(&manager.tick(start)),
        vec![(0, 1, ConnectReason::FirstAttempt)]
    );
    // A second tick with the clock standing still asks for nothing: the attempt
    // is in flight and its t0 has not expired.
    assert!(manager.tick(start).is_empty(), "one attempt at a time");
    assert!(!manager.station(0).unwrap().is_connected());

    // The caller's dial was refused and the caller says so. The attempt's own t0
    // stays armed: the retry is that expiry, not the refusal, or a peer that
    // refuses every dial would be dialled once per tick.
    manager.on_connection_lost(0).unwrap();
    assert!(
        manager.tick(start).is_empty(),
        "a refused dial does not restart t0"
    );
    assert_eq!(
        connects(&manager.tick(start + LinkParams::default().t0)),
        vec![(0, 2, ConnectReason::AttemptFailed)],
        "the retry is the attempt's own t0 expiry, and its reason the failed attempt"
    );
}

/// 5-104 cl.7.1, figure 21's own description (index 54, printed 53): *"Figure 21
/// shows the controlling station repeatedly attempting to establish a
/// connection with a controlled station. These attempts fail until the
/// controlled station has performed a local initialization and given a passive
/// open call to its TCP which has then acquired the listen status (status not
/// shown in the figure)."* One attempt per t0 expiry, and the retry never gives
/// up.
#[test]
fn figure_21_every_t0_expiry_starts_another_attempt() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    let t0 = LinkParams::default().t0;

    assert_eq!(
        connects(&manager.tick(start)),
        vec![(0, 1, ConnectReason::FirstAttempt)]
    );

    // Just short of t0: the attempt is still in flight.
    assert_eq!(
        manager.tick((start + t0).checked_sub(Duration::from_secs(1)).unwrap()),
        [] as [iec104::manager::Directive; 0]
    );
    // At t0 the attempt has timed out unanswered and the next one starts.
    assert_eq!(
        connects(&manager.tick(start + t0)),
        vec![(0, 2, ConnectReason::AttemptTimedOut)]
    );
    assert_eq!(
        connects(&manager.tick(start + t0 + t0)),
        vec![(0, 3, ConnectReason::AttemptTimedOut)],
        "no attempt limit: the peer may start listening at any time"
    );
    assert_eq!(
        connects(&manager.tick(start + t0 + t0 + t0)),
        vec![(0, 4, ConnectReason::AttemptTimedOut)]
    );
    assert_eq!(manager.station(0).unwrap().attempts(), 4);
    assert!(!manager.station(0).unwrap().is_connected());
}

/// 5-104 cl.7.1's second half (index 54, printed 53): *"The controlling station
/// is equivalent to the client (connector), the controlled station to the server
/// (listener)."* A controlled manager never dials (no `Connect` and no armed t0,
/// however long it is ticked), and its stations come up only through the
/// caller's own accept.
#[test]
fn clause_7_1_a_controlled_station_is_a_listener_and_never_dials() {
    let start = Instant::now();
    let t0 = LinkParams::default().t0;
    let mut manager = ConnectionManager::new(Role::Controlled, vec![station(), station()]).unwrap();

    for tick in [start, start + t0, start + t0 * 2, start + t0 * 60] {
        assert!(
            manager.tick(tick).is_empty(),
            "the server (listener) is not the connector"
        );
    }
    assert_eq!(
        manager.station(0).unwrap().attempts(),
        0,
        "no attempt was started"
    );
    assert!(
        manager
            .station(0)
            .unwrap()
            .timers()
            .deadline(Timer::T0)
            .is_none()
    );

    // The caller's own passive open accepted a connection; the station comes up
    // and, once that socket is gone again, returns to waiting without dialling.
    manager.on_connection_established(0, start).unwrap();
    assert!(manager.station(0).unwrap().is_connected());
    manager.on_connection_lost(0).unwrap();
    assert!(!manager.station(0).unwrap().is_connected());
    assert!(
        manager.tick(start + t0 * 60).is_empty(),
        "the lost listener connection is the caller's to accept again"
    );
}

/// Figure 21's peer refuses *every* dial until it listens, so a refused dial the
/// caller reports back leaves the attempt's own t0 armed (clause 9, index 114)
/// and the next dial comes at that expiry. A caller that polls far faster than t0
/// (99 ticks inside one t0 here) gets exactly one attempt, not 99.
#[test]
fn figure_21_a_refused_dial_is_retried_once_per_t0() {
    let start = Instant::now();
    let t0 = LinkParams::default().t0;
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();

    assert_eq!(connects(&manager.tick(start)).len(), 1);
    let mut attempts = 0;
    for i in 1..100u32 {
        let now = start + t0 * i / 100;
        manager.on_connection_lost(0).unwrap(); // the dial was refused at once
        attempts += connects(&manager.tick(now)).len();
    }
    assert_eq!(attempts, 0, "the refused dial's t0 has not expired yet");
    assert_eq!(manager.station(0).unwrap().attempts(), 1);
    assert_eq!(
        connects(&manager.tick(start + t0)),
        vec![(0, 2, ConnectReason::AttemptFailed)],
        "one attempt per t0 expiry, not one per tick"
    );
}

/// 5-104 clause 9's time-out table (index 114, printed 113): *"t0 30 s
/// Time-out of connection establishment"*. The manager's retry deadline is that
/// parameter and nothing of its own invention.
#[test]
fn clause_9_the_retry_is_the_t0_of_the_stations_own_parameters() {
    let start = Instant::now();
    let params = LinkParams {
        t0: Duration::from_secs(5),
        ..LinkParams::default()
    };
    let mut manager =
        ConnectionManager::new(Role::Controlling, vec![StationConfig::new(params)]).unwrap();

    assert_eq!(connects(&manager.tick(start)).len(), 1);
    assert_eq!(
        manager.tick(start + Duration::from_secs(4)),
        [] as [iec104::manager::Directive; 0]
    );
    assert_eq!(
        connects(&manager.tick(start + Duration::from_secs(5))).len(),
        1
    );
    assert_eq!(LinkParams::default().t0, Duration::from_secs(30));
}

/// 5-104 cl.10.4's figure 33 (initialisation of the controlled station with
/// redundant connections, index 126, printed 125) draws a `Timeout t0` after
/// each `active open` of the controlling station, i.e. the timer is raised per
/// attempt rather than once. A station that has never connected arms a fresh t0
/// for each attempt.
#[test]
fn clause_10_4_figure_33_raises_t0_per_attempt() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    let t0 = LinkParams::default().t0;

    manager.tick(start);
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T0),
        Some(start + t0)
    );
    manager.tick(start + t0);
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T0),
        Some(start + t0 + t0),
        "each attempt arms its own t0"
    );
}

// ---------------------------------------------------------------------------
// cl.10.5: reopening after a failed connection; cl.10.7: per-station timers
// ---------------------------------------------------------------------------

/// 5-104 cl.10.5 (index 128, printed 127): *"The failed connection is eventually
/// closed by both sides, and reopening is regularly retried by the controlling
/// station until the error has been corrected and the connection is
/// re-established."* The manager is that retry. A connection that lasted at
/// least t0 is reported lost and the next tick asks for a new connection at
/// once, with a reason saying the connection was lost (one lost sooner waits
/// for its attempt's t0, see the next test). Every further t0 expiry adds
/// another attempt, whose reason marks it as one of figure 21's repeated
/// attempts again.
#[test]
fn clause_10_5_reopening_is_retried_until_the_error_is_corrected() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    let t0 = LinkParams::default().t0;

    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    assert!(manager.station(0).unwrap().is_connected());
    assert!(
        manager.tick(start).is_empty(),
        "a live connection needs nothing"
    );

    // The socket went away a t0 later (the caller saw the peer's FIN, or an
    // OS error).
    let lost = start + t0;
    manager.on_connection_lost(0).unwrap();
    assert!(!manager.station(0).unwrap().is_connected());
    assert_eq!(
        connects(&manager.tick(lost)),
        vec![(0, 2, ConnectReason::ConnectionLost)],
        "the first attempt after a loss is clause 10.5's reopening"
    );
    // ... and it stays down: the attempts keep coming, and each further one is
    // one of figure 21's repeated attempts rather than a second reopening.
    let mut now = lost;
    for attempt in 3..=7 {
        now += t0;
        assert_eq!(
            connects(&manager.tick(now)),
            vec![(0, attempt, ConnectReason::AttemptTimedOut)]
        );
    }
    assert_eq!(manager.station(0).unwrap().attempts(), 7);
}

/// A peer that accepts each connection and closes it at once is not dialed
/// again at once: clause 10.5's reopening is *"regularly retried"*, and t0
/// (clause 9: *"Time-out of connection establishment"*) is the station's own
/// measure of an attempt. A connection lost less than t0 after its attempt
/// began is dialed again when that t0 runs out, so such a peer gets one
/// attempt per t0 and not one per round trip.
#[test]
fn clause_10_5_a_connection_lost_within_t0_is_dialed_again_after_t0() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    let t0 = LinkParams::default().t0;

    assert_eq!(
        connects(&manager.tick(start)),
        vec![(0, 1, ConnectReason::FirstAttempt)]
    );
    let up = start + Duration::from_millis(10);
    manager.on_connection_established(0, up).unwrap();
    // The peer closes it at once.
    manager.on_connection_lost(0).unwrap();
    assert!(
        connects(&manager.tick(up)).is_empty(),
        "not dialed again within the attempt's t0"
    );
    assert_eq!(manager.next_deadline(), Some(start + t0));
    assert_eq!(
        connects(&manager.tick((start + t0).checked_sub(Duration::from_millis(1)).unwrap())),
        [] as [(usize, u32, iec104::manager::ConnectReason); 0]
    );
    assert_eq!(
        connects(&manager.tick(start + t0)),
        vec![(0, 2, ConnectReason::ConnectionLost)]
    );
}

/// 5-104 cl.10.7 (index 136, printed 135): *"It should be possible to set the
/// values of the timers t0 to t3 individually for each connection within a
/// redundancy group."* The manager's stations are the crate's other
/// multi-connection value, and clause 10's sentence is why each station carries
/// its own scheduler: a short t0 on one station must not move another's
/// deadline.
#[test]
fn clause_10_7_each_station_keeps_its_own_timers_and_parameters() {
    let start = Instant::now();
    let quick = LinkParams {
        t0: Duration::from_secs(5),
        ..LinkParams::default()
    };
    let slow = LinkParams {
        t0: Duration::from_secs(30),
        ..LinkParams::default()
    };
    let mut manager = ConnectionManager::new(
        Role::Controlling,
        vec![StationConfig::new(quick), StationConfig::new(slow)],
    )
    .unwrap();

    assert_eq!(
        connects(&manager.tick(start)),
        vec![
            (0, 1, ConnectReason::FirstAttempt),
            (1, 1, ConnectReason::FirstAttempt),
        ]
    );
    assert_eq!(
        manager.station(1).unwrap().timers().deadline(Timer::T0),
        Some(start + Duration::from_secs(30)),
        "the slow station's own attempt is the one it armed"
    );
    assert_eq!(
        connects(&manager.tick(start + Duration::from_secs(5))),
        vec![(0, 2, ConnectReason::AttemptTimedOut)],
        "only the station whose t0 elapsed retries"
    );
    // Station 0's second attempt was armed at 5 s and expired at 10 s, so it
    // retries again; the slow station has still not moved.
    assert_eq!(
        connects(&manager.tick(start + Duration::from_secs(29))),
        vec![(0, 3, ConnectReason::AttemptTimedOut)]
    );
    assert_eq!(
        connects(&manager.tick(start + Duration::from_secs(30))),
        vec![(1, 2, ConnectReason::AttemptTimedOut)],
        "the slow station retries on its own t0, unchanged by its neighbour"
    );
    assert_eq!(
        manager.station(0).unwrap().params().t0,
        Duration::from_secs(5)
    );
    assert_eq!(
        manager.station(1).unwrap().params().t0,
        Duration::from_secs(30)
    );
}

/// Each station carries its own [`InteropProfile`] (the interoperability
/// profile of `iec104::interop`) rather than re-modelling it, as part of the
/// per-station parameters cl.10.7's sentence asks for. A station without a
/// profile says so; the manager never invents one.
#[test]
fn the_station_carries_its_profile_and_never_invents_one() {
    let marked = InteropProfile::conventional()
        .with_function(Function::StationInitialization, Direction::NotUsed);
    let manager = ConnectionManager::new(
        Role::Controlling,
        vec![station(), station().with_profile(marked.clone())],
    )
    .unwrap();

    assert!(manager.station(0).unwrap().profile().is_none());
    assert_eq!(
        manager.station(1).unwrap().profile(),
        Some(&marked),
        "the station holds the profile the caller gave it, not one of its own"
    );
    assert_eq!(
        manager.station(1).unwrap().params().port,
        LinkParams::default().port,
        "and it is the caller's station that carries the link parameters"
    );
}

// ---------------------------------------------------------------------------
// cl.5.2: the t3/t1/t2 supervision the manager keeps in step
// ---------------------------------------------------------------------------

/// 5-104 cl.5.2 (index 34, printed 33): *"The reception of every frame – I frame,
/// S frame or U frame – retriggers timer t3."* The retrigger belongs to the
/// station the frame arrived on; a frame on one station must not touch another
/// station's idle deadline.
#[test]
fn clause_5_2_a_received_frame_retriggers_only_that_stations_t3() {
    let start = Instant::now();
    let mut manager =
        ConnectionManager::new(Role::Controlling, vec![station(), station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    manager.on_connection_established(1, start).unwrap();

    // Station 0 hears a frame one second before its t3 would fire; clause 5.2
    // requires the act to be answered with exactly one con.
    let heard = start + Duration::from_secs(19);
    let answered = manager
        .on_frame(0, Apci::U(UFunction::TestFrAct), heard)
        .unwrap();
    assert_eq!(
        actions_of(&answered),
        vec![Action::Send(Apci::U(UFunction::TestFrCon))]
    );

    // At t3 both stations would have been idle; only station 1 is.
    let due = start + Duration::from_secs(20);
    let directives = manager.tick(due);
    assert_eq!(
        stations_of(&directives),
        vec![1],
        "station 0's t3 was retriggered by the frame it received"
    );
    assert_eq!(
        actions_of(&directives),
        vec![Action::Send(Apci::U(UFunction::TestFrAct))],
        "figure 13's `Time-out t3` → `U (TESTFR act)`"
    );

    // The peer confirms station 1's act, so its own t1 stops (clause 5.2: the
    // con ends the procedure).
    assert_eq!(
        manager
            .on_frame(
                1,
                Apci::U(UFunction::TestFrCon),
                due + Duration::from_secs(1)
            )
            .unwrap(),
        [] as [iec104::manager::Directive; 0]
    );
    assert_eq!(
        manager.tick(due + Duration::from_secs(2)),
        [] as [iec104::manager::Directive; 0]
    );

    // Station 0's own t3 fires 20 s after the frame it received, not 20 s after
    // the start.
    let later = manager.tick(heard + Duration::from_secs(20));
    assert_eq!(stations_of(&later), vec![0]);
}

/// 5-104 cl.5.2 and figure 14: the act the manager hands out is supervised by
/// t1, its con cancels t1, and an act that is never confirmed closes the
/// connection. The four-timer contract of [`iec104::link::Session::on_timeout`]
/// is untouched; the manager only keeps [`iec104::timers::Timers`] in step with
/// the frames it hands to the caller.
#[test]
fn clause_5_2_the_test_act_is_supervised_by_t1_and_its_con_cancels_it() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();

    // t3 fires 20 s into the idle connection.
    let act_at = start + Duration::from_secs(20);
    let directives = manager.tick(act_at);
    assert_eq!(
        actions_of(&directives),
        vec![Action::Send(Apci::U(UFunction::TestFrAct))]
    );
    assert!(manager.station(0).unwrap().session().test_pending());
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        Some(act_at + LinkParams::default().t1),
        "clause 9's t1 supervises the act we sent"
    );

    // The peer answers: the con ends the procedure and cancels t1.
    let con_at = act_at + Duration::from_secs(1);
    assert_eq!(
        manager
            .on_frame(0, Apci::U(UFunction::TestFrCon), con_at)
            .unwrap(),
        [] as [iec104::manager::Directive; 0]
    );
    assert!(!manager.station(0).unwrap().session().test_pending());
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        None
    );

    // An act whose con never comes is figure 14's unconfirmed variant: t1
    // expires and the connection is actively closed.
    let second = manager.tick(con_at + Duration::from_secs(20));
    assert_eq!(
        actions_of(&second),
        vec![Action::Send(Apci::U(UFunction::TestFrAct))]
    );
    let closes = manager.tick(con_at + Duration::from_secs(20 + 15));
    assert_eq!(
        actions_of(&closes),
        vec![Action::ActiveClose("t1 expired with no confirmation")]
    );
    assert_eq!(manager.station(0).unwrap().state(), State::Terminated);
}

/// The con the session answers the peer's act with is **not** supervised by t1.
/// Nothing confirms a con, so arming t1 for it would close a live peer (the note
/// on [`iec104::timers::Timers::frame_sent`]). The manager arms t1 for a sent
/// act or I-frame and for nothing else.
#[test]
fn a_confirmation_the_session_sends_is_never_supervised_by_t1() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlled, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();

    let directives = manager
        .on_frame(
            0,
            Apci::U(UFunction::StartDtAct),
            start + Duration::from_secs(1),
        )
        .unwrap();
    assert_eq!(
        actions_of(&directives),
        vec![Action::Send(Apci::U(UFunction::StartDtCon))]
    );
    assert_eq!(manager.station(0).unwrap().state(), State::Started);
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        None,
        "a con is never confirmed, so t1 must not supervise it"
    );
}

// ---------------------------------------------------------------------------
// figures 17/18 NOTE 2 and clause 9's t1: the supervision follows the oldest frame
// ---------------------------------------------------------------------------

/// 5-104 figures 17/18's NOTE 2 and clause 9's own row (index 114, printed 113:
/// *"t1 15 s Time-out of send or test APDUs"*): *"t1 is the timer of a sent
/// U-frame or I-frame"*, singular. A peer that confirms every frame about a second
/// after it arrives (so that exactly one frame is outstanding at any moment)
/// never has an unconfirmed frame for more than a second, and must not be
/// closed: the acknowledgement moves t1 to the frame that is now the oldest.
#[test]
fn clause_9_t1_moves_to_the_next_frame_when_one_is_acknowledged() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    manager.request_start(0, start).unwrap();
    manager
        .on_frame(0, Apci::U(UFunction::StartDtCon), start)
        .unwrap();
    let asdu = asdu();

    let mut closes: Vec<&'static str> = Vec::new();
    for second in 1..=40u64 {
        let now = start + Duration::from_secs(second);
        // One I-frame per second ...
        assert!(
            manager.send_i_frame(0, &asdu, now).unwrap().is_some(),
            "the k window is open at second {second}"
        );
        // ... and the peer acknowledges the previous one at the same instant, so
        // exactly one frame is outstanding from here on.
        manager
            .on_frame(
                0,
                Apci::S {
                    nr: SeqNo::new((second - 1) as u16),
                },
                now,
            )
            .unwrap();
        for directive in manager.tick(now) {
            if let Directive::Actions { actions, .. } = directive {
                closes.extend(actions.into_iter().filter_map(|action| match action {
                    Action::ActiveClose(reason) => Some(reason),
                    _ => None,
                }));
            }
        }
        assert_eq!(
            manager.station(0).unwrap().session().outstanding_i_frames(),
            1,
            "one frame is confirmed per second, so exactly one is outstanding"
        );
    }
    assert!(
        closes.is_empty(),
        "a peer that confirms each frame within t1 is never closed: {closes:?}"
    );
    assert_eq!(manager.station(0).unwrap().state(), State::Started);
}

/// The other half of the same note: the peer acknowledges frame 0 and then
/// nothing more. t1 was moved to frame 1 at that acknowledgement, so the
/// connection is closed exactly t1 after the *acknowledgement*: not t1 after the
/// send of frame 0, and not never.
#[test]
fn clause_9_the_connection_is_closed_exactly_t1_after_the_last_acknowledgement() {
    let start = Instant::now();
    let t1 = LinkParams::default().t1;
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    manager.request_start(0, start).unwrap();
    manager
        .on_frame(0, Apci::U(UFunction::StartDtCon), start)
        .unwrap();
    let asdu = asdu();

    // Frame 0 goes out at `start`, frame 1 a second later, the send buffer holds
    // both, and only frame 0 comes back acknowledged.
    manager.send_i_frame(0, &asdu, start).unwrap();
    let ack_at = start + Duration::from_secs(1);
    manager.send_i_frame(0, &asdu, ack_at).unwrap();
    manager
        .on_frame(0, Apci::S { nr: SeqNo::new(1) }, ack_at)
        .unwrap();
    assert_eq!(
        manager.station(0).unwrap().session().outstanding_i_frames(),
        1,
        "frame 1 is the one left in the send buffer"
    );
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        Some(ack_at + t1),
        "the acknowledgement moved t1 to the frame that is now the oldest"
    );

    assert!(
        manager
            .tick((ack_at + t1).checked_sub(Duration::from_secs(1)).unwrap())
            .is_empty(),
        "the frame left outstanding is not yet t1 old"
    );
    assert_eq!(
        actions_of(&manager.tick(ack_at + t1)),
        vec![Action::ActiveClose("t1 expired with no confirmation")]
    );
    assert_eq!(manager.station(0).unwrap().state(), State::Terminated);
}

// ---------------------------------------------------------------------------
// cl.5.3: the caller's own requests, through the same timer wiring
// ---------------------------------------------------------------------------

/// 5-104 cl.5.3 (index 38, printed 37): *"The controlling station must activate
/// the user data transfer on a connection by sending a STARTDT act via this
/// connection."* The act goes out as a directive and is supervised by t1
/// (figures 15/16); the con that answers it releases the supervision.
#[test]
fn clause_5_3_the_start_act_is_a_directive_and_is_supervised_by_t1() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();

    let at = start + Duration::from_secs(1);
    let directives = manager.request_start(0, at).unwrap();
    assert_eq!(
        actions_of(&directives),
        vec![Action::Send(Apci::U(UFunction::StartDtAct))]
    );
    assert_eq!(manager.station(0).unwrap().state(), State::PendingStarted);
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        Some(at + LinkParams::default().t1)
    );

    let con_at = at + Duration::from_secs(2);
    assert_eq!(
        manager
            .on_frame(0, Apci::U(UFunction::StartDtCon), con_at)
            .unwrap(),
        [] as [iec104::manager::Directive; 0]
    );
    assert_eq!(manager.station(0).unwrap().state(), State::Started);
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        None
    );
}

/// A user ASDU the caller hands to a station goes out as a directive and opens
/// t1 (clause 5.1: the frame stays in the send buffer until its N(R) comes
/// back), while the same call on a station that may not send yet is refused by
/// the session and held in its own clause 5.3 queue. The manager does not add a
/// second queue of its own. Clause 5.3's *"The controlling station may send
/// commands or setpoints even if it has not yet received the activation
/// confirmation."* is why the queued ASDU leaves behind the STARTDT act.
#[test]
fn a_sent_i_frame_is_a_directive_and_a_refused_one_is_the_sessions_queue() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    let asdu = asdu();

    // Data transfer is not enabled yet: the session refuses and the caller
    // queues.
    assert!(
        manager
            .send_i_frame(0, &asdu, start + Duration::from_secs(1))
            .unwrap()
            .is_none()
    );
    manager.queue_i_frame(0, &asdu).unwrap();
    assert_eq!(manager.station(0).unwrap().session().pending_user_data(), 1);

    // The STARTDT act and the queued ASDU leave together, in that order.
    let started = manager.request_start(0, start).unwrap();
    assert_eq!(
        actions_of(&started),
        vec![
            Action::Send(Apci::U(UFunction::StartDtAct)),
            Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: asdu.clone(),
            },
        ]
    );
    manager
        .on_frame(0, Apci::U(UFunction::StartDtCon), start)
        .unwrap();
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        Some(start + LinkParams::default().t1),
        "the oldest unconfirmed frame holds t1: the con did not cancel it"
    );

    // A later send is a directive of its own, and does not move t1.
    let at = start + Duration::from_secs(3);
    let directive = manager
        .send_i_frame(0, &asdu, at)
        .unwrap()
        .expect("data transfer is enabled and the k window is open");
    assert_eq!(
        directive,
        Directive::Actions {
            station: 0,
            actions: vec![Action::SendI {
                ns: SeqNo::new(1),
                nr: SeqNo::new(0),
                asdu: asdu.clone(),
            }],
        }
    );
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        Some(start + LinkParams::default().t1)
    );
    assert_eq!(
        manager.station(0).unwrap().session().outstanding_i_frames(),
        2
    );
}

/// A parse error is the connection's reaction (the table of
/// `iec104::link::reaction`), and the manager hands that reaction on as a
/// directive like any other action list; a framing condition produces none.
#[test]
fn a_parse_error_goes_through_the_stations_own_reaction_table() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();

    let framing = manager
        .on_parse_error(0, ParseError::Incomplete { needed: 2, have: 1 }, start)
        .unwrap();
    assert!(framing.is_empty(), "half an APDU is waited on");

    let closing = manager
        .on_parse_error(0, ParseError::ReservedOctetNotZero, start)
        .unwrap();
    assert_eq!(
        actions_of(&closing),
        vec![Action::ActiveClose("reserved control octets are not zero")]
    );
    assert_eq!(manager.station(0).unwrap().state(), State::Terminated);
}

// ---------------------------------------------------------------------------
// the refusals, and the module's own boundary
// ---------------------------------------------------------------------------

/// The manager's three refusals: an empty station list, an index that names no
/// station, and a parameter set the standard's ranges reject. The parameter
/// refusal is the same `ParamError` `Session::with_params` and `Timers::new`
/// return: one validation, not a second one.
#[test]
fn the_manager_refuses_what_it_cannot_manage() {
    assert_eq!(
        ConnectionManager::new(Role::Controlling, Vec::new()).unwrap_err(),
        ManagerError::NoStations
    );

    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    assert_eq!(
        manager.station(1).unwrap_err(),
        ManagerError::StationIndexOutOfRange {
            index: 1,
            stations: 1
        }
    );
    assert_eq!(
        manager
            .on_frame(9, Apci::U(UFunction::TestFrAct), Instant::now())
            .unwrap_err(),
        ManagerError::StationIndexOutOfRange {
            index: 9,
            stations: 1
        }
    );

    let bad = LinkParams {
        k: 0,
        ..LinkParams::default()
    };
    assert_eq!(
        ConnectionManager::new(Role::Controlling, vec![station(), StationConfig::new(bad)])
            .unwrap_err(),
        ManagerError::Params {
            station: 1,
            error: ParamError::KOutOfRange(0)
        }
    );
}

/// The manager is a value, not a runtime: it holds no socket, no clock and no
/// `static`, it is `Send` and `Debug`, and a manager of two stations that is
/// never ticked does nothing at all.
#[test]
fn the_manager_is_a_value_and_does_nothing_until_it_is_ticked() {
    fn assert_send<T: Send + std::fmt::Debug>() {}
    assert_send::<ConnectionManager>();

    let manager = ConnectionManager::new(Role::Controlling, vec![station(), station()]).unwrap();
    assert_eq!(manager.len(), 2);
    assert!(!manager.is_empty());
    assert_eq!(manager.role(), Role::Controlling);
    assert_ne!(format!("{manager:?}"), "");
    assert!(manager.stations()[0].timers().deadline(Timer::T0).is_none());
}

/// Figures 17/18 NOTE 2: t1 is the timer of *each* sent act. A peer that keeps
/// acknowledging our I-frames but never answers our STOPDT act is closed t1
/// after the act, not t1 after its latest acknowledgement.
#[test]
fn acknowledgements_do_not_postpone_the_t1_of_a_pending_act() {
    let start = Instant::now();
    let t1 = LinkParams::default().t1;
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    manager.request_start(0, start).unwrap();
    manager
        .on_frame(0, Apci::U(UFunction::StartDtCon), start)
        .unwrap();
    for _ in 0..3 {
        manager.send_i_frame(0, &asdu(), start).unwrap().unwrap();
    }
    let stop_at = start + Duration::from_secs(1);
    let stop = actions_of(&manager.request_stop(0, stop_at).unwrap());
    assert!(stop.contains(&Action::Send(Apci::U(UFunction::StopDtAct))));

    // The peer confirms one I-frame at 5 s, 10 s and 14 s, and never the act.
    for (second, nr) in [(5, 1), (10, 2), (14, 3)] {
        manager
            .on_frame(
                0,
                Apci::S { nr: SeqNo::new(nr) },
                start + Duration::from_secs(second),
            )
            .unwrap();
    }
    let just_before = actions_of(
        &manager.tick(
            (stop_at + t1)
                .checked_sub(Duration::from_millis(1))
                .unwrap(),
        ),
    );
    assert!(
        !just_before
            .iter()
            .any(|a| matches!(a, Action::ActiveClose(_)))
    );
    let at_deadline = actions_of(&manager.tick(stop_at + t1));
    assert!(
        at_deadline
            .iter()
            .any(|a| matches!(a, Action::ActiveClose(_))),
        "closed t1 after the STOPDT act: {at_deadline:?}"
    );
}

/// The converse of the test above, from the same NOTE 2: confirming a test act
/// says nothing about our I-frames. A peer that answers every TESTFR act (t3
/// shorter than t1, which clause 9 allows) but never acknowledges the I-frame
/// sent at `start` is closed t1 after that I-frame.
#[test]
fn a_confirmed_test_act_does_not_postpone_the_t1_of_an_i_frame() {
    let start = Instant::now();
    let params = LinkParams {
        t3: Duration::from_secs(5),
        ..LinkParams::default()
    };
    let t1 = params.t1;
    let mut manager =
        ConnectionManager::new(Role::Controlling, vec![StationConfig::new(params)]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    manager.request_start(0, start).unwrap();
    manager
        .on_frame(0, Apci::U(UFunction::StartDtCon), start)
        .unwrap();
    manager.send_i_frame(0, &asdu(), start).unwrap().unwrap();

    let mut closed_at = None;
    for tenth in 1..=(t1.as_millis() as u64 / 100) {
        let now = start + Duration::from_millis(tenth * 100);
        let actions = actions_of(&manager.tick(now));
        if actions.iter().any(|a| matches!(a, Action::ActiveClose(_))) {
            closed_at = Some(now);
            break;
        }
        if actions.contains(&Action::Send(Apci::U(UFunction::TestFrAct))) {
            manager
                .on_frame(0, Apci::U(UFunction::TestFrCon), now)
                .unwrap();
        }
    }
    assert_eq!(
        closed_at,
        Some(start + t1),
        "the I-frame was never acknowledged"
    );
}

/// A t0 expiry with no word from the caller is an attempt still in flight,
/// which the caller must abandon; a refused dial is not.
#[test]
fn an_unanswered_attempt_is_reported_as_timed_out() {
    let start = Instant::now();
    let t0 = LinkParams::default().t0;
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    assert_eq!(
        connects(&manager.tick(start + t0)),
        vec![(0, 2, ConnectReason::AttemptTimedOut)]
    );
    manager.on_connection_lost(0).unwrap(); // attempt 2 was refused
    assert_eq!(
        connects(&manager.tick(start + t0 + t0)),
        vec![(0, 3, ConnectReason::AttemptFailed)]
    );
}

// ---------------------------------------------------------------------------
// next_deadline: what an event loop sleeps until
// ---------------------------------------------------------------------------

/// Clause 9's default time-outs (index 114, printed 113), written out rather
/// than read back from `LinkParams::default()`: t0 30 s, t1 15 s, t2 10 s,
/// t3 20 s.
const T0: Duration = Duration::from_secs(30);
const T1: Duration = Duration::from_secs(15);
const T2: Duration = Duration::from_secs(10);
const T3: Duration = Duration::from_secs(20);

/// A controlling station that is dialing waits t0 for its attempt; a
/// controlled manager, which never dials (clause 7.1), has nothing to wait for.
#[test]
fn next_deadline_of_a_dialing_station_is_its_t0() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    assert_eq!(manager.next_deadline(), Some(start + T0));

    let mut controlled = ConnectionManager::new(Role::Controlled, vec![station()]).unwrap();
    controlled.tick(start);
    assert_eq!(controlled.next_deadline(), None);
}

/// Once up, the station's own t1–t3 decide: t3 for an idle connection
/// (clause 5.2), t1 behind a STARTDT act (figures 15/16), t2 behind a received
/// I-frame (clause 5.2), whichever is soonest.
#[test]
fn next_deadline_of_a_connected_station_follows_t1_t2_t3() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    assert_eq!(manager.next_deadline(), Some(start + T3), "idle: t3");

    let act = start + Duration::from_secs(1);
    manager.request_start(0, act).unwrap();
    assert_eq!(manager.next_deadline(), Some(act + T1), "act sent: t1");

    let con = start + Duration::from_secs(2);
    manager
        .on_frame(0, Apci::U(UFunction::StartDtCon), con)
        .unwrap();
    assert_eq!(
        manager.next_deadline(),
        Some(con + T3),
        "confirmed: t3 again"
    );

    let data = start + Duration::from_secs(3);
    manager
        .on_frame(
            0,
            Apci::I {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
            },
            data,
        )
        .unwrap();
    assert_eq!(
        manager.next_deadline(),
        Some(data + T2),
        "unacknowledged: t2"
    );
}

/// The soonest station wins, and a terminated connection (whose `tick` does
/// nothing) does not count.
#[test]
fn next_deadline_is_the_soonest_station_and_skips_a_terminated_one() {
    let start = Instant::now();
    let mut manager =
        ConnectionManager::new(Role::Controlling, vec![station(), station()]).unwrap();
    manager.tick(start);
    let up = start + Duration::from_secs(5);
    manager.on_connection_established(1, up).unwrap();
    assert_eq!(
        manager.next_deadline(),
        Some(up + T3),
        "station 1's t3 first"
    );

    manager.station_mut(1).unwrap().session_mut().close("test");
    assert_eq!(
        manager.next_deadline(),
        Some(start + T0),
        "only station 0's t0"
    );
}

/// A connection whose session closed itself (here a clause 5 violation in the
/// APCI) and that the caller re-establishes without reporting the loss is still
/// a fresh connection: clause 5.1, *"After the establishment of a TCP
/// connection, the send and receive sequence numbers are set to zero"*, so
/// nothing of the old connection is outstanding and no t1 (figures 17/18
/// NOTE 2: *"t1 is the timeout of a sent U-frame or I-frame"*) may run for it.
/// Only the idle timer t3 of clause 5.2 is due.
#[test]
fn a_reestablished_connection_keeps_no_t1_of_the_one_that_closed_itself() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    let act = start + Duration::from_secs(1);
    manager.request_start(0, act).unwrap();
    manager.send_i_frame(0, &asdu(), act).unwrap();
    manager
        .on_parse_error(
            0,
            ParseError::BadSFormatOctet {
                octet1: 0x01,
                octet2: 0x01,
            },
            act,
        )
        .unwrap();
    assert_eq!(manager.station(0).unwrap().state(), State::Terminated);

    let again = start + Duration::from_secs(2);
    manager.on_connection_established(0, again).unwrap();
    assert_eq!(
        manager.station(0).unwrap().session().outstanding_i_frames(),
        0
    );
    assert_eq!(
        manager.station(0).unwrap().timers().deadline(Timer::T1),
        None,
        "the old connection's I-frame is not supervised on the new one"
    );
    assert_eq!(manager.next_deadline(), Some(again + T3));
}

/// A lost connection is due when its attempt's t0 runs out: at once (an
/// instant already past) for one that lasted longer, as here. The next tick
/// asks for the attempt and arms its t0.
#[test]
fn next_deadline_after_a_loss_is_the_new_attempts_t0() {
    let start = Instant::now();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![station()]).unwrap();
    manager.tick(start);
    manager.on_connection_established(0, start).unwrap();
    manager.on_connection_lost(0).unwrap();
    assert_eq!(
        manager.next_deadline(),
        Some(start + T0),
        "the attempt's t0, already past when the loss is a minute later"
    );

    let later = start + Duration::from_secs(60);
    assert_eq!(
        connects(&manager.tick(later)),
        vec![(0, 2, ConnectReason::ConnectionLost)]
    );
    assert_eq!(manager.next_deadline(), Some(later + T0));
}
