//! The I/S/U session state machine.
//!
//! Transitions are pinned against IEC 60870-5-104:2006 clause 5.3 and its state
//! diagrams: figure 17 (controlled station, printed page 41) and figure 18
//! (controlling station, printed page 43). The prose rules that the diagrams
//! encode are quoted in `src/link.rs`.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used)]

use iec104::apci::{Apci, ParseError, SeqNo, UFunction};
use iec104::link::{
    Action, MAX_PENDING_USER_DATA, ParseReaction, QueueError, Role, Session, State, Timer, reaction,
};
use iec104::params::LinkParams;

const fn u(f: UFunction) -> Apci {
    Apci::U(f)
}

const fn i(ns: u16, nr: u16) -> Apci {
    Apci::I {
        ns: SeqNo::new(ns),
        nr: SeqNo::new(nr),
    }
}

const fn s_frame(nr: u16) -> Apci {
    Apci::S { nr: SeqNo::new(nr) }
}

/// The U-function the actions want sent, if any.
fn sent_u(actions: &[Action]) -> Option<UFunction> {
    actions.iter().find_map(|a| match a {
        Action::Send(Apci::U(f)) => Some(*f),
        _ => None,
    })
}

/// The N(R) of an S-frame the actions want sent, if any.
fn sent_s(actions: &[Action]) -> Option<u16> {
    actions.iter().find_map(|a| match a {
        Action::Send(Apci::S { nr }) => Some(nr.get()),
        _ => None,
    })
}

/// The (N(S), N(R), ASDU) of I-frames the actions want sent.
fn sent_i(actions: &[Action]) -> Vec<(u16, u16, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendI { ns, nr, asdu } => Some((ns.get(), nr.get(), asdu.clone())),
            _ => None,
        })
        .collect()
}

/// The same, for the single frame `Session::send_i_frame` returns.
fn sent_i_one(action: &Action) -> Vec<(u16, u16, Vec<u8>)> {
    sent_i(std::slice::from_ref(action))
}

fn closed(actions: &[Action]) -> Option<&'static str> {
    actions.iter().find_map(|a| match a {
        Action::ActiveClose(why) => Some(*why),
        _ => None,
    })
}

#[test]
fn a_fresh_session_is_stopped_in_both_roles() {
    for role in [Role::Controlling, Role::Controlled] {
        let s = Session::new(role);
        assert_eq!(s.state(), State::Stopped);
        assert_eq!(s.role(), role);
    }
}

#[test]
fn controlled_station_confirms_startdt_and_starts() {
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert_eq!(s.state(), State::Stopped);

    let actions = s.on_frame(u(UFunction::StartDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(s.state(), State::Started);
}

#[test]
fn controlled_station_repeats_the_confirmation_for_a_duplicate_startdt() {
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));
    let actions = s.on_frame(u(UFunction::StartDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(s.state(), State::Started);
}

#[test]
fn controlled_station_stops_cleanly_when_nothing_is_unconfirmed() {
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));

    let actions = s.on_frame(u(UFunction::StopDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtCon));
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn controlled_station_defers_stopdt_confirmation_until_frames_are_acknowledged() {
    // Figure 17: STOPDT act[unconfirmed I-frames] leads to the pending state and
    // no confirmation yet. The frames it waits for are the ones clause 5.1 keeps
    // in the send buffer, released when their N(S) comes back as an N(R).
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));
    assert!(s.send_i_frame(b"\x01\x02").is_some());
    assert!(s.send_i_frame(b"\x03\x04").is_some());
    assert_eq!(s.outstanding_i_frames(), 2);

    let actions = s.on_frame(u(UFunction::StopDtAct));
    assert_eq!(sent_u(&actions), None);
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);

    // One frame acknowledged: still no confirmation.
    let actions = s.on_frame(s_frame(1));
    assert_eq!(sent_u(&actions), None);
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);

    // Last one acknowledged -> the confirmation goes out and we are stopped.
    let actions = s.on_frame(s_frame(2));
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtCon));
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn controlling_station_moves_to_plain_pending_stopped_once_its_frames_are_acked() {
    // Figure 18: the unconfirmed pending box is left by
    // `S-frame or I-frame [No unconfirmed I-frames]`; the controlling station
    // then waits for STOPDT con instead of sending it.
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    s.on_frame(u(UFunction::StartDtCon));
    s.send_i_frame(b"\x01").unwrap();
    s.request_stop();
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);

    let actions = s.on_frame(s_frame(1));
    assert_eq!(
        sent_u(&actions),
        None,
        "the controlling station never sends a con"
    );
    assert_eq!(s.state(), State::PendingStopped);

    s.on_frame(u(UFunction::StopDtCon));
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn controlled_station_closes_when_data_arrives_while_stopped() {
    // Figure 17: from STOPPED connection, S-frame[] and I-frame[] lead to an
    // active close. Only U-frames are legal before STARTDT.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert!(closed(&s.on_frame(i(0, 0))).is_some());
    assert_eq!(s.state(), State::Terminated);

    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert!(closed(&s.on_frame(s_frame(0))).is_some());
    assert_eq!(s.state(), State::Terminated);
}

#[test]
fn controlled_station_may_not_send_user_data_before_startdt() {
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert!(!s.user_data_allowed());
    s.on_frame(u(UFunction::StartDtAct));
    assert!(s.user_data_allowed());
    s.on_frame(u(UFunction::StopDtAct));
    assert!(!s.user_data_allowed());
}

#[test]
fn controlling_station_sends_startdt_act_and_waits() {
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();

    let actions = s.request_start();
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(s.state(), State::PendingStarted);

    let actions = s.on_frame(u(UFunction::StartDtCon));
    assert_eq!(actions, vec![]);
    assert_eq!(s.state(), State::Started);
}

#[test]
fn controlling_station_may_send_commands_before_the_startdt_confirmation() {
    // clause 5.3: the controlling station may send commands or setpoints before
    // the activation confirmation arrives.
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    assert!(!s.user_data_allowed(), "stopped means no user data");
    s.request_start();
    assert!(s.user_data_allowed());
    s.on_frame(u(UFunction::StartDtCon));
    assert!(s.user_data_allowed());
}

#[test]
fn controlling_station_stops_cleanly_and_dirty() {
    // Clean: no unconfirmed I-frames.
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    s.on_frame(u(UFunction::StartDtCon));
    let actions = s.request_stop();
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtAct));
    assert_eq!(s.state(), State::PendingStopped);
    let actions = s.on_frame(u(UFunction::StopDtCon));
    assert_eq!(actions, vec![]);
    assert_eq!(s.state(), State::Stopped);

    // Dirty: frames still outstanding -> the unconfirmed pending state.
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    s.on_frame(u(UFunction::StartDtCon));
    s.send_i_frame(b"\x01").unwrap();
    let actions = s.request_stop();
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtAct));
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);
}

#[test]
fn controlling_station_sends_an_immediate_s_frame_while_pending_stopped() {
    // clause 5.3: in the Pending STOPPED and Pending UNCONFIRMED STOPPED
    // states, the controlling station should answer each received I-frame
    // with an S-frame straight away. The N(R) that frame carries comes
    // from the sequence layer (`iec104::seq`).
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    s.on_frame(u(UFunction::StartDtCon));
    s.request_stop();

    let actions = s.on_frame(i(0, 0));
    assert_eq!(
        sent_s(&actions),
        Some(1),
        "S(1) acknowledges the I-frame that just arrived"
    );
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::DeliverData { .. })),
        "the data is still delivered, got {actions:?}"
    );
}

#[test]
fn t1_expiry_closes_the_connection() {
    // Control direction, and the case the prose calls out explicitly: an
    // unconfirmed STARTDT makes the controlling station close the connection.
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    let actions = s.on_timeout(Timer::T1);
    assert!(closed(&actions).is_some(), "expected an active close");
    assert_eq!(s.state(), State::Terminated);

    // Controlled station: a t1 expiry closes the connection the same way.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));
    let actions = s.on_timeout(Timer::T1);
    assert!(closed(&actions).is_some());
    assert_eq!(s.state(), State::Terminated);
}

#[test]
fn testfr_is_confirmed_in_every_live_state() {
    for (role, setup) in [
        (Role::Controlling, 0usize),
        (Role::Controlled, 0),
        (Role::Controlling, 1),
        (Role::Controlled, 1),
    ] {
        let mut s = Session::new(role);
        s.on_connection_established();
        if setup == 1 {
            match role {
                Role::Controlling => {
                    s.request_start();
                    s.on_frame(u(UFunction::StartDtCon));
                }
                Role::Controlled => {
                    s.on_frame(u(UFunction::StartDtAct));
                }
            }
        }
        let actions = s.on_frame(u(UFunction::TestFrAct));
        assert_eq!(sent_u(&actions), Some(UFunction::TestFrCon), "{role:?}");
        assert_ne!(s.state(), State::Terminated);
    }
}

#[test]
fn connection_loss_terminates_the_session() {
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    s.on_frame(u(UFunction::StartDtCon));
    s.on_connection_lost();
    assert_eq!(s.state(), State::Terminated);
}

#[test]
fn starting_a_session_twice_is_not_an_error_but_is_not_a_second_act_either() {
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    let again = s.request_start();
    assert_eq!(again, vec![], "a second STARTDT act is not sent");
    assert_eq!(s.state(), State::PendingStarted);
}

// ---------------------------------------------------------------------------
// The session's view of the sequence numbers, the k/w window and the
// acknowledgement policy (clause 5.1 and 5.5).
// ---------------------------------------------------------------------------

fn session_with(role: Role, k: u16, w: u16) -> Session {
    let params = LinkParams {
        k,
        w,
        ..LinkParams::default()
    };
    Session::with_params(role, params).expect("test parameters are admissible")
}

/// A controlling station that has completed the STARTDT handshake.
fn started_controlling(k: u16, w: u16) -> Session {
    let mut s = session_with(Role::Controlling, k, w);
    s.on_connection_established();
    s.request_start();
    s.on_frame(u(UFunction::StartDtCon));
    assert_eq!(s.state(), State::Started);
    s
}

#[test]
fn a_fresh_session_reports_sequence_numbers_of_zero() {
    // clause 5.1: both sequence numbers start at zero once the TCP connection
    // is established.
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    assert_eq!(s.v_s().get(), 0);
    assert_eq!(s.v_r().get(), 0);
    assert_eq!(s.outstanding_i_frames(), 0);
}

#[test]
fn a_sent_frame_is_stamped_with_ns_and_the_current_nr() {
    let mut s = started_controlling(12, 8);
    let actions = s.send_i_frame(b"\x01\x02").unwrap();
    assert_eq!(sent_i_one(&actions), vec![(0, 0, b"\x01\x02".to_vec())]);

    // One frame received from the peer: the next outgoing frame acknowledges it.
    s.on_frame(i(0, 0));
    let actions = s.send_i_frame(b"\x03").unwrap();
    assert_eq!(sent_i_one(&actions), vec![(1, 1, b"\x03".to_vec())]);
    assert_eq!(s.v_s().get(), 2);
    assert_eq!(s.v_r().get(), 1);
}

#[test]
fn no_user_data_before_startdt_and_none_while_the_window_is_full() {
    let mut s = session_with(Role::Controlled, 2, 1);
    s.on_connection_established();
    assert!(s.send_i_frame(b"\x01").is_none(), "stopped: no user data");
    assert!(!s.can_send_i_frame());

    s.on_frame(u(UFunction::StartDtAct));
    assert!(s.can_send_i_frame());
    assert!(s.send_i_frame(b"\x01").is_some());
    assert!(s.send_i_frame(b"\x02").is_some());
    assert!(
        s.send_i_frame(b"\x03").is_none(),
        "k = 2 unacknowledged frames: the transmitter stops"
    );

    s.on_frame(s_frame(2));
    assert!(
        s.can_send_i_frame(),
        "the acknowledgement reopened the window"
    );
    assert_eq!(
        sent_i_one(&s.send_i_frame(b"\x03").unwrap()),
        vec![(2, 0, b"\x03".to_vec())]
    );
}

#[test]
fn the_session_emits_an_s_frame_after_w_received_i_frames() {
    // clause 5.5: the receiver acknowledges no later than the w-th received
    // I-format APDU.
    let mut s = started_controlling(12, 2);
    assert_eq!(
        s.on_frame(i(0, 0)),
        vec![Action::DeliverData {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0),
        }]
    );
    assert_eq!(
        s.on_frame(i(1, 0)),
        vec![
            Action::DeliverData {
                ns: SeqNo::new(1),
                nr: SeqNo::new(0),
            },
            Action::Send(Apci::S { nr: SeqNo::new(2) }),
        ]
    );
}

#[test]
fn a_t2_expiry_acknowledges_data_that_w_never_did() {
    // clause 5.2: t2 is the acknowledgement time-out for when no data flows.
    // Without it a single received frame would never be confirmed.
    let mut s = started_controlling(12, 8);
    assert!(!s.ack_pending());
    s.on_frame(i(0, 0));
    assert!(s.ack_pending());
    let actions = s.on_timeout(Timer::T2);
    assert_eq!(sent_s(&actions), Some(1));
    assert!(!s.ack_pending());

    // Nothing received since the last acknowledgement: t2 does nothing.
    assert_eq!(s.on_timeout(Timer::T2), vec![]);
}

#[test]
fn a_t3_expiry_sends_a_test_frame() {
    // clause 5.2: an open connection with no traffic may be tested now and
    // then from either side with a test APDU (TESTFR act), which the receiver
    // confirms with TESTFR con; either station may start the test once a set
    // idle period without data transfer has run out (a time-out). Figure 13
    // draws that expiry as
    // `Time-out t3` → `U (TESTFR act)`.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert_eq!(
        s.on_timeout(Timer::T3),
        vec![Action::Send(Apci::U(UFunction::TestFrAct))]
    );

    // A started connection is tested too: it is idleness that starts the
    // procedure, not the Start/Stop state.
    let mut s = started_controlling(12, 8);
    assert_eq!(sent_u(&s.on_timeout(Timer::T3)), Some(UFunction::TestFrAct));

    // There is no connection left to test once it has been terminated.
    s.on_connection_lost();
    assert_eq!(s.on_timeout(Timer::T3), vec![]);
}

#[test]
fn a_wrong_ns_closes_the_connection() {
    // Figure 11: a disturbed sequence is a sequence error, and the diagram
    // marks an active close. It also draws `S(1) (optional)` between the two,
    // which is the accepted `I(0,0)` being confirmed before the close (see
    // `the_sequence_error_of_figure_11_confirms_before_closing` for the figure
    // reading and the full assertion).
    let mut s = started_controlling(12, 8);
    s.on_frame(i(0, 0));
    let actions = s.on_frame(i(2, 0));
    assert!(closed(&actions).is_some(), "got {actions:?}");
    assert_eq!(s.state(), State::Terminated);
}

#[test]
fn an_acknowledgement_for_a_frame_we_never_sent_closes_the_connection() {
    // clause 5.1 has N(R) acknowledge up to the number whose APDUs arrived
    // correctly; a number we never sent is a protocol error. The
    // standard does not name the reaction, so this closes the connection, the
    // same reaction figure 11 gives a bad N(S).
    let mut s = started_controlling(12, 8);
    let actions = s.on_frame(s_frame(1));
    assert!(closed(&actions).is_some(), "got {actions:?}");
    assert_eq!(s.state(), State::Terminated);
}

#[test]
fn retransmission_replays_the_send_buffer_without_moving_the_counters() {
    // clause 5.1: the sender keeps its APDUs buffered until its own send
    // sequence number comes back to it as a receive sequence number. The
    // buffer is the replay source; the standard's own reaction to
    // t1 (figure 12) is an active close, so replaying is a caller decision.
    let mut s = started_controlling(12, 8);
    s.send_i_frame(b"\x11").unwrap();
    s.send_i_frame(b"\x22").unwrap();
    let v_s = s.v_s().get();
    assert_eq!(s.outstanding_i_frames(), 2);
    assert_eq!(s.outstanding_frames().len(), 2);

    let actions = s.retransmit();
    assert_eq!(
        sent_i(&actions),
        vec![(0, 0, b"\x11".to_vec()), (1, 0, b"\x22".to_vec())]
    );
    assert_eq!(s.v_s().get(), v_s, "replaying does not advance V(S)");
    assert_eq!(s.outstanding_i_frames(), 2);
}

#[test]
fn the_k_window_is_read_from_the_link_parameters() {
    // clause 5.5's k is a per-station selected value, so the session takes it
    // from `LinkParams` instead of hardcoding the standard's default of 12.
    let mut s = started_controlling(1, 1);
    assert!(s.send_i_frame(b"\x01").is_some());
    assert!(
        s.send_i_frame(b"\x02").is_none(),
        "k = 1 allows one outstanding I-frame only"
    );

    let mut default = started_controlling(12, 8);
    for _ in 0..12 {
        assert!(default.send_i_frame(b"\x01").is_some());
    }
    assert!(
        default.send_i_frame(b"\x01").is_none(),
        "the default k = 12"
    );
}

#[test]
fn a_duplicate_acknowledgement_is_harmless() {
    // Real peers repeat their N(R) on every frame; a number at or below the
    // oldest outstanding frame must neither release anything nor be an error.
    let mut s = started_controlling(12, 8);
    s.send_i_frame(b"\x01").unwrap();
    assert_eq!(s.on_frame(s_frame(1)), vec![]);
    assert_eq!(s.outstanding_i_frames(), 0);
    let actions = s.on_frame(s_frame(1));
    assert_eq!(actions, vec![], "a repeated S(1) is a no-op");
    assert_eq!(s.state(), State::Started);
}

/// True when the first action matching `first` precedes the first matching
/// `second`.
fn precedes(
    actions: &[Action],
    first: impl Fn(&Action) -> bool,
    second: impl Fn(&Action) -> bool,
) -> bool {
    matches!(
        (actions.iter().position(first), actions.iter().position(second)),
        (Some(a), Some(b)) if a < b
    )
}

#[test]
fn controlled_station_acknowledges_received_frames_before_stopdt_con() {
    // clause 5.3 (figure 18's own footnote): the controlled station should
    // confirm every received message before it returns the STOPDT con, and
    // where messages from the controlling station are still unconfirmed it
    // must confirm them with an S-frame before the STOPDT con goes out.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));
    s.on_frame(i(0, 0));
    assert!(s.ack_pending(), "one received I-frame is not yet confirmed");

    let actions = s.on_frame(u(UFunction::StopDtAct));
    assert_eq!(
        sent_s(&actions),
        Some(1),
        "S(1) confirms the received frame"
    );
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtCon));
    assert!(
        precedes(
            &actions,
            |a| matches!(a, Action::Send(Apci::S { .. })),
            |a| matches!(a, Action::Send(Apci::U(UFunction::StopDtCon))),
        ),
        "the acknowledgement goes out before the confirmation, got {actions:?}"
    );
    assert!(!s.ack_pending());
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn a_deferred_stopdt_con_also_acknowledges_received_frames_first() {
    // The same clause 5.3 rule on figure 17's deferred path: STOPDT act while
    // our own I-frames are unconfirmed, then the S-frame that confirms them.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));
    s.send_i_frame(b"\x01").unwrap();
    s.on_frame(i(0, 0));
    s.on_frame(i(1, 0));
    assert!(s.ack_pending());
    s.on_frame(u(UFunction::StopDtAct));
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);

    let actions = s.on_frame(s_frame(1));
    assert_eq!(
        sent_s(&actions),
        Some(2),
        "S(2) confirms both received frames"
    );
    assert!(
        precedes(
            &actions,
            |a| matches!(a, Action::Send(Apci::S { .. })),
            |a| matches!(a, Action::Send(Apci::U(UFunction::StopDtCon))),
        ),
        "the acknowledgement goes out before the confirmation, got {actions:?}"
    );
    assert!(!s.ack_pending());
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn controlling_station_acknowledges_received_frames_before_stopdt_act() {
    // clause 5.3: the controlling station should still confirm every received
    // message before it sends the STOPDT act.
    let mut s = started_controlling(12, 8);
    s.on_frame(i(0, 0));
    assert!(s.ack_pending());

    let actions = s.request_stop();
    assert_eq!(sent_s(&actions), Some(1));
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtAct));
    assert!(
        precedes(
            &actions,
            |a| matches!(a, Action::Send(Apci::S { .. })),
            |a| matches!(a, Action::Send(Apci::U(UFunction::StopDtAct))),
        ),
        "the acknowledgement goes out before STOPDT act, got {actions:?}"
    );
    assert!(!s.ack_pending());
    assert_eq!(s.state(), State::PendingStopped);
}

#[test]
fn controlled_station_closes_on_data_while_pending_unconfirmed_stopped() {
    // Figure 17 (controlled station): the `Pending UNCONFIRMED STOPPED
    // connection` box exits on "Timeout t1[]/Active close or I-frame[]/Active
    // close"; it has no I-frame self-loop. Only figure 18's controlling-station
    // box does, which is what clause 5.3's paragraph on answering an I-frame
    // with an immediate S-frame is about.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));
    s.send_i_frame(b"\x01").unwrap();
    assert_eq!(sent_u(&s.on_frame(u(UFunction::StopDtAct))), None);
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);

    let actions = s.on_frame(i(0, 0));
    assert!(closed(&actions).is_some(), "got {actions:?}");
    assert_eq!(s.state(), State::Terminated);
}

#[test]
fn controlling_station_answers_data_while_pending_unconfirmed_stopped() {
    // Figure 18's counterpart: the same box self-loops on
    // "U-frame[]/ or S-frame[]/ or I-frame[]/", and clause 5.3 says the
    // controlling station sends an S-frame immediately for an I-frame it
    // receives in either pending stopped state.
    let mut s = started_controlling(12, 8);
    s.send_i_frame(b"\x01").unwrap();
    s.request_stop();
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);

    let actions = s.on_frame(i(0, 0));
    assert_eq!(sent_s(&actions), Some(1));
    assert!(matches!(actions.first(), Some(Action::DeliverData { .. })));
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);
}

// ---------------------------------------------------------------------------
// The TESTFR keep-alive and its edge cases (clause 5.2, figures 13/14).
//
// The scheduling side (t3's expiry, the retrigger on every received frame) is
// `tests/timers.rs`; what is pinned here is the *policy* the session owns: when
// it must not initiate a test, and how a repeated or unsolicited act/con is
// handled.
// ---------------------------------------------------------------------------

/// A session in each state that is still alive, built the way the transition
/// tables of figures 17/18 build it.
fn every_live_state() -> Vec<(&'static str, Session)> {
    let mut out = Vec::new();

    for role in [Role::Controlling, Role::Controlled] {
        let mut s = Session::new(role);
        s.on_connection_established();
        out.push(("Stopped", s));
    }

    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();
    out.push(("PendingStarted", s));

    for role in [Role::Controlling, Role::Controlled] {
        // STARTED: the controlling station via the request, the controlled one
        // by being told to start.
        out.push(("Started", started_session(role)));

        // PendingStopped (controlling only, nothing outstanding) and
        // PendingUnconfirmedStopped (either role, an I-frame still in the send
        // buffer): the states whose stop has not completed yet.
        if role == Role::Controlling {
            let mut s = started_controlling(12, 8);
            s.request_stop();
            assert_eq!(s.state(), State::PendingStopped);
            out.push(("PendingStopped", s));
        }
        let mut s = started_session(role);
        s.send_i_frame(b"\x01").expect("data transfer is enabled");
        match role {
            // The controlling station sends the act; its own outstanding frame
            // keeps it from reaching the plain pending state.
            Role::Controlling => {
                let actions = s.request_stop();
                assert_eq!(sent_u(&actions), Some(UFunction::StopDtAct));
            }
            // Figure 17: on STOPDT act[unconfirmed I-frames] the confirmation
            // waits for the outstanding frame, so nothing goes out yet.
            Role::Controlled => {
                assert_eq!(s.on_frame(u(UFunction::StopDtAct)), vec![]);
            }
        }
        assert_eq!(s.state(), State::PendingUnconfirmedStopped);
        out.push(("PendingUnconfirmedStopped", s));
    }

    out
}

/// A session of `role` that has completed the STARTDT handshake.
fn started_session(role: Role) -> Session {
    match role {
        Role::Controlling => started_controlling(12, 8),
        Role::Controlled => {
            let mut s = Session::new(Role::Controlled);
            s.on_connection_established();
            s.on_frame(u(UFunction::StartDtAct));
            assert_eq!(s.state(), State::Started);
            s
        }
    }
}

#[test]
fn a_test_act_is_answered_with_exactly_one_con_from_every_live_state() {
    // clause 5.2: an idle open connection may be tested from either side with
    // TESTFR act, which the receiver confirms with TESTFR con. Every live state answers,
    // and the answer is exactly one con; it is not a state transition.
    for (name, mut s) in every_live_state() {
        let before = s.state();
        let actions = s.on_frame(u(UFunction::TestFrAct));
        assert_eq!(
            actions,
            vec![Action::Send(Apci::U(UFunction::TestFrCon))],
            "{name}"
        );
        assert_eq!(s.state(), before, "{name}: a test is no transition");
    }
}

#[test]
fn a_repeated_test_act_is_confirmed_again() {
    // A repeat is the peer's own t1 retransmission (figure 14 draws the
    // unconfirmed act ending in `Active close`), so the act must be answered
    // again rather than swallowed, one con per act received.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    for _ in 0..2 {
        assert_eq!(
            s.on_frame(u(UFunction::TestFrAct)),
            vec![Action::Send(Apci::U(UFunction::TestFrCon))]
        );
    }
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn a_second_test_act_is_not_sent_while_one_is_outstanding() {
    // Figure 14 is the reason: an act we sent is supervised by t1, and its
    // expiry is an active close. Starting a second procedure while the first is
    // still in flight would supervise two acts with one t1.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert_eq!(
        s.on_timeout(Timer::T3),
        vec![Action::Send(Apci::U(UFunction::TestFrAct))]
    );
    assert!(s.test_pending(), "the act awaits its con");

    assert_eq!(s.on_timeout(Timer::T3), vec![], "one at a time");

    // figure 13: the con ends the procedure, and the next idle interval may
    // start a new one (clause 5.2: once a set idle period without data
    // transfer has run out, a time-out).
    assert_eq!(s.on_frame(u(UFunction::TestFrCon)), vec![]);
    assert!(!s.test_pending());
    assert_eq!(sent_u(&s.on_timeout(Timer::T3)), Some(UFunction::TestFrAct));
}

#[test]
fn an_unsolicited_test_con_names_no_reaction() {
    // Figure 13 draws the con only as the answer to an act. The standard names
    // no reaction for a con with no procedure in flight, so it is ignored.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert_eq!(s.on_frame(u(UFunction::TestFrCon)), vec![]);
    assert!(!s.test_pending());
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn an_unconfirmed_test_act_ends_in_the_active_close() {
    // Figure 14: `U (TESTFR act)` → `Time-out t1` → `Active close` → `Active
    // open follows (see Figures 19 to 22)`.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert_eq!(sent_u(&s.on_timeout(Timer::T3)), Some(UFunction::TestFrAct));

    let actions = s.on_timeout(Timer::T1);
    assert!(closed(&actions).is_some(), "got {actions:?}");
    assert_eq!(s.state(), State::Terminated);
    assert!(!s.test_pending(), "nothing is left to confirm");
}

#[test]
fn a_new_connection_starts_with_no_test_in_flight() {
    // A fresh TCP connection owes no confirmation to anyone (clause 5.1: the
    // sequence numbers restart at zero, and so does the test procedure).
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    assert_eq!(sent_u(&s.on_timeout(Timer::T3)), Some(UFunction::TestFrAct));

    s.on_connection_lost();
    s.on_connection_established();
    assert!(!s.test_pending());
    assert_eq!(sent_u(&s.on_timeout(Timer::T3)), Some(UFunction::TestFrAct));
}

// ---------------------------------------------------------------------------
// The controlled station's pending user-data queue and the figure-18
// pending-state rules (clause 5.3).
//
// Clause 5.3: the controlled station holds back pending user data until after
// the STARTDT con. That makes the session the owner of the queue (it is
// the only layer that knows when the con went out), and it is flushed against
// the k window of clause 5.5, so what does not fit stays queued.
// ---------------------------------------------------------------------------

#[test]
fn data_handed_over_before_startdt_waits_for_the_confirmation() {
    // clause 5.3: the controlled station holds back pending user data until
    // after the STARTDT con. The frame, not just its transmission, belongs to
    // the session: the sequence number is stamped when the con goes out.
    let mut s = session_with(Role::Controlled, 12, 8);
    s.on_connection_established();
    assert!(s.queue_i_frame(b"\x11").is_ok());
    assert_eq!(s.pending_user_data(), 1);

    let actions = s.on_frame(u(UFunction::StartDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(sent_i(&actions), vec![(0, 0, b"\x11".to_vec())]);
    assert!(
        precedes(
            &actions,
            |a| matches!(a, Action::Send(Apci::U(UFunction::StartDtCon))),
            |a| matches!(a, Action::SendI { .. }),
        ),
        "the data goes out after the confirmation, got {actions:?}"
    );
    assert_eq!(s.pending_user_data(), 0);
    assert_eq!(s.state(), State::Started);
}

#[test]
fn nothing_is_emitted_while_data_transfer_is_stopped() {
    // The gate half of the same rule: a flush in `Stopped` emits nothing, and
    // the ASDU stays where it is rather than being dropped.
    let mut s = session_with(Role::Controlled, 12, 8);
    s.on_connection_established();
    s.queue_i_frame(b"\x11").unwrap();
    assert_eq!(s.flush_pending(), vec![]);
    assert_eq!(s.pending_user_data(), 1);
}

#[test]
fn a_queue_beyond_the_k_window_keeps_the_surplus_until_an_acknowledgement() {
    // clause 5.5: the sender stops sending once k I-format APDUs are
    // unacknowledged. The limit applies at flush time too, so the surplus
    // stays queued and goes out when the N(R) of clause 5.1 releases a slot.
    let mut s = session_with(Role::Controlled, 2, 8);
    s.on_connection_established();
    for asdu in [b"\x01".as_slice(), b"\x02", b"\x03"] {
        s.queue_i_frame(asdu).unwrap();
    }
    assert_eq!(s.pending_user_data(), 3);

    let actions = s.on_frame(u(UFunction::StartDtAct));
    assert_eq!(
        sent_i(&actions),
        vec![(0, 0, b"\x01".to_vec()), (1, 0, b"\x02".to_vec())],
        "k = 2 frames go out with the confirmation"
    );
    assert_eq!(s.pending_user_data(), 1, "the third frame is still queued");

    // The acknowledgement reopens the window, and the session emits the
    // surplus by itself with no caller action.
    let actions = s.on_frame(s_frame(1));
    assert_eq!(sent_i(&actions), vec![(2, 0, b"\x03".to_vec())]);
    assert_eq!(s.pending_user_data(), 0);
}

#[test]
fn a_connection_that_is_never_started_refuses_data_beyond_the_limit() {
    // A peer that connects, never sends STARTDT and answers every TESTFR keeps
    // the connection Stopped for good, so clause 5.3's queue would never drain.
    // It stops at the limit and refuses the next ASDU instead of growing.
    let mut s = session_with(Role::Controlled, 12, 8);
    s.on_connection_established();
    for _ in 0..MAX_PENDING_USER_DATA {
        assert_eq!(s.queue_i_frame(b"\x01"), Ok(()));
    }
    assert_eq!(s.queue_i_frame(b"\x01"), Err(QueueError::Full));
    assert_eq!(s.pending_user_data(), MAX_PENDING_USER_DATA);
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn the_queue_is_dropped_when_the_connection_goes_away() {
    // clause 5.1: both sequence numbers start at zero once the TCP connection
    // is established. A frame queued under the old
    // connection belongs to that connection, so it is not carried over: the
    // application re-supplies its data on the new one.
    let mut s = session_with(Role::Controlled, 12, 8);
    s.on_connection_established();
    s.queue_i_frame(b"\x01").unwrap();
    s.on_connection_lost();
    assert_eq!(s.pending_user_data(), 0);
    assert_eq!(
        s.queue_i_frame(b"\x01"),
        Err(QueueError::NotConnected),
        "nothing can be queued for a connection that is gone"
    );

    s.on_connection_established();
    assert_eq!(s.pending_user_data(), 0);
    let actions = s.on_frame(u(UFunction::StartDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(sent_i(&actions), vec![], "the new connection is clean");
}

#[test]
fn the_queue_survives_a_stop_and_goes_out_on_the_next_start() {
    // STOPDT deactivates the monitoring direction; it does not discard the
    // pending data, which is released by the next STARTDT con (clause 5.3).
    let mut s = started_session(Role::Controlled);
    s.queue_i_frame(b"\x77").unwrap();
    assert_eq!(s.pending_user_data(), 1);

    let actions = s.on_frame(u(UFunction::StopDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtCon));
    assert_eq!(s.pending_user_data(), 1, "a stop keeps the pending data");

    let actions = s.on_frame(u(UFunction::StartDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(sent_i(&actions), vec![(0, 0, b"\x77".to_vec())]);
}

#[test]
fn a_controlling_station_releases_its_queue_when_it_starts_the_transfer() {
    // clause 5.3: the controlling station may send commands or setpoints before
    // the activation confirmation arrives, so its own queue
    // is released by the act it sends, not by the con it waits for.
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.queue_i_frame(b"\x01").unwrap();

    let actions = s.request_start();
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(sent_i(&actions), vec![(0, 0, b"\x01".to_vec())]);
    assert!(
        precedes(
            &actions,
            |a| matches!(a, Action::Send(Apci::U(UFunction::StartDtAct))),
            |a| matches!(a, Action::SendI { .. }),
        ),
        "the command follows the act, got {actions:?}"
    );
    assert_eq!(s.pending_user_data(), 0);

    // ... and the con changes nothing about it.
    assert_eq!(s.on_frame(u(UFunction::StartDtCon)), vec![]);
    assert_eq!(s.pending_user_data(), 0);
}

#[test]
fn a_startdt_act_reverses_a_pending_stop() {
    // Figure 17's `Pending UNCONFIRMED STOPPED connection` box has no
    // STARTDT-act exit: the standard never describes the act arriving there.
    // The session applies the function's defined effect (clause 5.3: the act
    // activates user data transfer and is answered with a con) and abandons the
    // pending stop. Nothing is lost (the unconfirmed frames stay in the send
    // buffer for the peer's N(R)), but the STOPDT con obligation is dropped
    // with the stop. The standard leaves this undefined and TS 60870-5-604
    // does not settle it; the `src/link.rs` module doc records the choice.
    let mut s = Session::new(Role::Controlled);
    s.on_connection_established();
    s.on_frame(u(UFunction::StartDtAct));
    s.send_i_frame(b"\x01").unwrap();
    assert_eq!(s.on_frame(u(UFunction::StopDtAct)), vec![]);
    assert_eq!(s.state(), State::PendingUnconfirmedStopped);

    let actions = s.on_frame(u(UFunction::StartDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(s.state(), State::Started);
    assert_eq!(s.outstanding_i_frames(), 1, "the frame is still ours");
}

#[test]
fn a_controlling_station_closes_on_data_while_pending_started() {
    // Figure 18: the `Pending STARTED connection` box carries its own
    // `U-frame[]/` self-loop, `STARTDT con[]/` -> STARTED and
    // `Timeout t1[]/Active close or I-frame[]/Active close or S-frame[]/Active
    // close` -> stop. It shares that exit with the STOPPED box and must not
    // inherit anything else from it.
    for frame in [s_frame(0), i(0, 0)] {
        let mut s = Session::new(Role::Controlling);
        s.on_connection_established();
        s.request_start();
        assert_eq!(s.state(), State::PendingStarted);

        let actions = s.on_frame(frame);
        assert!(closed(&actions).is_some(), "got {actions:?}");
        assert_eq!(s.state(), State::Terminated);
    }
}

#[test]
fn a_controlling_station_reaches_started_from_pending_started() {
    // The other exit of figure 18's `Pending STARTED connection` box:
    // `STARTDT con[]/` -> `STARTED connection`, with no action of ours.
    let mut s = Session::new(Role::Controlling);
    s.on_connection_established();
    s.request_start();

    let actions = s.on_frame(u(UFunction::StartDtCon));
    assert_eq!(actions, vec![]);
    assert_eq!(s.state(), State::Started);
}

// ---------------------------------------------------------------------------
// The connection-level error paths (clause 5 parse rules, clause 5.1/5.2
// sequence and t1 reactions, figures 10/11 NOTE).
//
// `src/apci.rs` reports every malformed APCI as a typed `ParseError`; the
// session decides what the *connection* does with each class. The reaction
// table lives in the `src/link.rs` module doc, and every close goes through
// the session's single `terminate()` funnel.
// ---------------------------------------------------------------------------

/// Every `ParseError` the codec can report, with the class it belongs to.
fn every_parse_error() -> Vec<(&'static str, ParseError)> {
    vec![
        // No start octet where one belongs: the peer is not speaking clause 5.
        ("BadStart", ParseError::BadStart(0x00)),
        // A framing-layer condition: the framer buffers until the promised
        // length arrives.
        ("Incomplete", ParseError::Incomplete { needed: 2, have: 0 }),
        // An illegal APCI: the peer is not speaking clause 5.
        ("BadLength", ParseError::BadLength(3)),
        ("IFormatWithoutAsdu", ParseError::IFormatWithoutAsdu(4)),
        (
            "BadSFormatOctet",
            ParseError::BadSFormatOctet {
                octet1: 0x03,
                octet2: 0x00,
            },
        ),
        ("UnknownUFunction", ParseError::UnknownUFunction(0x2f)),
        ("ReservedOctetNotZero", ParseError::ReservedOctetNotZero),
        // Encode-side only: no peer can send these.
        (
            "FormatPayloadMismatch",
            ParseError::FormatPayloadMismatch("test"),
        ),
        ("AsduTooLong", ParseError::AsduTooLong(250)),
    ]
}

#[test]
fn every_parser_error_has_exactly_one_reaction_class() {
    // The table in the `src/link.rs` module doc names every class the parser
    // reports; this asserts the classification itself rather than the prose.
    let expected = [
        ("BadStart", ParseReaction::Close("")),
        ("Incomplete", ParseReaction::Framing),
        ("BadLength", ParseReaction::Close("")),
        ("IFormatWithoutAsdu", ParseReaction::Close("")),
        ("BadSFormatOctet", ParseReaction::Close("")),
        ("UnknownUFunction", ParseReaction::Close("")),
        ("ReservedOctetNotZero", ParseReaction::Close("")),
        ("FormatPayloadMismatch", ParseReaction::EncoderOnly),
        ("AsduTooLong", ParseReaction::EncoderOnly),
    ];
    let errors = every_parse_error();
    assert_eq!(
        errors.len(),
        expected.len(),
        "a new ParseError variant needs a row in this table"
    );
    for ((name, err), (want_name, want)) in errors.into_iter().zip(expected) {
        assert_eq!(name, want_name);
        match (reaction(err), want) {
            (ParseReaction::Close(why), ParseReaction::Close(_)) => assert!(
                !why.is_empty(),
                "{name}: a close has to name its reason for the log"
            ),
            (ParseReaction::Framing, ParseReaction::Framing)
            | (ParseReaction::EncoderOnly, ParseReaction::EncoderOnly) => {}
            (got, want) => panic!("{name}: unexpected reaction {got:?}, wanted {want:?}"),
        }
    }
}

#[test]
fn a_framing_condition_is_not_a_connection_error() {
    // A short buffer is simply waited on: TCP hands over arbitrary chunk
    // boundaries, so half an APDU is no reason to drop a live connection. An
    // unconfirmed received frame would make a close visible (an S-frame would
    // precede it), so having one here is the test.
    let mut s = started_controlling(12, 8);
    s.on_frame(i(0, 0));
    assert!(s.ack_pending(), "the frame is unconfirmed");
    assert_eq!(
        s.on_parse_error(ParseError::Incomplete { needed: 2, have: 1 }),
        vec![]
    );
    assert_eq!(s.state(), State::Started);
}

#[test]
fn an_octet_where_the_start_octet_belongs_closes_the_connection() {
    // Clause 5: `68H` marks where a frame starts in the stream. TCP neither
    // loses, corrupts nor reorders octets, so an octet
    // other than 68H where a frame must start means the peer is not speaking
    // clause 5 (a scanner, an HTTP request, a broken stack), and skipping to
    // the next 68H would read whatever the peer sent next as a frame. The
    // connection closes, as it does for a malformed APCI, and as lib60870-C
    // closes it (its receiveMessage takes a first octet other than 68H as a
    // message error on both the controlling and the controlled side).
    for octet in [0x00, 0xFF, b'G'] {
        let mut s = started_controlling(12, 8);
        let actions = s.on_parse_error(ParseError::BadStart(octet));
        let why = closed(&actions).unwrap_or_else(|| panic!("{octet:#04x}: {actions:?}"));
        assert!(!why.is_empty(), "{octet:#04x}: the close names its reason");
        assert_eq!(s.state(), State::Terminated, "{octet:#04x}");
    }
}

#[test]
fn a_malformed_control_field_closes_the_connection() {
    // The standard names no reaction for an APCI that violates clause 5, and
    // a frame that cannot be decoded cannot be acknowledged either, so the
    // connection closes: the answer figures 11 and 17/18 give in the same
    // class of situation. One case per malformed class.
    for (name, err) in [
        ("BadLength", ParseError::BadLength(3)),
        ("IFormatWithoutAsdu", ParseError::IFormatWithoutAsdu(4)),
        (
            "BadSFormatOctet",
            ParseError::BadSFormatOctet {
                octet1: 0x03,
                octet2: 0x00,
            },
        ),
        ("UnknownUFunction", ParseError::UnknownUFunction(0x2f)),
        ("ReservedOctetNotZero", ParseError::ReservedOctetNotZero),
    ] {
        let mut s = started_controlling(12, 8);
        let actions = s.on_parse_error(err);
        let why = closed(&actions).unwrap_or_else(|| panic!("{name}: {actions:?}"));
        assert!(!why.is_empty(), "{name}: the close has to name its reason");
        assert_eq!(s.state(), State::Terminated, "{name}");

        // The aftermath of the close decision: nothing more goes out.
        assert!(!s.user_data_allowed(), "{name}");
        assert!(s.send_i_frame(b"\x01").is_none(), "{name}");
        assert_eq!(s.flush_pending(), vec![], "{name}");
        assert_eq!(
            s.queue_i_frame(b"\x01"),
            Err(QueueError::NotConnected),
            "{name}"
        );
        // A second error after the close is a no-op, not a second close.
        assert_eq!(s.on_parse_error(err), vec![], "{name}");
    }
}

#[test]
fn an_encoder_only_error_names_no_connection_reaction() {
    // `FormatPayloadMismatch` and `AsduTooLong` are rejected by
    // `Apdu::encode`; no peer can put them on the wire, so they say nothing
    // about the connection and must not close a live one.
    for (name, err) in [
        (
            "FormatPayloadMismatch",
            ParseError::FormatPayloadMismatch("test"),
        ),
        ("AsduTooLong", ParseError::AsduTooLong(250)),
    ] {
        let mut s = started_controlling(12, 8);
        assert_eq!(s.on_parse_error(err), vec![], "{name}");
        assert_eq!(s.state(), State::Started, "{name}");
    }
}

#[test]
fn a_malformed_control_field_closes_from_every_live_state() {
    // The reaction belongs to the connection, not to one state: `terminate()`
    // is the single funnel out of the live set.
    for (name, mut s) in every_live_state() {
        let actions = s.on_parse_error(ParseError::BadSFormatOctet {
            octet1: 0x03,
            octet2: 0x00,
        });
        assert!(closed(&actions).is_some(), "{name}: {actions:?}");
        assert_eq!(s.state(), State::Terminated, "{name}");
        assert!(!s.user_data_allowed(), "{name}");
    }
}

#[test]
fn an_s_frame_precedes_the_active_close_when_frames_are_unconfirmed() {
    // Figures 10/11 NOTE, printed page 31: where it can, a station should send
    // an S-frame before the active close, so that APDUs already accepted are
    // not sent again. Figure 11 draws exactly that frame,
    // `S(1) (optional)`, immediately before `Active close`.
    let mut s = started_controlling(12, 8);
    s.on_frame(i(0, 0));
    assert!(s.ack_pending(), "one received frame is not yet confirmed");

    let actions = s.on_parse_error(ParseError::UnknownUFunction(0x2f));
    assert_eq!(
        sent_s(&actions),
        Some(1),
        "S(1) confirms what we accepted before closing, got {actions:?}"
    );
    assert!(
        precedes(
            &actions,
            |a| matches!(a, Action::Send(Apci::S { .. })),
            |a| matches!(a, Action::ActiveClose(_)),
        ),
        "the confirmation goes out before the close, got {actions:?}"
    );
    assert_eq!(s.state(), State::Terminated);
    assert!(!s.ack_pending(), "the S-frame cleared the obligation");
}

#[test]
fn no_s_frame_precedes_a_close_with_nothing_to_confirm() {
    // The NOTE says "if possible": with nothing received since the last
    // acknowledgement there is nothing to confirm, so the close is the only
    // action.
    let mut s = started_controlling(12, 8);
    let actions = s.on_parse_error(ParseError::ReservedOctetNotZero);
    assert!(closed(&actions).is_some(), "got {actions:?}");
    assert_eq!(
        sent_s(&actions),
        None,
        "nothing to confirm, got {actions:?}"
    );
}

#[test]
fn the_sequence_error_of_figure_11_confirms_before_closing() {
    // Figure 11: A sends `I(0,0)` then `I(2,0)`, the diagram marks a sequence
    // error, draws `S(1) (optional)` and then `Active close`. The `S(1)` is the
    // accepted `I(0,0)` being confirmed before the connection goes down.
    for role in [Role::Controlling, Role::Controlled] {
        let mut s = started_session(role);
        s.on_frame(i(0, 0));
        let actions = s.on_frame(i(2, 0));
        assert_eq!(sent_s(&actions), Some(1), "{role:?}: got {actions:?}");
        assert!(
            precedes(
                &actions,
                |a| matches!(a, Action::Send(Apci::S { .. })),
                |a| matches!(a, Action::ActiveClose(_)),
            ),
            "{role:?}: got {actions:?}"
        );
        assert_eq!(s.state(), State::Terminated, "{role:?}");
    }
}

#[test]
fn the_t1_active_close_confirms_first_too() {
    // Figure 12 is the t1 case, and the same NOTE applies: the frames we
    // accepted must be confirmed before the connection goes down, or the peer
    // retransmits them against a closed connection.
    let mut s = started_session(Role::Controlled);
    s.on_frame(i(0, 0));
    assert!(s.ack_pending());

    let actions = s.on_timeout(Timer::T1);
    assert_eq!(sent_s(&actions), Some(1), "got {actions:?}");
    assert!(
        precedes(
            &actions,
            |a| matches!(a, Action::Send(Apci::S { .. })),
            |a| matches!(a, Action::ActiveClose(_)),
        ),
        "got {actions:?}"
    );
    assert_eq!(s.state(), State::Terminated);
}

#[test]
fn a_close_leaves_nothing_behind_for_the_next_connection() {
    // `terminate()` is the single funnel: a pending user-data queue and a test
    // procedure must not survive the close (clause 5.1 restarts the numbering,
    // so a frame stamped for the old connection is not valid on the new one).
    let mut s = started_controlling(12, 8);
    assert_eq!(sent_u(&s.on_timeout(Timer::T3)), Some(UFunction::TestFrAct));
    s.on_frame(i(0, 0));
    s.queue_i_frame(b"\x42").unwrap();
    assert_eq!(s.pending_user_data(), 1);

    let actions = s.on_parse_error(ParseError::BadLength(3));
    assert!(closed(&actions).is_some(), "got {actions:?}");
    assert_eq!(s.pending_user_data(), 0, "the queue died with the close");
    assert!(!s.test_pending(), "so did the test procedure");
    assert!(!s.ack_pending());

    // ... and the new connection starts clean.
    s.on_connection_established();
    assert_eq!(s.pending_user_data(), 0);
    assert!(!s.test_pending());
    let actions = s.on_frame(u(UFunction::StartDtAct));
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(sent_i(&actions), vec![], "the new connection is clean");
}

#[test]
fn a_piggybacked_acknowledgement_needs_no_s_frame_before_the_close() {
    // Skipping the S-frame here does not miss the figures 10/11 NOTE. Clause
    // 5.1's acknowledgement is the *Receive Sequence Number*, and "any sent
    // I-frame carries N(R) = V(R), so it acks too"
    // (`Sequence::buffer_i_frame`). Once an I-frame of ours has carried N(R) = 1,
    // the peer has been told about the `I(0,0)` it would otherwise retransmit,
    // so the NOTE's purpose (sparing the peer a retransmission of what was
    // already accepted) is already served and its "where it can" does not apply.
    let mut s = started_controlling(12, 8);
    s.on_frame(i(0, 0));
    assert!(s.ack_pending());
    let out = s.send_i_frame(b"\x11").unwrap();
    assert_eq!(sent_i_one(&out), vec![(0, 1, b"\x11".to_vec())], "N(R) = 1");
    assert!(!s.ack_pending(), "the piggybacked N(R) did the telling");

    // A bogus N(R) then closes, and there is nothing left to confirm.
    let actions = s.on_frame(s_frame(5));
    assert_eq!(sent_s(&actions), None, "got {actions:?}");
    assert!(closed(&actions).is_some(), "got {actions:?}");
    assert_eq!(s.state(), State::Terminated);

    // Same window, the t1 path: also nothing to confirm.
    let mut s = started_controlling(12, 8);
    s.on_frame(i(0, 0));
    s.send_i_frame(b"\x11").unwrap();
    let actions = s.on_timeout(Timer::T1);
    assert_eq!(sent_s(&actions), None, "got {actions:?}");
    assert!(closed(&actions).is_some(), "got {actions:?}");
}

#[test]
fn a_bad_acknowledgement_piggybacked_on_an_i_frame_delivers_and_confirms_first() {
    // The frame is *accepted* before its own N(R) is examined, so a good N(S)
    // with a bogus piggybacked N(R) delivers the data, confirms it, and only then
    // closes: three actions, the close last. The public contract (`src/link.rs`
    // module doc) says so, and a caller that assumes a close is always the
    // two-action `[_, ActiveClose]` is wrong.
    let mut s = started_controlling(12, 8);
    s.on_frame(i(0, 0));
    s.send_i_frame(b"\x11").unwrap();

    let actions = s.on_frame(i(1, 5));
    assert_eq!(
        actions,
        vec![
            Action::DeliverData {
                ns: SeqNo::new(1),
                nr: SeqNo::new(5),
            },
            Action::Send(Apci::S { nr: SeqNo::new(2) }),
            Action::ActiveClose("N(R) acknowledged an I-frame that was never sent"),
        ],
        "delivered and confirmed before the close"
    );
    assert_eq!(s.state(), State::Terminated);
}

/// A new session is `Stopped` but has no connection: data handed over before
/// the first connection would be cleared by it, so it is refused, not dropped.
#[test]
fn a_session_is_connected_only_between_establishment_and_loss() {
    let mut s = Session::new(Role::Controlled);
    assert_eq!(s.state(), State::Stopped);
    assert!(!s.is_connected());
    assert_eq!(s.queue_i_frame(b"\x01"), Err(QueueError::NotConnected));

    s.on_connection_established();
    assert!(s.is_connected());
    assert_eq!(s.queue_i_frame(b"\x01"), Ok(()));

    s.on_connection_lost();
    assert!(!s.is_connected());
    assert_eq!(s.queue_i_frame(b"\x01"), Err(QueueError::NotConnected));
}

#[test]
fn a_controlling_station_confirms_a_received_stopdt_act_once_its_frames_are_acknowledged() {
    // The `src/link.rs` module doc records the choice for a STOPDT act that
    // reaches a controlling station: the machine acts on the function's
    // defined effect. Clause 5.3 defines it: the receiver ends user data
    // transfer on this connection and answers with a STOPDT con, and where the
    // controlled station still has unconfirmed messages, it waits for an
    // S-frame confirming them before the STOPDT con goes out. The sender
    // supervises its act with t1 (figures 17/18 NOTE 2: the time-out of a sent
    // U-frame or I-frame), so a con that never comes ends the connection. Once the
    // receiver's own frames are acknowledged, the con goes out, as figure 17's
    // `S-frame [no unconfirmed I-frames] /Send STOPDT con` exit sends it.
    let mut s = started_controlling(12, 8);
    s.send_i_frame(b"\x01").unwrap();
    assert_eq!(sent_u(&s.on_frame(u(UFunction::StopDtAct))), None);
    assert!(!s.user_data_allowed(), "STOPDT act stops I-frames at once");

    let actions = s.on_frame(s_frame(1));
    assert_eq!(
        sent_u(&actions),
        Some(UFunction::StopDtCon),
        "got {actions:?}"
    );
    assert_eq!(s.state(), State::Stopped);
}

#[test]
fn a_controlling_station_still_waits_for_the_con_of_its_own_stopdt_act() {
    // Figure 18: after `Stop connection[unconfirmed I-frames] /Send STOPDT act`
    // the `S-frame or I-frame [No unconfirmed I-frames]/` exit leads to
    // `Pending STOPPED`, which is left by `STOPDT con[]/`. The station that
    // sent the act sends no con of its own.
    let mut s = started_controlling(12, 8);
    s.send_i_frame(b"\x01").unwrap();
    s.request_stop();
    let actions = s.on_frame(s_frame(1));
    assert_eq!(sent_u(&actions), None, "got {actions:?}");
    assert_eq!(s.state(), State::PendingStopped);
}
