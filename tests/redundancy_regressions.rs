//! Redundancy-group scenarios that once lost or reordered data at a
//! connection switchover, one test each, in the exact sequence that showed the
//! fault (104 clause 10.5/10.6: data are neither lost nor reordered at a
//! connection switchover). `tests/redundancy_model.rs` covers the same ground
//! at random.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::as_conversions, clippy::cast_possible_truncation)]

use std::time::{Duration, Instant};

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::link::{Action, MAX_PENDING_USER_DATA, QueueError, Role, State, Timer};
use iec104::params::LinkParams;
use iec104::redundancy::{
    CLOSED_BY_START, GroupError, RedundancyGroup, Replay, ReplayOutcome, Routed, Switchover,
};

fn asdu(v: u8) -> Vec<u8> {
    vec![0x01, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, v]
}

fn i_asdus(actions: &[Action]) -> Vec<Vec<u8>> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendI { asdu, .. } => Some(asdu.clone()),
            _ => None,
        })
        .collect()
}

fn on_wire(routed: &[Routed], member: usize) -> Vec<Vec<u8>> {
    routed
        .iter()
        .filter(|r| r.member == member)
        .flat_map(|r| i_asdus(&r.actions))
        .collect()
}

/// Controlled, k = 1: A on the wire unconfirmed, B queued behind it. The master
/// starts 1 while 0 is still started (10.7 closes 0). Replaying 0 afterwards
/// must keep A before B on the new connection.
#[test]
fn displaced_started_connection_keeps_order() {
    let t = Instant::now();
    let params = LinkParams {
        k: 1,
        w: 1,
        ..LinkParams::default()
    };
    let mut group = RedundancyGroup::uniform(Role::Controlled, params, 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    group.on_connection_established(1, t).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some()); // A: ON, on the wire
    assert!(group.send_user_data(0, &asdu(0)).unwrap().is_none()); // B: OFF, queued (k)

    let mut on_1 = Vec::new();
    for r in group
        .on_frame_at(1, Apci::U(UFunction::StartDtAct), t)
        .unwrap()
    {
        if r.member == 1 {
            on_1.extend(i_asdus(&r.actions));
        }
    }
    let _ = group.on_frame_at(
        1,
        Apci::S {
            nr: SeqNo::new(on_1.len() as u16),
        },
        t,
    );
    match group.retransmit_unconfirmed(0, Replay::Retransmit).unwrap() {
        ReplayOutcome::Retransmitted { actions, .. } => on_1.extend(i_asdus(&actions)),
        other => panic!("{other:?}"),
    }
    on_1.extend(group.member(1).unwrap().queued_user_data().to_vec());
    assert_eq!(
        on_1,
        vec![asdu(1), asdu(0)],
        "A (older) must precede B on the new connection"
    );
}

/// Controlling: 10.2's manual switchover carried out with select + start
/// (the path the `Switchover` docs name for a caller that picks the
/// connection). Data handed over while 0 is stopped must not stay behind on 0.
#[test]
fn manual_switchover_via_select_moves_queued_data() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t)
        .unwrap();
    group.stop_at(0, t).unwrap();
    assert_eq!(
        group.send_user_data_at(0, &asdu(1), t).unwrap(),
        [] as [iec104::redundancy::Routed; 0]
    );
    group
        .on_frame_at(0, Apci::U(UFunction::StopDtCon), t)
        .unwrap();

    group.select(1).unwrap();
    let routed = group.start_at(1, t).unwrap();
    let on_1: Vec<_> = routed
        .iter()
        .filter(|r| r.member == 1)
        .flat_map(|r| i_asdus(&r.actions))
        .collect();
    assert_eq!(
        group.member(0).unwrap().session().pending_user_data(),
        0,
        "stuck on stopped 0"
    );
    assert_eq!(on_1, vec![asdu(1)]);
}

/// A session closed by hand, decided on (capture at decision), re-established
/// by hand (`session_mut`) and failing again: the data of the second connection
/// must still be captured.
#[test]
fn hand_reestablished_member_captures_its_next_failure() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    group.send_user_data(0, &asdu(1)).unwrap();
    group.member_mut(0).unwrap().session_mut().close("by hand");
    let _ = group.retransmit_unconfirmed(0, Replay::Discard);
    group
        .member_mut(0)
        .unwrap()
        .session_mut()
        .on_connection_established();
    assert!(group.send_user_data(0, &asdu(0)).unwrap().is_none());
    assert_eq!(group.member(0).unwrap().queued_user_data().len(), 1);
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.member(0).unwrap().left_behind(), &[asdu(0)], "B lost");
}

#[test]
fn clause_10_6_data_sent_after_a_t1_switchover_waits_behind_the_replay() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t)
        .unwrap();
    assert_eq!(
        on_wire(&group.send_user_data_at(0, &asdu(1), t).unwrap(), 0),
        vec![asdu(1)]
    );

    let later = t + Duration::from_secs(15);
    let outcome = group.tick(later);
    assert_eq!(
        outcome.switchovers,
        vec![Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1,
        }]
    );
    group.on_connection_lost(0).unwrap();
    group
        .on_frame_at(1, Apci::U(UFunction::StartDtCon), later)
        .unwrap();

    assert_eq!(
        group.send_user_data_at(1, &asdu(2), later).unwrap(),
        Vec::new(),
        "nothing overtakes the data the failed connection left behind"
    );
    assert_eq!(group.held_user_data(), &[asdu(2)]);

    let (outcome, routed) = group
        .retransmit_unconfirmed_at(0, Replay::Retransmit, later)
        .unwrap();
    assert!(matches!(
        outcome,
        ReplayOutcome::Retransmitted { queued: 0, .. }
    ));
    assert_eq!(on_wire(&routed, 1), vec![asdu(1), asdu(2)]);
    assert_eq!(group.held_user_data(), [] as [Vec<u8>; 0]);

    assert_eq!(
        on_wire(&group.send_user_data_at(1, &asdu(3), later).unwrap(), 1),
        vec![asdu(3)],
        "decided: user data flows again"
    );
}

#[test]
fn clause_10_6_an_event_sent_after_a_displacement_waits_behind_the_replay() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    assert_eq!(
        on_wire(&group.send_user_data_at(0, &asdu(1), t).unwrap(), 0),
        vec![asdu(1)]
    );

    let routed = group
        .on_frame_at(1, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    assert!(
        routed
            .iter()
            .any(|r| r.member == 0 && matches!(r.actions.last(), Some(Action::ActiveClose(_)))),
        "10.7 closes the displaced connection"
    );
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.member(0).unwrap().left_behind(), &[asdu(1)]);

    assert_eq!(
        group.send_user_data_at(1, &asdu(2), t).unwrap(),
        Vec::new(),
        "nothing overtakes the data the displaced connection left behind"
    );

    let (_, routed) = group
        .retransmit_unconfirmed_at(0, Replay::Retransmit, t)
        .unwrap();
    assert_eq!(on_wire(&routed, 1), vec![asdu(1), asdu(2)]);
}

#[test]
fn clause_10_7_data_sent_after_a_start_closed_another_connection_waits_for_the_decision() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t)
        .unwrap();
    group.send_user_data_at(0, &asdu(1), t).unwrap();

    let routed = group.start_at(1, t).unwrap();
    assert!(
        routed
            .iter()
            .any(|r| r.member == 0 && matches!(r.actions.last(), Some(Action::ActiveClose(_)))),
        "10.7 closes the connection that was started"
    );
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.member(0).unwrap().left_behind(), &[asdu(1)]);

    assert_eq!(group.send_user_data_at(1, &asdu(2), t).unwrap(), Vec::new());
    assert_eq!(group.held_user_data(), &[asdu(2)]);

    let (outcome, routed) = group
        .retransmit_unconfirmed_at(0, Replay::Discard, t)
        .unwrap();
    assert!(matches!(
        outcome,
        ReplayOutcome::Discarded { discarded: 1, .. }
    ));
    assert_eq!(on_wire(&routed, 1), vec![asdu(2)]);
    assert_eq!(group.held_user_data(), [] as [Vec<u8>; 0]);
}

#[test]
fn clause_10_7_an_act_on_a_connection_named_beforehand_still_closes_the_started_one() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    assert_eq!(group.state(0), Ok(State::Started));

    group.observe_startdt_act(1).unwrap();
    let routed = group
        .on_frame_at(1, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    assert_eq!(
        routed,
        vec![
            Routed {
                member: 0,
                actions: vec![Action::ActiveClose(CLOSED_BY_START)],
            },
            Routed {
                member: 1,
                actions: vec![Action::Send(Apci::U(UFunction::StartDtCon))],
            },
        ]
    );
    assert_eq!(group.started_index(), Some(1));
    assert_eq!(
        [group.state(0), group.state(1)],
        [Ok(State::Terminated), Ok(State::Started)],
        "rule 3: one started connection"
    );

    let again = group
        .on_frame_at(1, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    assert_eq!(
        again,
        vec![Routed {
            member: 1,
            actions: vec![Action::Send(Apci::U(UFunction::StartDtCon))],
        }],
        "a repeated act closes nothing"
    );
}

#[test]
fn clause_10_7_data_queued_between_select_and_start_waits_behind_the_replay() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t)
        .unwrap();
    group.send_user_data_at(0, &asdu(1), t).unwrap();

    group.select(1).unwrap();
    assert_eq!(group.send_user_data_at(1, &asdu(2), t).unwrap(), Vec::new());
    assert_eq!(group.member(1).unwrap().queued_user_data(), &[asdu(2)]);

    let routed = group.start_at(1, t).unwrap();
    assert_eq!(
        routed,
        vec![
            Routed {
                member: 0,
                actions: vec![Action::ActiveClose(CLOSED_BY_START)],
            },
            Routed {
                member: 1,
                actions: vec![Action::Send(Apci::U(UFunction::StartDtAct))],
            },
        ],
        "the Start carries no data ahead of what the closed connection left"
    );
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.member(0).unwrap().left_behind(), &[asdu(1)]);
    assert_eq!(group.held_user_data(), &[asdu(2)]);
    assert_eq!(
        group.member(1).unwrap().queued_user_data(),
        [] as [Vec<u8>; 0]
    );

    let (_, routed) = group
        .retransmit_unconfirmed_at(0, Replay::Retransmit, t)
        .unwrap();
    assert_eq!(on_wire(&routed, 1), vec![asdu(1), asdu(2)]);
}

#[test]
fn clause_10_7_an_event_queued_before_the_act_waits_behind_the_replay() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    group.send_user_data_at(0, &asdu(1), t).unwrap();

    group.observe_startdt_act(1).unwrap();
    assert_eq!(group.send_user_data_at(1, &asdu(2), t).unwrap(), Vec::new());

    let routed = group
        .on_frame_at(1, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
    assert_eq!(
        routed,
        vec![
            Routed {
                member: 0,
                actions: vec![Action::ActiveClose(CLOSED_BY_START)],
            },
            Routed {
                member: 1,
                actions: vec![Action::Send(Apci::U(UFunction::StartDtCon))],
            },
        ],
        "the con carries no data ahead of what the closed connection left"
    );
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.held_user_data(), &[asdu(2)]);

    let (_, routed) = group
        .retransmit_unconfirmed_at(0, Replay::Retransmit, t)
        .unwrap();
    assert_eq!(on_wire(&routed, 1), vec![asdu(1), asdu(2)]);
}

#[test]
fn rule_4_selecting_a_running_connection_again_puts_the_held_data_on_the_wire() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(1, t).unwrap();
    group
        .on_frame_at(1, Apci::U(UFunction::StartDtCon), t)
        .unwrap();

    assert_eq!(group.select_at(0, t).unwrap(), Vec::new());
    assert_eq!(group.state(1), Ok(State::Started), "still running");
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.started_index(), None);
    assert_eq!(group.send_user_data_at(0, &asdu(1), t).unwrap(), Vec::new());
    assert_eq!(group.held_user_data(), &[asdu(1)]);

    let later = t + Duration::from_secs(3);
    let routed = group.select_at(1, later).unwrap();
    assert_eq!(
        routed,
        vec![Routed {
            member: 1,
            actions: vec![Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: asdu(1),
            }],
        }]
    );
    assert_eq!(group.started_index(), Some(1));
    assert_eq!(group.held_user_data(), [] as [Vec<u8>; 0]);
    assert_eq!(
        group.member(1).unwrap().timers().deadline(Timer::T1),
        Some(later + Duration::from_secs(15)),
        "t1 supervises the released frame"
    );

    assert_eq!(
        on_wire(&group.send_user_data_at(1, &asdu(2), later).unwrap(), 1),
        vec![asdu(2)],
        "later user data goes straight out"
    );
}

#[test]
fn rule_4_selecting_a_stopped_connection_sends_nothing() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t)
        .unwrap();
    group.on_connection_lost(0).unwrap();
    group.send_user_data_at(0, &asdu(1), t).unwrap();

    assert_eq!(group.select(1), Ok(Vec::new()));
    assert_eq!(
        group.held_user_data(),
        &[asdu(1)],
        "held for the Start that carries the selection out"
    );
    assert_eq!(on_wire(&group.start_at(1, t).unwrap(), 1), vec![asdu(1)]);
}

#[test]
fn clause_10_5_a_reported_loss_starts_nothing_until_the_caller_starts_a_standby() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t)
        .unwrap();

    group.on_connection_lost(0).unwrap();
    assert_eq!(group.started_index(), None);
    assert_eq!(group.send_user_data_at(0, &asdu(1), t).unwrap(), Vec::new());

    let mut now = t;
    for _ in 0..25 {
        now += Duration::from_secs(1);
        let outcome = group.tick(now);
        assert_eq!(outcome.switchovers, Vec::new());
        for routed in outcome.routed {
            assert_eq!(
                routed,
                Routed {
                    member: 1,
                    actions: vec![Action::Send(Apci::U(UFunction::TestFrAct))],
                },
                "the standby is only supervised (rule 5)"
            );
            group
                .on_frame_at(1, Apci::U(UFunction::TestFrCon), now)
                .unwrap();
        }
    }
    assert_eq!(group.started_index(), None);
    assert_eq!(group.state(1), Ok(State::Stopped));
    assert_eq!(group.held_user_data(), &[asdu(1)]);

    let routed = group.start_at(1, now).unwrap();
    assert_eq!(
        routed,
        vec![Routed {
            member: 1,
            actions: vec![
                Action::Send(Apci::U(UFunction::StartDtAct)),
                Action::SendI {
                    ns: SeqNo::new(0),
                    nr: SeqNo::new(0),
                    asdu: asdu(1),
                },
            ],
        }]
    );
}

#[test]
fn figure_37_a_closed_started_connection_leaves_the_next_start_to_the_caller() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t)
        .unwrap();

    group.close_at(0, t).unwrap();
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.started_index(), None);
    assert_eq!(
        group.send_user_data_at(1, &asdu(1), t),
        Err(GroupError::NoStartedConnection)
    );
    assert_eq!(group.tick(t + Duration::from_secs(1)).routed, Vec::new());
    assert_eq!(group.state(1), Ok(State::Stopped));

    group.start_at(1, t).unwrap();
    assert_eq!(
        on_wire(&group.send_user_data_at(1, &asdu(1), t).unwrap(), 1),
        vec![asdu(1)]
    );
}

fn established(role: Role, k: u16) -> Result<RedundancyGroup, GroupError> {
    let t = Instant::now();
    let params = LinkParams {
        k,
        w: 1,
        ..LinkParams::default()
    };
    let mut group = RedundancyGroup::uniform(role, params, 2)?;
    group.on_connection_established(0, t)?;
    group.on_connection_established(1, t)?;
    Ok(group)
}

#[test]
fn clause_10_6_a_replay_decided_before_the_start_goes_out_ahead_of_newer_data() {
    let mut group = established(Role::Controlling, 12).unwrap();
    group.start(0).unwrap();
    group.on_frame(0, Apci::U(UFunction::StartDtCon)).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some());
    assert_eq!(group.select(1), Ok(Vec::new()));
    assert_eq!(group.send_user_data(1, &asdu(2)), Ok(None));
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.send_user_data(1, &asdu(3)), Ok(None));

    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: Vec::new(),
            queued: 1,
        })
    );
    assert_eq!(
        i_asdus(&group.start(1).unwrap()),
        vec![asdu(1), asdu(2), asdu(3)]
    );
}

#[test]
fn clause_10_6_a_replay_decided_before_the_act_goes_out_ahead_of_newer_data() {
    let mut group = established(Role::Controlled, 12).unwrap();
    group.on_startdt_act(0).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some());
    group.observe_startdt_act(1).unwrap();
    assert_eq!(group.send_user_data(1, &asdu(2)), Ok(None));
    group.on_connection_lost(0).unwrap();

    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: Vec::new(),
            queued: 1,
        })
    );
    assert_eq!(
        i_asdus(&group.on_startdt_act(1).unwrap()),
        vec![asdu(1), asdu(2)]
    );
}

#[test]
fn clause_10_5_data_left_on_a_stopping_connection_goes_out_ahead_of_newer_data() {
    let mut group = established(Role::Controlling, 12).unwrap();
    group.start(0).unwrap();
    group.on_frame(0, Apci::U(UFunction::StartDtCon)).unwrap();
    group.stop(0).unwrap();
    assert_eq!(group.send_user_data(0, &asdu(1)), Ok(None));
    assert_eq!(group.select(1), Ok(Vec::new()));
    assert_eq!(group.send_user_data(1, &asdu(2)), Ok(None));
    group.on_frame(0, Apci::U(UFunction::StopDtCon)).unwrap();

    assert_eq!(i_asdus(&group.start(1).unwrap()), vec![asdu(1), asdu(2)]);
}

#[test]
fn clause_10_6_a_replay_newer_than_the_named_connections_queue_goes_out_behind_it() {
    let mut group = established(Role::Controlling, 1).unwrap();
    group.start(1).unwrap();
    group.on_frame(1, Apci::U(UFunction::StartDtCon)).unwrap();
    assert!(group.send_user_data(1, &asdu(1)).unwrap().is_some());
    assert_eq!(group.send_user_data(1, &asdu(2)), Ok(None));
    assert_eq!(group.select(0), Ok(Vec::new()));
    assert_eq!(group.send_user_data(0, &asdu(3)), Ok(None));
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.select(1), Ok(Vec::new()));
    group.stop(1).unwrap();
    group.on_frame(1, Apci::S { nr: SeqNo::new(1) }).unwrap();
    group.on_frame(1, Apci::U(UFunction::StopDtCon)).unwrap();

    let mut wire = i_asdus(&group.start(1).unwrap());
    let Ok(ReplayOutcome::Retransmitted { actions, .. }) =
        group.retransmit_unconfirmed(0, Replay::Retransmit)
    else {
        panic!("the replay is refused");
    };
    wire.extend(i_asdus(&actions));
    group.on_frame(1, Apci::U(UFunction::StartDtCon)).unwrap();
    wire.extend(i_asdus(
        &group.on_frame(1, Apci::S { nr: SeqNo::new(2) }).unwrap(),
    ));
    assert_eq!(wire, vec![asdu(2), asdu(3)]);
}

#[test]
fn rule_4_an_act_observed_on_a_running_connection_puts_the_moved_data_on_the_wire() {
    let mut group = established(Role::Controlled, 12).unwrap();
    let t = Instant::now();
    group.on_startdt_act(0).unwrap();
    assert_eq!(group.observe_startdt_act(1), Ok(Vec::new()));
    assert_eq!(group.send_user_data(1, &asdu(1)), Ok(None));

    let later = t + Duration::from_secs(3);
    assert_eq!(
        group.observe_startdt_act_at(0, later).unwrap(),
        vec![Routed {
            member: 0,
            actions: vec![Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: asdu(1),
            }],
        }]
    );
    assert_eq!(group.member(0).unwrap().session().pending_user_data(), 0);
    assert_eq!(
        group.member(0).unwrap().timers().deadline(Timer::T1),
        Some(later + Duration::from_secs(15)),
        "t1 supervises the released frame"
    );
    assert!(group.send_user_data(0, &asdu(2)).unwrap().is_some());
}

#[test]
fn clause_10_5_a_late_failure_of_an_abandoned_dial_is_not_the_loss_of_its_successor() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    assert_eq!(group.tick(t).connect, vec![0, 1]);
    let abandoned = group.member(0).unwrap().attempt();
    assert_eq!(abandoned, 1);

    let later = t + Duration::from_secs(30);
    assert_eq!(group.tick(later).connect, vec![0, 1]);
    let latest = group.member(0).unwrap().attempt();
    assert_eq!(latest, 2);
    group.on_connection_established(0, later).unwrap();
    group.start_at(0, later).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), later)
        .unwrap();
    assert_eq!(
        on_wire(&group.send_user_data_at(0, &asdu(1), later).unwrap(), 0),
        vec![asdu(1)]
    );

    group.on_attempt_failed(0, abandoned).unwrap();
    group.on_attempt_failed(0, latest).unwrap();
    assert_eq!(group.state(0), Ok(State::Started));
    assert_eq!(group.started_index(), Some(0));
    assert_eq!(group.member(0).unwrap().left_behind(), [] as [Vec<u8>; 0]);
    assert_eq!(
        on_wire(&group.send_user_data_at(0, &asdu(2), later).unwrap(), 0),
        vec![asdu(2)]
    );
}

#[test]
fn clause_10_5_a_refused_dial_reported_by_its_number_is_retried_at_t0() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    assert_eq!(group.tick(t).connect, vec![0, 1]);
    group.on_connection_established(0, t).unwrap();
    assert_eq!(group.select(1), Ok(Vec::new()));
    assert_eq!(group.started_index(), Some(1));

    group.on_attempt_failed(1, 7).unwrap();
    assert_eq!(group.started_index(), Some(1), "not the latest attempt");
    assert_eq!(group.tick(t + Duration::from_secs(29)).connect, Vec::new());
    assert_eq!(group.tick(t + Duration::from_secs(30)).connect, vec![1]);
    assert_eq!(group.member(1).unwrap().attempt(), 2);
    group.on_attempt_failed(1, 1).unwrap();
    assert_eq!(group.started_index(), Some(1), "an abandoned attempt");
    group.on_attempt_failed(1, 2).unwrap();
    assert_eq!(group.started_index(), None, "the naming goes with the dial");

    assert_eq!(group.tick(t + Duration::from_secs(59)).connect, Vec::new());
    assert_eq!(group.tick(t + Duration::from_secs(60)).connect, vec![1]);
    assert_eq!(
        group.on_attempt_failed(2, 1),
        Err(GroupError::MemberIndexOutOfRange {
            index: 2,
            members: 2
        })
    );
}

#[test]
fn clause_10_7_a_start_closes_a_stopped_connection_that_has_frames_unconfirmed() {
    let mut group = established(Role::Controlling, 12).unwrap();
    let t = Instant::now();
    group.start(0).unwrap();
    group.on_frame(0, Apci::U(UFunction::StartDtCon)).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some());
    group.stop(0).unwrap();
    assert_eq!(group.send_user_data(0, &asdu(2)), Ok(None));
    group.on_frame(0, Apci::U(UFunction::StopDtCon)).unwrap();
    assert_eq!(group.state(0), Ok(State::Stopped));

    assert_eq!(
        group.start_at(1, t).unwrap(),
        vec![
            Routed {
                member: 0,
                actions: vec![Action::ActiveClose(CLOSED_BY_START)],
            },
            Routed {
                member: 1,
                actions: vec![Action::Send(Apci::U(UFunction::StartDtAct))],
            },
        ]
    );
    assert_eq!(group.member(0).unwrap().left_behind(), &[asdu(1), asdu(2)]);
    group.on_frame(1, Apci::U(UFunction::StartDtCon)).unwrap();
    assert_eq!(group.send_user_data(1, &asdu(3)), Ok(None));

    let Ok(ReplayOutcome::Retransmitted { actions, queued }) =
        group.retransmit_unconfirmed(0, Replay::Retransmit)
    else {
        panic!("the replay is refused");
    };
    assert_eq!(queued, 0);
    assert_eq!(i_asdus(&actions), vec![asdu(1), asdu(2), asdu(3)]);
}

#[test]
fn clause_10_6_held_data_waits_until_every_failure_is_decided() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 3).unwrap();
    for member in 0..3 {
        group.on_connection_established(member, t).unwrap();
    }
    group.start(0).unwrap();
    group.on_frame(0, Apci::U(UFunction::StartDtCon)).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some());
    assert_eq!(group.select(1), Ok(Vec::new()));
    assert_eq!(group.send_user_data(1, &asdu(2)), Ok(None));
    group.on_connection_lost(0).unwrap();
    group.on_connection_lost(1).unwrap();
    assert_eq!(group.member(0).unwrap().left_behind(), &[asdu(1)]);
    assert_eq!(group.member(1).unwrap().left_behind(), &[asdu(2)]);

    group.start(2).unwrap();
    group.on_frame(2, Apci::U(UFunction::StartDtCon)).unwrap();
    assert_eq!(group.send_user_data(2, &asdu(3)), Ok(None));

    let Ok(ReplayOutcome::Retransmitted { actions, queued }) =
        group.retransmit_unconfirmed(0, Replay::Retransmit)
    else {
        panic!("the replay is refused");
    };
    assert_eq!((i_asdus(&actions), queued), (vec![asdu(1)], 0));
    assert_eq!(group.held_user_data(), &[asdu(3)]);

    let Ok(ReplayOutcome::Retransmitted { actions, queued }) =
        group.retransmit_unconfirmed(1, Replay::Retransmit)
    else {
        panic!("the replay is refused");
    };
    assert_eq!((i_asdus(&actions), queued), (vec![asdu(2), asdu(3)], 0));
    assert_eq!(group.held_user_data(), [] as [Vec<u8>; 0]);
}

#[test]
fn a_replay_the_started_connections_queue_has_no_room_for_changes_nothing() {
    let mut group = established(Role::Controlled, 1).unwrap();
    group.on_startdt_act(0).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some());
    assert_eq!(group.send_user_data(0, &asdu(2)), Ok(None));
    group.on_connection_lost(0).unwrap();
    group.on_startdt_act(1).unwrap();
    let mut by_hand = 0_usize;
    for _ in 0..MAX_PENDING_USER_DATA {
        let session = group.member_mut(1).unwrap().session_mut();
        if session.queue_i_frame(&asdu(9)).is_ok() {
            by_hand += 1;
        }
    }
    assert_eq!(by_hand, MAX_PENDING_USER_DATA);

    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Err(GroupError::Queue(QueueError::Full))
    );
    assert_eq!(group.member(0).unwrap().left_behind(), &[asdu(1), asdu(2)]);
    let session = group.member(1).unwrap().session();
    assert_eq!(session.pending_user_data(), MAX_PENDING_USER_DATA);
    assert_eq!(session.outstanding_frames().len(), 0);
    assert!(!group.member(0).unwrap().replayed());
}

#[test]
fn data_queued_by_hand_stays_outside_the_mirror_when_held_data_is_only_appended() {
    let mut group = established(Role::Controlling, 1).unwrap();
    group.start(0).unwrap();
    group.on_frame(0, Apci::U(UFunction::StartDtCon)).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some());
    assert_eq!(group.send_user_data(0, &asdu(2)), Ok(None));
    let session = group.member_mut(0).unwrap().session_mut();
    session.queue_i_frame(&asdu(9)).unwrap();
    assert_eq!(group.send_user_data(0, &asdu(3)), Ok(None));
    assert_eq!(group.select(1), Ok(Vec::new()));
    assert_eq!(group.send_user_data(1, &asdu(4)), Ok(None));

    assert_eq!(group.select(0), Ok(Vec::new()));
    let member = group.member(0).unwrap();
    assert_eq!(member.queued_user_data(), &[asdu(2), asdu(3), asdu(4)]);
    assert_eq!(member.session().pending_user_data(), 4);
}

#[test]
fn data_queued_by_hand_keeps_its_place_when_older_held_data_is_merged_in() {
    let mut group = established(Role::Controlling, 12).unwrap();
    group.start(0).unwrap();
    group.on_frame(0, Apci::U(UFunction::StartDtCon)).unwrap();
    group.stop(0).unwrap();
    assert_eq!(group.send_user_data(0, &asdu(1)), Ok(None));
    assert_eq!(group.select(1), Ok(Vec::new()));
    assert_eq!(group.send_user_data(1, &asdu(2)), Ok(None));
    let session = group.member_mut(1).unwrap().session_mut();
    session.queue_i_frame(&asdu(9)).unwrap();
    assert_eq!(group.send_user_data(1, &asdu(3)), Ok(None));
    group.on_frame(0, Apci::U(UFunction::StopDtCon)).unwrap();

    assert_eq!(
        i_asdus(&group.start(1).unwrap()),
        vec![asdu(1), asdu(2), asdu(9), asdu(3)]
    );
}

#[test]
fn a_member_that_was_never_dialed_has_no_attempt_to_fail() {
    let t = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 2).unwrap();
    group.on_connection_established(0, t).unwrap();
    group.on_startdt_act(0).unwrap();
    assert_eq!(group.observe_startdt_act(1), Ok(Vec::new()));
    assert_eq!(group.member(1).unwrap().attempt(), 0);

    group.on_attempt_failed(1, 0).unwrap();
    assert_eq!(group.started_index(), Some(1));
}

fn three_controlled(k: u16) -> Result<RedundancyGroup, GroupError> {
    let t = Instant::now();
    let params = LinkParams {
        k,
        w: 1,
        ..LinkParams::default()
    };
    let mut group = RedundancyGroup::uniform(Role::Controlled, params, 3)?;
    for member in 0..3 {
        group.on_connection_established(member, t)?;
    }
    Ok(group)
}

#[test]
fn a_replayed_frame_sent_at_once_keeps_its_handover_number_on_the_wire() {
    let mut group = three_controlled(12).unwrap();
    group.on_startdt_act(0).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some());
    assert_eq!(group.observe_startdt_act(1), Ok(Vec::new()));
    assert_eq!(group.send_user_data(1, &asdu(2)), Ok(None));
    group.on_connection_lost(1).unwrap();
    group.on_connection_lost(0).unwrap();

    group.on_startdt_act(2).unwrap();
    let Ok(ReplayOutcome::Retransmitted { actions, queued }) =
        group.retransmit_unconfirmed(1, Replay::Retransmit)
    else {
        panic!("the replay is refused");
    };
    assert_eq!((i_asdus(&actions), queued), (vec![asdu(2)], 0));
    group.on_connection_lost(2).unwrap();
    assert_eq!(group.member(2).unwrap().left_behind(), &[asdu(2)]);

    group.on_connection_established(1, Instant::now()).unwrap();
    assert_eq!(group.observe_startdt_act(1), Ok(Vec::new()));
    group.retransmit_unconfirmed(0, Replay::Retransmit).unwrap();
    group.retransmit_unconfirmed(2, Replay::Retransmit).unwrap();
    assert_eq!(
        group.member(1).unwrap().queued_user_data(),
        &[asdu(1), asdu(2)]
    );
    assert_eq!(
        i_asdus(&group.on_startdt_act(1).unwrap()),
        vec![asdu(1), asdu(2)]
    );
}

#[test]
fn a_replayed_frame_sent_from_the_queue_keeps_its_handover_number_on_the_wire() {
    let mut group = three_controlled(1).unwrap();
    group.on_startdt_act(0).unwrap();
    assert!(group.send_user_data(0, &asdu(1)).unwrap().is_some());
    assert_eq!(group.observe_startdt_act(1), Ok(Vec::new()));
    assert_eq!(group.send_user_data(1, &asdu(2)), Ok(None));
    assert_eq!(group.send_user_data(1, &asdu(3)), Ok(None));
    group.on_connection_lost(1).unwrap();
    group.on_connection_lost(0).unwrap();

    group.on_startdt_act(2).unwrap();
    let Ok(ReplayOutcome::Retransmitted { actions, queued }) =
        group.retransmit_unconfirmed(1, Replay::Retransmit)
    else {
        panic!("the replay is refused");
    };
    assert_eq!((i_asdus(&actions), queued), (vec![asdu(2)], 1));
    assert_eq!(
        i_asdus(&group.on_frame(2, Apci::S { nr: SeqNo::new(1) }).unwrap()),
        vec![asdu(3)]
    );
    group.on_connection_lost(2).unwrap();
    assert_eq!(group.member(2).unwrap().left_behind(), &[asdu(3)]);

    group.on_connection_established(1, Instant::now()).unwrap();
    assert_eq!(group.observe_startdt_act(1), Ok(Vec::new()));
    group.retransmit_unconfirmed(0, Replay::Retransmit).unwrap();
    group.retransmit_unconfirmed(2, Replay::Retransmit).unwrap();
    assert_eq!(
        group.member(1).unwrap().queued_user_data(),
        &[asdu(1), asdu(3)]
    );
}
