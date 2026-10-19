//! The controlling station with a redundancy group (104 clause 10) over
//! in-memory pipes, on a paused clock. t1 is clause 9's default, 15 s.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

mod common;

use std::time::Duration;

use common::*;
use iec104::link::{Role, State};
use iec104::params::LinkParams;
use iec104::redundancy::{RedundancyGroup, Replay, ReplayOutcome, Switchover};
use iec104_tokio::{Event, Events, Handle, Options, master};
use tokio::sync::mpsc;
use tokio::time::Instant;

const T1: Duration = Duration::from_secs(15);

/// A two-member group with both connections up and member 0 started.
async fn started() -> (Handle, Events, mpsc::UnboundedReceiver<Dial>, Peer, Peer) {
    let group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    let (connector, mut dials) = Dials::new();
    let (handle, mut events) =
        master::spawn_redundant(group, connector, Options::default()).unwrap();
    let first = next_dial(&mut dials).await;
    let second = next_dial(&mut dials).await;
    assert_eq!((first.conn, second.conn), (0, 1));
    let mut peer0 = first.accept();
    let peer1 = second.accept();
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_ACT);
    peer0.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 0,
            state: State::Started,
        }
    })
    .await;
    (handle, events, dials, peer0, peer1)
}

/// 10.3: after connection establishment one connection, and only one, is
/// changed from the stopped into the started state; the other stays stopped
/// and carries no user data (rule 3).
#[tokio::test(start_paused = true)]
async fn clause_10_3_one_connection_is_started_and_carries_the_data() {
    let (handle, _events, _dials, mut peer0, mut peer1) = started().await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    assert!(
        tokio::time::timeout(Duration::from_secs(1), peer1.frame())
            .await
            .is_err(),
        "nothing on the stopped connection"
    );
}

/// 10.5: *"When transmission timeout (t1) has elapsed, one of the stopped
/// connections (connection n) is started using the STARTDT function"*. The
/// failed connection is closed and redialed.
#[tokio::test(start_paused = true)]
async fn clause_10_5_t1_on_the_started_connection_switches_over() {
    let (handle, mut events, mut dials, mut peer0, mut peer1) = started().await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    let sent = Instant::now();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));

    // The peer never acknowledges it.
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_ACT);
    assert_eq!(sent.elapsed(), T1);
    assert_eq!(peer0.frame().await, None, "the failed connection is closed");
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::Switchover(_))).await,
        Event::Switchover(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1
        })
    );
    assert_eq!(next_dial(&mut dials).await.conn, 0, "reopened (10.5)");
}

/// A started connection whose peer goes away leaves the group without one;
/// the driver starts the stopped connection that is still up.
#[tokio::test(start_paused = true)]
async fn a_lost_started_connection_is_replaced_by_the_stopped_one() {
    let (_handle, mut events, _dials, peer0, mut peer1) = started().await;
    drop(peer0);
    until(&mut events, |e| {
        matches!(e, Event::Disconnected { conn: 0, .. })
    })
    .await;
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_ACT);
    peer1.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 1,
            state: State::Started,
        }
    })
    .await;
}

/// 10.2's manual switchover: *"first issuing a `STOPDT_ACT` on the currently
/// started connection and then a `STARTDT_ACT` on the selected new started
/// connection"*.
#[tokio::test(start_paused = true)]
async fn clause_10_2_manual_switchover() {
    let (handle, mut events, _dials, mut peer0, mut peer1) = started().await;
    handle.stop(0).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), STOPDT_ACT);
    peer0.send(&STOPDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 0,
            state: State::Stopped,
        }
    })
    .await;
    handle.start(1).await.unwrap();
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_ACT);
    peer1.send(&STARTDT_CON).await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer1.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
}

/// A member whose own session closed it (an N(R) acknowledging a frame that
/// was never sent, clause 5.1) is redialed and comes back fresh: the t1 of
/// the frame the old connection never had confirmed does not close the new
/// one, which is only tested at t3 (clause 5.2, rule 5: every connection of the
/// group is supervised).
#[tokio::test(start_paused = true)]
async fn a_member_closed_by_its_session_comes_back_without_the_old_timers() {
    let (handle, mut events, mut dials, mut peer0, mut peer1) = started().await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    // N(R) 5: only one frame was ever sent. An S-frame arms no t2, so no
    // other expiry can hide the old t1.
    peer0.send(&s_frame(5)).await;
    assert_eq!(peer0.frame().await, None);
    until(&mut events, |e| {
        *e == Event::Disconnected {
            conn: 0,
            reason: "N(R) acknowledged an I-frame that was never sent".into(),
        }
    })
    .await;
    // The group moves to the other connection, which the peer confirms.
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_ACT);
    peer1.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 1,
            state: State::Started,
        }
    })
    .await;
    // The started connection stays healthy: its peer answers every test
    // frame (clause 5.2), so the group keeps it while member 0 is redialed,
    // which happens once the t0 of its attempt has run out.
    tokio::spawn(async move {
        while let Some(frame) = peer1.frame().await {
            if frame == TESTFR_ACT {
                peer1.send(&TESTFR_CON).await;
            }
        }
    });

    // Accepted only now, so nothing happens on the group between the new
    // connection and the old frame's t1 deadline.
    let mut again = next_dial(&mut dials).await.accept();
    let up = Instant::now();
    assert_eq!(again.frame().await.unwrap(), TESTFR_ACT, "not a close");
    assert_eq!(up.elapsed(), Duration::from_secs(20));
}

/// 10.5/10.6: the data the failed connection left unconfirmed goes out again
/// on the new started connection when the application asks, also after the
/// driver has already reopened the failed one (10.5's reopening, once the
/// t0 of its attempt has run out; the fresh session's send buffer starts
/// empty, clause 5.1).
#[tokio::test(start_paused = true)]
async fn clause_10_6_the_replay_survives_the_reopening_of_the_failed_connection() {
    let (handle, mut events, mut dials, mut peer0, mut peer1) = started().await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    // Never acknowledged: t1 switches over to member 1.
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_ACT);
    peer1.send(&STARTDT_CON).await;
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::Switchover(_))).await,
        Event::Switchover(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1
        })
    );
    let _again = next_dial(&mut dials).await.accept();
    until(&mut events, |e| *e == Event::Connected { conn: 0 }).await;

    let outcome = handle
        .retransmit_unconfirmed(0, Replay::Retransmit)
        .await
        .unwrap();
    assert!(
        matches!(&outcome, ReplayOutcome::Retransmitted { actions, queued: 0 } if actions.len() == 1),
        "{outcome:?}"
    );
    assert_eq!(peer1.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    assert_eq!(
        handle.retransmit_unconfirmed(0, Replay::Retransmit).await,
        Err(iec104_tokio::Error::Group(
            iec104::redundancy::GroupError::AlreadyRetransmitted { index: 0 }
        )),
        "once per failure"
    );
}

/// A started connection that fails without its t1 (here its peer goes away)
/// is reported as such, with what it held unconfirmed; the replay puts that on
/// the connection started in its place.
#[tokio::test(start_paused = true)]
async fn a_started_connection_lost_without_t1_is_reported_with_its_unconfirmed_data() {
    let (handle, mut events, _dials, mut peer0, mut peer1) = started().await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    drop(peer0);
    assert_eq!(
        until(&mut events, |e| matches!(
            e,
            Event::StartedConnectionFailed { .. }
        ))
        .await,
        Event::StartedConnectionFailed {
            conn: 0,
            unconfirmed: 1
        }
    );
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_ACT);
    peer1.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 1,
            state: State::Started,
        }
    })
    .await;
    handle
        .retransmit_unconfirmed(0, Replay::Retransmit)
        .await
        .unwrap();
    assert_eq!(peer1.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
}

/// The t1 switchover is reported once, as a switchover, and not a second
/// time as a failed started connection.
#[tokio::test(start_paused = true)]
async fn a_t1_switchover_is_not_also_reported_as_a_failed_started_connection() {
    let (handle, mut events, _dials, mut peer0, _peer1) = started().await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    // The close of the failed connection is reported before the switchover.
    let mut seen = Vec::new();
    loop {
        let event = events.recv().await.unwrap();
        let done = matches!(event, Event::Switchover(_));
        seen.push(event);
        if done {
            break;
        }
    }
    seen.extend(drain(&mut events));
    assert!(
        seen.iter()
            .any(|e| matches!(e, Event::Disconnected { conn: 0, .. }))
    );
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, Event::StartedConnectionFailed { .. })),
        "{seen:?}"
    );
}

/// The failed member is the only one left, so the driver reopens and starts
/// it again at once. The data its failed connection held is still the
/// group's, and the replay puts it on the member's new connection (10.6).
#[tokio::test(start_paused = true)]
async fn the_only_member_left_started_again_still_replays_its_data() {
    let group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    let (connector, mut dials) = Dials::new();
    let (handle, mut events) =
        master::spawn_redundant(group, connector, Options::default()).unwrap();
    let first = next_dial(&mut dials).await;
    let second = next_dial(&mut dials).await;
    assert_eq!((first.conn, second.conn), (0, 1));
    let mut peer0 = first.accept();
    second.refuse();
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_ACT);
    peer0.send(&STARTDT_CON).await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    drop(peer0);
    assert_eq!(
        until(&mut events, |e| matches!(
            e,
            Event::StartedConnectionFailed { .. }
        ))
        .await,
        Event::StartedConnectionFailed {
            conn: 0,
            unconfirmed: 1
        }
    );

    let again = next_dial(&mut dials).await;
    assert_eq!(again.conn, 0);
    let mut peer0 = again.accept();
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_ACT);
    peer0.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 0,
            state: State::Started,
        }
    })
    .await;
    handle
        .retransmit_unconfirmed(0, Replay::Retransmit)
        .await
        .unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
}

/// A started connection its session closes (figure 11's sequence error) is
/// reported as a failed started connection, and not as a t1 switchover.
#[tokio::test(start_paused = true)]
async fn a_self_closed_started_connection_is_reported() {
    let (handle, mut events, _dials, mut peer0, _peer1) = started().await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    peer0.send(&i_frame(5, 0, &MEASURAND)).await;
    let mut seen = Vec::new();
    loop {
        let event = events.recv().await.unwrap();
        let done = matches!(event, Event::StartedConnectionFailed { .. });
        seen.push(event);
        if done {
            break;
        }
    }
    assert_eq!(
        seen.last(),
        Some(&Event::StartedConnectionFailed {
            conn: 0,
            unconfirmed: 1
        })
    );
    assert!(!seen.iter().any(|e| matches!(e, Event::Switchover(_))));
}
