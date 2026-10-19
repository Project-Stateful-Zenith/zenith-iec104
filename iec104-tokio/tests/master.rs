//! The controlling-station driver over in-memory pipes, on a paused clock.
//!
//! Every time-out is clause 9's default (index 114, printed 113), written out:
//! t0 30 s, t1 15 s, t2 10 s, t3 20 s; and k 12, w 8.

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
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104_tokio::{Event, Events, Handle, Options, master};
use tokio::sync::mpsc;
use tokio::time::Instant;

const T0: Duration = Duration::from_secs(30);
const T1: Duration = Duration::from_secs(15);
const T2: Duration = Duration::from_secs(10);
const T3: Duration = Duration::from_secs(20);

fn one_station() -> ConnectionManager {
    ConnectionManager::new(
        Role::Controlling,
        vec![StationConfig::new(LinkParams::default())],
    )
    .unwrap()
}

/// A driver for one station and the test's end of its dials.
fn driver() -> (Handle, Events, mpsc::UnboundedReceiver<Dial>) {
    let (connector, dials) = Dials::new();
    let (handle, events) = master::spawn(one_station(), connector, Options::default()).unwrap();
    (handle, events, dials)
}

/// A driver whose one station is connected and started, the peer having
/// answered the STARTDT act.
async fn started() -> (Handle, Events, mpsc::UnboundedReceiver<Dial>, Peer) {
    let (handle, mut events, mut dials) = driver();
    let mut peer = next_dial(&mut dials).await.accept();
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
    peer.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 0,
            state: State::Started,
        }
    })
    .await;
    (handle, events, dials, peer)
}

/// Clause 5.3 / figure 18: the controlling station opens the connection and
/// sends STARTDT act; the peer's STARTDT con puts it in the started state.
#[tokio::test(start_paused = true)]
async fn clause_5_3_startdt_handshake() {
    let (_handle, mut events, mut dials) = driver();
    let dial = next_dial(&mut dials).await;
    assert_eq!(dial.conn, 0);
    let mut peer = dial.accept();
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
    peer.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        matches!(
            e,
            Event::State {
                state: State::Started,
                ..
            }
        )
    })
    .await;
    assert_eq!(
        drain(&mut events),
        [],
        "nothing after the start: {events:?}"
    );
}

/// Clause 5.1: our I-frame carries N(S) 0, N(R) 0; the peer's I-frame reaches
/// the application; clause 5.2: with no data to carry it, the acknowledgement
/// is an S-frame t2 after the I-frame arrived.
#[tokio::test(start_paused = true)]
async fn clause_5_1_i_frame_round_trip_and_the_t2_acknowledgement() {
    let (handle, mut events, _dials, mut peer) = started().await;
    handle.send_asdu(0, INTERROGATION).await.unwrap();
    assert_eq!(peer.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));

    peer.send(&i_frame(0, 1, &MEASURAND)).await;
    let arrived = Instant::now();
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::Asdu { .. })).await,
        Event::Asdu {
            conn: 0,
            asdu: MEASURAND.to_vec()
        }
    );
    assert_eq!(peer.frame().await.unwrap(), s_frame(1));
    assert_eq!(arrived.elapsed(), T2);
}

/// Clause 5.2 / figure 13: an idle connection is tested with TESTFR act t3
/// after the last frame received, and again t3 after the peer's con.
#[tokio::test(start_paused = true)]
async fn clause_5_2_t3_sends_testfr_act_on_an_idle_connection() {
    let (_handle, _events, _dials, mut peer) = started().await;
    let idle = Instant::now();
    assert_eq!(peer.frame().await.unwrap(), TESTFR_ACT);
    assert_eq!(idle.elapsed(), T3);

    peer.send(&TESTFR_CON).await;
    let confirmed = Instant::now();
    assert_eq!(peer.frame().await.unwrap(), TESTFR_ACT);
    assert_eq!(confirmed.elapsed(), T3);
}

/// Clause 5.3: *"If the STARTDT is not confirmed, the connection is closed by
/// the controlling station"*. The close comes t1 after the act, and clause
/// 10.5's reopening dials again once the attempt's t0 has run out: the
/// connection lasted less than t0, so not at once (a peer that takes every
/// connection and drops it is dialed once per t0, not in a loop).
#[tokio::test(start_paused = true)]
async fn clause_5_3_an_unconfirmed_startdt_is_closed_after_t1_and_redialed() {
    let (_handle, mut events, mut dials) = driver();
    let mut peer = next_dial(&mut dials).await.accept();
    let sent = Instant::now();
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
    assert_eq!(peer.frame().await, None, "closed");
    assert_eq!(sent.elapsed(), T1);
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::Disconnected { .. })).await,
        Event::Disconnected {
            conn: 0,
            reason: "t1 expired with no confirmation".into()
        }
    );
    let redial = next_dial(&mut dials).await;
    assert_eq!(redial.conn, 0);
    assert_eq!(
        sent.elapsed(),
        T0,
        "the reopening comes when the attempt's t0 runs out"
    );
}

/// Figure 21 / clause 9: a refused dial is retried when the attempt's t0
/// expires, not before.
#[tokio::test(start_paused = true)]
async fn figure_21_a_refused_dial_is_retried_after_t0() {
    let (_handle, mut events, mut dials) = driver();
    let first = Instant::now();
    next_dial(&mut dials).await.refuse();
    assert!(matches!(
        until(&mut events, |e| matches!(e, Event::ConnectFailed { .. })).await,
        Event::ConnectFailed { conn: 0, .. }
    ));
    next_dial(&mut dials).await.refuse();
    assert_eq!(first.elapsed(), T0);
}

/// `ConnectReason::AttemptTimedOut`: a dial unanswered when its t0 expires is
/// abandoned before the next one starts, so a late success cannot give the
/// station two connections.
#[tokio::test(start_paused = true)]
async fn an_attempt_unanswered_at_t0_is_abandoned_for_the_next() {
    let (_handle, _events, mut dials) = driver();
    let first = Instant::now();
    let hanging = next_dial(&mut dials).await;
    let second = next_dial(&mut dials).await;
    assert_eq!(first.elapsed(), T0);
    assert!(hanging.reply.is_closed(), "the first dial was dropped");

    // The second one carries the connection.
    let mut peer = second.accept();
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
}

/// Clause 5.5: with k = 12 frames unacknowledged the thirteenth waits in the
/// session's queue, and goes out when the peer's S-frame opens the window.
#[tokio::test(start_paused = true)]
async fn clause_5_5_a_full_k_window_queues_and_the_acknowledgement_flushes() {
    let (handle, _events, _dials, mut peer) = started().await;
    for _ in 0..13 {
        handle.send_asdu(0, INTERROGATION).await.unwrap();
    }
    for ns in 0..12 {
        assert_eq!(peer.frame().await.unwrap(), i_frame(ns, 0, &INTERROGATION));
    }
    assert!(
        tokio::time::timeout(Duration::from_secs(1), peer.frame())
            .await
            .is_err(),
        "the thirteenth waits for the window"
    );
    peer.send(&s_frame(12)).await;
    assert_eq!(peer.frame().await.unwrap(), i_frame(12, 0, &INTERROGATION));
}

/// Figures 10/11 NOTE: *"an S-frame should, if possible, be sent prior to the
/// active close"*. The application's close acknowledges the three I-frames
/// received (fewer than w, so none was acknowledged yet), then closes.
#[tokio::test(start_paused = true)]
async fn figures_10_11_the_s_frame_goes_out_before_the_active_close() {
    let (handle, mut events, _dials, mut peer) = started().await;
    for ns in 0..3 {
        peer.send(&i_frame(ns, 0, &MEASURAND)).await;
    }
    for _ in 0..3 {
        until(&mut events, |e| matches!(e, Event::Asdu { .. })).await;
    }
    handle.close(0).await.unwrap();
    assert_eq!(peer.frame().await.unwrap(), s_frame(3));
    assert_eq!(peer.frame().await, None, "then the close");
}

/// Clause 5.3: *"The controlling station should, however, confirm all
/// received messages before sending STOPDT act"*, and STOPDT con stops it.
#[tokio::test(start_paused = true)]
async fn clause_5_3_the_s_frame_goes_out_before_stopdt_act() {
    let (handle, mut events, _dials, mut peer) = started().await;
    peer.send(&i_frame(0, 0, &MEASURAND)).await;
    until(&mut events, |e| matches!(e, Event::Asdu { .. })).await;
    handle.stop(0).await.unwrap();
    assert_eq!(peer.frame().await.unwrap(), s_frame(1));
    assert_eq!(peer.frame().await.unwrap(), STOPDT_ACT);
    peer.send(&STOPDT_CON).await;
    until(&mut events, |e| {
        *e == Event::State {
            conn: 0,
            state: State::Stopped,
        }
    })
    .await;
}

/// Figures 17/18: an I-frame before the STARTDT con is `I-frame[]/Active
/// close`, and its ASDU never reaches the application.
#[tokio::test(start_paused = true)]
async fn an_i_frame_before_startdt_con_closes_and_is_not_delivered() {
    let (_handle, mut events, mut dials) = driver();
    let mut peer = next_dial(&mut dials).await.accept();
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
    peer.send(&i_frame(0, 0, &MEASURAND)).await;
    assert_eq!(peer.frame().await, None);
    let seen = until(&mut events, |e| matches!(e, Event::Disconnected { .. })).await;
    assert_eq!(
        seen,
        Event::Disconnected {
            conn: 0,
            reason: "I-frame received while data transfer is stopped".into()
        }
    );
    assert!(
        !drain(&mut events)
            .iter()
            .any(|e| matches!(e, Event::Asdu { .. }))
    );
}

/// Clause 5, figure 7: octets 1 and 2 of an S-format control field are 0x01
/// and 0x00. Anything else is a malformed APCI, and the connection closes.
#[tokio::test(start_paused = true)]
async fn a_malformed_control_field_closes_the_connection() {
    let (_handle, mut events, _dials, mut peer) = started().await;
    peer.send(&[0x68, 0x04, 0x01, 0x01, 0x00, 0x00]).await;
    assert_eq!(peer.frame().await, None);
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::Disconnected { .. })).await,
        Event::Disconnected {
            conn: 0,
            reason: "S-format control octets are not 0x01 0x00".into()
        }
    );
}

/// A peer that goes away is a lost connection: the application hears of it and
/// clause 10.5's reopening dials again.
#[tokio::test(start_paused = true)]
async fn a_peer_close_is_reported_and_redialed() {
    let (_handle, mut events, mut dials, peer) = started().await;
    drop(peer);
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::Disconnected { .. })).await,
        Event::Disconnected {
            conn: 0,
            reason: "peer closed the connection".into()
        }
    );
    assert_eq!(next_dial(&mut dials).await.conn, 0);
}

/// An ASDU no APDU can carry (clause 5's length field allows 249 octets) is
/// refused before it reaches the session, and so is an unknown connection.
#[tokio::test(start_paused = true)]
async fn an_oversized_asdu_is_refused() {
    let (handle, _events, _dials, _peer) = started().await;
    assert_eq!(
        handle.send_asdu(0, vec![0u8; 250]).await,
        Err(iec104_tokio::Error::BadAsdu(250))
    );
    assert_eq!(
        handle.send_asdu(1, INTERROGATION).await,
        Err(iec104_tokio::Error::NoSuchConnection(1))
    );
}

/// Shutting down closes the connection the way the application's close does,
/// and the handle reports the driver stopped afterwards.
#[tokio::test(start_paused = true)]
async fn shutdown_closes_and_stops() {
    let (handle, _events, _dials, mut peer) = started().await;
    handle.shutdown().await;
    assert_eq!(peer.frame().await, None);
    assert_eq!(handle.state(0).await, Err(iec104_tokio::Error::Stopped));
}

/// A controlled-role manager is not a master.
#[tokio::test]
async fn a_controlled_manager_is_refused() {
    let manager = ConnectionManager::new(
        Role::Controlled,
        vec![StationConfig::new(LinkParams::default())],
    )
    .unwrap();
    let (connector, _dials) = Dials::new();
    assert!(matches!(
        master::spawn(manager, connector, Options::default()),
        Err(iec104_tokio::Error::WrongRole)
    ));
}

/// A peer that stops reading holds up only its own connection: the other
/// station's frames go out at once, and the stuck one is closed by its own t1
/// (figure 12: an unacknowledged I-frame ends in an active close).
#[tokio::test(start_paused = true)]
async fn a_peer_that_stops_reading_does_not_stall_the_other_stations() {
    let manager = ConnectionManager::new(
        Role::Controlling,
        vec![
            StationConfig::new(LinkParams::default()),
            StationConfig::new(LinkParams::default()),
        ],
    )
    .unwrap();
    let (connector, mut dials) = Dials::new();
    let (handle, mut events) = master::spawn(manager, connector, Options::default()).unwrap();
    let mut peers = Vec::new();
    for _ in 0..2 {
        let dial = next_dial(&mut dials).await;
        // Station 0's pipe holds one U-frame and not much more.
        let capacity = if dial.conn == 0 { 16 } else { 64 * 1024 };
        peers.push((dial.conn, dial.accept_with_capacity(capacity)));
    }
    peers.sort_by_key(|(conn, _)| *conn);
    let [(_, mut stuck), (_, mut peer)] = <[_; 2]>::try_from(peers).ok().unwrap();
    for p in [&mut stuck, &mut peer] {
        assert_eq!(p.frame().await.unwrap(), STARTDT_ACT);
        p.send(&STARTDT_CON).await;
    }
    for conn in 0..2 {
        until(&mut events, |e| {
            *e == Event::State {
                conn,
                state: State::Started,
            }
        })
        .await;
    }

    // Station 0's peer reads nothing more; its I-frames fill the pipe.
    let sent = Instant::now();
    for _ in 0..12 {
        handle.send_asdu(0, INTERROGATION).await.unwrap();
    }
    handle.send_asdu(1, INTERROGATION).await.unwrap();
    assert_eq!(peer.frame().await.unwrap(), i_frame(0, 0, &INTERROGATION));
    assert_eq!(sent.elapsed(), Duration::ZERO, "station 1 did not wait");

    // Station 1 keeps its own supervision: its frame is confirmed, and t3
    // tests it 20 s after the last frame it received.
    peer.send(&s_frame(1)).await;
    let confirmed = Instant::now();
    assert!(matches!(
        until(&mut events, |e| matches!(e, Event::Disconnected { .. })).await,
        Event::Disconnected { conn: 0, .. }
    ));
    assert_eq!(sent.elapsed(), T1, "the stuck connection goes at its t1");
    assert_eq!(peer.frame().await.unwrap(), TESTFR_ACT);
    assert_eq!(confirmed.elapsed(), T3);
    drop(stuck);
}

/// Frames no timer of the session supervises (the S-frames acknowledging
/// every w = 8 I-frames, clause 5.5) still may not wait forever: a peer that
/// has not taken them within t1 is closed.
#[tokio::test(start_paused = true)]
async fn a_write_the_peer_does_not_take_within_t1_closes_the_connection() {
    let (_handle, mut events, mut dials) = driver();
    // 16 octets: once the peer has read the STARTDT act, room for two
    // S-frames (6 octets each), not three.
    let mut peer = next_dial(&mut dials).await.accept_with_capacity(16);
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
    peer.send(&STARTDT_CON).await;
    until(&mut events, |e| {
        matches!(
            e,
            Event::State {
                state: State::Started,
                ..
            }
        )
    })
    .await;

    let stalled = Instant::now();
    for ns in 0..24 {
        peer.send(&i_frame(ns, 0, &MEASURAND)).await;
    }
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::Disconnected { .. })).await,
        Event::Disconnected {
            conn: 0,
            reason: "write timed out (t1)".into()
        }
    );
    assert_eq!(stalled.elapsed(), T1);
}

/// Shutdown waits for every closing connection to put its last frames on the
/// wire, but not forever: with more connections stuck behind peers that do
/// not read than the engine's I/O queue holds (64), it still returns, within
/// one t1.
#[tokio::test(start_paused = true)]
async fn shutdown_returns_with_many_peers_that_do_not_read() {
    const N: usize = 70;
    let manager = ConnectionManager::new(
        Role::Controlling,
        (0..N)
            .map(|_| StationConfig::new(LinkParams::default()))
            .collect(),
    )
    .unwrap();
    let (connector, mut dials) = Dials::new();
    let (handle, mut events) = master::spawn(manager, connector, Options::default()).unwrap();
    let mut peers = Vec::new();
    for _ in 0..N {
        // Room for the STARTDT act only; the peer never reads.
        peers.push(next_dial(&mut dials).await.accept_with_capacity(6));
    }
    for conn in 0..N {
        until(&mut events, |e| {
            *e == Event::State {
                conn,
                state: State::PendingStarted,
            }
        })
        .await;
    }
    for conn in 0..N {
        handle.send_asdu(conn, INTERROGATION).await.unwrap();
    }
    let asked = Instant::now();
    tokio::time::timeout(Duration::from_secs(120), handle.shutdown())
        .await
        .expect("shutdown returns");
    assert!(asked.elapsed() <= T1);
    drop(peers);
}

/// Shutdown closes the way the application's close does: the acknowledgement
/// of what was received first (figures 10/11 NOTE), then the close.
#[tokio::test(start_paused = true)]
async fn shutdown_acknowledges_before_it_closes() {
    let (handle, mut events, _dials, mut peer) = started().await;
    peer.send(&i_frame(0, 0, &MEASURAND)).await;
    until(&mut events, |e| matches!(e, Event::Asdu { .. })).await;
    handle.shutdown().await;
    assert_eq!(peer.frame().await.unwrap(), s_frame(1));
    assert_eq!(peer.frame().await, None);
}

/// A start the connection cannot perform is refused, not answered `Ok` with
/// nothing sent: clause 5.3's STARTDT act needs an established, stopped
/// connection, and STOPDT act a started one.
#[tokio::test(start_paused = true)]
async fn start_and_stop_refuse_what_the_connection_cannot_do() {
    let options = Options {
        auto_start: false,
        ..Options::default()
    };
    let (connector, mut dials) = Dials::new();
    let (handle, mut events) = master::spawn(one_station(), connector, options).unwrap();
    let dial = next_dial(&mut dials).await; // not answered yet
    assert_eq!(
        handle.start(0).await,
        Err(iec104_tokio::Error::NotConnected(0))
    );

    let mut peer = dial.accept();
    until(&mut events, |e| *e == Event::Connected { conn: 0 }).await;
    assert_eq!(
        handle.stop(0).await,
        Err(iec104_tokio::Error::InvalidState {
            conn: 0,
            state: State::Stopped
        })
    );
    handle.start(0).await.unwrap();
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
    assert_eq!(
        handle.start(0).await,
        Err(iec104_tokio::Error::InvalidState {
            conn: 0,
            state: State::PendingStarted
        })
    );
}
