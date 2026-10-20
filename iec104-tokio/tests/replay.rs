//! The replay of what a failed started connection leaves behind (104 clause
//! 10.5/10.6), on an outstation: what counts as a failure, and that an
//! acknowledgement already received is not counted as unconfirmed.

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

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use common::*;
use iec104::link::{Role, State};
use iec104::params::LinkParams;
use iec104::redundancy::{RedundancyGroup, Replay};
use iec104_tokio::{Event, Events, Handle, Options, outstation};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};

fn driver(members: usize) -> (Handle, Events) {
    let group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), members).unwrap();
    outstation::spawn(group, Options::default()).unwrap()
}

#[derive(Default)]
struct Ctl {
    hold: bool,
    fail: bool,
    waker: Option<Waker>,
}

/// A pipe whose write side the test can hold and then fail.
struct Gate {
    inner: DuplexStream,
    ctl: Arc<Mutex<Ctl>>,
}

impl AsyncRead for Gate {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Gate {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        {
            let mut ctl = self.ctl.lock().unwrap();
            if ctl.fail {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if ctl.hold {
                ctl.waker = Some(cx.waker().clone());
                drop(ctl);
                return Poll::Pending;
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The peer's acknowledgement is already received when the write fails: the
/// acknowledged ASDU is not counted as unconfirmed (clause 5.1: its N(R)
/// released it). Real clock, current-thread runtime: the reader and the
/// writer are woken in that order, so both reports wait when the driver next
/// looks. The driver must take the received bytes first; the 32 rounds are
/// there because an engine that picked either at random would count the
/// acknowledged ASDU in about half of them.
#[tokio::test]
async fn an_acknowledgement_received_before_a_write_failure_counts() {
    for round in 0..32 {
        let (handle, mut events) = driver(1);
        let (near, far) = duplex(64 * 1024);
        let ctl = Arc::new(Mutex::new(Ctl::default()));
        let gate = Gate {
            inner: near,
            ctl: Arc::clone(&ctl),
        };
        let mut peer = Peer::new(far);
        handle.attach(None, gate).await.unwrap();
        peer.send(&STARTDT_ACT).await;
        assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
        handle.send_asdu(0, MEASURAND).await.unwrap();
        assert_eq!(peer.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));

        // The writer blocks on the next frame.
        ctl.lock().unwrap().hold = true;
        handle.send_asdu(0, INTERROGATION).await.unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // The peer confirms the first ASDU; then the write fails.
        peer.send(&s_frame(1)).await;
        {
            let mut c = ctl.lock().unwrap();
            c.fail = true;
            if let Some(w) = c.waker.take() {
                w.wake();
            }
        }
        let failed = until(&mut events, |e| {
            matches!(e, Event::StartedConnectionFailed { .. })
        })
        .await;
        assert_eq!(
            failed,
            Event::StartedConnectionFailed {
                conn: 0,
                unconfirmed: 1
            },
            "round {round}"
        );
        handle.shutdown().await;
    }
}

/// 10.2's manual switchover: a `STOPDT_ACT` on the connection that is
/// started now, then a `STARTDT_ACT` on the one chosen to take over.
/// Connection 0 is stopped, not closed (10.7 closes only one
/// that is not stopped), and has failed nothing: no failure is reported.
#[tokio::test(start_paused = true)]
async fn a_manual_switchover_is_not_a_failure() {
    let (handle, mut events) = driver(2);
    let (near0, mut peer0) = Peer::pipe();
    let (near1, mut peer1) = Peer::pipe();
    handle.attach(None, near0).await.unwrap();
    handle.attach(None, near1).await.unwrap();
    peer0.send(&STARTDT_ACT).await;
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_CON);
    peer0.send(&STOPDT_ACT).await;
    assert_eq!(peer0.frame().await.unwrap(), STOPDT_CON);
    peer1.send(&STARTDT_ACT).await;
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_CON);
    let mut seen = Vec::new();
    loop {
        let e = events.recv().await.unwrap();
        let done = e
            == Event::State {
                conn: 1,
                state: State::Started,
            };
        seen.push(e);
        if done {
            break;
        }
    }
    assert_eq!(handle.state(0).await, Ok(State::Stopped), "0 is alive");
    assert!(
        !seen
            .iter()
            .any(|e| matches!(e, Event::StartedConnectionFailed { .. })),
        "{seen:?}"
    );
}

/// 10.2's manual switchover with data handed over in between: it waited in
/// stopped 0's clause 5.3 queue, never went out, and moves with the naming. It
/// goes out once, on 1, right after the STARTDT con (clause 5.3): not on 0
/// when the master switches back, and not as a replay.
#[tokio::test(start_paused = true)]
async fn data_queued_during_a_manual_switchover_goes_out_once_on_the_new_connection() {
    let (handle, mut events) = driver(2);
    let (near0, mut peer0) = Peer::pipe();
    let (near1, mut peer1) = Peer::pipe();
    handle.attach(None, near0).await.unwrap();
    handle.attach(None, near1).await.unwrap();
    peer0.send(&STARTDT_ACT).await;
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_CON);
    peer0.send(&STOPDT_ACT).await;
    assert_eq!(peer0.frame().await.unwrap(), STOPDT_CON);
    handle.send_asdu(0, MEASURAND).await.unwrap(); // waits on stopped 0
    peer1.send(&STARTDT_ACT).await;
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_CON);
    assert_eq!(peer1.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));
    until(&mut events, |e| {
        *e == Event::State {
            conn: 1,
            state: State::Started,
        }
    })
    .await;
    assert_eq!(
        handle.retransmit_unconfirmed(0, Replay::Leave).await,
        Ok(iec104::redundancy::ReplayOutcome::Left { unconfirmed: 0 }),
        "nothing left behind on 0"
    );

    // The master switches back to 0 by hand: nothing is sent twice.
    peer1.send(&s_frame(1)).await;
    peer1.send(&STOPDT_ACT).await;
    assert_eq!(peer1.frame().await.unwrap(), STOPDT_CON);
    peer0.send(&STARTDT_ACT).await;
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_CON);
    let again = tokio::time::timeout(std::time::Duration::from_secs(1), peer0.frame()).await;
    assert!(again.is_err(), "sent twice: {again:?}");
}
