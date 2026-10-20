//! The controlled-station driver: sockets attached from in-memory pipes (and
//! one real TCP listener), a redundancy group underneath.

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
use iec104::redundancy::{GroupError, RedundancyGroup, Replay};
use iec104_tokio::{Error, Event, Events, Handle, Options, outstation};

fn driver(members: usize) -> (Handle, Events) {
    let group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), members).unwrap();
    outstation::spawn(group, Options::default()).unwrap()
}

/// Clause 5.3: the controlled station answers STARTDT act with STARTDT con,
/// and sends user data only once started. Before that, 10.4 has no started
/// connection to carry it (the controlled station sends no user data until
/// one connection has reached the started state).
#[tokio::test(start_paused = true)]
async fn clause_5_3_startdt_act_is_confirmed_and_data_follows() {
    let (handle, mut events) = driver(1);
    let (near, mut peer) = Peer::pipe();
    assert_eq!(handle.attach(None, near).await, Ok(0));
    assert_eq!(
        handle.send_asdu(0, MEASURAND).await,
        Err(Error::Group(GroupError::NoStartedConnection))
    );

    peer.send(&STARTDT_ACT).await;
    assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
    until(&mut events, |e| {
        *e == Event::State {
            conn: 0,
            state: State::Started,
        }
    })
    .await;
    handle.send_asdu(0, MEASURAND).await.unwrap();
    assert_eq!(peer.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));
}

/// The master's request reaches the application, and the w-th I-frame is
/// acknowledged at once (clause 5.5: the receiver acknowledges no later than
/// the w-th I-format APDU it receives, w = 8).
#[tokio::test(start_paused = true)]
async fn clause_5_5_the_wth_i_frame_is_acknowledged_at_once() {
    let (handle, mut events) = driver(1);
    let (near, mut peer) = Peer::pipe();
    handle.attach(None, near).await.unwrap();
    peer.send(&STARTDT_ACT).await;
    assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
    for ns in 0..8 {
        peer.send(&i_frame(ns, 0, &INTERROGATION)).await;
    }
    for _ in 0..8 {
        assert_eq!(
            until(&mut events, |e| matches!(e, Event::Asdu { .. })).await,
            Event::Asdu {
                conn: 0,
                asdu: INTERROGATION.to_vec()
            }
        );
    }
    assert_eq!(peer.frame().await.unwrap(), s_frame(8));
}

/// 10.2 rule 4 and 10.7: the connection the master last sent STARTDT act on
/// is the started one, and a start on a new connection closes at once every
/// connection not in the STOPPED state.
#[tokio::test(start_paused = true)]
async fn clause_10_7_a_start_on_a_second_connection_closes_the_first() {
    let (handle, mut events) = driver(2);
    let (near0, mut peer0) = Peer::pipe();
    let (near1, mut peer1) = Peer::pipe();
    assert_eq!(handle.attach(None, near0).await, Ok(0));
    assert_eq!(handle.attach(None, near1).await, Ok(1));

    peer0.send(&STARTDT_ACT).await;
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_CON);
    handle.send_asdu(0, MEASURAND).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));

    peer1.send(&STARTDT_ACT).await;
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_CON);
    assert_eq!(peer0.frame().await, None, "the first connection is closed");
    until(&mut events, |e| {
        matches!(e, Event::Disconnected { conn: 0, .. })
    })
    .await;

    // User data now goes on the second connection (rule 3).
    handle.send_asdu(0, MEASURAND).await.unwrap();
    assert_eq!(peer1.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));
}

/// 10.2 (index 116): N is the number of connections the group was built
/// for; one more has no member to take it.
#[tokio::test(start_paused = true)]
async fn a_connection_beyond_the_groups_n_is_refused() {
    let (handle, _events) = driver(1);
    let (near0, _peer0) = Peer::pipe();
    let (near1, _peer1) = Peer::pipe();
    handle.attach(None, near0).await.unwrap();
    assert_eq!(
        handle.attach(None, near1).await,
        Err(Error::NoFreeConnection)
    );
}

/// The member of a lost connection takes the next one.
#[tokio::test(start_paused = true)]
async fn a_lost_connections_member_takes_the_next_one() {
    let (handle, mut events) = driver(1);
    let (near, peer) = Peer::pipe();
    handle.attach(None, near).await.unwrap();
    drop(peer);
    until(&mut events, |e| {
        matches!(e, Event::Disconnected { conn: 0, .. })
    })
    .await;
    let (near, mut peer) = Peer::pipe();
    assert_eq!(handle.attach(None, near).await, Ok(0));
    peer.send(&STARTDT_ACT).await;
    assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
}

/// A controlling group is not an outstation.
#[tokio::test]
async fn a_controlling_group_is_refused() {
    let group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 1).unwrap();
    assert!(matches!(
        outstation::spawn(group, Options::default()),
        Err(Error::WrongRole)
    ));
}

/// `serve` over real TCP: a connection accepted on the listener is answered.
#[tokio::test]
async fn serve_answers_a_tcp_master() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (handle, _events) = driver(1);
    tokio::spawn(outstation::serve(listener, handle.clone()));

    let mut master = tokio::net::TcpStream::connect(address).await.unwrap();
    master.write_all(&STARTDT_ACT).await.unwrap();
    let mut answer = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), master.read_exact(&mut answer))
        .await
        .expect("answered in time")
        .unwrap();
    assert_eq!(answer, STARTDT_CON);
    handle.shutdown().await;
}

/// 10.2 rule 7: when several controlling stations need the same controlled
/// station at the same time, each must have a redundancy group of its own.
/// `serve_routed` gives each
/// master its own driver, so the second master's STARTDT act starts its own
/// connection and leaves the first one's alone (10.7 applies within a group).
#[tokio::test]
async fn serve_routed_keeps_each_master_in_its_own_group() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (first, _first_events) = driver(1);
    let (second, _second_events) = driver(1);
    // The masters are told apart by arrival here; a real station would route
    // on the peer's address. The third is nobody's.
    let arrivals = AtomicUsize::new(0);
    let drivers = [first.clone(), second.clone()];
    tokio::spawn(outstation::serve_routed(listener, move |_peer| {
        drivers
            .get(arrivals.fetch_add(1, Ordering::SeqCst))
            .cloned()
    }));

    let answer = |mut stream: tokio::net::TcpStream| async move {
        stream.write_all(&STARTDT_ACT).await.unwrap();
        let mut con = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut con))
            .await
            .expect("answered in time")
            .unwrap();
        assert_eq!(con, STARTDT_CON);
        stream
    };
    let mut a = answer(tokio::net::TcpStream::connect(address).await.unwrap()).await;
    let _b = answer(tokio::net::TcpStream::connect(address).await.unwrap()).await;

    // Both groups have a started connection; the first was not closed.
    assert_eq!(first.state(0).await, Ok(State::Started));
    assert_eq!(second.state(0).await, Ok(State::Started));
    first.send_asdu(0, MEASURAND).await.unwrap();
    let mut frame = [0u8; 18];
    a.read_exact(&mut frame).await.unwrap();
    assert_eq!(frame[..], i_frame(0, 0, &MEASURAND)[..]);

    // A connection no driver takes is closed.
    let mut c = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf))
        .await
        .expect("closed in time");
    assert!(matches!(read, Ok(0) | Err(_)));
    first.shutdown().await;
    second.shutdown().await;
}

/// 10.5/10.6 on an outstation: the master's started connection fails with an
/// ASDU unconfirmed, the master reconnects (on the same member, the first
/// free one) and starts it. The group still holds the ASDU, and the replay
/// puts it on the new connection, stamped N(S) 0 (clause 5.1).
#[tokio::test(start_paused = true)]
async fn the_masters_reconnection_on_the_same_member_keeps_the_unconfirmed_data() {
    let (handle, mut events) = driver(2);
    let (near, mut peer) = Peer::pipe();
    assert_eq!(handle.attach(None, near).await, Ok(0));
    peer.send(&STARTDT_ACT).await;
    assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
    handle.send_asdu(0, MEASURAND).await.unwrap();
    assert_eq!(peer.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));
    drop(peer);
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

    let (near, mut peer) = Peer::pipe();
    assert_eq!(handle.attach(None, near).await, Ok(0));
    peer.send(&STARTDT_ACT).await;
    assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
    handle
        .retransmit_unconfirmed(0, Replay::Retransmit)
        .await
        .unwrap();
    assert_eq!(peer.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));
}

/// 10.7: the master's STARTDT act on another connection closes the started
/// one. That is reported as a failure of the started connection, with what it
/// held unconfirmed, and the replay puts it on the connection now started.
#[tokio::test(start_paused = true)]
async fn clause_10_7_a_displaced_started_connection_is_reported() {
    let (handle, mut events) = driver(2);
    let (near0, mut peer0) = Peer::pipe();
    let (near1, mut peer1) = Peer::pipe();
    handle.attach(None, near0).await.unwrap();
    handle.attach(None, near1).await.unwrap();
    peer0.send(&STARTDT_ACT).await;
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_CON);
    handle.send_asdu(0, MEASURAND).await.unwrap();
    assert_eq!(peer0.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));

    peer1.send(&STARTDT_ACT).await;
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_CON);
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
    handle
        .retransmit_unconfirmed(0, Replay::Retransmit)
        .await
        .unwrap();
    assert_eq!(peer1.frame().await.unwrap(), i_frame(0, 0, &MEASURAND));
}

/// 10.5 (index 128): the controlled station acknowledges user data only on
/// the connection where its most recent `STARTDT_ACT` arrived. An I-frame on
/// the other connection is refused: it is not
/// delivered and not acknowledged, the connection stays up, and the
/// application is told.
#[tokio::test(start_paused = true)]
async fn clause_10_5_an_i_frame_on_a_connection_not_started_is_refused_and_reported() {
    let (handle, mut events) = driver(2);
    let (near0, mut peer0) = Peer::pipe();
    let (near1, mut peer1) = Peer::pipe();
    handle.attach(None, near0).await.unwrap();
    handle.attach(None, near1).await.unwrap();
    peer0.send(&STARTDT_ACT).await;
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_CON);

    peer1.send(&i_frame(0, 0, &INTERROGATION)).await;
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::FrameRefused { .. })).await,
        Event::FrameRefused {
            conn: 1,
            error: Error::Group(GroupError::NotStartedConnection { index: 1 })
        }
    );
    assert!(
        !drain(&mut events)
            .iter()
            .any(|e| matches!(e, Event::Asdu { .. } | Event::Disconnected { .. }))
    );
    // Connection 1 is still up: it still answers a test frame (clause 5.2).
    peer1.send(&TESTFR_ACT).await;
    assert_eq!(peer1.frame().await.unwrap(), TESTFR_CON);
}

/// A stream that holds what is written until it is flushed, as a TLS stream
/// holds its records.
struct Buffered {
    inner: tokio::io::DuplexStream,
    pending: Vec<u8>,
}

impl tokio::io::AsyncRead for Buffered {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Buffered {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.pending.extend_from_slice(data);
        std::task::Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        while !this.pending.is_empty() {
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &this.pending) {
                std::task::Poll::Ready(Ok(n)) => {
                    this.pending.drain(..n);
                }
                other => return other.map(|r| r.map(|_| ())),
            }
        }
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Every action list reaches the peer when it is written, also over a stream
/// that buffers until flushed: the STARTDT con (clause 5.3) arrives without a
/// later frame to push it out.
#[tokio::test(start_paused = true)]
async fn frames_go_out_at_once_over_a_buffering_stream() {
    let (handle, _events) = driver(1);
    let (near, mut peer) = Peer::pipe();
    handle
        .attach(
            None,
            Buffered {
                inner: near,
                pending: Vec::new(),
            },
        )
        .await
        .unwrap();
    peer.send(&STARTDT_ACT).await;
    let con = tokio::time::timeout(Duration::from_secs(1), peer.frame()).await;
    assert_eq!(con.ok().flatten().as_deref(), Some(&STARTDT_CON[..]));
}

/// Clause 5.5: at most k I-frames are unconfirmed, k = 12 by default (clause
/// 9). `Handle::window` is k while nothing is outstanding, shrinks with every
/// ASDU sent, counts what waits in the session's queue beyond k, and is 0
/// before STARTDT (clause 5.3). An S-frame confirming I-frames (clause 5.1,
/// figure 7) makes room and is reported as `Event::Acknowledged`; the STARTDT
/// that opens the window is not.
#[tokio::test(start_paused = true)]
async fn clause_5_5_the_window_and_its_acknowledgement() {
    let (handle, mut events) = driver(1);
    let (near, mut peer) = Peer::pipe();
    handle.attach(None, near).await.unwrap();
    assert_eq!(handle.window(0).await, Ok(0), "not started yet");

    peer.send(&STARTDT_ACT).await;
    assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
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
    assert_eq!(handle.window(0).await, Ok(12));
    assert_eq!(handle.window(5).await, Err(Error::NoSuchConnection(5)));

    for _ in 0..13 {
        handle.send_asdu(0, MEASURAND).await.unwrap();
    }
    for ns in 0..12 {
        assert_eq!(peer.frame().await.unwrap(), i_frame(ns, 0, &MEASURAND));
    }
    // Twelve unconfirmed and one queued: no room.
    assert_eq!(handle.window(0).await, Ok(0));
    assert!(
        !drain(&mut events)
            .iter()
            .any(|e| matches!(e, Event::Acknowledged { .. })),
        "the STARTDT opened the window, it confirmed nothing"
    );

    // Confirming one I-frame lets the queued ASDU out: still no room.
    peer.send(&s_frame(1)).await;
    assert_eq!(peer.frame().await.unwrap(), i_frame(12, 0, &MEASURAND));
    assert_eq!(handle.window(0).await, Ok(0));
    assert!(
        !drain(&mut events)
            .iter()
            .any(|e| matches!(e, Event::Acknowledged { .. }))
    );

    // Confirming five more makes room for five.
    peer.send(&s_frame(6)).await;
    assert_eq!(
        until(&mut events, |e| matches!(e, Event::Acknowledged { .. })).await,
        Event::Acknowledged { conn: 0 }
    );
    assert_eq!(handle.window(0).await, Ok(5));
}
