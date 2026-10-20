//! The server (a controlled station answering from its process image) over
//! in-memory pipes, on a paused clock.
//!
//! The far end is a scripted controlling station: the test writes its
//! requests and reads the ASDUs the server sends. Every ASDU is written out
//! from 5-101 clause 7.2 and 7.3's layouts with the conventional address
//! sizes: type identification, variable structure qualifier (`SQ = 0`, `N`),
//! cause (bit 7 `P/N`), originator, common address 1 (two octets), then the
//! three-octet object address and the elements, all little-endian.

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

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use common::*;
use iec104::asdu::{AsduError, Cp56Time2a, DoublePointState, LayoutError, Quality, Value};
use iec104::ci;
use iec104::ct::{Command, CommandMode, Family};
use iec104::params::LinkParams;
use iec104_tokio::server::{Application, PointConfig, Server, ServerConfig, ServerError};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

// ---------------------------------------------------------------- frames

/// Cause octets of 5-101 table 14, with bit 7 (`P/N`) set for the negative
/// forms.
const SPONT: u8 = 3;
const REQ: u8 = 5;
const ACT: u8 = 6;
const ACTCON: u8 = 7;
const ACTCON_NEGATIVE: u8 = 0x40 | 7;
const DEACT: u8 = 8;
const DEACTCON: u8 = 9;
const ACTTERM: u8 = 10;
const ACTTERM_NEGATIVE: u8 = 0x40 | 0x0A;
const INROGEN: u8 = 20;
const REQCOGEN: u8 = 37;
/// Clause 7.2.3's mirror of an unknown information object address: cause 47,
/// `P/N = 1`.
const UNKNOWN_IOA: u8 = 0x40 | 0x2F;
/// Clause 7.2.3's mirror of an unknown type identification: cause 44,
/// `P/N = 1`.
const UNKNOWN_TYPE: u8 = 0x40 | 0x2C;

/// Address 100 is `0x000064`, 200 is `0x0000C8`, 4001 is `0x000FA1`, 4002 is
/// `0x000FA2`.
const IOA_100: [u8; 3] = [0x64, 0x00, 0x00];
const IOA_200: [u8; 3] = [0xC8, 0x00, 0x00];
const IOA_4001: [u8; 3] = [0xA1, 0x0F, 0x00];
const IOA_4002: [u8; 3] = [0xA2, 0x0F, 0x00];

/// A data unit identifier (5-101 cl.7.1): `type`, one object, `cause`,
/// originator 0, common address 1.
fn head(type_id: u8, count: u8, cause: u8) -> Vec<u8> {
    vec![type_id, count, cause, 0x00, 0x01, 0x00]
}

/// `M_EI_NA_1` `<70>` (5-101 cl.7.3.3.1): cause 4, address 0, `COI` 0 (local
/// power on, parameters unchanged, cl.7.2.6.21).
const END_OF_INIT: [u8; 10] = [70, 0x01, 4, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];

/// `C_IC_NA_1` `<100>` (5-101 cl.7.3.4.1), address 0, `QOI` `qoi` (20 the
/// station, 21 to 36 groups 1 to 16, cl.7.2.6.22).
fn interrogation(cause: u8, qoi: u8) -> Vec<u8> {
    vec![100, 0x01, cause, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, qoi]
}

/// `C_CI_NA_1` `<101>` (5-101 cl.7.3.4.2), address 0, `QCC` `qcc`
/// (cl.7.2.6.23: `RQT` in bits 1–6, `FRZ` in bits 7–8).
fn counter_interrogation(cause: u8, qcc: u8) -> Vec<u8> {
    vec![101, 0x01, cause, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, qcc]
}

/// `M_ME_NB_1` `<11>` (5-101 cl.7.3.1.11) at address 100, `SVA` `value`,
/// `QDS` 0.
fn scaled(cause: u8, value: i16) -> Vec<u8> {
    let mut asdu = head(11, 1, cause);
    asdu.extend(IOA_100);
    asdu.extend(value.to_le_bytes());
    asdu.push(0x00);
    asdu
}

/// `M_DP_NA_1` `<3>` (5-101 cl.7.3.1.3) at address 4001, `DIQ` `diq`
/// (cl.7.2.6.2: `DPI` in bits 1–2, 2 is ON).
fn double_point(cause: u8, diq: u8) -> Vec<u8> {
    let mut asdu = head(3, 1, cause);
    asdu.extend(IOA_4001);
    asdu.push(diq);
    asdu
}

/// `M_IT_NA_1` `<15>` (5-101 cl.7.3.1.15) at address 200, `BCR` `reading`
/// (cl.7.2.6.9: four octets, then the sequence octet, 0 here).
fn total(cause: u8, reading: i32) -> Vec<u8> {
    let mut asdu = head(15, 1, cause);
    asdu.extend(IOA_200);
    asdu.extend(reading.to_le_bytes());
    asdu.push(0x00);
    asdu
}

/// `C_SC_NA_1` `<45>` (5-101 cl.7.3.2.1) at `ioa`, `SCO` `sco` (cl.7.2.6.15:
/// bit 1 `SCS`, bit 8 `S/E`).
fn single_command(cause: u8, ioa: [u8; 3], sco: u8) -> Vec<u8> {
    let mut asdu = head(45, 1, cause);
    asdu.extend(ioa);
    asdu.push(sco);
    asdu
}

/// `C_RD_NA_1` `<102>` (5-101 cl.7.3.4.3): the address alone, cause 5.
fn read(ioa: [u8; 3]) -> Vec<u8> {
    let mut asdu = head(102, 1, REQ);
    asdu.extend(ioa);
    asdu
}

/// 2026-09-28 12:34:56.789, a Monday, as `CP56Time2a` (5-101 cl.7.2.6.18):
/// milliseconds 56 789 (`0xDDD5`), minute 34 (bit 8 `IV`), hour 12, day 28
/// with day of week 1 in bits 6–8, month 9, year 26.
const TIME: [u8; 7] = [0xD5, 0xDD, 34, 12, 0x20 | 0x1C, 9, 26];

/// The same instant as the struct the server's clock returns.
fn station_time() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 56_789,
        minutes: 34,
        hours: 12,
        day_of_month: 28,
        day_of_week: 1,
        months: 9,
        years: 26,
        ..Cp56Time2a::default()
    }
}

/// 2026-09-28 13:00:00.000, the controlling station's time in the clock
/// synchronisation: milliseconds 0, minute 0, hour 13, the same day.
const MASTER_TIME: [u8; 7] = [0x00, 0x00, 0, 13, 0x20 | 0x1C, 9, 26];

/// `C_CS_NA_1` `<103>` (5-101 cl.7.3.4.4), address 0, carrying `time`.
fn clock_sync(cause: u8, time: [u8; 7]) -> Vec<u8> {
    let mut asdu = head(103, 1, cause);
    asdu.extend([0x00, 0x00, 0x00]);
    asdu.extend(time);
    asdu
}

/// `M_SP_TB_1` `<30>` (5-101 cl.7.3.1.22 as 104 cl.9 permits it) at 4002:
/// `SIQ` `siq`, then `time`.
fn single_tagged(siq: u8, time: [u8; 7]) -> Vec<u8> {
    let mut asdu = head(30, 1, SPONT);
    asdu.extend(IOA_4002);
    asdu.push(siq);
    asdu.extend(time);
    asdu
}

// ----------------------------------------------------------- application

/// The test's application: commands are handed to the test, which answers
/// each operation.
#[derive(Clone)]
struct App {
    accept: Arc<AtomicBool>,
    operations: mpsc::UnboundedSender<(Command, oneshot::Sender<bool>)>,
    synchronised: mpsc::UnboundedSender<Cp56Time2a>,
    resets: mpsc::UnboundedSender<ci::Request>,
}

struct AppSide {
    accept: Arc<AtomicBool>,
    operations: mpsc::UnboundedReceiver<(Command, oneshot::Sender<bool>)>,
    synchronised: mpsc::UnboundedReceiver<Cp56Time2a>,
    resets: mpsc::UnboundedReceiver<ci::Request>,
}

fn app() -> (App, AppSide) {
    let accept = Arc::new(AtomicBool::new(true));
    let (operations, operations_rx) = mpsc::unbounded_channel();
    let (synchronised, synchronised_rx) = mpsc::unbounded_channel();
    let (resets, resets_rx) = mpsc::unbounded_channel();
    (
        App {
            accept: Arc::clone(&accept),
            operations,
            synchronised,
            resets,
        },
        AppSide {
            accept,
            operations: operations_rx,
            synchronised: synchronised_rx,
            resets: resets_rx,
        },
    )
}

impl Application for App {
    fn accept(&self, _command: &Command) -> bool {
        self.accept.load(Ordering::SeqCst)
    }

    async fn operate(&self, command: Command) -> bool {
        let (reply, answer) = oneshot::channel();
        let _ = self.operations.send((command, reply));
        answer.await.unwrap_or(false)
    }

    fn synchronise(&self, time: Cp56Time2a) {
        let _ = self.synchronised.send(time);
    }

    fn reset_counters(&self, request: ci::Request) {
        let _ = self.resets.send(request);
    }
}

impl AppSide {
    async fn operation(&mut self) -> (Command, oneshot::Sender<bool>) {
        tokio::time::timeout(Duration::from_secs(3600), self.operations.recv())
            .await
            .expect("no operation")
            .expect("the server runs")
    }
}

// ---------------------------------------------------------------- master

/// The scripted controlling station. A background task answers TESTFR act,
/// acknowledges what it receives when told to, and hands the ASDUs over.
struct Master {
    received: mpsc::UnboundedReceiver<Vec<u8>>,
    to_send: mpsc::UnboundedSender<Out>,
    task: JoinHandle<()>,
}

enum Out {
    Asdu(Vec<u8>),
    /// Confirm everything received so far with an S-frame (clause 5.1).
    Ack,
    Close,
}

impl Master {
    /// Starts data transfer on `peer` (clause 5.3) and runs the station
    /// behind it. With `ack`, every I-frame is confirmed at once.
    async fn start(mut peer: Peer, ack: bool) -> Self {
        peer.send(&STARTDT_ACT).await;
        assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
        Self::run(peer, ack)
    }

    fn run(mut peer: Peer, ack: bool) -> Self {
        let (received_tx, received) = mpsc::unbounded_channel();
        let (to_send, mut outgoing) = mpsc::unbounded_channel::<Out>();
        let task = tokio::spawn(async move {
            // `acked` is what our N(R) has confirmed so far.
            let (mut ns, mut nr, mut acked) = (0u16, 0u16, 0u16);
            loop {
                tokio::select! {
                    frame = peer.frame() => {
                        let Some(frame) = frame else { return };
                        if frame[2] & 0x01 == 0 {
                            nr += 1;
                            if ack {
                                acked = nr;
                                peer.send(&s_frame(acked)).await;
                            }
                            let _ = received_tx.send(frame[6..].to_vec());
                        } else if frame == TESTFR_ACT {
                            peer.send(&TESTFR_CON).await;
                        }
                    }
                    out = outgoing.recv() => match out {
                        Some(Out::Asdu(asdu)) => {
                            peer.send(&i_frame(ns, acked, &asdu)).await;
                            ns += 1;
                        }
                        Some(Out::Ack) => {
                            acked = nr;
                            peer.send(&s_frame(acked)).await;
                        }
                        _ => return,
                    }
                }
            }
        });
        Self {
            received,
            to_send,
            task,
        }
    }

    /// The next ASDU the server sent; fails when none comes within an hour of
    /// the paused clock.
    async fn next(&mut self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(3600), self.received.recv())
            .await
            .expect("the server sent nothing")
            .expect("the connection is open")
    }

    /// Whether the server sends nothing within `window`.
    async fn silent_for(&mut self, window: Duration) -> bool {
        tokio::time::timeout(window, self.received.recv())
            .await
            .is_err()
    }

    fn send(&self, asdu: &[u8]) {
        self.to_send.send(Out::Asdu(asdu.to_vec())).unwrap();
    }

    fn ack(&self) {
        self.to_send.send(Out::Ack).unwrap();
    }

    async fn close(self) {
        let _ = self.to_send.send(Out::Close);
        let _ = self.task.await;
    }
}

/// Lets the server's task and the driver catch up with what was sent.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

// ---------------------------------------------------------------- server

/// A station at common address 1 with a fixed clock ([`station_time`]),
/// no end of initialisation, and these points:
///
/// - 100: a scaled measured value, 1000, untagged events, in group 1;
/// - 4001: a double point, ON, which takes single commands;
/// - 200: a counter, reading 5, untagged.
fn config() -> ServerConfig {
    let mut config = ServerConfig::new(1)
        .point(
            100,
            PointConfig::new(Value::Scaled(1000)).untagged().group(1),
        )
        .point(4001, PointConfig::new(Value::Double(DoublePointState::On)))
        .point(
            200,
            PointConfig::new(Value::Counter {
                reading: 5,
                sequence: 0,
                carry: false,
                adjusted: false,
            })
            .untagged(),
        )
        .command(4001, Family::Single);
    config.end_of_initialisation = None;
    config.clock = Arc::new(station_time);
    config
}

/// A server with one connection, its far end not started yet.
async fn server(config: ServerConfig) -> (Server, AppSide, Peer) {
    let (app, side) = app();
    let server = Server::spawn(config, app).unwrap();
    let (near, peer) = Peer::pipe();
    server.attach(near).await.unwrap();
    (server, side, peer)
}

/// A server with its connection started, confirming everything.
async fn started(config: ServerConfig) -> (Server, AppSide, Master) {
    let (server, side, peer) = server(config).await;
    let master = Master::start(peer, true).await;
    (server, side, master)
}

// ----------------------------------------------------------------- tests

/// Fifty scaled points at addresses 1 to 50 and a double point at 4001, all
/// without time tags, for the packing tests.
fn packing_config() -> ServerConfig {
    let mut config = ServerConfig::new(1).point(
        4001,
        PointConfig::new(Value::Double(DoublePointState::On)).untagged(),
    );
    for ioa in 1..=50 {
        config = config.point(ioa, PointConfig::new(Value::Scaled(0)).untagged());
    }
    config
}

/// A spontaneous `M_ME_NB_1` ASDU of common address 1 with `objects` as
/// (address, value), SQ = 0 (5-101 cl.7.2.2.1, cl.7.3.1.11: a three octet
/// address, SVA low octet first, QDS).
fn scaled_events(objects: &[(u32, i16)]) -> Vec<u8> {
    let mut asdu = vec![11, objects.len() as u8, 3, 0, 1, 0];
    for &(ioa, value) in objects {
        asdu.extend_from_slice(&ioa.to_le_bytes()[..3]);
        asdu.extend_from_slice(&value.to_le_bytes());
        asdu.push(0);
    }
    asdu
}

/// A server whose k window (12) is full: the end of initialisation and
/// eleven events sent and not confirmed, so what is reported next waits in
/// the queue.
async fn window_full() -> (Server, Master) {
    let (server, _side, peer) = server(packing_config()).await;
    let mut master = Master::start(peer, false).await;
    // M_EI_NA_1, cause 4, COI 0 (local power on): the first started
    // connection's first ASDU (104 cl.7.1).
    assert_eq!(master.next().await, vec![70, 1, 4, 0, 1, 0, 0, 0, 0, 0]);
    for ioa in 1..=11 {
        server
            .report(ioa, Value::Scaled(-1), Quality::default(), None)
            .await
            .unwrap();
        assert_eq!(master.next().await, scaled_events(&[(ioa, -1)]), "{ioa}");
    }
    assert!(
        master.silent_for(Duration::from_secs(1)).await,
        "the window is full"
    );
    (server, master)
}

/// TS 60870-5-604 5.4.16.1: "The Controlled station transmits events of the
/// same Type, COT and priority but with gaps in their addresses as a Set of
/// Information elements (SQ:=0) in one single ASDU, filled until the maximum
/// configured ASDU or ADPU length as in the PICS". Events that waited for the
/// window go out together, in the order they were reported.
#[tokio::test(start_paused = true)]
async fn clause_5_4_16_1_queued_events_of_one_type_share_an_asdu() {
    let (server, mut master) = window_full().await;
    let reported: Vec<(u32, i16)> = (13..=32).map(|ioa| (ioa, ioa as i16 * 10)).collect();
    for &(ioa, value) in &reported {
        server
            .report(ioa, Value::Scaled(value), Quality::default(), None)
            .await
            .unwrap();
    }
    master.ack();
    assert_eq!(master.next().await, scaled_events(&reported));
    assert!(master.silent_for(Duration::from_secs(1)).await);
}

/// Only consecutive events of one type share an ASDU: another type between
/// them ends the set, and the order on the wire is the order reported. An
/// address already in the set starts a new ASDU, so each value of it is seen.
#[tokio::test(start_paused = true)]
async fn a_set_of_events_ends_at_another_type_and_at_a_repeated_address() {
    let (server, mut master) = window_full().await;
    for (ioa, value) in [
        (13, Value::Scaled(1)),
        (14, Value::Scaled(2)),
        (4001, Value::Double(DoublePointState::Off)),
        (15, Value::Scaled(3)),
        (15, Value::Scaled(4)),
    ] {
        server
            .report(ioa, value, Quality::default(), None)
            .await
            .unwrap();
    }
    master.ack();
    assert_eq!(master.next().await, scaled_events(&[(13, 1), (14, 2)]));
    // M_DP_NA_1 (5-101 cl.7.3.1.3): the address and DIQ, OFF = 1.
    assert_eq!(
        master.next().await,
        vec![3, 1, 3, 0, 1, 0, 0xa1, 0x0f, 0, 1]
    );
    assert_eq!(master.next().await, scaled_events(&[(15, 3)]));
    assert_eq!(master.next().await, scaled_events(&[(15, 4)]));
}

/// A set is filled up to, and not beyond, the 249 octets of 5-104 cl.5: six
/// octets of header and six per `M_ME_NB_1` object take forty objects; the
/// rest go in the next ASDU.
#[tokio::test(start_paused = true)]
async fn a_set_of_events_is_filled_up_to_249_octets() {
    let (server, mut master) = window_full().await;
    // Addresses 1 to 50 once each, after the eleven already sent.
    let reported: Vec<(u32, i16)> = (1..=50).map(|ioa| (ioa, 500 + ioa as i16)).collect();
    for &(ioa, value) in &reported {
        server
            .report(ioa, Value::Scaled(value), Quality::default(), None)
            .await
            .unwrap();
    }
    master.ack();
    let first = master.next().await;
    assert_eq!(first, scaled_events(&reported[..40]));
    assert_eq!(first.len(), 246);
    assert_eq!(master.next().await, scaled_events(&reported[40..]));
}

/// 104 cl.5: "START 68H defines the point of start within the data stream."
/// Octets that do not start with it, from a peer that is not speaking clause 5
/// (a port scanner, an HTTP request), close the connection at once, and the
/// slot it held is free for a real controlling station. Without this a peer
/// that sends junk keeps the only connection (`members = 1`) for as long as it
/// likes: the junk is never a frame, so nothing times out but t3's test.
#[tokio::test(start_paused = true)]
async fn clause_5_junk_instead_of_a_start_octet_closes_the_connection() {
    for junk in [&[0xff_u8; 64][..], b"GET / HTTP/1.1\r\n\r\n"] {
        let (server, _side, mut peer) = server(config()).await;
        peer.send(junk).await;
        let ended = tokio::time::timeout(Duration::from_secs(1), peer.frame()).await;
        assert_eq!(ended, Ok(None), "{junk:?}: closed at once, nothing sent");
        let (near, real) = Peer::pipe();
        server.attach(near).await.unwrap();
        Master::start(real, true).await;
    }
}

/// The same in the middle of a started connection: junk after a frame closes
/// it.
#[tokio::test(start_paused = true)]
async fn clause_5_junk_after_a_frame_closes_the_connection() {
    let (server, _side, mut peer) = server(config()).await;
    peer.send(&STARTDT_ACT).await;
    assert_eq!(peer.frame().await.unwrap(), STARTDT_CON);
    peer.send(&[0xaa]).await;
    let ended = tokio::time::timeout(Duration::from_secs(1), async {
        while peer.frame().await.is_some() {}
    })
    .await;
    assert!(ended.is_ok(), "closed at once");
    let (near, real) = Peer::pipe();
    server.attach(near).await.unwrap();
    Master::start(real, true).await;
}

/// 104 cl.5.3: *"In this state, the controlled station does not send any data
/// via this connection, except unnumbered control functions and
/// confirmations to such functions."* and *"Any pending user data in the
/// controlled station is sent only after the STARTDT con."* The end of
/// initialisation comes first (5-101 Table 16's first row; 104 cl.7.1 figure
/// 21), then the event that was waiting.
#[tokio::test(start_paused = true)]
async fn clause_5_3_nothing_before_startdt_then_end_of_initialisation_first() {
    let mut config = config();
    config.end_of_initialisation = ServerConfig::new(1).end_of_initialisation;
    let (server, _side, mut peer) = server(config).await;
    server
        .report(100, Value::Scaled(1234), Quality::default(), None)
        .await
        .unwrap();
    let nothing = tokio::time::timeout(Duration::from_secs(5), peer.frame()).await;
    assert!(nothing.is_err(), "sent before STARTDT: {nothing:?}");

    let mut master = Master::start(peer, true).await;
    assert_eq!(master.next().await, END_OF_INIT);
    assert_eq!(master.next().await, scaled(SPONT, 1234));
}

/// TS 60870-5-604 5.4.12.30: after re-establishment *"no `M_EI` (End of
/// initialisation) is sent (nor needed) to the Controlling station"*. The
/// end of initialisation goes out on the first started connection only.
#[tokio::test(start_paused = true)]
async fn the_end_of_initialisation_is_sent_once() {
    let mut config = config();
    config.end_of_initialisation = ServerConfig::new(1).end_of_initialisation;
    let (server, _side, peer) = server(config).await;
    let mut master = Master::start(peer, true).await;
    assert_eq!(master.next().await, END_OF_INIT);
    master.close().await;
    settle().await;

    let (near, peer) = Peer::pipe();
    server.attach(near).await.unwrap();
    let mut master = Master::start(peer, true).await;
    assert!(master.silent_for(Duration::from_secs(5)).await);
}

/// 5-101 cl.7.4.5 and Table 17: the station interrogation is confirmed, the
/// points come with cause 20 in their untagged types (*"ASDUs with cause of
/// transmission 20 to 36 are transmitted without time tags"*), one ASDU per
/// type, and the termination ends it. The counter is not in it: counters
/// answer the counter interrogation.
#[tokio::test(start_paused = true)]
async fn clause_7_4_5_station_interrogation_from_the_image() {
    let (_server, _side, mut master) = started(config()).await;
    master.send(&interrogation(ACT, 20));
    assert_eq!(master.next().await, interrogation(ACTCON, 20));
    assert_eq!(master.next().await, scaled(INROGEN, 1000));
    // DIQ: DPI 2, ON.
    assert_eq!(master.next().await, double_point(INROGEN, 0x02));
    assert_eq!(master.next().await, interrogation(ACTTERM, 20));
}

/// 5-101 cl.7.2.6.22: `QOI` 21 is group 1, and its objects carry cause 21
/// (interrogated by group 1). Only point 100 is in group 1.
#[tokio::test(start_paused = true)]
async fn clause_7_4_5_group_interrogation() {
    let (_server, _side, mut master) = started(config()).await;
    master.send(&interrogation(ACT, 21));
    assert_eq!(master.next().await, interrogation(ACTCON, 21));
    assert_eq!(master.next().await, scaled(21, 1000));
    assert_eq!(master.next().await, interrogation(ACTTERM, 21));
}

/// A value written with `set` is sent in the next interrogation and not
/// before: no event.
#[tokio::test(start_paused = true)]
async fn a_silent_write_is_sent_when_asked_for() {
    let (server, _side, mut master) = started(config()).await;
    server
        .set(100, Value::Scaled(-2), Quality::default())
        .await
        .unwrap();
    assert!(master.silent_for(Duration::from_secs(5)).await);
    master.send(&interrogation(ACT, 21));
    assert_eq!(master.next().await, interrogation(ACTCON, 21));
    assert_eq!(master.next().await, scaled(21, -2));
    assert_eq!(master.next().await, interrogation(ACTTERM, 21));
}

/// 104 cl.7.2 and 5-101 cl.7.4.2: a read returns the object with cause 5
/// (*"Normally, these requested objects do not include the time tag."*); an
/// address the station has no point at is mirrored with cause 47 (5-101
/// cl.7.2.3).
#[tokio::test(start_paused = true)]
async fn clause_7_2_read() {
    let (_server, _side, mut master) = started(config()).await;
    master.send(&read(IOA_4001));
    assert_eq!(master.next().await, double_point(REQ, 0x02));
    master.send(&read(IOA_4002));
    let mut mirror = head(102, 1, UNKNOWN_IOA);
    mirror.extend(IOA_4002);
    assert_eq!(master.next().await, mirror);
}

/// 5-101 cl.7.4.8 and TS 60870-5-604 Table 20 (mode C): a general
/// collection (`QCC` 5, `FRZ` 0) is confirmed, the counter comes with cause
/// 37, and the termination follows. A freeze (`FRZ` 1, `QCC` `0x45`) is only
/// confirmed (5-101 figure 95), and the next collection returns the frozen
/// value, not the one written since.
#[tokio::test(start_paused = true)]
async fn clause_7_4_8_counter_interrogation_and_freeze() {
    let (server, mut side, mut master) = started(config()).await;
    master.send(&counter_interrogation(ACT, 0x05));
    assert_eq!(master.next().await, counter_interrogation(ACTCON, 0x05));
    assert_eq!(master.next().await, total(REQCOGEN, 5));
    assert_eq!(master.next().await, counter_interrogation(ACTTERM, 0x05));

    master.send(&counter_interrogation(ACT, 0x45));
    assert_eq!(master.next().await, counter_interrogation(ACTCON, 0x45));
    assert!(master.silent_for(Duration::from_secs(5)).await);
    server
        .set(
            200,
            Value::Counter {
                reading: 9,
                sequence: 1,
                carry: false,
                adjusted: false,
            },
            Quality::default(),
        )
        .await
        .unwrap();
    master.send(&counter_interrogation(ACT, 0x05));
    assert_eq!(master.next().await, counter_interrogation(ACTCON, 0x05));
    assert_eq!(master.next().await, total(REQCOGEN, 5));
    assert_eq!(master.next().await, counter_interrogation(ACTTERM, 0x05));

    // `FRZ` 3 (`QCC` `0xC5`): a reset, handed to the application.
    master.send(&counter_interrogation(ACT, 0xC5));
    assert_eq!(master.next().await, counter_interrogation(ACTCON, 0xC5));
    assert_eq!(side.resets.recv().await, Some(ci::Request::General));
}

/// 5-101 cl.7.2.3: a `T = 1` counter interrogation is answered under test
/// conditions and does not control the process: a reset is confirmed with
/// `T = 1` and no counter is reset; a collection, which only reads,
/// still runs and its totals carry `T = 1` too.
#[tokio::test(start_paused = true)]
async fn clause_7_2_3_a_test_counter_interrogation_does_not_reset() {
    let (_server, mut side, mut master) = started(config()).await;
    master.send(&counter_interrogation(0x80 | ACT, 0xC5));
    assert_eq!(
        master.next().await,
        counter_interrogation(0x80 | ACTCON, 0xC5)
    );
    settle().await;
    assert!(side.resets.try_recv().is_err(), "no counter is reset");

    master.send(&counter_interrogation(0x80 | ACT, 0x05));
    assert_eq!(
        master.next().await,
        counter_interrogation(0x80 | ACTCON, 0x05)
    );
    assert_eq!(master.next().await, total(0x80 | REQCOGEN, 5));
    assert_eq!(
        master.next().await,
        counter_interrogation(0x80 | ACTTERM, 0x05)
    );
}

/// 104 cl.7.6: *"After the execution of the clock sync internally the
/// controlled station generates a `C_CS` ACTCON PDU that contains the local
/// time before it was synchronized."* The application gets the new time.
/// Before it, a time-tagged event carries the invalid mark (*"This mark is
/// also set after station initializiation (warm and cold boot) of controlled
/// stations before reception of a valid `C_CS` ACT PDU."*); after it, not
/// (*"Time-tagged events that occur after the reception of valid `C_CS` ACT PDU
/// are transmitted without the mark."*).
#[tokio::test(start_paused = true)]
async fn clause_7_6_clock_synchronisation_and_the_invalid_mark() {
    let config = config().point(4002, PointConfig::new(Value::Single(false)));
    let (server, mut side, mut master) = started(config).await;
    server
        .report(4002, Value::Single(true), Quality::default(), None)
        .await
        .unwrap();
    // `CP56Time2a` octet 3, bit 8: `IV`.
    let mut invalid = TIME;
    invalid[2] |= 0x80;
    assert_eq!(master.next().await, single_tagged(0x01, invalid));

    master.send(&clock_sync(ACT, MASTER_TIME));
    assert_eq!(master.next().await, clock_sync(ACTCON, TIME));
    let synchronised = side.synchronised.recv().await.unwrap();
    assert_eq!((synchronised.hours, synchronised.minutes), (13, 0));

    server
        .report(4002, Value::Single(false), Quality::default(), None)
        .await
        .unwrap();
    assert_eq!(master.next().await, single_tagged(0x00, TIME));
}

/// 104 cl.7.6 names the alternative to the procedure: *"Use of this procedure
/// avoids the necessity of installing clock synchronization receivers or
/// similar equipment"*. A station whose clock such equipment keeps (GPS,
/// NTP) does not wait for a `C_CS ACT`: its time-tagged events carry no
/// invalid mark from the start, and none after the agreed interval either.
#[tokio::test(start_paused = true)]
async fn clause_7_6_an_external_clock_needs_no_clock_synchronisation() {
    let mut config = config().point(4002, PointConfig::new(Value::Single(false)));
    config.external_clock = true;
    let interval = config.sync_interval;
    let (server, _side, mut master) = started(config).await;
    server
        .report(4002, Value::Single(true), Quality::default(), None)
        .await
        .unwrap();
    assert_eq!(master.next().await, single_tagged(0x01, TIME));

    tokio::time::advance(interval + Duration::from_secs(1)).await;
    master.ack();
    server
        .report(4002, Value::Single(false), Quality::default(), None)
        .await
        .unwrap();
    assert_eq!(master.next().await, single_tagged(0x00, TIME));
}

/// 104 cl.7.7, TS 60870-5-604 5.4.19.20: a direct execute is mirrored with
/// cause 7, operated, and terminated with cause 10 when the operation ends.
/// 5.4.19.40's alternative: a failed operation is the negative termination.
#[tokio::test(start_paused = true)]
async fn clause_7_7_direct_execute_confirmed_operated_terminated() {
    let (_server, mut side, mut master) = started(config()).await;
    master.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x01));
    let (command, done) = side.operation().await;
    assert_eq!(command, Command::single(4001, true));
    done.send(true).unwrap();
    assert_eq!(master.next().await, single_command(ACTTERM, IOA_4001, 0x01));

    master.send(&single_command(ACT, IOA_4001, 0x00));
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x00));
    let (_, done) = side.operation().await;
    done.send(false).unwrap();
    assert_eq!(
        master.next().await,
        single_command(ACTTERM_NEGATIVE, IOA_4001, 0x00)
    );
}

/// 5-101 cl.7.2.3: the test bit marks an ASDU *"generated during test
/// conditions"*, used *"to test transmission and equipment without
/// controlling the process"*. A `T = 1` execute is confirmed and terminated
/// under test conditions, and never operated; a `T = 1` clock synchronisation
/// is answered under test conditions and does not set the clock.
#[tokio::test(start_paused = true)]
async fn clause_7_2_3_a_test_frame_does_not_control_the_process() {
    let (_server, mut side, mut master) = started(config()).await;
    master.send(&single_command(0x80 | ACT, IOA_4001, 0x01));
    assert_eq!(
        master.next().await,
        single_command(0x80 | ACTCON, IOA_4001, 0x01)
    );
    assert_eq!(
        master.next().await,
        single_command(0x80 | ACTTERM, IOA_4001, 0x01)
    );
    settle().await;
    assert!(side.operations.try_recv().is_err(), "nothing is operated");

    master.send(&clock_sync(0x80 | ACT, MASTER_TIME));
    assert_eq!(master.next().await, clock_sync(0x80 | ACTCON, TIME));
    settle().await;
    assert!(
        side.synchronised.try_recv().is_err(),
        "the clock is not set"
    );
}

/// An application whose first operation panics.
struct PanicsOnce(AtomicBool);

impl Application for PanicsOnce {
    fn accept(&self, _command: &Command) -> bool {
        true
    }

    async fn operate(&self, _command: Command) -> bool {
        tokio::task::yield_now().await;
        assert!(!self.0.swap(false, Ordering::SeqCst), "operation panics");
        true
    }

    fn synchronise(&self, _time: Cp56Time2a) {}

    fn reset_counters(&self, _request: ci::Request) {}
}

/// An operation that panics is a failed one (5.4.19.40): it is terminated
/// negatively and the object is free for the next execute, not held until
/// restart.
#[tokio::test(start_paused = true)]
async fn a_panicking_operation_fails_and_frees_its_object() {
    let server = Server::spawn(config(), PanicsOnce(AtomicBool::new(true))).unwrap();
    let (near, peer) = Peer::pipe();
    server.attach(near).await.unwrap();
    let mut master = Master::start(peer, true).await;

    master.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x01));
    assert_eq!(
        master.next().await,
        single_command(ACTTERM_NEGATIVE, IOA_4001, 0x01)
    );

    master.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x01));
    assert_eq!(master.next().await, single_command(ACTTERM, IOA_4001, 0x01));
}

/// TS 60870-5-604 5.4.19.50: a command to an address that takes none is
/// mirrored with cause 47; one the application refuses gets the negative
/// confirmation, and nothing is operated.
#[tokio::test(start_paused = true)]
async fn clause_7_7_unknown_address_and_refused_command() {
    let (_server, mut side, mut master) = started(config()).await;
    master.send(&single_command(ACT, IOA_4002, 0x01));
    assert_eq!(
        master.next().await,
        single_command(UNKNOWN_IOA, IOA_4002, 0x01)
    );

    side.accept.store(false, Ordering::SeqCst);
    master.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(
        master.next().await,
        single_command(ACTCON_NEGATIVE, IOA_4001, 0x01)
    );
    assert!(side.operations.try_recv().is_err());
}

/// TS 60870-5-604 5.4.19.1: *"Command function EXECUTE after SELECT shall be
/// received within the configured delay in the controlled station"*. An
/// execute 11 s after its select, past the 10 s default, is refused with the
/// negative confirmation (5.4.19.40); within it, it is operated.
#[tokio::test(start_paused = true)]
async fn select_timeout() {
    let mut config = config();
    config.command_mode = CommandMode::SelectAndExecute;
    let (_server, mut side, mut master) = started(config).await;
    // SCO 0x81: S/E = 1 (select), SCS ON.
    master.send(&single_command(ACT, IOA_4001, 0x81));
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x81));
    tokio::time::sleep(Duration::from_secs(11)).await;
    master.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(
        master.next().await,
        single_command(ACTCON_NEGATIVE, IOA_4001, 0x01)
    );

    master.send(&single_command(ACT, IOA_4001, 0x81));
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x81));
    tokio::time::sleep(Duration::from_secs(9)).await;
    master.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x01));
    let (_, done) = side.operation().await;
    done.send(true).unwrap();
    assert_eq!(master.next().await, single_command(ACTTERM, IOA_4001, 0x01));
}

/// TS 60870-5-604 Table 19: *"Command function during a running general
/// interrogation is processed and executed without waiting for the GI to
/// finish."* An operation that takes a minute does not hold up an
/// interrogation that arrives meanwhile.
#[tokio::test(start_paused = true)]
async fn a_slow_operation_does_not_hold_up_an_interrogation() {
    let (_server, mut side, mut master) = started(config()).await;
    master.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x01));
    let (_, done) = side.operation().await;
    master.send(&interrogation(ACT, 21));
    assert_eq!(master.next().await, interrogation(ACTCON, 21));
    assert_eq!(master.next().await, scaled(21, 1000));
    assert_eq!(master.next().await, interrogation(ACTTERM, 21));
    tokio::time::sleep(Duration::from_secs(60)).await;
    done.send(true).unwrap();
    assert_eq!(master.next().await, single_command(ACTTERM, IOA_4001, 0x01));
}

/// 104 cl.7.10: the test command is confirmed; parameter loading (5-101
/// cl.7.3.5, not served) is mirrored with cause 44 (5-101 cl.7.2.3).
#[tokio::test(start_paused = true)]
async fn clause_7_10_test_command_and_cause_44_for_parameters() {
    let (_server, _side, mut master) = started(config()).await;
    // C_TS_TA_1 <107> (104 cl.8.8): address 0, TSC 0x1092, then the time.
    let mut test = head(107, 1, ACT);
    test.extend([0x00, 0x00, 0x00, 0x92, 0x10]);
    test.extend(TIME);
    master.send(&test);
    let mut confirmation = head(107, 1, ACTCON);
    confirmation.extend(&test[6..]);
    assert_eq!(master.next().await, confirmation);

    // P_ME_NB_1 <111> (5-101 cl.7.3.5.2) at 100: SVA 250, QPM 1 (threshold).
    let mut parameter = head(111, 1, ACT);
    parameter.extend(IOA_100);
    parameter.extend([0xFA, 0x00, 0x01]);
    master.send(&parameter);
    let mut mirror = head(111, 1, UNKNOWN_TYPE);
    mirror.extend(&parameter[6..]);
    assert_eq!(master.next().await, mirror);
}

/// 5-101 cl.7.4, Table 16: *"If a controlled station has data for more than
/// one of the following ASDU types ready for transmission at the same time,
/// they must be sent in the following order regardless of which data was
/// generated first."* With k = 1 (clause 5.5) and the one I-frame
/// unconfirmed, an interrogation, an event and a command arrive in that
/// order; as the window opens one frame at a time they go out as the table
/// orders them: the command's mirror, the event, then the interrogation.
#[tokio::test(start_paused = true)]
async fn table_16_orders_what_is_ready_at_the_same_time() {
    let mut config = config();
    config.link = LinkParams {
        k: 1,
        w: 1,
        ..LinkParams::default()
    };
    let (server, mut side, peer) = server(config).await;
    let mut master = Master::start(peer, false).await;
    server
        .report(100, Value::Scaled(1), Quality::default(), None)
        .await
        .unwrap();
    assert_eq!(master.next().await, scaled(SPONT, 1));

    master.send(&interrogation(ACT, 21));
    settle().await;
    server
        .report(100, Value::Scaled(2), Quality::default(), None)
        .await
        .unwrap();
    master.send(&single_command(ACT, IOA_4001, 0x01));
    settle().await;
    assert!(master.silent_for(Duration::from_secs(1)).await, "k is full");

    master.ack();
    assert_eq!(master.next().await, single_command(ACTCON, IOA_4001, 0x01));
    master.ack();
    assert_eq!(master.next().await, scaled(SPONT, 2));
    master.ack();
    assert_eq!(master.next().await, interrogation(ACTCON, 21));
    master.ack();
    // Encoded when handed over: the value the event already reported.
    assert_eq!(master.next().await, scaled(21, 2));
    master.ack();
    assert_eq!(master.next().await, interrogation(ACTTERM, 21));
    let (_, done) = side.operation().await;
    done.send(true).unwrap();
    master.ack();
    assert_eq!(master.next().await, single_command(ACTTERM, IOA_4001, 0x01));
}

/// 5-101 cl.7.2.2.2: *"The transmission of successive values of a particular
/// INFORMATION OBJECT must always be in the chronological order in which the
/// values were measured."* An event that overtakes a waiting interrogation
/// does not leave the interrogation with an older value: it is encoded when
/// it is handed over.
#[tokio::test(start_paused = true)]
async fn clause_7_2_2_2_an_interrogation_is_never_older_than_an_event_sent() {
    let mut config = config();
    config.link = LinkParams {
        k: 1,
        w: 1,
        ..LinkParams::default()
    };
    let (server, _side, peer) = server(config).await;
    let mut master = Master::start(peer, false).await;
    server
        .report(
            4001,
            Value::Double(DoublePointState::Off),
            Quality::default(),
            None,
        )
        .await
        .unwrap();
    let first = master.next().await;
    assert_eq!(first[0], 31, "M_DP_TB_1: a tagged event");

    master.send(&interrogation(ACT, 21));
    settle().await;
    master.ack();
    assert_eq!(master.next().await, interrogation(ACTCON, 21));
    server
        .report(100, Value::Scaled(7), Quality::default(), None)
        .await
        .unwrap();
    settle().await;
    master.ack();
    assert_eq!(master.next().await, scaled(SPONT, 7));
    master.ack();
    assert_eq!(master.next().await, scaled(21, 7));
}

/// `M_ME_NB_1` `<11>` (5-101 cl.7.3.1.11) with `SQ = 0` and one object per
/// `(address, SVA)`, each with `QDS` 0: the address in three octets, the
/// value in two, the quality descriptor in one.
fn scaled_objects(cause: u8, objects: &[(u32, i16)]) -> Vec<u8> {
    let mut asdu = head(11, objects.len() as u8, cause);
    for (ioa, value) in objects {
        asdu.extend(&ioa.to_le_bytes()[..3]);
        asdu.extend(value.to_le_bytes());
        asdu.push(0x00);
    }
    asdu
}

/// 5-101 cl.7.4, Table 16: *"If a controlled station has data for more than
/// one of the following ASDU types ready for transmission at the same time,
/// they must be sent in the following order regardless of which data was
/// generated first."* Its rows put *"45 to 69"* (*"Command transmission"*,
/// *"Mirrored ASDUs"*) and *"1 to 44"* (*"Event reporting: In monitor
/// direction with COT = 3"*) above *"100, 101"* (*"Station interrogation,
/// transmission of integrated totals"*). The table holds while an
/// interrogation's answer is being sent, not only before it starts: a
/// command and an event that come up between two of its ASDUs go out before
/// the rest of it.
///
/// The station has 81 scaled points in the station interrogation (100 and
/// 1001 to 1080). 104 clause 5: *"The maximum length of the ASDU is limited to
/// 249"*; an `M_ME_NB_1` object with a three-octet address takes 6 octets
/// after the 6 of the data unit identifier, so an ASDU holds 40 of them and
/// the answer is three `M_ME_NB_1` ASDUs (40, 40 and 1 objects), then the
/// `M_DP_NA_1` of 4001, then the termination (5-101 cl.7.4.5). With k = 1
/// (clause 5.5) each acknowledgement opens room for one ASDU.
///
/// The same paragraph of 5-101 cl.7.4 ends *"The chronological reporting
/// requirements defined in 7.2.2.2 are valid."*, and 7.2.2.2 reads *"The
/// transmission of successive values of a particular INFORMATION OBJECT must
/// always be in the chronological order in which the values were
/// measured."* The event for 1050 overtakes the ASDU that holds 1050, so
/// that ASDU carries the event's value, not the older one.
#[tokio::test(start_paused = true)]
async fn table_16_holds_while_an_interrogation_is_being_sent() {
    let mut config = config();
    for ioa in 1001..=1080 {
        config = config.point(ioa, PointConfig::new(Value::Scaled(0)).untagged());
    }
    config.link = LinkParams {
        k: 1,
        w: 1,
        ..LinkParams::default()
    };
    let (server, mut side, peer) = server(config).await;
    let mut master = Master::start(peer, false).await;
    let first: Vec<(u32, i16)> = std::iter::once((100, 1000))
        .chain((1001..=1039).map(|ioa| (ioa, 0)))
        .collect();
    let second: Vec<(u32, i16)> = (1040..=1079)
        .map(|ioa| (ioa, if ioa == 1050 { 7 } else { 0 }))
        .collect();

    master.send(&interrogation(ACT, 20));
    assert_eq!(master.next().await, interrogation(ACTCON, 20));
    master.ack();
    assert_eq!(master.next().await, scaled_objects(INROGEN, &first));

    // The answer is under way; a command arrives and an event is reported.
    server
        .report(1050, Value::Scaled(7), Quality::default(), None)
        .await
        .unwrap();
    master.send(&single_command(ACT, IOA_4001, 0x01));
    let (_, done) = side.operation().await;
    done.send(true).unwrap();
    settle().await;
    assert!(master.silent_for(Duration::from_secs(1)).await, "k is full");

    let mut rest = Vec::new();
    for _ in 0..7 {
        master.ack();
        rest.push(master.next().await);
    }
    assert_eq!(
        rest,
        [
            single_command(ACTCON, IOA_4001, 0x01),
            single_command(ACTTERM, IOA_4001, 0x01),
            scaled_objects(SPONT, &[(1050, 7)]),
            scaled_objects(INROGEN, &second),
            scaled_objects(INROGEN, &[(1080, 0)]),
            double_point(INROGEN, 0x02),
            interrogation(ACTTERM, 20),
        ]
    );
}

/// The station of [`table_16_holds_while_an_interrogation_is_being_sent`]:
/// 81 scaled points in the station interrogation, three `M_ME_NB_1` ASDUs
/// (40, 40 and 1 objects) and the `M_DP_NA_1` of 4001, with k = 1.
fn large_station() -> ServerConfig {
    let mut config = config();
    for ioa in 1001..=1080 {
        config = config.point(ioa, PointConfig::new(Value::Scaled(0)).untagged());
    }
    config.link = LinkParams {
        k: 1,
        w: 1,
        ..LinkParams::default()
    };
    config
}

/// The station interrogation's answer from [`large_station`], its objects
/// as configured: 100 (1000), 1001 to 1080 (0), then 4001 ON.
fn large_answer() -> Vec<Vec<u8>> {
    let objects: Vec<(u32, i16)> = std::iter::once((100, 1000))
        .chain((1001..=1080).map(|ioa| (ioa, 0)))
        .collect();
    let mut answer: Vec<Vec<u8>> = objects
        .chunks(40)
        .map(|run| scaled_objects(INROGEN, run))
        .collect();
    answer.push(double_point(INROGEN, 0x02));
    answer
}

/// TS 60870-5-604 5.4.17.50, *"Deactivate a running Outstation
/// interrogation"*: *"The Controlling station sends an Interrogation Command
/// with COT = 8, `C_IC_DEACT` to the Controlled station with QOI=20 (station)
/// or 21..36 (group 1..16)"*, *"The Controlled station sends an Interrogation
/// Command with COT = 9, `C_IC_DEACTCON` to the Controlling station"*, then
/// *"No further Information Objects that are part of the GI for that QOI are
/// sent to the Controlling station. No Interrogation Command with COT = 10
/// (ACTTERM) to the Controlling station"*.
///
/// The deactivation arrives after the first of the answer's four data ASDUs,
/// while the rest wait for room in the k = 1 window. The interrogation is
/// still running (TS 60870-5-604 Table 17: *"A running GI means that the
/// controlling station has not received the `C_IC_ACTTERM` after it has sent
/// a `C_IC_ACT`"*), so the confirmation is positive, and nothing of the answer
/// follows it. A later group interrogation is answered in full.
#[tokio::test(start_paused = true)]
async fn ts_604_5_4_17_50_a_deactivation_stops_the_answer_being_sent() {
    let (_server, _side, peer) = server(large_station()).await;
    let mut master = Master::start(peer, false).await;
    let answer = large_answer();

    master.send(&interrogation(ACT, 20));
    assert_eq!(master.next().await, interrogation(ACTCON, 20));
    master.ack();
    assert_eq!(master.next().await, answer[0]);

    master.send(&interrogation(DEACT, 20));
    settle().await;
    master.ack();
    assert_eq!(master.next().await, interrogation(DEACTCON, 20));
    master.ack();
    assert!(
        master.silent_for(Duration::from_secs(5)).await,
        "nothing of the deactivated interrogation follows"
    );

    master.send(&interrogation(ACT, 21));
    assert_eq!(master.next().await, interrogation(ACTCON, 21));
    master.ack();
    assert_eq!(master.next().await, scaled(21, 1000));
    master.ack();
    assert_eq!(master.next().await, interrogation(ACTTERM, 21));
}

/// TS 60870-5-604 5.4.17.30, *"Re-activate a running Outstation
/// interrogation"*, *"Option 2: the running GI is stopped and the second GI
/// is started"* (`ReActivation::Restart`). The second activation arrives
/// after the first data ASDU: the stopped interrogation sends nothing more
/// of its answer, and the second one sends the whole answer from the start,
/// then its termination (5-101 cl.7.4.5). The stopped one is closed with a
/// termination before the second is confirmed, as `gi` does for this option.
#[tokio::test(start_paused = true)]
async fn ts_604_5_4_17_30_a_restart_stops_the_answer_being_sent() {
    let mut config = large_station();
    config.reactivation = iec104::gi::ReActivation::Restart;
    let (_server, _side, peer) = server(config).await;
    let mut master = Master::start(peer, false).await;
    let answer = large_answer();

    master.send(&interrogation(ACT, 20));
    assert_eq!(master.next().await, interrogation(ACTCON, 20));
    master.ack();
    assert_eq!(master.next().await, answer[0]);

    master.send(&interrogation(ACT, 20));
    settle().await;
    let mut expected = vec![interrogation(ACTTERM, 20), interrogation(ACTCON, 20)];
    expected.extend(answer);
    expected.push(interrogation(ACTTERM, 20));
    let mut sent = Vec::new();
    for _ in 0..expected.len() {
        master.ack();
        sent.push(master.next().await);
    }
    assert_eq!(sent, expected);
    master.ack();
    assert!(master.silent_for(Duration::from_secs(5)).await);
}

/// TS 60870-5-604 5.4.17.40, *"Option 3: the running GI continues and after
/// activation termination (COT=10) the second GI is started."*
/// (`ReActivation::Queue`). A group 1 interrogation arrives while the station
/// interrogation's confirmation waits for its acknowledgement (k = 1). The
/// second is confirmed, and each procedure keeps 5-101 Table 17's order:
/// `actcon`, the objects, `actterm`. So the second's objects follow both its
/// own confirmation and the first's termination.
#[tokio::test(start_paused = true)]
async fn ts_604_5_4_17_40_a_queued_interrogation_follows_its_confirmation() {
    let mut config = config();
    config.reactivation = iec104::gi::ReActivation::Queue;
    config.link = LinkParams {
        k: 1,
        w: 1,
        ..LinkParams::default()
    };
    let (_server, _side, peer) = server(config).await;
    let mut master = Master::start(peer, false).await;

    master.send(&interrogation(ACT, 20));
    assert_eq!(master.next().await, interrogation(ACTCON, 20));
    master.send(&interrogation(ACT, 21));
    settle().await;
    let expected = [
        scaled(INROGEN, 1000),
        double_point(INROGEN, 0x02),
        interrogation(ACTTERM, 20),
        interrogation(ACTCON, 21),
        scaled(21, 1000),
        interrogation(ACTTERM, 21),
    ];
    let mut sent = Vec::new();
    for _ in 0..expected.len() {
        master.ack();
        sent.push(master.next().await);
    }
    // The first procedure's objects and termination may come before or
    // after the second's confirmation; each procedure's own order may not.
    let at = |frame: &Vec<u8>| sent.iter().position(|f| f == frame).expect("sent");
    assert!(at(&expected[0]) < at(&expected[1]) && at(&expected[1]) < at(&expected[2]));
    assert!(at(&expected[3]) < at(&expected[4]) && at(&expected[4]) < at(&expected[5]));
    assert!(at(&expected[2]) < at(&expected[4]), "{sent:?}");
    master.ack();
    assert!(master.silent_for(Duration::from_secs(5)).await);
}

/// `M_IT_NA_1` `<15>` (5-101 cl.7.3.1.15) with `SQ = 0` and one object per
/// `(address, reading)`: the address in three octets, the `BCR` in five
/// (cl.7.2.6.9: the reading in four, then the sequence octet, 0 here).
fn totals(cause: u8, objects: &[(u32, i32)]) -> Vec<u8> {
    let mut asdu = head(15, objects.len() as u8, cause);
    for (ioa, reading) in objects {
        asdu.extend(&ioa.to_le_bytes()[..3]);
        asdu.extend(reading.to_le_bytes());
        asdu.push(0x00);
    }
    asdu
}

/// The counter interrogation's answer is sent the same way: 5-101 Table 16
/// puts *"101"* in the same row as *"100"*, below event reporting. 31
/// counters (200 and 1201 to 1230) need two `M_IT_NA_1` ASDUs: an object
/// takes 8 octets, so 30 fit in 104 clause 5's *"249"*. An event for 1230
/// reported while the first ASDU waits for its acknowledgement goes out
/// before the second, and the second carries the event's reading (5-101
/// cl.7.2.2.2). No freeze was made, so the counters answer with their
/// current readings.
#[tokio::test(start_paused = true)]
async fn table_16_holds_while_a_counter_interrogation_is_being_sent() {
    let counter = |reading| Value::Counter {
        reading,
        sequence: 0,
        carry: false,
        adjusted: false,
    };
    let mut config = config();
    for ioa in 1201..=1230 {
        config = config.point(ioa, PointConfig::new(counter(0)).untagged());
    }
    config.link = LinkParams {
        k: 1,
        w: 1,
        ..LinkParams::default()
    };
    let (server, _side, peer) = server(config).await;
    let mut master = Master::start(peer, false).await;
    let first: Vec<(u32, i32)> = std::iter::once((200, 5))
        .chain((1201..=1229).map(|ioa| (ioa, 0)))
        .collect();

    master.send(&counter_interrogation(ACT, 0x05));
    assert_eq!(master.next().await, counter_interrogation(ACTCON, 0x05));
    master.ack();
    assert_eq!(master.next().await, totals(REQCOGEN, &first));

    server
        .report(1230, counter(9), Quality::default(), None)
        .await
        .unwrap();
    settle().await;
    master.ack();
    assert_eq!(master.next().await, totals(SPONT, &[(1230, 9)]));
    master.ack();
    assert_eq!(master.next().await, totals(REQCOGEN, &[(1230, 9)]));
    master.ack();
    assert_eq!(master.next().await, counter_interrogation(ACTTERM, 0x05));
}

/// TS 60870-5-604 5.4.16.1's *"Local buffer function to collect events that
/// may appear faster than it is possible to transmit them"*: its size is the
/// station's. Beyond it the oldest event is dropped and counted.
#[tokio::test(start_paused = true)]
async fn the_event_buffer_drops_the_oldest() {
    let mut config = config();
    config.event_buffer = 2;
    let (server, _side, peer) = server(config).await;
    for value in 1..=3 {
        server
            .report(100, Value::Scaled(value), Quality::default(), None)
            .await
            .unwrap();
    }
    assert_eq!(server.dropped().await, Ok(1));
    let mut master = Master::start(peer, true).await;
    assert_eq!(master.next().await, scaled(SPONT, 2));
    assert_eq!(master.next().await, scaled(SPONT, 3));
}

/// The answers waiting for the window are bounded too: a controlling
/// station that floods reads and does not confirm gets the k window's worth
/// and the request buffer's worth answered; the other reads are dropped and
/// counted.
#[tokio::test(start_paused = true)]
async fn the_request_buffer_drops_new_requests() {
    let mut config = config();
    config.request_buffer = 2;
    let (server, _side, peer) = server(config).await;
    let mut master = Master::start(peer, false).await;
    for _ in 0..100 {
        master.send(&read(IOA_100));
    }
    settle().await;
    let k = LinkParams::default().k;
    let mut answers = 0;
    while !master.silent_for(Duration::from_secs(1)).await {
        answers += 1;
        master.ack();
    }
    assert_eq!(answers, usize::from(k) + 2);
    assert_eq!(server.dropped().await, Ok(100 - u64::from(k) - 2));
}

/// 104 cl.10.6: *"any unconfirmed user data will be retransmitted on the new
/// started connection after a connection switchover has been performed,
/// including potential unconfirmed ACTCONs or ACTTERMs."* An event the first
/// connection did not confirm goes out again on the second, once the
/// controlling station starts it (10.7: the first one is closed).
#[tokio::test(start_paused = true)]
async fn clause_10_6_unconfirmed_data_goes_out_on_the_next_started_connection() {
    let mut config = config();
    config.members = 2;
    let (server, _side, peer0) = server(config).await;
    let (near1, peer1) = Peer::pipe();
    server.attach(near1).await.unwrap();

    let mut first = Master::start(peer0, false).await;
    server
        .report(100, Value::Scaled(3), Quality::default(), None)
        .await
        .unwrap();
    assert_eq!(first.next().await, scaled(SPONT, 3));

    let mut second = Master::start(peer1, true).await;
    assert_eq!(second.next().await, scaled(SPONT, 3));
    first.close().await;
}

/// The value kind of a point is fixed, and an unknown address is refused.
#[tokio::test(start_paused = true)]
async fn writes_are_checked() {
    use iec104_tokio::server::ServerError;
    let (server, _side, _peer) = server(config()).await;
    assert_eq!(
        server
            .set(100, Value::Single(true), Quality::default())
            .await,
        Err(ServerError::WrongKind(100))
    );
    assert_eq!(
        server.set(9, Value::Single(true), Quality::default()).await,
        Err(ServerError::UnknownAddress(9))
    );
    let point = server.point(100).await.unwrap();
    assert_eq!(point.value, Value::Scaled(1000));
}

// ------------------------------------------------------ client and server

/// Dials by attaching the far end of a fresh pipe to the server.
struct ToServer(Server);

impl iec104_tokio::Connector for ToServer {
    type Stream = tokio::io::DuplexStream;

    async fn connect(&self, _conn: usize) -> std::io::Result<Self::Stream> {
        let (near, far) = tokio::io::duplex(64 * 1024);
        self.0
            .attach(far)
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(near)
    }
}

/// This crate's client against this crate's server, one call of each kind.
/// The expected values are the ones the server was configured with
/// ([`config`]) and the command the test operates, not values either side
/// computed.
#[tokio::test(start_paused = true)]
async fn the_client_against_the_server() {
    use iec104::asdu::FreezeMode;
    use iec104::gi::Scope;
    use iec104_tokio::client::{Client, ClientConfig, CommandOutcome};

    let (app, mut side) = app();
    let server = Server::spawn(config(), app).unwrap();
    let client_config = ClientConfig {
        interrogate_on_start: false,
        ..ClientConfig::new(1)
    };
    let client = Client::connect(ToServer(server.clone()), client_config)
        .await
        .unwrap();

    let image: Vec<_> = client
        .interrogate(Scope::Station)
        .await
        .unwrap()
        .iter()
        .flat_map(|asdu| asdu.objects.points())
        .map(|point| (point.ioa, point.value))
        .collect();
    assert_eq!(
        image,
        [
            (100, Value::Scaled(1000)),
            (4001, Value::Double(DoublePointState::On))
        ]
    );

    let totals: Vec<_> = client
        .counter_interrogate(ci::Request::General, FreezeMode::Read)
        .await
        .unwrap()
        .iter()
        .flat_map(|asdu| asdu.objects.points())
        .map(|point| (point.ioa, point.value))
        .collect();
    assert_eq!(
        totals,
        [(
            200,
            Value::Counter {
                reading: 5,
                sequence: 0,
                carry: false,
                adjusted: false
            }
        )]
    );

    let read = client.read(4001).await.unwrap();
    assert_eq!(
        read.objects.points()[0].value,
        Value::Double(DoublePointState::On)
    );

    client.sync_clock(station_time()).await.unwrap();
    assert!(side.synchronised.recv().await.is_some());

    let command = tokio::spawn({
        let client = client.clone();
        async move { client.command(Command::single(4001, true)).await }
    });
    let (operated, done) = side.operation().await;
    assert_eq!(operated, Command::single(4001, true));
    done.send(true).unwrap();
    assert_eq!(command.await.unwrap(), Ok(CommandOutcome::Terminated));
    client.shutdown().await;
    server.shutdown().await;
}

/// With one member the group is the whole logical link (104 cl.10.2): once
/// its connection is gone, what the controlling station had asked for is owed
/// to nobody. A station that sent thirty reads and a select and closed leaves
/// the next one only the twelve answers it had not confirmed (cl.10.6), not
/// the eighteen that waited, and no select to execute.
#[tokio::test(start_paused = true)]
async fn the_answers_and_select_of_a_closed_connection_are_dropped() {
    let mut config = config();
    config.command_mode = CommandMode::SelectAndExecute;
    let (server, _side, peer) = server(config).await;
    let mut first = Master::start(peer, false).await;
    first.send(&single_command(ACT, IOA_4001, 0x81));
    assert_eq!(first.next().await, single_command(ACTCON, IOA_4001, 0x81));
    first.ack();
    for _ in 0..30 {
        first.send(&read(IOA_4001));
    }
    for _ in 0..12 {
        assert_eq!(first.next().await, double_point(REQ, 0x02));
    }
    first.close().await;
    settle().await;

    let (near, peer) = Peer::pipe();
    server.attach(near).await.unwrap();
    let mut second = Master::start(peer, true).await;
    for _ in 0..12 {
        assert_eq!(second.next().await, double_point(REQ, 0x02));
    }
    assert!(second.silent_for(Duration::from_secs(1)).await);
    second.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(
        second.next().await,
        single_command(ACTCON_NEGATIVE, IOA_4001, 0x01)
    );
}

/// An execute still being operated when its link goes (104 cl.10.2) keeps its
/// object until the operation ends: the next controlling station's execute of
/// it is refused (TS 60870-5-604 5.4.19.40) rather than operated alongside,
/// and the old operation's termination is not sent to it. Once the operation
/// has ended, the object can be executed again.
#[tokio::test(start_paused = true)]
async fn an_execute_outliving_its_connection_is_held_until_it_ends() {
    let (server, mut side, peer) = server(config()).await;
    let mut first = Master::start(peer, true).await;
    first.send(&single_command(ACT, IOA_4001, 0x01));
    assert_eq!(first.next().await, single_command(ACTCON, IOA_4001, 0x01));
    let (_, done) = side.operation().await;
    first.close().await;
    settle().await;

    let (near, peer) = Peer::pipe();
    server.attach(near).await.unwrap();
    let mut second = Master::start(peer, true).await;
    second.send(&single_command(ACT, IOA_4001, 0x00));
    assert_eq!(
        second.next().await,
        single_command(ACTCON_NEGATIVE, IOA_4001, 0x00)
    );
    settle().await;
    assert!(side.operations.try_recv().is_err());

    done.send(true).unwrap();
    assert!(second.silent_for(Duration::from_secs(1)).await);

    second.send(&single_command(ACT, IOA_4001, 0x00));
    assert_eq!(second.next().await, single_command(ACTCON, IOA_4001, 0x00));
    let (_, done) = side.operation().await;
    done.send(false).unwrap();
    assert_eq!(
        second.next().await,
        single_command(ACTTERM_NEGATIVE, IOA_4001, 0x00)
    );
}

/// A point at an address the configured IOA width cannot carry would make
/// every interrogation drop the points of its type; the server refuses it at
/// spawn instead.
#[tokio::test]
async fn a_point_address_too_large_for_the_address_sizes_is_refused_at_spawn() {
    let point = config().point(0x0100_0000, PointConfig::new(Value::Scaled(0)));
    let (station, _side) = app();
    assert_eq!(
        Server::spawn(point, station).err(),
        Some(ServerError::Layout(LayoutError::Asdu(
            AsduError::IoaOutOfRange { ioa: 0x0100_0000 }
        )))
    );
    let command = config().command(0x0100_0000, Family::Single);
    let (station, _side) = app();
    assert_eq!(
        Server::spawn(command, station).err(),
        Some(ServerError::Layout(LayoutError::Asdu(
            AsduError::IoaOutOfRange { ioa: 0x0100_0000 }
        )))
    );
}

/// 5-101 cl.7.2.5 defines address `<0>` as irrelevant: a point there would go
/// out in interrogation answers but could never be read, so the server refuses
/// a point or a command at it at spawn.
#[tokio::test]
async fn a_point_or_command_at_address_0_is_refused_at_spawn() {
    let point = config().point(0, PointConfig::new(Value::Scaled(0)));
    let (station, _side) = app();
    assert_eq!(
        Server::spawn(point, station).err(),
        Some(ServerError::IrrelevantAddress)
    );
    let command = config().command(0, Family::Single);
    let (station, _side) = app();
    assert_eq!(
        Server::spawn(command, station).err(),
        Some(ServerError::IrrelevantAddress)
    );
}

/// A common address one octet cannot carry would leave every answer
/// unencodable, so interrogations would send no point at all.
#[tokio::test]
async fn a_common_address_too_large_for_the_address_sizes_is_refused_at_spawn() {
    let mut config = config();
    config.common_address = 300;
    config.sizes = iec104::asdu::AddressSizes::new(1, 3, true).expect("a defined profile");
    let (app, _side) = app();
    assert_eq!(
        Server::spawn(config, app).err(),
        Some(ServerError::Layout(LayoutError::Asdu(
            AsduError::CommonAddressOutOfRange {
                common_address: 300,
                max: 255
            }
        )))
    );
}
