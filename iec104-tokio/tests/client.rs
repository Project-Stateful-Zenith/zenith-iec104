//! The procedure-level client over in-memory pipes, on a paused clock.
//!
//! The far end is a scripted station: the test reads the ASDUs the client
//! sends and writes the answers. Every ASDU is written out from 5-101 clause
//! 7.2 and 7.3's layouts with the conventional address sizes: type
//! identification, variable structure qualifier, cause (bit 7 `P/N`),
//! originator, common address 1 (two octets), then the three-octet object
//! address and the elements, all little-endian.

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
use iec104::asdu::{
    Cause, Cp56Time2a, FreezeMode, Objects, Point, Qpa, Qpm, Qrp, Quality, Sva, TimeTag, Tsc, Value,
};
use iec104::ci;
use iec104::ct::{Command, CommandMode, Termination};
use iec104::gi::Scope;
use iec104::pm::{Parameter, ParameterValue};
use iec104_tokio::client::{
    Client, ClientConfig, ClientError, CommandOutcome, ImageEntry, ProcessImage, Update,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

// ---------------------------------------------------------------- frames

/// Cause octets of 5-101 table 14, with bit 7 (`P/N`) set for the negative
/// forms.
const ACT: u8 = 6;
const ACTCON: u8 = 7;
const ACTCON_NEGATIVE: u8 = 0x40 | 7;
const ACTTERM: u8 = 10;
const ACTTERM_NEGATIVE: u8 = 0x40 | 0x0A;
const DEACT: u8 = 8;
const DEACTCON: u8 = 9;
const DEACTCON_NEGATIVE: u8 = 0x40 | 9;
/// Clause 7.2.3's mirror of an unknown type identification: cause 44, `P/N = 1`.
const UNKNOWN_TYPE: u8 = 0x40 | 0x2C;
/// Clause 7.2.3's mirror of an unknown cause of transmission: cause 45,
/// `P/N = 1`.
const UNKNOWN_CAUSE: u8 = 0x40 | 0x2D;

/// Address 4001 is `0x000FA1`.
const IOA_4001: [u8; 3] = [0xA1, 0x0F, 0x00];

/// `C_SC_NA_1` `<45>` (5-101 cl.7.3.2.1) with the `SCO` octet `sco`
/// (cl.7.2.6.15: bit 1 `SCS`, bits 3–7 `QU`, bit 8 `S/E`).
fn single_command(cause: u8, sco: u8) -> Vec<u8> {
    let mut asdu = vec![45, 0x01, cause, 0x00, 0x01, 0x00];
    asdu.extend(IOA_4001);
    asdu.push(sco);
    asdu
}

/// `C_SE_NB_1` `<49>` (5-101 cl.7.3.2.5): `SVA` 1000 (`0x03E8`), `QOS` 0.
fn set_point(cause: u8) -> Vec<u8> {
    let mut asdu = vec![49, 0x01, cause, 0x00, 0x01, 0x00];
    asdu.extend(IOA_4001);
    asdu.extend([0xE8, 0x03, 0x00]);
    asdu
}

/// `C_IC_NA_1` `<100>` (5-101 cl.7.3.4.1), address 0, `QOI` `qoi` (20 is the
/// station, 21 to 36 the groups, cl.7.2.6.22).
fn interrogation(cause: u8, qoi: u8) -> Vec<u8> {
    vec![100, 0x01, cause, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, qoi]
}

/// `M_ME_NB_1` `<11>` (5-101 cl.7.3.1.11) at address 100 with `SVA` 1000 and
/// `QDS` 0, sent with `cause`.
fn measurand(cause: u8) -> Vec<u8> {
    vec![
        11, 0x01, cause, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0xE8, 0x03, 0x00,
    ]
}

/// `C_CI_NA_1` `<101>` (5-101 cl.7.3.4.2), address 0, `QCC` `qcc`
/// (cl.7.2.6.23: `RQT` in bits 1–6, `FRZ` in bits 7–8).
fn counter_interrogation(cause: u8, qcc: u8) -> Vec<u8> {
    vec![101, 0x01, cause, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, qcc]
}

/// `M_IT_NA_1` `<15>` (5-101 cl.7.3.1.15) at address 200: `BCR` reading 5,
/// sequence number 0, cause 37 (requested by general counter request).
const TOTAL: [u8; 14] = [
    15, 0x01, 37, 0x00, 0x01, 0x00, 0xC8, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
];

/// `C_RD_NA_1` `<102>` (5-101 cl.7.3.4.3): the address alone, cause 5.
const READ_4001: [u8; 9] = [102, 0x01, 5, 0x00, 0x01, 0x00, 0xA1, 0x0F, 0x00];

/// `M_SP_NA_1` `<1>` (5-101 cl.7.3.1.1) at address 4001, cause 5 (request),
/// `SIQ` ON (bit 1).
const READ_ANSWER: [u8; 10] = [1, 0x01, 5, 0x00, 0x01, 0x00, 0xA1, 0x0F, 0x00, 0x01];

/// 2026-09-28 12:34:56.789, a Monday, as `CP56Time2a` (5-101 cl.7.2.6.18):
/// milliseconds 56 789 (`0xDDD5`), minute 34, hour 12, day 28 with day of
/// week 1 in bits 6–8, month 9, year 26.
const TIME: [u8; 7] = [0xD5, 0xDD, 34, 12, 0x20 | 0x1C, 9, 26];

/// `C_CS_NA_1` `<103>` (5-101 cl.7.3.4.4), address 0, carrying [`TIME`].
fn clock_sync(cause: u8) -> Vec<u8> {
    let mut asdu = vec![103, 0x01, cause, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    asdu.extend(TIME);
    asdu
}

// --------------------------------------------------------------- station

/// The scripted far end. A background task keeps the link alive (it answers
/// TESTFR act and acknowledges every I-frame) and hands the ASDUs over.
struct Station {
    received: mpsc::UnboundedReceiver<Vec<u8>>,
    to_send: mpsc::UnboundedSender<Option<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl Station {
    fn run(peer: Peer) -> Self {
        Self::run_with(peer, true)
    }

    /// A station that acknowledges nothing it receives when `ack` is false,
    /// so the client's t1 runs out (clause 5.2).
    fn run_with(mut peer: Peer, ack: bool) -> Self {
        let (received_tx, received) = mpsc::unbounded_channel();
        let (to_send, mut outgoing) = mpsc::unbounded_channel::<Option<Vec<u8>>>();
        let task = tokio::spawn(async move {
            let (mut ns, mut nr) = (0u16, 0u16);
            loop {
                tokio::select! {
                    frame = peer.frame() => {
                        let Some(frame) = frame else { return };
                        if frame[2] & 0x01 == 0 {
                            nr += 1;
                            if ack {
                                peer.send(&s_frame(nr)).await;
                            }
                            let _ = received_tx.send(frame[6..].to_vec());
                        } else if frame == TESTFR_ACT {
                            peer.send(&TESTFR_CON).await;
                        }
                    }
                    asdu = outgoing.recv() => match asdu {
                        Some(Some(asdu)) => {
                            peer.send(&i_frame(ns, nr, &asdu)).await;
                            ns += 1;
                        }
                        // Dropping the pipe is the peer's close.
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

    /// The next ASDU the client sent. Fails, rather than hangs, when none
    /// comes within an hour of the paused clock.
    async fn next(&mut self) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(3600), self.received.recv())
            .await
            .expect("the client sent nothing")
            .expect("the station is running")
    }

    /// Whether the client sends anything within `window`.
    async fn silent_for(&mut self, window: Duration) -> bool {
        tokio::time::timeout(window, self.received.recv())
            .await
            .is_err()
    }

    fn send(&self, asdu: &[u8]) {
        self.to_send.send(Some(asdu.to_vec())).unwrap();
    }

    /// Closes the connection.
    async fn close(self) {
        let _ = self.to_send.send(None);
        let _ = self.task.await;
    }
}

fn config() -> ClientConfig {
    ClientConfig {
        interrogate_on_start: false,
        ..ClientConfig::new(1)
    }
}

/// A client whose connection is started, the station's end of it, and the
/// test's end of the client's dials.
async fn started(config: ClientConfig) -> (Client, Station, mpsc::UnboundedReceiver<Dial>) {
    let (connector, mut dials) = Dials::new();
    let client = Client::spawn(connector, config).unwrap();
    let station = accept(&mut dials).await;
    client.wait_started().await.unwrap();
    (client, station, dials)
}

/// Answers the next dial and its STARTDT act (clause 5.3).
async fn accept(dials: &mut mpsc::UnboundedReceiver<Dial>) -> Station {
    let mut peer = next_dial(dials).await.accept();
    assert_eq!(peer.frame().await.unwrap(), STARTDT_ACT);
    peer.send(&STARTDT_CON).await;
    Station::run(peer)
}

fn spawn_command(
    client: &Client,
    command: Command,
) -> JoinHandle<Result<CommandOutcome, ClientError>> {
    let client = client.clone();
    tokio::spawn(async move { client.command(command).await })
}

fn spawn_interrogation(
    client: &Client,
    scope: Scope,
) -> JoinHandle<Result<Vec<iec104::asdu::Asdu>, ClientError>> {
    let client = client.clone();
    tokio::spawn(async move { client.interrogate(scope).await })
}

// ------------------------------------------------------------------ tests

/// An update the station sends after `subscribe` returned reaches the new
/// subscriber: `subscribe` returns once the client's task holds the
/// subscription, not when the request is merely queued. Repeated, on the
/// multi-threaded runtime, because the race this rules out depends on
/// which of the request and the station's frame the task takes first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_update_after_subscribe_returns_is_delivered() {
    let (client, station, _dials) = started(config()).await;
    for round in 0..200 {
        let mut updates = client.subscribe().await.unwrap();
        station.send(&measurand(3));
        let update = tokio::time::timeout(Duration::from_secs(10), updates.recv())
            .await
            .unwrap_or_else(|_| panic!("round {round}: the event never reached the subscriber"));
        assert!(
            matches!(update, Some(Update::Data(_))),
            "round {round}: {update:?}"
        );
    }
    station.close().await;
}

/// `spawn_subscribed` sees everything from the first dial: here the
/// connection starts and the interrogation on start (104 cl.7.5) is
/// answered before anyone reads an update, and none of it is missed.
#[tokio::test(start_paused = true)]
async fn a_client_spawned_subscribed_misses_nothing_from_the_start() {
    let (connector, mut dials) = Dials::new();
    let config = ClientConfig {
        interrogate_on_start: true,
        ..ClientConfig::new(1)
    };
    let (client, mut updates) = Client::spawn_subscribed(connector, config).unwrap();
    let mut station = accept(&mut dials).await;
    assert_eq!(station.next().await, interrogation(ACT, 20));
    station.send(&interrogation(ACTCON, 20));
    station.send(&measurand(20));
    station.send(&interrogation(ACTTERM, 20));
    client.wait_started().await.unwrap();

    assert_eq!(updates.recv().await, Some(Update::Started));
    let cause = tokio::time::timeout(Duration::from_secs(3600), async {
        loop {
            if let Some(Update::Data(asdu)) = updates.recv().await {
                return asdu.header.cause;
            }
        }
    })
    .await
    .expect("the interrogation's data");
    assert_eq!(cause, Cause::InterrogatedByStation);
    station.close().await;
}

/// Nothing is sent before data transfer runs (clause 5.3).
#[tokio::test(start_paused = true)]
async fn a_call_before_the_start_is_not_started() {
    let (connector, _dials) = Dials::new();
    let client = Client::spawn(connector, config()).unwrap();
    assert_eq!(
        client.command(Command::single(4001, true)).await,
        Err(ClientError::NotStarted)
    );
}

/// 104 cl.7.5 / 5-101 figure 29: ACT, ACTCON, the objects with cause 20,
/// ACTTERM. The call returns the objects, decoded, and the subscribers see
/// them too.
#[tokio::test(start_paused = true)]
async fn a_station_interrogation_returns_its_objects() {
    let (client, mut station, _dials) = started(config()).await;
    let mut updates = client.subscribe().await.unwrap();
    let call = spawn_interrogation(&client, Scope::Station);

    assert_eq!(station.next().await, interrogation(ACT, 20));
    station.send(&interrogation(ACTCON, 20));
    station.send(&measurand(20));
    station.send(&interrogation(ACTTERM, 20));

    let image = call.await.unwrap().unwrap();
    assert_eq!(image.len(), 1);
    assert_eq!(image[0].header.cause, Cause::InterrogatedByStation);
    let Objects::MMeNb1(objects) = &image[0].objects else {
        panic!("not M_ME_NB_1: {:?}", image[0].objects.type_id());
    };
    assert_eq!((objects[0].ioa, objects[0].value.sva.value), (100, 1000));

    match updates.recv().await.unwrap() {
        Update::Data(asdu) => assert_eq!(asdu, image[0]),
        other => panic!("expected the data, got {other:?}"),
    }
}

/// TS 60870-5-604 5.4.13.10: after the connection is started the controlling
/// station "begins the General Interrogation procedure".
#[tokio::test(start_paused = true)]
async fn a_new_started_connection_is_interrogated() {
    let config = ClientConfig {
        interrogate_on_start: true,
        ..config()
    };
    let (_client, mut station, _dials) = started(config).await;
    assert_eq!(station.next().await, interrogation(ACT, 20));
}

/// 5-101 cl.7.4.5 locks the identical interrogation: a second call for the
/// same scope sends nothing and gets the first one's result.
#[tokio::test(start_paused = true)]
async fn a_second_identical_interrogation_joins_the_first() {
    let (client, mut station, _dials) = started(config()).await;
    let first = spawn_interrogation(&client, Scope::Group(1));
    assert_eq!(station.next().await, interrogation(ACT, 21));
    let second = spawn_interrogation(&client, Scope::Group(1));
    assert!(station.silent_for(Duration::from_secs(1)).await);

    station.send(&interrogation(ACTCON, 21));
    station.send(&interrogation(ACTTERM, 21));
    assert_eq!(first.await.unwrap(), Ok(Vec::new()));
    assert_eq!(second.await.unwrap(), Ok(Vec::new()));
}

/// An interrogation that is not confirmed within the confirmation time-out
/// ends, and the scope can be asked again (its lock is lifted).
#[tokio::test(start_paused = true)]
async fn an_unanswered_interrogation_times_out_and_can_be_repeated() {
    let (client, mut station, _dials) = started(config()).await;
    let started_at = Instant::now();
    let call = spawn_interrogation(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(ACT, 20));
    assert_eq!(call.await.unwrap(), Err(ClientError::Timeout));
    assert_eq!(started_at.elapsed(), Duration::from_secs(10));

    let _again = spawn_interrogation(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(ACT, 20));
}

/// 104 cl.7.7 / 5-101 figure 64: a direct command, ACT, ACTCON, ACTTERM.
/// `QU` short pulse is `<1>` in bits 3–7 (cl.7.2.6.26).
#[tokio::test(start_paused = true)]
async fn a_direct_command_ends_at_its_termination() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_command(
        &client,
        Command::single(4001, true).with_qualifier(iec104::asdu::CommandQualifier::ShortPulse),
    );
    assert_eq!(station.next().await, single_command(ACT, 0x05));
    station.send(&single_command(ACTCON, 0x05));
    station.send(&single_command(ACTTERM, 0x05));
    assert_eq!(call.await.unwrap(), Ok(CommandOutcome::Terminated));
}

/// 5-101 cl.7.4.7: *"`C_SE` ACTTERM may be used optionally"*. A station that
/// does not terminate set-points ends the command at its confirmation.
#[tokio::test(start_paused = true)]
async fn an_unterminated_set_point_ends_at_its_confirmation() {
    let config = ClientConfig {
        termination: Termination::SetPointsNotTerminated,
        ..config()
    };
    let (client, mut station, _dials) = started(config).await;
    let call = spawn_command(&client, Command::set_point_scaled(4001, 1000));
    assert_eq!(station.next().await, set_point(ACT));
    station.send(&set_point(ACTCON));
    assert_eq!(call.await.unwrap(), Ok(CommandOutcome::Confirmed));
}

/// TS 60870-5-604 5.4.19.1: select (`S/E = 1`), its confirmation, then the
/// execute (`S/E = 0`), its confirmation and termination.
#[tokio::test(start_paused = true)]
async fn select_and_execute_selects_first() {
    let config = ClientConfig {
        command_mode: CommandMode::SelectAndExecute,
        ..config()
    };
    let (client, mut station, _dials) = started(config).await;
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x81));
    station.send(&single_command(ACTCON, 0x81));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.send(&single_command(ACTCON, 0x01));
    station.send(&single_command(ACTTERM, 0x01));
    assert_eq!(call.await.unwrap(), Ok(CommandOutcome::Terminated));
}

/// A refused select: the execute is never sent.
#[tokio::test(start_paused = true)]
async fn a_refused_select_sends_no_execute() {
    let config = ClientConfig {
        command_mode: CommandMode::SelectAndExecute,
        ..config()
    };
    let (client, mut station, _dials) = started(config).await;
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x81));
    station.send(&single_command(ACTCON_NEGATIVE, 0x81));
    assert_eq!(call.await.unwrap(), Err(ClientError::Rejected));
    assert!(station.silent_for(Duration::from_secs(60)).await);
}

/// TS 60870-5-604 5.4.19.40: a positive confirmation, then a negative
/// termination.
#[tokio::test(start_paused = true)]
async fn a_negative_termination_is_a_failure() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.send(&single_command(ACTCON, 0x01));
    station.send(&single_command(ACTTERM_NEGATIVE, 0x01));
    assert_eq!(call.await.unwrap(), Err(ClientError::Failed));
}

/// 5-101 cl.7.2.3: a station without the type mirrors it with cause 44.
#[tokio::test(start_paused = true)]
async fn a_mirrored_command_is_refused_with_its_cause() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.send(&single_command(UNKNOWN_TYPE, 0x01));
    assert_eq!(
        call.await.unwrap(),
        Err(ClientError::Refused {
            cause: Cause::UnknownTypeId
        })
    );
}

/// An execute without an answer is not sent again, and the caller is told
/// the outcome is unknown, after the confirmation time-out.
#[tokio::test(start_paused = true)]
async fn an_unanswered_execute_is_not_resent() {
    let (client, mut station, _dials) = started(config()).await;
    let sent = Instant::now();
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
    assert_eq!(sent.elapsed(), Duration::from_secs(10));
    assert!(station.silent_for(Duration::from_secs(120)).await);
}

/// A confirmed command whose termination never comes: the termination
/// time-out runs from the confirmation.
#[tokio::test(start_paused = true)]
async fn a_missing_termination_leaves_the_outcome_unknown() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.send(&single_command(ACTCON, 0x01));
    let confirmed = Instant::now();
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
    assert!(confirmed.elapsed() >= Duration::from_secs(30));
    assert!(confirmed.elapsed() < Duration::from_secs(31));
}

/// A connection lost after the execute: outcome unknown, and the command is
/// not sent on the next connection.
#[tokio::test(start_paused = true)]
async fn a_command_cut_off_by_a_lost_connection_is_not_resent() {
    let (client, mut station, mut dials) = started(config()).await;
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));

    let mut station = accept(&mut dials).await;
    client.wait_started().await.unwrap();
    assert!(station.silent_for(Duration::from_secs(120)).await);
}

/// A connection lost after the select only: nothing operated.
#[tokio::test(start_paused = true)]
async fn a_select_cut_off_by_a_lost_connection_is_a_lost_connection() {
    let config = ClientConfig {
        command_mode: CommandMode::SelectAndExecute,
        ..config()
    };
    let (client, mut station, _dials) = started(config).await;
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x81));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::ConnectionLost));
}

/// A second command for an object whose command is outstanding is refused
/// without sending.
#[tokio::test(start_paused = true)]
async fn a_second_command_for_the_same_object_is_busy() {
    let (client, mut station, _dials) = started(config()).await;
    let _first = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    assert_eq!(
        client.command(Command::single(4001, false)).await,
        Err(ClientError::Busy)
    );
}

/// TS 60870-5-604 Table 19: *"Command function during a running general
/// interrogation is processed and executed without waiting for the GI to
/// finish."*
#[tokio::test(start_paused = true)]
async fn a_command_runs_during_an_interrogation() {
    let (client, mut station, _dials) = started(config()).await;
    let gi = spawn_interrogation(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(ACT, 20));
    station.send(&interrogation(ACTCON, 20));

    let command = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.send(&single_command(ACTCON, 0x01));
    station.send(&single_command(ACTTERM, 0x01));
    assert_eq!(command.await.unwrap(), Ok(CommandOutcome::Terminated));
    assert!(!gi.is_finished());

    station.send(&interrogation(ACTTERM, 20));
    assert_eq!(gi.await.unwrap(), Ok(Vec::new()));
}

/// A time-tagged command set with no clock and no time tag on the command.
#[tokio::test(start_paused = true)]
async fn a_tagged_command_needs_a_clock() {
    let config = ClientConfig {
        command_set: iec104::ct::CommandSet::Tagged,
        ..config()
    };
    let (client, _station, _dials) = started(config).await;
    assert_eq!(
        client.command(Command::single(4001, true)).await,
        Err(ClientError::NoClock)
    );
}

/// 104 cl.7.8, mode C: a general request (`RQT` 5) with `FRZ` 0 collects:
/// ACTCON, the totals with cause 37, ACTTERM.
#[tokio::test(start_paused = true)]
async fn a_counter_interrogation_returns_the_totals() {
    let (client, mut station, _dials) = started(config()).await;
    let caller = client.clone();
    let call = tokio::spawn(async move {
        caller
            .counter_interrogate(ci::Request::General, FreezeMode::Read)
            .await
    });
    assert_eq!(station.next().await, counter_interrogation(ACT, 0x05));
    station.send(&counter_interrogation(ACTCON, 0x05));
    station.send(&TOTAL);
    station.send(&counter_interrogation(ACTTERM, 0x05));
    let totals = call.await.unwrap().unwrap();
    assert_eq!(totals.len(), 1);
    assert!(matches!(totals[0].objects, Objects::MItNa1(_)));
}

/// 5-101 figure 95: a freeze (`FRZ` 1 in bits 7–8, `0x40`) is confirmed and
/// not terminated.
#[tokio::test(start_paused = true)]
async fn a_counter_freeze_ends_at_its_confirmation() {
    let (client, mut station, _dials) = started(config()).await;
    let caller = client.clone();
    let call = tokio::spawn(async move {
        caller
            .counter_interrogate(ci::Request::General, FreezeMode::FreezeWithoutReset)
            .await
    });
    assert_eq!(station.next().await, counter_interrogation(ACT, 0x45));
    station.send(&counter_interrogation(ACTCON, 0x45));
    assert_eq!(call.await.unwrap(), Ok(Vec::new()));
}

/// 104 cl.7.2: the read is answered by the object with cause 5.
#[tokio::test(start_paused = true)]
async fn a_read_returns_the_object() {
    let (client, mut station, _dials) = started(config()).await;
    let caller = client.clone();
    let call = tokio::spawn(async move { caller.read(4001).await });
    assert_eq!(station.next().await, READ_4001);
    station.send(&READ_ANSWER);
    let asdu = call.await.unwrap().unwrap();
    let Objects::MSpNa1(objects) = &asdu.objects else {
        panic!("not M_SP_NA_1: {:?}", asdu.objects.type_id());
    };
    assert_eq!(objects[0].ioa, 4001);
    assert!(objects[0].value.siq.spi);
}

/// 104 cl.7.6: the clock synchronisation is confirmed with the same time.
#[tokio::test(start_paused = true)]
async fn a_clock_synchronisation_ends_at_its_confirmation() {
    let (client, mut station, _dials) = started(config()).await;
    let time = Cp56Time2a::parse(&TIME).unwrap();
    let caller = client.clone();
    let call = tokio::spawn(async move { caller.sync_clock(time).await });
    assert_eq!(station.next().await, clock_sync(ACT));
    station.send(&clock_sync(ACTCON));
    assert_eq!(call.await.unwrap(), Ok(()));
}

/// Spontaneous data (cause 3) reaches the subscribers, and so does the link
/// going down.
#[tokio::test(start_paused = true)]
async fn subscribers_see_spontaneous_data_and_the_link() {
    let (client, station, _dials) = started(config()).await;
    let mut updates = client.subscribe().await.unwrap();
    station.send(&MEASURAND);
    match updates.recv().await.unwrap() {
        Update::Data(asdu) => assert_eq!(asdu.header.cause, Cause::Spontaneous),
        other => panic!("expected the data, got {other:?}"),
    }
    station.close().await;
    assert_eq!(updates.recv().await.unwrap(), Update::Stopped);
}

/// A subscriber that stops reading holds at most `update_buffer` updates:
/// the client drops the rest for it without waiting, and once there is room
/// tells it how many it missed. A second subscriber that reads gets all.
#[tokio::test(start_paused = true)]
async fn a_subscriber_that_does_not_read_is_bounded_and_told_it_lagged() {
    let (client, station, _dials) = started(ClientConfig {
        update_buffer: 2,
        ..config()
    })
    .await;
    let mut idle = client.subscribe().await.unwrap();
    let mut reader = client.subscribe().await.unwrap();
    for _ in 0..5 {
        station.send(&MEASURAND);
        assert!(matches!(next_update(&mut reader).await, Update::Data(_)));
    }
    assert!(matches!(idle.try_recv(), Ok(Update::Data(_))));
    assert!(matches!(idle.try_recv(), Ok(Update::Data(_))));
    assert!(idle.try_recv().is_err());

    station.send(&MEASURAND);
    assert!(matches!(next_update(&mut reader).await, Update::Data(_)));
    assert_eq!(idle.try_recv(), Ok(Update::Lagged(3)));
    assert!(matches!(idle.try_recv(), Ok(Update::Data(_))));
    station.close().await;
}

/// The smallest buffer still recovers: after a lag, a subscriber that reads
/// steadily gets data again, not only lag reports.
#[tokio::test(start_paused = true)]
async fn a_lagged_subscriber_recovers_with_the_smallest_buffer() {
    let (client, station, _dials) = started(ClientConfig {
        update_buffer: 1,
        ..config()
    })
    .await;
    let mut idle = client.subscribe().await.unwrap();
    let mut reader = client.subscribe().await.unwrap();
    for _ in 0..5 {
        station.send(&MEASURAND);
        assert!(matches!(next_update(&mut reader).await, Update::Data(_)));
    }
    while idle.try_recv().is_ok() {}
    let mut seen = Vec::new();
    for _ in 0..3 {
        station.send(&MEASURAND);
        assert!(matches!(next_update(&mut reader).await, Update::Data(_)));
        while let Ok(update) = idle.try_recv() {
            seen.push(update);
        }
    }
    assert!(
        seen.iter().any(|u| matches!(u, Update::Data(_))),
        "only lag reports: {seen:?}"
    );
    station.close().await;
}

/// 5-101 cl.7.2.3's mirror answers an interrogation and a clock
/// synchronisation too: cause 44 with `P/N = 1`.
#[tokio::test(start_paused = true)]
async fn a_mirrored_interrogation_or_clock_synchronisation_is_refused() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_interrogation(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(ACT, 20));
    station.send(&interrogation(UNKNOWN_TYPE, 20));
    assert_eq!(
        call.await.unwrap(),
        Err(ClientError::Refused {
            cause: Cause::UnknownTypeId
        })
    );

    let time = Cp56Time2a::parse(&TIME).unwrap();
    let caller = client.clone();
    let call = tokio::spawn(async move { caller.sync_clock(time).await });
    assert_eq!(station.next().await, clock_sync(ACT));
    station.send(&clock_sync(UNKNOWN_TYPE));
    assert_eq!(
        call.await.unwrap(),
        Err(ClientError::Refused {
            cause: Cause::UnknownTypeId
        })
    );
}

// ------------------------------------------- select, execute and cancel

fn select_and_execute() -> ClientConfig {
    ClientConfig {
        command_mode: CommandMode::SelectAndExecute,
        ..config()
    }
}

fn spawn_select(client: &Client, command: Command) -> JoinHandle<Result<(), ClientError>> {
    let client = client.clone();
    tokio::spawn(async move { client.select(command).await })
}

fn spawn_execute(
    client: &Client,
    command: Command,
) -> JoinHandle<Result<CommandOutcome, ClientError>> {
    let client = client.clone();
    tokio::spawn(async move { client.execute(command).await })
}

fn spawn_cancel(client: &Client, command: Command) -> JoinHandle<Result<(), ClientError>> {
    let client = client.clone();
    tokio::spawn(async move { client.cancel(command).await })
}

/// A select confirmed by the station, as TS 60870-5-604 5.4.19.1 has it:
/// `S/E = 1` in bit 8 of the `SCO` (5-101 cl.7.2.6.15), `SCS` ON in bit 1,
/// so `0x81`, mirrored with cause 7.
async fn selected(client: &Client, station: &mut Station) {
    let call = spawn_select(client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x81));
    station.send(&single_command(ACTCON, 0x81));
    assert_eq!(call.await.unwrap(), Ok(()));
}

/// TS 60870-5-604 5.4.19.1 with the operator between the steps: the select
/// returns at its confirmation and nothing more is sent until the execute
/// (`S/E = 0`, `0x01`), which ends at its termination.
#[tokio::test(start_paused = true)]
async fn a_manual_select_waits_for_the_execute() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    selected(&client, &mut station).await;
    assert!(station.silent_for(Duration::from_secs(60)).await);

    let call = spawn_execute(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.send(&single_command(ACTCON, 0x01));
    station.send(&single_command(ACTTERM, 0x01));
    assert_eq!(call.await.unwrap(), Ok(CommandOutcome::Terminated));
}

/// TS 60870-5-604 5.4.19.10: *"The Controlling station sends the same Command
/// message with COT=8, `C_SC/DC/SE/RC_DEACT`, and S/E=1 (SELECT)"*, the station
/// confirms with cause 9 (5-101 figure 64), and the select is gone: an
/// execute is refused without sending.
#[tokio::test(start_paused = true)]
async fn a_cancel_deactivates_the_select() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    selected(&client, &mut station).await;

    let call = spawn_cancel(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(DEACT, 0x81));
    station.send(&single_command(DEACTCON, 0x81));
    assert_eq!(call.await.unwrap(), Ok(()));

    assert_eq!(
        client.execute(Command::single(4001, true)).await,
        Err(ClientError::Command(
            iec104::ct::CtError::ExecuteWithoutSelect { ioa: 4001 }
        ))
    );
    assert!(station.silent_for(Duration::from_secs(60)).await);
}

/// 5-101 cl.7.2.3: *"The P/N-bit indicates the positive or negative
/// confirmation of activation requested by the primary application
/// function."* The same bit on the `DEACTCON` (cause 9, 5-101 figure 64)
/// refuses the deactivation: a negative `DEACTCON` is a refused cancel.
#[tokio::test(start_paused = true)]
async fn a_negative_deactivation_confirmation_is_rejected() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    selected(&client, &mut station).await;
    let call = spawn_cancel(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(DEACT, 0x81));
    station.send(&single_command(DEACTCON_NEGATIVE, 0x81));
    assert_eq!(call.await.unwrap(), Err(ClientError::Rejected));
}

/// 5-101 cl.7.2.3: a station without the deactivation mirrors it with cause
/// 45 (unknown cause of transmission).
#[tokio::test(start_paused = true)]
async fn a_mirrored_deactivation_is_refused_with_its_cause() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    selected(&client, &mut station).await;
    let call = spawn_cancel(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(DEACT, 0x81));
    station.send(&single_command(UNKNOWN_CAUSE, 0x81));
    assert_eq!(
        call.await.unwrap(),
        Err(ClientError::Refused {
            cause: Cause::UnknownCause
        })
    );
}

/// TS 60870-5-604 5.4.19.30: the station refuses the select with a negative
/// `ACTCON`; there is no select to execute afterwards.
#[tokio::test(start_paused = true)]
async fn a_refused_manual_select_leaves_nothing_to_execute() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    let call = spawn_select(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x81));
    station.send(&single_command(ACTCON_NEGATIVE, 0x81));
    assert_eq!(call.await.unwrap(), Err(ClientError::Rejected));
    assert!(matches!(
        client.execute(Command::single(4001, true)).await,
        Err(ClientError::Command(_))
    ));
    assert!(station.silent_for(Duration::from_secs(60)).await);
}

/// TS 60870-5-604 Table 19: the execute must carry *"exactly the same
/// information as the SELECT message"*. An execute of OFF after a select of
/// ON is refused without sending, and the select stays for the right one.
#[tokio::test(start_paused = true)]
async fn an_execute_other_than_the_select_is_not_sent() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    selected(&client, &mut station).await;
    assert_eq!(
        client.execute(Command::single(4001, false)).await,
        Err(ClientError::SelectMismatch)
    );
    assert!(station.silent_for(Duration::from_secs(1)).await);

    let call = spawn_execute(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.send(&single_command(ACTCON, 0x01));
    station.send(&single_command(ACTTERM, 0x01));
    assert_eq!(call.await.unwrap(), Ok(CommandOutcome::Terminated));
}

/// An unanswered select operated nothing: it times out after the
/// confirmation time-out (10 s by default).
#[tokio::test(start_paused = true)]
async fn an_unanswered_manual_select_times_out() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    let sent = Instant::now();
    let call = spawn_select(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x81));
    assert_eq!(call.await.unwrap(), Err(ClientError::Timeout));
    assert_eq!(sent.elapsed(), Duration::from_secs(10));
}

/// An unanswered cancel times out, and the select is dropped on this side:
/// the execute is refused rather than sent after a deactivation that may
/// have taken effect.
#[tokio::test(start_paused = true)]
async fn an_unanswered_cancel_times_out_and_drops_the_select() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    selected(&client, &mut station).await;
    let call = spawn_cancel(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(DEACT, 0x81));
    assert_eq!(call.await.unwrap(), Err(ClientError::Timeout));
    assert!(matches!(
        client.execute(Command::single(4001, true)).await,
        Err(ClientError::Command(_))
    ));
    assert!(station.silent_for(Duration::from_secs(60)).await);
}

/// The execute of a manual select that is never answered: outcome unknown,
/// and it is not sent again.
#[tokio::test(start_paused = true)]
async fn an_unanswered_manual_execute_is_not_resent() {
    let (client, mut station, _dials) = started(select_and_execute()).await;
    selected(&client, &mut station).await;
    let call = spawn_execute(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
    assert!(station.silent_for(Duration::from_secs(120)).await);
}

/// A lost connection: a select in flight ends as a lost connection, a
/// cancel likewise, an execute in flight with an unknown outcome.
#[tokio::test(start_paused = true)]
async fn a_lost_connection_ends_each_step_by_what_it_sent() {
    let (client, mut station, mut dials) = started(select_and_execute()).await;
    let call = spawn_select(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x81));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::ConnectionLost));

    let mut station = accept(&mut dials).await;
    client.wait_started().await.unwrap();
    selected(&client, &mut station).await;
    let call = spawn_cancel(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(DEACT, 0x81));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::ConnectionLost));

    let mut station = accept(&mut dials).await;
    client.wait_started().await.unwrap();
    selected(&client, &mut station).await;
    let call = spawn_execute(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
}

/// A confirmed select does not survive the connection (the procedure is reset
/// on the loss): the execute on the next connection is refused unsent.
#[tokio::test(start_paused = true)]
async fn a_select_does_not_survive_a_lost_connection() {
    let (client, mut station, mut dials) = started(select_and_execute()).await;
    selected(&client, &mut station).await;
    station.close().await;
    let mut station = accept(&mut dials).await;
    client.wait_started().await.unwrap();
    assert!(matches!(
        client.execute(Command::single(4001, true)).await,
        Err(ClientError::Command(_))
    ));
    assert!(station.silent_for(Duration::from_secs(60)).await);
}

/// 5-101 cl.7.4.7: *"The select procedure is only used in case of a select
/// and execute function."* A direct-execute station has no select.
#[tokio::test(start_paused = true)]
async fn a_direct_station_has_no_manual_select() {
    let (client, mut station, _dials) = started(config()).await;
    assert_eq!(
        client.select(Command::single(4001, true)).await,
        Err(ClientError::Command(
            iec104::ct::CtError::SelectNotAllowed {
                mode: CommandMode::Direct
            }
        ))
    );
    assert!(station.silent_for(Duration::from_secs(1)).await);
}

// ------------------------------------------------ stopping an interrogation

fn spawn_stop(client: &Client, scope: Scope) -> JoinHandle<Result<(), ClientError>> {
    let client = client.clone();
    tokio::spawn(async move { client.stop_interrogation(scope).await })
}

/// A station interrogation confirmed and one object into its data.
async fn interrogating(
    client: &Client,
    station: &mut Station,
) -> JoinHandle<Result<Vec<iec104::asdu::Asdu>, ClientError>> {
    let call = spawn_interrogation(client, Scope::Station);
    assert_eq!(station.next().await, interrogation(ACT, 20));
    station.send(&interrogation(ACTCON, 20));
    station.send(&measurand(20));
    call
}

/// TS 60870-5-604 5.4.17.50: *"The Controlling station sends an
/// Interrogation Command with COT = 8, `C_IC_DEACT`"*, *"The Controlled station
/// sends an Interrogation Command with COT = 9, `C_IC_DEACTCON`"*, and *"No
/// Interrogation Command with COT = 10 (ACTTERM)"* follows: the stop returns,
/// and the interrogation ends as stopped.
#[tokio::test(start_paused = true)]
async fn a_stop_deactivates_the_running_interrogation() {
    let (client, mut station, _dials) = started(config()).await;
    let gi = interrogating(&client, &mut station).await;
    let stop = spawn_stop(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(DEACT, 20));
    station.send(&interrogation(DEACTCON, 20));
    assert_eq!(stop.await.unwrap(), Ok(()));
    assert_eq!(gi.await.unwrap(), Err(ClientError::Deactivated));
}

/// A group interrogation is stopped with its own `QOI` (21 for group 1,
/// 5-101 cl.7.2.6.22).
#[tokio::test(start_paused = true)]
async fn a_group_interrogation_is_stopped_by_its_qoi() {
    let (client, mut station, _dials) = started(config()).await;
    let gi = spawn_interrogation(&client, Scope::Group(1));
    assert_eq!(station.next().await, interrogation(ACT, 21));
    station.send(&interrogation(ACTCON, 21));
    let stop = spawn_stop(&client, Scope::Group(1));
    assert_eq!(station.next().await, interrogation(DEACT, 21));
    station.send(&interrogation(DEACTCON, 21));
    assert_eq!(stop.await.unwrap(), Ok(()));
    assert_eq!(gi.await.unwrap(), Err(ClientError::Deactivated));
}

/// 5-101 cl.7.2.3: a negative `DEACTCON` refuses the deactivation; the
/// station has nothing of the scope running, so the interrogation ends too.
#[tokio::test(start_paused = true)]
async fn a_negative_stop_confirmation_is_rejected() {
    let (client, mut station, _dials) = started(config()).await;
    let gi = interrogating(&client, &mut station).await;
    let stop = spawn_stop(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(DEACT, 20));
    station.send(&interrogation(DEACTCON_NEGATIVE, 20));
    assert_eq!(stop.await.unwrap(), Err(ClientError::Rejected));
    assert_eq!(gi.await.unwrap(), Err(ClientError::Deactivated));
}

/// 5-101 cl.7.2.3: a station without the deactivation mirrors it with cause
/// 45; the interrogation goes on to its termination.
#[tokio::test(start_paused = true)]
async fn a_mirrored_stop_is_refused_and_the_interrogation_goes_on() {
    let (client, mut station, _dials) = started(config()).await;
    let gi = interrogating(&client, &mut station).await;
    let stop = spawn_stop(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(DEACT, 20));
    station.send(&interrogation(UNKNOWN_CAUSE, 20));
    assert_eq!(
        stop.await.unwrap(),
        Err(ClientError::Refused {
            cause: Cause::UnknownCause
        })
    );
    station.send(&interrogation(ACTTERM, 20));
    assert_eq!(gi.await.unwrap().unwrap().len(), 1);
}

/// Nothing of the scope is running: nothing is sent.
#[tokio::test(start_paused = true)]
async fn a_stop_with_nothing_running_is_not_sent() {
    let (client, mut station, _dials) = started(config()).await;
    assert_eq!(
        client.stop_interrogation(Scope::Station).await,
        Err(ClientError::Interrogation(iec104::gi::GiError::NotRunning))
    );
    assert!(station.silent_for(Duration::from_secs(1)).await);
}

/// An unanswered stop times out after the confirmation time-out and leaves
/// the interrogation running to its termination; a second stop while one is
/// outstanding is busy.
#[tokio::test(start_paused = true)]
async fn an_unanswered_stop_times_out_and_the_interrogation_goes_on() {
    let (client, mut station, _dials) = started(config()).await;
    let gi = interrogating(&client, &mut station).await;
    let sent = Instant::now();
    let stop = spawn_stop(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(DEACT, 20));
    assert_eq!(
        client.stop_interrogation(Scope::Station).await,
        Err(ClientError::Busy)
    );
    assert_eq!(stop.await.unwrap(), Err(ClientError::Timeout));
    assert_eq!(sent.elapsed(), Duration::from_secs(10));
    station.send(&interrogation(ACTTERM, 20));
    assert_eq!(gi.await.unwrap().unwrap().len(), 1);
}

/// A connection lost while the stop waits ends both calls as lost.
#[tokio::test(start_paused = true)]
async fn a_stop_cut_off_by_a_lost_connection_is_a_lost_connection() {
    let (client, mut station, _dials) = started(config()).await;
    let gi = interrogating(&client, &mut station).await;
    let stop = spawn_stop(&client, Scope::Station);
    assert_eq!(station.next().await, interrogation(DEACT, 20));
    station.close().await;
    assert_eq!(stop.await.unwrap(), Err(ClientError::ConnectionLost));
    assert_eq!(gi.await.unwrap(), Err(ClientError::ConnectionLost));
}

// ------------------------------------------------------------ test command

/// `C_TS_TA_1` `<107>` (104 cl.8.8, figure 30): address 0, the test sequence
/// counter `tsc` (`UI16`, little-endian), then [`TIME`].
fn test_command(cause: u8, tsc: u16) -> Vec<u8> {
    let mut asdu = vec![107, 0x01, cause, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    asdu.extend(tsc.to_le_bytes());
    asdu.extend(TIME);
    asdu
}

fn spawn_test(client: &Client, tsc: u16) -> JoinHandle<Result<(), ClientError>> {
    let client = client.clone();
    let time = Cp56Time2a::parse(&TIME).unwrap();
    tokio::spawn(async move { client.test(Tsc::from_raw(tsc), time).await })
}

/// 104 cl.7.10: `C_TS ACT`, `C_TS ACTCON`; cl.8.8: the confirmation echoes
/// the TSC and the time.
#[tokio::test(start_paused = true)]
async fn a_test_command_ends_at_its_confirmation() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_test(&client, 0x1234);
    assert_eq!(station.next().await, test_command(ACT, 0x1234));
    station.send(&test_command(ACTCON, 0x1234));
    assert_eq!(call.await.unwrap(), Ok(()));
}

/// 5-101 cl.7.2.3: `P/N = 1` is the negative confirmation.
#[tokio::test(start_paused = true)]
async fn a_negative_test_confirmation_is_rejected() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_test(&client, 7);
    assert_eq!(station.next().await, test_command(ACT, 7));
    station.send(&test_command(ACTCON_NEGATIVE, 7));
    assert_eq!(call.await.unwrap(), Err(ClientError::Rejected));
}

/// 104 cl.8.8: *"The TSC in the response shall match the request"*; TS
/// 60870-5-604 5.4.22.1: *"Mismatching values of TSC are detected by the
/// Primary station"*.
#[tokio::test(start_paused = true)]
async fn a_test_confirmation_with_another_tsc_is_a_mismatch() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_test(&client, 7);
    assert_eq!(station.next().await, test_command(ACT, 7));
    station.send(&test_command(ACTCON, 8));
    assert!(matches!(
        call.await.unwrap(),
        Err(ClientError::Test(iec104::ts::TsError::EchoMismatch { .. }))
    ));
}

/// 5-101 cl.7.2.3: a station without the type mirrors it with cause 44.
#[tokio::test(start_paused = true)]
async fn a_mirrored_test_command_is_refused_with_its_cause() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_test(&client, 7);
    assert_eq!(station.next().await, test_command(ACT, 7));
    station.send(&test_command(UNKNOWN_TYPE, 7));
    assert_eq!(
        call.await.unwrap(),
        Err(ClientError::Refused {
            cause: Cause::UnknownTypeId
        })
    );
}

/// One test at a time; an unanswered one times out after the confirmation
/// time-out.
#[tokio::test(start_paused = true)]
async fn an_unanswered_test_command_times_out() {
    let (client, mut station, _dials) = started(config()).await;
    let sent = Instant::now();
    let call = spawn_test(&client, 7);
    assert_eq!(station.next().await, test_command(ACT, 7));
    assert_eq!(
        spawn_test(&client, 8).await.unwrap(),
        Err(ClientError::Busy)
    );
    assert_eq!(call.await.unwrap(), Err(ClientError::Timeout));
    assert_eq!(sent.elapsed(), Duration::from_secs(10));
}

/// A lost connection ends the test command.
#[tokio::test(start_paused = true)]
async fn a_test_command_cut_off_by_a_lost_connection_is_a_lost_connection() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_test(&client, 7);
    assert_eq!(station.next().await, test_command(ACT, 7));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::ConnectionLost));
}

// ----------------------------------------------------------- reset process

/// `C_RP_NA_1` `<105>` (5-101 cl.7.3.4.6, figure 77): address 0 and the
/// qualifier `QRP` (cl.7.2.6.27: `<1>` general reset of process).
fn reset_process(cause: u8) -> Vec<u8> {
    vec![105, 0x01, cause, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01]
}

fn spawn_reset(client: &Client) -> JoinHandle<Result<(), ClientError>> {
    let client = client.clone();
    tokio::spawn(async move { client.reset_process(Qrp { value: 1 }).await })
}

/// 104 cl.7.1, figure 22: the station confirms the reset process, then
/// closes the connection, and the controlling station opens a new one
/// (every t0) once the station is back.
#[tokio::test(start_paused = true)]
async fn a_reset_process_ends_at_its_confirmation_and_the_client_redials() {
    let (client, mut station, mut dials) = started(config()).await;
    let call = spawn_reset(&client);
    assert_eq!(station.next().await, reset_process(ACT));
    station.send(&reset_process(ACTCON));
    assert_eq!(call.await.unwrap(), Ok(()));

    station.close().await;
    let _station = accept(&mut dials).await;
    client.wait_started().await.unwrap();
}

/// 5-101 cl.7.2.3: `P/N = 1` is the negative confirmation.
#[tokio::test(start_paused = true)]
async fn a_negative_reset_confirmation_is_rejected() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_reset(&client);
    assert_eq!(station.next().await, reset_process(ACT));
    station.send(&reset_process(ACTCON_NEGATIVE));
    assert_eq!(call.await.unwrap(), Err(ClientError::Rejected));
}

/// Figure 77 lists `<44>`–`<47>` in the monitor direction: the mirror of a
/// station without the type.
#[tokio::test(start_paused = true)]
async fn a_mirrored_reset_process_is_refused_with_its_cause() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_reset(&client);
    assert_eq!(station.next().await, reset_process(ACT));
    station.send(&reset_process(UNKNOWN_TYPE));
    assert_eq!(
        call.await.unwrap(),
        Err(ClientError::Refused {
            cause: Cause::UnknownTypeId
        })
    );
}

/// A reset process without an answer may or may not have happened: outcome
/// unknown after the confirmation time-out, and it is not sent again; a
/// second one while it waits is busy.
#[tokio::test(start_paused = true)]
async fn an_unanswered_reset_process_is_not_resent() {
    let (client, mut station, _dials) = started(config()).await;
    let sent = Instant::now();
    let call = spawn_reset(&client);
    assert_eq!(station.next().await, reset_process(ACT));
    assert_eq!(spawn_reset(&client).await.unwrap(), Err(ClientError::Busy));
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
    assert_eq!(sent.elapsed(), Duration::from_secs(10));
    assert!(station.silent_for(Duration::from_secs(120)).await);
}

/// A connection lost before the confirmation: the station may have reset
/// (figure 22 closes the connection right after the confirmation).
#[tokio::test(start_paused = true)]
async fn a_reset_process_cut_off_by_a_lost_connection_is_unknown() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_reset(&client);
    assert_eq!(station.next().await, reset_process(ACT));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
}

// ------------------------------------------------------- parameter loading

/// Cause 47 with `P/N = 1`: clause 7.2.3's mirror of an unknown information
/// object address.
const UNKNOWN_ADDRESS: u8 = 0x40 | 0x2F;

/// `P_ME_NB_1` `<111>` (5-101 cl.7.3.5.2, figure 80) at address 4001: `SVA`
/// `sva` (two octets, little-endian), then `QPM` `0x01` (cl.7.2.6.24: `KPA`
/// `<1>` threshold value in bits 1–6, `LPC` and `POP` zero).
fn scaled_parameter(cause: u8, sva: i16) -> Vec<u8> {
    let mut asdu = vec![111, 0x01, cause, 0x00, 0x01, 0x00];
    asdu.extend(IOA_4001);
    asdu.extend(sva.to_le_bytes());
    asdu.push(0x01);
    asdu
}

/// `P_AC_NA_1` `<113>` (5-101 cl.7.3.5.4, figure 82) at address 4001 with
/// `QPA` `<3>` (cl.7.2.6.25: act/deact of persistent cyclic or periodic
/// transmission of the addressed object).
fn parameter_activation(cause: u8) -> Vec<u8> {
    let mut asdu = vec![113, 0x01, cause, 0x00, 0x01, 0x00];
    asdu.extend(IOA_4001);
    asdu.push(0x03);
    asdu
}

fn threshold(value: i16) -> Parameter {
    Parameter::new(
        4001,
        ParameterValue::Scaled {
            sva: Sva { value },
            qpm: Qpm {
                kpa: Qpm::THRESHOLD,
                ..Default::default()
            },
        },
    )
}

const fn activation(qpa: u8) -> Parameter {
    Parameter::new(
        4001,
        ParameterValue::Activation {
            qpa: Qpa { value: qpa },
        },
    )
}

fn spawn_load(client: &Client, value: i16) -> JoinHandle<Result<Parameter, ClientError>> {
    let client = client.clone();
    tokio::spawn(async move { client.load_parameter(threshold(value)).await })
}

/// 104 cl.7.9: `P_ME ACT`, `P_ME ACTCON`. TS 60870-5-604 5.4.21.1: the
/// confirmation *"contain the actual parameter value that is in operation.
/// -The actual value in this case is the \"new\" value"*.
#[tokio::test(start_paused = true)]
async fn a_parameter_load_returns_the_value_in_operation() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_load(&client, 500);
    assert_eq!(station.next().await, scaled_parameter(ACT, 500));
    station.send(&scaled_parameter(ACTCON, 500));
    assert_eq!(call.await.unwrap(), Ok(threshold(500)));
}

/// TS 60870-5-604 5.4.21.10: *"The Controlled station mirrors the same ASDU
/// with COT=7(ACTCONneg) … The actual value in this case is the \"old\"
/// existing value"*.
#[tokio::test(start_paused = true)]
async fn a_refused_parameter_load_reports_the_old_value() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_load(&client, 500);
    assert_eq!(station.next().await, scaled_parameter(ACT, 500));
    station.send(&scaled_parameter(ACTCON_NEGATIVE, 300));
    assert_eq!(
        call.await.unwrap(),
        Err(ClientError::ParameterRejected {
            in_operation: threshold(300)
        })
    );
}

/// 104 cl.7.9's `P_AC ACT` / `ACTCON`, then 5-101 figure 82's deactivation
/// (cause 8) and its confirmation (cause 9).
#[tokio::test(start_paused = true)]
async fn a_parameter_is_activated_and_deactivated() {
    let (client, mut station, _dials) = started(config()).await;
    let caller = client.clone();
    let call = tokio::spawn(async move { caller.activate_parameter(activation(3)).await });
    assert_eq!(station.next().await, parameter_activation(ACT));
    station.send(&parameter_activation(ACTCON));
    assert_eq!(call.await.unwrap(), Ok(()));

    let caller = client.clone();
    let call = tokio::spawn(async move { caller.deactivate_parameter(activation(3)).await });
    assert_eq!(station.next().await, parameter_activation(DEACT));
    station.send(&parameter_activation(DEACTCON));
    assert_eq!(call.await.unwrap(), Ok(()));
}

/// 5-101 cl.7.2.3: `P/N = 1` on the `ACTCON` or the `DEACTCON` refuses the
/// activation or the deactivation.
#[tokio::test(start_paused = true)]
async fn a_negative_parameter_activation_or_deactivation_is_rejected() {
    let (client, mut station, _dials) = started(config()).await;
    let caller = client.clone();
    let call = tokio::spawn(async move { caller.activate_parameter(activation(3)).await });
    assert_eq!(station.next().await, parameter_activation(ACT));
    station.send(&parameter_activation(ACTCON_NEGATIVE));
    assert_eq!(call.await.unwrap(), Err(ClientError::Rejected));

    let caller = client.clone();
    let call = tokio::spawn(async move { caller.deactivate_parameter(activation(3)).await });
    assert_eq!(station.next().await, parameter_activation(DEACT));
    station.send(&parameter_activation(DEACTCON_NEGATIVE));
    assert_eq!(call.await.unwrap(), Err(ClientError::Rejected));
}

/// 5-101 figures 80 and 82 list `<44>`–`<47>`: a station without the
/// parameter mirrors the load with cause 47.
#[tokio::test(start_paused = true)]
async fn a_mirrored_parameter_load_is_refused_with_its_cause() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_load(&client, 500);
    assert_eq!(station.next().await, scaled_parameter(ACT, 500));
    station.send(&scaled_parameter(UNKNOWN_ADDRESS, 500));
    assert_eq!(
        call.await.unwrap(),
        Err(ClientError::Refused {
            cause: Cause::UnknownInformationObjectAddress
        })
    );
}

/// 5-101 cl.7.4.9: *"`P_AC` ACT/ACTCON and DEACT/DEACTCON are used only in
/// combination with QPA := <3>"*; `QPA` `<1>` is refused unsent.
#[tokio::test(start_paused = true)]
async fn an_unused_activation_qualifier_is_not_sent() {
    let (client, mut station, _dials) = started(config()).await;
    assert!(matches!(
        client.activate_parameter(activation(1)).await,
        Err(ClientError::Parameter(_))
    ));
    assert!(station.silent_for(Duration::from_secs(1)).await);
}

/// A load without an answer may or may not be in operation: outcome unknown
/// after the confirmation time-out, not sent again; a second request for
/// the same parameter while it waits is busy.
#[tokio::test(start_paused = true)]
async fn an_unanswered_parameter_load_is_not_resent() {
    let (client, mut station, _dials) = started(config()).await;
    let sent = Instant::now();
    let call = spawn_load(&client, 500);
    assert_eq!(station.next().await, scaled_parameter(ACT, 500));
    assert_eq!(
        spawn_load(&client, 600).await.unwrap(),
        Err(ClientError::Busy)
    );
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
    assert_eq!(sent.elapsed(), Duration::from_secs(10));
    assert!(station.silent_for(Duration::from_secs(120)).await);
}

/// A connection lost before the confirmation leaves the load's outcome
/// unknown.
#[tokio::test(start_paused = true)]
async fn a_parameter_load_cut_off_by_a_lost_connection_is_unknown() {
    let (client, mut station, _dials) = started(config()).await;
    let call = spawn_load(&client, 500);
    assert_eq!(station.next().await, scaled_parameter(ACT, 500));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
}

// ------------------------------------------------------------- redundancy

/// A two-member group (104 clause 10) with both connections up, member 0
/// started and answered by a station that acknowledges when `ack` is true,
/// and member 1 stopped.
async fn started_group(
    config: ClientConfig,
    ack: bool,
) -> (Client, Station, Peer, mpsc::UnboundedReceiver<Dial>) {
    let (connector, mut dials) = Dials::new();
    let client = Client::spawn_redundant(connector, 2, config).unwrap();
    let first = next_dial(&mut dials).await;
    let second = next_dial(&mut dials).await;
    assert_eq!((first.conn, second.conn), (0, 1));
    let mut peer0 = first.accept();
    let peer1 = second.accept();
    assert_eq!(peer0.frame().await.unwrap(), STARTDT_ACT);
    peer0.send(&STARTDT_CON).await;
    client.wait_started().await.unwrap();
    (client, Station::run_with(peer0, ack), peer1, dials)
}

/// By default a failed started connection's unconfirmed data is discarded,
/// so the command it carried has an unknown outcome; the group starts the
/// other connection (10.5).
#[tokio::test(start_paused = true)]
async fn a_group_discards_what_the_failed_connection_carried() {
    let (client, mut station, mut peer1, _dials) = started_group(config(), true).await;
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));
    station.close().await;
    assert_eq!(call.await.unwrap(), Err(ClientError::OutcomeUnknown));
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_ACT);
}

/// With the replay chosen, a command whose I-frame the failed connection
/// never had acknowledged goes out again on the connection the t1
/// switchover started (10.5, 10.6: *"the pending event is retransmitted"*),
/// and its answers arrive there.
#[tokio::test(start_paused = true)]
async fn a_group_replays_on_the_next_started_connection() {
    let config = ClientConfig {
        retransmit_on_switchover: true,
        timeouts: iec104_tokio::client::Timeouts {
            confirmation: Duration::from_secs(60),
            ..Default::default()
        },
        ..config()
    };
    let (client, mut station, mut peer1, _dials) = started_group(config, false).await;
    let mut updates = client.subscribe().await.unwrap();
    let call = spawn_command(&client, Command::single(4001, true));
    assert_eq!(station.next().await, single_command(ACT, 0x01));

    // Unacknowledged, member 0's t1 expires and member 1 is started.
    assert_eq!(peer1.frame().await.unwrap(), STARTDT_ACT);
    peer1.send(&STARTDT_CON).await;
    let mut station1 = Station::run(peer1);
    assert_eq!(station1.next().await, single_command(ACT, 0x01));
    station1.send(&single_command(ACTCON, 0x01));
    station1.send(&single_command(ACTTERM, 0x01));
    assert_eq!(call.await.unwrap(), Ok(CommandOutcome::Terminated));

    let mut switched = false;
    while let Ok(update) = updates.try_recv() {
        switched |= matches!(update, Update::Switchover(_));
    }
    assert!(switched, "the switchover is reported");
}

// --------------------------------------------------------- process image

/// `M_ME_NB_1` `<11>` (5-101 cl.7.3.1.11) at address 100 with `SVA` `sva`
/// (cl.7.2.6.7, little-endian) and the `QDS` octet `qds` (cl.7.2.6.3: bit 1
/// `OV`, bit 5 `BL`, bit 6 `SB`, bit 7 `NT`, bit 8 `IV`), sent with the cause
/// octet `cause` (bit 8 is the test bit `T`, cl.7.2.3).
fn measurand_at_100(cause: u8, sva: i16, qds: u8) -> Vec<u8> {
    let [low, high] = sva.to_le_bytes();
    vec![
        11, 0x01, cause, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, low, high, qds,
    ]
}

/// `M_SP_TB_1` `<30>` (5-101 cl.7.3.1.22) at address 4001: `SIQ` ON (bit 1
/// `SPI`, cl.7.2.6.1), then [`TIME`] as its `CP56Time2a`, cause 20
/// (interrogated by station).
fn tagged_single_4001() -> Vec<u8> {
    let mut asdu = vec![30, 0x01, 20, 0x00, 0x01, 0x00];
    asdu.extend(IOA_4001);
    asdu.push(0x01);
    asdu.extend(TIME);
    asdu
}

/// Feeds every update already delivered to `updates` into `image`, stamped
/// `now`, and returns how many points were stored.
fn drain_into(
    image: &mut ProcessImage,
    updates: &mut mpsc::Receiver<Update>,
    now: Instant,
) -> usize {
    let mut stored = 0;
    while let Ok(update) = updates.try_recv() {
        stored += image.apply(&update, now);
    }
    stored
}

/// The next update, failing rather than hanging when none comes within an
/// hour of the paused clock.
async fn next_update(updates: &mut mpsc::Receiver<Update>) -> Update {
    tokio::time::timeout(Duration::from_secs(3600), updates.recv())
        .await
        .expect("no update came")
        .expect("the client is running")
}

/// Runs a station interrogation (104 cl.7.5, 5-101 figure 29) whose data is a
/// measurand at address 100 (`SVA` 1000, `QDS` 0) and a time-tagged single
/// point at 4001, and feeds its updates into a new image at `now`.
async fn interrogated_image(
    client: &Client,
    station: &mut Station,
    updates: &mut mpsc::Receiver<Update>,
) -> (ProcessImage, Instant) {
    let call = spawn_interrogation(client, Scope::Station);
    assert_eq!(station.next().await, interrogation(ACT, 20));
    station.send(&interrogation(ACTCON, 20));
    station.send(&measurand_at_100(20, 1000, 0x00));
    station.send(&tagged_single_4001());
    station.send(&interrogation(ACTTERM, 20));
    assert_eq!(call.await.unwrap().unwrap().len(), 2);

    let mut image = ProcessImage::new();
    let now = Instant::now();
    assert_eq!(drain_into(&mut image, updates, now), 2);
    (image, now)
}

/// A station interrogation fills the image: one entry per object the station
/// sent, with the value, quality and time tag of its elements and cause 20.
#[tokio::test(start_paused = true)]
async fn an_interrogation_fills_the_process_image() {
    let (client, mut station, _dials) = started(config()).await;
    let mut updates = client.subscribe().await.unwrap();
    let (image, now) = interrogated_image(&client, &mut station, &mut updates).await;

    assert_eq!(image.len(), 2);
    // Common address 1, ordered by object address.
    let addresses: Vec<(u16, u32)> = image.iter().map(|(key, _)| key).collect();
    assert_eq!(addresses, [(1, 100), (1, 4001)]);

    // SVA 1000 with a QDS of 0: every bit clear, OV present and clear.
    assert_eq!(
        image.get(1, 100),
        Some(&ImageEntry {
            point: Point {
                ioa: 100,
                value: Value::Scaled(1000),
                quality: Some(Quality {
                    overflow: Some(false),
                    ..Quality::default()
                }),
                time: None,
            },
            cause: Cause::InterrogatedByStation,
            arrived: now,
        })
    );
    // SPI ON; a SIQ has no OV bit (5-101 cl.7.2.6.1).
    assert_eq!(
        image.get(1, 4001),
        Some(&ImageEntry {
            point: Point {
                ioa: 4001,
                value: Value::Single(true),
                quality: Some(Quality::default()),
                time: Some(TimeTag::Cp56(Cp56Time2a::parse(&TIME).unwrap())),
            },
            cause: Cause::InterrogatedByStation,
            arrived: now,
        })
    );
    assert_eq!(image.get(2, 100), None, "another common address");
    assert_eq!(image.get(1, 101), None, "an address never sent");
}

/// The interrogation the client runs on a new started connection (TS
/// 60870-5-604 5.4.13.10) fills an image subscribed before the start.
#[tokio::test(start_paused = true)]
async fn the_interrogation_on_start_fills_the_process_image() {
    let (connector, mut dials) = Dials::new();
    let client = Client::spawn(connector, ClientConfig::new(1)).unwrap();
    let mut updates = client.subscribe().await.unwrap();
    let mut station = accept(&mut dials).await;
    client.wait_started().await.unwrap();

    assert_eq!(station.next().await, interrogation(ACT, 20));
    station.send(&interrogation(ACTCON, 20));
    station.send(&measurand_at_100(20, 1000, 0x00));
    station.send(&interrogation(ACTTERM, 20));

    let mut image = ProcessImage::new();
    let now = Instant::now();
    // The confirmation and the termination are control-direction types
    // (`C_IC_NA_1`), which the updates do not carry: the first update after
    // `Started` is the measurand.
    assert_eq!(next_update(&mut updates).await, Update::Started);
    assert_eq!(image.apply(&next_update(&mut updates).await, now), 1);
    assert_eq!(image.len(), 1);
    let entry = image.get(1, 100).unwrap();
    assert_eq!(entry.point.value, Value::Scaled(1000));
    assert_eq!(entry.cause, Cause::InterrogatedByStation);
}

/// A spontaneous change (cause 3) replaces the value of its own address and
/// leaves the others as they were.
#[tokio::test(start_paused = true)]
async fn a_spontaneous_change_updates_one_address() {
    let (client, mut station, _dials) = started(config()).await;
    let mut updates = client.subscribe().await.unwrap();
    let (mut image, interrogated_at) =
        interrogated_image(&client, &mut station, &mut updates).await;
    let before = *image.get(1, 4001).unwrap();

    tokio::time::sleep(Duration::from_secs(5)).await;
    // SVA 2000 is 0x07D0.
    station.send(&measurand_at_100(3, 2000, 0x00));
    let update = next_update(&mut updates).await;
    let now = Instant::now();
    assert_eq!(image.apply(&update, now), 1);

    let changed = image.get(1, 100).unwrap();
    assert_eq!(changed.point.value, Value::Scaled(2000));
    assert_eq!(changed.cause, Cause::Spontaneous);
    assert_eq!(changed.arrived, now);
    assert!(now > interrogated_at);
    assert_eq!(image.get(1, 4001), Some(&before), "the other address");
    assert_eq!(image.len(), 2);
}

/// A value whose `QDS` has `IV` set (bit 8, 5-101 cl.7.2.6.3) is stored with
/// that quality, replacing the valid one, not dropped.
#[tokio::test(start_paused = true)]
async fn an_invalid_value_is_stored_with_its_quality() {
    let (client, mut station, _dials) = started(config()).await;
    let mut updates = client.subscribe().await.unwrap();
    let (mut image, _) = interrogated_image(&client, &mut station, &mut updates).await;

    // IV (0x80) and NT (0x40) set, SVA 1000 kept.
    station.send(&measurand_at_100(3, 1000, 0xC0));
    let update = next_update(&mut updates).await;
    assert_eq!(image.apply(&update, Instant::now()), 1);

    let entry = image.get(1, 100).unwrap();
    assert_eq!(entry.point.value, Value::Scaled(1000));
    assert_eq!(
        entry.point.quality,
        Some(Quality {
            invalid: true,
            not_topical: true,
            overflow: Some(false),
            ..Quality::default()
        })
    );
    assert_eq!(entry.cause, Cause::Spontaneous);
}

/// An ASDU with the test bit set (5-101 cl.7.2.3: *"generated during test
/// conditions"*, *"without controlling the process"*) reaches the
/// subscribers but does not change the image.
#[tokio::test(start_paused = true)]
async fn a_test_asdu_does_not_change_the_image() {
    let (client, mut station, _dials) = started(config()).await;
    let mut updates = client.subscribe().await.unwrap();
    let (mut image, _) = interrogated_image(&client, &mut station, &mut updates).await;
    let before = image.clone();

    // Cause 3 with T (bit 8 of the cause octet) set.
    station.send(&measurand_at_100(0x80 | 3, 2000, 0x00));
    let update = next_update(&mut updates).await;
    let Update::Data(asdu) = &update else {
        panic!("expected the ASDU, got {update:?}");
    };
    assert!(asdu.header.test);
    assert_eq!(image.apply(&update, Instant::now()), 0);
    assert_eq!(image, before);
}
