//! 604 Table 18, *"Clock synchronisation function conformance test
//! procedures"*, PDF page index 69 (printed 68), procedures `5.4.18.1`
//! (*"Clock synchronisation - sequential procedure"*), `5.4.18.10` (*"Clock
//! synchronisation – Change the clock"*), `5.4.18.15` (*"Clock
//! synchronisation – Broadcast"*) and `5.4.18.20` (*"COMPATIBILITY WITH OTHER
//! TEST CASES"*).
//!
//! The block's NOTE: *"The following tests are only required for systems
//! supporting Clock synchronization."* The crate supports it (`cs`).
//!
//! # The rows, and where each one is
//!
//! | Row (description, abridged) | Required | Here |
//! | --- | --- | --- |
//! | `.1` the controlling station sends `C_CS` (ASDU 103) with COT=6 | M | [`clause_5_4_18_1_and_10_the_controlling_station_synchronises_the_clock`] |
//! | `.1` its time label is the time of occurrence | M | the same case: the label is the controlling station's time, octet for octet |
//! | `.1` the controlled station mirrors ASDU 103 with COT=7 and its time before the sync | M | [`clause_5_4_18_1_the_controlled_station_confirms_with_its_time_before_the_sync`] |
//! | `.1` events waiting before the sync keep their unadjusted time tags | M | the same case |
//! | `.1` events after the sync use the corrected time | M | the same case |
//! | `.1` events before the first sync after initialisation have IV set | M | **not the library's**, see below |
//! | `.1` events after the clock accuracy interval without a sync have IV set | M | **not the library's**, see below |
//! | `.1` the sync runs after station initialisation and at configured intervals | M | the first sync of the controlling-station case is its first I-frame after STARTDT, and later ones follow; the interval is the caller's, see below |
//! | `.10` the controlling station's time one day and one hour ahead, then back; the procedure continues; later events use the new time | M | both roles: [`clause_5_4_18_1_and_10_the_controlling_station_synchronises_the_clock`] and [`clause_5_4_18_10_the_controlled_station_follows_a_changed_clock`] |
//! | `.15` broadcast CASDU; the controlled station replies with its own CASDU | PIXIT | both roles: [`clause_5_4_18_15_a_broadcast_sync_is_confirmed_with_the_station_address`] and [`clause_5_4_18_15_the_controlling_station_broadcasts_a_sync`] |
//! | `.20` compatibility with other test cases | M | the whole suite, as in `tests/conformance_604.rs` |
//!
//! # What is not the library's
//!
//! `cs` builds and classifies the two frames of 104 clause 7.6 and nothing
//! else; its section *"What the procedure does not have"* says *"No clock, no
//! timer, no interval"* and *"**setting** `IV`, running the re-sync interval
//! and choosing between UTC and local time are the application's"*. The three
//! rows that rest on a clock of the station's own therefore have no library
//! behaviour to drive, and a test application that set `IV` itself would only
//! test that application:
//!
//! - **IV before the first sync after initialisation**, and **IV after the
//!   clock accuracy interval**: 104 clause 7.6 (PDF page index 66): *"When the
//!   synchronization command does not arrive within this time interval, the
//!   controlled station sets all time-tagged information objects with a mark
//!   that the time tag may be inaccurate (invalid). This mark is also set after
//!   station initializiation (warm and cold boot) of controlled stations before
//!   reception of a valid `C_CS` ACT PDU."* The crate carries the `IV` bit
//!   (`Cp56Time2a::invalid`) unchanged; deciding it is the application's.
//! - **the configured sync interval** of the controlling station is its
//!   scheduler's. The controlling-station case shows the part the library
//!   has: a sync is the first I-frame after STARTDT, and the procedure has no
//!   running state, so the next one is accepted and answered as well.
//!
//! The row *"containing the local time minus the value of time correction"*
//! is read with 104 clause 7.6, which removes the correction: *"The procedure
//! is a copy of that of 6.7 of IEC 60870-5-5, with the "first bit" and "time
//! correction" requirements and link layer options (SEND/NO REPLY or
//! SEND/CONFIRM) removed."* So the confirmation carries *"the local time before
//! it was synchronized"*.
//!
//! # Direction
//!
//! The activation is control-direction only (5-101 figure 75, index 107:
//! `<6> activation` in the control direction, `<7>` in the monitor direction),
//! so both roles are driven as the procedure names them; the reverse of §5.1
//! would be the spontaneous clock time of Table 16, which 104 does not permit
//! (see `table16`). §5.1's COT44–47 exception does not apply: no case here
//! sends those causes.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use crate::conformance604::acquisition::{
    BROADCAST, Scripted, next_nr, read_i_frames, started_controlling, station_i_frames,
    station_known, station_send,
};
use crate::conformance604::{
    CA, ControlledStation, ORIGINATOR, Peer, StationApp, deadline, sample_time,
};
use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{Cp56Time2a, Header, Known, LayoutObject, MSpTb1, Siq};
use iec104::cs::{ClockSynchronisation, Reaction};
use iec104::tx::{ProjectList, StationFunctions, Transmission};

/// The controlled station's clock since initialisation: Friday 2026-09-25,
/// 12:00:00.000 ([`sample_time`]). On the wire (5-101 clause 7.2.6.18,
/// milliseconds low octet first, then minutes, hours, day of month with day of
/// week in bits 6..8, months, years): `00 00 00 0C B9 09 1A`.
const T0: [u8; 7] = [0x00, 0x00, 0x00, 0x0C, 0xB9, 0x09, 0x1A];

/// A controlling station's time: Friday 2026-09-25, 12:34:56.789. `56 789` ms
/// is `0xDDD5`, 34 minutes `0x22`.
const T_SYNC: [u8; 7] = [0xD5, 0xDD, 0x22, 0x0C, 0xB9, 0x09, 0x1A];

/// [`sample_time`] one day and one hour ahead: Saturday 2026-09-26,
/// 13:00:00.000 (day 26 with day of week 6: `0x1A | 0xC0 = 0xDA`).
const T_AHEAD: [u8; 7] = [0x00, 0x00, 0x00, 0x0D, 0xDA, 0x09, 0x1A];

/// [`sample_time`] one day and one hour back: Thursday 2026-09-24,
/// 11:00:00.000 (day 24 with day of week 4: `0x18 | 0x80 = 0x98`).
const T_BACK: [u8; 7] = [0x00, 0x00, 0x00, 0x0B, 0x98, 0x09, 0x1A];

/// A time from its seven octets.
fn time(octets: [u8; 7]) -> Cp56Time2a {
    Cp56Time2a::parse(&octets).expect("a CP56Time2a inside clause 7.2.6.18's ranges")
}

/// One `C_CS_NA_1`, octet by octet from 5-101 figure 75 (clause 7.3.4.4, PDF
/// page index 107): type 103, SQ = 0 N = 1, `cause`, `originator`, the common
/// address `ca`, information object address 0, then the `CP56Time2a`.
fn clock_sync(cause: u8, originator: u8, ca: u16, time: [u8; 7]) -> Vec<u8> {
    let ca = ca.to_le_bytes();
    let mut asdu = vec![103, 0x01, cause, originator, ca[0], ca[1], 0x00, 0x00, 0x00];
    asdu.extend_from_slice(&time);
    asdu
}

/// The time label of an event ASDU: its last seven octets.
fn label(asdu: &[u8]) -> [u8; 7] {
    asdu[asdu.len() - 7..].try_into().expect("seven octets")
}

/// The controlled station under test for this table: `cs::ClockSynchronisation
/// ::controlled` answers every `C_CS_NA_1` with the station's time before the
/// sync; the application then sets its clock to the time the library reports
/// (`cs::Reaction::Requested`), which is the application's part (*"applying it
/// to a clock is the application's"*, `cs`), and one event occurs after each
/// sync, stamped with the clock (`tx::spontaneous`, `M_SP_TB_1`).
///
/// The clock does not run: every stamp is the last time set, which is what
/// makes the expected labels exact.
struct ClockedStation {
    cs: ClockSynchronisation,
    tx: Transmission,
    clock: Cp56Time2a,
    events_due: usize,
    /// The library's reaction to each sync, for the case.
    syncs: Arc<Mutex<Vec<Reaction>>>,
}

impl ClockedStation {
    const fn new(syncs: Arc<Mutex<Vec<Reaction>>>) -> Self {
        Self {
            cs: ClockSynchronisation::controlled(CA, ORIGINATOR),
            tx: events(),
            clock: sample_time(),
            events_due: 0,
            syncs,
        }
    }
}

/// A controlled `tx::Transmission` that uses acquisition of events.
const fn events() -> Transmission {
    Transmission::controlled(
        StationFunctions {
            spontaneous: true,
            ..StationFunctions::NONE
        },
        ProjectList::empty(),
        CA,
        ORIGINATOR,
    )
}

/// One `M_SP_TB_1` event at `0x4001`, stamped `time`.
fn event(tx: &Transmission, time: Cp56Time2a) -> Result<Vec<u8>, String> {
    let object = LayoutObject {
        ioa: 0x4001,
        value: MSpTb1 {
            siq: Siq {
                spi: true,
                ..Siq::default()
            },
            time,
        },
    };
    tx.spontaneous(&object).map_err(|e| format!("tx: {e:?}"))
}

impl StationApp for ClockedStation {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let outcome = self
            .cs
            .on_request(asdu, &station_known(asdu)?, self.clock)
            .map_err(|e| format!("cs: {e:?}"))?;
        if let Reaction::Requested { time, .. } = outcome.reaction {
            self.clock = time;
            self.events_due += 1;
        }
        self.syncs
            .lock()
            .map_err(|_| "poisoned")?
            .push(outcome.reaction);
        Ok(outcome.send)
    }

    fn poll(&mut self, _now: std::time::Instant) -> Result<Vec<Vec<u8>>, String> {
        let mut out = Vec::new();
        while self.events_due > 0 {
            self.events_due -= 1;
            out.push(event(&self.tx, self.clock)?);
        }
        Ok(out)
    }
}

/// 604 Table 18, PDF page index 69 (printed 68), procedure **`5.4.18.1`**,
/// `Reference` `IEC 60870-5-104:2006, 7.6` / `IEC 60870-5-5:1995, 6.7`,
/// `Required` `M`:
///
/// > The Controlled station mirrors ASDU 103 with COT=7, C_CS_ACTCON,
/// > containing the local time minus the value of time correction in the
/// > Controlled station before it was adjusted back to the Controlling station
///
/// > Any events waiting in the Controlled station BEFORE the Time Sync arrives
/// > still have their previous, unadjusted time tags
///
/// > Events occurring AFTER the Time Sync has arrived in the Controlled station
/// > use the new, corrected time value
///
/// DUT: the **controlled** station ([`ClockedStation`]). One event occurred
/// before the sync, stamped with the station's clock [`T0`], and waits in the
/// library's clause 5.3 queue. The mock controlling station sends `STARTDT
/// act` and, without waiting, the `C_CS ACT` with its time [`T_SYNC`] and
/// originator 9.
///
/// Expected, from 104 clause 7.6 (PDF page index 66): *"After the execution of
/// the clock sync internally the controlled station generates a `C_CS` ACTCON
/// PDU that contains the local time before it was synchronized. This message
/// is transmitted after any buffered time-tagged PDUs, that may be waiting
/// for transmission. Time-tagged events that occur after the internal clock
/// synchronization are transmitted after the `C_CS` ACTCON PDU."* So, in order:
/// the waiting event labelled [`T0`]; the confirmation, figure 75 with cause 7,
/// address 0, the originator echoed (5-101 clause 7.2.3) and [`T0`]; the
/// event after the sync labelled [`T_SYNC`].
#[test]
fn clause_5_4_18_1_the_controlled_station_confirms_with_its_time_before_the_sync() {
    let syncs = Arc::new(Mutex::new(Vec::new()));
    let waiting = event(&events(), time(T0)).expect("the waiting event");
    let station = ControlledStation::start_app(
        ClockedStation::new(Arc::clone(&syncs)),
        vec![waiting.clone()],
    )
    .expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the peer connects");
    let request = clock_sync(6, 9, CA, T_SYNC);
    peer.send_u(UFunction::StartDtAct).expect("STARTDT act");
    peer.send_i(SeqNo::new(0), SeqNo::new(0), &request)
        .expect("the sync goes out");
    peer.expect_u(UFunction::StartDtCon, deadline(5))
        .expect("STARTDT con");
    let asdus = read_i_frames(&mut peer, 3, deadline(5)).expect("three I-frames");
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");

    assert_eq!(
        asdus[0], waiting,
        "5.4.18.1: the waiting event goes first, \"transmitted after any buffered \
         time-tagged PDUs\""
    );
    assert_eq!(
        label(&asdus[0]),
        T0,
        "5.4.18.1: \"Any events waiting … BEFORE the Time Sync arrives still have their \
         previous, unadjusted time tags\""
    );
    assert_eq!(
        asdus[1],
        clock_sync(7, 9, CA, T0),
        "5.4.18.1: \"mirrors ASDU 103 with COT=7, C_CS_ACTCON\" with the time before the sync"
    );
    assert_eq!(
        label(&asdus[2]),
        T_SYNC,
        "5.4.18.1: \"Events occurring AFTER the Time Sync … use the new, corrected time value\""
    );
    assert_eq!(
        *syncs.lock().expect("the record"),
        vec![Reaction::Requested {
            time: time(T_SYNC),
            test: false
        }],
        "5.4.18.1: the station took the controlling station's time"
    );
}

/// 604 Table 18, PDF page index 69 (printed 68), procedure **`5.4.18.10`**,
/// `Reference` `IEC 60870-5-104:2006, 7.6` / `IEC 60870-5-5:1995, 6.7`, every
/// row `Required` `M`:
///
/// > The Controlling station increases its internal time one day and one hour
/// > ahead
/// >
/// > Sequential Clock synchronisation procedure continues
/// >
/// > Events occurring AFTER the Time Sync has arrived in the Controlled station
/// > use the new, corrected time value
/// >
/// > The Controlling station increases its internal time one day and one hour
/// > back.
/// >
/// > Sequential Clock synchronisation procedure continues
/// >
/// > Events occurring AFTER the Time Sync has arrived in the Controlled station
/// > use the new, corrected time value
///
/// DUT: the **controlled** station ([`ClockedStation`]), whose clock is
/// [`T0`]. The mock controlling station syncs it to [`T_AHEAD`] (one day and
/// one hour ahead of [`T0`]: the date, the day of week and the hour all
/// change), then to [`T_BACK`] (one day and one hour back from [`T0`]).
///
/// Expected, per sync: the confirmation (cause 7) carries the station's time
/// before that sync (104 clause 7.6), so [`T0`] and then [`T_AHEAD`]; the
/// event after it is labelled with the new time.
#[test]
fn clause_5_4_18_10_the_controlled_station_follows_a_changed_clock() {
    let syncs = Arc::new(Mutex::new(Vec::new()));
    let station = ControlledStation::start_app(ClockedStation::new(Arc::clone(&syncs)), Vec::new())
        .expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the peer connects");
    peer.start_data_transfer().expect("STARTDT");

    let mut seen = VecDeque::new();
    for (ns, new_time) in [T_AHEAD, T_BACK].into_iter().enumerate() {
        let nr = next_nr(&peer);
        peer.send_i(
            SeqNo::new(ns as u16),
            nr,
            &clock_sync(6, ORIGINATOR, CA, new_time),
        )
        .expect("the sync goes out");
        seen.extend(read_i_frames(&mut peer, 2, deadline(5)).expect("confirmation and event"));
    }
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");

    assert_eq!(
        seen.pop_front().expect("a frame"),
        clock_sync(7, ORIGINATOR, CA, T0),
        "5.4.18.10: the first confirmation carries the time before the sync"
    );
    assert_eq!(
        label(&seen.pop_front().expect("a frame")),
        T_AHEAD,
        "5.4.18.10: the event after the sync one day and one hour ahead"
    );
    assert_eq!(
        seen.pop_front().expect("a frame"),
        clock_sync(7, ORIGINATOR, CA, T_AHEAD),
        "5.4.18.10: \"Sequential Clock synchronisation procedure continues\": the second \
         confirmation carries the time the first sync set"
    );
    assert_eq!(
        label(&seen.pop_front().expect("a frame")),
        T_BACK,
        "5.4.18.10: the event after the sync one day and one hour back"
    );
}

/// 604 Table 18, PDF page index 69 (printed 68), procedures **`5.4.18.1`** and
/// **`5.4.18.10`**, `Reference` `IEC 60870-5-104:2006, 7.6` /
/// `IEC 60870-5-5:1995, 6.7`, `Required` `M`:
///
/// > The Controlling station sends a Clock Synchronisation message (ASDU 103)
/// > with COT = 6, C_CS_ACT, to the Controlled station
///
/// > The time label in the clock synchronization message from the Controlling
/// > station represents the time of occurrence (plausibility test)
///
/// > The clock synchronisation is executed after station initialisation and at
/// > configured PID intervals
///
/// and `5.4.18.10`'s rows (the time one day and one hour ahead, then back, and
/// *"Sequential Clock synchronisation procedure continues"*).
///
/// DUT: the **controlling** station, `cs::ClockSynchronisation::controlling`
/// over `interop::Station`. Its first I-frame after STARTDT is a sync with its
/// time [`T_SYNC`]; then it syncs with its clock moved to [`T_AHEAD`] and to
/// [`T_BACK`]. The mock controlled peer records each request and confirms it
/// with its own time before the sync (figure 75, cause 7).
///
/// Expected: each request is figure 75 with cause 6, address 0, the station's
/// originator and common address, and the station's time octet for octet
/// (5-101 clause 7.2.6.18); each confirmation is `cs::Reaction::Answered` with
/// the peer's time and `P/N = 0`.
#[test]
fn clause_5_4_18_1_and_10_the_controlling_station_synchronises_the_clock() {
    // The peer's clock before each sync: its own T0, then what each sync set.
    let before = Arc::new(Mutex::new(VecDeque::from([T0, T_SYNC, T_AHEAD])));
    let answers = {
        let before = Arc::clone(&before);
        move |request: &[u8]| -> Vec<Vec<u8>> {
            let time = before
                .lock()
                .expect("the clock")
                .pop_front()
                .expect("a sync");
            vec![clock_sync(7, request[3], CA, time)]
        }
    };
    let (peer_app, received) = Scripted::answering(Vec::new(), Box::new(answers));
    let peer = ControlledStation::start_app(peer_app, Vec::new()).expect("the mock binds");
    let mut station = started_controlling(&peer).expect("the controlling station starts");
    let dut = ClockSynchronisation::controlling(CA, ORIGINATOR);

    let mut confirmations = Vec::new();
    for time_octets in [T_SYNC, T_AHEAD, T_BACK] {
        let request = dut.request(time(time_octets)).expect("the request");
        station_send(&mut station, &request).expect("the sync goes out");
        confirmations.extend(station_i_frames(&mut station, 1, deadline(5)).expect("ACTCON"));
    }
    let first_i_frame = station
        .sent
        .iter()
        .position(|frame| matches!(crate::conformance604::apci_of(frame), Ok(Apci::I { .. })))
        .expect("an I-frame");
    let start = station
        .sent
        .iter()
        .position(|frame| {
            crate::conformance604::apci_of(frame) == Ok(Apci::U(UFunction::StartDtAct))
        })
        .expect("STARTDT act");
    station.close().expect("close");
    let _ = peer.join();

    assert_eq!(
        first_i_frame,
        start + 1,
        "5.4.18.1: \"executed after station initialisation\": the first I-frame after STARTDT"
    );
    assert_eq!(
        *received.lock().expect("the record"),
        vec![
            clock_sync(6, ORIGINATOR, CA, T_SYNC),
            clock_sync(6, ORIGINATOR, CA, T_AHEAD),
            clock_sync(6, ORIGINATOR, CA, T_BACK),
        ],
        "5.4.18.1 / .10: \"ASDU 103 with COT = 6\" carrying the controlling station's time"
    );
    for (confirmation, peer_time) in confirmations.iter().zip([T0, T_SYNC, T_AHEAD]) {
        let header = Header::parse(confirmation).expect("the header");
        let known = Known::standard(&header, header.common_address == CA, true);
        assert_eq!(
            dut.on_response(confirmation, &known)
                .expect("the station takes it")
                .reaction,
            Reaction::Answered {
                time: time(peer_time),
                negative: false
            },
            "5.4.18.1: the confirmation, with the peer's time before the sync"
        );
    }
}

/// 604 Table 18, PDF page index 69 (printed 68), procedure **`5.4.18.15`**,
/// `Reference` `IEC 60870-5-104:2006, 7.6` / `IEC 60870-5-101, 7.2.4` /
/// `IEC 60870-5-5:1995, 6.7`, `Required` `PIXIT`:
///
/// > The Controlling station sends a Clock Synchronisation message (ASDU 103)
/// > with COT = 6, C_CS_ACT and with the Broadcast CASDU, to the Controlled
/// > station. The Controlled station replies with its own CASDU(s)
///
/// DUT: the **controlled** station ([`ClockedStation`]). The request is
/// addressed to `FFFF`. Expected, from 5-101 clause 7.2.4 (PDF page index
/// 43): *"When using the common address FF or FFFF (broadcast address, request
/// of all), ACTCON, ACTTERM and the interrogated information objects (if any)
/// are returned with the specific common addresses of the controlled stations
/// as they would be when caused by commands to specific controlled stations."*
/// So the confirmation is the one a request to CA 1 gets: cause 7, CA 1, the
/// station's time before the sync.
#[test]
fn clause_5_4_18_15_a_broadcast_sync_is_confirmed_with_the_station_address() {
    let syncs = Arc::new(Mutex::new(Vec::new()));
    let station = ControlledStation::start_app(ClockedStation::new(Arc::clone(&syncs)), Vec::new())
        .expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the peer connects");
    peer.start_data_transfer().expect("STARTDT");
    peer.send_i(
        SeqNo::new(0),
        SeqNo::new(0),
        &clock_sync(6, ORIGINATOR, BROADCAST, T_SYNC),
    )
    .expect("the broadcast sync goes out");
    let asdus = read_i_frames(&mut peer, 2, deadline(5)).expect("confirmation and event");
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");

    assert_eq!(
        asdus[0],
        clock_sync(7, ORIGINATOR, CA, T0),
        "5.4.18.15: \"The Controlled station replies with its own CASDU(s)\""
    );
    assert_eq!(
        label(&asdus[1]),
        T_SYNC,
        "5.4.18.15: the broadcast sync set the clock"
    );
    assert_eq!(
        Header::parse(&asdus[1]).expect("the header").common_address,
        CA
    );
}

/// 604 Table 18, PDF page index 69 (printed 68), procedure **`5.4.18.15`**, the
/// same row, controlling half: *"The Controlling station sends a Clock
/// Synchronisation message (ASDU 103) with COT = 6, `C_CS_ACT` and with the
/// Broadcast CASDU"*.
///
/// DUT: the **controlling** station, `cs::ClockSynchronisation::controlling`
/// with the broadcast common address, over `interop::Station`. 5-101 clause
/// 7.2.4 (index 43) permits `FFFF` for type `<103>` in the control direction.
/// The mock controlled peer answers with its own CA 1, as the same clause
/// requires. Expected: the request is figure 75 with CA `FFFF` and cause 6,
/// and the station takes the answer from CA 1 as `cs::Reaction::Answered`.
#[test]
fn clause_5_4_18_15_the_controlling_station_broadcasts_a_sync() {
    let (peer_app, received) = Scripted::answering(
        Vec::new(),
        Box::new(|request: &[u8]| vec![clock_sync(7, request[3], CA, T0)]),
    );
    let peer = ControlledStation::start_app(peer_app, Vec::new()).expect("the mock binds");
    let mut station = started_controlling(&peer).expect("the controlling station starts");
    let dut = ClockSynchronisation::controlling(BROADCAST, ORIGINATOR);
    let request = dut.request(time(T_SYNC)).expect("a broadcast request");
    station_send(&mut station, &request).expect("the sync goes out");
    let answer = station_i_frames(&mut station, 1, deadline(5)).expect("the confirmation");
    station.close().expect("close");
    let _ = peer.join();

    assert_eq!(
        *received.lock().expect("the record"),
        vec![clock_sync(6, ORIGINATOR, BROADCAST, T_SYNC)],
        "5.4.18.15: \"with the Broadcast CASDU\""
    );
    let header = Header::parse(&answer[0]).expect("the header");
    // The station knows the answering station's own address, CA 1.
    let known = Known::standard(&header, header.common_address == CA, true);
    assert_eq!(
        ClockSynchronisation::controlling(CA, ORIGINATOR)
            .on_response(&answer[0], &known)
            .expect("the station takes it")
            .reaction,
        Reaction::Answered {
            time: time(T0),
            negative: false
        },
        "5.4.18.15: the confirmation from the station's own CASDU"
    );
}
