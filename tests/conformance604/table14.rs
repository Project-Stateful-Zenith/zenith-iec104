//! 604 Table 14, *"Cyclic data transmission function conformance test
//! procedures"*, PDF page index 61 (printed 60), procedure `5.4.14.1` (*"Cyclic
//! data transmission and Background Scan – sequential procedure"*) and
//! `5.4.14.10` (*"COMPATIBILITY WITH OTHER TEST CASES"*).
//!
//! The block's NOTE makes every row conditional: the tests apply only to a
//! system that supports cyclic data transmission, background scan or both.
//! The crate supports both (`tx::cyclic`,
//! `tx::background`), so every row applies.
//!
//! # The rows, and where each one is
//!
//! | Row (description, abridged) | Required | Here |
//! | --- | --- | --- |
//! | configured cyclic data with COT=1 | PICS | [`clause_5_4_14_1_cyclic_data_goes_out_with_cause_1_for_every_cyclic_type`] |
//! | the configured period for COT=1 | PICS | not a library rule, see below |
//! | background scan data with COT=2 | PICS | [`clause_5_4_14_1_background_scan_data_goes_out_with_cause_2_for_every_background_type`] |
//! | gaps, SQ:=0, one ASDU filled up to the maximum | M | [`clause_5_4_14_1_objects_with_gaps_are_packed_into_one_sq0_asdu`] |
//! | sequential addresses, SQ:=1 | PIXIT | controlled side: optional, see below; controlling side: [`clause_5_4_14_1_the_controlling_station_takes_sets_and_sequences_of_cyclic_values`] |
//! | measured values with COT=1 not also in COT 2, 3, 20–36 | PIXIT | not a library rule, see below |
//! | the configured period for COT=2 | PICS | not a library rule, see below |
//! | values on the controlling station = values on the controlled station | M | both roles: the first two cases and the controlling-station case |
//! | `P_AC_NA_1` activates/deactivates cyclic transmission, ACTCON mirror | PICS | [`clause_5_4_14_1_parameter_activation_switches_cyclic_transmission`] |
//! | every ASDU in the PICS with COT=1 and/or 2 | M | the type loops of the first two cases |
//! | `5.4.14.10` compatibility with other test cases | M | the whole suite, as in `tests/conformance_604.rs` |
//!
//! # What is not the library's
//!
//! `tx` builds the frames and classifies them; the *schedule* is the caller's.
//! The module says so (its section *"What is the caller's"*): 5-101 clause
//! 7.4.13 leaves the transmission cycle to fixed parameters set in the
//! controlled station, and *"Nothing here reads a clock, holds a timer
//! or schedules anything."* So:
//!
//! - **the configured periods** of COT=1 and COT=2 are a property of the
//!   application's scheduler, not of this library; a test here would time the
//!   test's own loop, so none is written;
//! - **which measured values are cyclic** and therefore stay out of COT 2, 3
//!   and 20–36 is per information object address, a project configuration
//!   (the row is `PIXIT`, and 5-101 clause 7.4.13 says cyclic values are
//!   normally not also reported with those causes). `tx` gates by type only (`tx::CYCLIC_TYPES`,
//!   `tx::BACKGROUND_TYPES`), so there is no library rule to drive;
//! - the SQ:=1 row is `PIXIT` for the controlled station, and `tx` has no
//!   sequence producer (see the deviation below), so the controlled side of
//!   that row is not claimed.
//!
//! # Direction
//!
//! Cyclic and background data are monitor-direction traffic: 5-101 Table 14
//! defines causes `<1>` and `<2>` for the monitor types only, so §5.1's swap
//! gives the **controlling** station the receiving half: it must accept the
//! data (sets and sequences) and store the values it carries. That half is
//! driven through `interop::Station` and `tx::Transmission::controlling`.
//! §5.1's COT44–47 exception does not apply: no case here sends those causes.

use std::time::{Duration, Instant};

use crate::conformance604::acquisition::{
    Produce, Scripted, assert_single_object, controlled_sends, expect_no_i_frame, next_nr,
    read_i_frames, started_controlling, station_i_frames, station_known, visit_monitor_layout,
};
use crate::conformance604::{CA, ControlledStation, ORIGINATOR, Peer, StationApp, deadline};
use iec104::apci::SeqNo;
use iec104::asdu::{
    Cause, Header, Known, LayoutObject, MMeNb1, Qds, Sva, TypeId, decode_asdu, read_ioa,
};
use iec104::pm::{LocalChange, ParameterLoading, Reaction as PmReaction};
use iec104::tx::{
    BACKGROUND_TYPES, CYCLIC_TYPES, Function, ProjectList, Reaction, StationFunctions, Transmission,
};

/// The cyclic types of 5-101 **Table 16**, *"Respond priorities of the
/// controlled station"* (PDF page index 121), row `9, 11, 13, 21`: cyclic
/// data transmission, monitor direction, cause 1. The row's
/// `120 to 127` are file transfer, which is Table 23's.
const TABLE_16_CYCLIC: [u8; 4] = [9, 11, 13, 21];

/// The background-scan types of 5-101 **Table 21**, *"Type identifications for
/// background scan"* (PDF page index 149), each with *"<2> background scan"*.
const TABLE_21_BACKGROUND: [u8; 9] = [1, 3, 5, 7, 9, 11, 13, 20, 21];

/// Drives one producer over `types` against the controlled station under test
/// and checks each frame on the wire: type, `cause`, address, value.
fn every_type_goes_out(row: &str, function: Function, cause: Cause, types: &[u8]) {
    let mut frames = Vec::new();
    let mut expected = Vec::new();
    for (i, type_id) in types.iter().enumerate() {
        let ioa = 0x4000 + i as u32;
        let mut produce = Produce {
            function,
            ioa,
            marker: 1,
        };
        let (frame, element) = visit_monitor_layout(*type_id, &mut produce)
            .unwrap_or_else(|| panic!("{row}: type {type_id} has no layout here"))
            .unwrap_or_else(|why| panic!("{row}: {why}"));
        frames.push(frame);
        expected.push((*type_id, ioa, element));
    }
    let (asdus, _) =
        controlled_sends(frames, Vec::new()).unwrap_or_else(|why| panic!("{row}: {why}"));
    assert_eq!(
        asdus.len(),
        types.len(),
        "{row}: one ASDU per configured object"
    );
    for (asdu, (type_id, ioa, element)) in asdus.iter().zip(&expected) {
        assert_single_object(row, asdu, *type_id, cause, *ioa, element);
    }
}

/// 604 Table 14, PDF page index 61 (printed 60), procedure **`5.4.14.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.4.3` / `IEC 60870-5-5:1995, 6.3.1`,
/// `Required` `PICS, 9.6 Cyclic data transmission`:
///
/// the controlled station sends its configured periodic/cyclic process data to
/// the controlling station with cause 1, in the ASDUs its PICS lists;
///
/// with the `M` rows that the tests run for every ASDU of the PICS that
/// supports cause 1 (`PER/CYC`) and/or 2 (`BACK`), and that the values the
/// controlling station receives and stores should be the controlled station's
/// actual values.
///
/// DUT: the **controlled** station. Its application hands `tx::cyclic`'s
/// frames (through a controlled `tx::Transmission`) to the station's session;
/// the mock controlling station reads them. The expected values come from the
/// standard: the type set is 5-101 Table 16's cyclic row (index 121), cause
/// `<1>` is 5-101 Table 14's *"periodic, cyclic"*, and each element is the one
/// the station holds. `tx::CYCLIC_TYPES` is checked against that row first,
/// so the loop is the standard's set, not the library's.
#[test]
fn clause_5_4_14_1_cyclic_data_goes_out_with_cause_1_for_every_cyclic_type() {
    let library: Vec<u8> = CYCLIC_TYPES.iter().map(|t| t.to_u8()).collect();
    assert_eq!(
        library, TABLE_16_CYCLIC,
        "5.4.14.1: tx's cyclic types are 5-101 Table 16's cyclic row"
    );
    every_type_goes_out(
        "5.4.14.1 (COT=1)",
        Function::Cyclic,
        Cause::Periodic,
        &TABLE_16_CYCLIC,
    );
}

/// 604 Table 14, PDF page index 61 (printed 60), procedure **`5.4.14.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.4.13` / `IEC 60870-5-5:1995, 6.3.1`,
/// `Required` `PICS, 9.6 Background Scan`:
///
/// the controlled station sends its configured background-scan process data
/// to the controlling station with cause 2 (`BACK`);
///
/// and the same `M` rows as the case above (each ASDU with COT=2; the values
/// stored represent the actual ones).
///
/// DUT: the **controlled** station, through `tx::background`. The type set is
/// 5-101 Table 21 (index 149), checked against `tx::BACKGROUND_TYPES` first;
/// cause `<2>` is the table's *"<2> background scan"*.
#[test]
fn clause_5_4_14_1_background_scan_data_goes_out_with_cause_2_for_every_background_type() {
    let library: Vec<u8> = BACKGROUND_TYPES.iter().map(|t| t.to_u8()).collect();
    assert_eq!(
        library, TABLE_21_BACKGROUND,
        "5.4.14.1: tx's background types are 5-101 Table 21"
    );
    every_type_goes_out(
        "5.4.14.1 (COT=2)",
        Function::Background,
        Cause::BackgroundScan,
        &TABLE_21_BACKGROUND,
    );
}

/// How many `M_ME_NB_1` objects fit one SQ = 0 ASDU: 104 clause 5 caps the
/// ASDU at 249 octets, the data unit identifier takes 6 and each
/// object 3 address octets + `SVA` 2 + `QDS` 1 (5-101 clause 7.3.1.11).
/// `(249 - 6) / 6 = 40`, below 5-101 clause 7.2.2.1's `N` limit of 127.
const MME_NB_PER_ASDU: usize = 40;

/// 604 Table 14, PDF page index 61 (printed 60), procedure **`5.4.14.1`**,
/// `Reference` `IEC 60870-5-3:1992, 5.1.5` / `IEC 60870-5-101:2003, 7.2.2.2`,
/// `Required` **`M`**:
///
/// periodic, cyclic or background-scan data sharing type, cause and priority
/// but with non-consecutive addresses goes out as a set of information
/// objects (SQ:=0) in a single ASDU, filled as far as the maximum ASDU or APDU
/// length configured in the PICS allows and no further;
///
/// DUT: the **controlled** station. Fifty cyclic `M_ME_NB_1` values are due at
/// once, at the addresses `0x4001, 0x4003, …` (every other one: gaps), packed
/// by the library's set producer, `Transmission::cyclic_set`. The row
/// wants them in SQ = 0 ASDUs filled up to the maximum: [`MME_NB_PER_ASDU`]
/// objects in the first, the other ten in the second (5-101 clause 7.2.2.1
/// lets an ASDU carry one or several information objects of the same kind).
///
/// Before `tx` had the set producers it built one ASDU of `N = 1` per object:
/// a station sent fifty one-object ASDUs, and the first frame arrived with
/// `N = 1` instead of 40.
#[test]
fn clause_5_4_14_1_objects_with_gaps_are_packed_into_one_sq0_asdu() {
    let station = Transmission::controlled(
        StationFunctions {
            cyclic: true,
            ..StationFunctions::NONE
        },
        ProjectList::empty(),
        CA,
        ORIGINATOR,
    );
    let objects: Vec<LayoutObject<MMeNb1>> = (0..50u32)
        .map(|i| LayoutObject {
            ioa: 0x4001 + 2 * i,
            value: MMeNb1 {
                sva: Sva {
                    value: 100 + i as i16,
                },
                qds: Qds::default(),
            },
        })
        .collect();
    // Every object the application has for this cycle, through the library's
    // cyclic set producer.
    let frames = station.cyclic_set(&objects).expect("the cyclic set");

    let (app, _) = Scripted::sending(frames);
    let dut = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let mut peer = Peer::connect(dut.addr()).expect("the peer connects");
    peer.start_data_transfer().expect("STARTDT");
    let first = read_i_frames(&mut peer, 1, deadline(5)).expect("the first ASDU")[0].clone();
    peer.close().expect("close");
    let _ = dut.join();

    let header = Header::parse(&first).expect("the header");
    assert!(
        !header.sequence,
        "5.4.14.1: a set of objects with gaps is SQ = 0"
    );
    assert_eq!(
        usize::from(header.count),
        MME_NB_PER_ASDU,
        "5.4.14.1: one ASDU filled up to, and not past, the maximum \
         ASDU length: 40 M_ME_NB_1 objects fit 249 octets"
    );
    let decoded = decode_asdu::<MMeNb1>(&first).expect("the ASDU decodes");
    assert_eq!(
        decoded,
        objects[..MME_NB_PER_ASDU],
        "5.4.14.1: the first 40 objects, in order, with their gaps"
    );
}

/// The three `M_ME_NB_1` values the controlling-station case below receives,
/// with their addresses: a set with gaps (`0x4001`, `0x4003`, `0x4007`) and
/// a sequence starting at `0x5000`.
const VALUES: [i16; 3] = [0x1234, -2, 300];

/// 604 Table 14, PDF page index 61 (printed 60), procedure **`5.4.14.1`**, the
/// same rows as [`clause_5_4_14_1_objects_with_gaps_are_packed_into_one_sq0_asdu`]
/// and the SQ:=1 row (`Required` `PIXIT`: consecutive addresses go out as a
/// sequence of information elements, SQ:=1, in a single ASDU), plus the `M`
/// row that the values the controlling station receives and stores should be
/// the controlled station's actual values.
///
/// DUT: the **controlling** station (§5.1's swap: the receiving half of the
/// rows). The mock controlled peer sends two cyclic `M_ME_NB_1` ASDUs written
/// octet by octet from 5-101 clause 7.2.2.1 and figure 12's layout (SQ bit 8
/// of the variable structure qualifier) and clause 7.3.1.11's element (`SVA`
/// little endian, then `QDS`): a set of three objects with gaps (SQ = 0) and a
/// sequence of three elements (SQ = 1, each address one more than the one
/// before, from the first). The station classifies each with
/// `tx::Transmission::controlling` as cyclic data and decodes the values the
/// peer sent.
#[test]
fn clause_5_4_14_1_the_controlling_station_takes_sets_and_sequences_of_cyclic_values() {
    let [a, b, c] = VALUES.map(i16::to_le_bytes);
    // Type 11, SQ = 0 N = 3, COT 1, OA 0, CA 1; then IOA SVA QDS three times.
    let set = vec![
        0x0B, 0x03, 0x01, 0x00, 0x01, 0x00, // data unit identifier
        0x01, 0x40, 0x00, a[0], a[1], 0x00, // 0x4001
        0x03, 0x40, 0x00, b[0], b[1], 0x00, // 0x4003
        0x07, 0x40, 0x00, c[0], c[1], 0x00, // 0x4007
    ];
    // Type 11, SQ = 1 N = 3 (0x83), COT 1; one address, three elements.
    let sequence = vec![
        0x0B, 0x83, 0x01, 0x00, 0x01, 0x00, // data unit identifier
        0x00, 0x50, 0x00, // 0x5000
        a[0], a[1], 0x00, b[0], b[1], 0x00, c[0], c[1], 0x00,
    ];
    let (peer_app, _) = Scripted::sending(vec![set.clone(), sequence.clone()]);
    let peer = ControlledStation::start_app(peer_app, Vec::new()).expect("the mock binds");
    let mut station = started_controlling(&peer).expect("the controlling station starts");
    let asdus = station_i_frames(&mut station, 2, deadline(5)).expect("both ASDUs arrive");
    station.close().expect("close");
    let _ = peer.join();
    assert_eq!(asdus, vec![set, sequence], "the octets the mock sent");

    let dut = Transmission::controlling(CA, ORIGINATOR);
    let expected_ioas: [[u32; 3]; 2] = [[0x4001, 0x4003, 0x4007], [0x5000, 0x5001, 0x5002]];
    for (asdu, ioas) in asdus.iter().zip(expected_ioas) {
        let header = Header::parse(asdu).expect("the header");
        let known = Known::standard(&header, header.common_address == CA, true);
        let outcome = dut.on_response(asdu, &known).expect("the station takes it");
        assert_eq!(
            outcome.reaction,
            Reaction::Cyclic {
                type_id: TypeId::MMeNb1
            },
            "5.4.14.1 (SQ = {}): cyclic data with COT=1",
            u8::from(header.sequence)
        );
        assert!(
            outcome.send.is_empty(),
            "5.4.14.1: cyclic data answers nothing"
        );
        let stored: Vec<(u32, i16)> = decode_asdu::<MMeNb1>(asdu)
            .expect("the station decodes the values")
            .iter()
            .map(|object| (object.ioa, object.value.sva.value))
            .collect();
        assert_eq!(
            stored,
            ioas.iter().copied().zip(VALUES).collect::<Vec<_>>(),
            "5.4.14.1 (SQ = {}): the values stored on the controlling station must be the \
             controlled station's actual values",
            u8::from(header.sequence)
        );
    }
}

/// The object whose cyclic transmission the parameter activation switches.
const CYCLIC_IOA: u32 = 0x4100;

/// The cycle of the application below: short, so the case is quick.
const CYCLE: Duration = Duration::from_millis(30);

/// A controlled station whose one cyclic object is switched on and off by
/// `P_AC_NA_1` with `QPA` `<3>`: `pm::ParameterLoading::controlled` answers
/// every parameter ASDU, `tx::Transmission::cyclic` builds the cyclic frame.
/// The switch itself (send while activated, every [`CYCLE`]) is this
/// application's, as `tx` leaves the schedule to the caller.
struct CyclicUnderActivation {
    pm: ParameterLoading,
    tx: Transmission,
    active: bool,
    last: Option<Instant>,
    value: i16,
}

impl StationApp for CyclicUnderActivation {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let outcome = self
            .pm
            .on_request(asdu, &station_known(asdu)?)
            .map_err(|e| format!("pm: {e:?}"))?;
        match outcome.reaction {
            PmReaction::Activated { ioa, qpa } if ioa == CYCLIC_IOA && qpa.value == 3 => {
                self.active = true;
            }
            PmReaction::Deactivated {
                ioa,
                qpa,
                negative: false,
            } if ioa == CYCLIC_IOA && qpa.value == 3 => {
                self.active = false;
            }
            _ => {}
        }
        Ok(outcome.send)
    }

    fn poll(&mut self, now: Instant) -> Result<Vec<Vec<u8>>, String> {
        if !self.active || self.last.is_some_and(|last| now < last + CYCLE) {
            return Ok(Vec::new());
        }
        self.last = Some(now);
        self.value += 1;
        let object = LayoutObject {
            ioa: CYCLIC_IOA,
            value: MMeNb1 {
                sva: Sva { value: self.value },
                qds: Qds::default(),
            },
        };
        Ok(vec![
            self.tx.cyclic(&object).map_err(|e| format!("tx: {e:?}"))?,
        ])
    }
}

/// One `P_AC_NA_1` for [`CYCLIC_IOA`] with `QPA` `<3>`, octet by octet from
/// 5-101 figure 82 (clause 7.3.5.4, PDF page index 113): type 113, SQ = 0
/// N = 1, the cause, OA 0, CA 1, the address, `QPA`. `<3>` is clause
/// 7.2.6.25's value for switching persistent cyclic/periodic transmission of
/// the addressed object on or off.
fn parameter_activation(cause: u8) -> Vec<u8> {
    let ioa = CYCLIC_IOA.to_le_bytes();
    vec![
        113, 0x01, cause, 0x00, 0x01, 0x00, ioa[0], ioa[1], ioa[2], 3,
    ]
}

/// Reads I-frames (acknowledging each) until the one of type `type_id`,
/// returning it and how many cyclic ASDUs came before it.
fn until_type(peer: &mut Peer, type_id: u8) -> (Vec<u8>, usize) {
    let mut cyclic = 0;
    loop {
        let asdu = read_i_frames(peer, 1, deadline(5))
            .unwrap_or_else(|why| panic!("5.4.14.1: type {type_id}: {why}"))
            .remove(0);
        if asdu[0] == type_id {
            return (asdu, cyclic);
        }
        cyclic += 1;
    }
}

/// 604 Table 14, PDF page index 61 (printed 60), procedure **`5.4.14.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.3.5.4`, `Required` `PICS, 9.6
/// Parameter activation`:
///
/// the controlling station switches cyclic/periodic transmission of an object
/// on or off with `P_AC_NA_1` (type 113), and the controlled station confirms
/// either by mirroring the command with cause 7 (`ACTCON`);
///
/// DUT: the **controlled** station, `pm::ParameterLoading::controlled` for the
/// answer and `tx` for the cyclic frames. The expected answers are 5-101
/// figure 82's causes (index 113): the activation `<6>` is confirmed with
/// `<7> := activation confirmation`, the deactivation `<8>` with `<9> :=
/// deactivation confirmation` (the row names only COT=7; figure 82 gives the
/// deactivation its own confirmation), each a mirror of the command: same
/// type, address and `QPA`, `P/N = 0`.
///
/// Before the activation no cyclic data flows, after it cyclic data with
/// COT=1 does, and after the deactivation's confirmation it stops. That switch
/// is the test application's (see [`CyclicUnderActivation`]); the library's
/// share is the confirmation and the cyclic frames.
#[test]
fn clause_5_4_14_1_parameter_activation_switches_cyclic_transmission() {
    let app = CyclicUnderActivation {
        pm: ParameterLoading::controlled(LocalChange::NotUsed, CA, ORIGINATOR),
        tx: Transmission::controlled(
            StationFunctions {
                cyclic: true,
                ..StationFunctions::NONE
            },
            ProjectList::empty(),
            CA,
            ORIGINATOR,
        ),
        active: false,
        last: None,
        value: 0,
    };
    let dut = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let mut peer = Peer::connect(dut.addr()).expect("the peer connects");
    peer.start_data_transfer().expect("STARTDT");
    expect_no_i_frame(&mut peer, Instant::now() + 4 * CYCLE)
        .expect("5.4.14.1: nothing cyclic before the activation");

    let activation = parameter_activation(6);
    peer.send_i(SeqNo::new(0), next_nr(&peer), &activation)
        .expect("the activation goes out");
    let (confirmation, _) = until_type(&mut peer, 113);
    assert_eq!(
        confirmation[2], 7,
        "5.4.14.1: the command mirrored with cause 7 (ACTCON)"
    );
    assert_eq!(
        (&confirmation[..2], &confirmation[3..]),
        (&activation[..2], &activation[3..]),
        "5.4.14.1: a mirror of the command, P/N = 0"
    );
    let cyclic = read_i_frames(&mut peer, 2, deadline(5)).expect("cyclic data flows");
    for asdu in &cyclic {
        let header = Header::parse(asdu).expect("the header");
        assert_eq!(
            (header.type_id, header.cause),
            (TypeId::MMeNb1, Cause::Periodic),
            "5.4.14.1: the activated object goes out with COT=1"
        );
        assert_eq!(
            read_ioa(&asdu[Header::LEN..]).expect("an address"),
            CYCLIC_IOA
        );
    }

    let deactivation = parameter_activation(8);
    let received = peer.received.len();
    peer.send_i(SeqNo::new(1), next_nr(&peer), &deactivation)
        .expect("the deactivation goes out");
    let (confirmation, _) = until_type(&mut peer, 113);
    assert!(peer.received.len() > received, "the confirmation was read");
    assert_eq!(
        confirmation[2], 9,
        "5.4.14.1: 5-101 figure 82's <9> := deactivation confirmation"
    );
    assert_eq!(
        (&confirmation[..2], &confirmation[3..]),
        (&deactivation[..2], &deactivation[3..]),
        "5.4.14.1: a mirror of the command, P/N = 0"
    );
    expect_no_i_frame(&mut peer, Instant::now() + 4 * CYCLE)
        .expect("5.4.14.1: no cyclic data after the deactivation");
    peer.close().expect("close");
    dut.join().expect("the station ends cleanly");
}
