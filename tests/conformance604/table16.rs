//! 604 Table 16, *"Acquisition of events function conformance test
//! procedures"*, PDF page index 63 (printed 62), procedures `5.4.16.1`
//! (*"Acquisition of events - sequential procedure"*) and `5.4.16.10`
//! (*"COMPATIBILITY WITH OTHER TEST CASES"*).
//!
//! The block's NOTE: *"The following tests are only required for systems
//! supporting Acquisition of events."* The crate supports it
//! (`tx::spontaneous`), so every row applies unless said otherwise below.
//!
//! # The rows, and where each one is
//!
//! | Row (description, abridged) | Required | Here |
//! | --- | --- | --- |
//! | an event goes out with COT=3 | M | [`clause_5_4_16_1_events_go_out_with_cause_3_for_every_spontaneous_type`] |
//! | a local buffer keeps events that come faster than they can be sent | M | [`clause_5_4_16_1_events_faster_than_the_link_are_buffered_not_lost`] |
//! | untagged events in chronological order | PICS | [`clause_5_4_16_1_untagged_events_keep_their_chronological_order`] |
//! | gaps, SQ:=0, one ASDU filled up to the maximum | M | [`clause_5_4_16_1_events_with_gaps_are_packed_into_one_sq0_asdu`] |
//! | sequential addresses, SQ:=1: optional for the controlled station, mandatory for the controlling station | PIXIT | controlling side: [`clause_5_4_16_1_the_controlling_station_takes_sets_and_sequences_of_events`] |
//! | the time label is the time of occurrence | M | [`clause_5_4_16_1_the_time_label_is_the_time_of_occurrence`] |
//! | spontaneous clock synchronisation, COT=3, ASDU 103 | PICS | not permitted in 104: [`clause_5_4_16_1_a_spontaneous_clock_time_is_not_a_104_message`] |
//! | its time label is the time of occurrence | PICS | the same: not permitted in 104 |
//! | values stored on the controlling station = values on the controlled station | M | both roles: the first case and [`clause_5_4_16_1_the_controlling_station_stores_every_spontaneous_type`] |
//! | every ASDU in the PICS with COT=3 | M | the type loops of those two cases |
//! | `5.4.16.10` compatibility with other test cases | M | the whole suite, as in `tests/conformance_604.rs` |
//!
//! # The type set
//!
//! *"Each ASDU in the PICS that supports COT=3"* is 5-101 Table 16's event row
//! (PDF page index 121: `1 to 44`, *"Event reporting: In monitor direction
//! with COT = 3"*) within the monitor types 104 selects: `<1>` to `<21>`
//! without the `CP24Time2a` forms, and `<30>` to `<40>` (104 clause 9, PDF page
//! index 100). The row's `103` is the spontaneous clock time, handled on its
//! own below; its `106` is struck from 104 (`tx::is_spontaneous_type`'s note).
//!
//! # What is not claimed
//!
//! - SQ:=1 on the **controlled** side is optional (*"Using SQ=1 is optional
//!   for a controlled station"*), and `tx` has no sequence producer; that half
//!   of the row is not claimed.
//! - The two rows about the spontaneous clock synchronisation message: 104's
//!   interoperability list (clause 9) fills the `<103>` / cause 3 box black,
//!   *"option not permitted in this companion standard"*, and the row's
//!   *"subsequent ASDUs with short time tag"* are the `CP24Time2a` types 104
//!   does not permit either. The case for it shows the 104 reading: a
//!   controlling station on the conventional 104 profile ignores the message.
//!   `cs::announcement` builds it for a 101 peer that agreed to it; *when* to
//!   send it (an hour shift) is the application's.
//!
//! # Direction
//!
//! Events are monitor-direction traffic (5-101 Table 16: *"In monitor
//! direction with COT = 3"*), so §5.1's swap gives the **controlling** station
//! the receiving half, and the SQ:=1 row names it explicitly. §5.1's
//! COT44–47 exception does not apply: no case here sends those causes.

use crate::conformance604::acquisition::{
    Produce, Scripted, Stored, assert_single_object, controlled_sends, expect_no_i_frame,
    started_controlling, station_i_frames, visit_monitor_layout,
};
use crate::conformance604::{
    CA, ControlledStation, ORIGINATOR, Peer, asdu_with_body, deadline, monitor_direction_type_ids,
    sample_object_area,
};
use iec104::apci::{Apci, SeqNo};
use iec104::asdu::{
    Cause, Cp56Time2a, Discard, Header, Known, LayoutObject, MSpNa1, MSpTb1, Siq, TypeId,
    Unspecified, decode_asdu, read_ioa,
};
use iec104::cs::{ClockSynchronisation, Reaction as CsReaction};
use iec104::interop::InteropProfile;
use iec104::tx::{
    Function, ProjectList, Reaction, StationFunctions, Transmission, is_spontaneous_type,
};

/// The event types this table loops over, from the standard: 5-101 Table 16's
/// `1 to 44` row (index 121) within the monitor types 104 selects.
fn event_types() -> Vec<u8> {
    monitor_direction_type_ids()
        .into_iter()
        .filter(|t| (1..=44).contains(t))
        .collect()
}

/// A controlled `tx::Transmission` that uses acquisition of events only.
const fn events_station() -> Transmission {
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

/// One `M_SP_NA_1` event at `ioa`, through `tx::spontaneous`.
fn single_point(ioa: u32, on: bool) -> Vec<u8> {
    let object = LayoutObject {
        ioa,
        value: MSpNa1 {
            siq: Siq {
                spi: on,
                ..Siq::default()
            },
        },
    };
    events_station()
        .spontaneous(&object)
        .expect("an event frame")
}

/// 604 Table 16, PDF page index 63 (printed 62), procedure **`5.4.16.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.4.4` / `IEC 60870-5-5:1995, 6.4.1`,
/// `Required` `M`:
///
/// > When an event occurs in the Controlled station, The Controlled station
/// > transfers the configured process information data in ASDUs (look at PICS
/// > for the supported ASDUs)with COT=3 to the Controlling station
///
/// with the `M` rows *"The values of the object(s) transferred and stored on
/// the controlling station should represent the actual values on the
/// controlled station."* and *"The tests in this Table are performed correctly
/// by each ASDU in the PICS that supports COT=3, spontaneous"*.
///
/// DUT: the **controlled** station. One event per type of [`event_types`] is
/// built by `tx::spontaneous` and handed to the station's session; the mock
/// controlling station reads them, acknowledging each. Expected, from the
/// standard: cause `<3>` (5-101 Table 14, *"spontaneous"*), the type and
/// address the event has, and the value the station holds. The library's
/// `tx::is_spontaneous_type` is checked against the set first.
#[test]
fn clause_5_4_16_1_events_go_out_with_cause_3_for_every_spontaneous_type() {
    let types = event_types();
    assert!(
        types.len() > 12,
        "5.4.16.1: the set must be more than the k window, found {types:?}"
    );
    let mut frames = Vec::new();
    let mut expected = Vec::new();
    for (i, type_id) in types.iter().enumerate() {
        assert!(
            is_spontaneous_type(TypeId::from_u8(*type_id)),
            "5.4.16.1: type {type_id} is on 5-101 Table 16's event row"
        );
        let ioa = 0x4000 + i as u32;
        let (frame, element) = visit_monitor_layout(
            *type_id,
            &mut Produce {
                function: Function::Spontaneous,
                ioa,
                marker: 1,
            },
        )
        .unwrap_or_else(|| panic!("5.4.16.1: type {type_id} has no layout here"))
        .unwrap_or_else(|why| panic!("5.4.16.1: {why}"));
        frames.push(frame);
        expected.push((*type_id, ioa, element));
    }
    let (asdus, _) =
        controlled_sends(frames, Vec::new()).unwrap_or_else(|why| panic!("5.4.16.1: {why}"));
    assert_eq!(asdus.len(), types.len(), "5.4.16.1: one ASDU per event");
    for (asdu, (type_id, ioa, element)) in asdus.iter().zip(&expected) {
        assert_single_object(
            "5.4.16.1",
            asdu,
            *type_id,
            Cause::Spontaneous,
            *ioa,
            element,
        );
    }
}

/// The k window of 104 clause 9.6's default parameters (*"k 12 APDUs Maximum
/// difference receive sequence number to send state variable"*).
const K: usize = 12;

/// 604 Table 16, PDF page index 63 (printed 62), procedure **`5.4.16.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.4.4` / `IEC 60870-5-5:1995, 6.4`,
/// `Required` `M`:
///
/// > Local buffer function to collect events that may appear faster than it is
/// > possible to transmit them to the Controlling station to prevent the loss
/// > of events
///
/// DUT: the **controlled** station. Thirty events occur while the connection
/// cannot carry them at all (before STARTDT), handed to the library's own
/// buffer, `Session::queue_i_frame` (clause 5.3: *"Any pending user data in
/// the controlled station is sent only after the STARTDT con"*). Once started,
/// the mock controlling station does not acknowledge, so the link is slower
/// than the events: 104 clause 5.5 says *"The transmitter stops the
/// transmission at k unacknowledged I format APDUs."*, `k` = [`K`]. Then it
/// acknowledges, and the rest must follow.
///
/// Expected: exactly [`K`] events before the first acknowledgement, and all
/// thirty in the end, each once, in the order they occurred.
#[test]
fn clause_5_4_16_1_events_faster_than_the_link_are_buffered_not_lost() {
    let events: Vec<Vec<u8>> = (0..30u32)
        .map(|i| single_point(0x4001 + i, i % 2 == 0))
        .collect();
    let (app, _) = Scripted::sending(Vec::new());
    let station = ControlledStation::start_app(app, events.clone()).expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the peer connects");
    peer.start_data_transfer().expect("STARTDT");

    let mut received = Vec::new();
    for _ in 0..K {
        received.push(peer.expect_i(deadline(5)).expect("the window's events").1);
    }
    expect_no_i_frame(
        &mut peer,
        std::time::Instant::now() + std::time::Duration::from_millis(150),
    )
    .expect("5.4.16.1 / 104 cl.5.5: the station stops at k unacknowledged I-frames");
    while received.len() < events.len() {
        peer.send_s(SeqNo::new(received.len() as u16))
            .expect("an acknowledgement");
        let (apci, asdu) = peer
            .expect_i(deadline(5))
            .expect("the buffered events follow");
        assert!(matches!(apci, Apci::I { .. }));
        received.push(asdu);
    }
    peer.send_s(SeqNo::new(received.len() as u16))
        .expect("the last acknowledgement");
    peer.close().expect("close");
    let report = station.join().expect("the station ends cleanly");

    assert_eq!(
        received, events,
        "5.4.16.1: \"to prevent the loss of events\": every event, once, in order"
    );
    assert_eq!(
        report.outstanding_i_frames_at_eof, 0,
        "every event was confirmed"
    );
}

/// 604 Table 16, PDF page index 63 (printed 62), procedure **`5.4.16.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.2.2.2`, `Required` `PICS, 9.5 Type id
/// and COT assignment`:
///
/// > Events without a time tag are transmitted in chronological order of
/// > occurrence to the Controlling station
///
/// DUT: the **controlled** station. Twenty successive values of one
/// information object (`M_SP_NA_1` at `0x4001`, toggling, untagged) occur:
/// ten before data transfer starts (the library's clause 5.3 queue) and ten
/// after (handed over by the application as they occur). 5-101 clause 7.2.2.2
/// (PDF page index 35): *"The transmission of successive values of a
/// particular INFORMATION OBJECT must always be in the chronological order in
/// which the values were measured."*
///
/// Expected: the twenty ASDUs arrive in the order the values occurred.
#[test]
fn clause_5_4_16_1_untagged_events_keep_their_chronological_order() {
    let values: Vec<Vec<u8>> = (0..20u32)
        .map(|i| single_point(0x4001, i % 2 == 1))
        .collect();
    // Distinct as a sequence: a reordering changes it, since the values alternate.
    let (before, after) = values.split_at(10);
    let (asdus, _) = controlled_sends(after.to_vec(), before.to_vec())
        .unwrap_or_else(|why| panic!("5.4.16.1: {why}"));
    let states: Vec<bool> = asdus
        .iter()
        .map(|asdu| {
            decode_asdu::<MSpNa1>(asdu).expect("an event")[0]
                .value
                .siq
                .spi
        })
        .collect();
    assert_eq!(
        states,
        (0..20).map(|i| i % 2 == 1).collect::<Vec<_>>(),
        "5.4.16.1: \"in chronological order of occurrence\""
    );
    assert_eq!(asdus, values, "5.4.16.1: the events as they occurred");
}

/// How many `M_SP_NA_1` objects fit one SQ = 0 ASDU: 104 clause 5 caps the
/// ASDU at 249 octets (*"The maximum length of the ASDU is limited to 249"*),
/// the data unit identifier takes 6 and each object 3 address octets + `SIQ` 1
/// (5-101 clause 7.3.1.1). `(249 - 6) / 4 = 60`, below 5-101 clause
/// 7.2.2.1's `N` limit of 127.
const MSP_PER_ASDU: usize = 60;

/// 604 Table 16, PDF page index 63 (printed 62), procedure **`5.4.16.1`**,
/// `Reference` `IEC 60870-5-3:1992, 5.1.5` / `IEC 60870-5-101:2003, 7.2.2.2`,
/// `Required` **`M`**:
///
/// > The Controlled station transmits events of the same Type, COT and priority
/// > but with gaps in their addresses as a Set of Information elements (SQ:=0)
/// > in one single ASDU, filled until the maximum configured ASDU or ADPU
/// > length as in the PICS
///
/// DUT: the **controlled** station. Seventy `M_SP_NA_1` events at the
/// addresses `0x4001, 0x4003, …` are pending at once (in the clause 5.3 queue
/// before STARTDT), packed by the library's set producer,
/// `Transmission::spontaneous_set`. The row wants them in SQ = 0 ASDUs filled
/// to the maximum: [`MSP_PER_ASDU`] objects in the first.
///
/// Before `tx` had the set producers it built one ASDU of `N = 1` per event,
/// and the first frame arrived with `N = 1` instead of 60.
#[test]
fn clause_5_4_16_1_events_with_gaps_are_packed_into_one_sq0_asdu() {
    let station = Transmission::controlled(
        StationFunctions {
            spontaneous: true,
            ..StationFunctions::NONE
        },
        ProjectList::empty(),
        CA,
        ORIGINATOR,
    );
    let objects: Vec<LayoutObject<MSpNa1>> = (0..70u32)
        .map(|i| LayoutObject {
            ioa: 0x4001 + 2 * i,
            value: MSpNa1 {
                siq: Siq {
                    spi: true,
                    ..Siq::default()
                },
            },
        })
        .collect();
    let events = station
        .spontaneous_set(&objects)
        .expect("the spontaneous set");
    let (app, _) = Scripted::sending(Vec::new());
    let station = ControlledStation::start_app(app, events).expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the peer connects");
    peer.start_data_transfer().expect("STARTDT");
    let (_, first) = peer.expect_i(deadline(5)).expect("the first ASDU");
    peer.close().expect("close");
    let _ = station.join();

    let header = Header::parse(&first).expect("the header");
    assert!(
        !header.sequence,
        "5.4.16.1: a set of events with gaps is SQ = 0"
    );
    assert_eq!(
        usize::from(header.count),
        MSP_PER_ASDU,
        "5.4.16.1: \"in one single ASDU, filled until the maximum\" ASDU length: 60 \
         M_SP_NA_1 objects fit 249 octets"
    );
    let ioas: Vec<u32> = decode_asdu::<MSpNa1>(&first)
        .expect("the ASDU decodes")
        .iter()
        .map(|object| object.ioa)
        .collect();
    assert_eq!(
        ioas,
        (0..MSP_PER_ASDU as u32)
            .map(|i| 0x4001 + 2 * i)
            .collect::<Vec<_>>(),
        "5.4.16.1: the first 60 events, in order, with their gaps"
    );
}

/// 604 Table 16, PDF page index 63 (printed 62), procedure **`5.4.16.1`**,
/// `Reference` `IEC 60870-5-3:1992, 5.1.5` / `IEC 60870-5-101:2003, 7.2.2.2`,
/// `Required` `PIXIT`:
///
/// > The Controlled station transmits events of the same type, COT and priority
/// > and with sequential addresses as a Sequence of Information elements
/// > (SQ:=1) in one single ASDU, filled until the maximum configured ASDU or
/// > ADPU length as in the PICS. Using SQ=1 is optional for a controlled
/// > station and a mandatory requirement for a controlling station
///
/// and the SQ:=0 row above, from the receiving side.
///
/// DUT: the **controlling** station, `tx::Transmission::controlling` over
/// `interop::Station`. The mock controlled peer sends two spontaneous
/// `M_SP_NA_1` ASDUs written octet by octet from 5-101 clause 7.2.2.1 (the
/// variable structure qualifier's SQ bit 8) and clause 7.3.1.1's element
/// (`SIQ`, `SPI` in bit 1): a set of three events with gaps (`0x4001`,
/// `0x4003`, `0x4009`: ON, OFF, ON) and a sequence of four (`0x5000` to
/// `0x5003`, *"incrementing continuously by +1"*: ON, ON, OFF, ON).
///
/// Expected: both are `tx::Reaction::Spontaneous`, and the station decodes
/// every address and value the peer sent.
#[test]
fn clause_5_4_16_1_the_controlling_station_takes_sets_and_sequences_of_events() {
    let set = vec![
        0x01, 0x03, 0x03, 0x00, 0x01, 0x00, // type 1, SQ = 0 N = 3, COT 3, OA 0, CA 1
        0x01, 0x40, 0x00, 0x01, // 0x4001 ON
        0x03, 0x40, 0x00, 0x00, // 0x4003 OFF
        0x09, 0x40, 0x00, 0x01, // 0x4009 ON
    ];
    let sequence = vec![
        0x01, 0x84, 0x03, 0x00, 0x01, 0x00, // type 1, SQ = 1 N = 4, COT 3, OA 0, CA 1
        0x00, 0x50, 0x00, // 0x5000
        0x01, 0x01, 0x00, 0x01, // ON ON OFF ON
    ];
    let (peer_app, _) = Scripted::sending(vec![set.clone(), sequence.clone()]);
    let peer = ControlledStation::start_app(peer_app, Vec::new()).expect("the mock binds");
    let mut station = started_controlling(&peer).expect("the controlling station starts");
    let asdus = station_i_frames(&mut station, 2, deadline(5)).expect("both ASDUs arrive");
    station.close().expect("close");
    let _ = peer.join();
    assert_eq!(asdus, vec![set, sequence], "the octets the mock sent");

    let dut = Transmission::controlling(CA, ORIGINATOR);
    let expected: [Vec<(u32, bool)>; 2] = [
        vec![(0x4001, true), (0x4003, false), (0x4009, true)],
        vec![
            (0x5000, true),
            (0x5001, true),
            (0x5002, false),
            (0x5003, true),
        ],
    ];
    for (asdu, expected) in asdus.iter().zip(expected) {
        let header = Header::parse(asdu).expect("the header");
        let known = Known::standard(&header, header.common_address == CA, true);
        let outcome = dut.on_response(asdu, &known).expect("the station takes it");
        assert_eq!(
            outcome.reaction,
            Reaction::Spontaneous {
                type_id: TypeId::MSpNa1
            },
            "5.4.16.1 (SQ = {}): events with COT=3",
            u8::from(header.sequence)
        );
        let stored: Vec<(u32, bool)> = decode_asdu::<MSpNa1>(asdu)
            .expect("the station decodes the events")
            .iter()
            .map(|object| (object.ioa, object.value.siq.spi))
            .collect();
        assert_eq!(
            stored,
            expected,
            "5.4.16.1 (SQ = {}): \"a mandatory requirement for a controlling station\"",
            u8::from(header.sequence)
        );
    }
}

/// 604 Table 16, PDF page index 63 (printed 62), procedure **`5.4.16.1`**, the
/// `M` rows *"The values of the object(s) transferred and stored on the
/// controlling station should represent the actual values on the controlled
/// station."* and *"The tests in this Table are performed correctly by each
/// ASDU in the PICS that supports COT=3, spontaneous"*, from the receiving
/// side.
///
/// DUT: the **controlling** station. The mock controlled peer sends one event
/// per type of [`event_types`], each written from 5-101 clause 7.3's geometry
/// for its type (`sample_object_area`) with a value octet of 1 and cause
/// `<3>`. Expected: each is `tx::Reaction::Spontaneous` of its type, and the
/// station decodes the address and the value the peer holds.
#[test]
fn clause_5_4_16_1_the_controlling_station_stores_every_spontaneous_type() {
    let types = event_types();
    let sent: Vec<Vec<u8>> = types
        .iter()
        .enumerate()
        .map(|(i, type_id)| {
            let mut area = sample_object_area(*type_id, 0x4000 + i as u32);
            area[3] = 1;
            asdu_with_body(*type_id, Cause::Spontaneous.to_u8(), CA, &area)
        })
        .collect();
    let (peer_app, _) = Scripted::sending(sent.clone());
    let peer = ControlledStation::start_app(peer_app, Vec::new()).expect("the mock binds");
    let mut station = started_controlling(&peer).expect("the controlling station starts");
    let asdus = station_i_frames(&mut station, sent.len(), deadline(5)).expect("every event");
    station.close().expect("close");
    let _ = peer.join();
    assert_eq!(asdus, sent, "the octets the mock sent, in order");

    let dut = Transmission::controlling(CA, ORIGINATOR);
    for (i, (asdu, type_id)) in asdus.iter().zip(&types).enumerate() {
        let header = Header::parse(asdu).expect("the header");
        let known = Known::standard(&header, header.common_address == CA, true);
        assert_eq!(
            dut.on_response(asdu, &known)
                .expect("the station takes it")
                .reaction,
            Reaction::Spontaneous {
                type_id: header.type_id
            },
            "5.4.16.1 (type {type_id}): an event with COT=3"
        );
        let stored =
            visit_monitor_layout(*type_id, &mut Stored { asdu, marker: 1 }).expect("a layout");
        assert_eq!(
            stored,
            Ok(vec![0x4000 + i as u32]),
            "5.4.16.1 (type {type_id}): the values stored represent the peer's"
        );
    }
}

/// Two times of occurrence: Friday 2026-09-25, 12:00:00.000 and 12:00:01.500
/// (5-101 clause 7.2.6.18: milliseconds of the minute, then minutes, hours, day
/// of month with day of week, months, years).
const fn occurrences() -> [Cp56Time2a; 2] {
    let first = crate::conformance604::sample_time();
    [
        first,
        Cp56Time2a {
            milliseconds: 1_500,
            ..first
        },
    ]
}

/// 604 Table 16, PDF page index 63 (printed 62), procedure **`5.4.16.1`**,
/// `Required` `M`:
///
/// > The time label in ASDUs with a time tag represents the time of occurrence
/// > (plausibility test)
///
/// DUT: the **controlled** station. Two events of one object occur at the two
/// [`occurrences`] and are built by `tx::spontaneous` as `M_SP_TB_1` (the
/// `CP56Time2a` form 104 clause 9 permits). The time of occurrence is the
/// application's to supply (`tx` reads no clock); the library's share is to
/// carry it unchanged. Expected: each label on the wire is its event's time of
/// occurrence octet for octet (5-101 clause 7.2.6.18: `00 00 00 0C B9 09 1A`
/// for the first; day of month 25 with day of week 5 in bits 6..8 is `0xB9`),
/// valid (`IV` = 0), and the second is 1.5 s after the first.
#[test]
fn clause_5_4_16_1_the_time_label_is_the_time_of_occurrence() {
    let station = events_station();
    let frames: Vec<Vec<u8>> = occurrences()
        .iter()
        .enumerate()
        .map(|(i, time)| {
            let object = LayoutObject {
                ioa: 0x4001,
                value: MSpTb1 {
                    siq: Siq {
                        spi: i == 0,
                        ..Siq::default()
                    },
                    time: *time,
                },
            };
            station.spontaneous(&object).expect("an event frame")
        })
        .collect();
    let (asdus, _) = controlled_sends(frames, Vec::new()).unwrap_or_else(|why| panic!("{why}"));

    let labels: Vec<&[u8]> = asdus.iter().map(|asdu| &asdu[asdu.len() - 7..]).collect();
    assert_eq!(
        labels[0],
        [0x00, 0x00, 0x00, 0x0C, 0xB9, 0x09, 0x1A],
        "5.4.16.1: the label is the time of occurrence, 2026-09-25 12:00:00.000"
    );
    assert_eq!(
        labels[1],
        [0xDC, 0x05, 0x00, 0x0C, 0xB9, 0x09, 0x1A],
        "5.4.16.1: the second event occurred 1500 ms later"
    );
    for asdu in &asdus {
        let event = decode_asdu::<MSpTb1>(asdu).expect("an event")[0];
        assert!(!event.value.time.invalid, "5.4.16.1: a valid label, IV = 0");
        assert_eq!(read_ioa(&asdu[Header::LEN..]).expect("an address"), 0x4001);
    }
}

/// 604 Table 16, PDF page index 63 (printed 62), procedure **`5.4.16.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.3.4.4.` / `IEC 60870-5-101:2003,
/// 7.4.3`, `Required` `PICS, 9.5 Type id and COT assignment: COT 3 / ASDU 103`:
///
/// > The Controlled station sends a spontaneous clock synchronisation message
/// > with COT=3 to indicate its internal date and hour shift immediately after
/// > the hour shift or before sending subsequent ASDUs with short time tag
///
/// and the next row, *"The time label in the clock synchronization message
/// from the Controlled station represents the time of occurrence (plausibility
/// test)"*, `Required` the same PICS cell.
///
/// **Not applicable to a 104 station**: the PICS cell the rows depend on is
/// black in 104's interoperability list (clause 9, *"Black boxes: option not
/// permitted in this companion standard"*), and 104 clause 7.6's service table
/// has only `C_CS ACT` and `C_CS ACTCON`. What the case drives is that reading:
/// the mock controlled peer sends the message anyway (type 103, cause 3,
/// address 0, 5-101 figure 75 at index 107) and the **controlling** station,
/// on `interop::InteropProfile::conventional` (the 104 sheet's own selection),
/// classifies it with `cs::ClockSynchronisation::controlling` as 5-101 clause
/// 7.2.3's unknown cause: ignored, nothing sent back.
#[test]
fn clause_5_4_16_1_a_spontaneous_clock_time_is_not_a_104_message() {
    // Type 103, SQ = 0 N = 1, COT 3, OA 0, CA 1, IOA 0, CP56Time2a 2026-09-25 13:00:00.000.
    let announcement = vec![
        103, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0xB9, 0x09,
        0x1A,
    ];
    let (peer_app, _) = Scripted::sending(vec![announcement.clone()]);
    let peer = ControlledStation::start_app(peer_app, Vec::new()).expect("the mock binds");
    let mut station = started_controlling(&peer).expect("the controlling station starts");
    let asdus = station_i_frames(&mut station, 1, deadline(5)).expect("the message arrives");
    assert_eq!(asdus, vec![announcement]);
    let sent_before = station.sent.len();
    let outcome = {
        let header = Header::parse(&asdus[0]).expect("the header");
        let known = Known::for_profile(&InteropProfile::conventional(), &header, true, true);
        ClockSynchronisation::controlling(CA, ORIGINATOR)
            .on_response(&asdus[0], &known)
            .expect("the station takes it")
    };
    station.close().expect("close");
    let _ = peer.join();
    assert_eq!(
        outcome.reaction,
        CsReaction::Discard(Discard::Unspecified(Unspecified::CauseOfTransmission)),
        "5.4.16.1: <103> with COT 3 is a black box of 104 clause 9"
    );
    assert!(outcome.send.is_empty(), "an ignored ASDU is not answered");
    assert_eq!(station.sent.len(), sent_before, "nothing went back");
}
