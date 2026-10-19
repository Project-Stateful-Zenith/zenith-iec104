//! 604 Table 17, *"General interrogation function conformance test
//! procedures"*, PDF page indices 64–68 (printed 63–67), procedures
//! `5.4.17.1` … `5.4.17.60`: the **controlled**-station cases. The
//! controlling-station cases are in `table17_controlling.rs`, the harness in
//! `table17_support.rs`.
//!
//! # The procedure numbers
//!
//! Table 17 prints `5.4.17.1`, `5.4.17.10`, `5.4.17.50` and `5.4.17.60` in its
//! `No.` column; its three re-activation blocks (pages 3 and 4 of 5, indices 66
//! and 67) carry no number there. Their numbers come from the results table,
//! Table 27 (5 of 7), PDF page index 94 (printed 93): *"5.4.17.20 Re-activate a
//! running Outstation interrogation – Option 1: the running GI continues."*,
//! *"5.4.17.30 … Option 2: the running GI is stopped and the second GI is
//! started"* and *"5.4.17.40 … Option 3: the running GI continues and after
//! activation termination (COT=10) the second GI is started."*
//!
//! # Coverage, row by row
//!
//! | Procedure | Row | Controlled (here) | Controlling |
//! | --- | --- | --- | --- |
//! | `5.4.17.1` | `C_IC_ACT` on ENDINIT / loss of link / manually | n/a (the controlling station's rule) | ENDINIT, loss of link, manual |
//! | `5.4.17.1` | ACTCON when ready | yes | yes |
//! | `5.4.17.1` | `ACTCONneg` when not ready, may be repeated | yes | yes |
//! | `5.4.17.1` | all objects of the QOI with COT 20–36 | yes | yes |
//! | `5.4.17.1` | GI data without time stamp | yes | yes (the objects are read as untagged types) |
//! | `5.4.17.1` | SQ = 0 up to the ASDU length (`M`) | yes, see below | yes |
//! | `5.4.17.1` | SQ = 1 up to the ASDU length (`PIXIT`) | yes, see below | yes |
//! | `5.4.17.1` | ACTTERM after all configured data | yes | yes |
//! | `5.4.17.1` | an event during the GI updates the GI value | yes | end to end |
//! | `5.4.17.1` | stored values represent the actual values | n/a | end to end |
//! | `5.4.17.1` | every ASDU of the PICS with COT 20–36 | yes, all 12 | yes, all 12 |
//! | `5.4.17.1` | at least 3 groups | groups 1, 8, 16 | groups 1, 8, 16 |
//! | `5.4.17.10` | broadcast CASDU, every LRU answers with its own CASDU | yes | yes (a deviation this case found, fixed in `gi`) |
//! | `5.4.17.10` | an LRU's `ACTCONneg`, repeated to that LRU | yes | not driven yet (`gi` now tracks each LRU of a broadcast) |
//! | `5.4.17.10` | an LRU's ENDINIT, GI to that LRU (`PIXIT`) | n/a (ENDINIT is Table 12) | yes |
//! | `5.4.17.10` | broadcast group interrogation, 3 groups | yes | not driven yet, as above |
//! | `5.4.17.20` | option 1 | yes | yes |
//! | `5.4.17.30` | option 2 | yes | yes |
//! | `5.4.17.40` | option 3 | yes | yes |
//! | `5.4.17.50` | deactivation | yes | yes |
//! | `5.4.17.60` | compatibility with other test cases | no case: it is the whole suite, as for every table (see `tests/conformance_604.rs`) | |
//!
//! # What is the application's, and therefore not verified here
//!
//! The crate's controlled station answers through `gi::Interrogation` over the
//! caller's `gi::DataSource`. Which objects belong to which group, and how the
//! objects are **packed** into ASDUs, is project data the `DataSource` supplies
//! (the module doc of `gi`: *"Which objects belong to group 3 is project data"*).
//! So for the two packing rows:
//!
//! - *"filled up to"* the maximum length is the application's choice of how
//!   many objects it puts in one ASDU. The case below packs as a conforming
//!   application would and checks that the crate forwards the packed ASDUs
//!   unchanged and in order;
//! - *"but not exceeding"* the maximum is the crate's: the layout layer refuses
//!   an ASDU over 104 clause 5's 249 octets, so a `DataSource` cannot build one.
//!   The case asserts that refusal for one object more than fits;
//! - *"of the same Type, COT and priority"*: 104 clause 7.2 (index 64) removes
//!   the link classes (*"Request of user data class 1 and 2 are link functions
//!   of IEC 60870-5-2 and therefore not available in this standard."*), so the
//!   crate has no priority to group by.
//!
//! Likewise the send **order** of the spontaneous event and the GI data (*"With
//! single transfer, buffered time tagged events are transmitted from the
//! Controlled station before GI data"*) is the caller's: `tx`'s module doc
//! says *"Nothing in this module is scheduled, so that order is the caller's to
//! apply."* The event case therefore checks the crate's part, that the GI
//! reports the value the process image holds when the data is produced, not the
//! one it held at the activation.
//!
//! *"loss of link (unsuccessful repetitions of the link layer)"* is a 5-101
//! notion; over 104 it is the loss of the TCP connection, which is how the
//! controlling case drives it.
//!
//! # Direction
//!
//! §5.1 (index 10) swaps the roles for the reverse direction; every row that
//! names one role is driven for the other one in `table17_controlling.rs`,
//! except those that only one role can act out (the controlling station's
//! triggers, the controlled station's packing). None of the frames here uses
//! causes 44–47.

use crate::conformance604::table17_support::{
    BROADCAST, COT_ACT, COT_ACTCON, COT_ACTTERM, COT_DEACT, COT_DEACTCON, COT_SPONT, GiPeer,
    GiStation, IcFrame, Image, Point, QOI_STATION, SharedImage, c_ic, ic_frame, is_actterm,
    objects_of, qoi_group,
};
use crate::conformance604::{CA, ControlledStation, sample_time};
use iec104::asdu::{
    Cause, Header, LayoutObject, MMeNb1, MSpTb1, Qds, Siq, Sva, TypeId, encode_asdu,
};
use iec104::gi::{ReActivation, Scope};

/// 5-101 clause 7.4.5 (PDF page index 123): *"In response to a station
/// interrogation request, these information objects are reported in type
/// identifications <1>, <3>, <5>, <7>, <9>, <11>, <13>, <20> or <21>."*, and
/// 5-101 clauses 7.3.5.1–7.3.5.3 (PDF page indices 110–112) list the causes
/// `<20>` … `<36>` for the parameters of measured values `<110>`, `<111>`,
/// `<112>`. These twelve are every ASDU of this station's PICS that carries
/// causes 20–36. All are untagged.
const INTERROGATED: [u8; 12] = [1, 3, 5, 7, 9, 11, 13, 20, 21, 110, 111, 112];

/// 104 clause 5 (PDF page index 26): *"The maximum length of the ASDU is
/// limited to 249"*.
const MAX_ASDU: usize = 249;

/// The ASDU header of the conventional 104 profile: type 1 + VSQ 1 + COT 2 +
/// common address 2 (104 clause 9, the fixed sizes of the profile).
const HEADER: usize = 6;

/// The information object address of 104's profile: three octets.
const IOA_LEN: usize = 3;

/// `M_ME_NB_1`'s element, `SVA` (2 octets, 5-101 clause 7.2.6.7) + `QDS` (1
/// octet, 7.2.6.3): 5-101 clause 7.3.1.11 (PDF page index 72).
const SCALED_LEN: usize = 3;

/// A single-point object (`M_SP_NA_1`, `SIQ` 5-101 clause 7.2.6.1: bit 1 is
/// `SPI`, so `0x01` is ON).
fn single(ioa: u32, on: bool, groups: &[u8]) -> Point {
    Point {
        ioa,
        type_id: 1,
        element: vec![u8::from(on)],
        groups: groups.to_vec(),
    }
}

/// A double-point object (`M_DP_NA_1`, `DIQ` 5-101 clause 7.2.6.2: `<2>` is
/// ON).
fn double(ioa: u32, groups: &[u8]) -> Point {
    Point {
        ioa,
        type_id: 3,
        element: vec![0x02],
        groups: groups.to_vec(),
    }
}

/// A scaled measured value (`M_ME_NB_1`, `SVA` little-endian then `QDS`).
fn scaled(ioa: u32, value: i16, groups: &[u8]) -> Point {
    let v = value.to_le_bytes();
    Point {
        ioa,
        type_id: 11,
        element: vec![v[0], v[1], 0x00],
        groups: groups.to_vec(),
    }
}

/// A `C_IC_NA_1` read back from the wire, or a panic naming the case.
fn ic(what: &str, asdu: &[u8]) -> IcFrame {
    ic_frame(asdu).unwrap_or_else(|| panic!("{what}: a C_IC_NA_1 expected, got {asdu:02x?}"))
}

/// The expected `C_IC_NA_1` fields: figure 72 (5-101 clause 7.3.4.1, PDF page
/// index 105) prints `INFORMATION OBJECT ADDRESS = 0`.
const fn expect_ic(cause: u8, negative: bool, ca: u16, qoi: u8) -> IcFrame {
    IcFrame {
        cause,
        negative,
        ca,
        ioa: 0,
        qoi,
    }
}

/// Asserts one interrogated object's ASDU: its type, its cause, its common
/// address, and an object area of exactly `(ioa, element)`.
fn assert_object(what: &str, asdu: &[u8], point: &Point, cause: u8, ca: u16) {
    let header = Header::parse(asdu).expect("an object's header");
    assert_eq!(header.type_id.to_u8(), point.type_id, "{what}: the type");
    assert_eq!(header.cause.to_u8(), cause, "{what}: the cause (20–36)");
    assert_eq!(header.common_address, ca, "{what}: the common address");
    assert!(
        INTERROGATED.contains(&point.type_id),
        "{what}: \"The Controlled station sends GI data in ASDUs without time stamp\""
    );
    assert_eq!(
        objects_of(asdu).expect("the object area"),
        vec![(point.ioa, point.element.clone())],
        "{what}: the object"
    );
}

/// A station of one LRU at [`CA`] with `points`, released or held.
fn station(
    policy: ReActivation,
    points: Vec<Point>,
    release: bool,
) -> (
    ControlledStation,
    GiPeer,
    SharedImage,
    std::sync::Arc<crate::conformance604::table17_support::Controls>,
) {
    let image = SharedImage::new(Image::new(CA, points));
    let (app, controls) = GiStation::new(policy, std::slice::from_ref(&image), release);
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let peer = GiPeer::start(station.addr()).expect("the controlling station starts");
    (station, peer, image, controls)
}

/// 604 Table 17 (1 of 5), PDF page index 64 (printed 63), procedure
/// **`5.4.17.1`**, *"General interrogation – Outstation interrogation - one
/// Logical Remote Unit (LRU) available in the controlled station"*, the `M`
/// rows `Reference` `IEC 60870-5-101:2003, 7.4.5`:
///
/// > The Controlled station mirrors the Interrogation Command with COT = 7,
/// > C_IC_ACTCON to the Controlling station if the Controlled station is ready
/// > to return the interrogation information
///
/// > All Information Objects that are part of the initiated GI with that QOI are
/// > sent with the corresponding COT (20-36) to the Controlling station
///
/// > The Controlled station sends GI data in ASDUs without time stamp
///
/// > The Controlled station sends an Interrogation Command with COT = 10,
/// > C_IC_ACTTERM, to the Controlling station after all configured GI data is
/// > sent
///
/// DUT: the **controlled** station. Expected values: the `C_IC_NA_1` octets of
/// 5-101 figure 72 (index 105) with `QOI` `<20>` (clause 7.2.6.22, index 53),
/// the object cause `<20>` inrogen (clause 7.2.3 table 14, index 41), and the
/// station's configured objects.
#[test]
fn clause_5_4_17_1_a_station_interrogation_is_confirmed_answered_and_terminated() {
    let points = vec![
        single(0x0101, true, &[]),
        double(0x0102, &[]),
        scaled(0x0103, 1234, &[]),
    ];
    let (station, mut peer, _, _) = station(ReActivation::Continue, points.clone(), true);

    peer.send(&c_ic(COT_ACT, false, CA, QOI_STATION))
        .expect("the C_IC ACT goes out");
    let answer = peer
        .until(|asdu| is_actterm(asdu, CA))
        .expect("the interrogation ends with its ACTTERM");
    let trailing = peer.quiet(200);
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");

    assert_eq!(
        answer.len(),
        points.len() + 2,
        "5.4.17.1: ACTCON, every configured object, ACTTERM: {answer:02x?}"
    );
    assert_eq!(
        ic("5.4.17.1", &answer[0]),
        expect_ic(COT_ACTCON, false, CA, QOI_STATION),
        "5.4.17.1: \"mirrors the Interrogation Command with COT = 7, C_IC_ACTCON\""
    );
    for (asdu, point) in answer[1..=points.len()].iter().zip(&points) {
        assert_object("5.4.17.1", asdu, point, 20, CA);
    }
    assert_eq!(
        ic("5.4.17.1", answer.last().expect("the last frame")),
        expect_ic(COT_ACTTERM, false, CA, QOI_STATION),
        "5.4.17.1: \"C_IC_ACTTERM … after all configured GI data is sent\""
    );
    assert!(
        trailing.is_empty(),
        "5.4.17.1: nothing follows the termination: {trailing:02x?}"
    );
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `M`,
/// `Reference` `IEC 60870-5-101:2003, 7.4.5`:
///
/// > The Controlled station mirrors the Interrogation Command with COT = 7,
/// > C_IC_ACTCONneg to the Controlling station if the Controlled station is NOT
/// > ready to return the interrogation information. In this case, the
/// > Controlling station may repeat the command
///
/// DUT: the **controlled** station, whose `DataSource` is not ready at first.
/// Expected values: figure 72's frame with cause 7 and `P/N = 1`, then, once
/// ready, the repeated command answered as in the case above (5-101 clause
/// 7.4.5, index 124: *"In this case, the station interrogation command may be
/// repeated."*).
#[test]
fn clause_5_4_17_1_a_station_not_ready_confirms_negatively_and_the_command_may_be_repeated() {
    let points = vec![single(0x0201, true, &[])];
    let (station, mut peer, image, _) = station(ReActivation::Continue, points.clone(), true);
    image.lock().ready = false;

    peer.send(&c_ic(COT_ACT, false, CA, QOI_STATION))
        .expect("the first act");
    let first = peer.take(1).expect("the negative confirmation");
    let silence = peer.quiet(200);
    assert_eq!(
        ic("5.4.17.1", &first[0]),
        expect_ic(COT_ACTCON, true, CA, QOI_STATION),
        "5.4.17.1: \"C_IC_ACTCONneg … if the Controlled station is NOT ready\""
    );
    assert!(
        silence.is_empty(),
        "5.4.17.1: a refused interrogation returns no data and no ACTTERM: {silence:02x?}"
    );

    image.lock().ready = true;
    peer.send(&c_ic(COT_ACT, false, CA, QOI_STATION))
        .expect("the repeated act");
    let answer = peer
        .until(|asdu| is_actterm(asdu, CA))
        .expect("the repeated interrogation runs to its end");
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");

    assert_eq!(
        ic("5.4.17.1", &answer[0]),
        expect_ic(COT_ACTCON, false, CA, QOI_STATION),
        "5.4.17.1: \"the Controlling station may repeat the command\", now confirmed"
    );
    assert_eq!(
        answer.len(),
        3,
        "ACTCON, the object, ACTTERM: {answer:02x?}"
    );
    assert_object("5.4.17.1", &answer[1], &points[0], 20, CA);
}

/// `n` scaled values in one ASDU with the station cause 20, as an application
/// packs them: `SQ = 0` with each object's own address, or `SQ = 1` with the
/// first address only (5-101 clause 7.2.2.1, PDF page indices 34–35).
fn packed(sequence: bool, ioas: &[u32], value: impl Fn(usize) -> i16) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MMeNb1,
        sequence,
        count: ioas.len() as u8,
        cause: Cause::InterrogatedByStation,
        negative: false,
        test: false,
        originator: 0,
        common_address: CA,
    };
    let objects: Vec<LayoutObject<MMeNb1>> = ioas
        .iter()
        .enumerate()
        .map(|(i, ioa)| LayoutObject {
            ioa: *ioa,
            value: MMeNb1 {
                sva: Sva { value: value(i) },
                qds: Qds::default(),
            },
        })
        .collect();
    encode_asdu(&header, &objects).expect("the layout builds what fits")
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**,
/// `Reference` `IEC 60870-5-3:1992, 5.1.5` and `IEC 60870-5-101:2003, 7.2.2.2`,
/// `Required` `M`:
///
/// > The Controlled station transmits Interrogated process information data of
/// > the same Type, COT and priority but with gaps in their addresses as a Set
/// > of Information elements (SQ:=0) in one single ASDU, filled up to but not
/// > exceeding the maximum configured ASDU or APDU length as in the PICS.
///
/// and the same row with `Required` `PIXIT`:
///
/// > The Controlled station transmits Interrogated process information data of
/// > the same type, COT and priority and with sequential addresses as a
/// > Sequence of Information elements (SQ:=1) in one single ASDU, filled up to
/// > but not exceeding the maximum configured ASDU or APDU length as in the
/// > PICS.
///
/// DUT: the **controlled** station. The packing is the application's (see the
/// module doc); the crate's part is that the packed ASDUs reach the wire
/// unchanged and in order, and that its layout layer refuses one object more
/// than fits. Expected values, all from the standard: 249 octets (104 clause
/// 5, index 26), the 6-octet header and 3-octet address of the 104 profile, and
/// `M_ME_NB_1`'s 3-octet element (5-101 clause 7.3.1.11). So `SQ = 0` holds
/// `(249 − 6) / (3 + 3)` = 40 objects in 246 octets (a 41st would need 252),
/// and `SQ = 1` holds `(249 − 6 − 3) / 3` = 80 elements in exactly 249 octets.
#[test]
fn clause_5_4_17_1_interrogated_data_is_packed_as_sq0_and_sq1_up_to_the_asdu_limit() {
    let per_object = IOA_LEN + SCALED_LEN;
    let n0 = (MAX_ASDU - HEADER) / per_object;
    let n1 = (MAX_ASDU - HEADER - IOA_LEN) / SCALED_LEN;
    assert_eq!(
        (n0, n1),
        (40, 80),
        "the arithmetic of 104 cl.5 and 101 cl.7.3.1.11"
    );

    // SQ = 0: addresses with gaps. SQ = 1: consecutive addresses from 0x0400.
    let gapped: Vec<u32> = (0..n0 as u32).map(|i| 0x0100 + 2 * i).collect();
    let sequential: Vec<u32> = (0..n1 as u32).map(|i| 0x0400 + i).collect();
    let set = packed(false, &gapped, |i| i as i16 * 10);
    let sequence = packed(true, &sequential, |i| -(i as i16));
    assert_eq!(set.len(), HEADER + n0 * per_object);
    assert_eq!(sequence.len(), MAX_ASDU);

    // "not exceeding": one object more is refused by the layout layer, so no
    // application can hand the procedure an ASDU over 249 octets.
    let too_many: Vec<u32> = (0..=n0 as u32).map(|i| 0x0100 + 2 * i).collect();
    let too_long: Vec<u32> = (0..=n1 as u32).map(|i| 0x0400 + i).collect();
    for (sq, ioas) in [(false, &too_many), (true, &too_long)] {
        let header = Header {
            type_id: TypeId::MMeNb1,
            sequence: sq,
            count: ioas.len() as u8,
            cause: Cause::InterrogatedByStation,
            negative: false,
            test: false,
            originator: 0,
            common_address: CA,
        };
        let objects: Vec<LayoutObject<MMeNb1>> = ioas
            .iter()
            .map(|ioa| LayoutObject {
                ioa: *ioa,
                value: MMeNb1 {
                    sva: Sva { value: 0 },
                    qds: Qds::default(),
                },
            })
            .collect();
        assert!(
            encode_asdu(&header, &objects).is_err(),
            "5.4.17.1: \"not exceeding the maximum\": SQ = {} with {} objects is refused",
            u8::from(sq),
            ioas.len()
        );
    }

    let mut image = Image::new(CA, Vec::new());
    image.blocks = vec![
        (Scope::Station, set.clone()),
        (Scope::Station, sequence.clone()),
    ];
    let image = SharedImage::new(image);
    let (app, _) = GiStation::new(ReActivation::Continue, &[image], true);
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let mut peer = GiPeer::start(station.addr()).expect("start");
    peer.send(&c_ic(COT_ACT, false, CA, QOI_STATION))
        .expect("the act");
    let answer = peer.until(|asdu| is_actterm(asdu, CA)).expect("the GI");
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");

    assert_eq!(answer.len(), 4, "ACTCON, two packed ASDUs, ACTTERM");
    assert_eq!(
        answer[1], set,
        "5.4.17.1: the SQ = 0 ASDU reaches the wire as packed"
    );
    assert_eq!(
        answer[2], sequence,
        "5.4.17.1: the SQ = 1 ASDU reaches the wire as packed"
    );
    let h0 = Header::parse(&answer[1]).expect("header");
    let h1 = Header::parse(&answer[2]).expect("header");
    assert!(!h0.sequence && usize::from(h0.count) == n0);
    assert!(h1.sequence && usize::from(h1.count) == n1);
    assert!(
        answer[1].len() <= MAX_ASDU && answer[1].len() + per_object > MAX_ASDU,
        "5.4.17.1: SQ = 0 \"filled up to but not exceeding\" 249 octets: {}",
        answer[1].len()
    );
    assert!(
        answer[2].len() <= MAX_ASDU && answer[2].len() + SCALED_LEN > MAX_ASDU,
        "5.4.17.1: SQ = 1 \"filled up to but not exceeding\" 249 octets: {}",
        answer[2].len()
    );
    let seq_ioas: Vec<u32> = objects_of(&answer[2])
        .expect("the SQ = 1 area")
        .into_iter()
        .map(|(ioa, _)| ioa)
        .collect();
    assert_eq!(
        seq_ioas, sequential,
        "5-101 cl.7.2.2.1: \"numbers incrementing continuously by +1\""
    );
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `M`,
/// `Reference` `IEC 60870-5-101:2003, 7.4.5` / `7.2.2.2`:
///
/// > GI messages contain actual status information. Test by sending an event
/// > during the GI before the corresponding GI message. The value in the GI
/// > should be updated. With single transfer, buffered time tagged events are
/// > transmitted from the Controlled station before GI data
///
/// DUT: the **controlled** station. The interrogation is confirmed while the
/// object is OFF; the process then changes it to ON and the application sends
/// the time-tagged event (`M_SP_TB_1` from `tx::spontaneous`, cause `<3>`)
/// before it releases the GI data. Expected values: the event's `SIQ` ON and
/// the GI object's `SIQ` ON (the updated value, not the OFF of the
/// activation), the event before the GI message.
#[test]
fn clause_5_4_17_1_an_event_during_the_interrogation_updates_its_value() {
    let ioa = 0x0301;
    let (station, mut peer, image, controls) = station(
        ReActivation::Continue,
        vec![single(ioa, false, &[]), scaled(0x0302, 7, &[])],
        false,
    );
    peer.send(&c_ic(COT_ACT, false, CA, QOI_STATION))
        .expect("the act");
    let confirmation = peer.take(1).expect("the confirmation");
    assert_eq!(
        ic("5.4.17.1", &confirmation[0]),
        expect_ic(COT_ACTCON, false, CA, QOI_STATION)
    );

    // The event: the process image changes, and the application reports it.
    image.lock().set(ioa, &[0x01]);
    let event = iec104::tx::spontaneous(
        &LayoutObject {
            ioa,
            value: MSpTb1 {
                siq: Siq {
                    spi: true,
                    ..Siq::default()
                },
                time: sample_time(),
            },
        },
        CA,
        0,
    )
    .expect("tx builds the event");
    controls.push_event(event.clone());
    controls.release();

    let rest = peer
        .until(|asdu| is_actterm(asdu, CA))
        .expect("the GI completes");
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");

    let at = |pred: &dyn Fn(&Header) -> bool| {
        rest.iter()
            .position(|asdu| pred(&Header::parse(asdu).expect("header")))
    };
    let event_at = at(&|h| h.cause.to_u8() == COT_SPONT).expect("the event is sent");
    let gi_at = at(&|h| h.type_id == TypeId::MSpNa1).expect("the GI object is sent");
    assert_eq!(rest[event_at], event, "the event goes out as tx built it");
    assert!(
        event_at < gi_at,
        "5.4.17.1: \"buffered time tagged events are transmitted … before GI data\""
    );
    assert_object(
        "5.4.17.1: \"The value in the GI should be updated\"",
        &rest[gi_at],
        &single(ioa, true, &[]),
        20,
        CA,
    );
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `M`,
/// `Reference` `IEC 60870-5-101:2003, 8.5, 8.6`:
///
/// > The tests in this table are performed correctly by every ASDU in the PICS
/// > that supports the applicable COT=20-36
///
/// DUT: the **controlled** station, with one object of each of the twelve types
/// of [`INTERROGATED`] (their source is on the constant). Expected values:
/// each object on the wire with its own type, cause `<20>` and element.
#[test]
fn clause_5_4_17_1_every_asdu_with_causes_20_to_36_is_interrogated() {
    let points: Vec<Point> = INTERROGATED
        .iter()
        .enumerate()
        .map(|(i, type_id)| Point {
            ioa: 0x0500 + i as u32,
            type_id: *type_id,
            element: vec![
                i as u8 + 1;
                iec104::asdu::element_len(TypeId::from_u8(*type_id))
                    .expect("an element length")
            ],
            groups: Vec::new(),
        })
        .collect();
    let (station, mut peer, _, _) = station(ReActivation::Continue, points.clone(), true);
    peer.send(&c_ic(COT_ACT, false, CA, QOI_STATION))
        .expect("the act");
    let answer = peer.until(|asdu| is_actterm(asdu, CA)).expect("the GI");
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");

    assert_eq!(answer.len(), INTERROGATED.len() + 2, "{answer:02x?}");
    for (asdu, point) in answer[1..=INTERROGATED.len()].iter().zip(&points) {
        assert_object(
            &format!("5.4.17.1 (type {})", point.type_id),
            asdu,
            point,
            20,
            CA,
        );
    }
}

/// The objects of the group cases and their membership (project data): the
/// expected answer of each group is read off this table.
fn grouped_points() -> Vec<Point> {
    vec![
        single(0x0601, true, &[1]),
        scaled(0x0608, 80, &[8]),
        double(0x0610, &[16]),
        single(0x0611, false, &[1, 16]),
        scaled(0x0620, -5, &[]),
    ]
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.4.5` / `7.2.6.22`, `Required` `PICS,
/// 9.6 Station interrogation`:
///
/// > The tests in this Table are performed correctly for supported General
/// > Interrogation groups: The Controlling station sends an Interrogation
/// > Command (ASDU 100) with COT = 6, C_IC_ACT, to the Controlled station with
/// > QOI=21...36 (group 1...16).
/// > At least 3 groups need to be tested (unless only 1 or 2 groups are
/// > supported).
///
/// DUT: the **controlled** station, groups 1, 8 and 16 (`QOI` 21, 28, 36).
/// Expected values: 5-101 clause 7.2.6.22 (index 53) for the `QOI`, table 14
/// (index 41) for the causes `<21>`, `<28>`, `<36>`, and [`grouped_points`]'s
/// membership for which objects each group returns.
#[test]
fn clause_5_4_17_1_three_groups_are_interrogated_with_their_own_qoi_and_cause() {
    let points = grouped_points();
    let (station, mut peer, _, _) = station(ReActivation::Continue, points.clone(), true);
    for group in [1u8, 8, 16] {
        let qoi = qoi_group(group);
        peer.send(&c_ic(COT_ACT, false, CA, qoi)).expect("the act");
        let answer = peer.until(|asdu| is_actterm(asdu, CA)).expect("the GI");
        let what = format!("5.4.17.1 (group {group})");
        assert_eq!(
            ic(&what, &answer[0]),
            expect_ic(COT_ACTCON, false, CA, qoi),
            "{what}: the confirmation carries the group's QOI"
        );
        assert_eq!(
            ic(&what, answer.last().expect("last")),
            expect_ic(COT_ACTTERM, false, CA, qoi),
            "{what}: the termination carries the group's QOI"
        );
        let members: Vec<&Point> = points
            .iter()
            .filter(|p| p.groups.contains(&group))
            .collect();
        assert_eq!(
            answer.len(),
            members.len() + 2,
            "{what}: exactly the group's objects: {answer:02x?}"
        );
        for (asdu, point) in answer[1..=members.len()].iter().zip(members) {
            assert_object(&what, asdu, point, 20 + group, CA);
        }
    }
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");
}

/// 604 Table 17 (2 of 5), PDF page index 65 (printed 64), procedure
/// **`5.4.17.10`**, *"General interrogation – Outstation interrogation - more
/// than one Logical Remote Unit (LRU) available in the controlled station"*,
/// `M` for systems with the functionality in the PIXIT, `Reference`
/// `IEC 60870-5-101:2003, 7.4.5`:
///
/// > Every LRU mirrors the Interrogation Command with COT = 7, C_IC_ACTCON to
/// > the Controlling station, containing its configured CASDU address
///
/// > It may be possible that one or more LRU(s) mirrors the Interrogation
/// > Command with COT = 7, C_IC_ACTCONneg to the Controlling station (e.g. if
/// > the LRU(s) is not ready to return the interrogated information),
/// > containing its configured CASDU address. Then, the controlling station
/// > starts the normal GI procedure (for one LRU available) containing the
/// > CASDU address of that/those LRU(s) and finishes correctly the GI for every
/// > LRU as described
///
/// > All Information Objects that are part of the initiated GI with that QOI
/// > are sent with the corresponding COT (20-36) to the Controlling station for
/// > every LRU, containing its configured CASDU address
///
/// > The Controlled station sends an Interrogation Command with COT = 10,
/// > C_IC_ACTTERM, for every LRU to the Controlling station after all
/// > configured GI data of that LRU is sent, containing its configured CASDU
/// > address
///
/// DUT: the **controlled** station with two LRUs, common addresses 1 and 2,
/// each its own `gi::Interrogation::controlled`. LRU 2 is not ready for the
/// broadcast (`FFFF`) interrogation and is interrogated again at its own
/// address. Expected values: 5-101 clause 7.4.5 (index 124): *"ACTCON, ACTTERM
/// and the interrogated information objects are returned with the specific
/// common addresses of the LRUs in exactly the same manner as if they were
/// initiated by a station interrogation command issued to the specific LRU."*
/// Figure 91 lets the LRUs' answers be interspersed, so each LRU's own
/// sequence is asserted, not the global order.
#[test]
fn clause_5_4_17_10_every_lru_answers_a_broadcast_with_its_own_address() {
    let lru1 = SharedImage::new(Image::new(
        1,
        vec![single(0x0901, true, &[]), scaled(0x0902, 9, &[])],
    ));
    let lru2 = SharedImage::new(Image::new(2, vec![double(0x0A01, &[])]));
    lru2.lock().ready = false;
    let (app, _) = GiStation::new(ReActivation::Continue, &[lru1, lru2.clone()], true);
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let mut peer = GiPeer::start(station.addr()).expect("start");

    peer.send(&c_ic(COT_ACT, false, BROADCAST, QOI_STATION))
        .expect("the broadcast act");
    let first = peer.until(|asdu| is_actterm(asdu, 1)).expect("LRU 1 ends");
    let late = peer.quiet(200);
    let all: Vec<Vec<u8>> = first.iter().chain(&late).cloned().collect();
    let of = |ca: u16| -> Vec<Vec<u8>> {
        all.iter()
            .filter(|asdu| Header::parse(asdu).expect("header").common_address == ca)
            .cloned()
            .collect()
    };
    assert!(
        of(BROADCAST).is_empty(),
        "5.4.17.10: no answer carries the broadcast address"
    );
    let one = of(1);
    assert_eq!(
        one.len(),
        4,
        "LRU 1: ACTCON, 2 objects, ACTTERM: {one:02x?}"
    );
    assert_eq!(
        ic("5.4.17.10", &one[0]),
        expect_ic(COT_ACTCON, false, 1, QOI_STATION)
    );
    assert_object(
        "5.4.17.10 (LRU 1)",
        &one[1],
        &single(0x0901, true, &[]),
        20,
        1,
    );
    assert_object("5.4.17.10 (LRU 1)", &one[2], &scaled(0x0902, 9, &[]), 20, 1);
    assert_eq!(
        ic("5.4.17.10", &one[3]),
        expect_ic(COT_ACTTERM, false, 1, QOI_STATION)
    );
    assert_eq!(
        of(2)
            .iter()
            .map(|asdu| ic("5.4.17.10", asdu))
            .collect::<Vec<_>>(),
        vec![expect_ic(COT_ACTCON, true, 2, QOI_STATION)],
        "5.4.17.10: LRU 2 \"mirrors … C_IC_ACTCONneg … containing its configured CASDU \
         address\", and nothing else"
    );

    // "the controlling station starts the normal GI procedure (for one LRU
    // available) containing the CASDU address of that/those LRU(s)".
    lru2.lock().ready = true;
    peer.send(&c_ic(COT_ACT, false, 2, QOI_STATION))
        .expect("the repeated act to LRU 2");
    let two = peer.until(|asdu| is_actterm(asdu, 2)).expect("LRU 2 ends");
    let after = peer.quiet(200);
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");
    assert_eq!(
        two.len(),
        3,
        "LRU 2: ACTCON, its object, ACTTERM: {two:02x?}"
    );
    assert_eq!(
        ic("5.4.17.10", &two[0]),
        expect_ic(COT_ACTCON, false, 2, QOI_STATION)
    );
    assert_object("5.4.17.10 (LRU 2)", &two[1], &double(0x0A01, &[]), 20, 2);
    assert_eq!(
        ic("5.4.17.10", &two[2]),
        expect_ic(COT_ACTTERM, false, 2, QOI_STATION)
    );
    assert!(
        after.is_empty(),
        "5.4.17.10: LRU 1 does not answer an interrogation addressed to LRU 2: {after:02x?}"
    );
}

/// 604 Table 17 (3 of 5), PDF page index 66 (printed 65), procedure
/// **`5.4.17.10`**, `Reference` `IEC 60870-5-101:2003, 7.4.5` / `7.2.6.22`,
/// `Required` `PICS, 9.6 Station interrogation`:
///
/// > The tests in this Table are performed correctly for supported General
/// > Interrogation groups: The Controlling station sends an Interrogation
/// > Command (ASDU 100) with COT = 6, C_IC_ACT, to the Controlled station with
/// > QOI=21...36 (group 1...16) with CASDU broadcast address (FF or FFFF).
/// > At least 3 groups need to be tested (unless only 1 or 2 groups are
/// > supported).
///
/// DUT: the **controlled** station with two LRUs (common addresses 1 and 2),
/// groups 1, 8 and 16 broadcast. Expected values: per LRU, the group's `QOI` on
/// its ACTCON and ACTTERM, its own common address, the group's cause, and the
/// group members of [`grouped_points`].
#[test]
fn clause_5_4_17_10_three_groups_are_broadcast_to_every_lru() {
    let points = grouped_points();
    let lru1 = SharedImage::new(Image::new(1, points.clone()));
    let lru2 = SharedImage::new(Image::new(2, points.clone()));
    let (app, _) = GiStation::new(ReActivation::Continue, &[lru1, lru2], true);
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let mut peer = GiPeer::start(station.addr()).expect("start");
    for group in [1u8, 8, 16] {
        let qoi = qoi_group(group);
        peer.send(&c_ic(COT_ACT, false, BROADCAST, qoi))
            .expect("the act");
        let members: Vec<&Point> = points
            .iter()
            .filter(|p| p.groups.contains(&group))
            .collect();
        let answer = peer
            .take(2 * (members.len() + 2))
            .expect("both LRUs answer");
        for ca in [1u16, 2] {
            let what = format!("5.4.17.10 (group {group}, LRU {ca})");
            let own: Vec<&Vec<u8>> = answer
                .iter()
                .filter(|asdu| Header::parse(asdu).expect("header").common_address == ca)
                .collect();
            assert_eq!(own.len(), members.len() + 2, "{what}: {own:02x?}");
            assert_eq!(ic(&what, own[0]), expect_ic(COT_ACTCON, false, ca, qoi));
            for (asdu, point) in own[1..=members.len()].iter().zip(&members) {
                assert_object(&what, asdu, point, 20 + group, ca);
            }
            assert_eq!(
                ic(&what, own.last().expect("last")),
                expect_ic(COT_ACTTERM, false, ca, qoi)
            );
        }
    }
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");
}

/// The shape shared by the three re-activation cases: a station interrogation
/// confirmed and held running, then a second activation with `second_qoi`.
/// Returns the answer to the second activation, then everything up to the
/// quiet after the release.
fn re_activate(policy: ReActivation, second_qoi: u8) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (station, mut peer, _, controls) = station(policy, grouped_points(), false);
    peer.send(&c_ic(COT_ACT, false, CA, QOI_STATION))
        .expect("the first act");
    let first = peer.take(1).expect("the first confirmation");
    assert_eq!(
        ic("re-activation", &first[0]),
        expect_ic(COT_ACTCON, false, CA, QOI_STATION),
        "the first interrogation is confirmed and running"
    );
    peer.send(&c_ic(COT_ACT, false, CA, second_qoi))
        .expect("the second act");
    let mut answer = peer.quiet(300);
    controls.release();
    let rest = peer.quiet(400);
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");
    // Anything that raced the release belongs to the second half.
    let split = answer
        .iter()
        .position(|asdu| ic_frame(asdu).is_none())
        .unwrap_or(answer.len());
    let mut tail = answer.split_off(split);
    tail.extend(rest);
    (answer, tail)
}

/// The station-scope data the held first interrogation owes, cause `<20>`.
fn station_objects(tail: &[Vec<u8>], cause: u8) -> Vec<u32> {
    tail.iter()
        .filter(|asdu| {
            let h = Header::parse(asdu).expect("header");
            h.type_id.to_u8() != 100 && h.cause.to_u8() == cause
        })
        .map(|asdu| objects_of(asdu).expect("area")[0].0)
        .collect()
}

/// 604 Table 17 (3 of 5), PDF page index 66 (printed 65), procedure
/// **`5.4.17.20`** (numbered in Table 27, index 94), *"Re-activate a running
/// Outstation interrogation Option 1: the running GI continues"*, `Required`
/// `PIXIT`, `Reference` `IEC 60870-5-101:2003, 7.3.4.1` / `7.4.5`:
///
/// > The Controlling station sends an Interrogation Command (ASDU 100) with COT
/// > = 6, C_IC_ACT, to the Controlled station with QOI=20 (station) or 21..36
/// > (group 1..16) when a General Interrogation is already running.
///
/// > The Controlled station mirrors the Interrogation Command with COT = 7,
/// > C_IC_ACTCONneg, to the Controlling station
///
/// > The Controlled station continues the already running General
/// > Interrogation
///
/// DUT: the **controlled** station under `ReActivation::Continue`; the second
/// activation is group 1 (`QOI` 21). Expected values: the negative
/// confirmation mirrors the second command (cause 7, `P/N = 1`, `QOI` 21), then
/// the first interrogation's data with cause `<20>` (all five objects of
/// [`grouped_points`]) and its one termination (`QOI` 20).
#[test]
fn clause_5_4_17_20_option_1_the_running_interrogation_continues() {
    let (answer, tail) = re_activate(ReActivation::Continue, qoi_group(1));
    assert_eq!(
        answer
            .iter()
            .map(|a| ic("5.4.17.20", a))
            .collect::<Vec<_>>(),
        vec![expect_ic(COT_ACTCON, true, CA, qoi_group(1))],
        "5.4.17.20: \"mirrors the Interrogation Command with COT = 7, C_IC_ACTCONneg\""
    );
    assert_eq!(
        station_objects(&tail, 20),
        vec![0x0601, 0x0608, 0x0610, 0x0611, 0x0620],
        "5.4.17.20: \"continues the already running General Interrogation\""
    );
    let terms: Vec<IcFrame> = tail.iter().filter_map(|a| ic_frame(a)).collect();
    assert_eq!(
        terms,
        vec![expect_ic(COT_ACTTERM, false, CA, QOI_STATION)],
        "5.4.17.20: one termination, the first interrogation's"
    );
    assert!(
        is_actterm(tail.last().expect("last"), CA),
        "the termination follows the data"
    );
}

/// 604 Table 17 (4 of 5), PDF page index 67 (printed 66), procedure
/// **`5.4.17.30`** (numbered in Table 27, index 94), *"Re-activate a running
/// Outstation interrogation Option 2: the running GI is stopped and the second
/// GI is started"*, `Required` `PIXIT`:
///
/// > The Controlled station stops the running General Interrogation (this may
/// > be indicated by the Controlled station by sending a C_IC_ACTTERM or a
/// > C_IC_ACTCONneg) and mirrors the Interrogation Command with COT = 7,
/// > C_IC_ACTCON to the Controlling station
///
/// > The Controlled station continues the normal General Interrogation
/// > procedure
///
/// DUT: the **controlled** station under `ReActivation::Restart`; the second
/// activation is group 1 (`QOI` 21). Expected values: the first
/// interrogation's ACTTERM (`QOI` 20, the indication this crate chose of the
/// two the row allows), the positive ACTCON of the second (`QOI` 21), then
/// group 1's objects (`0x0601`, `0x0611`, cause `<21>`) and its ACTTERM. No
/// station-scope object is sent.
#[test]
fn clause_5_4_17_30_option_2_the_running_interrogation_stops_and_the_second_starts() {
    let (answer, tail) = re_activate(ReActivation::Restart, qoi_group(1));
    assert_eq!(
        answer
            .iter()
            .map(|a| ic("5.4.17.30", a))
            .collect::<Vec<_>>(),
        vec![
            expect_ic(COT_ACTTERM, false, CA, QOI_STATION),
            expect_ic(COT_ACTCON, false, CA, qoi_group(1)),
        ],
        "5.4.17.30: the running GI stopped (C_IC_ACTTERM), the second mirrored with C_IC_ACTCON"
    );
    assert!(
        station_objects(&tail, 20).is_empty(),
        "5.4.17.30: the stopped interrogation sends no more data"
    );
    assert_eq!(
        station_objects(&tail, 21),
        vec![0x0601, 0x0611],
        "5.4.17.30: \"continues the normal General Interrogation procedure\""
    );
    assert_eq!(
        tail.iter().filter_map(|a| ic_frame(a)).collect::<Vec<_>>(),
        vec![expect_ic(COT_ACTTERM, false, CA, qoi_group(1))],
        "5.4.17.30: the second interrogation's termination"
    );
}

/// 604 Table 17 (4 of 5), PDF page index 67, procedure **`5.4.17.40`**
/// (numbered in Table 27, index 94), *"Re-activate a running Outstation
/// interrogation Option 3: the running GI continues and after activation
/// termination (COT=10) the second GI is started."*, `Required` `PIXIT`:
///
/// > The Controlled station continues the running General Interrogation and
/// > mirrors the second Interrogation Command with COT = 7, C_IC_ACTCON to the
/// > Controlling station.
///
/// > The Controlled station continues with the first General Interrogation
/// > procedure. After activation termination (COT=10) the Information Objects
/// > that are part of the second initiated GI are sent with the correct COT
/// > (20-36) to the Controlling station
///
/// DUT: the **controlled** station under `ReActivation::Queue`; the second
/// activation is group 16 (`QOI` 36). Expected values: the positive ACTCON of
/// the second (`QOI` 36); then the first's five objects (cause `<20>`), its
/// ACTTERM (`QOI` 20), and only after it group 16's objects (`0x0610`,
/// `0x0611`, cause `<36>`). The second's own ACTTERM is not in the row's text;
/// 5.4.17.1's *"`C_IC_ACTTERM` … after all configured GI data is sent"* is why
/// the crate sends it, and this case requires it too.
#[test]
fn clause_5_4_17_40_option_3_the_second_interrogation_follows_the_first_termination() {
    let (answer, tail) = re_activate(ReActivation::Queue, qoi_group(16));
    assert_eq!(
        answer
            .iter()
            .map(|a| ic("5.4.17.40", a))
            .collect::<Vec<_>>(),
        vec![expect_ic(COT_ACTCON, false, CA, qoi_group(16))],
        "5.4.17.40: \"mirrors the second Interrogation Command with COT = 7, C_IC_ACTCON\""
    );
    let first_term = tail
        .iter()
        .position(|a| ic_frame(a) == Some(expect_ic(COT_ACTTERM, false, CA, QOI_STATION)))
        .expect("5.4.17.40: the first interrogation terminates");
    assert_eq!(
        station_objects(&tail[..first_term], 20),
        vec![0x0601, 0x0608, 0x0610, 0x0611, 0x0620],
        "5.4.17.40: \"continues with the first General Interrogation procedure\""
    );
    assert!(
        station_objects(&tail[..first_term], 36).is_empty(),
        "5.4.17.40: nothing of the second before the first's termination"
    );
    assert_eq!(
        station_objects(&tail[first_term..], 36),
        vec![0x0610, 0x0611],
        "5.4.17.40: \"After activation termination (COT=10) the Information Objects that are \
         part of the second initiated GI are sent with the correct COT\""
    );
    assert_eq!(
        ic_frame(tail.last().expect("last")),
        Some(expect_ic(COT_ACTTERM, false, CA, qoi_group(16))),
        "5.4.17.40: the second interrogation ends with its own termination"
    );
}

/// 604 Table 17 (5 of 5), PDF page index 68 (printed 67), procedure
/// **`5.4.17.50`**, *"General interrogation – Deactivate a running Outstation
/// interrogation"*, `M` for systems supporting the deactivation, `Reference`
/// `IEC 60870-5-101:2003, 7.3.4.1`:
///
/// > The Controlling station sends an Interrogation Command with COT = 8,
/// > C_IC_DEACT to the Controlled station with QOI=20 (station) or 21..36
/// > (group 1..16)
///
/// > The Controlled station sends an Interrogation Command with COT = 9,
/// > C_IC_DEACTCON to the Controlling station
///
/// > No further Information Objects that are part of the GI for that QOI are
/// > sent to the Controlling station. No Interrogation Command with COT = 10
/// > (ACTTERM) to the Controlling station
///
/// DUT: the **controlled** station, once for the station (`QOI` 20) and once
/// for group 5 (`QOI` 25). Expected values: figure 72's frame with cause 9,
/// `P/N = 0` and the deactivated `QOI`; then silence, although the application
/// releases the data after the deactivation.
#[test]
fn clause_5_4_17_50_a_deactivated_interrogation_sends_no_more_data_and_no_termination() {
    let mut points = grouped_points();
    points.push(single(0x0605, true, &[5]));
    let (station, mut peer, _, controls) = station(ReActivation::Continue, points, false);
    for qoi in [QOI_STATION, qoi_group(5)] {
        peer.send(&c_ic(COT_ACT, false, CA, qoi)).expect("the act");
        let confirmation = peer.take(1).expect("the confirmation");
        assert_eq!(
            ic("5.4.17.50", &confirmation[0]),
            expect_ic(COT_ACTCON, false, CA, qoi)
        );
        peer.send(&c_ic(COT_DEACT, false, CA, qoi))
            .expect("the deactivation");
        let answer = peer.take(1).expect("the deactivation's confirmation");
        assert_eq!(
            ic("5.4.17.50", &answer[0]),
            expect_ic(COT_DEACTCON, false, CA, qoi),
            "5.4.17.50: \"sends an Interrogation Command with COT = 9, C_IC_DEACTCON\""
        );
        controls.release();
        let after = peer.quiet(300);
        assert!(
            after.is_empty(),
            "5.4.17.50 (QOI {qoi}): \"No further Information Objects … No Interrogation Command \
             with COT = 10\": {after:02x?}"
        );
        controls
            .release
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
    peer.close().expect("close");
    station.join().expect("the station ends cleanly");
}
