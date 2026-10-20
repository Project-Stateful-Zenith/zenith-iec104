//! 604 Table 17, PDF page indices 64–68 (printed 63–67): the
//! **controlling**-station cases of the general interrogation procedures. The
//! module doc of `table17.rs` has the row-by-row coverage and what is not
//! verified.
//!
//! The DUT is this crate as the controlling station: the interoperability
//! harness's `Station` for the link layer, `gi::Interrogation::controlling` for
//! the procedure, `init::on_asdu` and `redundancy::RedundancyGroup::follow_up`
//! for the two triggers the crate names, and `asdu::BodyReader` for the object
//! areas. The mock controlled station is this crate's link layer with a
//! scripted application (`ScriptApp`): its frames are figure 72's octets and
//! hand-laid object areas, never built by `gi`.
//!
//! §5.1 (index 10): these are the reverse-direction halves of the rows
//! `table17.rs` drives for the controlled station. No frame uses causes 44–47.

use std::time::Instant;

use crate::conformance604::table17_support::{
    BROADCAST, COT_ACT, COT_ACTCON, COT_ACTTERM, COT_DEACT, COT_DEACTCON, IcFrame, LINK_DROPPED,
    Master, QOI_STATION, ScriptApp, SharedImage, c_ic, ic_frame, point_asdu, qoi_group,
    received_asdus,
};
use crate::conformance604::table17_support::{GiStation, Image, Point};
use crate::conformance604::{CA, ControlledStation, ORIGINATOR, sample_time};
use iec104::apci::{Apci, UFunction};
use iec104::asdu::{Header, Known, LayoutObject, MSpTb1, Siq, TypeId};
use iec104::gi::{GiError, Interrogation, ReActivation, Reaction, Scope, SecondActivation};
use iec104::init::FollowUp;
use iec104::link::Role;
use iec104::params::LinkParams;
use iec104::redundancy::RedundancyGroup;

/// The twelve types with causes 20–36 (see `table17.rs`'s `INTERROGATED`, and
/// its sources: 5-101 clause 7.4.5, index 123, and clauses 7.3.5.1–7.3.5.3,
/// indices 110–112).
const INTERROGATED: [u8; 12] = [1, 3, 5, 7, 9, 11, 13, 20, 21, 110, 111, 112];

/// The controlling station under test, locked as 5-101 clause 7.4.5 normally
/// has it (index 124: the controlling station normally refuses to start a
/// second, identical general interrogation of the same source while the first
/// has not terminated).
const fn locked() -> Interrogation {
    Interrogation::controlling(SecondActivation::Locked, CA, ORIGINATOR)
}

/// A mock controlled station at [`CA`] running `script`, with `pre_start` in
/// its clause 5.3 queue, and the controlling station under test connected and
/// started.
fn connect(
    script: ScriptApp,
    pre_start: Vec<Vec<u8>>,
    gi: Interrogation,
) -> (ControlledStation, Master) {
    let peer = ControlledStation::start_app(script, pre_start).expect("the mock binds");
    let master = Master::connect(peer.addr(), gi, &[CA]).expect("the controlling station starts");
    (peer, master)
}

/// The ASDUs the mock received, after the controlling station closed.
fn close(peer: ControlledStation, master: Master) -> Vec<Vec<u8>> {
    master.close().expect("close");
    let received = received_asdus(&peer.join().expect("the mock ends cleanly").received);
    // The master lives until the mock has finished, as it always did.
    drop(master);
    received
}

/// One single-point object of the station scope, cause `<20>`: `SIQ` ON.
fn object(ca: u16, ioa: u32) -> Vec<u8> {
    point_asdu(1, 20, ca, ioa, &[0x01])
}

/// A whole positive station interrogation's answer: ACTCON, `objects`,
/// ACTTERM.
fn answer(ca: u16, qoi: u8, objects: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut out = vec![c_ic(COT_ACTCON, false, ca, qoi)];
    out.extend(objects);
    out.push(c_ic(COT_ACTTERM, false, ca, qoi));
    out
}

const fn confirmed(scope: Scope, negative: bool) -> Reaction {
    Reaction::ActivationConfirmed { scope, negative }
}

const fn interrogated(scope: Scope) -> Reaction {
    Reaction::Interrogated { scope }
}

const fn terminated(scope: Scope) -> Reaction {
    Reaction::Terminated { scope }
}

/// The `C_IC ACT` of 5-101 figure 72 (index 105) the controlling station must
/// send: cause 6, `P/N = 0`, `INFORMATION OBJECT ADDRESS = 0`.
const fn act(ca: u16, qoi: u8) -> IcFrame {
    IcFrame {
        cause: COT_ACT,
        negative: false,
        ca,
        ioa: 0,
        qoi,
    }
}

fn frames(asdus: &[Vec<u8>]) -> Vec<Option<IcFrame>> {
    asdus.iter().map(|a| ic_frame(a)).collect()
}

/// 604 Table 17 (1 of 5), PDF page index 64 (printed 63), procedure
/// **`5.4.17.1`**, `M`, `Reference` `IEC 60870-5-101:2003, 7.4.5` / `7.2.6.22`:
///
/// Row (paraphrased): the controlling station sends ASDU 100 with COT=6
/// (`C_IC_ACT`) and QOI=20 (station) to the controlled station when one of the
/// listed triggers occurs; this case is the trigger "an ENDINIT is received".
///
/// DUT: the **controlling** station. The mock's end of initialisation
/// (`M_EI_NA_1`, type `<70>`, cause `<4>`, `COI` 0, 5-101 clause 7.3.3.1) is
/// queued before STARTDT (104 clause 5.3) and read by `init::on_asdu`, whose
/// follow-up the station performs. Expected values: figure 72's `C_IC ACT`
/// with `QOI` `<20>` and the station's common address, and the cycle to its
/// termination.
#[test]
fn clause_5_4_17_1_an_endinit_starts_a_station_interrogation() {
    let endinit = point_asdu(70, 4, CA, 0, &[0x00]);
    let script = ScriptApp::new(vec![answer(CA, QOI_STATION, vec![object(CA, 0x0101)])]);
    let (peer, mut master) = connect(script, vec![endinit], locked());

    let first = master
        .next_asdu(crate::conformance604::deadline(5))
        .expect("the ENDINIT");
    let header = Header::parse(&first).expect("header");
    let reaction = iec104::init::on_asdu(&first, &Known::standard(&header, true, true))
        .expect("init reads it");
    assert_eq!(
        reaction.follow_up(),
        Some(FollowUp::StationInterrogation),
        "5.4.17.1: an ENDINIT triggers the station interrogation"
    );
    let request = master.gi.request(Scope::Station).expect("the request");
    master.send(&request).expect("the act goes out");
    master
        .until(|r| *r == terminated(Scope::Station))
        .expect("the interrogation runs to its end");
    assert_eq!(
        master.reactions(),
        vec![
            confirmed(Scope::Station, false),
            interrogated(Scope::Station),
            terminated(Scope::Station)
        ]
    );
    let received = close(peer, master);
    assert_eq!(
        frames(&received),
        vec![Some(act(CA, QOI_STATION))],
        "5.4.17.1: ASDU 100, COT = 6, QOI = 20"
    );
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `M`:
///
/// Trigger (paraphrased): the controlling station has seen the link lost and
/// it has come back.
///
/// DUT: the **controlling** station. The first connection is lost while its
/// interrogation runs (ACTCON received, no ACTTERM). The crate names the
/// trigger through `RedundancyGroup::follow_up` (104 clause 10.3, index 120:
/// once one of the connections has been brought to the started state, the
/// controlling station shall start a station interrogation as soon as it can), kept in step with the socket here, and the lost
/// procedure is dropped with `Interrogation::reset` (its doc: *"For the
/// caller's connection loss or reconnect"*). Expected values: no follow-up
/// while the connection is down; after the new connection's STARTDT con the
/// follow-up is due and the `C_IC ACT` with `QOI` `<20>` goes out on it.
#[test]
fn clause_5_4_17_1_a_link_available_again_starts_a_station_interrogation() {
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 1)
        .expect("a one-connection group");
    let mut gi = locked();

    // The first connection: started, interrogation confirmed, then lost.
    group
        .on_connection_established(0, Instant::now())
        .expect("up");
    group.start(0).expect("the act");
    let peer = ControlledStation::start_app(
        ScriptApp::new(vec![vec![c_ic(COT_ACTCON, false, CA, QOI_STATION)]]).then_drop(),
        Vec::new(),
    )
    .expect("the mock binds");
    let mut master = Master::connect(peer.addr(), gi.clone(), &[CA]).expect("start");
    group
        .member_mut(0)
        .expect("member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.follow_up(0), Ok(Some(FollowUp::StationInterrogation)));
    let request = master.gi.request(Scope::Station).expect("the request");
    master.send(&request).expect("the act");
    master.take(1).expect("the confirmation");
    assert!(master.gi.is_running(Scope::Station));
    let lost = master.next_asdu(crate::conformance604::deadline(5));
    assert_eq!(
        lost.err().as_deref(),
        Some("the peer closed the connection early"),
        "the link is lost"
    );
    assert_eq!(
        peer.join().err().as_deref(),
        Some(LINK_DROPPED),
        "the mock dropped it"
    );
    let first_received = received_asdus(&master.station.sent);
    assert_eq!(frames(&first_received), vec![Some(act(CA, QOI_STATION))]);

    // The loss: no interrogation is due while the link is down, and the lost
    // procedure would still lock a new one until it is reset.
    group.on_connection_lost(0).expect("lost");
    assert_eq!(group.follow_up(0), Ok(None), "not while the link is down");
    gi = master.gi.clone();
    assert_eq!(
        gi.request(Scope::Station).err(),
        Some(GiError::AlreadyRunning {
            scope: Scope::Station
        }),
        "the lost procedure still locks the scope (5-101 cl.7.4.5)"
    );
    gi.reset();

    // The link is available again.
    group
        .on_connection_established(0, Instant::now())
        .expect("up again");
    group.start(0).expect("the act");
    let script = ScriptApp::new(vec![answer(CA, QOI_STATION, vec![object(CA, 0x0101)])]);
    let (peer, mut master) = connect(script, Vec::new(), gi);
    assert_eq!(group.follow_up(0), Ok(None), "not before the STARTDT con");
    group
        .member_mut(0)
        .expect("member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(
        group.follow_up(0),
        Ok(Some(FollowUp::StationInterrogation)),
        "5.4.17.1: the link is back"
    );
    let request = master.gi.request(Scope::Station).expect("the request");
    master.send(&request).expect("the act");
    master
        .until(|r| *r == terminated(Scope::Station))
        .expect("the new interrogation runs to its end");
    let received = close(peer, master);
    assert_eq!(
        frames(&received),
        vec![Some(act(CA, QOI_STATION))],
        "5.4.17.1: ASDU 100, COT = 6, QOI = 20 on the new connection"
    );
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `M`:
///
/// Rows (paraphrased): the interrogation may also be started by hand, for
/// example by an operator. A controlled station that is not ready to deliver
/// the interrogated data mirrors the command back with COT=7 and P/N = 1
/// (`C_IC_ACTCONneg`); the controlling station may then send the command
/// again.
///
/// DUT: the **controlling** station, which sends the interrogation on the
/// operator's request, receives a negative confirmation, and repeats it.
/// Expected values: 5-101 clause 7.4.5 (index 124) permits repeating the
/// station interrogation command in that case, so the lock of an identical
/// interrogation is released by the negative confirmation, and the repeat is
/// the same figure 72 frame.
#[test]
fn clause_5_4_17_1_a_manual_interrogation_refused_negatively_may_be_repeated() {
    let script = ScriptApp::new(vec![
        vec![c_ic(COT_ACTCON, true, CA, QOI_STATION)],
        answer(CA, QOI_STATION, vec![object(CA, 0x0101)]),
    ]);
    let (peer, mut master) = connect(script, Vec::new(), locked());
    let request = master
        .gi
        .request(Scope::Station)
        .expect("the operator's request");
    master.send(&request).expect("the act");
    assert_eq!(
        master.take(1).expect("the answer"),
        vec![confirmed(Scope::Station, true)]
    );
    assert!(
        !master.gi.is_running(Scope::Station),
        "5.4.17.1: a refused interrogation is not running"
    );
    let repeat = master
        .gi
        .request(Scope::Station)
        .expect("5.4.17.1: the controlling station may repeat the command");
    master.send(&repeat).expect("the repeat");
    master
        .until(|r| *r == terminated(Scope::Station))
        .expect("the repeat runs to its end");
    assert_eq!(master.gi.running(), [] as [iec104::gi::Scope; 0]);
    let received = close(peer, master);
    assert_eq!(
        frames(&received),
        vec![Some(act(CA, QOI_STATION)), Some(act(CA, QOI_STATION))]
    );
}

/// `n` scaled values laid out by hand as 5-101 clause 7.2.2.1 (PDF page
/// indices 34–35) and clause 7.3.1.11 (index 72) define them, cause `<20>`:
/// `SQ = 0` repeats the three-octet address before every `SVA` + `QDS`, `SQ =
/// 1` writes the first address once.
fn hand_packed(sequence: bool, ioas: &[u32], values: &[i16]) -> Vec<u8> {
    let vsq = (ioas.len() as u8) | if sequence { 0x80 } else { 0 };
    let mut out = vec![11, vsq, 20, ORIGINATOR, CA as u8, (CA >> 8) as u8];
    for (i, (ioa, value)) in ioas.iter().zip(values).enumerate() {
        if !sequence || i == 0 {
            out.extend_from_slice(&ioa.to_le_bytes()[..3]);
        }
        out.extend_from_slice(&value.to_le_bytes());
        out.push(0x00);
    }
    out
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `M`,
/// `Reference` `IEC 60870-5-3:1992, 5.1.5` / `IEC 60870-5-101:2003, 7.2.2.2`:
///
/// Row (paraphrased): the controlling station shall cope with both SQ=0 and
/// SQ=1;
///
/// and the rows on the stored values and the time stamp, among them that the
/// values the controlling station has received and stored should match the
/// current values in the controlled station.
///
/// DUT: the **controlling** station. The mock returns a full `SQ = 0` ASDU (40
/// scaled values with gaps, 246 octets) and a full `SQ = 1` ASDU (80
/// consecutive values, 249 octets), the numbers `table17.rs` derives from 104
/// clause 5. Expected values: every object classified as the station
/// interrogation's and stored at its address, the `SQ = 1` addresses
/// rising by one from object to object, starting at the first (5-101 clause 7.2.2.1,
/// index 35), each with the value the mock sent.
#[test]
fn clause_5_4_17_1_the_controlling_station_handles_sq0_and_sq1() {
    let gapped: Vec<u32> = (0..40).map(|i| 0x0100 + 2 * i).collect();
    let sequential: Vec<u32> = (0..80).map(|i| 0x0400 + i).collect();
    let v0: Vec<i16> = (0..40).map(|i| i * 10).collect();
    let v1: Vec<i16> = (0..80).map(|i| -i).collect();
    let set = hand_packed(false, &gapped, &v0);
    let sequence = hand_packed(true, &sequential, &v1);
    assert_eq!((set.len(), sequence.len()), (246, 249));

    let script = ScriptApp::new(vec![answer(CA, QOI_STATION, vec![set, sequence])]);
    let (peer, mut master) = connect(script, Vec::new(), locked());
    let request = master.gi.request(Scope::Station).expect("request");
    master.send(&request).expect("act");
    master
        .until(|r| *r == terminated(Scope::Station))
        .expect("the GI ends");
    assert_eq!(
        master.reactions(),
        vec![
            confirmed(Scope::Station, false),
            interrogated(Scope::Station),
            interrogated(Scope::Station),
            terminated(Scope::Station)
        ],
        "5.4.17.1: both ASDUs are the interrogation's"
    );
    let mut expected = std::collections::BTreeMap::new();
    for (ioa, value) in gapped.iter().zip(&v0).chain(sequential.iter().zip(&v1)) {
        let v = value.to_le_bytes();
        expected.insert((CA, *ioa), (11u8, vec![v[0], v[1], 0x00], 20u8));
    }
    assert_eq!(
        master.image, expected,
        "5.4.17.1: the stored values should match the controlled station's current \
         values"
    );
    close(peer, master);
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `M`,
/// `Reference` `IEC 60870-5-101:2003, 8.5, 8.6`:
///
/// Row (paraphrased): the table's tests are only complete when run for every
/// ASDU type in the PICS that supports the relevant causes 20 to 36.
///
/// DUT: the **controlling** station, receiving one object of each of the twelve
/// types. Expected values: each classified as the station interrogation's and
/// stored with its type and element.
#[test]
fn clause_5_4_17_1_the_controlling_station_takes_every_asdu_with_causes_20_to_36() {
    let objects: Vec<(u32, u8, Vec<u8>)> = INTERROGATED
        .iter()
        .enumerate()
        .map(|(i, type_id)| {
            let len = iec104::asdu::element_len(TypeId::from_u8(*type_id)).expect("a length");
            (0x0500 + i as u32, *type_id, vec![i as u8 + 1; len])
        })
        .collect();
    let asdus = objects
        .iter()
        .map(|(ioa, type_id, element)| point_asdu(*type_id, 20, CA, *ioa, element))
        .collect();
    let script = ScriptApp::new(vec![answer(CA, QOI_STATION, asdus)]);
    let (peer, mut master) = connect(script, Vec::new(), locked());
    let request = master.gi.request(Scope::Station).expect("request");
    master.send(&request).expect("act");
    master
        .until(|r| *r == terminated(Scope::Station))
        .expect("the GI ends");
    let reactions = master.reactions();
    assert_eq!(reactions.len(), INTERROGATED.len() + 2);
    for (reaction, (_, type_id, _)) in reactions[1..=INTERROGATED.len()].iter().zip(&objects) {
        assert_eq!(
            *reaction,
            interrogated(Scope::Station),
            "5.4.17.1 (type {type_id})"
        );
    }
    for (ioa, type_id, element) in &objects {
        assert_eq!(
            master.image.get(&(CA, *ioa)),
            Some(&(*type_id, element.clone(), 20)),
            "5.4.17.1 (type {type_id}): stored as received"
        );
    }
    close(peer, master);
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `PICS,
/// 9.6`, paraphrased: the controlling station sends ASDU 100 with COT=6
/// (`C_IC_ACT`) and QOI=21 to 36 (groups 1 to 16) to the controlled station, and
/// at least three groups are to be tested.
///
/// DUT: the **controlling** station, groups 1, 8 and 16. Expected values:
/// `QOI` 21, 28, 36 on the wire (5-101 clause 7.2.6.22, index 53), and each
/// group's answer (cause `<21>`, `<28>`, `<36>`, table 14, index 41)
/// classified as that group's.
#[test]
fn clause_5_4_17_1_the_controlling_station_interrogates_three_groups() {
    let groups = [1u8, 8, 16];
    let script = ScriptApp::new(
        groups
            .iter()
            .map(|g| {
                answer(
                    CA,
                    qoi_group(*g),
                    vec![point_asdu(1, 20 + g, CA, 0x0600 + u32::from(*g), &[0x01])],
                )
            })
            .collect(),
    );
    let (peer, mut master) = connect(script, Vec::new(), locked());
    for g in groups {
        let scope = Scope::Group(g);
        let request = master.gi.request(scope).expect("request");
        master.send(&request).expect("act");
        master
            .until(|r| *r == terminated(scope))
            .expect("the group's GI ends");
        assert_eq!(
            master.reactions()[master.log.len() - 3..],
            [
                confirmed(scope, false),
                interrogated(scope),
                terminated(scope)
            ],
            "5.4.17.1 (group {g})"
        );
        assert_eq!(
            master.image.get(&(CA, 0x0600 + u32::from(g))).map(|e| e.2),
            Some(20 + g)
        );
    }
    let received = close(peer, master);
    assert_eq!(
        frames(&received),
        groups
            .iter()
            .map(|g| Some(act(CA, qoi_group(*g))))
            .collect::<Vec<_>>(),
        "5.4.17.1: QOI = 21, 28, 36"
    );
}

/// 604 Table 17 (1 of 5), PDF page index 64, procedure **`5.4.17.1`**, `M`,
/// end to end:
///
/// Rows (paraphrased): GI data carries the current state, which is tested by
/// raising an event during the GI ahead of that object's GI message, whose
/// value should then be the updated one; and the values the controlling
/// station has stored should match the current values in the controlled
/// station.
///
/// DUT: **both** roles of this crate against each other: the controlling
/// station (`Master`) interrogates the controlled station (`GiStation`), and an
/// event changes one object between the confirmation and the data. Expected
/// values: after the termination, the controlling station's stored image
/// equals the controlled station's process image at that moment, object for
/// object.
#[test]
fn clause_5_4_17_1_the_stored_values_are_the_actual_values_after_an_event() {
    let points = vec![
        Point {
            ioa: 0x0701,
            type_id: 1,
            element: vec![0x00],
            groups: Vec::new(),
        },
        Point {
            ioa: 0x0702,
            type_id: 11,
            element: vec![0x39, 0x05, 0x00],
            groups: Vec::new(),
        },
    ];
    let image = SharedImage::new(Image::new(CA, points));
    let (app, controls) =
        GiStation::new(ReActivation::Continue, std::slice::from_ref(&image), false);
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let mut master = Master::connect(station.addr(), locked(), &[CA]).expect("start");
    let request = master.gi.request(Scope::Station).expect("request");
    master.send(&request).expect("act");
    assert_eq!(
        master.take(1).expect("the confirmation"),
        vec![confirmed(Scope::Station, false)]
    );

    image.lock().set(0x0701, &[0x01]);
    let event = iec104::tx::spontaneous(
        &LayoutObject {
            ioa: 0x0701,
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
    controls.push_event(event);
    controls.release();
    master
        .until(|r| *r == terminated(Scope::Station))
        .expect("the GI ends");
    let actual: std::collections::BTreeMap<(u16, u32), (u8, Vec<u8>, u8)> = image
        .lock()
        .points
        .iter()
        .map(|p| ((CA, p.ioa), (p.type_id, p.element.clone(), 20)))
        .collect();
    assert_eq!(
        master.image, actual,
        "5.4.17.1: the stored values match the controlled station's current values"
    );
    master.close().expect("close");
    station.join().expect("the station ends cleanly");
}

/// 604 Table 17 (2 of 5), PDF page index 65 (printed 64), procedure
/// **`5.4.17.10`**, `M` for systems with the functionality in the PIXIT:
///
/// Rows (paraphrased):
///
/// - the controlling station sends ASDU 100 with COT=6 (`C_IC_ACT`) and QOI=20
///   (station) to the broadcast CASDU (`FF` or `FFFF`) under the listed
///   conditions;
/// - each LRU mirrors it with COT=7 (`C_IC_ACTCON`) under its own configured
///   CASDU;
/// - for each LRU, once all of that LRU's configured GI data has gone out, the
///   controlled station sends COT=10 (`C_IC_ACTTERM`) under that LRU's CASDU.
///
/// DUT: the **controlling** station, one `gi::Interrogation::controlling` whose
/// common address is the broadcast `FFFF`, facing two LRUs (1 and 2). Expected
/// values: 5-101 clause 7.4.5 (index 124): ACTCON, ACTTERM and the interrogated
/// objects come back under each LRU's own common address, just as they would
/// for an interrogation addressed to that LRU alone. So both
/// LRUs' confirmations, objects and terminations belong to the procedure, and
/// it has finished only after the second termination.
#[test]
fn clause_5_4_17_10_a_broadcast_interrogation_is_followed_for_every_lru() {
    let script = ScriptApp::new(vec![vec![
        c_ic(COT_ACTCON, false, 1, QOI_STATION),
        c_ic(COT_ACTCON, false, 2, QOI_STATION),
        object(1, 0x0901),
        c_ic(COT_ACTTERM, false, 1, QOI_STATION),
        object(2, 0x0A01),
        c_ic(COT_ACTTERM, false, 2, QOI_STATION),
    ]]);
    let peer = ControlledStation::start_app(script, Vec::new()).expect("the mock binds");
    let gi = Interrogation::controlling(SecondActivation::Locked, BROADCAST, ORIGINATOR);
    let mut master = Master::connect(peer.addr(), gi, &[1, 2]).expect("start");
    let request = master.gi.request(Scope::Station).expect("request");
    master.send(&request).expect("act");
    let reactions = master.take(6).expect("both LRUs answer");
    let received = close(peer, master);
    assert_eq!(
        frames(&received),
        vec![Some(act(BROADCAST, QOI_STATION))],
        "5.4.17.10: the act carries the broadcast CASDU"
    );
    assert_eq!(
        reactions,
        vec![
            confirmed(Scope::Station, false),
            confirmed(Scope::Station, false),
            interrogated(Scope::Station),
            terminated(Scope::Station),
            interrogated(Scope::Station),
            terminated(Scope::Station),
        ],
        "5.4.17.10: every LRU's answer belongs to the broadcast interrogation"
    );
}

/// 604 Table 17 (2 of 5), PDF page index 65, procedure **`5.4.17.10`**,
/// `Required` `PIXIT`:
///
/// Row (paraphrased): an LRU that restarts may send an ENDINIT, under its own
/// configured CASDU, during or after the first interrogation; the controlling
/// station then runs the ordinary single-LRU GI addressed to that LRU's (or
/// those LRUs') CASDU and completes the GI for each of them.
///
/// DUT: the **controlling** station of two LRUs (1 and 2). LRU 2's ENDINIT
/// (`M_EI_NA_1`, common address 2) is read by `init::on_asdu`; the station
/// interrogates that LRU with an `Interrogation` at the ENDINIT's common
/// address. Expected values: figure 72's `C_IC ACT` with `QOI` `<20>` and
/// common address 2, and LRU 2's answer classified to its termination.
#[test]
fn clause_5_4_17_10_an_lrus_endinit_starts_an_interrogation_of_that_lru() {
    let endinit = point_asdu(70, 4, 2, 0, &[0x02]);
    let script = ScriptApp::new(vec![answer(2, QOI_STATION, vec![object(2, 0x0A01)])]);
    let peer = ControlledStation::start_app(script, vec![endinit]).expect("the mock binds");
    let mut master = Master::connect(peer.addr(), locked(), &[1, 2]).expect("start");
    let first = master
        .next_asdu(crate::conformance604::deadline(5))
        .expect("the ENDINIT");
    let header = Header::parse(&first).expect("header");
    let reaction = iec104::init::on_asdu(&first, &Known::standard(&header, true, true))
        .expect("init reads it");
    assert_eq!(reaction.follow_up(), Some(FollowUp::StationInterrogation));
    master.gi =
        Interrogation::controlling(SecondActivation::Locked, header.common_address, ORIGINATOR);
    let request = master.gi.request(Scope::Station).expect("request");
    master.send(&request).expect("act");
    master
        .until(|r| *r == terminated(Scope::Station))
        .expect("LRU 2's GI ends");
    assert_eq!(
        master.image.get(&(2, 0x0A01)).map(|e| e.2),
        Some(20),
        "LRU 2's object is stored under its own common address"
    );
    let received = close(peer, master);
    assert_eq!(
        frames(&received),
        vec![Some(act(2, QOI_STATION))],
        "5.4.17.10: addressed to the restarted LRU's CASDU"
    );
}

/// The shape shared by the three re-activation cases on the controlling side:
/// the station interrogation confirmed, then a second activation of the same
/// scope (`SecondActivation::Allowed`, the configuration of Table 17's NOTE on
/// page 3 of 5, index 66: a controlling station that can start a new
/// interrogation while one is still running shall cope with every one of the
/// options), answered with
/// `script`. Returns the reactions to it and whether anything is left running.
fn handle_option(script: Vec<Vec<u8>>) -> (Vec<Reaction>, Vec<Scope>) {
    let n = script.len();
    let gi = Interrogation::controlling(SecondActivation::Allowed, CA, ORIGINATOR);
    let (peer, mut master) = connect(
        ScriptApp::new(vec![vec![c_ic(COT_ACTCON, false, CA, QOI_STATION)], script]),
        Vec::new(),
        gi,
    );
    let first = master.gi.request(Scope::Station).expect("the first act");
    master.send(&first).expect("send");
    assert_eq!(
        master.take(1).expect("the confirmation"),
        vec![confirmed(Scope::Station, false)]
    );
    let second = master
        .gi
        .request(Scope::Station)
        .expect("the second act while the first runs");
    master.send(&second).expect("send");
    let reactions = master.take(n).expect("the option's answer");
    let running = master.gi.running();
    let received = close(peer, master);
    assert_eq!(
        frames(&received),
        vec![Some(act(CA, QOI_STATION)), Some(act(CA, QOI_STATION))]
    );
    (reactions, running)
}

/// 604 Table 17 (3 of 5), PDF page index 66, procedure **`5.4.17.20`**
/// (numbered in Table 27, index 94), option 1, `PIXIT`, paraphrased: the
/// controlled station mirrors the second command negatively with COT=7
/// (`C_IC_ACTCONneg`) and carries on with the GI already running.
///
/// DUT: the **controlling** station. Expected values: the negative
/// confirmation is taken as the second activation's, the first's data and
/// termination as the running procedure's, and nothing is left running.
#[test]
fn clause_5_4_17_20_the_controlling_station_handles_option_1() {
    let (reactions, running) = handle_option(vec![
        c_ic(COT_ACTCON, true, CA, QOI_STATION),
        object(CA, 0x0101),
        c_ic(COT_ACTTERM, false, CA, QOI_STATION),
    ]);
    assert_eq!(
        reactions,
        vec![
            confirmed(Scope::Station, true),
            interrogated(Scope::Station),
            terminated(Scope::Station)
        ],
        "5.4.17.20"
    );
    assert!(running.is_empty(), "5.4.17.20: finished, {running:?}");
}

/// 604 Table 17 (4 of 5), PDF page index 67, procedure **`5.4.17.30`**
/// (numbered in Table 27, index 94), option 2, `PIXIT`, paraphrased: the
/// controlled station abandons the running GI (and may signal that with a
/// `C_IC_ACTTERM` or a `C_IC_ACTCONneg`), confirms the new command with COT=7
/// (`C_IC_ACTCON`), and then runs the GI procedure as usual.
///
/// DUT: the **controlling** station, for the ACTTERM indication. Expected
/// values: the first procedure terminated, the second confirmed, its data
/// taken, its termination ending it, nothing left running.
#[test]
fn clause_5_4_17_30_the_controlling_station_handles_option_2() {
    let (reactions, running) = handle_option(vec![
        c_ic(COT_ACTTERM, false, CA, QOI_STATION),
        c_ic(COT_ACTCON, false, CA, QOI_STATION),
        object(CA, 0x0101),
        c_ic(COT_ACTTERM, false, CA, QOI_STATION),
    ]);
    assert_eq!(
        reactions,
        vec![
            terminated(Scope::Station),
            confirmed(Scope::Station, false),
            interrogated(Scope::Station),
            terminated(Scope::Station)
        ],
        "5.4.17.30"
    );
    assert!(running.is_empty(), "5.4.17.30: finished, {running:?}");
}

/// 604 Table 17 (4 of 5), PDF page index 67, procedure **`5.4.17.40`**
/// (numbered in Table 27, index 94), option 3, `PIXIT`, paraphrased: the
/// controlled station keeps the running GI going and confirms the second
/// command with COT=7 (`C_IC_ACTCON`); after the first GI's termination
/// (COT=10) it sends the second GI's objects with their proper cause (20 to
/// 36).
///
/// DUT: the **controlling** station. Expected values: the second confirmed
/// while the first runs, the second's objects still taken after the first's
/// termination, and its own termination ending it.
#[test]
fn clause_5_4_17_40_the_controlling_station_handles_option_3() {
    let (reactions, running) = handle_option(vec![
        c_ic(COT_ACTCON, false, CA, QOI_STATION),
        object(CA, 0x0101),
        c_ic(COT_ACTTERM, false, CA, QOI_STATION),
        object(CA, 0x0101),
        c_ic(COT_ACTTERM, false, CA, QOI_STATION),
    ]);
    assert_eq!(
        reactions,
        vec![
            confirmed(Scope::Station, false),
            interrogated(Scope::Station),
            terminated(Scope::Station),
            interrogated(Scope::Station),
            terminated(Scope::Station)
        ],
        "5.4.17.40: the second GI's objects follow the first's termination"
    );
    assert!(running.is_empty(), "5.4.17.40: finished, {running:?}");
}

/// 604 Table 17 (5 of 5), PDF page index 68 (printed 67), procedure
/// **`5.4.17.50`**, `M` for systems supporting deactivation:
///
/// Rows (paraphrased):
///
/// - the controlling station sends ASDU 100 with COT=8 (`C_IC_DEACT`) and
///   QOI=20 (station) or 21 to 36 (groups 1 to 16);
/// - the controlled station answers with COT=9 (`C_IC_DEACTCON`);
/// - after that, no more objects of that QOI's GI are sent, and no COT=10
///   (ACTTERM) follows.
///
/// DUT: the **controlling** station, for the station and for group 2.
/// Expected values: figure 72's frame with cause 8 and the running `QOI` on
/// the wire; the `DEACTCON` ends the procedure (nothing is left running, so no
/// ACTTERM is awaited), and a late object of that scope is not taken as the
/// procedure's.
#[test]
fn clause_5_4_17_50_the_controlling_station_deactivates_a_running_interrogation() {
    let mut script = Vec::new();
    for qoi in [QOI_STATION, qoi_group(2)] {
        script.push(vec![c_ic(COT_ACTCON, false, CA, qoi)]);
        script.push(vec![
            c_ic(COT_DEACTCON, false, CA, qoi),
            point_asdu(1, qoi, CA, 0x0101, &[0x01]),
        ]);
    }
    let (peer, mut master) = connect(ScriptApp::new(script), Vec::new(), locked());
    for scope in [Scope::Station, Scope::Group(2)] {
        let request = master.gi.request(scope).expect("request");
        master.send(&request).expect("act");
        assert_eq!(
            master.take(1).expect("confirmation"),
            vec![confirmed(scope, false)]
        );
        let deact = master.gi.deactivate(scope).expect("the deactivation");
        master.send(&deact).expect("deact");
        assert_eq!(
            master.take(2).expect("the deactivation's answer"),
            vec![
                Reaction::DeactivationConfirmed {
                    scope,
                    negative: false
                },
                Reaction::Other
            ],
            "5.4.17.50 ({scope:?}): DEACTCON ends it; a late object is not the procedure's"
        );
        assert!(
            master.gi.running().is_empty(),
            "5.4.17.50: no ACTTERM is awaited"
        );
    }
    let received = close(peer, master);
    let d = |qoi| IcFrame {
        cause: COT_DEACT,
        ..act(CA, qoi)
    };
    assert_eq!(
        frames(&received),
        vec![
            Some(act(CA, QOI_STATION)),
            Some(d(QOI_STATION)),
            Some(act(CA, qoi_group(2))),
            Some(d(qoi_group(2))),
        ],
        "5.4.17.50: C_IC_DEACT, COT = 8, with the running QOI"
    );
}
