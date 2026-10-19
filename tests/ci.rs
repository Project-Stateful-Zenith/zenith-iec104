//! Counter interrogation: `C_CI_NA_1`, its `QCC`, the response cycle of 5-101
//! clause 7.4.8 and 104 clause 9's four counter modes.
//!
//! The clause citations are 5-104 cl.7.8 (the service table, PDF page index 70),
//! 5-104 cl.9 (the four modes, page index 112), 5-101 cl.7.3.4.2 (the layout,
//! page index 105, figure 73), cl.7.2.6.23 (`QCC`, page index 54) and cl.7.4.8
//! (the procedure, page indices 126–129); TS 60870-5-604 Table 20 (PDF page
//! indices 78–81) is the conformance model.
//!
//! These tests drive the two roles against each other, so every assertion is
//! about a frame one role sent and the other classified.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::as_conversions
)]

use iec104::asdu::{
    Bcr, Cause, Cp24Time2a, Cp56Time2a, FreezeMode, Header, Known, LayoutError, LayoutObject,
    MItNa1, MItTa1, MItTb1, MMeNb1, Qcc, Qds, Sva, TypeId, decode_asdu, encode_asdu,
};
use iec104::ci::{
    CAUSE_ACTIVATION, CAUSE_ACTIVATION_CON, CAUSE_ACTIVATION_TERM, COUNTER_TYPES, CiError,
    CounterInterrogation, CounterMode, CounterSource, Outcome, Reaction, Request, Role, TYPE_ID,
    is_counter_type, request,
};

const CA: u16 = 12;

// ---------------------------------------------------------------- helpers

/// An `M_IT_NA_1` ASDU (`BCR`, 5 element octets) with the given cause.
fn total(cause: Cause, ioa: u32, reading: i32) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MItNa1,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: 0,
        common_address: CA,
    };
    let object = LayoutObject {
        ioa,
        value: MItNa1 {
            bcr: Bcr {
                reading,
                sequence: 1,
                ..Bcr::default()
            },
        },
    };
    encode_asdu(&header, &[object]).expect("the layout builds it")
}

/// An `M_IT_TB_1` ASDU (`BCR` + `CP56Time2a`, 12 element octets).
fn total_tagged(cause: Cause, ioa: u32, reading: i32) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MItTb1,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: 0,
        common_address: CA,
    };
    let object = LayoutObject {
        ioa,
        value: MItTb1 {
            bcr: Bcr {
                reading,
                sequence: 2,
                ..Bcr::default()
            },
            time: Cp56Time2a::default(),
        },
    };
    encode_asdu(&header, &[object]).expect("the layout builds it")
}

/// An `M_IT_TA_1` ASDU (`BCR` + `CP24Time2a`, 8 element octets).
fn total_short_tagged(cause: Cause, ioa: u32, reading: i32) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MItTa1,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: 0,
        common_address: CA,
    };
    let object = LayoutObject {
        ioa,
        value: MItTa1 {
            bcr: Bcr {
                reading,
                sequence: 3,
                ..Bcr::default()
            },
            time: Cp24Time2a::default(),
        },
    };
    encode_asdu(&header, &[object]).expect("the layout builds it")
}

/// A measured-value ASDU, for the "not a counter object" cases.
fn measured(cause: Cause, ioa: u32) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MMeNb1,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: 0,
        common_address: CA,
    };
    encode_asdu(
        &header,
        &[LayoutObject {
            ioa,
            value: MMeNb1 {
                sva: Sva { value: 1 },
                qds: Qds::default(),
            },
        }],
    )
    .expect("the layout builds it")
}

/// The `QCC` of a type-101 frame.
fn qcc_of(asdu: &[u8]) -> Qcc {
    decode_asdu::<iec104::asdu::CCiNa1>(asdu).expect("type 101")[0]
        .value
        .qcc
}

/// Asserts a frame is a type-101 ASDU of `cause` carrying `request`/`freeze`.
fn assert_counter_frame(
    asdu: &[u8],
    cause: Cause,
    negative: bool,
    request: Request,
    freeze: FreezeMode,
) {
    let header = Header::parse(asdu).expect("header");
    assert_eq!(header.type_id, TYPE_ID);
    assert_eq!(header.type_id, TypeId::CCiNa1);
    assert_eq!(header.cause, cause);
    assert_eq!(header.negative, negative, "P/N");
    assert!(!header.test, "T = 0 in normal conditions");
    assert!(!header.sequence, "Single information object (SQ = 0)");
    assert_eq!(header.count, 1, "N = 1");
    assert_eq!(header.common_address, CA);
    assert_eq!(&asdu[6..9], &[0, 0, 0], "INFORMATION OBJECT ADDRESS = 0");
    let qcc = qcc_of(asdu);
    assert_eq!(qcc.rqt, request.rqt(), "RQT");
    assert_eq!(qcc.frz, freeze, "FRZ");
}

/// A controlled station's data: which totals each request returns.
struct Device {
    ready: bool,
    objects: Vec<(Request, Vec<u8>)>,
}

impl Device {
    /// The station's data: two general totals (untagged `M_IT_NA_1` and tagged
    /// `M_IT_TB_1`) and one of group 2 and group 3 each.
    fn new() -> Self {
        Self {
            ready: true,
            objects: vec![
                (
                    Request::General,
                    total(Request::General.cause(), 0x3010, 101),
                ),
                (
                    Request::General,
                    total_tagged(Request::General.cause(), 0x3011, 102),
                ),
                (
                    Request::Group(2),
                    total(Request::Group(2).cause(), 0x3020, 202),
                ),
                (
                    Request::Group(3),
                    total_tagged(Request::Group(3).cause(), 0x3030, 303),
                ),
            ],
        }
    }

    /// A data source that offers nothing and is not ready.
    const fn silent() -> Self {
        Self {
            ready: false,
            objects: Vec::new(),
        }
    }
}

impl CounterSource for Device {
    fn ready(&self, _request: Request) -> bool {
        self.ready
    }

    fn totals(&self, request: Request, out: &mut Vec<Vec<u8>>) {
        for (owner, asdu) in &self.objects {
            if *owner == request {
                out.push(asdu.clone());
            }
        }
    }
}

/// Drives one whole exchange between the two roles and returns the frames each
/// side sent, plus the controlling station's classification of the other side's
/// frames.
fn drive(
    mode: CounterMode,
    request: Request,
    freeze: FreezeMode,
    device: &Device,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<Reaction>) {
    let known = Known::EVERYTHING;
    let mut controlling = CounterInterrogation::controlling(mode, CA, 0);
    let mut controlled = CounterInterrogation::controlled(mode, CA, 0);

    let from_controlling = vec![
        controlling
            .request(request, freeze)
            .expect("the mode issues it"),
    ];
    let mut from_controlled = Vec::new();

    let outcome = controlled
        .on_request(&from_controlling[0], &known, device)
        .expect("the mode accepts it");
    from_controlled.extend(outcome.send.clone());
    if outcome.reaction
        == (Reaction::ActivationConfirmed {
            request,
            freeze,
            negative: !device.ready,
        })
        && freeze == FreezeMode::Read
        && device.ready
    {
        from_controlled.extend(
            controlled
                .interrogated(device)
                .expect("a collection owes data"),
        );
        from_controlled.extend(
            controlled
                .complete(device)
                .expect("a collection terminates"),
        );
    }

    let mut reactions = Vec::new();
    for frame in &from_controlled {
        reactions.push(
            controlling
                .on_response(frame, &known)
                .expect("well formed")
                .reaction,
        );
    }
    (from_controlling, from_controlled, reactions)
}

// ---------------------------------------------------------------- the request

#[test]
fn the_activation_is_ten_octets_field_for_field() {
    let freezes = [
        FreezeMode::Read,
        FreezeMode::FreezeWithoutReset,
        FreezeMode::FreezeWithReset,
        FreezeMode::Reset,
    ];
    let requests = [
        Request::General,
        Request::Group(1),
        Request::Group(2),
        Request::Group(3),
        Request::Group(4),
    ];
    for wanted in requests {
        for freeze in freezes {
            let asdu = request(wanted, freeze, CA, 0).unwrap();
            assert_eq!(asdu.len(), 10, "six header octets, three IOA, one QCC");
            assert_counter_frame(&asdu, CAUSE_ACTIVATION, false, wanted, freeze);
            assert_eq!(asdu[2], 0x06, "cause 6 act in octet 2");
            assert_eq!(asdu[3], 0x00, "originator");
            // The qualifier is octet 9, and the two fields share it: RQT in
            // bits 1..6 (0x3F), FRZ in bits 7..8 (0xC0), as in clause
            // 7.2.6.23's `CP8{RQT,FRZ}`.
            assert_eq!(
                asdu[9],
                wanted.rqt() | (freeze.to_bits() << 6),
                "RQT | FRZ << 6"
            );
        }
    }
}

#[test]
fn the_qcc_octet_is_six_bits_and_two_bits_not_two_nibbles() {
    // `QCC := CP8{RQT,FRZ}`, RQT `UI6[1..6]` = 0x3F, FRZ `UI2[7..8]` = 0xC0.
    // A four-and-four reading would put RQT 5 in the high nibble (0x50) and
    // FRZ 3 in the low one (0x03).
    assert_eq!(
        Qcc {
            rqt: 5,
            frz: FreezeMode::Read
        }
        .raw(),
        0x05
    );
    assert_eq!(
        Qcc {
            rqt: 1,
            frz: FreezeMode::Reset
        }
        .raw(),
        0xC1
    );
    // The element keeps its two fields in the same octet and round-trips.
    let raw = Qcc {
        rqt: 4,
        frz: FreezeMode::FreezeWithReset,
    }
    .raw();
    assert_eq!(raw, 0x84, "4 | 2 << 6");
    assert_eq!(Qcc::from_raw(raw).rqt, 4);
    assert_eq!(Qcc::from_raw(raw).frz, FreezeMode::FreezeWithReset);
}

#[test]
fn the_request_names_the_causes_of_transmission_of_its_objects() {
    assert_eq!(Request::General.cause(), Cause::RequestedByGeneralCounter);
    assert_eq!(Request::Group(2).cause(), Cause::RequestedByCounterGroup(2));
    // `<37>` general, `<38>` … `<41>` group 1 … 4, and back.
    assert_eq!(Request::General.rqt(), 5);
    assert_eq!(Request::Group(4).rqt(), 4);
    for n in 1..=4u8 {
        assert_eq!(Request::Group(n).cause(), Cause::RequestedByCounterGroup(n));
        assert_eq!(
            Request::from_cause(Request::Group(n).cause()),
            Some(Request::Group(n))
        );
    }
    assert_eq!(
        Request::from_cause(Cause::RequestedByGeneralCounter),
        Some(Request::General)
    );
    assert_eq!(Request::from_cause(Cause::InterrogatedByGroup(2)), None);
    assert_eq!(Request::from_cause(Cause::Activation), None);
}

#[test]
fn the_rqt_maps_only_its_defined_values() {
    // `<0>` "no counter requested (not used)", `<1>`..`<4>` groups,
    // `<5>` general, `<6..31>` reserved, `<32..63>` private.
    assert_eq!(Request::from_rqt(0), None);
    assert_eq!(Request::from_rqt(1), Some(Request::Group(1)));
    assert_eq!(Request::from_rqt(4), Some(Request::Group(4)));
    assert_eq!(Request::from_rqt(5), Some(Request::General));
    for rqt in 6..=63u8 {
        assert_eq!(Request::from_rqt(rqt), None, "RQT {rqt}");
    }
    for rqt in 64..=255u8 {
        assert_eq!(Request::from_rqt(rqt), None, "RQT {rqt}");
    }
    // Out-of-range group numbers are clamped rather than put on the wire.
    assert_eq!(Request::group(0), Request::Group(1));
    assert_eq!(Request::group(9), Request::Group(4));
    assert_eq!(Request::Group(9).rqt(), 4);
    assert_eq!(Request::Group(0).rqt(), 1);
    assert_eq!(Request::Group(9).group_number(), Some(4));
    assert_eq!(Request::General.group_number(), None);
    assert!(Request::General.is_general());
    assert!(!Request::Group(1).is_general());
}

#[test]
fn the_counter_family_is_the_two_m_it_types_104_selects() {
    assert_eq!(COUNTER_TYPES, [TypeId::MItNa1, TypeId::MItTb1]);
    assert!(is_counter_type(TypeId::MItNa1));
    assert!(is_counter_type(TypeId::MItTb1));
    // 5-101 clause 7.3.1 defines a third M_IT type, and it is *not* one of the
    // family: 5-104 clause 9 (PDF page index 100, printed page 99) says "In
    // this companion standard only the use of the set <30> - <40> for ASDUs
    // with time tag is permitted.", and type 16 is outside that set. The
    // crate's own catalogue already answers the question, so the two cannot
    // drift.
    assert!(!TypeId::MItTa1.is_selected_104());
    assert!(!is_counter_type(TypeId::MItTa1));
    // A measured-value type is not a counter, and neither is the GI command.
    assert!(!is_counter_type(TypeId::MMeNb1));
    assert!(!is_counter_type(TypeId::CIcNa1));
}

// ---------------------------------------------------------------- the cycle

#[test]
fn the_scripted_collection_of_every_request() {
    // The acceptance test: one exchange per RQT value, the COT of every
    // response asserted, and the termination closing it.
    let device = Device::new();
    for request in [
        Request::General,
        Request::Group(1),
        Request::Group(2),
        Request::Group(3),
        Request::Group(4),
    ] {
        let (from_controlling, from_controlled, reactions) = drive(
            CounterMode::FreezeAndTransmit,
            request,
            FreezeMode::Read,
            &device,
        );

        // The request is cause 6 with the request and FRZ = 0.
        assert_counter_frame(
            &from_controlling[0],
            CAUSE_ACTIVATION,
            false,
            request,
            FreezeMode::Read,
        );

        // The confirmation mirrors the request, the objects carry the
        // request's own cause, and the termination closes the collection.
        assert_counter_frame(
            &from_controlled[0],
            CAUSE_ACTIVATION_CON,
            false,
            request,
            FreezeMode::Read,
        );

        let expected_objects: Vec<usize> = device
            .objects
            .iter()
            .enumerate()
            .filter(|(_, (owner, _))| *owner == request)
            .map(|(i, _)| i)
            .collect();
        for (offset, _) in expected_objects.iter().enumerate() {
            let asdu = &from_controlled[1 + offset];
            let header = Header::parse(asdu).unwrap();
            assert!(is_counter_type(header.type_id));
            assert_eq!(header.cause, request.cause(), "the object's COT");
        }
        let termination = from_controlled.last().unwrap();
        assert_counter_frame(
            termination,
            CAUSE_ACTIVATION_TERM,
            false,
            request,
            FreezeMode::Read,
        );

        // The controlling station's classification, frame by frame.
        assert_eq!(
            reactions[0],
            Reaction::ActivationConfirmed {
                request,
                freeze: FreezeMode::Read,
                negative: false,
            }
        );
        for reaction in &reactions[1..reactions.len() - 1] {
            assert_eq!(*reaction, Reaction::Counted { request });
        }
        assert_eq!(*reactions.last().unwrap(), Reaction::Terminated { request });
    }
}

#[test]
fn the_scripted_collection_sends_the_general_and_group_objects_in_cause_order() {
    let device = Device::new();
    // Group 2's one object comes with cause 39 (`reqco2`). The group-1 cause
    // is <38>, so the group number and the cause differ by 37.
    let (_, from_controlled, reactions) = drive(
        CounterMode::FreezeAndTransmit,
        Request::Group(2),
        FreezeMode::Read,
        &device,
    );
    let object = &from_controlled[1];
    assert_eq!(
        Header::parse(object).unwrap().cause,
        Cause::RequestedByCounterGroup(2)
    );
    // The octet itself, not only the decode that would agree with any encoder.
    assert_eq!(object[2], 39, "cause 39 = reqco2 in octet 2");
    assert_eq!(
        reactions[1],
        Reaction::Counted {
            request: Request::Group(2)
        }
    );
    // A group nobody asked for is not reported.
    assert!(!reactions.contains(&Reaction::Counted {
        request: Request::Group(4)
    }));
}

#[test]
fn a_memorize_is_confirmed_and_not_terminated() {
    // 5-101 figure 95: `C_CI ACT` (FRZ = 1) -> `C_CI ACTCON` (FRZ = 1), then
    // "Continue with the collection of the frozen values as described in mode
    // B". No data and no ACTTERM belong to the memorize transaction.
    let device = Device::new();
    for freeze in [
        FreezeMode::FreezeWithoutReset,
        FreezeMode::FreezeWithReset,
        FreezeMode::Reset,
    ] {
        let (from_controlling, from_controlled, reactions) = drive(
            CounterMode::FreezeAndTransmit,
            Request::General,
            freeze,
            &device,
        );

        assert_counter_frame(
            &from_controlling[0],
            CAUSE_ACTIVATION,
            false,
            Request::General,
            freeze,
        );
        assert_eq!(
            from_controlled.len(),
            1,
            "the confirmation and nothing else"
        );
        assert_counter_frame(
            &from_controlled[0],
            CAUSE_ACTIVATION_CON,
            false,
            Request::General,
            freeze,
        );
        assert_eq!(
            reactions,
            vec![Reaction::ActivationConfirmed {
                request: Request::General,
                freeze,
                negative: false,
            }]
        );

        // The controlled station has nothing to collect and nothing to
        // terminate, and the controlling station keeps no running procedure.
        let mut controlled =
            CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
        let known = Known::EVERYTHING;
        controlled
            .on_request(&from_controlling[0], &known, &device)
            .unwrap();
        assert!(!controlled.awaiting_data());
        assert_eq!(controlled.interrogated(&device), Err(CiError::NotRunning));
        assert_eq!(controlled.complete(&device), Err(CiError::NotRunning));

        let mut controlling =
            CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
        controlling.request(Request::General, freeze).unwrap();
        controlling
            .on_response(&from_controlled[0], &known)
            .unwrap();
        assert!(
            controlling.running().is_empty(),
            "a memorize is never running"
        );
    }
}

/// Abandoning one request forgets it and nothing else, whether its
/// confirmation is still awaited or it is running.
#[test]
fn abandoning_a_request_forgets_only_that_request() {
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    controlling
        .request(Request::General, FreezeMode::Read)
        .unwrap();
    controlling
        .request(Request::Group(2), FreezeMode::Read)
        .unwrap();

    assert!(controlling.abandon(Request::General));
    assert!(!controlling.is_running(Request::General));
    assert!(controlling.is_running(Request::Group(2)));
    assert!(!controlling.abandon(Request::General), "already forgotten");
}

#[test]
fn the_termination_mirrors_the_command_it_closes() {
    let device = Device::new();
    // The collection is the FRZ = 0 command, so the termination carries FRZ = 0
    // and the same RQT (TS 604 Table 20: "sends the same Counter interrogation
    // command it received (ASDU 101) with COT = 10").
    let (_, from_controlled, _) = drive(
        CounterMode::FreezeAndTransmit,
        Request::Group(3),
        FreezeMode::Read,
        &device,
    );
    let termination = from_controlled.last().unwrap();
    let qcc = qcc_of(termination);
    assert_eq!(qcc.rqt, 3);
    assert_eq!(qcc.frz, FreezeMode::Read);
    assert_eq!(
        Header::parse(termination).unwrap().cause,
        Cause::ActivationTermination
    );
}

#[test]
fn the_negative_confirmation_leaves_the_request_repeatable() {
    // The clause names no "not ready" case for counters; the type's cause list
    // carries <7> with the P/N flag, so a data source that is not ready gets a
    // negative confirmation and no state changes.
    let device = Device::silent();
    let known = Known::EVERYTHING;
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    let act = request(Request::General, FreezeMode::Read, CA, 0).unwrap();

    let outcome = controlled.on_request(&act, &known, &device).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::ActivationConfirmed {
            request: Request::General,
            freeze: FreezeMode::Read,
            negative: true,
        }
    );
    assert_counter_frame(
        &outcome.send[0],
        CAUSE_ACTIVATION_CON,
        true,
        Request::General,
        FreezeMode::Read,
    );
    assert!(!controlled.awaiting_data(), "nothing is owed");
    assert!(controlled.running().is_empty(), "nothing is running");

    // It starts and completes, and the controlling side accepts the mirror.
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    controlling
        .request(Request::General, FreezeMode::Read)
        .unwrap();
    let mirror = actcon(true, Request::General, FreezeMode::Read);
    assert_eq!(
        controlling.on_response(&mirror, &known).unwrap().reaction,
        Reaction::ActivationConfirmed {
            request: Request::General,
            freeze: FreezeMode::Read,
            negative: true,
        }
    );
    assert!(
        controlling.running().is_empty(),
        "a negative confirms nothing"
    );
}

/// Builds one type-101 answer frame directly: an activation confirmation or a
/// termination, with the `QCC` and the `P/N` bit the test asks for.
fn actcon(negative: bool, request: Request, freeze: FreezeMode) -> Vec<u8> {
    let header = Header {
        type_id: TYPE_ID,
        sequence: false,
        count: 1,
        cause: CAUSE_ACTIVATION_CON,
        negative,
        test: false,
        originator: 0,
        common_address: CA,
    };
    encode_asdu(
        &header,
        &[LayoutObject {
            ioa: 0,
            value: iec104::asdu::CCiNa1 {
                qcc: request.qcc(freeze),
            },
        }],
    )
    .expect("the layout builds it")
}

#[test]
fn a_second_activation_is_honoured_and_its_data_is_owed_once() {
    // No clause locks a second counter interrogation (unlike GI's 7.4.5) and
    // Table 20 defines no re-activation options, so a repeat is honoured.
    let device = Device::new();
    let known = Known::EVERYTHING;
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    let act = request(Request::Group(2), FreezeMode::Read, CA, 0).unwrap();

    let first = controlled.on_request(&act, &known, &device).unwrap();
    let second = controlled.on_request(&act, &known, &device).unwrap();
    assert_eq!(first.reaction, second.reaction);
    assert_eq!(controlled.running(), vec![Request::Group(2)]);
    assert!(controlled.awaiting_data());

    // One collection is owed, so one data call and one termination.
    let totals = controlled.interrogated(&device).unwrap();
    assert_eq!(totals.len(), 1);
    assert_eq!(controlled.interrogated(&device), Err(CiError::NotRunning));
    controlled.complete(&device).unwrap();
    assert_eq!(controlled.running(), [] as [iec104::ci::Request; 0]);
}

#[test]
fn a_deactivation_of_this_type_is_not_the_procedure() {
    // 5-101 clause 7.4.8: "C_CI DEACT and DEACTCON are not used." A type-101
    // ASDU carrying cause 8 or 9 is therefore not a frame of this procedure.
    let known = Known::EVERYTHING;
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    let device = Device::new();

    for cause in [Cause::Deactivation, Cause::DeactivationCon] {
        let header = Header {
            type_id: TYPE_ID,
            sequence: false,
            count: 1,
            cause,
            negative: false,
            test: false,
            originator: 0,
            common_address: CA,
        };
        let frame = encode_asdu(
            &header,
            &[LayoutObject {
                ioa: 0,
                value: iec104::asdu::CCiNa1 {
                    qcc: Request::General.qcc(FreezeMode::Read),
                },
            }],
        )
        .unwrap();
        assert_eq!(
            controlling.on_response(&frame, &known).unwrap(),
            Outcome {
                reaction: Reaction::Other,
                send: Vec::new()
            }
        );
        assert_eq!(
            controlled.on_request(&frame, &known, &device).unwrap(),
            Outcome {
                reaction: Reaction::Other,
                send: Vec::new()
            }
        );
    }
}

#[test]
fn a_confirmation_nobody_asked_for_is_other() {
    let known = Known::EVERYTHING;
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    let mirror = actcon(false, Request::General, FreezeMode::Read);
    assert_eq!(
        controlling.on_response(&mirror, &known).unwrap().reaction,
        Reaction::Other
    );

    // A termination for a request that is not running is Other too: the
    // responses of a collection end at the termination, so a later object no
    // longer belongs to it.
    let mut running = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    running
        .request(Request::Group(1), FreezeMode::Read)
        .unwrap();
    let stray = actcon(false, Request::Group(1), FreezeMode::Read);
    running.on_response(&stray, &known).unwrap();
    let termination = {
        let mut controlled =
            CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
        let act = request(Request::Group(1), FreezeMode::Read, CA, 0).unwrap();
        let device = Device::new();
        controlled.on_request(&act, &known, &device).unwrap();
        // Data first, then the termination: the termination is the last frame.
        controlled.complete(&device).unwrap().pop().unwrap()
    };
    assert_eq!(
        running.on_response(&termination, &known).unwrap().reaction,
        Reaction::Terminated {
            request: Request::Group(1)
        }
    );
    // Now it is gone: the same termination again is Other, and so is an object.
    assert_eq!(
        running.on_response(&termination, &known).unwrap().reaction,
        Reaction::Other
    );
    let object = total(Request::Group(1).cause(), 0x3020, 7);
    assert_eq!(
        running.on_response(&object, &known).unwrap().reaction,
        Reaction::Other
    );
}

#[test]
fn a_reserved_rqt_is_not_this_procedure() {
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    for rqt in [0u8, 6, 31, 32, 63] {
        let header = Header {
            type_id: TYPE_ID,
            sequence: false,
            count: 1,
            cause: CAUSE_ACTIVATION,
            negative: false,
            test: false,
            originator: 0,
            common_address: CA,
        };
        let frame = encode_asdu(
            &header,
            &[LayoutObject {
                ioa: 0,
                value: iec104::asdu::CCiNa1 {
                    qcc: Qcc {
                        rqt,
                        frz: FreezeMode::Read,
                    },
                },
            }],
        )
        .unwrap();
        assert_eq!(
            controlled
                .on_request(&frame, &known, &device)
                .unwrap()
                .reaction,
            Reaction::Other,
            "RQT {rqt}"
        );
    }
}

// ---------------------------------------------------------------- the modes

#[test]
fn mode_a_issues_no_counter_interrogation_commands() {
    // 5-101 cl.7.4.8 mode A: "The controlling station does not issue counter
    // interrogation commands (C_CI)."
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut controlling =
        CounterInterrogation::controlling(CounterMode::LocalFreezeSpontaneous, CA, 0);
    assert_eq!(
        controlling.request(Request::General, FreezeMode::Read),
        Err(CiError::RequestsNotAccepted {
            mode: CounterMode::LocalFreezeSpontaneous
        })
    );

    let mut controlled =
        CounterInterrogation::controlled(CounterMode::LocalFreezeSpontaneous, CA, 0);
    let act = request(Request::General, FreezeMode::Read, CA, 0).unwrap();
    assert_rejected(
        controlled.on_request(&act, &known, &device),
        Request::General,
        FreezeMode::Read,
        CiError::RequestsNotAccepted {
            mode: CounterMode::LocalFreezeSpontaneous,
        },
    );
}

/// A mode violation is answered with a negative `ACTCON`, so the peer is not
/// left waiting, and the reason is reported to the caller.
fn assert_rejected(
    received: Result<Outcome, CiError>,
    request: Request,
    freeze: FreezeMode,
    reason: CiError,
) {
    let outcome = received.expect("answered, not an error");
    assert_eq!(
        outcome.reaction,
        Reaction::Rejected {
            request,
            freeze,
            reason
        }
    );
    assert_eq!(outcome.send, [actcon(true, request, freeze)]);
}

#[test]
fn mode_b_refuses_a_freeze_and_accepts_a_collection() {
    // Mode B: "the command qualifier must contain FRZ = 0".
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut controlled =
        CounterInterrogation::controlled(CounterMode::LocalFreezeByInterrogation, CA, 0);

    for freeze in [
        FreezeMode::FreezeWithoutReset,
        FreezeMode::FreezeWithReset,
        FreezeMode::Reset,
    ] {
        let act = request(Request::General, freeze, CA, 0).unwrap();
        assert_rejected(
            controlled.on_request(&act, &known, &device),
            Request::General,
            freeze,
            CiError::FreezeNotAllowed {
                mode: CounterMode::LocalFreezeByInterrogation,
            },
        );
    }

    let read = request(Request::Group(2), FreezeMode::Read, CA, 0).unwrap();
    let outcome = controlled.on_request(&read, &known, &device).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::ActivationConfirmed {
            request: Request::Group(2),
            freeze: FreezeMode::Read,
            negative: false,
        }
    );
}

#[test]
fn modes_c_and_d_accept_a_freeze() {
    let known = Known::EVERYTHING;
    let device = Device::new();
    for mode in [
        CounterMode::FreezeAndTransmit,
        CounterMode::FreezeSpontaneous,
    ] {
        let mut controlled = CounterInterrogation::controlled(mode, CA, 0);
        let act = request(Request::General, FreezeMode::FreezeWithoutReset, CA, 0).unwrap();
        assert!(
            controlled.on_request(&act, &known, &device).is_ok(),
            "{mode:?}"
        );
    }
}

#[test]
fn mode_d_refuses_a_collection_because_its_values_are_spontaneous() {
    // 5-101 clause 7.4.8 defines mode D as "a combination of the counter
    // command from the controlling station as specified in mode C, with
    // spontaneous reporting of the integrated totals, as described in mode A",
    // and TS 60870-5-604 Table 20's mode D procedure (test 5.4.20.30) draws
    // exactly that: "C_CI_ACT, FRZ=1..3 (freeze, freeze with reset, reset)"
    // and then "M_IT_SPONT" with "COT = 3 (SPONT)": no collection, and no
    // C_CI_ACTTERM. A FRZ = 0 activation is therefore not that mode's
    // procedure, on either side.
    let known = Known::EVERYTHING;
    let device = Device::new();
    let read = request(Request::General, FreezeMode::Read, CA, 0).unwrap();

    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeSpontaneous, CA, 0);
    assert_rejected(
        controlled.on_request(&read, &known, &device),
        Request::General,
        FreezeMode::Read,
        CiError::CollectionNotAllowed {
            mode: CounterMode::FreezeSpontaneous,
        },
    );
    assert!(!controlled.is_running(Request::General));

    // The freeze mode D *does* use is still accepted...
    let act = request(Request::General, FreezeMode::FreezeWithoutReset, CA, 0).unwrap();
    assert!(controlled.on_request(&act, &known, &device).is_ok());
    // ...and so is the collection on the two modes the procedure belongs to.
    for mode in [
        CounterMode::LocalFreezeByInterrogation,
        CounterMode::FreezeAndTransmit,
    ] {
        let mut station = CounterInterrogation::controlled(mode, CA, 0);
        assert!(
            station.on_request(&read, &known, &device).is_ok(),
            "{mode:?}"
        );
    }

    // The controlling station will not build it either.
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeSpontaneous, CA, 0);
    assert_eq!(
        controlling.request(Request::General, FreezeMode::Read),
        Err(CiError::CollectionNotAllowed {
            mode: CounterMode::FreezeSpontaneous
        })
    );
}

#[test]
fn the_mode_predicates_are_the_clauses_own_rules() {
    assert!(!CounterMode::LocalFreezeSpontaneous.accepts_requests());
    for mode in [
        CounterMode::LocalFreezeByInterrogation,
        CounterMode::FreezeAndTransmit,
        CounterMode::FreezeSpontaneous,
    ] {
        assert!(mode.accepts_requests(), "{mode:?}");
    }
    assert!(!CounterMode::LocalFreezeByInterrogation.accepts_freeze());
    assert!(!CounterMode::LocalFreezeSpontaneous.accepts_freeze());
    assert!(CounterMode::FreezeAndTransmit.accepts_freeze());
    assert!(CounterMode::FreezeSpontaneous.accepts_freeze());
    assert!(CounterMode::LocalFreezeSpontaneous.reports_spontaneously());
    assert!(CounterMode::FreezeSpontaneous.reports_spontaneously());
    assert!(!CounterMode::LocalFreezeByInterrogation.reports_spontaneously());
    assert!(!CounterMode::FreezeAndTransmit.reports_spontaneously());
    assert!(!CounterMode::LocalFreezeSpontaneous.accepts_collection());
    assert!(CounterMode::LocalFreezeByInterrogation.accepts_collection());
    assert!(CounterMode::FreezeAndTransmit.accepts_collection());
    assert!(!CounterMode::FreezeSpontaneous.accepts_collection());
}

// ---------------------------------------------------------------- the payload

#[test]
fn the_data_source_is_checked_before_anything_reaches_the_wire() {
    // The two M_IT types 104 selects are accepted; anything else is refused.
    let known = Known::EVERYTHING;
    for good in [
        total(Request::General.cause(), 1, 1),
        total_tagged(Request::General.cause(), 2, 2),
    ] {
        let device = Device {
            ready: true,
            objects: vec![(Request::General, good.clone())],
        };
        let mut controlled =
            CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
        let act = request(Request::General, FreezeMode::Read, CA, 0).unwrap();
        controlled.on_request(&act, &known, &device).unwrap();
        assert_eq!(controlled.interrogated(&device).unwrap(), vec![good]);
    }

    // 5-101 clause 7.3.1's third M_IT type is a counter on the wire, but not
    // one a 104 station may answer with (5-104 clause 9: only the set
    // <30> to <40> may carry a time tag), so the data source's offer is refused
    // by type rather than sent.
    let short_tagged = Device {
        ready: true,
        objects: vec![(
            Request::General,
            total_short_tagged(Request::General.cause(), 3, 3),
        )],
    };
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    let act = request(Request::General, FreezeMode::Read, CA, 0).unwrap();
    controlled.on_request(&act, &known, &short_tagged).unwrap();
    assert_eq!(
        controlled.interrogated(&short_tagged),
        Err(CiError::NotCounterType {
            type_id: TypeId::MItTa1
        })
    );

    let wrong_type = Device {
        ready: true,
        objects: vec![(
            Request::General,
            measured(Cause::RequestedByGeneralCounter, 4),
        )],
    };
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    let act = request(Request::General, FreezeMode::Read, CA, 0).unwrap();
    controlled.on_request(&act, &known, &wrong_type).unwrap();
    assert_eq!(
        controlled.interrogated(&wrong_type),
        Err(CiError::NotCounterType {
            type_id: TypeId::MMeNb1
        })
    );

    let wrong_cause = Device {
        ready: true,
        objects: vec![(Request::General, total(Cause::InterrogatedByStation, 5, 5))],
    };
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    controlled.on_request(&act, &known, &wrong_cause).unwrap();
    assert_eq!(
        controlled.interrogated(&wrong_cause),
        Err(CiError::WrongCause {
            expected: Cause::RequestedByGeneralCounter,
            got: Cause::InterrogatedByStation,
        })
    );
}

#[test]
fn the_discard_rule_runs_first() {
    // Clause 7.2.3: an unknown type identification, an unknown information
    // object address and a mirror are discarded, not treated as this
    // procedure, exactly as `src/init.rs` and `src/gi.rs` do it.
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);

    // An M_IT object for a type the catalogue does not define. `Known` is the
    // station's answer about *this* ASDU, so the type question is turned off
    // for it (clause 7.2.3's first class, cause 44).
    let unknown_type = {
        let mut asdu = total(Request::General.cause(), 1, 1);
        asdu[0] = 250;
        asdu
    };
    let type_unknown = Known {
        type_id: false,
        ..Known::EVERYTHING
    };
    assert!(matches!(
        controlling
            .on_response(&unknown_type, &type_unknown)
            .unwrap()
            .reaction,
        Reaction::Discard(_)
    ));
    // The controlled station mirrors it instead (cause 44, P/N = 1).
    let mirrored = controlled
        .on_request(&unknown_type, &type_unknown, &device)
        .unwrap();
    assert_eq!(
        mirrored.reaction,
        Reaction::Refused {
            activation: None,
            cause: Cause::UnknownTypeId
        }
    );
    let header = Header::parse(&mirrored.send[0]).unwrap();
    assert!(header.negative);
    assert_eq!(header.cause, Cause::UnknownTypeId);
    assert_eq!(
        &mirrored.send[0][Header::LEN..],
        &unknown_type[Header::LEN..]
    );

    // An unknown information object address inside a response: the profile
    // answers clause 7.2.3's address question with `false`, and the class is
    // the fourth of the clause's table (cause 47).
    let addresses_unknown = Known {
        information_object_address: false,
        ..Known::EVERYTHING
    };
    let unknown_ioa = total(Request::General.cause(), 0x9999, 1);
    assert!(matches!(
        controlling
            .on_response(&unknown_ioa, &addresses_unknown)
            .unwrap()
            .reaction,
        Reaction::Discard(_)
    ));

    // A mirror (P/N = 1 with one of the 44–47 causes) is logged, never
    // mirrored back.
    let mut mirror = total(Request::General.cause(), 1, 1);
    mirror[2] |= 0x40; // P/N
    mirror[2] = (mirror[2] & 0xC0) | 0x2F; // cause 47, P/N = 1
    assert!(matches!(
        controlling.on_response(&mirror, &known).unwrap().reaction,
        Reaction::Discard(_)
    ));
}

#[test]
fn every_short_prefix_of_a_real_frame_is_a_typed_error() {
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    let act = request(Request::General, FreezeMode::FreezeWithReset, CA, 0).unwrap();
    let answer = actcon(false, Request::General, FreezeMode::FreezeWithReset);

    // The controlled station decodes every activation's `QCC`, so every prefix
    // of one is a typed error rather than a panic.
    for len in 0..act.len() {
        let prefix = &act[..len];
        let received = controlled.on_request(prefix, &known, &device);
        assert!(
            matches!(received, Err(CiError::Layout(_))),
            "prefix {len} on the controlled side, got {received:?}"
        );
    }

    // The controlling station decodes the `QCC` of every answer, so every
    // prefix of one is a typed error too.
    for len in 0..answer.len() {
        let prefix = &answer[..len];
        let received = controlling.on_response(prefix, &known);
        assert!(
            matches!(received, Err(CiError::Layout(_))),
            "prefix {len} of the confirmation, got {received:?}"
        );
    }
}

#[test]
fn the_layout_refuses_the_count_and_sequence_the_figure_does_not_have() {
    // Figure 73 heads the type "Single information object (SQ = 0)", so N ≥ 2
    // and SQ = 1 are not type 101's shapes. The reader refuses them before the
    // procedure sees a QCC.
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);

    // N = 2, SQ = 0: two IOAs and two QCCs.
    let n2 = [
        0x65, 0x02, 0x06, 0x00, 0x0C, 0x00, 0, 0, 0, 0x05, 0, 0, 0, 0x05,
    ];
    assert!(matches!(
        controlled.on_request(&n2, &known, &device),
        Err(CiError::Layout(LayoutError::ObjectCountNotAllowed { .. }))
    ));

    // SQ = 1, N = 1: one base address and one QCC.
    let sq1 = [0x65, 0x81, 0x06, 0x00, 0x0C, 0x00, 0, 0, 0, 0x05];
    assert!(matches!(
        controlled.on_request(&sq1, &known, &device),
        Err(CiError::Layout(LayoutError::SequenceNotAllowed { .. }))
    ));
}

#[test]
fn the_roles_are_guarded_on_every_entry_point() {
    let known = Known::EVERYTHING;
    let device = Device::new();
    let act = request(Request::General, FreezeMode::Read, CA, 0).unwrap();
    let mirror = actcon(false, Request::General, FreezeMode::Read);

    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    assert_eq!(
        controlling.on_request(&act, &known, &device),
        Err(CiError::WrongRole)
    );
    assert_eq!(controlling.interrogated(&device), Err(CiError::WrongRole));
    assert_eq!(controlling.complete(&device), Err(CiError::WrongRole));

    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    assert_eq!(
        controlled.request(Request::General, FreezeMode::Read),
        Err(CiError::WrongRole)
    );
    assert_eq!(
        controlled.on_response(&mirror, &known),
        Err(CiError::WrongRole)
    );
}

#[test]
fn the_role_is_the_procedures_not_the_transports() {
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut station = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    assert_eq!(station.role(), Role::Controlling);
    assert_eq!(station.mode(), CounterMode::FreezeAndTransmit);
    assert_eq!(station.addressing(), (CA, 0));
    let act = station.request(Request::General, FreezeMode::Read).unwrap();
    assert_eq!(station.awaiting_confirmation(), &[Request::General]);

    // The same station type holds the other role's instance for the reverse
    // direction.
    let mut server = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    assert_eq!(server.role(), Role::Controlled);
    server.on_request(&act, &known, &device).unwrap();
    assert!(server.awaiting_data());
    assert_eq!(server.running(), vec![Request::General]);
}

#[test]
fn an_asdu_this_procedure_does_not_own_is_other() {
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);

    // An `M_ME_NB_1` with the counter cause is not an M_IT object.
    let not_a_counter = measured(Cause::RequestedByGeneralCounter, 1);
    asserting_other(
        &mut controlling,
        &mut controlled,
        known,
        &device,
        &not_a_counter,
    );

    // A type-101 frame with a cause the list does not carry.
    let mut stray = request(Request::General, FreezeMode::Read, CA, 0).unwrap();
    stray[2] = 0x01; // cause 1, periodic
    asserting_other(&mut controlling, &mut controlled, known, &device, &stray);

    // A non-counter type on the wire is not this procedure either.
    let other_type = {
        let mut asdu = measured(Cause::Activation, 1);
        asdu[2] = 0x06;
        asdu
    };
    asserting_other(
        &mut controlling,
        &mut controlled,
        known,
        &device,
        &other_type,
    );
}

/// Asserts both roles classify `asdu` as [`Reaction::Other`].
fn asserting_other(
    controlling: &mut CounterInterrogation,
    controlled: &mut CounterInterrogation,
    known: Known,
    device: &Device,
    asdu: &[u8],
) {
    assert_eq!(
        controlling.on_response(asdu, &known).unwrap().reaction,
        Reaction::Other
    );
    assert_eq!(
        controlled
            .on_request(asdu, &known, device)
            .unwrap()
            .reaction,
        Reaction::Other
    );
}

#[test]
fn a_request_and_its_mirror_are_byte_identical_but_for_the_cause_and_pn() {
    // The confirmation repeats the request's own RQT and FRZ; only the cause
    // octet and the P/N bit differ.
    let asdu = request(Request::Group(4), FreezeMode::FreezeWithReset, CA, 0).unwrap();
    let mirror = actcon(false, Request::Group(4), FreezeMode::FreezeWithReset);
    assert_eq!(asdu.len(), mirror.len());
    assert_eq!(asdu[0], mirror[0], "type");
    assert_eq!(asdu[1], mirror[1], "VSQ");
    assert_eq!(asdu[3], mirror[3], "originator");
    assert_eq!(asdu[4..], mirror[4..], "CA, IOA and QCC");
    assert_eq!(asdu[2], 0x06);
    assert_eq!(mirror[2], 0x07);
}

// ------------------------------------------------------------- recovery

/// Two collections running at once each get their own data, then their own
/// termination.
#[test]
fn concurrent_collections_each_get_their_data() {
    let device = Device::new();
    let known = Known::EVERYTHING;
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    for group in [2, 3] {
        let act = request(Request::Group(group), FreezeMode::Read, CA, 0).unwrap();
        controlled.on_request(&act, &known, &device).unwrap();
    }

    for group in [2, 3] {
        let data = controlled.interrogated(&device).expect("its data");
        assert_eq!(data.len(), 1);
        assert_eq!(
            Header::parse(&data[0]).unwrap().cause,
            Request::Group(group).cause()
        );
        assert_eq!(
            qcc_of(
                controlled
                    .complete(&device)
                    .expect("its termination")
                    .last()
                    .unwrap()
            ),
            Request::Group(group).qcc(FreezeMode::Read)
        );
    }
    assert!(!controlled.awaiting_data());
    assert_eq!(controlled.complete(&device), Err(CiError::NotRunning));
}

/// Mode C's freeze and the later collection of the same group are two
/// activations: the collection's confirmation, data and termination are not
/// swallowed by the freeze's.
#[test]
fn a_freeze_and_a_collection_of_the_same_group_are_told_apart() {
    let known = Known::EVERYTHING;
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    let group = Request::Group(2);
    controlling
        .request(group, FreezeMode::FreezeWithoutReset)
        .unwrap();
    controlling.request(group, FreezeMode::Read).unwrap();

    for freeze in [FreezeMode::FreezeWithoutReset, FreezeMode::Read] {
        assert_eq!(
            controlling
                .on_response(&actcon(false, group, freeze), &known)
                .unwrap()
                .reaction,
            Reaction::ActivationConfirmed {
                request: group,
                freeze,
                negative: false
            }
        );
    }
    assert_eq!(
        controlling
            .on_response(&total(group.cause(), 0x3020, 202), &known)
            .unwrap()
            .reaction,
        Reaction::Counted { request: group }
    );
}

/// A cause 44–47 mirror of a pending activation settles it, and `reset`
/// drops everything on both roles.
#[test]
fn a_mirror_or_a_reset_releases_the_activation() {
    let known = Known::EVERYTHING;
    let device = Device::new();
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);

    let act = controlling
        .request(Request::General, FreezeMode::Read)
        .unwrap();
    let ca_unknown = Known {
        common_address: false,
        ..Known::EVERYTHING
    };
    let mirror = controlled.on_request(&act, &ca_unknown, &device).unwrap();
    assert_eq!(
        controlling
            .on_response(&mirror.send[0], &known)
            .unwrap()
            .reaction,
        Reaction::Refused {
            activation: Some((Request::General, FreezeMode::Read)),
            cause: Cause::UnknownCommonAddress
        }
    );
    assert_eq!(
        controlling.awaiting_confirmation(),
        [] as [iec104::ci::Request; 0]
    );
    assert!(!controlling.is_running(Request::General));

    let act = controlling
        .request(Request::General, FreezeMode::Read)
        .unwrap();
    controlled.on_request(&act, &known, &device).unwrap();
    controlling.reset();
    controlled.reset();
    assert_eq!(controlling.running(), [] as [iec104::ci::Request; 0]);
    assert_eq!(controlled.running(), [] as [iec104::ci::Request; 0]);
    assert!(!controlled.awaiting_data());
    assert_eq!(controlled.complete(&device), Err(CiError::NotRunning));
}

/// 5-101 cl.7.2.3: confirmation, totals and termination echo the request's
/// originator address.
#[test]
fn every_answer_echoes_the_requests_originator() {
    let device = Device::new();
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    let act = request(Request::General, FreezeMode::Read, CA, 42).unwrap();
    let mut frames = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .unwrap()
        .send;
    frames.extend(controlled.interrogated(&device).unwrap());
    frames.extend(controlled.complete(&device).unwrap());
    assert_eq!(frames.len(), 4, "actcon, two totals, actterm");
    for frame in &frames {
        assert_eq!(Header::parse(frame).unwrap().originator, 42);
    }
}

/// A counter group outside 1..=4 is refused rather than clamped.
#[test]
fn a_counter_group_outside_the_standards_range_is_refused() {
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    for group in [0, 5] {
        assert_eq!(
            controlling.request(Request::Group(group), FreezeMode::Read),
            Err(CiError::GroupOutOfRange { group })
        );
        assert_eq!(Request::try_group(group), None);
        assert_eq!(Qcc::try_counter_group(group), None);
    }
    assert!(
        controlling
            .request(Request::Group(4), FreezeMode::Read)
            .is_ok()
    );
}

#[test]
fn a_termination_ends_the_collection_even_before_its_confirmation() {
    // 5-101 clause 7.4.8, figure 95: `C_CI ACTTERM` is `A_ITERM`, "COUNTER
    // REQUEST TERMINATED". A termination that overtakes its confirmation still
    // ends the request: afterwards it is neither running nor awaiting a
    // confirmation, and the late confirmation opens nothing.
    let known = Known::EVERYTHING;
    let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    controlling
        .request(Request::Group(1), FreezeMode::Read)
        .unwrap();
    let termination = {
        let mut controlled =
            CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
        let act = request(Request::Group(1), FreezeMode::Read, CA, 0).unwrap();
        let device = Device::new();
        controlled.on_request(&act, &known, &device).unwrap();
        // Data first, then the termination: the termination is the last frame.
        controlled.complete(&device).unwrap().pop().unwrap()
    };

    assert_eq!(
        controlling
            .on_response(&termination, &known)
            .unwrap()
            .reaction,
        Reaction::Terminated {
            request: Request::Group(1)
        }
    );
    assert!(!controlling.is_running(Request::Group(1)));
    assert_eq!(
        controlling.awaiting_confirmation(),
        [] as [iec104::ci::Request; 0]
    );

    let late = actcon(false, Request::Group(1), FreezeMode::Read);
    assert_eq!(
        controlling.on_response(&late, &known).unwrap().reaction,
        Reaction::Other
    );
    assert!(!controlling.is_running(Request::Group(1)));
}

/// 5-101 clause 7.4.8 and figure 95: the totals, then `COUNTER REQUEST
/// TERMINATED`. A controlled station that calls `complete` before sending the
/// totals gets them first, then `C_CI ACTTERM` (cause 10).
#[test]
fn complete_sends_the_owed_totals_before_the_termination() {
    let device = Device::new();
    let known = Known::EVERYTHING;
    let mut controlled = CounterInterrogation::controlled(CounterMode::FreezeAndTransmit, CA, 0);
    let act = request(Request::General, FreezeMode::Read, CA, 0).unwrap();
    controlled.on_request(&act, &known, &device).unwrap();
    assert!(controlled.awaiting_data());

    let frames = controlled
        .complete(&device)
        .expect("totals and termination");
    let causes: Vec<u8> = frames
        .iter()
        .map(|f| Header::parse(f).unwrap().cause.to_u8())
        .collect();
    assert_eq!(causes.last(), Some(&10), "ACTTERM last: {causes:?}");
    assert!(causes.len() > 1, "the totals come first: {causes:?}");
    assert!(
        causes[..causes.len() - 1].iter().all(|&c| c == 37),
        "cause 37, general counter request: {causes:?}"
    );
    assert!(!controlled.awaiting_data());
    assert_eq!(controlled.complete(&device), Err(CiError::NotRunning));
}
