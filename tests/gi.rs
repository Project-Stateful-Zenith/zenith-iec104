//! General interrogation: `C_IC_NA_1`, its scope and cause, the response cycle
//! of 5-101 clause 7.4.5 and the three re-activation options of
//! TS 60870-5-604 clause 5.4.17.
//!
//! The clause citations are 5-104 cl.7.5 (the service table, PDF page index 64),
//! 5-101 cl.7.3.4.1 (the layout, page index 105, figure 72), cl.7.2.6.22 (`QOI`,
//! page index 53) and cl.7.4.5 (the procedure and Table 17, page indices
//! 122–125); TS 60870-5-604 Table 17 (PDF page indices 64–68) is the
//! re-activation and deactivation model.
//!
//! These tests drive the two roles against each other, so every assertion is
//! about a frame one role sent and the other classified. The scripted exchange
//! is the end-to-end acceptance test of the procedure.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::as_conversions)]

use iec104::asdu::{
    CIcNa1, Cause, Cp56Time2a, Direction, Discard, Header, IOA_IRRELEVANT, Known, LayoutError,
    LayoutObject, MMeNb1, MMeTd1, MSpNa1, Nva, Qds, Qoi, Siq, Sva, TypeId, Unspecified,
    decode_asdu, encode_asdu,
};
use iec104::gi::{
    CAUSE_ACTIVATION, CAUSE_ACTIVATION_CON, CAUSE_ACTIVATION_TERM, CAUSE_DEACTIVATION,
    CAUSE_DEACTIVATION_CON, DataSource, GiError, INTERROGATED_TYPES, Interrogation, Outcome,
    ReActivation, Reaction, Role, Scope, SecondActivation, TYPE_ID, deactivation, is_interrogated,
    request,
};

const CA: u16 = 12;

// ---------------------------------------------------------------- helpers

/// A `M_ME_NB_1` ASDU (`SVA` + `QDS`, 3 element octets) through the layout
/// layer, with the cause the scope demands.
fn scaled(cause: Cause, ioa: u32, value: i16) -> Vec<u8> {
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
    let object = LayoutObject {
        ioa,
        value: MMeNb1 {
            sva: Sva { value },
            qds: Qds::default(),
        },
    };
    encode_asdu(&header, &[object]).expect("the layout builds it")
}

/// A `M_SP_NA_1` ASDU of any cause, for the "not this procedure" cases.
fn single(cause: Cause, ioa: u32) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MSpNa1,
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
            value: MSpNa1 {
                siq: Siq::default(),
            },
        }],
    )
    .expect("the layout builds it")
}

/// The `QOI` octet of a type-100 frame.
fn qoi_of(asdu: &[u8]) -> Qoi {
    decode_asdu::<CIcNa1>(asdu).expect("type 100")[0].value.qoi
}

/// Asserts a frame is a type-100 ASDU of `cause` with an irrelevant IOA.
fn assert_interrogation_frame(asdu: &[u8], cause: Cause, negative: bool, scope: Scope) {
    let header = Header::parse(asdu).expect("header");
    assert_eq!(header.type_id, TYPE_ID);
    assert_eq!(header.type_id, TypeId::CIcNa1);
    assert_eq!(header.cause, cause);
    assert_eq!(header.negative, negative, "P/N");
    assert!(!header.test, "T = 0 in normal conditions");
    assert!(!header.sequence, "Single information object (SQ = 0)");
    assert_eq!(header.count, 1, "N = 1");
    assert_eq!(header.common_address, CA);
    assert_eq!(&asdu[6..9], &[0, 0, 0], "INFORMATION OBJECT ADDRESS = 0");
    assert_eq!(qoi_of(asdu), scope.qoi(), "the same qualifier comes back");
}

// ---------------------------------------------------------------- mock device

/// A controlled station's data: one scope's objects, pre-built through the
/// layout layer exactly as a real application would build them.
struct Device {
    ready: bool,
    objects: Vec<(Scope, Vec<u8>)>,
}

impl Device {
    /// Two `M_ME_NB_1` objects of the station scope, and one of group 3.
    fn new() -> Self {
        Self {
            ready: true,
            objects: vec![
                (
                    Scope::Station,
                    scaled(Cause::InterrogatedByStation, 0x3010, 2494),
                ),
                (
                    Scope::Station,
                    scaled(Cause::InterrogatedByStation, 0x3011, 2448),
                ),
                (
                    Scope::Group(3),
                    scaled(Cause::InterrogatedByGroup(3), 0x3012, 117),
                ),
            ],
        }
    }

    /// The same, but a station that is not ready to answer.
    fn not_ready() -> Self {
        Self {
            ready: false,
            ..Self::new()
        }
    }
}

impl DataSource for Device {
    fn ready(&self, _scope: Scope) -> bool {
        self.ready
    }

    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
        for (s, asdu) in &self.objects {
            if *s == scope {
                out.push(asdu.clone());
            }
        }
    }
}

/// A controlled station already running the station scope, plus the controlling
/// station that started it.
fn running_pair(policy: ReActivation) -> (Interrogation, Interrogation, Device) {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(policy, CA, 0);
    let device = Device::new();
    let act = controlling.request(Scope::Station).expect("activation");
    let confirmed = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("confirmation");
    controlling
        .on_response(&confirmed.send[0], &Known::EVERYTHING)
        .expect("actcon");
    (controlling, controlled, device)
}

// ------------------------------------------------------------ the request

/// Ten octets, one field at a time: type 100, VSQ `0x01`, COT 6 with P/N = 0
/// and T = 0, originator, CA little-endian, IOA zero (figure 72), then the QOI.
#[test]
fn the_activation_has_its_ten_octets() {
    let asdu = request(Scope::Station, CA, 0).expect("frame");
    assert_eq!(asdu.len(), Header::LEN + 3 + Qoi::LEN);
    assert_eq!(asdu[0], TypeId::CIcNa1.to_u8());
    assert_eq!(asdu[0], 100);
    assert_eq!(asdu[1], 0x01, "SQ = 0, N = 1");
    assert_eq!(asdu[2], CAUSE_ACTIVATION.to_u8());
    assert_eq!(asdu[2], 6);
    assert_eq!(asdu[2] & 0xC0, 0, "P/N = 0 and T = 0");
    assert_eq!(asdu[3], 0x00);
    assert_eq!(&asdu[4..6], &CA.to_le_bytes(), "CA little-endian");
    assert_eq!(&asdu[6..9], &[0x00, 0x00, 0x00]);
    assert_eq!(asdu[9], 20, "<20> station interrogation");

    let group = request(Scope::Group(3), 0x1234, 7).expect("frame");
    let header = Header::parse(&group).expect("header");
    assert_eq!(header.common_address, 0x1234);
    assert_eq!(header.originator, 7);
    assert_eq!(group[9], 23, "<21> + n - 1 for group 3");
    assert_eq!(qoi_of(&group), Qoi::group(3));

    // The cause is the clause's list for type 100, not a parameter.
    assert_eq!(asdu[2], Cause::Activation.to_u8());
}

/// The qualifier and the cause are one mapping, and the reserved and private
/// ranges have no scope (5-101 cl.7.2.6.22).
#[test]
fn the_scope_maps_to_its_qualifier_and_its_cause() {
    assert_eq!(Scope::from_qoi(Qoi { value: 20 }), Some(Scope::Station));
    for n in 1..=16u8 {
        assert_eq!(
            Scope::from_qoi(Qoi::group(n)),
            Some(Scope::Group(n)),
            "group {n}"
        );
    }

    for reserved in [0u8, 1, 19, 37, 63, 64, 255] {
        assert_eq!(
            Scope::from_qoi(Qoi { value: reserved }),
            None,
            "{reserved} is not a scope"
        );
    }

    assert_eq!(Scope::Station.qoi(), Qoi { value: 20 });
    assert_eq!(Scope::Group(1).qoi(), Qoi { value: 21 });
    assert_eq!(Scope::Group(16).qoi(), Qoi { value: 36 });
    assert_eq!(Scope::Group(1).qoi().value, Qoi::GROUP_1, "<21> is group 1");
    assert_eq!(Scope::Group(16).qoi().value, Qoi::GROUP_16);

    assert_eq!(Scope::Station.cause(), Cause::InterrogatedByStation);
    assert_eq!(Scope::Station.cause().to_u8(), 20);
    assert_eq!(Scope::Group(1).cause(), Cause::InterrogatedByGroup(1));
    assert_eq!(Scope::Group(16).cause(), Cause::InterrogatedByGroup(16));
    assert_eq!(Scope::Group(3).cause().mnemonic(), "inro3");

    assert_eq!(Scope::Station.group_number(), None);
    assert_eq!(Scope::Group(3).group_number(), Some(3));
    assert!(Scope::Station.is_station_wide());
    assert!(!Scope::Group(1).is_station_wide());

    // `Scope::group`, `qoi` and `cause` clamp an out-of-range group, so it never
    // reaches the wire out of range (`request` refuses one, see the last test).
    assert_eq!(Scope::group(0), Scope::Group(1));
    assert_eq!(Scope::group(99), Scope::Group(16));
    assert_eq!(Scope::group(3), Scope::Group(3));
    assert_eq!(Scope::Group(99).qoi().value, 36);
    assert_eq!(Scope::Group(0).cause(), Cause::InterrogatedByGroup(1));
}

/// Deactivation is the same frame with cause 8 (5-101 figure 72's
/// control-direction list; TS 60870-5-604 clause 5.4.17.50).
#[test]
fn the_deactivation_is_the_same_frame_with_cause_eight() {
    let on = request(Scope::Group(2), CA, 0).expect("frame");
    let off = deactivation(Scope::Group(2), CA, 0).expect("frame");

    assert_eq!(
        Header::parse(&off).expect("header").cause,
        CAUSE_DEACTIVATION
    );
    assert_eq!(off[2], 8);
    assert_eq!(on.len(), off.len());
    assert_eq!(on[9], off[9], "the same qualifier");
    let differing: Vec<usize> = on
        .iter()
        .zip(off.iter())
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(differing, vec![2], "only the cause octet differs");
    assert_eq!(qoi_of(&off), Qoi::group(2));
}

// ------------------------------------------------- the scripted exchange

/// The acceptance test: a full interrogation between the two roles, asserted
/// frame by frame (the request's COT and QOI, the confirmation, the cause of
/// every object, the termination, and that the data stops there).
#[test]
fn a_scripted_interrogation_runs_to_its_termination() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();

    // 1. The controlling station activates the station-wide scope.
    let act = controlling.request(Scope::Station).expect("activation");
    assert_interrogation_frame(&act, CAUSE_ACTIVATION, false, Scope::Station);
    assert_eq!(controlling.awaiting_confirmation(), [Scope::Station]);
    assert_eq!(
        controlling.running(),
        [Scope::Station],
        "clause 7.4.5: a running GI means the C_IC_ACTTERM has not been received \
         after the C_IC_ACT was sent, so an activation in flight is running"
    );

    // 2. The controlled station confirms positively and owes its data.
    let confirmed = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("confirmation");
    assert_eq!(
        confirmed.reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: false
        }
    );
    assert_eq!(
        confirmed.send.len(),
        1,
        "the confirmation is its whole answer"
    );
    assert_interrogation_frame(
        &confirmed.send[0],
        CAUSE_ACTIVATION_CON,
        false,
        Scope::Station,
    );

    // The controlling station classifies it and is now running.
    assert_eq!(
        controlling
            .on_response(&confirmed.send[0], &Known::EVERYTHING)
            .expect("actcon")
            .reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: false
        }
    );
    assert!(controlling.is_running(Scope::Station));
    assert_eq!(controlling.awaiting_confirmation(), []);

    // 3. The data, in the close formation of 5-101's figure 91.
    let data = controlled.interrogated(&device).expect("data");
    assert_eq!(
        data.len(),
        2,
        "the station scope's two objects, not group 3's"
    );
    for asdu in &data {
        let header = Header::parse(asdu).expect("header");
        assert_eq!(header.cause, Scope::Station.cause());
        assert_eq!(header.cause.to_u8(), 20);
        assert!(is_interrogated(header.type_id), "an untagged monitor type");
        assert_eq!(
            controlling
                .on_response(asdu, &Known::EVERYTHING)
                .expect("interrogated")
                .reaction,
            Reaction::Interrogated {
                scope: Scope::Station
            }
        );
    }
    assert!(controlled.is_running(Scope::Station));

    // 4. The termination ends the procedure on both sides.
    let term = controlled.complete(&device).expect("termination");
    assert_eq!(term.len(), 1);
    assert_interrogation_frame(&term[0], CAUSE_ACTIVATION_TERM, false, Scope::Station);
    assert_eq!(
        controlling
            .on_response(&term[0], &Known::EVERYTHING)
            .expect("actterm")
            .reaction,
        Reaction::Terminated {
            scope: Scope::Station
        }
    );
    assert!(!controlling.is_running(Scope::Station));
    assert_eq!(controlled.running(), [] as [iec104::gi::Scope; 0]);

    // 5. And the procedure ends at its termination: a further object of the same cause
    //    is no longer this procedure.
    assert_eq!(
        controlling
            .on_response(&data[0], &Known::EVERYTHING)
            .expect("late object")
            .reaction,
        Reaction::Other
    );
    assert_eq!(
        controlled.interrogated(&device),
        Err(GiError::NotRunning),
        "nothing is running to owe data"
    );
    assert_eq!(controlled.complete(&device), Err(GiError::NotRunning));
}

/// A group interrogation is the same cycle with the group's own cause and
/// qualifier, and it returns the group's objects, not the station's.
#[test]
fn a_group_interrogation_carries_the_groups_cause() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();

    let act = controlling.request(Scope::Group(3)).expect("activation");
    assert_interrogation_frame(&act, CAUSE_ACTIVATION, false, Scope::Group(3));

    let confirmed = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("confirmation");
    assert_interrogation_frame(
        &confirmed.send[0],
        CAUSE_ACTIVATION_CON,
        false,
        Scope::Group(3),
    );
    controlling
        .on_response(&confirmed.send[0], &Known::EVERYTHING)
        .expect("actcon");

    let data = controlled.interrogated(&device).expect("data");
    assert_eq!(data.len(), 1, "only group 3's one object");
    let header = Header::parse(&data[0]).expect("header");
    assert_eq!(header.cause, Cause::InterrogatedByGroup(3));
    assert_eq!(header.cause.to_u8(), 23);
    assert_eq!(
        controlling
            .on_response(&data[0], &Known::EVERYTHING)
            .expect("interrogated")
            .reaction,
        Reaction::Interrogated {
            scope: Scope::Group(3)
        }
    );

    let term = controlled.complete(&device).expect("termination");
    assert_interrogation_frame(&term[0], CAUSE_ACTIVATION_TERM, false, Scope::Group(3));
    assert_eq!(
        controlling
            .on_response(&term[0], &Known::EVERYTHING)
            .expect("actterm")
            .reaction,
        Reaction::Terminated {
            scope: Scope::Group(3)
        }
    );
}

/// The nine types of the clause's own sentence, and the refusal of anything
/// else. This is also the "no time tags" rule, since every time-tagged monitor
/// type is outside the nine.
#[test]
fn a_response_may_only_carry_the_nine_types_the_clause_lists() {
    // A data source that returns a time-tagged type is a typed refusal, not a
    // frame on the wire.
    struct TimeTagged;
    impl DataSource for TimeTagged {
        fn ready(&self, _scope: Scope) -> bool {
            true
        }
        fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
            let header = Header {
                type_id: TypeId::MMeTd1,
                sequence: false,
                count: 1,
                cause: scope.cause(),
                negative: false,
                test: false,
                originator: 0,
                common_address: CA,
            };
            out.push(
                encode_asdu(
                    &header,
                    &[LayoutObject {
                        ioa: 1,
                        value: MMeTd1 {
                            nva: Nva::default(),
                            qds: Qds::default(),
                            time: Cp56Time2a::default(),
                        },
                    }],
                )
                .expect("layout"),
            );
        }
    }

    // A data source that answers with a wrong cause is refused the same way.
    struct WrongCause;
    impl DataSource for WrongCause {
        fn ready(&self, _scope: Scope) -> bool {
            true
        }
        fn interrogated(&self, _scope: Scope, out: &mut Vec<Vec<u8>>) {
            out.push(single(Cause::Spontaneous, 1));
        }
    }

    assert_eq!(INTERROGATED_TYPES.len(), 9);
    assert_eq!(
        INTERROGATED_TYPES,
        [
            TypeId::MSpNa1,
            TypeId::MDpNa1,
            TypeId::MStNa1,
            TypeId::MBoNa1,
            TypeId::MMeNa1,
            TypeId::MMeNb1,
            TypeId::MMeNc1,
            TypeId::MPsNa1,
            TypeId::MMeNd1,
        ],
        "5-101 cl.7.4.5's <1>, <3>, <5>, <7>, <9>, <11>, <13>, <20>, <21>"
    );
    for type_id in INTERROGATED_TYPES {
        assert!(is_interrogated(type_id), "{}", type_id.name());
        assert_eq!(type_id.direction(), Some(Direction::Monitor));
    }
    assert!(!is_interrogated(TypeId::MMeTd1), "a time-tagged type");
    assert!(!is_interrogated(TypeId::MSpTa1), "a CP24Time2a type");
    assert!(!is_interrogated(TypeId::MMeTf1));
    assert!(!is_interrogated(TypeId::CIcNa1), "the command itself");

    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let act = controlling.request(Scope::Station).expect("activation");
    controlled
        .on_request(&act, &Known::EVERYTHING, &TimeTagged)
        .expect("the confirmation itself is fine");
    assert_eq!(
        controlled.interrogated(&TimeTagged),
        Err(GiError::NotInterrogatedType {
            type_id: TypeId::MMeTd1
        }),
        "ASDUs with COT 20 to 36 are transmitted without time tags"
    );

    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    controlled
        .on_request(&act, &Known::EVERYTHING, &WrongCause)
        .expect("confirmation");
    assert_eq!(
        controlled.interrogated(&WrongCause),
        Err(GiError::WrongCause {
            expected: Cause::InterrogatedByStation,
            got: Cause::Spontaneous
        })
    );
}

/// Clause 7.4.5's negative confirmation: the station is not ready, the
/// controlling station may repeat the command, and the repeat is not locked.
#[test]
fn a_negative_confirmation_may_be_repeated() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::not_ready();

    let act = controlling.request(Scope::Station).expect("activation");
    let rejected = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("negative confirmation");
    assert_eq!(
        rejected.reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: true
        }
    );
    assert_eq!(rejected.send.len(), 1, "no data and no termination");
    assert_interrogation_frame(
        &rejected.send[0],
        CAUSE_ACTIVATION_CON,
        true,
        Scope::Station,
    );
    assert!(!controlled.is_running(Scope::Station));

    let reaction = controlling
        .on_response(&rejected.send[0], &Known::EVERYTHING)
        .expect("actconneg")
        .reaction;
    assert_eq!(
        reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: true
        }
    );
    assert!(
        controlling.awaiting_confirmation().is_empty(),
        "the activation is settled"
    );
    assert!(!controlling.is_running(Scope::Station));

    // The station interrogation may be requested again, and it is not
    // locked, because nothing is running.
    let again = controlling.request(Scope::Station).expect("repeat");
    assert_eq!(
        Header::parse(&again).expect("header").cause,
        CAUSE_ACTIVATION
    );
}

// ------------------------------------------------------- the three options

/// A second activation arriving while one runs: the three options of
/// TS 60870-5-604 Table 17, page 3 of 5 (PDF page index 66).
#[test]
fn option_1_continues_the_running_interrogation() {
    let (_controlling, mut controlled, device) = running_pair(ReActivation::Continue);
    let second = request(Scope::Group(3), CA, 0).expect("frame");

    let outcome = controlled
        .on_request(&second, &Known::EVERYTHING, &device)
        .expect("option 1");
    assert_eq!(
        outcome.reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Group(3),
            negative: true
        },
        "the Controlled station mirrors the Interrogation Command with COT = 7, C_IC_ACTCONneg"
    );
    assert_interrogation_frame(
        &outcome.send[0],
        CAUSE_ACTIVATION_CON,
        true,
        Scope::Group(3),
    );
    assert!(
        controlled.is_running(Scope::Station),
        "the already running General Interrogation continues"
    );
    assert_eq!(controlled.queued(), []);
}

#[test]
fn option_2_restarts_the_interrogation() {
    let (_controlling, mut controlled, device) = running_pair(ReActivation::Restart);
    let second = request(Scope::Group(3), CA, 0).expect("frame");

    let outcome = controlled
        .on_request(&second, &Known::EVERYTHING, &device)
        .expect("option 2");
    assert_eq!(
        outcome.reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Group(3),
            negative: false
        }
    );
    // The stopped procedure is indicated with a termination, then the second
    // is confirmed positively.
    assert_eq!(outcome.send.len(), 2);
    assert_interrogation_frame(
        &outcome.send[0],
        CAUSE_ACTIVATION_TERM,
        false,
        Scope::Station,
    );
    assert_interrogation_frame(
        &outcome.send[1],
        CAUSE_ACTIVATION_CON,
        false,
        Scope::Group(3),
    );

    assert!(controlled.is_running(Scope::Group(3)));
    assert!(!controlled.is_running(Scope::Station));

    // And the second procedure runs normally to its own termination.
    let data = controlled.interrogated(&device).expect("data");
    assert_eq!(data.len(), 1);
    assert_eq!(
        Header::parse(&data[0]).expect("header").cause,
        Cause::InterrogatedByGroup(3)
    );
    let term = controlled.complete(&device).expect("termination");
    assert_interrogation_frame(&term[0], CAUSE_ACTIVATION_TERM, false, Scope::Group(3));
}

#[test]
fn option_3_queues_the_second_until_the_first_terminates() {
    let (_controlling, mut controlled, device) = running_pair(ReActivation::Queue);
    let second = request(Scope::Group(3), CA, 0).expect("frame");

    let outcome = controlled
        .on_request(&second, &Known::EVERYTHING, &device)
        .expect("option 3");
    assert_eq!(
        outcome.reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Group(3),
            negative: false
        },
        "mirrors the second Interrogation Command with COT = 7, C_IC_ACTCON"
    );
    assert_eq!(outcome.send.len(), 1, "the second's data waits");
    assert_interrogation_frame(
        &outcome.send[0],
        CAUSE_ACTIVATION_CON,
        false,
        Scope::Group(3),
    );
    assert_eq!(controlled.queued(), [Scope::Group(3)]);
    assert!(
        controlled.is_running(Scope::Station),
        "the first still runs"
    );

    // The first procedure nevertheless returns its own data and termination,
    // and the queued second follows it in the same action list.
    let data = controlled.interrogated(&device).expect("the first's data");
    assert_eq!(data.len(), 2);
    assert_eq!(
        Header::parse(&data[0]).expect("header").cause,
        Cause::InterrogatedByStation
    );

    let term = controlled.complete(&device).expect("both terminations");
    assert_eq!(
        term.len(),
        3,
        "termination, the second's data, its termination"
    );
    assert_interrogation_frame(&term[0], CAUSE_ACTIVATION_TERM, false, Scope::Station);
    assert_eq!(
        Header::parse(&term[1]).expect("header").cause,
        Cause::InterrogatedByGroup(3)
    );
    assert_interrogation_frame(&term[2], CAUSE_ACTIVATION_TERM, false, Scope::Group(3));
    assert_eq!(controlled.running(), [] as [iec104::gi::Scope; 0]);
    assert_eq!(controlled.queued(), []);
}

/// The controlling station's lock is on the **identical** interrogation
/// (5-101 cl.7.4.5), it holds from the activation until the termination, and a
/// different scope is not the identical one.
#[test]
fn an_identical_interrogation_is_locked_while_it_runs() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();

    let act = controlling.request(Scope::Station).expect("activation");
    assert_eq!(
        controlling.request(Scope::Station),
        Err(GiError::AlreadyRunning {
            scope: Scope::Station
        }),
        "the initialization of an identical general interrogation ... is normally locked"
    );

    let confirmed = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("confirmation");
    controlling
        .on_response(&confirmed.send[0], &Known::EVERYTHING)
        .expect("actcon");
    assert_eq!(
        controlling.request(Scope::Station),
        Err(GiError::AlreadyRunning {
            scope: Scope::Station
        }),
        "still locked once running"
    );

    // A different scope is not the identical one.
    let group = controlling.request(Scope::Group(3)).expect("another scope");
    assert_interrogation_frame(&group, CAUSE_ACTIVATION, false, Scope::Group(3));

    // Once terminated, the same scope is free again.
    let _ = controlled.interrogated(&device);
    let term = controlled.complete(&device).expect("termination");
    assert_eq!(
        controlling
            .on_response(&term[0], &Known::EVERYTHING)
            .expect("actterm")
            .reaction,
        Reaction::Terminated {
            scope: Scope::Station
        }
    );
    assert!(controlling.request(Scope::Station).is_ok());
}

/// Abandoning one scope lifts clause 7.4.5's lock on it alone: the caller has
/// given up waiting for its termination, and another scope keeps running.
#[test]
fn abandoning_a_scope_unlocks_only_that_scope() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    controlling.request(Scope::Station).expect("activation");
    controlling.request(Scope::Group(3)).expect("another scope");

    assert!(controlling.abandon(Scope::Station));
    assert!(!controlling.is_running(Scope::Station));
    assert!(controlling.is_running(Scope::Group(3)));
    assert!(controlling.request(Scope::Station).is_ok(), "unlocked");
    assert_eq!(
        controlling.request(Scope::Group(3)),
        Err(GiError::AlreadyRunning {
            scope: Scope::Group(3)
        }),
        "the other scope is still locked"
    );
    assert!(!controlling.abandon(Scope::Group(7)), "nothing to abandon");
}

// ---------------------------------------------------------- deactivation

/// TS 60870-5-604 clause 5.4.17.50: cause 8 stops the interrogation, cause 9
/// confirms it, no termination follows it and no further objects of that scope
/// are sent.
#[test]
fn a_deactivation_stops_the_interrogation_without_a_termination() {
    let (mut controlling, mut controlled, device) = running_pair(ReActivation::Continue);
    let _ = controlled.interrogated(&device);

    let off = controlling
        .deactivate(Scope::Station)
        .expect("deactivation");
    assert_interrogation_frame(&off, CAUSE_DEACTIVATION, false, Scope::Station);
    assert_eq!(off[2], 8);

    let outcome = controlled
        .on_request(&off, &Known::EVERYTHING, &device)
        .expect("deactivation");
    assert_eq!(
        outcome.reaction,
        Reaction::DeactivationConfirmed {
            scope: Scope::Station,
            negative: false
        }
    );
    assert_eq!(outcome.send.len(), 1, "no ACTTERM follows a DEACTCON");
    assert_interrogation_frame(
        &outcome.send[0],
        CAUSE_DEACTIVATION_CON,
        false,
        Scope::Station,
    );
    assert_eq!(controlled.running(), [] as [iec104::gi::Scope; 0]);
    assert_eq!(
        controlled.interrogated(&device),
        Err(GiError::NotRunning),
        "no further Information Objects ... are sent"
    );
    assert_eq!(controlled.complete(&device), Err(GiError::NotRunning));

    assert_eq!(
        controlling
            .on_response(&outcome.send[0], &Known::EVERYTHING)
            .expect("deactcon")
            .reaction,
        Reaction::DeactivationConfirmed {
            scope: Scope::Station,
            negative: false
        }
    );
}

// ------------------------------------------------------------- the guards

/// Every entry point belongs to one role, and the wrong one is a typed error.
#[test]
fn the_entry_points_are_guarded_by_role() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();
    let act = request(Scope::Station, CA, 0).expect("frame");

    assert_eq!(controlling.role(), Role::Controlling);
    assert_eq!(controlled.role(), Role::Controlled);
    assert_eq!(controlled.policy(), Some(ReActivation::Continue));
    assert_eq!(controlling.policy(), None);
    assert_eq!(controlling.addressing(), (CA, 0));

    assert_eq!(controlled.request(Scope::Station), Err(GiError::WrongRole));
    assert_eq!(
        controlled.deactivate(Scope::Station),
        Err(GiError::WrongRole)
    );
    assert_eq!(
        controlling.on_request(&act, &Known::EVERYTHING, &device),
        Err(GiError::WrongRole)
    );
    assert_eq!(
        controlled.on_response(&act, &Known::EVERYTHING),
        Err(GiError::WrongRole)
    );
    assert_eq!(
        controlling.interrogated(&device),
        Err(GiError::WrongRole),
        "only the controlled station builds responses"
    );
    assert_eq!(controlling.complete(&device), Err(GiError::WrongRole));
}

/// Clause 7.2.3's rule runs before the type is examined, on both sides: the
/// controlling station discards, the controlled station mirrors.
#[test]
fn the_discard_rule_runs_before_the_type_is_examined() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();
    let act = request(Scope::Station, CA, 0).expect("frame");

    let expected = Reaction::Discard(Discard::Unspecified(Unspecified::TypeIdentification));
    assert_eq!(
        controlling
            .on_response(&act, &Known::NOTHING)
            .expect("discard")
            .reaction,
        expected
    );
    let refused = controlled
        .on_request(&act, &Known::NOTHING, &device)
        .expect("mirror");
    assert_eq!(
        refused.reaction,
        Reaction::Refused {
            scope: Some(Scope::Station),
            cause: Cause::UnknownTypeId
        }
    );
    assert_eq!(refused.send.len(), 1);
    assert_interrogation_frame(&refused.send[0], Cause::UnknownTypeId, true, Scope::Station);
    assert!(!controlled.is_running(Scope::Station));

    // A mirror is the clause's third log bullet and is never this procedure.
    let mut mirrored = act.clone();
    mirrored[2] = Cause::UnknownTypeId.to_u8() | 0x40;
    assert_eq!(
        controlling
            .on_response(&mirrored, &Known::EVERYTHING)
            .expect("mirror")
            .reaction,
        Reaction::Discard(Discard::Mirror)
    );

    // And a station whose station address this is not discards it the same way.
    let mut known = Known::EVERYTHING;
    known.common_address = false;
    assert_eq!(
        controlling
            .on_response(&act, &known)
            .expect("discard")
            .reaction,
        Reaction::Discard(Discard::Unspecified(Unspecified::CommonAddress))
    );
}

/// Anything that is not this procedure (another type, another cause, another
/// qualifier) is [`Reaction::Other`] and produces no frame.
#[test]
fn anything_else_is_not_this_procedure() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();

    // A monitor ASDU with an ordinary cause.
    let spontaneous = single(Cause::Spontaneous, 0x3010);
    assert_eq!(
        controlling
            .on_response(&spontaneous, &Known::EVERYTHING)
            .expect("other")
            .reaction,
        Reaction::Other
    );
    let outcome = controlled
        .on_request(&spontaneous, &Known::EVERYTHING, &device)
        .expect("other");
    assert_eq!(outcome.reaction, Reaction::Other);
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);

    // A type-100 ASDU with a cause outside figure 72's list.
    let mut stray = request(Scope::Station, CA, 0).expect("frame");
    stray[2] = Cause::Spontaneous.to_u8();
    assert_eq!(
        controlling
            .on_response(&stray, &Known::EVERYTHING)
            .expect("other")
            .reaction,
        Reaction::Other
    );
    assert_eq!(
        controlled
            .on_request(&stray, &Known::EVERYTHING, &device)
            .expect("other")
            .reaction,
        Reaction::Other
    );

    // A QOI clause 7.2.6.22 leaves reserved.
    let mut reserved = request(Scope::Station, CA, 0).expect("frame");
    reserved[9] = 19;
    assert_eq!(
        controlled
            .on_request(&reserved, &Known::EVERYTHING, &device)
            .expect("other")
            .reaction,
        Reaction::Other
    );

    // A confirmation nobody asked for.
    let actcon = {
        let mut frame = request(Scope::Station, CA, 0).expect("frame");
        frame[2] = CAUSE_ACTIVATION_CON.to_u8();
        frame
    };
    assert_eq!(
        controlling
            .on_response(&actcon, &Known::EVERYTHING)
            .expect("other")
            .reaction,
        Reaction::Other,
        "nothing is pending for it"
    );
}

/// A malformed frame is a typed error, never a panic, on every short prefix.
#[test]
fn a_malformed_frame_is_a_typed_error() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();
    let act = request(Scope::Station, CA, 0).expect("frame");

    for len in 0..Header::LEN {
        let short = vec![0u8; len];
        assert!(matches!(
            controlling.on_response(&short, &Known::EVERYTHING),
            Err(GiError::Layout(_))
        ));
        assert!(matches!(
            controlled.on_request(&short, &Known::EVERYTHING, &device),
            Err(GiError::Layout(_))
        ));
    }

    // A type-100 ASDU promising two objects: the figure says one.
    let mut two = act.clone();
    two[1] = 0x02;
    assert_eq!(
        controlled.on_request(&two, &Known::EVERYTHING, &device),
        Err(GiError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::CIcNa1,
            count: 2
        }))
    );

    // And a sequence form, which no definition line of the type defines.
    let mut sequence = act;
    sequence[1] = 0x81;
    assert_eq!(
        controlled.on_request(&sequence, &Known::EVERYTHING, &device),
        Err(GiError::Layout(LayoutError::SequenceNotAllowed {
            type_id: TypeId::CIcNa1
        }))
    );
}

/// The procedure's role is not the transport's: the same module runs the
/// reverse direction, where the interrogated side is the TCP client.
#[test]
fn the_reverse_direction_runs_from_the_same_module() {
    // The server-side station interrogates; the client-side station answers.
    let mut server = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut client = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();

    assert_eq!(server.role(), Role::Controlling);
    assert_eq!(client.role(), Role::Controlled);

    let act = server.request(Scope::Station).expect("activation");
    let confirmed = client
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("confirmation");
    assert_eq!(
        server
            .on_response(&confirmed.send[0], &Known::EVERYTHING)
            .expect("actcon")
            .reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: false
        }
    );
    let data = client.interrogated(&device).expect("data");
    assert_ne!(data, [] as [std::vec::Vec<u8>; 0]);
    let term = client.complete(&device).expect("termination");
    assert_eq!(
        server
            .on_response(&term[0], &Known::EVERYTHING)
            .expect("actterm")
            .reaction,
        Reaction::Terminated {
            scope: Scope::Station
        }
    );
    assert!(!server.is_running(Scope::Station));

    // The outcome is a value with two fields the caller matches on.
    let outcome = Outcome {
        reaction: Reaction::Other,
        send: Vec::new(),
    };
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
    assert_eq!(outcome.reaction, Reaction::Other);
    assert_eq!(CAUSE_ACTIVATION.to_u8(), 6);
    assert_eq!(IOA_IRRELEVANT, 0);
    assert_eq!(CAUSE_ACTIVATION_TERM.to_u8(), 10);
}

/// A controlling station configured with [`SecondActivation::Allowed`] sends an
/// identical activation again, and then accepts whichever of the three options
/// the other station implements: TS 60870-5-604 Table 17 requires the
/// controlling station to cope with every one of the options.
#[test]
fn an_allowed_second_activation_handles_every_option() {
    let mut controlling = Interrogation::controlling(SecondActivation::Allowed, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();

    assert_eq!(controlling.second_activation(), SecondActivation::Allowed);

    let act = controlling.request(Scope::Station).expect("activation");
    let confirmed = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("confirmation");
    controlling
        .on_response(&confirmed.send[0], &Known::EVERYTHING)
        .expect("actcon");
    assert_eq!(controlling.awaiting_confirmation(), []);

    // The clause's lock is "normally"; Allowed sends the identical scope again.
    let second = controlling
        .request(Scope::Station)
        .expect("second activation");
    assert_eq!(
        Header::parse(&second).expect("header").cause,
        CAUSE_ACTIVATION
    );
    assert_eq!(controlling.awaiting_confirmation(), [Scope::Station]);

    // Option 1: the mirror is negative and the first GI continues, so the
    // still-running procedure survives the second's confirmation.
    let option_1 = controlled
        .on_request(&second, &Known::EVERYTHING, &device)
        .expect("option 1");
    assert_eq!(
        option_1.reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: true
        }
    );
    assert_eq!(
        controlling
            .on_response(&option_1.send[0], &Known::EVERYTHING)
            .expect("actconneg")
            .reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: true
        }
    );
    assert_eq!(controlling.awaiting_confirmation(), []);
    assert!(
        controlling.is_running(Scope::Station),
        "the first GI is still running after option 1"
    );

    // And it still terminates normally.
    let _ = controlled.interrogated(&device);
    let term = controlled.complete(&device).expect("termination");
    assert_eq!(
        controlling
            .on_response(&term[0], &Known::EVERYTHING)
            .expect("actterm")
            .reaction,
        Reaction::Terminated {
            scope: Scope::Station
        }
    );
    assert!(!controlling.is_running(Scope::Station));
    assert_eq!(controlling.running(), [] as [iec104::gi::Scope; 0]);
}

// ------------------------------------------------------------- recovery

/// A cause 44–47 mirror of the controlling station's activation settles it:
/// the lock on that scope is released, so the interrogation can be repeated.
#[test]
fn a_mirrored_activation_releases_the_lock() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();

    let act = controlling.request(Scope::Station).expect("activation");
    let mirror = controlled
        .on_request(&act, &Known::NOTHING, &device)
        .expect("mirror");
    assert_eq!(
        controlling
            .on_response(&mirror.send[0], &Known::EVERYTHING)
            .expect("mirror")
            .reaction,
        Reaction::Refused {
            scope: Some(Scope::Station),
            cause: Cause::UnknownTypeId
        }
    );
    assert!(controlling.request(Scope::Station).is_ok(), "not locked");
}

/// `reset` drops every procedure on both roles, for a reconnect or the
/// caller's own reply time-out.
#[test]
fn reset_releases_both_roles() {
    let (mut controlling, mut controlled, device) = running_pair(ReActivation::Queue);
    let second = request(Scope::Group(3), CA, 0).expect("frame");
    controlled
        .on_request(&second, &Known::EVERYTHING, &device)
        .expect("queued");

    controlling.reset();
    controlled.reset();
    assert!(controlling.request(Scope::Station).is_ok(), "not locked");
    assert_eq!(controlled.running(), [] as [iec104::gi::Scope; 0]);
    assert_eq!(controlled.queued(), []);
    assert_eq!(controlled.interrogated(&device), Err(GiError::NotRunning));
    assert_eq!(controlled.complete(&device), Err(GiError::NotRunning));
}

/// Deactivating a scope that is not running changes nothing and is answered
/// negatively; in particular the running interrogation's data is not re-armed.
#[test]
fn deactivating_nothing_is_negative_and_changes_nothing() {
    let (_controlling, mut controlled, device) = running_pair(ReActivation::Continue);
    assert_eq!(controlled.interrogated(&device).expect("data").len(), 2);

    let off = deactivation(Scope::Group(3), CA, 0).expect("frame");
    let outcome = controlled
        .on_request(&off, &Known::EVERYTHING, &device)
        .expect("deactcon");
    assert_eq!(
        outcome.reaction,
        Reaction::DeactivationConfirmed {
            scope: Scope::Group(3),
            negative: true
        }
    );
    assert_interrogation_frame(
        &outcome.send[0],
        CAUSE_DEACTIVATION_CON,
        true,
        Scope::Group(3),
    );
    assert!(controlled.is_running(Scope::Station));
    assert_eq!(
        controlled.interrogated(&device),
        Err(GiError::NotRunning),
        "the running interrogation's data is not sent twice"
    );
}

/// Option 3: deactivating the running interrogation promotes the queued one,
/// which was already confirmed positively and so must still be served.
#[test]
fn deactivating_the_running_one_promotes_the_queued_one() {
    let (_controlling, mut controlled, device) = running_pair(ReActivation::Queue);
    let second = request(Scope::Group(3), CA, 0).expect("frame");
    controlled
        .on_request(&second, &Known::EVERYTHING, &device)
        .expect("queued");

    let off = deactivation(Scope::Station, CA, 0).expect("frame");
    controlled
        .on_request(&off, &Known::EVERYTHING, &device)
        .expect("deactcon");
    assert_eq!(controlled.running(), [Scope::Group(3)]);
    assert_eq!(controlled.queued(), []);

    let data = controlled.interrogated(&device).expect("the second's data");
    assert_eq!(data.len(), 1);
    assert_eq!(
        Header::parse(&data[0]).expect("header").cause,
        Cause::InterrogatedByGroup(3)
    );
    let term = controlled.complete(&device).expect("termination");
    assert_eq!(term.len(), 1);
    assert_interrogation_frame(&term[0], CAUSE_ACTIVATION_TERM, false, Scope::Group(3));
}

/// Option 3 queues a scope at most once: a repeat of a queued scope is
/// refused, and deactivating the running one keeps the confirmed queued one.
#[test]
fn option_3_queues_each_scope_once() {
    let (_controlling, mut controlled, device) = running_pair(ReActivation::Queue);
    // Its own originator, so the termination shows which entry survived.
    let again = request(Scope::Station, CA, 9).expect("frame");
    let first = controlled
        .on_request(&again, &Known::EVERYTHING, &device)
        .expect("queued");
    assert_eq!(
        first.reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: false
        }
    );
    let second = controlled
        .on_request(&again, &Known::EVERYTHING, &device)
        .expect("refused");
    assert_eq!(
        second.reaction,
        Reaction::ActivationConfirmed {
            scope: Scope::Station,
            negative: true
        }
    );
    assert_interrogation_frame(&second.send[0], CAUSE_ACTIVATION_CON, true, Scope::Station);
    assert_eq!(controlled.queued(), [Scope::Station]);

    let off = deactivation(Scope::Station, CA, 0).expect("frame");
    controlled
        .on_request(&off, &Known::EVERYTHING, &device)
        .expect("deactcon");
    assert_eq!(
        controlled.running(),
        [Scope::Station],
        "the queued one runs"
    );
    let term = controlled
        .complete(&device)
        .expect("its data and termination");
    assert_eq!(term.len(), 3);
    assert_interrogation_frame(&term[2], CAUSE_ACTIVATION_TERM, false, Scope::Station);
    assert_eq!(Header::parse(&term[2]).expect("header").originator, 9);
}

/// TS 60870-5-604 5.4.17.40 from the controlling station's side: under
/// option 3 with the **same** scope, the second interrogation's objects and
/// termination still belong to it after the first one terminates.
#[test]
fn the_master_follows_option_3_with_the_same_scope() {
    let mut controlling = Interrogation::controlling(SecondActivation::Allowed, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Queue, CA, 0);
    let device = Device::new();
    let deliver = |frames: Vec<Vec<u8>>, controlling: &mut Interrogation| -> Vec<Reaction> {
        frames
            .iter()
            .map(|f| {
                controlling
                    .on_response(f, &Known::EVERYTHING)
                    .unwrap()
                    .reaction
            })
            .collect()
    };

    for _ in 0..2 {
        let act = controlling.request(Scope::Station).unwrap();
        let confirmed = controlled
            .on_request(&act, &Known::EVERYTHING, &device)
            .unwrap();
        deliver(confirmed.send, &mut controlling);
    }
    let mut frames = controlled.interrogated(&device).unwrap();
    frames.extend(controlled.complete(&device).unwrap());
    let reactions = deliver(frames, &mut controlling);
    let station = Scope::Station;
    assert_eq!(
        reactions,
        [
            Reaction::Interrogated { scope: station },
            Reaction::Interrogated { scope: station },
            Reaction::Terminated { scope: station },
            // The second interrogation, after the first one's termination.
            Reaction::Interrogated { scope: station },
            Reaction::Interrogated { scope: station },
            Reaction::Terminated { scope: station },
        ]
    );
    assert!(!controlling.is_running(station));
}

/// 5.4.17.30, option 2: the first interrogation is terminated before the
/// second is confirmed, and the master ends with nothing running.
#[test]
fn the_master_follows_option_2_with_the_same_scope() {
    let mut controlling = Interrogation::controlling(SecondActivation::Allowed, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Restart, CA, 0);
    let device = Device::new();
    let mut frames = Vec::new();
    for _ in 0..2 {
        let act = controlling.request(Scope::Station).unwrap();
        frames.extend(
            controlled
                .on_request(&act, &Known::EVERYTHING, &device)
                .unwrap()
                .send,
        );
    }
    frames.extend(controlled.interrogated(&device).unwrap());
    frames.extend(controlled.complete(&device).unwrap());
    let terminations = frames
        .iter()
        .map(|f| {
            controlling
                .on_response(f, &Known::EVERYTHING)
                .unwrap()
                .reaction
        })
        .filter(|r| matches!(r, Reaction::Terminated { .. }))
        .count();
    assert_eq!(terminations, 2);
    assert!(!controlling.is_running(Scope::Station));
    assert_eq!(controlling.running(), [] as [iec104::gi::Scope; 0]);
}

/// 5-101 cl.7.3.5.1–7.3.5.3 list causes 20–36 for the three parameters of
/// measured values, so a response may carry them; `P_AC_NA_1` stays out.
#[test]
fn a_response_may_carry_the_parameters_of_measured_values() {
    struct Parameters;
    impl DataSource for Parameters {
        fn ready(&self, _scope: Scope) -> bool {
            true
        }
        fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
            let header = Header {
                type_id: TypeId::PMeNb1,
                sequence: false,
                count: 1,
                cause: scope.cause(),
                negative: false,
                test: false,
                originator: 0,
                common_address: CA,
            };
            let object = LayoutObject {
                ioa: 0x4000,
                value: iec104::asdu::PMeNb1 {
                    sva: Sva { value: 10 },
                    qpm: iec104::asdu::Qpm::from_raw(1),
                },
            };
            out.push(encode_asdu(&header, &[object]).unwrap());
        }
    }

    use iec104::gi::INTERROGATED_PARAMETER_TYPES;
    for type_id in INTERROGATED_PARAMETER_TYPES {
        assert!(is_interrogated(type_id), "{}", type_id.name());
    }
    assert!(!is_interrogated(TypeId::PAcNa1));

    let (mut controlling, mut controlled, _) = running_pair(ReActivation::Continue);
    let data = controlled
        .interrogated(&Parameters)
        .expect("a parameter is allowed");
    assert_eq!(
        controlling
            .on_response(&data[0], &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Interrogated {
            scope: Scope::Station
        }
    );
}

/// 5-101 cl.7.2.3: the controlled station echoes the request's originator
/// address on everything that answers it: confirmation, data, termination.
#[test]
fn every_answer_echoes_the_requests_originator() {
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();
    let act = request(Scope::Station, CA, 42).unwrap();
    let mut frames = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .unwrap()
        .send;
    frames.extend(controlled.interrogated(&device).unwrap());
    frames.extend(controlled.complete(&device).unwrap());
    assert_eq!(frames.len(), 4, "actcon, two objects, actterm");
    for frame in &frames {
        assert_eq!(Header::parse(frame).unwrap().originator, 42);
    }
}

/// 5-101 cl.7.2.3: the controlled station answers a `T = 1` request under
/// test conditions, so the confirmation, the deactivation's confirmation and
/// the termination echo its test bit.
#[test]
fn every_answer_echoes_the_requests_test_bit() {
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();
    let mut act = request(Scope::Station, CA, 0).unwrap();
    act[2] |= 0x80;
    let mut frames = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .unwrap()
        .send;
    frames.extend(controlled.complete(&device).unwrap());
    let terminated = frames.last().unwrap();
    assert_eq!(
        Header::parse(terminated).unwrap().cause,
        CAUSE_ACTIVATION_TERM
    );
    assert!(Header::parse(&frames[0]).unwrap().test, "the confirmation");
    assert!(Header::parse(terminated).unwrap().test, "the termination");

    let mut deact = deactivation(Scope::Station, CA, 0).unwrap();
    deact[2] |= 0x80;
    let answer = controlled
        .on_request(&deact, &Known::EVERYTHING, &device)
        .unwrap()
        .send;
    assert!(
        Header::parse(&answer[0]).unwrap().test,
        "the deactivation's confirmation"
    );
}

/// 5-101 cl.7.2.3: the data answering a `T = 1` interrogation is generated
/// under test conditions too, so it carries `T = 1`; an interrogation queued
/// behind it (option 3) answers with its own request's `T = 0`.
#[test]
fn the_data_echoes_its_own_requests_test_bit() {
    let mut controlled = Interrogation::controlled(ReActivation::Queue, CA, 0);
    let device = Device::new();
    let mut tested = request(Scope::Station, CA, 0).unwrap();
    tested[2] |= 0x80;
    controlled
        .on_request(&tested, &Known::EVERYTHING, &device)
        .unwrap();
    let normal = request(Scope::Station, CA, 0).unwrap();
    controlled
        .on_request(&normal, &Known::EVERYTHING, &device)
        .unwrap();
    let frames = controlled.complete(&device).unwrap();
    let tests: Vec<_> = frames
        .iter()
        .map(|frame| Header::parse(frame).unwrap().test)
        .collect();
    assert_eq!(
        tests,
        [true, true, true, false, false, false],
        "T = 1 data and actterm, then the queued T = 0 data and actterm"
    );
}

/// A group outside 1..=16 is refused rather than clamped into another group.
#[test]
fn a_group_outside_the_standards_range_is_refused() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    for group in [0, 17] {
        assert_eq!(
            controlling.request(Scope::Group(group)),
            Err(GiError::GroupOutOfRange { group })
        );
        assert_eq!(Scope::try_group(group), None);
        assert_eq!(Qoi::try_group(group), None);
    }
    assert_eq!(Scope::try_group(16), Some(Scope::Group(16)));
    assert!(controlling.request(Scope::Group(16)).is_ok());
}

// ------------------------------------------- what "running" means on the wire

/// TS 60870-5-604 Table 17 defines a GI as running from the controlling
/// station's `C_IC_ACT` until it receives the matching `C_IC_ACTTERM`. A
/// termination that overtakes its confirmation still ends the procedure: once
/// it is received, the scope is no longer running and may be requested again.
#[test]
fn a_termination_ends_the_interrogation_even_before_its_confirmation() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();
    let act = controlling.request(Scope::Station).expect("activation");
    let confirmed = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("confirmation");
    controlled.interrogated(&device).expect("data");
    let term = controlled.complete(&device).expect("termination");

    let outcome = controlling
        .on_response(&term[0], &Known::EVERYTHING)
        .expect("actterm");
    assert_eq!(
        outcome.reaction,
        Reaction::Terminated {
            scope: Scope::Station
        }
    );
    assert!(!controlling.is_running(Scope::Station));
    assert_eq!(controlling.awaiting_confirmation(), []);

    // The confirmation that arrives late opens nothing.
    controlling
        .on_response(&confirmed.send[0], &Known::EVERYTHING)
        .expect("late actcon");
    assert!(!controlling.is_running(Scope::Station));
    assert!(controlling.request(Scope::Station).is_ok(), "not locked");
}

/// The same definition from the other end: one `C_IC_ACT` is one procedure, so
/// a confirmation received twice for it does not make it two, and its one
/// `C_IC_ACTTERM` ends it.
#[test]
fn a_repeated_confirmation_does_not_open_a_second_interrogation() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut controlled = Interrogation::controlled(ReActivation::Continue, CA, 0);
    let device = Device::new();
    let act = controlling.request(Scope::Station).expect("activation");
    let confirmed = controlled
        .on_request(&act, &Known::EVERYTHING, &device)
        .expect("confirmation");
    for _ in 0..2 {
        controlling
            .on_response(&confirmed.send[0], &Known::EVERYTHING)
            .expect("actcon");
    }
    controlled.interrogated(&device).expect("data");
    let term = controlled.complete(&device).expect("termination");
    controlling
        .on_response(&term[0], &Known::EVERYTHING)
        .expect("actterm");

    assert!(!controlling.is_running(Scope::Station));
    assert_eq!(controlling.running(), vec![]);
}

/// 5-101 clause 7.4.5 closes the procedure with the termination *after* the
/// interrogated objects. A controlled station that calls `complete` without
/// having sent the data gets the data first, then `C_IC ACTTERM` (cause 10):
/// a bare termination would tell the controlling station it has everything.
#[test]
fn complete_sends_the_owed_data_before_the_termination() {
    let (mut controlling, mut controlled, device) = running_pair(ReActivation::Continue);
    let frames = controlled.complete(&device).expect("data and termination");
    assert_eq!(
        frames.len(),
        3,
        "the station scope's two objects, then ACTTERM"
    );
    for asdu in &frames[..2] {
        assert_eq!(Header::parse(asdu).unwrap().cause.to_u8(), 20);
    }
    assert_interrogation_frame(&frames[2], CAUSE_ACTIVATION_TERM, false, Scope::Station);
    for asdu in &frames {
        controlling.on_response(asdu, &Known::EVERYTHING).unwrap();
    }
    assert!(!controlling.is_running(Scope::Station));
    assert!(!controlled.is_running(Scope::Station));
}

/// When the data source hands over an object the procedure may not send (a
/// cause that is not the scope's, 5-101 clause 7.4.5), `complete` refuses and
/// nothing is sent or forgotten: the interrogation still runs, and a later
/// `complete` sends the data and the termination.
#[test]
fn a_failed_complete_changes_nothing() {
    let (_controlling, mut controlled, device) = running_pair(ReActivation::Continue);
    let broken = Device {
        ready: true,
        objects: vec![(Scope::Station, scaled(Cause::Spontaneous, 0x3010, 1))],
    };
    assert!(controlled.complete(&broken).is_err());
    assert!(controlled.is_running(Scope::Station));
    let frames = controlled.complete(&device).expect("data and termination");
    assert_eq!(frames.len(), 3);
    assert_interrogation_frame(&frames[2], CAUSE_ACTIVATION_TERM, false, Scope::Station);
}

// ------------------------------------------------------ the broadcast address

/// A `C_IC_NA_1` answer from one LRU: the activation's octets with the cause
/// octet and the common address of that LRU written in (5-101 figure 72, the
/// cause in octet 3, the two-octet common address in octets 5 and 6).
fn lru_answer(cause: Cause, negative: bool, lru: u16) -> Vec<u8> {
    let mut asdu = request(Scope::Station, 0xFFFF, 0).expect("the activation");
    asdu[2] = cause.to_u8() | if negative { 0x40 } else { 0 };
    asdu[4..6].copy_from_slice(&lru.to_le_bytes());
    asdu
}

/// One interrogated object from one LRU.
fn lru_object(lru: u16) -> Vec<u8> {
    let mut asdu = scaled(Cause::InterrogatedByStation, 0x0901, 7);
    asdu[4..6].copy_from_slice(&lru.to_le_bytes());
    asdu
}

/// 5-101 clause 7.4.5 (PDF page index 124): a station interrogation sent to
/// the broadcast common address (FF or FFFF, a request of all) is answered as
/// if each LRU had been interrogated on its own: the ACTCON, the ACTTERM and
/// the interrogated objects all come back under each LRU's own common
/// address. TS 60870-5-604 5.4.17.10
/// (index 65) has the controlling station finish the GI for every LRU.
///
/// LRU 1 and LRU 2 confirm, LRU 1 terminates first: LRU 2's object and
/// termination still belong to the procedure, and the lock holds until the last
/// LRU that confirmed has terminated. LRU 3's negative confirmation starts
/// nothing, so its object is not this procedure's.
#[test]
fn a_broadcast_interrogation_is_followed_for_every_lru() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, 0xFFFF, 0);
    controlling.request(Scope::Station).expect("activation");
    let mut react = |asdu: Vec<u8>| {
        controlling
            .on_response(&asdu, &Known::EVERYTHING)
            .expect("an answer")
            .reaction
    };
    let confirmed = |negative| Reaction::ActivationConfirmed {
        scope: Scope::Station,
        negative,
    };
    let interrogated = Reaction::Interrogated {
        scope: Scope::Station,
    };
    let terminated = Reaction::Terminated {
        scope: Scope::Station,
    };

    assert_eq!(
        react(lru_answer(Cause::ActivationCon, false, 1)),
        confirmed(false)
    );
    assert_eq!(
        react(lru_answer(Cause::ActivationCon, false, 2)),
        confirmed(false)
    );
    assert_eq!(
        react(lru_answer(Cause::ActivationCon, true, 3)),
        confirmed(true)
    );
    assert_eq!(react(lru_object(1)), interrogated);
    assert_eq!(
        react(lru_answer(Cause::ActivationTermination, false, 1)),
        terminated
    );
    assert_eq!(react(lru_object(2)), interrogated, "LRU 2 is still running");
    assert_eq!(react(lru_object(3)), Reaction::Other, "LRU 3 refused");
    assert_eq!(
        react(lru_answer(Cause::ActivationTermination, false, 2)),
        terminated
    );
    assert_eq!(
        react(lru_object(2)),
        Reaction::Other,
        "after its termination"
    );

    assert!(
        !controlling.is_running(Scope::Station),
        "every LRU terminated"
    );
    controlling
        .request(Scope::Station)
        .expect("no longer locked");
}

/// While LRU 2 is still running, an identical broadcast interrogation is
/// locked (clause 7.4.5's lock, [`SecondActivation::Locked`]).
#[test]
fn a_broadcast_interrogation_is_locked_until_the_last_lru_terminates() {
    let mut controlling = Interrogation::controlling(SecondActivation::Locked, 0xFFFF, 0);
    controlling.request(Scope::Station).expect("activation");
    for asdu in [
        lru_answer(Cause::ActivationCon, false, 1),
        lru_answer(Cause::ActivationCon, false, 2),
        lru_answer(Cause::ActivationTermination, false, 1),
    ] {
        controlling
            .on_response(&asdu, &Known::EVERYTHING)
            .expect("an answer");
    }
    assert_eq!(
        controlling.request(Scope::Station),
        Err(GiError::AlreadyRunning {
            scope: Scope::Station
        })
    );
}
