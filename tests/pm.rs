//! Parameter loading (`iec104::pm`): the three parameters of measured values
//! (`P_ME_NA_1`/`P_ME_NB_1`/`P_ME_NC_1`, types 110–112) with their `QPM`, and
//! the parameter activation (`P_AC_NA_1`, type 113) with its `QPA`.
//!
//! The clause citations are 5-104 cl.7.9 (the five service rows, PDF page index
//! 70) and cl.9's Table 5 (the `CON` column of the four types, page index 52);
//! 5-101 cl.7.3.5.1–.4's figures 79–82 (the per-type layouts and cause lists,
//! page indices 110–113), cl.7.2.6.24 (`QPM`, page indices 54–55), cl.7.2.6.25
//! (`QPA`, page index 55), cl.7.4.9 (the profile's selections, page index 130)
//! and cl.7.2.3 (the echo and the 44–47 mirror, page index 38); and TS
//! 60870-5-604 Table 21 (5.4.21.1/.10/.15, PDF page index 82).
//!
//! Every frame is pinned as the octet string the figure draws, and the second
//! half drives the two roles against each other. The scripted exchange is the
//! acceptance test.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::unwrap_used, clippy::as_conversions)]

use iec104::asdu::{
    Cause, Discard, Header, Known, Nva, PAcNa1, PMeNa1, PMeNb1, PMeNc1, Qpa, Qpm, R32, Sva, TypeId,
    Unspecified, decode_asdu,
};
use iec104::pm::{
    CAUSE_ACTIVATION, CAUSE_ACTIVATION_CON, CAUSE_DEACTIVATION, CAUSE_DEACTIVATION_CON, Family,
    LocalChange, Parameter, ParameterLoading, ParameterValue, PmError, Reaction, Role, activation,
    announcement, confirmation, deactivation, deactivation_confirmation, is_parameter_type, load,
    mirror, unknown_reply,
};

/// The broadcast common address of the conventional two-octet profile.
const BROADCAST_CA: u16 = iec104::asdu::AddressSizes::CONVENTIONAL.broadcast_common_address();

const CA: u16 = 12;
const ORG: u8 = 7;
const IOA: u32 = 0x4001;

// ---------------------------------------------------------------- helpers

/// A `QPM` of one kind, with the two extension bits clear. That is the only
/// shape this crate builds (5-101 cl.7.2.6.24: the standard leaves `LPC` and
/// `POP` unused, at zero).
fn qpm(kpa: u8) -> Qpm {
    Qpm {
        kpa,
        ..Default::default()
    }
}

/// A normalized parameter of measured values, `NVA` as given, threshold kind.
fn normalized(value: i16) -> Parameter {
    Parameter::new(
        IOA,
        ParameterValue::Normalized {
            nva: Nva { value },
            qpm: qpm(Qpm::THRESHOLD),
        },
    )
}

/// A scaled parameter of measured values, smoothing-factor kind.
fn scaled(value: i16) -> Parameter {
    Parameter::new(
        IOA,
        ParameterValue::Scaled {
            sva: Sva { value },
            qpm: qpm(Qpm::SMOOTHING_FACTOR),
        },
    )
}

/// A short floating point parameter, high-limit kind.
fn float(value: f32) -> Parameter {
    float_with_kpa(value, Qpm::HIGH_LIMIT)
}

/// A short floating point parameter with an explicit `KPA`, for the kinds whose
/// values have a sign rule of their own.
fn float_with_kpa(value: f32, kpa: u8) -> Parameter {
    Parameter::new(
        IOA,
        ParameterValue::Float {
            r32: R32 { value },
            qpm: qpm(kpa),
        },
    )
}

/// A parameter activation with the `QPA` given (`<3>` is the act/deact of
/// persistent cyclic or periodic transmission of the addressed object).
const fn activation_parameter(qpa: u8) -> Parameter {
    Parameter::new(
        IOA,
        ParameterValue::Activation {
            qpa: Qpa { value: qpa },
        },
    )
}

/// The controlling and controlled instances of one exchange, both at `CA`/`ORG`
/// with 5-101's selection (cl.7.4.9: `P_ME SPONT` is not used).
const fn roles() -> (ParameterLoading, ParameterLoading) {
    (
        ParameterLoading::controlling(LocalChange::NotUsed, CA, ORG),
        ParameterLoading::controlled(LocalChange::NotUsed, CA, ORG),
    )
}

/// Every frame the `pm` builders produce, for the truncation sweep.
fn every_frame() -> Vec<Vec<u8>> {
    vec![
        load(&normalized(0x2000), CA, ORG).unwrap(),
        load(&scaled(0x1234), CA, ORG).unwrap(),
        load(&float(1.5), CA, ORG).unwrap(),
        activation(&activation_parameter(Qpa::PERSISTENT_CYCLIC), CA, ORG).unwrap(),
        deactivation(&activation_parameter(Qpa::PERSISTENT_CYCLIC), CA, ORG).unwrap(),
        announcement(&normalized(0x2000), CA, ORG).unwrap(),
        confirmation(&normalized(0x2000), false, CA, ORG, false).unwrap(),
        confirmation(&normalized(0x2000), true, CA, ORG, true).unwrap(),
        deactivation_confirmation(
            &activation_parameter(Qpa::PERSISTENT_CYCLIC),
            CA,
            ORG,
            false,
        )
        .unwrap(),
    ]
}

/// An `M_SP_NA_1` ASDU, a type this procedure does not own.
const MONITOR_FRAME: [u8; 10] = [0x01, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00];

// ------------------------------------------------- the four types, byte for byte

#[test]
fn the_normalized_load_is_the_twelve_octets_of_figure_79() {
    let frame = load(&normalized(0x2000), CA, ORG).unwrap();
    // Figure 79 (5-101 PDF page index 110): P_ME_NA_1 := CP{data unit
    // identifier, information object address, NVA, QPM}: 6 header octets,
    // IOA(3), NVA(2, little-endian F16), QPM(1).
    assert_eq!(
        frame,
        vec![
            0x6E, 0x01, 0x06, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x20, 0x01
        ]
    );
    // The octets the figure draws, one by one.
    assert_eq!(frame[0], TypeId::PMeNa1.to_u8(), "type 110");
    assert_eq!(frame[1], 0x01, "SQ = 0, one information object");
    assert_eq!(frame[2], 0x06, "cause <6> act, P/N and T clear");
    assert_eq!(frame[3], ORG, "originator");
    assert_eq!(&frame[4..6], &CA.to_le_bytes(), "common address");
    assert_eq!(&frame[6..9], &[0x01, 0x40, 0x00], "the IOA, little-endian");
    assert_eq!(&frame[9..11], &[0x00, 0x20], "NVA little-endian");
    assert_eq!(frame[11], 0x01, "QPM: KPA = <1> threshold, LPC/POP clear");
}

#[test]
fn the_scaled_load_is_the_twelve_octets_of_figure_80() {
    let frame = load(&scaled(0x1234), CA, ORG).unwrap();
    // Figure 80 (page index 111): P_ME_NB_1 := CP{…, SVA, QPM}.
    assert_eq!(
        frame,
        vec![
            0x6F, 0x01, 0x06, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x34, 0x12, 0x02
        ]
    );
    assert_eq!(frame[0], TypeId::PMeNb1.to_u8(), "type 111");
    assert_eq!(frame[11], 0x02, "KPA = <2> smoothing factor");
}

#[test]
fn the_float_load_is_the_fourteen_octets_of_figure_81() {
    let frame = load(&float(1.5), CA, ORG).unwrap();
    // Figure 81 (page index 112): P_ME_NC_1 := CP{…, IEEE STD 754, QPM}; the
    // R32 is an IEEE 754 single in little-endian octet order (1.5 = 0x3FC00000).
    assert_eq!(
        frame,
        vec![
            0x70, 0x01, 0x06, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0xC0, 0x3F, 0x04
        ]
    );
    assert_eq!(frame[0], TypeId::PMeNc1.to_u8(), "type 112");
    assert_eq!(&frame[9..13], &1.5f32.to_le_bytes());
    assert_eq!(frame[13], 0x04, "KPA = <4> high limit");
}

#[test]
fn the_activation_is_the_ten_octets_of_figure_82() {
    let parameter = activation_parameter(Qpa::PERSISTENT_CYCLIC);
    let frame = activation(&parameter, CA, ORG).unwrap();
    // Figure 82 (page index 113): P_AC_NA_1 := CP{…, QPA}, a one-octet element.
    assert_eq!(
        frame,
        vec![0x71, 0x01, 0x06, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03]
    );
    assert_eq!(frame[0], TypeId::PAcNa1.to_u8(), "type 113");
    assert_eq!(frame[9], 0x03, "QPA = <3> act/deact of persistent cyclic");
}

#[test]
fn the_deactivation_takes_cause_8() {
    let frame = deactivation(&activation_parameter(Qpa::PERSISTENT_CYCLIC), CA, ORG).unwrap();
    assert_eq!(
        frame,
        vec![0x71, 0x01, 0x08, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03]
    );
    assert_eq!(frame[2], 0x08, "figure 82's control-direction <8> deact");
}

#[test]
fn every_frame_decodes_back_into_the_landed_layout() {
    let normalized = load(&normalized(0x2000), CA, ORG).unwrap();
    let object = decode_asdu::<PMeNa1>(&normalized).unwrap();
    assert_eq!(object.len(), 1);
    assert_eq!(object[0].ioa, IOA);
    assert_eq!(
        object[0].value,
        PMeNa1 {
            nva: Nva { value: 0x2000 },
            qpm: qpm(Qpm::THRESHOLD)
        }
    );

    let scaled = load(&scaled(0x1234), CA, ORG).unwrap();
    assert_eq!(
        decode_asdu::<PMeNb1>(&scaled).unwrap()[0].value,
        PMeNb1 {
            sva: Sva { value: 0x1234 },
            qpm: qpm(Qpm::SMOOTHING_FACTOR)
        }
    );

    let float = load(&float(1.5), CA, ORG).unwrap();
    assert_eq!(
        decode_asdu::<PMeNc1>(&float).unwrap()[0].value,
        PMeNc1 {
            r32: R32 { value: 1.5 },
            qpm: qpm(Qpm::HIGH_LIMIT)
        }
    );

    let activation = activation(&activation_parameter(3), CA, ORG).unwrap();
    assert_eq!(
        decode_asdu::<PAcNa1>(&activation).unwrap()[0].value,
        PAcNa1 {
            qpa: Qpa { value: 3 }
        }
    );
}

// ------------------------------------------------------------------ the mirror

#[test]
fn the_confirmation_is_the_request_with_only_the_header_changed() {
    let request = load(&normalized(0x2000), CA, ORG).unwrap();
    let answer = confirmation(&normalized(0x2000), false, CA, ORG, false).unwrap();
    assert_eq!(answer[0], request[0], "same type identification");
    assert_eq!(answer[1], request[1], "same VSQ");
    assert_eq!(
        answer[3..],
        request[3..],
        "same originator, address, element"
    );
    assert_eq!(answer[2], 0x07, "cause <7> actcon, positive");
    assert_eq!(answer.len(), request.len());
}

#[test]
fn the_negative_confirmation_sets_pn_and_keeps_the_element() {
    let answer = confirmation(&normalized(0x2000), true, CA, ORG, true).unwrap();
    assert_eq!(
        answer,
        vec![
            0x6E, 0x01, 0xC7, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x20, 0x01
        ]
    );
    // 0xC7 = cause 7 in bits 1-6, P/N in bit 7, T in bit 8: TS 60870-5-604
    // 5.4.21.10's ACTCONneg under test conditions.
    let header = Header::parse(&answer).unwrap();
    assert_eq!(header.cause, CAUSE_ACTIVATION_CON);
    assert!(header.negative);
    assert!(header.test);
}

#[test]
fn the_deactivation_confirmation_carries_cause_9() {
    let parameter = activation_parameter(3);
    let answer = deactivation_confirmation(&parameter, CA, ORG, false).unwrap();
    assert_eq!(
        answer,
        vec![0x71, 0x01, 0x09, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03]
    );
    assert_eq!(
        Header::parse(&answer).unwrap().cause,
        CAUSE_DEACTIVATION_CON
    );
}

#[test]
fn the_announcement_carries_cause_3() {
    let frame = announcement(&normalized(0x2000), CA, ORG).unwrap();
    assert_eq!(
        frame,
        vec![
            0x6E, 0x01, 0x03, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x20, 0x01
        ]
    );
    assert_eq!(Header::parse(&frame).unwrap().cause, Cause::Spontaneous);
}

#[test]
fn the_unknown_reply_is_the_class_cause_with_pn() {
    let request = load(&normalized(0x2000), CA, ORG).unwrap();
    let answer = unknown_reply(
        &normalized(0x2000),
        Unspecified::InformationObjectAddress,
        CA,
        ORG,
        false,
    )
    .unwrap();
    assert_eq!(answer[2], 0x2F | 0x40, "cause 47 and P/N = 1");
    assert_eq!(answer[3..], request[3..], "the element is reproduced");
    assert_eq!(
        Header::parse(&answer).unwrap().cause,
        Cause::UnknownInformationObjectAddress
    );
}

// ------------------------------------------------- the clause's value grammar

#[test]
fn the_four_kinds_are_the_clauses_own_and_the_reserved_ranges_are_refused() {
    for kpa in [
        Qpm::THRESHOLD,
        Qpm::SMOOTHING_FACTOR,
        Qpm::LOW_LIMIT,
        Qpm::HIGH_LIMIT,
    ] {
        assert!(load(&parameter_with_kpa(kpa), CA, ORG).is_ok(), "KPA {kpa}");
    }
    // <32..63> is "reserved for special use (private range)", so it is carried.
    assert!(load(&parameter_with_kpa(32), CA, ORG).is_ok());
    assert!(load(&parameter_with_kpa(63), CA, ORG).is_ok());
    // <0> is unused and <5..31> is the compatible range, kept for the
    // companion standard's own definitions. Neither is a value this
    // crate writes.
    for kpa in [0, 5, 7, 31] {
        assert_eq!(
            load(&parameter_with_kpa(kpa), CA, ORG),
            Err(PmError::KpaNotUsed { kpa }),
            "KPA {kpa}"
        );
    }
}

/// A normalized parameter with the kind of parameter given.
fn parameter_with_kpa(kpa: u8) -> Parameter {
    Parameter::new(
        IOA,
        ParameterValue::Normalized {
            nva: Nva { value: 0x2000 },
            qpm: qpm(kpa),
        },
    )
}

#[test]
fn a_qpm_with_lpc_or_pop_is_refused() {
    let local_change = Parameter::new(
        IOA,
        ParameterValue::Normalized {
            nva: Nva { value: 1 },
            qpm: Qpm {
                kpa: Qpm::THRESHOLD,
                local_parameter_change: true,
                parameter_not_in_operation: false,
            },
        },
    );
    assert_eq!(load(&local_change, CA, ORG), Err(PmError::QpmNotZeroed));

    let not_in_operation = Parameter::new(
        IOA,
        ParameterValue::Normalized {
            nva: Nva { value: 1 },
            qpm: Qpm {
                kpa: Qpm::THRESHOLD,
                local_parameter_change: false,
                parameter_not_in_operation: true,
            },
        },
    );
    assert_eq!(load(&not_in_operation, CA, ORG), Err(PmError::QpmNotZeroed));
}

#[test]
fn the_activation_refuses_every_qpa_the_profile_does_not_use() {
    // 5-101 cl.7.2.6.25: <0> not used, <1>/<2> not used in this companion
    // standard, <4..127> reserved for standard definitions. TS 60870-5-604
    // 5.4.21.15 makes 1 and 2 a rejection.
    for value in [0, 1, 2, 4, 127] {
        assert_eq!(
            activation(&activation_parameter(value), CA, ORG),
            Err(PmError::QpaNotUsed { value }),
            "QPA {value}"
        );
        assert_eq!(
            deactivation(&activation_parameter(value), CA, ORG),
            Err(PmError::QpaNotUsed { value }),
            "QPA {value}"
        );
    }
    assert!(activation(&activation_parameter(Qpa::PERSISTENT_CYCLIC), CA, ORG).is_ok());
    // <128..255> is "reserved for special use (private range)", so it is
    // carried.
    assert!(activation(&activation_parameter(128), CA, ORG).is_ok());
    assert!(activation(&activation_parameter(255), CA, ORG).is_ok());
}

#[test]
fn the_three_parameters_have_no_deactivation() {
    for parameter in [normalized(0x2000), scaled(0x1234), float(1.5)] {
        let expected = Err(PmError::DeactivationNotDefined {
            type_id: parameter.type_id(),
        });
        assert_eq!(deactivation(&parameter, CA, ORG), expected);
        assert_eq!(
            deactivation_confirmation(&parameter, CA, ORG, false),
            expected
        );
    }
}

#[test]
fn a_cause_the_type_does_not_define_is_refused() {
    assert_eq!(
        mirror(
            &normalized(0x2000),
            CAUSE_DEACTIVATION,
            false,
            false,
            CA,
            ORG
        ),
        Err(PmError::CauseNotDefined {
            type_id: TypeId::PMeNa1,
            cause: CAUSE_DEACTIVATION,
        })
    );
    assert_eq!(
        mirror(
            &normalized(0x2000),
            Cause::DeactivationCon,
            false,
            false,
            CA,
            ORG
        ),
        Err(PmError::CauseNotDefined {
            type_id: TypeId::PMeNa1,
            cause: Cause::DeactivationCon,
        })
    );
    assert_eq!(
        mirror(
            &activation_parameter(3),
            Cause::Spontaneous,
            false,
            false,
            CA,
            ORG
        ),
        Err(PmError::CauseNotDefined {
            type_id: TypeId::PAcNa1,
            cause: Cause::Spontaneous,
        })
    );
    assert_eq!(
        mirror(
            &activation_parameter(3),
            Cause::InterrogatedByStation,
            false,
            false,
            CA,
            ORG
        ),
        Err(PmError::CauseNotDefined {
            type_id: TypeId::PAcNa1,
            cause: Cause::InterrogatedByStation,
        })
    );
    // Cause 10 is listed for no parameter type: figures 79-82 print <6>/<8> in
    // the control direction and <7>/<9>, the interrogation causes and the
    // 44-47 replies in the monitor direction only.
    assert_eq!(
        mirror(
            &normalized(0x2000),
            Cause::ActivationTermination,
            false,
            false,
            CA,
            ORG
        ),
        Err(PmError::CauseNotDefined {
            type_id: TypeId::PMeNa1,
            cause: Cause::ActivationTermination,
        })
    );
}

#[test]
fn the_families_are_the_figures_own_cause_lists() {
    assert_eq!(Family::of_type(TypeId::PMeNa1), Some(Family::Measured));
    assert_eq!(Family::of_type(TypeId::PMeNb1), Some(Family::Measured));
    assert_eq!(Family::of_type(TypeId::PMeNc1), Some(Family::Measured));
    assert_eq!(Family::of_type(TypeId::PAcNa1), Some(Family::Activation));
    assert_eq!(Family::of_type(TypeId::MSpNa1), None);
    assert_eq!(Family::of_type(TypeId::CScNa1), None);
    assert!(is_parameter_type(TypeId::PAcNa1));
    assert!(!is_parameter_type(TypeId::CCsNa1));

    // Figure 82 is the one of the four with a deactivation.
    assert!(!Family::Measured.has_deactivation());
    assert!(Family::Activation.has_deactivation());

    let cases = [
        (Family::Measured, Cause::Activation, true, false),
        // Figure 79 prints no <3>, but 104 cl.7.9's A_LCPACH row names it.
        (Family::Measured, Cause::Spontaneous, false, true),
        (Family::Measured, Cause::Deactivation, false, false),
        (Family::Measured, Cause::ActivationCon, false, true),
        (Family::Measured, Cause::DeactivationCon, false, false),
        (Family::Measured, Cause::InterrogatedByStation, false, true),
        (
            Family::Measured,
            Cause::InterrogatedByGroup(16),
            false,
            true,
        ),
        (Family::Measured, Cause::Periodic, false, false),
        (Family::Measured, Cause::UnknownTypeId, false, true),
        (
            Family::Measured,
            Cause::UnknownInformationObjectAddress,
            false,
            true,
        ),
        (Family::Activation, Cause::Activation, true, false),
        (Family::Activation, Cause::Deactivation, true, false),
        (Family::Activation, Cause::ActivationCon, false, true),
        (Family::Activation, Cause::DeactivationCon, false, true),
        (
            Family::Activation,
            Cause::InterrogatedByStation,
            false,
            false,
        ),
        (Family::Activation, Cause::UnknownCause, false, true),
    ];
    assert_eq!(cases.len(), 16);
    for (family, cause, control, monitor) in cases {
        assert_eq!(
            family.is_control_cause(cause),
            control,
            "{family:?} {cause:?}"
        );
        assert_eq!(
            family.is_monitor_cause(cause),
            monitor,
            "{family:?} {cause:?}"
        );
        assert_eq!(
            family.allows(cause),
            control || monitor,
            "{family:?} {cause:?}"
        );
    }
}

#[test]
fn the_wrong_family_is_refused() {
    assert_eq!(
        load(&activation_parameter(3), CA, ORG),
        Err(PmError::WrongFamily {
            expected: Family::Measured,
            got: Family::Activation,
        })
    );
    assert_eq!(
        activation(&normalized(0x2000), CA, ORG),
        Err(PmError::WrongFamily {
            expected: Family::Activation,
            got: Family::Measured,
        })
    );
    assert_eq!(
        announcement(&activation_parameter(3), CA, ORG),
        Err(PmError::WrongFamily {
            expected: Family::Measured,
            got: Family::Activation,
        })
    );
}

#[test]
fn a_parameter_reports_its_own_type_family_and_qualifier() {
    let measured = normalized(0x2000);
    assert_eq!(measured.type_id(), TypeId::PMeNa1);
    assert_eq!(measured.family(), Family::Measured);
    assert_eq!(measured.qpm(), Some(qpm(Qpm::THRESHOLD)));
    assert_eq!(measured.qpa(), None);
    assert_eq!(measured.value.type_id(), TypeId::PMeNa1);
    assert_eq!(measured.value.family(), Family::Measured);

    let activation = activation_parameter(3);
    assert_eq!(activation.type_id(), TypeId::PAcNa1);
    assert_eq!(activation.family(), Family::Activation);
    assert_eq!(activation.qpm(), None);
    assert_eq!(activation.qpa(), Some(Qpa { value: 3 }));
}

// ------------------------------------------------------------ the two roles

#[test]
fn a_load_with_a_qpm_the_builder_refuses_is_confirmed_negatively() {
    // 5-101 cl.7.2.6.24: KPA <0> "not used" and <5..31> reserved, LPC (0x40)
    // and POP (0x80) "set to zero". `load` refuses each, so `on_request` must
    // not accept one either: the request mirrored with cause 7 and P/N = 1.
    let (_, controlled) = roles();
    for qpm_byte in [0x00, 0x05, 0x1F, 0x41, 0x81] {
        let request = vec![
            0x6E, 0x01, 0x06, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x20, qpm_byte,
        ];
        let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
        assert_eq!(
            outcome.reaction,
            Reaction::Refused {
                ioa: IOA,
                cause: Cause::ActivationCon,
            },
            "QPM {qpm_byte:#04x}"
        );
        assert_eq!(
            outcome.send,
            vec![vec![
                0x6E, 0x01, 0x47, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x20, qpm_byte,
            ]],
            "QPM {qpm_byte:#04x}"
        );
    }
}

#[test]
fn the_load_exchange_accepts_with_the_new_value() {
    let (controlling, controlled) = roles();
    let new = normalized(0x2000);

    let request = controlling.load(&new).unwrap();
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Loaded {
            ioa: IOA,
            value: new.value,
        }
    );
    assert_eq!(outcome.send.len(), 1);
    assert_eq!(
        outcome.send[0],
        vec![
            0x6E, 0x01, 0x07, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x20, 0x01
        ],
        "the answer is the request with cause 7"
    );
    assert_eq!(outcome.send[0][Header::LEN..], request[Header::LEN..]);

    let answer = controlling
        .on_response(&outcome.send[0], &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        answer.reaction,
        Reaction::Confirmed {
            ioa: IOA,
            value: new.value,
            negative: false,
        },
        "5-101 cl.7.4.9: the confirmation carries the value now in operation"
    );
    assert!(
        answer.send.is_empty(),
        "a controlling station answers nothing"
    );
}

#[test]
fn a_refused_load_answers_with_the_old_value() {
    let (controlling, controlled) = roles();
    let new = normalized(0x2000);
    let old = normalized(0x1000);

    let request = controlling.load(&new).unwrap();
    let outcome = controlled.refuse(&request, &old).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: IOA,
            value: old.value,
            negative: true,
        }
    );
    // The same ASDU with P/N = 1, carrying the *old* element, not the new one.
    assert_eq!(
        outcome.send[0],
        vec![
            0x6E, 0x01, 0x47, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x10, 0x01
        ]
    );

    let answer = controlling
        .on_response(&outcome.send[0], &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        answer.reaction,
        Reaction::Confirmed {
            ioa: IOA,
            value: old.value,
            negative: true,
        },
        "TS 60870-5-604 5.4.21.10: the actual value is the old existing one"
    );
}

#[test]
fn the_activation_exchange_runs_between_the_two_roles() {
    let (controlling, controlled) = roles();
    let parameter = activation_parameter(Qpa::PERSISTENT_CYCLIC);
    let qpa = parameter.qpa().unwrap();

    let request = controlling.activate(&parameter).unwrap();
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    assert_eq!(outcome.reaction, Reaction::Activated { ioa: IOA, qpa });
    assert_eq!(
        outcome.send[0],
        vec![0x71, 0x01, 0x07, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03]
    );

    let answer = controlling
        .on_response(&outcome.send[0], &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        answer.reaction,
        Reaction::Confirmed {
            ioa: IOA,
            value: parameter.value,
            negative: false,
        }
    );
}

#[test]
fn the_deactivation_exchange_carries_cause_8_then_9() {
    let (controlling, controlled) = roles();
    let parameter = activation_parameter(Qpa::PERSISTENT_CYCLIC);
    let qpa = parameter.qpa().unwrap();

    let request = controlling.deactivate(&parameter).unwrap();
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Deactivated {
            ioa: IOA,
            qpa,
            negative: false,
        }
    );
    assert_eq!(
        outcome.send[0],
        vec![0x71, 0x01, 0x09, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03]
    );

    let answer = controlling
        .on_response(&outcome.send[0], &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        answer.reaction,
        Reaction::Deactivated {
            ioa: IOA,
            qpa,
            negative: false,
        }
    );
}

#[test]
fn a_negative_deactivation_confirmation_carries_the_flag() {
    // 5-101 cl.7.2.3 defines `P/N` without tying it to a cause (0 positive,
    // 1 negative confirmation), and TS 60870-5-604 5.4.21.15 mirrors every
    // received parameter activation (ASDU 113) with QPA = 1 or 2 with P/N = 1,
    // negative. The module's own controlled
    // side sends `71 01 49 …` (cause 9, P/N = 1) for a DEACT whose QPA it will
    // not serve, so the controlling side must not read that frame as a
    // success.
    let controlling = ParameterLoading::controlling(LocalChange::NotUsed, CA, ORG);
    let qpa = Qpa {
        value: Qpa::PERSISTENT_CYCLIC,
    };

    let negative = [0x71, 0x01, 0x49, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03];
    assert_eq!(
        controlling
            .on_response(&negative, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Deactivated {
            ioa: IOA,
            qpa,
            negative: true,
        },
        "P/N = 1 is DEACTCONneg, not a successful deactivation"
    );

    let positive = [0x71, 0x01, 0x09, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03];
    assert_eq!(
        controlling
            .on_response(&positive, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Deactivated {
            ioa: IOA,
            qpa,
            negative: false,
        }
    );
}

#[test]
fn a_negative_threshold_or_smoothing_factor_is_not_confirmed_positively() {
    // TS 60870-5-604 Table 21, 5.4.21.10 (PDF page index 82): a negative
    // threshold value or smoothing factor is always invalid and is never
    // activated. The station answers such a
    // load with ACTCONneg carrying the OLD value. This crate does not hold that
    // value, so its controlled side emits nothing and hands the decision to
    // `refuse`.
    let (_, controlled) = roles();
    let cases = [
        normalized(-100),                            // P_ME_NA_1, KPA <1>
        scaled(-100),                                // P_ME_NB_1, KPA <2>
        float_with_kpa(-1.0, Qpm::SMOOTHING_FACTOR), // P_ME_NC_1, KPA <2>
    ];
    assert_eq!(cases.len(), 3, "one per P_ME type");
    for parameter in cases {
        let request = load(&parameter, CA, ORG).unwrap();
        let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
        assert_eq!(
            outcome.reaction,
            Reaction::Infeasible {
                ioa: IOA,
                value: parameter.value,
            },
            "{:?} must not be confirmed positively",
            parameter.value
        );
        assert!(
            outcome.send.is_empty(),
            "nothing is sent: the crate holds no old value (refuse answers it)"
        );
    }
}

#[test]
fn a_negative_limit_is_still_confirmed_positively() {
    // 5.4.21.10 names the threshold value and the smoothing factor only: the
    // low and high limits ("for transmission of measured values") may be
    // negative, and they are activated normally.
    let (_, controlled) = roles();
    let low = Parameter::new(
        IOA,
        ParameterValue::Normalized {
            nva: Nva { value: -100 },
            qpm: qpm(Qpm::LOW_LIMIT),
        },
    );
    let high = float_with_kpa(-1.0, Qpm::HIGH_LIMIT);
    for parameter in [low, high] {
        let request = load(&parameter, CA, ORG).unwrap();
        let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
        assert_eq!(
            outcome.reaction,
            Reaction::Loaded {
                ioa: IOA,
                value: parameter.value,
            }
        );
        assert_eq!(outcome.send.len(), 1);
        let header = Header::parse(&outcome.send[0]).unwrap();
        assert_eq!(header.cause, CAUSE_ACTIVATION_CON);
        assert!(!header.negative);
    }
}

#[test]
fn a_refused_activation_mirrors_the_received_qpa() {
    let (controlling, controlled) = roles();
    let qpa = Qpa {
        value: Qpa::PERSISTENT_CYCLIC,
    };
    let request = controlling
        .activate(&activation_parameter(qpa.value))
        .unwrap();

    // The caller's "value now in operation" names another QPA. For P_AC_NA_1
    // the mirror is the same ASDU sent back (604 5.4.21.15), and a QPA is a qualifier,
    // not a value now in operation. So the received QPA answers, not the
    // caller's.
    let outcome = controlled
        .refuse(&request, &activation_parameter(200))
        .unwrap();
    assert_eq!(
        outcome.send[0],
        vec![0x71, 0x01, 0x47, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03],
        "the received QPA 3, not the caller's 200"
    );
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: IOA,
            value: activation_parameter(qpa.value).value,
            negative: true,
        }
    );
}

#[test]
fn a_refused_deactivation_answers_cause_9_with_the_flag() {
    // Figure 82 (5-101 cl.7.3.5.4, PDF page index 113) lists `<8>`/`<9>`, so a
    // controlled station refuses a P_AC deactivation with the cause-9 mirror
    // and P/N = 1, not with `CauseNotDefined`.
    let (controlling, controlled) = roles();
    let qpa = Qpa {
        value: Qpa::PERSISTENT_CYCLIC,
    };
    let request = controlling
        .deactivate(&activation_parameter(qpa.value))
        .unwrap();
    let outcome = controlled
        .refuse(&request, &activation_parameter(200))
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Deactivated {
            ioa: IOA,
            qpa,
            negative: true,
        }
    );
    assert_eq!(
        outcome.send[0],
        vec![0x71, 0x01, 0x49, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x03]
    );

    // The three P_ME types have no <8>, so a deactivation of one stays an
    // error rather than a frame.
    let mut pme_deactivation = load(&normalized(0x2000), CA, ORG).unwrap();
    pme_deactivation[2] = CAUSE_DEACTIVATION.to_u8();
    assert_eq!(
        controlled.refuse(&pme_deactivation, &normalized(0x2000)),
        Err(PmError::CauseNotDefined {
            type_id: TypeId::PMeNa1,
            cause: CAUSE_DEACTIVATION,
        })
    );
}

#[test]
fn the_answer_echoes_the_requests_originator_and_test_bit() {
    let (_, controlled) = roles();
    let request = mirror(&normalized(0x2000), CAUSE_ACTIVATION, false, true, CA, 9).unwrap();
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    let header = Header::parse(&outcome.send[0]).unwrap();
    assert_eq!(header.originator, 9, "cl.7.2.3's echo");
    assert!(header.test, "a test frame is answered with a test frame");
    assert_eq!(header.common_address, CA, "the station's own address");
    assert_eq!(header.cause, CAUSE_ACTIVATION_CON);
}

#[test]
fn a_qpa_the_profile_does_not_use_is_answered_negatively_not_as_an_error() {
    let (_, controlled) = roles();
    // The frame a controlling station out of line with cl.7.4.9 sends: QPA = 1.
    let request = [0x71, 0x01, 0x06, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x01];
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: CAUSE_ACTIVATION_CON,
        },
        "TS 60870-5-604 5.4.21.15: mirrored with P/N = 1, not an error"
    );
    assert_eq!(
        outcome.send[0],
        vec![0x71, 0x01, 0x47, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x01],
        "the same ASDU with P/N = 1, the QPA reproduced"
    );

    // QPA = 2, and the same on a deactivation: cause 9 answers cause 8.
    let request = [0x71, 0x01, 0x06, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x02];
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: CAUSE_ACTIVATION_CON,
        }
    );
    assert_eq!(outcome.send[0][2], 0x47);

    let request = [0x71, 0x01, 0x08, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x01];
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: CAUSE_DEACTIVATION_CON,
        }
    );
    assert_eq!(
        outcome.send[0],
        vec![0x71, 0x01, 0x49, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x01]
    );
}

#[test]
fn a_control_direction_cause_the_type_does_not_define_is_mirrored_with_cause_45() {
    let (_, controlled) = roles();
    // A confirmation is a monitor-direction frame: it is not a request, and
    // figure 79's control direction lists only <6>.
    let request = confirmation(&normalized(0x2000), false, CA, ORG, false).unwrap();
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: Cause::UnknownCause,
        }
    );
    let header = Header::parse(&outcome.send[0]).unwrap();
    assert_eq!(header.cause, Cause::UnknownCause);
    assert!(header.negative);
}

#[test]
fn the_readback_causes_20_to_36_are_accepted_on_the_controlling_side() {
    let (controlling, _) = roles();
    let value = normalized(0x2000).value;

    let station = mirror(
        &normalized(0x2000),
        Cause::InterrogatedByStation,
        false,
        false,
        CA,
        ORG,
    )
    .unwrap();
    assert_eq!(
        controlling
            .on_response(&station, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Interrogated {
            ioa: IOA,
            value,
            cause: Cause::InterrogatedByStation,
        }
    );

    for group in [1u8, 16] {
        let frame = mirror(
            &normalized(0x2000),
            Cause::InterrogatedByGroup(group),
            false,
            false,
            CA,
            ORG,
        )
        .unwrap();
        assert_eq!(frame[2], 20 + group, "inro{group}");
        assert_eq!(
            controlling
                .on_response(&frame, &Known::EVERYTHING)
                .unwrap()
                .reaction,
            Reaction::Interrogated {
                ioa: IOA,
                value,
                cause: Cause::InterrogatedByGroup(group),
            }
        );
    }

    // Figure 82 lists no interrogation cause for the activation type.
    let mut frame = activation(&activation_parameter(3), CA, ORG).unwrap();
    frame[2] = 20;
    assert_eq!(
        controlling
            .on_response(&frame, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );
}

#[test]
fn the_pme_spont_announcement_is_the_stations_own_selection() {
    let frame = announcement(&normalized(0x2000), CA, ORG).unwrap();
    let value = normalized(0x2000).value;

    let not_used = ParameterLoading::controlling(LocalChange::NotUsed, CA, ORG);
    assert_eq!(
        not_used
            .on_response(&frame, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other,
        "5-101 cl.7.4.9: P_ME SPONT for local parameter change is not used"
    );

    let used = ParameterLoading::controlling(LocalChange::Used, CA, ORG);
    assert_eq!(
        used.on_response(&frame, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Announced { ioa: IOA, value }
    );

    // The controlled station can only announce what its selection has.
    let not_used = ParameterLoading::controlled(LocalChange::NotUsed, CA, ORG);
    assert_eq!(
        not_used.announce(&normalized(0x2000)),
        Err(PmError::LocalChangeNotUsed)
    );
    let used = ParameterLoading::controlled(LocalChange::Used, CA, ORG);
    assert_eq!(used.announce(&normalized(0x2000)).unwrap(), frame);
}

#[test]
fn a_cause_the_types_own_figure_does_not_list_is_not_a_frame_of_this_procedure() {
    // `on_response` accepts only the causes of figures 79-82's lists, through
    // `Family::is_monitor_cause`, the same list the mirror builder checks on
    // the way out. Figure 82 prints no `<3>` for `P_AC_NA_1` (the
    // `P_ME SPONT` announcement is a `P_ME` service), and figures 79-81 print
    // no `<9>`; both are `Reaction::Other`, not a frame of another shape.
    let controlling = ParameterLoading::controlling(LocalChange::Used, CA, ORG);
    let activation_qpa_3 = activation_parameter(Qpa::PERSISTENT_CYCLIC);

    let mut activation_with_cause_3 = activation(&activation_qpa_3, CA, ORG).unwrap();
    activation_with_cause_3[2] = Cause::Spontaneous.to_u8();
    assert_eq!(
        mirror(&activation_qpa_3, Cause::Spontaneous, false, false, CA, ORG),
        Err(PmError::CauseNotDefined {
            type_id: TypeId::PAcNa1,
            cause: Cause::Spontaneous,
        }),
        "the builder refuses the frame the reception side must not name"
    );
    assert_eq!(
        controlling
            .on_response(&activation_with_cause_3, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );

    let mut load_with_cause_9 = announcement(&normalized(0x2000), CA, ORG).unwrap();
    load_with_cause_9[2] = Cause::DeactivationCon.to_u8();
    assert_eq!(
        controlling
            .on_response(&load_with_cause_9, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other,
        "figures 79-81 list no <9>: a P_ME cannot be deactivated"
    );

    // The cause the three types do carry is still the announcement.
    let spontaneous = announcement(&normalized(0x2000), CA, ORG).unwrap();
    assert!(matches!(
        controlling
            .on_response(&spontaneous, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Announced { .. }
    ));
}

#[test]
fn the_roles_are_separated() {
    let (controlling, controlled) = roles();
    let request = controlling.load(&normalized(0x2000)).unwrap();
    let parameter = activation_parameter(3);

    assert_eq!(
        controlling.on_request(&request, &Known::EVERYTHING),
        Err(PmError::WrongRole)
    );
    assert_eq!(
        controlled.on_response(&request, &Known::EVERYTHING),
        Err(PmError::WrongRole)
    );
    assert_eq!(
        controlled.load(&normalized(0x2000)),
        Err(PmError::WrongRole)
    );
    assert_eq!(controlled.activate(&parameter), Err(PmError::WrongRole));
    assert_eq!(controlled.deactivate(&parameter), Err(PmError::WrongRole));
    assert_eq!(
        controlling.announce(&normalized(0x2000)),
        Err(PmError::WrongRole)
    );
    assert_eq!(
        controlling.refuse(&request, &normalized(0x1000)),
        Err(PmError::WrongRole)
    );
}

#[test]
fn a_refused_load_must_be_the_requests_own_parameter() {
    let (controlling, controlled) = roles();
    let request = controlling.load(&normalized(0x2000)).unwrap();

    assert_eq!(
        controlled.refuse(&request, &scaled(0x1234)),
        Err(PmError::ValueTypeMismatch {
            expected: TypeId::PMeNa1,
            got: TypeId::PMeNb1,
        })
    );

    let elsewhere = Parameter::new(0x4002, normalized(0x1000).value);
    assert_eq!(
        controlled.refuse(&request, &elsewhere),
        Err(PmError::IoaMismatch {
            expected: IOA,
            got: 0x4002,
        })
    );

    // A deactivation of P_AC_NA_1 is *not* an error (figure 82 lists
    // `<8>`/`<9>`); its own refusal is pinned by
    // `a_refused_deactivation_answers_cause_9_with_the_flag`. The three `P_ME`
    // types have no `<8>`, so a deactivation of one is an error.

    // And so is an ASDU that is not a parameter ASDU at all.
    assert_eq!(
        controlled.refuse(&MONITOR_FRAME, &normalized(0x2000)),
        Err(PmError::NotAParameter {
            type_id: TypeId::MSpNa1,
        })
    );
    let empty = [0x6E, 0x00, 0x06, 0x07, 0x0C, 0x00];
    assert_eq!(
        controlled.refuse(&empty, &normalized(0x2000)),
        Err(PmError::NotAParameter {
            type_id: TypeId::PMeNa1,
        })
    );
}

#[test]
fn the_instances_report_their_own_address_and_selection() {
    let controlling = ParameterLoading::controlling(LocalChange::Used, CA, ORG);
    assert_eq!(controlling.role(), Role::Controlling);
    assert_eq!(controlling.local_change(), LocalChange::Used);
    assert_eq!(controlling.addressing(), (CA, ORG));
    let controlled = ParameterLoading::controlled(LocalChange::NotUsed, 1, 0);
    assert_eq!(controlled.role(), Role::Controlled);
    assert_eq!(controlled.local_change(), LocalChange::NotUsed);
    assert_eq!(controlled.addressing(), (1, 0));
}

// ------------------------------------------------------- refusals and discards

#[test]
fn a_parameter_addressed_to_the_broadcast_address_is_refused_with_cause_46() {
    let (_, controlled) = roles();
    let request = load(&normalized(0x2000), BROADCAST_CA, ORG).unwrap();
    // TS 60870-5-604 5.4.10.10: the broadcast CASDU is used only with types
    // 100/101/103/105, so "all other ASDU Types" are mirrored with P/N = 1,
    // whatever the caller's Known says.
    let outcome = controlled.on_request(&request, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: Cause::UnknownCommonAddress,
        }
    );
    let header = Header::parse(&outcome.send[0]).unwrap();
    assert_eq!(header.cause, Cause::UnknownCommonAddress);
    assert!(header.negative);
    assert_eq!(header.originator, ORG);
    assert_eq!(
        header.common_address, CA,
        "the answer carries the answering station's own address"
    );
    assert_eq!(outcome.send[0][Header::LEN..], request[Header::LEN..]);
}

#[test]
fn every_unknown_field_class_is_mirrored_with_its_own_cause_on_the_controlled_side() {
    let (_, controlled) = roles();
    let request = load(&normalized(0x2000), CA, ORG).unwrap();
    let cases = [
        (
            Known {
                type_id: false,
                ..Known::EVERYTHING
            },
            Cause::UnknownTypeId,
        ),
        (
            Known {
                cause: false,
                ..Known::EVERYTHING
            },
            Cause::UnknownCause,
        ),
        (
            Known {
                common_address: false,
                ..Known::EVERYTHING
            },
            Cause::UnknownCommonAddress,
        ),
        (
            Known {
                information_object_address: false,
                ..Known::EVERYTHING
            },
            Cause::UnknownInformationObjectAddress,
        ),
    ];
    assert_eq!(cases.len(), 4);
    for (known, cause) in cases {
        let outcome = controlled.on_request(&request, &known).unwrap();
        assert_eq!(outcome.reaction, Reaction::Refused { ioa: IOA, cause });
        let header = Header::parse(&outcome.send[0]).unwrap();
        assert_eq!(header.cause, cause, "the clause's own report order");
        assert!(header.negative);
        assert_eq!(header.originator, ORG);
        assert_eq!(header.common_address, CA);
        assert_eq!(outcome.send[0][Header::LEN..], request[Header::LEN..]);
    }
}

#[test]
fn the_discard_rule_runs_first_on_the_controlling_side() {
    let (controlling, _) = roles();
    let outcome = controlling
        .on_response(&MONITOR_FRAME, &Known::NOTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Discard(Discard::Unspecified(Unspecified::TypeIdentification))
    );
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);

    // The same frame at a station that knows every field is simply not ours.
    let outcome = controlling
        .on_response(&MONITOR_FRAME, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(outcome.reaction, Reaction::Other);
}

#[test]
fn a_mirror_from_the_peer_is_never_mirrored_back() {
    let (controlling, controlled) = roles();
    let reply = unknown_reply(
        &normalized(0x2000),
        Unspecified::TypeIdentification,
        CA,
        ORG,
        false,
    )
    .unwrap();

    let outcome = controlled.on_request(&reply, &Known::EVERYTHING).unwrap();
    assert_eq!(outcome.reaction, Reaction::Discard(Discard::Mirror));
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);

    // On the controlling side the mirror is the peer's refusal of the load.
    let outcome = controlling.on_response(&reply, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: Cause::UnknownTypeId,
        }
    );
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
}

/// The outstation does not know parameter 0x4001 and mirrors the load with
/// cause 47 (5-101 cl.7.2.3): the controlling station reports the refusal.
#[test]
fn a_cause_47_mirror_of_a_load_is_refused_with_its_address() {
    let (controlling, _) = roles();
    let reply = unknown_reply(
        &normalized(0x2000),
        Unspecified::InformationObjectAddress,
        CA,
        ORG,
        false,
    )
    .unwrap();

    let outcome = controlling.on_response(&reply, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x4001,
            cause: Cause::UnknownInformationObjectAddress,
        }
    );
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
}

#[test]
fn every_short_prefix_of_every_frame_is_a_typed_error() {
    let (controlling, controlled) = roles();
    for frame in every_frame() {
        for len in 0..frame.len() {
            let prefix = &frame[..len];
            assert!(
                controlled.on_request(prefix, &Known::EVERYTHING).is_err(),
                "on_request swallowed {} octets of {frame:?}",
                prefix.len()
            );
            assert!(
                controlling.on_response(prefix, &Known::EVERYTHING).is_err(),
                "on_response swallowed {} octets of {frame:?}",
                prefix.len()
            );
        }
    }
}

#[test]
fn a_mirror_is_never_a_parameter_this_station_answers() {
    // The 44–47 mirror of a parameter carries P/N = 1 and one of the four
    // causes; a built positive confirmation is never mistaken for one.
    let answer = confirmation(&normalized(0x2000), false, CA, ORG, false).unwrap();
    let header = Header::parse(&answer).unwrap();
    assert!(!header.negative);
    assert_eq!(header.cause, CAUSE_ACTIVATION_CON);
}
