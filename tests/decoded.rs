//! `asdu::decode`: one entry point for every laid-out type identification.
//!
//! The frames come from Beckhoff's published samples ("IEC 60870-5-104
//! telegram structure", TF6500, the same source as `tests/wire_vectors.rs`)
//! and from the element layouts of 5-101 clause 7.3 written out by hand. The
//! type identification numbers are 5-101 tables 8 to 13 and 5-104 clause 8.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used)]

use iec104::asdu::{
    self, AddressSizes, CATALOGUE, Cause, Cp24Time2a, Cp56Time2a, DoublePointState, EventState,
    Header, LayoutError, Objects, Oci, Point, Quality, Spe, TimeTag, TypeId, Validity, Value,
    layout_for,
};

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
        .collect()
}

/// Beckhoff sample 2 without its six-octet APCI: `M_ME_NB_1`, seven objects,
/// spontaneous, CA 12. Each object is a three-octet address, a two-octet
/// scaled value and a `QDS` of zero (5-101 cl.7.3.1.11).
#[test]
fn beckhoff_scaled_values_decode_to_their_variant() {
    let frame = hex("0B 07 03 00 0C 00 10 30 00 BE 09 00 11 30 00 90 09 00 \
         0E 30 00 75 00 00 28 30 00 25 09 00 29 30 00 75 00 00 0F 30 00 0F 0A 00 \
         2E 30 00 AE 05 00");
    let asdu = asdu::decode(&frame).unwrap();
    assert_eq!(asdu.header.type_id, TypeId::MMeNb1);
    assert_eq!(asdu.header.cause, Cause::Spontaneous);
    assert_eq!(asdu.header.common_address, 12);
    assert_eq!(asdu.objects.type_id(), TypeId::MMeNb1);
    assert_eq!(asdu.objects.len(), 7);
    let Objects::MMeNb1(objects) = &asdu.objects else {
        panic!("wrong variant: {:?}", asdu.objects.type_id());
    };
    let read: Vec<(u32, i16)> = objects.iter().map(|o| (o.ioa, o.value.sva.value)).collect();
    assert_eq!(
        read,
        [
            (0x3010, 0x09BE),
            (0x3011, 0x0990),
            (0x300E, 0x0075),
            (0x3028, 0x0925),
            (0x3029, 0x0075),
            (0x300F, 0x0A0F),
            (0x302E, 0x05AE),
        ]
    );
    assert!(objects.iter().all(|o| o.value.qds.raw() == 0));
    assert_eq!(asdu.encode().unwrap(), frame);
}

/// Beckhoff sample 1 without its APCI: `C_CI_NA_1`, activation termination,
/// CA 12, address 0 and `QCC` `<5>` (5-101 cl.7.3.4.2, cl.7.2.6.23: `RQT`
/// `<5>` general request counter).
#[test]
fn beckhoff_counter_interrogation_decodes_to_its_variant() {
    let frame = hex("65 01 0A 00 0C 00 00 00 00 05");
    let asdu = asdu::decode(&frame).unwrap();
    assert_eq!(asdu.header.cause, Cause::ActivationTermination);
    let Objects::CCiNa1(objects) = &asdu.objects else {
        panic!("wrong variant: {:?}", asdu.objects.type_id());
    };
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].ioa, 0);
    assert_eq!(objects[0].value.qcc.raw(), 0x05);
    assert_eq!(asdu.encode().unwrap(), frame);
}

/// Every type identification of the catalogue that has a layout reaches its
/// own variant. The frame is a header with no information object (5-101
/// cl.7.2.2's number of objects `<0>`), except `F_DR_TA_1` `<126>`, whose
/// figure 89 defines only the sequence form, so its `SQ` is set. `F_SG_NA_1`
/// `<125>` is left out: a segment ASDU without its object has nothing to read.
#[test]
fn every_laid_out_type_reaches_its_own_variant() {
    let mut reached = 0;
    for info in CATALOGUE {
        let type_id = TypeId::from_u8(info.id);
        if layout_for(type_id).is_none() || info.id == 125 {
            continue;
        }
        let vsq = if info.id == 126 { 0x80 } else { 0x00 };
        let frame = [info.id, vsq, 0x03, 0x00, 0x0C, 0x00];
        let asdu = asdu::decode(&frame).unwrap_or_else(|e| panic!("{}: {e:?}", info.name));
        assert_eq!(asdu.objects.type_id(), type_id, "{}", info.name);
        assert!(asdu.objects.is_empty(), "{}", info.name);
        reached += 1;
    }
    // 67 laid-out types less the segment.
    assert_eq!(reached, 66);
}

/// `F_SG_NA_1` `<125>` (5-101 cl.7.3.6.6, figure 88): `NOF` (two octets),
/// `NOS` (one), `LOS` (one), then `LOS` octets of the segment. Cause `<13>`
/// file transfer.
#[test]
fn a_segment_decodes_with_its_payload() {
    let frame = hex("7D 01 0D 00 0C 00 01 00 00 02 00 01 03 AA BB CC");
    let asdu = asdu::decode(&frame).unwrap();
    let Objects::FSgNa1(object) = &asdu.objects else {
        panic!("wrong variant: {:?}", asdu.objects.type_id());
    };
    assert_eq!(object.ioa, 1);
    assert_eq!(object.value.nof.value, 2);
    assert_eq!(object.value.nos.value, 1);
    assert_eq!(object.value.los.value, 3);
    assert_eq!(object.value.payload, [0xAA, 0xBB, 0xCC]);
    assert_eq!(asdu.objects.len(), 1);
    assert_eq!(asdu.encode().unwrap(), frame);
}

/// A type identification with no layout, reserved (`<22>`, 5-101 table 8's
/// `<22..29>`) or private (`<200>`, `<136..255>`), is refused by name.
#[test]
fn a_type_without_a_layout_is_no_layout() {
    for id in [22, 200] {
        let frame = [id, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            asdu::decode(&frame),
            Err(LayoutError::NoLayout {
                type_id: TypeId::Other(id)
            })
        );
    }
}

/// The addressing rules of clause 7.3 hold here as in `decode_asdu`:
/// `M_EP_TD_1` `<38>` has its own time tag per object and no sequence form
/// (5-101 cl.7.3.1.30).
#[test]
fn the_clause_7_3_rules_still_apply() {
    let frame = [38, 0x81, 0x03, 0x00, 0x0C, 0x00];
    assert_eq!(
        asdu::decode(&frame),
        Err(LayoutError::SequenceNotAllowed {
            type_id: TypeId::MEpTd1
        })
    );
}

/// The address sizes of the profile apply (5-101 cl.7.2.3 to 7.2.5): no
/// originator, a one-octet common address and a two-octet object address.
/// `M_SP_NA_1` `<1>`, spontaneous, CA 5, address 0x0102, `SIQ` ON (bit 1,
/// cl.7.2.6.1).
#[test]
fn a_narrow_profile_decodes() {
    let sizes = AddressSizes::new(1, 2, false).unwrap();
    let frame = [0x01, 0x01, 0x03, 0x05, 0x02, 0x01, 0x01];
    let asdu = asdu::decode_with(&frame, sizes).unwrap();
    assert_eq!(asdu.header.common_address, 5);
    let Objects::MSpNa1(objects) = &asdu.objects else {
        panic!("wrong variant: {:?}", asdu.objects.type_id());
    };
    assert_eq!(objects[0].ioa, 0x0102);
    assert!(objects[0].value.siq.spi);
    assert_eq!(asdu.encode_with(sizes).unwrap(), frame);
}

/// A header whose type identification disagrees with the objects is refused
/// on the way out rather than written with the wrong layout.
#[test]
fn encode_refuses_a_header_of_another_type() {
    let frame = hex("65 01 0A 00 0C 00 00 00 00 05");
    let mut asdu = asdu::decode(&frame).unwrap();
    asdu.header = Header {
        type_id: TypeId::CIcNa1,
        ..asdu.header
    };
    assert_eq!(
        asdu.encode(),
        Err(LayoutError::TypeMismatch {
            expected: TypeId::CCiNa1,
            got: TypeId::CIcNa1
        })
    );
}

// ------------------------------------------------------------------ validity

/// `CP56Time2a` 2026-09-28 12:34:56.789 (5-101 cl.7.2.6.18), with the minutes
/// octet's bit 8, `IV`, set when `invalid`.
const fn cp56(invalid: bool) -> [u8; 7] {
    [
        0xD5,
        0xDD,
        0x22 | if invalid { 0x80 } else { 0 },
        12,
        0x20 | 0x1C,
        9,
        26,
    ]
}

/// `M_ME_TF_1` `<36>` (5-101 cl.7.3.1.28): a short float with its `QDS`
/// (cl.7.2.6.3, `IV` bit 8) and a `CP56Time2a`. The two invalid bits are
/// independent: every combination reads back as sent.
#[test]
fn validity_reads_the_value_and_the_time_tag_apart() {
    for (value_invalid, time_invalid) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let mut frame = vec![36, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x10, 0x30, 0x00];
        frame.extend([0x00, 0x00, 0xC0, 0x3F]);
        frame.push(if value_invalid { 0x80 } else { 0x00 });
        frame.extend(cp56(time_invalid));
        let asdu = asdu::decode(&frame).unwrap();
        assert_eq!(
            asdu.objects.validity(),
            [Validity {
                ioa: 0x3010,
                invalid: Some(value_invalid),
                time_invalid: Some(time_invalid),
            }]
        );
    }
}

/// Each object of an ASDU keeps its own flags. `M_SP_NA_1` `<1>` (5-101
/// cl.7.3.1.1): `SIQ` with `IV` in bit 8 (cl.7.2.6.1), no time tag.
#[test]
fn validity_is_per_object() {
    let frame = [
        1, 0x02, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x81,
    ];
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.validity(),
        [
            Validity {
                ioa: 1,
                invalid: Some(false),
                time_invalid: None
            },
            Validity {
                ioa: 2,
                invalid: Some(true),
                time_invalid: None
            },
        ]
    );
}

/// `M_SP_TA_1` `<2>` (5-101 cl.7.3.1.2) carries a `CP24Time2a`, the first
/// three octets of `CP56Time2a` with the same `IV` bit (cl.7.2.6.19).
#[test]
fn validity_reads_the_three_octet_time_tag() {
    let frame = [
        2,
        0x01,
        0x03,
        0x00,
        0x0C,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0xD5,
        0xDD,
        0x80 | 0x22,
    ];
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.validity(),
        [Validity {
            ioa: 1,
            invalid: Some(false),
            time_invalid: Some(true)
        }]
    );
}

/// `M_ME_ND_1` `<21>` (5-101 cl.7.3.1.21) is a normalized value *"without
/// quality descriptor"*: there is no `IV` to read.
#[test]
fn a_type_without_a_quality_descriptor_has_no_invalid_flag() {
    let frame = [
        21, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40,
    ];
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.validity(),
        [Validity {
            ioa: 1,
            invalid: None,
            time_invalid: None
        }]
    );
}

/// A time-tagged command, `C_SC_TA_1` `<58>` (5-104 cl.8.1), has a time tag
/// and no quality descriptor.
#[test]
fn a_time_tagged_command_has_only_the_time_flag() {
    let mut frame = vec![58, 0x01, 0x06, 0x00, 0x0C, 0x00, 0xA1, 0x0F, 0x00, 0x01];
    frame.extend(cp56(true));
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.validity(),
        [Validity {
            ioa: 4001,
            invalid: None,
            time_invalid: Some(true)
        }]
    );
}

/// Protection events: `M_EP_TD_1` `<38>` (5-101 cl.7.3.1.30) reads `IV` from
/// its `SEP` (cl.7.2.6.10) and `M_EP_TE_1` `<39>` (cl.7.3.1.31) from its `QDP`
/// (cl.7.2.6.4), bit 8 in both.
#[test]
fn protection_events_read_iv_from_their_own_descriptor() {
    let mut sep = vec![
        38, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x81, 0x00, 0x00,
    ];
    sep.extend(cp56(false));
    assert_eq!(
        asdu::decode(&sep).unwrap().objects.validity()[0].invalid,
        Some(true)
    );
    let mut qdp = vec![
        39, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00,
    ];
    qdp.extend(cp56(true));
    assert_eq!(
        asdu::decode(&qdp).unwrap().objects.validity(),
        [Validity {
            ioa: 1,
            invalid: Some(true),
            time_invalid: Some(true)
        }]
    );
}

/// Integrated totals carry `IV` in the `BCR` (5-101 cl.7.2.6.9, bit 8 of the
/// fifth octet). `M_IT_TB_1` `<37>` (cl.7.3.1.29).
#[test]
fn integrated_totals_read_iv_from_the_counter_reading() {
    let mut frame = vec![37, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00];
    frame.extend([0x05, 0x00, 0x00, 0x00, 0x80]);
    frame.extend(cp56(false));
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.validity(),
        [Validity {
            ioa: 1,
            invalid: Some(true),
            time_invalid: Some(false)
        }]
    );
}

// -------------------------------------------------------------------- points
//
// Every frame below is written out by hand from the layout of its type (5-101
// cl.7.3.1.x) and the bit layout of each element (cl.7.2.6.x). The header is
// the same throughout: the type identification, a variable structure qualifier
// of one object (cl.7.2.2), cause `<3>` spontaneous with originator 0
// (cl.7.2.3), common address 12 (cl.7.2.4); then a three-octet information
// object address (cl.7.2.5).

/// Header and address of a one-object ASDU of type `type_id`, IOA 0x3010.
fn one_object(type_id: u8) -> Vec<u8> {
    vec![type_id, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x10, 0x30, 0x00]
}

/// The `CP56Time2a` that `cp56(false)` writes: 2026-09-28 12:34:56.789, a
/// Monday (day of week `<1>`, cl.7.2.6.18), genuine and valid.
const fn cp56_expected() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 56_789,
        minutes: 34,
        substituted: false,
        invalid: false,
        hours: 12,
        summer_time: false,
        day_of_month: 28,
        day_of_week: 1,
        months: 9,
        years: 26,
    }
}

/// `CP24Time2a` (cl.7.2.6.19), the first three octets of `cp56`: 56 789 ms
/// (`D5 DD`) and minute 34 with `IV` (bit 8) set.
const CP24_INVALID: [u8; 3] = [0xD5, 0xDD, 0x80 | 0x22];

const fn cp24_invalid_expected() -> TimeTag {
    TimeTag::Cp24(Cp24Time2a {
        milliseconds: 56_789,
        minutes: 34,
        substituted: false,
        invalid: true,
    })
}

/// A `QDS` quality (cl.7.2.6.3) with every bit clear, `OV` included.
const QDS_GOOD: Quality = Quality {
    invalid: false,
    not_topical: false,
    substituted: false,
    blocked: false,
    overflow: Some(false),
};

/// A quality from an element without `OV` (`SIQ`, `DIQ`, `QDP`, `SEP`,
/// `BCR`) with every bit clear.
const NO_OV_GOOD: Quality = Quality {
    invalid: false,
    not_topical: false,
    substituted: false,
    blocked: false,
    overflow: None,
};

/// Single points, `M_SP_NA_1` `<1>` (cl.7.3.1.1), two objects. `SIQ`
/// (cl.7.2.6.1): `SPI` is bit 1, then `BL` bit 5, `SB` bit 6, `NT` bit 7, `IV`
/// bit 8. `0x01` is ON with a good quality; `0xF0` is OFF with all four bits
/// set. `SIQ` has no `OV`.
#[test]
fn points_read_single_points() {
    let frame = [
        1, 0x02, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0xF0,
    ];
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [
            Point {
                ioa: 1,
                value: Value::Single(true),
                quality: Some(NO_OV_GOOD),
                time: None,
            },
            Point {
                ioa: 2,
                value: Value::Single(false),
                quality: Some(Quality {
                    invalid: true,
                    not_topical: true,
                    substituted: true,
                    blocked: true,
                    overflow: None,
                }),
                time: None,
            },
        ]
    );
}

/// A double point with a seven-octet time tag, `M_DP_TB_1` `<31>`
/// (cl.7.3.1.23): `DIQ` (cl.7.2.6.2) `0x02` is `DPI` `<2>` "determined state
/// ON", then the `CP56Time2a`.
#[test]
fn points_read_double_points_and_their_seven_octet_time() {
    let mut frame = one_object(31);
    frame.push(0x02);
    frame.extend(cp56(false));
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::Double(DoublePointState::On),
            quality: Some(NO_OV_GOOD),
            time: Some(TimeTag::Cp56(cp56_expected())),
        }]
    );
}

/// Step position, `M_ST_NA_1` `<5>` (cl.7.3.1.5): `VTI` (cl.7.2.6.5) `0xFF`
/// is `Value := I7[1..7]` all ones (two's complement -1) with `Transient`
/// (bit 8) set, then a `QDS` (cl.7.2.6.3) `0x01`, `OV` set.
#[test]
fn points_read_a_step_position() {
    let mut frame = one_object(5);
    frame.extend([0xFF, 0x01]);
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::StepPosition {
                value: -1,
                transient: true,
            },
            quality: Some(Quality {
                overflow: Some(true),
                ..QDS_GOOD
            }),
            time: None,
        }]
    );
}

/// Bitstring, `M_BO_NA_1` `<7>` (cl.7.3.1.7): `BSI` (cl.7.2.6.13) is 32 bits
/// least significant octet first, so `01 00 00 80` sets bit 1 and bit 32,
/// then a good `QDS`.
#[test]
fn points_read_a_bitstring() {
    let mut frame = one_object(7);
    frame.extend([0x01, 0x00, 0x00, 0x80, 0x00]);
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::Bitstring(0x8000_0001),
            quality: Some(QDS_GOOD),
            time: None,
        }]
    );
}

/// Normalized values, `M_ME_NA_1` `<9>` (cl.7.3.1.9): `NVA` (cl.7.2.6.6) is
/// `F16[1..16]<-1..+1-2^-15>`, so `00 40` (0x4000) is 0.5 and `00 80`
/// (0x8000) is -1; the second object's `QDS` has `IV`. `M_ME_ND_1` `<21>`
/// (cl.7.3.1.21) is the same value *"without quality descriptor"*, so its
/// quality is `None`.
#[test]
fn points_read_normalized_values_with_and_without_quality() {
    let frame = [
        9, 0x02, 0x03, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x80, 0x80,
    ];
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [
            Point {
                ioa: 1,
                value: Value::Normalized(0.5),
                quality: Some(QDS_GOOD),
                time: None,
            },
            Point {
                ioa: 2,
                value: Value::Normalized(-1.0),
                quality: Some(Quality {
                    invalid: true,
                    ..QDS_GOOD
                }),
                time: None,
            },
        ]
    );
    let mut frame = one_object(21);
    frame.extend([0x00, 0x40]);
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::Normalized(0.5),
            quality: None,
            time: None,
        }]
    );
}

/// A scaled value with a three-octet time tag, `M_ME_TB_1` `<12>`
/// (cl.7.3.1.12): `SVA` (cl.7.2.6.7) `18 FC` is 0xFC18, -1000 in two's
/// complement; a good `QDS`; then `CP24Time2a` with `IV` set.
#[test]
fn points_read_a_scaled_value_and_its_three_octet_time() {
    let mut frame = one_object(12);
    frame.extend([0x18, 0xFC, 0x00]);
    frame.extend(CP24_INVALID);
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::Scaled(-1000),
            quality: Some(QDS_GOOD),
            time: Some(cp24_invalid_expected()),
        }]
    );
}

/// A short float, `M_ME_TF_1` `<36>` (cl.7.3.1.28): `R32-IEEE STD 754`
/// (cl.7.2.6.8) -2.5 is 0xC0200000 (sign 1, exponent 128, fraction 0.25),
/// written `00 00 20 C0`; `QDS` `0x40` is `NT`; then a `CP56Time2a`.
#[test]
fn points_read_a_short_float() {
    let mut frame = one_object(36);
    frame.extend([0x00, 0x00, 0x20, 0xC0, 0x40]);
    frame.extend(cp56(false));
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::Float(-2.5),
            quality: Some(Quality {
                not_topical: true,
                ..QDS_GOOD
            }),
            time: Some(TimeTag::Cp56(cp56_expected())),
        }]
    );
}

/// Integrated totals, `M_IT_NA_1` `<15>` (cl.7.3.1.15): `BCR` (cl.7.2.6.9)
/// is an `I32` reading, 100 000 = 0x000186A0 written `A0 86 01 00`, then
/// `SQ` in bits 1 to 5 (5), `CY` bit 6 set, `CA` bit 7 clear, `IV` bit 8
/// set: `0xA5`. The reading's only quality bit is `IV`.
#[test]
fn points_read_a_counter_reading() {
    let mut frame = one_object(15);
    frame.extend([0xA0, 0x86, 0x01, 0x00, 0xA5]);
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::Counter {
                reading: 100_000,
                sequence: 5,
                carry: true,
                adjusted: false,
            },
            quality: Some(Quality {
                invalid: true,
                ..NO_OV_GOOD
            }),
            time: None,
        }]
    );
}

/// A protection event, `M_EP_TA_1` `<17>` (cl.7.3.1.17): `SEP`
/// (cl.7.2.6.10) `0x0A` is `ES` `<2>` ON with `EI` (bit 4) set; the elapsed
/// time `CP16Time2a` (cl.7.2.6.20) `FA 00` is 250 ms; then `CP24Time2a`.
#[test]
fn points_read_a_protection_event() {
    let mut frame = one_object(17);
    frame.extend([0x0A, 0xFA, 0x00]);
    frame.extend(CP24_INVALID);
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::ProtectionEvent {
                state: EventState::On,
                elapsed_ms: 250,
                elapsed_invalid: true,
            },
            quality: Some(NO_OV_GOOD),
            time: Some(cp24_invalid_expected()),
        }]
    );
}

/// Packed start events, `M_EP_TE_1` `<39>` (cl.7.3.1.31): `SPE`
/// (cl.7.2.6.11) `0x03` is `GS` and `SL1`; `QDP` (cl.7.2.6.4) `0x18` is `EI`
/// (bit 4) and `BL` (bit 5); the relay duration time `E8 03` is 1000 ms; then
/// a `CP56Time2a`.
#[test]
fn points_read_packed_start_events() {
    let mut frame = one_object(39);
    frame.extend([0x03, 0x18, 0xE8, 0x03]);
    frame.extend(cp56(false));
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::ProtectionStart {
                start: Spe {
                    general_start: true,
                    start_l1: true,
                    ..Spe::default()
                },
                elapsed_ms: 1000,
                elapsed_invalid: true,
            },
            quality: Some(Quality {
                blocked: true,
                ..NO_OV_GOOD
            }),
            time: Some(TimeTag::Cp56(cp56_expected())),
        }]
    );
}

/// Packed output circuit information, `M_EP_TC_1` `<19>` (cl.7.3.1.19):
/// `OCI` (cl.7.2.6.12) `0x09` is `GC` and `CL3`; `QDP` (cl.7.2.6.4) `0x20` is
/// `SB`, `EI` clear; the relay operating time `64 00` is 100 ms; then
/// `CP24Time2a`.
#[test]
fn points_read_packed_output_circuit_information() {
    let mut frame = one_object(19);
    frame.extend([0x09, 0x20, 0x64, 0x00]);
    frame.extend(CP24_INVALID);
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::ProtectionCommand {
                command: Oci {
                    general_command: true,
                    command_l3: true,
                    ..Oci::default()
                },
                elapsed_ms: 100,
                elapsed_invalid: false,
            },
            quality: Some(Quality {
                substituted: true,
                ..NO_OV_GOOD
            }),
            time: Some(cp24_invalid_expected()),
        }]
    );
}

/// Packed single points, `M_PS_NA_1` `<20>` (cl.7.3.1.20): `SCD`
/// (cl.7.2.6.40) is `ST` in the first two octets and `CD` in the next two,
/// least significant first: `05 00 04 00` is states 1 and 3 ON and a change
/// on 3. Then a good `QDS`.
#[test]
fn points_read_packed_single_points() {
    let mut frame = one_object(20);
    frame.extend([0x05, 0x00, 0x04, 0x00, 0x00]);
    assert_eq!(
        asdu::decode(&frame).unwrap().objects.points(),
        [Point {
            ioa: 0x3010,
            value: Value::PackedSingle {
                status: 0x0005,
                change: 0x0004,
            },
            quality: Some(QDS_GOOD),
            time: None,
        }]
    );
}

/// What each monitor type yields, one object of all-zero elements per type.
/// The element lengths and the presence of a quality and a time tag come from
/// each type's definition line in 5-101 cl.7.3.1.1 to 7.3.1.32 (element
/// octets: `SIQ`, `DIQ`, `QDS`, `QDP`, `VTI`, `SEP`, `SPE`, `OCI` 1; `NVA`,
/// `SVA`, `CP16Time2a` 2; `CP24Time2a` 3; `BSI`, `R32`, `SCD` 4; `BCR` 5;
/// `CP56Time2a` 7). The table lists the 32 monitor types of 5-101 table 8.
#[test]
fn points_cover_every_monitor_type() {
    #[derive(Debug, PartialEq)]
    enum Kind {
        Single,
        Double,
        Step,
        Bits,
        Normalized,
        Scaled,
        Float,
        Counter,
        Event,
        Start,
        Command,
        Packed,
    }
    #[derive(Debug, PartialEq)]
    enum Time {
        None,
        Cp24,
        Cp56,
    }
    use Kind::*;
    // (type, element octets, value kind, has a quality, time tag)
    let table = [
        (1, 1, Single, true, Time::None),
        (2, 1 + 3, Single, true, Time::Cp24),
        (3, 1, Double, true, Time::None),
        (4, 1 + 3, Double, true, Time::Cp24),
        (5, 1 + 1, Step, true, Time::None),
        (6, 1 + 1 + 3, Step, true, Time::Cp24),
        (7, 4 + 1, Bits, true, Time::None),
        (8, 4 + 1 + 3, Bits, true, Time::Cp24),
        (9, 2 + 1, Normalized, true, Time::None),
        (10, 2 + 1 + 3, Normalized, true, Time::Cp24),
        (11, 2 + 1, Scaled, true, Time::None),
        (12, 2 + 1 + 3, Scaled, true, Time::Cp24),
        (13, 4 + 1, Float, true, Time::None),
        (14, 4 + 1 + 3, Float, true, Time::Cp24),
        (15, 5, Counter, true, Time::None),
        (16, 5 + 3, Counter, true, Time::Cp24),
        (17, 1 + 2 + 3, Event, true, Time::Cp24),
        (18, 1 + 1 + 2 + 3, Start, true, Time::Cp24),
        (19, 1 + 1 + 2 + 3, Command, true, Time::Cp24),
        (20, 4 + 1, Packed, true, Time::None),
        (21, 2, Normalized, false, Time::None),
        (30, 1 + 7, Single, true, Time::Cp56),
        (31, 1 + 7, Double, true, Time::Cp56),
        (32, 1 + 1 + 7, Step, true, Time::Cp56),
        (33, 4 + 1 + 7, Bits, true, Time::Cp56),
        (34, 2 + 1 + 7, Normalized, true, Time::Cp56),
        (35, 2 + 1 + 7, Scaled, true, Time::Cp56),
        (36, 4 + 1 + 7, Float, true, Time::Cp56),
        (37, 5 + 7, Counter, true, Time::Cp56),
        (38, 1 + 2 + 7, Event, true, Time::Cp56),
        (39, 1 + 1 + 2 + 7, Start, true, Time::Cp56),
        (40, 1 + 1 + 2 + 7, Command, true, Time::Cp56),
    ];
    assert_eq!(table.len(), 32);
    for (type_id, octets, kind, quality, time) in table {
        let mut frame = one_object(type_id);
        frame.extend(std::iter::repeat_n(0, octets));
        let asdu = asdu::decode(&frame).unwrap_or_else(|e| panic!("<{type_id}>: {e:?}"));
        let points = asdu.objects.points();
        assert_eq!(points.len(), 1, "<{type_id}>");
        let point = points[0];
        assert_eq!(point.ioa, 0x3010, "<{type_id}>");
        let got = match point.value {
            Value::Single(_) => Single,
            Value::Double(_) => Double,
            Value::StepPosition { .. } => Step,
            Value::Bitstring(_) => Bits,
            Value::Normalized(_) => Normalized,
            Value::Scaled(_) => Scaled,
            Value::Float(_) => Float,
            Value::Counter { .. } => Counter,
            Value::ProtectionEvent { .. } => Event,
            Value::ProtectionStart { .. } => Start,
            Value::ProtectionCommand { .. } => Command,
            Value::PackedSingle { .. } => Packed,
        };
        assert_eq!(got, kind, "<{type_id}>");
        assert_eq!(point.quality.is_some(), quality, "<{type_id}>");
        let got = match point.time {
            None => Time::None,
            Some(TimeTag::Cp24(_)) => Time::Cp24,
            Some(TimeTag::Cp56(_)) => Time::Cp56,
        };
        assert_eq!(got, time, "<{type_id}>");
    }
}

/// Only process information yields points. A single command `C_SC_NA_1`
/// `<45>` (5-101 cl.7.3.2.1, `SCO` `0x01`), its time-tagged form `C_SC_TA_1`
/// `<58>` (5-104 cl.8.1), end of initialisation `M_EI_NA_1` `<70>` (5-101
/// cl.7.3.3.1, `COI` `0x00`) and a station interrogation `C_IC_NA_1` `<100>`
/// (cl.7.3.4.1, `QOI` `<20>`) carry none.
#[test]
fn points_skip_commands_system_and_interrogation_types() {
    let mut time_tagged = vec![58, 0x01, 0x06, 0x00, 0x0C, 0x00, 0xA1, 0x0F, 0x00, 0x01];
    time_tagged.extend(cp56(false));
    for frame in [
        vec![45, 0x01, 0x06, 0x00, 0x0C, 0x00, 0xA1, 0x0F, 0x00, 0x01],
        time_tagged,
        vec![70, 0x01, 0x04, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00],
        vec![100, 0x01, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 20],
    ] {
        let asdu = asdu::decode(&frame).unwrap();
        assert_eq!(asdu.objects.len(), 1);
        assert!(
            asdu.objects.points().is_empty(),
            "{:?}",
            asdu.header.type_id
        );
    }
}
