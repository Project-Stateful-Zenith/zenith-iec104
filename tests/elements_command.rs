//! Command information elements: IEC 60870-5-101:2003 clause 7.2.6.15–7.2.6.17,
//! 7.2.6.26 and 7.2.6.39.
//!
//! Every type here is one octet. Bit numbers are 1-based from the least
//! significant bit, so `QOC`'s `QU := UI5[3..7]` is `0x7C` and `S/E := BS1[8]`
//! is `0x80`.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use iec104::asdu::elements::RegulatingStepState;
use iec104::asdu::{AsduError, CommandQualifier, Dco, DoubleCommandState, Qoc, Qos, Rco, Sco};

fn assert_too_short<T, F>(parse: F, encoded: &[u8])
where
    T: std::fmt::Debug,
    F: Fn(&[u8]) -> Result<T, AsduError>,
{
    let need = encoded.len();
    for have in 0..need {
        let err = parse(&encoded[..have]).expect_err("a prefix must not parse");
        assert_eq!(err, AsduError::TooShort { need, have });
    }
}

/// Clause 7.2.6.16: `DCS` maps `<0>`/`<1>`/`<2>`/`<3>` onto the four states.
#[test]
fn dcs_maps_both_not_permitted_values() {
    assert_eq!(
        DoubleCommandState::from_bits(0),
        DoubleCommandState::NotPermitted
    );
    assert_eq!(DoubleCommandState::from_bits(1), DoubleCommandState::Off);
    assert_eq!(DoubleCommandState::from_bits(2), DoubleCommandState::On);
    assert_eq!(
        DoubleCommandState::from_bits(3),
        DoubleCommandState::NotPermittedAlt
    );
    assert_eq!(DoubleCommandState::NotPermitted.to_bits(), 0);
    assert_eq!(DoubleCommandState::Off.to_bits(), 1);
    assert_eq!(DoubleCommandState::On.to_bits(), 2);
    assert_eq!(DoubleCommandState::NotPermittedAlt.to_bits(), 3);
}

/// Clause 7.2.6.17: `RCS` maps `<1>` to LOWER and `<2>` to HIGHER.
#[test]
fn rcs_maps_lower_and_higher() {
    assert_eq!(
        RegulatingStepState::from_bits(0),
        RegulatingStepState::NotPermitted
    );
    assert_eq!(
        RegulatingStepState::from_bits(1),
        RegulatingStepState::Lower
    );
    assert_eq!(
        RegulatingStepState::from_bits(2),
        RegulatingStepState::Higher
    );
    assert_eq!(
        RegulatingStepState::from_bits(3),
        RegulatingStepState::NotPermittedAlt
    );
    assert_eq!(RegulatingStepState::Lower.to_bits(), 1);
    assert_eq!(RegulatingStepState::Higher.to_bits(), 2);
}

/// Clause 7.2.6.26: `QOC` is one octet; `QU` is `UI5[3..7]` and `S/E` is bit 8.
#[test]
fn qoc_len_and_select_bit() {
    assert_eq!(Qoc::LEN, 1);
    let all_set = Qoc::from_raw(0xFF);
    assert_eq!(all_set.qu, 31);
    assert!(all_set.select);
    // Bits 1–2 belong to the command state and are written as zero.
    assert_eq!(all_set.raw(), 0xFC);
    assert_eq!(
        Qoc {
            qu: 3,
            select: true
        }
        .raw(),
        0x80 | 0x0C
    );
    assert!(
        !Qoc {
            qu: 0,
            select: false
        }
        .select
    );
    assert_eq!(
        Qoc {
            qu: 0,
            select: false
        }
        .raw(),
        0x00
    );
}

/// Clause 7.2.6.26: a fully populated `QOC` round-trips, and bits 1–2 stay zero.
#[test]
fn qoc_round_trip_clears_command_state_bits() {
    let qoc = Qoc {
        qu: 31,
        select: true,
    };
    let mut out = Vec::new();
    qoc.encode(&mut out);
    assert_eq!(out, vec![0xFC]);
    assert_eq!(Qoc::parse(&out).unwrap(), qoc);
    // Received command-state bits (1–2) are dropped, not stored.
    assert_eq!(Qoc::parse(&[0xFF]).unwrap().raw(), 0xFC);
    assert_too_short(Qoc::parse, &out);
}

/// Clause 7.2.6.26: the named `QU` values. `<0>` no additional definition,
/// `<1>` short pulse, `<2>` long pulse, `<3>` persistent output, `<4..8>`
/// compatible range, `<9..15>` other predefined functions, `<16..31>` private
/// range.
#[test]
fn qu_named_values_follow_the_clause() {
    assert_eq!(
        CommandQualifier::from_raw(0),
        CommandQualifier::NoAdditionalDefinition
    );
    assert_eq!(CommandQualifier::from_raw(1), CommandQualifier::ShortPulse);
    assert_eq!(CommandQualifier::from_raw(2), CommandQualifier::LongPulse);
    assert_eq!(
        CommandQualifier::from_raw(3),
        CommandQualifier::PersistentOutput
    );
    assert_eq!(CommandQualifier::from_raw(4), CommandQualifier::Reserved(4));
    assert_eq!(CommandQualifier::from_raw(8), CommandQualifier::Reserved(8));
    assert_eq!(
        CommandQualifier::from_raw(9),
        CommandQualifier::PredefinedFunction(9)
    );
    assert_eq!(
        CommandQualifier::from_raw(15),
        CommandQualifier::PredefinedFunction(15)
    );
    assert_eq!(
        CommandQualifier::from_raw(16),
        CommandQualifier::Private(16)
    );
    assert_eq!(
        CommandQualifier::from_raw(31),
        CommandQualifier::Private(31)
    );
    // Every UI5 value round-trips.
    for raw in 0..=31 {
        assert_eq!(CommandQualifier::from_raw(raw).raw(), raw);
    }
    // Footnote 5's "no additional definition" is the default.
    assert_eq!(
        CommandQualifier::default(),
        CommandQualifier::NoAdditionalDefinition
    );
}

/// Clause 7.2.6.26: `QU := UI5[3..7]` (`0x7C`), `S/E := BS1[8]` (`0x80`), so a
/// selected short pulse is `0x80 | 1 << 2` and an executed persistent output is
/// `3 << 2`.
#[test]
fn qoc_from_named_qualifier() {
    let select_short = Qoc::new(CommandQualifier::ShortPulse, true);
    assert_eq!(select_short.raw(), 0x84);
    assert_eq!(select_short.qualifier(), CommandQualifier::ShortPulse);
    let persistent = Qoc::new(CommandQualifier::PersistentOutput, false);
    assert_eq!(persistent.raw(), 0x0C);
    assert_eq!(Qoc::from_raw(0x88).qualifier(), CommandQualifier::LongPulse);
    assert_eq!(
        Qoc::default().qualifier(),
        CommandQualifier::NoAdditionalDefinition
    );
}

/// Clause 7.2.6.15: `SCO` is one octet; `SCS` is bit 1 and the reserved bit is zero.
#[test]
fn sco_len_and_off_on_wire() {
    assert_eq!(Sco::LEN, 1);
    let off = Sco {
        scs: false,
        qoc: Qoc {
            qu: 0,
            select: false,
        },
    };
    assert_eq!(off.raw(), 0x00);
    let on = Sco {
        scs: true,
        qoc: Qoc {
            qu: 0,
            select: false,
        },
    };
    assert_eq!(on.raw(), 0x01);
    let mut out = Vec::new();
    on.encode(&mut out);
    assert_eq!(out, vec![0x01]);
}

/// Clause 7.2.6.15: select with `QU = 3` occupies bit 8 and `UI5[3..7]`.
#[test]
fn sco_select_bit_is_0x80() {
    let select = Sco {
        scs: false,
        qoc: Qoc {
            qu: 3,
            select: true,
        },
    };
    assert_eq!(select.raw(), 0x80 | 0x0C);
    assert_eq!(Sco::from_raw(0x8C), select);
}

/// Clause 7.2.6.15: a fully populated `SCO` round-trips and drops the reserved bit.
#[test]
fn sco_round_trip_and_truncation() {
    let sco = Sco {
        scs: true,
        qoc: Qoc {
            qu: 17,
            select: true,
        },
    };
    let mut out = Vec::new();
    sco.encode(&mut out);
    assert_eq!(out.len(), Sco::LEN);
    assert_eq!(Sco::parse(&out).unwrap(), sco);
    // RES is bit 2 (0x02); a received 1 is written back as zero.
    assert_eq!(Sco::from_raw(0x03).raw(), 0x01);
    assert_too_short(Sco::parse, &out);
}

/// Clause 7.2.6.16: `DCO` OFF + select is `0x81`; ON + short pulse is `0x06`.
#[test]
fn dco_named_wire_bytes() {
    assert_eq!(Dco::LEN, 1);
    let off_select = Dco {
        dcs: DoubleCommandState::Off,
        qoc: Qoc {
            qu: 0,
            select: true,
        },
    };
    assert_eq!(off_select.raw(), 0x81);
    // DCS = 2 in bits 1–2 (0x02), QU = 1 in bits 3–7 (0x04) → 0x06.
    let on_short = Dco {
        dcs: DoubleCommandState::On,
        qoc: Qoc {
            qu: 1,
            select: false,
        },
    };
    assert_eq!(on_short.raw(), 0x06);
    assert_eq!(Dco::from_raw(0x81), off_select);
    assert_eq!(Dco::from_raw(0x06), on_short);
}

/// Clause 7.2.6.16: a fully populated `DCO` round-trips, including both not-permitted states.
#[test]
fn dco_round_trip_and_truncation() {
    let dco = Dco {
        dcs: DoubleCommandState::NotPermittedAlt,
        qoc: Qoc {
            qu: 31,
            select: true,
        },
    };
    let mut out = Vec::new();
    dco.encode(&mut out);
    assert_eq!(out, vec![0xFF]);
    assert_eq!(Dco::parse(&out).unwrap(), dco);
    assert_eq!(
        Dco::parse(&[0x00]).unwrap().dcs,
        DoubleCommandState::NotPermitted
    );
    assert_too_short(Dco::parse, &out);
}

/// Clause 7.2.6.17: `RCO` next-step LOWER with an idle qualifier is `0x01`.
#[test]
fn rco_lower_is_0x01() {
    assert_eq!(Rco::LEN, 1);
    let lower = Rco {
        rcs: RegulatingStepState::Lower,
        qoc: Qoc {
            qu: 0,
            select: false,
        },
    };
    assert_eq!(lower.raw(), 0x01);
    let mut out = Vec::new();
    lower.encode(&mut out);
    assert_eq!(out, vec![0x01]);
    assert_eq!(Rco::parse(&out).unwrap(), lower);
}

/// Clause 7.2.6.17: HIGHER + select occupies bits 1–2 and bit 8.
#[test]
fn rco_round_trip_and_truncation() {
    let higher = Rco {
        rcs: RegulatingStepState::Higher,
        qoc: Qoc {
            qu: 4,
            select: true,
        },
    };
    assert_eq!(higher.raw(), 0x80 | 0x10 | 0x02);
    let mut out = Vec::new();
    higher.encode(&mut out);
    assert_eq!(Rco::parse(&out).unwrap(), higher);
    assert_eq!(
        Rco::from_raw(0x03).rcs,
        RegulatingStepState::NotPermittedAlt
    );
    assert_too_short(Rco::parse, &out);
}

/// Clause 7.2.6.39: `QOS` is one octet; `QL` is `UI7[1..7]` and `S/E` is bit 8.
#[test]
fn qos_select_is_0x80() {
    assert_eq!(Qos::LEN, 1);
    let select = Qos {
        ql: 0,
        select: true,
    };
    assert_eq!(select.raw(), 0x80);
    assert_eq!(Qos::from_raw(0x80), select);
    assert_eq!(
        Qos {
            ql: 127,
            select: false
        }
        .raw(),
        0x7F
    );
}

/// Clause 7.2.6.39: a fully populated `QOS` round-trips.
#[test]
fn qos_round_trip_and_truncation() {
    let qos = Qos {
        ql: 64,
        select: true,
    };
    let mut out = Vec::new();
    qos.encode(&mut out);
    assert_eq!(out, vec![0xC0]);
    assert_eq!(Qos::parse(&out).unwrap(), qos);
    assert_eq!(Qos::parse(&[0xFF]).unwrap().ql, 127);
    assert_too_short(Qos::parse, &out);
}
