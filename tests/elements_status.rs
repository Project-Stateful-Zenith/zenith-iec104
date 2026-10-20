//! Quality and status information elements: IEC 60870-5-101:2003
//! clause 7.2.6.1–7.2.6.13, plus `SCD` (clause 7.2.6.40).
//!
//! Bit numbers in the clause text are 1-based from the least significant bit,
//! so field `[n]` is `1 << (n - 1)`. Multi-octet fields are little-endian.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use iec104::asdu::{
    AsduError, Bsi, Diq, DoublePointState, EventState, Oci, Qdp, Qds, Scd, Sep, Siq, Spe, Vti,
};

/// Every prefix shorter than `LEN` is a typed shortfall, never a panic and
/// never `Ok` (clause 7.2.6: an element is exactly `LEN` octets).
fn assert_truncation<T, F>(encoded: &[u8], len: usize, parse: F)
where
    T: std::fmt::Debug,
    F: Fn(&[u8]) -> Result<T, AsduError>,
{
    for have in 0..len {
        let err = parse(&encoded[..have]).expect_err("a short prefix must not parse");
        assert_eq!(err, AsduError::TooShort { need: len, have });
    }
}

// --- SIQ, clause 7.2.6.1 ----------------------------------------------------

/// Clause 7.2.6.1: `SIQ := CP8{SPI,RES,BL,SB,NT,IV}` is one octet.
#[test]
fn siq_len_is_one_octet() {
    assert_eq!(Siq::LEN, 1);
}

/// Clause 7.2.6.1: SPI bit 1 is 0x01, BL bit 5 is 0x10, SB bit 6 is 0x20,
/// NT bit 7 is 0x40, IV bit 8 is 0x80.
#[test]
fn siq_named_bits_are_at_the_clause_positions() {
    let off = Siq::default();
    assert_eq!(off.raw(), 0x00);
    assert_eq!(Siq { spi: true, ..off }.raw(), 0x01);
    assert_eq!(
        Siq {
            blocked: true,
            ..off
        }
        .raw(),
        0x10
    );
    assert_eq!(
        Siq {
            substituted: true,
            ..off
        }
        .raw(),
        0x20
    );
    assert_eq!(
        Siq {
            not_topical: true,
            ..off
        }
        .raw(),
        0x40
    );
    assert_eq!(
        Siq {
            invalid: true,
            ..off
        }
        .raw(),
        0x80
    );
}

/// Clause 7.2.6.1: a fully-populated SIQ round-trips, and `quality()` maps
/// BL/SB/NT/IV onto a QDS with overflow false.
#[test]
fn siq_round_trip_and_quality_mapping() {
    let value = Siq {
        spi: true,
        blocked: true,
        substituted: true,
        not_topical: true,
        invalid: true,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0xF1]);
    assert_eq!(Siq::parse(&out).unwrap(), value);
    assert_eq!(Siq::from_raw(0xF1), value);

    let quality = value.quality();
    assert_eq!(
        quality,
        Qds {
            overflow: false,
            blocked: true,
            substituted: true,
            not_topical: true,
            invalid: true,
        }
    );
    // OV is not a SIQ bit: a QDS overflow does not come back on the wire.
    let rebuilt = Siq::with_quality(
        true,
        Qds {
            overflow: true,
            blocked: true,
            substituted: false,
            not_topical: false,
            invalid: false,
        },
    );
    assert_eq!(rebuilt.raw(), 0x11);
    assert!(!rebuilt.quality().overflow);
}

/// Clause 7.2.6.1: every prefix of a valid SIQ is `TooShort { need: 1, .. }`.
#[test]
fn siq_truncation_is_a_typed_error() {
    assert_truncation(&[0xF1], Siq::LEN, Siq::parse);
}

// --- QDS, clause 7.2.6.3 ---------------------------------------------------

/// Clause 7.2.6.3: `QDS := CP8{OV,RES,BL,SB,NT,IV}` is one octet.
#[test]
fn qds_len_is_one_octet() {
    assert_eq!(Qds::LEN, 1);
}

/// Clause 7.2.6.3: `OV := BS1[1]<0..1>`, `RES := BS3[2..4]<0>`, `BL := BS1[5]`,
/// `SB := BS1[6]`, `NT := BS1[7]`, `IV := BS1[8]`, so OV is 0x01 and the other
/// four are 0x10/0x20/0x40/0x80, with the three reserved bits zero. The figure's
/// own row (`|IV NT SB BL 0 0 0 OV|`) is the same assignment printed MSB-first.
#[test]
fn qds_named_bits_are_at_the_clause_positions() {
    let off = Qds::default();
    assert_eq!(off.raw(), 0x00);
    assert_eq!(
        Qds {
            overflow: true,
            ..off
        }
        .raw(),
        0x01
    );
    assert_eq!(
        Qds {
            blocked: true,
            ..off
        }
        .raw(),
        0x10
    );
    assert_eq!(
        Qds {
            substituted: true,
            ..off
        }
        .raw(),
        0x20
    );
    assert_eq!(
        Qds {
            not_topical: true,
            ..off
        }
        .raw(),
        0x40
    );
    assert_eq!(
        Qds {
            invalid: true,
            ..off
        }
        .raw(),
        0x80
    );
}

/// Clause 7.2.6.3: a fully-populated QDS is 0xF1 on the wire and comes back
/// through `parse`, and the reserved bits 2-4 are ignored on decode.
#[test]
fn qds_round_trip() {
    let value = Qds {
        overflow: true,
        blocked: true,
        substituted: true,
        not_topical: true,
        invalid: true,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0xF1]);
    assert_eq!(Qds::parse(&out).unwrap(), value);
    // RES := BS3[2..4]<0> is not a field: 0xFF sets them, they are ignored.
    assert_eq!(Qds::from_raw(0xFF), value);
    assert_eq!(Qds::from_raw(0xFF).raw(), 0xF1);
}

/// Clause 7.2.6.3: every prefix of a valid QDS is `TooShort { need: 1, .. }`.
#[test]
fn qds_truncation_is_a_typed_error() {
    assert_truncation(&[0xF1], Qds::LEN, Qds::parse);
}

// --- DIQ, clause 7.2.6.2 ----------------------------------------------------

/// Clause 7.2.6.2: `DIQ := CP8{DPI,RES,BL,SB,NT,IV}` is one octet.
#[test]
fn diq_len_is_one_octet() {
    assert_eq!(Diq::LEN, 1);
}

/// Clause 7.2.6.2: DPI is UI2[1..2] (0 indeterminate-or-intermediate, 1 OFF,
/// 2 ON, 3 indeterminate); BL/SB/NT/IV sit at 0x10/0x20/0x40/0x80.
#[test]
fn diq_named_bits_are_at_the_clause_positions() {
    let base = Diq::with_quality(DoublePointState::NotDetermined, Qds::default());
    assert_eq!(base.raw(), 0x00);
    assert_eq!(
        Diq {
            dpi: DoublePointState::Off,
            ..base
        }
        .raw(),
        0x01
    );
    assert_eq!(
        Diq {
            dpi: DoublePointState::On,
            ..base
        }
        .raw(),
        0x02
    );
    assert_eq!(
        Diq {
            dpi: DoublePointState::Indeterminate,
            ..base
        }
        .raw(),
        0x03
    );
    assert_eq!(
        Diq {
            blocked: true,
            ..base
        }
        .raw(),
        0x10
    );
    assert_eq!(
        Diq {
            substituted: true,
            ..base
        }
        .raw(),
        0x20
    );
    assert_eq!(
        Diq {
            not_topical: true,
            ..base
        }
        .raw(),
        0x40
    );
    assert_eq!(
        Diq {
            invalid: true,
            ..base
        }
        .raw(),
        0x80
    );
}

/// Clause 7.2.6.2: DPI 0..=3 maps onto the four states and back, and a
/// fully-populated DIQ round-trips with RES bits ignored on decode.
#[test]
fn diq_round_trip_and_dpi_states() {
    assert_eq!(
        DoublePointState::from_bits(0),
        DoublePointState::NotDetermined
    );
    assert_eq!(DoublePointState::from_bits(1), DoublePointState::Off);
    assert_eq!(DoublePointState::from_bits(2), DoublePointState::On);
    assert_eq!(
        DoublePointState::from_bits(3),
        DoublePointState::Indeterminate
    );
    for bits in 0..=3 {
        assert_eq!(DoublePointState::from_bits(bits).to_bits(), bits);
    }
    // Bits above the UI2 field are not part of DPI.
    assert_eq!(DoublePointState::from_bits(0xFF).to_bits(), 0x03);

    let value = Diq {
        dpi: DoublePointState::On,
        blocked: true,
        substituted: true,
        not_topical: true,
        invalid: true,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0xF2]);
    assert_eq!(Diq::parse(&out).unwrap(), value);
    // RES bits 3-4 (0x04 | 0x08) are ignored.
    assert_eq!(Diq::from_raw(0xFE), value);

    let quality = value.quality();
    assert!(!quality.overflow);
    assert!(quality.blocked && quality.substituted && quality.not_topical && quality.invalid);
    let rebuilt = Diq::with_quality(DoublePointState::Off, quality);
    assert_eq!(rebuilt.dpi, DoublePointState::Off);
    assert_eq!(rebuilt.raw() & 0xF0, 0xF0);
}

/// Clause 7.2.6.2: every prefix of a valid DIQ is `TooShort { need: 1, .. }`.
#[test]
fn diq_truncation_is_a_typed_error() {
    assert_truncation(&[0xF2], Diq::LEN, Diq::parse);
}

// --- QDP, clause 7.2.6.4 ----------------------------------------------------

/// Clause 7.2.6.4: `QDP := CP8{RES,EI,BL,SB,NT,IV}` is one octet.
#[test]
fn qdp_len_is_one_octet() {
    assert_eq!(Qdp::LEN, 1);
}

/// Clause 7.2.6.4: EI is bit 4 (0x08); BL/SB/NT/IV are 0x10/0x20/0x40/0x80.
/// RES bits 1-3 are written as zero.
#[test]
fn qdp_named_bits_are_at_the_clause_positions() {
    let off = Qdp::default();
    assert_eq!(off.raw(), 0x00);
    assert_eq!(
        Qdp {
            elapsed_time_invalid: true,
            ..off
        }
        .raw(),
        0x08
    );
    assert_eq!(
        Qdp {
            blocked: true,
            ..off
        }
        .raw(),
        0x10
    );
    assert_eq!(
        Qdp {
            substituted: true,
            ..off
        }
        .raw(),
        0x20
    );
    assert_eq!(
        Qdp {
            not_topical: true,
            ..off
        }
        .raw(),
        0x40
    );
    assert_eq!(
        Qdp {
            invalid: true,
            ..off
        }
        .raw(),
        0x80
    );
}

/// Clause 7.2.6.4: a fully-populated QDP round-trips; `quality()` carries
/// BL/SB/NT/IV onto a QDS and does not treat EI as OV.
#[test]
fn qdp_round_trip_and_quality_is_not_overflow() {
    let value = Qdp {
        elapsed_time_invalid: true,
        blocked: true,
        substituted: true,
        not_topical: true,
        invalid: true,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0xF8]);
    assert_eq!(Qdp::parse(&out).unwrap(), value);
    // RES bits 1-3 ignored.
    assert_eq!(Qdp::from_raw(0xFF), value);

    let quality = value.quality();
    assert!(!quality.overflow, "EI is not OV");
    assert!(quality.blocked && quality.substituted && quality.not_topical && quality.invalid);
}

/// Clause 7.2.6.4: every prefix of a valid QDP is `TooShort { need: 1, .. }`.
#[test]
fn qdp_truncation_is_a_typed_error() {
    assert_truncation(&[0xF8], Qdp::LEN, Qdp::parse);
}

// --- VTI, clause 7.2.6.5 ----------------------------------------------------

/// Clause 7.2.6.5: `VTI := CP8{Value,Transient}` is one octet.
#[test]
fn vti_len_is_one_octet() {
    assert_eq!(Vti::LEN, 1);
}

/// Clause 7.2.6.5: Value is I7[1..7] two's complement (−64..=63) and
/// Transient is bit 8 (0x80). Boundary encodings: −64 is 0x40, 63 is 0x3F,
/// −1 is 0x7F.
#[test]
fn vti_boundaries_and_transient_bit() {
    assert_eq!(
        Vti {
            value: 0,
            transient: false
        }
        .raw(),
        0x00
    );
    assert_eq!(
        Vti {
            value: 1,
            transient: false
        }
        .raw(),
        0x01
    );
    assert_eq!(
        Vti {
            value: 63,
            transient: false
        }
        .raw(),
        0x3F
    );
    assert_eq!(
        Vti {
            value: -1,
            transient: false
        }
        .raw(),
        0x7F
    );
    assert_eq!(
        Vti {
            value: -64,
            transient: false
        }
        .raw(),
        0x40
    );
    assert_eq!(
        Vti {
            value: -64,
            transient: true
        }
        .raw(),
        0xC0
    );
    assert_eq!(
        Vti {
            value: 0,
            transient: true
        }
        .raw(),
        0x80
    );

    assert_eq!(
        Vti::from_raw(0x40),
        Vti {
            value: -64,
            transient: false
        }
    );
    assert_eq!(
        Vti::from_raw(0x3F),
        Vti {
            value: 63,
            transient: false
        }
    );
    assert_eq!(
        Vti::from_raw(0x7F),
        Vti {
            value: -1,
            transient: false
        }
    );
    assert_eq!(
        Vti::from_raw(0xC0),
        Vti {
            value: -64,
            transient: true
        }
    );
}

/// Clause 7.2.6.5: every legal step position round-trips, transient included.
#[test]
fn vti_round_trip_covers_the_whole_range() {
    for value in -64..=63 {
        for transient in [false, true] {
            let vti = Vti { value, transient };
            let mut out = Vec::new();
            vti.encode(&mut out);
            assert_eq!(out.len(), 1);
            assert_eq!(Vti::parse(&out).unwrap(), vti);
            assert_eq!(Vti::from_raw(vti.raw()), vti);
        }
    }
}

/// Clause 7.2.6.5: a `Value` outside `-64..=63` clamps to the nearest end on
/// encode; it never wraps into the opposite sign.
#[test]
fn vti_out_of_range_value_clamps_on_encode() {
    for (value, expected) in [
        (63, 63),
        (-64, -64),
        (64, 63),
        (100, 63),
        (i8::MAX, 63),
        (-65, -64),
        (i8::MIN, -64),
    ] {
        for transient in [false, true] {
            let mut out = Vec::new();
            Vti { value, transient }.encode(&mut out);
            assert_eq!(
                Vti::parse(&out).unwrap(),
                Vti {
                    value: expected,
                    transient
                },
                "value {value}"
            );
        }
    }
}

/// Clause 7.2.6.5: every prefix of a valid VTI is `TooShort { need: 1, .. }`.
#[test]
fn vti_truncation_is_a_typed_error() {
    assert_truncation(&[0xC0], Vti::LEN, Vti::parse);
}

// --- SEP, clause 7.2.6.10 ---------------------------------------------------

/// Clause 7.2.6.10: `SEP := CP8{ES,RES,EI,BL,SB,NT,IV}` is one octet.
#[test]
fn sep_len_is_one_octet() {
    assert_eq!(Sep::LEN, 1);
}

/// Clause 7.2.6.10: ES is UI2[1..2] (0 indeterminate, 1 OFF, 2 ON,
/// 3 indeterminate); EI bit 4 is 0x08; BL/SB/NT/IV as in QDP.
#[test]
fn sep_named_bits_are_at_the_clause_positions() {
    let base = Sep::from_raw(0x00);
    assert_eq!(base.raw(), 0x00);
    assert_eq!(
        Sep {
            event_state: EventState::Off,
            ..base
        }
        .raw(),
        0x01
    );
    assert_eq!(
        Sep {
            event_state: EventState::On,
            ..base
        }
        .raw(),
        0x02
    );
    assert_eq!(
        Sep {
            event_state: EventState::Indeterminate,
            ..base
        }
        .raw(),
        0x03
    );
    assert_eq!(
        Sep {
            elapsed_time_invalid: true,
            ..base
        }
        .raw(),
        0x08
    );
    assert_eq!(
        Sep {
            blocked: true,
            ..base
        }
        .raw(),
        0x10
    );
    assert_eq!(
        Sep {
            substituted: true,
            ..base
        }
        .raw(),
        0x20
    );
    assert_eq!(
        Sep {
            not_topical: true,
            ..base
        }
        .raw(),
        0x40
    );
    assert_eq!(
        Sep {
            invalid: true,
            ..base
        }
        .raw(),
        0x80
    );
}

/// Clause 7.2.6.10: ES 0..=3 maps onto the four event states, a
/// fully-populated SEP round-trips, and `quality()` is a QDP (EI included).
#[test]
fn sep_round_trip_and_quality_is_a_qdp() {
    assert_eq!(EventState::from_bits(0), EventState::NotDetermined);
    assert_eq!(EventState::from_bits(1), EventState::Off);
    assert_eq!(EventState::from_bits(2), EventState::On);
    assert_eq!(EventState::from_bits(3), EventState::Indeterminate);
    for bits in 0..=3 {
        assert_eq!(EventState::from_bits(bits).to_bits(), bits);
    }
    assert_eq!(EventState::from_bits(0xFF).to_bits(), 0x03);

    let value = Sep {
        event_state: EventState::On,
        elapsed_time_invalid: true,
        blocked: true,
        substituted: true,
        not_topical: true,
        invalid: true,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0xFA]);
    assert_eq!(Sep::parse(&out).unwrap(), value);
    // RES bit 3 (0x04) ignored.
    assert_eq!(Sep::from_raw(0xFE), value);

    assert_eq!(
        value.quality(),
        Qdp {
            elapsed_time_invalid: true,
            blocked: true,
            substituted: true,
            not_topical: true,
            invalid: true,
        }
    );
}

/// Clause 7.2.6.10: every prefix of a valid SEP is `TooShort { need: 1, .. }`.
#[test]
fn sep_truncation_is_a_typed_error() {
    assert_truncation(&[0xFA], Sep::LEN, Sep::parse);
}

// --- SPE, clause 7.2.6.11 ---------------------------------------------------

/// Clause 7.2.6.11: `SPE := BS8{GS,SL1,SL2,SL3,SIE,SRD,RES}` is one octet.
#[test]
fn spe_len_is_one_octet() {
    assert_eq!(Spe::LEN, 1);
}

/// Clause 7.2.6.11: GS 0x01, SL1 0x02, SL2 0x04, SL3 0x08, SIE 0x10, SRD 0x20.
/// RES bits 7-8 are written as zero.
#[test]
fn spe_named_bits_are_at_the_clause_positions() {
    let off = Spe::default();
    assert_eq!(off.raw(), 0x00);
    assert_eq!(
        Spe {
            general_start: true,
            ..off
        }
        .raw(),
        0x01
    );
    assert_eq!(
        Spe {
            start_l1: true,
            ..off
        }
        .raw(),
        0x02
    );
    assert_eq!(
        Spe {
            start_l2: true,
            ..off
        }
        .raw(),
        0x04
    );
    assert_eq!(
        Spe {
            start_l3: true,
            ..off
        }
        .raw(),
        0x08
    );
    assert_eq!(
        Spe {
            start_ie: true,
            ..off
        }
        .raw(),
        0x10
    );
    assert_eq!(
        Spe {
            start_reverse: true,
            ..off
        }
        .raw(),
        0x20
    );
}

/// Clause 7.2.6.11: a fully-populated SPE round-trips; reserved bits ignored.
#[test]
fn spe_round_trip_ignores_reserved_bits() {
    let value = Spe {
        general_start: true,
        start_l1: true,
        start_l2: true,
        start_l3: true,
        start_ie: true,
        start_reverse: true,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0x3F]);
    assert_eq!(Spe::parse(&out).unwrap(), value);
    // RES bits 7-8 (0x40 | 0x80) ignored.
    assert_eq!(Spe::from_raw(0xFF), value);
}

/// Clause 7.2.6.11: every prefix of a valid SPE is `TooShort { need: 1, .. }`.
#[test]
fn spe_truncation_is_a_typed_error() {
    assert_truncation(&[0x3F], Spe::LEN, Spe::parse);
}

// --- OCI, clause 7.2.6.12 ---------------------------------------------------

/// Clause 7.2.6.12: `OCI := BS8{GC,CL1,CL2,CL3,RES}` is one octet.
#[test]
fn oci_len_is_one_octet() {
    assert_eq!(Oci::LEN, 1);
}

/// Clause 7.2.6.12: GC 0x01, CL1 0x02, CL2 0x04, CL3 0x08. RES bits 5-8
/// are written as zero.
#[test]
fn oci_named_bits_are_at_the_clause_positions() {
    let off = Oci::default();
    assert_eq!(off.raw(), 0x00);
    assert_eq!(
        Oci {
            general_command: true,
            ..off
        }
        .raw(),
        0x01
    );
    assert_eq!(
        Oci {
            command_l1: true,
            ..off
        }
        .raw(),
        0x02
    );
    assert_eq!(
        Oci {
            command_l2: true,
            ..off
        }
        .raw(),
        0x04
    );
    assert_eq!(
        Oci {
            command_l3: true,
            ..off
        }
        .raw(),
        0x08
    );
}

/// Clause 7.2.6.12: a fully-populated OCI round-trips; reserved bits ignored.
#[test]
fn oci_round_trip_ignores_reserved_bits() {
    let value = Oci {
        general_command: true,
        command_l1: true,
        command_l2: true,
        command_l3: true,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0x0F]);
    assert_eq!(Oci::parse(&out).unwrap(), value);
    // RES bits 5-8 ignored.
    assert_eq!(Oci::from_raw(0xFF), value);
}

/// Clause 7.2.6.12: every prefix of a valid OCI is `TooShort { need: 1, .. }`.
#[test]
fn oci_truncation_is_a_typed_error() {
    assert_truncation(&[0x0F], Oci::LEN, Oci::parse);
}

// --- BSI, clause 7.2.6.13 ---------------------------------------------------

/// Clause 7.2.6.13: `BSI := 32BS1[1..32]` is four octets.
#[test]
fn bsi_len_is_four_octets() {
    assert_eq!(Bsi::LEN, 4);
}

/// Clause 7.2.6.13 / 7.3.1.7: bit 1 is the first octet's low bit and bit 32
/// is the fourth octet's high bit. Little-endian: `0x00000001` encodes as
/// `[01 00 00 00]`, `0x80000000` as `[00 00 00 80]`.
#[test]
fn bsi_bit_1_and_bit_32_are_the_wire_ends() {
    let bit1 = Bsi { bits: 0x0000_0001 };
    let mut out = Vec::new();
    bit1.encode(&mut out);
    assert_eq!(out, vec![0x01, 0x00, 0x00, 0x00]);
    assert!(bit1.bit(1));
    assert!(!bit1.bit(32));

    let bit32 = Bsi { bits: 0x8000_0000 };
    let mut out = Vec::new();
    bit32.encode(&mut out);
    assert_eq!(out, vec![0x00, 0x00, 0x00, 0x80]);
    assert!(bit32.bit(32));
    assert!(!bit32.bit(1));
    assert_eq!(Bsi::parse(&out).unwrap(), bit32);
    assert_eq!(Bsi::from_raw(0x8000_0000).raw(), 0x8000_0000);
}

/// Clause 7.2.6.13: `bit`/`set_bit` number 1..=32; outside that range they
/// are a no-op (`false` / unchanged).
#[test]
fn bsi_bit_access_is_bounded_to_1_through_32() {
    let mut value = Bsi { bits: 0 };
    assert!(!value.bit(0));
    assert!(!value.bit(33));
    value.set_bit(0, true);
    value.set_bit(33, true);
    assert_eq!(value.bits, 0);

    value.set_bit(1, true);
    value.set_bit(32, true);
    assert!(value.bit(1) && value.bit(32));
    assert_eq!(value.bits, 0x8000_0001);
    value.set_bit(1, false);
    assert_eq!(value.bits, 0x8000_0000);

    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(Bsi::parse(&out).unwrap(), value);
}

/// Clause 7.2.6.13: every prefix of a valid BSI is `TooShort { need: 4, .. }`.
#[test]
fn bsi_truncation_is_a_typed_error() {
    assert_truncation(&[0x01, 0x00, 0x00, 0x00], Bsi::LEN, Bsi::parse);
}

// --- SCD, clause 7.2.6.40 ---------------------------------------------------

/// Clause 7.2.6.40: `SCD := CP32{ST,CD}` is four octets.
#[test]
fn scd_len_is_four_octets() {
    assert_eq!(Scd::LEN, 4);
}

/// Clause 7.2.6.40: ST occupies the first two octets and CD the next two,
/// both little-endian. Status bit 1 is octet 1's low bit; status bit 16 is
/// octet 2's high bit; change bit 1 is octet 3's low bit; change bit 16 is
/// octet 4's high bit.
#[test]
fn scd_status_then_change_little_endian() {
    let value = Scd {
        status: 0x0001,
        change: 0x0000,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0x01, 0x00, 0x00, 0x00]);

    let value = Scd {
        status: 0x8000,
        change: 0x0000,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0x00, 0x80, 0x00, 0x00]);

    let value = Scd {
        status: 0x0000,
        change: 0x0001,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0x00, 0x00, 0x01, 0x00]);

    let value = Scd {
        status: 0x0000,
        change: 0x8000,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0x00, 0x00, 0x00, 0x80]);
    assert!(value.change_bit(16));
    assert!(!value.status_bit(16));
    assert!(!value.change_bit(1));
}

/// Clause 7.2.6.40: a fully-populated SCD round-trips, and bit accessors
/// number 1..=16 (outside that range they are false).
#[test]
fn scd_round_trip_and_bit_accessors() {
    let value = Scd {
        status: 0xA5A5,
        change: 0x5A5A,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, vec![0xA5, 0xA5, 0x5A, 0x5A]);
    assert_eq!(Scd::parse(&out).unwrap(), value);

    assert!(value.status_bit(1));
    assert!(!value.status_bit(2));
    assert!(value.change_bit(2));
    assert!(!value.status_bit(0));
    assert!(!value.status_bit(17));
    assert!(!value.change_bit(0));
    assert!(!value.change_bit(17));
}

/// Clause 7.2.6.40: every prefix of a valid SCD is `TooShort { need: 4, .. }`.
#[test]
fn scd_truncation_is_a_typed_error() {
    assert_truncation(&[0xA5, 0xA5, 0x5A, 0x5A], Scd::LEN, Scd::parse);
}
