//! Value information elements: IEC 60870-5-101:2003 clause 7.2.6.6–7.2.6.9
//! and 7.2.6.14.
//!
//! Multi-octet fields are little-endian (least significant octet first). Bit
//! numbers are 1-based from the least significant bit, so `BCR`'s `SQ :=
//! UI5[33..37]` is `0x1F`, `CY := BS1[38]` is `0x20`, `CA := BS1[39]` is
//! `0x40` and `IV := BS1[40]` is `0x80`.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use iec104::asdu::{AsduError, Bcr, Fbp, Nva, R32, Sva, Tsc};

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

fn encode_of<T>(value: &T, encode: fn(&T, &mut Vec<u8>)) -> Vec<u8> {
    let mut out = Vec::new();
    encode(value, &mut out);
    out
}

/// Clause 7.2.6.6: `NVA` is two octets; `i16::MIN` is exactly −1.0 and encodes as `00 80`.
#[test]
fn nva_min_is_minus_one() {
    assert_eq!(Nva::LEN, 2);
    let nva = Nva::from_raw(i16::MIN);
    assert_eq!(nva.raw(), i16::MIN);
    assert_eq!(nva.to_scaled(), -1.0);
    let out = encode_of(&nva, Nva::encode);
    assert_eq!(out, vec![0x00, 0x80]);
    assert_eq!(out.len(), Nva::LEN);
    assert_eq!(Nva::parse(&out).unwrap(), nva);
}

/// Clause 7.2.6.6: `i16::MAX` is `1.0 − 2^−15` and encodes as `FF 7F`.
#[test]
fn nva_max_is_one_minus_lsb() {
    let nva = Nva::from_raw(i16::MAX);
    assert_eq!(nva.raw(), i16::MAX);
    assert_eq!(nva.to_scaled(), 1.0 - 2.0_f64.powi(-15));
    let out = encode_of(&nva, Nva::encode);
    assert_eq!(out, vec![0xFF, 0x7F]);
    assert_eq!(Nva::parse(&out).unwrap(), nva);
}

/// Clause 7.2.6.6: `from_scaled(−1.0)` is `i16::MIN`; `from_scaled(1.0)` saturates at `i16::MAX`.
#[test]
fn nva_from_scaled_saturates_the_ends() {
    assert_eq!(Nva::from_scaled(-1.0).raw(), i16::MIN);
    assert_eq!(Nva::from_scaled(1.0).raw(), i16::MAX);
    assert_eq!(Nva::from_scaled(2.0).raw(), i16::MAX);
    assert_eq!(Nva::from_scaled(-2.0).raw(), i16::MIN);
}

/// Clause 7.2.6.6: `from_scaled(0.5)` is 16384; half an LSB rounds away from zero to 1.
#[test]
fn nva_from_scaled_rounds_half_away_from_zero() {
    assert_eq!(Nva::from_scaled(0.5).raw(), 16384);
    assert_eq!(Nva::from_scaled(1.0 / 65536.0).raw(), 1);
    assert_eq!(Nva::from_scaled(-1.0 / 65536.0).raw(), -1);
}

/// Clause 7.2.6.6: a fully populated `NVA` round-trips, and every prefix is too short.
#[test]
fn nva_round_trip_and_truncation() {
    let nva = Nva { value: -12345 };
    let out = encode_of(&nva, Nva::encode);
    assert_eq!(out, (-12345_i16).to_le_bytes());
    assert_eq!(Nva::parse(&out).unwrap(), nva);
    assert_eq!(
        Nva::parse(&out).unwrap().to_scaled(),
        f64::from(-12345) / 32768.0
    );
    assert_too_short(Nva::parse, &out);
}

/// Clause 7.2.6.7: `SVA` is two octets; −1 encodes as `FF FF`, `i16::MIN` as `00 80`, 1234 as `D2 04`.
#[test]
fn sva_named_wire_bytes() {
    assert_eq!(Sva::LEN, 2);
    assert_eq!(encode_of(&Sva::from_raw(-1), Sva::encode), vec![0xFF, 0xFF]);
    assert_eq!(
        encode_of(&Sva::from_raw(i16::MIN), Sva::encode),
        vec![0x00, 0x80]
    );
    assert_eq!(
        encode_of(&Sva::from_raw(1234), Sva::encode),
        vec![0xD2, 0x04]
    );
    assert_eq!(Sva::from_raw(1234).raw(), 1234);
}

/// Clause 7.2.6.7: a fully populated `SVA` round-trips; decimal point and range are not fields.
#[test]
fn sva_round_trip_and_truncation() {
    let sva = Sva { value: -32767 };
    let out = encode_of(&sva, Sva::encode);
    assert_eq!(out.len(), Sva::LEN);
    assert_eq!(out, vec![0x01, 0x80]);
    assert_eq!(Sva::parse(&out).unwrap(), sva);
    assert_eq!(Sva::parse(&out).unwrap().raw(), -32767);
    assert_too_short(Sva::parse, &out);
}

/// Clause 7.2.6.8: `R32` is four octets; 1.0 is `00 00 80 3F`, 13.5 is `00 00 58 41`.
#[test]
fn r32_named_wire_bytes() {
    assert_eq!(R32::LEN, 4);
    assert_eq!(
        encode_of(&R32::from_raw(1.0), R32::encode),
        vec![0x00, 0x00, 0x80, 0x3F]
    );
    assert_eq!(
        encode_of(&R32::from_raw(13.5), R32::encode),
        vec![0x00, 0x00, 0x58, 0x41]
    );
    assert_eq!(R32::from_raw(13.5).raw(), 13.5);
}

/// Clause 7.2.6.8: −0.0 keeps its sign bit (`00 00 00 80`) across a round trip.
#[test]
fn r32_negative_zero_keeps_the_sign_bit() {
    let r32 = R32::from_raw(-0.0);
    let out = encode_of(&r32, R32::encode);
    assert_eq!(out, vec![0x00, 0x00, 0x00, 0x80]);
    assert_eq!(out.len(), R32::LEN);
    let back = R32::parse(&out).unwrap();
    assert!(back.raw().is_sign_negative());
    assert_eq!(back.raw().to_bits(), (-0.0_f32).to_bits());
}

/// Clause 7.2.6.8: `NaN` survives a round trip bit-for-bit.
#[test]
fn r32_nan_round_trips_bit_for_bit() {
    let bits = 0x7FC0_1234_u32;
    let r32 = R32::from_raw(f32::from_bits(bits));
    assert!(r32.raw().is_nan());
    let out = encode_of(&r32, R32::encode);
    assert_eq!(out, bits.to_le_bytes());
    let back = R32::parse(&out).unwrap();
    assert_eq!(back.raw().to_bits(), bits);
    assert_eq!(back.value.to_bits(), bits);
}

/// Clause 7.2.6.8: a fully populated `R32` round-trips, and every prefix is too short.
#[test]
fn r32_round_trip_and_truncation() {
    let r32 = R32 { value: -13.5 };
    let out = encode_of(&r32, R32::encode);
    assert_eq!(out, (-13.5_f32).to_le_bytes());
    assert_eq!(
        R32::parse(&out).unwrap().raw().to_bits(),
        (-13.5_f32).to_bits()
    );
    assert_too_short(R32::parse, &out);
}

/// Clause 7.2.6.9: `BCR` is five octets; reading 1, sequence 3 and carry sets only bit 6 of octet 5.
#[test]
fn bcr_carry_sets_bit_6() {
    assert_eq!(Bcr::LEN, 5);
    let bcr = Bcr {
        reading: 1,
        sequence: 3,
        carry: true,
        adjusted: false,
        invalid: false,
    };
    let out = encode_of(&bcr, Bcr::encode);
    assert_eq!(out, vec![0x01, 0x00, 0x00, 0x00, 0x23]);
    assert_eq!(out[4] & 0x20, 0x20);
    assert_eq!(out.len(), Bcr::LEN);
    assert_eq!(Bcr::parse(&out).unwrap(), bcr);
}

/// Clause 7.2.6.9: reading −2 encodes as `FE FF FF FF` in the counter octets.
#[test]
fn bcr_negative_reading_is_little_endian() {
    let bcr = Bcr {
        reading: -2,
        sequence: 0,
        carry: false,
        adjusted: false,
        invalid: false,
    };
    let out = encode_of(&bcr, Bcr::encode);
    assert_eq!(out, vec![0xFE, 0xFF, 0xFF, 0xFF, 0x00]);
    assert_eq!(Bcr::parse(&out).unwrap(), bcr);
}

/// Clause 7.2.6.9: `SQ` is a five-bit field, so `encode` masks a sequence of 33 down to 1.
#[test]
fn bcr_sequence_is_masked_to_five_bits() {
    let bcr = Bcr {
        reading: 0,
        sequence: 33,
        carry: false,
        adjusted: false,
        invalid: false,
    };
    let out = encode_of(&bcr, Bcr::encode);
    assert_eq!(out, vec![0x00, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(Bcr::parse(&out).unwrap().sequence, 1);
}

/// Clause 7.2.6.9: every status bit of a fully populated `BCR` round-trips, and every prefix is too short.
#[test]
fn bcr_round_trip_and_truncation() {
    let bcr = Bcr {
        reading: i32::MIN,
        sequence: 31,
        carry: true,
        adjusted: true,
        invalid: true,
    };
    let out = encode_of(&bcr, Bcr::encode);
    assert_eq!(out, vec![0x00, 0x00, 0x00, 0x80, 0xFF]);
    assert_eq!(Bcr::parse(&out).unwrap(), bcr);
    assert_too_short(Bcr::parse, &out);
}

/// Clause 7.2.6.14: `FBP` is two octets and the one legal value `55AAH` encodes as `AA 55`.
#[test]
fn fbp_encodes_the_fixed_pattern() {
    assert_eq!(Fbp::LEN, 2);
    assert_eq!(Fbp::VALUE, 0x55AA);
    let out = encode_of(&Fbp, Fbp::encode);
    assert_eq!(out, vec![0xAA, 0x55]);
    assert_eq!(out.len(), Fbp::LEN);
    assert_eq!(Fbp::parse(&out).unwrap(), Fbp);
    assert_eq!(Fbp::parse(&[0xAA, 0x55, 0x00]).unwrap(), Fbp);
}

/// Clause 7.2.6.14: any other pattern is `FixedPatternMismatch`, never a value.
#[test]
fn fbp_rejects_any_other_pattern() {
    let err = Fbp::parse(&[0x55, 0xAA]).unwrap_err();
    assert_eq!(
        err,
        AsduError::FixedPatternMismatch {
            expected: Fbp::VALUE,
            got: 0xAA55,
        }
    );
    let err = Fbp::parse(&[0x00, 0x00]).unwrap_err();
    assert_eq!(
        err,
        AsduError::FixedPatternMismatch {
            expected: 0x55AA,
            got: 0x0000,
        }
    );
}

/// Clause 7.2.6.14: every prefix of the legal pattern is too short, never a mismatch.
#[test]
fn fbp_truncation() {
    assert_too_short(Fbp::parse, &[0xAA, 0x55]);
}

/// IEC 60870-5-104:2006 clause 8.8: `TSC` is two octets, `UI16[1..16]<0..65535>`,
/// little-endian. It is the test sequence counter of the time-tagged test
/// command `C_TS_TA_1` (type 107), and the one type in this module that 5-101
/// does not define.
#[test]
fn tsc_is_a_little_endian_ui16() {
    assert_eq!(Tsc::LEN, 2);
    let tsc = Tsc::from_raw(0x1234);
    assert_eq!(tsc.raw(), 0x1234);

    // Figure 30's field is 16 bit; the least significant octet goes first, as
    // every other multi-octet element of this crate does.
    let out = encode_of(&tsc, Tsc::encode);
    assert_eq!(out, vec![0x34, 0x12]);
    assert_eq!(out.len(), Tsc::LEN);
    assert_eq!(Tsc::parse(&out).unwrap(), tsc);
}

/// Clause 8.8: `TSC := UI16[1..16]<0..65535>`. Both ends of the field
/// round-trip, and so does `0x55AA`: that is the `FBP` pattern of the untimed
/// test command, but for a `TSC` it is an ordinary counter value.
#[test]
fn tsc_covers_the_whole_ui16_range() {
    for value in [0u16, 1, 0x55AA, 0x8000, u16::MAX] {
        let tsc = Tsc::from_raw(value);
        assert_eq!(tsc.raw(), value);
        assert_eq!(Tsc::parse(&encode_of(&tsc, Tsc::encode)).unwrap(), tsc);
    }
}

/// Clause 8.8: the same truncation contract as every other element. A prefix
/// of the two octets is `TooShort`, never a panic and never a silent read.
#[test]
fn tsc_rejects_every_short_prefix() {
    let encoded = encode_of(&Tsc::from_raw(0x0102), Tsc::encode);
    assert_too_short(Tsc::parse, &encoded);
}
