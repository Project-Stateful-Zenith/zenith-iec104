//! File-transfer information elements: IEC 60870-5-101:2003 clause
//! 7.2.6.28–7.2.6.38.
//!
//! Bit numbers are 1-based from the least significant bit, so `FRQ`'s value is
//! bits 1–7 (`0x7F`) and its negative-confirm bit is bit 8 (`0x80`). Multi-octet
//! fields are little-endian: `NOF` a `UI16`, `LOF` a `UI24`.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use iec104::asdu::{Afq, AsduError, Chs, Frq, Lof, Los, Lsq, Nof, Nos, Scq, Sof, Srq};

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

/// Clause 7.2.6.28: `FRQ` is one octet; the value is `UI7[1..7]` and bit 8 is the confirm.
#[test]
fn frq_len_and_field_masks() {
    assert_eq!(Frq::LEN, 1);
    let full = Frq::from_raw(0xFF);
    assert_eq!(full.value, 0x7F);
    assert!(full.negative_confirm);
    assert_eq!(full.raw(), 0xFF);
    let positive = Frq::from_raw(0x05);
    assert_eq!(positive.value, 5);
    assert!(!positive.negative_confirm);
    assert_eq!(positive.raw(), 0x05);
}

/// Clause 7.2.6.28: a negative confirm encodes to `0x80`.
#[test]
fn frq_negative_confirm() {
    let frq = Frq {
        value: 0,
        negative_confirm: true,
    };
    assert_eq!(frq.raw(), 0x80);
    let mut out = Vec::new();
    frq.encode(&mut out);
    assert_eq!(out, vec![0x80]);
    assert_eq!(Frq::parse(&out).unwrap(), frq);
}

/// Clause 7.2.6.28: value 5 encodes to `0x05`.
#[test]
fn frq_value_five() {
    let frq = Frq {
        value: 5,
        negative_confirm: false,
    };
    assert_eq!(frq.raw(), 0x05);
    let mut out = Vec::new();
    frq.encode(&mut out);
    assert_eq!(out, vec![0x05]);
    assert_eq!(Frq::parse(&out).unwrap(), frq);
}

/// Clause 7.2.6.28: a fully populated `FRQ` round-trips, and every prefix is too short.
#[test]
fn frq_round_trip_and_truncation() {
    let frq = Frq {
        value: 64,
        negative_confirm: true,
    };
    assert_eq!(frq.raw(), 0xC0);
    let mut out = Vec::new();
    frq.encode(&mut out);
    assert_eq!(out, vec![0xC0]);
    assert_eq!(Frq::parse(&out).unwrap(), frq);
    assert_eq!(out.len(), Frq::LEN);
    assert_too_short(Frq::parse, &out);
}

/// Clause 7.2.6.29: `SRQ` is one octet; the value is `UI7[1..7]` and bit 8 is not-ready.
#[test]
fn srq_len_and_field_masks() {
    assert_eq!(Srq::LEN, 1);
    let full = Srq::from_raw(0xFF);
    assert_eq!(full.value, 0x7F);
    assert!(full.not_ready);
    assert_eq!(full.raw(), 0xFF);
}

/// Clause 7.2.6.29: section not ready to load encodes to `0x80`.
#[test]
fn srq_not_ready() {
    let srq = Srq {
        value: 0,
        not_ready: true,
    };
    assert_eq!(srq.raw(), 0x80);
    let mut out = Vec::new();
    srq.encode(&mut out);
    assert_eq!(out, vec![0x80]);
    assert_eq!(Srq::parse(&out).unwrap(), srq);
}

/// Clause 7.2.6.29: a fully populated `SRQ` round-trips, and every prefix is too short.
#[test]
fn srq_round_trip_and_truncation() {
    let srq = Srq {
        value: 17,
        not_ready: true,
    };
    assert_eq!(srq.raw(), 0x91);
    let mut out = Vec::new();
    srq.encode(&mut out);
    assert_eq!(out, vec![0x91]);
    assert_eq!(Srq::parse(&out).unwrap(), srq);
    assert_eq!(out.len(), Srq::LEN);
    assert_too_short(Srq::parse, &out);
}

/// Clause 7.2.6.30: `SCQ` is one octet; the action is `UI4[1..4]` and the error is `UI4[5..8]`.
#[test]
fn scq_len_and_field_masks() {
    assert_eq!(Scq::LEN, 1);
    assert_eq!(Scq::SELECT_FILE, 1);
    assert_eq!(Scq::REQUEST_FILE, 2);
    assert_eq!(Scq::DEACTIVATE_FILE, 3);
    assert_eq!(Scq::DELETE_FILE, 4);
    assert_eq!(Scq::SELECT_SECTION, 5);
    assert_eq!(Scq::REQUEST_SECTION, 6);
    assert_eq!(Scq::DEACTIVATE_SECTION, 7);
    let full = Scq::from_raw(0xFF);
    assert_eq!(full.action, 0x0F);
    assert_eq!(full.error, 0x0F);
    assert_eq!(full.raw(), 0xFF);
}

/// Clause 7.2.6.30: select file encodes to `0x01`.
#[test]
fn scq_select_file() {
    let scq = Scq {
        action: Scq::SELECT_FILE,
        error: 0,
    };
    assert_eq!(scq.raw(), 0x01);
    let mut out = Vec::new();
    scq.encode(&mut out);
    assert_eq!(out, vec![0x01]);
    assert_eq!(Scq::parse(&out).unwrap(), scq);
}

/// Clause 7.2.6.30: request file with checksum failed encodes to `0x22`.
#[test]
fn scq_request_file_checksum_failed() {
    let scq = Scq {
        action: Scq::REQUEST_FILE,
        error: 2,
    };
    assert_eq!(scq.raw(), 0x22);
    let mut out = Vec::new();
    scq.encode(&mut out);
    assert_eq!(out, vec![0x22]);
    assert_eq!(Scq::parse(&out).unwrap(), scq);
}

/// Clause 7.2.6.30: a fully populated `SCQ` round-trips, and every prefix is too short.
#[test]
fn scq_round_trip_and_truncation() {
    let scq = Scq {
        action: Scq::DEACTIVATE_SECTION,
        error: 5,
    };
    assert_eq!(scq.raw(), 0x57);
    let mut out = Vec::new();
    scq.encode(&mut out);
    assert_eq!(out, vec![0x57]);
    assert_eq!(Scq::parse(&out).unwrap(), scq);
    assert_eq!(out.len(), Scq::LEN);
    assert_too_short(Scq::parse, &out);
}

/// Clause 7.2.6.31: `LSQ` is the whole octet, with the four named transfer values.
#[test]
fn lsq_len_and_constants() {
    assert_eq!(Lsq::LEN, 1);
    assert_eq!(Lsq::FILE_WITHOUT_DEACTIVATION, 1);
    assert_eq!(Lsq::FILE_WITH_DEACTIVATION, 2);
    assert_eq!(Lsq::SECTION_WITHOUT_DEACTIVATION, 3);
    assert_eq!(Lsq::SECTION_WITH_DEACTIVATION, 4);
}

/// Clause 7.2.6.31: file transfer with deactivation encodes to `0x02`.
#[test]
fn lsq_file_with_deactivation() {
    let lsq = Lsq {
        value: Lsq::FILE_WITH_DEACTIVATION,
    };
    let mut out = Vec::new();
    lsq.encode(&mut out);
    assert_eq!(out, vec![0x02]);
    assert_eq!(Lsq::parse(&out).unwrap(), lsq);
}

/// Clause 7.2.6.31: a fully populated `LSQ` round-trips, and every prefix is too short.
#[test]
fn lsq_round_trip_and_truncation() {
    let lsq = Lsq { value: 0xA5 };
    let mut out = Vec::new();
    lsq.encode(&mut out);
    assert_eq!(out, vec![0xA5]);
    assert_eq!(Lsq::parse(&out).unwrap(), lsq);
    assert_eq!(out.len(), Lsq::LEN);
    assert_too_short(Lsq::parse, &out);
}

/// Clause 7.2.6.32: `AFQ` is one octet; the action is `UI4[1..4]` and the error is `UI4[5..8]`.
#[test]
fn afq_len_and_field_masks() {
    assert_eq!(Afq::LEN, 1);
    assert_eq!(Afq::FILE_POSITIVE, 1);
    assert_eq!(Afq::FILE_NEGATIVE, 2);
    assert_eq!(Afq::SECTION_POSITIVE, 3);
    assert_eq!(Afq::SECTION_NEGATIVE, 4);
    let full = Afq::from_raw(0xFF);
    assert_eq!(full.action, 0x0F);
    assert_eq!(full.error, 0x0F);
    assert_eq!(full.raw(), 0xFF);
}

/// Clause 7.2.6.32: positive acknowledge of file transfer encodes to `0x01`.
#[test]
fn afq_file_positive() {
    let afq = Afq {
        action: Afq::FILE_POSITIVE,
        error: 0,
    };
    assert_eq!(afq.raw(), 0x01);
    let mut out = Vec::new();
    afq.encode(&mut out);
    assert_eq!(out, vec![0x01]);
    assert_eq!(Afq::parse(&out).unwrap(), afq);
}

/// Clause 7.2.6.32: negative acknowledge of section transfer encodes to `0x04`.
#[test]
fn afq_section_negative() {
    let afq = Afq {
        action: Afq::SECTION_NEGATIVE,
        error: 0,
    };
    assert_eq!(afq.raw(), 0x04);
    let mut out = Vec::new();
    afq.encode(&mut out);
    assert_eq!(out, vec![0x04]);
    assert_eq!(Afq::parse(&out).unwrap(), afq);
}

/// Clause 7.2.6.32: a fully populated `AFQ` round-trips, and every prefix is too short.
#[test]
fn afq_round_trip_and_truncation() {
    let afq = Afq {
        action: Afq::SECTION_POSITIVE,
        error: 4,
    };
    assert_eq!(afq.raw(), 0x43);
    let mut out = Vec::new();
    afq.encode(&mut out);
    assert_eq!(out, vec![0x43]);
    assert_eq!(Afq::parse(&out).unwrap(), afq);
    assert_eq!(out.len(), Afq::LEN);
    assert_too_short(Afq::parse, &out);
}

/// Clause 7.2.6.33: `NOF` is two octets, little-endian.
#[test]
fn nof_len() {
    assert_eq!(Nof::LEN, 2);
}

/// Clause 7.2.6.33: `0x1234` encodes as `34 12`.
#[test]
fn nof_0x1234_is_little_endian() {
    let nof = Nof { value: 0x1234 };
    let mut out = Vec::new();
    nof.encode(&mut out);
    assert_eq!(out, vec![0x34, 0x12]);
    assert_eq!(Nof::parse(&out).unwrap(), nof);
}

/// Clause 7.2.6.33: a fully populated `NOF` round-trips, and every prefix is too short.
#[test]
fn nof_round_trip_and_truncation() {
    let nof = Nof { value: 0xFFFF };
    let mut out = Vec::new();
    nof.encode(&mut out);
    assert_eq!(out, vec![0xFF, 0xFF]);
    assert_eq!(Nof::parse(&out).unwrap(), nof);
    assert_eq!(out.len(), Nof::LEN);
    assert_too_short(Nof::parse, &out);
}

/// Clause 7.2.6.34: `NOS` is the whole octet.
#[test]
fn nos_len_round_trip_and_truncation() {
    assert_eq!(Nos::LEN, 1);
    let nos = Nos { value: 0x5A };
    let mut out = Vec::new();
    nos.encode(&mut out);
    assert_eq!(out, vec![0x5A]);
    assert_eq!(Nos::parse(&out).unwrap(), nos);
    assert_eq!(out.len(), Nos::LEN);
    assert_too_short(Nos::parse, &out);
}

/// Clause 7.2.6.35: `LOF` is three octets; the largest length is `2^24 − 1`.
#[test]
fn lof_len_and_max() {
    assert_eq!(Lof::LEN, 3);
    assert_eq!(Lof::MAX, 16_777_215);
}

/// Clause 7.2.6.35: `0x010203` encodes as `03 02 01`.
#[test]
fn lof_0x010203_is_little_endian() {
    let lof = Lof { value: 0x0001_0203 };
    let mut out = Vec::new();
    lof.encode(&mut out);
    assert_eq!(out, vec![0x03, 0x02, 0x01]);
    assert_eq!(Lof::parse(&out).unwrap(), lof);
}

/// Clause 7.2.6.35: `16_777_215` encodes as `FF FF FF`.
#[test]
fn lof_max_is_three_ff() {
    let lof = Lof { value: 16_777_215 };
    let mut out = Vec::new();
    lof.encode(&mut out);
    assert_eq!(out, vec![0xFF, 0xFF, 0xFF]);
    assert_eq!(Lof::parse(&out).unwrap(), lof);
}

/// Clause 7.2.6.35: a fully populated `LOF` round-trips, and every prefix is too short.
#[test]
fn lof_round_trip_and_truncation() {
    let lof = Lof { value: 0x00AB_CDEF };
    let mut out = Vec::new();
    lof.encode(&mut out);
    assert_eq!(out, vec![0xEF, 0xCD, 0xAB]);
    assert_eq!(Lof::parse(&out).unwrap(), lof);
    assert_eq!(out.len(), Lof::LEN);
    assert_too_short(Lof::parse, &out);
}

/// Clause 7.2.6.36: `LOS` is the whole octet, and the clause's largest segment is 240.
#[test]
fn los_len_max_round_trip_and_truncation() {
    assert_eq!(Los::LEN, 1);
    assert_eq!(Los::MAX, 240);
    let los = Los { value: 240 };
    let mut out = Vec::new();
    los.encode(&mut out);
    assert_eq!(out, vec![240]);
    assert_eq!(Los::parse(&out).unwrap(), los);
    assert_eq!(out.len(), Los::LEN);
    assert_too_short(Los::parse, &out);
}

/// Clause 7.2.6.37: `CHS` is the whole octet; the element only carries the sum
/// (computing it is `iec104::ft::checksum`).
#[test]
fn chs_len_round_trip_and_truncation() {
    assert_eq!(Chs::LEN, 1);
    let chs = Chs { value: 0x3C };
    let mut out = Vec::new();
    chs.encode(&mut out);
    assert_eq!(out, vec![0x3C]);
    assert_eq!(Chs::parse(&out).unwrap(), chs);
    assert_eq!(out.len(), Chs::LEN);
    assert_too_short(Chs::parse, &out);
}

/// Clause 7.2.6.38: `SOF` is one octet; status is `UI5[1..5]`, LFD bit 6, FOR bit 7, FA bit 8.
#[test]
fn sof_len_and_field_masks() {
    assert_eq!(Sof::LEN, 1);
    let full = Sof::from_raw(0xFF);
    assert_eq!(full.status, 0x1F);
    assert!(full.last_file_of_directory);
    assert!(full.name_defines_subdirectory);
    assert!(full.transfer_active);
    assert_eq!(full.raw(), 0xFF);
}

/// Clause 7.2.6.38: status 3 with LFD and FA encodes to `0xA3`.
#[test]
fn sof_status_3_with_lfd_and_fa() {
    let sof = Sof {
        status: 3,
        last_file_of_directory: true,
        name_defines_subdirectory: false,
        transfer_active: true,
    };
    assert_eq!(sof.raw(), 0xA3);
    let mut out = Vec::new();
    sof.encode(&mut out);
    assert_eq!(out, vec![0xA3]);
    assert_eq!(Sof::parse(&out).unwrap(), sof);
}

/// Clause 7.2.6.38: a fully populated `SOF` round-trips, and every prefix is too short.
#[test]
fn sof_round_trip_and_truncation() {
    let sof = Sof {
        status: 16,
        last_file_of_directory: true,
        name_defines_subdirectory: true,
        transfer_active: true,
    };
    assert_eq!(sof.raw(), 0xF0);
    let mut out = Vec::new();
    sof.encode(&mut out);
    assert_eq!(out, vec![0xF0]);
    assert_eq!(Sof::parse(&out).unwrap(), sof);
    assert_eq!(out.len(), Sof::LEN);
    assert_too_short(Sof::parse, &out);
}
