//! Qualifier information elements: IEC 60870-5-101:2003 clause 7.2.6.21–7.2.6.25
//! and 7.2.6.27.
//!
//! Every type here is one octet. Bit numbers are 1-based from the least
//! significant bit, so `QCC`'s `RQT := UI6[1..6]` is `0x3F` and `FRZ := UI2[7..8]`
//! is `0xC0`.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use iec104::asdu::{AsduError, Coi, FreezeMode, Qcc, Qoi, Qpa, Qpm, Qrp};

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

/// Clause 7.2.6.21: `COI` is one octet; the cause is `UI7[1..7]` and bit 8 is the change flag.
#[test]
fn coi_len_and_cause_range() {
    assert_eq!(Coi::LEN, 1);
    assert_eq!(Coi::LOCAL_POWER_ON, 0);
    assert_eq!(Coi::LOCAL_MANUAL_RESET, 1);
    assert_eq!(Coi::REMOTE_RESET, 2);
    let full = Coi::from_raw(0xFF);
    assert_eq!(full.cause, 127);
    assert!(full.changed_local_parameters);
    assert_eq!(full.raw(), 0xFF);
}

/// Clause 7.2.6.21: cause 2 with changed local parameters encodes to `0x82`.
#[test]
fn coi_remote_reset_after_parameter_change() {
    let coi = Coi {
        cause: 2,
        changed_local_parameters: true,
    };
    assert_eq!(coi.raw(), 0x82);
    let mut out = Vec::new();
    coi.encode(&mut out);
    assert_eq!(out, vec![0x82]);
    assert_eq!(Coi::parse(&out).unwrap(), coi);
}

/// Clause 7.2.6.21: a fully populated `COI` round-trips, and an empty buffer is too short.
#[test]
fn coi_round_trip_and_truncation() {
    let coi = Coi {
        cause: 32,
        changed_local_parameters: false,
    };
    let mut out = Vec::new();
    coi.encode(&mut out);
    assert_eq!(out, vec![0x20]);
    assert_eq!(Coi::parse(&out).unwrap(), coi);
    assert_too_short(Coi::parse, &out);
}

/// Clause 7.2.6.22: `QOI` is the whole octet; `<20>` is station-wide, `<21>`…`<36>` are groups.
#[test]
fn qoi_len_and_station_wide() {
    assert_eq!(Qoi::LEN, 1);
    assert_eq!(Qoi::STATION_INTERROGATION, 20);
    assert_eq!(Qoi::GROUP_1, 21);
    assert_eq!(Qoi::GROUP_16, 36);
    let station = Qoi { value: 20 };
    assert!(station.is_station_wide());
    assert_eq!(station.group_number(), None);
    assert!(!Qoi { value: 0 }.is_station_wide());
}

/// Clause 7.2.6.22: `Qoi::group(1)` is 21; group 16 is 36; out-of-range `n` clamps.
#[test]
fn qoi_group_clamps_into_1_to_16() {
    assert_eq!(Qoi::group(1).value, 21);
    assert_eq!(Qoi::group(1).group_number(), Some(1));
    assert_eq!(Qoi::group(16).value, 36);
    assert_eq!(Qoi { value: 36 }.group_number(), Some(16));
    assert_eq!(Qoi { value: 20 }.group_number(), None);
    assert_eq!(Qoi { value: 37 }.group_number(), None);
    assert_eq!(Qoi::group(0).value, 21);
    assert_eq!(Qoi::group(255).value, 36);
}

/// Clause 7.2.6.22: the whole octet round-trips, including a private-range value.
#[test]
fn qoi_round_trip_and_truncation() {
    let qoi = Qoi { value: 64 };
    let mut out = Vec::new();
    qoi.encode(&mut out);
    assert_eq!(out, vec![64]);
    assert_eq!(Qoi::parse(&out).unwrap(), qoi);
    assert_eq!(Qoi::parse(&[0xFF]).unwrap().value, 255);
    assert_too_short(Qoi::parse, &out);
}

/// Clause 7.2.6.23: `FRZ` maps `<0>`…`<3>` onto read / freeze / freeze-reset / reset.
#[test]
fn freeze_mode_maps_all_four() {
    assert_eq!(FreezeMode::from_bits(0), FreezeMode::Read);
    assert_eq!(FreezeMode::from_bits(1), FreezeMode::FreezeWithoutReset);
    assert_eq!(FreezeMode::from_bits(2), FreezeMode::FreezeWithReset);
    assert_eq!(FreezeMode::from_bits(3), FreezeMode::Reset);
    assert_eq!(FreezeMode::Read.to_bits(), 0);
    assert_eq!(FreezeMode::FreezeWithReset.to_bits(), 2);
    assert_eq!(FreezeMode::Reset.to_bits(), 3);
}

/// Clause 7.2.6.23: `QCC` is one octet; `RQT` is `UI6[1..6]` and `FRZ` is `UI2[7..8]`.
#[test]
fn qcc_len_and_field_masks() {
    assert_eq!(Qcc::LEN, 1);
    assert_eq!(Qcc::GENERAL_REQUEST, 5);
    let decoded = Qcc::from_raw(0xFF);
    assert_eq!(decoded.rqt, 63);
    assert_eq!(decoded.frz, FreezeMode::Reset);
    assert_eq!(decoded.raw(), 0xFF);
    assert_eq!(
        Qcc {
            rqt: 5,
            frz: FreezeMode::Read
        }
        .raw(),
        0x05
    );
}

/// Clause 7.2.6.23: general request + freeze with reset is `0x85` (`RQT` 5, `FRZ` 2 in bits 7–8).
#[test]
fn qcc_general_request_freeze_with_reset() {
    let qcc = Qcc {
        rqt: 5,
        frz: FreezeMode::FreezeWithReset,
    };
    assert_eq!(qcc.raw(), 0x85);
    assert_eq!(Qcc::from_raw(0x85), qcc);
    let mut out = Vec::new();
    qcc.encode(&mut out);
    assert_eq!(out, vec![0x85]);
}

/// Clause 7.2.6.23: `counter_group` clamps `n` into 1..=4 and leaves `FRZ` at Read.
#[test]
fn qcc_counter_group_clamps() {
    assert_eq!(Qcc::counter_group(1).rqt, 1);
    assert_eq!(Qcc::counter_group(1).frz, FreezeMode::Read);
    assert_eq!(Qcc::counter_group(4).rqt, 4);
    assert_eq!(Qcc::counter_group(0).rqt, 1);
    assert_eq!(Qcc::counter_group(9).rqt, 4);
    assert_eq!(Qcc::counter_group(4).raw(), 0x04);
}

/// Clause 7.2.6.23: a fully populated `QCC` round-trips.
#[test]
fn qcc_round_trip_and_truncation() {
    let qcc = Qcc {
        rqt: 32,
        frz: FreezeMode::FreezeWithoutReset,
    };
    let mut out = Vec::new();
    qcc.encode(&mut out);
    assert_eq!(out, vec![0x60]);
    assert_eq!(Qcc::parse(&out).unwrap(), qcc);
    assert_too_short(Qcc::parse, &out);
}

/// Clause 7.2.6.24: `QPM` kind constants, and THRESHOLD + LPC is `0x41`.
#[test]
fn qpm_threshold_plus_lpc() {
    assert_eq!(Qpm::LEN, 1);
    assert_eq!(Qpm::THRESHOLD, 1);
    assert_eq!(Qpm::SMOOTHING_FACTOR, 2);
    assert_eq!(Qpm::LOW_LIMIT, 3);
    assert_eq!(Qpm::HIGH_LIMIT, 4);
    let qpm = Qpm {
        kpa: Qpm::THRESHOLD,
        local_parameter_change: true,
        parameter_not_in_operation: false,
    };
    assert_eq!(qpm.raw(), 0x41);
    assert_eq!(Qpm::from_raw(0x41), qpm);
}

/// Clause 7.2.6.24: `KPA` is `UI6[1..6]`, `LPC` is bit 7, `POP` is bit 8.
#[test]
fn qpm_field_masks_and_round_trip() {
    let full = Qpm::from_raw(0xFF);
    assert_eq!(full.kpa, 63);
    assert!(full.local_parameter_change);
    assert!(full.parameter_not_in_operation);
    assert_eq!(full.raw(), 0xFF);
    let mut out = Vec::new();
    full.encode(&mut out);
    assert_eq!(out, vec![0xFF]);
    assert_eq!(Qpm::parse(&out).unwrap(), full);
    assert_too_short(Qpm::parse, &out);
}

/// Clause 7.2.6.25: `QPA` is the whole octet, with the three named values.
#[test]
fn qpa_len_constants_and_round_trip() {
    assert_eq!(Qpa::LEN, 1);
    assert_eq!(Qpa::PREVIOUSLY_LOADED, 1);
    assert_eq!(Qpa::ADDRESSED_OBJECT, 2);
    assert_eq!(Qpa::PERSISTENT_CYCLIC, 3);
    let qpa = Qpa {
        value: Qpa::PERSISTENT_CYCLIC,
    };
    let mut out = Vec::new();
    qpa.encode(&mut out);
    assert_eq!(out, vec![0x03]);
    assert_eq!(Qpa::parse(&out).unwrap(), qpa);
    assert_eq!(Qpa::parse(&[0x80]).unwrap().value, 128);
    assert_too_short(Qpa::parse, &out);
}

/// Clause 7.2.6.27: `QRP` is the whole octet; general reset is `<1>`, pending is `<2>`.
#[test]
fn qrp_len_constants_and_round_trip() {
    assert_eq!(Qrp::LEN, 1);
    assert_eq!(Qrp::GENERAL_RESET, 1);
    assert_eq!(Qrp::RESET_PENDING_INFORMATION, 2);
    let qrp = Qrp {
        value: Qrp::RESET_PENDING_INFORMATION,
    };
    let mut out = Vec::new();
    qrp.encode(&mut out);
    assert_eq!(out, vec![0x02]);
    assert_eq!(Qrp::parse(&out).unwrap(), qrp);
    assert_eq!(Qrp::parse(&[0xFF]).unwrap().value, 255);
    assert_too_short(Qrp::parse, &out);
}
