//! Wire vectors taken from public vendor documentation.
//!
//! Source: Beckhoff Information System, "IEC 60870-5-104 telegram structure"
//! (TF6500 `TwinCAT` 3 IEC 60870-5-10x), sections "Simple samples and
//! explanations". Byte strings are reproduced as published examples; the
//! decoding expectations below are our own reading of the documented layout.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::as_conversions)]

use iec104::apci::{self, Apci, SeqNo, UFunction};
use iec104::asdu::{Cause, Header, TypeId};

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
        .collect()
}

/// Beckhoff sample 1: counter interrogation command, I-format.
#[test]
fn sample_1_counter_interrogation() {
    let bytes = hex("68 0E 4E 14 7C 00 65 01 0A 00 0C 00 00 00 00 05");
    let (apdu, used) = apci::parse(&bytes).expect("parse");
    assert_eq!(used, bytes.len());

    assert_eq!(
        apdu.apci,
        Apci::I {
            ns: SeqNo::new(2599),
            nr: SeqNo::new(62)
        }
    );

    let h = Header::parse(apdu.asdu).expect("asdu header");
    assert_eq!(h.type_id, TypeId::CCiNa1);
    assert_eq!(h.count, 1);
    assert!(!h.sequence);
    assert_eq!(h.cause, Cause::ActivationTermination);
    assert!(!h.negative);
    assert!(!h.test);
    assert_eq!(h.originator, 0);
    assert_eq!(h.common_address, 12);
    assert_eq!(&apdu.asdu[6..], &[0x00, 0x00, 0x00, 0x05]);

    // Round-trip through the encoder.
    let mut out = Vec::new();
    apdu.encode(&mut out).expect("encode");
    assert_eq!(out, bytes);
}

/// Beckhoff sample 2: spontaneous scaled measured values, 7 objects, I-format.
#[test]
fn sample_2_spontaneous_measured_values() {
    let bytes = hex(
        "68 34 5A 14 7C 00 0B 07 03 00 0C 00 10 30 00 BE 09 00 11 30 00 90 09 00 \
         0E 30 00 75 00 00 28 30 00 25 09 00 29 30 00 75 00 00 0F 30 00 0F 0A 00 \
         2E 30 00 AE 05 00",
    );
    let (apdu, used) = apci::parse(&bytes).expect("parse");
    assert_eq!(used, 54);
    assert_eq!(
        apdu.apci,
        Apci::I {
            ns: SeqNo::new(2605),
            nr: SeqNo::new(62)
        }
    );

    let h = Header::parse(apdu.asdu).expect("asdu header");
    assert_eq!(h.type_id, TypeId::MMeNb1);
    assert_eq!(h.count, 7);
    assert_eq!(h.cause, Cause::Spontaneous);
    assert_eq!(h.common_address, 12);

    // 6-octet header + 7 * (3-octet IOA + 3-octet value+QDS)
    assert_eq!(apdu.asdu.len(), 6 + 7 * 6);
    assert_eq!(iec104::asdu::read_ioa(&apdu.asdu[6..]).unwrap(), 0x3010);
}

/// Beckhoff sample 3: S-format acknowledgement.
#[test]
fn sample_3_s_format() {
    let bytes = hex("68 04 01 00 7E 14");
    let (apdu, used) = apci::parse(&bytes).expect("parse");
    assert_eq!(used, 6);
    assert_eq!(
        apdu.apci,
        Apci::S {
            nr: SeqNo::new(2623)
        }
    );
    assert_eq!(apdu.asdu, []);
}

/// All six U-format functions encode and decode symmetrically, and the known
/// control octets from the standard are reproduced.
#[test]
fn u_format_round_trip() {
    let expected = [
        (UFunction::StartDtAct, 0x07u8),
        (UFunction::StartDtCon, 0x0B),
        (UFunction::StopDtAct, 0x13),
        (UFunction::StopDtCon, 0x23),
        (UFunction::TestFrAct, 0x43),
        (UFunction::TestFrCon, 0x83),
    ];
    for (func, code) in expected {
        let apdu = apci::Apdu {
            apci: Apci::U(func),
            asdu: &[],
        };
        let mut out = Vec::new();
        apdu.encode(&mut out).expect("encode");
        assert_eq!(out, vec![0x68, 0x04, code, 0x00, 0x00, 0x00]);
        let (parsed, n) = apci::parse(&out).expect("parse");
        assert_eq!(n, 6);
        assert_eq!(parsed.apci, Apci::U(func));
    }
}

/// A truncated frame must report Incomplete (stream framing wants to retry),
/// and a bad start octet or length must be a hard error.
#[test]
fn framing_errors() {
    let full = hex("68 0E 4E 14 7C 00 65 01 0A 00 0C 00 00 00 00 05");
    for cut in 1..full.len() {
        match apci::parse(&full[..cut]) {
            Err(apci::ParseError::Incomplete { needed, have }) => {
                assert_eq!(have, cut);
                assert_eq!(needed, if cut < 2 { 2 } else { 2 + full[1] as usize });
            }
            other => panic!("cut {cut}: expected Incomplete, got {other:?}"),
        }
    }
    assert_eq!(
        apci::parse(&[0x00, 0x04, 0, 0, 0, 0]),
        Err(apci::ParseError::BadStart(0))
    );
    assert_eq!(apci::apdu_len(0x68, 3), Err(apci::ParseError::BadLength(3)));
    assert_eq!(
        apci::apdu_len(0x68, 254),
        Err(apci::ParseError::BadLength(254))
    );
    assert_eq!(apci::apdu_len(0x68, 253), Ok(255));
}

/// Sequence numbers are 15 bits wide and wrap at 32768.
#[test]
fn sequence_numbers_wrap_at_15_bits() {
    assert_eq!(SeqNo::new(0xFFFF).get(), 0x7FFF);
    assert_eq!(SeqNo::new(32767).next(), SeqNo::new(0));
    // N(S) = 32767 must not bleed into the format flag.
    let cf = Apci::I {
        ns: SeqNo::new(32767),
        nr: SeqNo::new(0),
    }
    .control_field();
    assert_eq!(cf[0] & 0x01, 0, "low bit is the I-format flag, must stay 0");
    assert_eq!(
        cf,
        [0xFE, 0xFF, 0x00, 0x00],
        "all 15 counter bits on the wire"
    );
}

/// Every N(S)/N(R) value survives encode → parse, for I- and S-format frames.
#[test]
fn every_sequence_number_round_trips_through_the_wire() {
    for n in 0..=0x7FFF_u16 {
        let other = SeqNo::new(0x7FFF - n);
        for apci in [
            Apci::I {
                ns: SeqNo::new(n),
                nr: other,
            },
            Apci::I {
                ns: other,
                nr: SeqNo::new(n),
            },
            Apci::S { nr: SeqNo::new(n) },
        ] {
            let mut frame = vec![0x68, 0x04];
            frame.extend_from_slice(&apci.control_field());
            if apci.is_i_format() {
                frame[1] = 0x0E;
                frame.extend_from_slice(&[
                    0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14,
                ]);
            }
            let (apdu, _) = apci::parse(&frame).expect("parse");
            assert_eq!(apdu.apci, apci, "n = {n}");
        }
    }
}

/// Header round-trip including the flags.
#[test]
fn header_round_trip() {
    let h = Header {
        type_id: TypeId::MMeNc1,
        sequence: true,
        count: 3,
        cause: Cause::Activation,
        negative: true,
        test: true,
        originator: 7,
        common_address: 4711,
    };
    let mut out = Vec::new();
    h.encode(&mut out).expect("the header encodes");
    assert_eq!(out.len(), Header::LEN);
    assert_eq!(Header::parse(&out).unwrap(), h);
}
