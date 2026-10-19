//! Conformance tests derived from the standard itself.
//!
//! Sources:
//! - IEC 60870-5-104:2006 clause 5 (APDU/APCI geometry, control-field formats),
//!   clause 5.4/5.5 and the clause 9 interoperability list (parameters),
//!   clause 6 / tables 1–6 (ASDU selection).
//! - IEC 60870-5-101:2003 clause 7.2.1 / tables 8–13 (type identifications),
//!   clause 7.2.3 / table 14 (cause of transmission).
//!
//! Every expected value here is read from the standard, not from vendor
//! documentation: working from vendor documentation alone once put the
//! set-point type identifiers one place too high (49/50 for what the standard
//! numbers 48/49).

use iec104::apci::{self, Apci, Apdu, MAX_APDU, MAX_ASDU, ParseError, SeqNo};
use iec104::asdu::{CATALOGUE, Cause, Header, TypeId, TypeRange};
use iec104::params::{LinkParams, PORT, ParamError, T3_RECOMMENDED_MAX};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Clause 6 / 5-101 tables: type identifications
// ---------------------------------------------------------------------------

/// 5-101 table 9: 48 `C_SE_NA_1`, 49 `C_SE_NB_1`, 50 `C_SE_NC_1`.
///
/// Pins the numbering against the off-by-one that reads 49 as `C_SE_NA_1` and
/// 50 as `C_SE_NB_1`.
#[test]
fn setpoint_commands_use_the_standard_numbers() {
    assert_eq!(TypeId::from_u8(48), TypeId::CSeNa1);
    assert_eq!(TypeId::from_u8(49), TypeId::CSeNb1);
    assert_eq!(TypeId::from_u8(50), TypeId::CSeNc1);
    assert_eq!(TypeId::CSeNa1.name(), "C_SE_NA_1");
    assert_eq!(TypeId::CSeNb1.name(), "C_SE_NB_1");
    assert_eq!(TypeId::CSeNc1.name(), "C_SE_NC_1");
    assert_eq!(TypeId::CSeNa1.to_u8(), 48);
    assert_eq!(TypeId::CSeNb1.to_u8(), 49);
    assert_eq!(TypeId::CSeNc1.to_u8(), 50);
}

/// Every catalogue row must round-trip through the enum, and the names must be
/// the standard's spelling. This is the check that keeps the catalogue table
/// and the `from_u8`/`to_u8` matches from drifting apart.
#[test]
fn catalogue_round_trips() {
    for t in CATALOGUE {
        let id = TypeId::from_u8(t.id);
        assert_eq!(id.to_u8(), t.id, "{} round-trip", t.name);
        assert_eq!(id.name(), t.name, "name of {}", t.name);
    }
    assert_eq!(CATALOGUE.len(), 67, "named type identifications");
}

/// The set of type identifications 5-104 clause 6 selects must be exactly the
/// union of tables 1–6: no more (nothing invented) and no less.
#[test]
fn selection_matches_clause_6_tables() {
    let mut selected: Vec<u8> = CATALOGUE
        .iter()
        .filter(|t| t.selected_104)
        .map(|t| t.id)
        .collect();
    selected.sort_unstable();

    let mut expected: Vec<u8> = Vec::new();
    expected.extend([1, 3, 5, 7, 9, 11, 13, 15, 20, 21]); // table 1, untagged
    expected.extend(30..=40); // table 1, CP56Time2a
    expected.extend(45..=51); // table 2, untagged commands
    expected.extend(58..=64); // table 2, time-tagged commands
    expected.push(70); // table 3
    expected.extend([100, 101, 102, 103, 105, 107]); // table 4 (no 104, no 106)
    expected.extend(110..=113); // table 5
    expected.extend(120..=127); // table 6
    expected.sort_unstable();

    assert_eq!(selected, expected);
}

/// 104 does not select the `CP24Time2a` monitor types; they stay named because a
/// peer can still send them.
#[test]
fn cp24_monitor_types_are_named_but_not_selected() {
    for id in [2u8, 4, 6, 8, 10, 12, 14, 16, 17, 18, 19] {
        let t = TypeId::from_u8(id);
        assert!(t.info().is_some(), "{id} should be named");
        assert!(!t.is_selected_104(), "{id} must not be selected by 104");
    }
}

/// Directions and the CON marker, straight out of the tables.
#[test]
fn directions_and_confirmed_services() {
    assert!(!TypeId::MSpNa1.is_confirmed());
    assert!(TypeId::CScNa1.is_confirmed());
    assert!(TypeId::CIcNa1.is_confirmed());
    // 104 lists the read command without the CON mark (101 marks it CON).
    assert!(!TypeId::CRdNa1.is_confirmed());

    assert_eq!(
        TypeId::MMeTf1.direction(),
        Some(iec104::asdu::Direction::Monitor)
    );
    assert_eq!(
        TypeId::CSeNb1.direction(),
        Some(iec104::asdu::Direction::Control)
    );
    assert_eq!(
        TypeId::FSgNa1.direction(),
        Some(iec104::asdu::Direction::Both)
    );
    // Not a named type.
    assert_eq!(TypeId::from_u8(200).direction(), None);
}

/// Reserved, routing and private ranges, and the `Other` pass-through.
#[test]
fn unnamed_type_identifications_pass_through() {
    let unknown = TypeId::from_u8(22);
    assert_eq!(unknown, TypeId::Other(22));
    assert_eq!(unknown.to_u8(), 22);
    assert_eq!(unknown.name(), "reserved");

    assert_eq!(TypeId::from_u8(0).name(), "not defined");
    assert_eq!(TypeId::from_u8(130).name(), "routing (private)");
    assert_eq!(TypeId::from_u8(200).name(), "private");
    assert_eq!(iec104::asdu::range_of(41), TypeRange::Reserved);
    // 127 is reserved in 101 but Query Log in 104.
    assert_eq!(TypeId::from_u8(127).name(), "F_SC_NB_1");
}

// ---------------------------------------------------------------------------
// 5-101 table 14: cause of transmission
// ---------------------------------------------------------------------------

#[test]
fn cause_table_matches_101_table_14() {
    let table: [(u8, Cause); 20] = [
        (1, Cause::Periodic),
        (2, Cause::BackgroundScan),
        (3, Cause::Spontaneous),
        (4, Cause::Initialized),
        (5, Cause::Request),
        (6, Cause::Activation),
        (7, Cause::ActivationCon),
        (8, Cause::Deactivation),
        (9, Cause::DeactivationCon),
        (10, Cause::ActivationTermination),
        (11, Cause::ReturnInfoRemote),
        (12, Cause::ReturnInfoLocal),
        (13, Cause::FileTransfer),
        (20, Cause::InterrogatedByStation),
        (37, Cause::RequestedByGeneralCounter),
        (44, Cause::UnknownTypeId),
        (45, Cause::UnknownCause),
        (46, Cause::UnknownCommonAddress),
        (47, Cause::UnknownInformationObjectAddress),
        (0, Cause::NotUsed),
    ];
    for (raw, cause) in table {
        assert_eq!(Cause::from_u8(raw), cause, "cause {raw}");
        assert_eq!(cause.to_u8(), raw, "cause {raw} round-trip");
    }

    // Group interrogations 21..=36 and counter groups 38..=41.
    for group in 1..=16u8 {
        let raw = 20 + group;
        assert_eq!(Cause::from_u8(raw), Cause::InterrogatedByGroup(group));
        assert_eq!(Cause::InterrogatedByGroup(group).to_u8(), raw);
    }
    for group in 1..=4u8 {
        let raw = 37 + group;
        assert_eq!(Cause::from_u8(raw), Cause::RequestedByCounterGroup(group));
        assert_eq!(Cause::RequestedByCounterGroup(group).to_u8(), raw);
    }

    // 14..=19 and 42..=43 are reserved, 48..=63 private.
    for raw in [14u8, 19, 42, 43] {
        assert_eq!(Cause::from_u8(raw), Cause::Reserved(raw));
    }
    for raw in [48u8, 63] {
        assert_eq!(Cause::from_u8(raw), Cause::Private(raw));
    }
    // The field is six bits: the P/N and T bits must not leak into the cause.
    assert_eq!(Cause::from_u8(0xC0 | 3), Cause::Spontaneous);
}

/// Table 14's last column, transcribed row by row (5-101 printed page 40).
/// The causes it leaves blank (`<0>`, the reserved ranges, `<44..47>` and the
/// private range) have no mnemonic.
#[test]
fn cause_mnemonics_match_101_table_14() {
    let named: [(u8, &str); 41] = [
        (1, "per/cyc"),
        (2, "back"),
        (3, "spont"),
        (4, "init"),
        (5, "req"),
        (6, "act"),
        (7, "actcon"),
        (8, "deact"),
        (9, "deactcon"),
        (10, "actterm"),
        (11, "retrem"),
        (12, "retloc"),
        (13, "file"),
        (20, "inrogen"),
        (21, "inro1"),
        (22, "inro2"),
        (23, "inro3"),
        (24, "inro4"),
        (25, "inro5"),
        (26, "inro6"),
        (27, "inro7"),
        (28, "inro8"),
        (29, "inro9"),
        (30, "inro10"),
        (31, "inro11"),
        (32, "inro12"),
        (33, "inro13"),
        (34, "inro14"),
        (35, "inro15"),
        (36, "inro16"),
        (37, "reqcogen"),
        (38, "reqco1"),
        (39, "reqco2"),
        (40, "reqco3"),
        (41, "reqco4"),
        // Blank in the table.
        (0, ""),
        (44, ""),
        (45, ""),
        (46, ""),
        (47, ""),
        (48, ""),
    ];
    for (raw, mnemonic) in named {
        assert_eq!(Cause::from_u8(raw).mnemonic(), mnemonic, "cause {raw}");
    }
    for raw in (14..=19).chain(42..=43).chain(49..=63) {
        assert_eq!(Cause::from_u8(raw).mnemonic(), "", "cause {raw}");
    }
}

/// A group number outside the family's range is written clamped
/// (`Cause::to_u8`), and its mnemonic names the cause that goes on the wire.
#[test]
fn cause_mnemonic_agrees_with_the_written_number() {
    for cause in [
        Cause::InterrogatedByGroup(0),
        Cause::InterrogatedByGroup(17),
        Cause::RequestedByCounterGroup(0),
        Cause::RequestedByCounterGroup(9),
    ] {
        assert_eq!(
            cause.mnemonic(),
            Cause::from_u8(cause.to_u8()).mnemonic(),
            "{cause:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5-104 clause 5: APCI formats
// ---------------------------------------------------------------------------

#[test]
fn s_format_octets_must_be_exactly_0x01_0x00() {
    // Figure 7: octet 1 = 0000 0001, octet 2 = 0000 0000.
    let good = [0x68, 0x04, 0x01, 0x00, 0x7E, 0x14];
    assert_eq!(
        apci::parse(&good).unwrap().0.apci,
        Apci::S {
            nr: SeqNo::new(2623)
        }
    );

    // Any other bit in octet 1 must be rejected instead of quietly accepted as
    // an S-frame: checking the format bits alone is not enough.
    for octet1 in [0x05u8, 0x09, 0x11, 0x21, 0x41, 0x81] {
        let bad = [0x68, 0x04, octet1, 0x00, 0x00, 0x00];
        assert_eq!(
            apci::parse(&bad),
            Err(ParseError::BadSFormatOctet { octet1, octet2: 0 }),
            "octet1 {octet1:#04x}"
        );
    }
    // Octet 2 of an S-frame must be zero.
    let bad = [0x68, 0x04, 0x01, 0x01, 0x00, 0x00];
    assert_eq!(
        apci::parse(&bad),
        Err(ParseError::BadSFormatOctet {
            octet1: 0x01,
            octet2: 0x01
        })
    );
}

#[test]
fn i_format_always_carries_an_asdu() {
    // Length 4 with octet 1 bit 1 = 0: an I-frame with no ASDU at all.
    let bad = [0x68, 0x04, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(apci::parse(&bad), Err(ParseError::IFormatWithoutAsdu(4)));

    // One ASDU octet is the minimum.
    let good = [0x68, 0x05, 0x00, 0x00, 0x00, 0x00, 0x64];
    let (apdu, used) = apci::parse(&good).unwrap();
    assert_eq!(used, 7);
    assert_eq!(apdu.asdu, &[0x64]);
}

#[test]
fn only_one_u_function_may_be_set() {
    // Two function bits at once is not one of the six codes.
    for octet1 in [0x0Fu8, 0x1B, 0x63, 0xC3, 0xFF] {
        assert_eq!(
            apci::parse(&[0x68, 0x04, octet1, 0x00, 0x00, 0x00]),
            Err(ParseError::UnknownUFunction(octet1))
        );
    }
    // U-format octets 2–4 are zero.
    assert_eq!(
        apci::parse(&[0x68, 0x04, 0x07, 0x01, 0x00, 0x00]),
        Err(ParseError::ReservedOctetNotZero)
    );
}

#[test]
fn asdu_limit_is_249_octets() {
    let longest = vec![0u8; MAX_ASDU];
    let apdu = Apdu {
        apci: Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0),
        },
        asdu: &longest,
    };
    let mut out = Vec::new();
    apdu.encode(&mut out).unwrap();
    assert_eq!(out.len(), MAX_APDU);
    assert_eq!(out[1], 253);
    assert_eq!(apci::parse(&out).unwrap().1, MAX_APDU);

    let too_long = vec![0u8; MAX_ASDU + 1];
    let apdu = Apdu {
        apci: Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0),
        },
        asdu: &too_long,
    };
    assert_eq!(
        apdu.encode(&mut Vec::new()),
        Err(ParseError::AsduTooLong(MAX_ASDU + 1))
    );
}

#[test]
fn encoder_refuses_format_payload_mismatches() {
    // S/U formats consist of the APCI only.
    let s = Apdu {
        apci: Apci::S { nr: SeqNo::new(1) },
        asdu: &[0x01],
    };
    assert_eq!(
        s.encode(&mut Vec::new()),
        Err(ParseError::FormatPayloadMismatch(
            "S/U-format APDU with an ASDU"
        ))
    );
    // I format always contains an ASDU.
    let i = Apdu {
        apci: Apci::I {
            ns: SeqNo::new(1),
            nr: SeqNo::new(1),
        },
        asdu: &[],
    };
    assert_eq!(
        i.encode(&mut Vec::new()),
        Err(ParseError::FormatPayloadMismatch(
            "I-format APDU without an ASDU"
        ))
    );
}

/// The header geometry and the COT flag bits (figure 14 of 5-101).
#[test]
fn header_flag_bits_match_table_14() {
    let raw = [0x2Du8, 0x01, 0x80 | 0x40 | 6, 0x00, 0x0C, 0x00, 0, 0, 0];
    let h = Header::parse(&raw).unwrap();
    assert_eq!(h.type_id, TypeId::CScNa1);
    assert_eq!(h.cause, Cause::Activation);
    assert!(h.test, "bit 8 is the test flag");
    assert!(h.negative, "bit 7 is the negative-confirm flag");
    assert_eq!(h.common_address, 12);
    assert_eq!(h.count, 1);
    assert!(!h.sequence);
}

// ---------------------------------------------------------------------------
// Clause 5.4, 5.5 and the interoperability parameter list
// ---------------------------------------------------------------------------

#[test]
fn default_link_parameters_are_the_standard_values() {
    let p = LinkParams::default();
    assert_eq!(p.port, PORT);
    assert_eq!(p.port, 2404);
    assert_eq!(p.k, 12);
    assert_eq!(p.w, 8);
    assert_eq!(p.t0, Duration::from_secs(30));
    assert_eq!(p.t1, Duration::from_secs(15));
    assert_eq!(p.t2, Duration::from_secs(10));
    assert_eq!(p.t3, Duration::from_secs(20));
    assert_eq!(p.validate(), Ok(()));
    assert!(p.w_within_recommendation(), "8 <= 2/3 * 12");
    assert_eq!(LinkParams::max_k(), 32767);
}

#[test]
fn parameter_ranges_are_enforced() {
    let p = LinkParams {
        k: 0,
        ..LinkParams::default()
    };
    assert_eq!(p.validate(), Err(ParamError::KOutOfRange(0)));

    let p = LinkParams {
        k: 32768,
        ..LinkParams::default()
    };
    assert_eq!(p.validate(), Err(ParamError::KOutOfRange(32768)));

    let p = LinkParams {
        w: 32768,
        ..LinkParams::default()
    };
    assert_eq!(p.validate(), Err(ParamError::WOutOfRange(32768)));

    // t0 … t2 maximum range is 1 s … 255 s.
    let p = LinkParams {
        t1: Duration::from_secs(256),
        ..LinkParams::default()
    };
    assert_eq!(
        p.validate(),
        Err(ParamError::TimeoutOutOfRange {
            which: "t1",
            secs: 256
        })
    );

    // The table states t2 < t1.
    let p = LinkParams {
        t1: Duration::from_secs(10),
        t2: Duration::from_secs(10),
        ..LinkParams::default()
    };
    assert_eq!(
        p.validate(),
        Err(ParamError::T2NotLessThanT1 { t1: 10, t2: 10 })
    );

    // t3 has a recommended (not normative) upper bound of 48 h.
    let p = LinkParams {
        t3: T3_RECOMMENDED_MAX + Duration::from_secs(1),
        ..LinkParams::default()
    };
    assert_eq!(
        p.validate(),
        Err(ParamError::T3OutOfRecommendedRange(48 * 3600 + 1))
    );

    // A control station may use an ephemeral local port; only the server side
    // is pinned to 2404, so port is not validated here.
    let p = LinkParams {
        port: 0,
        ..LinkParams::default()
    };
    assert_eq!(p.validate(), Ok(()));
}
