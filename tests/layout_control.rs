//! The per-type ASDU layouts of IEC 60870-5-101:2003 clauses 7.3.2–7.3.5 and
//! the eight types IEC 60870-5-104:2006 clause 8 adds.
//!
//! Clause 7.3.2 is the process information of the **control** direction (the
//! seven command ASDUs 45–51), 7.3.3 is the system information in the monitor
//! direction (`M_EI_NA_1`, type 70), 7.3.4 is the system information in the
//! control direction (types 100–106) and 7.3.5 the parameters (110–113).
//! 5-104 clause 8 adds the time-tagged command forms 58–64 and the time-tagged
//! test command 107.
//!
//! The octet counts asserted below are the sums of the clause 7.2.6 element
//! `LEN` constants, read one type at a time from the definition lines on PDF
//! page indices 99–113 of 5-101 and 76–90 of 5-104:
//!
//! ```text
//! §        type  ASDU         elements                         octets
//! 7.3.2.1   45  C_SC_NA_1     SCO                                 1
//! 7.3.2.2   46  C_DC_NA_1     DCO                                 1
//! 7.3.2.3   47  C_RC_NA_1     RCO                                 1
//! 7.3.2.4   48  C_SE_NA_1     NVA, QOS                            3
//! 7.3.2.5   49  C_SE_NB_1     SVA, QOS                            3
//! 7.3.2.6   50  C_SE_NC_1     R32 (IEEE STD 754), QOS             5
//! 7.3.2.7   51  C_BO_NA_1     BSI                                 4
//! 104 8.1   58  C_SC_TA_1     SCO, CP56Time2a                     8
//! 104 8.2   59  C_DC_TA_1     DCO, CP56Time2a                     8
//! 104 8.3   60  C_RC_TA_1     RCO, CP56Time2a                     8
//! 104 8.4   61  C_SE_TA_1     NVA, QOS, CP56Time2a               10
//! 104 8.5   62  C_SE_TB_1     SVA, QOS, CP56Time2a               10
//! 104 8.6   63  C_SE_TC_1     R32, QOS, CP56Time2a               12
//! 104 8.7   64  C_BO_TA_1     BSI, CP56Time2a                    11
//! 7.3.3.1   70  M_EI_NA_1     COI                                 1
//! 7.3.4.1  100  C_IC_NA_1     QOI                                 1
//! 7.3.4.2  101  C_CI_NA_1     QCC                                 1
//! 7.3.4.3  102  C_RD_NA_1     (none: the IOA is the payload)      0
//! 7.3.4.4  103  C_CS_NA_1     CP56Time2a                          7
//! 7.3.4.5  104  C_TS_NA_1     FBP                                 2
//! 7.3.4.6  105  C_RP_NA_1     QRP                                 1
//! 7.3.4.7  106  C_CD_NA_1     CP16Time2a                          2
//! 104 8.8  107  C_TS_TA_1     TSC, CP56Time2a                     9
//! 7.3.5.1  110  P_ME_NA_1     NVA, QPM                            3
//! 7.3.5.2  111  P_ME_NB_1     SVA, QPM                            3
//! 7.3.5.3  112  P_ME_NC_1     R32, QPM                            5
//! 7.3.5.4  113  P_AC_NA_1     QPA                                 1
//! ```
//!
//! Three rules hold for all 27 and are asserted rather than assumed: every
//! clause page prints "Single information object (SQ = 0)" and no "Number i of
//! objects" row (so `ObjectCount::Single`), no definition line has an
//! `i(...)`/`j(...)` form (so `Sequence::NotDefined`), and the octets are the
//! element layer's own `LEN` constants rather than a second hand-written table.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use iec104::asdu::{
    AsduError, AsduLayout, Bsi, CBoNa1, CBoTa1, CCdNa1, CCiNa1, CCsNa1, CDcNa1, CDcTa1, CIcNa1,
    CONTROL_LAYOUTS, CRcNa1, CRcTa1, CRdNa1, CRpNa1, CScNa1, CScTa1, CSeNa1, CSeNb1, CSeNc1,
    CSeTa1, CSeTb1, CSeTc1, CTsNa1, CTsTa1, Cause, Coi, Cp16Time2a, Cp56Time2a, Dco, Direction,
    DoubleCommandState, Fbp, FreezeMode, Header, LayoutError, LayoutObject, MEiNa1, Nva,
    ObjectCount, PAcNa1, PMeNa1, PMeNb1, PMeNc1, Qcc, Qoc, Qoi, Qos, Qpa, Qpm, Qrp, R32, Rco,
    RegulatingStepState, Sco, Sequence, Sva, Tsc, TypeId, decode_asdu, element_len, encode_asdu,
    layout_for,
};

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
        .collect()
}

/// A header of `type_id` with SQ = `sequence` and `count` objects, activation,
/// CA 12. Activation is the command direction's own cause.
const fn header(type_id: TypeId, sequence: bool, count: u8) -> Header {
    Header {
        type_id,
        sequence,
        count,
        cause: Cause::Activation,
        negative: false,
        test: false,
        originator: 0,
        common_address: 12,
    }
}

// One sample of every information element these layouts are built from. Each
// has a distinctive octet pattern, so a layout that wrote its elements in the
// wrong order (or dropped one) cannot produce the expected bytes.

const fn qoc() -> Qoc {
    Qoc {
        qu: 3,
        select: true,
    }
}

const fn sco() -> Sco {
    Sco {
        scs: true,
        qoc: qoc(),
    }
}

const fn dco() -> Dco {
    Dco {
        dcs: DoubleCommandState::On,
        qoc: Qoc {
            qu: 5,
            select: false,
        },
    }
}

const fn rco() -> Rco {
    Rco {
        rcs: RegulatingStepState::Lower,
        qoc: Qoc {
            qu: 0,
            select: true,
        },
    }
}

const fn qos() -> Qos {
    Qos {
        ql: 0x0A,
        select: true,
    }
}

const fn nva() -> Nva {
    Nva { value: 0x1234 }
}

const fn sva() -> Sva {
    Sva { value: 0x2345 }
}

const fn r32() -> R32 {
    R32 { value: 1.5 }
}

const fn bsi() -> Bsi {
    Bsi { bits: 0x0A0B_0C0D }
}

const fn coi() -> Coi {
    Coi {
        cause: Coi::REMOTE_RESET,
        changed_local_parameters: true,
    }
}

const fn qoi() -> Qoi {
    Qoi {
        value: Qoi::STATION_INTERROGATION,
    }
}

const fn qcc() -> Qcc {
    Qcc {
        rqt: Qcc::GENERAL_REQUEST,
        frz: FreezeMode::FreezeWithReset,
    }
}

const fn qpm() -> Qpm {
    Qpm {
        kpa: Qpm::THRESHOLD,
        local_parameter_change: false,
        parameter_not_in_operation: false,
    }
}

const fn qpa() -> Qpa {
    Qpa {
        value: Qpa::ADDRESSED_OBJECT,
    }
}

const fn qrp() -> Qrp {
    Qrp {
        value: Qrp::GENERAL_RESET,
    }
}

const fn elapsed() -> Cp16Time2a {
    Cp16Time2a {
        milliseconds: 0x0102,
    }
}

const fn tsc() -> Tsc {
    Tsc { value: 0x0102 }
}

/// The same seven-octet time tag `tests/layout.rs` uses: 0x0506 ms (`06 05`),
/// 7 min, invalid, 8 h, day 9, day-of-week 3, month 10, year 11. Chosen for its
/// distinctive octets, not for a real instant.
const fn cp56() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 0x0506,
        minutes: 7,
        substituted: false,
        invalid: true,
        hours: 8,
        summer_time: false,
        day_of_month: 9,
        day_of_week: 3,
        months: 10,
        years: 11,
    }
}

/// One layout's whole contract at once: the octet count the clause's page
/// gives, the exact wire octets in definition-line order, a round trip, and
/// every short prefix a typed `TooShort` rather than a panic.
fn check<A: AsduLayout + PartialEq + std::fmt::Debug>(value: &A, expected: &[u8]) {
    assert_eq!(
        A::LEN,
        expected.len(),
        "AsduLayout::LEN against the clause page's octet count"
    );
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, expected, "wire octets in definition-line order");
    assert_eq!(&A::parse(expected).expect("parse"), value, "round trip");
    for cut in 0..A::LEN {
        assert_eq!(
            A::parse(&expected[..cut]),
            Err(AsduError::TooShort {
                need: A::LEN,
                have: cut
            }),
            "a prefix of {cut} octets must be a typed error"
        );
    }
    // Octets beyond LEN are ignored, exactly as every clause 7.2.6 parser
    // ignores them (the layout module's stated contract).
    let mut surplus = expected.to_vec();
    surplus.push(0xFF);
    assert_eq!(&A::parse(&surplus).expect("surplus ignored"), value);
}

/// Every one of the 27 layouts, byte for byte, in the order its definition line
/// lists its elements.
#[test]
fn every_control_layout_reads_and_writes_its_definition_line() {
    // 7.3.2.1 C_SC_NA_1 := CP{…,Information object address,SCO}
    check(&CScNa1 { sco: sco() }, &hex("8D"));
    // 7.3.2.2 C_DC_NA_1 := CP{…,Information object address,DCO}
    check(&CDcNa1 { dco: dco() }, &hex("16"));
    // 7.3.2.3 C_RC_NA_1 := CP{…,Information object address,RCO}
    check(&CRcNa1 { rco: rco() }, &hex("81"));
    // 7.3.2.4 C_SE_NA_1 := CP{…,Information object address,NVA,QOS}
    check(
        &CSeNa1 {
            nva: nva(),
            qos: qos(),
        },
        &hex("34 12 8A"),
    );
    // 7.3.2.5 C_SE_NB_1 := CP{…,Information object address,SVA,QOS}
    check(
        &CSeNb1 {
            sva: sva(),
            qos: qos(),
        },
        &hex("45 23 8A"),
    );
    // 7.3.2.6 C_SE_NC_1 := CP{…,Information object address,IEEE STD 754,QOS}
    check(
        &CSeNc1 {
            r32: r32(),
            qos: qos(),
        },
        &hex("00 00 C0 3F 8A"),
    );
    // 7.3.2.7 C_BO_NA_1 := CP{…,Information object address,BSI}
    check(&CBoNa1 { bsi: bsi() }, &hex("0D 0C 0B 0A"));
    check_time_tagged_command_layouts();
    // 7.3.3.1 M_EI_NA_1 := CP{…,Information object address,COI}
    check(&MEiNa1 { coi: coi() }, &hex("82"));
    // 7.3.4.1 C_IC_NA_1 := CP{…,Information object address,QOI}
    check(&CIcNa1 { qoi: qoi() }, &hex("14"));
    // 7.3.4.2 C_CI_NA_1 := CP{…,Information object address,QCC}
    check(&CCiNa1 { qcc: qcc() }, &hex("85"));
    // 7.3.4.3 C_RD_NA_1 := CP{Data unit identifier,Information object address}
    check(&CRdNa1, &[]);
    // 7.3.4.4 C_CS_NA_1 := CP{…,Information object address,CP56Time2a}
    check(&CCsNa1 { time: cp56() }, &hex("06 05 87 08 69 0A 0B"));
    // 7.3.4.5 C_TS_NA_1 := CP{…,Information object address,FBP}
    check(&CTsNa1 { fbp: Fbp }, &hex("AA 55"));
    // 7.3.4.6 C_RP_NA_1 := CP{…,Information object address,QRP}
    check(&CRpNa1 { qrp: qrp() }, &hex("01"));
    // 7.3.4.7 C_CD_NA_1 := CP{…,Information object address,CP16Time2a}
    check(&CCdNa1 { elapsed: elapsed() }, &hex("02 01"));
    // 5-104 8.8 C_TS_TA_1 := CP{…,Information object address,TSC,CP56Time2a}
    check(
        &CTsTa1 {
            tsc: tsc(),
            time: cp56(),
        },
        &hex("02 01 06 05 87 08 69 0A 0B"),
    );
    // 7.3.5.1 P_ME_NA_1 := CP{…,Information object address,NVA,QPM}
    check(
        &PMeNa1 {
            nva: nva(),
            qpm: qpm(),
        },
        &hex("34 12 01"),
    );
    // 7.3.5.2 P_ME_NB_1 := CP{…,Information object address,SVA,QPM}
    check(
        &PMeNb1 {
            sva: sva(),
            qpm: qpm(),
        },
        &hex("45 23 01"),
    );
    // 7.3.5.3 P_ME_NC_1 := CP{…,Information object address,IEEE STD 754,QPM}
    check(
        &PMeNc1 {
            r32: r32(),
            qpm: qpm(),
        },
        &hex("00 00 C0 3F 01"),
    );
    // 7.3.5.4 P_AC_NA_1 := CP{…,Information object address,QPA}
    check(&PAcNa1 { qpa: qpa() }, &hex("02"));
}

/// The time-tagged commands of 5-104 clauses 8.1 to 8.7.
fn check_time_tagged_command_layouts() {
    // 5-104 8.1 C_SC_TA_1 := CP{…,Information object address,SCO,CP56Time2a}
    check(
        &CScTa1 {
            sco: sco(),
            time: cp56(),
        },
        &hex("8D 06 05 87 08 69 0A 0B"),
    );
    // 5-104 8.2 C_DC_TA_1 := CP{…,Information object address,DCO,CP56Time2a}
    check(
        &CDcTa1 {
            dco: dco(),
            time: cp56(),
        },
        &hex("16 06 05 87 08 69 0A 0B"),
    );
    // 5-104 8.3 C_RC_TA_1 := CP{…,Information object address,RCO,CP56Time2a}
    check(
        &CRcTa1 {
            rco: rco(),
            time: cp56(),
        },
        &hex("81 06 05 87 08 69 0A 0B"),
    );
    // 5-104 8.4 C_SE_TA_1 := CP{…,Information object address,NVA,QOS,CP56Time2a}
    check(
        &CSeTa1 {
            nva: nva(),
            qos: qos(),
            time: cp56(),
        },
        &hex("34 12 8A 06 05 87 08 69 0A 0B"),
    );
    // 5-104 8.5 C_SE_TB_1 := CP{…,Information object address,SVA,QOS,CP56Time2a}
    check(
        &CSeTb1 {
            sva: sva(),
            qos: qos(),
            time: cp56(),
        },
        &hex("45 23 8A 06 05 87 08 69 0A 0B"),
    );
    // 5-104 8.6 C_SE_TC_1 := CP{…,Information object address,IEEE STD 754,QOS,CP56Time2a}
    check(
        &CSeTc1 {
            r32: r32(),
            qos: qos(),
            time: cp56(),
        },
        &hex("00 00 C0 3F 8A 06 05 87 08 69 0A 0B"),
    );
    // 5-104 8.7 C_BO_TA_1 := CP{…,Information object address,BSI,CP56Time2a}
    check(
        &CBoTa1 {
            bsi: bsi(),
            time: cp56(),
        },
        &hex("0D 0C 0B 0A 06 05 87 08 69 0A 0B"),
    );
}

/// The 27 control layouts: (ASDU name, type, `AsduLayout::LEN`, page octets, direction).
const CONTROL_GEOMETRY: &[(&str, TypeId, usize, usize, Direction)] = &[
    (
        "C_SC_NA_1",
        TypeId::CScNa1,
        CScNa1::LEN,
        1,
        Direction::Control,
    ),
    (
        "C_DC_NA_1",
        TypeId::CDcNa1,
        CDcNa1::LEN,
        1,
        Direction::Control,
    ),
    (
        "C_RC_NA_1",
        TypeId::CRcNa1,
        CRcNa1::LEN,
        1,
        Direction::Control,
    ),
    (
        "C_SE_NA_1",
        TypeId::CSeNa1,
        CSeNa1::LEN,
        3,
        Direction::Control,
    ),
    (
        "C_SE_NB_1",
        TypeId::CSeNb1,
        CSeNb1::LEN,
        3,
        Direction::Control,
    ),
    (
        "C_SE_NC_1",
        TypeId::CSeNc1,
        CSeNc1::LEN,
        5,
        Direction::Control,
    ),
    (
        "C_BO_NA_1",
        TypeId::CBoNa1,
        CBoNa1::LEN,
        4,
        Direction::Control,
    ),
    (
        "C_SC_TA_1",
        TypeId::CScTa1,
        CScTa1::LEN,
        8,
        Direction::Control,
    ),
    (
        "C_DC_TA_1",
        TypeId::CDcTa1,
        CDcTa1::LEN,
        8,
        Direction::Control,
    ),
    (
        "C_RC_TA_1",
        TypeId::CRcTa1,
        CRcTa1::LEN,
        8,
        Direction::Control,
    ),
    (
        "C_SE_TA_1",
        TypeId::CSeTa1,
        CSeTa1::LEN,
        10,
        Direction::Control,
    ),
    (
        "C_SE_TB_1",
        TypeId::CSeTb1,
        CSeTb1::LEN,
        10,
        Direction::Control,
    ),
    (
        "C_SE_TC_1",
        TypeId::CSeTc1,
        CSeTc1::LEN,
        12,
        Direction::Control,
    ),
    (
        "C_BO_TA_1",
        TypeId::CBoTa1,
        CBoTa1::LEN,
        11,
        Direction::Control,
    ),
    (
        "M_EI_NA_1",
        TypeId::MEiNa1,
        MEiNa1::LEN,
        1,
        Direction::Monitor,
    ),
    (
        "C_IC_NA_1",
        TypeId::CIcNa1,
        CIcNa1::LEN,
        1,
        Direction::Control,
    ),
    (
        "C_CI_NA_1",
        TypeId::CCiNa1,
        CCiNa1::LEN,
        1,
        Direction::Control,
    ),
    (
        "C_RD_NA_1",
        TypeId::CRdNa1,
        CRdNa1::LEN,
        0,
        Direction::Control,
    ),
    (
        "C_CS_NA_1",
        TypeId::CCsNa1,
        CCsNa1::LEN,
        7,
        Direction::Control,
    ),
    (
        "C_TS_NA_1",
        TypeId::CTsNa1,
        CTsNa1::LEN,
        2,
        Direction::Control,
    ),
    (
        "C_RP_NA_1",
        TypeId::CRpNa1,
        CRpNa1::LEN,
        1,
        Direction::Control,
    ),
    (
        "C_CD_NA_1",
        TypeId::CCdNa1,
        CCdNa1::LEN,
        2,
        Direction::Control,
    ),
    (
        "C_TS_TA_1",
        TypeId::CTsTa1,
        CTsTa1::LEN,
        9,
        Direction::Control,
    ),
    (
        "P_ME_NA_1",
        TypeId::PMeNa1,
        PMeNa1::LEN,
        3,
        Direction::Control,
    ),
    (
        "P_ME_NB_1",
        TypeId::PMeNb1,
        PMeNb1::LEN,
        3,
        Direction::Control,
    ),
    (
        "P_ME_NC_1",
        TypeId::PMeNc1,
        PMeNc1::LEN,
        5,
        Direction::Control,
    ),
    (
        "P_AC_NA_1",
        TypeId::PAcNa1,
        PAcNa1::LEN,
        1,
        Direction::Control,
    ),
];

/// The geometry table itself: 27 rows, each naming its clause subsection's type
/// identification, the octet count of one information object's elements, and
/// the two addressing rules.
#[test]
fn the_layout_table_names_all_27_control_types_with_their_figure_geometry() {
    let cases = CONTROL_GEOMETRY;

    assert_eq!(cases.len(), 27, "19 5-101 layouts plus 8 of 5-104 clause 8");
    assert_eq!(CONTROL_LAYOUTS.len(), 27, "the table must have 27 rows");

    let mut seen = Vec::new();
    for (name, type_id, len, page, direction) in cases {
        let layout = layout_for(*type_id)
            .unwrap_or_else(|| panic!("{name} has no layout in CONTROL_LAYOUTS"));
        seen.push(*type_id);

        assert_eq!(layout.type_id, *type_id);
        assert_eq!(
            layout.element_len, *len,
            "{name}: CONTROL_LAYOUTS and AsduLayout::LEN must be the same number"
        );
        assert_eq!(
            layout.element_len, *page,
            "{name}: {page} octets is what the clause page adds up to"
        );
        assert_eq!(element_len(*type_id), Some(*page), "{name}: element_len()");

        // Every one of these pages prints "Single information object (SQ = 0)"
        // and gives no "Number i of objects" row, and no definition line has an
        // i(...)/j(...) form.
        assert_eq!(
            layout.sequence,
            Sequence::NotDefined,
            "{name}: no control, system or parameter ASDU has an SQ = 1 form"
        );
        assert_eq!(
            layout.count,
            ObjectCount::Single,
            "{name}: one information object only"
        );

        // The catalogue's own name and direction, so a layout cannot silently
        // be attached to the wrong type identification.
        assert_eq!(type_id.name(), *name);
        assert_eq!(type_id.direction(), Some(*direction), "{name}");
    }

    seen.sort_unstable_by_key(|t| t.to_u8());
    seen.dedup();
    assert_eq!(seen.len(), 27);
    for layout in CONTROL_LAYOUTS {
        assert!(
            cases.iter().any(|(_, t, _, _, _)| *t == layout.type_id),
            "{} is in the table but not in the list above",
            layout.type_id.name()
        );
    }
}

/// `C_RD_NA_1` (7.3.4.3) is the one layout with no element: its whole payload
/// is its information object address (clause 7.2.5: "its information object
/// address serves to address available information objects which are returned
/// in the monitor direction"). A
/// 0-octet element is the case `BodyReader::next_object(0)` exists for, and this
/// is the only type in the crate that produces it.
#[test]
fn the_zero_element_read_command_is_its_address_alone() {
    assert_eq!(CRdNa1::LEN, 0);
    assert_eq!(element_len(TypeId::CRdNa1), Some(0));

    // Header (type 102, SQ = 0, one object, request, CA 12) + IOA 0x040302.
    let asdu = hex("66 01 05 00 0C 00 02 03 04");
    let objects = decode_asdu::<CRdNa1>(&asdu).expect("read command");
    assert_eq!(objects.len(), 1);
    assert_eq!(objects[0].ioa, 0x0004_0302);
    assert_eq!(objects[0].value, CRdNa1);

    let header = Header::parse(&asdu).expect("header");
    assert_eq!(
        encode_asdu(&header, &objects).expect("encode"),
        asdu,
        "the read command's whole body is its address"
    );

    // One object of zero element octets, and not a byte more.
    assert_eq!(asdu.len(), Header::LEN + 3);
    let surplus = hex("66 01 05 00 0C 00 02 03 04 FF");
    assert_eq!(
        decode_asdu::<CRdNa1>(&surplus),
        Err(LayoutError::Asdu(AsduError::ObjectsNotExhausted {
            count: 1,
            remaining: 1
        })),
        "an octet the address cannot claim is a typed error"
    );
}

/// No control, system or parameter type has an SQ = 1 form: the pages print
/// "Single information object (SQ = 0)" and the definition lines have no
/// `j(...)`, so a sequence is refused on both paths.
#[test]
fn a_sequence_is_refused_for_a_control_type() {
    // C_SC_NA_1 with SQ = 1 and one address: the shape itself is the violation.
    let asdu = hex("2D 81 06 00 0C 00 10 30 00 8D");
    assert_eq!(
        decode_asdu::<CScNa1>(&asdu),
        Err(LayoutError::SequenceNotAllowed {
            type_id: TypeId::CScNa1
        })
    );

    let sequence_header = header(TypeId::CScNa1, true, 1);
    let one = [LayoutObject {
        ioa: 0x3010,
        value: CScNa1 { sco: sco() },
    }];
    assert_eq!(
        encode_asdu(&sequence_header, &one),
        Err(LayoutError::SequenceNotAllowed {
            type_id: TypeId::CScNa1
        })
    );

    // The same on SQ = 0: the type is legal, the sequence is not.
    let plain = hex("2D 01 06 00 0C 00 10 30 00 8D");
    assert_eq!(decode_asdu::<CScNa1>(&plain).expect("SQ = 0").len(), 1);
}

/// N = 1 is the shape a single-object type defines and N ≥ 2 is refused, the
/// same on the wire and in the writer. N = 0 is read but never written.
#[test]
fn two_objects_are_refused_for_a_control_type() {
    let value = CCsNa1 { time: cp56() };

    let one_header = header(TypeId::CCsNa1, false, 1);
    let one = [LayoutObject { ioa: 3, value }];
    let encoded = encode_asdu(&one_header, &one).expect("one object");
    assert_eq!(encoded.len(), Header::LEN + 3 + Cp56Time2a::LEN);
    let decoded = decode_asdu::<CCsNa1>(&encoded).expect("decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].ioa, 3);
    assert_eq!(decoded[0].value, value);

    // N = 0 is clause 7.2.2's "<0> := ASDU contains no INFORMATION OBJECT":
    // a received one decodes to nothing, but the writer does not produce one.
    assert!(encode_asdu::<CCsNa1>(&header(TypeId::CCsNa1, false, 0), &[]).is_err());
    let mut none = Vec::new();
    header(TypeId::CCsNa1, false, 0)
        .encode(&mut none)
        .expect("the header encodes");
    assert_eq!(none.len(), Header::LEN);
    assert_eq!(decode_asdu::<CCsNa1>(&none).expect("N = 0"), Vec::new());

    let two = [
        LayoutObject { ioa: 3, value },
        LayoutObject { ioa: 4, value },
    ];
    assert_eq!(
        encode_asdu(&header(TypeId::CCsNa1, false, 2), &two),
        Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::CCsNa1,
            count: 2
        })
    );
    // The same shape on the wire.
    let two_on_the_wire =
        hex("67 02 06 00 0C 00 03 00 00 06 05 87 08 69 0A 0B 04 00 00 06 05 87 08 69 0A 0B");
    assert_eq!(
        decode_asdu::<CCsNa1>(&two_on_the_wire),
        Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::CCsNa1,
            count: 2
        })
    );
}

/// The header of a decode must be the layout's own type, and a whole ASDU of
/// the control direction survives the header-to-values path.
#[test]
fn a_whole_command_asdu_round_trips_through_the_header() {
    let asdu_header = header(TypeId::CScNa1, false, 1);
    let objects = [LayoutObject {
        ioa: 0x3021,
        value: CScNa1 { sco: sco() },
    }];
    let encoded = encode_asdu(&asdu_header, &objects).expect("encode");
    assert_eq!(encoded.len(), Header::LEN + 3 + Sco::LEN);
    assert_eq!(decode_asdu::<CScNa1>(&encoded).expect("decode"), objects);

    // And the header/type agreement, both directions.
    assert_eq!(
        decode_asdu::<CScNa1>(&hex("67 01 06 00 0C 00 10 30 00 14")),
        Err(LayoutError::TypeMismatch {
            expected: TypeId::CScNa1,
            got: TypeId::CCsNa1
        }),
        "the ASDU is a clock synchronisation command"
    );
    assert_eq!(
        encode_asdu(&header(TypeId::CIcNa1, false, 1), &objects),
        Err(LayoutError::TypeMismatch {
            expected: TypeId::CScNa1,
            got: TypeId::CIcNa1
        })
    );
}

/// 5-104 clause 8.8's time-tagged test command: the counter is the caller's and
/// the ASDU is `TSC(2) + CP56Time2a(7)` = 9 octets. The clause says "The
/// requesting station may choose any value of TSC. The TSC in the response
/// shall match the request". That is why the counter is a field rather than a
/// constant, unlike `C_TS_NA_1`'s fixed pattern.
#[test]
fn the_time_tagged_test_command_carries_a_chosen_counter() {
    for counter in [0u16, 1, 0x1234, u16::MAX] {
        let header = header(TypeId::CTsTa1, false, 1);
        let objects = [LayoutObject {
            ioa: 0,
            value: CTsTa1 {
                tsc: Tsc { value: counter },
                time: cp56(),
            },
        }];
        let encoded = encode_asdu(&header, &objects).expect("encode");
        assert_eq!(encoded.len(), Header::LEN + 3 + 9);
        assert_eq!(
            &encoded[Header::LEN + 3..Header::LEN + 5],
            &counter.to_le_bytes(),
            "the counter is little-endian, 5-104 cl.8.8"
        );
        assert_eq!(decode_asdu::<CTsTa1>(&encoded).expect("decode"), objects);
    }
}

/// The three rules that hold for all 27, read off the table rather than the
/// per-type tests: no sequence form, one object, and an octet count that is the
/// element layer's own sum rather than a second hand-written number.
#[test]
fn the_control_table_holds_no_sequence_and_no_multi_object_row() {
    assert_eq!(CONTROL_LAYOUTS.len(), 27);
    for layout in CONTROL_LAYOUTS {
        assert_eq!(layout.sequence, Sequence::NotDefined);
        assert_eq!(layout.count, ObjectCount::Single);
        assert!(layout.element_len <= 12, "the widest control ASDU element");
    }

    // The element layer is the source of every row's number: the widest command
    // (R32 + QOS + CP56Time2a) is 4 + 1 + 7, and the narrowest (C_RD_NA_1) is 0.
    assert_eq!(
        CONTROL_LAYOUTS
            .iter()
            .map(|l| l.element_len)
            .max()
            .expect("rows"),
        R32::LEN + Qos::LEN + Cp56Time2a::LEN
    );
    assert_eq!(
        CONTROL_LAYOUTS
            .iter()
            .map(|l| l.element_len)
            .min()
            .expect("rows"),
        0
    );
}

/// The writer does not produce a single-object ASDU with no object, and a
/// zero-count segment is refused by name rather than as a missing layout.
#[test]
fn a_single_object_type_is_not_written_with_no_object() {
    use iec104::asdu::{CIcNa1, Cause, Header, LayoutError, LayoutObject, TypeId, encode_asdu};
    let header = Header {
        type_id: TypeId::CIcNa1,
        sequence: false,
        count: 0,
        cause: Cause::Activation,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
    };
    let none: [LayoutObject<CIcNa1>; 0] = [];
    assert_eq!(
        encode_asdu(&header, &none),
        Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::CIcNa1,
            count: 0
        })
    );
    let empty_segment = [125, 0x00, 13, 0, 1, 0];
    assert_eq!(
        iec104::asdu::decode_segment(&empty_segment).unwrap_err(),
        LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FSgNa1,
            count: 0
        }
    );
}
