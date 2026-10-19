//! The per-type ASDU layouts of IEC 60870-5-101:2003 clause 7.3.1.
//!
//! Clause 7.3.1 defines 32 monitor-direction ASDUs (type identifications 1–21
//! and 30–40) as definition lines of the form
//!
//! ```text
//! M_ME_NC_1 := CP{Data unit identifier,i(Information object address,IEEE STD 754,QDS)}
//! ```
//!
//! where the arguments of `i(...)` are the information elements of clause
//! 7.2.6, in wire order. The octet counts asserted below are the sums of those
//! elements' `LEN` constants, read one type at a time from the definition lines
//! and the clause 7.3.1 figures on PDF page indices 60–98:
//!
//! ```text
//! §        type  ASDU         elements                          octets
//! 7.3.1.1    1  M_SP_NA_1     SIQ                                  1
//! 7.3.1.2    2  M_SP_TA_1     SIQ, CP24Time2a                      4
//! 7.3.1.3    3  M_DP_NA_1     DIQ                                  1
//! 7.3.1.4    4  M_DP_TA_1     DIQ, CP24Time2a                      4
//! 7.3.1.5    5  M_ST_NA_1     VTI, QDS                             2
//! 7.3.1.6    6  M_ST_TA_1     VTI, QDS, CP24Time2a                 5
//! 7.3.1.7    7  M_BO_NA_1     BSI, QDS                             5
//! 7.3.1.8    8  M_BO_TA_1     BSI, QDS, CP24Time2a                 8
//! 7.3.1.9    9  M_ME_NA_1     NVA, QDS                             3
//! 7.3.1.10  10  M_ME_TA_1     NVA, QDS, CP24Time2a                 6
//! 7.3.1.11  11  M_ME_NB_1     SVA, QDS                             3
//! 7.3.1.12  12  M_ME_TB_1     SVA, QDS, CP24Time2a                 6
//! 7.3.1.13  13  M_ME_NC_1     R32 (IEEE STD 754), QDS              5
//! 7.3.1.14  14  M_ME_TC_1     R32, QDS, CP24Time2a                 8
//! 7.3.1.15  15  M_IT_NA_1     BCR                                  5
//! 7.3.1.16  16  M_IT_TA_1     BCR, CP24Time2a                      8
//! 7.3.1.17  17  M_EP_TA_1     SEP, CP16Time2a, CP24Time2a          6
//! 7.3.1.18  18  M_EP_TB_1     SPE, QDP, CP16Time2a, CP24Time2a     7
//! 7.3.1.19  19  M_EP_TC_1     OCI, QDP, CP16Time2a, CP24Time2a     7
//! 7.3.1.20  20  M_PS_NA_1     SCD, QDS                             5
//! 7.3.1.21  21  M_ME_ND_1     NVA                                  2
//! 7.3.1.22  30  M_SP_TB_1     SIQ, CP56Time2a                      8
//! 7.3.1.23  31  M_DP_TB_1     DIQ, CP56Time2a                      8
//! 7.3.1.24  32  M_ST_TB_1     VTI, QDS, CP56Time2a                 9
//! 7.3.1.25  33  M_BO_TB_1     BSI, QDS, CP56Time2a                12
//! 7.3.1.26  34  M_ME_TD_1     NVA, QDS, CP56Time2a                10
//! 7.3.1.27  35  M_ME_TE_1     SVA, QDS, CP56Time2a                10
//! 7.3.1.28  36  M_ME_TF_1     R32, QDS, CP56Time2a                12
//! 7.3.1.29  37  M_IT_TB_1     BCR, CP56Time2a                     12
//! 7.3.1.30  38  M_EP_TD_1     SEP, CP16Time2a, CP56Time2a         10
//! 7.3.1.31  39  M_EP_TE_1     SPE, QDP, CP16Time2a, CP56Time2a    11
//! 7.3.1.32  40  M_EP_TF_1     OCI, QDP, CP16Time2a, CP56Time2a    11
//! ```
//!
//! Seven rows are easy to miscount, and the figures decide them:
//! `SEP`+`CP16Time2a`+`CP24Time2a` = 6 for `M_EP_TA_1`;
//! `SPE`/`OCI`+`QDP`+`CP16Time2a`+`CP24Time2a` = 7 for `M_EP_TB_1` and
//! `M_EP_TC_1`; `SCD`(4)+`QDS`(1) = 5 for `M_PS_NA_1`; and
//! `SEP`/`SPE`/`OCI` + `CP16Time2a`(2) + `CP56Time2a`(7) = 10/11/11 for the
//! `CP56Time2a` protection types. The rows here are composed from the `LEN`
//! constants, which clause 7.2.6 fixes and `tests/elements_table.rs` pins.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing)]

use iec104::asdu::{
    AsduError, AsduLayout, Bcr, Bsi, Cause, Cp16Time2a, Cp24Time2a, Cp56Time2a, Diq, Direction,
    DoublePointState, EventState, Header, LayoutError, LayoutObject, MAX_BODY, MBoNa1, MBoTa1,
    MBoTb1, MDpNa1, MDpTa1, MDpTb1, MEpTa1, MEpTb1, MEpTc1, MEpTd1, MEpTe1, MEpTf1, MItNa1, MItTa1,
    MItTb1, MMeNa1, MMeNb1, MMeNc1, MMeNd1, MMeTa1, MMeTb1, MMeTc1, MMeTd1, MMeTe1, MMeTf1,
    MONITOR_LAYOUTS, MPsNa1, MSpNa1, MSpTa1, MSpTb1, MStNa1, MStTa1, MStTb1, Nva, ObjectCount, Oci,
    Qdp, Qds, R32, Scd, Sep, Sequence, Siq, Spe, Sva, TypeId, Vti, decode_asdu, element_len,
    encode_asdu, layout_for,
};

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
        .collect()
}

/// A header of `type_id` with SQ = `sequence` and `count` objects, spontaneous,
/// CA 12: the same shape the vendor vectors use.
const fn header(type_id: TypeId, sequence: bool, count: u8) -> Header {
    Header {
        type_id,
        sequence,
        count,
        cause: Cause::Spontaneous,
        negative: false,
        test: false,
        originator: 0,
        common_address: 12,
    }
}

// One sample of every information element these layouts are built from. Each
// has a distinctive octet pattern, so a layout that wrote its elements in the
// wrong order cannot produce the expected bytes.

const fn siq() -> Siq {
    Siq {
        spi: true,
        blocked: false,
        substituted: true,
        not_topical: false,
        invalid: false,
    }
}

const fn diq() -> Diq {
    Diq {
        dpi: DoublePointState::On,
        blocked: false,
        substituted: true,
        not_topical: false,
        invalid: false,
    }
}

const fn vti() -> Vti {
    Vti {
        value: 5,
        transient: true,
    }
}

const fn qds() -> Qds {
    Qds {
        overflow: false,
        blocked: true,
        substituted: true,
        not_topical: false,
        invalid: false,
    }
}

const fn qdp() -> Qdp {
    Qdp {
        elapsed_time_invalid: true,
        blocked: true,
        substituted: true,
        not_topical: false,
        invalid: false,
    }
}

const fn bsi() -> Bsi {
    Bsi { bits: 0x0A0B_0C0D }
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

const fn bcr() -> Bcr {
    Bcr {
        reading: 0x0102_0304,
        sequence: 5,
        carry: true,
        adjusted: false,
        invalid: false,
    }
}

const fn scd() -> Scd {
    Scd {
        status: 0xAABB,
        change: 0xCCDD,
    }
}

const fn sep() -> Sep {
    Sep {
        event_state: EventState::On,
        elapsed_time_invalid: true,
        blocked: false,
        substituted: false,
        not_topical: false,
        invalid: true,
    }
}

const fn spe() -> Spe {
    Spe {
        general_start: true,
        start_l1: true,
        start_l2: false,
        start_l3: false,
        start_ie: true,
        start_reverse: false,
    }
}

const fn oci() -> Oci {
    Oci {
        general_command: true,
        command_l1: false,
        command_l2: false,
        command_l3: true,
    }
}

const fn elapsed() -> Cp16Time2a {
    Cp16Time2a {
        milliseconds: 0x0102,
    }
}

const fn cp24() -> Cp24Time2a {
    Cp24Time2a {
        milliseconds: 0x0304,
        minutes: 5,
        substituted: true,
        invalid: true,
    }
}

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

/// One layout's whole contract at once: the octet count the clause's figure
/// gives, the exact wire octets in definition-line order, a round trip, and
/// every short prefix a typed `TooShort` rather than a panic.
fn check<A: AsduLayout + PartialEq + std::fmt::Debug>(value: &A, expected: &[u8]) {
    assert_eq!(
        A::LEN,
        expected.len(),
        "AsduLayout::LEN against the clause 7.3.1 figure's octet count"
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

/// Every one of the 32 layouts, byte for byte, in the order its definition line
/// lists its elements.
#[test]
fn every_monitor_layout_reads_and_writes_its_definition_line() {
    // 7.3.1.1 M_SP_NA_1 := CP{…,i(Information object address,SIQ)}
    check(&MSpNa1 { siq: siq() }, &hex("21"));
    // 7.3.1.2 M_SP_TA_1 := CP{…,i(Information object address,SIQ,CP24Time2a)}
    check(
        &MSpTa1 {
            siq: siq(),
            time: cp24(),
        },
        &hex("21 04 03 C5"),
    );
    // 7.3.1.3 M_DP_NA_1 := CP{…,i(Information object address,DIQ)}
    check(&MDpNa1 { diq: diq() }, &hex("22"));
    // 7.3.1.4 M_DP_TA_1 := CP{…,i(Information object address,DIQ,CP24Time2a)}
    check(
        &MDpTa1 {
            diq: diq(),
            time: cp24(),
        },
        &hex("22 04 03 C5"),
    );
    // 7.3.1.5 M_ST_NA_1 := CP{…,i(Information object address,VTI,QDS)}
    check(
        &MStNa1 {
            vti: vti(),
            qds: qds(),
        },
        &hex("85 30"),
    );
    // 7.3.1.6 M_ST_TA_1 := CP{…,i(Information object address,VTI,QDS,CP24Time2a)}
    check(
        &MStTa1 {
            vti: vti(),
            qds: qds(),
            time: cp24(),
        },
        &hex("85 30 04 03 C5"),
    );
    // 7.3.1.7 M_BO_NA_1 := CP{…,i(Information object address,BSI,QDS)}
    check(
        &MBoNa1 {
            bsi: bsi(),
            qds: qds(),
        },
        &hex("0D 0C 0B 0A 30"),
    );
    // 7.3.1.8 M_BO_TA_1 := CP{…,i(Information object address,BSI,QDS,CP24Time2a)}
    check(
        &MBoTa1 {
            bsi: bsi(),
            qds: qds(),
            time: cp24(),
        },
        &hex("0D 0C 0B 0A 30 04 03 C5"),
    );
    // 7.3.1.9 M_ME_NA_1 := CP{…,i(Information object address,NVA,QDS)}
    check(
        &MMeNa1 {
            nva: nva(),
            qds: qds(),
        },
        &hex("34 12 30"),
    );
    // 7.3.1.10 M_ME_TA_1 := CP{…,i(Information object address,NVA,QDS,CP24Time2a)}
    check(
        &MMeTa1 {
            nva: nva(),
            qds: qds(),
            time: cp24(),
        },
        &hex("34 12 30 04 03 C5"),
    );
    // 7.3.1.11 M_ME_NB_1 := CP{…,i(Information object address,SVA,QDS)}
    check(
        &MMeNb1 {
            sva: sva(),
            qds: qds(),
        },
        &hex("45 23 30"),
    );
    check_monitor_layouts_12_to_21();
    check_cp56_monitor_layouts();
}

/// The monitor layouts of clauses 7.3.1.12 to 7.3.1.21.
fn check_monitor_layouts_12_to_21() {
    // 7.3.1.12 M_ME_TB_1 := CP{…,i(Information object address,SVA,QDS,CP24Time2a)}
    check(
        &MMeTb1 {
            sva: sva(),
            qds: qds(),
            time: cp24(),
        },
        &hex("45 23 30 04 03 C5"),
    );
    // 7.3.1.13 M_ME_NC_1 := CP{…,i(Information object address,IEEE STD 754,QDS)}
    check(
        &MMeNc1 {
            r32: r32(),
            qds: qds(),
        },
        &hex("00 00 C0 3F 30"),
    );
    // 7.3.1.14 M_ME_TC_1 := CP{…,i(Information object address,IEEE STD 754,QDS,CP24Time2a)}
    check(
        &MMeTc1 {
            r32: r32(),
            qds: qds(),
            time: cp24(),
        },
        &hex("00 00 C0 3F 30 04 03 C5"),
    );
    // 7.3.1.15 M_IT_NA_1 := CP{…,i(Information object address,BCR)}
    check(&MItNa1 { bcr: bcr() }, &hex("04 03 02 01 25"));
    // 7.3.1.16 M_IT_TA_1 := CP{…,i(Information object address,BCR,CP24Time2a)}
    check(
        &MItTa1 {
            bcr: bcr(),
            time: cp24(),
        },
        &hex("04 03 02 01 25 04 03 C5"),
    );
    // 7.3.1.17 M_EP_TA_1 := CP{…,i(Information object address,SEP,CP16Time2a,CP24Time2a)}
    check(
        &MEpTa1 {
            sep: sep(),
            elapsed: elapsed(),
            time: cp24(),
        },
        &hex("8A 02 01 04 03 C5"),
    );
    // 7.3.1.18 M_EP_TB_1 := CP{Data unit identifier,Information object address,SPE,QDP,CP16Time2a,CP24Time2a}
    check(
        &MEpTb1 {
            spe: spe(),
            qdp: qdp(),
            elapsed: elapsed(),
            time: cp24(),
        },
        &hex("13 38 02 01 04 03 C5"),
    );
    // 7.3.1.19 M_EP_TC_1 := CP{…,Information object address,OCI,QDP,CP16Time2a,CP24Time2a}
    check(
        &MEpTc1 {
            oci: oci(),
            qdp: qdp(),
            elapsed: elapsed(),
            time: cp24(),
        },
        &hex("09 38 02 01 04 03 C5"),
    );
    // 7.3.1.20 M_PS_NA_1 := CP{…,i(Information object address,SCD,QDS)}
    check(
        &MPsNa1 {
            scd: scd(),
            qds: qds(),
        },
        &hex("BB AA DD CC 30"),
    );
    // 7.3.1.21 M_ME_ND_1 := CP{…,i(Information object address,NVA)}
    check(&MMeNd1 { nva: nva() }, &hex("34 12"));
}

/// The monitor layouts with a `CP56Time2a`, clauses 7.3.1.22 to 7.3.1.32.
fn check_cp56_monitor_layouts() {
    // 7.3.1.22 M_SP_TB_1 := CP{…,i(Information object address,SIQ,CP56Time2a)}
    check(
        &MSpTb1 {
            siq: siq(),
            time: cp56(),
        },
        &hex("21 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.23 M_DP_TB_1 := CP{…,i(Information object address,DIQ,CP56Time2a)}
    check(
        &MDpTb1 {
            diq: diq(),
            time: cp56(),
        },
        &hex("22 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.24 M_ST_TB_1 := CP{…,i(Information object address,VTI,QDS,CP56Time2a)}
    check(
        &MStTb1 {
            vti: vti(),
            qds: qds(),
            time: cp56(),
        },
        &hex("85 30 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.25 M_BO_TB_1 := CP{…,i(Information object address,BSI,QDS,CP56Time2a)}
    check(
        &MBoTb1 {
            bsi: bsi(),
            qds: qds(),
            time: cp56(),
        },
        &hex("0D 0C 0B 0A 30 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.26 M_ME_TD_1 := CP{…,i(Information object address,NVA,QDS,CP56Time2a)}
    check(
        &MMeTd1 {
            nva: nva(),
            qds: qds(),
            time: cp56(),
        },
        &hex("34 12 30 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.27 M_ME_TE_1 := CP{…,i(Information object address,SVA,QDS,CP56Time2a)}
    check(
        &MMeTe1 {
            sva: sva(),
            qds: qds(),
            time: cp56(),
        },
        &hex("45 23 30 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.28 M_ME_TF_1 := CP{…,i(Information object address,IEEE STD 754,QDS,CP56Time2a)}
    check(
        &MMeTf1 {
            r32: r32(),
            qds: qds(),
            time: cp56(),
        },
        &hex("00 00 C0 3F 30 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.29 M_IT_TB_1 := CP{…,i(Information object address,BCR,CP56Time2a)}
    check(
        &MItTb1 {
            bcr: bcr(),
            time: cp56(),
        },
        &hex("04 03 02 01 25 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.30 M_EP_TD_1 := CP{…,i(Information object address,SEP,CP16Time2a,CP56Time2a)}
    check(
        &MEpTd1 {
            sep: sep(),
            elapsed: elapsed(),
            time: cp56(),
        },
        &hex("8A 02 01 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.31 M_EP_TE_1 := CP{…,Information object address,SPE,QDP,CP16Time2a,CP56Time2a}
    check(
        &MEpTe1 {
            spe: spe(),
            qdp: qdp(),
            elapsed: elapsed(),
            time: cp56(),
        },
        &hex("13 38 02 01 06 05 87 08 69 0A 0B"),
    );
    // 7.3.1.32 M_EP_TF_1 := CP{…,Information object address,OCI,QDP,CP16Time2a,CP56Time2a}
    check(
        &MEpTf1 {
            oci: oci(),
            qdp: qdp(),
            elapsed: elapsed(),
            time: cp56(),
        },
        &hex("09 38 02 01 06 05 87 08 69 0A 0B"),
    );
}

/// The geometry table itself: 32 rows, each naming its clause 7.3.1 subsection's
/// type identification, the octet count of one information object's elements,
/// and the two addressing rules.
#[test]
fn the_layout_table_names_all_32_monitor_types_with_their_figure_geometry() {
    // (ASDU name, type, AsduLayout::LEN, figure octets, SQ = 1 defined, one object only)
    let cases: &[(&str, TypeId, usize, usize, bool, bool)] = &[
        ("M_SP_NA_1", TypeId::MSpNa1, MSpNa1::LEN, 1, true, false),
        ("M_SP_TA_1", TypeId::MSpTa1, MSpTa1::LEN, 4, false, false),
        ("M_DP_NA_1", TypeId::MDpNa1, MDpNa1::LEN, 1, true, false),
        ("M_DP_TA_1", TypeId::MDpTa1, MDpTa1::LEN, 4, false, false),
        ("M_ST_NA_1", TypeId::MStNa1, MStNa1::LEN, 2, true, false),
        ("M_ST_TA_1", TypeId::MStTa1, MStTa1::LEN, 5, false, false),
        ("M_BO_NA_1", TypeId::MBoNa1, MBoNa1::LEN, 5, true, false),
        ("M_BO_TA_1", TypeId::MBoTa1, MBoTa1::LEN, 8, false, false),
        ("M_ME_NA_1", TypeId::MMeNa1, MMeNa1::LEN, 3, true, false),
        ("M_ME_TA_1", TypeId::MMeTa1, MMeTa1::LEN, 6, false, false),
        ("M_ME_NB_1", TypeId::MMeNb1, MMeNb1::LEN, 3, true, false),
        ("M_ME_TB_1", TypeId::MMeTb1, MMeTb1::LEN, 6, false, false),
        ("M_ME_NC_1", TypeId::MMeNc1, MMeNc1::LEN, 5, true, false),
        ("M_ME_TC_1", TypeId::MMeTc1, MMeTc1::LEN, 8, false, false),
        ("M_IT_NA_1", TypeId::MItNa1, MItNa1::LEN, 5, true, false),
        ("M_IT_TA_1", TypeId::MItTa1, MItTa1::LEN, 8, false, false),
        ("M_EP_TA_1", TypeId::MEpTa1, MEpTa1::LEN, 6, false, false),
        ("M_EP_TB_1", TypeId::MEpTb1, MEpTb1::LEN, 7, false, true),
        ("M_EP_TC_1", TypeId::MEpTc1, MEpTc1::LEN, 7, false, true),
        ("M_PS_NA_1", TypeId::MPsNa1, MPsNa1::LEN, 5, true, false),
        ("M_ME_ND_1", TypeId::MMeNd1, MMeNd1::LEN, 2, true, false),
        ("M_SP_TB_1", TypeId::MSpTb1, MSpTb1::LEN, 8, false, false),
        ("M_DP_TB_1", TypeId::MDpTb1, MDpTb1::LEN, 8, false, false),
        ("M_ST_TB_1", TypeId::MStTb1, MStTb1::LEN, 9, false, false),
        ("M_BO_TB_1", TypeId::MBoTb1, MBoTb1::LEN, 12, false, false),
        ("M_ME_TD_1", TypeId::MMeTd1, MMeTd1::LEN, 10, false, false),
        ("M_ME_TE_1", TypeId::MMeTe1, MMeTe1::LEN, 10, false, false),
        ("M_ME_TF_1", TypeId::MMeTf1, MMeTf1::LEN, 12, false, false),
        ("M_IT_TB_1", TypeId::MItTb1, MItTb1::LEN, 12, false, false),
        ("M_EP_TD_1", TypeId::MEpTd1, MEpTd1::LEN, 10, false, false),
        ("M_EP_TE_1", TypeId::MEpTe1, MEpTe1::LEN, 11, false, true),
        ("M_EP_TF_1", TypeId::MEpTf1, MEpTf1::LEN, 11, false, true),
    ];

    assert_eq!(cases.len(), 32, "clause 7.3.1 has 32 subsections");
    assert_eq!(MONITOR_LAYOUTS.len(), 32, "the table must have 32 rows");

    let mut seen = Vec::new();
    for (name, type_id, len, figure, sq1, single) in cases {
        let layout = layout_for(*type_id)
            .unwrap_or_else(|| panic!("{name} has no layout in MONITOR_LAYOUTS"));
        seen.push(*type_id);

        assert_eq!(layout.type_id, *type_id);
        assert_eq!(
            layout.element_len, *len,
            "{name}: MONITOR_LAYOUTS and AsduLayout::LEN must be the same number"
        );
        assert_eq!(
            layout.element_len, *figure,
            "{name}: {figure} octets is what clause 7.3.1's figure adds up to"
        );
        assert_eq!(
            element_len(*type_id),
            Some(*figure),
            "{name}: element_len()"
        );
        assert_eq!(
            layout.sequence == Sequence::Defined,
            *sq1,
            "{name}: SQ = 1 is {}defined for this type",
            if *sq1 { "" } else { "not " }
        );
        assert_eq!(
            layout.count == ObjectCount::Single,
            *single,
            "{name}: one information object only"
        );

        // A monitor-direction type of the catalogue, under the name the standard
        // gives it, so a layout cannot silently be attached to the wrong octet.
        assert_eq!(type_id.direction(), Some(Direction::Monitor), "{name}");
        assert_eq!(type_id.name(), *name);
    }

    // Every row distinct, and the table holds nothing the case list does not.
    seen.sort_unstable_by_key(|t| t.to_u8());
    seen.dedup();
    assert_eq!(seen.len(), 32);
    for layout in MONITOR_LAYOUTS {
        assert!(
            cases.iter().any(|(_, t, _, _, _, _)| *t == layout.type_id),
            "{} is in the table but not in the list above",
            layout.type_id.name()
        );
    }
}

/// The ten types whose definition line has a `j(...)` form, and the four whose
/// figure says "Single information object (SQ = 0)". Both sets are checked by
/// name, so a change to either is visible.
#[test]
fn the_sequence_and_single_object_sets_are_the_ones_the_clause_names() {
    let mut defined: Vec<&str> = MONITOR_LAYOUTS
        .iter()
        .filter(|l| l.sequence == Sequence::Defined)
        .map(|l| l.type_id.name())
        .collect();
    defined.sort_unstable();
    assert_eq!(
        defined,
        [
            "M_BO_NA_1",
            "M_DP_NA_1",
            "M_IT_NA_1",
            "M_ME_NA_1",
            "M_ME_NB_1",
            "M_ME_NC_1",
            "M_ME_ND_1",
            "M_PS_NA_1",
            "M_SP_NA_1",
            "M_ST_NA_1",
        ],
        "clause 7.3.1 defines j(...) for exactly these ten types"
    );

    let mut single: Vec<&str> = MONITOR_LAYOUTS
        .iter()
        .filter(|l| l.count == ObjectCount::Single)
        .map(|l| l.type_id.name())
        .collect();
    single.sort_unstable();
    assert_eq!(
        single,
        ["M_EP_TB_1", "M_EP_TC_1", "M_EP_TE_1", "M_EP_TF_1"],
        "7.3.1.18, .19, .31 and .32 are \"Single information object (SQ = 0)\""
    );

    // A sequence always carries several elements of one object, so a type that
    // has one is never a single-object type.
    for layout in MONITOR_LAYOUTS {
        assert!(
            !(layout.sequence == Sequence::Defined && layout.count == ObjectCount::Single),
            "{}",
            layout.type_id.name()
        );
    }
}

/// Every family clause 7.3 defines is laid out, and a type identification the
/// clause never defines has no layout: asking for one says so rather than
/// guessing a geometry. The families are 7.3.1 (monitor direction); 7.3.2–7.3.5
/// (control direction, system information, system commands, parameters) with
/// the 5-104 clause 8 additions; and 7.3.6 (file transfer) with 5-104 clause 8.9.
#[test]
fn a_type_only_the_clause_does_not_define_has_no_layout() {
    for type_id in [
        TypeId::MSpNa1, // a monitor layout of 7.3.1
        TypeId::CScNa1, // a control layout of 7.3.2
        TypeId::MEiNa1, // the system information of 7.3.3
        TypeId::PMeNc1, // a parameter ASDU of 7.3.5
        TypeId::FFrNa1, // clause 7.3.6, file transfer
        TypeId::FDrTa1,
    ] {
        assert!(layout_for(type_id).is_some(), "{}", type_id.name());
        assert!(element_len(type_id).is_some(), "{}", type_id.name());
    }
    // The one row whose element length is not a constant says so rather than
    // answering a number (see `the_segment_element_length_is_not_a_constant`
    // in `tests/file_transfer.rs`).
    assert!(layout_for(TypeId::FSgNa1).is_some());
    assert_eq!(element_len(TypeId::FSgNa1), None);
    // Types the clause never defines.
    assert_eq!(layout_for(TypeId::Other(200)), None);
    assert_eq!(element_len(TypeId::Other(200)), None);
}

/// SQ = 1 for a type whose definition line has no `j(...)`: refused on the read
/// path and on the write path, with the clause's own reason.
#[test]
fn a_sequence_is_refused_for_a_type_whose_definition_line_has_none() {
    // M_SP_TA_1 (7.3.1.2): "does not exist as a sequence of information elements".
    let asdu = hex("02 82 03 00 0C 00 10 30 00 21 04 03 C5 11 30 00 21 04 03 C5");
    assert_eq!(
        decode_asdu::<MSpTa1>(&asdu),
        Err(LayoutError::SequenceNotAllowed {
            type_id: TypeId::MSpTa1
        })
    );

    let sequence_header = header(TypeId::MSpTa1, true, 1);
    let one = [LayoutObject {
        ioa: 0x3010,
        value: MSpTa1 {
            siq: siq(),
            time: cp24(),
        },
    }];
    assert_eq!(
        encode_asdu(&sequence_header, &one),
        Err(LayoutError::SequenceNotAllowed {
            type_id: TypeId::MSpTa1
        })
    );

    // The same on SQ = 0: the type is legal, the sequence is not.
    let plain = hex("02 01 03 00 0C 00 10 30 00 21 04 03 C5");
    assert_eq!(decode_asdu::<MSpTa1>(&plain).expect("SQ = 0").len(), 1);
}

/// The four single-object types (7.3.1.18, .19, .31, .32): N = 1 is the shape
/// the figure prints and N ≥ 2 is refused. N = 0 (clause 7.2.2's "no
/// information object") is read, but never written.
#[test]
fn two_objects_are_refused_for_a_single_object_type() {
    let value = MEpTb1 {
        spe: spe(),
        qdp: qdp(),
        elapsed: elapsed(),
        time: cp24(),
    };

    // The type's own shape: one object.
    let one_header = header(TypeId::MEpTb1, false, 1);
    let one = [LayoutObject { ioa: 3, value }];
    let encoded = encode_asdu(&one_header, &one).expect("one object");
    assert_eq!(encoded.len(), 6 + 3 + 7);
    let decoded = decode_asdu::<MEpTb1>(&encoded).expect("decode");
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].ioa, 3);
    assert_eq!(decoded[0].value, value);

    // N = 0 is clause 7.2.2's "<0> := ASDU contains no INFORMATION OBJECT":
    // a received one decodes to nothing, but the writer does not produce one.
    assert_eq!(
        encode_asdu::<MEpTb1>(&header(TypeId::MEpTb1, false, 0), &[]),
        Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::MEpTb1,
            count: 0
        })
    );
    let mut none = Vec::new();
    header(TypeId::MEpTb1, false, 0).encode(&mut none);
    assert_eq!(none.len(), 6);
    assert_eq!(decode_asdu::<MEpTb1>(&none).expect("N = 0"), Vec::new());

    // N = 2 has no layout: the figure prints one information object and no
    // "Number i of objects" field.
    let two = [
        LayoutObject { ioa: 3, value },
        LayoutObject { ioa: 4, value },
    ];
    assert_eq!(
        encode_asdu(&header(TypeId::MEpTb1, false, 2), &two),
        Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::MEpTb1,
            count: 2
        })
    );
    let two_objects_on_the_wire = hex("12 02 03 00 0C 00 03 00 00 13 38 02 01 04 03 C5 \
                                       04 00 00 13 38 02 01 04 03 C5");
    assert_eq!(
        decode_asdu::<MEpTb1>(&two_objects_on_the_wire),
        Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::MEpTb1,
            count: 2
        })
    );
}

/// SQ = 1 for a type that has the form: one base address on the wire, elements
/// at base + *i* (clause 7.2.2.1), read and written by the same layout.
#[test]
fn a_sequence_round_trips_for_a_type_that_has_one() {
    // M_ME_NB_1, SQ = 1: base IOA 0x3010, three SVA+QDS elements.
    let asdu = hex("0B 83 03 00 0C 00 10 30 00 45 23 30 46 23 30 47 23 30");
    let objects = decode_asdu::<MMeNb1>(&asdu).expect("sequence");
    assert_eq!(objects.len(), 3);
    assert_eq!(objects[0].ioa, 0x3010);
    assert_eq!(objects[1].ioa, 0x3011);
    assert_eq!(objects[2].ioa, 0x3012);
    assert_eq!(objects[0].value.sva.value, 0x2345);
    assert_eq!(objects[1].value.sva.value, 0x2346);
    assert_eq!(objects[2].value.sva.value, 0x2347);
    assert!(objects[2].value.qds.blocked);

    let header = Header::parse(&asdu).expect("header");
    assert!(header.sequence);
    assert_eq!(encode_asdu(&header, &objects).expect("encode"), asdu);
}

/// The header of a decode must be the layout's own type, and the caller's slice
/// must be exactly the objects the header promises.
#[test]
fn the_header_and_the_layout_must_agree() {
    // M_SP_NA_1 where an M_ME_NB_1 layout was asked for.
    let asdu = hex("01 01 03 00 0C 00 10 30 00 21");
    assert_eq!(
        decode_asdu::<MMeNb1>(&asdu),
        Err(LayoutError::TypeMismatch {
            expected: TypeId::MMeNb1,
            got: TypeId::MSpNa1
        })
    );

    let wrong_header = header(TypeId::MSpNa1, false, 1);
    let object = LayoutObject {
        ioa: 0x3010,
        value: MMeNb1 {
            sva: sva(),
            qds: qds(),
        },
    };
    assert_eq!(
        encode_asdu(&wrong_header, &[object]),
        Err(LayoutError::TypeMismatch {
            expected: TypeId::MMeNb1,
            got: TypeId::MSpNa1
        })
    );

    // One octet too many behind the promised object: not silently dropped.
    let junk = hex("01 01 03 00 0C 00 10 30 00 21 FF");
    assert_eq!(
        decode_asdu::<MSpNa1>(&junk),
        Err(LayoutError::Asdu(AsduError::ObjectsNotExhausted {
            count: 1,
            remaining: 1
        }))
    );

    // An object area that ran out inside the second object.
    let short = hex("0B 02 03 00 0C 00 10 30 00 45 23 30");
    assert_eq!(
        decode_asdu::<MMeNb1>(&short),
        Err(LayoutError::Asdu(AsduError::TruncatedElement {
            index: 1,
            need: 3,
            have: 0
        }))
    );
}

/// The whole-object reader on the vendor vector: Beckhoff's seven spontaneous
/// scaled measured values (`tests/wire_vectors.rs` holds the APDU; this is its
/// ASDU), decoded to seven typed values.
#[test]
fn the_beckhoff_sample_decodes_to_seven_typed_values() {
    let asdu = hex(
        "0B 07 03 00 0C 00 10 30 00 BE 09 00 11 30 00 90 09 00 0E 30 00 75 00 00 \
         28 30 00 25 09 00 29 30 00 75 00 00 0F 30 00 0F 0A 00 2E 30 00 AE 05 00",
    );
    let objects = decode_asdu::<MMeNb1>(&asdu).expect("seven objects");
    let got: Vec<(u32, i16, u8)> = objects
        .iter()
        .map(|o| (o.ioa, o.value.sva.value, o.value.qds.raw()))
        .collect();
    assert_eq!(
        got,
        [
            (0x3010, 2494, 0),
            (0x3011, 2448, 0),
            (0x300E, 117, 0),
            (0x3028, 2341, 0),
            (0x3029, 117, 0),
            (0x300F, 2575, 0),
            (0x302E, 1454, 0),
        ]
    );

    let header = Header::parse(&asdu).expect("header");
    assert_eq!(encode_asdu(&header, &objects).expect("encode"), asdu);
}

/// The 243-octet object area of a 249-octet ASDU (5-104 clause 5), against the
/// widest element of each addressing mode.
#[test]
fn the_asdu_budget_bites_at_the_element_that_fills_it() {
    // SQ = 0, 12-octet element (M_ME_TF_1): 3 + 12 octets per object.
    let tf = MMeTf1 {
        r32: r32(),
        qds: qds(),
        time: cp56(),
    };
    let objects = |n: u8| -> Vec<LayoutObject<MMeTf1>> {
        (0..n)
            .map(|i| LayoutObject {
                ioa: 0x1000 + u32::from(i),
                value: tf,
            })
            .collect()
    };
    let sixteen =
        encode_asdu(&header(TypeId::MMeTf1, false, 16), &objects(16)).expect("16 objects");
    assert_eq!(sixteen.len() - Header::LEN, 240, "16 x 15 octets");
    assert_eq!(decode_asdu::<MMeTf1>(&sixteen).expect("decode").len(), 16);
    assert_eq!(
        encode_asdu(&header(TypeId::MMeTf1, false, 17), &objects(17)),
        Err(LayoutError::Asdu(AsduError::BodyTooLong {
            len: 255,
            max: MAX_BODY
        }))
    );

    // SQ = 1, 5-octet element (M_ME_NC_1): 3 + 5 octets per element.
    let nc = |n: u8| -> Vec<LayoutObject<MMeNc1>> {
        (0..n)
            .map(|i| LayoutObject {
                ioa: 0x1000 + u32::from(i),
                value: MMeNc1 {
                    r32: r32(),
                    qds: qds(),
                },
            })
            .collect()
    };
    let forty_eight = encode_asdu(&header(TypeId::MMeNc1, true, 48), &nc(48)).expect("48 elements");
    assert_eq!(forty_eight.len() - Header::LEN, 243, "3 + 48 x 5 octets");
    assert_eq!(
        decode_asdu::<MMeNc1>(&forty_eight).expect("decode").len(),
        48
    );
    assert_eq!(
        encode_asdu(&header(TypeId::MMeNc1, true, 49), &nc(49)),
        Err(LayoutError::Asdu(AsduError::BodyTooLong {
            len: 248,
            max: MAX_BODY
        }))
    );

    // SQ = 0 with the same 5-octet element: three octets more per object, so the
    // boundary is 30 objects (240 octets); the 31st needs 248.
    let thirty = encode_asdu(&header(TypeId::MMeNc1, false, 30), &nc(30)).expect("30 objects");
    assert_eq!(thirty.len() - Header::LEN, 240, "30 x 8 octets");
    assert_eq!(decode_asdu::<MMeNc1>(&thirty).expect("decode").len(), 30);
    assert_eq!(
        encode_asdu(&header(TypeId::MMeNc1, false, 31), &nc(31)),
        Err(LayoutError::Asdu(AsduError::BodyTooLong {
            len: 248,
            max: MAX_BODY
        }))
    );
}

/// A user-defined type is not in the layout table: the trait still plugs into
/// `decode_asdu`, and the missing table row is reported rather than guessed.
/// It uses a type identification 5-101 does not define, because every type the
/// clause defines has a layout.
#[test]
fn a_layout_absent_from_the_table_is_reported() {
    #[derive(Debug, PartialEq, Eq)]
    struct NotAAsduLayout;

    impl AsduLayout for NotAAsduLayout {
        const TYPE_ID: TypeId = TypeId::Other(200);
        const LEN: usize = 1;

        fn parse(_element: &[u8]) -> Result<Self, AsduError> {
            Ok(Self)
        }

        fn encode(&self, _out: &mut Vec<u8>) {}
    }

    // Type identification `C8` = 200, so the header matches the trait's own
    // `TYPE_ID` and the missing table row is what is left to report.
    let asdu = hex("C8 01 06 00 0C 00 10 30 00 01");
    assert_eq!(
        decode_asdu::<NotAAsduLayout>(&asdu),
        Err(LayoutError::NoLayout {
            type_id: TypeId::Other(200)
        })
    );
}
