//! Cyclic transmission (`iec104::tx`), the background scan and the acquisition of
//! events: the three monitor-direction causes `<1>`, `<2>` and `<3>` as the
//! controlled station's producers, plus 104 clause 9's double transmission.
//!
//! The clause citations are 5-104 clause 7.3 and 7.4 (the two service rows,
//! PDF page index 64); 5-101 clause 7.4.13 with its **Table 21** (the
//! background scan and its nine types, page index 149), table 14's footnote 3
//! (cause `<2>`'s semantics, page index 41) and clauses 7.4.2/.3/.4 with
//! **Table 16** (the selections, the per-cause type rows and the send order,
//! page indices 122 and 121); 5-104 clause 9 (the permitted tag set `<30>` to
//! `<40>`, page index 100) and clause 9.6 (the seven double-transmission
//! families and the project-specific list, page index 108; the three
//! checkboxes, page index 114);
//! and 5-101 clause 7.2.3 (the discard rule, page index 38).
//!
//! Every frame is pinned as the octet string the tables imply, and the
//! reception half drives the two roles against each other.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::as_conversions)]

use iec104::asdu::{
    AsduError, AsduLayout, Bcr, BodyReader, Bsi, Cause, Cp24Time2a, Cp56Time2a, Diq, Discard,
    Header, Known, LayoutObject, MBoNa1, MDpNa1, MItNa1, MMeNa1, MMeNb1, MMeNc1, MMeNd1, MMeTd1,
    MSpNa1, MSpTa1, MSpTb1, MStNa1, Nva, Qds, R32, Siq, Sva, TypeId, Unspecified, Vti, decode_asdu,
    element_len,
};
use iec104::tx;
use iec104::tx::{
    BACKGROUND_TYPES, CAUSE_BACKGROUND, CAUSE_PERIODIC, CAUSE_SPONTANEOUS, CYCLIC_TYPES,
    DoublePair, Doubles, Function, ProjectList, Reaction, Role, SPONTANEOUS_MAX, SPONTANEOUS_MIN,
    StationFunctions, Transmission, TxError, background, cyclic, doubled, function_of,
    is_permitted_tag, is_spontaneous_type, spontaneous,
};

const CA: u16 = 12;
const ORG: u8 = 7;
const IOA: u32 = 0x4001;

/// 26.965 s, 16 min past 13:00 on 19 January 2001: the worked example of
/// Clarke/Reynders/Wright, App. D, which `src/cs.rs`'s doc test also uses.
/// The book's octets are `55 69 10 0D 13 01 01`, with no day of the week. This
/// test adds Monday: the fifth octet carries the day of the month in bits 0..4
/// and the day of the week in bits 5..7 (cl.7.2.6.18), so the Monday=1 adds
/// `0x20` to the 19 and the octets are `55 69 10 0D 33 01 01`.
fn time() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 26_965,
        minutes: 16,
        hours: 13,
        day_of_month: 19,
        day_of_week: 1,
        months: 1,
        years: 1,
        ..Cp56Time2a::default()
    }
}

const TIME_BYTES: [u8; 7] = [0x55, 0x69, 0x10, 0x0D, 0x33, 0x01, 0x01];

// ---------------------------------------------------------------- helpers

fn m_sp(on: bool) -> LayoutObject<MSpNa1> {
    LayoutObject {
        ioa: IOA,
        value: MSpNa1 {
            siq: Siq {
                spi: on,
                ..Siq::default()
            },
        },
    }
}

const fn m_dp() -> LayoutObject<MDpNa1> {
    LayoutObject {
        ioa: IOA,
        value: MDpNa1 {
            diq: Diq::from_raw(0x00),
        },
    }
}

fn m_st() -> LayoutObject<MStNa1> {
    LayoutObject {
        ioa: IOA,
        value: MStNa1 {
            // `0x7D` shifts to -3 with the transient bit clear (cl.7.2.6.5).
            vti: Vti::from_raw(0x7D),
            qds: Qds::default(),
        },
    }
}

fn m_bo() -> LayoutObject<MBoNa1> {
    LayoutObject {
        ioa: IOA,
        value: MBoNa1 {
            bsi: Bsi { bits: 0xDEAD_BEEF },
            qds: Qds::default(),
        },
    }
}

fn m_me_na(value: i16) -> LayoutObject<MMeNa1> {
    LayoutObject {
        ioa: IOA,
        value: MMeNa1 {
            nva: Nva { value },
            qds: Qds::default(),
        },
    }
}

fn m_me_nb(value: i16) -> LayoutObject<MMeNb1> {
    LayoutObject {
        ioa: IOA,
        value: MMeNb1 {
            sva: Sva { value },
            qds: Qds::default(),
        },
    }
}

fn m_me_nc(value: f32) -> LayoutObject<MMeNc1> {
    LayoutObject {
        ioa: IOA,
        value: MMeNc1 {
            r32: R32 { value },
            qds: Qds::default(),
        },
    }
}

const fn m_me_nd(value: i16) -> LayoutObject<MMeNd1> {
    LayoutObject {
        ioa: IOA,
        value: MMeNd1 { nva: Nva { value } },
    }
}

/// A hand-built ASDU of `type_id` with a zero-filled but **complete** object
/// area, for the causes and types the `tx` producers do not build. The element
/// geometry comes from the crate's own layout table, so the frame is a legal
/// ASDU of its type and only the type/cause combination is what the test is
/// about.
fn hand_built(type_id: TypeId, cause: Cause) -> Vec<u8> {
    let mut out = vec![
        type_id.to_u8(),
        0x01,
        cause.to_u8(),
        ORG,
        (CA & 0xFF) as u8,
        (CA >> 8) as u8,
        0x01,
        0x40,
        0x00,
    ];
    out.extend(std::iter::repeat_n(
        0u8,
        element_len(type_id).expect("a type with a layout"),
    ));
    out
}

/// Every frame this module's producers build, for the truncation sweep.
fn every_frame() -> Vec<Vec<u8>> {
    let mut frames = vec![
        cyclic(&m_me_na(0x2000), CA, ORG).unwrap(),
        cyclic(&m_me_nb(0x1234), CA, ORG).unwrap(),
        cyclic(&m_me_nc(1.5), CA, ORG).unwrap(),
        cyclic(&m_me_nd(0x2000), CA, ORG).unwrap(),
        background(&m_sp(true), CA, ORG).unwrap(),
        background(&m_dp(), CA, ORG).unwrap(),
        background(&m_st(), CA, ORG).unwrap(),
        background(&m_bo(), CA, ORG).unwrap(),
        spontaneous(&m_me_nb(0x1234), CA, ORG).unwrap(),
        spontaneous(&m_sp(false), CA, ORG).unwrap(),
    ];
    frames.extend(doubled(&m_sp(true), time(), CA, ORG).unwrap());
    frames.extend(doubled(&m_dp(), time(), CA, ORG).unwrap());
    frames.extend(doubled(&m_st(), time(), CA, ORG).unwrap());
    frames.extend(doubled(&m_bo(), time(), CA, ORG).unwrap());
    frames.extend(doubled(&m_me_na(0x2000), time(), CA, ORG).unwrap());
    frames.extend(doubled(&m_me_nb(0x1234), time(), CA, ORG).unwrap());
    frames.extend(doubled(&m_me_nc(1.5), time(), CA, ORG).unwrap());
    frames
}

fn controlled_all() -> Transmission {
    Transmission::controlled(StationFunctions::ALL, ProjectList::new([IOA]), CA, ORG)
}

const fn listening() -> Transmission {
    Transmission::controlling(CA, ORG)
}

// ------------------------------------------- the three causes, byte for byte

#[test]
fn the_cyclic_frame_is_the_twelve_octets_of_a_cause_one_m_me_na_1() {
    let frame = cyclic(&m_me_na(0x2000), CA, ORG).unwrap();
    // 5-104 clause 7.3 (PDF page index 64): `M CYCLIC` is a clause-7.3.1 ASDU
    // with cause `<1>`; 5-101 Table 16's cyclic row (page index 121) carries
    // types 9, 11, 13, 21. `M_ME_NA_1 := CP{data unit identifier,
    // information object address, NVA, QDS}` (clause 7.3.1.9, page index 70) is
    // 6 header + 3 IOA + 2 NVA + 1 QDS = 12 octets.
    assert_eq!(
        frame,
        vec![
            0x09, 0x01, 0x01, 0x07, 0x0C,
            0x00, // M_ME_NA_1, SQ 0 N 1, COT 1 per/cyc, ORG 7, CA 12
            0x01, 0x40, 0x00, // information object address 0x4001
            0x00, 0x20, // NVA: F16 0x2000, little-endian
            0x00, // QDS: all quality bits clear
        ]
    );
    let header = Header::parse(&frame).unwrap();
    assert_eq!(header.type_id, TypeId::MMeNa1);
    assert_eq!(header.cause, CAUSE_PERIODIC);
    assert_eq!(header.cause.mnemonic(), "per/cyc");
    assert_eq!(header.count, 1);
    assert!(!header.sequence, "SQ = 0");
    assert!(!header.negative, "P/N = 0: the frame confirms nothing");
    assert_eq!(header.originator, ORG);
    assert_eq!(header.common_address, CA);
}

#[test]
fn the_background_scan_frame_is_the_ten_octets_of_a_cause_two_m_sp_na_1() {
    let frame = background(&m_sp(true), CA, ORG).unwrap();
    // 5-101 clause 7.4.13 and Table 21 (PDF page index 149): `M_SP_NA_1` with
    // cause `<2>` background scan. `M_SP_NA_1 := CP{data unit identifier,
    // i(Information object address, SIQ)}` (clause 7.3.1.1, page index 60) is
    // 6 + 3 + 1 = 10 octets.
    assert_eq!(
        frame,
        vec![
            0x01, 0x01, 0x02, 0x07, 0x0C,
            0x00, // M_SP_NA_1, SQ 0 N 1, COT 2 back, ORG 7, CA 12
            0x01, 0x40, 0x00, // information object address 0x4001
            0x01, // SIQ: SPI = ON, quality clear
        ]
    );
    let header = Header::parse(&frame).unwrap();
    assert_eq!(header.cause, CAUSE_BACKGROUND);
    assert_eq!(header.cause.mnemonic(), "back");
    assert_eq!(header.type_id, TypeId::MSpNa1);
}

#[test]
fn the_spontaneous_frame_is_the_twelve_octets_of_a_cause_three_m_me_nb_1() {
    let frame = spontaneous(&m_me_nb(0x1234), CA, ORG).unwrap();
    // 5-104 clause 7.4 (PDF page index 64): `M SPONT` is a clause-7.3.1 ASDU
    // with cause `<3>`; 5-101 Table 16's event row (page index 121) carries the
    // event-reporting range, and 5-104 clause 9 (index 100) narrows it to the
    // types a 104 station may send. `M_ME_NB_1 := CP{data unit identifier,
    // information object address, SVA, QDS}` (clause 7.3.1.11, page index 72)
    // is 6 + 3 + 2 + 1 = 12 octets.
    assert_eq!(
        frame,
        vec![
            0x0B, 0x01, 0x03, 0x07, 0x0C,
            0x00, // M_ME_NB_1, SQ 0 N 1, COT 3 spont, ORG 7, CA 12
            0x01, 0x40, 0x00, // information object address 0x4001
            0x34, 0x12, // SVA: I16 0x1234, little-endian
            0x00, // QDS
        ]
    );
    let header = Header::parse(&frame).unwrap();
    assert_eq!(header.cause, CAUSE_SPONTANEOUS);
    assert_eq!(header.cause.mnemonic(), "spont");
    assert_eq!(header.type_id, TypeId::MMeNb1);
}

// ------------------------------------------------- the three causes' type sets

#[test]
fn table_16s_cyclic_row_is_the_four_measured_value_types() {
    // 5-101 Table 16 (PDF page index 121), the row `9, 11, 13, 21 / 120 to
    // 127`: the four measured-value types are this module's half of it; the
    // file-transfer numbers 120–127 belong to file transfer (`iec104::ft`).
    assert_eq!(
        CYCLIC_TYPES
            .iter()
            .map(|type_id| type_id.to_u8())
            .collect::<Vec<_>>(),
        vec![9, 11, 13, 21]
    );
    for frame in [
        cyclic(&m_me_na(0x2000), CA, ORG).unwrap(),
        cyclic(&m_me_nb(0x1234), CA, ORG).unwrap(),
        cyclic(&m_me_nc(1.5), CA, ORG).unwrap(),
        cyclic(&m_me_nd(0x2000), CA, ORG).unwrap(),
    ] {
        assert_eq!(Header::parse(&frame).unwrap().cause, CAUSE_PERIODIC);
    }
    // The type-21 form has no quality descriptor: 6 + 3 + 2 = 11 octets.
    assert_eq!(
        cyclic(&m_me_nd(0x2000), CA, ORG).unwrap(),
        vec![
            0x15, 0x01, 0x01, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x00, 0x20
        ]
    );
}

#[test]
fn table_21_is_the_nine_types_of_the_background_scan() {
    // 5-101 Table 21 (PDF page index 149), the table's own order.
    assert_eq!(
        BACKGROUND_TYPES
            .iter()
            .map(|type_id| type_id.to_u8())
            .collect::<Vec<_>>(),
        vec![1, 3, 5, 7, 9, 11, 13, 20, 21]
    );
    assert_eq!(
        BACKGROUND_TYPES.map(iec104::asdu::TypeId::name),
        [
            "M_SP_NA_1",
            "M_DP_NA_1",
            "M_ST_NA_1",
            "M_BO_NA_1",
            "M_ME_NA_1",
            "M_ME_NB_1",
            "M_ME_NC_1",
            "M_PS_NA_1",
            "M_ME_ND_1"
        ],
        "the clause's prose names the same nine as a station-interrogation response"
    );
    // All nine build; the clause carries no time-tagged background-scan frame,
    // so each of the nine is the untagged form.
    for frame in [
        background(&m_sp(true), CA, ORG).unwrap(),
        background(&m_dp(), CA, ORG).unwrap(),
        background(&m_st(), CA, ORG).unwrap(),
        background(&m_bo(), CA, ORG).unwrap(),
        background(&m_me_na(0x2000), CA, ORG).unwrap(),
        background(&m_me_nb(0x1234), CA, ORG).unwrap(),
        background(&m_me_nc(1.5), CA, ORG).unwrap(),
    ] {
        let header = Header::parse(&frame).unwrap();
        assert_eq!(header.cause, CAUSE_BACKGROUND);
        assert!(BACKGROUND_TYPES.contains(&header.type_id));
        assert!(
            header.type_id.to_u8() < 30,
            "every Table 21 type is untagged"
        );
    }
    // `M_PS_NA_1` and `M_ME_ND_1` have no helper of their own; build them from
    // the layout layer and hand them in.
    let ps = LayoutObject {
        ioa: IOA,
        value: iec104::asdu::MPsNa1 {
            scd: iec104::asdu::Scd::default(),
            qds: Qds::default(),
        },
    };
    assert!(background(&ps, CA, ORG).is_ok());
    assert!(background(&m_me_nd(0x2000), CA, ORG).is_ok());
}

#[test]
fn the_background_scan_refuses_a_type_outside_table_21() {
    // A time-tagged measured value and a counter value are both real monitor
    // types, and neither is in Table 21 (page index 149).
    let tagged = LayoutObject {
        ioa: IOA,
        value: MMeTd1 {
            nva: Nva { value: 0x2000 },
            qds: Qds::default(),
            time: time(),
        },
    };
    assert_eq!(
        background(&tagged, CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::MMeTd1,
            cause: CAUSE_BACKGROUND,
        })
    );
    let counter = LayoutObject {
        ioa: IOA,
        value: MItNa1 {
            bcr: Bcr::default(),
        },
    };
    assert_eq!(
        background(&counter, CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::MItNa1,
            cause: CAUSE_BACKGROUND,
        })
    );
}

#[test]
fn the_cyclic_cause_refuses_a_type_outside_table_16s_row() {
    // A single-point information is an event and a background-scan type, but
    // Table 16's cyclic row (page index 121) carries only 9, 11, 13 and 21.
    assert_eq!(
        cyclic(&m_sp(true), CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::MSpNa1,
            cause: CAUSE_PERIODIC,
        })
    );
    assert!(
        spontaneous(&m_sp(true), CA, ORG).is_ok(),
        "the same type is legal with the spontaneous cause"
    );
    // Every time-tagged type is outside the row as well.
    let tagged = LayoutObject {
        ioa: IOA,
        value: MMeTd1 {
            nva: Nva { value: 0 },
            qds: Qds::default(),
            time: time(),
        },
    };
    assert_eq!(
        cyclic(&tagged, CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::MMeTd1,
            cause: CAUSE_PERIODIC,
        })
    );
}

#[test]
fn the_spontaneous_set_is_table_16s_event_row_as_104_clause_nine_narrows_it() {
    // 5-101 Table 16 (PDF page index 121): the row `1 to 44 / 103 / 106`.
    // 5-104 clause 9 (index 100, printed page 99) strikes the CP24Time2a
    // monitor forms <2>,<4>,<6>,<8>,<10>,<12>,<14>,<16>,<17>,<18>,<19> and the
    // delay acquisition <106> out of its type lists, and its type/cause grid
    // draws the <103>/cause 3 box black (clause 7.6 names only C_CS ACT and
    // C_CS ACTCON). So the cause-<3> set is `1..=44` minus those eleven.
    assert_eq!((SPONTANEOUS_MIN, SPONTANEOUS_MAX), (1, 44));
    for octet in [
        1u8, 3, 5, 7, 9, 11, 13, 15, 20, 21, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    ] {
        assert!(
            is_spontaneous_type(TypeId::from_u8(octet)),
            "type {octet} is in 104's selected event set"
        );
    }
    for octet in [
        0u8, 2, 4, 6, 8, 10, 12, 14, 16, 17, 18, 19, 45, 46, 70, 100, 102, 106, 107, 120, 127,
    ] {
        assert!(
            !is_spontaneous_type(TypeId::from_u8(octet)),
            "type {octet} is outside 104's selected event set"
        );
    }
    // Table 16's range is literal, so the reserved numbers it covers answer
    // `true` even though no catalogue name exists for them (the caller's
    // `Known` is what decides whether such an arrival is processed).
    for octet in 41u8..=44 {
        assert!(
            is_spontaneous_type(TypeId::from_u8(octet)),
            "type {octet} is inside Table 16's literal range"
        );
    }
    // Neither control type of the row is spontaneous in 104.
    assert!(!is_spontaneous_type(TypeId::CCsNa1), "103 C_CS_NA_1");
    assert!(!is_spontaneous_type(TypeId::CCdNa1), "106 C_CD_NA_1");
    assert_eq!(TypeId::CCsNa1.to_u8(), 103);
    assert_eq!(TypeId::CCdNa1.to_u8(), 106);
}

#[test]
fn the_spontaneous_set_is_read_over_the_wire_octet_not_over_the_variant() {
    // `is_spontaneous_type`'s own doc says the test is over the type's wire
    // octet, and `TypeId::Other` is the public variant for an octet without a
    // name. The two must agree for every octet: an exclusion list keyed on the
    // named variants answers `true` for `Other(2)` while the named `<2>`
    // answers `false`, which is one wire octet with two answers. 5-104 clause 9
    // (index 100) strikes the octet, not a Rust variant.
    for octet in 0u8..=255 {
        assert_eq!(
            is_spontaneous_type(TypeId::Other(octet)),
            is_spontaneous_type(TypeId::from_u8(octet)),
            "octet {octet} answered differently through TypeId::Other"
        );
    }
    // The octet the clause strikes is the one that answers `false` either way.
    assert!(!is_spontaneous_type(TypeId::Other(2)));
    assert!(!is_spontaneous_type(TypeId::Other(106)));
    assert!(!is_spontaneous_type(TypeId::Other(103)));
}

#[test]
fn the_spontaneous_cause_refuses_a_type_104_clause_nine_strikes_out() {
    // 5-104 clause 9 (PDF page index 100, printed page 99): the CP24Time2a
    // monitor forms and the delay acquisition are struck from the type lists,
    // so a producer must not emit them with cause <3> even though 5-101's
    // Table 16 event row names their octets.
    let m_sp_ta = LayoutObject {
        ioa: IOA,
        value: MSpTa1 {
            siq: Siq::default(),
            time: Cp24Time2a::default(),
        },
    };
    assert_eq!(
        spontaneous(&m_sp_ta, CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::MSpTa1,
            cause: CAUSE_SPONTANEOUS,
        })
    );
    let c_cd_na = LayoutObject {
        ioa: IOA,
        value: iec104::asdu::CCdNa1 {
            elapsed: iec104::asdu::Cp16Time2a::default(),
        },
    };
    assert_eq!(
        spontaneous(&c_cd_na, CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::CCdNa1,
            cause: CAUSE_SPONTANEOUS,
        })
    );
    // The typed refusal is the same one the station's own builder raises.
    let station = controlled_all();
    assert_eq!(
        station.spontaneous(&m_sp_ta),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::MSpTa1,
            cause: CAUSE_SPONTANEOUS,
        })
    );
}

#[test]
fn the_spontaneous_cause_refuses_a_type_outside_the_event_row() {
    // A command ASDU (45–51) is not event reporting, and 113 is a parameter.
    let command = LayoutObject {
        ioa: IOA,
        value: iec104::asdu::CScNa1 {
            sco: iec104::asdu::Sco {
                scs: false,
                qoc: iec104::asdu::Qoc::default(),
            },
        },
    };
    assert_eq!(
        spontaneous(&command, CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::CScNa1,
            cause: CAUSE_SPONTANEOUS,
        })
    );
    let parameter = LayoutObject {
        ioa: IOA,
        value: iec104::asdu::PAcNa1 {
            qpa: iec104::asdu::Qpa { value: 3 },
        },
    };
    assert_eq!(
        spontaneous(&parameter, CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::PAcNa1,
            cause: CAUSE_SPONTANEOUS,
        })
    );
    // Nor does the clock time: 5-104 clause 7.6's service table names only
    // C_CS ACT and C_CS ACTCON, and clause 9 draws the <103>/cause 3 box black.
    let clock = LayoutObject {
        ioa: 0,
        value: iec104::asdu::CCsNa1 { time: time() },
    };
    assert_eq!(
        spontaneous(&clock, CA, ORG),
        Err(TxError::CauseTypeNotAllowed {
            type_id: TypeId::CCsNa1,
            cause: CAUSE_SPONTANEOUS,
        })
    );
}

// ------------------------------------------------------------ the functions

#[test]
fn function_of_names_the_three_causes_and_nothing_else() {
    assert_eq!(function_of(Cause::Periodic), Ok(Function::Cyclic));
    assert_eq!(function_of(Cause::BackgroundScan), Ok(Function::Background));
    assert_eq!(function_of(Cause::Spontaneous), Ok(Function::Spontaneous));
    for cause in [
        Cause::ActivationCon,
        Cause::FileTransfer,
        Cause::InterrogatedByStation,
        Cause::UnknownTypeId,
    ] {
        assert_eq!(function_of(cause), Err(TxError::NotOurCause { cause }));
    }
    assert_eq!(Function::ALL.len(), 3);
    for function in Function::ALL {
        assert_eq!(Function::of_cause(function.cause()), Some(function));
        assert_eq!(function_of(function.cause()), Ok(function));
    }
    assert_eq!(Function::Cyclic.mnemonic(), "per/cyc");
    assert_eq!(Function::Background.mnemonic(), "back");
    assert_eq!(Function::Spontaneous.mnemonic(), "spont");
}

#[test]
fn a_functions_table_is_the_one_its_cause_owns() {
    // The producers ask `carries`, so the two tables cannot drift apart from
    // what the reception side accepts.
    assert!(Function::Cyclic.carries(TypeId::MMeNa1));
    assert!(!Function::Cyclic.carries(TypeId::MSpNa1));
    assert!(!Function::Cyclic.carries(TypeId::MMeTd1));
    assert!(Function::Background.carries(TypeId::MSpNa1));
    assert!(Function::Background.carries(TypeId::MMeNd1));
    assert!(!Function::Background.carries(TypeId::MMeTd1));
    assert!(!Function::Background.carries(TypeId::MItNa1));
    assert!(Function::Spontaneous.carries(TypeId::MSpNa1));
    assert!(Function::Spontaneous.carries(TypeId::MMeTd1));
    assert!(!Function::Spontaneous.carries(TypeId::CCsNa1));
    assert!(!Function::Spontaneous.carries(TypeId::MSpTa1));
    assert!(!Function::Spontaneous.carries(TypeId::CCdNa1));
    assert!(!Function::Spontaneous.carries(TypeId::CScNa1));
}

// ------------------------------------------------- the station's selection

#[test]
fn the_station_selection_gates_the_producers() {
    // 104 clause 9.6 (PDF page index 114): each of the three functions is a
    // station-specific checkbox, so a station that does not use one cannot
    // produce its ASDUs.
    let none = Transmission::controlled(StationFunctions::NONE, ProjectList::empty(), CA, ORG);
    assert_eq!(
        none.cyclic(&m_me_na(0x2000)),
        Err(TxError::FunctionNotUsed {
            cause: CAUSE_PERIODIC
        })
    );
    assert_eq!(
        none.background(&m_sp(true)),
        Err(TxError::FunctionNotUsed {
            cause: CAUSE_BACKGROUND
        })
    );
    assert_eq!(
        none.spontaneous(&m_sp(true)),
        Err(TxError::FunctionNotUsed {
            cause: CAUSE_SPONTANEOUS
        })
    );
    assert_eq!(
        none.double(&m_sp(true), time()),
        Err(TxError::FunctionNotUsed {
            cause: CAUSE_SPONTANEOUS
        })
    );

    let cyclic_only = StationFunctions::NONE.with(Function::Cyclic, true);
    let station = Transmission::controlled(cyclic_only, ProjectList::empty(), CA, ORG);
    assert!(station.cyclic(&m_me_na(0x2000)).is_ok());
    assert!(station.background(&m_sp(true)).is_err());

    // An unscoped station uses none: the value is not `ALL`.
    assert_eq!(StationFunctions::default(), StationFunctions::NONE);
    assert_eq!(StationFunctions::NONE.count(), 0);
    assert_eq!(StationFunctions::ALL.count(), 3);
    assert_eq!(station.functions(), Some(cyclic_only));
    assert_eq!(station.role(), Role::Controlled);
    assert_eq!(station.addressing(), (CA, ORG));

    // The frames of an `ALL` station carry the instance's addressing.
    let frame = controlled_all().cyclic(&m_me_na(0x2000)).unwrap();
    assert_eq!(
        frame,
        cyclic(&m_me_na(0x2000), CA, ORG).unwrap(),
        "the instance builds what the free builder builds"
    );
}

// ------------------------------------------------------- the double transmission

#[test]
fn the_double_transmission_pair_is_untagged_first_and_tagged_second() {
    // 104 clause 9.6 (PDF page index 108): one status change of an information
    // object may produce two transmissions in a row, with the same value in
    // both frames.
    let pair = doubled(&m_sp(true), time(), CA, ORG).unwrap();
    assert_eq!(pair.len(), 2);
    // `M_SP_NA_1` (type 1) first: 6 + 3 + 1 = 10 octets.
    assert_eq!(
        pair[0],
        vec![0x01, 0x01, 0x03, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x01]
    );
    // `M_SP_TB_1` (type 30, the permitted tagged half) second: 6 + 3 + 1 + 7.
    let mut expected = vec![0x1E, 0x01, 0x03, 0x07, 0x0C, 0x00, 0x01, 0x40, 0x00, 0x01];
    expected.extend_from_slice(&TIME_BYTES);
    assert_eq!(pair[1], expected);

    let first = Header::parse(&pair[0]).unwrap();
    let second = Header::parse(&pair[1]).unwrap();
    assert_eq!(first.type_id, DoublePair::SinglePoint.untagged());
    assert_eq!(second.type_id, DoublePair::SinglePoint.tagged());
    assert_eq!(first.cause, CAUSE_SPONTANEOUS);
    assert_eq!(
        second.cause, CAUSE_SPONTANEOUS,
        "the clause's heading is 'with cause of transmission spontaneous'"
    );

    // The same value, read back out of both frames.
    let untagged = decode_asdu::<MSpNa1>(&pair[0]).unwrap();
    let tagged = decode_asdu::<MSpTb1>(&pair[1]).unwrap();
    assert_eq!(untagged[0].ioa, tagged[0].ioa);
    assert_eq!(untagged[0].value.siq, tagged[0].value.siq);
    assert_eq!(tagged[0].value.time, time());
}

#[test]
fn every_pair_of_clause_nine_six_is_untagged_then_tagged_in_the_permitted_set() {
    for pair in DoublePair::ALL {
        assert!(pair.untagged().to_u8() < 30, "{}", pair.name());
        assert!(
            is_permitted_tag(pair.tagged()),
            "{}: {} is outside clause 9's <30>-<40>",
            pair.name(),
            pair.tagged().name()
        );
        assert_eq!(DoublePair::of_type(pair.types()[0]), Some(pair));
        assert!(
            pair.types().contains(&pair.untagged()) && pair.types().contains(&pair.tagged()),
            "{}: the pair's halves are members of the clause's own bullet",
            pair.name()
        );
    }
    // The bullets' lengths are the clause's own lists (page index 108).
    assert_eq!(DoublePair::SinglePoint.types().len(), 4);
    assert_eq!(DoublePair::MeasuredNormalized.types().len(), 4);
    for pair in DoublePair::ALL {
        assert!(pair.types().len() >= 3);
    }
    // `M_PS_NA_1` and `M_ME_ND_1` are the extra untagged members, and a tagged
    // member names its own family.
    assert_eq!(
        DoublePair::of_type(TypeId::MPsNa1),
        Some(DoublePair::SinglePoint)
    );
    assert_eq!(
        DoublePair::of_type(TypeId::MMeNd1),
        Some(DoublePair::MeasuredNormalized)
    );
    assert_eq!(
        DoublePair::of_type(TypeId::MSpTb1),
        Some(DoublePair::SinglePoint)
    );
    assert_eq!(
        DoublePair::of_type(TypeId::MMeTb1),
        Some(DoublePair::MeasuredScaled)
    );
    assert_eq!(DoublePair::of_type(TypeId::MItNa1), None);
    assert_eq!(
        DoublePair::of_type(TypeId::MSpTa1),
        Some(DoublePair::SinglePoint)
    );
}

#[test]
fn clause_nines_permitted_tag_set_is_30_to_40() {
    // 104 clause 9 (PDF page index 100): for time-tagged ASDUs this companion
    // standard allows only the types <30> to <40>.
    for octet in 30u8..=40 {
        assert!(is_permitted_tag(TypeId::from_u8(octet)), "type {octet}");
    }
    // The `CP24Time2a` forms of 5-101 clause 7.3.1 are exactly what the
    // sentence removes from a 104 station's pairs.
    for type_id in [
        TypeId::MSpTa1,
        TypeId::MDpTa1,
        TypeId::MStTa1,
        TypeId::MBoTa1,
        TypeId::MMeTa1,
        TypeId::MMeTb1,
        TypeId::MMeTc1,
    ] {
        assert!(!is_permitted_tag(type_id), "{}", type_id.name());
    }
    for type_id in [TypeId::MSpNa1, TypeId::CScTa1, TypeId::FFrNa1] {
        assert!(!is_permitted_tag(type_id), "{}", type_id.name());
    }
}

/// A stand-in for the untagged half of a pair whose tagged twin is
/// `M_SP_TA_1` `<2>`, the `CP24Time2a` form a 104 station may not send
/// (clause 9, page index 100). It is here so the refusal is observable at all;
/// the crate's own `Doubles` implementations all use a `<30>` to `<40>` twin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ta2(MSpNa1);

impl AsduLayout for Ta2 {
    const TYPE_ID: TypeId = TypeId::MSpNa1;
    const LEN: usize = <MSpNa1 as AsduLayout>::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        Ok(Self(MSpNa1::parse(element)?))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

/// The `<2>` twin the stand-in would emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ta2Twin;

impl AsduLayout for Ta2Twin {
    const TYPE_ID: TypeId = TypeId::MSpTa1;
    const LEN: usize = <MSpTa1 as AsduLayout>::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        MSpTa1::parse(element)?;
        Ok(Self)
    }

    fn encode(&self, out: &mut Vec<u8>) {
        MSpTa1 {
            siq: Siq::default(),
            time: Cp24Time2a::default(),
        }
        .encode(out);
    }
}

impl Doubles for Ta2 {
    type Tagged = Ta2Twin;
    const PAIR: DoublePair = DoublePair::SinglePoint;

    fn doubled(&self, time: Cp56Time2a) -> Ta2Twin {
        // Never reached: the tag check runs first. The conversion is here so
        // the stand-in is a complete implementation of the trait.
        let _ = time.to_cp24();
        Ta2Twin
    }
}

/// A stand-in for a type outside clause 9.6's seven bullets: a counter value
/// with a pair claimed, so `NotADoublePair` is observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotAPair(MItNa1);

impl AsduLayout for NotAPair {
    const TYPE_ID: TypeId = TypeId::MItNa1;
    const LEN: usize = <MItNa1 as AsduLayout>::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        Ok(Self(MItNa1::parse(element)?))
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Doubles for NotAPair {
    type Tagged = Ta2Twin;
    const PAIR: DoublePair = DoublePair::SinglePoint;

    fn doubled(&self, _time: Cp56Time2a) -> Ta2Twin {
        Ta2Twin
    }
}

#[test]
fn a_tagged_twin_outside_the_permitted_set_is_refused() {
    let object = LayoutObject {
        ioa: IOA,
        value: Ta2(m_sp(true).value),
    };
    assert_eq!(
        doubled(&object, time(), CA, ORG),
        Err(TxError::TagNotPermitted {
            type_id: TypeId::MSpTa1,
        })
    );
    // And the same guard on the instance's method, after the selection.
    let station = controlled_all();
    assert_eq!(
        station.double(&object, time()),
        Err(TxError::TagNotPermitted {
            type_id: TypeId::MSpTa1,
        })
    );
}

#[test]
fn a_type_outside_clause_nine_sixs_seven_families_is_refused() {
    let object = LayoutObject {
        ioa: IOA,
        value: NotAPair(MItNa1 {
            bcr: Bcr::default(),
        }),
    };
    assert_eq!(
        doubled(&object, time(), CA, ORG),
        Err(TxError::NotADoublePair {
            type_id: TypeId::MItNa1,
        })
    );
}

#[test]
fn the_project_list_gates_the_double_transmission() {
    // 104 clause 9.6: which information object addresses get double
    // transmission is set by a list specific to the project.
    let list = ProjectList::new([IOA, 0x4002]);
    assert_eq!(list.addresses(), [IOA, 0x4002]);
    assert_eq!(list.len(), 2);
    assert!(!list.is_empty());
    assert!(list.contains(IOA));
    assert!(!list.contains(0x4009));
    assert!(ProjectList::empty().is_empty());
    assert!(!ProjectList::empty().contains(IOA));

    let station = Transmission::controlled(StationFunctions::ALL, ProjectList::empty(), CA, ORG);
    assert_eq!(
        station.double(&m_sp(true), time()),
        Err(TxError::DoubleNotEnabled { ioa: IOA })
    );
    let listed = Transmission::controlled(StationFunctions::ALL, ProjectList::new([IOA]), CA, ORG);
    assert_eq!(listed.double(&m_sp(true), time()).unwrap().len(), 2);
    assert_eq!(
        listed.doubles(),
        &ProjectList::new([IOA]),
        "the station exposes the list it was built with"
    );
    // Another address is not doubled by this list.
    let elsewhere = LayoutObject {
        ioa: 0x5000,
        value: m_sp(true).value,
    };
    assert_eq!(
        listed.double(&elsewhere, time()),
        Err(TxError::DoubleNotEnabled { ioa: 0x5000 })
    );
}

// ---------------------------------------------------------- the reception role

#[test]
fn the_reception_role_routes_the_three_causes() {
    let station = listening();
    assert_eq!(station.role(), Role::Controlling);
    assert_eq!(station.functions(), None, "a listener selects no function");

    let cases = [
        (
            cyclic(&m_me_na(0x2000), CA, ORG).unwrap(),
            Reaction::Cyclic {
                type_id: TypeId::MMeNa1,
            },
        ),
        (
            background(&m_sp(true), CA, ORG).unwrap(),
            Reaction::BackgroundScanned {
                type_id: TypeId::MSpNa1,
            },
        ),
        (
            spontaneous(&m_me_nb(0x1234), CA, ORG).unwrap(),
            Reaction::Spontaneous {
                type_id: TypeId::MMeNb1,
            },
        ),
    ];
    for (frame, expected) in cases {
        let outcome = station.on_response(&frame, &Known::EVERYTHING).unwrap();
        assert_eq!(outcome.reaction, expected);
        assert!(
            outcome.send.is_empty(),
            "none of the three causes answers anything"
        );
    }
}

#[test]
fn a_spontaneous_asdu_is_not_mistaken_for_an_answer() {
    // Cause 3 is the controlled station's own report; the answers of the other
    // procedures are causes 7/9/10/11/12 and 20–36, so nothing here can be
    // read as a confirmation.
    let station = listening();
    let frame = spontaneous(&m_sp(true), CA, ORG).unwrap();
    let outcome = station.on_response(&frame, &Known::EVERYTHING).unwrap();
    assert!(matches!(outcome.reaction, Reaction::Spontaneous { .. }));
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
    // A spontaneous clock time (TS 60870-5-604's announcement, `cs`) is not
    // one of this module's types in 104 (clause 9 draws <103>/cause 3 black).
    let clock = iec104::cs::announcement(time(), CA, ORG).unwrap();
    let outcome = station.on_response(&clock, &Known::EVERYTHING).unwrap();
    assert!(!matches!(outcome.reaction, Reaction::Spontaneous { .. }));
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
    // An activation confirmation is a different cause, not one of the three.
    let confirmation = hand_built(TypeId::MSpNa1, Cause::ActivationCon);
    assert_eq!(
        station
            .on_response(&confirmation, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );
}

#[test]
fn a_cause_the_types_table_does_not_carry_is_not_this_packages_frame() {
    let station = listening();
    // A counter value with cause `<2>`: `M_IT_NA_1` is not in Table 21.
    let counter = hand_built(TypeId::MItNa1, Cause::BackgroundScan);
    assert_eq!(
        station
            .on_response(&counter, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );
    // A time-tagged type with cause `<1>`: Table 16's cyclic row has no `<30>`
    // to `<40>` member (clause 9's tag set).
    let tagged = hand_built(TypeId::MSpTb1, Cause::Periodic);
    assert_eq!(
        station
            .on_response(&tagged, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );
    // A cause outside the three, on a type the three causes carry.
    let file = hand_built(TypeId::MSpNa1, Cause::FileTransfer);
    assert_eq!(
        station
            .on_response(&file, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );
    // A CP24Time2a monitor form with cause `<3>`: 5-101 Table 16's event row
    // names its octet, but 5-104 clause 9 (index 100) strikes it out of the
    // direction list, so the reception side reads it as not one of its frames.
    let m_sp_ta = hand_built(TypeId::MSpTa1, Cause::Spontaneous);
    assert_eq!(
        station
            .on_response(&m_sp_ta, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );
    // The delay acquisition is struck out of 104's control-direction list too,
    // so a cause-`<3>` frame of it is not a spontaneous ASDU either.
    let c_cd_na = hand_built(TypeId::CCdNa1, Cause::Spontaneous);
    assert_eq!(
        station
            .on_response(&c_cd_na, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );
    // The reception side does not consult a selection: a listener that selects
    // nothing still classifies what arrives.
    assert_eq!(station.functions(), None);
}

#[test]
fn the_discard_rule_runs_first() {
    let station = listening();
    // 5-101 clause 7.2.3 (PDF page index 38): a monitor-direction ASDU the
    // station's profile does not know is discarded and may be logged, and
    // receiving one must leave the handling of later messages unaffected.
    let frame = cyclic(&m_me_na(0x2000), CA, ORG).unwrap();
    let outcome = station.on_response(&frame, &Known::NOTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Discard(Discard::Unspecified(Unspecified::TypeIdentification))
    );
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
    // The same frame is a cyclic ASDU when the profile knows the fields.
    assert!(matches!(
        station
            .on_response(&frame, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Cyclic { .. }
    ));
    // A received 44–47 mirror is discarded rather than processed (5-101
    // cl.7.2.3).
    let mut mirror = hand_built(TypeId::MSpNa1, Cause::UnknownTypeId);
    mirror[2] |= 0x40;
    assert_eq!(
        station
            .on_response(&mirror, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Discard(Discard::Mirror)
    );
}

#[test]
fn the_wrong_role_is_a_typed_refusal() {
    let station = controlled_all();
    assert_eq!(
        station.on_response(
            &cyclic(&m_me_na(0x2000), CA, ORG).unwrap(),
            &Known::EVERYTHING
        ),
        Err(TxError::WrongRole)
    );
    let listener = listening();
    assert_eq!(listener.cyclic(&m_me_na(0x2000)), Err(TxError::WrongRole));
    assert_eq!(listener.background(&m_sp(true)), Err(TxError::WrongRole));
    assert_eq!(listener.spontaneous(&m_sp(true)), Err(TxError::WrongRole));
    assert_eq!(
        listener.double(&m_sp(true), time()),
        Err(TxError::WrongRole)
    );
}

// ---------------------------------------------------------------- truncation

#[test]
fn every_short_prefix_of_every_frame_is_a_typed_error() {
    let station = listening();
    let frames = every_frame();
    assert!(frames.len() >= 17, "the sweep must cover every producer");
    for frame in frames {
        for cut in 0..frame.len() {
            let outcome = station.on_response(&frame[..cut], &Known::EVERYTHING);
            assert!(
                outcome.is_err(),
                "a {cut}-octet prefix of a {}-octet frame was accepted",
                frame.len()
            );
        }
        // The whole frame is accepted: the sweep is about the prefixes.
        assert!(station.on_response(&frame, &Known::EVERYTHING).is_ok());
    }
}

#[test]
fn a_prefix_of_a_header_alone_is_never_a_frame() {
    let station = listening();
    for cut in 0..6 {
        assert_eq!(
            station.on_response(
                &[0x01, 0x01, 0x02, 0x07, 0x0C, 0x00][..cut],
                &Known::EVERYTHING
            ),
            Err(TxError::Layout(iec104::asdu::LayoutError::Asdu(
                AsduError::TooShort { need: 6, have: cut }
            )))
        );
    }
    // A body one octet short of the element geometry is a truncation, not a
    // classification: the address reads, its `SIQ` does not.
    let frame = background(&m_sp(true), CA, ORG).unwrap();
    let short = &frame[..frame.len() - 1];
    assert_eq!(
        station.on_response(short, &Known::EVERYTHING),
        Err(TxError::Layout(iec104::asdu::LayoutError::Asdu(
            AsduError::TruncatedElement {
                index: 0,
                need: 1,
                have: 0,
            }
        )))
    );
}

#[test]
fn the_body_cursor_agrees_with_the_reception_walk() {
    // The reception side walks the object area with the type's own element
    // length; the same call the crate's own reader makes must see the same
    // frame.
    let frame = background(&m_sp(true), CA, ORG).unwrap();
    let mut cursor = BodyReader::from_asdu(&frame).unwrap();
    let object = cursor
        .next_object(element_len(TypeId::MSpNa1).unwrap())
        .unwrap();
    assert_eq!(object.unwrap().ioa, IOA);
    assert!(cursor.next_object(1).unwrap().is_none());
    cursor.finish().unwrap();
}

/// The six-octet data unit identifier of 5-101 cl.7.1 (figure 11), written out
/// by hand: type, variable structure qualifier (`SQ = 0`, `N = 1`), cause,
/// originator 0, common address 1 (two octets).
fn header(type_id: u8, cause: u8) -> iec104::asdu::Header {
    let octets = [type_id, 0x01, cause, 0x00, 0x01, 0x00];
    iec104::asdu::Header::parse(&octets).expect("a valid data unit identifier")
}

/// 5-101 Table 16 (clause 7.4, PDF page index 121), several ASDUs per row of
/// the table, each classified by the row the table gives it, and the rows in
/// the table's order. The "Request ASDU" column makes an answer part of its
/// request's row: interrogated data (causes 20 to 41) is in the `100, 101`
/// row, a read's object (cause 5) in the `102` row, events (`COT = 3`) in the
/// `1 to 44` row and cyclic data (`COT = 1`) in the last.
#[test]
fn table_16_rows() {
    use iec104::tx::{Priority, respond_priority};
    let rows = [
        // 70 End of initialization, cause 4.
        (header(70, 4), Priority::EndOfInitialisation),
        // 45 to 69 Command transmission, "Mirrored ASDUs": ACTCON, ACTTERM,
        // and a cause 47 mirror with P/N = 1 (0x40 | 47).
        (header(45, 7), Priority::Command),
        (header(46, 10), Priority::Command),
        (header(58, 0x40 | 0x2F), Priority::Command),
        // 1 to 44 with COT = 3, 103 and 106.
        (header(1, 3), Priority::Event),
        (header(30, 3), Priority::Event),
        (header(103, 7), Priority::Event),
        (header(106, 7), Priority::Event),
        // 102, 104, 105, 110 to 113, and a read's answer with cause 5.
        (header(11, 5), Priority::Request),
        (header(104, 7), Priority::Request),
        (header(105, 7), Priority::Request),
        (header(110, 7), Priority::Request),
        (header(113, 7), Priority::Request),
        // 100, 101 and the data they return (causes 20 to 36, 37 to 41).
        (header(100, 7), Priority::Interrogation),
        (header(1, 20), Priority::Interrogation),
        (header(13, 36), Priority::Interrogation),
        (header(101, 10), Priority::Interrogation),
        (header(15, 37), Priority::Interrogation),
        (header(15, 41), Priority::Interrogation),
        // 9, 11, 13, 21 with COT = 1, and 120 to 127.
        (header(9, 1), Priority::Cyclic),
        (header(21, 1), Priority::Cyclic),
        (header(120, 13), Priority::Cyclic),
        (header(127, 5), Priority::Cyclic),
    ];
    for (header, row) in rows {
        assert_eq!(respond_priority(&header), row, "{header:?}");
    }
    assert!(Priority::EndOfInitialisation < Priority::Command);
    assert!(Priority::Command < Priority::Event);
    assert!(Priority::Event < Priority::Request);
    assert!(Priority::Request < Priority::Interrogation);
    assert!(Priority::Interrogation < Priority::Cyclic);
}

/// What Table 16 does not name, placed by this crate's reading (see
/// `respond_priority`): `<107>` `C_TS_TA_1` is 104's test command (104 Table
/// 4) and takes the test procedure's row; return information (causes 11, 12,
/// 5-101 cl.7.4.7) goes with the events; the background scan (cause 2, 5-101
/// cl.7.4.13, run continuously at low priority) with the cyclic data; a
/// mirror of a type the table does not list (cause 44, `P/N = 1`) with the
/// requests.
#[test]
fn table_16_what_it_does_not_name() {
    use iec104::tx::{Priority, respond_priority};
    assert_eq!(respond_priority(&header(107, 7)), Priority::Request);
    assert_eq!(respond_priority(&header(31, 11)), Priority::Event);
    assert_eq!(respond_priority(&header(1, 12)), Priority::Event);
    assert_eq!(respond_priority(&header(1, 2)), Priority::Cyclic);
    assert_eq!(
        respond_priority(&header(200, 0x40 | 0x2C)),
        Priority::Request
    );
}

// ---------------------------------------------------------------------------
// Packing events: TS 60870-5-604 5.4.16.1 (PDF page index 63): events that
// share type, COT and priority but have non-contiguous addresses go out
// together in one ASDU as a set of information elements (SQ = 0), filled up
// to the maximum ASDU or APDU length the PICS configures. The octets below
// are 5-101 clause 7.2.2.1's variable structure
// qualifier (SQ = 0, N objects) and clause 7.3.1.11's M_ME_NB_1 object (a
// three octet address, SVA as two octets low first, QDS), with the
// conventional sizes: type, VSQ, cause, originator, common address (two).
// ---------------------------------------------------------------------------

/// One spontaneous `M_ME_NB_1` object at `ioa` of common address 1.
fn scaled_event(ioa: u32, value: i16) -> Vec<u8> {
    let [a0, a1, a2, _] = ioa.to_le_bytes();
    let [v0, v1] = value.to_le_bytes();
    vec![11, 1, 3, 0, 1, 0, a0, a1, a2, v0, v1, 0]
}

#[test]
fn two_events_of_one_type_and_cause_share_an_asdu() {
    let mut asdu = scaled_event(100, 1000);
    assert!(tx::append_objects(
        &mut asdu,
        &scaled_event(101, -2),
        iec104::asdu::AddressSizes::CONVENTIONAL
    ));
    assert_eq!(
        asdu,
        [
            11, 2, 3, 0, 1, 0, // M_ME_NB_1, SQ = 0 and N = 2, cause 3, CA 1
            100, 0, 0, 0xe8, 0x03, 0, // address 100, 1000, QDS 0
            101, 0, 0, 0xfe, 0xff, 0, // address 101, -2, QDS 0
        ]
    );
}

#[test]
fn events_that_differ_in_what_5_4_16_1_names_do_not_share_an_asdu() {
    let sizes = iec104::asdu::AddressSizes::CONVENTIONAL;
    let other = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut asdu = scaled_event(101, 7);
        f(&mut asdu);
        asdu
    };
    for (name, next) in [
        // M_SP_NA_1, SIQ ON: another type.
        ("type", vec![1, 1, 3, 0, 1, 0, 101, 0, 0, 1]),
        ("cause", other(&|a| a[2] = 20)),
        ("test bit", other(&|a| a[2] |= 0x80)),
        ("negative bit", other(&|a| a[2] |= 0x40)),
        ("originator", other(&|a| a[3] = 9)),
        ("common address", other(&|a| a[4] = 2)),
        ("SQ = 1", other(&|a| a[1] = 0x81)),
        // Kept apart so a controlling station that takes an ASDU as a set
        // still sees both values.
        ("the same address", scaled_event(100, 8)),
        ("cut short", scaled_event(101, 7)[..10].to_vec()),
    ] {
        let mut asdu = scaled_event(100, 1000);
        assert!(!tx::append_objects(&mut asdu, &next, sizes), "{name}");
        assert_eq!(asdu, scaled_event(100, 1000), "{name}: unchanged");
    }
}

#[test]
fn an_asdu_is_filled_up_to_and_not_beyond_249_octets() {
    // 5-104 clause 5: the ASDU is 249 octets at most.
    // Six octets of header and six per M_ME_NB_1 object: 40 objects make 246
    // octets, a 41st would make 252.
    let sizes = iec104::asdu::AddressSizes::CONVENTIONAL;
    let mut asdu = scaled_event(1, 0);
    for ioa in 2..=40 {
        assert!(
            tx::append_objects(&mut asdu, &scaled_event(ioa, 0), sizes),
            "{ioa}"
        );
    }
    assert_eq!(asdu.len(), 246);
    assert_eq!(asdu[1], 40);
    assert!(!tx::append_objects(&mut asdu, &scaled_event(41, 0), sizes));
    assert_eq!(asdu.len(), 246);
}
