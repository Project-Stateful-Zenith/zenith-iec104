//! The clause 9 interoperability support matrix as data (`iec104::interop`).
//!
//! One test per clause 9 subsection, each reading its own row back against the
//! page it was read on (PDF page indices, 0-based; every one re-read with
//! `pymupdf` on 2026-09-25 before it was quoted here). The module under test is
//! `src/interop.rs`; the clause 7.2.3 seam it feeds is `asdu::Known::for_profile`.
//!
//! The rows and their pages: 9.1/9.2/9.3/9.4 (index 94 and index 96: the
//! system/device and network rows, and the two subsections 104 strikes through),
//! 9.5 (index 98: the transmission mode, the four address-width rows and the
//! APDU length), 9.6 (index 108, index 112 and index 114: the thirteen function
//! rows and the two parameter tables) and the type/cause grid (index 104 and
//! index 106, whose drawn fills are the standard's own selection).

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::unwrap_used)]

use iec104::apci;
use iec104::asdu::{
    Cause, Discard, Header, Known, TypeId, Unspecified, classify, discard_reason, mirror_reply,
};
use iec104::interop::{
    CAUSE_COLUMNS, CauseColumn, Cell, Direction, Function, InteropProfile, SHEET, TYPE_ROWS,
    column_of, row_of,
};
use iec104::params::{K_MAX, LinkParams, PORT, T_MAX, T3_RECOMMENDED_MAX};
use iec104::{ci, ft, ts};

/// A minimal `M_SP_NA_1` ASDU: one object, cause 3, CA 1, IOA 1, SIQ 0.
const M_SP_NA_1: &[u8] = &[0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00];

/// A minimal `C_CS_NA_1` ASDU: one object, cause 6 (activation), CA 1, IOA 0
/// and an all-zero `CP56Time2a` (the field is what the header path under test
/// never reads).
const C_CS_NA_1: &[u8] = &[
    0x67, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,
];

/// 9.1 System or device / 9.2 Network configuration / 9.3 Physical layer / 9.4
/// Link layer: the four subsections this crate does **not** make
/// configurable, and the two fixed values 104 prints.
///
/// Index 94 prints 9.1 (*"(system-specific parameter, indicate definition of a
/// system or a device by marking one of the following with \" **X** \")"*) and
/// 9.2 (*"(network-specific parameter, all configurations that are used are to
/// be marked \" **X** \")"*); index 96 prints 9.3 (*"(network-specific parameter,
/// all interfaces and data rates that are used are to be marked \" **X** \")"*)
/// and 9.4 (*"(network-specific parameter, all options that are used are to be
/// marked \" **X** \". Specify the maximum frame length. …)"*) and then strikes
/// the link layer through: *"Frame format FT 1.2, single character 1 and the
/// fixed time out interval are used exclusively in this companion standard."*
///
/// Those rows describe the **network and the device**, not the ASDU exchange, so
/// the profile carries none of them: there is no interface, data-rate, frame
/// length or balance knob anywhere in this crate, and the two values 104 fixes
/// on 9.5's page are asserted here as the constants they are.
#[test]
fn the_network_and_device_rows_of_9_1_to_9_4_are_not_configurables() {
    // 9.5 (index 98): "The maximum length of APDU for both directions is 253.
    // It is a fixed system parameter." The length *field* is 253, the ASDU
    // 249 (104 cl.5, index 26).
    assert_eq!(apci::MAX_LENGTH, 253);
    assert_eq!(apci::MAX_ASDU, 249);
    // 9.4 (index 96) strikes the FT 1.2 frame format through; the modular TCP
    // profile of 104 keeps the 68H start octet alone.
    assert_eq!(apci::START, 0x68);
    // 9.5 (index 98): "Mode 1 (Least significant octet first), as defined in
    // 4.10 of IEC 60870-5-4, is used exclusively in this companion standard."
    // There is no transmission-mode setting, and the one byte-order decision the
    // crate makes is little-endian, asserted on the header's CA field.
    let header = Header::parse(&[0x01, 0x01, 0x03, 0x00, 0x34, 0x12]).unwrap();
    assert_eq!(header.common_address, 0x1234, "little-endian, Mode 1");
}

/// 9.5 Application layer (index 98): the sheet's **filled example**.
///
/// *"Common address of ASDU (system-specific parameter, all configurations that
/// are used are to be marked \" **X** \")"* with *"One octet"* / *"Two octets"*;
/// *"Information object address …"* with *"One octet"* / *"Structured"* /
/// *"Two octets"* / *"Unstructured"* / *"Three octets"*; *"Cause of
/// transmission …"* with *"One octet"* / *"Two octets (with originator address).
/// Originator address is set to zero if not used"*.
///
/// The printed page's three `X` marks are in the *Two octets* CA column, the
/// *Three octets* IOA row and the *Two octets (with originator address)* COT
/// column (measured on index 98: three `X` glyphs, nothing else marked), which
/// is exactly `AddressSizes::CONVENTIONAL`. The conventional profile is
/// therefore the sheet's own example and not a crate preference.
#[test]
fn the_address_rows_of_9_5_are_the_sheets_own_marked_example() {
    let profile = InteropProfile::conventional();
    assert_eq!(
        profile.address_sizes,
        iec104::asdu::AddressSizes::CONVENTIONAL
    );
    assert!(profile.address_sizes.originator_address());
    assert_eq!(profile.address_sizes.common_address_octets(), 2);
    assert_eq!(profile.address_sizes.information_object_address_octets(), 3);
    assert_eq!(profile.address_sizes.header_len(), 6);
    // The sheet's own example is the crate's default, and `AddressSizes` (the
    // crate's configurable address widths) is the value the profile carries
    // rather than re-models.
    assert_eq!(
        InteropProfile::default().address_sizes,
        profile.address_sizes
    );
}

/// 9.6's *"Definition of time outs"* and *"Maximum number of outstanding I
/// format APDUs k and latest acknowledge APDUs (w)"* (index 114), and 9.6's
/// port number.
///
/// *"t0 30 s Time-out of connection establishment"*, *"t1 15 s Time-out of send
/// or test APDUs"*, *"t2 10 s Time-out for acknowledges in case of no data
/// messages t2 < t1"*, *"t3 20 s Time-out for sending test frames in case of a
/// long idle state"*, *"Maximum range for timeouts t0 to t2: 1 s to 255 s,
/// accuracy 1 s."*, *"Recommended range for timeout t3: 1 s to 48 h, resolution
/// 1 s."*; *"k 12 APDUs"*, *"w 8 APDUs"*, *"Maximum range of values k: 1 to
/// 32767 (215–1) APDUs, accuracy 1 APDU"*.
///
/// The profile **carries** `params::LinkParams` (the crate's one time-out type)
/// rather than a second copy of the table, and the table's own ranges are the
/// constants beside it.
#[test]
fn the_time_outs_and_k_w_of_9_5_are_the_link_params_table() {
    let profile = InteropProfile::conventional();
    assert_eq!(profile.link, LinkParams::default());
    assert_eq!(profile.link.validate(), Ok(()));
    assert_eq!(profile.link.port, PORT);
    assert_eq!((profile.link.k, profile.link.w), (12, 8));
    assert_eq!(profile.link.t0.as_secs(), 30);
    assert_eq!(profile.link.t1.as_secs(), 15);
    assert_eq!(profile.link.t2.as_secs(), 10);
    assert_eq!(profile.link.t3.as_secs(), 20);
    assert!(profile.link.t2 < profile.link.t1, "t2 < t1");
    // The printed ranges.
    assert_eq!(T_MAX.as_secs(), 255, "1 s to 255 s for t0 to t2");
    assert_eq!(T3_RECOMMENDED_MAX.as_secs(), 48 * 60 * 60, "1 s to 48 h");
    assert_eq!(K_MAX, 32767, "1 to 32767 (2^15 - 1) APDUs");
}

/// The marking scheme of index 94.
///
/// *"The selected parameters should be marked in the white boxes as follows:"*
/// *"Function or ASDU is not used"* (blank), *"**X** Function or ASDU is used as
/// standardized (default)"*, *"**R** Function or ASDU is used in reverse mode"*,
/// *"**B** Function or ASDU is used in standard and reverse mode"*; and *"The
/// possible selection (blank, X, R, or B) is specified for each specific clause
/// or parameter."*
#[test]
fn the_marking_scheme_is_the_four_valued_one_of_index_94() {
    assert_eq!(Direction::ALL.len(), 4, "blank, X, R, B");
    assert_eq!(Direction::ALL[0], Direction::NotUsed);

    assert!(
        !Direction::NotUsed.is_used(),
        "Function or ASDU is not used"
    );
    assert!(Direction::Standard.is_used());
    assert!(Direction::Reverse.is_used());
    assert!(Direction::Both.is_used());

    assert!(Direction::Standard.is_standard());
    assert!(
        !Direction::Reverse.is_standard(),
        "R is not the standard mark"
    );
    assert!(!Direction::Both.is_standard(), "B is not X");
    assert!(!Direction::NotUsed.is_standard());

    assert!(!Direction::Standard.is_reverse());
    assert!(Direction::Reverse.is_reverse(), "used in reverse mode");
    assert!(
        Direction::Both.is_reverse(),
        "used in standard and reverse mode"
    );
    assert!(!Direction::NotUsed.is_reverse());

    // The three accessors partition the four marks the way the sheet's four
    // sentences do: exactly one blank, and X and R/B split the rest.
    let blank = Direction::ALL.iter().filter(|mark| !mark.is_used()).count();
    let standard = Direction::ALL
        .iter()
        .filter(|mark| mark.is_standard())
        .count();
    let reverse = Direction::ALL
        .iter()
        .filter(|mark| mark.is_reverse())
        .count();
    assert_eq!((blank, standard, reverse), (1, 1, 2));
}

/// The grid's header row (index 104 and index 106),
/// *"Type identification / Cause of transmission"*, `1 2 3 4 5 6 7 8 9 10
/// 11 12 13 20 to 36 37 to 41 44 45 46 47`: **nineteen** columns.
///
/// The sheet groups the causes itself, so the type stores the grouping: the
/// interrogation causes 20–36 share a column and the counter requests 37–41
/// share one, exactly as the header prints *"20 to 36"* and *"37 to 41"*.
#[test]
fn the_grid_header_row_is_the_nineteen_columns_of_index_104() {
    assert_eq!(CAUSE_COLUMNS.len(), 19);
    let headings: Vec<&str> = CAUSE_COLUMNS
        .iter()
        .map(|column| column.heading())
        .collect();
    assert_eq!(
        headings,
        [
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "20 to 36",
            "37 to 41", "44", "45", "46", "47"
        ]
    );

    // Every one of the sheet's 39 named causes falls in exactly one column, and
    // the reserved/private/not-used values fall in none.
    for value in 1u8..=47 {
        let cause = Cause::from_u8(value);
        let columns: Vec<usize> = CAUSE_COLUMNS
            .iter()
            .enumerate()
            .filter(|(_, column)| column.accepts(cause))
            .map(|(index, _)| index)
            .collect();
        if matches!(cause, Cause::Reserved(_) | Cause::NotUsed) {
            assert!(columns.is_empty(), "{value} is not a grid column");
            assert_eq!(column_of(cause), None);
        } else {
            assert_eq!(columns.len(), 1, "cause {value} is one column");
            assert_eq!(column_of(cause), Some(columns[0]));
        }
    }
    // The ranges are columns of their own, not single causes.
    assert!(CAUSE_COLUMNS[13].accepts(Cause::InterrogatedByStation));
    assert!(CAUSE_COLUMNS[13].accepts(Cause::InterrogatedByGroup(16)));
    assert!(CAUSE_COLUMNS[14].accepts(Cause::RequestedByGeneralCounter));
    assert!(CAUSE_COLUMNS[14].accepts(Cause::RequestedByCounterGroup(4)));
    assert!(matches!(CAUSE_COLUMNS[13], CauseColumn::Interrogated));
    assert!(matches!(CAUSE_COLUMNS[14], CauseColumn::CounterRequested));
    // The four "unknown …" columns are the clause 7.2.3 replies.
    assert!(
        CAUSE_COLUMNS[15..]
            .iter()
            .all(|column| column.is_unknown_reply())
    );
    assert!(!CAUSE_COLUMNS[0].is_unknown_reply());
}

/// The grid's rows: the type identifications index 104 and index 106 print.
///
/// The list is the sheet's own, **including** the rows 104 black-boxes:
/// *"Black boxes: option not permitted in this companion standard"*. `<104>`
/// (`C_TS_NA_1`) and `<106>` (`C_CD_NA_1`) are printed and have no white box on
/// the sheet, so they are rows with every cell blank and not missing entries.
#[test]
fn the_grid_rows_are_the_types_of_index_104_and_index_106() {
    assert_eq!(TYPE_ROWS.len(), 67, "the sheet's own row count");
    let mut seen = Vec::new();
    for row in TYPE_ROWS {
        assert!(!seen.contains(&row.to_u8()), "{row:?} appears twice");
        seen.push(row.to_u8());
        assert!(row.info().is_some(), "{row:?} is not a catalogued type");
        assert_eq!(row_of(row), Some(seen.len() - 1));
    }
    // The two black-boxed rows are in the table and are all blank.
    assert!(TYPE_ROWS.contains(&TypeId::CTsNa1));
    assert!(TYPE_ROWS.contains(&TypeId::CCdNa1));
    let profile = InteropProfile::conventional();
    assert!(!profile.uses_type(TypeId::CTsNa1), "104 black-boxes <104>");
    assert!(!profile.uses_type(TypeId::CCdNa1), "104 black-boxes <106>");
    // A private type has no row at all.
    assert_eq!(row_of(TypeId::Other(200)), None);
    assert!(!profile.uses_type(TypeId::Other(200)));
}

/// 9.6 Basic application functions (index 108, index 112, index 114): the
/// thirteen rows, one [`Direction`] each, and the profile's default.
///
/// index 108: *"Station initialization (station-specific parameter, mark \" **X**
/// \" if function is used)"* with *"Remote initialization"*; *"Cyclic data
/// transmission (station-specific parameter, mark \" **X** \" if function is only
/// used in the standard direction, …)"*; *"Read procedure …"*; *"Spontaneous
/// transmission …"*; *"Double transmission of information objects with cause of
/// transmission spontaneous"*.
///
/// index 112: *"Transmission of integrated totals (station- or object-specific
/// parameter, …)"*; *"Parameter loading (object-specific parameter, …)"*;
/// *"Parameter activation (object-specific parameter, …)"*; *"Test procedure
/// (station-specific parameter, …)"*.
///
/// index 114: *"File transfer (station-specific parameter, mark \" **X** \" if
/// function is used)."* with *"File transfer in monitor direction"* and *"File
/// transfer in control direction"*; *"Background scan (station-specific
/// parameter, …)"*; *"Acquisition of transmission delay (station-specific
/// parameter, …)"*, struck through on the page, which 104's own rule explains:
/// *"the text descriptions of parameters which are not applicable to this
/// companion standard are strike-through"* (index 94).
#[test]
fn every_clause_9_6_row_reads_its_own_mark_back() {
    assert_eq!(Function::ALL.len(), 13);
    for (index, row) in Function::ALL.iter().enumerate() {
        assert_eq!(row.index(), index, "Function::ALL is the index order");
        assert_ne!(row.name(), "");
        assert!((108..=114).contains(&row.page_index()));
    }

    let profile = InteropProfile::conventional();
    for row in Function::ALL {
        if row == Function::AcquisitionOfTransmissionDelay {
            // Struck through in this companion standard.
            assert_eq!(profile.function(row), Direction::NotUsed, "{row:?}");
            assert!(!profile.uses_function(row));
        } else {
            assert_eq!(profile.function(row), Direction::Standard, "{row:?}");
            assert!(profile.uses_function(row));
        }
    }

    // The three "if function is used" rows are the sheet's two-valued ones
    // (index 108's "Station initialization" and index 114's two "File transfer"
    // direction rows, which share its one sentence).
    let used_only: Vec<Function> = Function::ALL
        .iter()
        .copied()
        .filter(|row| row.is_used_only())
        .collect();
    assert_eq!(
        used_only,
        [
            Function::StationInitialization,
            Function::FileTransferMonitor,
            Function::FileTransferControl
        ]
    );

    // Every row is settable and reads back: the profile is data, not a branch.
    for row in Function::ALL {
        let marked = profile.clone().with_function(row, Direction::Reverse);
        assert_eq!(marked.function(row), Direction::Reverse, "{row:?}");
        assert!(marked.function(row).is_reverse());
        assert!(!marked.function(row).is_standard());
        // The original profile is untouched.
        assert_eq!(
            profile.function(row),
            if row == Function::AcquisitionOfTransmissionDelay {
                Direction::NotUsed
            } else {
                Direction::Standard
            }
        );
    }
}

/// The type/cause grid itself, *"Mark Type Identification/Cause of
/// transmission combinations"* (index 104), is the **sheet's own** selection
/// and not a derivation: the grid body carries no letter, but every box is
/// drawn, and the legend beside the grid names the three fills.
///
/// *"Shaded boxes: option not required. Black boxes: option not permitted in
/// this companion standard Blank: functions or ASDU not used."* So a white box
/// is the only one a station may select ([`Cell::White`]), and
/// [`InteropProfile::conventional`] marks precisely those, one `X` each.
///
/// The expected counts are the measurement recorded on `interop::SHEET_ROWS`:
/// each page rendered and every box centre sampled, cross-checked against the
/// fills `pymupdf`'s `page.get_drawings()` reports (`fill 0.0` black, `fill 0.88`
/// shaded, and no fill, or an explicit white `fill 1.0` over the shading, for a
/// white box), on index 104 (rows `<1>`–`<12>`) and index 106 (rows
/// `<13>`–`<127>`, the English continuation).
#[test]
fn the_type_cause_grid_is_the_sheets_own_white_boxes() {
    // The three fills over the whole 67 × 19 grid: 303 white, 39 black, 931
    // shaded, so all 1 273 boxes are accounted for.
    let mut white = 0usize;
    let mut black = 0usize;
    let mut shaded = 0usize;
    for row in SHEET {
        for cell in row {
            match cell {
                Cell::White => white += 1,
                Cell::Black => black += 1,
                Cell::Shaded => shaded += 1,
            }
        }
    }
    assert_eq!((white, black, shaded), (303, 39, 931));
    assert_eq!(
        white + black + shaded,
        TYPE_ROWS.len() * CAUSE_COLUMNS.len()
    );
    assert_eq!(SHEET.len(), TYPE_ROWS.len());
    assert_eq!(SHEET[0].len(), CAUSE_COLUMNS.len());

    // The whole-table check: the conventional grid's marked-cell count is
    // exactly the sheet's white-box count.
    let profile = InteropProfile::conventional();
    let marked: usize = profile
        .grid_rows()
        .iter()
        .map(|line| {
            line.split_once(' ')
                .map_or(1, |(_, columns)| columns.split(',').count())
        })
        .sum();
    assert_eq!(
        marked, white,
        "the conventional grid is the sheet's white boxes and nothing else"
    );

    // The converse over every box: a black one is never marked, and there are
    // as many checked as the table counted.
    let representative = |column: CauseColumn| match column {
        CauseColumn::One(cause) => cause,
        CauseColumn::Interrogated => Cause::InterrogatedByStation,
        CauseColumn::CounterRequested => Cause::RequestedByGeneralCounter,
    };
    let mut checked = 0usize;
    for (row, &type_id) in TYPE_ROWS.iter().enumerate() {
        for (column, &cell) in SHEET[row].iter().enumerate() {
            if cell.is_not_permitted() {
                let cause = representative(CAUSE_COLUMNS[column]);
                assert!(!profile.uses(type_id, cause), "{type_id:?} with {cause:?}");
                checked += 1;
            }
        }
    }
    assert_eq!(checked, black);
}

/// The grid answers pair by pair, and every answer is the sheet's own.
///
/// One assertion per family the nineteen columns group: the two ranges the
/// header prints (`20 to 36` and `37 to 41`), the monitor causes a status type
/// answers, the control causes, the read reply and the parameter row, plus the
/// end-to-end answer through the clause 7.2.3 seam.
#[test]
fn the_type_cause_grid_answers_pair_by_pair() {
    let profile = InteropProfile::conventional();

    // A status type answers the request, the return information and the
    // interrogation column. It is not periodic, not an activation, and never
    // its own unknown-cause.
    for cause in [
        Cause::Request,
        Cause::ReturnInfoRemote,
        Cause::ReturnInfoLocal,
        Cause::InterrogatedByGroup(7),
    ] {
        assert_eq!(
            profile.direction(TypeId::MSpNa1, cause),
            Direction::Standard,
            "M_SP_NA_1 with {cause:?}"
        );
    }
    for cause in [Cause::Periodic, Cause::Activation, Cause::UnknownCause] {
        assert_eq!(
            profile.direction(TypeId::MSpNa1, cause),
            Direction::NotUsed,
            "M_SP_NA_1 with {cause:?}"
        );
    }

    // The initialisation end is the one monitor type in the `init` column.
    assert_eq!(
        profile.direction(TypeId::MEiNa1, Cause::Initialized),
        Direction::Standard
    );
    assert_eq!(
        profile.direction(TypeId::MSpNa1, Cause::Initialized),
        Direction::NotUsed
    );

    // The transmission of integrated totals: `M_IT_NA_1` and `M_IT_TB_1` are
    // the types the `37 to 41` column is for, and the interrogation column is
    // not theirs.
    assert_eq!(
        profile.direction(TypeId::MItNa1, Cause::RequestedByGeneralCounter),
        Direction::Standard
    );
    assert_eq!(
        profile.direction(TypeId::MItNa1, Cause::InterrogatedByStation),
        Direction::NotUsed
    );
    assert_eq!(
        profile.direction(TypeId::MItTb1, Cause::RequestedByCounterGroup(4)),
        Direction::Standard
    );

    // `C_CI_NA_1` asks for the counters; it is not itself a counter reply, and
    // its activation is its own.
    assert_eq!(
        profile.direction(TypeId::CCiNa1, Cause::RequestedByCounterGroup(2)),
        Direction::NotUsed
    );
    assert_eq!(
        profile.direction(TypeId::CCiNa1, Cause::Activation),
        Direction::Standard
    );
    assert_eq!(
        profile.direction(TypeId::CCsNa1, Cause::Activation),
        Direction::Standard
    );

    // A command is not the answer to a read, and neither is the read's own
    // activation; the read request is.
    assert_eq!(
        profile.direction(TypeId::CScNa1, Cause::Request),
        Direction::NotUsed
    );
    assert_eq!(
        profile.direction(TypeId::CRdNa1, Cause::Activation),
        Direction::NotUsed
    );
    assert_eq!(
        profile.direction(TypeId::CRdNa1, Cause::Request),
        Direction::Standard
    );

    // A parameter type answers the interrogation.
    assert_eq!(
        profile.direction(TypeId::PMeNa1, Cause::InterrogatedByGroup(1)),
        Direction::Standard
    );

    // A file-transfer type: cause 13 only.
    assert_eq!(
        profile.direction(TypeId::FFrNa1, Cause::FileTransfer),
        Direction::Standard
    );
    assert_eq!(
        profile.direction(TypeId::FFrNa1, Cause::Spontaneous),
        Direction::NotUsed
    );

    // A cause outside the grid is blank for every type.
    assert_eq!(
        profile.direction(TypeId::MSpNa1, Cause::Private(50)),
        Direction::NotUsed
    );
    assert_eq!(
        profile.direction(TypeId::MSpNa1, Cause::NotUsed),
        Direction::NotUsed
    );

    the_seam_and_the_mutators(&profile);
}

/// The end of the grid test: a pair the profile uses passes the clause 7.2.3
/// seam, and the two mutators change only what the sheet prints.
fn the_seam_and_the_mutators(profile: &InteropProfile) {
    // End to end through the clause 7.2.3 seam: a counter-interrogation reply is
    // a pair the conventional station uses, so there is nothing to refuse.
    // M_IT_NA_1 <15>, one object, cause 37, CA 1, IOA 1; body: BCR 0.
    let asdu = [
        0x0f, 0x01, 0x25, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let header = Header::parse(&asdu).unwrap();
    assert_eq!(header.type_id, TypeId::MItNa1);
    assert_eq!(header.cause, Cause::RequestedByGeneralCounter);
    let known = Known::for_profile(profile, &header, true, true);
    assert_eq!(classify(&known), None);
    assert_eq!(profile.known(&header, true, true), known);

    // The two mutators are data: a cell and a whole row, and neither touches a
    // pair the sheet does not print.
    let one = profile
        .clone()
        .with_cell(TypeId::MSpNa1, Cause::Activation, Direction::Both);
    assert_eq!(
        one.direction(TypeId::MSpNa1, Cause::Activation),
        Direction::Both
    );
    assert!(one.uses(TypeId::MSpNa1, Cause::Activation));
    assert_eq!(
        profile.direction(TypeId::MSpNa1, Cause::Activation),
        Direction::NotUsed,
        "the original is unchanged"
    );

    let rowless =
        profile
            .clone()
            .with_cell(TypeId::Other(200), Cause::Spontaneous, Direction::Both);
    assert!(!rowless.uses_type(TypeId::Other(200)), "no row, no cell");

    let all_blank = profile
        .clone()
        .with_type_row(TypeId::MMeNb1, Direction::NotUsed);
    assert!(!all_blank.uses_type(TypeId::MMeNb1));
    assert!(!all_blank.uses(TypeId::MMeNb1, Cause::Spontaneous));
    assert!(profile.uses_type(TypeId::MMeNb1));
}

/// A box the sheet draws **black** is *"option not permitted in this companion
/// standard"* (index 104), so no station may select it and the builders refuse
/// it: `with_cell` leaves the profile unchanged and `with_type_row` skips the
/// box while marking the row's other boxes normally.
///
/// `C_CS_NA_1` `<103>` with cause 3 (`Spontaneous`) is one such box; the row is
/// otherwise a control row whose white boxes are 6, 7 and 44–47.
#[test]
fn a_black_box_is_option_not_permitted_and_the_builders_refuse_it() {
    let row = row_of(TypeId::CCsNa1).expect("the sheet prints <103>");
    let column = column_of(Cause::Spontaneous).expect("the sheet prints cause 3");
    assert_eq!(
        row,
        TYPE_ROWS
            .iter()
            .position(|&type_id| type_id == TypeId::CCsNa1)
            .unwrap()
    );
    assert_eq!(SHEET[row][column], Cell::Black);
    assert!(!SHEET[row][column].is_selectable());
    assert!(SHEET[row][column].is_not_permitted());

    let profile = InteropProfile::conventional();
    assert_eq!(
        profile.direction(TypeId::CCsNa1, Cause::Spontaneous),
        Direction::NotUsed,
        "a black box is blank in the conventional grid"
    );

    // `with_cell` refuses it whatever the mark asked for.
    for mark in [
        Direction::Standard,
        Direction::Reverse,
        Direction::Both,
        Direction::NotUsed,
    ] {
        let attempted = profile
            .clone()
            .with_cell(TypeId::CCsNa1, Cause::Spontaneous, mark);
        assert_eq!(
            attempted.direction(TypeId::CCsNa1, Cause::Spontaneous),
            Direction::NotUsed,
            "with_cell({mark:?}) on a black box is a no-op"
        );
    }

    // `with_type_row` marks the row's white boxes and leaves the black one.
    let row_marked = profile
        .clone()
        .with_type_row(TypeId::CCsNa1, Direction::Both);
    assert_eq!(
        row_marked.direction(TypeId::CCsNa1, Cause::Spontaneous),
        Direction::NotUsed,
        "the black box is not permitted, whatever the row asks for"
    );
    for cause in [Cause::Activation, Cause::ActivationCon, Cause::UnknownCause] {
        assert_eq!(
            row_marked.direction(TypeId::CCsNa1, cause),
            Direction::Both,
            "{cause:?}"
        );
    }
    // Neither builder touched the original.
    assert_eq!(
        profile.direction(TypeId::CCsNa1, Cause::Activation),
        Direction::Standard
    );
}

/// Clause 7.2.3: a row or cell the profile does not use shows up at the
/// receiver as **the clause's own typed answer**, never a panic and never
/// silence.
///
/// 5-101 clause 7.2.3's table, in its own words: an ASDU whose *"type
/// identification"* is unknown is mirrored with cause 44, one whose *"cause of
/// transmission"* is unknown *for that type identification* with cause 45, the
/// common address with 46 and the information object address with 47. The
/// profile's `NotUsed` is one of the first two classes, so the tests assert the
/// **variant and the cause**, and the profile is never a second copy of
/// `asdu::unknown`'s precedence.
#[test]
fn a_row_or_cell_the_profile_does_not_use_is_the_clauses_own_typed_refusal() {
    let header = Header::parse(C_CS_NA_1).unwrap();
    assert_eq!(header.type_id, TypeId::CCsNa1);
    assert_eq!(header.cause, Cause::Activation);

    // A station that does not use the type at all: cause 44.
    let without = InteropProfile::conventional().with_type_row(TypeId::CCsNa1, Direction::NotUsed);
    let known = Known::for_profile(&without, &header, true, true);
    assert!(!known.type_id);
    assert_eq!(classify(&known), Some(Unspecified::TypeIdentification));
    let reply = mirror_reply(&header, &known, &C_CS_NA_1[Header::LEN..]).unwrap();
    assert_eq!(
        reply[2],
        Cause::UnknownTypeId.to_u8() | 0x40,
        "clause 7.2.3's type-identification row, cause 44 with P/N = 1"
    );
    assert_eq!(&reply[Header::LEN..], &C_CS_NA_1[Header::LEN..], "mirrored");

    // A station that uses the type but not that cause for it: cause 45.
    let narrow = InteropProfile::conventional().with_cell(
        TypeId::CCsNa1,
        Cause::Activation,
        Direction::NotUsed,
    );
    let known = Known::for_profile(&narrow, &header, true, true);
    assert!(known.type_id, "the type is used");
    assert!(!known.cause, "this cause is not");
    assert_eq!(classify(&known), Some(Unspecified::CauseOfTransmission));
    let reply = mirror_reply(&header, &known, &C_CS_NA_1[Header::LEN..]).unwrap();
    assert_eq!(reply[2], Cause::UnknownCause.to_u8() | 0x40);

    // Both blank: the clause's table order decides, and the type comes first.
    let both = not_used(without, Cause::Activation);
    let known = Known::for_profile(&both, &header, true, true);
    assert_eq!(classify(&known), Some(Unspecified::TypeIdentification));

    // The monitor direction gets the clause's discard verdict instead of a
    // reply, and a received mirror is still a mirror.
    assert_eq!(
        discard_reason(&header, &known),
        Some(Discard::Unspecified(Unspecified::TypeIdentification))
    );
    let mirror = Header {
        negative: true,
        cause: Cause::UnknownCause,
        ..header
    };
    assert_eq!(discard_reason(&mirror, &known), Some(Discard::Mirror));

    // And the profile adds nothing to the paths that were already there: the
    // conventional answer for this frame is a full station's.
    let full = Known::for_profile(&InteropProfile::conventional(), &header, true, true);
    assert_eq!(classify(&full), None);
    assert_eq!(
        mirror_reply(&header, &full, &C_CS_NA_1[Header::LEN..]),
        None
    );
}

/// One cell of one row: helper for the "both blank" case above.
fn not_used(profile: InteropProfile, cause: Cause) -> InteropProfile {
    profile.with_cell(TypeId::CCsNa1, cause, Direction::NotUsed)
}

/// Where a procedure module owns the refusal, the profile's answer is
/// translated into that module's own type at the seam.
///
/// The types are the modules' own and are **not** duplicated by the profile:
/// `ts::Selection` (the *"Test procedure"* row with its form), `ft::Selection`
/// (the two *"File transfer in … direction"* rows), `ci::CounterMode` (the
/// *"Transmission of integrated totals"* row's modes A–D) and `rd`'s per-station
/// `used` flag (the *"Read procedure"* row).
#[test]
fn the_profile_translates_into_the_procedure_modules_own_values() {
    let profile = InteropProfile::conventional();
    assert_eq!(
        profile.test_selection(),
        ts::Selection::TAGGED,
        "the 9.6 checkbox is marked and the 104 form is <107>"
    );
    assert_eq!(profile.file_transfer(), ft::Selection::BOTH);
    assert!(profile.counter_requests_accepted());
    assert!(profile.read_procedure_used());
    assert_eq!(profile.counter_mode, ci::CounterMode::FreezeAndTransmit);

    // Marking the rows not used flips the translations and nothing else.
    let off = profile
        .with_function(Function::TestProcedure, Direction::NotUsed)
        .with_function(Function::IntegratedTotals, Direction::NotUsed)
        .with_function(Function::ReadProcedure, Direction::NotUsed)
        .with_function(Function::FileTransferMonitor, Direction::NotUsed)
        .with_function(Function::FileTransferControl, Direction::NotUsed);
    assert!(!off.test_selection().uses());
    assert_eq!(off.file_transfer(), ft::Selection::NONE);
    assert!(!off.counter_requests_accepted());
    assert!(!off.read_procedure_used());
    // A mode whose `accepts_requests` is false is refused by the translation
    // even with the row marked: mode A issues no `C_CI` at all.
    let mode_a =
        InteropProfile::conventional().with_counter_mode(ci::CounterMode::LocalFreezeSpontaneous);
    assert!(!mode_a.counter_requests_accepted());
    // The form beside the checkbox is the profile's own value, not derived from
    // the mark: the 5-101 untagged `<104>` is a form a 104 profile mints only
    // with the sync form set.
    let untagged = InteropProfile::conventional().with_test_form(ts::Form::Untagged);
    assert!(untagged.test_selection().uses());
    assert_eq!(untagged.test_selection().form(), ts::Form::Untagged);
}

/// The profile is a **value**: built by the caller, passed by reference, equal
/// when equal, and with no global anywhere.
///
/// The profile uses no global, no `static`, no interior mutability and no
/// extra dependency. Two constructions are equal, [`Default`] is
/// [`InteropProfile::conventional`], the builders return owned values and leave
/// their receiver alone, and the whole grid is inspectable as data
/// ([`InteropProfile::grid_rows`]) rather than reachable only through a branch.
#[test]
fn the_profile_is_a_value_and_its_grid_is_a_table() {
    assert_eq!(InteropProfile::default(), InteropProfile::conventional());
    assert_eq!(
        InteropProfile::conventional(),
        InteropProfile::conventional()
    );

    // The grid, read out as data: one line per row with at least one marked
    // cell, headed by that row's marked columns, so the table is inspectable
    // without a debug print of 1 273 cells. The line count is the number of rows
    // the sheet gives a white box, i.e. the types 104 selects.
    let rows = InteropProfile::conventional().grid_rows();
    assert_eq!(
        rows.len(),
        54,
        "67 sheet rows less the 13 types 104 does not select"
    );
    // The marked cells are the sheet's white boxes: 303 of the 1 273, measured
    // on index 104 and index 106 (`interop::SHEET_ROWS` records the method).
    let white: usize = SHEET
        .iter()
        .flat_map(|row| row.iter())
        .filter(|cell| cell.is_selectable())
        .count();
    assert_eq!(white, 303);
    let marked: usize = rows
        .iter()
        .map(|line| {
            line.split_once(' ')
                .map_or(1, |(_, columns)| columns.split(',').count())
        })
        .sum();
    assert_eq!(marked, white, "every white box is marked, and nothing else");

    // The four carried values are the crate's own types, not copies.
    let profile = InteropProfile::conventional();
    let _: iec104::asdu::AddressSizes = profile.address_sizes;
    let _: LinkParams = profile.link;
    let _: ci::CounterMode = profile.counter_mode;
    let _: ts::Form = profile.test_form;

    // `known` and `Known::for_profile` are the same call.
    let header = Header::parse(M_SP_NA_1).unwrap();
    assert_eq!(
        profile.known(&header, true, false),
        Known::for_profile(&profile, &header, true, false)
    );
    assert_eq!(
        profile.known(&header, true, false),
        Known {
            type_id: true,
            cause: true,
            common_address: true,
            information_object_address: false,
        }
    );
}

/// The thirteen all-blank rows are exactly the types 104 does not select (the
/// two black boxes `<104>`, `<106>` and the eleven struck-through time-tagged
/// twins), so [`InteropProfile::grid_rows`]'s 54 lines and the 67 rows are one
/// statement about 104's own catalogue selection.
#[test]
fn the_all_blank_rows_are_the_types_104_does_not_select() {
    let profile = InteropProfile::conventional();
    let blank: Vec<TypeId> = TYPE_ROWS
        .iter()
        .copied()
        .filter(|row| !profile.uses_type(*row))
        .collect();
    assert_eq!(blank.len(), 13);
    for row in &blank {
        assert!(
            !row.is_selected_104(),
            "{row:?} is blank but 104 selects it"
        );
    }
    // The converse: every catalogue type 104 selects is a used row.
    for octet in 1u8..=127 {
        let type_id = TypeId::from_u8(octet);
        if type_id.info().is_some_and(|info| info.selected_104) {
            assert!(
                profile.uses_type(type_id),
                "{type_id:?} is selected but blank"
            );
        }
    }
}
