//! IEC 60870-5-104 clause **9**: the interoperability support matrix, as data.
//!
//! Clause 9 is the one clause of the companion standard that is a **form**. Its
//! opening calls its content *"sets of parameters and alternatives from which
//! subsets must be selected to implement particular telecontrol systems"* and
//! states the rule that makes it a profile: *"This means that only one value of
//! the defined parameters is admitted per system."* (index 94, printed 93). Its
//! closing sentence is why this module exists: *"If a system is composed of
//! equipment stemming from different manufacturers, it is necessary that all
//! partners agree on the selected parameters."*
//!
//! Several parts of clause 9 are already values in their own modules:
//! [`crate::asdu::AddressSizes`] (9.5's system parameters),
//! [`crate::params::LinkParams`] (9.6's time-outs and k/w),
//! [`crate::ci::CounterMode`] (9.6's four counter modes), [`crate::ts::Form`] /
//! [`crate::ts::Selection`] (9.6's test procedure), [`crate::ct::CommandMode`]
//! (9.6's command transmission) and [`crate::gi::Scope`] (9.6's station
//! interrogation). [`InteropProfile`] gathers the station's profile into one
//! value: it **carries** the address sizes, link parameters, counter mode and
//! test form rather than re-modelling them, and adds the two things clause 9
//! has that no other type represents: the four-valued **marking scheme**
//! ([`Direction`]) and the **type/cause grid** ([`InteropProfile::direction`]).
//!
//! # The marking scheme
//!
//! Verbatim from index 94: *"The selected parameters should be marked in the
//! white boxes as follows:"*
//!
//! > Function or ASDU is not used
//! > **X** Function or ASDU is used as standardized (default)
//! > **R** Function or ASDU is used in reverse mode
//! > **B** Function or ASDU is used in standard and reverse mode
//!
//! and the two sentences that bound it: *"The possible selection (blank, X, R, or
//! B) is specified for each specific clause or parameter."* and *"A black check
//! box indicates that the option cannot be selected in this companion
//! standard."* The four letters are [`Direction`]'s four variants; blank is
//! [`Direction::NotUsed`].
//!
//! # The type/cause grid
//!
//! Index 104 (printed 103) and index 106 (printed 105) print
//! *"Type identifier and cause of transmission assignments (station-specific
//! parameters)"* with the rule
//!
//! > Mark Type Identification/Cause of transmission combinations: *"X"* if only
//! > used in the standard direction; *"R"* if only used in the reverse
//! > direction; *"B"* if used in both directions.
//!
//! and the header *"Shaded boxes: option not required. Black boxes: option not
//! permitted in this companion standard Blank: functions or ASDU not used."* Its
//! column header reads `1 2 3 4 5 6 7 8 9 10 11 12 13 20 to 36 37 to 41 44 45 46
//! 47`: **nineteen** columns ([`CAUSE_COLUMNS`]). [`InteropProfile`] stores the
//! grid as the table it is, [`TYPE_ROWS`] × [`CAUSE_COLUMNS`], each cell one
//! [`Direction`].
//!
//! The printed body carries no *letter*, but every box is drawn with one of the
//! three fills the legend names, so the sheet's own selection is on the page.
//! [`SHEET`] is that transcription, taken from the fills of index 104 (rows
//! `<1>`–`<12>`) and index 106, the English continuation (rows
//! `<13>`–`<127>`; index 105 is the French page). Over the 67 × 19 = 1 273
//! cells it is **303 white, 39 black and 931 shaded**. The conventional grid
//! is those white cells in the standard direction and nothing else
//! ([`InteropProfile::conventional`]).
//!
//! # What is fixed, and therefore not here
//!
//! Three values on clause 9's pages are **not** configurable and this module
//! does not make them so:
//!
//! - the application-data transmission mode (index 98): *"Mode 1 (Least
//!   significant octet first), as defined in 4.10 of IEC 60870-5-4, is used
//!   exclusively in this companion standard."*
//! - the APDU length (index 98): *"The maximum length of APDU for both
//!   directions is 253. It is a fixed system parameter."*
//! - clause 9.3's physical layer and 9.4's link layer (index 96), which 104
//!   strike through: *"Frame format FT 1.2, single character 1 and the fixed
//!   time out interval are used exclusively in this companion standard."*
//!
//! # The time-outs are `LinkParams`, not a second type
//!
//! Clause 9.6's *"Definition of time outs"* (index 114) prints `t0 30 s`,
//! `t1 15 s`, `t2 10 s`, `t3 20 s` with *"Maximum range for timeouts t0 to t2:
//! 1 s to 255 s, accuracy 1 s."* and *"Recommended range for timeout t3: 1 s to
//! 48 h, resolution 1 s."*, and the *"Maximum number of outstanding I format
//! APDUs k and latest acknowledge APDUs (w)"* table prints `k 12 APDUs`, `w 8
//! APDUs` with *"Maximum range of values k: 1 to 32767 (215–1) APDUs, accuracy 1
//! APDU"*. Those are exactly [`crate::params::LinkParams`]' fields, its
//! `Default` and its `validate`, so [`InteropProfile::link`] **is** a
//! `LinkParams`.
//!
//! # How the profile is used
//!
//! The profile is a **value the caller builds and passes**: no global, no
//! `static`, no interior mutability. [`InteropProfile::conventional`] is the
//! default, and the single way into the reception paths is
//! [`crate::asdu::Known::for_profile`], beside `Known::standard`. Nothing in
//! `Session`, `link`, `seq` or `timers` reads it.
//!
//! # Example
//!
//! A station whose grid marks `C_CS_NA_1`'s activation `NotUsed`. Clause
//! 7.2.3's answer to a cause the station does not accept for that type
//! identification is cause 45, which [`crate::asdu::mirror_reply`] produces:
//!
//! ```
//! use iec104::asdu::{mirror_reply, Cause, Header, Known, TypeId};
//! use iec104::interop::{Direction, InteropProfile};
//!
//! // C_CS_NA_1, one object, cause 6 (activation), CA 1; body: IOA 0 + CP56Time2a.
//! let asdu = [
//!     0x67, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//!     0x00,
//! ];
//! let header = Header::parse(&asdu).unwrap();
//! assert_eq!(header.type_id, TypeId::CCsNa1);
//!
//! let profile = InteropProfile::conventional()
//!     .with_cell(TypeId::CCsNa1, Cause::Activation, Direction::NotUsed);
//! let known = Known::for_profile(&profile, &header, true, true);
//! assert!(!known.cause);
//!
//! let reply = mirror_reply(&header, &known, &asdu[Header::LEN..]).unwrap();
//! assert_eq!(reply[2], Cause::UnknownCause.to_u8() | 0x40);
//! ```

use crate::asdu::{AddressSizes, Cause, Header, Known, TypeId};
use crate::params::LinkParams;
use crate::{ci, ft, ts};

/// The sheet's marking scheme (index 94): blank, `X`, `R` or `B`, one per
/// variant, in the standard's order.
///
/// *"The possible selection (blank, X, R, or B) is specified for each specific
/// clause or parameter."* So a [`Direction`] is the value of **one row or one
/// cell** of clause 9.
///
/// Do not confuse it with [`crate::asdu::Direction`], which is the direction a
/// *type identification* may travel (monitor, control or both). A
/// [`Direction`] here is the *mark* a station puts on a row, and
/// [`Direction::Reverse`] says a function is used **only** against the type's
/// own direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Blank: *"Function or ASDU is not used"*.
    NotUsed,
    /// `X`: *"Function or ASDU is used as standardized (default)"*.
    Standard,
    /// `R`: *"Function or ASDU is used in reverse mode"*.
    Reverse,
    /// `B`: *"Function or ASDU is used in standard and reverse mode"*.
    Both,
}

impl Direction {
    /// Every mark, in the sheet's own order: blank, `X`, `R`, `B`.
    pub const ALL: [Self; 4] = [Self::NotUsed, Self::Standard, Self::Reverse, Self::Both];

    /// Whether the row or cell is marked at all (not blank), which answers
    /// *"does the station use it?"*.
    #[must_use]
    pub const fn is_used(self) -> bool {
        !matches!(self, Self::NotUsed)
    }

    /// Whether the mark is `X`, *"only used in the standard direction"*.
    #[must_use]
    pub const fn is_standard(self) -> bool {
        matches!(self, Self::Standard)
    }

    /// Whether the mark says the function is used against the standard
    /// direction: `R` (*"only used in the reverse direction"*) or `B` (*"used
    /// in both directions"*).
    #[must_use]
    pub const fn is_reverse(self) -> bool {
        matches!(self, Self::Reverse | Self::Both)
    }
}

/// One column of clause 9's type/cause grid: the sheet's own grouping of the
/// causes, read off the header row of index 104 and index 106
/// (`1 2 3 4 5 6 7 8 9 10 11 12 13 20 to 36 37 to 41 44 45 46 47`).
///
/// Two of the sheet's columns are **ranges**, which is why this is not simply a
/// [`Cause`]: the interrogation causes 20–36 (5-101 table 14's
/// `InterrogatedByStation` / `InterrogatedByGroup`) share one column, and so do
/// the counter-request causes 37–41 (`RequestedByGeneralCounter` /
/// `RequestedByCounterGroup`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CauseColumn {
    /// A single cause: the sheet's columns `1` … `13` and `44` … `47`.
    One(Cause),
    /// The sheet's *"20 to 36"* column: station and group interrogation.
    Interrogated,
    /// The sheet's *"37 to 41"* column: general and group counter request.
    CounterRequested,
}

impl CauseColumn {
    /// Whether a cause of transmission falls in this column.
    #[must_use]
    pub fn accepts(self, cause: Cause) -> bool {
        let value = cause.to_u8();
        match self {
            Self::One(one) => value == one.to_u8(),
            Self::Interrogated => (20..=36).contains(&value),
            Self::CounterRequested => (37..=41).contains(&value),
        }
    }

    /// Whether this is one of the four *"unknown …"* reply columns 44 to 47,
    /// the causes of 5-101 clause 7.2.3's mirror. The sheet draws them white
    /// only on the control-direction rows and the file-transfer rows other than
    /// `F_DR_TA_1`, so only those rows have them marked in the conventional
    /// grid.
    #[must_use]
    pub fn is_unknown_reply(self) -> bool {
        matches!(self, Self::One(cause) if (44..=47).contains(&cause.to_u8()))
    }

    /// The column's own heading as the sheet prints it (`"1"`, `"20 to 36"`,
    /// `"37 to 41"`, `"44"` …).
    #[must_use]
    pub fn heading(self) -> &'static str {
        match self {
            Self::Interrogated => "20 to 36",
            Self::CounterRequested => "37 to 41",
            Self::One(cause) => match cause.to_u8() {
                1 => "1",
                2 => "2",
                3 => "3",
                4 => "4",
                5 => "5",
                6 => "6",
                7 => "7",
                8 => "8",
                9 => "9",
                10 => "10",
                11 => "11",
                12 => "12",
                13 => "13",
                44 => "44",
                45 => "45",
                46 => "46",
                _ => "47",
            },
        }
    }
}

/// The grid's nineteen columns, in the order of index 104's header row.
pub const CAUSE_COLUMNS: [CauseColumn; 19] = [
    CauseColumn::One(Cause::Periodic),
    CauseColumn::One(Cause::BackgroundScan),
    CauseColumn::One(Cause::Spontaneous),
    CauseColumn::One(Cause::Initialized),
    CauseColumn::One(Cause::Request),
    CauseColumn::One(Cause::Activation),
    CauseColumn::One(Cause::ActivationCon),
    CauseColumn::One(Cause::Deactivation),
    CauseColumn::One(Cause::DeactivationCon),
    CauseColumn::One(Cause::ActivationTermination),
    CauseColumn::One(Cause::ReturnInfoRemote),
    CauseColumn::One(Cause::ReturnInfoLocal),
    CauseColumn::One(Cause::FileTransfer),
    CauseColumn::Interrogated,
    CauseColumn::CounterRequested,
    CauseColumn::One(Cause::UnknownTypeId),
    CauseColumn::One(Cause::UnknownCause),
    CauseColumn::One(Cause::UnknownCommonAddress),
    CauseColumn::One(Cause::UnknownInformationObjectAddress),
];

/// The grid's rows: the type identifications index 104 and index 106 print, in
/// their order.
///
/// The list is the sheet's own, **including** the rows 104 black-boxes
/// (`<104>` and `<106>`: *"Black boxes: option not permitted in this companion
/// standard"*) and the `CP24Time2a` types it does not select. A profile is a
/// form, so a row with every cell blank is a statement, not a missing entry.
pub const TYPE_ROWS: [TypeId; 67] = [
    TypeId::MSpNa1,
    TypeId::MSpTa1,
    TypeId::MDpNa1,
    TypeId::MDpTa1,
    TypeId::MStNa1,
    TypeId::MStTa1,
    TypeId::MBoNa1,
    TypeId::MBoTa1,
    TypeId::MMeNa1,
    TypeId::MMeTa1,
    TypeId::MMeNb1,
    TypeId::MMeTb1,
    TypeId::MMeNc1,
    TypeId::MMeTc1,
    TypeId::MItNa1,
    TypeId::MItTa1,
    TypeId::MEpTa1,
    TypeId::MEpTb1,
    TypeId::MEpTc1,
    TypeId::MPsNa1,
    TypeId::MMeNd1,
    TypeId::MSpTb1,
    TypeId::MDpTb1,
    TypeId::MStTb1,
    TypeId::MBoTb1,
    TypeId::MMeTd1,
    TypeId::MMeTe1,
    TypeId::MMeTf1,
    TypeId::MItTb1,
    TypeId::MEpTd1,
    TypeId::MEpTe1,
    TypeId::MEpTf1,
    TypeId::CScNa1,
    TypeId::CDcNa1,
    TypeId::CRcNa1,
    TypeId::CSeNa1,
    TypeId::CSeNb1,
    TypeId::CSeNc1,
    TypeId::CBoNa1,
    TypeId::CScTa1,
    TypeId::CDcTa1,
    TypeId::CRcTa1,
    TypeId::CSeTa1,
    TypeId::CSeTb1,
    TypeId::CSeTc1,
    TypeId::CBoTa1,
    TypeId::MEiNa1,
    TypeId::CIcNa1,
    TypeId::CCiNa1,
    TypeId::CRdNa1,
    TypeId::CCsNa1,
    TypeId::CTsNa1,
    TypeId::CRpNa1,
    TypeId::CCdNa1,
    TypeId::CTsTa1,
    TypeId::PMeNa1,
    TypeId::PMeNb1,
    TypeId::PMeNc1,
    TypeId::PAcNa1,
    TypeId::FFrNa1,
    TypeId::FSrNa1,
    TypeId::FScNa1,
    TypeId::FLsNa1,
    TypeId::FAfNa1,
    TypeId::FSgNa1,
    TypeId::FDrTa1,
    TypeId::FScNb1,
];

/// The number of rows in the grid, [`TYPE_ROWS`].
pub const TYPE_ROW_COUNT: usize = TYPE_ROWS.len();

/// The grid itself: one [`Direction`] per ([`TYPE_ROWS`] row, [`CAUSE_COLUMNS`]
/// column) cell, indexed `grid[row][column]`.
pub type Grid = [[Direction; CAUSE_COLUMNS.len()]; TYPE_ROW_COUNT];

/// The row index of a type identification, or `None` for one the sheet's grid
/// does not print.
///
/// A type outside the table is `None` rather than a synthetic row: an unnamed
/// or private type identification (5-101 clause 7.3's range 128–255, *"by
/// agreement between the system user and the vendor"*) has no cell on the
/// sheet, so a profile cannot mark one. A station that uses one states so in
/// [`crate::asdu::Known`], not here.
#[must_use]
pub fn row_of(type_id: TypeId) -> Option<usize> {
    let octet = type_id.to_u8();
    TYPE_ROWS.iter().position(|row| row.to_u8() == octet)
}

/// The column index of a cause of transmission, or `None` for one the sheet's
/// header row does not print (the reserved values 14–19/42–43, the private
/// range 48–63 and `<0>`).
#[must_use]
pub fn column_of(cause: Cause) -> Option<usize> {
    CAUSE_COLUMNS
        .iter()
        .position(|column| column.accepts(cause))
}

/// One box of the sheet's clause 9 type/cause grid, as index 104 and index 106
/// draw it: the fill the box carries, which the legend beside the grid names.
///
/// *"Shaded boxes: option not required. Black boxes: option not permitted in
/// this companion standard Blank: functions or ASDU not used."* (index 104).
/// The marking rule addresses the white boxes: *"The selected parameters should
/// be marked in the white boxes"* (index 94), so a white box is the only box a
/// station may select.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cell {
    /// White: a combination the station may select (`X`, `R` or `B`).
    White,
    /// Shaded: *"option not required"*, so the station need not implement it.
    Shaded,
    /// Black: *"option not permitted in this companion standard"*, so no
    /// station of this companion standard may select it.
    Black,
}

impl Cell {
    /// Whether the sheet lets a station mark this box at all: white only
    /// (index 94's *"marked in the white boxes"*).
    #[must_use]
    pub const fn is_selectable(self) -> bool {
        matches!(self, Self::White)
    }

    /// Whether the sheet **forbids** the combination:
    /// *"Black boxes: option not permitted in this companion standard"*.
    #[must_use]
    pub const fn is_not_permitted(self) -> bool {
        matches!(self, Self::Black)
    }
}

/// The sheet's grid body as it is printed: one [`Cell`] per ([`TYPE_ROWS`] row,
/// [`CAUSE_COLUMNS`] column), indexed `SHEET[row][column]`.
pub type SheetGrid = [[Cell; CAUSE_COLUMNS.len()]; TYPE_ROW_COUNT];

/// The grid body, one 19-box string per [`TYPE_ROWS`] entry and in that order:
/// the transcription [`SHEET`] is decoded from.
///
/// `W` is a white box, `S` a shaded one and `B` a black one, one character per
/// [`CAUSE_COLUMNS`] entry. The grid prints **no letter** in its body, so these
/// characters were **measured**, not read: each page was rendered and every box
/// centre sampled, and the result was cross-checked against the fills
/// `pymupdf`'s `page.get_drawings()` reports (`fill 0.0` black, `fill 0.88`
/// shaded, and either no fill or an explicit white `fill 1.0` drawn over the
/// shading for a white box; 2026-09-25). Rows `<1>`–`<12>` are on index 104,
/// rows `<13>`–`<127>` on index 106, the English continuation; the French page
/// index 105 is not used. The counts over the 67 × 19 = 1 273 boxes are **303
/// white, 39 black, 931 shaded**.
const SHEET_ROWS: [&str; TYPE_ROW_COUNT] = [
    "SWWSWSSSSSWWSWSSSSS", // <1>   M_SP_NA_1
    "SSBSBSSSSSBBSSSSSSS", // <2>   M_SP_TA_1
    "SWWSWSSSSSWWSWSSSSS", // <3>   M_DP_NA_1
    "SSBSBSSSSSBBSSSSSSS", // <4>   M_DP_TA_1
    "SWWSWSSSSSWWSWSSSSS", // <5>   M_ST_NA_1
    "SSBSBSSSSSBBSSSSSSS", // <6>   M_ST_TA_1
    "SWWSWSSSSSSSSWSSSSS", // <7>   M_BO_NA_1
    "SSBSBSSSSSSSSSSSSSS", // <8>   M_BO_TA_1
    "WWWSWSSSSSSSSWSSSSS", // <9>   M_ME_NA_1
    "SSBSBSSSSSSSSSSSSSS", // <10>  M_ME_TA_1
    "WWWSWSSSSSSSSWSSSSS", // <11>  M_ME_NB_1
    "SSBSBSSSSSSSSSSSSSS", // <12>  M_ME_TB_1
    "WWWSWSSSSSSSSWSSSSS", // <13>  M_ME_NC_1
    "SSBSBSSSSSSSSSSSSSS", // <14>  M_ME_TC_1
    "SSWSSSSSSSSSSSWSSSS", // <15>  M_IT_NA_1
    "SSBSSSSSSSSSSSBSSSS", // <16>  M_IT_TA_1
    "SSBSSSSSSSSSSSSSSSS", // <17>  M_EP_TA_1
    "SSBSSSSSSSSSSSSSSSS", // <18>  M_EP_TB_1
    "SSBSSSSSSSSSSSSSSSS", // <19>  M_EP_TC_1
    "SWWSWSSSSSSSSWSSSSS", // <20>  M_PS_NA_1
    "WWWSWSSSSSSSSWSSSSS", // <21>  M_ME_ND_1
    "SSWSWSSSSSWWSSSSSSS", // <30>  M_SP_TB_1
    "SSWSWSSSSSWWSSSSSSS", // <31>  M_DP_TB_1
    "SSWSWSSSSSWWSSSSSSS", // <32>  M_ST_TB_1
    "SSWSWSSSSSSSSSSSSSS", // <33>  M_BO_TB_1
    "SSWSWSSSSSSSSSSSSSS", // <34>  M_ME_TD_1
    "SSWSWSSSSSSSSSSSSSS", // <35>  M_ME_TE_1
    "SSWSWSSSSSSSSSSSSSS", // <36>  M_ME_TF_1
    "SSWSSSSSSSSSSSWSSSS", // <37>  M_IT_TB_1
    "SSWSSSSSSSSSSSSSSSS", // <38>  M_EP_TD_1
    "SSWSSSSSSSSSSSSSSSS", // <39>  M_EP_TE_1
    "SSWSSSSSSSSSSSSSSSS", // <40>  M_EP_TF_1
    "SSSSSWWWWWSSSSSWWWW", // <45>  C_SC_NA_1
    "SSSSSWWWWWSSSSSWWWW", // <46>  C_DC_NA_1
    "SSSSSWWWWWSSSSSWWWW", // <47>  C_RC_NA_1
    "SSSSSWWWWWSSSSSWWWW", // <48>  C_SE_NA_1
    "SSSSSWWWWWSSSSSWWWW", // <49>  C_SE_NB_1
    "SSSSSWWWWWSSSSSWWWW", // <50>  C_SE_NC_1
    "SSSSSWWSSWSSSSSWWWW", // <51>  C_BO_NA_1
    "SSSSSWWWWWSSSSSWWWW", // <58>  C_SC_TA_1
    "SSSSSWWWWWSSSSSWWWW", // <59>  C_DC_TA_1
    "SSSSSWWWWWSSSSSWWWW", // <60>  C_RC_TA_1
    "SSSSSWWWWWSSSSSWWWW", // <61>  C_SE_TA_1
    "SSSSSWWWWWSSSSSWWWW", // <62>  C_SE_TB_1
    "SSSSSWWWWWSSSSSWWWW", // <63>  C_SE_TC_1
    "SSSSSWWSSWSSSSSWWWW", // <64>  C_BO_TA_1
    "SSSWSSSSSSSSSSSSSSS", // <70>  M_EI_NA_1
    "SSSSSWWWWWSSSSSWWWW", // <100> C_IC_NA_1
    "SSSSSWWSSWSSSSSWWWW", // <101> C_CI_NA_1
    "SSSSWSSSSSSSSSSWWWW", // <102> C_RD_NA_1
    "SSBSSWWSSSSSSSSWWWW", // <103> C_CS_NA_1
    "SSSSSBBSSSSSSSSBBBB", // <104> C_TS_NA_1
    "SSSSSWWSSSSSSSSWWWW", // <105> C_RP_NA_1
    "SSBSSBBSSSSSSSSBBBB", // <106> C_CD_NA_1
    "SSSSSWWSSSSSSSSWWWW", // <107> C_TS_TA_1
    "SSSSSWWSSSSSSWSWWWW", // <110> P_ME_NA_1
    "SSSSSWWSSSSSSWSWWWW", // <111> P_ME_NB_1
    "SSSSSWWSSSSSSWSWWWW", // <112> P_ME_NC_1
    "SSSSSWWWWSSSSSSWWWW", // <113> P_AC_NA_1
    "SSSSSSSSSSSSWSSWWWW", // <120> F_FR_NA_1
    "SSSSSSSSSSSSWSSWWWW", // <121> F_SR_NA_1
    "SSSSWSSSSSSSWSSWWWW", // <122> F_SC_NA_1
    "SSSSSSSSSSSSWSSWWWW", // <123> F_LS_NA_1
    "SSSSSSSSSSSSWSSWWWW", // <124> F_AF_NA_1
    "SSSSSSSSSSSSWSSWWWW", // <125> F_SG_NA_1
    "SSWSWSSSSSSSSSSSSSS", // <126> F_DR_TA_1
    "SSSSWSSSSSSSWSSWWWW", // <127> F_SC_NB_1
];

/// The sheet's own clause 9 grid, *"Type identifier and cause of transmission
/// assignments (station-specific parameters)"* (index 104 and index 106): one
/// [`Cell`] per ([`TYPE_ROWS`] row, [`CAUSE_COLUMNS`] column).
///
/// This is the standard's selection rather than the crate's: **303** of the
/// 1 273 boxes are white, **39** are black and **931** are shaded. The body
/// prints no letters, so the fills were measured from the rendered pages and
/// cross-checked against the PDF's drawing fills. Only the white boxes may be
/// marked (see [`Cell`]), and [`InteropProfile::conventional`] marks exactly
/// those.
pub const SHEET: SheetGrid = decode_sheet(&SHEET_ROWS);

/// Decode [`SHEET_ROWS`] into the typed grid at compile time.
const fn decode_sheet(rows: &[&str; TYPE_ROW_COUNT]) -> SheetGrid {
    let mut grid = [[Cell::Shaded; CAUSE_COLUMNS.len()]; TYPE_ROW_COUNT];
    let mut rows: &[&str] = rows;
    let mut out: &mut [[Cell; CAUSE_COLUMNS.len()]] = &mut grid;
    while let ([row, rest_rows @ ..], [cells, rest_out @ ..]) = (rows, out) {
        decode_row(row.as_bytes(), cells);
        rows = rest_rows;
        out = rest_out;
    }
    grid
}

/// Decode one [`SHEET_ROWS`] entry into `cells`.
const fn decode_row(mut boxes: &[u8], mut cells: &mut [Cell]) {
    assert!(
        boxes.len() == cells.len(),
        "every SHEET_ROWS entry is as wide as the grid"
    );
    while let ([box_, rest_boxes @ ..], [cell, rest_cells @ ..]) = (boxes, cells) {
        assert!(
            matches!(box_, b'W' | b'S' | b'B'),
            "SHEET_ROWS uses only W, S and B"
        );
        *cell = match box_ {
            b'W' => Cell::White,
            b'B' => Cell::Black,
            _ => Cell::Shaded,
        };
        boxes = rest_boxes;
        cells = rest_cells;
    }
}

/// The conventional grid: [`SHEET`]'s white boxes, in the standard direction.
///
/// Nothing is derived from the crate's catalogue: each white box is marked `X`
/// (*"only used in the standard direction"*) and every shaded or black box
/// stays blank.
fn conventional_grid() -> Grid {
    SHEET.map(|boxes| {
        boxes.map(|box_| {
            if box_.is_selectable() {
                Direction::Standard
            } else {
                Direction::NotUsed
            }
        })
    })
}

/// One row of clause 9.6, *"Basic application functions"* (index 108, printed
/// 107; index 112, printed 111; index 114, printed 113).
///
/// Each variant is one row the sheet prints, and the profile holds one
/// [`Direction`] per variant. Clause 9.6's station interrogation, clock
/// synchronization and command transmission rows are not in this list. The
/// sheet uses two marking sentences:
///
/// > (station-specific parameter, mark " **X** " if function is used)
/// > (station-specific parameter, mark " **X** " if function is only used in the
/// > standard direction, " **R** " if only used in the reverse direction, and
/// > " **B** " if used in both directions)
///
/// The **three** rows behind the first sentence (index 108's *"Station
/// initialization"* and the two direction rows of index 114's *"File
/// transfer"*) have **two** values, blank or `X` ([`Function::is_used_only`]);
/// the other ten are four-valued. Both are stored as [`Direction`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Function {
    /// *"Station initialization"* (index 108): *"Remote initialization"*.
    StationInitialization,
    /// *"Cyclic data transmission"* (index 108).
    CyclicDataTransmission,
    /// *"Read procedure"* (index 108).
    ReadProcedure,
    /// *"Spontaneous transmission"* (index 108).
    SpontaneousTransmission,
    /// *"Double transmission of information objects with cause of transmission
    /// spontaneous"* (index 108): *"both a Type ID without time and corresponding
    /// Type ID with time are issued in response to a single spontaneous change
    /// of a monitored object"*.
    ///
    /// The sheet marks this row **per information type** (*"mark each
    /// information type \"X\" where both a Type ID without time and corresponding
    /// Type ID with time are issued in response to a single spontaneous change of
    /// a monitored object"*) and leaves the addresses to a project-specific list,
    /// so one [`Direction`] here is a simplification: the profile records the
    /// station's answer for the row as a whole. The per-type pairs and the
    /// address list are [`crate::tx::DoublePair`] and [`crate::tx::ProjectList`].
    DoubleTransmission,
    /// *"Transmission of integrated totals"* (index 112): the row whose value
    /// is [`crate::ci::CounterMode`]'s four modes A to D.
    IntegratedTotals,
    /// *"Parameter loading"* (index 112), an *"object-specific parameter"*.
    ParameterLoading,
    /// *"Parameter activation"* (index 112), an *"object-specific parameter"*.
    ParameterActivation,
    /// *"Test procedure"* (index 112): the row whose value is
    /// [`crate::ts::Form`].
    TestProcedure,
    /// *"File transfer in monitor direction"* (index 114): *"mark \"X\" if
    /// function is used"*.
    FileTransferMonitor,
    /// *"File transfer in control direction"* (index 114).
    FileTransferControl,
    /// *"Background scan"* (index 114).
    BackgroundScan,
    /// *"Acquisition of transmission delay"* (index 114). 104 strikes it
    /// through (*"the text descriptions of parameters which are not applicable
    /// to this companion standard are strike-through"*, index 94), so a 104
    /// station leaves it [`Direction::NotUsed`] and a profile that marks it is a
    /// 5-101 one.
    AcquisitionOfTransmissionDelay,
}

impl Function {
    /// Every row, in the sheet's order; [`Function::index`] is a position in it.
    pub const ALL: [Self; 13] = [
        Self::StationInitialization,
        Self::CyclicDataTransmission,
        Self::ReadProcedure,
        Self::SpontaneousTransmission,
        Self::DoubleTransmission,
        Self::IntegratedTotals,
        Self::ParameterLoading,
        Self::ParameterActivation,
        Self::TestProcedure,
        Self::FileTransferMonitor,
        Self::FileTransferControl,
        Self::BackgroundScan,
        Self::AcquisitionOfTransmissionDelay,
    ];

    /// The row's index, its position in [`Function::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::StationInitialization => 0,
            Self::CyclicDataTransmission => 1,
            Self::ReadProcedure => 2,
            Self::SpontaneousTransmission => 3,
            Self::DoubleTransmission => 4,
            Self::IntegratedTotals => 5,
            Self::ParameterLoading => 6,
            Self::ParameterActivation => 7,
            Self::TestProcedure => 8,
            Self::FileTransferMonitor => 9,
            Self::FileTransferControl => 10,
            Self::BackgroundScan => 11,
            Self::AcquisitionOfTransmissionDelay => 12,
        }
    }

    /// The row's name as the sheet prints it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::StationInitialization => "Station initialization",
            Self::CyclicDataTransmission => "Cyclic data transmission",
            Self::ReadProcedure => "Read procedure",
            Self::SpontaneousTransmission => "Spontaneous transmission",
            Self::DoubleTransmission => {
                "Double transmission of information objects with cause of transmission spontaneous"
            }
            Self::IntegratedTotals => "Transmission of integrated totals",
            Self::ParameterLoading => "Parameter loading",
            Self::ParameterActivation => "Parameter activation",
            Self::TestProcedure => "Test procedure",
            Self::FileTransferMonitor => "File transfer in monitor direction",
            Self::FileTransferControl => "File transfer in control direction",
            Self::BackgroundScan => "Background scan",
            Self::AcquisitionOfTransmissionDelay => "Acquisition of transmission delay",
        }
    }

    /// The clause-9 page index the row is printed on (PDF page index, 0-based).
    #[must_use]
    pub const fn page_index(self) -> usize {
        match self {
            Self::StationInitialization
            | Self::CyclicDataTransmission
            | Self::ReadProcedure
            | Self::SpontaneousTransmission
            | Self::DoubleTransmission => 108,
            Self::IntegratedTotals
            | Self::ParameterLoading
            | Self::ParameterActivation
            | Self::TestProcedure => 112,
            Self::FileTransferMonitor
            | Self::FileTransferControl
            | Self::BackgroundScan
            | Self::AcquisitionOfTransmissionDelay => 114,
        }
    }

    /// Whether the row is one of the **three** the sheet marks *"if function is
    /// used"*: a two-valued row (blank or `X`), not a directional one. The
    /// sheet prints that sentence twice, for index 108's *"Station
    /// initialization"* and for index 114's *"File transfer"*, whose two
    /// direction rows are [`Function::FileTransferMonitor`] and
    /// [`Function::FileTransferControl`].
    #[must_use]
    pub const fn is_used_only(self) -> bool {
        matches!(
            self,
            Self::StationInitialization | Self::FileTransferMonitor | Self::FileTransferControl
        )
    }
}

/// A station's clause 9 interoperability profile: the values the standard
/// leaves *"to be selected"* for one device, as one value.
///
/// It carries the existing types rather than copies of them:
/// [`crate::asdu::AddressSizes`] (9.5's CA/IOA/COT widths),
/// [`crate::params::LinkParams`] (9.6's t0 to t3 and k/w),
/// [`crate::ci::CounterMode`] (9.6's four integrated-totals modes) and
/// [`crate::ts::Form`] (9.6's test procedure form), plus the marking scheme and
/// the type/cause grid, which are this module's own.
///
/// [`InteropProfile::conventional`] is the [`Default`]. The profile is **not**
/// a connection setting: nothing in `Session`, `link`, `seq` or `timers` reads
/// it. Its one way into the reception paths is [`Known::for_profile`].
#[derive(Clone, PartialEq, Eq)]
pub struct InteropProfile {
    /// Clause 9.5's *"system-specific parameter"* widths: 9.5's rows for the
    /// common address, the information object address and the cause of
    /// transmission (index 98). [`AddressSizes::CONVENTIONAL`] is the sheet's
    /// own marked example and the crate's default.
    pub address_sizes: AddressSizes,
    /// Clause 9.6's time-out and k/w tables (index 114).
    /// [`LinkParams::default`] is the sheet's *"Default value"* column.
    pub link: LinkParams,
    /// Clause 9.6's *"Transmission of integrated totals"* row as the crate's
    /// four-mode value ([`crate::ci::CounterMode`], 5-101 clause 7.4.8). The
    /// sheet marks modes A to D under that one row, so the mode is a field
    /// beside the row's [`Direction`].
    pub counter_mode: ci::CounterMode,
    /// Clause 9.6's *"Test procedure"* row's form: the untagged `C_TS_NA_1`
    /// `<104>` of 5-101 or 104 clause 8.8's time-tagged `C_TS_TA_1` `<107>`
    /// ([`crate::ts::Form`]), kept beside the row's [`Direction`].
    pub test_form: ts::Form,
    /// One [`Direction`] per clause 9.6 row, indexed by [`Function`].
    functions: [Direction; Function::ALL.len()],
    /// Clause 9's type/cause grid, [`TYPE_ROWS`] × [`CAUSE_COLUMNS`].
    grid: Grid,
}

impl InteropProfile {
    /// The profile a 104 station of this crate is: the sheet's own marked
    /// address example, the default time-outs and k/w, and the standard
    /// type/cause grid.
    ///
    /// Every [`Function`] row is marked [`Direction::Standard`] except
    /// *"Acquisition of transmission delay"*, which 104 strikes through (index
    /// 114) and which is therefore [`Direction::NotUsed`]. The grid is
    /// [`SHEET`]'s white boxes, each marked `X` (*"only used in the standard
    /// direction"*): the standard's own selection (303 of the 1 273 boxes), not
    /// a derivation from the crate's catalogue.
    #[must_use]
    pub fn conventional() -> Self {
        let functions = Function::ALL.map(|which| {
            if which == Function::AcquisitionOfTransmissionDelay {
                Direction::NotUsed
            } else {
                Direction::Standard
            }
        });
        Self {
            address_sizes: AddressSizes::CONVENTIONAL,
            link: LinkParams::default(),
            counter_mode: ci::CounterMode::FreezeAndTransmit,
            test_form: ts::Form::Tagged,
            functions,
            grid: conventional_grid(),
        }
    }

    /// The profile with one clause 9.6 row marked `direction`.
    #[must_use]
    pub fn with_function(mut self, which: Function, direction: Direction) -> Self {
        if let Some(slot) = self.functions.get_mut(which.index()) {
            *slot = direction;
        }
        self
    }

    /// The profile with clause 9.6's *"Transmission of integrated totals"* row's
    /// mode set to `mode` ([`crate::ci::CounterMode`]).
    #[must_use]
    pub const fn with_counter_mode(mut self, mode: ci::CounterMode) -> Self {
        self.counter_mode = mode;
        self
    }

    /// The profile with clause 9.6's *"Test procedure"* row's form set to
    /// `form` ([`crate::ts::Form`]).
    #[must_use]
    pub const fn with_test_form(mut self, form: ts::Form) -> Self {
        self.test_form = form;
        self
    }

    /// The profile with one grid cell marked `direction`.
    ///
    /// Two kinds of (type identification, cause) pair have **no mark to set**
    /// and leave the profile unchanged:
    ///
    /// - a pair the sheet's grid does not print at all: a private or reserved
    ///   type, or a cause outside [`CAUSE_COLUMNS`];
    /// - a box the sheet fills **black** ([`SHEET`], `Cell::Black`), which the
    ///   legend calls *"option not permitted in this companion standard"*, so
    ///   the builder refuses it rather than recording an illegal mark.
    ///   `C_CS_NA_1` `<103>` with cause 3 (`Spontaneous`) is one such box.
    ///
    /// White and shaded boxes are both set.
    #[must_use]
    pub fn with_cell(mut self, type_id: TypeId, cause: Cause, direction: Direction) -> Self {
        if let (Some(row), Some(column)) = (row_of(type_id), column_of(cause))
            && SHEET
                .get(row)
                .and_then(|boxes| boxes.get(column))
                .is_some_and(|box_| !box_.is_not_permitted())
            && let Some(mark) = self
                .grid
                .get_mut(row)
                .and_then(|marks| marks.get_mut(column))
        {
            *mark = direction;
        }
        self
    }

    /// The profile with every cell of one type's row marked `direction`,
    /// except the boxes the sheet fills black.
    ///
    /// For a type the grid does not print the profile is unchanged (see
    /// [`with_cell`](Self::with_cell)). A black box (*"option not permitted in
    /// this companion standard"*) stays [`Direction::NotUsed`]; white and
    /// shaded boxes are both marked.
    #[must_use]
    pub fn with_type_row(mut self, type_id: TypeId, direction: Direction) -> Self {
        if let Some(row) = row_of(type_id)
            && let (Some(boxes), Some(marks)) = (SHEET.get(row), self.grid.get_mut(row))
        {
            for (mark, box_) in marks.iter_mut().zip(boxes) {
                if !box_.is_not_permitted() {
                    *mark = direction;
                }
            }
        }
        self
    }

    /// The mark clause 9.6 gives one row.
    #[must_use]
    pub fn function(&self, which: Function) -> Direction {
        self.functions
            .get(which.index())
            .copied()
            .unwrap_or(Direction::NotUsed)
    }

    /// Whether the profile uses a clause 9.6 row at all (blank is not used).
    #[must_use]
    pub fn uses_function(&self, which: Function) -> bool {
        self.function(which).is_used()
    }

    /// The mark the grid gives one (`type_id`, `cause`) pair: index 104's
    /// *"Mark Type Identification/Cause of transmission combinations"*.
    ///
    /// [`Direction::NotUsed`] for a pair the sheet's grid has no cell for: a
    /// type identification outside [`TYPE_ROWS`], or a cause outside
    /// [`CAUSE_COLUMNS`].
    #[must_use]
    pub fn direction(&self, type_id: TypeId, cause: Cause) -> Direction {
        row_of(type_id)
            .zip(column_of(cause))
            .and_then(|(row, column)| self.grid.get(row)?.get(column).copied())
            .unwrap_or(Direction::NotUsed)
    }

    /// Whether the profile uses the pair at all (the grid's cell is not
    /// blank).
    #[must_use]
    pub fn uses(&self, type_id: TypeId, cause: Cause) -> bool {
        self.direction(type_id, cause).is_used()
    }

    /// Whether the profile uses a type identification in **any** direction:
    /// the question [`Known::for_profile`] puts to the grid as *"the station
    /// implements the ASDU's type identification"*.
    ///
    /// `false` for a type the sheet's grid has no row for ([`row_of`]) and for
    /// one whose whole row is blank. In the conventional profile those are the
    /// thirteen types 104 does not select, including `<104>` and `<106>`.
    #[must_use]
    pub fn uses_type(&self, type_id: TypeId) -> bool {
        row_of(type_id)
            .and_then(|row| self.grid.get(row))
            .is_some_and(|marks| marks.iter().any(|cell| cell.is_used()))
    }

    /// The profile's answer for a received ASDU, in [`Known`]'s shape: the
    /// seam [`InteropProfile`] has into the reception paths, beside
    /// [`Known::standard`].
    ///
    /// The profile answers *"I use this type identification"* (any mark in its
    /// row) and *"I accept this cause of transmission for that type"* (the
    /// grid's cell). The two project-data answers stay the caller's: *"this
    /// common address is mine"* and *"I have data for every information object
    /// address in this ASDU"*. Following clause 7.2.3's precedence, an unused
    /// type reports cause 44 and a used type with an unaccepted cause reports
    /// 45.
    #[must_use]
    pub fn known(
        &self,
        header: &Header,
        common_address: bool,
        information_object_address: bool,
    ) -> Known {
        Known::for_profile(self, header, common_address, information_object_address)
    }

    /// Clause 9.6's *"Test procedure"* row translated into [`crate::ts`]'s own
    /// value: the row's [`Direction`] is the checkbox and
    /// [`InteropProfile::test_form`] is the form beside it.
    #[must_use]
    pub fn test_selection(&self) -> ts::Selection {
        ts::Selection::default()
            .with_used(self.uses_function(Function::TestProcedure))
            .with_form(self.test_form)
    }

    /// Clause 9.6's two *"File transfer in monitor direction"* / *"File
    /// transfer in control direction"* rows translated into [`crate::ft`]'s own
    /// value.
    #[must_use]
    pub fn file_transfer(&self) -> ft::Selection {
        ft::Selection {
            monitor: self.uses_function(Function::FileTransferMonitor),
            control: self.uses_function(Function::FileTransferControl),
        }
    }

    /// Clause 9.6's *"Transmission of integrated totals"* row as the question
    /// [`crate::ci`] asks of its own mode: whether a counter-interrogation
    /// command may be issued at all ([`crate::ci::CounterMode::accepts_requests`]).
    ///
    /// The row's [`Direction`] is the checkbox; which of the four modes the
    /// station is, is [`InteropProfile::counter_mode`].
    #[must_use]
    pub fn counter_requests_accepted(&self) -> bool {
        self.uses_function(Function::IntegratedTotals) && self.counter_mode.accepts_requests()
    }

    /// Clause 9.6's *"Read procedure"* row as a boolean: the `uses_read`
    /// argument of [`crate::rd::Read::controlling`] and
    /// [`crate::rd::Read::controlled`].
    #[must_use]
    pub fn read_procedure_used(&self) -> bool {
        self.uses_function(Function::ReadProcedure)
    }

    /// The grid as readable text: one line per row with at least one marked
    /// cell, giving the type's name and then that row's marked column headings,
    /// so a profile can be inspected without a debug print of 1 273 cells.
    #[must_use]
    pub fn grid_rows(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for (type_id, marks) in TYPE_ROWS.iter().zip(&self.grid) {
            let marked: Vec<&str> = CAUSE_COLUMNS
                .iter()
                .zip(marks)
                .filter(|(_, mark)| mark.is_used())
                .map(|(column, _)| column.heading())
                .collect();
            if !marked.is_empty() {
                lines.push(format!("{} {}", type_id.name(), marked.join(",")));
            }
        }
        lines
    }
}

impl Default for InteropProfile {
    /// [`InteropProfile::conventional`].
    fn default() -> Self {
        Self::conventional()
    }
}

impl core::fmt::Debug for InteropProfile {
    /// A summary rather than 1 273 cells: the four carried values, the marked
    /// clause 9.6 rows and the count of marked grid cells.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let marked_rows: Vec<&str> = Function::ALL
            .iter()
            .copied()
            .filter(|row| self.uses_function(*row))
            .map(Function::name)
            .collect();
        let marked_cells = self
            .grid
            .iter()
            .flatten()
            .filter(|cell| cell.is_used())
            .count();
        f.debug_struct("InteropProfile")
            .field("address_sizes", &self.address_sizes)
            .field("link", &self.link)
            .field("counter_mode", &self.counter_mode)
            .field("test_form", &self.test_form)
            .field("functions", &marked_rows)
            .field("grid_cells_marked", &marked_cells)
            .finish()
    }
}
