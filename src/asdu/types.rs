//! The type-identification catalogue: every named type of IEC 60870-5-101
//! plus the types IEC 60870-5-104 adds, with direction, confirmation and
//! whether 104 selects it.
//!
//! Sources:
//!
//! - IEC 60870-5-101:2003 clause 7.2.1 / tables 8–13 (type identifications).
//! - IEC 60870-5-104:2006 clause 6 / tables 1–6: the *selection* of those types
//!   that is valid in 104, plus the types 104 itself adds (58–64, 107, 127).
//!
//! Two facts that are easy to get wrong and are pinned by the tables above:
//!
//! - The set-point commands are `48 C_SE_NA_1`, `49 C_SE_NB_1`, `50 C_SE_NC_1`.
//! - 104 does **not** select the `CP24Time2a` "…`TA_1"/"…TB_1"/"…TC_1`" monitor
//!   types (2, 4, 6, 8, 10, 12, 14, 16–19): only the untagged and `CP56Time2a`
//!   variants are valid in 104. They are still named here because they are
//!   legal ASDUs that a real link may see from a misconfigured peer.

/// Direction in which an ASDU may travel. "Monitor" is controlled → controlling
/// (the standard direction), "control" is controlling → controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Controlled station to controlling station.
    Monitor,
    /// Controlling station to controlled station.
    Control,
    /// File-transfer ASDUs, defined for both directions.
    Both,
}

/// Static description of one type identification, from 5-101 tables 8–13 and
/// the 104 selection in 5-104 clause 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypeInfo {
    /// The type-identification octet.
    pub id: u8,
    /// ASDU name as spelled in the standard (`M_SP_NA_1`).
    pub name: &'static str,
    /// The direction the tables list this ASDU in.
    pub direction: Direction,
    /// The tables mark this ASDU "CON": a confirmed application service that is
    /// mirrored in the monitor direction for positive/negative confirmation.
    pub confirmed: bool,
    /// True when 5-104 clause 6 selects this type for use over 104.
    pub selected_104: bool,
}

use Direction::{Both, Control, Monitor};

/// Every named type identification of the 101 catalogue, plus the types 104
/// adds. The single source for [`TypeId::name`], [`TypeId::direction`] and
/// [`TypeId::is_confirmed`].
pub const CATALOGUE: &[TypeInfo] = &[
    // 5-101 table 8: process information in monitor direction.
    info(1, "M_SP_NA_1", Monitor, false, true),
    info(2, "M_SP_TA_1", Monitor, false, false),
    info(3, "M_DP_NA_1", Monitor, false, true),
    info(4, "M_DP_TA_1", Monitor, false, false),
    info(5, "M_ST_NA_1", Monitor, false, true),
    info(6, "M_ST_TA_1", Monitor, false, false),
    info(7, "M_BO_NA_1", Monitor, false, true),
    info(8, "M_BO_TA_1", Monitor, false, false),
    info(9, "M_ME_NA_1", Monitor, false, true),
    info(10, "M_ME_TA_1", Monitor, false, false),
    info(11, "M_ME_NB_1", Monitor, false, true),
    info(12, "M_ME_TB_1", Monitor, false, false),
    info(13, "M_ME_NC_1", Monitor, false, true),
    info(14, "M_ME_TC_1", Monitor, false, false),
    info(15, "M_IT_NA_1", Monitor, false, true),
    info(16, "M_IT_TA_1", Monitor, false, false),
    info(17, "M_EP_TA_1", Monitor, false, false),
    info(18, "M_EP_TB_1", Monitor, false, false),
    info(19, "M_EP_TC_1", Monitor, false, false),
    info(20, "M_PS_NA_1", Monitor, false, true),
    info(21, "M_ME_ND_1", Monitor, false, true),
    info(30, "M_SP_TB_1", Monitor, false, true),
    info(31, "M_DP_TB_1", Monitor, false, true),
    info(32, "M_ST_TB_1", Monitor, false, true),
    info(33, "M_BO_TB_1", Monitor, false, true),
    info(34, "M_ME_TD_1", Monitor, false, true),
    info(35, "M_ME_TE_1", Monitor, false, true),
    info(36, "M_ME_TF_1", Monitor, false, true),
    info(37, "M_IT_TB_1", Monitor, false, true),
    info(38, "M_EP_TD_1", Monitor, false, true),
    info(39, "M_EP_TE_1", Monitor, false, true),
    info(40, "M_EP_TF_1", Monitor, false, true),
    // 5-101 table 9: process information in control direction.
    info(45, "C_SC_NA_1", Control, true, true),
    info(46, "C_DC_NA_1", Control, true, true),
    info(47, "C_RC_NA_1", Control, true, true),
    info(48, "C_SE_NA_1", Control, true, true),
    info(49, "C_SE_NB_1", Control, true, true),
    info(50, "C_SE_NC_1", Control, true, true),
    info(51, "C_BO_NA_1", Control, true, true),
    // 5-104 clause 8 / table 2: the time-tagged commands 104 adds.
    info(58, "C_SC_TA_1", Control, true, true),
    info(59, "C_DC_TA_1", Control, true, true),
    info(60, "C_RC_TA_1", Control, true, true),
    info(61, "C_SE_TA_1", Control, true, true),
    info(62, "C_SE_TB_1", Control, true, true),
    info(63, "C_SE_TC_1", Control, true, true),
    info(64, "C_BO_TA_1", Control, true, true),
    // 5-101 table 10: system information in monitor direction.
    info(70, "M_EI_NA_1", Monitor, false, true),
    // 5-101 table 11 / 5-104 table 4: system information in control direction.
    // 104 lists <102> without the CON mark (101 marks it CON).
    info(100, "C_IC_NA_1", Control, true, true),
    info(101, "C_CI_NA_1", Control, true, true),
    info(102, "C_RD_NA_1", Control, false, true),
    info(103, "C_CS_NA_1", Control, true, true),
    // 104 does not select the untagged test command; 107 supersedes it.
    info(104, "C_TS_NA_1", Control, true, false),
    info(105, "C_RP_NA_1", Control, true, true),
    info(106, "C_CD_NA_1", Control, true, false),
    info(107, "C_TS_TA_1", Control, true, true),
    // 5-101 table 12: parameters in control direction.
    info(110, "P_ME_NA_1", Control, true, true),
    info(111, "P_ME_NB_1", Control, true, true),
    info(112, "P_ME_NC_1", Control, true, true),
    info(113, "P_AC_NA_1", Control, true, true),
    // 5-101 table 13 / 5-104 table 6: file transfer. 104 fills <127>, which
    // 5-101 leaves reserved, with F_SC_NB_1 (Query Log).
    info(120, "F_FR_NA_1", Both, false, true),
    info(121, "F_SR_NA_1", Both, false, true),
    info(122, "F_SC_NA_1", Both, false, true),
    info(123, "F_LS_NA_1", Both, false, true),
    info(124, "F_AF_NA_1", Both, false, true),
    info(125, "F_SG_NA_1", Both, false, true),
    info(126, "F_DR_TA_1", Both, false, true),
    info(127, "F_SC_NB_1", Both, false, true),
];

const fn info(
    id: u8,
    name: &'static str,
    direction: Direction,
    confirmed: bool,
    selected_104: bool,
) -> TypeInfo {
    TypeInfo {
        id,
        name,
        direction,
        confirmed,
        selected_104,
    }
}

/// Looks up the catalogue entry for a type-identification octet.
#[must_use]
pub fn lookup(id: u8) -> Option<&'static TypeInfo> {
    CATALOGUE.iter().find(|t| t.id == id)
}

/// How the standard classifies a type-identification octet that has no name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeRange {
    /// `<0>`: not defined.
    NotDefined,
    /// Reserved for further compatible definitions.
    Reserved,
    /// `128..=135`: reserved for routing of messages (private range).
    Routing,
    /// `136..=255`: for special use (private range).
    Private,
}

/// Classifies a type identification that is not in [`CATALOGUE`].
#[must_use]
pub const fn range_of(id: u8) -> TypeRange {
    match id {
        0 => TypeRange::NotDefined,
        128..=135 => TypeRange::Routing,
        136..=255 => TypeRange::Private,
        _ => TypeRange::Reserved,
    }
}

/// Type identification: the function code of the ASDU.
///
/// Named variants cover both the 5-101 catalogue and the types 5-104 adds; any
/// other octet round-trips as [`TypeId::Other`] so an unexpected type never
/// breaks a link. Use [`TypeId::is_selected_104`] to tell a named type that
/// 104 does not select from one it does.
///
/// Each named variant's description is its line in 5-101 Tables 8 to 13, or in
/// 5-104 Tables 2, 4 and 6 for the types 104 adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeId {
    /// `<1>` `M_SP_NA_1`: single-point information.
    MSpNa1,
    /// `<2>` `M_SP_TA_1`: single-point information with time tag.
    MSpTa1,
    /// `<3>` `M_DP_NA_1`: double-point information.
    MDpNa1,
    /// `<4>` `M_DP_TA_1`: double-point information with time tag.
    MDpTa1,
    /// `<5>` `M_ST_NA_1`: step position information.
    MStNa1,
    /// `<6>` `M_ST_TA_1`: step position information with time tag.
    MStTa1,
    /// `<7>` `M_BO_NA_1`: bitstring of 32 bit.
    MBoNa1,
    /// `<8>` `M_BO_TA_1`: bitstring of 32 bit with time tag.
    MBoTa1,
    /// `<9>` `M_ME_NA_1`: measured value, normalized value.
    MMeNa1,
    /// `<10>` `M_ME_TA_1`: measured value, normalized value with time tag.
    MMeTa1,
    /// `<11>` `M_ME_NB_1`: measured value, scaled value.
    MMeNb1,
    /// `<12>` `M_ME_TB_1`: measured value, scaled value with time tag.
    MMeTb1,
    /// `<13>` `M_ME_NC_1`: measured value, short floating point number.
    MMeNc1,
    /// `<14>` `M_ME_TC_1`: measured value, short floating point number with time tag.
    MMeTc1,
    /// `<15>` `M_IT_NA_1`: integrated totals.
    MItNa1,
    /// `<16>` `M_IT_TA_1`: integrated totals with time tag.
    MItTa1,
    /// `<17>` `M_EP_TA_1`: event of protection equipment with time tag.
    MEpTa1,
    /// `<18>` `M_EP_TB_1`: packed start events of protection equipment with time tag.
    MEpTb1,
    /// `<19>` `M_EP_TC_1`: packed output circuit information of protection equipment with time tag.
    MEpTc1,
    /// `<20>` `M_PS_NA_1`: packed single-point information with status change detection.
    MPsNa1,
    /// `<21>` `M_ME_ND_1`: measured value, normalized value without quality descriptor.
    MMeNd1,
    /// `<30>` `M_SP_TB_1`: single-point information with time tag `CP56Time2a`.
    MSpTb1,
    /// `<31>` `M_DP_TB_1`: double-point information with time tag `CP56Time2a`.
    MDpTb1,
    /// `<32>` `M_ST_TB_1`: step position information with time tag `CP56Time2a`.
    MStTb1,
    /// `<33>` `M_BO_TB_1`: bitstring of 32 bits with time tag `CP56Time2a`.
    MBoTb1,
    /// `<34>` `M_ME_TD_1`: measured value, normalized value with time tag `CP56Time2a`.
    MMeTd1,
    /// `<35>` `M_ME_TE_1`: measured value, scaled value with time tag `CP56Time2a`.
    MMeTe1,
    /// `<36>` `M_ME_TF_1`: measured value, short floating point number with time tag `CP56Time2a`.
    MMeTf1,
    /// `<37>` `M_IT_TB_1`: integrated totals with time tag `CP56Time2a`.
    MItTb1,
    /// `<38>` `M_EP_TD_1`: event of protection equipment with time tag `CP56Time2a`.
    MEpTd1,
    /// `<39>` `M_EP_TE_1`: packed start events of protection equipment with time tag `CP56Time2a`.
    MEpTe1,
    /// `<40>` `M_EP_TF_1`: packed output circuit information of protection equipment with time tag `CP56Time2a`.
    MEpTf1,
    /// `<45>` `C_SC_NA_1`: single command.
    CScNa1,
    /// `<46>` `C_DC_NA_1`: double command.
    CDcNa1,
    /// `<47>` `C_RC_NA_1`: regulating step command.
    CRcNa1,
    /// `<48>` `C_SE_NA_1`: set point command, normalized value.
    CSeNa1,
    /// `<49>` `C_SE_NB_1`: set point command, scaled value.
    CSeNb1,
    /// `<50>` `C_SE_NC_1`: set point command, short floating point number.
    CSeNc1,
    /// `<51>` `C_BO_NA_1`: bitstring of 32 bits.
    CBoNa1,
    /// `<58>` `C_SC_TA_1`: single command with time tag `CP56Time2a`.
    CScTa1,
    /// `<59>` `C_DC_TA_1`: double command with time tag `CP56Time2a`.
    CDcTa1,
    /// `<60>` `C_RC_TA_1`: regulating step command with time tag `CP56Time2a`.
    CRcTa1,
    /// `<61>` `C_SE_TA_1`: set point command, normalized value with time tag `CP56Time2a`.
    CSeTa1,
    /// `<62>` `C_SE_TB_1`: set point command, scaled value with time tag `CP56Time2a`.
    CSeTb1,
    /// `<63>` `C_SE_TC_1`: set point command, short floating-point number with time tag `CP56Time2a`.
    CSeTc1,
    /// `<64>` `C_BO_TA_1`: bitstring of 32 bits with time tag `CP56Time2a`.
    CBoTa1,
    /// `<70>` `M_EI_NA_1`: end of initialization.
    MEiNa1,
    /// `<100>` `C_IC_NA_1`: interrogation command.
    CIcNa1,
    /// `<101>` `C_CI_NA_1`: counter interrogation command.
    CCiNa1,
    /// `<102>` `C_RD_NA_1`: read command.
    CRdNa1,
    /// `<103>` `C_CS_NA_1`: clock synchronization command.
    CCsNa1,
    /// `<104>` `C_TS_NA_1`: test command.
    CTsNa1,
    /// `<105>` `C_RP_NA_1`: reset process command.
    CRpNa1,
    /// `<106>` `C_CD_NA_1`: delay acquisition command.
    CCdNa1,
    /// `<107>` `C_TS_TA_1`: test command with time tag `CP56Time2a`.
    CTsTa1,
    /// `<110>` `P_ME_NA_1`: parameter of measured value, normalized value.
    PMeNa1,
    /// `<111>` `P_ME_NB_1`: parameter of measured value, scaled value.
    PMeNb1,
    /// `<112>` `P_ME_NC_1`: parameter of measured value, short floating-point number.
    PMeNc1,
    /// `<113>` `P_AC_NA_1`: parameter activation.
    PAcNa1,
    /// `<120>` `F_FR_NA_1`: file ready.
    FFrNa1,
    /// `<121>` `F_SR_NA_1`: section ready.
    FSrNa1,
    /// `<122>` `F_SC_NA_1`: call directory, select file, call file, call section.
    FScNa1,
    /// `<123>` `F_LS_NA_1`: last section, last segment.
    FLsNa1,
    /// `<124>` `F_AF_NA_1`: ack file, ack section.
    FAfNa1,
    /// `<125>` `F_SG_NA_1`: segment.
    FSgNa1,
    /// `<126>` `F_DR_TA_1`: directory.
    FDrTa1,
    /// `<127>` `F_SC_NB_1`: *"Query Log – Request archive file"*.
    FScNb1,
    /// Any type-identification octet without a named variant.
    Other(u8),
}

impl TypeId {
    /// Decodes the type-identification octet.
    #[must_use]
    pub const fn from_u8(raw: u8) -> Self {
        match raw {
            1 => Self::MSpNa1,
            2 => Self::MSpTa1,
            3 => Self::MDpNa1,
            4 => Self::MDpTa1,
            5 => Self::MStNa1,
            6 => Self::MStTa1,
            7 => Self::MBoNa1,
            8 => Self::MBoTa1,
            9 => Self::MMeNa1,
            10 => Self::MMeTa1,
            11 => Self::MMeNb1,
            12 => Self::MMeTb1,
            13 => Self::MMeNc1,
            14 => Self::MMeTc1,
            15 => Self::MItNa1,
            16 => Self::MItTa1,
            17 => Self::MEpTa1,
            18 => Self::MEpTb1,
            19 => Self::MEpTc1,
            20 => Self::MPsNa1,
            21 => Self::MMeNd1,
            30 => Self::MSpTb1,
            31 => Self::MDpTb1,
            32 => Self::MStTb1,
            33 => Self::MBoTb1,
            34 => Self::MMeTd1,
            35 => Self::MMeTe1,
            36 => Self::MMeTf1,
            37 => Self::MItTb1,
            38 => Self::MEpTd1,
            39 => Self::MEpTe1,
            40 => Self::MEpTf1,
            45 => Self::CScNa1,
            46 => Self::CDcNa1,
            47 => Self::CRcNa1,
            48 => Self::CSeNa1,
            49 => Self::CSeNb1,
            50 => Self::CSeNc1,
            51 => Self::CBoNa1,
            58 => Self::CScTa1,
            59 => Self::CDcTa1,
            60 => Self::CRcTa1,
            61 => Self::CSeTa1,
            62 => Self::CSeTb1,
            63 => Self::CSeTc1,
            64 => Self::CBoTa1,
            70 => Self::MEiNa1,
            100 => Self::CIcNa1,
            101 => Self::CCiNa1,
            102 => Self::CRdNa1,
            103 => Self::CCsNa1,
            104 => Self::CTsNa1,
            105 => Self::CRpNa1,
            106 => Self::CCdNa1,
            107 => Self::CTsTa1,
            110 => Self::PMeNa1,
            111 => Self::PMeNb1,
            112 => Self::PMeNc1,
            113 => Self::PAcNa1,
            120 => Self::FFrNa1,
            121 => Self::FSrNa1,
            122 => Self::FScNa1,
            123 => Self::FLsNa1,
            124 => Self::FAfNa1,
            125 => Self::FSgNa1,
            126 => Self::FDrTa1,
            127 => Self::FScNb1,
            other => Self::Other(other),
        }
    }

    /// The type-identification octet.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::MSpNa1 => 1,
            Self::MSpTa1 => 2,
            Self::MDpNa1 => 3,
            Self::MDpTa1 => 4,
            Self::MStNa1 => 5,
            Self::MStTa1 => 6,
            Self::MBoNa1 => 7,
            Self::MBoTa1 => 8,
            Self::MMeNa1 => 9,
            Self::MMeTa1 => 10,
            Self::MMeNb1 => 11,
            Self::MMeTb1 => 12,
            Self::MMeNc1 => 13,
            Self::MMeTc1 => 14,
            Self::MItNa1 => 15,
            Self::MItTa1 => 16,
            Self::MEpTa1 => 17,
            Self::MEpTb1 => 18,
            Self::MEpTc1 => 19,
            Self::MPsNa1 => 20,
            Self::MMeNd1 => 21,
            Self::MSpTb1 => 30,
            Self::MDpTb1 => 31,
            Self::MStTb1 => 32,
            Self::MBoTb1 => 33,
            Self::MMeTd1 => 34,
            Self::MMeTe1 => 35,
            Self::MMeTf1 => 36,
            Self::MItTb1 => 37,
            Self::MEpTd1 => 38,
            Self::MEpTe1 => 39,
            Self::MEpTf1 => 40,
            Self::CScNa1 => 45,
            Self::CDcNa1 => 46,
            Self::CRcNa1 => 47,
            Self::CSeNa1 => 48,
            Self::CSeNb1 => 49,
            Self::CSeNc1 => 50,
            Self::CBoNa1 => 51,
            Self::CScTa1 => 58,
            Self::CDcTa1 => 59,
            Self::CRcTa1 => 60,
            Self::CSeTa1 => 61,
            Self::CSeTb1 => 62,
            Self::CSeTc1 => 63,
            Self::CBoTa1 => 64,
            Self::MEiNa1 => 70,
            Self::CIcNa1 => 100,
            Self::CCiNa1 => 101,
            Self::CRdNa1 => 102,
            Self::CCsNa1 => 103,
            Self::CTsNa1 => 104,
            Self::CRpNa1 => 105,
            Self::CCdNa1 => 106,
            Self::CTsTa1 => 107,
            Self::PMeNa1 => 110,
            Self::PMeNb1 => 111,
            Self::PMeNc1 => 112,
            Self::PAcNa1 => 113,
            Self::FFrNa1 => 120,
            Self::FSrNa1 => 121,
            Self::FScNa1 => 122,
            Self::FLsNa1 => 123,
            Self::FAfNa1 => 124,
            Self::FSgNa1 => 125,
            Self::FDrTa1 => 126,
            Self::FScNb1 => 127,
            Self::Other(raw) => raw,
        }
    }

    /// Its catalogue entry, if the standard names this type.
    #[must_use]
    pub fn info(self) -> Option<&'static TypeInfo> {
        lookup(self.to_u8())
    }

    /// ASDU name from the standard, e.g. `"M_ME_NB_1"`, or a description of the
    /// reserved/private range it falls in.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.info().map_or_else(
            || match range_of(self.to_u8()) {
                TypeRange::NotDefined => "not defined",
                TypeRange::Reserved => "reserved",
                TypeRange::Routing => "routing (private)",
                TypeRange::Private => "private",
            },
            |t| t.name,
        )
    }

    /// Direction this type may travel, if it is a named type.
    #[must_use]
    pub fn direction(self) -> Option<Direction> {
        self.info().map(|t| t.direction)
    }

    /// True for the "CON" ASDUs (confirmed application services).
    #[must_use]
    pub fn is_confirmed(self) -> bool {
        self.info().is_some_and(|t| t.confirmed)
    }

    /// True when 5-104 clause 6 selects this type for use over IEC 104.
    #[must_use]
    pub fn is_selected_104(self) -> bool {
        self.info().is_some_and(|t| t.selected_104)
    }
}
