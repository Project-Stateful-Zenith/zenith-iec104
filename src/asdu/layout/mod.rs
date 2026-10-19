//! The per-type ASDU layouts of IEC 60870-5-101:2003 clause **7.3**.
//!
//! They cover the process information of the monitor direction (clause 7.3.1), the control
//! direction, system information and parameters (clauses 7.3.2–7.3.5), the
//! eight time-tagged command ASDUs that IEC 60870-5-104:2006 clause 8 adds, and
//! the eight file-transfer ASDUs of 5-101 clause 7.3.6 plus 5-104 clause 8.9.
//!
//! Clause 7.2.6 (the element layer, [`super::elements`]) defines *what an
//! information element is*; clause 7.3 defines *which elements an ASDU of a
//! given type identification carries, and in what order*. This module is that
//! second half: one type per ASDU, each named as the standard names it
//! (`MSpNa1` for `M_SP_NA_1`, `CScNa1` for `C_SC_NA_1`, …), each carrying its
//! elements as fields in the order the clause's definition line lists them, and
//! each able to read itself from, and append itself to, the object's element
//! octets.
//!
//! ```text
//! M_ME_NC_1 := CP{Data unit identifier,i(Information object address,IEEE STD 754,QDS)}
//!                                                    \_____ this module _____/
//! ```
//!
//! The data unit identifier is [`super::Header`]; the information object
//! address is [`super::BodyReader`]'s; only the `i(...)`/`CP{…}` arguments are
//! a layout, and [`AsduLayout::LEN`] is exactly the octet count the body cursor
//! takes (`BodyReader::next_object(element_len)`).
//!
//! # The 32 monitor ASDUs
//!
//! Clause 7.3.1 has 32 contiguous subsections, `7.3.1.1` … `7.3.1.32`, and they
//! are the type identifications 1–21 and 30–40. 5-101 imposes no numbering
//! correspondence: `7.3.1.22` is type **30** `M_SP_TB_1`. Each type's doc
//! comment names its own subsection and quotes its definition line. The
//! complete geometry, with the octet count this module derives from the
//! element layer's `LEN` constants, is [`MONITOR_LAYOUTS`].
//!
//! # The 27 control, system and parameter ASDUs
//!
//! Clauses 7.3.2 (`.1`–`.7`, the seven command ASDUs 45–51), 7.3.3 (`.1`,
//! `M_EI_NA_1` type 70), 7.3.4 (`.1`–`.7`, the system commands 100–106) and
//! 7.3.5 (`.1`–`.4`, the parameters 110–113) give 19 more 5-101 layouts, and
//! clause 8 of 5-104 gives the eight time-tagged command forms (58–64 and 107):
//! together [`CONTROL_LAYOUTS`]. Every one of those pages prints *"Single information
//! object (SQ = 0)"*, gives no "Number i of objects" field and has no `j(...)`
//! definition line, so all 27 are [`Sequence::NotDefined`] with
//! [`ObjectCount::Single`]. Two of them are worth naming here:
//!
//! * `C_RD_NA_1` (type 102) is the one layout with **no element at all**: its
//!   whole payload is the information object address (clause 7.2.5), so its
//!   `LEN` is 0 and `BodyReader::next_object(0)` yields the object with an empty
//!   element slice.
//! * `C_TS_TA_1` (type 107) carries `TSC`, which is 5-104 clause 8.8's element
//!   and not a clause 7.2.6 one: the only such element in the crate.
//!
//! # The eight file-transfer ASDUs
//!
//! Clause 7.3.6 (`7.3.6.1`–`.7`, types 120–126, figures 83–89) plus 5-104
//! clause 8.9's `F_SC_NB_1` `<127>` (figure 31) are [`FILE_LAYOUTS`]; their
//! geometry, figures and page indices are in the doc of the private `file`
//! module (`src/asdu/layout/file.rs`). `F_SR_NA_1`'s element is 7 octets, not 5:
//! figure 84's *"Length of section"* is `LOF` (7.2.6.35, three octets). Two of
//! the eight need more than a constant-length row:
//!
//! * `<125>` `F_SG_NA_1` carries a variable-length element (figure 88's
//!   `Octet 1 … Octet n`), so its row has `variable = true` and it is read
//!   and written through [`decode_segment`] / [`encode_segment`]. This is why
//!   [`Layout::variable`] exists.
//! * `<126>` `F_DR_TA_1` is the family's only sequence form, and that is its
//!   only form: a 13-octet element per file, `j` files at `A + i − 1`. It needs
//!   no machinery beyond [`Sequence::Required`] (figure 89 defines nothing else,
//!   so an `SQ = 0` ASDU of it is [`LayoutError::SequenceRequired`] rather than
//!   a read that loses every file after the first) and `Multiple`'s maximum of
//!   18 files ([`MAX_DIRECTORY_FILES`], 5-104 index 26).
//!
//! # The two addressing rules of the clause
//!
//! * **SQ = 1 only where the definition line has `j(...)`.** Ten monitor types
//!   define a sequence form (`M_SP_NA_1`, `M_DP_NA_1`, `M_ST_NA_1`,
//!   `M_BO_NA_1`, `M_ME_NA_1`, `M_ME_NB_1`, `M_ME_NC_1`, `M_IT_NA_1`,
//!   `M_PS_NA_1`, `M_ME_ND_1`: [`Sequence::Defined`]) and **no** control,
//!   system or parameter type does. One type has the sequence and nothing else
//!   ([`Sequence::Required`], `<126>` `F_DR_TA_1`). Every time-tagged monitor
//!   type says the opposite in its own words, *"Since each … has its individual
//!   time tag, this type of ASDU does not exist as a sequence of information
//!   elements"* (7.3.1.2, .4, .6, .8, .10, .12, .14, .16, .17 and again for the
//!   `CP56Time2a` forms .22–.32), and the four protection-equipment types 18, 19,
//!   39 and 40 define no `i(...)`/`j(...)` at all. A sequence for one of those
//!   is [`LayoutError::SequenceNotAllowed`], never a decode that happens to fit.
//! * **Thirty-eight types carry exactly one information object.** 7.3.1.18,
//!   .19, .31 and .32 print *"Single information object (SQ = 0)"* and give no
//!   "Number i of objects" field, as do all 27 of [`CONTROL_LAYOUTS`]; seven of
//!   the eight [`FILE_LAYOUTS`] (all but `F_DR_TA_1`) are single-object too.
//!   Those ASDU types have one object by construction ([`ObjectCount::Single`]):
//!   `N ≥ 2` is [`LayoutError::ObjectCountNotAllowed`]. A received `N = 0`
//!   stays clause 7.2.2's defined "ASDU contains no INFORMATION OBJECT".
//!
//! Both rules are enforced on the read and the write side by the same private
//! `check_layout` (and, for `<125>`, by the segment path's own
//! `check_single`), and neither is expressible with [`super::encode_body`]
//! alone: the body cursor cannot know that `M_EP_TB_1` has no sequence form.
//!
//! # The 12-octet ceiling and the 249-octet ASDU
//!
//! The widest element of clauses 7.3.1–7.3.5 and 5-104 clause 8 is 12 octets
//! (`M_BO_TB_1`, `M_ME_TF_1`, `M_IT_TB_1`, `C_SE_TC_1`; 7 of them the time
//! tag), but all four are time-tagged and therefore have no sequence form; the
//! widest element there that *can* be sequenced is 5 octets (`M_BO_NA_1`,
//! `M_ME_NC_1`, `M_IT_NA_1`, `M_PS_NA_1`). Clause 7.3.6 adds two rows that move
//! both numbers: `F_DR_TA_1` `<126>` has a **13-octet** element and *is* a
//! sequence (figure 89's `j` files), while `F_SG_NA_1` `<125>` has no constant
//! element length at all. The ASDU budget of 5-104 clause 5 (249 octets, 243
//! behind the 6-octet header) therefore bites at a different point for each
//! shape, and [`super::encode_body`] reports [`AsduError::BodyTooLong`] past
//! each of them:
//!
//! ```text
//! SQ = 0, 12-octet element:  3 + 12 per object: 16 objects (240) fit, 17 (255) do not
//! SQ = 0, 5-octet element:   3 + 5  per object: 30 objects (240) fit, 31 (248) do not
//! SQ = 1, 12-octet element:  not possible, those types have no sequence form
//! SQ = 1, 13-octet element:  3 + 13 per element: 18 elements (237) fit, 19 (250) do not
//! SQ = 1, 5-octet element:   3 + 5 per element: 48 elements (243) fit, 49 (248) do not
//! ```
//!
//! The two `SQ = 0` boundaries and the `SQ = 1`, 5-octet one are pinned by
//! `tests/layout.rs`; the `SQ = 1`, 13-octet one is `F_DR_TA_1`'s
//! [`MAX_DIRECTORY_FILES`], pinned by `tests/file_transfer.rs`. `F_SG_NA_1`'s
//! segment is bounded by [`MAX_SEGMENT`], the same limit `src/ft.rs` enforces.
//!
//! # What is the project's choice, not the standard's
//!
//! * **The per-type structs are this crate's spelling.** The standard has no
//!   identifiers for "a parsed `M_ME_NB_1` object"; the field names are the
//!   clause's element abbreviations in lower case, in definition-line order.
//! * **[`decode_asdu`] accepts `N = 0` for every type**, including the
//!   single-object ones: clause 7.2.2 defines `<0>` for the variable structure
//!   qualifier, and refusing it would contradict that while protecting nothing.
//!   The write side does not produce `N = 0` for a single-object type
//!   ([`encode_asdu`] and [`encode_segment`] refuse it), and [`decode_segment`]
//!   refuses it on read, since a segment ASDU without its object has nothing to
//!   read.
//! * **A longer element slice is read as its first `LEN` octets**, exactly as
//!   every parser in [`super::elements`] reads its own prefix. The body cursor
//!   never hands over more, so this only matters to a caller passing a slice of
//!   its own.
//!
//! # Example
//!
//! A three-object `M_ME_NB_1` ASDU (scaled value + quality descriptor, three
//! octets per element) read to typed values and written back:
//!
//! ```
//! use iec104::asdu::{decode_asdu, element_len, encode_asdu, Header, MMeNb1, TypeId};
//!
//! // Header: M_ME_NB_1, SQ = 0, 3 objects, spontaneous, CA 12.
//! let asdu = [
//!     0x0B, 0x03, 0x03, 0x00, 0x0C, 0x00,
//!     0x10, 0x30, 0x00, 0xBE, 0x09, 0x00,
//!     0x11, 0x30, 0x00, 0x90, 0x09, 0x00,
//!     0x12, 0x30, 0x00, 0x75, 0x00, 0x00,
//! ];
//!
//! let objects = decode_asdu::<MMeNb1>(&asdu).unwrap();
//! assert_eq!(objects.len(), 3);
//! assert_eq!(objects[0].ioa, 0x3010);
//! assert_eq!(objects[0].value.sva.value, 0x09BE);
//! assert!(!objects[2].value.qds.invalid);
//!
//! // The octet length the body cursor has always taken as an argument:
//! assert_eq!(element_len(TypeId::MMeNb1), Some(3));
//!
//! // And back out, byte for byte.
//! let header = Header::parse(&asdu).unwrap();
//! assert_eq!(encode_asdu(&header, &objects).unwrap(), asdu);
//! ```
//!
//! # Sources
//!
//! IEC 60870-5-101:2003 clause 7.3.1, PDF page indices 60–98 (printed pages
//! 59–97), clauses 7.3.2–7.3.5, page indices 99–113, and IEC 60870-5-104:2006
//! clause 8, page indices 76–90 (the English pages). The definition lines (`M_ME_NC_1 := CP{Data
//! unit identifier,i(Information object address,IEEE STD 754,QDS)}`) are text
//! and extract cleanly; the ASCII field rows around them are printed MSB-first
//! and are *not* used here. Where a figure was read as a cross-check it agrees
//! with the definition line once its rows are read by coordinate: figure 46 on
//! page 81 draws `CP16Time2a` above `CP24Time2a`, as `M_EP_TA_1`'s definition
//! line says, while a plain text dump of that page prints them the other way
//! round. Element octet counts are the `LEN` constants of clause 7.2.6, except
//! `TSC`, 5-104 clause 8.8's element, which 5-101 does not define.
//!
//! The 104 profile's selection of these types is 5-104's selection tables 1–6
//! (PDF page indices 48–52; the tables, not clause 6, which maps the selected
//! ASDUs onto the TCP services). They list 1, 3, 5, 7, 9, 11, 13, 15, 20, 21,
//! 30–40 for the monitor direction, 45–51, 58–64 and 70 for the control
//! direction, 100–103, 105, 107 and 110–113 for the system and parameter ASDUs.
//! The `CP24Time2a` monitor forms 2/4/6/8/10/12/14/16, the `CP24Time2a` protection
//! types 17/18/19 and the untagged test command 104 are legal 5-101 ASDUs with
//! no row in those tables, and the delay acquisition command 106 is a 5-101
//! function 104 omits (clause 9.5's cause table marks both rows "option not
//! permitted"). All are laid out here anyway because a real link may see them.

mod control;
mod file;
mod monitor;

pub use control::{
    CBoNa1, CBoTa1, CCdNa1, CCiNa1, CCsNa1, CDcNa1, CDcTa1, CIcNa1, CRcNa1, CRcTa1, CRdNa1, CRpNa1,
    CScNa1, CScTa1, CSeNa1, CSeNb1, CSeNc1, CSeTa1, CSeTb1, CSeTc1, CTsNa1, CTsTa1, MEiNa1, PAcNa1,
    PMeNa1, PMeNb1, PMeNc1,
};
pub use file::max_segment_with;
pub use file::{
    FAfNa1, FDrTa1, FFrNa1, FILE_LAYOUTS, FLsNa1, FScNa1, FScNb1, FSrNa1, MAX_DIRECTORY_FILES,
    MAX_SEGMENT, Segment, decode_segment, decode_segment_with, encode_segment, encode_segment_with,
};
pub use monitor::{
    MBoNa1, MBoTa1, MBoTb1, MDpNa1, MDpTa1, MDpTb1, MEpTa1, MEpTb1, MEpTc1, MEpTd1, MEpTe1, MEpTf1,
    MItNa1, MItTa1, MItTb1, MMeNa1, MMeNb1, MMeNc1, MMeNd1, MMeTa1, MMeTb1, MMeTc1, MMeTd1, MMeTe1,
    MMeTf1, MPsNa1, MSpNa1, MSpTa1, MSpTb1, MStNa1, MStTa1, MStTb1,
};

use super::elements::{
    Bcr, Bsi, Coi, Cp16Time2a, Cp24Time2a, Cp56Time2a, Dco, Diq, Fbp, Nva, Oci, Qcc, Qdp, Qds, Qoi,
    Qos, Qpa, Qpm, Qrp, R32, Rco, Scd, Sco, Sep, Siq, Spe, Sva, Tsc, Vti,
};
use super::{AddressSizes, AsduError, BodyReader, Header, Object, TypeId};
use crate::asdu::encode_body_with;

/// Whether clause 7.3 defines a sequence form (`j(...)`) for a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sequence {
    /// The definition line has a `j(...)` form and the figure carries the row
    /// "Sequence of information elements in a single information object
    /// (SQ = 1)". Exactly ten monitor types have this, and SQ = 0 is legal for
    /// them beside it.
    Defined,
    /// SQ = 1 **only**: the figure's whole object area *is* the sequence, so an
    /// ASDU of the type with `SQ = 0` cannot be read as one
    /// ([`LayoutError::SequenceRequired`]). One type is this: `<126>`
    /// `F_DR_TA_1`, whose figure 89 heading is *"Sequence of information
    /// elements in a single information object (SQ = 1)"* and whose definition
    /// line's `j` is *"number of set of elements defined in the variable
    /// structure qualifier"*, so the `j` sets have no `SQ = 0` form to fall back
    /// on (5-101 clause 7.3.6.7, index 120).
    Required,
    /// SQ = 0 only: either the type states in so many words that it "does not
    /// exist as a sequence of information elements" (every time-tagged monitor
    /// type), or it defines no `i(...)`/`j(...)` at all (types 18, 19, 39, 40,
    /// and every control, system, parameter and file type except `<126>`).
    NotDefined,
}

/// How many information objects an ASDU of a type can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectCount {
    /// `N = 0..=127`, the variable structure qualifier's own range
    /// (5-101 clause 7.2.2).
    Multiple,
    /// Exactly one: the type's figure says "Single information object (SQ = 0)"
    /// and gives no "Number i of objects" field. Types 18, 19, 39, 40, every
    /// control, system and parameter type, and every file type except `<126>`.
    Single,
}

/// The geometry of one ASDU type: what the body cursor needs, and the two
/// addressing rules of clause 7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// The type identification this layout belongs to.
    pub type_id: TypeId,
    /// Octets of one information object's element part: the `element_len`
    /// argument of [`BodyReader::next_object`]. Derived from the element
    /// layer's `LEN` constants, never retyped. It is **0** for the one type
    /// whose figure prints `Octet 1 … Octet n` (`<125>` `F_SG_NA_1`, figure 88):
    /// that type's length is carried by the element's own octets, no constant
    /// exists to put here, and [`Layout::variable`] says so. Read the two
    /// together: [`element_len`] returns `None` for it rather than this 0, and
    /// [`decode_asdu`] / [`encode_asdu`] refuse it with
    /// [`LayoutError::VariableElementLength`].
    pub element_len: usize,
    /// Whether the element's own octets carry its length, so `element_len` is
    /// meaningless and the type is read and written through its own entry point
    /// ([`decode_segment`] / [`encode_segment`]) instead of
    /// [`decode_asdu`] / [`encode_asdu`]. True for `<125>` `F_SG_NA_1` alone.
    pub variable: bool,
    /// Whether clause 7.3 defines the SQ = 1 form for this type.
    pub sequence: Sequence,
    /// How many information objects an ASDU of this type can carry.
    pub count: ObjectCount,
}

const fn layout(
    type_id: TypeId,
    element_len: usize,
    sequence: Sequence,
    count: ObjectCount,
) -> Layout {
    Layout {
        type_id,
        element_len,
        variable: false,
        sequence,
        count,
    }
}

/// The same row for a type whose element length is not a constant (`<125>`
/// `F_SG_NA_1`, figure 88). See [`Layout::variable`].
const fn variable_layout(type_id: TypeId, sequence: Sequence, count: ObjectCount) -> Layout {
    Layout {
        type_id,
        element_len: 0,
        variable: true,
        sequence,
        count,
    }
}

use ObjectCount::{Multiple, Single};
use Sequence::{Defined, NotDefined};

/// Every monitor-direction ASDU layout of 5-101 clause 7.3.1, in type order.
///
/// The `element_len` of each row is the sum of the clause 7.2.6 `LEN`
/// constants the type's definition line names. This is the single place where
/// the per-type octet geometry is stated.
pub const MONITOR_LAYOUTS: &[Layout] = &[
    // 7.3.1.1–7.3.1.21: the untagged, CP24Time2a and CP16Time2a forms.
    layout(TypeId::MSpNa1, Siq::LEN, Defined, Multiple),
    layout(
        TypeId::MSpTa1,
        Siq::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(TypeId::MDpNa1, Diq::LEN, Defined, Multiple),
    layout(
        TypeId::MDpTa1,
        Diq::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(TypeId::MStNa1, Vti::LEN + Qds::LEN, Defined, Multiple),
    layout(
        TypeId::MStTa1,
        Vti::LEN + Qds::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(TypeId::MBoNa1, Bsi::LEN + Qds::LEN, Defined, Multiple),
    layout(
        TypeId::MBoTa1,
        Bsi::LEN + Qds::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(TypeId::MMeNa1, Nva::LEN + Qds::LEN, Defined, Multiple),
    layout(
        TypeId::MMeTa1,
        Nva::LEN + Qds::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(TypeId::MMeNb1, Sva::LEN + Qds::LEN, Defined, Multiple),
    layout(
        TypeId::MMeTb1,
        Sva::LEN + Qds::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(TypeId::MMeNc1, R32::LEN + Qds::LEN, Defined, Multiple),
    layout(
        TypeId::MMeTc1,
        R32::LEN + Qds::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(TypeId::MItNa1, Bcr::LEN, Defined, Multiple),
    layout(
        TypeId::MItTa1,
        Bcr::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MEpTa1,
        Sep::LEN + Cp16Time2a::LEN + Cp24Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MEpTb1,
        Spe::LEN + Qdp::LEN + Cp16Time2a::LEN + Cp24Time2a::LEN,
        NotDefined,
        Single,
    ),
    layout(
        TypeId::MEpTc1,
        Oci::LEN + Qdp::LEN + Cp16Time2a::LEN + Cp24Time2a::LEN,
        NotDefined,
        Single,
    ),
    layout(TypeId::MPsNa1, Scd::LEN + Qds::LEN, Defined, Multiple),
    layout(TypeId::MMeNd1, Nva::LEN, Defined, Multiple),
    // 7.3.1.22–7.3.1.32: the CP56Time2a forms (types 30–40).
    layout(
        TypeId::MSpTb1,
        Siq::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MDpTb1,
        Diq::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MStTb1,
        Vti::LEN + Qds::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MBoTb1,
        Bsi::LEN + Qds::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MMeTd1,
        Nva::LEN + Qds::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MMeTe1,
        Sva::LEN + Qds::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MMeTf1,
        R32::LEN + Qds::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MItTb1,
        Bcr::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MEpTd1,
        Sep::LEN + Cp16Time2a::LEN + Cp56Time2a::LEN,
        NotDefined,
        Multiple,
    ),
    layout(
        TypeId::MEpTe1,
        Spe::LEN + Qdp::LEN + Cp16Time2a::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    layout(
        TypeId::MEpTf1,
        Oci::LEN + Qdp::LEN + Cp16Time2a::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
];

/// Every control-direction, system and parameter ASDU layout of 5-101 clauses
/// 7.3.2–7.3.5 plus the eight of 5-104 clause 8, in type order.
///
/// Every row is `NotDefined`/`Single`: every clause page prints *"Single
/// information object (SQ = 0)"* and no "Number i of objects" field, and no
/// definition line has an `i(...)`/`j(...)` form. So no control, system or
/// parameter ASDU has a sequence form, and none carries more than one
/// information object. The `element_len` of each row is again the sum of the
/// clause 7.2.6 `LEN` constants its definition line names (`TSC`, of 5-104
/// clause 8.8, being the one element outside that clause). `C_RD_NA_1`'s row is
/// the 0 of a type whose whole payload is its address.
pub const CONTROL_LAYOUTS: &[Layout] = &[
    // 7.3.2: the control direction (types 45–51).
    layout(TypeId::CScNa1, Sco::LEN, NotDefined, Single),
    layout(TypeId::CDcNa1, Dco::LEN, NotDefined, Single),
    layout(TypeId::CRcNa1, Rco::LEN, NotDefined, Single),
    layout(TypeId::CSeNa1, Nva::LEN + Qos::LEN, NotDefined, Single),
    layout(TypeId::CSeNb1, Sva::LEN + Qos::LEN, NotDefined, Single),
    layout(TypeId::CSeNc1, R32::LEN + Qos::LEN, NotDefined, Single),
    layout(TypeId::CBoNa1, Bsi::LEN, NotDefined, Single),
    // 5-104 clause 8.1–8.6: the time-tagged command forms (types 58–63).
    layout(
        TypeId::CScTa1,
        Sco::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    layout(
        TypeId::CDcTa1,
        Dco::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    layout(
        TypeId::CRcTa1,
        Rco::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    layout(
        TypeId::CSeTa1,
        Nva::LEN + Qos::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    layout(
        TypeId::CSeTb1,
        Sva::LEN + Qos::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    layout(
        TypeId::CSeTc1,
        R32::LEN + Qos::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    // 5-104 clause 8.7: the time-tagged bitstring command (type 64).
    layout(
        TypeId::CBoTa1,
        Bsi::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    // 7.3.3: station initialisation (type 70).
    layout(TypeId::MEiNa1, Coi::LEN, NotDefined, Single),
    // 7.3.4: the system commands (types 100–106).
    layout(TypeId::CIcNa1, Qoi::LEN, NotDefined, Single),
    layout(TypeId::CCiNa1, Qcc::LEN, NotDefined, Single),
    layout(TypeId::CRdNa1, 0, NotDefined, Single),
    layout(TypeId::CCsNa1, Cp56Time2a::LEN, NotDefined, Single),
    layout(TypeId::CTsNa1, Fbp::LEN, NotDefined, Single),
    layout(TypeId::CRpNa1, Qrp::LEN, NotDefined, Single),
    layout(TypeId::CCdNa1, Cp16Time2a::LEN, NotDefined, Single),
    // 5-104 clause 8.8: the time-tagged test command (type 107).
    layout(
        TypeId::CTsTa1,
        Tsc::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
    // 7.3.5: the parameters (types 110–113).
    layout(TypeId::PMeNa1, Nva::LEN + Qpm::LEN, NotDefined, Single),
    layout(TypeId::PMeNb1, Sva::LEN + Qpm::LEN, NotDefined, Single),
    layout(TypeId::PMeNc1, R32::LEN + Qpm::LEN, NotDefined, Single),
    layout(TypeId::PAcNa1, Qpa::LEN, NotDefined, Single),
];

/// The layout of a type identification, if clause 7.3 defines one.
///
/// The three families are consulted in one lookup, so a caller has a single
/// entry point and never has to know which clause a type came from:
/// [`MONITOR_LAYOUTS`] (clause 7.3.1), [`CONTROL_LAYOUTS`] (clauses 7.3.2–7.3.5
/// and 5-104 clause 8) then [`FILE_LAYOUTS`] (clause 7.3.6 and 5-104 clause
/// 8.9). `None` means "no layout": a type outside the catalogue has no layout at
/// all. All **67** laid-out types are answered: the 58 of 5-101 clause 7.3 and
/// the nine ASDUs 104 adds, including `<127>`, which 101 leaves inside its
/// `<120..127>` range but never defines.
#[must_use]
pub fn layout_for(type_id: TypeId) -> Option<&'static Layout> {
    MONITOR_LAYOUTS
        .iter()
        .chain(CONTROL_LAYOUTS)
        .chain(FILE_LAYOUTS)
        .find(|l| l.type_id == type_id)
}

/// The octet count of one information object's element part for `type_id`:
/// the argument [`BodyReader::next_object`] takes, and the reason this module
/// exists.
///
/// `None` for the two cases in which there is no single number: a type with no
/// layout at all, and `F_SG_NA_1` `<125>`, whose element length is carried by its
/// own `LOS` octet ([`Layout::variable`]). That type is read and written
/// through [`decode_segment`] / [`encode_segment`] instead, and a number here
/// would be wrong for every segment but one.
#[must_use]
pub fn element_len(type_id: TypeId) -> Option<usize> {
    let layout = layout_for(type_id)?;
    if layout.variable {
        None
    } else {
        Some(layout.element_len)
    }
}

/// One ASDU type's element geometry, as a type: the fields of the struct are
/// the elements of the type's definition line, in order.
///
/// Implementors are the 32 layouts of clause 7.3.1 (the monitor types), the 27
/// of clauses 7.3.2–7.3.5 and 5-104 clause 8 (the control, system and
/// parameter types), and seven of the eight of clause 7.3.6 and 5-104 clause
/// 8.9 (the file types). `F_SG_NA_1` `<125>` is the one type with no
/// implementor, because its element length is not a constant (figure 88's
/// `Octet 1 … Octet n`) and the trait's `LEN` could not state it; it is read
/// and written through [`decode_segment`] / [`encode_segment`] instead. The
/// trait is direction-neutral on purpose: it is what the generic readers and
/// writers of this module are written against, so all the families go through
/// the same [`decode_asdu`] / [`encode_asdu`] path.
///
/// `parse` must read the object's element octets the [`BodyReader`] hands over
/// and report every short prefix as [`AsduError::TooShort`]. It must never
/// index past the slice and never panic. Octets beyond `LEN` are ignored,
/// exactly as every element parser of clause 7.2.6 ignores them. `LEN` may be
/// 0: `C_RD_NA_1`'s
/// whole payload is its information object address, so its element part is
/// empty and `parse` accepts an empty slice.
pub trait AsduLayout: Sized {
    /// The type identification this layout belongs to.
    const TYPE_ID: TypeId;
    /// Octets of one information object's element part.
    const LEN: usize;
    /// Decodes one object's element octets.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] for an element shorter than `LEN`, or the
    /// element layer's own error for octets it refuses.
    fn parse(element: &[u8]) -> Result<Self, AsduError>;
    /// Appends one object's element octets.
    fn encode(&self, out: &mut Vec<u8>);
}

/// One decoded information object: its information object address and the
/// typed value of its elements (5-101 clause 7.2.5 and 7.3).
///
/// No `Eq`: several of the layouts carry an `R32` (an IEEE 754 `f32`), which is
/// `PartialEq` only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutObject<A> {
    /// Information object address (`UI24` in the conventional profile);
    /// [`super::IOA_IRRELEVANT`] means the type has no use for the field.
    pub ioa: u32,
    /// The decoded elements of this object.
    pub value: A,
}

/// What can go wrong in this layer, over and above the codec's
/// [`AsduError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// The ASDU itself could not be parsed; the codec's own error, unchanged.
    Asdu(AsduError),
    /// `A::TYPE_ID` has no row in the layout tables (a caller's own
    /// [`AsduLayout`] for a type clause 7.3 does not define), so there is no
    /// layout to check the addressing rules against.
    NoLayout {
        /// The type identification concerned.
        type_id: TypeId,
    },
    /// The ASDU carries a different type identification than the layout it is
    /// being read or written with.
    TypeMismatch {
        /// The type identification of the layout, or of the objects being
        /// encoded.
        expected: TypeId,
        /// The ASDU's type identification.
        got: TypeId,
    },
    /// SQ = 1 for a type whose definition line has no `j(...)`: clause 7.3
    /// gives those types no sequence of information elements.
    SequenceNotAllowed {
        /// The type identification concerned.
        type_id: TypeId,
    },
    /// SQ = 0 for the one type whose figure defines only the sequence form:
    /// `<126>` `F_DR_TA_1`, figure 89's *"Sequence of information elements in a
    /// single information object (SQ = 1)"* (5-101 clause 7.3.6.7, index 120).
    /// Read as `SQ = 0`, the octets of the files after the first would be taken
    /// for addresses and elements they are not, so the layer refuses the ASDU
    /// instead.
    SequenceRequired {
        /// The type identification concerned.
        type_id: TypeId,
    },
    /// More than one information object for a type whose figure says "Single
    /// information object (SQ = 0)" ([`ObjectCount::Single`]), or, on the write
    /// path and in [`decode_segment`], none at all.
    ObjectCountNotAllowed {
        /// The type identification concerned.
        type_id: TypeId,
        /// The number of information objects.
        count: u8,
    },
    /// A `<125>` `F_SG_NA_1` element with no segment octets: 5-101 clause
    /// 7.2.6.36 (index 58) defines `LOS`'s `<0>` as *"not used"*, so a zero
    /// length is not a segment of no octets but the absence of one.
    EmptySegment {
        /// The type identification concerned.
        type_id: TypeId,
    },
    /// A `<125>` `F_SG_NA_1` element whose segment octets exceed
    /// [`MAX_SEGMENT`]: 236, the 249-octet ASDU of 5-104 index 26 less the
    /// header, the address and the element's own prefix (or the
    /// [`max_segment_with`] of the profile's address sizes). The element's
    /// `LOS` is one octet, so without the check an oversized payload would
    /// either be clamped to a length its octets contradict or be written as a
    /// truncated byte.
    SegmentTooLong {
        /// The segment's length in octets.
        len: usize,
        /// The longest segment the profile carries.
        max: usize,
    },
    /// [`decode_asdu`] or [`encode_asdu`] was asked for a type whose element
    /// length is not a constant: `F_SG_NA_1` `<125>`, whose figure 88 prints
    /// `Octet 1 … Octet n` and whose length is carried by its own `LOS`. That
    /// type is read and written through [`decode_segment`] /
    /// [`encode_segment`].
    VariableElementLength {
        /// The type identification concerned.
        type_id: TypeId,
    },
}

impl From<AsduError> for LayoutError {
    fn from(err: AsduError) -> Self {
        Self::Asdu(err)
    }
}

/// The fixed element length of a layout, or [`LayoutError::VariableElementLength`]
/// for the one type whose element carries its own length.
///
/// [`decode_asdu`] and [`encode_asdu`] are the *constant-geometry* path: they
/// hand the body cursor one number for every object of the ASDU. `F_SG_NA_1`
/// `<125>` has no such number (figure 88 prints `Octet 1 … Octet n`) and is read
/// through [`decode_segment`] instead, so a generic decode of it is refused
/// rather than guessed. No [`AsduLayout`] implementor names `<125>`, so the arm
/// is a guard rather than a path in use.
const fn fixed_element_len(layout: &Layout) -> Result<usize, LayoutError> {
    if layout.variable {
        return Err(LayoutError::VariableElementLength {
            type_id: layout.type_id,
        });
    }
    Ok(layout.element_len)
}

/// Checks the two addressing rules of clause 7.3 against a header: SQ = 1
/// only where a `j(...)` form exists (and **required** for the one type whose
/// figure defines nothing else, [`Sequence::Required`]), and at most one
/// object where the figure says so. Shared by the reader and the writer so the
/// two cannot disagree.
fn check_layout(layout: &Layout, header: &Header) -> Result<(), LayoutError> {
    match layout.sequence {
        Sequence::NotDefined if header.sequence => {
            return Err(LayoutError::SequenceNotAllowed {
                type_id: layout.type_id,
            });
        }
        Sequence::Required if !header.sequence => {
            return Err(LayoutError::SequenceRequired {
                type_id: layout.type_id,
            });
        }
        _ => {}
    }
    if layout.count == ObjectCount::Single && header.count > 1 {
        return Err(LayoutError::ObjectCountNotAllowed {
            type_id: layout.type_id,
            count: header.count,
        });
    }
    Ok(())
}

/// Reads a complete ASDU (header and object area), decoding every object with
/// `A`'s own layout.
///
/// The addresses come from [`BodyReader`], so SQ = 0 and SQ = 1 are handled
/// exactly as clause 7.2.2.1 defines them; the element octets come from
/// `A::parse`. Both clause 7.3 addressing rules are enforced first, and the
/// object area must be consumed exactly.
///
/// The read path does *not* enforce the 249-octet ASDU limit of 5-104 clause 5:
/// [`encode_asdu`] refuses to produce more than that (as `encode_body` does),
/// but a caller handing in a raw slice gets whatever length they hand in,
/// which is also `BodyReader`'s behaviour. On a real link the APCI length field
/// bounds it before an ASDU is reached.
///
/// # Errors
///
/// As [`decode_asdu_with`].
pub fn decode_asdu<A: AsduLayout>(asdu: &[u8]) -> Result<Vec<LayoutObject<A>>, LayoutError> {
    decode_asdu_with::<A>(asdu, AddressSizes::CONVENTIONAL)
}

/// The same read path with the address sizes `sizes` fixes: the profile's
/// header width locates the object area and its IOA width addresses every
/// object (5-101 cl.7.2.4–7.2.5; 104 cl.9.5, index 98).
///
/// [`decode_asdu`] is this function with [`AddressSizes::CONVENTIONAL`], so the
/// conventional profile's decode is byte-identical; a 1-octet-CA profile's
/// header is one octet shorter, which is exactly why the object area starts at
/// [`AddressSizes::header_len`] and not at [`Header::LEN`].
///
/// # Errors
///
/// [`LayoutError::Asdu`] for a header, object area or element that does not
/// parse, [`LayoutError::TypeMismatch`] for an ASDU of another type,
/// [`LayoutError::NoLayout`] or [`LayoutError::VariableElementLength`] for a
/// type this path cannot read, and the addressing rule errors of clause 7.3.
pub fn decode_asdu_with<A: AsduLayout>(
    asdu: &[u8],
    sizes: AddressSizes,
) -> Result<Vec<LayoutObject<A>>, LayoutError> {
    let header = Header::parse_with(asdu, sizes)?;
    if header.type_id != A::TYPE_ID {
        return Err(LayoutError::TypeMismatch {
            expected: A::TYPE_ID,
            got: header.type_id,
        });
    }
    let layout = layout_for(A::TYPE_ID).ok_or(LayoutError::NoLayout {
        type_id: A::TYPE_ID,
    })?;
    check_layout(layout, &header)?;
    let element_len = fixed_element_len(layout)?;

    // `parse_with` read the whole header, so the slice is in range.
    let area = asdu.get(sizes.header_len()..).unwrap_or_default();
    let mut cursor = BodyReader::with_sizes(header, area, sizes);
    let mut objects = Vec::with_capacity(usize::from(header.count));
    while let Some(object) = cursor.next_object(element_len)? {
        objects.push(LayoutObject {
            ioa: object.ioa,
            value: A::parse(object.element)?,
        });
    }
    cursor.finish()?;
    Ok(objects)
}

/// Writes a complete ASDU (header and object area) from typed objects.
///
/// `header` supplies the type identification, SQ, count, cause and addresses;
/// the objects supply the IOAs and the elements. The two must agree, and the
/// same clause 7.3 addressing rules apply as on the read path, and `N = 0` is
/// refused for a single-object type.
///
/// # Errors
///
/// As [`encode_asdu_with`].
pub fn encode_asdu<A: AsduLayout>(
    header: &Header,
    objects: &[LayoutObject<A>],
) -> Result<Vec<u8>, LayoutError> {
    encode_asdu_with(header, objects, AddressSizes::CONVENTIONAL)
}

/// The same write path with the address sizes `sizes` fixes, the counterpart
/// of [`decode_asdu_with`].
///
/// # Errors
///
/// [`LayoutError::TypeMismatch`] if `header` names another type,
/// [`LayoutError::NoLayout`] or [`LayoutError::VariableElementLength`] for a
/// type this path cannot write, the addressing rule errors of clause 7.3, and
/// [`LayoutError::Asdu`] for a header or object area the codec refuses.
pub fn encode_asdu_with<A: AsduLayout>(
    header: &Header,
    objects: &[LayoutObject<A>],
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    if header.type_id != A::TYPE_ID {
        return Err(LayoutError::TypeMismatch {
            expected: A::TYPE_ID,
            got: header.type_id,
        });
    }
    let layout = layout_for(A::TYPE_ID).ok_or(LayoutError::NoLayout {
        type_id: A::TYPE_ID,
    })?;
    check_layout(layout, header)?;
    if layout.count == ObjectCount::Single && header.count == 0 {
        // The figure's single object is the frame's content; the reader
        // tolerates N = 0 (cl.7.2.2's "no information object"), the writer
        // does not produce one.
        return Err(LayoutError::ObjectCountNotAllowed {
            type_id: layout.type_id,
            count: 0,
        });
    }
    let element_len = fixed_element_len(layout)?;

    // Each object's element octets, in the layout's own order, then the same
    // `(IOA, element)` pairs the body writer already takes.
    let mut elements: Vec<Vec<u8>> = Vec::with_capacity(objects.len());
    for object in objects {
        let mut element = Vec::with_capacity(element_len);
        object.value.encode(&mut element);
        elements.push(element);
    }
    let body_objects: Vec<Object<'_>> = objects
        .iter()
        .zip(&elements)
        .map(|(object, element)| Object {
            ioa: object.ioa,
            element: element.as_slice(),
        })
        .collect();
    let body = encode_body_with(header, &body_objects, sizes)?;

    let mut out = Vec::with_capacity(sizes.header_len().saturating_add(body.len()));
    header.encode_with(&mut out, sizes)?;
    out.extend_from_slice(&body);
    Ok(out)
}
