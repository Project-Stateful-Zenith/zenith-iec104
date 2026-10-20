//! The file-transfer ASDUs: the seven of 5-101 clause **7.3.6** (types 120–126,
//! figures 83–89) plus 5-104 clause **8.9**'s `F_SC_NB_1` `<127>` (figure 31).
//!
//! Clause 7.3.6 sits at PDF page indices **114–120** (printed pages 113–119) and
//! is headed *"ASDUs for file transfer"*. 104's Table 6 (index 52, printed page
//! 51) is the family's own selection table and prints the range
//! `UI8[1..8]<120..127>` with the eighth row 101 does not define:
//!
//! | § | Type | Figure | Index | Definition line | Element octets |
//! | --- | --- | --- | --- | --- | --- |
//! | 7.3.6.1 | `<120>` `F_FR_NA_1` | 83 | 114 | `F_FR_NA_1 := CP{Data unit identifier,Information object address,Name of file, Length of file, FRQ}` | `NOF` 2 + `LOF` 3 + `FRQ` 1 = 6 |
//! | 7.3.6.2 | `<121>` `F_SR_NA_1` | 84 | 115 | `F_SR_NA_1 := CP{Data unit identifier,Information object address,Name of file, Name of section,Length of section,SRQ}` | `NOF` 2 + `NOS` 1 + `LOF` 3 + `SRQ` 1 = 7 |
//! | 7.3.6.3 | `<122>` `F_SC_NA_1` | 85 | 116 | `F_SC_NA_1 := CP{Data unit identifier,Information object address,Name of file, Name of section,SCQ}` | `NOF` 2 + `NOS` 1 + `SCQ` 1 = 4 |
//! | 7.3.6.4 | `<123>` `F_LS_NA_1` | 86 | 117 | `F_LS_NA_1 := CP{Data unit identifier,Information object address,Name of file,Name of section,LSQ,Checksum}` | `NOF` 2 + `NOS` 1 + `LSQ` 1 + `CHS` 1 = 5 |
//! | 7.3.6.5 | `<124>` `F_AF_NA_1` | 87 | 118 | `F_AF_NA_1 := CP{Data unit identifier,Information object address,Name of file,Name of section, AFQ}` | `NOF` 2 + `NOS` 1 + `AFQ` 1 = 4 |
//! | 7.3.6.6 | `<125>` `F_SG_NA_1` | 88 | 119 | `F_SG_NA_1 := CP{Data unit identifier,Information object address,Name of file,Name of section,Length of segment,Segment}` | `NOF` 2 + `NOS` 1 + `LOS` 1 + **n** |
//! | 7.3.6.7 | `<126>` `F_DR_TA_1` | 89 | 120 | `F_DR_TA_1 := CP{Data unit identifier,Information object address,j(Name of file,Length of file,Status of file,CP56Time2a)}` | `j` × 13 |
//! | 8.9 (104) | `<127>` `F_SC_NB_1` | 31 | 92 | figure 31's rows: `Name of file` (7.2.6.33), `RangeStartTime` `CP56Time2a` (7.2.6.18), `RangeStopTime` `CP56Time2a` (7.2.6.18) | `NOF` 2 + 7 + 7 = 16 |
//!
//! **`F_SR_NA_1`'s element is 7 octets, not 5.** 7.3.6.2's element list is
//! *"Name of file, Name of section, Length of section, SRQ"* and figure 84's own
//! field rows print *"Name of section — Defined in 7.2.6.34"* (`NOS`, one octet)
//! beside *"Length of section — Defined in **7.2.6.35**"*. 7.2.6.35 is `LOF`,
//! *"Length of file or section"*, `UI24[1..24]<0..16777215>`, **three** octets,
//! which is also what `F_FR_NA_1`'s figure 83 names for "Length of file". So a
//! section-ready element is `2 + 1 + 3 + 1 = 7` octets: `LOS` (7.2.6.36) is the
//! *segment* length and belongs to `<125>` alone.
//!
//! **Every type but `<126>` is `SQ = 0` with exactly one object.** Each of
//! 7.3.6.1 to 7.3.6.6 prints *"Single information object (SQ = 0)"* in its
//! heading and names no "Number i of objects" field; those rows, and `<127>`'s,
//! are [`Sequence::NotDefined`] / [`ObjectCount::Single`].
//! Two types need more than a constant-length row:
//!
//! * **`<125>` `F_SG_NA_1` carries a variable-length element.** Figure 88 prints
//!   `UI8 LOS = Length of segment, defined in 7.2.6.36` followed by two rows
//!   *"Octet 1"* and *"Octet n"* under the heading `Segment`. The element
//!   therefore carries its own length: 4 fixed octets (`NOF` + `NOS` + `LOS`)
//!   plus `LOS` segment octets. No constant states it, so the row has
//!   [`Layout::variable`] `= true` and the type is read and written through
//!   [`Segment`] and [`decode_segment`] rather than through the generic
//!   `decode_asdu`/`encode_asdu` path. That keeps a wrong number out of
//!   [`Layout::element_len`], where a caller would trust it.
//! * **`<126>` `F_DR_TA_1` is the family's only sequence form.** Its heading is
//!   *"Sequence of information elements in a single information object
//!   (SQ = 1)"*, its definition line's `j` is the number of element sets,
//!   given by the variable structure qualifier, and figure 89 prints `File 1` …
//!   `File j`, each of `Name of file or subdirectory` (`NOF`, 2) + `Length of
//!   file` (`LOF`, 3) + `SOF = Status of file` (7.2.6.38, 1) + `CP56Time2a`
//!   (7.2.6.18, 7) = **13 octets**, with file *i* belonging to information object
//!   address `A + i − 1`. Its row is [`Sequence::Required`] / `Multiple` with a
//!   13-octet element. Figure 89 defines no `SQ = 0` form, so an ASDU of `<126>`
//!   with `SQ = 0` is a typed refusal rather than a read that keeps the first
//!   file and loses the rest. The body cursor's base-address arithmetic yields
//!   the `A + i − 1` addresses.
//!
//! **The 249-octet ceiling is 5-104's and not clause 7.3.6's.** 104 index 26
//! (printed page 25): an ASDU is at most 249 octets, since the APDU length
//! field is at most 253 (`APDUmax` = 255 less the start and length octets) and
//! the control field takes 4. The header is 6 octets and the object area's address another 3, so
//! one `<125>` object's segment can carry at most
//! **236** octets (`249 − 6 − 3 − NOF 2 − NOS 1 − LOS 1`) and one `<126>` ASDU at
//! most **18** files (`249 = 6 + 3 + 13 j` gives `j ≤ 18.46`). `src/ft.rs`
//! refuses past both numbers and its tests pin them; this module states them in
//! [`MAX_SEGMENT`] and [`MAX_DIRECTORY_FILES`], from which `src/ft.rs` defines
//! its own limits, so the two layers cannot disagree.
//!
//! **The causes are the figures'.** Six of the eight print
//! `<13> := file transfer` plus figure 76's four `<44>`–`<47>`;
//! `F_SC_NA_1` prints `<5> := request (only for Call Directory)` beside `<13> :=
//! file transfer (all except for Call Directory)` (index 116);
//! `F_DR_TA_1` prints `<3> := spontaneous <5> := requested` and **no `<13>`**
//! (index 120); and 104's `<127>` prints `<13> := file transfer` with
//! `<44> := unknown type **of file**` (index 92), the *file* class of 104
//! clause 8.9 and **not** clause 7.2.3's type-identification class. The causes
//! are enforced in `src/ft.rs`, where the exchange lives; this module is
//! geometry only.
//!
//! Sources: IEC 60870-5-101:2003 clause 7.3.6 (PDF page indices 114–120) and
//! clause 7.2.6.28–7.2.6.38 for the element widths (indices 56–58), IEC
//! 60870-5-104:2006 clause 8.9 (index 92), Table 6 (index 52) and clause 5's
//! 249-octet limit (index 26).

use super::super::elements::{
    Afq, Chs, Cp56Time2a, Frq, Lof, Los, Lsq, Nof, Nos, Scq, Sof, Srq, split_off, take,
};
use super::super::{
    AddressSizes, AsduError, BodyReader, Header, LayoutError, LayoutObject, TypeId,
};
use super::{AsduLayout, Layout, ObjectCount, Sequence};

/// Every file-transfer layout of 5-101 clause 7.3.6 and 5-104 clause 8.9, in
/// type order.
///
/// Seven of the eight rows carry a constant `element_len`, the sum of the
/// clause 7.2.6 `LEN` constants its figure names. The remaining row,
/// `F_SG_NA_1`, is [`Layout::variable`] because figure 88 prints
/// `Octet 1 … Octet n`. `F_DR_TA_1` is the only row with a sequence form.
pub const FILE_LAYOUTS: &[Layout] = &[
    // 7.3.6.1: file ready, figure 83 (index 114).
    layout(
        TypeId::FFrNa1,
        Nof::LEN + Lof::LEN + Frq::LEN,
        NotDefined,
        Single,
    ),
    // 7.3.6.2: section ready, figure 84 (index 115). "Length of section" is
    // `LOF` (7.2.6.35, three octets), not `LOS`.
    layout(
        TypeId::FSrNa1,
        Nof::LEN + Nos::LEN + Lof::LEN + Srq::LEN,
        NotDefined,
        Single,
    ),
    // 7.3.6.3: call directory, select file, call file, call section, figure 85
    // (index 116).
    layout(
        TypeId::FScNa1,
        Nof::LEN + Nos::LEN + Scq::LEN,
        NotDefined,
        Single,
    ),
    // 7.3.6.4: last section, last segment, figure 86 (index 117).
    layout(
        TypeId::FLsNa1,
        Nof::LEN + Nos::LEN + Lsq::LEN + Chs::LEN,
        NotDefined,
        Single,
    ),
    // 7.3.6.5: ACK file, ACK section, figure 87 (index 118).
    layout(
        TypeId::FAfNa1,
        Nof::LEN + Nos::LEN + Afq::LEN,
        NotDefined,
        Single,
    ),
    // 7.3.6.6: segment, figure 88 (index 119): "Octet 1 … Octet n".
    variable_layout(TypeId::FSgNa1, NotDefined, Single),
    // 7.3.6.7: directory, figure 89 (index 120), `j` elements of 13 octets.
    // The family's only `SQ = 1`, and since figure 89 defines nothing else, its
    // only form at all (`Sequence::Required`).
    layout(
        TypeId::FDrTa1,
        Nof::LEN + Lof::LEN + Sof::LEN + Cp56Time2a::LEN,
        Required,
        Multiple,
    ),
    // 5-104 clause 8.9: QueryLog, figure 31 (index 92).
    layout(
        TypeId::FScNb1,
        Nof::LEN + Cp56Time2a::LEN + Cp56Time2a::LEN,
        NotDefined,
        Single,
    ),
];

/// The largest segment `F_SG_NA_1` may carry: 249 ASDU octets less the 6-octet
/// header, the 3-octet information object address, `NOF` (2), `NOS` (1) and
/// `LOS` (1). The 249 is 5-104 index 26 (printed page 25).
pub const MAX_SEGMENT: usize = 249 - Header::LEN - 3 - Nof::LEN - Nos::LEN - Los::LEN;

/// [`MAX_SEGMENT`] for the address sizes `sizes`: a narrower header and object
/// address leave room for a longer segment in the same 249-octet ASDU.
#[must_use]
pub fn max_segment_with(sizes: AddressSizes) -> usize {
    // At most 6 + 3 + 4 octets come off 249, so this never saturates.
    crate::apci::MAX_ASDU
        .saturating_sub(sizes.header_len())
        .saturating_sub(usize::from(sizes.information_object_address_octets()))
        .saturating_sub(Segment::PREFIX_LEN)
}

/// The largest number of files one `F_DR_TA_1` ASDU may carry: `249 = 6 + 3 +
/// 13 j` leaves `j ≤ 18`, so a 19th file is what the ceiling forbids (5-104
/// index 26).
pub const MAX_DIRECTORY_FILES: usize =
    (249 - Header::LEN - 3) / (Nof::LEN + Lof::LEN + Sof::LEN + Cp56Time2a::LEN);

use ObjectCount::{Multiple, Single};
use Sequence::{NotDefined, Required};

// The two constructors live in `super`; this module only names the rows.
use super::{layout, variable_layout};

/// `F_FR_NA_1`: File ready, 5-101 clause 7.3.6.1, figure 83 (PDF page index
/// 114).
///
/// ```text
/// F_FR_NA_1 := CP{Data unit identifier,Information object address,Name of file, Length of file, FRQ}
/// ```
///
/// *"Single information object (SQ = 0)"*, so one object. The element is the
/// file's name (`NOF`), its length (`LOF`, three octets) and the file-ready
/// qualifier (`FRQ`, whose bit 8 is the positive/negative confirm of *select*).
/// Cause `<13> := file transfer`, plus the four `<44>`–`<47>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FFrNa1 {
    /// Name of file (`NOF`, 7.2.6.33).
    pub nof: Nof,
    /// Length of file in octets (`LOF`, 7.2.6.35).
    pub lof: Lof,
    /// File ready qualifier (`FRQ`, 7.2.6.28).
    pub frq: Frq,
}

impl AsduLayout for FFrNa1 {
    const TYPE_ID: TypeId = TypeId::FFrNa1;
    const LEN: usize = Nof::LEN + Lof::LEN + Frq::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nof: Nof::parse(split_off(&mut element, Nof::LEN)?)?,
            lof: Lof::parse(split_off(&mut element, Lof::LEN)?)?,
            frq: Frq::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nof.encode(out);
        self.lof.encode(out);
        self.frq.encode(out);
    }
}

/// `F_SR_NA_1`: Section ready, 5-101 clause 7.3.6.2, figure 84 (index 115).
///
/// ```text
/// F_SR_NA_1 := CP{Data unit identifier,Information object address,Name of file, Name of section,Length of section,SRQ}
/// ```
///
/// *"Single information object (SQ = 0)"*. Figure 84's field rows name *"Name of
/// section — Defined in 7.2.6.34"* (`NOS`) and *"Length of section — Defined in
/// 7.2.6.35"* (`LOF`, three octets), so the element is seven octets. Cause
/// `<13> := file transfer`, plus the four `<44>`–`<47>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FSrNa1 {
    /// Name of file (`NOF`, 7.2.6.33).
    pub nof: Nof,
    /// Name of section (`NOS`, 7.2.6.34).
    pub nos: Nos,
    /// Length of file or section in octets (`LOF`, 7.2.6.35).
    pub lof: Lof,
    /// Section ready qualifier (`SRQ`, 7.2.6.29).
    pub srq: Srq,
}

impl AsduLayout for FSrNa1 {
    const TYPE_ID: TypeId = TypeId::FSrNa1;
    const LEN: usize = Nof::LEN + Nos::LEN + Lof::LEN + Srq::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nof: Nof::parse(split_off(&mut element, Nof::LEN)?)?,
            nos: Nos::parse(split_off(&mut element, Nos::LEN)?)?,
            lof: Lof::parse(split_off(&mut element, Lof::LEN)?)?,
            srq: Srq::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nof.encode(out);
        self.nos.encode(out);
        self.lof.encode(out);
        self.srq.encode(out);
    }
}

/// `F_SC_NA_1`: Call directory, select file, call file, call section, 5-101
/// clause 7.3.6.3, figure 85 (index 116).
///
/// ```text
/// F_SC_NA_1 := CP{Data unit identifier,Information object address,Name of file, Name of section,SCQ}
/// ```
///
/// *"Single information object (SQ = 0)"*. One type carries **five** different
/// requests through `SCQ`'s action field (`<0>` default = call directory, `<1>`
/// select file, `<2>` request file, `<3>` deactivate file, `<4>` delete file,
/// `<5>` select section, `<6>` request section, `<7>` deactivate section). Its
/// cause list is the family's only split one, as index 116 prints it:
/// `<5> := request (only for Call Directory)` and `<13> := file transfer (all
/// except for Call Directory)`, plus the four `<44>`–`<47>`. `src/ft.rs` enforces
/// that split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FScNa1 {
    /// Name of file (`NOF`, 7.2.6.33).
    pub nof: Nof,
    /// Name of section (`NOS`, 7.2.6.34).
    pub nos: Nos,
    /// Select and call qualifier (`SCQ`, 7.2.6.30).
    pub scq: Scq,
}

impl AsduLayout for FScNa1 {
    const TYPE_ID: TypeId = TypeId::FScNa1;
    const LEN: usize = Nof::LEN + Nos::LEN + Scq::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nof: Nof::parse(split_off(&mut element, Nof::LEN)?)?,
            nos: Nos::parse(split_off(&mut element, Nos::LEN)?)?,
            scq: Scq::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nof.encode(out);
        self.nos.encode(out);
        self.scq.encode(out);
    }
}

/// `F_LS_NA_1`: Last section, last segment, 5-101 clause 7.3.6.4, figure 86
/// (index 117).
///
/// ```text
/// F_LS_NA_1 := CP{Data unit identifier,Information object address,Name of file,Name of section,LSQ,Checksum}
/// ```
///
/// *"Single information object (SQ = 0)"*. `LSQ`'s values `<1>`/`<2>` say a
/// *file* transfer ends with or without deactivation and `<3>`/`<4>` a *section*
/// transfer; `CHS` is clause 7.2.6.37's sum modulo 256 over every octet of a
/// section or of the whole file, whose computation and check are `src/ft.rs`'s. Cause `<13> := file transfer`,
/// plus the four `<44>`–`<47>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FLsNa1 {
    /// Name of file (`NOF`, 7.2.6.33).
    pub nof: Nof,
    /// Name of section (`NOS`, 7.2.6.34).
    pub nos: Nos,
    /// Last section or segment qualifier (`LSQ`, 7.2.6.31).
    pub lsq: Lsq,
    /// Checksum over the section or file (`CHS`, 7.2.6.37).
    pub chs: Chs,
}

impl AsduLayout for FLsNa1 {
    const TYPE_ID: TypeId = TypeId::FLsNa1;
    const LEN: usize = Nof::LEN + Nos::LEN + Lsq::LEN + Chs::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nof: Nof::parse(split_off(&mut element, Nof::LEN)?)?,
            nos: Nos::parse(split_off(&mut element, Nos::LEN)?)?,
            lsq: Lsq::parse(split_off(&mut element, Lsq::LEN)?)?,
            chs: Chs::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nof.encode(out);
        self.nos.encode(out);
        self.lsq.encode(out);
        self.chs.encode(out);
    }
}

/// `F_AF_NA_1`: ACK file, ACK section, 5-101 clause 7.3.6.5, figure 87
/// (index 118).
///
/// ```text
/// F_AF_NA_1 := CP{Data unit identifier,Information object address,Name of file,Name of section, AFQ}
/// ```
///
/// *"Single information object (SQ = 0)"*. `AFQ`'s acknowledgement field is
/// `<1>`/`<2>` for a file and `<3>`/`<4>` for a section, positive/negative, with
/// `SCQ`'s error code in bits 5–8. Cause `<13> := file transfer`, plus the four
/// `<44>`–`<47>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FAfNa1 {
    /// Name of file (`NOF`, 7.2.6.33).
    pub nof: Nof,
    /// Name of section (`NOS`, 7.2.6.34).
    pub nos: Nos,
    /// ACK file or section qualifier (`AFQ`, 7.2.6.32).
    pub afq: Afq,
}

impl AsduLayout for FAfNa1 {
    const TYPE_ID: TypeId = TypeId::FAfNa1;
    const LEN: usize = Nof::LEN + Nos::LEN + Afq::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nof: Nof::parse(split_off(&mut element, Nof::LEN)?)?,
            nos: Nos::parse(split_off(&mut element, Nos::LEN)?)?,
            afq: Afq::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nof.encode(out);
        self.nos.encode(out);
        self.afq.encode(out);
    }
}

/// `F_DR_TA_1`: Directory, 5-101 clause 7.3.6.7, figure 89 (index 120).
///
/// ```text
/// F_DR_TA_1 := CP{Data unit identifier,Information object address,j(Name of file,Length of file,Status of file,CP56Time2a)}
/// ```
///
/// *"Sequence of information elements in a single information object (SQ = 1)"*:
/// the family's only sequence form. Figure 89 prints file 1 … file *j*, each
/// `Name of file or subdirectory` (`NOF` 2) + `Length of file` (`LOF` 3) +
/// `SOF` (1) + `CP56Time2a` (7) = **13** octets, with file *i* belonging to
/// information object address `A + i − 1`; the body cursor's SQ = 1 arithmetic
/// yields exactly those addresses. Cause `<3> := spontaneous <5> := requested`
/// and **no `<13>`** (index 120), the only file-transfer figure without
/// `<13>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FDrTa1 {
    /// Name of file or subdirectory (`NOF`, 7.2.6.33).
    pub nof: Nof,
    /// Length of file in octets (`LOF`, 7.2.6.35).
    pub lof: Lof,
    /// Status of file (`SOF`, 7.2.6.38).
    pub sof: Sof,
    /// Creation time of the file (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for FDrTa1 {
    const TYPE_ID: TypeId = TypeId::FDrTa1;
    const LEN: usize = Nof::LEN + Lof::LEN + Sof::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nof: Nof::parse(split_off(&mut element, Nof::LEN)?)?,
            lof: Lof::parse(split_off(&mut element, Lof::LEN)?)?,
            sof: Sof::parse(split_off(&mut element, Sof::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nof.encode(out);
        self.lof.encode(out);
        self.sof.encode(out);
        self.time.encode(out);
    }
}

/// `F_SC_NB_1`: `QueryLog` / Request archive file, 5-104 clause 8.9, figure 31
/// (index 92).
///
/// `UI8[1..8]<127>` is the type 101 leaves inside its `<120..127>` range but
/// never defines, which is why Table 6's eighth row is 104's. Figure 31's three
/// information-object rows are *"Name of file — Defined in 7.2.6.33 of IEC
/// 60870-5-101"* (`NOF`, 2), `CP56Time2a` *"(`RangeStartTime`)"* (7) and
/// `CP56Time2a` *"(`RangeStopTime`)"* (7), sixteen octets in all. Its cause list is
/// `<13> := file transfer` with `<44> := unknown type **of file**`: the file
/// class of clause 8.9, not clause 7.2.3's type-identification class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FScNb1 {
    /// Name of file (`NOF`, 7.2.6.33 of 5-101).
    pub nof: Nof,
    /// Start of the requested range (`RangeStartTime`, a `CP56Time2a`), zero
    /// for "from the beginning" (cl.8.9).
    pub range_start: Cp56Time2a,
    /// End of the requested range (`RangeStopTime`, a `CP56Time2a`), zero for
    /// "to the end" (cl.8.9).
    pub range_stop: Cp56Time2a,
}

impl AsduLayout for FScNb1 {
    const TYPE_ID: TypeId = TypeId::FScNb1;
    const LEN: usize = Nof::LEN + Cp56Time2a::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nof: Nof::parse(split_off(&mut element, Nof::LEN)?)?,
            range_start: Cp56Time2a::parse(split_off(&mut element, Cp56Time2a::LEN)?)?,
            range_stop: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nof.encode(out);
        self.range_start.encode(out);
        self.range_stop.encode(out);
    }
}

/// The `<125>` element: `NOF`, `NOS`, `LOS` and the segment's own octets (the
/// figure 88 `Segment` row that reads *"Octet 1 … Octet n"*).
///
/// This is the one file-transfer element whose length is **not** a constant of
/// clause 7.2.6: `LOS` (7.2.6.36, one octet) states the number of segment octets
/// that follow it, so the whole element is `4 + LOS` octets and a caller must
/// read `LOS` first. The `F_SG_NA_1` row therefore has [`Layout::variable`] set
/// and an `element_len` of 0, and the type has no [`AsduLayout`] `LEN`: this
/// struct plus [`decode_segment`] / [`encode_segment`] are its entry point.
///
/// `LOS`'s own clause bounds it between 234 and 240 octets, depending on how
/// long the link field, data unit identifier and information object addresses
/// are (7.2.6.36, index 58), i.e. up to `249 − 6 − 3` = 240 octets of
/// segment when nothing else is in the element, which is the element layer's
/// `Los::MAX`. [`MAX_SEGMENT`] is the same budget with the element's own
/// `NOF`/`NOS`/`LOS` octets also taken off: 236.
///
/// **A segment whose stated `LOS` disagrees with the octets actually present is
/// a typed error, not a short read** ([`Segment::stated_len`] versus
/// [`Segment::payload`]). The octets can only be counted once the element's end
/// is known, so the check is `src/ft.rs`'s
/// [`FtError::SegmentLengthMismatch`](crate::ft::FtError::SegmentLengthMismatch)
/// rather than this parser's, which rejects only an element too short to hold
/// the three fields (`AsduError::TooShort`, never a panic). `LOS` = 0
/// (7.2.6.36's *"<0> := not used"*) is read as the empty payload it is and
/// refused by `src/ft.rs` ([`FtError::EmptySegment`](crate::ft::FtError::EmptySegment)),
/// while [`Segment::encode`] refuses to write one at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Name of file (`NOF`, 7.2.6.33).
    pub nof: Nof,
    /// Name of section (`NOS`, 7.2.6.34).
    pub nos: Nos,
    /// The number of octets of the segment (`LOS`, 7.2.6.36).
    pub los: Los,
    /// The segment's octets, `Octet 1 … Octet n`: the caller's payload, which
    /// this crate never sources from a file (there is no file management here).
    pub payload: Vec<u8>,
}

impl Segment {
    /// Octets of the element's fixed part, before `Octet 1`: `NOF` + `NOS` +
    /// `LOS`.
    pub const PREFIX_LEN: usize = Nof::LEN + Nos::LEN + Los::LEN;

    /// The segment's octets as the figure numbers them: `Octet 1` is the
    /// first octet of [`Segment::payload`].
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The length `LOS` *states*, as opposed to the octets actually present.
    #[must_use]
    pub fn stated_len(&self) -> usize {
        usize::from(self.los.value)
    }

    /// This element as it appears on the wire: the three fixed fields then the
    /// payload, `4 + payload.len()` octets.
    ///
    /// Fallible for the same two reasons [`Segment::encode`] is: a payload of
    /// zero octets and a payload past [`MAX_SEGMENT`].
    ///
    /// # Errors
    ///
    /// As [`Segment::encode`].
    pub fn element(&self) -> Result<Vec<u8>, LayoutError> {
        self.element_with(AddressSizes::CONVENTIONAL)
    }

    /// [`Segment::element`] with the segment limit of the address sizes
    /// `sizes` ([`max_segment_with`]).
    ///
    /// # Errors
    ///
    /// As [`Segment::encode_with`].
    pub fn element_with(&self, sizes: AddressSizes) -> Result<Vec<u8>, LayoutError> {
        let mut out = Vec::with_capacity(Self::PREFIX_LEN.saturating_add(self.payload.len()));
        self.encode_with(&mut out, sizes)?;
        Ok(out)
    }

    /// Reads one `<125>` element from `element`, whose length is what the caller
    /// could hand over: the three fixed fields are required, everything after
    /// them is the segment. A prefix shorter than 4 octets is
    /// [`AsduError::TooShort`].
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] for an element shorter than
    /// [`Segment::PREFIX_LEN`].
    pub fn parse(element: &[u8]) -> Result<Self, AsduError> {
        take(element, Self::PREFIX_LEN)?;
        let mut rest = element;
        Ok(Self {
            nof: Nof::parse(split_off(&mut rest, Nof::LEN)?)?,
            nos: Nos::parse(split_off(&mut rest, Nos::LEN)?)?,
            los: Los::parse(split_off(&mut rest, Los::LEN)?)?,
            payload: rest.to_vec(),
        })
    }

    /// Appends the element: `NOF`, `NOS`, `LOS`, then the payload. `LOS` is
    /// written as the payload's own length, so a caller cannot state a length
    /// other than the octets it hands over.
    ///
    /// Fallible, because `LOS` is one octet and the clause's two ends do not
    /// both fit it: a payload of **zero** octets is
    /// [`LayoutError::EmptySegment`] (7.2.6.36's `<0> := not used`, index 58)
    /// and one longer than [`MAX_SEGMENT`] is [`LayoutError::SegmentTooLong`].
    /// Writing a clamped `LOS` would put an element on the wire whose stated
    /// length contradicts its own octets.
    ///
    /// # Errors
    ///
    /// [`LayoutError::EmptySegment`] or [`LayoutError::SegmentTooLong`] as
    /// above, in which case nothing is appended.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), LayoutError> {
        self.encode_with(out, AddressSizes::CONVENTIONAL)
    }

    /// [`Segment::encode`] with the segment limit of the address sizes
    /// `sizes` ([`max_segment_with`]) instead of [`MAX_SEGMENT`].
    ///
    /// # Errors
    ///
    /// As [`Segment::encode`], against [`max_segment_with`].
    pub fn encode_with(&self, out: &mut Vec<u8>, sizes: AddressSizes) -> Result<(), LayoutError> {
        let max = max_segment_with(sizes);
        if self.payload.is_empty() {
            return Err(LayoutError::EmptySegment {
                type_id: TypeId::FSgNa1,
            });
        }
        // `max` is at most 240, so a length within it fits `LOS`'s one octet.
        let len = self.payload.len();
        let value = u8::try_from(len)
            .ok()
            .filter(|_| len <= max)
            .ok_or(LayoutError::SegmentTooLong { len, max })?;
        self.nof.encode(out);
        self.nos.encode(out);
        Los { value }.encode(out);
        out.extend_from_slice(&self.payload);
        Ok(())
    }
}

/// Reads one complete `<125>` `F_SG_NA_1` ASDU: header, the object's address,
/// and the variable element of [`Segment`].
///
/// The generic [`decode_asdu`](super::decode_asdu) path cannot read this type,
/// because its element length is not a constant, so this is the one
/// file-transfer type with its own entry point. The element length is the
/// object area less the 3-octet address (the ASDU carries exactly one object),
/// every short prefix is a typed error, and the object area must be consumed
/// exactly, as the body cursor's rules require. `N = 0` is
/// [`LayoutError::ObjectCountNotAllowed`]: a segment ASDU with no object has
/// nothing to read.
///
/// One `<125>` object never carries more than [`MAX_SEGMENT`] segment octets:
/// beyond it the ASDU could not fit in a 249-octet APDU, so a longer object is
/// a [`LayoutError::Asdu`] carrying [`AsduError::BodyTooLong`]. The check is the same
/// 249-octet rule the writer applies, not a second ceiling.
///
/// A zero-length segment (`LOS` = 0, *"not used"*, 7.2.6.36) **is** read here
/// as the empty payload it is: this is the geometry layer, and what is on the
/// wire is what it reads. The rule that a segment has octets is 5-101 clause
/// 7.2.6.36's and lives in `src/ft.rs`, which refuses it on both the read and
/// the write path ([`FtError::EmptySegment`](crate::ft::FtError::EmptySegment));
/// the writer here refuses to *produce* one as well, because no producer has
/// one to send.
///
/// # Errors
///
/// As [`decode_segment_with`].
pub fn decode_segment(asdu: &[u8]) -> Result<LayoutObject<Segment>, LayoutError> {
    decode_segment_with(asdu, AddressSizes::CONVENTIONAL)
}

/// The same read path with the address sizes `sizes` fixes.
///
/// The header is [`AddressSizes::header_len`] octets and the object's address
/// [`AddressSizes::information_object_address_octets`] octets (5-101
/// cl.7.2.4–7.2.5; 104 cl.9.5, index 98), and the element length is the object
/// area the profile's header leaves minus that address. The 249-octet ASDU
/// limit of 5-104 cl.5 is checked against the profile's own budget
/// ([`max_segment_with`]), not against the conventional one.
///
/// # Errors
///
/// [`LayoutError::TypeMismatch`] for an ASDU of another type,
/// [`LayoutError::SequenceNotAllowed`] or
/// [`LayoutError::ObjectCountNotAllowed`] for SQ = 1 or a count other than
/// one, and [`LayoutError::Asdu`] for a header or object area that does not
/// parse or exceeds the profile's budget.
pub fn decode_segment_with(
    asdu: &[u8],
    sizes: AddressSizes,
) -> Result<LayoutObject<Segment>, LayoutError> {
    let header = Header::parse_with(asdu, sizes)?;
    if header.type_id != TypeId::FSgNa1 {
        return Err(LayoutError::TypeMismatch {
            expected: TypeId::FSgNa1,
            got: header.type_id,
        });
    }
    let layout = super::layout_for(TypeId::FSgNa1).ok_or(LayoutError::NoLayout {
        type_id: TypeId::FSgNa1,
    })?;
    check_single(layout, &header)?;
    if header.count == 0 {
        // A segment with no object carries nothing to read.
        return Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FSgNa1,
            count: 0,
        });
    }

    let ioa_octets = usize::from(sizes.information_object_address_octets());
    // `parse_with` read the whole header, so the slice is in range.
    let area = asdu.get(sizes.header_len()..).unwrap_or_default();
    let need = ioa_octets.saturating_add(Segment::PREFIX_LEN);
    if area.len() < need {
        return Err(AsduError::TruncatedElement {
            index: 0,
            need,
            have: area.len(),
        }
        .into());
    }
    // Both subtractions are covered by the length check above.
    let element_len = area.len().saturating_sub(ioa_octets);
    let max_segment = max_segment_with(sizes);
    if element_len.saturating_sub(Segment::PREFIX_LEN) > max_segment {
        // Both numbers are object areas, the variant's unit and the one the
        // writer reports: the frame's area against the profile's own budget
        // (`AddressSizes::max_body`, 5-104 cl.5's 249 minus the profile's
        // header): `ioa_octets + PREFIX_LEN + max_segment` == `max_body()`.
        // Adding the header length again would report the whole ASDU, 249, as
        // the area budget.
        return Err(AsduError::BodyTooLong {
            len: area.len(),
            max: need.saturating_add(max_segment),
        }
        .into());
    }

    let mut cursor = BodyReader::with_sizes(header, area, sizes);
    let object = cursor
        .next_object(element_len)?
        .ok_or(LayoutError::NoLayout {
            type_id: TypeId::FSgNa1,
        })?;
    cursor.finish()?;
    Ok(LayoutObject {
        ioa: object.ioa,
        value: Segment::parse(object.element)?,
    })
}

/// Writes one complete `<125>` `F_SG_NA_1` ASDU from `header` and one
/// [`Segment`], the write side of [`decode_segment`].
///
/// `header` must name `F_SG_NA_1`, must not carry SQ = 1 and must carry
/// exactly one object ([`LayoutError::ObjectCountNotAllowed`] otherwise). An
/// empty segment is [`LayoutError::EmptySegment`] and one longer than
/// [`MAX_SEGMENT`] is [`LayoutError::SegmentTooLong`], from [`Segment::encode`];
/// `src/ft.rs`'s builder refuses the same two segments against the same limit.
///
/// # Errors
///
/// As [`encode_segment_with`].
pub fn encode_segment(
    header: &Header,
    ioa: u32,
    segment: &Segment,
) -> Result<Vec<u8>, LayoutError> {
    encode_segment_with(header, ioa, segment, AddressSizes::CONVENTIONAL)
}

/// The same write path with the address sizes `sizes` fixes, the counterpart
/// of [`decode_segment_with`].
///
/// # Errors
///
/// [`LayoutError::TypeMismatch`] if `header` names another type,
/// [`LayoutError::SequenceNotAllowed`] or
/// [`LayoutError::ObjectCountNotAllowed`] for SQ = 1 or a count other than
/// one, the segment errors of [`Segment::encode_with`], and
/// [`LayoutError::Asdu`] for a header or body the codec refuses.
pub fn encode_segment_with(
    header: &Header,
    ioa: u32,
    segment: &Segment,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    if header.type_id != TypeId::FSgNa1 {
        return Err(LayoutError::TypeMismatch {
            expected: TypeId::FSgNa1,
            got: header.type_id,
        });
    }
    let layout = super::layout_for(TypeId::FSgNa1).ok_or(LayoutError::NoLayout {
        type_id: TypeId::FSgNa1,
    })?;
    check_single(layout, header)?;
    if header.count != 1 {
        return Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FSgNa1,
            count: header.count,
        });
    }

    let element = segment.element_with(sizes)?;
    let body = crate::asdu::encode_body_with(
        header,
        &[crate::asdu::Object {
            ioa,
            element: &element,
        }],
        sizes,
    )?;
    let mut out = Vec::with_capacity(sizes.header_len().saturating_add(body.len()));
    header.encode_with(&mut out, sizes)?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// The two addressing rules for `<125>`, shared by [`decode_segment`] and
/// [`encode_segment`]: `SQ = 0` and at most one object. Each caller then
/// handles `N = 0` itself.
const fn check_single(layout: &Layout, header: &Header) -> Result<(), LayoutError> {
    if header.sequence {
        return Err(LayoutError::SequenceNotAllowed {
            type_id: layout.type_id,
        });
    }
    if header.count > 1 {
        return Err(LayoutError::ObjectCountNotAllowed {
            type_id: layout.type_id,
            count: header.count,
        });
    }
    Ok(())
}
