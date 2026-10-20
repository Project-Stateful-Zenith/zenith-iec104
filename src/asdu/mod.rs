//! ASDU (Application Service Data Unit): the IEC 60870-5-101 payload carried
//! inside I-format APDUs.
//!
//! Header layout with the **conventional address sizes** (2-octet COT
//! *including* the originator address, 2-octet common address, 3-octet IOA;
//! the profile marked on 104's own interoperability sheet, 5-104 cl.9.5,
//! index 98):
//!
//! ```text
//! 0        type identification (TypeId)
//! 1        VSQ: bit 7 = SQ, bits 6..0 = number of information objects
//! 2        COT: bits 5..0 = cause, bit 6 = P/N, bit 7 = T (test)
//! 3        originator address (ORG)
//! 4..5     common address of ASDU (CA), little-endian
//! 6..8     information object address (IOA) of first object, little-endian,
//!          followed by that object's information elements; for SQ = 1 the
//!          remaining objects share the first IOA as a base address
//! ```
//!
//! Those widths are a system parameter, not fixed by a clause: 5-101
//! cl.7.2.4 (index 42) and cl.7.2.5 (index 43) call the CA's and the IOA's
//! length a parameter fixed for the whole system, and 104 cl.9.5 (index 98)
//! lists the cause of transmission (*"One octet"* / *"Two octets (with
//! originator address)"*, an unused originator address being zero), the
//! common address (*"One octet"* / *"Two octets"*) and the information object
//! address as system-specific parameters. [`AddressSizes`] carries the three
//! choices; the conventional profile is its default and is what the plain
//! names (`Header::parse`, `Header::encode`, ...) use, while the `_with`
//! variants take the profile as an argument. Two values on that page **are**
//! fixed and not configurable here: the 253-octet APDU length and the
//! application-data transmission mode (this companion standard uses only
//! mode 1, least significant octet first, of IEC 60870-5-4 clause 4.10).
//!
//! Sources:
//!
//! - IEC 60870-5-101:2003 clause 7.2.1 / tables 8–13 (type identifications),
//!   clause 7.2.2 / figure 12 (variable structure qualifier), clause 7.2.3 /
//!   table 14 (cause of transmission), clause 7.2.4 (common address),
//!   clause 7.2.5 (information object address).
//! - IEC 60870-5-104:2006 clause 6 / tables 1–6: the *selection* of those
//!   types that is valid in 104, plus the types 104 itself adds (58–64, 107,
//!   127); clause 9.5 (index 98) for the address sizes.
//!
//! The module is layered:
//!
//! - the type-identification catalogue (`types`, re-exported here);
//! - the object area behind the header, walked by [`BodyReader`] and written by
//!   [`encode_body`], which own the SQ = 0/1 addressing of 5-101 clause 7.2.2.1
//!   and the exact-remaining-octets check;
//! - the 40 information elements of 5-101 clause 7.2.6, in [`elements`], each a
//!   type with its own `LEN`/`parse`/`encode`;
//! - the per-type geometry of 5-101 clause 7.3 (which elements a type carries,
//!   in what order), in [`layout`]: the 32 monitor-direction types of clause
//!   7.3.1, the 27 control-direction, system and parameter types (19 of
//!   clauses 7.3.2–7.3.5 and the eight time-tagged forms of 5-104 clause 8),
//!   and the eight file-transfer types of 5-101 clause 7.3.6 plus 5-104 clause
//!   8.9.
//!   `element_len(TypeId)` gives the element length the body cursor takes, and
//!   `decode_asdu`/`encode_asdu` go from header to typed values.
//!   `F_SG_NA_1` `<125>` is the one type whose element length is not a
//!   constant (figure 88's `Octet 1 … Octet n`): it goes through
//!   [`layout::decode_segment`] / [`layout::encode_segment`], and
//!   `element_len(TypeId::FSgNa1)` answers `None` rather than a number that
//!   would be wrong for every segment but one;
//! - a whole ASDU at once: [`decode`] and [`decode_with`] give an [`Asdu`]
//!   whose [`Objects`] hold every object typed, and [`Objects::points`] gives
//!   the monitored values of the process information types as [`Point`]s, one
//!   shape whatever the type. [`Cp56Time2a::from_unix`],
//!   [`Cp56Time2a::from_system_time`], [`Cp56Time2a::to_unix`] and
//!   [`Cp56Time2a::to_system_time`] convert time tags to and from the system's
//!   time.
//!
//! # Example
//!
//! A three-object `M_ME_NB_1` ASDU (scaled value + quality, 3 octets per
//! element), decoding each object's address and element octets:
//!
//! ```
//! use iec104::asdu::{BodyReader, Cause, Header, TypeId, IOA_IRRELEVANT};
//!
//! // Header: M_ME_NB_1, SQ = 0, 3 objects, spontaneous, CA 12.
//! // Body: three objects of `IOA(3) + element(3)`.
//! let asdu = [
//!     0x0B, 0x03, 0x03, 0x00, 0x0C, 0x00,
//!     0x10, 0x30, 0x00, 0x00, 0x01, 0x00,
//!     0x11, 0x30, 0x00, 0x00, 0x02, 0x00,
//!     0x12, 0x30, 0x00, 0x00, 0x03, 0x00,
//! ];
//!
//! let header = Header::parse(&asdu).unwrap();
//! assert_eq!(header.type_id, TypeId::MMeNb1);
//! assert_eq!(header.cause, Cause::Spontaneous);
//! assert_eq!(header.count, 3);
//!
//! let mut body = BodyReader::from_asdu(&asdu).unwrap();
//! let mut ioas = Vec::new();
//! while let Some(object) = body.next_object(3).unwrap() {
//!     ioas.push(object.ioa);
//! }
//! body.finish().unwrap();
//! assert_eq!(ioas, [0x3010, 0x3011, 0x3012]);
//!
//! // An IOA that is not used by the type is written as zero (5-101 cl.7.2.5).
//! assert_eq!(IOA_IRRELEVANT, 0);
//! ```

mod body;
mod decoded;
pub mod elements;
pub mod layout;
mod types;
mod unknown;

pub use body::{
    BodyReader, IOA_IRRELEVANT, MAX_BODY, MAX_IOA, Object, encode_body, encode_body_with,
};
pub use decoded::{Asdu, Objects, Point, Quality, TimeTag, Validity, Value, decode, decode_with};
pub use elements::{
    Afq, Bcr, Bsi, Chs, Coi, CommandQualifier, Cp16Time2a, Cp24Time2a, Cp56Time2a, Dco, Diq,
    DoubleCommandState, DoublePointState, EventState, Fbp, FreezeMode, Frq, Lof, Los, Lsq, Nof,
    Nos, Nva, Oci, Qcc, Qdp, Qds, Qoc, Qoi, Qos, Qpa, Qpm, Qrp, R32, Rco, RegulatingStepState, Scd,
    Sco, Scq, Sep, Siq, Sof, Spe, Srq, Sva, TimeField, TimeRangeError, Tsc, Vti,
};
pub use layout::max_segment_with;
pub use layout::{
    AsduLayout, CBoNa1, CBoTa1, CCdNa1, CCiNa1, CCsNa1, CDcNa1, CDcTa1, CIcNa1, CONTROL_LAYOUTS,
    CRcNa1, CRcTa1, CRdNa1, CRpNa1, CScNa1, CScTa1, CSeNa1, CSeNb1, CSeNc1, CSeTa1, CSeTb1, CSeTc1,
    CTsNa1, CTsTa1, FAfNa1, FDrTa1, FFrNa1, FILE_LAYOUTS, FLsNa1, FScNa1, FScNb1, FSrNa1, Layout,
    LayoutError, LayoutObject, MAX_DIRECTORY_FILES, MAX_SEGMENT, MBoNa1, MBoTa1, MBoTb1, MDpNa1,
    MDpTa1, MDpTb1, MEiNa1, MEpTa1, MEpTb1, MEpTc1, MEpTd1, MEpTe1, MEpTf1, MItNa1, MItTa1, MItTb1,
    MMeNa1, MMeNb1, MMeNc1, MMeNd1, MMeTa1, MMeTb1, MMeTc1, MMeTd1, MMeTe1, MMeTf1,
    MONITOR_LAYOUTS, MPsNa1, MSpNa1, MSpTa1, MSpTb1, MStNa1, MStTa1, MStTb1, ObjectCount, PAcNa1,
    PMeNa1, PMeNb1, PMeNc1, Segment, Sequence, decode_asdu, decode_asdu_with, decode_segment,
    decode_segment_with, element_len, encode_asdu, encode_asdu_with, encode_segment,
    encode_segment_with, layout_for,
};
pub use types::{CATALOGUE, Direction, TypeId, TypeInfo, TypeRange, lookup, range_of};
pub use unknown::{
    Discard, Known, Unspecified, cause_is_defined, classify, discard_reason, is_mirror,
    mirror_frame, mirror_header, mirror_reply, mirror_reply_with, type_is_defined,
};

/// Cause of transmission (5-101 table 14).
///
/// The cause is a 6-bit field (`UI6`); `1..=47` are the standard's values and
/// `48..=63` are the private range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// 0: not used.
    NotUsed,
    /// 1 periodic, cyclic.
    Periodic,
    /// 2 background scan.
    BackgroundScan,
    /// 3 spontaneous.
    Spontaneous,
    /// 4 initialized.
    Initialized,
    /// 5 request or requested.
    Request,
    /// 6 activation.
    Activation,
    /// 7 activation confirmation.
    ActivationCon,
    /// 8 deactivation.
    Deactivation,
    /// 9 deactivation confirmation.
    DeactivationCon,
    /// 10 activation termination.
    ActivationTermination,
    /// 11 return information caused by a remote command.
    ReturnInfoRemote,
    /// 12 return information caused by a local command.
    ReturnInfoLocal,
    /// 13 file transfer.
    FileTransfer,
    /// 20 interrogated by station interrogation.
    InterrogatedByStation,
    /// 21–36 interrogated by group 1–16 interrogation (1..=16).
    InterrogatedByGroup(u8),
    /// 37 requested by general counter request.
    RequestedByGeneralCounter,
    /// 38–41 requested by counter group 1–4 request (1..=4).
    RequestedByCounterGroup(u8),
    /// 44 unknown type identification.
    UnknownTypeId,
    /// 45 unknown cause of transmission.
    UnknownCause,
    /// 46 unknown common address of ASDU.
    UnknownCommonAddress,
    /// 47 unknown information object address.
    UnknownInformationObjectAddress,
    /// 14–19, 42–43: reserved for further compatible definitions.
    Reserved(u8),
    /// 48–63: private range.
    Private(u8),
}

impl Cause {
    /// Decodes the 6-bit cause value.
    #[must_use]
    pub const fn from_u8(raw: u8) -> Self {
        let raw = raw & 0x3F;
        match raw {
            0 => Self::NotUsed,
            1 => Self::Periodic,
            2 => Self::BackgroundScan,
            3 => Self::Spontaneous,
            4 => Self::Initialized,
            5 => Self::Request,
            6 => Self::Activation,
            7 => Self::ActivationCon,
            8 => Self::Deactivation,
            9 => Self::DeactivationCon,
            10 => Self::ActivationTermination,
            11 => Self::ReturnInfoRemote,
            12 => Self::ReturnInfoLocal,
            13 => Self::FileTransfer,
            20 => Self::InterrogatedByStation,
            21..=36 => Self::InterrogatedByGroup(raw.wrapping_sub(20)),
            37 => Self::RequestedByGeneralCounter,
            38..=41 => Self::RequestedByCounterGroup(raw.wrapping_sub(37)),
            44 => Self::UnknownTypeId,
            45 => Self::UnknownCause,
            46 => Self::UnknownCommonAddress,
            47 => Self::UnknownInformationObjectAddress,
            48..=63 => Self::Private(raw),
            reserved => Self::Reserved(reserved),
        }
    }

    /// The 6-bit cause value.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::NotUsed => 0,
            Self::Periodic => 1,
            Self::BackgroundScan => 2,
            Self::Spontaneous => 3,
            Self::Initialized => 4,
            Self::Request => 5,
            Self::Activation => 6,
            Self::ActivationCon => 7,
            Self::Deactivation => 8,
            Self::DeactivationCon => 9,
            Self::ActivationTermination => 10,
            Self::ReturnInfoRemote => 11,
            Self::ReturnInfoLocal => 12,
            Self::FileTransfer => 13,
            Self::InterrogatedByStation => 20,
            Self::InterrogatedByGroup(n) => n.clamp(1, 16).wrapping_add(20),
            Self::RequestedByGeneralCounter => 37,
            Self::RequestedByCounterGroup(n) => n.clamp(1, 4).wrapping_add(37),
            Self::UnknownTypeId => 44,
            Self::UnknownCause => 45,
            Self::UnknownCommonAddress => 46,
            Self::UnknownInformationObjectAddress => 47,
            Self::Reserved(raw) | Self::Private(raw) => raw,
        }
    }

    /// The standard's mnemonic (`spont`, `inrogen`, `inro3`, …), or an empty
    /// string for values the standard does not name: table 14's last column.
    ///
    /// A group number outside its family's range is named as [`Cause::to_u8`]
    /// writes it (clamped), so the name always matches the number on the wire.
    #[must_use]
    pub fn mnemonic(self) -> &'static str {
        const INRO: [&str; 16] = [
            "inro1", "inro2", "inro3", "inro4", "inro5", "inro6", "inro7", "inro8", "inro9",
            "inro10", "inro11", "inro12", "inro13", "inro14", "inro15", "inro16",
        ];
        const REQCO: [&str; 4] = ["reqco1", "reqco2", "reqco3", "reqco4"];
        match self {
            Self::Periodic => "per/cyc",
            Self::BackgroundScan => "back",
            Self::Spontaneous => "spont",
            Self::Initialized => "init",
            Self::Request => "req",
            Self::Activation => "act",
            Self::ActivationCon => "actcon",
            Self::Deactivation => "deact",
            Self::DeactivationCon => "deactcon",
            Self::ActivationTermination => "actterm",
            Self::ReturnInfoRemote => "retrem",
            Self::ReturnInfoLocal => "retloc",
            Self::FileTransfer => "file",
            Self::InterrogatedByStation => "inrogen",
            Self::InterrogatedByGroup(n) => INRO
                .get(usize::from(n.clamp(1, 16).wrapping_sub(1)))
                .copied()
                .unwrap_or_default(),
            Self::RequestedByGeneralCounter => "reqcogen",
            Self::RequestedByCounterGroup(n) => REQCO
                .get(usize::from(n.clamp(1, 4).wrapping_sub(1)))
                .copied()
                .unwrap_or_default(),
            _ => "",
        }
    }
}

/// Decoded ASDU header (everything before the information objects).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Type identification.
    pub type_id: TypeId,
    /// SQ: 0 = one IOA per object, 1 = sequence (IOA of the first object only).
    pub sequence: bool,
    /// Number of information objects in this ASDU (UI7, 0..=127).
    pub count: u8,
    /// Cause of transmission.
    pub cause: Cause,
    /// P/N: negative confirm flag.
    pub negative: bool,
    /// T: test flag.
    pub test: bool,
    /// Originator address (ORG).
    pub originator: u8,
    /// Common address of ASDU (CA).
    pub common_address: u16,
}

impl Header {
    /// Octets of the header with the **conventional** address sizes: type id
    /// (1), VSQ (1), COT (1) + originator (1), CA (2).
    ///
    /// A constant of the conventional profile only; the width under another
    /// profile is [`AddressSizes::header_len`].
    pub const LEN: usize = 6;

    /// Parses the header of an ASDU with the conventional address sizes.
    ///
    /// Thin wrapper over [`Header::parse_with`] with
    /// [`AddressSizes::CONVENTIONAL`].
    ///
    /// # Errors
    ///
    /// As [`Header::parse_with`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Self::parse_with(buf, AddressSizes::CONVENTIONAL)
    }

    /// Parses the header of an ASDU with the address sizes `sizes` fixes.
    ///
    /// The header is type id (1) + VSQ (1) + COT (1), then the originator octet
    /// **only if the profile carries one**, then the common address in
    /// `sizes.common_address_octets` octets little-endian (5-101 cl.7.2.3
    /// index 37/38, cl.7.2.4 index 42; 104 cl.9.5 index 98). A profile without
    /// the originator octet reports [`Header::originator`] as `0` (104 cl.9.5:
    /// an unused originator address is zero).
    ///
    /// Reads exactly [`AddressSizes::header_len`] octets: a shorter buffer is
    /// [`AsduError::TooShort`]. The parser never reads past the configured
    /// header to find a wider address.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than the header.
    pub fn parse_with(buf: &[u8], sizes: AddressSizes) -> Result<Self, AsduError> {
        let len = sizes.header_len();
        let too_short = AsduError::TooShort {
            need: len,
            have: buf.len(),
        };
        let Some(&[type_id, vsq, cot, ref rest @ ..]) = buf.get(..len) else {
            return Err(too_short);
        };
        let (originator, common_address) = match (sizes.originator_address(), rest) {
            (true, &[originator, ref ca @ ..]) => (originator, ca),
            (false, ca) => (0, ca),
            (true, []) => return Err(too_short),
        };
        // The profile makes the common address one or two octets.
        let common_address = match *common_address {
            [lo] => u16::from(lo),
            [lo, hi] => u16::from_le_bytes([lo, hi]),
            _ => return Err(too_short),
        };
        Ok(Self {
            type_id: TypeId::from_u8(type_id),
            sequence: vsq & 0x80 != 0,
            count: vsq & 0x7F,
            cause: Cause::from_u8(cot & 0x3F),
            negative: cot & 0x40 != 0,
            test: cot & 0x80 != 0,
            originator,
            common_address,
        })
    }

    /// Appends the conventional 6-octet header to `out`.
    ///
    /// Thin wrapper over [`Header::encode_with`] with
    /// [`AddressSizes::CONVENTIONAL`]; on an error nothing is appended.
    ///
    /// # Errors
    ///
    /// As [`Header::encode_with`]: a count above 127, a cause with no 6-bit
    /// code of its own, or (never, with two octets) a common address out of
    /// range.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), AsduError> {
        self.encode_with(out, AddressSizes::CONVENTIONAL)
    }

    /// Appends the header to `out` with the address sizes `sizes` fixes.
    ///
    /// Refuses a common address the profile's `common_address_octets` cannot
    /// carry (5-101 cl.7.2.4, figures 17–18: `UI8[1..8]<0..255>` with one
    /// octet, `UI16[1..16]<0..65535>` with two) as
    /// [`AsduError::CommonAddressOutOfRange`] rather than truncating it to a
    /// different station address. An originator octet is written only when the
    /// profile carries one (104 cl.9.5).
    ///
    /// Also refuses what the header octets cannot carry rather than masking it
    /// into a different, valid header: a `count` above 127 (cl.7.2.2, `UI7`)
    /// and a [`Cause`] that does not decode back to itself (a `Reserved` or
    /// `Private` value of a named cause, a value above 63, or a group number
    /// outside 1–16 / 1–4).
    ///
    /// # Errors
    ///
    /// [`AsduError::CountOutOfRange`], [`AsduError::CauseNotEncodable`] or
    /// [`AsduError::CommonAddressOutOfRange`] for a header the octets cannot
    /// carry, in which case nothing is appended.
    pub fn encode_with(&self, out: &mut Vec<u8>, sizes: AddressSizes) -> Result<(), AsduError> {
        if self.count > 0x7F {
            return Err(AsduError::CountOutOfRange { count: self.count });
        }
        if Cause::from_u8(self.cause.to_u8() & 0x3F) != self.cause {
            return Err(AsduError::CauseNotEncodable { cause: self.cause });
        }
        let max = sizes.max_common_address();
        if self.common_address > max {
            return Err(AsduError::CommonAddressOutOfRange {
                common_address: self.common_address,
                max,
            });
        }
        out.push(self.type_id.to_u8());
        out.push((if self.sequence { 0x80 } else { 0 }) | (self.count & 0x7F));
        out.push(
            (self.cause.to_u8() & 0x3F)
                | if self.negative { 0x40 } else { 0 }
                | if self.test { 0x80 } else { 0 },
        );
        if sizes.originator_address() {
            out.push(self.originator);
        }
        let [lo, hi] = self.common_address.to_le_bytes();
        out.push(lo);
        if sizes.common_address_octets() != 1 {
            out.push(hi);
        }
        Ok(())
    }
}

/// `asdu` with its header's originator address and test bit replaced by the
/// request's, for a response that must echo them (5-101 cl.7.2.3). The
/// originator stays as it is when the profile carries no originator octet.
pub(crate) fn with_origin(
    asdu: &[u8],
    originator: u8,
    test: bool,
    sizes: AddressSizes,
) -> Result<Vec<u8>, AsduError> {
    let header = Header::parse_with(asdu, sizes)?;
    let originator = if sizes.originator_address() {
        originator
    } else {
        header.originator
    };
    if header.originator == originator && header.test == test {
        return Ok(asdu.to_vec());
    }
    let mut out = Vec::with_capacity(asdu.len());
    Header {
        test,
        originator,
        ..header
    }
    .encode_with(&mut out, sizes)?;
    // `parse_with` above read the whole header, so the slice is in range.
    out.extend_from_slice(asdu.get(sizes.header_len()..).unwrap_or_default());
    Ok(out)
}

/// The ASDU address sizes of one system, which the standard leaves to the
/// project as a fixed system parameter.
///
/// 5-101 cl.7.2.3 (index 38) defines the originator address as `UI8[9..16]`
/// inside the cause field, and figure 14 labels it *"Originator address
/// optional per system"*; cl.7.2.4 (index 42) and cl.7.2.5 (index 43) make the
/// common address's and the information object address's length a parameter
/// fixed for the whole system. 104 cl.9.5 (index 98) lists all of them as
/// system-specific parameters: cause *"One octet"* / *"Two octets (with
/// originator address)"*, common address *"One octet"* / *"Two octets"*,
/// information object address *"One octet"* / *"Structured"* + *"Two octets"*
/// / *"Unstructured"* + *"Three octets"* (the two words are the sheet's names
/// for those forms; this type models the three widths). The APDU length (at
/// most 253 in either direction, a fixed system parameter) and the transmission mode are fixed on that page and
/// are **not** configurable here.
///
/// [`AddressSizes::CONVENTIONAL`] (originator present, CA two octets, IOA
/// three octets) is the profile marked on 104's own interoperability sheet
/// (index 98). It is [`Default`], and the plain `Header::parse` /
/// `Header::encode` / `read_ioa` / `write_ioa_checked` / `BodyReader::new` /
/// `encode_body` / `decode_asdu` / `decode_segment` names are its wrappers.
///
/// The fields are read through accessors and the only constructor of a
/// non-conventional profile is the checked [`AddressSizes::new`]: a width the
/// standard does not define is refused with [`AsduError::InvalidAddressSizes`]
/// instead of producing a header nothing can parse. Note that `<0>` means
/// *irrelevant* for the IOA (`INFORMATION OBJECT ADDRESS is irrelevant`, 5-101
/// cl.7.2.5 figure 19) but *not used* for the CA (`<0> := not used`, cl.7.2.4
/// figure 17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressSizes {
    /// Whether the cause of transmission carries the originator octet (104
    /// cl.9.5's *"Two octets (with originator address)"*; 5-101 cl.7.2.3
    /// figure 14's *"Originator address optional per system"*).
    originator_address: bool,
    /// Octets of the common address of ASDU: 1 or 2 (5-101 cl.7.2.4).
    common_address_octets: u8,
    /// Octets of the information object address: 1, 2 or 3 (5-101 cl.7.2.5).
    information_object_address_octets: u8,
}

impl AddressSizes {
    /// Originator present, CA two octets, IOA three octets: the profile marked
    /// on the 104 interoperability sheet (index 98).
    pub const CONVENTIONAL: Self = Self {
        originator_address: true,
        common_address_octets: 2,
        information_object_address_octets: 3,
    };

    /// Builds a profile from its three choices, refusing a width the standard
    /// does not define.
    ///
    /// `common_address_octets` is 1 or 2 (5-101 cl.7.2.4, figures 17–18);
    /// `information_object_address_octets` is 1, 2 or 3 (cl.7.2.5, figures
    /// 19–21; 104 cl.9.5's three options). Anything else is
    /// [`AsduError::InvalidAddressSizes`].
    ///
    /// # Errors
    ///
    /// [`AsduError::InvalidAddressSizes`] for a width outside those ranges.
    pub fn new(
        common_address_octets: u8,
        information_object_address_octets: u8,
        originator_address: bool,
    ) -> Result<Self, AsduError> {
        if !(1..=2).contains(&common_address_octets)
            || !(1..=3).contains(&information_object_address_octets)
        {
            return Err(AsduError::InvalidAddressSizes {
                common_address_octets,
                information_object_address_octets,
            });
        }
        Ok(Self {
            originator_address,
            common_address_octets,
            information_object_address_octets,
        })
    }

    /// Whether the cause of transmission carries the originator octet.
    #[must_use]
    pub const fn originator_address(&self) -> bool {
        self.originator_address
    }

    /// Octets of the common address of ASDU (1 or 2).
    #[must_use]
    pub const fn common_address_octets(&self) -> u8 {
        self.common_address_octets
    }

    /// Octets of the information object address (1, 2 or 3).
    #[must_use]
    pub const fn information_object_address_octets(&self) -> u8 {
        self.information_object_address_octets
    }

    /// Octets of one ASDU header under this profile: type id (1) + VSQ (1) +
    /// COT (1), the originator octet if the profile carries one, and the common
    /// address.
    ///
    /// `6` for [`AddressSizes::CONVENTIONAL`], which is why [`Header::LEN`]
    /// stays the conventional profile's own constant.
    #[must_use]
    pub fn header_len(&self) -> usize {
        3usize
            .wrapping_add(usize::from(self.originator_address))
            .wrapping_add(usize::from(self.common_address_octets))
    }

    /// The largest information object address this profile can carry:
    /// `255` (`UI8[1..8]`, 5-101 cl.7.2.5 figure 19), `65535` (`UI16[1..16]`,
    /// figure 20) or `16777215` (`UI24[1..24]`, figure 21).
    #[must_use]
    pub const fn max_ioa(&self) -> u32 {
        match self.information_object_address_octets {
            1 => 0x0000_00FF,
            2 => 0x0000_FFFF,
            _ => 0x00FF_FFFF,
        }
    }

    /// The largest common address this profile can carry: `255` (`UI8[1..8]`,
    /// 5-101 cl.7.2.4 figure 17) or `65535` (`UI16[1..16]`, figure 18).
    #[must_use]
    pub const fn max_common_address(&self) -> u16 {
        if self.common_address_octets == 1 {
            0x00FF
        } else {
            0xFFFF
        }
    }

    /// The broadcast common address of 5-101 cl.7.2.4 in this profile: `FF`
    /// with one octet, `FFFF` with two.
    #[must_use]
    pub const fn broadcast_common_address(&self) -> u16 {
        self.max_common_address()
    }

    /// Largest object area that fits under this profile's header in a 249-octet
    /// ASDU (5-104 cl.5, index 26: an ASDU is at most 249 octets).
    ///
    /// [`MAX_BODY`] is this number for [`AddressSizes::CONVENTIONAL`] only; the
    /// body budget is per profile, because a narrower header leaves more room.
    #[must_use]
    pub fn max_body(&self) -> usize {
        crate::apci::MAX_ASDU.saturating_sub(self.header_len())
    }
}

impl Default for AddressSizes {
    /// [`AddressSizes::CONVENTIONAL`].
    fn default() -> Self {
        Self::CONVENTIONAL
    }
}

/// The typed error for an information object address the profile's width cannot
/// carry.
///
/// A three-octet IOA reports [`AsduError::IoaOutOfRange`] (its bound is
/// `UI24`'s own); a narrower one reports [`AsduError::IoaOutOfRangeForWidth`],
/// which carries the configured bound so the error names the width.
pub(crate) const fn ioa_out_of_range(ioa: u32, max: u32) -> AsduError {
    if max == body::MAX_IOA {
        AsduError::IoaOutOfRange { ioa }
    } else {
        AsduError::IoaOutOfRangeForWidth { ioa, max }
    }
}

/// Errors from coding an ASDU header, address or object area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsduError {
    /// Fewer octets available than the field needs.
    TooShort {
        /// Octets the field needs.
        need: usize,
        /// Octets that were left.
        have: usize,
    },
    /// A header's object count above 127, which the 7-bit number field of
    /// cl.7.2.2 cannot carry.
    CountOutOfRange {
        /// The object count asked for.
        count: u8,
    },
    /// A cause of transmission the 6-bit field cannot carry as itself: it
    /// would go on the wire as, and decode to, a different cause.
    CauseNotEncodable {
        /// The cause asked for.
        cause: Cause,
    },
    /// The object area ran out inside the *object* numbered `index`: its
    /// configured address (`AddressSizes::information_object_address_octets`,
    /// one to three octets) or its information element needed `need` octets and
    /// only `have` were left (5-101 cl.7.2.2.1; the cursor never reads short).
    TruncatedElement {
        /// The object's position in the ASDU, from 0.
        index: u8,
        /// Octets the object's address or element needs.
        need: usize,
        /// Octets that were left.
        have: usize,
    },
    /// The header promises `count` objects but the object area still holds
    /// `remaining` octets no object can claim (5-101 cl.7.2.2.1: the count *is*
    /// the number of objects).
    ObjectsNotExhausted {
        /// The header's object count.
        count: u8,
        /// Octets left after the last counted object.
        remaining: usize,
    },
    /// A body was encoded for a header whose object count it does not match.
    ObjectCountMismatch {
        /// The header's object count.
        header: u8,
        /// The number of objects given.
        objects: usize,
    },
    /// The objects of one ASDU do not share one element length. Clause 7.2.2.1
    /// defines an ASDU as one or more **equal** INFORMATION OBJECTs (SQ = 0) or a
    /// sequence of **equal** COMBINATIONs (SQ = 1), and the element length is not
    /// on the wire, so a reader given a different length for a later object and
    /// a writer given unequal elements both report this.
    ElementLengthMismatch {
        /// The object's position in the ASDU, from 0.
        index: u8,
        /// The element length of the first object.
        expected: usize,
        /// This object's element length.
        got: usize,
    },
    /// An SQ = 1 sequence was encoded with an address that is not base + index
    /// (clause 7.2.2.1: only the base address goes on the wire).
    SequenceNotContiguous {
        /// The object's position in the sequence, from 0.
        index: u8,
        /// The base address plus `index`.
        expected: u32,
        /// The address given.
        got: u32,
    },
    /// An information object address outside `UI24[1..24]<0..16777215>`
    /// (5-101 cl.7.2.5, figure 21): the bound of every three-octet IOA,
    /// including the conventional profile's.
    IoaOutOfRange {
        /// The address given.
        ioa: u32,
    },
    /// An information object address outside the range the **configured**
    /// profile's `information_object_address_octets` fixes: `max` is `255`
    /// (`UI8[1..8]`, 5-101 cl.7.2.5 figure 19) or `65535` (`UI16[1..16]`,
    /// figure 20). A three-octet IOA reports [`AsduError::IoaOutOfRange`]
    /// instead, since its bound is `UI24`'s own.
    IoaOutOfRangeForWidth {
        /// The address given.
        ioa: u32,
        /// The largest address the configured width carries.
        max: u32,
    },
    /// A common address the profile's `common_address_octets` cannot carry
    /// (5-101 cl.7.2.4, figures 17–18): `max` is `255` with one octet and
    /// `65535` with two.
    CommonAddressOutOfRange {
        /// The common address given.
        common_address: u16,
        /// The largest common address the configured width carries.
        max: u16,
    },
    /// A requested [`AddressSizes`] the standard does not define: the common
    /// address is one or two octets and the information object address one, two
    /// or three (5-101 cl.7.2.4–7.2.5, figures 17–21; 104 cl.9.5, index 98).
    InvalidAddressSizes {
        /// The common address width asked for, in octets.
        common_address_octets: u8,
        /// The information object address width asked for, in octets.
        information_object_address_octets: u8,
    },
    /// The encoded object area would exceed the profile's own ASDU budget,
    /// `AddressSizes::max_body()`: 249 octets less the profile's header
    /// (5-104 clause 5: an ASDU is at most 249 octets),
    /// which is 243 under [`AddressSizes::CONVENTIONAL`].
    BodyTooLong {
        /// The object area's length in octets.
        len: usize,
        /// The profile's budget, `AddressSizes::max_body()`.
        max: usize,
    },
    /// An information element that the standard fixes to one value carried a
    /// different one: `FBP` is `UI16[1..16]<55AAH>` and nothing else (5-101
    /// clause 7.2.6.14), so a wrong pattern is not a value to hand on.
    FixedPatternMismatch {
        /// The value the standard fixes.
        expected: u16,
        /// The value carried.
        got: u16,
    },
}

/// Reads the 3-octet little-endian information object address of the
/// **conventional** profile.
///
/// Thin wrapper over [`read_ioa_with`] with [`AddressSizes::CONVENTIONAL`]; a
/// profile whose IOA is one or two octets reads it with the `_with` form.
///
/// # Errors
///
/// As [`read_ioa_with`].
pub fn read_ioa(buf: &[u8]) -> Result<u32, AsduError> {
    read_ioa_with(buf, AddressSizes::CONVENTIONAL)
}

/// Reads a little-endian information object address in the width the profile
/// fixes.
///
/// The width is `UI8[1..8]` (`<1..255>`, 5-101 cl.7.2.5 figure 19), `UI16[1..16]` (figure
/// 20) or `UI24[1..24]<0..16777215>` (figure 21), per
/// [`AddressSizes::information_object_address_octets`].
///
/// A buffer shorter than the configured width is [`AsduError::TooShort`] with
/// `need` the width: the field is read exactly as wide as the profile says,
/// never widened to the conventional three octets.
///
/// # Errors
///
/// [`AsduError::TooShort`] if `buf` is shorter than the configured width.
pub fn read_ioa_with(buf: &[u8], sizes: AddressSizes) -> Result<u32, AsduError> {
    let width = usize::from(sizes.information_object_address_octets());
    let field = buf.get(..width).ok_or(AsduError::TooShort {
        need: width,
        have: buf.len(),
    })?;
    let mut octets = [0u8; 4];
    for (octet, &read) in octets.iter_mut().zip(field) {
        *octet = read;
    }
    Ok(u32::from_le_bytes(octets))
}

/// Writes the 3-octet little-endian information object address field of the
/// conventional profile (5-101 cl.7.2.5, figure 21).
///
/// This is the raw field writer: the field is 24 bits wide, so an address above
/// [`MAX_IOA`] is truncated to its low three octets, which puts a *different*
/// address on the wire. Callers holding an address that did not come
/// from a parsed ASDU should use [`write_ioa_checked`]; [`encode_body`] checks
/// every object's address itself.
pub fn write_ioa(buf: &mut Vec<u8>, ioa: u32) {
    write_ioa_with(buf, ioa, AddressSizes::CONVENTIONAL);
}

/// Appends the profile's raw information object address field: the low
/// [`AddressSizes::information_object_address_octets`] octets of `ioa`,
/// little-endian.
///
/// Like [`write_ioa`] this truncates an address the field cannot hold (the raw
/// writer's contract); the checked form is [`write_ioa_checked_with`].
pub fn write_ioa_with(buf: &mut Vec<u8>, ioa: u32, sizes: AddressSizes) {
    let width = usize::from(sizes.information_object_address_octets());
    buf.extend(ioa.to_le_bytes().iter().take(width));
}

/// Writes the conventional 3-octet field, refusing an address outside `UI24[1..24]<0..16777215>`
/// (5-101 cl.7.2.5, figure 21) instead of truncating it.
///
/// Thin wrapper over [`write_ioa_checked_with`] with
/// [`AddressSizes::CONVENTIONAL`].
///
/// # Errors
///
/// As [`write_ioa_checked_with`].
pub fn write_ioa_checked(buf: &mut Vec<u8>, ioa: u32) -> Result<(), AsduError> {
    write_ioa_checked_with(buf, ioa, AddressSizes::CONVENTIONAL)
}

/// Writes the profile's address field, refusing an address outside
/// [`AddressSizes::max_ioa`] instead of truncating it.
///
/// A three-octet IOA reports [`AsduError::IoaOutOfRange`] (its bound is
/// `UI24`'s); a narrower one reports [`AsduError::IoaOutOfRangeForWidth`],
/// which carries the configured bound: `255` for a one-octet IOA (`UI8[1..8]`,
/// 5-101 cl.7.2.5 figure 19), `65535` for two (figure 20).
///
/// # Errors
///
/// [`AsduError::IoaOutOfRange`] or [`AsduError::IoaOutOfRangeForWidth`] for an
/// address above [`AddressSizes::max_ioa`], in which case nothing is written.
pub fn write_ioa_checked_with(
    buf: &mut Vec<u8>,
    ioa: u32,
    sizes: AddressSizes,
) -> Result<(), AsduError> {
    let max = sizes.max_ioa();
    if ioa > max {
        return Err(ioa_out_of_range(ioa, max));
    }
    write_ioa_with(buf, ioa, sizes);
    Ok(())
}
