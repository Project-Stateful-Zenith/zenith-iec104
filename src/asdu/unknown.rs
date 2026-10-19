//! Unknown ASDUs and the 44–47 replies: the two rules of IEC 60870-5-101:2003
//! clause **7.2.3** (PDF page index 42, printed page 41).
//!
//! The clause's first rule:
//!
//! > ASDUs in the control direction with undefined values in the data unit
//! > identifier (except the variable structure qualifier) and the information
//! > object address are mirrored by the controlled station with bit "P/N := <1>
//! > negative confirm" and the following causes of transmission:
//! >
//! > | Unknown | Cause of transmission |
//! > | --- | --- |
//! > | type identification | 44 |
//! > | cause of transmission | 45 |
//! > | common address of ASDU | 46 |
//! > | information object address | 47 |
//!
//! and its second, for the monitor direction:
//!
//! > A controlling station may monitor for and maintain a communications error
//! > log reporting each time that the following ASDUs are received:
//! > • ASDUs in the monitor direction with undefined values in the data unit
//! > identifier (except the variable structure qualifier);
//! > • ASDUs in the monitor direction with undefined values of information
//! > object address;
//! > • mirrored ASDUs due to unknown numbers in the control direction (type
//! > identifications 45 to 51).
//! >
//! > Receipt of one of these ASDUs does not affect the processing of subsequent
//! > messages.
//!
//! An ASDU whose type identification is itself undefined has no type to tell
//! its direction, so the station's role decides: 5-101 clause 7.3 (page index
//! 59, printed page 58) says that, if only the standardized range is defined,
//! type identification numbers above 127 "are discarded by controlling
//! stations (monitor direction) or mirrored with CAUSE OF TRANSMISSION = 44 by
//! controlled stations (control direction)". A controlling station also
//! discards, rather than mirrors, an ASDU whose cause is undefined *for its
//! type identification*: "ASDUs with undefined values of CAUSE OF TRANSMISSION
//! for a given type identification are discarded by controlling stations"
//! (clause 7.2.3, page index 38). This module therefore has one entry point
//! per direction ([`mirror_reply`] for the control direction,
//! [`discard_reason`] for the monitor direction) instead of one function that
//! would have to guess the direction of a type it does not know.
//!
//! # What "undefined" means here
//!
//! It is a property of the **receiving station**, not of the octet: clause
//! 7.3's own words are "if the standardized range only is defined", and a
//! station implements a subset of the standard. The crate cannot know a
//! project's profile, so [`Known`] carries the caller's four answers: which
//! type identifications it implements, which causes of transmission it accepts,
//! whether the common address is one of its own, and whether every information
//! object address in the ASDU is one it has data for. [`type_is_defined`] and
//! [`cause_is_defined`] are the *standard's* answers for the first two, and
//! [`Known::standard`] uses them; neither is a substitute for the caller's own
//! profile, because the private range 128–255 is defined "by agreement between
//! the system user and the vendor" (clause 7.3).
//!
//! # The decisions this module makes, and why
//!
//! * **Precedence.** The clause gives no order among the four fields. This
//!   crate reports them in the order the clause's table lists them (type
//!   identification, cause of transmission, common address of ASDU,
//!   information object address) and asserts that order in
//!   `tests/unknown.rs`. A station reporting 44 for an ASDU whose cause is also
//!   undefined is conformant either way; what matters is that the choice is not
//!   silent.
//! * **A mirrored ASDU is copied, never rebuilt.** "Mirrored" means the
//!   received ASDU comes back, so [`mirror_reply`] takes the received object
//!   area as octets and appends them unchanged: a payload this crate cannot
//!   decode (an undefined type identification) survives octet for octet, which
//!   is also the pass-through rule for [`TypeId::Other`]. A station that
//!   cannot decode the ASDU has nothing to re-encode from.
//! * **The VSQ is excluded, in terms.** "(except the variable structure
//!   qualifier)" leaves `SQ` and `N` out of the four classes: clause 7.2.2.1
//!   gives both a range, and a value out of range is a range violation, not an
//!   undefined field. No 48th cause is invented for it; the VSQ is checked by
//!   [`AsduError`](super::AsduError) and
//!   [`LayoutError::SequenceNotAllowed`](super::LayoutError::SequenceNotAllowed),
//!   and [`classify`] does not look at the field at all.
//! * **A mirror is never mirrored back.** A received ASDU with `P/N = 1` and one
//!   of the four causes *is* a peer's reply; the control-direction rule is about
//!   requests, so [`mirror_reply`] answers `None` for it and the monitor-side
//!   [`discard_reason`] reports it as [`Discard::Mirror`]. That is the
//!   clause's third log bullet, and it stops two stations from mirroring each
//!   other's mirrors forever. `P/N = 1` with a *defined* cause (7 `actcon`, 9
//!   `deactcon`, …) is an ordinary negative confirmation, so [`is_mirror`]
//!   requires both the flag and one of the four causes.
//! * **The error log is a value, not I/O.** [`discard_reason`] says *why* the
//!   ASDU is not to be processed, [`crate::diag::discard`] writes that verdict
//!   as a line, and the caller owns the sink.
//!
//! # Where the boundary with the layout layer runs
//!
//! [`layout_for`](super::layout_for) and [`element_len`](super::element_len)
//! answer "does this *crate* know the element geometry of this type
//! identification": the 67 named types of clauses 7.3.1–7.3.6 and 5-104
//! clause 8 are laid out, reserved and private-range types are not. This
//! module's question is "does the *station* implement this type
//! identification", which the caller answers in [`Known`]. The two sets
//! overlap without being equal: a station may implement a private-range type
//! this crate has no layout for, and a station is free not to implement types
//! this crate lays out. Nothing here consults `layout_for`.
//!
//! # Example
//!
//! A `C_SC_NA_1` (45) whose information object address the station does not have
//! data for, mirrored back as the clause requires:
//!
//! ```
//! use iec104::asdu::{
//!     classify, discard_reason, mirror_reply, Cause, Discard, Header, Known, TypeId, Unspecified,
//! };
//!
//! // C_SC_NA_1, SQ = 0, one object, activation, CA 12; body: IOA 0x3000, SCO.
//! let asdu = [
//!     0x2D, 0x01, 0x06, 0x00, 0x0C, 0x00,
//!     0x00, 0x30, 0x00, 0x01,
//! ];
//! let header = Header::parse(&asdu).unwrap();
//! assert_eq!(header.type_id, TypeId::CScNa1);
//!
//! // The station implements what the standard defines, and knows the type and
//! // the cause — but has no data for that information object address.
//! let known = Known::standard(&header, true, false);
//! assert_eq!(classify(&known), Some(Unspecified::InformationObjectAddress));
//!
//! let reply = mirror_reply(&header, &known, &asdu[Header::LEN..]).unwrap();
//! // The header is mirrored with P/N = 1 and cause 47, the body untouched.
//! assert_eq!(reply[2], Cause::UnknownInformationObjectAddress.to_u8() | 0x40);
//! assert_eq!(&reply[Header::LEN..], &asdu[Header::LEN..]);
//!
//! // In the monitor direction the same ASDU is discarded (and may be logged),
//! // and nothing about it is carried into the next message.
//! assert_eq!(
//!     discard_reason(&header, &known),
//!     Some(Discard::Unspecified(Unspecified::InformationObjectAddress))
//! );
//! ```

use super::{AddressSizes, Cause, Header, TypeId};
use crate::interop::InteropProfile;

/// A field of the data unit identifier, or the information object address, that
/// the receiving station does not know: clause 7.2.3's four classes, in the
/// order its table lists them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unspecified {
    /// The type identification is not one the station implements: cause 44
    /// `unknown type identification`.
    TypeIdentification,
    /// The cause of transmission is not one the station accepts for that type
    /// identification: cause 45 `unknown cause of transmission`.
    CauseOfTransmission,
    /// The common address of ASDU is not one of the station's own: cause 46
    /// `unknown common address of ASDU`.
    CommonAddress,
    /// An information object address in the ASDU is not one the station has
    /// data for: cause 47 `unknown information object address`.
    InformationObjectAddress,
}

impl Unspecified {
    /// All four classes in the clause's table order, which is the order
    /// [`classify`] reports them in.
    pub const ALL: [Self; 4] = [
        Self::TypeIdentification,
        Self::CauseOfTransmission,
        Self::CommonAddress,
        Self::InformationObjectAddress,
    ];

    /// The cause of transmission clause 7.2.3's table pairs with the class:
    /// 44, 45, 46 and 47.
    #[must_use]
    pub const fn cause(self) -> Cause {
        match self {
            Self::TypeIdentification => Cause::UnknownTypeId,
            Self::CauseOfTransmission => Cause::UnknownCause,
            Self::CommonAddress => Cause::UnknownCommonAddress,
            Self::InformationObjectAddress => Cause::UnknownInformationObjectAddress,
        }
    }

    /// The field's name as the clause writes it, for a log line.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::TypeIdentification => "type identification",
            Self::CauseOfTransmission => "cause of transmission",
            Self::CommonAddress => "common address of ASDU",
            Self::InformationObjectAddress => "information object address",
        }
    }
}

/// The receiving station's answers to the four questions clause 7.2.3's
/// mirroring decision turns on.
///
/// Every one of them is project data (which type identifications a station
/// implements, which causes of transmission it accepts for them, which common
/// addresses are its own, and which information object addresses it holds), so
/// the crate does not guess them: the caller answers, and this module owns the
/// precedence and the reply the answers imply. [`Known::standard`] answers the
/// first two from the standard's own tables, for a station that implements
/// exactly what those tables define.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Known {
    /// The station implements the ASDU's type identification.
    pub type_id: bool,
    /// The station accepts the ASDU's cause of transmission *for that type
    /// identification* (clause 7.2.3, page index 38).
    pub cause: bool,
    /// The ASDU's common address is one of the station's own.
    pub common_address: bool,
    /// **Every** information object address in the ASDU is one the station has
    /// data for. An ASDU with `N = 0` carries no address at all, so there is
    /// nothing for this to be false about: clause 7.2.2 defines `<0>` as "ASDU
    /// contains no INFORMATION OBJECT".
    pub information_object_address: bool,
}

impl Known {
    /// A station that knows all four fields: nothing is mirrored, nothing is
    /// discarded.
    pub const EVERYTHING: Self = Self {
        type_id: true,
        cause: true,
        common_address: true,
        information_object_address: true,
    };

    /// A station that knows none of them, so the clause's table order decides
    /// which cause the mirror reports: 44 first.
    pub const NOTHING: Self = Self {
        type_id: false,
        cause: false,
        common_address: false,
        information_object_address: false,
    };

    /// The answers for a station that implements exactly what the standard's
    /// own tables define ([`type_is_defined`] and [`cause_is_defined`] on the
    /// ASDU's own fields), with the two project-data answers given by the
    /// caller: "this common address is mine" and "I have data for every
    /// information object address in this ASDU".
    ///
    /// [`cause_is_defined`] asks whether table 14 names the cause at all, not
    /// whether it is defined for this type identification; a station that
    /// needs the per-type answer uses [`Known::for_profile`] or sets
    /// [`Known::cause`] itself.
    ///
    /// A station with a different profile (a private-range type by agreement, a
    /// subset of the standardized types, causes accepted per type
    /// identification, a per-address data set) builds [`Known`] itself; that is
    /// why its fields are public.
    #[must_use]
    pub fn standard(
        header: &Header,
        common_address: bool,
        information_object_address: bool,
    ) -> Self {
        Self {
            type_id: type_is_defined(header.type_id),
            cause: cause_is_defined(header.cause),
            common_address,
            information_object_address,
        }
    }

    /// The answers for a station whose **clause 9 interoperability profile**
    /// says which type identifications it uses and which causes of transmission
    /// it accepts for each.
    ///
    /// The first two answers come from the profile's type/cause grid
    /// ([`InteropProfile::uses_type`] and [`InteropProfile::uses`]); the two
    /// project-data answers stay the caller's, exactly as in
    /// [`Known::standard`]. The precedence, the reply and the monitor-direction
    /// verdict are still [`classify`], [`mirror_reply`] and [`discard_reason`]:
    /// a type the profile does not use reports cause 44, and a cause it does
    /// not accept for that type reports 45.
    ///
    /// ```
    /// use iec104::asdu::{classify, Cause, Header, Known, TypeId, Unspecified};
    /// use iec104::interop::{Direction, InteropProfile};
    ///
    /// // M_SP_NA_1, one object, cause 3 (spontaneous), CA 1; body: IOA 1 + SIQ.
    /// let asdu = [0x01, 0x01, 0x03, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00];
    /// let header = Header::parse(&asdu).unwrap();
    ///
    /// // The conventional profile uses it, so a full station knows the ASDU.
    /// let known = Known::for_profile(&InteropProfile::conventional(), &header, true, true);
    /// assert_eq!(classify(&known), None);
    ///
    /// // A station that does not implement M_SP_NA_1 answers cause 44.
    /// let without = InteropProfile::conventional().with_type_row(TypeId::MSpNa1, Direction::NotUsed);
    /// let known = Known::for_profile(&without, &header, true, true);
    /// assert_eq!(classify(&known), Some(Unspecified::TypeIdentification));
    ///
    /// // One that uses the type but not cause 3 for it answers cause 45.
    /// let narrow = InteropProfile::conventional()
    ///     .with_cell(TypeId::MSpNa1, Cause::Spontaneous, Direction::NotUsed);
    /// let known = Known::for_profile(&narrow, &header, true, true);
    /// assert_eq!(classify(&known), Some(Unspecified::CauseOfTransmission));
    /// ```
    #[must_use]
    pub fn for_profile(
        profile: &InteropProfile,
        header: &Header,
        common_address: bool,
        information_object_address: bool,
    ) -> Self {
        Self {
            type_id: profile.uses_type(header.type_id),
            cause: profile.uses(header.type_id, header.cause),
            common_address,
            information_object_address,
        }
    }
}

/// Whether 5-101 tables 8–13 (or 5-104's additions) define this type
/// identification: the *standard's* answer, not a station's.
///
/// `false` for [`TypeId::Other`] and for the reserved gaps of the standardized
/// range (clause 7.2.1.1's `<41..44>`, `<52..69>` and the like). A station that
/// wants the private range 128–255 answers for itself: clause 7.3 leaves that
/// range to agreement between the system user and the vendor.
#[must_use]
pub fn type_is_defined(type_id: TypeId) -> bool {
    type_id.info().is_some()
}

/// Whether 5-101 table 14 defines this cause of transmission: the standard's
/// answer, not a station's.
///
/// `false` for `<0>` "not used", for the reserved values 14–19 and 42–43, and
/// for the private range 48–63 (again by agreement, so not the standard's to
/// define). `true` for the **39** values of table 14 that the standard names:
/// the range 1–47 less the eight reserved numbers 14–19, 42 and 43, and
/// including the four "unknown …" replies 44–47.
#[must_use]
pub const fn cause_is_defined(cause: Cause) -> bool {
    !matches!(
        cause,
        Cause::NotUsed | Cause::Reserved(_) | Cause::Private(_)
    )
}

/// Which of clause 7.2.3's four classes a set of station answers reports, or
/// `None` when the station knows all four fields.
///
/// The clause's table order is the report order: type identification, cause of
/// transmission, common address of ASDU, information object address. The
/// variable structure qualifier is excluded in terms (see the module doc) and
/// is not read here.
#[must_use]
pub fn classify(known: &Known) -> Option<Unspecified> {
    let answers = [
        known.type_id,
        known.cause,
        known.common_address,
        known.information_object_address,
    ];
    Unspecified::ALL
        .into_iter()
        .zip(answers)
        .find_map(|(class, known)| (!known).then_some(class))
}

/// The header clause 7.2.3 says to send back.
///
/// It is the received header with `negative: true` and `why.cause()`, and everything else echoed: the type
/// identification, the VSQ, the T flag, the originator address ("the controlled
/// station should echo this originator address in the response", clause 7.2.3,
/// page index 38) and the common address.
#[must_use]
pub const fn mirror_header(header: &Header, why: Unspecified) -> Header {
    Header {
        cause: why.cause(),
        negative: true,
        ..*header
    }
}

/// A complete mirrored reply, or `None` when the ASDU needs no reply (every
/// field is known, or the ASDU is itself a mirror).
///
/// `objects` is the received object area, octets [`Header::LEN`] onwards, and it
/// is appended to the mirrored header unchanged: the clause says "mirrored", and
/// this is the path that keeps an ASDU this crate cannot decode (an undefined
/// type identification) byte for byte.
#[must_use]
pub fn mirror_reply(header: &Header, known: &Known, objects: &[u8]) -> Option<Vec<u8>> {
    mirror_reply_with(header, known, objects, AddressSizes::CONVENTIONAL)
}

/// [`mirror_reply`] with the address sizes `sizes` fixes: `objects` starts at
/// octet [`AddressSizes::header_len`].
///
/// Also `None` when the mirrored header cannot be encoded under `sizes` (see
/// [`Header::encode_with`]).
#[must_use]
pub fn mirror_reply_with(
    header: &Header,
    known: &Known,
    objects: &[u8],
    sizes: AddressSizes,
) -> Option<Vec<u8>> {
    if is_mirror(header) {
        return None;
    }
    let why = classify(known)?;
    let mut out = Vec::with_capacity(sizes.header_len().saturating_add(objects.len()));
    mirror_header(header, why)
        .encode_with(&mut out, sizes)
        .ok()?;
    out.extend_from_slice(objects);
    Some(out)
}

/// A controlled station's clause 7.2.3 mirror of the received `asdu`.
///
/// The mirror is the received header with `P/N = 1`, the class's cause and the station's own
/// `common_address`, then the received object area octet for octet, all in
/// the address sizes `sizes` fixes.
///
/// A `common_address` wider than `sizes` allows keeps the received one, so the
/// mirror is always a frame the peer can parse.
#[must_use]
pub fn mirror_frame(
    header: &Header,
    asdu: &[u8],
    why: Unspecified,
    common_address: u16,
    sizes: AddressSizes,
) -> Vec<u8> {
    let received = mirror_header(header, why);
    let mirrored = Header {
        common_address,
        ..received
    };
    let objects = asdu.get(sizes.header_len()..).unwrap_or(&[]);
    let mut out = Vec::with_capacity(sizes.header_len().saturating_add(objects.len()));
    if mirrored.encode_with(&mut out, sizes).is_err() {
        out.clear();
        let _ = received.encode_with(&mut out, sizes);
    }
    out.extend_from_slice(objects);
    out
}

/// A received ASDU that is itself a mirror: `P/N = 1` (the negative confirm of
/// clause 7.2.3) carrying one of the four "unknown …" causes.
///
/// A negative confirmation with a *defined* cause (7 `actcon`, 9 `deactcon`, …)
/// is an ordinary reply and not a mirror, so both the flag and one of the four
/// causes are required. The clause's log bullet names the command types it
/// expects to see this shape on ("type identifications 45 to 51"), but a
/// mirror of a system or parameter ASDU has the same shape with another type
/// identification; a caller keeping the clause's exact log list filters by type
/// itself.
#[must_use]
pub const fn is_mirror(header: &Header) -> bool {
    header.negative
        && matches!(
            header.cause,
            Cause::UnknownTypeId
                | Cause::UnknownCause
                | Cause::UnknownCommonAddress
                | Cause::UnknownInformationObjectAddress
        )
}

/// Why a received ASDU is not to be processed, for the caller's error log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Discard {
    /// A field the station does not know (the clause's first two log bullets).
    Unspecified(Unspecified),
    /// A mirrored ASDU received from the peer (the clause's third bullet).
    Mirror,
}

/// The monitor direction's half of clause 7.2.3: why this ASDU is discarded and
/// may be logged, or `None` when it is to be processed normally.
///
/// "Receipt of one of these ASDUs does not affect the processing of subsequent
/// messages" is a statement about state, and this function is where the crate
/// makes it true: the decision is a pure function of one header and one
/// [`Known`], so nothing of a discarded ASDU can reach the next one.
pub fn discard_reason(header: &Header, known: &Known) -> Option<Discard> {
    if is_mirror(header) {
        return Some(Discard::Mirror);
    }
    classify(known).map(Discard::Unspecified)
}
