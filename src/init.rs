//! Station initialisation: the controlled station's end of initialisation and
//! what the controlling station does with it.
//!
//! # The ASDU
//!
//! 5-101 clause **7.3.3.1** (PDF page index 104, printed page 103) defines it:
//!
//! ```text
//! M_EI_NA_1 := CP{Data unit identifier,Information object address,COI}
//! ```
//!
//! as a single information object (SQ = 0) whose figure prints
//! `INFORMATION OBJECT ADDRESS = 0`, with one cause of transmission:
//!
//! > CAUSES OF TRANSMISSION used with TYPE IDENT 70 := M_EI_NA_1
//! > CAUSE OF TRANSMISSION <4> := initialized
//!
//! Its `COI` is clause **7.2.6.21** (page index 53): `CP8{UI7[1..7],BS1[8]}`.
//! The seven-bit cause is `<0>` local power switch on, `<1>` local manual reset,
//! `<2>` remote reset, `<3..31>` compatible range, `<32..127>` private range;
//! bit 8 is `<0>` initialization with unchanged local parameters or `<1>`
//! initialization after change of local parameters.
//!
//! # The behaviour
//!
//! 5-101 clause **7.4** (page index 121): *"After successful station
//! initialization, all application functions must be available to run
//! simultaneously."* The same clause's **Table 16, Respond priorities of the
//! controlled station**, puts type 70 End of initialization in its first row,
//! ahead of every other ASDU. So the end of initialisation is the first thing
//! the controlled station sends, and it is the controlling station's cue to
//! start a station interrogation ([`crate::gi`]).
//!
//! 5-104 clause **7.1** (page indices 53–56) is the TCP-level half of station
//! initialisation and defines no ASDU of its own: connection establishment and
//! release (figures 19–22), including figure 22's `Reset_Process`. That
//! procedure is carried by `C_RP_NA_1` (type 105), a command of the act/actcon
//! family, and 5-101 clause 8.6 lists remote initialization as a
//! station-specific selection. This module implements neither.
//!
//! # What this module is not
//!
//! * **Not the link layer.** The end of initialisation is data in the monitor
//!   direction, so the controlled station hands its octets to
//!   [`Session::queue_i_frame`](crate::link::Session::queue_i_frame). Clause
//!   5.3: *"This implies that after station initialization (see 7.1) STARTDT
//!   must always be sent before any user data transfer from the controlled
//!   station (for example, general interrogated information) is initiated."*
//!   The end of initialisation therefore waits for the STARTDT con like any
//!   other queued I-frame.
//! * **Not general interrogation.** The controlling station's next step is
//!   named here as a value ([`FollowUp::StationInterrogation`]) and performed by
//!   [`crate::gi`]. In a redundancy group the started connection is the one that
//!   acts (5-104 cl.10.3, [`crate::redundancy`]); nothing in this module chooses
//!   a connection.
//! * **Not I/O.** Every function here is a pure function of its arguments; the
//!   caller owns the socket, the printing and the retry.
//!
//! # Choices of this crate
//!
//! * **The builder fixes the cause.** [`end_of_initialisation`] always writes
//!   cause 4 `init` and `INFORMATION OBJECT ADDRESS = 0`, so a caller cannot
//!   produce a frame the clause's cause list does not cover. That is why it
//!   takes no cause argument and its only failure mode is the layout layer's.
//! * **The reception decision reports, it does not act.** [`Reaction`] carries
//!   the `COI` of an end of initialisation, clause 7.2.3's discard reason for an
//!   ASDU the station does not know, or "not this procedure". The caller decides
//!   what to do; clause 7.2.3's discard rule ([`crate::asdu::discard_reason`])
//!   runs *before* the type is examined.
//!
//! # Example
//!
//! ```
//! use iec104::asdu::{Cause, Coi, Header, TypeId, IOA_IRRELEVANT};
//! use iec104::init::{end_of_initialisation, on_asdu, FollowUp, Reaction};
//! use iec104::asdu::Known;
//!
//! // The controlled station declares itself ready: local manual reset, local
//! // parameters unchanged, ASDU address 12.
//! let coi = Coi {
//!     cause: Coi::LOCAL_MANUAL_RESET,
//!     changed_local_parameters: false,
//! };
//! let asdu = end_of_initialisation(coi, 12, 0).unwrap();
//! assert_eq!(asdu.len(), 10);
//!
//! let header = Header::parse(&asdu).unwrap();
//! assert_eq!(header.type_id, TypeId::MEiNa1);
//! assert_eq!(header.cause, Cause::Initialized);
//! assert_eq!(header.common_address, 12);
//! assert_eq!(header.count, 1);
//! assert!(!header.sequence);
//!
//! // The controlling station sees it and names its next step.
//! let reaction = on_asdu(&asdu, &Known::EVERYTHING).unwrap();
//! assert_eq!(reaction, Reaction::EndOfInitialisation(coi));
//! assert_eq!(reaction.follow_up(), Some(FollowUp::StationInterrogation));
//!
//! // An ASDU the station does not know is clause 7.2.3's business instead.
//! assert!(matches!(on_asdu(&asdu, &Known::NOTHING), Ok(Reaction::Discard(_))));
//! ```

use crate::asdu::{
    AddressSizes, Cause, Coi, Discard, Header, IOA_IRRELEVANT, Known, LayoutError, LayoutObject,
    MEiNa1, TypeId, decode_asdu_with, discard_reason, encode_asdu_with,
};

/// The cause the clause lists for an end of initialisation: `<4> initialized`.
pub const CAUSE: Cause = Cause::Initialized;

/// The type identification of the end of initialisation.
pub const TYPE_ID: TypeId = TypeId::MEiNa1;

/// Builds the controlled station's end of initialisation: the ten octets of an
/// `M_EI_NA_1` ASDU with cause `init`, `N = 1`, `SQ = 0` and an information
/// object address of zero (5-101 cl.7.3.3.1).
///
/// The cause and the information object address are the clause's, not the
/// caller's, so a frame that the standard does not list for type 70 cannot be
/// built. The error is the layout layer's and cannot occur for these
/// arguments; it is propagated rather than unwrapped so this path cannot panic.
///
/// # Errors
///
/// A [`LayoutError`] from the layout layer, which cannot occur for these
/// arguments.
pub fn end_of_initialisation(
    coi: Coi,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, LayoutError> {
    end_of_initialisation_with(coi, common_address, originator, AddressSizes::CONVENTIONAL)
}

/// [`end_of_initialisation`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`end_of_initialisation`].
pub fn end_of_initialisation_with(
    coi: Coi,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    let header = Header {
        type_id: TYPE_ID,
        sequence: false,
        count: 1,
        cause: CAUSE,
        negative: false,
        test: false,
        originator,
        common_address,
    };
    let object = LayoutObject {
        ioa: IOA_IRRELEVANT,
        value: MEiNa1 { coi },
    };
    encode_asdu_with(&header, &[object], sizes)
}

/// What a received ASDU is, as far as station initialisation is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// An end of initialisation arrived, carrying the sender's `COI`.
    EndOfInitialisation(Coi),
    /// Clause 7.2.3 says this ASDU is discarded and may be logged.
    Discard(Discard),
    /// Not this procedure: the type or the cause says the ASDU belongs to
    /// another one, and this module leaves it alone.
    Other,
}

/// The step a reaction starts, for the caller to perform.
///
/// A value rather than a frame, because the step belongs to another module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FollowUp {
    /// Start a station interrogation (`C_IC_NA_1` with `QOI` 20). The request
    /// is built by [`crate::gi`]; in a redundancy group, 5-104 cl.10.3's choice
    /// of the connection that acts is [`crate::redundancy`]'s.
    StationInterrogation,
}

impl Reaction {
    /// The procedure this reaction starts, or `None` when it starts none.
    #[must_use]
    pub const fn follow_up(self) -> Option<FollowUp> {
        match self {
            Self::EndOfInitialisation(_) => Some(FollowUp::StationInterrogation),
            Self::Discard(_) | Self::Other => None,
        }
    }
}

/// Reads one received ASDU against station initialisation and clause 7.2.3.
///
/// The order is the clause's: an ASDU whose fields the station does not know is
/// discarded first (5-101 cl.7.2.3, whose table gives an undefined type
/// identification its own cause), and only afterwards is the type examined. A
/// type 70 ASDU whose cause is not `<4> initialized` is not this procedure and
/// is reported as [`Reaction::Other`], because the clause lists no other cause
/// for the type.
///
/// # Errors
///
/// A [`LayoutError`] when the ASDU header, or the object of a type 70 ASDU,
/// cannot be decoded.
pub fn on_asdu(asdu: &[u8], known: &Known) -> Result<Reaction, LayoutError> {
    on_asdu_with(asdu, known, AddressSizes::CONVENTIONAL)
}

/// [`on_asdu`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`on_asdu`].
pub fn on_asdu_with(
    asdu: &[u8],
    known: &Known,
    sizes: AddressSizes,
) -> Result<Reaction, LayoutError> {
    let header = Header::parse_with(asdu, sizes)?;
    if let Some(reason) = discard_reason(&header, known) {
        return Ok(Reaction::Discard(reason));
    }
    if header.type_id != TYPE_ID || header.cause != CAUSE {
        return Ok(Reaction::Other);
    }
    // `N = 0` is clause 7.2.2's defined "ASDU contains no INFORMATION OBJECT",
    // so a type 70 frame can legally carry no `COI` at all. There is nothing to
    // act on then.
    Ok(decode_asdu_with::<MEiNa1>(asdu, sizes)?
        .first()
        .map_or(Reaction::Other, |object| {
            Reaction::EndOfInitialisation(object.value.coi)
        }))
}
