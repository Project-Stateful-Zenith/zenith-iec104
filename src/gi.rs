//! General interrogation: the `C_IC_NA_1` activation, its response cycle and
//! the two roles that run it.
//!
//! # The procedure
//!
//! 5-104 clause **7.5** (PDF page index 64, printed page 63) defines no
//! procedure of its own. It is the service table that maps the IEC 60870-5-5
//! primitives onto ASDU labels, and it is the whole of the clause:
//!
//! | Application service | ASDU label |
//! | --- | --- |
//! | `A_GENINCOM.req` / `A_GENINCOM.ind` | `C_IC ACT` |
//! | `A_GENINACK.req` / `A_GENINACK.ind` | `C_IC ACTCON` |
//! | `A_INTINF.req` / `A_INTINF.ind` | `M` |
//! | `A_ENDINT.req` / `A_ENDINT.ind` | `C_IC ACTTERM` |
//!
//! So every rule this module implements is 5-101's. Clause **7.4.5** (PDF page
//! indices 122–125, printed pages 121–124) is the procedure, clause **7.2.6.22**
//! (page index 53) is the qualifier, and clause **7.3.4.1** (page index 105,
//! figure 72) is the layout.
//!
//! # The request
//!
//! `C_IC_NA_1 := CP{Data unit identifier,Information object address,QOI}`, headed
//! *"Single information object (SQ = 0)"*, its figure printing `INFORMATION
//! OBJECT ADDRESS = 0`: ten octets, `SQ = 0`, `N = 1`, type 100. The clause's
//! per-type cause list is the whole set of causes the type may carry:
//!
//! ```text
//! CAUSES OF TRANSMISSION used with TYPE IDENT 100 := C_IC_NA_1
//!   in control direction: <6> activation, <8> deactivation
//!   in monitor direction: <7> activation confirmation,
//!                         <9> deactivation confirmation,
//!                         <10> activation termination,
//!                         <44> .. <47> the four unknown-address replies
//! ```
//!
//! so [`request`] writes cause 6 and [`deactivation`] cause 8, and neither takes
//! a cause argument.
//!
//! # The scope and its cause
//!
//! `QOI := UI8[1..8]<0..255>` (clause 7.2.6.22): `<20>` is the station
//! interrogation and `<21>` … `<36>` are groups 1 … 16 (`<0>` "not used",
//! `<1..19>`/`<37..63>` reserved-compatible, `<64..255>` private). The scope the
//! qualifier names is also the cause of transmission of every object the scope
//! returns (`<20>` interrogated by station interrogation, `<21>` … `<36>`
//! interrogated by group 1 … 16). That is why [`Scope::cause`] sits next to
//! [`Scope::qoi`] as one mapping.
//!
//! # The response cycle
//!
//! Clause 7.4.5 and its **Table 17** (PDF page index 123, printed page 122) fix
//! the exchange:
//!
//! - the controlling station sends `C_IC ACT`;
//! - a controlled station that is ready confirms positively and returns the
//!   objects, while *"the station interrogation command `C_IC` ACT is negatively
//!   acknowledged by a `C_IC` ACTCON when the controlled station is not ready to
//!   return the interrogated information. In this case, the station
//!   interrogation command may be repeated"*;
//! - the objects are returned with causes `<20>` … `<36>`;
//! - `C_IC ACTTERM` ends the procedure once all of the scope's data is sent.
//!
//! Two sentences bound the payload: *"ASDUs with cause of transmission 20 to 36
//! are transmitted without time tags"*, and *"In response to a station
//! interrogation request, these information objects are reported in type
//! identifications `<1>`, `<3>`, `<5>`, `<7>`, `<9>`, `<11>`, `<13>`, `<20>` or
//! `<21>`."* Those nine untagged monitor types are [`INTERROGATED_TYPES`]. The
//! time-tag rule and the type rule are therefore one rule and one check. The
//! controlled station also accepts the three parameter types of
//! [`INTERROGATED_PARAMETER_TYPES`], and refuses anything else in a response.
//!
//! # Re-activation of a running interrogation
//!
//! A running interrogation is one *"the controlling station has not received
//! the `C_IC_ACTTERM` after it has sent a `C_IC_ACT`"* (TS 60870-5-604:2016
//! clause 5.4.17, Table 17 page 3 of 5, PDF page index 66). 5-101 clause 7.4.5
//! locks a second **identical** interrogation on the controlling side
//! (*"the initialization of an identical general interrogation of the same
//! source before the previous one is terminated is normally locked by the
//! controlling station"*). For a second activation that does arrive, the
//! conformance specification requires the controlled station to implement one
//! of three PIXIT options and the controlling station to handle all three.
//! [`ReActivation`] is that selection:
//!
//! | Option | Name in Table 17 | Controlled station |
//! | --- | --- | --- |
//! | 1 | "the running GI continues" | negative confirmation, the first procedure continues |
//! | 2 | "the running GI is stopped and the second GI is started" | an indication that the first stopped (a termination or a negative confirmation; this crate sends the termination), then a positive confirmation for the second |
//! | 3 | "the running GI continues and after activation termination (COT = 10) the second GI is started" | positive confirmation for the second now, its data after the first's termination |
//!
//! # What this module is not
//!
//! * **Not I/O and not a clock.** Every result here depends only on the
//!   arguments and the procedure's own state; the caller owns the socket, the flow control and the logging
//!   (the connection layer is [`crate::manager`], the log line
//!   [`crate::diag`]). Frames come back as `Vec<u8>` ASDUs.
//! * **Not the group membership.** Which objects belong to group 3 is project
//!   data (5-101 clause 8.9's interoperability list, see [`crate::interop`]),
//!   so the controlled station's data arrives through the caller's
//!   [`DataSource`].
//! * **Not the deactivation of a *connection*.** 5-104 clause 7.1's
//!   `Reset_Process` is the TCP-level procedure, not this.
//! * **Not the counter interrogation.** `C_CI_NA_1` (type 101) and `QCC` are
//!   [`crate::ci`]. Its shape is the same, which is why this module's names are
//!   neutral about which interrogation they serve where they can be.
//!
//! # Example
//!
//! ```
//! use iec104::asdu::{Cause, Header, Known, TypeId, IOA_IRRELEVANT};
//! use iec104::gi::{deactivation, request, Scope};
//!
//! // The controlling station asks for group 3.
//! let asdu = request(Scope::Group(3), 12, 0).unwrap();
//! let header = Header::parse(&asdu).unwrap();
//! assert_eq!(header.type_id, TypeId::CIcNa1);
//! assert_eq!(header.cause, Cause::Activation);
//! assert_eq!(header.count, 1);
//! assert_eq!(asdu[9], 23, "QOI 21 + n - 1 for group 3");
//!
//! // The same qualifier names the cause of every object the group returns.
//! assert_eq!(Scope::Group(3).cause(), Cause::InterrogatedByGroup(3));
//! assert_eq!(Scope::Station.cause(), Cause::InterrogatedByStation);
//!
//! // Deactivation is the same frame with cause 8 (TS 60870-5-604, 5.4.17.50).
//! let off = deactivation(Scope::Group(3), 12, 0).unwrap();
//! assert_eq!(Header::parse(&off).unwrap().cause, Cause::Deactivation);
//! ```

use crate::asdu::{
    AddressSizes, AsduError, CIcNa1, Cause, Discard, Header, IOA_IRRELEVANT, Known, LayoutError,
    LayoutObject, Qoi, TypeId, decode_asdu_with, discard_reason, encode_asdu_with, is_mirror,
    mirror_frame,
};

/// The type identification of the interrogation command and of every frame of
/// its procedure (5-101 clause 7.3.4.1).
pub const TYPE_ID: TypeId = TypeId::CIcNa1;

/// `<6> activation`: the cause of the request (figure 72's control-direction
/// list).
pub const CAUSE_ACTIVATION: Cause = Cause::Activation;

/// `<8> deactivation`: the cause that stops a running interrogation
/// (figure 72; TS 60870-5-604 clause 5.4.17.50).
pub const CAUSE_DEACTIVATION: Cause = Cause::Deactivation;

/// `<7> activation confirmation`: the cause of the controlled station's
/// positive **and** negative confirmation (figure 72; 604's `C_IC_ACTCON` and
/// `C_IC_ACTCONneg` are the same cause, told apart by `P/N`).
pub const CAUSE_ACTIVATION_CON: Cause = Cause::ActivationCon;

/// `<9> deactivation confirmation`.
pub const CAUSE_DEACTIVATION_CON: Cause = Cause::DeactivationCon;

/// `<10> activation termination`: the frame that ends the procedure.
pub const CAUSE_ACTIVATION_TERM: Cause = Cause::ActivationTermination;

/// The nine monitor types an interrogation response may carry, in the clause's
/// own order (5-101 clause 7.4.5, page index 122; quoted in the module doc).
///
/// All nine are untagged, which is the same rule as *"ASDUs with cause of
/// transmission 20 to 36 are transmitted without time tags"* (5-101 clause
/// 7.4.5, PDF page index 124, printed page 123).
pub const INTERROGATED_TYPES: [TypeId; 9] = [
    TypeId::MSpNa1,
    TypeId::MDpNa1,
    TypeId::MStNa1,
    TypeId::MBoNa1,
    TypeId::MMeNa1,
    TypeId::MMeNb1,
    TypeId::MMeNc1,
    TypeId::MPsNa1,
    TypeId::MMeNd1,
];

/// The parameters of measured values that an interrogation may report.
///
/// 5-101 cl.7.3.5.1–7.3.5.3 list them with causes `<20>` … `<36>` as well: a
/// station interrogation may report a station's local parameters. `P_AC_NA_1`
/// `<113>` is not among them.
pub const INTERROGATED_PARAMETER_TYPES: [TypeId; 3] =
    [TypeId::PMeNa1, TypeId::PMeNb1, TypeId::PMeNc1];

/// Whether `type_id` may be sent in an interrogation response: one of the
/// nine [`INTERROGATED_TYPES`] or of the three [`INTERROGATED_PARAMETER_TYPES`].
#[must_use]
pub fn is_interrogated(type_id: TypeId) -> bool {
    INTERROGATED_TYPES.contains(&type_id) || INTERROGATED_PARAMETER_TYPES.contains(&type_id)
}

/// Which information an interrogation asks for: the `QOI` of 5-101 clause
/// 7.2.6.22, as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// `<20>`: station interrogation, the whole station.
    Station,
    /// `<21>` … `<36>`: group 1 … 16. The variant is public, so besides
    /// [`Scope::group`], [`Scope::qoi`] and [`Scope::cause`] clamp it too and an
    /// out-of-range group can never reach the wire.
    Group(u8),
}

impl Scope {
    /// The scope a `QOI` names, or `None` for a value clause 7.2.6.22 leaves
    /// reserved or private (`<0>`, `<1..19>`, `<37..255>`).
    #[must_use]
    pub const fn from_qoi(qoi: Qoi) -> Option<Self> {
        match qoi.value {
            Qoi::STATION_INTERROGATION => Some(Self::Station),
            Qoi::GROUP_1..=Qoi::GROUP_16 => Some(Self::Group(
                qoi.value.wrapping_sub(Qoi::STATION_INTERROGATION),
            )),
            _ => None,
        }
    }

    /// Group `n` (`1..=16`), clamped into the standard's range the way
    /// [`Qoi::group`] is.
    #[must_use]
    pub fn group(n: u8) -> Self {
        Self::Group(n.clamp(1, 16))
    }

    /// Group `n`, or `None` outside `1..=16`.
    #[must_use]
    pub fn try_group(n: u8) -> Option<Self> {
        (1..=16).contains(&n).then_some(Self::Group(n))
    }

    /// Whether the scope is one the standard defines: the station, or a
    /// group `1..=16`. A `Scope::Group` built directly can be outside it.
    #[must_use]
    pub fn is_valid(self) -> bool {
        match self {
            Self::Station => true,
            Self::Group(n) => (1..=16).contains(&n),
        }
    }

    /// The qualifier of interrogation this scope is requested with.
    #[must_use]
    pub fn qoi(self) -> Qoi {
        Qoi {
            value: match self {
                Self::Station => Qoi::STATION_INTERROGATION,
                Self::Group(n) => Qoi::STATION_INTERROGATION.wrapping_add(n.clamp(1, 16)),
            },
        }
    }

    /// The cause of transmission every object of this scope is reported with
    /// (`<20>` inrogen, `<21>` … `<36>` inro 1…16).
    #[must_use]
    pub fn cause(self) -> Cause {
        match self {
            Self::Station => Cause::InterrogatedByStation,
            Self::Group(n) => Cause::InterrogatedByGroup(n.clamp(1, 16)),
        }
    }

    /// The group number, `Some(1..=16)`, or `None` for the station scope.
    #[must_use]
    pub fn group_number(self) -> Option<u8> {
        match self {
            Self::Station => None,
            Self::Group(n) => Some(n.clamp(1, 16)),
        }
    }

    /// Whether this is the station-wide scope `<20>`.
    #[must_use]
    pub const fn is_station_wide(self) -> bool {
        matches!(self, Self::Station)
    }
}

/// What the controlled station does with a second activation while an
/// interrogation is already running.
///
/// These are the three options of TS 60870-5-604 clause 5.4.17 (Table 17, page
/// 3 of 5), a per-station PIXIT selection this crate models rather than
/// chooses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReActivation {
    /// Option 1: the running interrogation continues, the second is negatively
    /// confirmed.
    Continue,
    /// Option 2: the running interrogation is stopped (with its termination)
    /// and the second starts.
    Restart,
    /// Option 3: the running interrogation continues; the second is positively
    /// confirmed and its data follows the first's termination.
    Queue,
}

/// The controlled station's own process data.
///
/// Neither of the two facts the procedure needs can be invented here: the
/// *membership* of a group is project data (5-101 clause 8.9's interoperability
/// list), and the *geometry* of a response ASDU is 5-101 clause 7.3's (the
/// layouts in [`crate::asdu`]). An implementation builds each ASDU through the
/// layout layer with [`Scope::cause`] as its cause of transmission and a type
/// for which [`is_interrogated`] holds, which the procedure checks.
pub trait DataSource {
    /// Whether the station can return `scope` right now. If not, this is clause
    /// 7.4.5's *"not ready to return the interrogated information"*, answered
    /// with a negative activation confirmation.
    fn ready(&self, scope: Scope) -> bool;

    /// Appends the ASDUs `scope` interrogates, in the order they are to be sent.
    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>);
}

/// What one frame of the procedure means, from the point of view of the role
/// that received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// An activation confirmation arrived or was sent, positive when `negative`
    /// is false. The same cause 7 carries both, with `P/N` as the flag (5-101
    /// clause 7.3.4.1 figure 72).
    ActivationConfirmed {
        /// The interrogation the confirmation answers.
        scope: Scope,
        /// `P/N = 1`: a negative confirmation, which the controlling station
        /// may answer by repeating the command.
        negative: bool,
    },
    /// An interrogated information object arrived, with the scope's cause of
    /// transmission `<20>` … `<36>`.
    Interrogated {
        /// The scope the object was returned for.
        scope: Scope,
    },
    /// The procedure ended (`C_IC ACTTERM`, cause `<10>`).
    Terminated {
        /// The scope that ended.
        scope: Scope,
    },
    /// A deactivation was confirmed (cause `<9>`).
    DeactivationConfirmed {
        /// The scope that was stopped.
        scope: Scope,
        /// `P/N = 1`: the controlled station had nothing of this scope to stop.
        negative: bool,
    },
    /// Clause 7.2.3's cause 44–47 mirror: sent by a controlled station for a
    /// field it does not know, or received by a controlling station for one of
    /// its own pending activations (which that settles).
    Refused {
        /// The scope of the mirrored frame, where it is a decodable `C_IC_NA_1`.
        scope: Option<Scope>,
        /// The mirror's cause, `<44>` … `<47>`.
        cause: Cause,
    },
    /// Clause 7.2.3 says this ASDU is discarded and may be logged.
    Discard(Discard),
    /// Not this procedure: the type, the cause or the qualifier says the ASDU
    /// belongs to another one.
    Other,
}

/// What a received ASDU means, and what to send because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The classification of the received ASDU.
    pub reaction: Reaction,
    /// The ASDUs to send, in order. Always empty for a controlling station;
    /// for a controlled station it carries the confirmation (preceded, under
    /// [`ReActivation::Restart`], by the first procedure's termination) or the
    /// clause 7.2.3 mirror.
    pub send: Vec<Vec<u8>>,
}

/// What can go wrong in this layer, over and above the codec's own errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GiError {
    /// A group outside `1..=16`: the request would interrogate another
    /// group, so it is refused rather than clamped.
    GroupOutOfRange {
        /// The group number asked for.
        group: u8,
    },
    /// A second identical interrogation while one is running: clause 7.4.5's
    /// lock on the *controlling* side. The controlled side's choice for a
    /// second activation that does arrive is [`ReActivation`].
    AlreadyRunning {
        /// The scope already running.
        scope: Scope,
    },
    /// The entry point does not belong to this instance's role: `request` and
    /// `on_response` are the controlling station's, `on_request` and the
    /// response-building methods are the controlled station's.
    WrongRole,
    /// The controlled station's [`DataSource`] returned an ASDU whose type
    /// [`is_interrogated`] rejects. Every time-tagged type is among them, which
    /// clause 7.4.5 forbids here in terms.
    NotInterrogatedType {
        /// The type the data source returned.
        type_id: TypeId,
    },
    /// The same data source returned an ASDU whose cause of transmission is not
    /// the scope's own (`<20>` … `<36>`).
    WrongCause {
        /// The scope's cause, which the ASDU should have carried.
        expected: Cause,
        /// The cause it carried.
        got: Cause,
    },
    /// There is nothing to produce the frames for: no interrogation is running,
    /// or (for [`Interrogation::interrogated`]) its data was already produced.
    NotRunning,
    /// The ASDU itself could not be parsed; the layout/header layer's error,
    /// unchanged.
    Layout(LayoutError),
}

impl From<LayoutError> for GiError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<AsduError> for GiError {
    /// The header/codec error reaches this layer through the layout layer's own
    /// wrapper, exactly as [`crate::asdu::decode_asdu`] surfaces it.
    fn from(err: AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// Builds one type-100 frame: `N = 1`, `SQ = 0`, an information object address
/// of zero (figure 72) and `P/N` as given. The cause is the caller's here and
/// the clause's in every public builder.
fn frame(
    cause: Cause,
    negative: bool,
    scope: Scope,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    let header = Header {
        type_id: TYPE_ID,
        sequence: false,
        count: 1,
        cause,
        negative,
        test: false,
        originator,
        common_address,
    };
    let object = LayoutObject {
        ioa: IOA_IRRELEVANT,
        value: CIcNa1 { qoi: scope.qoi() },
    };
    encode_asdu_with(&header, &[object], sizes)
}

/// Builds the activation.
///
/// The activation is the ten-octet `C_IC_NA_1` of 5-101 clause 7.3.4.1, with
/// cause 6 (`act`), `N = 1`, `SQ = 0` and an information object address of
/// zero (figure 72's `INFORMATION OBJECT ADDRESS = 0`), carrying `scope`'s
/// qualifier.
///
/// The cause and the information object address are the clause's, not the
/// caller's, so a frame the standard does not list for type 100 cannot be built
/// from this API. The error is the layout layer's and cannot occur for these
/// arguments; it is propagated rather than unwrapped because nothing in `src/`
/// panics.
///
/// # Errors
///
/// None for these arguments in the conventional address sizes; the layout
/// layer's [`LayoutError`] is passed through unchanged.
pub fn request(scope: Scope, common_address: u16, originator: u8) -> Result<Vec<u8>, LayoutError> {
    request_with(
        scope,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`request`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// [`LayoutError::Asdu`] when `common_address` does not fit the common address
/// size `sizes` fixes.
pub fn request_with(
    scope: Scope,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    frame(
        CAUSE_ACTIVATION,
        false,
        scope,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the deactivation.
///
/// The deactivation is the same ten octets with cause 8 (`deact`), which TS
/// 60870-5-604's clause 5.4.17.50 stops a running interrogation with. The
/// controlled station answers with cause 9 and sends no further objects of that
/// scope, and no termination.
///
/// # Errors
///
/// None for these arguments in the conventional address sizes; the layout
/// layer's [`LayoutError`] is passed through unchanged.
pub fn deactivation(
    scope: Scope,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, LayoutError> {
    deactivation_with(
        scope,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`deactivation`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// [`LayoutError::Asdu`] when `common_address` does not fit the common address
/// size `sizes` fixes.
pub fn deactivation_with(
    scope: Scope,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    frame(
        CAUSE_DEACTIVATION,
        false,
        scope,
        common_address,
        originator,
        sizes,
    )
}

/// The controlling station's stance on activating an interrogation while
/// another one of the same scope is running.
///
/// 5-101 clause 7.4.5 states the lock (quoted in the module doc), and TS
/// 60870-5-604 Table 17 (page 3 of 5) leaves the other case open: *"If the
/// Controlling station supports activating a new interrogation while another
/// interrogation is already running, then the Controlling station shall be able
/// to handle each option."* [`SecondActivation`] is that support, as a
/// selection; [`Interrogation::on_response`] handles all three options either
/// way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondActivation {
    /// The clause's normal behaviour: an identical activation is refused while
    /// one is pending or running ([`GiError::AlreadyRunning`]).
    Locked,
    /// The conformance note's configuration: the second activation is sent, and
    /// whichever of the three options the other station implements is accepted
    /// as it arrives.
    Allowed,
}

/// One role's general interrogation procedure.
///
/// The role here is the *procedure's* role, not the transport's: a station that
/// is the TCP client is the controlling station (5-104 clause 7, page index 54:
/// *"The controlling station is equivalent to the client (connector), the
/// controlled station to the server (listener)"*), but the same station may hold
/// the other role's instance for the reverse direction, which clause 7.1 calls
/// the case of "two equivalent controlling stations or partners".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interrogation {
    role: Role,
    policy: ReActivation,
    second: SecondActivation,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
    pending: Vec<Scope>,
    running: Vec<Scope>,
    queued: Vec<Scope>,
    awaiting_data: bool,
    /// Controlled station: the originator address of each positively
    /// confirmed activation, oldest first, echoed on everything that answers
    /// it (5-101 cl.7.2.3).
    origins: Vec<(Scope, u8)>,
    /// Controlling station addressing the broadcast common address: each LRU
    /// that has positively confirmed a scope and not yet terminated it, by
    /// its own common address (5-101 cl.7.4.5, see [`Interrogation::on_response`]).
    lrus: Vec<(Scope, u16)>,
}

/// Which side of the procedure an [`Interrogation`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The interrogating side: sends the activation, confirms nothing.
    Controlling,
    /// The interrogated side: confirms, returns the objects, terminates.
    Controlled,
}

impl Interrogation {
    /// A controlling station's instance. Its re-activation policy is unused:
    /// clause 7.4.5 locks a repeat of an identical interrogation (see
    /// [`SecondActivation`]), and Table 17 requires it to *handle* all three
    /// controlled-station options rather than select one.
    #[must_use]
    pub const fn controlling(
        second: SecondActivation,
        common_address: u16,
        originator: u8,
    ) -> Self {
        Self {
            role: Role::Controlling,
            policy: ReActivation::Continue,
            second,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
            pending: Vec::new(),
            running: Vec::new(),
            queued: Vec::new(),
            awaiting_data: false,
            origins: Vec::new(),
            lrus: Vec::new(),
        }
    }

    /// A controlled station's instance, selecting its re-activation option
    /// (TS 60870-5-604 clause 5.4.17).
    #[must_use]
    pub const fn controlled(policy: ReActivation, common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlled,
            policy,
            second: SecondActivation::Locked,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
            pending: Vec::new(),
            running: Vec::new(),
            queued: Vec::new(),
            awaiting_data: false,
            origins: Vec::new(),
            lrus: Vec::new(),
        }
    }

    /// The same instance with the system's address sizes (104 cl.9.5), for
    /// every frame it reads and builds. [`AddressSizes::CONVENTIONAL`] by
    /// default.
    #[must_use]
    pub const fn with_address_sizes(mut self, sizes: AddressSizes) -> Self {
        self.sizes = sizes;
        self
    }

    /// The address sizes this instance reads and builds frames with.
    #[must_use]
    pub const fn address_sizes(&self) -> AddressSizes {
        self.sizes
    }

    /// Which side of the procedure this instance is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The controlled station's re-activation option, if this is one.
    #[must_use]
    pub const fn policy(&self) -> Option<ReActivation> {
        match self.role {
            Role::Controlled => Some(self.policy),
            Role::Controlling => None,
        }
    }

    /// The controlling station's stance on a second activation.
    #[must_use]
    pub const fn second_activation(&self) -> SecondActivation {
        self.second
    }

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// The procedures that are running, in TS 60870-5-604 clause 5.4.17's sense:
    /// *"a running GI means that the controlling station has not received the
    /// `C_IC_ACTTERM` after it has sent a `C_IC_ACT`"*. An activation whose
    /// confirmation is still in flight therefore counts as running. For a
    /// controlled station it is the interrogation it has confirmed and not yet
    /// terminated (a queued one is in [`Interrogation::queued`]).
    #[must_use]
    pub fn running(&self) -> Vec<Scope> {
        let mut scopes = self.pending.clone();
        for scope in self
            .running
            .iter()
            .chain(self.lrus.iter().map(|(scope, _)| scope))
        {
            if !scopes.contains(scope) {
                scopes.push(*scope);
            }
        }
        scopes
    }

    /// Whether `scope` is running.
    #[must_use]
    pub fn is_running(&self, scope: Scope) -> bool {
        self.pending.contains(&scope)
            || self.running.contains(&scope)
            || self.lrus.iter().any(|(s, _)| *s == scope)
    }

    /// Whether this is a controlling instance addressing the broadcast common
    /// address, whose answers come from every LRU under its own address.
    fn is_broadcast(&self) -> bool {
        self.role == Role::Controlling && self.ca == self.sizes.broadcast_common_address()
    }

    /// The activations sent whose confirmation has not arrived.
    #[must_use]
    pub fn awaiting_confirmation(&self) -> &[Scope] {
        &self.pending
    }

    /// The scopes a controlled station has confirmed under [`ReActivation::Queue`]
    /// and not yet started.
    #[must_use]
    pub fn queued(&self) -> &[Scope] {
        &self.queued
    }

    /// Drops every pending, running and queued interrogation, for either role.
    ///
    /// For the caller's connection loss or reconnect (TS 60870-5-604
    /// 5.4.13.10 starts a fresh general interrogation afterwards) and for its
    /// own reply time-out, neither of which this module observes.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.running.clear();
        self.queued.clear();
        self.awaiting_data = false;
        self.origins.clear();
        self.lrus.clear();
    }

    /// Drops everything outstanding for `scope` (an activation awaiting its
    /// confirmation, a running or queued interrogation, the LRUs of a broadcast
    /// one) and reports whether there was anything. Nothing is sent.
    ///
    /// For the controlling station's own reply time-out on one scope: it
    /// lifts clause 7.4.5's lock on that scope and leaves every other scope
    /// running, where [`Interrogation::reset`] drops them all. A frame of the
    /// abandoned scope that still arrives is no longer expected.
    pub fn abandon(&mut self, scope: Scope) -> bool {
        let had = self.is_running(scope) || self.queued.contains(&scope);
        self.pending.retain(|s| *s != scope);
        self.running.retain(|s| *s != scope);
        self.queued.retain(|s| *s != scope);
        self.origins.retain(|(s, _)| *s != scope);
        self.lrus.retain(|(s, _)| *s != scope);
        if self.running.is_empty() {
            self.awaiting_data = false;
        }
        had
    }

    /// The controlling station's activation of `scope`, as the frame to send.
    ///
    /// An identical interrogation is refused while one is running (clause
    /// 7.4.5's lock); a different scope is not, because the clause locks only
    /// the identical one. [`SecondActivation::Allowed`] is the configuration
    /// that sends the second one anyway.
    ///
    /// # Errors
    ///
    /// [`GiError::WrongRole`] on a controlled instance,
    /// [`GiError::GroupOutOfRange`] for a group outside `1..=16`,
    /// [`GiError::AlreadyRunning`] for an identical interrogation under the
    /// lock, and [`GiError::Layout`] when the frame cannot be built.
    pub fn request(&mut self, scope: Scope) -> Result<Vec<u8>, GiError> {
        if self.role != Role::Controlling {
            return Err(GiError::WrongRole);
        }
        if let Scope::Group(group) = scope
            && !scope.is_valid()
        {
            return Err(GiError::GroupOutOfRange { group });
        }
        if self.second == SecondActivation::Locked && self.is_running(scope) {
            return Err(GiError::AlreadyRunning { scope });
        }
        let frame = request_with(scope, self.ca, self.org, self.sizes)?;
        // One entry per activation: with [`SecondActivation::Allowed`] the same
        // scope can be in flight twice, and each gets its own confirmation.
        self.pending.push(scope);
        Ok(frame)
    }

    /// The controlling station's deactivation of `scope`.
    ///
    /// The scope stays running until the other station's confirmation arrives:
    /// nothing here is cleared, because a deactivation that was never answered
    /// leaves the interrogation running.
    ///
    /// # Errors
    ///
    /// [`GiError::WrongRole`] on a controlled instance, and [`GiError::Layout`]
    /// when the frame cannot be built.
    pub fn deactivate(&mut self, scope: Scope) -> Result<Vec<u8>, GiError> {
        if self.role != Role::Controlling {
            return Err(GiError::WrongRole);
        }
        Ok(deactivation_with(scope, self.ca, self.org, self.sizes)?)
    }

    /// The controlling station's decision for one received ASDU.
    ///
    /// Clause 7.2.3's discard rule runs first, exactly as it does in
    /// [`crate::init::on_asdu`]; a `C_IC_NA_1` whose cause is not one of the
    /// responses of figure 72's monitor-direction list is
    /// [`Reaction::Other`]. The returned [`Outcome::send`] is always empty.
    ///
    /// Every one of Table 17's three re-activation options is accepted here,
    /// because the controlled station chooses the option: a positive
    /// confirmation starts the scope, a negative one settles the activation and
    /// leaves the scope repeatable, and an object or a termination for a scope
    /// that is not running is [`Reaction::Other`]. 5-101 clause 7.4.5 closes the
    /// procedure with `C_IC ACTTERM` after the scope's data, so this crate
    /// treats a later object as no longer belonging to it.
    ///
    /// A cause 44–47 mirror of an activation still awaiting its confirmation
    /// settles it like a negative confirmation ([`Reaction::Refused`]).
    ///
    /// An instance whose common address is the **broadcast** `FF`/`FFFF`
    /// follows every LRU separately. 5-101 clause 7.4.5 (PDF page index 124):
    /// *"When issuing a station interrogation command to a controlled station
    /// using the common address FF or FFFF (request of all), ACTCON, ACTTERM and
    /// the interrogated information objects are returned with the specific
    /// common addresses of the LRUs in exactly the same manner as if they were
    /// initiated by a station interrogation command issued to the specific
    /// LRU."* The activation stays in flight after the first confirmation, so
    /// each LRU's positive `ACTCON` starts that LRU's procedure, its objects
    /// belong to it and its `ACTTERM` ends it (TS 60870-5-604 5.4.17.10, index
    /// 65). Objects or a termination from an LRU that has not confirmed
    /// positively are [`Reaction::Other`]. The broadcast is over once every LRU that confirmed has terminated.
    /// The number of LRUs is not on the wire: a confirmation after that point
    /// is [`Reaction::Other`], and an activation no LRU ever confirms stays in
    /// flight until the caller's reply time-out calls [`Interrogation::reset`].
    /// Which LRU addresses exist is the caller's [`Known`].
    ///
    /// # Errors
    ///
    /// [`GiError::WrongRole`] on a controlled instance, and [`GiError::Layout`]
    /// when the header, or the qualifier of a `C_IC_NA_1` answer, cannot be
    /// parsed.
    pub fn on_response(&mut self, asdu: &[u8], known: &Known) -> Result<Outcome, GiError> {
        if self.role != Role::Controlling {
            return Err(GiError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if header.type_id == TYPE_ID && is_mirror(&header) {
            // The peer refused an activation still in flight: settle it, or
            // the lock would refuse that scope forever.
            if let Some(scope) = scope_of(asdu, self.sizes).ok().flatten()
                && remove_one(&mut self.pending, &scope)
            {
                return Ok(Outcome {
                    reaction: Reaction::Refused {
                        scope: Some(scope),
                        cause: header.cause,
                    },
                    send: Vec::new(),
                });
            }
        }
        if let Some(reason) = discard_reason(&header, known) {
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        // The frame's own type decides which family it belongs to: the three
        // answers to the command (ACTCON, ACTTERM, DEACTCON) are `C_IC_NA_1`
        // frames carrying the qualifier of interrogation, while the objects of
        // the response are the application's own monitor types and are
        // recognised by their cause of transmission alone. Their type is not
        // checked on this side.
        let reaction = match (header.type_id == TYPE_ID, header.cause) {
            (true, Cause::ActivationCon) => self.confirmed(asdu, &header)?,
            (false, Cause::InterrogatedByStation) => {
                self.reporting(Scope::Station, header.common_address)
            }
            (false, Cause::InterrogatedByGroup(n)) => {
                self.reporting(Scope::group(n), header.common_address)
            }
            (true, Cause::ActivationTermination) => self.terminated(asdu, &header)?,
            (true, Cause::DeactivationCon) => {
                let Some(scope) = scope_of(asdu, self.sizes)? else {
                    return Ok(other());
                };
                if !self.is_running(scope) {
                    return Ok(other());
                }
                // A negative one clears the scope too: this module's
                // controlled role sends it only when the scope is not running.
                self.running.retain(|s| *s != scope);
                self.pending.retain(|s| *s != scope);
                self.lrus.retain(|(s, _)| *s != scope);
                Reaction::DeactivationConfirmed {
                    scope,
                    negative: header.negative,
                }
            }
            _ => Reaction::Other,
        };
        Ok(Outcome {
            reaction,
            send: Vec::new(),
        })
    }

    /// The controlling station's reaction to a `C_IC ACTCON` (see
    /// [`Interrogation::on_response`]).
    fn confirmed(&mut self, asdu: &[u8], header: &Header) -> Result<Reaction, GiError> {
        let Some(scope) = scope_of(asdu, self.sizes)? else {
            return Ok(Reaction::Other);
        };
        if !self.is_running(scope) {
            return Ok(Reaction::Other);
        }
        if self.is_broadcast() {
            let lru = (scope, header.common_address);
            if !self.pending.contains(&scope) {
                return Ok(Reaction::Other);
            }
            if !header.negative && !self.lrus.contains(&lru) {
                self.lrus.push(lru);
            }
            return Ok(Reaction::ActivationConfirmed {
                scope,
                negative: header.negative,
            });
        }
        let answered = remove_one(&mut self.pending, &scope);
        if header.negative {
            // "the station interrogation command may be repeated": a
            // negative confirmation settles the activation in flight
            // and starts nothing. It cannot stop a procedure that is
            // already running (option 1 answers with this same frame
            // while the first GI continues), so `running` is untouched;
            // only a termination or a deactivation clears it.
        } else {
            // Counted, not deduplicated: every positive confirmation
            // is matched by one termination in all three options of
            // Table 17 (option 2 terminates the first before
            // confirming the second), so option 3's second
            // interrogation outlives the first one's termination.
            // Only a confirmation that answers an activation of ours
            // counts: one `C_IC ACT` is one procedure (TS 60870-5-604
            // Table 17: "A running GI means that the controlling
            // station has not received the C_IC_ACTTERM after it has
            // sent a C_IC_ACT"), so a repeated confirmation opens none.
            if answered {
                self.running.push(scope);
            }
        }
        Ok(Reaction::ActivationConfirmed {
            scope,
            negative: header.negative,
        })
    }

    /// The controlling station's reaction to a `C_IC ACTTERM` (see
    /// [`Interrogation::on_response`]).
    fn terminated(&mut self, asdu: &[u8], header: &Header) -> Result<Reaction, GiError> {
        let Some(scope) = scope_of(asdu, self.sizes)? else {
            return Ok(Reaction::Other);
        };
        if !self.is_running(scope) {
            return Ok(Reaction::Other);
        }
        if self.is_broadcast() {
            // One LRU's procedure ends; the broadcast ends with the
            // last LRU that confirmed.
            let lru = (scope, header.common_address);
            if !remove_one(&mut self.lrus, &lru) {
                return Ok(Reaction::Other);
            }
            if !self.lrus.iter().any(|(s, _)| *s == scope) {
                remove_one(&mut self.pending, &scope);
            }
            return Ok(Reaction::Terminated { scope });
        }
        // The same definition: once the termination is received the
        // procedure is over, also when it overtook its confirmation.
        if !remove_one(&mut self.running, &scope) {
            remove_one(&mut self.pending, &scope);
        }
        Ok(Reaction::Terminated { scope })
    }

    /// Whether one object of `scope` from `common_address` is ours to report:
    /// the procedure has to be running, so the rule that the responses end at
    /// the termination lives in this one predicate. Under a broadcast it is
    /// that LRU's procedure: an LRU sends its `ACTCON` before its objects
    /// (clause 7.4.5), so one that has not confirmed positively reports none.
    fn reporting(&self, scope: Scope, common_address: u16) -> Reaction {
        let running = if self.is_broadcast() {
            self.lrus.contains(&(scope, common_address))
        } else {
            self.is_running(scope)
        };
        if running {
            Reaction::Interrogated { scope }
        } else {
            Reaction::Other
        }
    }

    /// The controlled station's decision for one received ASDU, with its own
    /// data as the source of a response.
    ///
    /// A positively confirmed activation (`[actcon]` in [`Outcome::send`]) leaves
    /// the scope *running* but does not yet produce its data: the caller asks
    /// [`Interrogation::interrogated`] for it, so a station whose response does
    /// not fit one window releases it under its own flow control, and then
    /// [`Interrogation::complete`] ends the procedure. That is what makes
    /// [`ReActivation`]'s three options observable at all: option 3's second
    /// interrogation is confirmed *while* the first is still running.
    ///
    /// A frame with a field the caller's [`Known`] does not know is mirrored
    /// ([`Reaction::Refused`]), never silently dropped. A deactivation of a
    /// scope neither running nor queued is answered with a negative `DEACTCON`.
    ///
    /// # Errors
    ///
    /// [`GiError::WrongRole`] on a controlling instance, and [`GiError::Layout`]
    /// when the header or the command's qualifier cannot be parsed, or an
    /// answer cannot be built.
    pub fn on_request(
        &mut self,
        asdu: &[u8],
        known: &Known,
        data: &dyn DataSource,
    ) -> Result<Outcome, GiError> {
        if self.role != Role::Controlled {
            return Err(GiError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if let Some(reason) = discard_reason(&header, known) {
            if let Discard::Unspecified(which) = reason {
                // Clause 7.2.3: a control-direction field the station does not
                // know is mirrored with P/N = 1 and the class's cause.
                let scope = if header.type_id == TYPE_ID {
                    scope_of(asdu, self.sizes).ok().flatten()
                } else {
                    None
                };
                return Ok(Outcome {
                    reaction: Reaction::Refused {
                        scope,
                        cause: which.cause(),
                    },
                    send: vec![mirror_frame(&header, asdu, which, self.ca, self.sizes)],
                });
            }
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        if header.type_id != TYPE_ID {
            return Ok(other());
        }
        match header.cause {
            Cause::Activation => self.activated(asdu, &header, data),
            Cause::Deactivation => {
                let Some(scope) = scope_of(asdu, self.sizes)? else {
                    return Ok(other());
                };
                let current = self.running.first() == Some(&scope);
                let queued = self.queued.contains(&scope);
                // Nothing of this scope to stop: a negative confirmation that
                // changes no state, as for an activation that is not ready.
                let negative = !current && !queued;
                self.queued.retain(|s| *s != scope);
                if !negative {
                    self.origins.retain(|(s, _)| *s != scope);
                }
                if current {
                    self.running.clear();
                    self.awaiting_data = false;
                    // Option 3's queued interrogation was confirmed already;
                    // it becomes the running one.
                    if !self.queued.is_empty() {
                        self.running.push(self.queued.remove(0));
                        self.awaiting_data = true;
                    }
                }
                Ok(Outcome {
                    reaction: Reaction::DeactivationConfirmed { scope, negative },
                    send: vec![self.deactivation_confirmation(
                        scope,
                        negative,
                        header.originator,
                    )?],
                })
            }
            _ => Ok(other()),
        }
    }

    /// The controlled station's answer to a `C_IC ACT` (see
    /// [`Interrogation::on_request`]).
    fn activated(
        &mut self,
        asdu: &[u8],
        header: &Header,
        data: &dyn DataSource,
    ) -> Result<Outcome, GiError> {
        let Some(scope) = scope_of(asdu, self.sizes)? else {
            return Ok(other());
        };
        match self.running.first().copied() {
            // A second activation while one runs: TS 60870-5-604
            // Table 17's note, one branch per option.
            Some(current) => match self.policy {
                ReActivation::Continue => self.confirmation_outcome(scope, true, header.originator),
                ReActivation::Restart => {
                    // "the current GI is stopped": indicated with the
                    // termination that procedure owed, then the second
                    // activation is confirmed positively.
                    let stopped = self.terminate(current)?;
                    self.running.clear();
                    self.running.push(scope);
                    self.awaiting_data = true;
                    self.origins.push((scope, header.originator));
                    let confirmed = self.confirmation(scope, false, header.originator)?;
                    Ok(Outcome {
                        reaction: Reaction::ActivationConfirmed {
                            scope,
                            negative: false,
                        },
                        send: vec![stopped, confirmed],
                    })
                }
                ReActivation::Queue => {
                    // "mirrors the second Interrogation Command with
                    // COT = 7, C_IC_ACTCON"; its data waits for the
                    // first procedure's termination.
                    let confirmed = self.confirmation(scope, false, header.originator)?;
                    self.queued.push(scope);
                    self.origins.push((scope, header.originator));
                    Ok(Outcome {
                        reaction: Reaction::ActivationConfirmed {
                            scope,
                            negative: false,
                        },
                        send: vec![confirmed],
                    })
                }
            },
            None if data.ready(scope) => {
                self.running.push(scope);
                self.awaiting_data = true;
                self.origins.push((scope, header.originator));
                self.confirmation_outcome(scope, false, header.originator)
            }
            // Not ready: a negative confirmation changes no state, so
            // "the station interrogation command may be repeated".
            None => self.confirmation_outcome(scope, true, header.originator),
        }
    }

    /// The frames of the running interrogation's data, which the controlled
    /// station sends before its termination.
    ///
    /// Every ASDU comes from the [`DataSource`] and is checked here: its cause
    /// of transmission must be the running scope's, and [`is_interrogated`]
    /// must hold for its type. Each frame echoes the activation's originator
    /// address (5-101 clause 7.2.3).
    ///
    /// # Errors
    ///
    /// [`GiError::WrongRole`] on a controlling instance,
    /// [`GiError::NotRunning`] when no interrogation's data is owed, and
    /// [`GiError::NotInterrogatedType`], [`GiError::WrongCause`] or
    /// [`GiError::Layout`] when an ASDU from the source fails the checks.
    pub fn interrogated(&mut self, data: &dyn DataSource) -> Result<Vec<Vec<u8>>, GiError> {
        if self.role != Role::Controlled {
            return Err(GiError::WrongRole);
        }
        let scope = self
            .running
            .first()
            .copied()
            .filter(|_| self.awaiting_data)
            .ok_or(GiError::NotRunning)?;
        let frames = collect(data, scope, self.sizes, self.origin(scope))?;
        self.awaiting_data = false;
        Ok(frames)
    }

    /// Ends the running interrogation.
    ///
    /// The frames are its data, if [`Interrogation::interrogated`] has not
    /// produced it yet, then the termination (`C_IC ACTTERM`, cause
    /// 10) and, where [`ReActivation::Queue`] left one waiting, the queued
    /// interrogation's data and **its own** termination.
    ///
    /// The data always comes before the termination: 5-101 clause 7.4.5 ends
    /// the procedure with the termination after the interrogated objects, so a
    /// termination without them would tell the controlling station it has
    /// everything when it has nothing. If the [`DataSource`] fails, the error
    /// is returned and nothing has changed, so the call can be repeated.
    ///
    /// Table 17's option 3 spells out only the objects that follow the first
    /// procedure's termination; the second `C_IC ACTTERM` is here because the
    /// queued procedure is a general interrogation in its own right, and
    /// TS 60870-5-604 clause 5.4.17.1 closes every one of them with
    /// `C_IC ACTTERM` after its data is sent. Without it the controlling
    /// station would keep the finished procedure running.
    ///
    /// # Errors
    ///
    /// [`GiError::WrongRole`] on a controlling instance,
    /// [`GiError::NotRunning`] when no interrogation is running, the errors of
    /// [`Interrogation::interrogated`] for the data, and [`GiError::Layout`]
    /// when a termination cannot be built.
    pub fn complete(&mut self, data: &dyn DataSource) -> Result<Vec<Vec<u8>>, GiError> {
        if self.role != Role::Controlled {
            return Err(GiError::WrongRole);
        }
        let current = self.running.first().copied().ok_or(GiError::NotRunning)?;
        let mut frames = if self.awaiting_data {
            collect(data, current, self.sizes, self.origin(current))?
        } else {
            Vec::new()
        };
        frames.push(self.terminate(current)?);
        self.running.clear();
        self.awaiting_data = false;
        // "After activation termination (COT=10) the Information Objects that
        // are part of the second initiated GI are sent with the correct COT."
        while let Some(next) = self.queued.first().copied() {
            self.queued.remove(0);
            frames.extend(collect(data, next, self.sizes, self.origin(next))?);
            frames.push(self.terminate(next)?);
        }
        Ok(frames)
    }

    /// The originator address the oldest running activation of `scope` came
    /// with, or this station's own when none is recorded.
    fn origin(&self, scope: Scope) -> u8 {
        self.origins
            .iter()
            .find(|(s, _)| *s == scope)
            .map_or(self.org, |(_, org)| *org)
    }

    /// The confirmation of `scope` with `P/N` as given, echoing `originator`.
    fn confirmation(
        &self,
        scope: Scope,
        negative: bool,
        originator: u8,
    ) -> Result<Vec<u8>, GiError> {
        Ok(frame(
            CAUSE_ACTIVATION_CON,
            negative,
            scope,
            self.ca,
            originator,
            self.sizes,
        )?)
    }

    /// The termination of `scope`'s oldest procedure (`C_IC ACTTERM`), echoing
    /// its activation's originator, which it retires.
    fn terminate(&mut self, scope: Scope) -> Result<Vec<u8>, GiError> {
        let originator = self.origin(scope);
        if let Some(at) = self.origins.iter().position(|(s, _)| *s == scope) {
            self.origins.remove(at);
        }
        Ok(frame(
            CAUSE_ACTIVATION_TERM,
            false,
            scope,
            self.ca,
            originator,
            self.sizes,
        )?)
    }

    /// The deactivation's confirmation (`C_IC DEACTCON`), echoing `originator`.
    fn deactivation_confirmation(
        &self,
        scope: Scope,
        negative: bool,
        originator: u8,
    ) -> Result<Vec<u8>, GiError> {
        Ok(frame(
            CAUSE_DEACTIVATION_CON,
            negative,
            scope,
            self.ca,
            originator,
            self.sizes,
        )?)
    }

    /// The whole answer to an activation: the confirmation, and nothing else.
    /// The data follows from [`Interrogation::interrogated`].
    fn confirmation_outcome(
        &self,
        scope: Scope,
        negative: bool,
        originator: u8,
    ) -> Result<Outcome, GiError> {
        Ok(Outcome {
            reaction: Reaction::ActivationConfirmed { scope, negative },
            send: vec![self.confirmation(scope, negative, originator)?],
        })
    }
}

/// The reaction for an ASDU this procedure does not own.
const fn other() -> Outcome {
    Outcome {
        reaction: Reaction::Other,
        send: Vec::new(),
    }
}

/// Removes one occurrence of `scope`, reporting whether there was one.
fn remove_one<T: PartialEq>(scopes: &mut Vec<T>, scope: &T) -> bool {
    scopes
        .iter()
        .position(|s| s == scope)
        .map(|at| scopes.remove(at))
        .is_some()
}

/// The scope of a received type-100 ASDU's qualifier, or `None` when clause
/// 7.2.6.22 leaves the value reserved or private.
fn scope_of(asdu: &[u8], sizes: AddressSizes) -> Result<Option<Scope>, GiError> {
    let objects = decode_asdu_with::<CIcNa1>(asdu, sizes)?;
    Ok(objects
        .first()
        .and_then(|object| Scope::from_qoi(object.value.qoi)))
}

/// The data one scope's procedure reports, checked against clause 7.4.5 before
/// it can reach the wire: every ASDU must carry that scope's own cause of
/// transmission, and [`is_interrogated`] must hold for its type, so every
/// time-tagged type is refused here.
fn collect(
    data: &dyn DataSource,
    scope: Scope,
    sizes: AddressSizes,
    originator: u8,
) -> Result<Vec<Vec<u8>>, GiError> {
    let mut raw = Vec::new();
    data.interrogated(scope, &mut raw);
    let mut frames = Vec::with_capacity(raw.len());
    for asdu in raw {
        let header = Header::parse_with(&asdu, sizes)?;
        if !is_interrogated(header.type_id) {
            return Err(GiError::NotInterrogatedType {
                type_id: header.type_id,
            });
        }
        if header.cause != scope.cause() {
            return Err(GiError::WrongCause {
                expected: scope.cause(),
                got: header.cause,
            });
        }
        // The data answers the request too, so it echoes its originator.
        frames.push(crate::asdu::with_originator(&asdu, originator, sizes)?);
    }
    Ok(frames)
}
