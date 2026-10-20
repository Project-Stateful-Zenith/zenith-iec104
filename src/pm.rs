//! Parameter loading: the parameters of measured values (`P_ME_NA_1`,
//! `P_ME_NB_1`, `P_ME_NC_1`, types 110–112) with their `QPM`, and the parameter
//! activation (`P_AC_NA_1`, type 113) with its `QPA`.
//!
//! # The procedure: two round trips, no termination
//!
//! 5-104 clause **7.9** (PDF page index 70, printed page 69) is headed
//! *"Parameter loading (6.10 of IEC 60870-5-5)"* and its table is:
//!
//! | Application service | ASDU label |
//! | --- | --- |
//! | `A_PARAM.req` / `.ind` | `P_ME ACT` |
//! | `A_PARAM.res` / `.con` | `P_ME ACTCON` |
//! | `A_PACTIV.req` / `.ind` | `P_AC ACT` |
//! | `A_PACTIV.res` / `.con` | `P_AC ACTCON` |
//! | `A_LCPACH.req` / `.ind` | `P_ME SPONT` |
//!
//! `P_ME` and `P_AC` are families of type identifications, as `C_SC` is in
//! clause 7.7: `P_ME` is the three parameter types of 5-101 cl.7.3.5.1–.3 and
//! `P_AC` is `P_AC_NA_1`, cl.7.3.5.4 ([`Family`]). The procedure has two round
//! trips (load a parameter, activate a parameter) plus the monitor-direction
//! `P_ME SPONT` of a local parameter change. There is no termination: none of
//! the four types' figures lists an `ACTTERM`, unlike [`crate::gi`] and
//! [`crate::ct`].
//!
//! # The confirmation carries the value now in operation
//!
//! 5-101 clause **7.4.9** (PDF page index 130, printed page 129) selects the
//! profile's options: single parameters are loaded with `P_ME` ACT and ACTCON;
//! each one is checked for feasibility, accepted if its value is valid, and
//! then activated at once. Whether the load is accepted or refused, the value
//! the `P_ME` ACTCON carries is the value (new or old) that is in operation
//! afterwards. TS 60870-5-604 Table 21 (PDF page index 82, printed page 81)
//! makes it a test: in 5.4.21.1 the controlled station mirrors the ASDU with
//! cause 7, positive, carrying the value now in operation, which is the new
//! one; in 5.4.21.10 it mirrors it with cause 7, negative, carrying the old
//! value still in operation rather than the one it could not activate.
//!
//! [`confirmation`] therefore takes the value as an argument: the crate has no
//! process image, and keeping parameter state would make it an application
//! database.
//!
//! One feasibility rule is the standard's own. TS 60870-5-604 Table 21,
//! 5.4.21.10 (PDF page index 82): a negative threshold value or smoothing
//! factor is always invalid and is never activated. A received `P_ME` load whose `KPA` is `<1>` (threshold value) or
//! `<2>` (smoothing factor) with a negative value is therefore
//! [`Reaction::Infeasible`] ([`ParameterValue::is_infeasible_negative`]), with
//! an empty [`Outcome::send`]: the negative answer carries the old value, which
//! the crate does not hold. The caller answers with [`ParameterLoading::refuse`]
//! and the value now in operation. The limits `KPA = <3>`/`<4>` have no sign
//! rule and load normally.
//!
//! The same clause makes two more selections. The first, that `P_AC`
//! ACT/ACTCON and DEACT/DEACTCON occur only with `QPA := <3>` (act/deact of
//! persistent cyclic or periodic transmission of the addressed object), is
//! enforced on the `QPA` this station sends ([`PmError::QpaNotUsed`]). The
//! second, that the profile does not use `P_ME` SPONT for a local parameter
//! change, is a per-station setting, [`LocalChange`], rather than a silence.
//!
//! # The confirmation is a mirror
//!
//! 5-104 Table 5, *"Parameter in control direction"* (PDF page index 52,
//! printed page 51), marks `<110>`, `<111>`, `<112>` and `<113>` as `CON`, so
//! Table 2's NOTE (PDF page index 50, printed page 49) applies: a control
//! direction ASDU marked `CON` is a confirmed service, and the monitor
//! direction may send it back mirrored with another cause of transmission.
//! The `ACTCON` is the same type identification, information
//! object address and element with cause 7 (cause 9 for a `P_AC_NA_1`
//! deactivation), and `P/N = 1` on a refusal; a negative `P_ME` confirmation
//! carries the value now in operation as its element. The answer is rebuilt
//! from the decoded fields, so apart from the header it matches the received
//! frame; only a frame with no decodable parameter object is copied octet for
//! octet.
//!
//! # The per-type cause lists
//!
//! 5-101 cl.7.3.5.1–.4 prints one figure per type with its whole cause list.
//! Figure 79 (`P_ME_NA_1`, index 110), figure 80 (`P_ME_NB_1`, index 111) and
//! figure 81 (`P_ME_NC_1`, index 112) list the same causes: `<6>` activation
//! in the control direction; in the monitor direction `<7>` activation
//! confirmation, `<20>` (station interrogation), `<21>` to `<36>` (group 1 to
//! 16 interrogation) and `<44>` to `<47>`. There is no `<8>` and no `<9>`, so a
//! parameter of measured values cannot be deactivated
//! ([`PmError::DeactivationNotDefined`]). Figure 82 (`P_AC_NA_1`, index 113)
//! adds the deactivation: `<6>` and `<8>` in the control direction, `<7>` and
//! `<9>` (activation and deactivation confirmation) in the monitor direction,
//! and no interrogation cause.
//!
//! [`Family::is_control_cause`] and [`Family::is_monitor_cause`] are those
//! lists, plus **`<3>` spontaneous** for the three `P_ME` types. Figures 79–81
//! omit it because the 101 selection does not use the service, but 104 cl.7.9's
//! table names the frame (`A_LCPACH`, `P_ME SPONT`), and a label's second word
//! is its cause of transmission. Whether a station uses it is [`LocalChange`].
//! The builders refuse a cause outside these lists
//! ([`PmError::CauseNotDefined`]) and [`ParameterLoading::on_response`] does not
//! classify one, so the module never accepts on reception what it would refuse
//! to build.
//!
//! # The two qualifiers
//!
//! `QPM` is 5-101 cl.7.2.6.24 (PDF page index 54, printed page 53, continuing on
//! index 55): `QPM := CP8{KPA,LPC,POP}` with `KPA := UI6[1..6]<0..63>`, *"kind of
//! parameter"*: `<0>` *not used*, `<1>` threshold value, `<2>` smoothing
//! factor, `<3>` low limit for transmission of measured values, `<4>` high
//! limit, `<5..31>` reserved for this companion standard (the compatible
//! range), `<32..63>` reserved for special use (the private range). `LPC` is
//! the local parameter change and `POP` the parameter operation; the clause
//! does not use either and requires both to be zero. [`PmError::KpaNotUsed`] and [`PmError::QpmNotZeroed`]
//! apply those rules to the loads and announcements this crate builds
//! ([`load`], [`announcement`]). A confirmation ([`confirmation`],
//! [`ParameterLoading::refuse`]) carries the value the caller passes without
//! that check, and a mirror of a received frame reproduces the bits the peer
//! sent. The clause also requires every parameter to have its own information
//! object address, unique within the system.
//!
//! `QPA` is cl.7.2.6.25 (index 55): `<0>` not used, `<1>` act/deact of the
//! previously loaded parameters (object address = 0), `<2>` act/deact of the
//! parameter of the addressed object, `<3>` act/deact of persistent cyclic or
//! periodic transmission of the addressed object, `<4..127>` reserved,
//! `<128..255>` private. A footnote marks `<1>` and `<2>` as unused by this
//! companion standard, kept for a future extension of parameter loading. TS
//! 60870-5-604 5.4.21.15 (PDF page index 82) makes that a test: the controlled
//! station refuses a received `P_AC_NA_1` (ASDU 113) whose `QPA` is 1 or 2 by
//! mirroring it with `P/N = 1`, and with cause 44 too if it supports that
//! cause. The refusal is therefore a frame, not an error:
//! [`ParameterLoading::on_request`] answers with cause 7 (or 9) and `P/N = 1`.
//! Because cause 44 is conditional on support, a
//! station that supports it uses [`unknown_reply`] with
//! [`crate::asdu::Unspecified::TypeIdentification`] instead.
//!
//! A `QPA` is a qualifier, not a value in operation, so the negative answer to a
//! `P_AC_NA_1` reproduces the received `QPA` (5.4.21.15's *"the same ASDU"*);
//! see [`ParameterLoading::refuse`].
//!
//! The private range `<128..255>` is accepted on reception and by the builders,
//! although cl.7.4.9 selects `QPA := <3>` only: that selection is about what a
//! station sends, and cl.7.2.6.25 reserves `<128..255>` for special use (the
//! private range), the same reading `KPA`'s private range gets.
//!
//! # The answer echoes the request's originator address
//!
//! 5-101 clause 7.2.3 (PDF page index 38, printed page 37): the source of a
//! command should set its originator address, and the controlled station
//! should return that same originator address in its monitor-direction
//! response. Every answer [`ParameterLoading`]
//! builds (`ACTCON`, `DEACTCON`, the negative confirmation and the 44–47
//! mirror) carries the received frame's originator address and test bit, and
//! the answering station's own common address. The free builders
//! ([`confirmation`], [`deactivation_confirmation`], [`unknown_reply`]) take
//! the originator address and the test bit as arguments.
//!
//! A parameter is never broadcast. TS 60870-5-604 5.4.10.10 (PDF page index 54)
//! permits the global address `<65535>` only with types 100/101/103/105, so
//! every other type at that address, parameters included, are mirrored
//! with `P/N = 1`, whatever the caller's [`Known`] says.
//!
//! # What is left to the caller
//!
//! - Whether the station uses `P_ME SPONT` ([`LocalChange`]).
//! - Whether a parameter value is **feasible**: cl.7.4.9's feasibility and
//!   validity check is the application's,
//!   because the crate has no process image. A caller that will not accept a
//!   received load answers with [`ParameterLoading::refuse`], which writes the
//!   negative confirmation with the value now in operation. The one rule the
//!   standard states itself (a negative threshold or smoothing factor, 604
//!   5.4.21.10) is reported as [`Reaction::Infeasible`], and the caller answers
//!   it the same way.
//! - What the value now in operation is, and which information object addresses
//!   exist (the caller's [`Known`] answers the second).
//! - What a `KPA` in the private range `<32..63>` means: the clause leaves it
//!   for special use, that is, to agreement between the system user and the
//!   vendor (5-101 cl.7.3).
//! - Timing: cl.7.4.9's immediate activation is the application's, and
//!   this module reads no clock and holds no timer.
//!
//! # Example
//!
//! A controlled station that accepts a load and confirms it with the value now
//! in operation (the *new* one, 5-101 cl.7.4.9):
//!
//! ```
//! use iec104::asdu::{Cause, Header, Known, Nva, Qpm, TypeId};
//! use iec104::pm::{LocalChange, Parameter, ParameterLoading, ParameterValue, Role, Reaction};
//!
//! let outstation = ParameterLoading::controlled(LocalChange::NotUsed, 12, 0);
//! let controlling = ParameterLoading::controlling(LocalChange::NotUsed, 12, 0);
//! assert_eq!(outstation.role(), Role::Controlled);
//!
//! let parameter = Parameter::new(
//!     0x4001,
//!     ParameterValue::Normalized {
//!         nva: Nva { value: 0x2000 },
//!         qpm: Qpm { kpa: Qpm::THRESHOLD, ..Default::default() },
//!     },
//! );
//!
//! // The load travels in the control direction with cause <6>.
//! let load = controlling.load(&parameter).unwrap();
//! assert_eq!(load[0], TypeId::PMeNa1.to_u8());
//! assert_eq!(Header::parse(&load).unwrap().cause, Cause::Activation);
//!
//! // The outstation answers with the same ASDU and cause <7>.
//! let outcome = outstation.on_request(&load, &Known::EVERYTHING).unwrap();
//! assert_eq!(outcome.send.len(), 1);
//! assert_eq!(
//!     Header::parse(&outcome.send[0]).unwrap().cause,
//!     Cause::ActivationCon
//! );
//! assert_eq!(&outcome.send[0][Header::LEN..], &load[Header::LEN..]);
//!
//! // The controlling station reads the value now in operation out of it.
//! let seen = controlling
//!     .on_response(&outcome.send[0], &Known::EVERYTHING)
//!     .unwrap();
//! match seen.reaction {
//!     Reaction::Confirmed { value, negative, .. } => {
//!         assert_eq!(value, parameter.value);
//!         assert!(!negative);
//!     }
//!     other => panic!("expected a confirmation, got {other:?}"),
//! }
//! ```

use crate::asdu::{
    AddressSizes, AsduError, Cause, Discard, Header, Known, LayoutError, LayoutObject, Nva, PAcNa1,
    PMeNa1, PMeNb1, PMeNc1, Qpa, Qpm, R32, Sva, TypeId, Unspecified, decode_asdu_with,
    discard_reason, encode_asdu_with, is_mirror,
};

/// `<6> activation`: the cause of a load or an activation (figures 79–82's
/// control direction).
pub const CAUSE_ACTIVATION: Cause = Cause::Activation;

/// `<7> activation confirmation`: the cause of the confirmation, positive and
/// negative (figures 79–82's monitor direction; `P/N` tells them apart).
pub const CAUSE_ACTIVATION_CON: Cause = Cause::ActivationCon;

/// `<8> deactivation`: the cause of a `P_AC_NA_1` deactivation. Figure 82 is
/// the only one of the four that lists it.
pub const CAUSE_DEACTIVATION: Cause = Cause::Deactivation;

/// `<9> deactivation confirmation`: the mirror of a deactivation, again
/// `P_AC_NA_1` only.
pub const CAUSE_DEACTIVATION_CON: Cause = Cause::DeactivationCon;

/// `<3> spontaneous`: the cause of the `P_ME SPONT` local parameter change
/// announcement of 5-104 cl.7.9's `A_LCPACH` row.
pub const CAUSE_SPONTANEOUS: Cause = Cause::Spontaneous;

/// The global address of 5-101 cl.7.2.4 for a two-octet common address.
///
/// TS 60870-5-604 5.4.10.10 calls it the *broadcast CASDU*. It is used in the control direction
/// only for the system ASDUs 100 (`C_IC`), 101 (`C_CI`), 103 (`C_CS`) and 105
/// (`C_RP`); a parameter addressed to it is mirrored back with `P/N = 1` and
/// cause 46 instead of being loaded or activated.
#[deprecated(
    note = "the broadcast address depends on the common-address width: use AddressSizes::broadcast_common_address"
)]
pub const BROADCAST_CA: u16 = 0xFFFF;

/// One of the two families of type identifications 5-104 cl.7.9's `P_ME` and
/// `P_AC` labels stand for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `P_ME_NA_1`, `P_ME_NB_1` and `P_ME_NC_1` (110–112): a parameter of
    /// measured values.
    Measured,
    /// `P_AC_NA_1` (113): the activation and deactivation of a parameter.
    Activation,
}

impl Family {
    /// The family `type_id` belongs to, or `None` when it is not one of the
    /// four parameter types (5-101 cl.7.3.5, PDF page indices 110–113).
    #[must_use]
    pub const fn of_type(type_id: TypeId) -> Option<Self> {
        match type_id {
            TypeId::PMeNa1 | TypeId::PMeNb1 | TypeId::PMeNc1 => Some(Self::Measured),
            TypeId::PAcNa1 => Some(Self::Activation),
            _ => None,
        }
    }

    /// Whether the family has a deactivation at all. 5-101 cl.7.3.5's figures
    /// 79–81 list only `<6>` (activation) in the control direction, no `<8>`,
    /// for the three `P_ME` types; figure 82 prints `<6>` **and** `<8>` for
    /// `P_AC_NA_1`.
    #[must_use]
    pub fn has_deactivation(self) -> bool {
        self == Self::Activation
    }

    /// Whether the family's cause list (its figure, 5-101 cl.7.3.5.1–.4) has
    /// `cause` in the **control** direction.
    #[must_use]
    pub fn is_control_cause(self, cause: Cause) -> bool {
        // Match on the octet, not the enum: `Cause::InterrogatedByGroup(n)`
        // above 16 encodes as 37, which no figure lists.
        match cause.to_u8() {
            6 => true,
            8 => self.has_deactivation(),
            _ => false,
        }
    }

    /// Whether the family's cause list has `cause` in the **monitor**
    /// direction.
    ///
    /// The lists are figures 79–82's, plus `<3>` spontaneous for the three
    /// `P_ME` types. Figures 79–81 omit it because 5-101 cl.7.4.9 does not use
    /// the service (`P_ME` SPONT for a local parameter change),
    /// but 5-104 cl.7.9's service table names the frame (`A_LCPACH`,
    /// `P_ME SPONT`), and a label's second word is its cause of transmission. A
    /// station that does not use the service says so with
    /// [`LocalChange::NotUsed`], which is 101's selection.
    #[must_use]
    pub fn is_monitor_cause(self, cause: Cause) -> bool {
        match cause.to_u8() {
            3 | 20..=36 => self == Self::Measured,
            7 | 44..=47 => true,
            9 => self.has_deactivation(),
            _ => false,
        }
    }

    /// Whether the family's figure lists `cause` in either direction.
    #[must_use]
    pub fn allows(self, cause: Cause) -> bool {
        self.is_control_cause(cause) || self.is_monitor_cause(cause)
    }
}

/// The element part of one of the four parameter types, as defined in 5-101
/// cl.7.3.5.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ParameterValue {
    /// `P_ME_NA_1 := CP{…, NVA, QPM}`: a normalized parameter value.
    Normalized {
        /// `NVA`, the normalized value (cl.7.2.6.6).
        nva: Nva,
        /// `QPM`, the qualifier of parameter of measured values (cl.7.2.6.24).
        qpm: Qpm,
    },
    /// `P_ME_NB_1 := CP{…, SVA, QPM}`: a scaled parameter value.
    Scaled {
        /// `SVA`, the scaled value (cl.7.2.6.7).
        sva: Sva,
        /// `QPM`, the qualifier of parameter of measured values (cl.7.2.6.24).
        qpm: Qpm,
    },
    /// `P_ME_NC_1 := CP{…, IEEE STD 754, QPM}`: a short floating point
    /// parameter value.
    Float {
        /// `R32`, the short floating point number (cl.7.2.6.8).
        r32: R32,
        /// `QPM`, the qualifier of parameter of measured values (cl.7.2.6.24).
        qpm: Qpm,
    },
    /// `P_AC_NA_1 := CP{…, QPA}`: the parameter activation qualifier, the
    /// whole element of the type.
    Activation {
        /// `QPA`, the qualifier of parameter activation (cl.7.2.6.25).
        qpa: Qpa,
    },
}

impl ParameterValue {
    /// The type identification this value is the element of.
    #[must_use]
    pub const fn type_id(&self) -> TypeId {
        match self {
            Self::Normalized { .. } => TypeId::PMeNa1,
            Self::Scaled { .. } => TypeId::PMeNb1,
            Self::Float { .. } => TypeId::PMeNc1,
            Self::Activation { .. } => TypeId::PAcNa1,
        }
    }

    /// Which of the two families the value belongs to.
    #[must_use]
    pub const fn family(&self) -> Family {
        match self {
            Self::Activation { .. } => Family::Activation,
            _ => Family::Measured,
        }
    }

    /// The `QPM` of a parameter of measured values, or `None` for
    /// `P_AC_NA_1`'s `QPA`.
    #[must_use]
    pub const fn qpm(&self) -> Option<Qpm> {
        match self {
            Self::Normalized { qpm, .. } | Self::Scaled { qpm, .. } | Self::Float { qpm, .. } => {
                Some(*qpm)
            }
            Self::Activation { .. } => None,
        }
    }

    /// The `QPA` of a parameter activation, or `None` for a `P_ME` value.
    #[must_use]
    pub const fn qpa(&self) -> Option<Qpa> {
        match self {
            Self::Activation { qpa } => Some(*qpa),
            _ => None,
        }
    }

    /// Whether the standard forbids this value outright: a **negative**
    /// threshold value (`KPA = <1>`) or smoothing factor (`KPA = <2>`).
    ///
    /// TS 60870-5-604 Table 21, 5.4.21.10 (PDF page index 82): a negative
    /// threshold value or smoothing factor is always invalid and is never
    /// activated. The rule names those two
    /// kinds only, so a negative value of any other `KPA` (the limits `<3>`/`<4>`
    /// or the private range) returns `false`.
    #[must_use]
    pub fn is_infeasible_negative(&self) -> bool {
        let negative = match self {
            Self::Normalized { nva, .. } => nva.value < 0,
            Self::Scaled { sva, .. } => sva.value < 0,
            Self::Float { r32, .. } => r32.value < 0.0,
            Self::Activation { .. } => false,
        };
        negative
            && matches!(
                self.qpm().map(|qpm| qpm.kpa),
                Some(Qpm::THRESHOLD | Qpm::SMOOTHING_FACTOR)
            )
    }
}

/// One parameter ASDU's whole information object: the address the parameter is
/// known by and its element.
///
/// 5-101 cl.7.2.6.24 requires every parameter to have its own information
/// object address, unique within the system. The crate carries the address and
/// does not check its uniqueness.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Parameter {
    /// The information object address the parameter is defined by.
    pub ioa: u32,
    /// The element the type carries.
    pub value: ParameterValue,
}

impl Parameter {
    /// The parameter at `ioa` with the element `value`.
    #[must_use]
    pub const fn new(ioa: u32, value: ParameterValue) -> Self {
        Self { ioa, value }
    }

    /// The type identification of this parameter's value.
    #[must_use]
    pub const fn type_id(&self) -> TypeId {
        self.value.type_id()
    }

    /// Which family this parameter belongs to.
    #[must_use]
    pub const fn family(&self) -> Family {
        self.value.family()
    }

    /// The value's `QPM`, for a parameter of measured values.
    #[must_use]
    pub const fn qpm(&self) -> Option<Qpm> {
        self.value.qpm()
    }

    /// The value's `QPA`, for a parameter activation.
    #[must_use]
    pub const fn qpa(&self) -> Option<Qpa> {
        self.value.qpa()
    }
}

/// Which side of the procedure a [`ParameterLoading`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The controlling station: loads a parameter and activates it.
    Controlling,
    /// The controlled station: mirrors the load, performs the activation.
    Controlled,
}

/// Whether the station uses the `P_ME SPONT` announcement of a local parameter
/// change.
///
/// 5-101 cl.7.4.9 (PDF page index 130, printed page 129) selects the options:
/// the profile does not use `P_ME` SPONT for a local parameter change. The service exists in
/// 5-104 cl.7.9's table (`A_LCPACH.req`/`.ind`, `P_ME SPONT`), so a station that
/// uses it says so here rather than being silent about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalChange {
    /// The 101 selection: the station neither announces a local parameter
    /// change nor answers one.
    NotUsed,
    /// The station uses `A_LCPACH` in both directions.
    Used,
}

/// What one frame of the procedure means, from the point of view of the role
/// that received it.
#[derive(Debug, Clone, PartialEq)]
pub enum Reaction {
    /// A load arrived and was accepted: a `P_ME ACT` in the control direction
    /// with a parameter of measured values, or the positive answer this station
    /// sent to one.
    Loaded {
        /// The information object address of the parameter.
        ioa: u32,
        /// The value the frame carried.
        value: ParameterValue,
    },
    /// The confirmation of a load or an activation arrived. The value in the
    /// frame is the value now in operation: the new one when `negative` is
    /// false, the old one when it is true (5-101 cl.7.4.9 and TS 60870-5-604
    /// Table 21's 5.4.21.1/.10).
    Confirmed {
        /// The information object address of the parameter.
        ioa: u32,
        /// The value the frame carried: the one in operation.
        value: ParameterValue,
        /// `P/N = 1`: the negative confirmation (`ACTCONneg`).
        negative: bool,
    },
    /// A parameter activation arrived (`P_AC ACT`) or was answered.
    Activated {
        /// The information object address of the parameter.
        ioa: u32,
        /// The qualifier the frame carried.
        qpa: Qpa,
    },
    /// A parameter deactivation arrived (`P_AC DEACT`, cause 8) or was
    /// answered with its cause-9 mirror. Like [`Reaction::Confirmed`], it
    /// carries the `P/N` flag. 5-101 cl.7.2.3 defines the bit without tying it
    /// to a cause: `P/N := BS1[7]`, `<0>` positive and `<1>` negative
    /// confirm. Its prose ties the bit only to confirming an activation the
    /// primary application function requested, but TS 60870-5-604 5.4.21.15
    /// has the station refuse any received `P_AC_NA_1` (ASDU 113) with
    /// `QPA` 1 or 2 by mirroring it with `P/N = 1`, a deactivation included. So a `DEACTCON` with
    /// `negative` true is a deactivation the station refused.
    Deactivated {
        /// The information object address of the parameter.
        ioa: u32,
        /// The qualifier the frame carried.
        qpa: Qpa,
        /// `P/N = 1`: the negative confirmation (`DEACTCONneg`).
        negative: bool,
    },
    /// A load the station must not confirm positively: 5-101 cl.7.4.9's
    /// feasibility check failed on a rule of the standard itself. TS
    /// 60870-5-604 Table 21, 5.4.21.10 (PDF page index 82) treats a negative
    /// threshold value or smoothing factor as always invalid and never
    /// activated, so a negative value of
    /// `KPA = <1>` or `KPA = <2>` is not activated and the answer is an
    /// `ACTCONneg` carrying the **old** value.
    ///
    /// The crate holds no process image and therefore no old value, so this
    /// reaction is returned with an **empty** [`Outcome::send`]: the caller
    /// answers with [`ParameterLoading::refuse`] and the value now in
    /// operation. The low and high limits (`KPA` `<3>`/`<4>`) have no sign rule
    /// and are loaded normally, whatever their sign.
    Infeasible {
        /// The information object address of the parameter.
        ioa: u32,
        /// The value the frame carried, which the standard refuses.
        value: ParameterValue,
    },
    /// The monitor-direction announcement of a local parameter change
    /// (`P_ME SPONT`, cause 3): 5-104 cl.7.9's `A_LCPACH` row, used only by a
    /// station whose [`LocalChange`] is [`LocalChange::Used`] and only on the
    /// three `P_ME` types, whose cause 3 [`Family::is_monitor_cause`] holds
    /// (figure 82 lists no `<3>` for `P_AC_NA_1`).
    Announced {
        /// The information object address of the parameter.
        ioa: u32,
        /// The value the frame carried.
        value: ParameterValue,
    },
    /// A parameter read back by an interrogation: the `P_ME` types' causes
    /// `<20>`–`<36>` (figures 79–81). The cause is the value of it; the caller
    /// builds the same one with [`crate::gi::Scope::cause`].
    Interrogated {
        /// The information object address of the parameter.
        ioa: u32,
        /// The value the frame carried.
        value: ParameterValue,
        /// The cause: `<20>` inrogen, `<21>`–`<36>` inro 1…16.
        cause: Cause,
    },
    /// A refusal: the received ASDU mirrored with `P/N = 1` and `cause`, which
    /// is clause 7.2.3's 44–47 class for a field the station does not know, 7/9
    /// for the `QPA` refusal of TS 60870-5-604 5.4.21.15, or 7 for a load whose
    /// `QPM` is outside 5-101 cl.7.2.6.24's grammar.
    /// [`Outcome::send`] holds the frame. On the controlling side
    /// ([`ParameterLoading::on_response`]) it is the peer's 44–47 mirror of
    /// this station's load or activation, and nothing is sent.
    Refused {
        /// The information object address the received frame addressed.
        ioa: u32,
        /// The cause the mirror carries.
        cause: Cause,
    },
    /// Clause 7.2.3 says this ASDU is discarded and may be logged.
    Discard(Discard),
    /// Not this procedure: the type, the cause or the value says the ASDU
    /// belongs to another one.
    Other,
}

/// What a received ASDU means, and what to send because of it.
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    /// The classification of the received ASDU.
    pub reaction: Reaction,
    /// The ASDUs to send, in order. Always empty for a controlling station;
    /// for a controlled station it carries the mirror.
    pub send: Vec<Vec<u8>>,
}

/// What can go wrong in this layer, over and above the codec's own errors.
///
/// Every variant is a rule of the standard that the call would have broken; the
/// **reception** side answers with a frame instead of an error wherever the
/// standard defines one, so these describe the frames this station is asked to
/// *originate*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmError {
    /// The entry point does not belong to this instance's role: `load`,
    /// `activate`, `deactivate` and `on_response` are the controlling
    /// station's, `announce`, `on_request` and `refuse` the controlled
    /// station's.
    WrongRole,
    /// The parameter is of the other family: `load` and `announcement` take a
    /// `P_ME` parameter, `activation` a `P_AC_NA_1`. (A `P_ME` parameter offered
    /// to `deactivation` is [`PmError::DeactivationNotDefined`].)
    WrongFamily {
        /// The family the entry point takes.
        expected: Family,
        /// The family the caller offered.
        got: Family,
    },
    /// A cause the type's figure (5-101 cl.7.3.5.1–.4) does not list.
    CauseNotDefined {
        /// The type identification.
        type_id: TypeId,
        /// The cause that is not in its list.
        cause: Cause,
    },
    /// A deactivation of one of the three parameters of measured values, which
    /// have none: figures 79–81 print no `<8>`/`<9>`.
    DeactivationNotDefined {
        /// The type identification that has no deactivation.
        type_id: TypeId,
    },
    /// A `QPA` a controlling station may not send: `<0>` *not used*, `<1>` and
    /// `<2>` *not used in this companion standard* (TS 60870-5-604 5.4.21.15
    /// makes those a rejection) and `<4..127>` *reserved for standard
    /// definitions*. The private range `<128..255>` is carried.
    QpaNotUsed {
        /// The qualifier value.
        value: u8,
    },
    /// A `KPA` the clause defines no parameter kind for: `<0>` *not used* and
    /// `<5..31>` *reserved for standard definitions of this companion
    /// standard*. The four kinds `<1>`–`<4>` and the private range `<32..63>`
    /// are carried.
    KpaNotUsed {
        /// The kind of parameter the value named.
        kpa: u8,
    },
    /// A `QPM` whose `LPC` or `POP` bit is set. 5-101 cl.7.2.6.24 does not use
    /// either and requires both to be zero. This crate writes
    /// neither; a mirror of a received frame still reproduces them, because the
    /// mirror reproduces every field it decodes.
    QpmNotZeroed,
    /// The station's [`LocalChange`] is [`LocalChange::NotUsed`], so it has no
    /// `P_ME SPONT` to announce (5-101 cl.7.4.9).
    LocalChangeNotUsed,
    /// The ASDU is not a parameter ASDU: a type identification outside the four
    /// of 5-101 cl.7.3.5, or a frame that carries no information object at all
    /// (cl.7.2.2's `<0> := ASDU contains no INFORMATION OBJECT`).
    NotAParameter {
        /// The type identification the frame carried.
        type_id: TypeId,
    },
    /// The value the caller offered as the one now in operation is not of the
    /// type the received request carried.
    ValueTypeMismatch {
        /// The type the received request carried.
        expected: TypeId,
        /// The type the caller offered.
        got: TypeId,
    },
    /// The value the caller offered as the one now in operation addresses
    /// another information object than the received request.
    IoaMismatch {
        /// The address the received request carried.
        expected: u32,
        /// The address the caller offered.
        got: u32,
    },
    /// The ASDU itself could not be parsed; the layout/header layer's error,
    /// unchanged.
    Layout(LayoutError),
}

impl From<LayoutError> for PmError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<AsduError> for PmError {
    /// The header/codec error reaches this layer through the layout layer's own
    /// wrapper, exactly as [`crate::asdu::decode_asdu`] surfaces it.
    fn from(err: AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// Whether `type_id` is one of the four parameter types of 5-101 cl.7.3.5
/// (110–113).
#[must_use]
pub const fn is_parameter_type(type_id: TypeId) -> bool {
    Family::of_type(type_id).is_some()
}

/// The core builder: `parameter`'s own ASDU with `cause`, `P/N` and the test
/// bit as given.
///
/// The cause is checked against the type's own figure: a cause the type does
/// not define is [`PmError::CauseNotDefined`]. The value is not checked,
/// because a mirror reproduces the peer's value even when it is one this
/// station refuses.
///
/// # Errors
///
/// [`PmError::CauseNotDefined`] when the type's figure does not list
/// `cause`, and [`PmError::Layout`] when the frame cannot be encoded.
pub fn mirror(
    parameter: &Parameter,
    cause: Cause,
    negative: bool,
    test: bool,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, PmError> {
    mirror_with(
        parameter,
        cause,
        negative,
        test,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`mirror`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`mirror`].
pub fn mirror_with(
    parameter: &Parameter,
    cause: Cause,
    negative: bool,
    test: bool,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, PmError> {
    let family = parameter.family();
    if !family.allows(cause) {
        return Err(PmError::CauseNotDefined {
            type_id: parameter.type_id(),
            cause,
        });
    }
    let header = Header {
        type_id: parameter.type_id(),
        sequence: false,
        count: 1,
        cause,
        negative,
        test,
        originator,
        common_address,
    };
    let ioa = parameter.ioa;
    let out = match &parameter.value {
        ParameterValue::Normalized { nva, qpm } => encode_asdu_with(
            &header,
            &[LayoutObject {
                ioa,
                value: PMeNa1 {
                    nva: *nva,
                    qpm: *qpm,
                },
            }],
            sizes,
        )?,
        ParameterValue::Scaled { sva, qpm } => encode_asdu_with(
            &header,
            &[LayoutObject {
                ioa,
                value: PMeNb1 {
                    sva: *sva,
                    qpm: *qpm,
                },
            }],
            sizes,
        )?,
        ParameterValue::Float { r32, qpm } => encode_asdu_with(
            &header,
            &[LayoutObject {
                ioa,
                value: PMeNc1 {
                    r32: *r32,
                    qpm: *qpm,
                },
            }],
            sizes,
        )?,
        ParameterValue::Activation { qpa } => encode_asdu_with(
            &header,
            &[LayoutObject {
                ioa,
                value: PAcNa1 { qpa: *qpa },
            }],
            sizes,
        )?,
    };
    Ok(out)
}

/// Builds the control-direction load: a parameter of measured values with cause
/// 6 (`act`), 5-104 cl.7.9's `A_PARAM.req` row and figure 79/80/81's
/// control-direction cause `<6>` (activation).
///
/// The value is the caller's to check: cl.7.4.9's feasibility and validity
/// check is the application's, because this crate
/// has no process image. What **is** checked is the clause's own value grammar:
/// a `QPM` whose `LPC`/`POP` is set or whose `KPA` is in a range the clause marks
/// *not used*/*reserved* is refused rather than put on the wire.
///
/// # Errors
///
/// [`PmError::WrongFamily`] for a `P_AC_NA_1` parameter,
/// [`PmError::QpmNotZeroed`] or [`PmError::KpaNotUsed`] for a `QPM` outside
/// the clause's grammar, and [`PmError::Layout`] when the frame cannot be
/// encoded.
pub fn load(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, PmError> {
    load_with(
        parameter,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`load`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`load`].
pub fn load_with(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, PmError> {
    if parameter.family() != Family::Measured {
        return Err(PmError::WrongFamily {
            expected: Family::Measured,
            got: parameter.family(),
        });
    }
    if let Some(qpm) = parameter.qpm() {
        ParameterLoading::check_qpm(qpm)?;
    }
    mirror_with(
        parameter,
        CAUSE_ACTIVATION,
        false,
        false,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the control-direction activation of a parameter: `P_AC_NA_1` with
/// cause 6 and the `QPA` given (figure 82's `<6>`; cl.7.4.9 uses `P_AC` only
/// with `QPA := <3>`).
///
/// The `QPA` gate is [`PmError::QpaNotUsed`]. A station that *receives* a `QPA`
/// the profile does not use answers it with the negative confirmation
/// (TS 60870-5-604 5.4.21.15), which is [`ParameterLoading::on_request`]'s
/// business and never an error.
///
/// # Errors
///
/// [`PmError::WrongFamily`] for a `P_ME` parameter, [`PmError::QpaNotUsed`],
/// and [`PmError::Layout`] when the frame cannot be encoded.
pub fn activation(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, PmError> {
    activation_with(
        parameter,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`activation`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`activation`].
pub fn activation_with(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, PmError> {
    if parameter.family() != Family::Activation {
        return Err(PmError::WrongFamily {
            expected: Family::Activation,
            got: parameter.family(),
        });
    }
    if let Some(qpa) = parameter.qpa()
        && ParameterLoading::qpa_not_used(qpa)
    {
        return Err(PmError::QpaNotUsed { value: qpa.value });
    }
    mirror_with(
        parameter,
        CAUSE_ACTIVATION,
        false,
        false,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the control-direction deactivation of a parameter.
///
/// `P_AC_NA_1` with cause 8 and the `QPA` given (figure 82's control-direction
/// `<8>`, which the three `P_ME` types do not have:
/// [`PmError::DeactivationNotDefined`]). The `QPA` gate is the same as for
/// [`activation`].
///
/// # Errors
///
/// [`PmError::DeactivationNotDefined`] for a `P_ME` parameter,
/// [`PmError::QpaNotUsed`], and [`PmError::Layout`] when the frame cannot be
/// encoded.
pub fn deactivation(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, PmError> {
    deactivation_with(
        parameter,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`deactivation`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`deactivation`].
pub fn deactivation_with(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, PmError> {
    if parameter.family() != Family::Activation {
        return Err(PmError::DeactivationNotDefined {
            type_id: parameter.type_id(),
        });
    }
    if let Some(qpa) = parameter.qpa()
        && ParameterLoading::qpa_not_used(qpa)
    {
        return Err(PmError::QpaNotUsed { value: qpa.value });
    }
    mirror_with(
        parameter,
        CAUSE_DEACTIVATION,
        false,
        false,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the monitor-direction `P_ME SPONT`: a parameter of measured values
/// with cause 3 (5-104 cl.7.9's `A_LCPACH.req` row). [`ParameterLoading::announce`]
/// also checks the station's [`LocalChange`].
///
/// # Errors
///
/// As [`load`]: [`PmError::WrongFamily`], [`PmError::QpmNotZeroed`],
/// [`PmError::KpaNotUsed`] and [`PmError::Layout`].
pub fn announcement(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, PmError> {
    announcement_with(
        parameter,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`announcement`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`announcement`].
pub fn announcement_with(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, PmError> {
    if parameter.family() != Family::Measured {
        return Err(PmError::WrongFamily {
            expected: Family::Measured,
            got: parameter.family(),
        });
    }
    if let Some(qpm) = parameter.qpm() {
        ParameterLoading::check_qpm(qpm)?;
    }
    mirror_with(
        parameter,
        CAUSE_SPONTANEOUS,
        false,
        false,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the confirmation of a load or an activation: the parameter ASDU with
/// cause 7 (`actcon`) and `P/N` as given, for both the positive and the
/// negative confirmation.
///
/// `parameter` carries the value now in operation (5-101 cl.7.4.9: the
/// `P_ME` ACTCON returns the value, new or old, that is in operation after
/// the load): the request's own value when the
/// station accepts it (TS 60870-5-604 5.4.21.1) and the old one on the negative
/// answer (5.4.21.10). The value is an argument because the crate keeps no
/// parameter state.
///
/// The type identification and address should be the request's. This function
/// does not see the request, so it does not check them;
/// [`ParameterLoading::refuse`] does.
///
/// # Errors
///
/// As [`mirror`] with cause 7.
pub fn confirmation(
    parameter: &Parameter,
    negative: bool,
    common_address: u16,
    originator: u8,
    test: bool,
) -> Result<Vec<u8>, PmError> {
    confirmation_with(
        parameter,
        negative,
        common_address,
        originator,
        test,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`confirmation`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`confirmation`].
pub fn confirmation_with(
    parameter: &Parameter,
    negative: bool,
    common_address: u16,
    originator: u8,
    test: bool,
    sizes: AddressSizes,
) -> Result<Vec<u8>, PmError> {
    mirror_with(
        parameter,
        CAUSE_ACTIVATION_CON,
        negative,
        test,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the deactivation's positive mirror: `P_AC_NA_1` with cause 9
/// (`deactcon`) and `P/N = 0`, figure 82's monitor-direction `<9>`, which no
/// `P_ME` type has ([`PmError::DeactivationNotDefined`]).
///
/// # Errors
///
/// [`PmError::DeactivationNotDefined`] for a `P_ME` parameter, and
/// [`PmError::Layout`] when the frame cannot be encoded.
pub fn deactivation_confirmation(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
    test: bool,
) -> Result<Vec<u8>, PmError> {
    deactivation_confirmation_with(
        parameter,
        common_address,
        originator,
        test,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`deactivation_confirmation`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`deactivation_confirmation`].
pub fn deactivation_confirmation_with(
    parameter: &Parameter,
    common_address: u16,
    originator: u8,
    test: bool,
    sizes: AddressSizes,
) -> Result<Vec<u8>, PmError> {
    if !parameter.family().has_deactivation() {
        return Err(PmError::DeactivationNotDefined {
            type_id: parameter.type_id(),
        });
    }
    mirror_with(
        parameter,
        CAUSE_DEACTIVATION_CON,
        false,
        test,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the 44–47 mirror of a received parameter.
///
/// The same ASDU with `P/N = 1` and the cause of the field the station does
/// not know (5-101 cl.7.2.3's four classes). [`crate::asdu::mirror_reply`] builds the same
/// mirror octet-wise for a frame with no layout to rebuild from.
///
/// # Errors
///
/// As [`mirror`] with the class's cause.
pub fn unknown_reply(
    parameter: &Parameter,
    reason: Unspecified,
    common_address: u16,
    originator: u8,
    test: bool,
) -> Result<Vec<u8>, PmError> {
    unknown_reply_with(
        parameter,
        reason,
        common_address,
        originator,
        test,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`unknown_reply`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`unknown_reply`].
pub fn unknown_reply_with(
    parameter: &Parameter,
    reason: Unspecified,
    common_address: u16,
    originator: u8,
    test: bool,
    sizes: AddressSizes,
) -> Result<Vec<u8>, PmError> {
    mirror_with(
        parameter,
        reason.cause(),
        true,
        test,
        common_address,
        originator,
        sizes,
    )
}

/// One role's parameter loading procedure.
///
/// The state is the role, the station's addressing and its [`LocalChange`]
/// selection. There is no parameter value here: the value now in operation is
/// an argument of the answers that need it (see the module doc). Nothing here
/// reads a clock or schedules anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterLoading {
    role: Role,
    local_change: LocalChange,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
}

impl ParameterLoading {
    /// A controlling station's instance.
    #[must_use]
    pub const fn controlling(
        local_change: LocalChange,
        common_address: u16,
        originator: u8,
    ) -> Self {
        Self {
            role: Role::Controlling,
            local_change,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
        }
    }

    /// A controlled station's instance.
    #[must_use]
    pub const fn controlled(
        local_change: LocalChange,
        common_address: u16,
        originator: u8,
    ) -> Self {
        Self {
            role: Role::Controlled,
            local_change,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
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

    /// The station's `P_ME SPONT` selection.
    #[must_use]
    pub const fn local_change(&self) -> LocalChange {
        self.local_change
    }

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// The controlling station's load ([`load`]).
    ///
    /// # Errors
    ///
    /// [`PmError::WrongRole`] on a controlled instance, and the errors of
    /// [`load`].
    pub fn load(&self, parameter: &Parameter) -> Result<Vec<u8>, PmError> {
        if self.role != Role::Controlling {
            return Err(PmError::WrongRole);
        }
        load_with(parameter, self.ca, self.org, self.sizes)
    }

    /// The controlling station's activation ([`activation`]).
    ///
    /// # Errors
    ///
    /// [`PmError::WrongRole`] on a controlled instance, and the errors of
    /// [`activation`].
    pub fn activate(&self, parameter: &Parameter) -> Result<Vec<u8>, PmError> {
        if self.role != Role::Controlling {
            return Err(PmError::WrongRole);
        }
        activation_with(parameter, self.ca, self.org, self.sizes)
    }

    /// The controlling station's deactivation ([`deactivation`]).
    ///
    /// # Errors
    ///
    /// [`PmError::WrongRole`] on a controlled instance, and the errors of
    /// [`deactivation`].
    pub fn deactivate(&self, parameter: &Parameter) -> Result<Vec<u8>, PmError> {
        if self.role != Role::Controlling {
            return Err(PmError::WrongRole);
        }
        deactivation_with(parameter, self.ca, self.org, self.sizes)
    }

    /// The controlled station's `P_ME SPONT` announcement ([`announcement`]).
    ///
    /// # Errors
    ///
    /// [`PmError::WrongRole`] on a controlling instance,
    /// [`PmError::LocalChangeNotUsed`] when the station's [`LocalChange`] is not
    /// [`LocalChange::Used`], and the errors of [`announcement`].
    pub fn announce(&self, parameter: &Parameter) -> Result<Vec<u8>, PmError> {
        if self.role != Role::Controlled {
            return Err(PmError::WrongRole);
        }
        if self.local_change != LocalChange::Used {
            return Err(PmError::LocalChangeNotUsed);
        }
        announcement_with(parameter, self.ca, self.org, self.sizes)
    }

    /// The controlled station's decision for one received ASDU, with the mirror
    /// it owes.
    ///
    /// Every refusal the standard defines is an answer here, not an error or a
    /// silence: a `QPA` the profile does not use is mirrored with `P/N = 1` (TS
    /// 60870-5-604 5.4.21.15), and so is a load whose `QPM` [`load`] would
    /// refuse to build (5-101 cl.7.2.6.24: a `KPA` not used or reserved, or a
    /// set `LPC`/`POP`); a cause the type does not define in the control
    /// direction is mirrored with clause 7.2.3's cause 45, and a parameter
    /// addressed to the broadcast CASDU with cause 46; a field the caller's
    /// [`Known`] does not know is mirrored with its class's cause 44–47.
    ///
    /// Any other load is answered positively with the received value, which is
    /// what cl.7.4.9 describes after the feasibility check. The crate cannot
    /// perform that check (it has no process image), so a station that will not
    /// accept the value answers with [`ParameterLoading::refuse`] instead,
    /// passing the value now in operation.
    ///
    /// One negative case is the standard's own and never reaches that decision:
    /// a load whose `KPA` is `<1>` (threshold value) or `<2>` (smoothing
    /// factor) and whose value is negative is [`Reaction::Infeasible`] with
    /// nothing sent, because the answer is an `ACTCONneg` carrying the *old*
    /// value (TS 60870-5-604 5.4.21.10) and the crate holds none. The caller
    /// answers it with [`ParameterLoading::refuse`] as well.
    ///
    /// # Errors
    ///
    /// [`PmError::WrongRole`] on a controlling instance, and
    /// [`PmError::Layout`] when the frame cannot be parsed or the answer cannot
    /// be encoded.
    pub fn on_request(&self, asdu: &[u8], known: &Known) -> Result<Outcome, PmError> {
        if self.role != Role::Controlled {
            return Err(PmError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        // A parameter is never broadcast: TS 60870-5-604 5.4.10.10's broadcast
        // CASDU carries types 100/101/103/105 only, and every other type is
        // mirrored with P/N = 1. The check reads the header, so it holds
        // whatever `Known` says, and it runs before the discard rule because a
        // broadcast parameter must be answered, not swallowed. A received
        // mirror is left to the discard rule so two stations cannot mirror each
        // other.
        if header.common_address == self.sizes.broadcast_common_address()
            && !is_mirror(&header)
            && is_parameter_type(header.type_id)
        {
            return self.refuse_frame(&header, asdu, Unspecified::CommonAddress);
        }
        if let Some(reason) = discard_reason(&header, known) {
            // Clause 7.2.3's table is about the **control** direction: a field
            // the station does not know is mirrored with its class's cause
            // 44–47, never discarded. The only ASDU this method discards is a
            // mirror a peer sent.
            if let Discard::Unspecified(which) = reason {
                return self.refuse_frame(&header, asdu, which);
            }
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        if !is_parameter_type(header.type_id) {
            return Ok(other());
        }
        let Some(parameter) = decode(asdu, self.sizes)? else {
            return Ok(other());
        };
        match header.cause {
            Cause::Activation => {
                if let ParameterValue::Activation { qpa } = parameter.value {
                    self.answer_qpa(
                        &parameter,
                        &header,
                        qpa,
                        CAUSE_ACTIVATION_CON,
                        Reaction::Activated {
                            ioa: parameter.ioa,
                            qpa,
                        },
                    )
                } else {
                    // 5-101 cl.7.2.6.24: a `QPM` the builders refuse (`KPA`
                    // not used/reserved, `LPC`/`POP` set) is not accepted on
                    // reception either; it is mirrored with `P/N = 1`.
                    if parameter
                        .qpm()
                        .is_some_and(|qpm| Self::check_qpm(qpm).is_err())
                    {
                        return self.answer(
                            &parameter,
                            &header,
                            CAUSE_ACTIVATION_CON,
                            true,
                            Reaction::Refused {
                                ioa: parameter.ioa,
                                cause: CAUSE_ACTIVATION_CON,
                            },
                        );
                    }
                    // TS 60870-5-604 5.4.21.10: a negative threshold value or
                    // smoothing factor is always invalid and never
                    // activated. The ACTCONneg carries the old value, which
                    // the crate does not hold, so nothing is sent here and the
                    // caller answers through `refuse`.
                    if parameter.value.is_infeasible_negative() {
                        return Ok(Outcome {
                            reaction: Reaction::Infeasible {
                                ioa: parameter.ioa,
                                value: parameter.value,
                            },
                            send: Vec::new(),
                        });
                    }
                    self.answer(
                        &parameter,
                        &header,
                        CAUSE_ACTIVATION_CON,
                        false,
                        Reaction::Loaded {
                            ioa: parameter.ioa,
                            value: parameter.value,
                        },
                    )
                }
            }
            Cause::Deactivation => match parameter.value {
                ParameterValue::Activation { qpa } => self.answer_qpa(
                    &parameter,
                    &header,
                    qpa,
                    CAUSE_DEACTIVATION_CON,
                    Reaction::Deactivated {
                        ioa: parameter.ioa,
                        qpa,
                        negative: false,
                    },
                ),
                // Figures 79–81 list no <8>: a deactivation of a parameter of
                // measured values is a cause the type does not define.
                _ => self.refuse_frame(&header, asdu, Unspecified::CauseOfTransmission),
            },
            _ => self.refuse_frame(&header, asdu, Unspecified::CauseOfTransmission),
        }
    }

    /// The controlled station's negative confirmation of a load it will not
    /// accept: the same ASDU with `P/N = 1` and the value the caller says is now
    /// in operation, or the received `QPA` for a `P_AC_NA_1`.
    ///
    /// 5-101 cl.7.4.9 and TS 60870-5-604 Table 21's 5.4.21.10 (quoted in the
    /// module doc): the negative confirmation carries the old value, the one
    /// still in operation.
    ///
    /// The element depends on the family. For a `P_ME` type, `in_operation`
    /// names the value now in operation. A `QPA` is a qualifier, not a value,
    /// and 5.4.21.15's mirror is *"the same ASDU"*, so for `P_AC_NA_1` the
    /// received `QPA` is reproduced and `in_operation`'s is ignored. On either
    /// family, `in_operation`'s type and address must match the received
    /// frame's ([`PmError::ValueTypeMismatch`], [`PmError::IoaMismatch`]).
    ///
    /// Both causes figure 82 lists are accepted for `P_AC_NA_1`: cause 6 is
    /// refused with cause 7 and cause 8 with cause 9, each with `P/N = 1`. The
    /// three `P_ME` types have no `<8>`, so a deactivation of one stays
    /// [`PmError::CauseNotDefined`].
    ///
    /// # Errors
    ///
    /// [`PmError::WrongRole`] on a controlling instance,
    /// [`PmError::NotAParameter`] when `asdu` carries no parameter,
    /// [`PmError::CauseNotDefined`], [`PmError::ValueTypeMismatch`] and
    /// [`PmError::IoaMismatch`] as above, and [`PmError::Layout`] when the frame
    /// cannot be parsed or the answer cannot be encoded.
    pub fn refuse(&self, asdu: &[u8], in_operation: &Parameter) -> Result<Outcome, PmError> {
        if self.role != Role::Controlled {
            return Err(PmError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        let Some(received) = decode(asdu, self.sizes)? else {
            return Err(PmError::NotAParameter {
                type_id: header.type_id,
            });
        };
        // Cause 6 is refused on both families; cause 8 exists on `P_AC_NA_1`
        // alone (figure 82), so for a `P_ME` type it is a cause the figure
        // does not list, as in `mirror`.
        let cause = match (received.family(), header.cause) {
            (_, Cause::Activation) => CAUSE_ACTIVATION_CON,
            (Family::Activation, Cause::Deactivation) => CAUSE_DEACTIVATION_CON,
            _ => {
                return Err(PmError::CauseNotDefined {
                    type_id: header.type_id,
                    cause: header.cause,
                });
            }
        };
        if in_operation.type_id() != received.type_id() {
            return Err(PmError::ValueTypeMismatch {
                expected: received.type_id(),
                got: in_operation.type_id(),
            });
        }
        if in_operation.ioa != received.ioa {
            return Err(PmError::IoaMismatch {
                expected: received.ioa,
                got: in_operation.ioa,
            });
        }
        // `QPA` is a qualifier, so the `P_AC_NA_1` mirror carries the received
        // frame's own one; only a `P_ME` value comes from the caller.
        if let ParameterValue::Activation { qpa } = received.value {
            let reaction = if cause == CAUSE_DEACTIVATION_CON {
                Reaction::Deactivated {
                    ioa: received.ioa,
                    qpa,
                    negative: true,
                }
            } else {
                Reaction::Confirmed {
                    ioa: received.ioa,
                    value: received.value,
                    negative: true,
                }
            };
            return self.answer(&received, &header, cause, true, reaction);
        }
        self.answer(
            in_operation,
            &header,
            cause,
            true,
            Reaction::Confirmed {
                ioa: in_operation.ioa,
                value: in_operation.value,
                negative: true,
            },
        )
    }

    /// The controlling station's classification of a monitor-direction frame:
    /// the confirmation of a load or an activation (cause 7), the mirror of a
    /// deactivation (cause 9), the `P_ME SPONT` announcement (cause 3, only for
    /// a station whose [`LocalChange`] is [`LocalChange::Used`]) and an
    /// interrogation readback (causes 20–36).
    ///
    /// Nothing is sent: a controlling station answers none of these. A
    /// parameter type's 44–47 mirror is the peer's refusal and is a
    /// [`Reaction::Refused`]; then the discard rule runs, then the type's own
    /// cause list.
    /// [`Family::is_monitor_cause`] is the list [`mirror`] checks on the way
    /// out, so a cause the received type's figure does not carry (the `P_ME`
    /// types' `<9>`, `P_AC_NA_1`'s `<3>` or `<20>`–`<36>`) is
    /// [`Reaction::Other`].
    ///
    /// # Errors
    ///
    /// [`PmError::WrongRole`] on a controlled instance, and
    /// [`PmError::Layout`] when the frame cannot be parsed.
    pub fn on_response(&self, asdu: &[u8], known: &Known) -> Result<Outcome, PmError> {
        if self.role != Role::Controlling {
            return Err(PmError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if is_parameter_type(header.type_id) && is_mirror(&header) {
            // The peer's refusal of this station's load or activation, so it
            // is classified before the discard rule (as `ts`, `rd`, `ci` do).
            return Ok(Outcome {
                reaction: Reaction::Refused {
                    ioa: decode(asdu, self.sizes)?.map_or(0, |p| p.ioa),
                    cause: header.cause,
                },
                send: Vec::new(),
            });
        }
        if let Some(reason) = discard_reason(&header, known) {
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        if !is_parameter_type(header.type_id) {
            return Ok(other());
        }
        let Some(parameter) = decode(asdu, self.sizes)? else {
            return Ok(other());
        };
        if !parameter.family().is_monitor_cause(header.cause) {
            return Ok(other());
        }
        let reaction = match header.cause {
            Cause::ActivationCon => Reaction::Confirmed {
                ioa: parameter.ioa,
                value: parameter.value,
                negative: header.negative,
            },
            Cause::DeactivationCon => match parameter.value {
                ParameterValue::Activation { qpa } => Reaction::Deactivated {
                    ioa: parameter.ioa,
                    qpa,
                    // 5-101 cl.7.2.3 defines `P/N` without tying it to a
                    // cause (`<0>` positive, `<1>` negative confirm), so a `P/N = 1` cause-9 frame is a refused
                    // deactivation.
                    negative: header.negative,
                },
                // Figures 79–81 have no <9>; the type does not define it.
                _ => return Ok(other()),
            },
            Cause::Spontaneous => {
                if self.local_change == LocalChange::NotUsed {
                    return Ok(other());
                }
                Reaction::Announced {
                    ioa: parameter.ioa,
                    value: parameter.value,
                }
            }
            Cause::InterrogatedByStation | Cause::InterrogatedByGroup(_) => {
                if parameter.family() != Family::Measured
                    || !(20..=36).contains(&header.cause.to_u8())
                {
                    return Ok(other());
                }
                Reaction::Interrogated {
                    ioa: parameter.ioa,
                    value: parameter.value,
                    cause: header.cause,
                }
            }
            _ => Reaction::Other,
        };
        Ok(Outcome {
            reaction,
            send: Vec::new(),
        })
    }

    /// The mirror of a received frame for one of clause 7.2.3's four undefined
    /// classes. A parameter frame this crate can decode is rebuilt through
    /// [`mirror`]; any other frame (another type, or no object) is copied octet
    /// for octet behind the header ([`crate::asdu::mirror_frame`]).
    fn refuse_frame(
        self,
        header: &Header,
        asdu: &[u8],
        which: Unspecified,
    ) -> Result<Outcome, PmError> {
        let cause = which.cause();
        if let Some(parameter) = decode(asdu, self.sizes)? {
            return self.answer(
                &parameter,
                header,
                cause,
                true,
                Reaction::Refused {
                    ioa: parameter.ioa,
                    cause,
                },
            );
        }
        let objects = asdu.get(self.sizes.header_len()..).unwrap_or(&[]);
        Ok(Outcome {
            reaction: Reaction::Refused {
                ioa: crate::asdu::read_ioa_with(objects, self.sizes).unwrap_or(0),
                cause,
            },
            send: vec![crate::asdu::mirror_frame(
                header, asdu, which, self.ca, self.sizes,
            )],
        })
    }

    /// The mirror of a decoded parameter with `cause` and `P/N` as given, as
    /// the whole answer, echoing the answered frame's originator address and
    /// test bit.
    fn answer(
        self,
        parameter: &Parameter,
        header: &Header,
        cause: Cause,
        negative: bool,
        reaction: Reaction,
    ) -> Result<Outcome, PmError> {
        Ok(Outcome {
            reaction,
            send: vec![mirror_with(
                parameter,
                cause,
                negative,
                header.test,
                self.ca,
                header.originator,
                self.sizes,
            )?],
        })
    }

    /// The `con` answer to a received `P_AC_NA_1`: negative when the profile
    /// does not use its `QPA` (TS 60870-5-604 5.4.21.15), else positive with
    /// `accepted`.
    fn answer_qpa(
        self,
        parameter: &Parameter,
        header: &Header,
        qpa: Qpa,
        con: Cause,
        accepted: Reaction,
    ) -> Result<Outcome, PmError> {
        if Self::qpa_not_used(qpa) {
            return self.answer(
                parameter,
                header,
                con,
                true,
                Reaction::Refused {
                    ioa: parameter.ioa,
                    cause: con,
                },
            );
        }
        self.answer(parameter, header, con, false, accepted)
    }

    /// Checks a `QPM` against 5-101 cl.7.2.6.24: `LPC` and
    /// `POP` zero, `KPA` one of the four kinds or the private range.
    const fn check_qpm(qpm: Qpm) -> Result<(), PmError> {
        if qpm.local_parameter_change || qpm.parameter_not_in_operation {
            return Err(PmError::QpmNotZeroed);
        }
        match qpm.kpa {
            1..=4 | 32..=63 => Ok(()),
            kpa => Err(PmError::KpaNotUsed { kpa }),
        }
    }

    /// Whether a `QPA` is one the profile does not use: `<0>` *not used*, `<1>`
    /// and `<2>` *not used in this companion standard*, `<4..127>` *reserved for
    /// standard definitions*.
    const fn qpa_not_used(qpa: Qpa) -> bool {
        matches!(qpa.value, 0..=2 | 4..=127)
    }
}

/// The reaction for an ASDU this procedure does not own.
const fn other() -> Outcome {
    Outcome {
        reaction: Reaction::Other,
        send: Vec::new(),
    }
}

/// Reads a parameter ASDU's single information object, or `None` when it
/// carries none at all (5-101 cl.7.2.2's `<0> := ASDU contains no INFORMATION
/// OBJECT`).
fn decode(asdu: &[u8], sizes: AddressSizes) -> Result<Option<Parameter>, LayoutError> {
    let header = Header::parse_with(asdu, sizes)?;
    let parameter = match header.type_id {
        TypeId::PMeNa1 => decode_asdu_with::<PMeNa1>(asdu, sizes)?
            .first()
            .map(|object| {
                Parameter::new(
                    object.ioa,
                    ParameterValue::Normalized {
                        nva: object.value.nva,
                        qpm: object.value.qpm,
                    },
                )
            }),
        TypeId::PMeNb1 => decode_asdu_with::<PMeNb1>(asdu, sizes)?
            .first()
            .map(|object| {
                Parameter::new(
                    object.ioa,
                    ParameterValue::Scaled {
                        sva: object.value.sva,
                        qpm: object.value.qpm,
                    },
                )
            }),
        TypeId::PMeNc1 => decode_asdu_with::<PMeNc1>(asdu, sizes)?
            .first()
            .map(|object| {
                Parameter::new(
                    object.ioa,
                    ParameterValue::Float {
                        r32: object.value.r32,
                        qpm: object.value.qpm,
                    },
                )
            }),
        TypeId::PAcNa1 => decode_asdu_with::<PAcNa1>(asdu, sizes)?
            .first()
            .map(|object| {
                Parameter::new(
                    object.ioa,
                    ParameterValue::Activation {
                        qpa: object.value.qpa,
                    },
                )
            }),
        _ => None,
    };
    Ok(parameter)
}
