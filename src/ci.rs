//! Counter interrogation: the `C_CI_NA_1` activation, its response cycle and
//! 104 clause 9's four counter modes.
//!
//! # The procedure
//!
//! 5-104 clause **7.8** (PDF page index 70, printed page 69) is the service
//! table and the whole of the clause:
//!
//! | Application service | ASDU label |
//! | --- | --- |
//! | `A_MEMCNT.req` / `.ind` | `C_CI ACT` |
//! | `A_MEMCNT.res` / `.con` | `C_CI ACTCON` |
//! | `A_MEMINCR.req` / `.ind` | `C_CI ACT` |
//! | `A_MEMINCR.res` / `.con` | `C_CI ACTCON` |
//! | `A_REQINTO.req` / `.ind` | `C_CI ACT` |
//! | `A_REQINTO.res` / `.con` | `C_CI ACTCON` |
//! | `A_INTO_INF.req` / `.ind` | `M_IT` |
//! | `A_ITERM.req` / `.ind` | `C_CI ACTTERM` |
//!
//! So every rule this module implements is 5-101's. Clause **7.4.8** (PDF page
//! indices 126–129, printed pages 125–128) is the procedure, clause **7.2.6.23**
//! (page index 54, printed page 53) is the qualifier and clause **7.3.4.2**
//! (page index 105, figure 73) is the layout.
//!
//! # The request
//!
//! `C_CI_NA_1 := CP{Data unit identifier,Information object address,QCC}`, headed
//! *"Single information object (SQ = 0)"*, its figure printing `INFORMATION
//! OBJECT ADDRESS = 0`: ten octets, `SQ = 0`, `N = 1`, type 101. The clause's
//! per-type cause list is the whole set of causes the type may carry:
//!
//! ```text
//! CAUSES OF TRANSMISSION used with TYPE IDENT 101 := C_CI_NA_1
//!   in control direction: <6> activation, <8> deactivation
//!   in monitor direction: <7> activation confirmation,
//!                         <9> deactivation confirmation,
//!                         <10> activation termination,
//!                         <44> .. <47> the four unknown-address replies
//! ```
//!
//! so [`request`] writes cause 6 and the controlled station answers with cause 7
//! and, for a collection, cause 10.
//!
//! **There is no deactivation in this procedure.** Clause 7.4.8 states it in
//! terms (*"`C_CI` DEACT and DEACTCON are not used."*), so this module has no
//! deactivation builder, and a type-101 ASDU carrying cause 8 or 9 is
//! [`Reaction::Other`]. The cause list above has both because it is the
//! *type's*; the procedure's selection removes them.
//!
//! # The qualifier and its two fields
//!
//! `QCC := CP8{RQT,FRZ}` (clause 7.2.6.23): `RQT := UI6[1..6]<0..63>` (`0x3F`)
//! is the request and `FRZ := UI2[7..8]<0..3>` (`0xC0`) is the freeze mode,
//! **one octet split six and two**, not two four-bit nibbles:
//!
//! ```text
//! RQT  := <0> no counter requested (not used), <1..4> request counter group 1..4,
//!         <5> general request counter, <6..31> reserved, <32..63> private
//! FRZ  := <0> read (no freeze or reset)
//!         <1> counter freeze without reset (value frozen represents integrated total)
//!         <2> counter freeze with reset (value frozen represents incremental information)
//!         <3> counter reset
//! ```
//!
//! and the sentence that gates the whole procedure: *"The action specified by
//! the FRZ code is applied only to the group specified by the RQT code."* The
//! element itself is [`Qcc`] with [`FreezeMode`].
//!
//! [`Request`] is `RQT` as a type (`<5>` general, `<1>` … `<4>` group 1 … 4),
//! and it names the response's cause of transmission the way
//! [`crate::gi::Scope`] does: `<37>` requested by general counter request for
//! the general one, `<38>` … `<41>` requested by counter group 1 … 4 otherwise.
//! Values `<0>`, `<6..31>` and `<32..63>` are "not used", reserved or private,
//! so an ASDU carrying one is [`Reaction::Other`].
//!
//! # The response cycle
//!
//! Clause 7.4.8 and TS 60870-5-604 Table 20 (PDF page indices 78–81) fix the
//! exchange, which has the same shape as general interrogation's:
//!
//! - the controlling station sends `C_CI ACT` with cause 6;
//! - the controlled station *"mirrors the counter interrogation command (ASDU
//!   101) with COT=7, `C_CI_ACTCON`"*: the confirmation repeats the request's
//!   own `RQT` **and** `FRZ`;
//! - *"All Counter Information Objects that are part of the Counter
//!   Interrogation for the requested RQT are sent with the corresponding COT
//!   (37-41)"*: the objects are the application's own `M_IT` ASDUs, per
//!   clause 7.4.8's *"Requested integrated totals are transmitted with cause of
//!   transmission 37 to 41."*;
//! - the controlled station *"sends the same Counter interrogation command it
//!   received (ASDU 101) with COT = 10, `C_CI_ACTTERM`"*.
//!
//! The `M_IT` family is **two** types in this companion standard, `M_IT_NA_1`
//! (15) and `M_IT_TB_1` (37), and the clause prefers neither: Table 20 asks
//! that *"The tests in this table are performed correctly by every `M_IT` ASDU in
//! the PICS that supports COT 37-41"*, so which one a station sends is the
//! application's choice ([`COUNTER_TYPES`]; a data source offering anything
//! else is a typed refusal). 5-101 clause 7.3.1 defines a third, `M_IT_TA_1`
//! (16, with a three-octet `CP24Time2a` tag), but 5-104 clause 9 (PDF page
//! index 100, printed 99) rules that set out: *"In this companion standard only
//! the use of the set `<30>` – `<40>` for ASDUs with time tag is permitted."*
//! [`TypeId::is_selected_104`] accordingly answers `false` for type 16.
//!
//! # A memorize is confirmed, not terminated
//!
//! The freeze/reset command is a **memorize** transaction and ends with its
//! confirmation: 5-101 figure 95 draws `C_CI ACT` (`FRZ = <1>`) → `C_CI
//! ACTCON` (`FRZ = <1>`) and then *"Continue with the collection of the frozen
//! values as described in mode B"*, and Table 20's mode C procedure lists
//! `C_CI_ACTTERM` only after the **collection**'s objects. Clause 7.4.8 says
//! the same from the other side: *"This command does not cause the counter
//! values to be transmitted."* So a request with `FRZ` other than
//! [`FreezeMode::Read`] is answered with the confirmation alone (no data, no
//! termination), and only a `Read` request opens a collection that
//! [`CounterInterrogation::interrogated`] and
//! [`CounterInterrogation::complete`] then serve.
//!
//! # The four modes
//!
//! 5-101 clause 7.4.8 defines four "modes of acquisition of integrated totals
//! or incremental information", and 5-104 clause 9's interoperability list
//! (PDF page index 112, printed page 111) asks a station to mark which it
//! supports:
//!
//! ```text
//! Mode A: Local freeze with spontaneous transmission
//! Mode B: Local freeze with counter interrogation
//! Mode C: Freeze and transmit by counter-interrogation commands
//! Mode D: Freeze by counter-interrogation command, frozen values reported
//! ```
//!
//! The clause's own description of each:
//!
//! - **Mode A**: *"Local clocks in the controlled station initiate the freeze
//!   or freeze with reset operations. The integrated totals (frozen values) are
//!   transmitted spontaneously in `M_IT` ASDUs after the freeze or freeze with
//!   reset operation has been performed. The controlling station does not issue
//!   counter interrogation commands (`C_CI`)."*
//! - **Mode B**: *"Local clocks in the controlled station initiate the freeze
//!   or freeze with reset operations. The integrated totals (frozen values) are
//!   requested by counter interrogation commands (`C_CI`). In this case, the
//!   freeze or freeze with reset functionality must not be used in the counter
//!   interrogation command (i.e. the command qualifier must contain FRZ = 0)."*
//! - **Mode C**: *"counter interrogation commands from the controlling station
//!   initiate the freeze, freeze with reset or reset commands. A subsequent
//!   counter interrogation command is issued by the controlling station to
//!   collect the frozen values from the controlled station."*
//! - **Mode D**: *"counter interrogation commands from the controlling station
//!   initiate the freeze operation, and the frozen values are reported
//!   spontaneously. This mode is a combination of the counter command from the
//!   controlling station as specified in mode C, with spontaneous reporting of
//!   the integrated totals, as described in mode A."*
//!
//! [`CounterMode`] is that selection as a type. It is the *station's* answer,
//! so it is a parameter of both roles' instances, modelled rather than chosen,
//! like [`crate::gi::ReActivation`]. Four predicates carry the clause's words:
//!
//! - [`CounterMode::accepts_requests`]: mode A issues no request;
//! - [`CounterMode::accepts_freeze`]: mode B refuses a `FRZ` other than `Read`;
//! - [`CounterMode::accepts_collection`]: only modes B and C accept
//!   `FRZ = <0>` (mode D's command is `FRZ` 1…3 and its values are reported
//!   spontaneously, so a collection on it is `CollectionNotAllowed`);
//! - [`CounterMode::reports_spontaneously`]: modes A and D, whose values this
//!   module does not produce (that is spontaneous transmission,
//!   [`crate::tx`]).
//!
//! # What the clauses do not say
//!
//! Three things a general interrogation settles are **absent** here, and the
//! standard's silence is the reason:
//!
//! - **No lock, no re-activation options.** Clause 7.4.5 locks a second
//!   *identical* general interrogation, and TS 60870-5-604 Table 17 gives the
//!   controlled station three options for one that arrives anyway. The counter
//!   procedure has neither sentence, and Table 20's four mode procedures and
//!   Table 27's five counter rows (PDF page index 95) contain no re-activation
//!   test. A second activation is therefore honoured as its own procedure; an
//!   identical request already owing a collection is confirmed again and its
//!   data is still owed once (covered in `tests/ci.rs`).
//! - **No negative-confirmation rule.** Table 20 draws only the positive
//!   confirmation and clause 7.4.8 names no "not ready" case. The type's cause
//!   list nevertheless carries `<7>` with the `P/N` flag, so, as this crate's
//!   own reading, [`CounterInterrogation::on_request`] answers a data source
//!   that is not ready with a negative confirmation and changes no state. The
//!   request stays repeatable, as a general interrogation's does. An activation
//!   the station's [`CounterMode`] does not permit is answered the same way
//!   ([`Reaction::Rejected`]), so the peer is never left waiting.
//! - **No deactivation.** See above.
//!
//! # What this module is not
//!
//! * **Not I/O, not a clock, not a socket.** Every result depends only on the
//!   arguments and the procedure's own state; the caller owns the connection, the flow control, the
//!   log and the retry. Data goes out through
//!   [`Session::queue_i_frame`](crate::link::Session::queue_i_frame), which
//!   holds it until the STARTDT con.
//! * **Not the counter values.** Which objects belong to counter group 3, and
//!   what a `BCR` reading means, is project data: the controlled station's
//!   data arrives through the caller's [`CounterSource`], as general
//!   interrogation's does through [`crate::gi::DataSource`].
//! * **Not the local freeze.** Modes A and D report spontaneously from the
//!   controlled station's own clock, with cause 3; that is [`crate::tx`], and
//!   this module neither schedules it nor produces it.
//!
//! # Example
//!
//! ```
//! use iec104::asdu::{Cause, FreezeMode, Header, TypeId};
//! use iec104::ci::{request, CounterInterrogation, CounterMode, Request};
//!
//! // The controlling station collects counter group 2 (RQT = 2, FRZ = 0).
//! let asdu = request(Request::Group(2), FreezeMode::Read, 12, 0).unwrap();
//! let header = Header::parse(&asdu).unwrap();
//! assert_eq!(header.type_id, TypeId::CCiNa1);
//! assert_eq!(header.cause, Cause::Activation);
//! assert_eq!(header.count, 1);
//! assert_eq!(asdu[9], 2, "RQT 2, FRZ 0");
//!
//! // The request names the cause every object of that group comes back with.
//! assert_eq!(Request::Group(2).cause(), Cause::RequestedByCounterGroup(2));
//! assert_eq!(Request::General.cause(), Cause::RequestedByGeneralCounter);
//!
//! // Modes A and B differ in exactly the way clause 7.4.8 says they do.
//! assert!(!CounterMode::LocalFreezeSpontaneous.accepts_requests());
//! assert!(!CounterMode::LocalFreezeByInterrogation.accepts_freeze());
//! assert!(CounterMode::FreezeAndTransmit.accepts_freeze());
//!
//! // A collection's request, and the station that would answer it.
//! let mut controlling = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, 12, 0);
//! let _ = controlling.request(Request::Group(2), FreezeMode::Read);
//! ```

use crate::asdu::{
    AddressSizes, AsduError, CCiNa1, Cause, Discard, FreezeMode, Header, IOA_IRRELEVANT, Known,
    LayoutError, LayoutObject, Qcc, TypeId, decode_asdu_with, discard_reason, encode_asdu_with,
    is_mirror, mirror_frame,
};

/// The type identification of the counter interrogation command and of every
/// control-direction frame of its procedure (5-101 clause 7.3.4.2, figure 73).
pub const TYPE_ID: TypeId = TypeId::CCiNa1;

/// `<6> activation`: the cause of the request (figure 73's control-direction
/// list).
pub const CAUSE_ACTIVATION: Cause = Cause::Activation;

/// `<7> activation confirmation`: the cause of the controlled station's
/// positive **and** negative confirmation (figure 73).
pub const CAUSE_ACTIVATION_CON: Cause = Cause::ActivationCon;

/// `<10> activation termination`: the frame that ends a **collection**. A
/// memorize transaction (any `FRZ` other than [`FreezeMode::Read`]) has no
/// termination; see the module doc.
pub const CAUSE_ACTIVATION_TERM: Cause = Cause::ActivationTermination;

/// The `M_IT` family a response object may carry, in type-identification order:
/// `M_IT_NA_1` (15) and `M_IT_TB_1` (37).
///
/// 5-101 clause 7.4.8 and TS 60870-5-604 Table 20 select neither of the two,
/// so the crate accepts both and the application chooses. 5-101 clause
/// 7.3.1's third member, `M_IT_TA_1` (16), is **not** in the list: 5-104
/// clause 9 permits only the `<30>` to `<40>` set for time-tagged ASDUs (see
/// the module doc), as [`TypeId::is_selected_104`] reports for it.
pub const COUNTER_TYPES: [TypeId; 2] = [TypeId::MItNa1, TypeId::MItTb1];

/// Whether `type_id` is one of the two `M_IT` types of [`COUNTER_TYPES`].
#[must_use]
pub fn is_counter_type(type_id: TypeId) -> bool {
    COUNTER_TYPES.contains(&type_id)
}

/// Which counters a `C_CI_NA_1` requests: the `RQT` field of 5-101 clause
/// 7.2.6.23, as a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Request {
    /// `<5>`: general request counter, the whole station.
    General,
    /// `<1>` … `<4>`: counter group 1 … 4. The variant is public and
    /// [`Request::rqt`] and [`Request::cause`] clamp it, so an out-of-range
    /// group can never reach the wire.
    Group(u8),
}

impl Request {
    /// `<5>`: the `RQT` of the general request.
    pub const GENERAL: u8 = 5;
    /// `<1>`: the `RQT` of counter group 1.
    pub const GROUP_1: u8 = 1;
    /// `<4>`: the `RQT` of counter group 4.
    pub const GROUP_4: u8 = 4;

    /// The request a received `RQT` names, or `None` for the values clause
    /// 7.2.6.23 leaves "not used", reserved or private (`<0>`, `<6..31>`,
    /// `<32..63>`).
    #[must_use]
    pub const fn from_rqt(rqt: u8) -> Option<Self> {
        match rqt {
            Self::GENERAL => Some(Self::General),
            Self::GROUP_1..=Self::GROUP_4 => Some(Self::Group(rqt)),
            _ => None,
        }
    }

    /// Counter group `n` (`1..=4`), clamped into the standard's range the way
    /// [`Qcc::counter_group`] is.
    #[must_use]
    pub fn group(n: u8) -> Self {
        Self::Group(n.clamp(Self::GROUP_1, Self::GROUP_4))
    }

    /// Counter group `n`, or `None` outside `1..=4`.
    #[must_use]
    pub fn try_group(n: u8) -> Option<Self> {
        (Self::GROUP_1..=Self::GROUP_4)
            .contains(&n)
            .then_some(Self::Group(n))
    }

    /// The `RQT` this request is sent with.
    #[must_use]
    pub fn rqt(self) -> u8 {
        match self {
            Self::General => Self::GENERAL,
            Self::Group(n) => n.clamp(Self::GROUP_1, Self::GROUP_4),
        }
    }

    /// The group number, `Some(1..=4)`, or `None` for the general request.
    #[must_use]
    pub fn group_number(self) -> Option<u8> {
        match self {
            Self::General => None,
            Self::Group(n) => Some(n.clamp(Self::GROUP_1, Self::GROUP_4)),
        }
    }

    /// Whether this is the general request `<5>`.
    #[must_use]
    pub const fn is_general(self) -> bool {
        matches!(self, Self::General)
    }

    /// The cause of transmission every object of this request is reported with
    /// (`<37>` requested by general counter request, `<38>` … `<41>` requested
    /// by counter group 1 … 4).
    #[must_use]
    pub fn cause(self) -> Cause {
        match self {
            Self::General => Cause::RequestedByGeneralCounter,
            Self::Group(n) => Cause::RequestedByCounterGroup(n.clamp(Self::GROUP_1, Self::GROUP_4)),
        }
    }

    /// The request a received cause of transmission names, or `None` for any
    /// other cause.
    #[must_use]
    pub fn from_cause(cause: Cause) -> Option<Self> {
        match cause {
            Cause::RequestedByGeneralCounter => Some(Self::General),
            Cause::RequestedByCounterGroup(n) => Some(Self::group(n)),
            _ => None,
        }
    }

    /// The qualifier of counter interrogation carrying this request and
    /// `freeze`.
    #[must_use]
    pub fn qcc(self, freeze: FreezeMode) -> Qcc {
        Qcc {
            rqt: self.rqt(),
            frz: freeze,
        }
    }
}

/// The station's selection among 5-101 clause 7.4.8's four "modes of
/// acquisition of integrated totals or incremental information", as 5-104
/// clause 9's interoperability list asks a station to mark it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CounterMode {
    /// Mode A: local freeze with spontaneous transmission. The controlled
    /// station's own clock freezes, the frozen values are sent spontaneously in
    /// `M_IT` ASDUs, and the controlling station issues no `C_CI` at all.
    LocalFreezeSpontaneous,
    /// Mode B: local freeze with counter interrogation. The freeze is local
    /// and the frozen values are *requested*; the command qualifier *"must
    /// contain FRZ = 0"*, so a freeze in a `C_CI` is refused.
    LocalFreezeByInterrogation,
    /// Mode C: freeze and transmit by counter-interrogation commands. A
    /// `C_CI` with `FRZ` 1 … 3 freezes or resets without transmitting, and a
    /// later `C_CI` with `FRZ = 0` collects.
    FreezeAndTransmit,
    /// Mode D: freeze by counter-interrogation command, frozen values reported
    /// spontaneously. Mode C's command with mode A's reporting.
    FreezeSpontaneous,
}

impl CounterMode {
    /// Whether a counter interrogation command may be issued at all: false
    /// only for mode A, whose *"controlling station does not issue counter
    /// interrogation commands (`C_CI`)"*.
    #[must_use]
    pub const fn accepts_requests(self) -> bool {
        !matches!(self, Self::LocalFreezeSpontaneous)
    }

    /// Whether a `C_CI` may carry a `FRZ` other than [`FreezeMode::Read`]:
    /// true only for modes C and D. Mode B's *"the freeze or freeze with reset
    /// functionality must not be used in the counter interrogation command
    /// (i.e. the command qualifier must contain FRZ = 0)"* is the clause's own
    /// sentence for the false case.
    #[must_use]
    pub const fn accepts_freeze(self) -> bool {
        matches!(self, Self::FreezeAndTransmit | Self::FreezeSpontaneous)
    }

    /// Whether the frozen values are reported spontaneously rather than asked
    /// for: modes A and D. Those values carry cause 3 and belong to spontaneous
    /// transmission ([`crate::tx`]); this procedure produces none of them.
    #[must_use]
    pub const fn reports_spontaneously(self) -> bool {
        matches!(self, Self::LocalFreezeSpontaneous | Self::FreezeSpontaneous)
    }

    /// Whether a `FRZ = <0>` **collection** belongs to this mode: true only
    /// for modes B and C.
    ///
    /// Mode A issues no `C_CI` at all, and mode D is *"a combination of the
    /// counter command from the controlling station as specified in mode C,
    /// with spontaneous reporting of the integrated totals, as described in
    /// mode A"*: its command is `FRZ` 1…3 and its values arrive by themselves.
    /// TS 60870-5-604 Table 20's mode D procedure (test 5.4.20.30, PDF page
    /// index 81, printed 80) draws exactly that (*"`C_CI_ACT`, FRZ=1..3 (freeze,
    /// freeze with reset, reset)"* then *"`M_IT_SPONT`"* with *"COT = 3
    /// (SPONT)"*) and has no collection and no `C_CI_ACTTERM`.
    #[must_use]
    pub const fn accepts_collection(self) -> bool {
        matches!(
            self,
            Self::LocalFreezeByInterrogation | Self::FreezeAndTransmit
        )
    }
}

/// The controlled station's own counter data.
///
/// Neither fact the procedure needs can be invented here: the *membership* of
/// a counter group is project data (5-101 clause 7.4.8: *"The assignments of
/// the information object addresses of the integrated totals to the specific
/// groups have to be specified in the controlled station."*), and the
/// *geometry* of an `M_IT` ASDU is clause 7.3.1's (the layouts in
/// [`crate::asdu`]). An implementation builds each ASDU through the layout
/// layer with [`Request::cause`] as its cause of transmission and one of the
/// [`COUNTER_TYPES`], which the procedure checks.
pub trait CounterSource {
    /// Whether the station can return `request` right now. A `false` answers
    /// the activation with a negative confirmation; see the module doc for why
    /// this is the crate's reading rather than a clause sentence.
    fn ready(&self, request: Request) -> bool;

    /// Appends the `M_IT` ASDUs `request` returns, in the order they are to be
    /// sent.
    fn totals(&self, request: Request, out: &mut Vec<Vec<u8>>);
}

/// What one frame of the procedure means, from the point of view of the role
/// that received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// An activation confirmation arrived or was sent, positive when
    /// `negative` is false. The same cause 7 carries both, with `P/N` as the
    /// flag, and `freeze` is the `FRZ` of the request it mirrors: a request
    /// whose `FRZ` is not [`FreezeMode::Read`] is a memorize transaction and
    /// ends here (5-101 figure 95).
    ActivationConfirmed {
        /// The request the confirmation answers.
        request: Request,
        /// The `FRZ` the confirmation mirrors.
        freeze: FreezeMode,
        /// `P/N = 1`: a negative confirmation.
        negative: bool,
    },
    /// An integrated total arrived, with the request's cause of transmission
    /// `<37>` … `<41>`.
    Counted {
        /// The request the object was returned for.
        request: Request,
    },
    /// A collection ended (`C_CI ACTTERM`, cause `<10>`).
    Terminated {
        /// The request that ended.
        request: Request,
    },
    /// Controlled station: the station's [`CounterMode`] does not permit the
    /// activation, and it was answered with a negative confirmation. `reason`
    /// is [`CiError::RequestsNotAccepted`], [`CiError::FreezeNotAllowed`] or
    /// [`CiError::CollectionNotAllowed`].
    Rejected {
        /// The request the negative confirmation answers.
        request: Request,
        /// The `FRZ` it mirrors.
        freeze: FreezeMode,
        /// Why the mode refuses it.
        reason: CiError,
    },
    /// A clause 7.2.3 mirror (`P/N = 1`, cause 44–47). Controlled station: the
    /// received ASDU had an unknown field and its mirror is in
    /// [`Outcome::send`]. Controlling station: the peer mirrored a `C_CI`,
    /// which settles that activation.
    Refused {
        /// The mirrored `QCC`, when the frame is type 101 with a defined `RQT`.
        activation: Option<(Request, FreezeMode)>,
        /// The mirror's cause: 44, 45, 46 or 47.
        cause: Cause,
    },
    /// Clause 7.2.3 says this ASDU is discarded and may be logged.
    Discard(Discard),
    /// Not this procedure: the type, the cause or the qualifier says the ASDU
    /// belongs to another one. This includes a deactivation of this type, which
    /// clause 7.4.8 removes from the procedure in terms.
    Other,
}

/// What a received ASDU means, and what to send because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The classification of the received ASDU.
    pub reaction: Reaction,
    /// The ASDUs to send, in order. Always empty for a controlling station;
    /// for a controlled station it carries the confirmation or the clause
    /// 7.2.3 mirror.
    pub send: Vec<Vec<u8>>,
}

/// What can go wrong in this layer, over and above the codec's own errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiError {
    /// A counter group outside `1..=4`: the request would name another group,
    /// so it is refused rather than clamped.
    GroupOutOfRange {
        /// The group number asked for.
        group: u8,
    },
    /// The entry point does not belong to this instance's role: `request` and
    /// `on_response` are the controlling station's, `on_request` and the
    /// response-building methods are the controlled station's.
    WrongRole,
    /// The station's [`CounterMode`] does not issue counter interrogation
    /// commands at all: mode A's *"The controlling station does not issue
    /// counter interrogation commands (`C_CI`)."*
    RequestsNotAccepted {
        /// The mode that refuses it.
        mode: CounterMode,
    },
    /// The [`CounterMode`] does not permit a `FRZ` other than
    /// [`FreezeMode::Read`]: mode B's *"the command qualifier must contain
    /// FRZ = 0"*.
    FreezeNotAllowed {
        /// The mode that refuses it.
        mode: CounterMode,
    },
    /// The [`CounterMode`] does not define a `FRZ = <0>` collection (modes A
    /// and D). See [`CounterMode::accepts_collection`].
    CollectionNotAllowed {
        /// The mode that refuses it.
        mode: CounterMode,
    },
    /// There is nothing to produce the frames for: no collection is running (a
    /// memorize never opens one), or, for
    /// [`CounterInterrogation::interrogated`], its data was already produced.
    NotRunning,
    /// The controlled station's [`CounterSource`] returned an ASDU that is not
    /// one of the [`COUNTER_TYPES`] `M_IT` types.
    NotCounterType {
        /// The type the data source returned.
        type_id: TypeId,
    },
    /// The same data source returned an ASDU whose cause of transmission is not
    /// the request's own (`<37>` … `<41>`).
    WrongCause {
        /// The request's cause, which the ASDU should have carried.
        expected: Cause,
        /// The cause it carried.
        got: Cause,
    },
    /// The ASDU itself could not be parsed; the layout/header layer's error,
    /// unchanged.
    Layout(LayoutError),
}

impl From<LayoutError> for CiError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<AsduError> for CiError {
    /// The header/codec error reaches this layer through the layout layer's own
    /// wrapper, exactly as [`crate::asdu::decode_asdu`] surfaces it.
    fn from(err: AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// Builds one type-101 frame: `N = 1`, `SQ = 0`, an information object address
/// of zero (figure 73), and the `QCC`, `P/N` and `T` as given. The cause is the caller's here
/// and the clause's in every public builder.
fn frame(
    cause: Cause,
    negative: bool,
    test: bool,
    qcc: Qcc,
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
        test,
        originator,
        common_address,
    };
    let object = LayoutObject {
        ioa: IOA_IRRELEVANT,
        value: CCiNa1 { qcc },
    };
    encode_asdu_with(&header, &[object], sizes)
}

/// Builds the activation.
///
/// The activation is the ten-octet `C_CI_NA_1` of 5-101 clause 7.3.4.2, with
/// cause 6 (`act`), `N = 1`, `SQ = 0` and an information object address of
/// zero (figure 73's `INFORMATION OBJECT ADDRESS = 0`), carrying `request` and
/// `freeze` as its `QCC`.
///
/// The cause and the information object address are the clause's, not the
/// caller's, so a frame the standard does not list for type 101 cannot be built
/// from this API. The error is the layout layer's and cannot occur for these
/// arguments; it is propagated rather than unwrapped because nothing in `src/`
/// panics.
///
/// # Errors
///
/// None for these arguments in the conventional address sizes; the layout
/// layer's [`LayoutError`] is passed through unchanged.
pub fn request(
    request: Request,
    freeze: FreezeMode,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, LayoutError> {
    request_with(
        request,
        freeze,
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
    request: Request,
    freeze: FreezeMode,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    frame(
        CAUSE_ACTIVATION,
        false,
        false,
        request.qcc(freeze),
        common_address,
        originator,
        sizes,
    )
}

/// Which side of the procedure a [`CounterInterrogation`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The requesting side: sends the activation, confirms nothing.
    Controlling,
    /// The requested side: confirms, returns the totals, terminates.
    Controlled,
}

/// One role's counter interrogation procedure.
///
/// The role here is the *procedure's* role, not the transport's: a station that
/// is the TCP client is the controlling station (5-104 clause 7), but the same
/// station may hold the other role's instance for the reverse direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterInterrogation {
    role: Role,
    mode: CounterMode,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
    /// Controlling station: activations sent whose confirmation has not
    /// arrived, keyed by `FRZ` too so a freeze and a collection of the same
    /// request are told apart.
    pending: Vec<(Request, FreezeMode)>,
    /// Both roles: activations that are confirmed and not yet terminated.
    running: Vec<Request>,
    /// Controlled station: the running collections whose data is still owed.
    owed: Vec<Request>,
    /// Controlled station: the originator address and test bit each running
    /// collection's activation came with, echoed on its termination, and the
    /// originator on its data too (cl.7.2.3).
    origins: Vec<(Request, u8, bool)>,
}

impl CounterInterrogation {
    /// A controlling station's instance, selecting the station's counter mode.
    #[must_use]
    pub const fn controlling(mode: CounterMode, common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlling,
            mode,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
            pending: Vec::new(),
            running: Vec::new(),
            owed: Vec::new(),
            origins: Vec::new(),
        }
    }

    /// A controlled station's instance, selecting the station's counter mode.
    #[must_use]
    pub const fn controlled(mode: CounterMode, common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlled,
            mode,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
            pending: Vec::new(),
            running: Vec::new(),
            owed: Vec::new(),
            origins: Vec::new(),
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

    /// The station's counter mode.
    #[must_use]
    pub const fn mode(&self) -> CounterMode {
        self.mode
    }

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// The requests that are running: sent and not yet confirmed, or
    /// confirmed collections not yet terminated. A memorize transaction appears
    /// only while its confirmation is in flight, because it has no termination.
    /// For a controlled station it is the confirmed collections whose
    /// termination is still owed (whether their data is owed too is
    /// [`CounterInterrogation::awaiting_data`]).
    #[must_use]
    pub fn running(&self) -> Vec<Request> {
        let mut requests: Vec<Request> = Vec::new();
        for (request, _) in &self.pending {
            if !requests.contains(request) {
                requests.push(*request);
            }
        }
        for request in &self.running {
            if !requests.contains(request) {
                requests.push(*request);
            }
        }
        requests
    }

    /// Whether `request` is running.
    #[must_use]
    pub fn is_running(&self, request: Request) -> bool {
        self.pending.iter().any(|(r, _)| *r == request) || self.running.contains(&request)
    }

    /// The activations sent whose confirmation has not arrived.
    #[must_use]
    pub fn awaiting_confirmation(&self) -> Vec<Request> {
        self.pending.iter().map(|(r, _)| *r).collect()
    }

    /// Whether the controlled station owes a running collection's data.
    #[must_use]
    pub const fn awaiting_data(&self) -> bool {
        !self.owed.is_empty()
    }

    /// Drops every pending and running activation, for either role.
    ///
    /// For the caller's connection loss or reconnect and for its own reply
    /// time-out, neither of which this module observes.
    pub fn reset(&mut self) {
        self.pending.clear();
        self.running.clear();
        self.owed.clear();
        self.origins.clear();
    }

    /// Drops everything outstanding for `request` (activations awaiting their
    /// confirmation, whatever their `FRZ`, and a running collection) and
    /// reports whether there was anything. Nothing is sent.
    ///
    /// For the controlling station's own reply time-out on one request, where
    /// [`CounterInterrogation::reset`] drops them all.
    pub fn abandon(&mut self, request: Request) -> bool {
        let had = self.is_running(request) || self.owed.contains(&request);
        self.pending.retain(|(r, _)| *r != request);
        self.running.retain(|r| *r != request);
        self.owed.retain(|r| *r != request);
        self.origins.retain(|(r, _, _)| *r != request);
        had
    }

    /// The controlling station's activation of `request` with `freeze`, as the
    /// frame to send.
    ///
    /// A station whose mode does not issue counter interrogation commands
    /// (mode A) refuses it with [`CiError::RequestsNotAccepted`]; one whose mode
    /// has no collection procedure (mode D) refuses a [`FreezeMode::Read`] with
    /// [`CiError::CollectionNotAllowed`]; and one that must not freeze refuses a
    /// `FRZ` other than `Read` with [`CiError::FreezeNotAllowed`]. There is no
    /// lock on a second activation: 5-101 clause 7.4.5's "normally locked"
    /// sentence is general interrogation's, and this procedure has no
    /// counterpart (see the module doc).
    ///
    /// # Errors
    ///
    /// [`CiError::WrongRole`] on a controlled instance,
    /// [`CiError::GroupOutOfRange`] for a group outside `1..=4`, the mode's
    /// refusals named above, and [`CiError::Layout`] when the frame cannot be
    /// built.
    pub fn request(&mut self, request: Request, freeze: FreezeMode) -> Result<Vec<u8>, CiError> {
        if self.role != Role::Controlling {
            return Err(CiError::WrongRole);
        }
        if let Request::Group(group) = request
            && Request::try_group(group).is_none()
        {
            return Err(CiError::GroupOutOfRange { group });
        }
        if !self.mode.accepts_requests() {
            return Err(CiError::RequestsNotAccepted { mode: self.mode });
        }
        if freeze == FreezeMode::Read && !self.mode.accepts_collection() {
            return Err(CiError::CollectionNotAllowed { mode: self.mode });
        }
        if freeze != FreezeMode::Read && !self.mode.accepts_freeze() {
            return Err(CiError::FreezeNotAllowed { mode: self.mode });
        }
        let frame = request_with(request, freeze, self.ca, self.org, self.sizes)?;
        if !self.pending.contains(&(request, freeze)) {
            self.pending.push((request, freeze));
        }
        Ok(frame)
    }

    /// The controlling station's decision for one received ASDU.
    ///
    /// Clause 7.2.3's discard rule runs first, exactly as it does in
    /// [`crate::init::on_asdu`] and [`crate::gi`]. A type-101 frame whose cause
    /// is not one of figure 73's monitor-direction responses is
    /// [`Reaction::Other`]. That includes a deactivation confirmation, because
    /// clause 7.4.8 removes causes 8 and 9 from this procedure. The returned
    /// [`Outcome::send`] is always empty.
    ///
    /// # Errors
    ///
    /// [`CiError::WrongRole`] on a controlled instance, and [`CiError::Layout`]
    /// when the header, or the `QCC` of a confirmation or termination, cannot
    /// be parsed.
    pub fn on_response(&mut self, asdu: &[u8], known: &Known) -> Result<Outcome, CiError> {
        if self.role != Role::Controlling {
            return Err(CiError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if header.type_id == TYPE_ID && is_mirror(&header) {
            // The peer refused an activation still in flight: settle it, or it
            // would stay pending forever.
            if let Some(activation) = qcc_of(asdu, self.sizes).ok().flatten()
                && self.pending.contains(&activation)
            {
                self.pending.retain(|p| *p != activation);
                return Ok(Outcome {
                    reaction: Reaction::Refused {
                        activation: Some(activation),
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
        // The frame's own type decides which family it belongs to: the answers
        // to the command are `C_CI_NA_1` frames carrying the qualifier of
        // counter interrogation, while the objects of the response are `M_IT`
        // ASDUs recognised by their cause of transmission.
        let reaction = match (header.type_id == TYPE_ID, header.cause) {
            (true, Cause::ActivationCon) => {
                let Some((request, freeze)) = qcc_of(asdu, self.sizes)? else {
                    return Ok(other());
                };
                if !self.pending.contains(&(request, freeze)) {
                    return Ok(other());
                }
                self.pending.retain(|p| *p != (request, freeze));
                // Only a collection opens a running procedure: a memorize is
                // confirmed and ends there (5-101 figure 95), so a later
                // termination for it would be nothing to end. A negative
                // confirmation settles the activation in flight and starts
                // nothing; the request stays repeatable.
                if !header.negative
                    && freeze == FreezeMode::Read
                    && !self.running.contains(&request)
                {
                    self.running.push(request);
                }
                Reaction::ActivationConfirmed {
                    request,
                    freeze,
                    negative: header.negative,
                }
            }
            (false, Cause::RequestedByGeneralCounter) if is_counter_type(header.type_id) => {
                self.reporting(Request::General)
            }
            (false, Cause::RequestedByCounterGroup(n)) if is_counter_type(header.type_id) => {
                self.reporting(Request::group(n))
            }
            (true, Cause::ActivationTermination) => {
                let Some((request, _)) = qcc_of(asdu, self.sizes)? else {
                    return Ok(other());
                };
                // Figure 95: the termination is "COUNTER REQUEST TERMINATED".
                // It ends a confirmed collection, or one whose confirmation it
                // overtook; a memorize has no termination (see above).
                let collection = (request, FreezeMode::Read);
                if self.running.contains(&request) {
                    self.running.retain(|r| *r != request);
                } else if self.pending.contains(&collection) {
                    self.pending.retain(|p| *p != collection);
                } else {
                    return Ok(other());
                }
                Reaction::Terminated { request }
            }
            _ => Reaction::Other,
        };
        Ok(Outcome {
            reaction,
            send: Vec::new(),
        })
    }

    /// Whether one object of `request` is ours to report: the collection has to
    /// be running, so the rule that the responses end at the termination lives
    /// in this one predicate.
    fn reporting(&self, request: Request) -> Reaction {
        if self.running.contains(&request) {
            Reaction::Counted { request }
        } else {
            Reaction::Other
        }
    }

    /// The controlled station's decision for one received ASDU, with its own
    /// data as the source of a response.
    ///
    /// A positively confirmed **collection** (`FRZ = 0`) leaves the request
    /// running but does not yet produce its data: the caller asks
    /// [`CounterInterrogation::interrogated`] for it, so a station whose totals
    /// do not fit one window releases them under its own flow control, and then
    /// [`CounterInterrogation::complete`] ends the procedure. A **memorize**
    /// (`FRZ` other than [`FreezeMode::Read`]) is confirmed and ends there,
    /// with no data and no termination, which is 5-101 figure 95's exchange.
    ///
    /// # Errors
    ///
    /// [`CiError::WrongRole`] on a controlling instance, and [`CiError::Layout`]
    /// when the header or the activation's `QCC` cannot be parsed, or the
    /// confirmation cannot be built.
    pub fn on_request(
        &mut self,
        asdu: &[u8],
        known: &Known,
        data: &dyn CounterSource,
    ) -> Result<Outcome, CiError> {
        if self.role != Role::Controlled {
            return Err(CiError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if let Some(reason) = discard_reason(&header, known) {
            if let Discard::Unspecified(which) = reason {
                // Clause 7.2.3: a control-direction field the station does not
                // know is mirrored with P/N = 1 and the class's cause.
                let activation = if header.type_id == TYPE_ID {
                    qcc_of(asdu, self.sizes).ok().flatten()
                } else {
                    None
                };
                return Ok(Outcome {
                    reaction: Reaction::Refused {
                        activation,
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
            Cause::Activation => {
                let Some((request, freeze)) = qcc_of(asdu, self.sizes)? else {
                    return Ok(other());
                };
                let refused = if !self.mode.accepts_requests() {
                    Some(CiError::RequestsNotAccepted { mode: self.mode })
                } else if freeze != FreezeMode::Read && !self.mode.accepts_freeze() {
                    Some(CiError::FreezeNotAllowed { mode: self.mode })
                } else if freeze == FreezeMode::Read && !self.mode.accepts_collection() {
                    Some(CiError::CollectionNotAllowed { mode: self.mode })
                } else {
                    None
                };
                if let Some(reason) = refused {
                    // Answered negatively so the peer is not left waiting.
                    return Ok(Outcome {
                        reaction: Reaction::Rejected {
                            request,
                            freeze,
                            reason,
                        },
                        send: vec![self.confirmation(request, freeze, true, &header)?],
                    });
                }
                if !data.ready(request) {
                    return self.confirmation_outcome(request, freeze, true, &header);
                }
                if freeze == FreezeMode::Read {
                    if !self.running.contains(&request) {
                        self.running.push(request);
                    }
                    if !self.owed.contains(&request) {
                        self.owed.push(request);
                    }
                    self.origins.retain(|(r, _, _)| *r != request);
                    self.origins.push((request, header.originator, header.test));
                }
                self.confirmation_outcome(request, freeze, false, &header)
            }
            // Clause 7.4.8: "C_CI DEACT and DEACTCON are not used."
            _ => Ok(other()),
        }
    }

    /// The frames of the running collection's data, which the controlled
    /// station sends before its termination.
    ///
    /// Every ASDU comes from the [`CounterSource`] and is checked here: its
    /// cause of transmission must be the running request's, and its type must
    /// be one of the [`COUNTER_TYPES`] `M_IT` types.
    ///
    /// # Errors
    ///
    /// [`CiError::WrongRole`] on a controlling instance,
    /// [`CiError::NotRunning`] when no collection's data is owed, and
    /// [`CiError::NotCounterType`], [`CiError::WrongCause`] or
    /// [`CiError::Layout`] when an ASDU from the source fails the checks.
    pub fn interrogated(&mut self, data: &dyn CounterSource) -> Result<Vec<Vec<u8>>, CiError> {
        if self.role != Role::Controlled {
            return Err(CiError::WrongRole);
        }
        let request = self.owed.first().copied().ok_or(CiError::NotRunning)?;
        let frames = collect(data, request, self.sizes, self.origin(request))?;
        self.owed.remove(0);
        Ok(frames)
    }

    /// Ends the running collection.
    ///
    /// The frames are its data, if [`CounterInterrogation::interrogated`] has
    /// not produced it yet, then the termination (`C_CI ACTTERM`, cause 10),
    /// mirroring the request it closes (5-101 clause 7.4.8 and Table 20's
    /// *"The Controlled station sends the same Counter interrogation command it
    /// received (ASDU 101) with COT = 10, `C_CI_ACTTERM`"*). The `FRZ` it carries
    /// is [`FreezeMode::Read`], the collection's own.
    ///
    /// The data always comes before the termination (5-101 clause 7.4.8 and
    /// figure 95: the totals, then `COUNTER REQUEST TERMINATED`). If the
    /// [`CounterSource`] fails, the error is returned and nothing has changed.
    ///
    /// # Errors
    ///
    /// [`CiError::WrongRole`] on a controlling instance,
    /// [`CiError::NotRunning`] when no collection is running, the errors of
    /// [`CounterInterrogation::interrogated`] for owed data, and
    /// [`CiError::Layout`] when the termination cannot be built.
    pub fn complete(&mut self, data: &dyn CounterSource) -> Result<Vec<Vec<u8>>, CiError> {
        if self.role != Role::Controlled {
            return Err(CiError::WrongRole);
        }
        let request = self.running.first().copied().ok_or(CiError::NotRunning)?;
        let mut frames = if self.owed.contains(&request) {
            collect(data, request, self.sizes, self.origin(request))?
        } else {
            Vec::new()
        };
        let (originator, test) = self.origin(request);
        frames.push(frame(
            CAUSE_ACTIVATION_TERM,
            false,
            test,
            request.qcc(FreezeMode::Read),
            self.ca,
            originator,
            self.sizes,
        )?);
        self.running.retain(|r| *r != request);
        self.owed.retain(|r| *r != request);
        self.origins.retain(|(r, _, _)| *r != request);
        Ok(frames)
    }

    /// The originator address and test bit `request`'s activation came with,
    /// or this station's own and `T = 0` when none is recorded.
    fn origin(&self, request: Request) -> (u8, bool) {
        self.origins
            .iter()
            .find(|(r, _, _)| *r == request)
            .map_or((self.org, false), |(_, org, test)| (*org, *test))
    }

    /// The confirmation of `request` with `P/N` as given, echoing the
    /// activation's originator address and test bit.
    fn confirmation(
        &self,
        request: Request,
        freeze: FreezeMode,
        negative: bool,
        activation: &Header,
    ) -> Result<Vec<u8>, CiError> {
        Ok(frame(
            CAUSE_ACTIVATION_CON,
            negative,
            activation.test,
            request.qcc(freeze),
            self.ca,
            activation.originator,
            self.sizes,
        )?)
    }

    /// The whole answer to an activation: the confirmation, and nothing else.
    /// A collection's data follows from
    /// [`CounterInterrogation::interrogated`].
    fn confirmation_outcome(
        &self,
        request: Request,
        freeze: FreezeMode,
        negative: bool,
        activation: &Header,
    ) -> Result<Outcome, CiError> {
        Ok(Outcome {
            reaction: Reaction::ActivationConfirmed {
                request,
                freeze,
                negative,
            },
            send: vec![self.confirmation(request, freeze, negative, activation)?],
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

/// The request and freeze mode of a received type-101 ASDU's qualifier, or
/// `None` when clause 7.2.6.23 leaves the `RQT` not used, reserved or private.
fn qcc_of(asdu: &[u8], sizes: AddressSizes) -> Result<Option<(Request, FreezeMode)>, CiError> {
    let objects = decode_asdu_with::<CCiNa1>(asdu, sizes)?;
    Ok(objects.first().and_then(|object| {
        Request::from_rqt(object.value.qcc.rqt).map(|r| (r, object.value.qcc.frz))
    }))
}

/// The data one request's collection returns, checked against the clause before
/// it can reach the wire: every ASDU must carry that request's own cause of
/// transmission `<37>` … `<41>` and be one of the [`COUNTER_TYPES`] `M_IT`
/// types.
fn collect(
    data: &dyn CounterSource,
    request: Request,
    sizes: AddressSizes,
    (originator, test): (u8, bool),
) -> Result<Vec<Vec<u8>>, CiError> {
    let mut raw = Vec::new();
    data.totals(request, &mut raw);
    let mut frames = Vec::with_capacity(raw.len());
    for asdu in raw {
        let header = Header::parse_with(&asdu, sizes)?;
        if !is_counter_type(header.type_id) {
            return Err(CiError::NotCounterType {
                type_id: header.type_id,
            });
        }
        if header.cause != request.cause() {
            return Err(CiError::WrongCause {
                expected: request.cause(),
                got: header.cause,
            });
        }
        // The totals answer the request too, so they echo its originator and test bit.
        frames.push(crate::asdu::with_origin(&asdu, originator, test, sizes)?);
    }
    Ok(frames)
}
