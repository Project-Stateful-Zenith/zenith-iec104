//! The application test procedure: 5-104 clause **7.10**'s `C_TS ACT` /
//! `C_TS ACTCON` exchange, in both forms the two standards define.
//!
//! # The service, and which type carries it
//!
//! 5-104 clause **7.10** (PDF page index 72, printed page 71) is headed *"Test
//! procedure (6.11 of IEC 60870-5-5)"* and its table is four rows, verbatim:
//!
//! ```text
//! A_TEST.req  send     C_TS ACT
//! A_TEST.ind  receive  C_TS ACT
//! A_TEST.res  send     C_TS ACTCON
//! A_TEST.con  receive  C_TS ACTCON
//! ```
//!
//! The ASDU label is `C_TS`, not a type number; the type comes from the profile.
//! 104 **Table 4** (index 52, printed page 51), *"System information in control
//! direction"*, carries `CON <107> := test command with time tag CP56Time2a` /
//! `C_TS_TA_1` and has no `<104>` row (it runs `<100>`, `<101>`, `<102>`,
//! `<103>`, `<105>`, `<107>`). 5-101 **Table 11** (index 33, printed page 32)
//! marks `CON <104> := test command` / `C_TS_NA_1` and puts `<107..109>` under
//! *"reserved for further compatible definitions"*.
//!
//! 104's clause-9 type/cause matrix (index **106**, printed page 105) draws the
//! whole `<104>` `C_TS_NA_1` row as black boxes and leaves the `<107>`
//! `C_TS_TA_1` row blank (read from the page's vector fills). The legend (index
//! **104**, printed page 103) reads *"Black boxes: option not permitted in this
//! companion standard"*. The PICS page *"System information in control
//! direction"* (index 102, printed page 101) lists `<104> := Test command
//! C_TS_NA_1` and `<107> := Test command with time tag CP56Time2a C_TS_TA_1`.
//! The type catalogue follows this reading: [`TypeId::is_selected_104`] is
//! false for 104 and true for 107.
//!
//! So [`Form::Untagged`] is the 5-101 profile's command and [`Form::Tagged`] is
//! 104's, and a station selects one of them ([`Selection`]). This is not a 104
//! feature switch: a 104 station has no untagged test command.
//!
//! # The untagged command: one constant element
//!
//! 5-101 clause **7.3.4.5** (index 108, printed page 107) is headed *"TYPE IDENT
//! 104: `C_TS_NA_1` Test command"*, *"Single information object (SQ = 0)"*, and
//! its **figure 76** prints
//!
//! ```text
//! C_TS_NA_1 := CP{Data unit identifier,Information object address,FBP}
//! ```
//!
//! with `INFORMATION OBJECT ADDRESS = 0` in the figure's field row and the
//! causes `<6>` activation (control direction), `<7>` activation confirmation
//! and `<44>`–`<47>` (monitor direction). `FBP` is 5-101 clause **7.2.6.14**
//! (index 51, printed page 50), verbatim: *"Fixed test bit pattern, two
//! octets"*, `FBP := UI16[1..16]<55AAH>` (Type 1.1). A station recognises the
//! command by the pattern, so [`Fbp::parse`] accepts `0x55AA` and nothing else
//! ([`AsduError::FixedPatternMismatch`]). On the wire it is `AA 55`
//! ([`Fbp::VALUE`] little-endian).
//!
//! # The tagged command and its echo rule (104 clause 8.8)
//!
//! Clause **8.8** (index 90, printed page 89) is headed *"TYPE IDENT 107:
//! `C_TS_TA_1` Test command with time tag `CP56Time2a`"*, *"Single information
//! object (SQ = 0)"*, and **figure 30** prints `C_TS_TA_1 := CP{Data unit
//! identifier,Information object address,TSC,CP56Time2a}`,
//! `TSC := UI16[1..16]<0..65535>`, *"TSC = Test sequence counter, 16 bit"*, the
//! seven-octet `CP56Time2a`, and the same cause list as figure 76. The clause's
//! rule, verbatim:
//!
//! > The requesting station may choose any value of TSC. The TSC in the
//! > response shall match the request, and the time in the response shall also
//! > exactly match the time in the request.
//!
//! The caller picks the values; the echo check is the crate's. A confirmation
//! whose value differs from what this station sent is [`TsError::EchoMismatch`],
//! not [`Reaction::Answered`]. That is what TS 60870-5-604 asks for with
//! *"Mismatching values of TSC are detected by the Primary station"* (Table 22,
//! row `5.4.22.1`, index 83, printed page 82, required `M`). Whether to log it,
//! drop the link or retry is the caller's decision.
//!
//! # The confirmation is the command mirrored
//!
//! 5-101 Table 11 marks `CON <104>` and 104 Table 4 marks `CON <107>`. The NOTE
//! under 104 Tables 3 to 6 (index 52) says: *"ASDUs marked CON in the
//! control direction are confirmed application services and may be mirrored in
//! the monitor direction with different causes of transmission. These mirrored
//! ASDUs are used for positive/negative acknowledgements (verifications)."* So
//! the `ACTCON` of clause 7.10 is the same type and element with cause `<7>`
//! instead of `<6>`: the received object area, copied. That is not what
//! [`crate::cs`] does for type 103, whose `ACTCON` carries the controlled
//! station's time before the synchronisation, and unlike the read command's
//! answer of a different type ([`crate::rd`]; 104 does not mark `<102>`
//! `CON`). Taking *mirrored* literally has two consequences:
//!
//! * [`answer`] rewrites the header and copies the received object area; it does
//!   not re-encode the element, so a command at an information object address
//!   other than the figures' `<0>` is answered at that same address.
//! * The `P/N` bit makes the acknowledgement positive or negative (5-101 clause
//!   7.2.3, index 38: *"The P/N-bit indicates the positive or negative
//!   confirmation of activation requested by the primary application
//!   function"*), so [`Reaction::Answered`] carries it as its `negative` field.
//!
//! # 5-101's selection
//!
//! 5-101 clause **7.4.10** (index 130, printed page 129), *"Selections from test
//! procedure"*, reads in full: *"The complete procedure, defined in IEC
//! 60870-5-5, 6.11 is used."* 5-101 Table 16 (*"Respond priorities of the
//! controlled station"*, index 121, printed page 120) has the row *"102, 104,
//! 105, 110 to 113 | Read command, test procedure, reset process, parameter
//! loading"* between event reporting and station interrogation. This crate does
//! not order what is sent, so that priority is the caller's.
//!
//! # The 44–47 mirror, and why address `<0>` is accepted
//!
//! Both figures list `<44>`–`<47>` in the monitor direction: 5-101 clause
//! **7.2.3**'s mirror rule ([`crate::asdu::mirror_frame`]), where the received
//! ASDU comes back with `P/N = 1` and the class's cause, its object area copied
//! octet for octet. A positive `ACTCON` is never that mirror.
//!
//! A test command's information object address is `<0>` by definition: figure
//! 76's field row prints `INFORMATION OBJECT ADDRESS = 0`, and 5-101 clause
//! **7.2.5** says *"If the INFORMATION OBJECT ADDRESS is not relevant (not used)
//! in some ASDUs, it is set to zero"*. So nothing here refuses an address of
//! zero. [`crate::rd`] refuses `<0>` because there the address is the object
//! being read; that rule does not apply here.
//!
//! # A test command cannot be broadcast
//!
//! 5-101 clause **7.2.4** (index 43, printed page 42) restricts the broadcast
//! address to types `<100>`, `<101>`, `<103>` and `<105>`; neither 104 nor 107 is
//! on that list. TS 60870-5-604 clause **5.4.10.10** (index 54, printed page
//! 53) states the receiving side's rule: *"The Controlled station rejects
//! all other ASDU Types with a Broadcast CASDU value by mirroring the ASDU with
//! P/N = 1 negative (and with COT = 46, if supported)"*. So the builders refuse
//! `FF`/`FFFF` ([`TsError::BroadcastAddress`]), the answer carries the station's
//! own common address, and a broadcast test command that arrives gets the
//! class-46 mirror whatever the caller's [`Known`] says.
//!
//! # No state
//!
//! [`TestProcedure`] holds the role, the [`Selection`] and the addressing.
//! Clause 7.10's table has one act and one actcon, with no termination or
//! deactivation, so there is no running activation to track; a type-104/107
//! frame with another cause is [`Reaction::Other`]. Remembering what was sent
//! is the caller's job, which is why [`TestProcedure::on_response`] takes the
//! sent [`Command`] as an argument, as [`crate::cs::answer`] takes the
//! pre-synchronisation time.
//!
//! # What is left to the caller
//!
//! * **Whether the test runs on a cycle.** TS 60870-5-604 Table 22's row
//!   *"The Test command is sent at the configured interval period"* is marked
//!   `PID`/`PIXIT` (index 83), a configured interval. This module schedules
//!   nothing, holds no timer and reads no clock.
//! * **Which form the station's profile uses**: the [`Selection`]'s `form`.
//! * **Whether the station uses the function at all**: 104 clause 9.6's
//!   *"Test procedure (station-specific parameter, mark \"X\" if function is only
//!   used in the standard direction, \"R\" if only used in the reverse direction,
//!   and \"B\" if used in both directions)"* (index **112**, printed page 111;
//!   the *"Read procedure"* checkbox on index 108 is a different function).
//! * **What to do with a mismatched confirmation** ([`TsError::EchoMismatch`]):
//!   log it, close the link or retry.
//! * **The station's [`Known`] profile** for a received frame, from which the
//!   discard rule and the mirror decision are made.
//!
//! # Example
//!
//! ```
//! use iec104::asdu::{Cause, Cp56Time2a, Header, Known, Tsc, TypeId};
//! use iec104::ts::{
//!     answer, request_tagged, Command, Form, Reaction, Selection, TestProcedure,
//! };
//!
//! // A 104 station: the tagged form, which is the one 104 Table 4 carries.
//! let controlling = TestProcedure::controlling(Selection::TAGGED, 12, 0);
//! let controlled = TestProcedure::controlled(Selection::TAGGED, 12, 0);
//!
//! let tsc = Tsc::from_raw(7);
//! let time = Cp56Time2a { hours: 13, minutes: 16, ..Cp56Time2a::default() };
//! let command = controlling.request(Command::Tagged { tsc, time }).unwrap();
//! assert_eq!(command.len(), 18, "6 header + 3 IOA + 2 TSC + 7 time");
//! assert_eq!(Header::parse(&command).unwrap().cause, Cause::Activation);
//! assert_eq!(Header::parse(&command).unwrap().type_id, TypeId::CTsTa1);
//!
//! // The controlled station mirrors the command: the same type and the same
//! // element, cause 7, the request's originator and test bit.
//! let outcome = controlled.on_request(&command, &Known::EVERYTHING).unwrap();
//! assert_eq!(outcome.reaction, Reaction::Requested { command: Command::Tagged { tsc, time } });
//! assert_eq!(outcome.send[0], answer(&command, 12).unwrap());
//! assert_eq!(Header::parse(&outcome.send[0]).unwrap().type_id, TypeId::CTsTa1);
//!
//! // The requesting station checks the echo: the same TSC and the same time.
//! let confirmed = controlling
//!     .on_response(&outcome.send[0], &Known::EVERYTHING, Command::Tagged { tsc, time })
//!     .unwrap();
//! assert_eq!(
//!     confirmed.reaction,
//!     Reaction::Answered { command: Command::Tagged { tsc, time }, negative: false }
//! );
//!
//! // A confirmation whose TSC differs is a finding, not an answer
//! // (104 cl.8.8: "The TSC in the response shall match the request").
//! let other = answer(
//!     &request_tagged(Tsc::from_raw(8), time, 12, 0).unwrap(),
//!     12,
//! )
//! .unwrap();
//! assert!(controlling
//!     .on_response(&other, &Known::EVERYTHING, Command::Tagged { tsc, time })
//!     .is_err());
//!
//! // 5-101's untagged form exists too; a 104 station refuses to build it.
//! assert!(controlling.request(Command::Untagged { fbp: iec104::asdu::Fbp }).is_err());
//! assert_eq!(Form::Untagged.type_id(), TypeId::CTsNa1);
//! assert_eq!(request_tagged(tsc, time, 12, 0).unwrap(), command);
//! ```

use crate::asdu::{
    AddressSizes, AsduError, CTsNa1, CTsTa1, Cause, Cp56Time2a, Discard, Fbp, Header,
    IOA_IRRELEVANT, Known, LayoutError, LayoutObject, Tsc, TypeId, decode_asdu_with,
    discard_reason, encode_asdu_with, is_mirror, mirror_frame,
};

/// The untagged test command's type identification: 5-101 clause 7.3.4.5,
/// figure 76 (PDF page index 108), whose type-identification bit row reads
/// `0 1 1 0 1 0 0 0` = 104.
pub const TYPE_ID_UNTAGGED: TypeId = TypeId::CTsNa1;

/// The time-tagged test command's type identification: 5-104 clause 8.8,
/// figure 30 (PDF page index 90), whose type-identification bit row reads
/// `0 1 1 0 1 0 1 1` = 107.
pub const TYPE_ID_TAGGED: TypeId = TypeId::CTsTa1;

/// `<6> activation`: the cause of the request, and the only control-direction
/// cause figures 76 and 30 list.
pub const CAUSE_ACTIVATION: Cause = Cause::Activation;

/// `<7> activation confirmation`: the cause of the mirror (figures 76 and 30).
pub const CAUSE_ACTIVATION_CON: Cause = Cause::ActivationCon;

/// The broadcast address of 5-101 clause 7.2.4 (index 43) for a two-octet
/// common address. The clause permits broadcast only for `<100>`, `<101>`,
/// `<103>` and `<105>`; neither test command is on the list.
#[deprecated(
    note = "the broadcast address depends on the common-address width: use AddressSizes::broadcast_common_address"
)]
pub const BROADCAST_CA: u16 = 0xFFFF;

/// Which of the two test-command forms a station's profile uses.
///
/// 5-101 **Table 11** (index 33) marks `CON <104>` and leaves `<107..109>`
/// *"reserved for further compatible definitions"*, so [`Form::Untagged`] is the
/// 5-101 profile's command. 104 **Table 4** (index 52) carries `CON <107>` and
/// no `<104>` row, and the clause-9 matrix (index 106) marks the `<104>` row
/// *"option not permitted in this companion standard"*, so [`Form::Tagged`] is
/// the 104 profile's.
///
/// The form decides both which command a station sends and which one it
/// answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
    /// `C_TS_NA_1` `<104>`, 5-101 clause 7.3.4.5 (figure 76): the untagged
    /// command whose whole element is the constant `FBP`.
    Untagged,
    /// `C_TS_TA_1` `<107>`, 5-104 clause 8.8 (figure 30): the time-tagged
    /// command carrying the caller's `TSC` and `CP56Time2a`.
    Tagged,
}

impl Form {
    /// The type identification this form puts on the wire.
    #[must_use]
    pub const fn type_id(self) -> TypeId {
        match self {
            Self::Untagged => TYPE_ID_UNTAGGED,
            Self::Tagged => TYPE_ID_TAGGED,
        }
    }

    /// The other form: the one a station of this profile refuses.
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::Untagged => Self::Tagged,
            Self::Tagged => Self::Untagged,
        }
    }
}

/// Whether `type_id` is one of the two test-command types, over the **wire
/// octet** so an unnamed [`TypeId::Other`] of 104 or 107 answers as the named
/// variant does.
#[must_use]
pub const fn is_test_type(type_id: TypeId) -> bool {
    let raw = type_id.to_u8();
    raw == TYPE_ID_UNTAGGED.to_u8() || raw == TYPE_ID_TAGGED.to_u8()
}

/// Which form a type identification is.
#[must_use]
pub const fn form_of(type_id: TypeId) -> Option<Form> {
    if type_id.to_u8() == TYPE_ID_UNTAGGED.to_u8() {
        Some(Form::Untagged)
    } else if type_id.to_u8() == TYPE_ID_TAGGED.to_u8() {
        Some(Form::Tagged)
    } else {
        None
    }
}

/// Whether a station uses the test procedure, and in which form.
///
/// `used` is 104 clause 9.6's *"Test procedure"* checkbox (index 112, printed
/// page 111); `form` is which of the two types the station's profile carries
/// (104 Table 4 against 5-101 Table 11). A station that does not use the
/// function refuses to build either command and answers a received one with
/// the cause-44 mirror ([`Reaction::Unsupported`]). The `Default` selects
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// 104 clause 9.6's *"Test procedure"* checkbox.
    pub used: bool,
    /// Which form this station's profile carries.
    pub form: Form,
}

impl Selection {
    /// No function selected: the station builds neither command and answers
    /// neither.
    pub const NONE: Self = Self {
        used: false,
        form: Form::Tagged,
    };

    /// The 104 profile's selection: checkbox marked, tagged form (104 Table 4
    /// carries `<107>` and no `<104>`).
    pub const TAGGED: Self = Self {
        used: true,
        form: Form::Tagged,
    };

    /// The 5-101 profile's selection: checkbox marked, untagged form (5-101
    /// Table 11 marks `CON <104>` and reserves `<107..109>`).
    pub const UNTAGGED: Self = Self {
        used: true,
        form: Form::Untagged,
    };

    /// Whether the station uses the procedure at all.
    #[must_use]
    pub const fn uses(self) -> bool {
        self.used
    }

    /// The form this station's profile carries.
    #[must_use]
    pub const fn form(self) -> Form {
        self.form
    }

    /// The same selection with the clause 9.6 checkbox set to `used`.
    #[must_use]
    pub const fn with_used(self, used: bool) -> Self {
        Self { used, ..self }
    }

    /// The same selection with the profile's form set to `form`.
    #[must_use]
    pub const fn with_form(self, form: Form) -> Self {
        Self { form, ..self }
    }
}

impl Default for Selection {
    /// [`Selection::NONE`]: a station that has not said it uses the test
    /// procedure does not.
    fn default() -> Self {
        Self::NONE
    }
}

/// One test command's information element, as a value: the two forms' whole
/// payloads differ, and this is what the confirmation must carry back unchanged.
///
/// The untagged form's element is the constant `FBP` (5-101 clause 7.2.6.14:
/// `FBP := UI16[1..16]<55AAH>`, one legal value, by which a station recognises
/// the command); the tagged form carries 104 clause 8.8's `TSC` and
/// `CP56Time2a`. Carrying the `Fbp` in the value keeps the echo check of clause
/// 8.8 a comparison of complete values. A command whose `FBP` is not `55AAH` is
/// already [`AsduError::FixedPatternMismatch`] when it is parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// 5-101 clause 7.3.4.5's `C_TS_NA_1` `<104>`: the untagged form, whose
    /// whole element is the fixed test bit pattern.
    Untagged {
        /// The fixed test bit pattern the command carried: always [`Fbp`],
        /// which parses `55AAH` and nothing else.
        fbp: Fbp,
    },
    /// 5-104 clause 8.8's `C_TS_TA_1` `<107>`: the tagged form.
    Tagged {
        /// The test sequence counter the requesting station chose,
        /// `UI16[1..16]<0..65535>`.
        tsc: Tsc,
        /// The seven-octet time tag of the request.
        time: Cp56Time2a,
    },
}

impl Command {
    /// Which form this value is.
    #[must_use]
    pub const fn form(self) -> Form {
        match self {
            Self::Untagged { .. } => Form::Untagged,
            Self::Tagged { .. } => Form::Tagged,
        }
    }

    /// This value's type identification.
    #[must_use]
    pub const fn type_id(self) -> TypeId {
        self.form().type_id()
    }
}

/// Builds one untagged test command.
///
/// The frame is the eleven octets of 5-101 clause 7.3.4.5 (figure 76, index
/// 108), that is 6 header, 3 information object address and 2 `FBP`, with cause
/// `<6>`, `N = 1`, `SQ = 0`, the figure's information object address of zero
/// and the `FBP` constant `55AAH` (clause 7.2.6.14, index 51, wire order
/// `AA 55`).
///
/// The cause, the address and the element are fixed by the clause, so this
/// cannot build a frame the standard does not list for type 104. The broadcast
/// common address is [`TsError::BroadcastAddress`] (clause 7.2.4 does not permit
/// it for either test command). The test bit is written zero; the answer to a
/// `T = 1` command echoes the bit. This application-layer test is unrelated to
/// the link layer's `TESTFR` ([`crate::link`]).
///
/// # Errors
///
/// [`TsError::BroadcastAddress`] when `common_address` is the broadcast address,
/// and [`TsError::Layout`] when the frame cannot be encoded.
pub fn request_untagged(common_address: u16, originator: u8) -> Result<Vec<u8>, TsError> {
    request_untagged_with(common_address, originator, AddressSizes::CONVENTIONAL)
}

/// [`request_untagged`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`request_untagged`].
pub fn request_untagged_with(
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, TsError> {
    if common_address == sizes.broadcast_common_address() {
        return Err(TsError::BroadcastAddress { common_address });
    }
    Ok(untagged_frame(
        CAUSE_ACTIVATION,
        false,
        false,
        originator,
        common_address,
        sizes,
    )?)
}

/// Builds one time-tagged test command.
///
/// The frame is the eighteen octets of 104 clause 8.8 (figure 30, index 90),
/// that is 6 header, 3 information object address, 2 `TSC` and 7 `CP56Time2a`,
/// with cause `<6>`, `N = 1`, `SQ = 0`, the figure's information object address
/// of zero, and the caller's `tsc` and `time`.
///
/// The clause's own sentence is why both values are arguments: *"The requesting
/// station may choose any value of TSC."* The echo of both on the answer is
/// [`answer`]'s work, and [`TestProcedure::on_response`] checks it.
///
/// As in [`request_untagged`], the broadcast address is
/// [`TsError::BroadcastAddress`] and the cause and address are the clause's.
///
/// # Errors
///
/// [`TsError::BroadcastAddress`] when `common_address` is the broadcast address,
/// and [`TsError::Layout`] when the frame cannot be encoded.
pub fn request_tagged(
    tsc: Tsc,
    time: Cp56Time2a,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, TsError> {
    request_tagged_with(
        tsc,
        time,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`request_tagged`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`request_tagged`].
pub fn request_tagged_with(
    tsc: Tsc,
    time: Cp56Time2a,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, TsError> {
    if common_address == sizes.broadcast_common_address() {
        return Err(TsError::BroadcastAddress { common_address });
    }
    Ok(tagged_frame(
        CAUSE_ACTIVATION,
        false,
        false,
        originator,
        common_address,
        tsc,
        time,
        sizes,
    )?)
}

/// Builds the request of whichever form `command` is, through
/// [`request_untagged`] or [`request_tagged`].
///
/// The broadcast address is refused for both forms
/// ([`TsError::BroadcastAddress`]).
///
/// # Errors
///
/// As [`request_untagged`] or [`request_tagged`], whichever form `command` is.
pub fn request(command: Command, common_address: u16, originator: u8) -> Result<Vec<u8>, TsError> {
    request_with(
        command,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`request`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`request`].
pub fn request_with(
    command: Command,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, TsError> {
    match command {
        Command::Untagged { .. } => request_untagged_with(common_address, originator, sizes),
        Command::Tagged { tsc, time } => {
            request_tagged_with(tsc, time, common_address, originator, sizes)
        }
    }
}

/// Builds the controlled station's answer to a received test command.
///
/// The answer is the received frame with cause `<7>`, `P/N = 0` and this
/// station's common address, and the object area copied octet for octet. The
/// command's information object address therefore comes back unchanged even
/// when it is not `<0>`, and its originator address and `T` bit are echoed.
/// This follows 104 clause 7.10's `ACTCON` row and the NOTE under 104 Tables 3
/// to 6 (index 52): *"ASDUs marked CON in the control direction … may be
/// mirrored in the monitor direction with different causes of transmission."*
///
/// `command` is the received frame itself:
///
/// * its type identification must be one of the two test types
///   ([`TsError::NotThisType`]) and its cause `<6>`, the only control-direction
///   cause of figures 76 and 30 ([`TsError::CauseNotListed`]);
/// * its common address must not be the broadcast address, which clause 7.2.4
///   does not permit for 104 or 107 ([`TsError::BroadcastAddress`]);
/// * it must carry the one information object both figures define
///   ([`TsError::NoObjectInCommand`]). The frame is decoded, so a short prefix
///   is a typed error, and a command whose `FBP` is not `55AAH` is
///   [`AsduError::FixedPatternMismatch`] inside [`TsError::Layout`];
/// * its originator address and `T` bit are echoed (5-101 clause 7.2.3, index
///   38: *"the controlled station should echo this originator address in the
///   response in the monitor direction"*).
///
/// `common_address` is the station's own, since clause 7.2.4 answers with *"the
/// specific defined COMMON ADDRESS (station address)"*; the broadcast value is
/// refused ([`TsError::BroadcastAddress`]).
///
/// # Errors
///
/// [`TsError::Layout`] when `command` cannot be parsed or decoded,
/// [`TsError::NotThisType`], [`TsError::CauseNotListed`],
/// [`TsError::BroadcastAddress`] and [`TsError::NoObjectInCommand`] as listed
/// above.
pub fn answer(command: &[u8], common_address: u16) -> Result<Vec<u8>, TsError> {
    answer_with(command, common_address, AddressSizes::CONVENTIONAL)
}

/// [`answer`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`answer`].
pub fn answer_with(
    command: &[u8],
    common_address: u16,
    sizes: AddressSizes,
) -> Result<Vec<u8>, TsError> {
    let given = Header::parse_with(command, sizes)?;
    if !is_test_type(given.type_id) {
        return Err(TsError::NotThisType {
            type_id: given.type_id,
        });
    }
    if given.cause != CAUSE_ACTIVATION {
        return Err(TsError::CauseNotListed { cause: given.cause });
    }
    if given.common_address == sizes.broadcast_common_address() {
        return Err(TsError::BroadcastAddress {
            common_address: given.common_address,
        });
    }
    if common_address == sizes.broadcast_common_address() {
        // The answer carries the station's own address, never the broadcast one
        // (cl.7.2.4's *"specific defined COMMON ADDRESS (station address)"*).
        return Err(TsError::BroadcastAddress { common_address });
    }
    let Some(_) = command_of(command, sizes)? else {
        return Err(TsError::NoObjectInCommand);
    };
    Ok(activation_confirmation(
        &given,
        command,
        common_address,
        sizes,
    ))
}

/// The received command as the controlled station's answer: its header with
/// cause `<7>`, `P/N = 0` and the station's own common address, followed by the
/// received object area octet for octet, so the answer keeps the command's
/// information object address.
fn activation_confirmation(
    given: &Header,
    asdu: &[u8],
    common_address: u16,
    sizes: AddressSizes,
) -> Vec<u8> {
    let header = Header {
        cause: CAUSE_ACTIVATION_CON,
        negative: false,
        common_address,
        ..*given
    };
    let objects = asdu.get(sizes.header_len()..).unwrap_or(&[]);
    let mut out = Vec::with_capacity(sizes.header_len().saturating_add(objects.len()));
    let _ = header.encode_with(&mut out, sizes);
    out.extend_from_slice(objects);
    out
}

/// The 44–47 mirror of a received test command.
///
/// This is 5-101 clause 7.2.3's rule (`P/N = 1` and the class's cause, the
/// received object area copied octet for octet, [`crate::asdu::mirror_frame`]),
/// which the cause lists of figures 76 and 30 both print.
///
/// `Ok(None)` means the station knows every field [`Known`] asks about, so there
/// is nothing to refuse and the caller answers with [`answer`]. Otherwise the
/// mirror carries the class [`crate::asdu::classify`] reports, in the clause's
/// table order: 44, 45, 46, 47.
///
/// A broadcast common address is never legal on a test command, so its reply is
/// the class-46 mirror whatever `known` says (TS 60870-5-604 5.4.10.10). As in
/// [`crate::rd::refusal`], this is checked before the profile because it is a
/// property of the header. Unlike the read command there is no rule about an
/// address of zero, because a test command's address is zero by definition
/// (figure 76's field row).
///
/// `common_address` is the station's own, not the received frame's: clause
/// 7.2.4 answers with *"the specific defined COMMON ADDRESS (station
/// address)"*.
///
/// A frame that is not a test command is [`TsError::NotThisType`] (its type
/// identification is neither 104 nor 107) or [`TsError::CauseNotListed`] (a
/// test type with another cause, which clause 7.10's table does not define).
///
/// # Errors
///
/// [`TsError::NotThisType`] and [`TsError::CauseNotListed`] as above, and
/// [`TsError::Layout`] when the frame cannot be parsed or its object area
/// decoded.
pub fn refusal(
    asdu: &[u8],
    known: &Known,
    common_address: u16,
) -> Result<Option<Vec<u8>>, TsError> {
    refusal_with(asdu, known, common_address, AddressSizes::CONVENTIONAL)
}

/// [`refusal`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`refusal`].
pub fn refusal_with(
    asdu: &[u8],
    known: &Known,
    common_address: u16,
    sizes: AddressSizes,
) -> Result<Option<Vec<u8>>, TsError> {
    let header = Header::parse_with(asdu, sizes)?;
    if !is_test_type(header.type_id) {
        return Err(TsError::NotThisType {
            type_id: header.type_id,
        });
    }
    if header.cause != CAUSE_ACTIVATION {
        return Err(TsError::CauseNotListed {
            cause: header.cause,
        });
    }
    // Decode before mirroring: a truncated object area, or an `FBP` that is not
    // 55AAH, is a typed error rather than a malformed frame copied back.
    command_of(asdu, sizes)?;
    if header.common_address == sizes.broadcast_common_address() {
        return Ok(Some(mirror_frame(
            &header,
            asdu,
            crate::asdu::Unspecified::CommonAddress,
            common_address,
            sizes,
        )));
    }
    if let Some(which) = crate::asdu::classify(known) {
        return Ok(Some(mirror_frame(
            &header,
            asdu,
            which,
            common_address,
            sizes,
        )));
    }
    Ok(None)
}

/// What one frame of the test procedure means, from the point of view of the
/// station that received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// A test command arrived: one of the two types with cause `<6>` (clause
    /// 7.10's `A_TEST.ind`, figures 76 and 30). A controlled station answers it
    /// with [`answer`]'s frame, which carries the value back unchanged.
    Requested {
        /// The command's element: the untagged form's `FBP`, or the tagged
        /// form's `TSC` and time.
        command: Command,
    },
    /// The confirmation arrived: the same type and element with cause `<7>`
    /// (clause 7.10's `A_TEST.con`), carrying the value this station sent. A
    /// confirmation whose `TSC` or time differs is [`TsError::EchoMismatch`]
    /// instead (104 clause 8.8, TS 60870-5-604 5.4.22.1).
    ///
    /// `negative` is the header's `P/N` bit, which makes the confirmation
    /// positive or negative (5-101 clause 7.2.3, index 38).
    Answered {
        /// The command's element, unchanged.
        command: Command,
        /// The header's `P/N` bit: `false` = positive confirmation, `true` =
        /// negative one.
        negative: bool,
    },
    /// The 44–47 mirror of a test command arrived: the controlled station
    /// refused a field it does not know (5-101 clause 7.2.3). `cause` is the
    /// class the mirror carries, which names the field.
    Refused {
        /// The class's cause: 44, 45, 46 or 47.
        cause: Cause,
    },
    /// A test command this controlled station does not serve arrived; it was
    /// mirrored with cause 44 (unknown type identification, 5-101 cl.7.2.3), and
    /// the mirror is in [`Outcome::send`].
    Unsupported {
        /// Why the station does not serve it.
        reason: Unsupported,
    },
    /// Clause 7.2.3 says this ASDU is discarded and may be logged. A
    /// received mirror on the *controlled* side is this reaction rather than
    /// [`Reaction::Refused`], so two stations cannot mirror each other.
    Discard(Discard),
    /// Not this procedure: the type is not a test command, the cause is not
    /// the one this role expects, or the frame carries no information object
    /// at all (clause 7.2.2's `N = 0`).
    Other,
}

/// Why a controlled station answered a test command with the cause-44 mirror
/// ([`Reaction::Unsupported`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unsupported {
    /// The station does not use the test procedure (104 cl.9.6 checkbox).
    FunctionNotUsed,
    /// The command is of the other form than the station's [`Selection`].
    OtherForm,
}

/// What a received ASDU means, and what to send because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The classification of the received ASDU.
    pub reaction: Reaction,
    /// The ASDUs to send, in order. Empty on the requesting side and for every
    /// frame that is not a test command; otherwise the controlled station's one
    /// answer (clause 7.10's table has no third frame).
    pub send: Vec<Vec<u8>>,
}

/// What can go wrong in this layer, over and above the codec's own errors.
///
/// Every variant names a rule of the standard that the call would have broken. A
/// refusal the standard defines as a *frame* is not an error: the 44–47 mirror
/// of a test command is [`refusal`]'s `Ok(Some(..))` and [`Reaction::Refused`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TsError {
    /// The entry point does not belong to this instance's role: `request` and
    /// `on_response` are the controlling station's, `answer` and `on_request`
    /// the controlled station's.
    WrongRole,
    /// The station does not use the test procedure: 104 clause 9.6's *"Test
    /// procedure"* checkbox (index 112, printed page 111) is not marked.
    /// Returned by [`TestProcedure::request`], [`TestProcedure::answer`] and
    /// [`TestProcedure::on_response`]. A command received by such a station is
    /// answered with the cause-44 mirror instead ([`Reaction::Unsupported`]).
    FunctionNotUsed,
    /// The frame is not a test command at all: its type identification is
    /// neither [`TYPE_ID_UNTAGGED`] nor [`TYPE_ID_TAGGED`].
    NotThisType {
        /// The type identification the frame carried.
        type_id: TypeId,
    },
    /// The frame is a test command of the other form than the one this
    /// station's profile carries: an untagged `<104>` at a 104 station, or a
    /// tagged `<107>` at a 5-101 one (see [`Form`]).
    NotSelectedForm {
        /// The type identification the frame carried.
        type_id: TypeId,
    },
    /// The frame's cause of transmission is not `<6> activation`, the only
    /// control-direction cause figures 76 and 30 list ([`answer`],
    /// [`refusal`]).
    CauseNotListed {
        /// The cause the frame carried.
        cause: Cause,
    },
    /// The confirmation's value does not match what this station sent. 104
    /// clause 8.8: *"The TSC in the response shall match the request, and the
    /// time in the response shall also exactly match the time in the request."*
    /// TS 60870-5-604 5.4.22.1 (index 83) requires that *"Mismatching values of
    /// TSC are detected by the Primary station"*; what to do about it is the
    /// application's decision.
    EchoMismatch {
        /// What this station sent.
        sent: Command,
        /// What the confirmation carried.
        got: Command,
    },
    /// The common address is the broadcast address `FF`/`FFFF`, which 5-101
    /// clause 7.2.4 (index 43) restricts to types `<100>`, `<101>`, `<103>` and
    /// `<105>`; neither test command is on the list. Offered to the builders,
    /// carried by a command [`answer`] is asked to answer, or offered as the
    /// answering station's own address; a broadcast command that *arrives* is
    /// refused with the class-46 mirror instead (TS 60870-5-604 5.4.10.10).
    BroadcastAddress {
        /// The common address offered.
        common_address: u16,
    },
    /// The command carries no object (5-101 clause 7.2.2's `N = 0`). Both
    /// figures define `Single information object (SQ = 0)`, so a command
    /// without one carries no `FBP`/`TSC` to echo and nothing to answer with.
    NoObjectInCommand,
    /// The ASDU itself could not be parsed; the layout/header layer's error,
    /// unchanged. A command whose `FBP` is not `55AAH` arrives here as
    /// [`LayoutError::Asdu`] holding [`AsduError::FixedPatternMismatch`].
    Layout(LayoutError),
}

impl From<LayoutError> for TsError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<AsduError> for TsError {
    fn from(err: AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// Which side of the test procedure a [`TestProcedure`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The requesting side: sends the activation and checks the confirmation's
    /// echo, answering nothing.
    Controlling,
    /// The requested side: answers the command with the command mirrored.
    Controlled,
}

/// One role's test procedure.
///
/// The role here is the *procedure's* role, not the transport's: a station that
/// is the TCP client is the controlling station (5-104 clause 7), but the same
/// station may hold the other role's instance for the reverse direction.
///
/// The state is the role, the [`Selection`] and the addressing. Clause 7.10's
/// table has one activation and one confirmation, no termination, deactivation
/// or lock; nothing here reads a clock, holds a timer or remembers what it sent
/// (see [`TestProcedure::on_response`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestProcedure {
    role: Role,
    selection: Selection,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
}

impl TestProcedure {
    /// A controlling station's instance: the station's clause 9.6 selection and
    /// form, and the addressing its commands carry.
    #[must_use]
    pub const fn controlling(selection: Selection, common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlling,
            selection,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
        }
    }

    /// A controlled station's instance: the station's clause 9.6 selection and
    /// form, and the addressing its answers carry.
    #[must_use]
    pub const fn controlled(selection: Selection, common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlled,
            selection,
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

    /// The station's selection: 104 clause 9.6's checkbox and the form.
    #[must_use]
    pub const fn selection(&self) -> Selection {
        self.selection
    }

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// The controlling station's command; see [`request`].
    ///
    /// Refused with [`TsError::FunctionNotUsed`] when the clause 9.6 checkbox is
    /// not marked, and with [`TsError::NotSelectedForm`] when `command`'s form is
    /// not this station's: a 104 station builds `<107>` and no `<104>`.
    ///
    /// # Errors
    ///
    /// [`TsError::WrongRole`] on a controlled station, the two refusals above,
    /// and the errors of [`request`].
    pub fn request(&self, command: Command) -> Result<Vec<u8>, TsError> {
        if self.role != Role::Controlling {
            return Err(TsError::WrongRole);
        }
        if !self.selection.used {
            return Err(TsError::FunctionNotUsed);
        }
        if command.form() != self.selection.form {
            return Err(TsError::NotSelectedForm {
                type_id: command.type_id(),
            });
        }
        request_with(command, self.ca, self.org, self.sizes)
    }

    /// The controlled station's answer to a received test command; see
    /// [`answer`].
    ///
    /// The answer's **common address** is the instance's; its **originator
    /// address** and `T` bit are the *command's*, which the controlled station
    /// echoes (clause 7.2.3, index 38). Refused with
    /// [`TsError::FunctionNotUsed`] when the station does not use the procedure,
    /// and with [`TsError::NotSelectedForm`] for a command of the other form.
    ///
    /// # Errors
    ///
    /// [`TsError::WrongRole`] on a controlling station, the two refusals above,
    /// [`TsError::Layout`] when the header cannot be parsed, and the errors of
    /// [`answer`].
    pub fn answer(&self, command: &[u8]) -> Result<Vec<u8>, TsError> {
        if self.role != Role::Controlled {
            return Err(TsError::WrongRole);
        }
        if !self.selection.used {
            return Err(TsError::FunctionNotUsed);
        }
        let given = Header::parse_with(command, self.sizes)?;
        if form_of(given.type_id).is_some() && given.type_id != self.selection.form.type_id() {
            return Err(TsError::NotSelectedForm {
                type_id: given.type_id,
            });
        }
        answer_with(command, self.ca, self.sizes)
    }

    /// The controlling station's decision for one received ASDU, with the
    /// [`Command`] this station sent.
    ///
    /// In this order:
    ///
    /// 1. **A mirrored test command** (one of the two types with `P/N = 1` and
    ///    a cause 44–47: a peer's refusal of a command this station sent) is
    ///    [`Reaction::Refused`] with the class's cause. It is checked before the
    ///    discard rule because it is the answer the controlling station asked
    ///    for. 5-101 clause 7.2.3's monitor-direction log list names
    ///    *"mirrored ASDUs due to unknown numbers in the control direction"* as
    ///    something to log, not to drop.
    /// 2. **Clause 7.2.3's discard rule** for everything else, as in the other
    ///    procedure modules.
    /// 3. **The frame's own meaning.** A cause-`<7>` frame of this station's
    ///    selected form is the confirmation, and its value must equal `sent`: a
    ///    different `TSC` or time, or a different [`Command`] variant, is
    ///    [`TsError::EchoMismatch`] (clause 8.8; TS 60870-5-604 5.4.22.1).
    ///    [`Reaction::Answered`] carries the header's `P/N` bit as `negative`.
    ///    A cause-`<7>` frame of the other form is [`TsError::NotSelectedForm`].
    ///    Another type, another cause or `N = 0` is [`Reaction::Other`].
    ///
    /// For a mirror or a cause-`<7>` frame, a station that does not use the
    /// procedure gets [`TsError::FunctionNotUsed`]. That check runs before the
    /// form check (as in [`TestProcedure::request`]), so such a station reports
    /// `FunctionNotUsed` for either form.
    ///
    /// The object area of a test-type frame is decoded before the frame is
    /// classified, so a short prefix is a typed error. The returned
    /// [`Outcome::send`] is always empty.
    ///
    /// # Errors
    ///
    /// [`TsError::WrongRole`] on a controlled station, [`TsError::Layout`] for a
    /// frame that cannot be parsed or decoded, and [`TsError::FunctionNotUsed`],
    /// [`TsError::NotSelectedForm`], [`TsError::CauseNotListed`] (a mirror whose
    /// cause is not 44 to 47) and [`TsError::EchoMismatch`] as described above.
    pub fn on_response(
        &self,
        asdu: &[u8],
        known: &Known,
        sent: Command,
    ) -> Result<Outcome, TsError> {
        if self.role != Role::Controlling {
            return Err(TsError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if is_test_type(header.type_id) && is_mirror(&header) {
            // The reply to this station's request, so it is classified before
            // the discard rule. The object area is decoded first (a short
            // prefix is a typed error), then the profile's checks run.
            command_of(asdu, self.sizes)?;
            if !self.selection.used {
                return Err(TsError::FunctionNotUsed);
            }
            if form_of(header.type_id) != Some(self.selection.form) {
                return Err(TsError::NotSelectedForm {
                    type_id: header.type_id,
                });
            }
            let which = class_of(header.cause).ok_or(TsError::CauseNotListed {
                cause: header.cause,
            })?;
            return Ok(Outcome {
                reaction: Reaction::Refused {
                    cause: which.cause(),
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
        let Some(form) = form_of(header.type_id) else {
            return Ok(other());
        };
        if header.cause != CAUSE_ACTIVATION_CON {
            return Ok(other());
        }
        if !self.selection.used {
            return Err(TsError::FunctionNotUsed);
        }
        if form != self.selection.form {
            return Err(TsError::NotSelectedForm {
                type_id: header.type_id,
            });
        }
        let Some(got) = command_of(asdu, self.sizes)? else {
            // Clause 7.2.2's `N = 0`: a confirmation with no element carries no
            // echo to check.
            return Ok(other());
        };
        if got != sent {
            return Err(TsError::EchoMismatch { sent, got });
        }
        Ok(Outcome {
            reaction: Reaction::Answered {
                command: got,
                negative: header.negative,
            },
            send: Vec::new(),
        })
    }

    /// The controlled station's decision for one received ASDU.
    ///
    /// 1. **A mirrored test command** (a mirror a peer sent back) is clause
    ///    7.2.3's discard, [`Reaction::Discard`] with [`Discard::Mirror`], so two
    ///    stations cannot mirror each other.
    /// 2. **A broadcast test command** (one of the two types at `FF`/`FFFF`,
    ///    which clause 7.2.4, index 43, restricts to types `<100>`, `<101>`,
    ///    `<103>` and `<105>`) is *"rejected … by mirroring the ASDU with P/N = 1
    ///    negative (and with COT = 46, if supported)"* (TS 60870-5-604
    ///    5.4.10.10, index 54). It is [`Reaction::Refused`] with the class-46
    ///    mirror in [`Outcome::send`], whatever the caller's [`Known`] says, and
    ///    the mirror carries this station's own common address.
    /// 3. **Clause 7.2.3's rule for the control direction**: a frame whose type
    ///    identification, cause of transmission, common address or information
    ///    object address the station does not know (per the caller's [`Known`])
    ///    is *"mirrored … with bit `P/N := <1>` negative confirm"* with the
    ///    class's cause ([`Reaction::Refused`] with the mirror in
    ///    [`Outcome::send`]). These are the `<44>`–`<47>` of figures 76 and 30.
    /// 4. **Everything else**: a cause-`<6>` command of this station's selected
    ///    form is [`Reaction::Requested`] and is answered with [`answer`]. A
    ///    cause-`<6>` command the station does not serve (the function is not
    ///    used, or the command is of the other form) is
    ///    [`Reaction::Unsupported`] with the cause-44 mirror in
    ///    [`Outcome::send`]. Another type, another cause or `N = 0` is
    ///    [`Reaction::Other`].
    ///
    /// Address `<0>` is not refused: it is a test command's address by
    /// definition (figure 76's field row).
    ///
    /// # Errors
    ///
    /// [`TsError::WrongRole`] on a controlling station, and [`TsError::Layout`]
    /// for a frame that cannot be parsed or a test command whose object area
    /// cannot be decoded, and the errors of [`answer`] when building the reply.
    pub fn on_request(&self, asdu: &[u8], known: &Known) -> Result<Outcome, TsError> {
        if self.role != Role::Controlled {
            return Err(TsError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if is_test_type(header.type_id) && is_mirror(&header) {
            // The peer mirrored a command back to us; nothing is mirrored in
            // return (clause 7.2.3's third log bullet, the same reason
            // `discard_reason` reports it). The object area is decoded first,
            // so a truncated frame is a typed error rather than a discard.
            command_of(asdu, self.sizes)?;
            return Ok(Outcome {
                reaction: Reaction::Discard(Discard::Mirror),
                send: Vec::new(),
            });
        }
        if header.common_address == self.sizes.broadcast_common_address()
            && is_test_type(header.type_id)
        {
            return Ok(self.refuse(&header, asdu, crate::asdu::Unspecified::CommonAddress));
        }
        if let Some(reason) = discard_reason(&header, known) {
            if let Discard::Unspecified(which) = reason {
                // Clause 7.2.3's table is about the control direction: an ASDU
                // whose field the station does not know is *mirrored*, never
                // discarded.
                return Ok(self.refuse(&header, asdu, which));
            }
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        let Some(form) = form_of(header.type_id) else {
            return Ok(other());
        };
        if header.cause != CAUSE_ACTIVATION {
            return Ok(other());
        }
        let value = command_of(asdu, self.sizes)?;
        // A test command this station does not serve is an unknown type here:
        // mirrored with cause 44 (cl.7.2.3) so the peer is not left waiting.
        let unsupported = if !self.selection.used {
            Some(Unsupported::FunctionNotUsed)
        } else if form != self.selection.form {
            Some(Unsupported::OtherForm)
        } else {
            None
        };
        if let Some(reason) = unsupported {
            return Ok(Outcome {
                reaction: Reaction::Unsupported { reason },
                send: vec![mirror_frame(
                    &header,
                    asdu,
                    crate::asdu::Unspecified::TypeIdentification,
                    self.ca,
                    self.sizes,
                )],
            });
        }
        let Some(value) = value else {
            return Ok(other());
        };
        Ok(Outcome {
            reaction: Reaction::Requested { command: value },
            send: vec![crate::ts::answer_with(asdu, self.ca, self.sizes)?],
        })
    }

    /// Clause 7.2.3's mirror of a received frame for one of the four undefined
    /// classes: [`Reaction::Refused`] with the class's cause and the mirror in
    /// [`Outcome::send`], carrying **this station's** common address.
    fn refuse(&self, header: &Header, asdu: &[u8], which: crate::asdu::Unspecified) -> Outcome {
        Outcome {
            reaction: Reaction::Refused {
                cause: which.cause(),
            },
            send: vec![mirror_frame(header, asdu, which, self.ca, self.sizes)],
        }
    }
}

/// The class of clause 7.2.3's table a 44–47 cause names: the inverse of
/// [`crate::asdu::Unspecified::cause`].
fn class_of(cause: Cause) -> Option<crate::asdu::Unspecified> {
    crate::asdu::Unspecified::ALL
        .into_iter()
        .find(|which| which.cause() == cause)
}

/// The eleven octets of figure 76: `C_TS_NA_1`, cause as given, the figure's
/// information object address of zero, the `FBP` constant. Only the request
/// builders use this; [`answer`] copies the received octets instead (see
/// [`activation_confirmation`]).
fn untagged_frame(
    cause: Cause,
    negative: bool,
    test: bool,
    originator: u8,
    common_address: u16,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    let header = Header {
        type_id: TYPE_ID_UNTAGGED,
        sequence: false,
        count: 1,
        cause,
        negative,
        test,
        originator,
        common_address,
    };
    encode_asdu_with(
        &header,
        &[LayoutObject {
            ioa: IOA_IRRELEVANT,
            value: CTsNa1 { fbp: Fbp },
        }],
        sizes,
    )
}

/// The eighteen octets of figure 30: `C_TS_TA_1`, cause as given, the figure's
/// information object address of zero, the caller's `TSC` and `CP56Time2a`. Like
/// [`untagged_frame`], only the request builders use this.
#[allow(clippy::too_many_arguments)] // the figure's fields, one parameter each
fn tagged_frame(
    cause: Cause,
    negative: bool,
    test: bool,
    originator: u8,
    common_address: u16,
    tsc: Tsc,
    time: Cp56Time2a,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    let header = Header {
        type_id: TYPE_ID_TAGGED,
        sequence: false,
        count: 1,
        cause,
        negative,
        test,
        originator,
        common_address,
    };
    encode_asdu_with(
        &header,
        &[LayoutObject {
            ioa: IOA_IRRELEVANT,
            value: CTsTa1 { tsc, time },
        }],
        sizes,
    )
}

/// The element a received test command carries, or `None` when it carries no
/// information object at all (clause 7.2.2's `N = 0`). A frame of another type
/// is [`TsError::NotThisType`], and every other short prefix is a typed error, so
/// a truncated command never reaches the application.
fn command_of(asdu: &[u8], sizes: AddressSizes) -> Result<Option<Command>, TsError> {
    let header = Header::parse_with(asdu, sizes)?;
    match form_of(header.type_id) {
        Some(Form::Untagged) => {
            Ok(decode_asdu_with::<CTsNa1>(asdu, sizes)?
                .first()
                .map(|object| Command::Untagged {
                    fbp: object.value.fbp,
                }))
        }
        Some(Form::Tagged) => Ok(decode_asdu_with::<CTsTa1>(asdu, sizes)?
            .first()
            .map(|object| Command::Tagged {
                tsc: object.value.tsc,
                time: object.value.time,
            })),
        None => Err(TsError::NotThisType {
            type_id: header.type_id,
        }),
    }
}

/// The outcome for an ASDU this procedure does not own.
const fn other() -> Outcome {
    Outcome {
        reaction: Reaction::Other,
        send: Vec::new(),
    }
}
