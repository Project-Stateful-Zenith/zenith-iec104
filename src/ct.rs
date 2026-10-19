//! Command transmission.
//!
//! The seven command families of 5-101 clause 7.3.2 and
//! their 5-104 time-tagged twins, with the select/execute bit, the mirrored
//! confirmation and termination, the deactivation of a select and the return
//! information.
//!
//! # The procedure: eight service rows, three calls
//!
//! 5-104 clause **7.7** (PDF page index 68, printed page 67) is headed *"Command
//! transmission (6.8 of IEC 60870-5-5)"*. Its table spells every row as a
//! `req`/`ind` (or `res`/`con`) pair; these are its eight distinct rows:
//!
//! | Application service | ASDU label |
//! | --- | --- |
//! | `A_SELECT.req` / `.ind` | `C_SC, C_DC, C_SE, C_RC, C_BO ACT` |
//! | `A_SELECT.res` / `.con` | `C_SC, C_DC, C_SE, C_RC, C_BO ACTCON` |
//! | `A_BREAK.req` / `.ind` | `C_SC, C_DC, C_SE, C_RC, C_BO DEACT` |
//! | `A_BREAK.res` / `.con` | `C_SC, C_DC, C_SE, C_RC, C_BO DEACTCON` |
//! | `A_EXCO.req` / `.ind` | `C_SC, C_DC, C_SE, C_RC, C_BO ACT` |
//! | `A_EXCO.res` / `.con` | `C_SC, C_DC, C_SE, C_RC, C_BO ACTCON` |
//! | `A_RETURN_INF.req` / `.ind` | `M_SP, M_DP, M_ST` |
//! | `A_COTERM.req` / `.ind` | `C_SC, C_DC, C_SE, C_RC, C_BO ACTTERM` |
//!
//! Select and execute are **the same ASDU label** (`… ACT`), told apart by the
//! `S/E` bit of the command qualifier. The procedure has both a deactivation
//! and a termination: the three-call shape (confirm, data, terminate) that
//! [`crate::gi`] has and [`crate::cs`] does not, with the select/execute pair
//! in front of it. The `A_RETURN_INF` row is **not** a command ASDU: it carries
//! the monitor-direction process ASDU of the object being controlled.
//!
//! # The confirmation is a *mirror* of the command
//!
//! 5-104 Table 2's NOTE (PDF page index 50, printed page 49): *"ASDUs marked
//! \"CON\" in the control direction are confirmed application services and may
//! be mirrored in the monitor direction with different causes of transmission.
//! These mirrored ASDUs are used for positive/negative acknowledgements
//! (verifications)."* 5-101 clause **7.2.3** (PDF page index 38, printed page
//! 37) says the same.
//!
//! So an `ACTCON` **is the command ASDU again** (same type identification, same
//! information object address, same element, same `S/E`) with the cause
//! changed and, on a refusal, `P/N = 1`. [`confirmation`] and
//! [`CommandTransmission::on_request`] rebuild the received command's own
//! [`Command`] value rather than copying octets, so the mirror reproduces every
//! *field* the crate decodes but **not** the bits the standard fixes to zero
//! (`SCO`'s `RES := BS1[2]<0>` in cl.7.2.6.15, and `CP56Time2a`'s `RES1..RES4`
//! in cl.7.2.6.18). A peer that sets one of those is out of spec, and its
//! reserved bits are dropped rather than echoed. The **return information** is
//! a different type identification and codec path, and [`return_information`]
//! builds it from a monitor layout.
//!
//! # The mirror echoes the request's originator address and test bit
//!
//! 5-101 clause **7.2.3** (PDF page index 38, printed page 37): *"In these
//! systems, the information source should set the originator address of the
//! ASDUs in the command direction, and the controlled station should echo this
//! originator address in the response in the monitor direction."*
//!
//! Every answer this module builds for a received frame (the `ACTCON`, the
//! `DEACTCON`, the `ACTTERM` and the cause 44 to 47 mirror) therefore carries
//! **the received command's** originator address and test bit, so a frame sent
//! under test conditions (`T=1`) is answered under test conditions. The common
//! address stays the station's own: the answer carries the answering station's
//! address.
//!
//! **A command is never broadcast.** cl.7.2.4's global address (`<65535>` with
//! a two-octet common address), the *broadcast CASDU* of TS 60870-5-604
//! 5.4.10.10 (PDF page index 54), is *"only used in control direction with ASDU
//! Types 100 (Interrogation), 101 (Counter interrogation), 103 (Clock Sync) or
//! 105 (Reset Process)"* (`C_IC`, `C_CI`, `C_CS`, `C_RP`), and *"the
//! Controlled station rejects all other ASDU Types with a Broadcast CASDU value
//! by mirroring the ASDU with P/N = 1 negative (and with COT = 46, if
//! supported)"*. A command addressed to the global address is therefore
//! answered with that mirror and **records no state**; it is not answered for
//! every station in turn. The check reads the received header itself, so the
//! rule holds whatever the caller's [`Known`] says. Only the fourteen command
//! types, the ASDUs this procedure owns, are rejected: any other type at the
//! global address (the system types 100/101/103/105, or a monitor type) falls
//! through to [`Reaction::Other`] as it does at the station's own address, and
//! the procedure that owns it answers.
//!
//! # The per-type cause lists
//!
//! 5-101 clause **7.3.2** prints one figure per family and each figure carries
//! the type's whole cause list. Figure 64 (cl.7.3.2.1, PDF page index 99) reads:
//!
//! ```text
//! CAUSES OF TRANSMISSION used with TYPE IDENT 45 := C_SC_NA_1
//!   in control direction: <6> activation, <8> deactivation
//!   in monitor direction: <7> activation confirmation,
//!                         <9> deactivation confirmation,
//!                         <10> activation termination,
//!                         <44> unknown type identification,
//!                         <45> unknown cause of transmission,
//!                         <46> unknown common address of ASDU,
//!                         <47> unknown information object address
//! ```
//!
//! Figures 65–70 (cl.7.3.2.2 to .7, PDF page indices 99–103) carry the same
//! list for types 46–51, and 5-104 clause **8**'s figures 23–29 (types 58–64,
//! PDF page indices 76, 78, 80, 82, 84, 86 and 88) carry their own. The 44–47
//! replies are the four [`Unspecified`] classes of clause 7.2.3; `<10>` is what
//! makes `ACTTERM` legal here and not in [`crate::cs`].
//!
//! # Which of the command procedures are used
//!
//! 5-101 clause **7.4.7** (PDF page index 126, printed page 125), verbatim:
//!
//! - *"The select procedure is only used in case of a select and execute
//!   function. DEACT, DEACTCON is only used in case of a select and execute
//!   function."*
//! - *"`C_SC`, `C_DC`, `C_RC` ACT, ACTCON and ACTTERM are used."*
//! - *"`C_SE` ACT and ACTCON is used with direct command transmission or select
//!   and execute procedures. `C_SE` ACTTERM may be used optionally."*
//! - *"`RETURN_INF` for control operation commenced is not used."*
//! - *"`RETURN_INF` for control operation complete is used (if available)."*
//! - *"S/E of the qualifier of command QOC is irrelevant in ASDUs with causes
//!   of transmission DEACT and DEACTCON."*
//!
//! The first sentence makes the select procedure and the deactivation a
//! *function* a station may or may not have, so [`CommandMode`] is a
//! per-station selection (`Direct` or `SelectAndExecute`). The second and third
//! make the `ACTTERM` policy per family, so [`Termination`] is a per-station
//! selection too. Of the two `RETURN_INF` sentences only the second is built
//! ([`ReturnInfo`] has no "commenced" variant), and the last is why
//! [`deactivation`] writes the `S/E` bit it is given without policing it.
//!
//! The clause's NOTE maps the three families onto what they control: *"Usually,
//! a single command (type identification 45) is used to control an object that
//! is monitored as a single-point (type identification 1, 2 and 30), a double
//! command (type identification 46) is used to control an object that is
//! monitored as double-point (type identification 3, 4 or 31) and a regulating
//! step command (type identification 47) is used to control an object that is
//! monitored as a step position information (type identifications 5, 6 and 32)."*
//! [`monitored_types`] extends the same idea to the set-point and bitstring
//! families (a normalized set-point controls a normalized measured value, and
//! so on); that part is the crate's reading, not the NOTE's.
//!
//! # The two command sets must not be mixed toward one station
//!
//! 5-104 clause **9** (PDF page index 102, printed page 101): *"Either the ASDUs
//! of the set `<45>` – `<51>` or of the set `<58>` – `<64>` are used."* Table 2's
//! sentence on the same subject (PDF page index 50, printed page 49): *"Process
//! information in control direction may be sent with or without a time tag but
//! must not be mixed when sending to a given station."* [`CommandSet`] is that
//! choice as a value on both roles, in the shape of
//! [`CounterMode`](crate::ci::CounterMode)'s gates. A controlling station
//! refuses to send a command of the other set with [`CtError::WrongCommandSet`]
//! (and returns the same error for a response of the other set). A controlled
//! station that *receives* the other set answers it with cause 44 (the type is
//! not one it implements) and reports [`Reaction::WrongCommandSet`]. The choice
//! is between untagged and `CP56Time2a`-tagged commands, **not** between select
//! and direct execute.
//!
//! # The time-tagged forms are the untagged bodies plus the time
//!
//! 5-104 clause **8.1** (PDF page index 76, printed page 75) prints
//! `C_SC_TA_1 := CP{Data unit identifier,Information object address,SCO,
//! CP56Time2a}` under *"Figure 23 – ASDU: `C_SC_TA_1`"*, headed *"Single
//! information object (SQ = 0)"*: 6 header + 3 address + 1 element + 7 time =
//! **17 octets**. `C_DC_TA_1 := …{DCO,CP56Time2a}` and the rest follow
//! (cl.8.2 to 8.7; the set-point families carry their value element plus `QOS`
//! instead of `SCO`). A [`Command`] holds that time in [`Command::time`], so one
//! value builds either set and the command set decides which.
//!
//! # The qualifiers, and the one family that has none
//!
//! `QOC` is 5-101 clause **7.2.6.26** (PDF page index 55, printed page 54):
//! `QOC := CP6{QU, S/E}`, `QU := UI5[3..7]<0..31>` with *"<0> := no additional
//! definition"*, *"<1> := short pulse duration (circuit-breaker), duration
//! determined by a system parameter in the outstation"*, *"<2> := long pulse
//! duration …"*, *"<3> := persistent output"*, and `S/E := BS1[8]<0..1>` with
//! *"<0> := execute"* and *"<1> := select"*. `QOS` (clause 7.2.6.39,
//! `QOS := CP8{QL, S/E}`) carries the same bit for the three set-point
//! families. `C_SC_NA_1`/`C_DC_NA_1`/`C_RC_NA_1` put that `QOC` inside the
//! element (`SCO`/`DCO`/`RCO`).
//!
//! **A bitstring command has no qualifier at all:**
//! `C_BO_NA_1 := CP{Data unit identifier,Information object address,BSI}` (figure
//! 70, PDF page index 103), so it has no `S/E` bit and cannot select. TS
//! 60870-5-604 Table 19 agrees by omission: 5.4.19.1 ("Select and Execute", PDF
//! page index 70) names *"a Single, Double, Regulating step or Setpoint Command
//! message"* while 5.4.19.20 and 5.4.19.50 ("Direct Execute", PDF page index 73
//! and 76) add *"Bitstring"*. [`CommandValue::supports_select`] is that fact.
//! [`CommandTransmission::select`] refuses such a family with
//! [`CtError::NotSelectable`], while [`CommandTransmission::execute`] serves it
//! directly, because a station with the select and execute *function* still
//! sends and accepts a bitstring command as a direct execute.
//!
//! # The negative paths
//!
//! TS 60870-5-604 Table 19 (PDF page indices 70–76, printed pages 69–75) has one
//! row per procedure: 5.4.19.1 *"Select and Execute"*, 5.4.19.10 *"Select and
//! Deactivation"*, 5.4.19.20 *"Direct Execute"*, 5.4.19.30 *"Select with Negative
//! Confirmation by Controlled station (Abort)"*, 5.4.19.40 *"Select with Negative
//! Execute Confirmation by Controlled station if Execute is received after
//! configured delay"*, 5.4.19.50 *"Direct Execute with Negative Confirmation"*.
//! Four rejection points follow from them:
//!
//! - **A not-allowed command state is refused with `P/N = 1`.** *"The controlled
//!   station does not accept and responds with a P/N=1 if a not allowed command
//!   (e.g. DCO=0 or 3; RCO=0 or 3) is received"* (5.4.19.30 and .50). `DCS` and
//!   `RCS` values 0 and 3 are the values the clause marks *not permitted*
//!   (cl.7.2.6.16/.17), so the controlled station answers `ACTCON` with
//!   `P/N = 1`. [`Command::is_command_state`] is that predicate, and the free
//!   [`activation`] refuses to build such a command for its own station.
//! - **An execute that does not match its select is refused.** *"If the EXECUTE
//!   message from the Controlling does not contain exactly the same information
//!   as the SELECT message, then the Controlled mirrors the same ASDU with COT=7,
//!   `C_SC/DC/SE/RC_ACTCONneg` (Negative ACTCON)"* (Table 19 page 2 of 9, PDF page
//!   index 71). [`Command::state_eq`] compares the element without the `S/E`
//!   bit, which is the one thing that *must* differ between the two.
//! - **An unknown information object address is mirrored with cause 47** where
//!   the PIXIT supports it: *"the controlled station could instead mirror the
//!   same ASDU with COT=47 (unknown Information Object Address)"* (5.4.19.30,
//!   .50). The caller's [`Known`] decides which addresses are known, exactly as
//!   in [`crate::gi`].
//! - **A select or execute the station will not serve is answered, not
//!   ignored.** 5.4.19.30's description begins *"The Controlling station
//!   sends … with COT = 6 … and S/E=1 (SELECT) to the Controlled station for a
//!   not controllable or not existing Information object"* and the required
//!   answer is *"mirrors the same ASDU with COT=7, `C_SC/DC/SE/RC_ACTCONneg`
//!   (Negative ACTCON)"*. So a select at a [`CommandMode::Direct`] station, a
//!   second select of an address already selected and an execute at a
//!   select-and-execute station with no select to repeat each get an
//!   `ACTCONneg`, and a deactivation with nothing to deactivate gets a negative
//!   `DEACTCON`; none of them is an error. The caller decides whether an object
//!   is *controllable* at all (the crate has no process image), and
//!   [`CommandTransmission::refuse`] is the negative answer for an object it
//!   will not serve.
//!
//! **In the control direction an unknown field is mirrored, never discarded.**
//! 5-101 clause 7.2.3's table (PDF page index 42): *"ASDUs in the control
//! direction with undefined values in the data unit identifier … and the
//! information object address are mirrored by the controlled station with bit
//! \"P/N := <1> negative confirm\" and the following causes of transmission"*:
//! 44 for a type identification the station does not implement (cl.7.3, index
//! 59: *"TYPE IDENTIFICATION numbers > 127 are discarded by controlling
//! stations (monitor direction) or mirrored with CAUSE OF TRANSMISSION = 44 by
//! controlled stations (control direction)"*), 45 for an unknown cause of
//! transmission, 46 for a common address that is not the station's own (a
//! command to the global address included) and 47 for an unknown information
//! object address. The monitor direction's discard rule ([`discard_reason`])
//! runs on the *receiving* side of a response. The only thing this module
//! discards in the control direction is a mirror a peer sent (`P/N = 1` with
//! one of the four causes), which must never be mirrored back.
//!
//! **The one conflict between cl.7.7's table and the figures.** 5-104 clause
//! 7.7's table (PDF page index 68) lists `C_BO` under `A_SELECT` and `A_BREAK`
//! like the other six families, while figure 70 (5-101, index 103) gives
//! `C_BO_NA_1` no qualifier to carry the `S/E` bit, and TS 60870-5-604's
//! select-and-execute procedures name no bitstring command. This module
//! follows the figures: a bitstring cannot be selected
//! ([`CtError::NotSelectable`]) and is served as a direct execute. The cl.7.7
//! row is read as the label family it is (`C_BO` = the bitstring commands), not
//! as a claim that a select exists for it. The figures also decide the
//! deactivation: figure 29 (index 88) gives `C_BO_TA_1` **no** cause 8 or 9
//! while figure 70 gives `C_BO_NA_1` both, so a *tagged* bitstring has no
//! deactivation ([`CtError::DeactivationNotDefined`]).
//!
//! Table 19 also fixes the *order*: *"The controlled station may send the
//! `RETURN_INF` with COT=3, 11, or 12 after the ACTTERM"*, and *"The Controlling
//! station performs an overall check on the correct command procedure and
//! corresponding status change, regardless of the order in which they occur."*
//! The termination and the return information are therefore two independent
//! frames the caller may send in either order, and
//! [`CommandTransmission::on_response`] classifies both as they arrive.
//!
//! # What is deliberately the caller's
//!
//! * **The outstation's pulse duration.** `QU` is *"duration determined by a
//!   system parameter in the outstation"* (cl.7.2.6.26): a value that travels,
//!   not a timer this crate runs.
//! * **The clock.** The controlled station's select timeout is configured with
//!   [`CommandTransmission::with_select_timeout`], but time only enters through
//!   the caller's own `now`: [`CommandTransmission::on_request_at`], or
//!   [`CommandTransmission::expire_selections`] called before each
//!   [`CommandTransmission::on_request`] and periodically. A lapsed select is
//!   dropped, so a late execute is refused (5.4.19.40) and a new select of that
//!   object is accepted. The controlling station's delay is the caller's:
//!   [`CommandTransmission::abandon`] and [`CommandTransmission::reset`] drop
//!   state the caller has given up on.
//! * **Which command set the station uses:** [`CommandSet`]. The module only
//!   refuses the other one.
//! * **Whether `C_SE` and `C_BO` terminate:** [`Termination`], from the
//!   clause's *"may be used optionally"* and the *"(opt)"* marking of the
//!   bitstring's `<10>` in figures 70 and 29.
//! * **Which monitor ASDU reports the object.** `M_SP`/`M_DP`/`M_ST` are
//!   *families* in 104 clause 7.7's table, and the specific type identification
//!   is the application's; [`return_information`] takes it as a layout.
//! * **Whether a command is to be allowed at all.** Which information object
//!   addresses exist and what a command means for them is project data and
//!   arrives through the caller's [`Known`].
//!
//! # What this module is not
//!
//! * **Not I/O, not a clock, not a socket.** Nothing here reads a clock or
//!   touches a connection; the caller owns the connection, the flow control,
//!   the log and the retry. Frames go out through
//!   [`Session::queue_i_frame`](crate::link::Session::queue_i_frame), which holds
//!   them until the STARTDT con (5-104 clause 5.3).
//! * **Not a data source.** Unlike [`crate::gi`] and [`crate::ci`] there is no
//!   trait here: the return information reports the *controlled object's own*
//!   state, which the application builds with [`return_information`] when that
//!   state changes. Clause 7.4.7's *"`RETURN_INF` for control operation complete
//!   is used (if available)"* leaves to the application whether any is sent at
//!   all.
//! * **Not the counter or the interrogation procedures.** `C_IC_NA_1` is
//!   [`crate::gi`], `C_CI_NA_1` is [`crate::ci`]; the shapes are similar and the
//!   causes are not.
//!
//! # Example
//!
//! ```
//! use iec104::asdu::{Cause, Header, Known, Qoc, Sco};
//! use iec104::ct::{
//!     Command, CommandMode, CommandSet, CommandTransmission, CommandValue, Reaction, Termination,
//! };
//!
//! // A single command for information object address 0x3000: close the switch.
//! let command = Command::new(
//!     0x3000,
//!     CommandValue::Single {
//!         sco: Sco {
//!             scs: true,
//!             qoc: Qoc { qu: 1, select: false },
//!         },
//!     },
//! );
//!
//! // The controlling station selects, the controlled station mirrors it.
//! let mut controlling = CommandTransmission::controlling(
//!     CommandMode::SelectAndExecute,
//!     CommandSet::Untagged,
//!     Termination::All,
//!     12,
//!     0,
//! );
//! let selected = controlling.select(&command).unwrap();
//! assert_eq!(Header::parse(&selected).unwrap().cause, Cause::Activation);
//! assert_eq!(selected[9] & 0x80, 0x80, "S/E = 1: this is the select");
//!
//! let mut controlled = CommandTransmission::controlled(
//!     CommandMode::SelectAndExecute,
//!     CommandSet::Untagged,
//!     Termination::All,
//!     12,
//!     0,
//! );
//! let outcome = controlled.on_request(&selected, &Known::EVERYTHING).unwrap();
//! assert_eq!(
//!     outcome.reaction,
//!     Reaction::Confirmed { ioa: 0x3000, select: true, negative: false }
//! );
//!
//! // The confirmation is the command ASDU with only its header changed.
//! let mirror = &outcome.send[0];
//! assert_eq!(mirror[0], selected[0], "type identification");
//! assert_eq!(mirror[1], selected[1], "VSQ");
//! assert_eq!(mirror[2], 7, "cause 7, activation confirmation");
//! assert_eq!(&mirror[6..], &selected[6..], "the object is the command's own");
//! ```

use crate::asdu::{
    AddressSizes, AsduError, AsduLayout, Bsi, CBoNa1, CBoTa1, CDcNa1, CDcTa1, CRcNa1, CRcTa1,
    CScNa1, CScTa1, CSeNa1, CSeNb1, CSeNc1, CSeTa1, CSeTb1, CSeTc1, Cause, CommandQualifier,
    Cp56Time2a, Dco, Discard, DoubleCommandState, Header, Known, LayoutError, LayoutObject, Nva,
    Qoc, Qos, R32, Rco, RegulatingStepState, Sco, Sva, TypeId, Unspecified, decode_asdu_with,
    discard_reason, encode_asdu_with, is_mirror, mirror_frame,
};
use std::time::{Duration, Instant};

/// `<6> activation`: the cause of an activation, a select and an execute alike
/// (figure 64's control-direction list).
pub const CAUSE_ACTIVATION: Cause = Cause::Activation;

/// `<7> activation confirmation`: the cause of the mirror, positive **and**
/// negative (figure 64; the two are told apart by `P/N`).
pub const CAUSE_ACTIVATION_CON: Cause = Cause::ActivationCon;

/// `<8> deactivation`: the cause that stops a select (figure 64; TS
/// 60870-5-604 5.4.19.10).
pub const CAUSE_DEACTIVATION: Cause = Cause::Deactivation;

/// `<9> deactivation confirmation`: the mirror of a deactivation.
pub const CAUSE_DEACTIVATION_CON: Cause = Cause::DeactivationCon;

/// `<10> activation termination`: the frame that ends an execute (figure 64;
/// TS 60870-5-604's *"mirrors the previous Command message with COT=10"*).
pub const CAUSE_ACTIVATION_TERM: Cause = Cause::ActivationTermination;

/// The global address of 5-101 clause 7.2.4 for a two-octet common address,
/// TS 60870-5-604 5.4.10.10's *broadcast CASDU*.
///
/// It is used in the control direction only for the system ASDUs 100 (`C_IC`),
/// 101 (`C_CI`), 103 (`C_CS`) and 105 (`C_RP`); a **command** addressed to it
/// is mirrored back with `P/N = 1` and cause 46 instead of being executed or
/// confirmed, and records no state.
#[deprecated(
    note = "the broadcast address depends on the common-address width: use AddressSizes::broadcast_common_address"
)]
pub const BROADCAST_CA: u16 = 0xFFFF;

/// The six type identifications a return information may carry.
///
/// These are the three monitor families `M_SP`, `M_DP` and `M_ST` of 5-104
/// clause 7.7's `A_RETURN_INF` row (PDF page index 68), in the 104 selection:
/// the untagged form and the `CP56Time2a` form of each. The `CP24Time2a` twins
/// (`M_SP_TA_1` 2, `M_DP_TA_1` 4, `M_ST_TA_1` 6) are **not** in the list: 5-104
/// clause 6 does not select them for use over 104, which is the same fact
/// [`TypeId::is_selected_104`](crate::asdu::TypeId::is_selected_104) reports.
pub const RETURN_TYPES: [TypeId; 6] = [
    TypeId::MSpNa1,
    TypeId::MDpNa1,
    TypeId::MStNa1,
    TypeId::MSpTb1,
    TypeId::MDpTb1,
    TypeId::MStTb1,
];

/// Whether `type_id` is one of the six types of [`RETURN_TYPES`].
#[must_use]
pub fn is_return_type(type_id: TypeId) -> bool {
    RETURN_TYPES.contains(&type_id)
}

/// The three monitor-family type identifications a command family controls,
/// in the clause's own order (5-101 cl.7.4.7's NOTE): the untagged form, the
/// `CP24Time2a` form and the `CP56Time2a` form.
///
/// The NOTE names this mapping for the single, double and regulating-step
/// commands and their monitor families; for the set-point and bitstring
/// families it is the crate's reading of the same idea (a normalized set-point
/// controls a normalized measured value, and so on).
#[must_use]
pub const fn monitored_types(family: Family) -> [TypeId; 3] {
    match family {
        Family::Single => [TypeId::MSpNa1, TypeId::MSpTa1, TypeId::MSpTb1],
        Family::Double => [TypeId::MDpNa1, TypeId::MDpTa1, TypeId::MDpTb1],
        Family::RegulatingStep => [TypeId::MStNa1, TypeId::MStTa1, TypeId::MStTb1],
        Family::SetPointNormalized => [TypeId::MMeNa1, TypeId::MMeTa1, TypeId::MMeTd1],
        Family::SetPointScaled => [TypeId::MMeNb1, TypeId::MMeTb1, TypeId::MMeTe1],
        Family::SetPointFloat => [TypeId::MMeNc1, TypeId::MMeTc1, TypeId::MMeTf1],
        Family::Bitstring => [TypeId::MBoNa1, TypeId::MBoTa1, TypeId::MBoTb1],
    }
}

/// One command family of 5-101 clause 7.3.2, with its 5-104 time-tagged twin.
///
/// The variant names are this crate's spelling; the grouping is clause 7.3.2's
/// own clustering of the seven types 45–51, paired with 5-104 clause 8's seven
/// twins 58–64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// `C_SC_NA_1` (45) / `C_SC_TA_1` (58): single command.
    Single,
    /// `C_DC_NA_1` (46) / `C_DC_TA_1` (59): double command.
    Double,
    /// `C_RC_NA_1` (47) / `C_RC_TA_1` (60): regulating step command.
    RegulatingStep,
    /// `C_SE_NA_1` (48) / `C_SE_TA_1` (61): set-point, normalized value.
    SetPointNormalized,
    /// `C_SE_NB_1` (49) / `C_SE_TB_1` (62): set-point, scaled value.
    SetPointScaled,
    /// `C_SE_NC_1` (50) / `C_SE_TC_1` (63): set-point, short floating point.
    SetPointFloat,
    /// `C_BO_NA_1` (51) / `C_BO_TA_1` (64): bitstring of 32 bit.
    Bitstring,
}

impl Family {
    /// All seven, in type-identification order.
    pub const ALL: [Self; 7] = [
        Self::Single,
        Self::Double,
        Self::RegulatingStep,
        Self::SetPointNormalized,
        Self::SetPointScaled,
        Self::SetPointFloat,
        Self::Bitstring,
    ];

    /// The family's type identification in the 5-101 set `<45>`–`<51>`.
    #[must_use]
    pub const fn untagged(self) -> TypeId {
        match self {
            Self::Single => TypeId::CScNa1,
            Self::Double => TypeId::CDcNa1,
            Self::RegulatingStep => TypeId::CRcNa1,
            Self::SetPointNormalized => TypeId::CSeNa1,
            Self::SetPointScaled => TypeId::CSeNb1,
            Self::SetPointFloat => TypeId::CSeNc1,
            Self::Bitstring => TypeId::CBoNa1,
        }
    }

    /// The family's type identification in the 5-104 set `<58>`–`<64>`.
    #[must_use]
    pub const fn tagged(self) -> TypeId {
        match self {
            Self::Single => TypeId::CScTa1,
            Self::Double => TypeId::CDcTa1,
            Self::RegulatingStep => TypeId::CRcTa1,
            Self::SetPointNormalized => TypeId::CSeTa1,
            Self::SetPointScaled => TypeId::CSeTb1,
            Self::SetPointFloat => TypeId::CSeTc1,
            Self::Bitstring => TypeId::CBoTa1,
        }
    }

    /// The family's type identification in `set`.
    #[must_use]
    pub const fn type_id(self, set: CommandSet) -> TypeId {
        match set {
            CommandSet::Untagged => self.untagged(),
            CommandSet::Tagged => self.tagged(),
        }
    }

    /// The family a type identification belongs to, and the set it is in, or
    /// `None` for any type outside the two command sets.
    #[must_use]
    pub fn of_type(type_id: TypeId) -> Option<(Self, CommandSet)> {
        Self::ALL.into_iter().find_map(|family| {
            if type_id == family.untagged() {
                Some((family, CommandSet::Untagged))
            } else if type_id == family.tagged() {
                Some((family, CommandSet::Tagged))
            } else {
                None
            }
        })
    }

    /// The ASDU name of the family's 5-101 type, as the standard spells it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Single => "C_SC_NA_1",
            Self::Double => "C_DC_NA_1",
            Self::RegulatingStep => "C_RC_NA_1",
            Self::SetPointNormalized => "C_SE_NA_1",
            Self::SetPointScaled => "C_SE_NB_1",
            Self::SetPointFloat => "C_SE_NC_1",
            Self::Bitstring => "C_BO_NA_1",
        }
    }

    /// Whether this is one of the three set-point families, the split 5-101
    /// clause 7.4.7 draws for the `ACTTERM` policy.
    #[must_use]
    pub const fn is_set_point(self) -> bool {
        matches!(
            self,
            Self::SetPointNormalized | Self::SetPointScaled | Self::SetPointFloat
        )
    }

    /// Whether the family's figure marks its `ACTTERM` *"(opt)"*.
    ///
    /// True for the set-points and the bitstring, the four families whose
    /// figures print *"`<10>` := activation termination (opt)"*: figures 67–70 (5-101, PDF
    /// page indices 101–103) for types 48–51 and figures 26–29 (5-104, indices
    /// 82–88) for types 61–64. Figures 64–66 and 23–25 print `<10>` without the
    /// marking, so `C_SC`/`C_DC`/`C_RC` always terminate. This is what
    /// [`Termination::uses`] reads.
    #[must_use]
    pub const fn termination_is_optional(self) -> bool {
        matches!(
            self,
            Self::SetPointNormalized | Self::SetPointScaled | Self::SetPointFloat | Self::Bitstring
        )
    }

    /// Whether the family's figure lists causes 8 and 9 (the deactivation) in
    /// the given set.
    ///
    /// False for exactly one of the fourteen types: `C_BO_TA_1`
    /// (64), whose figure 29 (5-104, PDF page index 88) lists only `<6>` in the
    /// control direction and no `<9>` in the monitor direction, while figure 70
    /// (5-101, index 103) gives `C_BO_NA_1` both. The two sets are not
    /// interchangeable here, so the set is an argument.
    #[must_use]
    pub fn has_deactivation(self, set: CommandSet) -> bool {
        !(self == Self::Bitstring && set == CommandSet::Tagged)
    }
}

/// Whether `type_id` is one of the fourteen command type identifications.
#[must_use]
pub fn is_command_type(type_id: TypeId) -> bool {
    Family::of_type(type_id).is_some()
}

/// The command set a station sends and receives.
///
/// 5-104 clause 9: *"Either the ASDUs of the set `<45>` – `<51>` or of the set
/// `<58>` – `<64>` are used."* Table 2: *"must not be mixed when sending to a
/// given station."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandSet {
    /// The 5-101 set `<45>`–`<51>`: commands without a time tag.
    Untagged,
    /// The 5-104 set `<58>`–`<64>`: commands carrying `CP56Time2a`.
    Tagged,
}

impl CommandSet {
    /// Whether `type_id` is one of this set's seven type identifications.
    #[must_use]
    pub fn contains(self, type_id: TypeId) -> bool {
        match Family::of_type(type_id) {
            Some((_, set)) => set == self,
            None => false,
        }
    }
}

/// The station's choice between 5-101 clause 7.4.7's two command procedures,
/// PICS 9.6's *"Direct command"* and *"Select and execute command"*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandMode {
    /// Direct command transmission: every activation carries `S/E = 0` and no
    /// select precedes it. TS 60870-5-604's 5.4.19.20 and 5.4.19.50.
    Direct,
    /// The select and execute function: a select (`S/E = 1`) precedes the
    /// execute, which repeats the select's information. TS 60870-5-604's
    /// 5.4.19.1, .10, .30 and .40, and clause 7.4.7's *"The select procedure is
    /// only used in case of a select and execute function."*
    SelectAndExecute,
}

impl CommandMode {
    /// Whether this mode uses the select procedure: true only for
    /// [`CommandMode::SelectAndExecute`].
    ///
    /// Used on both roles. When true, an execute needs a confirmed select before
    /// it (the controlling station will not send one without, the controlled
    /// station answers one without with an `ACTCONneg`); when false, a select is
    /// refused on both sides.
    #[must_use]
    pub const fn requires_select(self) -> bool {
        matches!(self, Self::SelectAndExecute)
    }
}

/// Whether a command family's procedure is terminated.
///
/// 5-101 clause 7.4.7's *"`C_SC`, `C_DC`, `C_RC` ACT, ACTCON and ACTTERM are used."*
/// against *"`C_SE` ACTTERM may be used optionally."* A per-station PIXIT
/// selection, not a hard-coded branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Termination {
    /// Every family the station serves terminates: the three the clause requires,
    /// and the set-points and the bitstring, whose termination is optional.
    All,
    /// Only the three the clause requires terminate; a set-point or bitstring
    /// command ends at its confirmation.
    SetPointsNotTerminated,
}

impl Termination {
    /// Whether a command of `family` is terminated by an `ACTTERM`.
    ///
    /// [`Termination::All`] terminates every family. [`Termination::SetPointsNotTerminated`]
    /// terminates only the families whose figures print `<10>` without the
    /// *"(opt)"* marking (`C_SC`, `C_DC` and `C_RC`), and leaves both the
    /// set-points of cl.7.4.7's *"`C_SE` ACTTERM may be used optionally"* **and**
    /// the bitstring to the caller, because figures 70 and 29 mark the
    /// bitstring's `<10>` optional too ([`Family::termination_is_optional`]).
    #[must_use]
    pub const fn uses(self, family: Family) -> bool {
        match self {
            Self::All => true,
            Self::SetPointsNotTerminated => !family.termination_is_optional(),
        }
    }
}

/// The cause of a return information.
///
/// 5-101 clause 7.4.7's *"`RETURN_INF` for control operation complete is used (if
/// available)"* and TS 60870-5-604 Table 19's *"The Controlled station generates an event (`RETURN_INF`) with COT=11
/// (`RETURN_INF` caused by a remote command) or COT=12 (`RETURN_INF` caused by a
/// local command) … The controlled station may send the `RETURN_INF` with COT=3,
/// 11, or 12 after the ACTTERM."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReturnInfo {
    /// `<11>`: the object changed as a result of a **remote** command.
    Remote,
    /// `<12>`: the object changed as a result of a **local** command.
    Local,
    /// `<3>`: the object changed spontaneously, and the frame answers no
    /// command in particular.
    Spontaneous,
}

impl ReturnInfo {
    /// The cause of transmission of this return information.
    #[must_use]
    pub const fn cause(self) -> Cause {
        match self {
            Self::Remote => Cause::ReturnInfoRemote,
            Self::Local => Cause::ReturnInfoLocal,
            Self::Spontaneous => Cause::Spontaneous,
        }
    }

    /// The return information a cause of transmission names, or `None` for any
    /// other cause.
    #[must_use]
    pub const fn from_cause(cause: Cause) -> Option<Self> {
        match cause {
            Cause::ReturnInfoRemote => Some(Self::Remote),
            Cause::ReturnInfoLocal => Some(Self::Local),
            Cause::Spontaneous => Some(Self::Spontaneous),
            _ => None,
        }
    }

    /// The standard's mnemonic for the cause, as [`Cause::mnemonic`] gives it.
    #[must_use]
    pub fn mnemonic(self) -> &'static str {
        self.cause().mnemonic()
    }
}

/// The element of a command: one variant per family, carrying the element(s)
/// of that family's definition line.
///
/// The `S/E` bit lives in the qualifier the family carries: inside `SCO`/`DCO`/
/// `RCO` for the three command families, in `QOS` for the set-points, and
/// **nowhere** for the bitstring, whose definition line has no qualifier at all.
/// No `Eq`, because the short floating point element carries an `f32`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CommandValue {
    /// `SCO`: single command (7.3.2.1).
    Single {
        /// The single command and its qualifier of command.
        sco: Sco,
    },
    /// `DCO`: double command (7.3.2.2).
    Double {
        /// The double command and its qualifier of command.
        dco: Dco,
    },
    /// `RCO`: regulating step command (7.3.2.3).
    RegulatingStep {
        /// The regulating step command and its qualifier of command.
        rco: Rco,
    },
    /// `NVA, QOS`: set-point, normalized value (7.3.2.4).
    SetPointNormalized {
        /// The normalized set-point value.
        nva: Nva,
        /// The qualifier of set-point command.
        qos: Qos,
    },
    /// `SVA, QOS`: set-point, scaled value (7.3.2.5).
    SetPointScaled {
        /// The scaled set-point value.
        sva: Sva,
        /// The qualifier of set-point command.
        qos: Qos,
    },
    /// `IEEE STD 754, QOS`: set-point, short floating point (7.3.2.6).
    SetPointFloat {
        /// The short floating point set-point value.
        r32: R32,
        /// The qualifier of set-point command.
        qos: Qos,
    },
    /// `BSI`: bitstring of 32 bit (7.3.2.7). No qualifier, so no `S/E` bit.
    Bitstring {
        /// The 32-bit string.
        bsi: Bsi,
    },
}

impl CommandValue {
    /// The family this value belongs to.
    #[must_use]
    pub const fn family(&self) -> Family {
        match self {
            Self::Single { .. } => Family::Single,
            Self::Double { .. } => Family::Double,
            Self::RegulatingStep { .. } => Family::RegulatingStep,
            Self::SetPointNormalized { .. } => Family::SetPointNormalized,
            Self::SetPointScaled { .. } => Family::SetPointScaled,
            Self::SetPointFloat { .. } => Family::SetPointFloat,
            Self::Bitstring { .. } => Family::Bitstring,
        }
    }

    /// Whether this family has an `S/E` bit to carry: false only for the
    /// bitstring, whose definition line is `CP{…, BSI}` (figure 70, PDF page
    /// index 103) and therefore has no qualifier. TS 60870-5-604's select-and-
    /// execute procedures name no bitstring command.
    #[must_use]
    pub const fn supports_select(&self) -> bool {
        !matches!(self, Self::Bitstring { .. })
    }

    /// The `S/E` bit: `true` selects, `false` executes (5-101 cl.7.2.6.26).
    /// Always `false` for a bitstring, which carries no qualifier.
    #[must_use]
    pub const fn select(&self) -> bool {
        match self {
            Self::Single { sco } => sco.qoc.select,
            Self::Double { dco } => dco.qoc.select,
            Self::RegulatingStep { rco } => rco.qoc.select,
            Self::SetPointNormalized { qos, .. }
            | Self::SetPointScaled { qos, .. }
            | Self::SetPointFloat { qos, .. } => qos.select,
            Self::Bitstring { .. } => false,
        }
    }

    /// The same value with the `S/E` bit set to `select`, everything else
    /// unchanged. A bitstring is returned unchanged: it has no bit to set.
    #[must_use]
    pub const fn with_select(self, select: bool) -> Self {
        match self {
            Self::Single { mut sco } => {
                sco.qoc.select = select;
                Self::Single { sco }
            }
            Self::Double { mut dco } => {
                dco.qoc.select = select;
                Self::Double { dco }
            }
            Self::RegulatingStep { mut rco } => {
                rco.qoc.select = select;
                Self::RegulatingStep { rco }
            }
            Self::SetPointNormalized { nva, mut qos } => {
                qos.select = select;
                Self::SetPointNormalized { nva, qos }
            }
            Self::SetPointScaled { sva, mut qos } => {
                qos.select = select;
                Self::SetPointScaled { sva, qos }
            }
            Self::SetPointFloat { r32, mut qos } => {
                qos.select = select;
                Self::SetPointFloat { r32, qos }
            }
            Self::Bitstring { bsi } => Self::Bitstring { bsi },
        }
    }

    /// Whether `self` and `other` are the same command **ignoring the `S/E`
    /// bit**, the one field that must differ between a select and its execute.
    ///
    /// TS 60870-5-604 Table 19: *"If the EXECUTE message from the Controlling
    /// does not contain exactly the same information as the SELECT message"*.
    #[must_use]
    pub fn state_eq(&self, other: &Self) -> bool {
        // The short floating point value is compared by its bits, because Table
        // 19 asks for "exactly the same information" and `f32 ==` is not that
        // comparison: it answers `false` for the *same* NaN encoding and `true`
        // for `-0.0` against `+0.0`, which are two different octet strings
        // (5-101 cl.7.2.6.8's IEEE 754 form).
        match (self, other) {
            (Self::SetPointFloat { r32: a, qos: qa }, Self::SetPointFloat { r32: b, qos: qb }) => {
                a.value.to_bits() == b.value.to_bits() && qa.ql == qb.ql
            }
            _ => self.with_select(false) == other.with_select(false),
        }
    }

    /// Whether the command state is one the family's clause defines: false for
    /// `DCS`/`RCS` values 0 and 3, which 5-101 clause 7.2.6.16/.17 mark *not
    /// permitted* and TS 60870-5-604 Table 19 calls *"a not allowed command
    /// (e.g. DCO=0 or 3; RCO=0 or 3)"*. Every other family's element is defined
    /// for all its bit patterns.
    #[must_use]
    pub const fn is_command_state(&self) -> bool {
        match self {
            Self::Double { dco } => !matches!(
                dco.dcs,
                DoubleCommandState::NotPermitted | DoubleCommandState::NotPermittedAlt
            ),
            Self::RegulatingStep { rco } => !matches!(
                rco.rcs,
                RegulatingStepState::NotPermitted | RegulatingStepState::NotPermittedAlt
            ),
            _ => true,
        }
    }
}

/// One command on the wire: its information object address, its element, and
/// (for the 5-104 set `<58>`–`<64>`) its `CP56Time2a` time tag.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Command {
    /// Information object address (`UI24`), the object the command controls.
    pub ioa: u32,
    /// The command's element, carrying the `S/E` bit where the family has one.
    pub value: CommandValue,
    /// The time tag of a command in the 104 set (`C_*_TA_1`/`TB_1`/`TC_1`), or
    /// `None` for the 5-101 set. It is the only difference between the two
    /// sets' bodies (5-104 cl.8.1 to 8.7).
    pub time: Option<Cp56Time2a>,
}

impl Command {
    /// An untagged command of the 5-101 set.
    #[must_use]
    pub const fn new(ioa: u32, value: CommandValue) -> Self {
        Self {
            ioa,
            value,
            time: None,
        }
    }

    /// A time-tagged command of the 5-104 set.
    #[must_use]
    pub const fn tagged(ioa: u32, value: CommandValue, time: Cp56Time2a) -> Self {
        Self {
            ioa,
            value,
            time: Some(time),
        }
    }

    /// An untagged single command (`SCO`, 5-101 cl.7.2.6.15) switching `ioa`
    /// ON (`true`, `SCS = <1>`) or OFF (`false`, `SCS = <0>`), with `S/E`
    /// execute and `QU` no additional definition.
    ///
    /// ```
    /// use iec104::asdu::{CommandQualifier, TypeId};
    /// use iec104::ct::Command;
    ///
    /// let on = Command::single(4001, true).with_qualifier(CommandQualifier::ShortPulse);
    /// assert_eq!(on.type_id(), TypeId::CScNa1);
    /// ```
    #[must_use]
    pub fn single(ioa: u32, on: bool) -> Self {
        let sco = Sco {
            scs: on,
            qoc: Qoc::default(),
        };
        Self::new(ioa, CommandValue::Single { sco })
    }

    /// An untagged double command (`DCO`, 5-101 cl.7.2.6.16) in `state`,
    /// with `S/E` execute and `QU` no additional definition.
    #[must_use]
    pub fn double(ioa: u32, state: DoubleCommandState) -> Self {
        let dco = Dco {
            dcs: state,
            qoc: Qoc::default(),
        };
        Self::new(ioa, CommandValue::Double { dco })
    }

    /// An untagged regulating step command (`RCO`, 5-101 cl.7.2.6.17) in
    /// `state`, with `S/E` execute and `QU` no additional definition.
    #[must_use]
    pub fn regulating_step(ioa: u32, state: RegulatingStepState) -> Self {
        let rco = Rco {
            rcs: state,
            qoc: Qoc::default(),
        };
        Self::new(ioa, CommandValue::RegulatingStep { rco })
    }

    /// An untagged set-point with a normalized value (`NVA`, 5-101
    /// cl.7.2.6.6), `value` in `[-1, 1)` as [`Nva::from_scaled`] rounds and
    /// clamps it, with `S/E` execute and `QL` `<0>` default (cl.7.2.6.39).
    #[must_use]
    pub fn set_point_normalized(ioa: u32, value: f64) -> Self {
        Self::new(
            ioa,
            CommandValue::SetPointNormalized {
                nva: Nva::from_scaled(value),
                qos: Qos::default(),
            },
        )
    }

    /// An untagged set-point with a scaled value (`SVA`, 5-101 cl.7.2.6.7),
    /// with `S/E` execute and `QL` `<0>` default (cl.7.2.6.39).
    #[must_use]
    pub fn set_point_scaled(ioa: u32, value: i16) -> Self {
        Self::new(
            ioa,
            CommandValue::SetPointScaled {
                sva: Sva::from_raw(value),
                qos: Qos::default(),
            },
        )
    }

    /// An untagged set-point with a short floating point value (5-101
    /// cl.7.2.6.8), with `S/E` execute and `QL` `<0>` default (cl.7.2.6.39).
    #[must_use]
    pub fn set_point_float(ioa: u32, value: f32) -> Self {
        Self::new(
            ioa,
            CommandValue::SetPointFloat {
                r32: R32::from_raw(value),
                qos: Qos::default(),
            },
        )
    }

    /// An untagged bitstring of 32 bit (`BSI`, 5-101 cl.7.2.6.13). It has no
    /// qualifier, so no `S/E` bit.
    #[must_use]
    pub const fn bitstring(ioa: u32, bits: u32) -> Self {
        Self::new(ioa, CommandValue::Bitstring { bsi: Bsi { bits } })
    }

    /// The same command with the `QU` of its qualifier of command set to
    /// `qualifier`, everything else unchanged.
    ///
    /// Only the single, double and regulating step commands carry a `QOC`
    /// (5-101 cl.7.2.6.15 to 7.2.6.17). A set-point's `QOS` has no `QU`
    /// (cl.7.2.6.39) and a bitstring has no qualifier at all, so both are
    /// returned unchanged.
    #[must_use]
    pub const fn with_qualifier(self, qualifier: CommandQualifier) -> Self {
        let value = match self.value {
            CommandValue::Single { mut sco } => {
                sco.qoc.qu = qualifier.raw();
                CommandValue::Single { sco }
            }
            CommandValue::Double { mut dco } => {
                dco.qoc.qu = qualifier.raw();
                CommandValue::Double { dco }
            }
            CommandValue::RegulatingStep { mut rco } => {
                rco.qoc.qu = qualifier.raw();
                CommandValue::RegulatingStep { rco }
            }
            other => other,
        };
        Self { value, ..self }
    }

    /// The same command with the time tag `time`, which moves it into the
    /// 5-104 set `<58>`–`<64>` (5-104 cl.8.1 to 8.7).
    #[must_use]
    pub const fn with_time(self, time: Cp56Time2a) -> Self {
        Self {
            time: Some(time),
            ..self
        }
    }

    /// Which set this command belongs to.
    #[must_use]
    pub const fn set(&self) -> CommandSet {
        match self.time {
            None => CommandSet::Untagged,
            Some(_) => CommandSet::Tagged,
        }
    }

    /// The type identification this command is sent with.
    #[must_use]
    pub const fn type_id(&self) -> TypeId {
        self.value.family().type_id(self.set())
    }

    /// The family of the command.
    #[must_use]
    pub const fn family(&self) -> Family {
        self.value.family()
    }

    /// The `S/E` bit the command carries.
    #[must_use]
    pub const fn select(&self) -> bool {
        self.value.select()
    }

    /// The same command with the `S/E` bit set to `select`, everything else
    /// (the time tag included) unchanged.
    #[must_use]
    pub const fn with_select(self, select: bool) -> Self {
        Self {
            value: self.value.with_select(select),
            ..self
        }
    }

    /// Whether this is a command state the type defines; see
    /// [`CommandValue::is_command_state`].
    #[must_use]
    pub const fn is_command_state(&self) -> bool {
        self.value.is_command_state()
    }

    /// Whether the elements of two commands are the same ignoring the `S/E`
    /// bit; see [`CommandValue::state_eq`].
    ///
    /// Neither the time tag nor the information object address is compared:
    /// the time tag by the crate's reading of Table 19's execute-matches-select
    /// rule for a time-tagged station, the address because callers match it
    /// first.
    #[must_use]
    pub fn state_eq(&self, other: &Self) -> bool {
        self.value.state_eq(&other.value)
    }
}

/// The frame one command is written into, with the cause, the `P/N` flag and
/// the test bit as given. Every builder goes through here, so this is the one
/// place the type identification and the element's order are decided.
fn frame(
    command: &Command,
    cause: Cause,
    negative: bool,
    test: bool,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    let header = Header {
        type_id: command.type_id(),
        sequence: false,
        count: 1,
        cause,
        negative,
        test,
        originator,
        common_address,
    };
    let ioa = command.ioa;
    macro_rules! build {
        ($value:expr) => {
            encode_asdu_with(&header, &[LayoutObject { ioa, value: $value }], sizes)
        };
    }
    match (&command.value, command.time) {
        (CommandValue::Single { sco }, None) => build!(CScNa1 { sco: *sco }),
        (CommandValue::Single { sco }, Some(time)) => build!(CScTa1 { sco: *sco, time }),
        (CommandValue::Double { dco }, None) => build!(CDcNa1 { dco: *dco }),
        (CommandValue::Double { dco }, Some(time)) => build!(CDcTa1 { dco: *dco, time }),
        (CommandValue::RegulatingStep { rco }, None) => build!(CRcNa1 { rco: *rco }),
        (CommandValue::RegulatingStep { rco }, Some(time)) => build!(CRcTa1 { rco: *rco, time }),
        (CommandValue::SetPointNormalized { nva, qos }, None) => build!(CSeNa1 {
            nva: *nva,
            qos: *qos
        }),
        (CommandValue::SetPointNormalized { nva, qos }, Some(time)) => build!(CSeTa1 {
            nva: *nva,
            qos: *qos,
            time
        }),
        (CommandValue::SetPointScaled { sva, qos }, None) => build!(CSeNb1 {
            sva: *sva,
            qos: *qos
        }),
        (CommandValue::SetPointScaled { sva, qos }, Some(time)) => build!(CSeTb1 {
            sva: *sva,
            qos: *qos,
            time
        }),
        (CommandValue::SetPointFloat { r32, qos }, None) => build!(CSeNc1 {
            r32: *r32,
            qos: *qos
        }),
        (CommandValue::SetPointFloat { r32, qos }, Some(time)) => build!(CSeTc1 {
            r32: *r32,
            qos: *qos,
            time
        }),
        (CommandValue::Bitstring { bsi }, None) => build!(CBoNa1 { bsi: *bsi }),
        (CommandValue::Bitstring { bsi }, Some(time)) => build!(CBoTa1 { bsi: *bsi, time }),
    }
}

/// The command a received command ASDU carries (its address, value, `S/E` and
/// time tag), or `None` when it carries no object.
///
/// For an application that acts on a [`Reaction::Confirmed`] execute.
///
/// # Errors
///
/// [`LayoutError`] when `asdu` is not a well-formed ASDU, its header or its
/// first command object.
pub fn decode_command(asdu: &[u8]) -> Result<Option<Command>, LayoutError> {
    decode(asdu, AddressSizes::CONVENTIONAL)
}

/// [`decode_command`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`decode_command`].
pub fn decode_command_with(
    asdu: &[u8],
    sizes: AddressSizes,
) -> Result<Option<Command>, LayoutError> {
    decode(asdu, sizes)
}

/// Reads a command ASDU's first information object, or `None` for a type that
/// is not a command or an ASDU that carries none at all (5-101 clause 7.2.2's `<0> := ASDU contains no INFORMATION
/// OBJECT`).
fn decode(asdu: &[u8], sizes: AddressSizes) -> Result<Option<Command>, LayoutError> {
    match Header::parse_with(asdu, sizes)?.type_id {
        TypeId::CScNa1 => first::<CScNa1>(asdu, sizes, |o| {
            Command::new(o.ioa, CommandValue::Single { sco: o.value.sco })
        }),
        TypeId::CScTa1 => first::<CScTa1>(asdu, sizes, |o| {
            Command::tagged(
                o.ioa,
                CommandValue::Single { sco: o.value.sco },
                o.value.time,
            )
        }),
        TypeId::CDcNa1 => first::<CDcNa1>(asdu, sizes, |o| {
            Command::new(o.ioa, CommandValue::Double { dco: o.value.dco })
        }),
        TypeId::CDcTa1 => first::<CDcTa1>(asdu, sizes, |o| {
            Command::tagged(
                o.ioa,
                CommandValue::Double { dco: o.value.dco },
                o.value.time,
            )
        }),
        TypeId::CRcNa1 => first::<CRcNa1>(asdu, sizes, |o| {
            Command::new(o.ioa, CommandValue::RegulatingStep { rco: o.value.rco })
        }),
        TypeId::CRcTa1 => first::<CRcTa1>(asdu, sizes, |o| {
            Command::tagged(
                o.ioa,
                CommandValue::RegulatingStep { rco: o.value.rco },
                o.value.time,
            )
        }),
        TypeId::CSeNa1 => first::<CSeNa1>(asdu, sizes, |o| {
            Command::new(
                o.ioa,
                CommandValue::SetPointNormalized {
                    nva: o.value.nva,
                    qos: o.value.qos,
                },
            )
        }),
        TypeId::CSeTa1 => first::<CSeTa1>(asdu, sizes, |o| {
            Command::tagged(
                o.ioa,
                CommandValue::SetPointNormalized {
                    nva: o.value.nva,
                    qos: o.value.qos,
                },
                o.value.time,
            )
        }),
        TypeId::CSeNb1 => first::<CSeNb1>(asdu, sizes, |o| {
            Command::new(
                o.ioa,
                CommandValue::SetPointScaled {
                    sva: o.value.sva,
                    qos: o.value.qos,
                },
            )
        }),
        TypeId::CSeTb1 => first::<CSeTb1>(asdu, sizes, |o| {
            Command::tagged(
                o.ioa,
                CommandValue::SetPointScaled {
                    sva: o.value.sva,
                    qos: o.value.qos,
                },
                o.value.time,
            )
        }),
        TypeId::CSeNc1 => first::<CSeNc1>(asdu, sizes, |o| {
            Command::new(
                o.ioa,
                CommandValue::SetPointFloat {
                    r32: o.value.r32,
                    qos: o.value.qos,
                },
            )
        }),
        TypeId::CSeTc1 => first::<CSeTc1>(asdu, sizes, |o| {
            Command::tagged(
                o.ioa,
                CommandValue::SetPointFloat {
                    r32: o.value.r32,
                    qos: o.value.qos,
                },
                o.value.time,
            )
        }),
        TypeId::CBoNa1 => first::<CBoNa1>(asdu, sizes, |o| {
            Command::new(o.ioa, CommandValue::Bitstring { bsi: o.value.bsi })
        }),
        TypeId::CBoTa1 => first::<CBoTa1>(asdu, sizes, |o| {
            Command::tagged(
                o.ioa,
                CommandValue::Bitstring { bsi: o.value.bsi },
                o.value.time,
            )
        }),
        _ => Ok(None),
    }
}

/// The first object of a command ASDU of layout `A`, turned into a [`Command`]
/// by `to`, or `None` when the ASDU carries none.
fn first<A: AsduLayout>(
    asdu: &[u8],
    sizes: AddressSizes,
    to: impl FnOnce(&LayoutObject<A>) -> Command,
) -> Result<Option<Command>, LayoutError> {
    Ok(decode_asdu_with::<A>(asdu, sizes)?.first().map(to))
}

/// Builds the control-direction activation: the command ASDU with cause 6
/// (`act`), the `S/E` bit the command's own qualifier carries, and `P/N = 0`.
///
/// The cause is the clause's, not the caller's, so a frame the standard does not
/// list for the type cannot be built from this API. A command state the clause
/// marks *not permitted* (`DCS`/`RCS` 0 or 3) is refused with
/// [`CtError::NotACommandState`] rather than put on the wire (TS 60870-5-604
/// Table 19: *"a not allowed command (e.g. DCO=0 or 3; RCO=0 or 3)"*); the
/// **mirror** of such a command is [`confirmation`], which does build it, because
/// that refusal is exactly what the controlled station has to send.
///
/// # Errors
///
/// [`CtError::NotACommandState`] for a not-permitted command state, and
/// [`CtError::Layout`] when the ASDU cannot be encoded, for example an address
/// too wide for the field `sizes` gives it.
pub fn activation(
    command: &Command,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, CtError> {
    activation_with(
        command,
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
    command: &Command,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, CtError> {
    if !command.is_command_state() {
        return Err(CtError::NotACommandState { ioa: command.ioa });
    }
    Ok(frame(
        command,
        CAUSE_ACTIVATION,
        false,
        false,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds the deactivation: the command ASDU with cause 8 (`deact`).
///
/// 5-101 clause 7.4.7: *"DEACT, DEACTCON is only used in case of a select and
/// execute function."* and *"S/E of the qualifier of command QOC is irrelevant
/// in ASDUs with causes of transmission DEACT and DEACTCON."* The `S/E` the
/// command carries is therefore written as given and never policed. The
/// conformance test 5.4.19.10 sends its `DEACT` with `S/E = 1` (TS 60870-5-604
/// PDF page index 72).
///
/// The one type the clause does not give a deactivation is the tagged bitstring,
/// `C_BO_TA_1` (64): figure 29 (5-104, PDF page index 88) lists cause 8 neither
/// in the control direction nor 9 in the monitor direction, and a frame the
/// standard does not list for the type cannot be built from this API
/// ([`CtError::DeactivationNotDefined`]). Its 5-101 twin `C_BO_NA_1` (51) *does*
/// list both (figure 70, index 103), so the set is part of the question.
///
/// # Errors
///
/// [`CtError::DeactivationNotDefined`] for `C_BO_TA_1`, and
/// [`CtError::Layout`] when the ASDU cannot be encoded, for example an address
/// too wide for the field `sizes` gives it.
pub fn deactivation(
    command: &Command,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, CtError> {
    deactivation_with(
        command,
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
    command: &Command,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, CtError> {
    if !command.family().has_deactivation(command.set()) {
        return Err(CtError::DeactivationNotDefined {
            type_id: command.type_id(),
        });
    }
    Ok(frame(
        command,
        CAUSE_DEACTIVATION,
        false,
        false,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds the mirror: the command ASDU again, with cause 7 (`actcon`) and `P/N`
/// as given, for the positive **and** the negative confirmation.
///
/// The command state is **not** checked here: a negative confirmation of a
/// command the clause marks *not permitted* is the controlled station's
/// required answer, not a frame to refuse (TS 60870-5-604 5.4.19.30).
///
/// `test` is the answered frame's test bit (`T`), which goes back unchanged, as
/// does the originator address the caller passes (cl.7.2.3's *"the controlled
/// station should echo this originator address in the response"*). Both are the
/// caller's to hand over, because the caller holds the received header.
///
/// # Errors
///
/// [`CtError::Layout`] when the ASDU cannot be encoded, for example an address
/// too wide for the field `sizes` gives it.
pub fn confirmation(
    command: &Command,
    negative: bool,
    common_address: u16,
    originator: u8,
    test: bool,
) -> Result<Vec<u8>, CtError> {
    confirmation_with(
        command,
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
    command: &Command,
    negative: bool,
    common_address: u16,
    originator: u8,
    test: bool,
    sizes: AddressSizes,
) -> Result<Vec<u8>, CtError> {
    Ok(frame(
        command,
        CAUSE_ACTIVATION_CON,
        negative,
        test,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds the cause 44 to 47 mirror of a received command: the command ASDU
/// again with `P/N = 1` and the cause of the field the station does not know.
///
/// 5-101 clause 7.2.3's table (PDF page index 42): *"ASDUs in the control
/// direction with undefined values in the data unit identifier (except the
/// variable structure qualifier) and the information object address are mirrored
/// by the controlled station with bit \"P/N := <1> negative confirm\" and the
/// following causes of transmission"*: 44 unknown type identification, 45
/// unknown cause of transmission, 46 unknown common address of ASDU, 47 unknown
/// information object address. [`CommandTransmission::on_request`] sends the
/// same reply by itself for what the caller's [`Known`] does not know, and
/// [`crate::asdu::mirror_reply`] builds it octet-wise for a frame whose type
/// identification has no layout to rebuild from.
///
/// # Errors
///
/// [`CtError::Layout`] when the ASDU cannot be encoded, for example an address
/// too wide for the field `sizes` gives it.
pub fn unknown_reply(
    command: &Command,
    reason: crate::asdu::Unspecified,
    common_address: u16,
    originator: u8,
    test: bool,
) -> Result<Vec<u8>, CtError> {
    unknown_reply_with(
        command,
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
    command: &Command,
    reason: crate::asdu::Unspecified,
    common_address: u16,
    originator: u8,
    test: bool,
    sizes: AddressSizes,
) -> Result<Vec<u8>, CtError> {
    Ok(frame(
        command,
        reason.cause(),
        true,
        test,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds the deactivation's mirror: the command ASDU with cause 9
/// (`deactcon`), echoing the answered frame's originator and test bit.
///
/// The tagged bitstring `C_BO_TA_1` (64) has no deactivation (figure 29, 5-104,
/// PDF page index 88, lists neither cause 8 nor cause 9), so this builder
/// carries the same gate as [`deactivation`] and refuses it with
/// [`CtError::DeactivationNotDefined`].
///
/// # Errors
///
/// [`CtError::DeactivationNotDefined`] for `C_BO_TA_1`, and
/// [`CtError::Layout`] when the ASDU cannot be encoded, for example an address
/// too wide for the field `sizes` gives it.
pub fn deactivation_confirmation(
    command: &Command,
    common_address: u16,
    originator: u8,
    test: bool,
) -> Result<Vec<u8>, CtError> {
    deactivation_confirmation_with(
        command,
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
    command: &Command,
    common_address: u16,
    originator: u8,
    test: bool,
    sizes: AddressSizes,
) -> Result<Vec<u8>, CtError> {
    if !command.family().has_deactivation(command.set()) {
        return Err(CtError::DeactivationNotDefined {
            type_id: command.type_id(),
        });
    }
    Ok(frame(
        command,
        CAUSE_DEACTIVATION_CON,
        false,
        test,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds the termination: the command ASDU with cause 10 (`actterm`) and `P/N`
/// as given.
///
/// This is TS 60870-5-604 Table 19's *"mirrors the previous Command message
/// with COT=10, `C_SC/DC/SE/RC_ACTTERM`"*, and for 5.4.19.40/.50 the **negative**
/// termination of a command that was accepted and then failed.
///
/// # Errors
///
/// [`CtError::Layout`] when the ASDU cannot be encoded, for example an address
/// too wide for the field `sizes` gives it.
pub fn termination(
    command: &Command,
    negative: bool,
    common_address: u16,
    originator: u8,
    test: bool,
) -> Result<Vec<u8>, CtError> {
    termination_with(
        command,
        negative,
        common_address,
        originator,
        test,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`termination`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`termination`].
pub fn termination_with(
    command: &Command,
    negative: bool,
    common_address: u16,
    originator: u8,
    test: bool,
    sizes: AddressSizes,
) -> Result<Vec<u8>, CtError> {
    Ok(frame(
        command,
        CAUSE_ACTIVATION_TERM,
        negative,
        test,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds the return information: the monitor-direction process ASDU of the
/// object the command changed, with the cause [`ReturnInfo`] names and
/// `P/N = 0`.
///
/// 5-104 clause 7.7's `A_RETURN_INF` row carries **`M_SP, M_DP, M_ST`**, a
/// different type identification and codec path from the command ASDU the
/// confirmation mirrors, so this builder takes a monitor layout, not a
/// [`CommandValue`]. Its type must be one of [`RETURN_TYPES`]; anything else is
/// [`CtError::NotReturnType`], because 104 clause 7.7 lists three families and
/// this crate will not silently send a fourth. The frame's test bit is 0.
///
/// Nothing schedules it: clause 7.4.7's *"`RETURN_INF` for control operation
/// complete is used (if available)"* puts both the availability and the moment
/// in the application's hands, and TS 60870-5-604 Table 19 permits the frame
/// before or after the `ACTTERM` (*"The controlled station may send the
/// `RETURN_INF` with COT=3, 11, or 12 after the ACTTERM"*).
///
/// # Errors
///
/// [`CtError::NotReturnType`] when `A` is not one of [`RETURN_TYPES`], and
/// [`CtError::Layout`] when the ASDU cannot be encoded, for example an address
/// too wide for the field `sizes` gives it.
pub fn return_information<A: AsduLayout>(
    ioa: u32,
    value: A,
    info: ReturnInfo,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, CtError> {
    return_information_with(
        ioa,
        value,
        info,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`return_information`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`return_information`].
pub fn return_information_with<A: AsduLayout>(
    ioa: u32,
    value: A,
    info: ReturnInfo,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, CtError> {
    if !is_return_type(A::TYPE_ID) {
        return Err(CtError::NotReturnType {
            type_id: A::TYPE_ID,
        });
    }
    let header = Header {
        type_id: A::TYPE_ID,
        sequence: false,
        count: 1,
        cause: info.cause(),
        negative: false,
        test: false,
        originator,
        common_address,
    };
    Ok(encode_asdu_with(
        &header,
        &[LayoutObject { ioa, value }],
        sizes,
    )?)
}

/// Which side of the procedure a [`CommandTransmission`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The commanding side: selects, executes and deactivates.
    Controlling,
    /// The commanded side: mirrors, executes and terminates.
    Controlled,
}

/// What one frame of the procedure means, from the point of view of the role
/// that received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// An activation confirmation arrived or was sent. `select` says whether it
    /// answers a select (`S/E = 1`) or an execute, and `negative` is the `P/N`
    /// flag (5-101 cl.7.2.3's negative confirmation, TS 60870-5-604's
    /// `ACTCONneg`).
    Confirmed {
        /// The information object address the command controls.
        ioa: u32,
        /// `true` for a select's confirmation, `false` for an execute's.
        select: bool,
        /// `P/N = 1`: a negative confirmation.
        negative: bool,
    },
    /// The procedure ended (`ACTTERM`, cause `<10>`), positive or negative.
    Terminated {
        /// The information object address that ended.
        ioa: u32,
        /// `P/N = 1`: the negative termination of TS 60870-5-604 5.4.19.40/.50,
        /// *"first accept the command with a Positive ACTCON and then send a
        /// Negative Termination by mirroring the previous Command message with
        /// COT=10 … and P/N=1"*. The controlling station has to tell the two
        /// apart, since on the negative one it *"stops the Command function with
        /// an indication at user level"*, so the flag is part of the reaction.
        negative: bool,
    },
    /// The controlled station refused the received frame with clause 7.2.3's
    /// mirror (PDF page index 42): the same ASDU with `P/N = 1` and `cause`, one
    /// of the four *"unknown …"* causes. That is 44 for a type identification the
    /// station does not implement, 45 for a cause of transmission the type does
    /// not define in the control direction, 46 for a common address that is not
    /// the station's own (a command to the global address included), 47 for an
    /// information object address the station has no data for. [`Outcome::send`]
    /// holds the frame.
    ///
    /// A *negative `ACTCON`* (TS 60870-5-604 5.4.19.30/.50's refusal of a select
    /// or an execute) is [`Reaction::Confirmed`] with `negative: true` on both
    /// roles, because it is the ordinary mirror with its `P/N` flag set, and the
    /// controlling station has to see the same shape whichever side sent it.
    Refused {
        /// The information object address the received command addressed.
        ioa: u32,
        /// The cause the mirror carries: one of 44–47.
        cause: Cause,
    },
    /// A **positive select confirmation that does not repeat the select this
    /// station sent**: TS 60870-5-604 5.4.19.1's *"If the SELECT message from
    /// the Controlling station is not correctly mirrored by the Controlled
    /// station, then the Controlling station does not proceed with sending the
    /// EXECUTE message"*. The select is dropped exactly as a negative
    /// confirmation drops it, and this variant is how the caller is told that
    /// the drop was a broken mirror and not a refusal: `Confirmed` with
    /// `negative: false` would read as success until `execute` failed.
    NotMirrored {
        /// The information object address whose select was not mirrored.
        ioa: u32,
    },
    /// The controlled station received a command of the other [`CommandSet`]
    /// (5-104 cl.9). It is answered like any type the station does not
    /// implement: [`Outcome::send`] holds the cause-44 mirror with `P/N = 1`.
    WrongCommandSet {
        /// The information object address the received command addressed.
        ioa: u32,
        /// The received type identification.
        type_id: TypeId,
        /// The station's own set.
        set: CommandSet,
    },
    /// Controlled station, [`CommandTransmission::on_request_at`]: a
    /// time-tagged command older than the
    /// [maximum command delay](CommandTransmission::with_max_command_delay).
    /// 104 cl.8: nothing is sent and nothing is performed. The application
    /// can record that the command arrived too late; [`decode_command`] gives
    /// it the whole command.
    TooLate {
        /// The information object address the command named.
        ioa: u32,
        /// The command's time tag: when the controlling station initiated it.
        time: Cp56Time2a,
    },
    /// Controlled station: a deactivation of an object with no select to stop,
    /// answered with a negative `DEACTCON` in [`Outcome::send`].
    NothingToDeactivate {
        /// The information object address the deactivation named.
        ioa: u32,
    },
    /// A deactivation was confirmed (cause `<9>`), and the select it stopped.
    Deactivated {
        /// The information object address that was deactivated.
        ioa: u32,
    },
    /// The monitor-direction process ASDU of the controlled object arrived: a
    /// return information, with cause 11, 12 or 3.
    Returned {
        /// The information object address of the object that changed.
        ioa: u32,
        /// The cause it carried, as a value.
        info: ReturnInfo,
    },
    /// Clause 7.2.3 says this ASDU is discarded and may be logged
    /// ([`discard_reason`]'s verdict).
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
    /// The ASDUs to send, in order. Always empty for a controlling station; for
    /// a controlled station it carries the one answer the frame is owed (the
    /// mirror, or the `DEACTCON` of a deactivation), or nothing for a discarded
    /// or [`Reaction::TooLate`] frame or one this procedure does not own.
    pub send: Vec<Vec<u8>>,
}

/// What can go wrong in this layer, over and above the codec's own errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtError {
    /// The entry point does not belong to this instance's role: `select`,
    /// `execute`, `deactivate` and `on_response` are the controlling station's,
    /// `on_request`, `refuse` and `terminate` are the controlled station's.
    WrongRole,
    /// A select for an information object address that is already selected or
    /// whose select is still awaiting its mirror: one select at a time, per
    /// object (5-101 cl.7.4.7's select and execute function).
    AlreadySelected {
        /// The information object address already selected.
        ioa: u32,
    },
    /// An execute with no confirmed select before it, from a station whose
    /// [`CommandMode`] is [`CommandMode::SelectAndExecute`].
    ExecuteWithoutSelect {
        /// The information object address.
        ioa: u32,
    },
    /// A deactivation of an information object address that has no confirmed
    /// select outstanding.
    DeactivationWithoutSelect {
        /// The information object address.
        ioa: u32,
    },
    /// A deactivation whose command is not the message the select carried.
    /// TS 60870-5-604 5.4.19.10: *"The Controlling station sends the same Command
    /// message with COT=8 … and S/E=1 (SELECT)"*.
    DeactivationMismatch {
        /// The information object address.
        ioa: u32,
    },
    /// The type identification has no deactivation in its set: `C_BO_TA_1`
    /// (64), whose figure 29 (5-104, PDF page index 88) lists neither cause 8 nor
    /// cause 9.
    DeactivationNotDefined {
        /// The type identification that has none.
        type_id: TypeId,
    },
    /// A command state the type does not define: `DCS`/`RCS` 0 or 3
    /// (5-101 cl.7.2.6.16/.17, TS 60870-5-604's *"not allowed command"*).
    NotACommandState {
        /// The information object address the command addresses.
        ioa: u32,
    },
    /// A select by or to a station whose [`CommandMode`] is
    /// [`CommandMode::Direct`], which has no select procedure (5-101 cl.7.4.7's
    /// *"The select procedure is only used in case of a select and execute
    /// function."*). Also returned by `deactivate` on such a station.
    SelectNotAllowed {
        /// The mode that refuses it.
        mode: CommandMode,
    },
    /// A select of a family that carries no qualifier and therefore has no
    /// `S/E` bit: the bitstring command (figure 70, PDF page index 103).
    NotSelectable {
        /// The information object address the command addresses.
        ioa: u32,
    },
    /// The command's type identification is not in the station's
    /// [`CommandSet`] (5-104 clause 9's *"Either the ASDUs of the set `<45>` –
    /// `<51>` or of the set `<58>` – `<64>` are used."*).
    WrongCommandSet {
        /// The type identification that does not belong to the station's set.
        type_id: TypeId,
        /// The station's own set.
        set: CommandSet,
    },
    /// There is nothing to terminate: no execute of that information object
    /// address is running.
    NotRunning {
        /// The information object address.
        ioa: u32,
    },
    /// The station's [`Termination`] does not use an `ACTTERM` for the family
    /// of this information object address.
    TerminationNotUsed {
        /// The information object address.
        ioa: u32,
    },
    /// The layout the caller offered as a return information is not one of the
    /// six types of [`RETURN_TYPES`].
    NotReturnType {
        /// The type identification the caller offered.
        type_id: TypeId,
    },
    /// The ASDU itself could not be parsed; the layout/header layer's error,
    /// unchanged.
    Layout(LayoutError),
}

impl From<LayoutError> for CtError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<AsduError> for CtError {
    /// The header/codec error reaches this layer through the layout layer's own
    /// wrapper, exactly as [`crate::asdu::decode_asdu`] surfaces it.
    fn from(err: AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// One role's command transmission procedure.
///
/// The role here is the *procedure's* role, not the transport's: a station that
/// is the TCP client is the controlling station (5-104 clause 7), but the same
/// station may hold the other role's instance for the reverse direction.
///
/// The state is the select and the running execute, keyed by information object
/// address. Nothing here reads a clock: the controlled station's select timeout
/// runs on the `now` the caller hands to
/// [`expire_selections`](Self::expire_selections), and [`abandon`](Self::abandon)
/// and [`reset`](Self::reset) drop state on either role.
#[derive(Debug, Clone, PartialEq)]
pub struct CommandTransmission {
    role: Role,
    mode: CommandMode,
    set: CommandSet,
    termination: Termination,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
    /// The controlling station: the selects it has **sent** whose mirror has not
    /// arrived yet. Nothing here is executable (TS 60870-5-604 5.4.19.1: *"If
    /// the SELECT message from the Controlling station is not correctly mirrored
    /// by the Controlled station, then the Controlling station does not proceed
    /// with sending the EXECUTE message"*), so a select moves to `selected` only
    /// when the controlled station's positive `ACTCON` arrives, and is dropped
    /// when the mirror is negative or is a 44–47 reply. The controlled station
    /// holds its own selects in `selected` directly: it is the one answering.
    awaiting: Vec<Command>,
    /// Both roles: the selects that are outstanding (confirmed, not yet
    /// executed and not yet deactivated).
    selected: Vec<Command>,
    /// Both roles: the executes whose procedure still owes its termination.
    /// The controlling station records one when it sends the execute; only
    /// families [`Termination`] terminates are recorded.
    running: Vec<Command>,
    /// The controlled station: the originator address and test bit each running
    /// execute arrived with, so the `ACTTERM` can echo them (cl.7.2.3).
    reply_to: Vec<(u32, u8, bool)>,
    /// The controlled station's select timeout, if configured.
    select_timeout: Option<Duration>,
    /// The last `now` given to `expire_selections`; new selects are timed from it.
    clock: Option<Instant>,
    /// The deadline of each timed select, keyed by information object address.
    deadlines: Vec<(u32, Instant)>,
    /// The controlled station's maximum allowable delay of a time-tagged
    /// command (104 cl.8), if configured.
    max_delay: Option<Duration>,
    /// The wall-clock time [`CommandTransmission::on_request_at`] is serving,
    /// for the duration of that call.
    wall_clock: Option<Cp56Time2a>,
}

impl CommandTransmission {
    /// A controlling station's instance, selecting the station's procedure mode,
    /// its command set and its termination policy.
    #[must_use]
    pub const fn controlling(
        mode: CommandMode,
        set: CommandSet,
        termination: Termination,
        common_address: u16,
        originator: u8,
    ) -> Self {
        Self::new(
            Role::Controlling,
            mode,
            set,
            termination,
            common_address,
            originator,
        )
    }

    /// A controlled station's instance, selecting the same three things.
    #[must_use]
    pub const fn controlled(
        mode: CommandMode,
        set: CommandSet,
        termination: Termination,
        common_address: u16,
        originator: u8,
    ) -> Self {
        Self::new(
            Role::Controlled,
            mode,
            set,
            termination,
            common_address,
            originator,
        )
    }

    const fn new(
        role: Role,
        mode: CommandMode,
        set: CommandSet,
        termination: Termination,
        ca: u16,
        org: u8,
    ) -> Self {
        Self {
            role,
            mode,
            set,
            termination,
            ca,
            org,
            sizes: AddressSizes::CONVENTIONAL,
            awaiting: Vec::new(),
            selected: Vec::new(),
            running: Vec::new(),
            reply_to: Vec::new(),
            select_timeout: None,
            clock: None,
            deadlines: Vec::new(),
            max_delay: None,
            wall_clock: None,
        }
    }

    /// The same instance with a select timeout: on the controlled station, a
    /// select not executed or deactivated within `timeout` of its arrival is
    /// dropped by [`expire_selections`](Self::expire_selections). Without one,
    /// a select stays until it is executed, deactivated, abandoned or reset.
    #[must_use]
    pub const fn with_select_timeout(mut self, timeout: Duration) -> Self {
        self.select_timeout = Some(timeout);
        self
    }

    /// The same instance with 104 cl.8's maximum allowable delay of a
    /// time-tagged command: on the controlled station, a command whose
    /// `CP56Time2a` is older than `max` when it arrives gets **no** protocol
    /// response and changes no state. It is [`Reaction::TooLate`], so the
    /// application can see it arrived but must not act on it. Checked only by
    /// [`on_request_at`](Self::on_request_at), which is given the time.
    #[must_use]
    pub const fn with_max_command_delay(mut self, max: Duration) -> Self {
        self.max_delay = Some(max);
        self
    }

    /// The configured maximum command delay, if any.
    #[must_use]
    pub const fn max_command_delay(&self) -> Option<Duration> {
        self.max_delay
    }

    /// [`on_request`](Self::on_request) at a known time.
    ///
    /// `now` expires lapsed selects and times any select this request makes.
    /// `wall_clock`, this station's calendar time in the same time zone as the
    /// controlling station's time tags (its `SU` bit set in summer time; a tag's
    /// and the clock's `SU` are both taken into account), supervises the
    /// [maximum command delay](Self::with_max_command_delay) of an activation;
    /// with `None` no command is too late.
    ///
    /// # Errors
    ///
    /// As [`on_request`](Self::on_request).
    pub fn on_request_at(
        &mut self,
        asdu: &[u8],
        known: &Known,
        now: Instant,
        wall_clock: Option<Cp56Time2a>,
    ) -> Result<Outcome, CtError> {
        self.expire_selections(now);
        self.clock = Some(now);
        self.wall_clock = wall_clock;
        let outcome = self.on_request(asdu, known);
        self.wall_clock = None;
        outcome
    }

    /// The configured select timeout, if any.
    #[must_use]
    pub const fn select_timeout(&self) -> Option<Duration> {
        self.select_timeout
    }

    /// Advances the controlled station's clock to `now` and drops every select
    /// whose timeout has lapsed (deadline `<= now`), returning their information
    /// object addresses. An execute that arrives afterwards finds no select and
    /// is refused with a negative `ACTCON` (TS 60870-5-604 5.4.19.40); a new
    /// select of the object is accepted.
    ///
    /// Call it with the receive time before each
    /// [`on_request`](Self::on_request): a select accepted there is timed from
    /// the last `now` given here. A select accepted before the first call is
    /// timed from that call. Does nothing without a
    /// [select timeout](Self::with_select_timeout) or on the controlling role.
    pub fn expire_selections(&mut self, now: Instant) -> Vec<u32> {
        let Some(timeout) = self.select_timeout else {
            return Vec::new();
        };
        if self.role != Role::Controlled {
            return Vec::new();
        }
        self.clock = Some(now);
        // Stamp selects that arrived before the clock was known.
        for command in &self.selected {
            if !self.deadlines.iter().any(|(ioa, _)| *ioa == command.ioa)
                && let Some(deadline) = now.checked_add(timeout)
            {
                self.deadlines.push((command.ioa, deadline));
            }
        }
        let lapsed: Vec<u32> = self
            .deadlines
            .iter()
            .filter(|(_, deadline)| *deadline <= now)
            .map(|(ioa, _)| *ioa)
            .collect();
        for ioa in &lapsed {
            self.drop_select(*ioa);
        }
        lapsed
    }

    /// Drops every select, pending select, running execute and deadline, for a
    /// reconnect or when the caller gives up on the whole procedure. The
    /// configuration and the clock are kept.
    pub fn reset(&mut self) {
        self.awaiting.clear();
        self.selected.clear();
        self.running.clear();
        self.reply_to.clear();
        self.deadlines.clear();
    }

    /// Drops every select, pending select and deadline but keeps the running
    /// executes, for a controlled station whose controlling station has gone
    /// while an operation is still under way: the object stays occupied until
    /// [`terminate`](Self::terminate) frees it, so a second execute of it is
    /// refused (TS 60870-5-604 5.4.19.40) rather than operated alongside.
    pub fn drop_selects(&mut self) {
        let running = std::mem::take(&mut self.running);
        let reply_to = std::mem::take(&mut self.reply_to);
        self.reset();
        self.running = running;
        self.reply_to = reply_to;
    }

    /// Drops everything outstanding for `ioa` (a select in flight, a confirmed
    /// select, a running execute) and reports whether there was anything. The
    /// controlling station uses it when its own delay for an answer lapses; a
    /// controlled station uses it to deselect an object. Nothing is sent.
    pub fn abandon(&mut self, ioa: u32) -> bool {
        let had = self.is_awaiting(ioa) || self.is_selected(ioa) || self.is_running(ioa);
        self.forget(ioa);
        self.reply_to.retain(|(address, _, _)| *address != ioa);
        had
    }

    /// Whether `command` is past the maximum command delay at the wall-clock
    /// time [`on_request_at`](Self::on_request_at) was given. A tag from the
    /// future by more than the same margin, or a time that cannot be converted,
    /// is treated the same way: it cannot be the command's initiation time.
    ///
    /// Both times are compared as standard time
    /// ([`Cp56Time2a::standard_millis_since_2000`]), so the `SU` bit of the tag
    /// and of the clock is taken into account: TS 60870-5-604 5.4.25.4 (PDF page
    /// index 88), *"A command using summer time bit shall be used to either
    /// accept or ignore the command based on its configured acceptable delay for
    /// command transmission"*.
    fn too_late(&self, command: &Command) -> bool {
        let (Some(tag), Some(max), Some(now)) = (command.time, self.max_delay, self.wall_clock)
        else {
            return false;
        };
        let (Some(tag), Some(now)) = (
            tag.standard_millis_since_2000(),
            now.standard_millis_since_2000(),
        ) else {
            return true;
        };
        let max = u64::try_from(max.as_millis()).unwrap_or(u64::MAX);
        now.abs_diff(tag) > max
    }

    /// Removes the select of `ioa` and its deadline.
    fn drop_select(&mut self, ioa: u32) {
        self.selected.retain(|selected| selected.ioa != ioa);
        self.deadlines.retain(|(address, _)| *address != ioa);
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

    /// The station's command procedure mode.
    #[must_use]
    pub const fn mode(&self) -> CommandMode {
        self.mode
    }

    /// The station's command set.
    #[must_use]
    pub const fn set(&self) -> CommandSet {
        self.set
    }

    /// The station's termination policy.
    #[must_use]
    pub const fn termination(&self) -> Termination {
        self.termination
    }

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// The selects that are outstanding, in the order they were selected.
    #[must_use]
    pub fn selected(&self) -> &[Command] {
        &self.selected
    }

    /// The controlling station's selects that are sent but not yet confirmed:
    /// the outstanding `A_SELECT.req`s whose `A_SELECT.con` has not arrived.
    #[must_use]
    pub fn awaiting(&self) -> &[Command] {
        &self.awaiting
    }

    /// The executes whose procedure still owes its termination, for the
    /// families [`Termination`] terminates. The controlling station records an
    /// execute when it sends it, the controlled station when it confirms it.
    #[must_use]
    pub fn running(&self) -> &[Command] {
        &self.running
    }

    /// Whether `ioa` is selected and therefore executable. A select that has
    /// been sent but not yet mirrored positively is **not** selected.
    #[must_use]
    pub fn is_selected(&self, ioa: u32) -> bool {
        self.selected.iter().any(|command| command.ioa == ioa)
    }

    /// Whether `ioa` has a select in flight: sent, still waiting for its mirror.
    #[must_use]
    pub fn is_awaiting(&self, ioa: u32) -> bool {
        self.awaiting.iter().any(|command| command.ioa == ioa)
    }

    /// Whether `ioa` has an execute running.
    #[must_use]
    pub fn is_running(&self, ioa: u32) -> bool {
        self.running.iter().any(|command| command.ioa == ioa)
    }

    /// The command's set against the station's: the "not mixed" gate for the
    /// controlling station's sends.
    fn check_set(&self, command: &Command) -> Result<(), CtError> {
        if command.set() == self.set {
            Ok(())
        } else {
            Err(CtError::WrongCommandSet {
                type_id: command.type_id(),
                set: self.set,
            })
        }
    }

    /// The controlling station's select of `command`: the same command with
    /// `S/E = 1` and cause 6, as the frame to send.
    ///
    /// The `S/E` bit is written by this method, not read from `command`, so one
    /// [`Command`] value serves both calls: 5-101 clause 7.2.6.26's `S/E`
    /// (*"<0> := execute"*, *"<1> := select"*) is the procedure's, not the
    /// caller's. A station whose mode has no select procedure refuses it
    /// ([`CtError::SelectNotAllowed`]), a family without a qualifier refuses it
    /// ([`CtError::NotSelectable`]), and a second select for an address that is
    /// already selected or already in flight is [`CtError::AlreadySelected`].
    ///
    /// The select is only *sent* here: it enters [`selected`](Self::selected)
    /// when the controlled station's positive `ACTCON` arrives
    /// ([`CommandTransmission::on_response`]), and a negative one drops it.
    /// Until then [`CommandTransmission::execute`] refuses the execute
    /// (TS 60870-5-604 5.4.19.1's *"does not proceed with sending the EXECUTE
    /// message"*).
    ///
    /// # Errors
    ///
    /// [`CtError::WrongRole`] on the controlled role, [`CtError::WrongCommandSet`]
    /// for a command of the other set, [`CtError::SelectNotAllowed`],
    /// [`CtError::NotSelectable`], [`CtError::NotACommandState`],
    /// [`CtError::AlreadySelected`], and [`CtError::Layout`] when the frame
    /// cannot be encoded.
    pub fn select(&mut self, command: &Command) -> Result<Vec<u8>, CtError> {
        if self.role != Role::Controlling {
            return Err(CtError::WrongRole);
        }
        self.check_set(command)?;
        if !self.mode.requires_select() {
            return Err(CtError::SelectNotAllowed { mode: self.mode });
        }
        if !command.value.supports_select() {
            return Err(CtError::NotSelectable { ioa: command.ioa });
        }
        if !command.is_command_state() {
            return Err(CtError::NotACommandState { ioa: command.ioa });
        }
        if self.is_selected(command.ioa) || self.is_awaiting(command.ioa) {
            return Err(CtError::AlreadySelected { ioa: command.ioa });
        }
        let sent = command.with_select(true);
        let frame = activation_with(&sent, self.ca, self.org, self.sizes)?;
        self.awaiting.push(sent);
        Ok(frame)
    }

    /// The controlling station's execute of `command`: the same command with
    /// `S/E = 0` and cause 6.
    ///
    /// A station whose mode is [`CommandMode::SelectAndExecute`] requires the
    /// select before it and consumes that select here, so an execute with no
    /// **confirmed** select is [`CtError::ExecuteWithoutSelect`]; a select that
    /// was sent but never mirrored positively does not count (TS 60870-5-604
    /// 5.4.19.1). The exception is the bitstring, a family with no `S/E` bit,
    /// which is always a direct execute ([`CommandValue::supports_select`]). A station
    /// whose mode is [`CommandMode::Direct`] sends the execute alone. Whether the
    /// procedure will be terminated is [`Termination`]'s answer, and a family it
    /// does not terminate is not recorded as running.
    ///
    /// # Errors
    ///
    /// [`CtError::WrongRole`] on the controlled role, [`CtError::WrongCommandSet`]
    /// for a command of the other set, [`CtError::NotACommandState`],
    /// [`CtError::ExecuteWithoutSelect`], and [`CtError::Layout`] when the
    /// frame cannot be encoded.
    pub fn execute(&mut self, command: &Command) -> Result<Vec<u8>, CtError> {
        if self.role != Role::Controlling {
            return Err(CtError::WrongRole);
        }
        self.check_set(command)?;
        if !command.is_command_state() {
            return Err(CtError::NotACommandState { ioa: command.ioa });
        }
        if self.mode.requires_select() && command.value.supports_select() {
            let index = self
                .selected
                .iter()
                .position(|selected| selected.ioa == command.ioa)
                .ok_or(CtError::ExecuteWithoutSelect { ioa: command.ioa })?;
            self.selected.remove(index);
        } else {
            self.selected.retain(|selected| selected.ioa != command.ioa);
        }
        let sent = command.with_select(false);
        let frame = activation_with(&sent, self.ca, self.org, self.sizes)?;
        if self.termination.uses(sent.value.family()) && !self.is_running(sent.ioa) {
            self.running.push(sent);
        }
        Ok(frame)
    }

    /// The controlling station's deactivation of the select outstanding for
    /// `command`: the command ASDU with cause 8.
    ///
    /// TS 60870-5-604 5.4.19.10: *"The Controlling station sends the same Command
    /// message with COT=8, `C_SC/DC/SE/RC_DEACT`, and S/E=1 (SELECT) to the
    /// Controlled station"*. The frame therefore repeats the **stored** select,
    /// `S/E = 1` included, and not the caller's value; `command` must carry that
    /// select's element or the call is [`CtError::DeactivationMismatch`]. Only a
    /// *confirmed* select can be deactivated, and only by a station whose mode
    /// has the select procedure ([`CtError::SelectNotAllowed`] otherwise).
    ///
    /// The select is left outstanding until the other station's `DEACTCON`
    /// arrives: a deactivation that was never answered leaves the select in
    /// place, exactly as [`crate::gi`] leaves a deactivation's scope running.
    ///
    /// # Errors
    ///
    /// [`CtError::WrongRole`] on the controlled role, [`CtError::WrongCommandSet`]
    /// for a command of the other set, [`CtError::SelectNotAllowed`],
    /// [`CtError::DeactivationWithoutSelect`], [`CtError::DeactivationMismatch`],
    /// [`CtError::DeactivationNotDefined`], and [`CtError::Layout`] when the
    /// frame cannot be encoded.
    pub fn deactivate(&mut self, command: &Command) -> Result<Vec<u8>, CtError> {
        if self.role != Role::Controlling {
            return Err(CtError::WrongRole);
        }
        self.check_set(command)?;
        if !self.mode.requires_select() {
            return Err(CtError::SelectNotAllowed { mode: self.mode });
        }
        let selected = self
            .selected
            .iter()
            .find(|selected| selected.ioa == command.ioa)
            .copied()
            .ok_or(CtError::DeactivationWithoutSelect { ioa: command.ioa })?;
        if !selected.state_eq(command) {
            return Err(CtError::DeactivationMismatch { ioa: command.ioa });
        }
        deactivation_with(&selected, self.ca, self.org, self.sizes)
    }

    /// The controlling station's decision for one received ASDU.
    ///
    /// Clause 7.2.3's discard rule runs first, as in [`crate::init::on_asdu`],
    /// with one addition: a **mirror** (the clause's 44–47 reply, `P/N = 1`)
    /// ends whatever this station had outstanding for its address, because a
    /// refusal is a "stop the Command function" and not a frame to carry on
    /// from (TS 60870-5-604 5.4.19.30). A command ASDU of the other
    /// [`CommandSet`] is [`CtError::WrongCommandSet`]. A command ASDU whose
    /// cause is not one of figure 64's monitor-direction responses is
    /// [`Reaction::Other`], and so is a monitor-direction ASDU that is not a
    /// return information, and an `ACTTERM` or `DEACTCON` for an address with
    /// nothing outstanding.
    ///
    /// Every accepted frame moves this side's own state with it: a positive
    /// select confirmation promotes the select this station actually sent into
    /// [`CommandTransmission::selected`], a negative one drops it, a negative
    /// execute confirmation drops the run, a `DEACTCON` clears the select, and
    /// an `ACTTERM` ends the run. A positive select confirmation that does
    /// **not** repeat what this station sent is [`Reaction::NotMirrored`]: the
    /// select is dropped all the same (TS 60870-5-604 5.4.19.1's *"not correctly
    /// mirrored"*), but the caller is told, because otherwise the drop is
    /// invisible until `execute` fails. A confirmation that answers nothing this
    /// station sent changes no state and is still reported as
    /// [`Reaction::Confirmed`], so the caller can log it.
    ///
    /// # Errors
    ///
    /// [`CtError::WrongRole`] on the controlled role, [`CtError::WrongCommandSet`]
    /// for a command ASDU of the other set, and [`CtError::Layout`] (or the
    /// ASDU error it wraps) when `asdu` cannot be parsed.
    pub fn on_response(&mut self, asdu: &[u8], known: &Known) -> Result<Outcome, CtError> {
        if self.role != Role::Controlling {
            return Err(CtError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if let Some(reason) = discard_reason(&header, known) {
            if reason == Discard::Mirror
                && let Some(command) = decode(asdu, self.sizes)?
            {
                self.forget(command.ioa);
            }
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        if let Some((_, set)) = Family::of_type(header.type_id) {
            if set != self.set {
                return Err(CtError::WrongCommandSet {
                    type_id: header.type_id,
                    set: self.set,
                });
            }
            let Some(command) = decode(asdu, self.sizes)? else {
                return Ok(other());
            };
            let reaction = match header.cause {
                Cause::ActivationCon => self.on_activation_con(&command, header.negative),
                Cause::ActivationTermination => {
                    if !self.is_running(command.ioa) {
                        return Ok(other());
                    }
                    self.running.retain(|running| running.ioa != command.ioa);
                    Reaction::Terminated {
                        ioa: command.ioa,
                        negative: header.negative,
                    }
                }
                Cause::DeactivationCon => {
                    if !self.is_selected(command.ioa) && !self.is_awaiting(command.ioa) {
                        return Ok(other());
                    }
                    self.selected.retain(|selected| selected.ioa != command.ioa);
                    self.awaiting.retain(|sent| sent.ioa != command.ioa);
                    Reaction::Deactivated { ioa: command.ioa }
                }
                _ => Reaction::Other,
            };
            return Ok(Outcome {
                reaction,
                send: Vec::new(),
            });
        }
        // Not a command type: the only other frame this procedure defines is
        // the return information, a monitor-direction process ASDU.
        match return_info(asdu, self.sizes)? {
            Some((ioa, info)) => Ok(Outcome {
                reaction: Reaction::Returned { ioa, info },
                send: Vec::new(),
            }),
            None => Ok(other()),
        }
    }

    /// The controlling station's handling of an `ACTCON`, select or execute
    /// alike, for [`CommandTransmission::on_response`].
    fn on_activation_con(&mut self, command: &Command, negative: bool) -> Reaction {
        // The mirror's `S/E` is the command's own, so the frame says
        // which call it answers.
        if command.select() {
            if negative {
                // A refused select is no select at all: "the
                // Controlling station does not proceed with sending
                // the EXECUTE message" (5.4.19.1).
                self.awaiting.retain(|sent| sent.ioa != command.ioa);
                Reaction::Confirmed {
                    ioa: command.ioa,
                    select: true,
                    negative: true,
                }
            } else if let Some(index) = self
                .awaiting
                .iter()
                .position(|sent| sent.ioa == command.ioa)
            {
                // Only the select this station sent becomes
                // executable, and only if the mirror repeats it;
                // otherwise it is 5.4.19.1's "not correctly
                // mirrored" and the select is dropped.
                let sent = self.awaiting.remove(index);
                if sent.state_eq(command) {
                    self.selected.push(sent);
                    Reaction::Confirmed {
                        ioa: command.ioa,
                        select: true,
                        negative: false,
                    }
                } else {
                    Reaction::NotMirrored { ioa: command.ioa }
                }
            } else {
                // A confirmation that answers nothing this station
                // sent changes no state and is still reported.
                Reaction::Confirmed {
                    ioa: command.ioa,
                    select: true,
                    negative: false,
                }
            }
        } else {
            if negative {
                // A negative execute confirmation ends the run: the
                // command was not executed after all.
                self.running.retain(|running| running.ioa != command.ioa);
            }
            // A positive execute confirmation records nothing: the
            // run was recorded when the execute was sent, and a
            // confirmation that answers nothing this station sent
            // changes no state.
            Reaction::Confirmed {
                ioa: command.ioa,
                select: false,
                negative,
            }
        }
    }

    /// Drops every trace of `ioa`: a select in flight, a confirmed select and
    /// its deadline, and a running execute.
    fn forget(&mut self, ioa: u32) {
        self.awaiting.retain(|sent| sent.ioa != ioa);
        self.drop_select(ioa);
        self.running.retain(|running| running.ioa != ioa);
    }

    /// The controlled station's decision for one received ASDU, with the mirror
    /// it owes.
    ///
    /// A select is recorded and mirrored positively; an execute is mirrored
    /// positively and, where [`Termination`] uses an `ACTTERM` for the family,
    /// recorded as running. The termination is the caller's later call to
    /// [`CommandTransmission::terminate`], so a station whose execution takes
    /// time answers the confirmation first rather than holding it. A
    /// deactivation it can perform is mirrored with cause 9 and **changes no
    /// value** (Table 19: *"The value of the Object(s) does not change at all
    /// during this command procedure"*).
    ///
    /// **Every** refusal of TS 60870-5-604 Table 19 is an answer rather than an
    /// error or a silence:
    ///
    /// - a not-allowed command state, an execute that does not repeat its
    ///   select's element, an execute with no select to repeat, a select at a
    ///   station whose mode has no select procedure, and a second select of an
    ///   address already selected: `ACTCON` with `P/N = 1`;
    /// - a field the caller's [`Known`] does not know (type identification,
    ///   cause, common address or information object address): clause 7.2.3's
    ///   cause 44, 45, 46 or 47 with `P/N = 1`;
    /// - a command of the other [`CommandSet`]: cause 44, reported as
    ///   [`Reaction::WrongCommandSet`];
    /// - a deactivation the station cannot perform (no select procedure, or no
    ///   deactivation for the type), or one that does not repeat the select it
    ///   claims to stop: cause 45; a deactivation with no select to stop: a
    ///   negative `DEACTCON` ([`Reaction::NothingToDeactivate`]);
    /// - a **command addressed to the broadcast CASDU**: cause 46 whatever
    ///   [`Known`] says, because no command type may be broadcast (TS
    ///   60870-5-604 5.4.10.10). A non-command type at that address stays
    ///   `Reaction::Other`, as it is at the station's own address.
    ///
    /// No refusal is recorded: a refused frame leaves no select, no run and no
    /// state of any kind behind. A mismatched execute does spend the select it
    /// failed to match.
    ///
    /// A received mirror (`P/N = 1` with cause 44 to 47) is discarded, never
    /// mirrored back. Every answer echoes the received frame's originator
    /// address and test bit (cl.7.2.3) and carries the station's own common
    /// address.
    ///
    /// # Errors
    ///
    /// [`CtError::WrongRole`] on the controlling role, and [`CtError::Layout`]
    /// (or the ASDU error it wraps) when `asdu` cannot be parsed or an answer
    /// cannot be encoded.
    pub fn on_request(&mut self, asdu: &[u8], known: &Known) -> Result<Outcome, CtError> {
        if self.role != Role::Controlled {
            return Err(CtError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        // A command is never broadcast (TS 60870-5-604 5.4.10.10; see the
        // module doc). The check reads the header rather than the caller's
        // `Known`, so it holds for a station whose profile says
        // `common_address: true`. It runs before the discard rule because a
        // broadcast command must be *answered*, not swallowed; a received
        // mirror is left to that rule so two stations cannot mirror each other.
        if header.common_address == self.sizes.broadcast_common_address()
            && !is_mirror(&header)
            && Family::of_type(header.type_id).is_some()
        {
            return self.refuse_frame(&header, asdu, Unspecified::CommonAddress);
        }
        if let Some(reason) = discard_reason(&header, known) {
            // In the control direction clause 7.2.3 mirrors an unknown field
            // with its cause 44 to 47 and never discards it. The only ASDU this
            // method discards is a mirror a peer sent, which must not be
            // mirrored back.
            if let Discard::Unspecified(which) = reason {
                return self.refuse_frame(&header, asdu, which);
            }
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        let Some((_, set)) = Family::of_type(header.type_id) else {
            return Ok(other());
        };
        if set != self.set {
            // The peer is owed an answer: a type outside the station's set is
            // one it does not implement, so cl.7.2.3's cause-44 mirror.
            let refused = self.refuse_frame(&header, asdu, Unspecified::TypeIdentification)?;
            let ioa = match refused.reaction {
                Reaction::Refused { ioa, .. } => ioa,
                _ => 0,
            };
            return Ok(Outcome {
                reaction: Reaction::WrongCommandSet {
                    ioa,
                    type_id: header.type_id,
                    set: self.set,
                },
                send: refused.send,
            });
        }
        let Some(command) = decode(asdu, self.sizes)? else {
            return Ok(other());
        };
        if let (true, Some(time)) = (
            header.cause == CAUSE_ACTIVATION && self.too_late(&command),
            command.time,
        ) {
            // 104 cl.8: no ACTCON, positive or negative, and no action.
            return Ok(Outcome {
                reaction: Reaction::TooLate {
                    ioa: command.ioa,
                    time,
                },
                send: Vec::new(),
            });
        }
        match header.cause {
            Cause::Activation => self.on_activation(command, &header),
            Cause::Deactivation => self.on_deactivation(&command, &header),
            // Figures 64–70 list only <6> and <8> in the control direction, so
            // any other cause is unknown for these types and clause 7.2.3's
            // cause-45 mirror is the answer.
            _ => self.refuse_with(&command, &header, Unspecified::CauseOfTransmission),
        }
    }

    /// The controlled station's answer to a cause-6 (`act`) command, select
    /// or execute, for [`CommandTransmission::on_request`].
    fn on_activation(&mut self, command: Command, header: &Header) -> Result<Outcome, CtError> {
        let select = command.select();
        if select && !self.mode.requires_select() {
            // The station has no select procedure: TS 60870-5-604
            // 5.4.19.30's ACTCONneg, not silence and not an Err. The
            // peer is owed an answer whatever this station's mode is.
            return self.refuse_negative(&command, header);
        }
        if !command.is_command_state() {
            // TS 60870-5-604 Table 19: "The controlled station does not
            // accept and responds with a P/N=1 if a not allowed command
            // (e.g. DCO=0 or 3; RCO=0 or 3) is received".
            return self.refuse_negative(&command, header);
        }
        if select {
            if self.is_selected(command.ioa) {
                // A second select of an object already selected is
                // refused with the same negative ACTCON.
                return self.refuse_negative(&command, header);
            }
            self.selected.push(command);
            if let Some(deadline) = self
                .clock
                .zip(self.select_timeout)
                .and_then(|(clock, timeout)| clock.checked_add(timeout))
            {
                self.deadlines.push((command.ioa, deadline));
            }
            return self.mirror(&command, header, true, false, CAUSE_ACTIVATION_CON);
        }
        match self
            .selected
            .iter()
            .find(|selected| selected.ioa == command.ioa)
            .copied()
        {
            Some(selected) => {
                // The select is spent either way: a matching execute
                // consumes it and runs, a mismatched one is refused and
                // the select-and-execute procedure ends there.
                self.drop_select(command.ioa);
                if !selected.state_eq(&command) {
                    return self.mirror(&command, header, false, true, CAUSE_ACTIVATION_CON);
                }
                self.start(command, header)
            }
            // A direct-execute station honours the execute. A
            // select-and-execute station refuses it, because the
            // information it must repeat is not there, except for a
            // family with no `S/E` bit, which has nothing to repeat.
            None => {
                if self.mode.requires_select() && command.value.supports_select() {
                    self.mirror(&command, header, false, true, CAUSE_ACTIVATION_CON)
                } else {
                    self.start(command, header)
                }
            }
        }
    }

    /// The controlled station's answer to a cause-8 (`deact`) command, for
    /// [`CommandTransmission::on_request`].
    fn on_deactivation(&mut self, command: &Command, header: &Header) -> Result<Outcome, CtError> {
        // 5-101 cl.7.4.7: "DEACT, DEACTCON is only used in case of a
        // select and execute function." A station without the function,
        // or a type whose figure has no cause 8, answers clause 7.2.3's
        // cause-45 mirror instead of confirming a deactivation it did
        // not perform.
        if !self.mode.requires_select() || !command.family().has_deactivation(command.set()) {
            return self.refuse_with(command, header, Unspecified::CauseOfTransmission);
        }
        // The deactivation is defined here but there is no select to
        // stop: a negative DEACTCON, which changes nothing.
        let Some(selected) = self
            .selected
            .iter()
            .find(|selected| selected.ioa == command.ioa)
            .copied()
        else {
            return Ok(Outcome {
                reaction: Reaction::NothingToDeactivate { ioa: command.ioa },
                send: vec![frame(
                    command,
                    CAUSE_DEACTIVATION_CON,
                    true,
                    header.test,
                    self.ca,
                    header.originator,
                    self.sizes,
                )?],
            });
        };
        // TS 60870-5-604 5.4.19.10: "The Controlling station sends the
        // same Command message with COT=8 … and S/E=1 (SELECT)". A
        // DEACT with another type identification or element is not that
        // message, so it gets the same cause-45 mirror and the select
        // stays outstanding. `state_eq` leaves out the `S/E` bit
        // (cl.7.4.7: "S/E of the qualifier of command QOC is irrelevant
        // in ASDUs with causes of transmission DEACT and DEACTCON").
        if selected.type_id() != command.type_id() || !selected.state_eq(command) {
            return self.refuse_with(command, header, Unspecified::CauseOfTransmission);
        }
        self.drop_select(command.ioa);
        Ok(Outcome {
            reaction: Reaction::Deactivated { ioa: command.ioa },
            send: vec![deactivation_confirmation_with(
                command,
                self.ca,
                header.originator,
                header.test,
                self.sizes,
            )?],
        })
    }

    /// The controlled station's refusal of a command whose object it will not
    /// control: TS 60870-5-604 5.4.19.30/.50's *"not controllable or not
    /// existing Information object"*. Nothing enters the state.
    ///
    /// The answer follows the **request's cause**: a cause-6 (`act`) frame is
    /// mirrored with cause 7 and `P/N = 1` (the `ACTCONneg`), while a cause-8
    /// (`deact`) frame, or one whose cause these types do not use in the control
    /// direction, gets clause 7.2.3's cause-45 mirror. A cause-7 answer to a
    /// deactivation would confirm an activation that was never requested,
    /// which figure 64 does not define.
    ///
    /// This is the caller's hook: the crate has no process image, so which
    /// information object addresses exist and what a command means for them is
    /// project data. A caller that knows an object is not controllable calls
    /// this instead of [`CommandTransmission::on_request`] for that frame. A
    /// caller whose [`Known`] already answers *no* needs nothing more, because
    /// `on_request` mirrors clause 7.2.3's causes by itself. The mirror echoes
    /// the received frame's originator address and test bit.
    ///
    /// # Errors
    ///
    /// [`CtError::WrongRole`] on the controlling role, and [`CtError::Layout`]
    /// (or the ASDU error it wraps) when `asdu` cannot be parsed or the mirror
    /// cannot be encoded.
    pub fn refuse(&self, asdu: &[u8]) -> Result<Outcome, CtError> {
        if self.role != Role::Controlled {
            return Err(CtError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        let Some(command) = decode(asdu, self.sizes)? else {
            return Ok(other());
        };
        match header.cause {
            // 5.4.19.30/.50's ACTCONneg: cause 7, P/N = 1, the received `S/E`.
            Cause::Activation => self.refuse_negative(&command, &header),
            // A deactivation, or any cause outside <6>/<8> (which figure 64
            // does not list in the control direction), is refused with clause
            // 7.2.3's cause-45 mirror, the same answer `on_request` gives a
            // DEACT it cannot perform.
            _ => self.refuse_with(&command, &header, Unspecified::CauseOfTransmission),
        }
    }

    /// The controlled station's termination of the execute running for `ioa`:
    /// the stored command mirrored with cause 10 and `P/N` as given, or
    /// [`CtError::NotRunning`] when no execute of that address is running. The
    /// mirror echoes the originator address and test bit the execute arrived
    /// with.
    ///
    /// The negative form is TS 60870-5-604 5.4.19.40/.50's alternative: *"first
    /// accept the command with a Positive ACTCON and then send a Negative
    /// Termination"*. [`CtError::TerminationNotUsed`] is the station's own
    /// [`Termination`] choosing "not used" for a family whose `ACTTERM` is
    /// optional.
    ///
    /// # Errors
    ///
    /// [`CtError::WrongRole`] on the controlling role, [`CtError::NotRunning`],
    /// [`CtError::TerminationNotUsed`], and [`CtError::Layout`] when the frame
    /// cannot be encoded.
    pub fn terminate(&mut self, ioa: u32, negative: bool) -> Result<Vec<u8>, CtError> {
        if self.role != Role::Controlled {
            return Err(CtError::WrongRole);
        }
        let index = self
            .running
            .iter()
            .position(|running| running.ioa == ioa)
            .ok_or(CtError::NotRunning { ioa })?;
        let command = *self.running.get(index).ok_or(CtError::NotRunning { ioa })?;
        if !self.termination.uses(command.value.family()) {
            return Err(CtError::TerminationNotUsed { ioa });
        }
        self.running.remove(index);
        let (originator, test) = self.take_reply_to(ioa);
        termination_with(&command, negative, self.ca, originator, test, self.sizes)
    }

    /// The controlled station's whole answer to a positive execute: the mirror
    /// and, where [`Termination`] uses an `ACTTERM` for the family, the run
    /// recorded together with the addressing the `ACTTERM` will have to echo.
    ///
    /// An execute for an object whose earlier execute still awaits its `ACTTERM`
    /// is refused: TS 60870-5-604 5.4.19.20 owes each execute *"the previous
    /// Command message with COT=10"*, and 5.4.19.50 answers a command the object
    /// cannot take with *"COT=7, `C_SC/DC/SE/RC_ACTCONneg`"*.
    fn start(&mut self, command: Command, header: &Header) -> Result<Outcome, CtError> {
        if self.termination.uses(command.value.family()) {
            if self.is_running(command.ioa) {
                return self.refuse_negative(&command, header);
            }
            self.running.push(command);
            self.reply_to.retain(|(ioa, _, _)| *ioa != command.ioa);
            self.reply_to
                .push((command.ioa, header.originator, header.test));
        }
        self.mirror(&command, header, false, false, CAUSE_ACTIVATION_CON)
    }

    /// Removes and returns the originator address and test bit the execute of
    /// `ioa` arrived with, to echo in its `ACTTERM`; without a record, the
    /// station's own originator and `T = 0`.
    fn take_reply_to(&mut self, ioa: u32) -> (u8, bool) {
        match self
            .reply_to
            .iter()
            .position(|(address, _, _)| *address == ioa)
        {
            Some(index) => {
                let (_, originator, test) = self.reply_to.remove(index);
                (originator, test)
            }
            None => (self.org, false),
        }
    }

    /// The controlled station's negative `ACTCON` for `command`: the same ASDU
    /// with cause 7 and `P/N = 1`, as TS 60870-5-604 5.4.19.30/.50 ask.
    fn refuse_negative(&self, command: &Command, header: &Header) -> Result<Outcome, CtError> {
        self.mirror(
            command,
            header,
            command.select(),
            true,
            CAUSE_ACTIVATION_CON,
        )
    }

    /// Clause 7.2.3's mirror of `command` for a field the station does not know:
    /// the same ASDU with `P/N = 1` and the field's cause (44–47).
    fn refuse_with(
        &self,
        command: &Command,
        header: &Header,
        which: Unspecified,
    ) -> Result<Outcome, CtError> {
        self.mirror(command, header, command.select(), true, which.cause())
    }

    /// Clause 7.2.3's mirror of a received frame the station will not serve for
    /// one of its four *undefined* classes: the type identification, the cause,
    /// the common address (the broadcast address included) or an information
    /// object address. The answer is the received ASDU with `P/N = 1` and the
    /// class's cause 44–47, the station's own common address, and the answered
    /// frame's originator address and test bit.
    ///
    /// A frame this crate can decode as a command is *rebuilt* through
    /// [`frame`], which writes every field it holds and drops the reserved bits
    /// the clause fixes to zero. A frame it cannot decode (an unknown type
    /// identification has no layout to rebuild from) is *copied* octet for
    /// octet behind the header, which is [`crate::asdu::mirror_reply`]'s rule
    /// for exactly that case.
    fn refuse_frame(
        &self,
        header: &Header,
        asdu: &[u8],
        which: Unspecified,
    ) -> Result<Outcome, CtError> {
        if let Some(command) = decode(asdu, self.sizes)? {
            return self.refuse_with(&command, header, which);
        }
        let objects = asdu.get(self.sizes.header_len()..).unwrap_or(&[]);
        Ok(Outcome {
            reaction: Reaction::Refused {
                ioa: crate::asdu::read_ioa_with(objects, self.sizes).unwrap_or(0),
                cause: which.cause(),
            },
            send: vec![mirror_frame(header, asdu, which, self.ca, self.sizes)],
        })
    }

    /// The mirror of `command` with `cause` and `P/N` as given, as the whole
    /// answer, echoing the answered frame's originator address and test bit.
    fn mirror(
        &self,
        command: &Command,
        header: &Header,
        select: bool,
        negative: bool,
        cause: Cause,
    ) -> Result<Outcome, CtError> {
        Ok(Outcome {
            reaction: if cause == CAUSE_ACTIVATION_CON {
                Reaction::Confirmed {
                    ioa: command.ioa,
                    select,
                    negative,
                }
            } else {
                Reaction::Refused {
                    ioa: command.ioa,
                    cause,
                }
            },
            send: vec![frame(
                command,
                cause,
                negative,
                header.test,
                self.ca,
                header.originator,
                self.sizes,
            )?],
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

/// The information object address and the cause of a received return
/// information, or `None` when the ASDU is not one: a type outside
/// [`RETURN_TYPES`], a cause that is not 11, 12 or 3, or an ASDU that carries no
/// information object at all (5-101 clause 7.2.2's `N = 0`).
fn return_info(asdu: &[u8], sizes: AddressSizes) -> Result<Option<(u32, ReturnInfo)>, LayoutError> {
    let header = Header::parse_with(asdu, sizes)?;
    let Some(info) = ReturnInfo::from_cause(header.cause) else {
        return Ok(None);
    };
    if !is_return_type(header.type_id) || header.count == 0 {
        return Ok(None);
    }
    let objects = asdu.get(sizes.header_len()..).unwrap_or(&[]);
    Ok(Some((crate::asdu::read_ioa_with(objects, sizes)?, info)))
}
