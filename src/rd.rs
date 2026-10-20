//! The read command and data acquisition by polling: `C_RD_NA_1` `<102>`, the
//! one control-direction ASDU whose information object address *is* the object
//! it asks for.
//!
//! # The service (5-104 clause 7.2)
//!
//! 5-104 clause **7.2** (PDF page index 64, printed page 63) is headed *"Data
//! acquisition by polling (6.2 of IEC 60870-5-5)"*. It opens by noting that the
//! class 1 and class 2 user-data requests belong to the IEC 60870-5-2 link layer
//! and so do not exist in 104; data can still be read (requested), following
//! the lower part of figure 10 of IEC 60870-5-5.
//!
//! Its table has four rows: `A_RD_DATA.req` / `send` / `C_RD`, `A_RD_DATA.ind` /
//! `receive` / `C_RD`, then `A_M_DATA.req` / `send` / `M` and `A_M_DATA.ind` /
//! `receive` / `M`. `C_RD` is `C_RD_NA_1` (type 102) and `M` is any
//! monitor-direction ASDU of clause 7.3.1 the read may return. Figure 10 of
//! IEC 60870-5-5 is not in this repository, so this module cites the deferral
//! rather than reconstructing the figure.
//!
//! The same page continues: requesting data with cyclic requests is allowed
//! but should be avoided, since it loads the network with unnecessary
//! traffic. This warns against repeating a
//! *read request* on a cycle. It is not a rule about clause 7.3's cyclic data
//! transmission (cause `<1>`, [`crate::tx`]), and it is not a refusal: the
//! cycle is permitted. [`Read`] schedules nothing, reads no clock and keeps no
//! state, so repeating a read is the caller's choice.
//!
//! # The address is the object (5-101 clause 7.2.5)
//!
//! 5-101 clause **7.2.5** (PDF page index 44, printed page 43; figure 21 on the
//! same page) singles out `C_RD_NA_1` as the general exception: its information
//! object address points at an existing information object, which is sent back
//! in the monitor direction.
//!
//! The same page defines `<0>` as the irrelevant information object address, so
//! a read command at `<0>` names nothing. [`request`] and [`answer`] refuse it
//! ([`RdError::IrrelevantAddress`]), and a received command at `<0>` is mirrored
//! with cause 47 ([`refusal`], [`Read::on_request`]), the class for an address
//! "unknown (not defined) in the controlled station". The address class is the
//! last one in clause 7.2.3's table, so this applies only when the station's
//! [`Known`] profile accepts every earlier field; a command at `<0>` whose type
//! identification the station does not know gets the class-44 mirror. The same
//! page limits a system to 65536 different information object addresses; that
//! is a station property and this crate does not enforce it.
//!
//! # The command: one control-direction cause, no element
//!
//! Figure **74** (5-101 clause **7.3.4.3**, PDF page index 106, printed page
//! 105) is headed *"Single information object (SQ = 0)"* and defines the type as
//! `C_RD_NA_1 := CP{Data unit identifier,Information object address}` with the
//! cause list
//!
//! ```text
//! CAUSES OF TRANSMISSION used with TYPE IDENT 102 := C_RD_NA_1
//!   in control direction: <5>    := request
//!   in monitor direction: <44> … <47> := the four unknown-address replies
//! ```
//!
//! The whole payload is the three-octet information object address, and
//! [`CRdNa1`] has `LEN` 0. `<5>` is the type's only control-direction cause and
//! there is no `ACT`/`ACTCON`/`ACTTERM`, so [`Read::request`] takes no cause
//! argument and cannot build a frame the standard does not list for type 102.
//!
//! **104 does not mark the type `CON`, so a positive answer is not a mirror.**
//! 104 **Table 4** (index 52, printed page 51) prints `<102>` without the `CON`
//! mark that `<100>`, `<101>`, `<103>`, `<105>` and `<107>` carry, and the NOTE
//! under Tables 3 to 6 on that page says that only control-direction ASDUs
//! marked CON are confirmed services, which may come back mirrored in the
//! monitor direction with another cause of transmission. 5-101 **Table 11**
//! (index 33, printed page 32) does mark `<102>` `CON`. This crate follows 104
//! (the `confirmed: false` row for 102 in `src/asdu/types.rs`), so the positive
//! answer is the monitor ASDU of the addressed object.
//!
//! # The read procedure and the answer's type set (5-101 clause 7.4.14)
//!
//! 5-101 clause **7.4.14** (index 149, printed page 148), *"Read procedure"*,
//! draws figure **109**: `A_RD_DATA.req` → `C_RD_NA_1 <5> REQ` →
//! `A_RD_DATA.ind` (read the information object the address names), then
//! `A_M_DATA.req` → `M_ <5> REQ` → `A_M_DATA.ind` (the object that was read,
//! returned). Index 150 (printed page 149) describes the return: the controlled
//! station's application process hands the requested object to the
//! communication services as `A_M_DATA.req`, and they put it into the matching
//! monitor-direction ASDU and send it as an `M_PDU` with cause `<5>` REQ.
//!
//! So the command goes out as type 102 and a monitor ASDU of the addressed
//! object comes back, both with cause `<5>` (table 14, index 41, printed page
//! 40: *"`<5>` := request or requested"*).
//!
//! Index 150 then lists the `M_REQ` ASDUs a read may return in the monitor
//! direction:
//!
//! | or-pair | untagged | tagged alternative |
//! | --- | --- | --- |
//! | `<1>` / `<30>` | `M_SP_NA_1` | `M_SP_TB_1` |
//! | `<3>` / `<31>` | `M_DP_NA_1` | `M_DP_TB_1` |
//! | `<5>` / `<32>` | `M_ST_NA_1` | `M_ST_TB_1` |
//! | `<7>` / `<33>` | `M_BO_NA_1` | `M_BO_TB_1` |
//! | `<9>` / `<34>` | `M_ME_NA_1` | `M_ME_TD_1` |
//! | `<11>` / `<35>` | `M_ME_NB_1` | `M_ME_TE_1` |
//! | `<13>` / `<36>` | `M_ME_NC_1` | `M_ME_TF_1` |
//! | — | `<20>` `M_PS_NA_1` | — |
//! | — | `<21>` `M_ME_ND_1` | — |
//! | — | `<126>` `F_DR_TA_1` | — |
//!
//! **104 clause 9** (index 100, printed page 99) allows only the set
//! `<30>`–`<40>` for time-tagged ASDUs in 104. ([`crate::tx`] and
//! [`crate::ci`] enforce the same rule.) A
//! 104 station's tagged alternative is therefore `<30>`–`<36>`, never the
//! `CP24Time2a` forms `<2>`, `<4>`, `<6>`, `<8>`, `<10>`, `<12>` or `<14>` the
//! table's or-columns name ([`RdError::TagNotPermitted`]). [`is_returned`] is
//! the intersection of the list with clause 9's set: the nine untagged types of
//! [`RETURNED_UNTAGGED`] plus the seven tagged ones of [`RETURNED_TAGGED`].
//! `<37>`–`<40>` are inside clause 9's set but not on the list, so they are
//! [`RdError::NotReturnedType`]. `<126>` `F_DR_TA_1` belongs to file transfer
//! ([`crate::ft`]) and is not built here.
//!
//! # The untagged form is the usual answer (5-101 clause 7.4.2)
//!
//! 5-101 clause **7.4.2** (index 122, printed page 121), *"Selections from data
//! acquisition by polling"*, selects all of IEC 60870-5-5 6.2. Its class 1 and
//! class 2 paragraphs describe the link layer's poll, which 104 clause 7.2
//! excludes. What applies on TCP is the read-command paragraph: the read
//! command asks for individual information objects by their addresses, they
//! come back with cause `<5>` requested, and as a rule they come back without
//! a time tag.
//!
//! *"As a rule"* makes the untagged form the usual answer and the tagged form of
//! index 150's list the alternative. Which form goes out is the application's
//! choice, and [`is_returned`] accepts both.
//!
//! # The refusal is a mirror
//!
//! Index 150's closing sentence: when a field of the read command's data unit
//! identifier (the variable structure qualifier aside) or its information
//! object address is unknown (not defined) in the controlled station, the
//! station sends `C_RD_NA_1` back mirrored with cause `<44>`–`<47>`, and it
//! refers to 7.2.3.1 for this.
//!
//! This PDF prints no numbered subsection 7.2.3.1. The mirror rule it does print
//! is 5-101 clause **7.2.3** (index 42, printed page 41): the received ASDU comes
//! back with `P/N = 1` and the class's cause (44 for the type identification, 45
//! for the cause of transmission, 46 for the common address of ASDU, 47 for the
//! information object address). This module builds it with
//! [`crate::asdu::mirror_frame`], which copies the received object area octet
//! for octet. A positive answer is never that mirror.
//!
//! # A read command cannot be broadcast
//!
//! 5-101 clause **7.2.4** (index 43, printed page 42) restricts the common
//! address FF or FFFF in the control direction to types `<100>`, `<101>`,
//! `<103>` and `<105>`. Type 102 is not on the list, so [`request`] and
//! [`Read::request`] refuse the broadcast address
//! ([`RdError::BroadcastAddress`]). [`answer`] refuses both a broadcast command
//! and an answer *at* the broadcast address, because the same clause requires
//! a broadcast request to be answered in the monitor direction by ASDUs that
//! carry the station's own defined common address.
//!
//! A broadcast read command that arrives anyway gets the class-46 mirror,
//! whatever the caller's [`Known`] says: TS 60870-5-604 clause **5.4.10.10**
//! (PDF page index 54) has the controlled station refuse any other type sent to
//! the broadcast CASDU by mirroring it with P/N = 1 (negative), using COT = 46
//! when it supports that cause. [`Read::on_request`] and
//! [`refusal`] both apply this before the discard rule, as [`crate::ct`] and
//! [`crate::pm`] do for their own command types.
//!
//! # The answer echoes the command's originator address and test bit
//!
//! 5-101 clause **7.2.3** (index 38, printed page 37): the source of a
//! command-direction ASDU should fill in its originator address, and the
//! controlled station should return that same originator address in its
//! monitor-direction response. The `M` ASDU of clause 7.4.14 and the 44–47 mirror
//! are both such responses, so [`answer`] takes the received command and copies
//! its originator address, and its `T` bit with it.
//!
//! A [`DataSource`] frame that does not carry the command's originator address
//! and `T` bit, whose common address is not the station's own, that is a
//! negative confirmation, or that carries anything but the one requested object
//! is a typed error ([`RdError::OriginatorMismatch`], [`RdError::TestMismatch`],
//! [`RdError::WrongCommonAddress`], [`RdError::NegativeAnswer`],
//! [`RdError::WrongObjectCount`]) instead of a frame on the wire.
//!
//! # What is left to the caller
//!
//! * **Whether the station uses the function.** 104 clause **9.6** (index 108,
//!   printed page 107) lists *"Read procedure"* as a station-specific
//!   parameter; it is the first argument of the [`Read`] constructors. A station
//!   that does not use it refuses to build the request and answers a received
//!   one with the cause-44 mirror (unknown type identification), so the peer is
//!   not left waiting.
//! * **Whether a read is repeated on a cycle.** The crate schedules nothing;
//!   clause 7.2's warning names the cost.
//! * **The process image behind the returned object**, reached through
//!   [`DataSource`]: the caller owns the typed value and the address, as
//!   [`crate::asdu::encode_asdu`] takes them.
//! * **Untagged or `<30>`–`<36>`-tagged answer**: both are legal here.
//! * **The station's [`Known`] profile** for a received frame, from which the
//!   discard rule and the mirror decision are made.
//!
//! # Example
//!
//! ```
//! use iec104::asdu::{Cause, Header, Known, LayoutObject, MMeNa1, Nva, Qds, TypeId};
//! use iec104::rd::{answer, is_returned, request, DataSource, Read, Reaction};
//!
//! // The controlling station asks for the object at address 0x3010.
//! let command = request(0x3010, 12, 0).unwrap();
//! assert_eq!(command.len(), 9);
//! assert_eq!(Header::parse(&command).unwrap().cause, Cause::Request);
//! assert_eq!(Header::parse(&command).unwrap().type_id, TypeId::CRdNa1);
//!
//! // The controlled station's answer is a *different* type at the same
//! // address, with the same cause, echoing the request's originator.
//! let value = MMeNa1 {
//!     nva: Nva { value: 0x2000 },
//!     qds: Qds::default(),
//! };
//! let reply = answer(&LayoutObject { ioa: 0x3010, value }, &command, 12).unwrap();
//! let header = Header::parse(&reply).unwrap();
//! assert_eq!(header.type_id, TypeId::MMeNa1);
//! assert_eq!(header.cause, Cause::Request);
//! assert!(is_returned(header.type_id));
//!
//! // The requesting side classifies the object it asked for.
//! let asking = Read::controlling(true, 12, 0);
//! assert_eq!(
//!     asking.on_response(&reply, &Known::EVERYTHING).unwrap().reaction,
//!     Reaction::Answered { type_id: TypeId::MMeNa1, ioa: 0x3010 }
//! );
//!
//! // A station with no data for the address mirrors the command back with
//! // cause 47 and P/N = 1 (5-101 cl.7.4.14).
//! struct Empty;
//! impl DataSource for Empty {
//!     fn object(&self, _ioa: u32) -> Option<Vec<u8>> {
//!         None
//!     }
//! }
//! let serving = Read::controlled(true, 12, 0);
//! let outcome = serving
//!     .on_request(&command, &Known::EVERYTHING, &Empty)
//!     .unwrap();
//! assert_eq!(
//!     outcome.reaction,
//!     Reaction::Refused { ioa: 0x3010, cause: Cause::UnknownInformationObjectAddress }
//! );
//! assert_eq!(outcome.send.len(), 1);
//! ```

use crate::asdu::{
    AddressSizes, AsduError, AsduLayout, BodyReader, CRdNa1, Cause, Discard, Header, Known,
    LayoutError, LayoutObject, TypeId, decode_asdu_with, discard_reason, element_len,
    encode_asdu_with, is_mirror, mirror_frame,
};

/// The type identification of the read command: 5-101 clause 7.3.4.3, figure
/// 74 (PDF page index 106, printed page 105), whose type-identification bit row
/// reads `0 1 1 0 0 1 1 0` = 102.
pub const TYPE_ID: TypeId = TypeId::CRdNa1;

/// `<5>` `request or requested`, the type's only control-direction cause.
///
/// 5-101 table 14 (index 41, printed page 40) and figure 74. It is also the
/// cause of the monitor answer, which has a different type identification
/// (clause 7.4.14, index 149/150).
pub const CAUSE_REQUEST: Cause = Cause::Request;

/// The nine untagged monitor types a read may return.
///
/// 5-101 clause 7.4.14 (PDF page index 150, printed page 149), in the list's
/// own order: one per or-pair, plus `M_PS_NA_1` and `M_ME_ND_1`, which the
/// list names without an alternative.
///
/// They are the same nine types as [`crate::gi::INTERROGATED_TYPES`], but the
/// two constants come from different clauses and are kept separate, so a change
/// to one does not silently change the other.
pub const RETURNED_UNTAGGED: [TypeId; 9] = [
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

/// The seven `CP56Time2a` alternatives of index 150's list.
///
/// `<30>` `M_SP_TB_1` to `<36>` `M_ME_TF_1`: the part of 104 clause 9's
/// permitted set `<30>`–`<40>` (PDF page index 100, printed page 99) that the
/// read may return.
///
/// Clause 9 excludes the `CP24Time2a` forms `<2>`, `<4>`, `<6>`, `<8>`, `<10>`,
/// `<12>` and `<14>` the list's or-columns name ([`RdError::TagNotPermitted`]).
/// `<37>`–`<40>` are inside the permitted set but absent from index 150's list,
/// and are [`RdError::NotReturnedType`].
pub const RETURNED_TAGGED: [TypeId; 7] = [
    TypeId::MSpTb1,
    TypeId::MDpTb1,
    TypeId::MStTb1,
    TypeId::MBoTb1,
    TypeId::MMeTd1,
    TypeId::MMeTe1,
    TypeId::MMeTf1,
];

/// Every type identification a read may be answered with.
///
/// [`RETURNED_UNTAGGED`] then [`RETURNED_TAGGED`]. The untagged form comes
/// first because it is the usual one (5-101 clause 7.4.2: requested objects
/// come back without a time tag as a rule).
///
/// `<126>` `F_DR_TA_1`, the list's last line, is not here: it is a
/// file-transfer type of 5-101 clause 7.3.6, handled by [`crate::ft`].
pub const RETURNED_TYPES: [TypeId; 16] = [
    TypeId::MSpNa1,
    TypeId::MDpNa1,
    TypeId::MStNa1,
    TypeId::MBoNa1,
    TypeId::MMeNa1,
    TypeId::MMeNb1,
    TypeId::MMeNc1,
    TypeId::MPsNa1,
    TypeId::MMeNd1,
    TypeId::MSpTb1,
    TypeId::MDpTb1,
    TypeId::MStTb1,
    TypeId::MBoTb1,
    TypeId::MMeTd1,
    TypeId::MMeTe1,
    TypeId::MMeTf1,
];

/// Whether `type_id` is on index 150's returned list as 104 clause 9 narrows
/// it: the untagged nine or the `<30>`–`<36>` tagged seven.
///
/// The test is over the type's **wire octet**, so an unnamed [`TypeId::Other`]
/// of a returned number answers exactly as the named variant does, and a
/// `CP24Time2a` twin such as `<2>` answers `false` even though index 150's
/// or-column prints it.
#[must_use]
pub fn is_returned(type_id: TypeId) -> bool {
    let raw = type_id.to_u8();
    RETURNED_TYPES
        .into_iter()
        .any(|returned| returned.to_u8() == raw)
}

/// Whether `type_id` is a `CP24Time2a` monitor form.
///
/// That is the first alternative of each or-pair of index 150's list (`<2>`,
/// `<4>`, `<6>`, `<8>`, `<10>`, `<12>`, `<14>`), which 104 clause 9 (index
/// 100) excludes from a 104 station's answers.
///
/// As in [`is_returned`], the test is over the type's **wire octet**, so an
/// unnamed [`TypeId::Other`] of a `CP24Time2a` form is [`RdError::TagNotPermitted`]
/// rather than [`RdError::NotReturnedType`].
#[must_use]
pub const fn is_cp24_form(type_id: TypeId) -> bool {
    matches!(type_id.to_u8(), 2 | 4 | 6 | 8 | 10 | 12 | 14)
}

/// The controlled station's own process image, asked for **one** object by
/// address.
///
/// The one-object counterpart of [`crate::gi::DataSource`]: an interrogation
/// answers with the objects of a scope, a read with the single object the
/// command addresses. The implementation builds that ASDU with cause `<5>`, as
/// [`answer`] does, and returns `None` when this station has no data for the
/// address. That is clause 7.4.14's *"unknown (not defined) in the controlled
/// station"* for the address class, and is mirrored with cause 47.
///
/// [`Read::on_request`] checks the returned frame: its type identification must
/// be one of [`RETURNED_TYPES`], its cause `<5>`, its information object address
/// the one asked for, its originator address and `T` bit the command's, its
/// common address the station's own, and it must be a positive frame of one
/// object (`P/N = 0`, `SQ = 0`, `N = 1`). Anything else is a typed error rather
/// than a frame on the wire.
pub trait DataSource {
    /// The monitor ASDU answering a read of `ioa`, or `None` when this station
    /// has no data for that address.
    fn object(&self, ioa: u32) -> Option<Vec<u8>>;
}

/// Builds one read command.
///
/// The `C_RD_NA_1` of 5-101 clause 7.3.4.3 (figure 74, page index 106),
/// `SQ = 0`, `N = 1`, cause `<5>` and no element. The whole payload is `ioa`, the address of the object to be read (clause 7.2.5, page
/// index 44).
///
/// Refused:
///
/// * an address of `<0>`, which clause 7.2.5 defines as irrelevant and which
///   therefore names nothing to read ([`RdError::IrrelevantAddress`]);
/// * the common address `FF`/`FFFF`: clause 7.2.4 restricts broadcast to
///   `<100>`, `<101>`, `<103>` and `<105>`, and type 102 is not on the list
///   ([`RdError::BroadcastAddress`]).
///
/// Figure 74 lists one control-direction cause, so the cause is not an
/// argument. The test bit is written zero (a normal read is not a test frame);
/// the answer to a `T = 1` command echoes that bit.
///
/// # Errors
///
/// [`RdError::IrrelevantAddress`] for `ioa` `<0>`,
/// [`RdError::BroadcastAddress`] for the broadcast common address, and
/// [`RdError::Layout`] when the frame cannot be encoded.
pub fn request(ioa: u32, common_address: u16, originator: u8) -> Result<Vec<u8>, RdError> {
    request_with(ioa, common_address, originator, AddressSizes::CONVENTIONAL)
}

/// [`request`] in the address sizes `sizes` fixes; the broadcast address is
/// that profile's.
///
/// # Errors
///
/// As [`request`].
pub fn request_with(
    ioa: u32,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, RdError> {
    if ioa == 0 {
        return Err(RdError::IrrelevantAddress { ioa });
    }
    if common_address == sizes.broadcast_common_address() {
        return Err(RdError::BroadcastAddress { common_address });
    }
    let header = Header {
        type_id: TYPE_ID,
        sequence: false,
        count: 1,
        cause: CAUSE_REQUEST,
        negative: false,
        test: false,
        originator,
        common_address,
    };
    Ok(encode_asdu_with(
        &header,
        &[LayoutObject { ioa, value: CRdNa1 }],
        sizes,
    )?)
}

/// The broadcast address of 5-101 clause 7.2.4 for a two-octet common address.
///
/// Index 43, printed page 42. The clause permits broadcast only for `<100>`,
/// `<101>`, `<103>` and `<105>`; type 102 is not on the list.
#[deprecated(
    note = "the broadcast address depends on the common-address width: use AddressSizes::broadcast_common_address"
)]
pub const BROADCAST_CA: u16 = 0xFFFF;

/// Builds the controlled station's answer to a received read command: the
/// monitor ASDU of the requested object, with cause `<5>`.
///
/// The answer has a different type identification from the command (clause
/// 7.4.14, figure 109: `C_RD_NA_1 <5> REQ` out, `M_ <5> REQ` back). It is not a
/// mirror because 104 does not mark type 102 `CON` (its Table 4, index 52,
/// against 5-101's Table 11, index 33).
///
/// `command` is the received `C_RD_NA_1` itself:
///
/// * its information object address must be the address of `object`
///   ([`RdError::AddressMismatch`]), and it must carry an object at all
///   ([`RdError::NoObjectInCommand`] for `N = 0`);
/// * its type identification must be [`TYPE_ID`] and its cause `<5>`
///   ([`RdError::NotThisType`], [`RdError::CauseNotListed`]);
/// * its common address must not be the broadcast address
///   ([`RdError::BroadcastAddress`]); a broadcast read that arrives is refused
///   with cause 46 instead ([`Read::on_request`]);
/// * its originator address and `T` bit are echoed on the answer (5-101 clause
///   7.2.3, index 38: the controlled station should return the originator
///   address in its monitor-direction response).
///
/// `object`'s type must be one of [`RETURNED_TYPES`] and its address must not
/// be `<0>` ([`RdError::IrrelevantAddress`], clause 7.2.5). `common_address` is
/// the station's own, since clause 7.2.4 answers with the station's own
/// defined common address; the broadcast value is refused
/// ([`RdError::BroadcastAddress`]).
///
/// # Errors
///
/// The [`RdError`] variants named above, and [`RdError::Layout`] when
/// `command` cannot be parsed or the answer cannot be encoded.
pub fn answer<A: AsduLayout>(
    object: &LayoutObject<A>,
    command: &[u8],
    common_address: u16,
) -> Result<Vec<u8>, RdError> {
    answer_with(object, command, common_address, AddressSizes::CONVENTIONAL)
}

/// [`answer`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`answer`].
pub fn answer_with<A: AsduLayout>(
    object: &LayoutObject<A>,
    command: &[u8],
    common_address: u16,
    sizes: AddressSizes,
) -> Result<Vec<u8>, RdError> {
    let given = Header::parse_with(command, sizes)?;
    if given.type_id != TYPE_ID {
        return Err(RdError::NotThisType {
            type_id: given.type_id,
        });
    }
    if given.cause != CAUSE_REQUEST {
        return Err(RdError::CauseNotListed { cause: given.cause });
    }
    if given.common_address == sizes.broadcast_common_address() {
        return Err(RdError::BroadcastAddress {
            common_address: given.common_address,
        });
    }
    if common_address == sizes.broadcast_common_address() {
        // The answer carries the station's own address (cl.7.2.4: the
        // station's own defined common address), never the broadcast one.
        return Err(RdError::BroadcastAddress { common_address });
    }
    if object.ioa == 0 {
        return Err(RdError::IrrelevantAddress { ioa: object.ioa });
    }
    if !is_returned(A::TYPE_ID) {
        return Err(if is_cp24_form(A::TYPE_ID) {
            RdError::TagNotPermitted {
                type_id: A::TYPE_ID,
            }
        } else {
            RdError::NotReturnedType {
                type_id: A::TYPE_ID,
            }
        });
    }
    let asked = command_ioa(command, sizes)?.ok_or(RdError::NoObjectInCommand)?;
    if asked != object.ioa {
        return Err(RdError::AddressMismatch {
            asked,
            got: object.ioa,
        });
    }
    let header = Header {
        type_id: A::TYPE_ID,
        sequence: false,
        count: 1,
        cause: CAUSE_REQUEST,
        negative: false,
        test: given.test,
        originator: given.originator,
        common_address,
    };
    Ok(encode_asdu_with(
        &header,
        std::slice::from_ref(object),
        sizes,
    )?)
}

/// The 44–47 mirror of a received read command.
///
/// Clause 7.4.14's return of `C_RD_NA_1` mirrored with cause `<44>`–`<47>`
/// (index 150, printed page 149), with `P/N = 1` and the received object area
/// copied octet for octet ([`crate::asdu::mirror_frame`]).
///
/// `Ok(None)` means the station knows every field [`Known`] asks about, so there
/// is nothing to refuse and the caller answers with the object ([`answer`]).
/// Otherwise the mirror carries the class [`crate::asdu::classify`] reports, in
/// the clause's table order: 44, 45, 46, 47.
///
/// Two rules depend on the field rather than on the profile:
///
/// * a **broadcast** common address is never legal on a read command, so the
///   reply is the class-46 mirror whatever `known` says (TS 60870-5-604
///   5.4.10.10, quoted on [`Read::on_request`]). This rule is checked before
///   the profile, because it is a property of the header;
/// * the irrelevant information object address `<0>` (5-101 cl.7.2.5, index
///   44) holds no object, so the reply is the class-47 mirror rather than
///   `Ok(None)`. This rule decides the address class only, so it is checked
///   after the profile, in the clause's table order. A command at `<0>` whose
///   type identification the station does not know gets the class-44 mirror,
///   as in [`Read::on_request`].
///
/// `common_address` is the station's own, not the received frame's: clause
/// 7.2.4 (index 43) answers with the station's own defined common address.
///
/// A frame that is not a read command is [`RdError::NotThisType`] (another
/// type) or [`RdError::CauseNotListed`] (type 102 with a cause other than
/// `<5>`, which figure 74 does not list).
///
/// # Errors
///
/// [`RdError::NotThisType`] and [`RdError::CauseNotListed`] as above, and
/// [`RdError::Layout`] when the header or the command's object cannot be
/// parsed.
pub fn refusal(
    asdu: &[u8],
    known: &Known,
    common_address: u16,
) -> Result<Option<Vec<u8>>, RdError> {
    refusal_with(asdu, known, common_address, AddressSizes::CONVENTIONAL)
}

/// [`refusal`] in the address sizes `sizes` fixes; the broadcast address is
/// that profile's.
///
/// # Errors
///
/// As [`refusal`].
pub fn refusal_with(
    asdu: &[u8],
    known: &Known,
    common_address: u16,
    sizes: AddressSizes,
) -> Result<Option<Vec<u8>>, RdError> {
    let header = Header::parse_with(asdu, sizes)?;
    if header.type_id != TYPE_ID {
        return Err(RdError::NotThisType {
            type_id: header.type_id,
        });
    }
    if header.cause != CAUSE_REQUEST {
        return Err(RdError::CauseNotListed {
            cause: header.cause,
        });
    }
    // The frame is decoded as a read command before anything is mirrored: a
    // truncated object area is a typed error, not a malformed frame copied back.
    let ioa = command_ioa(asdu, sizes)?;
    // A read command is never broadcast: TS 60870-5-604 5.4.10.10 mirrors it
    // with cause 46 whatever `known` says, here as in `Read::on_request`.
    if header.common_address == sizes.broadcast_common_address() {
        return Ok(Some(mirror_frame(
            &header,
            asdu,
            crate::asdu::Unspecified::CommonAddress,
            common_address,
            sizes,
        )));
    }
    // Address `<0>` is the field's "irrelevant" value (5-101 cl.7.2.5), so no
    // object is held there: cause 47 rather than `Ok(None)`. It decides the
    // address class only, so it comes after the profile's classification, in
    // the clause's table order.
    if let Some(why) = crate::asdu::classify(known) {
        return Ok(Some(mirror_frame(
            &header,
            asdu,
            why,
            common_address,
            sizes,
        )));
    }
    if ioa == Some(0) {
        return Ok(Some(mirror_frame(
            &header,
            asdu,
            crate::asdu::Unspecified::InformationObjectAddress,
            common_address,
            sizes,
        )));
    }
    Ok(None)
}

/// What one frame of the read procedure means, from the point of view of the
/// station that received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// A read command arrived: type 102 with cause `<5>`, naming the object at
    /// `ioa` (figure 74; clause 7.4.14's `A_RD_DATA.ind`). A controlled station
    /// answers it with the object, or with the 44–47 mirror when the object is
    /// unknown.
    Requested {
        /// The information object address the command named.
        ioa: u32,
    },
    /// The requested object arrived: a monitor ASDU of a [`RETURNED_TYPES`]
    /// type with cause `<5>` at `ioa` (clause 7.4.14's `A_M_DATA.ind`). It is
    /// not a mirror, because 104 does not mark type 102 `CON`.
    Answered {
        /// The type identification the answer carried.
        type_id: TypeId,
        /// The information object address the answer carried.
        ioa: u32,
    },
    /// The 44–47 mirror of a read command arrived: the controlled station
    /// refused a field it does not know (clause 7.4.14, index 150). `cause` is
    /// the class the mirror carries, which names the field.
    Refused {
        /// The information object address the mirrored command named.
        ioa: u32,
        /// The class's cause: 44, 45, 46 or 47.
        cause: Cause,
    },
    /// Clause 7.2.3 says this ASDU is discarded and may be logged.
    /// A received mirror on the *controlled* side is this reaction rather than
    /// [`Reaction::Refused`], so two stations cannot mirror each other.
    Discard(Discard),
    /// Not this procedure: the cause is not `<5>` (nor a 44–47 mirror), or the
    /// type is not one this procedure's direction carries.
    Other,
}

/// What a received ASDU means, and what to send because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The classification of the received ASDU.
    pub reaction: Reaction,
    /// The ASDUs to send, in order. Empty on the requesting side and for every
    /// frame that is not a read command; otherwise the controlled station's one
    /// answer (the monitor object or the 44–47 mirror).
    pub send: Vec<Vec<u8>>,
}

/// What can go wrong in this layer, over and above the codec's own errors.
///
/// Every variant names a rule of the standard that the call would have broken.
/// A refusal the standard defines as a *frame* is not an error: the 44–47 mirror
/// of a read command is [`refusal`]'s `Ok(Some(..))` and
/// [`Reaction::Refused`], not a variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RdError {
    /// The entry point does not belong to this instance's role: `request` and
    /// `on_response` are the controlling station's, `on_request` and `answer`
    /// the controlled station's.
    WrongRole,
    /// The station does not use the read procedure: 104 clause 9.6's *"Read
    /// procedure"* checkbox (PDF page index 108, printed page 107) is not
    /// marked. [`Read::request`] and [`Read::answer`] refuse rather than send a
    /// frame the station was not configured to send ([`Read::on_request`]
    /// answers a received command with the cause-44 mirror instead).
    FunctionNotUsed,
    /// The frame is not a read command at all: its type identification is not
    /// [`TYPE_ID`].
    NotThisType {
        /// The type identification the frame carried.
        type_id: TypeId,
    },
    /// The frame's cause of transmission is not `<5> request`, the only
    /// control-direction cause figure 74 lists for this type (PDF page index
    /// 106).
    CauseNotListed {
        /// The cause the frame carried.
        cause: Cause,
    },
    /// The information object address is `<0>`, the field's *"irrelevant"*
    /// value (5-101 clause 7.2.5, index 44, figure 21). A read's address is its
    /// object, so `<0>` names nothing.
    IrrelevantAddress {
        /// The address offered.
        ioa: u32,
    },
    /// The common address is the broadcast address `FF`/`FFFF`, which 5-101
    /// clause 7.2.4 (index 43) restricts to types `<100>`, `<101>`, `<103>` and
    /// `<105>`, not type 102. Returned by [`request`], and by [`answer`] for a
    /// broadcast command or a broadcast `common_address`; a broadcast command
    /// that arrives gets the class-46 mirror instead ([`Read::on_request`]).
    BroadcastAddress {
        /// The common address offered.
        common_address: u16,
    },
    /// The read command carries no object (5-101 clause 7.2.2's `N = 0`). A
    /// read's information object address is the object it asks for (clause
    /// 7.2.5, index 44), so a command without one names nothing to answer.
    NoObjectInCommand,
    /// The answer's type identification is not one clause 7.4.14 returns
    /// (index 150's list as 104 clause 9 narrows it). This covers `<37>`–`<40>`,
    /// which are inside clause 9's permitted set `<30>`–`<40>` (index 100) but
    /// absent from the list, and `<126>` `F_DR_TA_1`, a file-transfer type
    /// ([`crate::ft`]).
    NotReturnedType {
        /// The type the answer would have carried.
        type_id: TypeId,
    },
    /// The answer's time tag is outside 104 clause 9's permitted set: a
    /// `CP24Time2a` form (`<2>`, `<4>`, `<6>`, `<8>`, `<10>`, `<12>` or `<14>`,
    /// [`is_cp24_form`]) that index 150's or-columns print but clause 9
    /// excludes, since it allows only `<30>` – `<40>` for time-tagged ASDUs.
    TagNotPermitted {
        /// The tagged type the answer would have carried.
        type_id: TypeId,
    },
    /// The answer the [`DataSource`] returned does not carry cause `<5>`, which
    /// clause 7.4.14 requires of the returned object (it goes out as an `M_PDU`
    /// with cause `<5>` REQ).
    WrongCause {
        /// The cause the answer carried.
        got: Cause,
    },
    /// The answer the [`DataSource`] returned is not the object that was asked
    /// for: a read asks for one address, and clause 7.4.14 reads the object
    /// that address names.
    AddressMismatch {
        /// The address the command named.
        asked: u32,
        /// The address the answer carried.
        got: u32,
    },
    /// The answer the [`DataSource`] returned has its `P/N` bit set. Clause
    /// 7.4.14's answer is the requested object (`M_ <5> REQ`), never negative;
    /// the refusal is the 44–47 mirror, which this module builds itself.
    NegativeAnswer,
    /// The answer the [`DataSource`] returned does not carry exactly one
    /// object: figure 74 (5-101 clause 7.3.4.3, PDF page index 106) defines
    /// `C_RD_NA_1` as `SQ = 0`, `N = 1`, and clause 7.4.14 returns the one
    /// information object that was specified.
    WrongObjectCount {
        /// The answer's `SQ` bit: `true` for a sequence of objects.
        sequence: bool,
        /// The answer's `N`: the number of objects, or the sequence's count.
        count: u8,
    },
    /// The answer's common address is not the station's own. 5-101 clause 7.2.4
    /// (index 43): a control-direction ASDU sent to the broadcast address is
    /// answered in the monitor direction by ASDUs carrying the station's own
    /// defined common address.
    WrongCommonAddress {
        /// The common address the answer carried.
        got: u16,
    },
    /// The answer's originator address is not the command's. 5-101 clause 7.2.3
    /// (index 38): the controlled station should return the originator address
    /// in its monitor-direction response.
    OriginatorMismatch {
        /// The originator the command carried.
        command: u8,
        /// The originator the answer carried.
        answer: u8,
    },
    /// The answer's `T` bit is not the command's. This module applies 5-101
    /// clause 7.2.3's echo to the test bit as well as to the originator
    /// address.
    TestMismatch {
        /// The `T` bit the command carried.
        command: bool,
        /// The `T` bit the answer carried.
        answer: bool,
    },
    /// The ASDU itself could not be parsed; the layout/header layer's error,
    /// unchanged.
    Layout(LayoutError),
}

impl From<LayoutError> for RdError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<AsduError> for RdError {
    fn from(err: AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// Which side of the read procedure a [`Read`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The requesting side: sends `C_RD_NA_1` with cause `<5>` and classifies
    /// what comes back (the requested object or the 44–47 mirror).
    Controlling,
    /// The requested side: receives the command, answers with the object or
    /// refuses with the mirror.
    Controlled,
}

/// One role's read procedure.
///
/// The role here is the *procedure's* role, not the transport's: a station that
/// is the TCP client is the controlling station (5-104 clause 7), but the same
/// station may hold the other role's instance for the reverse direction.
///
/// The state is the role, 104 clause 9.6's *"Read procedure"* checkbox and the
/// addressing. The procedure has no activation, confirmation, termination or
/// lock: a read is one command and one answer, and repeating it is the caller's
/// decision (clause 7.2's warning). Nothing here reads a clock or holds a
/// timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Read {
    role: Role,
    in_use: bool,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
}

impl Read {
    /// A controlling station's instance: whether this station uses the read
    /// procedure (104 clause 9.6's checkbox) and the addressing its commands
    /// carry.
    #[must_use]
    pub const fn controlling(uses_read: bool, common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlling,
            in_use: uses_read,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
        }
    }

    /// A controlled station's instance: whether this station uses the read
    /// procedure (104 clause 9.6's checkbox) and the addressing its answers
    /// carry.
    #[must_use]
    pub const fn controlled(uses_read: bool, common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlled,
            in_use: uses_read,
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

    /// Whether 104 clause 9.6's *"Read procedure"* checkbox is marked for this
    /// station.
    #[must_use]
    pub const fn uses_read(&self) -> bool {
        self.in_use
    }

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// The controlling station's command for the object at `ioa`; see
    /// [`request`].
    ///
    /// Refused with [`RdError::FunctionNotUsed`] when the station's
    /// [`Read::uses_read`] is false, and with the two clause rules [`request`]
    /// enforces (an irrelevant address, a broadcast common address).
    ///
    /// # Errors
    ///
    /// [`RdError::WrongRole`] on a controlled instance,
    /// [`RdError::FunctionNotUsed`], and the errors of [`request`].
    pub fn request(&self, ioa: u32) -> Result<Vec<u8>, RdError> {
        if self.role != Role::Controlling {
            return Err(RdError::WrongRole);
        }
        if !self.in_use {
            return Err(RdError::FunctionNotUsed);
        }
        request_with(ioa, self.ca, self.org, self.sizes)
    }

    /// The controlled station's answer to a received read command; see
    /// [`answer`].
    ///
    /// The answer's common address is the instance's; its originator address
    /// and `T` bit are the command's, which the controlled station echoes
    /// (clause 7.2.3, index 38). The instance's own originator is not used on
    /// this path. [`Read::on_request`] applies the same echo.
    ///
    /// Refused with [`RdError::FunctionNotUsed`] when [`Read::uses_read`] is
    /// false.
    ///
    /// # Errors
    ///
    /// [`RdError::WrongRole`] on a controlling instance,
    /// [`RdError::FunctionNotUsed`], and the errors of [`answer`].
    pub fn answer<A: AsduLayout>(
        &self,
        object: &LayoutObject<A>,
        command: &[u8],
    ) -> Result<Vec<u8>, RdError> {
        if self.role != Role::Controlled {
            return Err(RdError::WrongRole);
        }
        if !self.in_use {
            return Err(RdError::FunctionNotUsed);
        }
        answer_with(object, command, self.ca, self.sizes)
    }

    /// The controlling station's decision for one received ASDU.
    ///
    /// Three answers, in this order:
    ///
    /// 1. **A mirrored read command** (type 102, `P/N = 1`, one of the causes
    ///    44–47) is clause 7.4.14's refusal, [`Reaction::Refused`]. It is
    ///    checked before the discard rule because the mirror is the answer the
    ///    controlling station asked for: clause 7.2.3's monitor-direction log
    ///    list (index 42) names only control-direction ASDUs mirrored because of
    ///    an unknown value, for type identifications 45 to 51, which does not
    ///    include type 102.
    /// 2. **Clause 7.2.3's discard rule** for everything else, as in the other
    ///    procedure modules.
    /// 3. The frame's own meaning: a read command ([`Reaction::Requested`]), or
    ///    the requested object ([`Reaction::Answered`]) when its type is one of
    ///    [`RETURNED_TYPES`] and its cause `<5>`. Any other cause (for example
    ///    a spontaneous `<3>`) answers nothing and is [`Reaction::Other`].
    ///
    /// The object area is walked against the type's own geometry before the
    /// frame is named, so every short prefix is a typed error rather than a
    /// classification.
    ///
    /// # Errors
    ///
    /// [`RdError::WrongRole`] on a controlled instance,
    /// [`RdError::CauseNotListed`] for a mirror whose cause is not 44 to 47,
    /// and [`RdError::Layout`] when the header or object area cannot be parsed.
    pub fn on_response(&self, asdu: &[u8], known: &Known) -> Result<Outcome, RdError> {
        if self.role != Role::Controlling {
            return Err(RdError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if header.type_id == TYPE_ID && is_mirror(&header) {
            let why = class_of(header.cause).ok_or(RdError::CauseNotListed {
                cause: header.cause,
            })?;
            return Ok(Outcome {
                reaction: Reaction::Refused {
                    ioa: command_ioa(asdu, self.sizes)?.unwrap_or(0),
                    cause: why.cause(),
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
        let reaction = if header.type_id == TYPE_ID && header.cause == CAUSE_REQUEST {
            Reaction::Requested {
                ioa: command_ioa(asdu, self.sizes)?.unwrap_or(0),
            }
        } else if is_returned(header.type_id) && header.cause == CAUSE_REQUEST {
            Reaction::Answered {
                type_id: header.type_id,
                ioa: first_ioa(asdu, &header, self.sizes)?.unwrap_or(0),
            }
        } else {
            Reaction::Other
        };
        Ok(Outcome {
            reaction,
            send: Vec::new(),
        })
    }

    /// The controlled station's decision for one received ASDU, with the
    /// application's process image behind [`DataSource`].
    ///
    /// 1. **A mirrored read command** (a mirror a peer sent back) is clause
    ///    7.2.3's discard, [`Reaction::Discard`] with `Discard::Mirror`, so two
    ///    stations cannot mirror each other.
    /// 2. **A broadcast read command** (type 102 at `FF`/`FFFF`, which clause
    ///    7.2.4, index 43, restricts to types `<100>`, `<101>`, `<103>` and
    ///    `<105>`) is refused by a mirror with P/N = 1 (negative), with
    ///    COT = 46 when supported (TS 60870-5-604 5.4.10.10, PDF page
    ///    index 54). It is [`Reaction::Refused`] with the class-46 mirror in
    ///    [`Outcome::send`], whatever the caller's [`Known`] says, and the mirror
    ///    carries this station's own common address, as in [`crate::ct`] and
    ///    [`crate::pm`].
    /// 3. **Clause 7.2.3's rule for the control direction**: a frame whose type
    ///    identification, cause of transmission, common address or information
    ///    object address the station does not know (per the caller's [`Known`])
    ///    is mirrored with `P/N := <1>` (negative confirmation) and the
    ///    class's cause, never discarded. This is clause 7.4.14's 44–47 mirror:
    ///    [`Reaction::Refused`] with the mirror in [`Outcome::send`].
    /// 4. **Everything else**: a station that does not use the procedure
    ///    answers a type-102 cause-`<5>` command with the cause-44 mirror
    ///    ([`Reaction::Refused`]). Otherwise the command is
    ///    [`Reaction::Requested`] and is answered with the source's object when
    ///    [`DataSource::object`] has one, and with the class-47 mirror when it
    ///    does not. Address `<0>` gets the class-47 mirror without asking the
    ///    source (clause 7.2.5, index 44); it is reached only after step 3, the
    ///    order [`refusal`] uses. A frame of another type, of this type with
    ///    another cause, or with no object (clause 7.2.2's `N = 0`) is
    ///    [`Reaction::Other`].
    ///
    /// Every frame the source returns is checked here before it goes out (see
    /// [`DataSource`]): cause `<5>`, a [`RETURNED_TYPES`] type identification,
    /// the address the command named, the command's originator address and `T`
    /// bit, this station's common address, and the one positive object
    /// (`P/N = 0`, `SQ = 0`, `N = 1`) the read asked for.
    ///
    /// # Errors
    ///
    /// [`RdError::WrongRole`] on a controlling instance,
    /// [`RdError::Layout`] when the received frame or the source's frame
    /// cannot be parsed, and the typed error of each check above when the
    /// source's frame fails it.
    pub fn on_request(
        &self,
        asdu: &[u8],
        known: &Known,
        source: &dyn DataSource,
    ) -> Result<Outcome, RdError> {
        if self.role != Role::Controlled {
            return Err(RdError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if header.type_id == TYPE_ID && is_mirror(&header) {
            // A mirror of our own command shape coming back: the peer mirrored
            // *us*. Nothing is mirrored back (clause 7.2.3's third log bullet),
            // which is the same reason `discard_reason` reports it. The object
            // area is still walked first, so a truncated frame is a typed error
            // rather than a discard.
            first_ioa(asdu, &header, self.sizes)?;
            return Ok(Outcome {
                reaction: Reaction::Discard(Discard::Mirror),
                send: Vec::new(),
            });
        }
        // A read command is never broadcast (TS 60870-5-604 5.4.10.10). The
        // check reads the header, so it holds whatever `Known` says, and it runs
        // before the discard rule because a broadcast command must be answered,
        // not swallowed.
        if header.common_address == self.sizes.broadcast_common_address()
            && !is_mirror(&header)
            && header.type_id == TYPE_ID
        {
            return self.refuse(&header, asdu, crate::asdu::Unspecified::CommonAddress);
        }
        if let Some(reason) = discard_reason(&header, known) {
            if let Discard::Unspecified(which) = reason {
                // Clause 7.2.3's table is about the control direction: an ASDU
                // whose field the station does not know is mirrored (clause
                // 7.4.14's 44–47 sentence), never discarded.
                return self.refuse(&header, asdu, which);
            }
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        if header.type_id != TYPE_ID || header.cause != CAUSE_REQUEST {
            return Ok(other());
        }
        if !self.in_use {
            // Not serving reads makes C_RD_NA_1 an unknown type here (cl.7.2.3).
            return self.refuse(&header, asdu, crate::asdu::Unspecified::TypeIdentification);
        }
        // The type's layout is `LEN` 0 and `Single` (5-101 cl.7.3.4.3, figure
        // 74): its whole payload is the one address, and a frame carrying no
        // object (cl.7.2.2's `N = 0`) names nothing to read.
        let Some(ioa) = command_ioa(asdu, self.sizes)? else {
            return Ok(other());
        };
        if ioa == 0 {
            // `<0>` is the field's "irrelevant" value (5-101 cl.7.2.5), so it
            // names no object: the class-47 mirror, not a positive answer.
            return self.refuse(
                &header,
                asdu,
                crate::asdu::Unspecified::InformationObjectAddress,
            );
        }
        let Some(frame) = source.object(ioa) else {
            // The address is not one this station holds: clause 7.4.14's
            // *"unknown (not defined) in the controlled station"* for the
            // information object address, mirrored with cause 47.
            return self.refuse(
                &header,
                asdu,
                crate::asdu::Unspecified::InformationObjectAddress,
            );
        };
        let reply = Header::parse_with(&frame, self.sizes)?;
        if reply.cause != CAUSE_REQUEST {
            return Err(RdError::WrongCause { got: reply.cause });
        }
        if !is_returned(reply.type_id) {
            return Err(if is_cp24_form(reply.type_id) {
                RdError::TagNotPermitted {
                    type_id: reply.type_id,
                }
            } else {
                RdError::NotReturnedType {
                    type_id: reply.type_id,
                }
            });
        }
        if reply.negative {
            return Err(RdError::NegativeAnswer);
        }
        if reply.sequence || reply.count != 1 {
            return Err(RdError::WrongObjectCount {
                sequence: reply.sequence,
                count: reply.count,
            });
        }
        if reply.common_address != self.ca {
            return Err(RdError::WrongCommonAddress {
                got: reply.common_address,
            });
        }
        if reply.originator != header.originator {
            return Err(RdError::OriginatorMismatch {
                command: header.originator,
                answer: reply.originator,
            });
        }
        if reply.test != header.test {
            return Err(RdError::TestMismatch {
                command: header.test,
                answer: reply.test,
            });
        }
        if let Some(got) = first_ioa(&frame, &reply, self.sizes)?
            && got != ioa
        {
            return Err(RdError::AddressMismatch { asked: ioa, got });
        }
        Ok(Outcome {
            reaction: Reaction::Requested { ioa },
            send: vec![frame],
        })
    }

    /// Clause 7.2.3's mirror of a received frame for one of the four undefined
    /// classes: [`Reaction::Refused`] with the class's cause and the mirror in
    /// [`Outcome::send`], carrying this station's own common address (clause
    /// 7.2.4: the station's own defined common address).
    fn refuse(
        self,
        header: &Header,
        asdu: &[u8],
        which: crate::asdu::Unspecified,
    ) -> Result<Outcome, RdError> {
        Ok(Outcome {
            reaction: Reaction::Refused {
                ioa: first_ioa(asdu, header, self.sizes)?.unwrap_or(0),
                cause: which.cause(),
            },
            send: vec![mirror_frame(header, asdu, which, self.ca, self.sizes)],
        })
    }
}

/// The class of clause 7.2.3's table a 44–47 cause names: the inverse of
/// [`crate::asdu::Unspecified::cause`].
fn class_of(cause: Cause) -> Option<crate::asdu::Unspecified> {
    crate::asdu::Unspecified::ALL
        .into_iter()
        .find(|which| which.cause() == cause)
}

/// The information object address of the single object a `C_RD_NA_1` carries
/// (its whole payload, figure 74), or `None` when the ASDU carries no object
/// (clause 7.2.2's `N = 0`). Every other short prefix is a typed error, so a
/// truncated command never reaches the application.
fn command_ioa(asdu: &[u8], sizes: AddressSizes) -> Result<Option<u32>, RdError> {
    Ok(decode_asdu_with::<CRdNa1>(asdu, sizes)?
        .first()
        .map(|object| object.ioa))
}

/// The information object address of the first object of a monitor ASDU, with
/// the object area walked to its end so every short prefix is a typed error.
/// `None` when the ASDU carries no object (clause 7.2.2's `N = 0`) or when its
/// type has no fixed element length ([`element_len`] is `None`: a type with no
/// layout, or `F_SG_NA_1`).
fn first_ioa(asdu: &[u8], header: &Header, sizes: AddressSizes) -> Result<Option<u32>, AsduError> {
    let Some(len) = element_len(header.type_id) else {
        return Ok(None);
    };
    let body = asdu.get(sizes.header_len()..).unwrap_or(&[]);
    let mut cursor = BodyReader::with_sizes(*header, body, sizes);
    let first = cursor.next_object(len)?.map(|object| object.ioa);
    while cursor.next_object(len)?.is_some() {}
    cursor.finish()?;
    Ok(first)
}

/// The outcome for an ASDU this procedure does not own.
const fn other() -> Outcome {
    Outcome {
        reaction: Reaction::Other,
        send: Vec::new(),
    }
}
