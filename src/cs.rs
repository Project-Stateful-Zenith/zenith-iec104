//! Clock synchronisation: the `C_CS_NA_1` activation, the confirmation that
//! carries the controlled station's pre-synchronisation time, and the
//! spontaneous monitor-direction use of the same type.
//!
//! # The procedure
//!
//! 5-104 clause **7.6** (PDF page index 66, printed page 65) is headed *"Clock
//! synchronization (6.7 of IEC 60870-5-5)"* and its service table has two
//! rows:
//!
//! | Application service | ASDU label |
//! | --- | --- |
//! | `A_CLOCKSYN.req` / `.ind` | `C_CS ACT` |
//! | `A_TIMEMESS.req` / `.ind` | `C_CS ACTCON` |
//!
//! **There is no `ACTTERM`, no `DEACT` and no `DEACTCON`**: the exchange is two
//! frames and ends there. 5-101 figure 75 (clause 7.3.4.4, PDF page index 107,
//! printed page 106) prints the same thing per type:
//!
//! ```text
//! CAUSES OF TRANSMISSION used with TYPE IDENT 103 := C_CS_NA_1
//!   in control direction: <6> activation
//!   in monitor direction: <3> spontaneous, <7> activation confirmation,
//!                         <44> .. <47> the four unknown-address replies
//! ```
//!
//! Unlike [`crate::gi`] and [`crate::ci`] this module therefore has **no
//! `complete()` call**, like [`crate::ci`] it has **no deactivation builder**,
//! and the controlled station's answer is a single frame. A type-103 ASDU carrying any other cause
//! (a termination, a deactivation) is [`Reaction::Other`].
//!
//! # The answer carries the time the station had *before* the correction
//!
//! Clause 7.6, verbatim: *"After the execution of the clock sync internally the
//! controlled station generates a `C_CS` ACTCON PDU that contains the local time
//! before it was synchronized."* Clause 7.6.1 (PDF page index 68, printed page
//! 67) again: *"This request contains the time which is known in the
//! application process in the controlled station before reception of the
//! `A_CLOCKSYN.ind`."* TS 60870-5-604 Table 18's row 5.4.18.1 (PDF page index 69,
//! printed page 68) calls this answer a mirror of ASDU 103 with COT 7.
//!
//! Clause 7.6 also removes the correction value of IEC 60870-5-5: *"The
//! procedure is a copy of that of 6.7 of IEC 60870-5-5, with the \"first bit\"
//! and \"time correction\" requirements and link layer options (SEND/NO REPLY or
//! SEND/CONFIRM) removed."* The pre-sync time is therefore an **argument** to
//! [`answer`] and to [`ClockSynchronisation::on_request`]: the module never
//! computes it, and has no correction field to compute it from.
//!
//! # The answer echoes the request's originator address
//!
//! 5-101 clause **7.2.3** (PDF page index 38, printed page 37): *"In these
//! systems, the information source should set the originator address of the
//! ASDUs in the command direction, and the controlled station should echo this
//! originator address in the response in the monitor direction."*
//!
//! [`ClockSynchronisation::on_request`] therefore builds its answer with **the
//! request's** originator, not with the station's own. The common address is
//! the station's own even for a broadcast request (clause 7.2.4, below). The
//! free [`answer`] and [`ClockSynchronisation::answer`] builders take whatever
//! originator the caller hands them.
//!
//! # One type, two monitor-direction causes with different meanings
//!
//! Figure 75's caption: *"In addition to the procedure shown in 6.7 of IEC
//! 60870-5-5, `C_CS_NA_1` may be used in the monitor direction for spontaneous
//! transmission of the clock time. For example to indicate the change of hour at
//! an outstation, thus enabling messages to be stored for more than 1 h in an
//! outstation without ambiguity."* TS 60870-5-604 Table 16 (PDF page index 63,
//! printed page 62) tests it under *"Acquisition of events"* (COT 3 / ASDU
//! 103): *"The Controlled station sends a spontaneous clock synchronisation
//! message with COT=3 to indicate its internal date and hour shift immediately
//! after the hour shift or before sending subsequent ASDUs with short time
//! tag"*.
//!
//! So **cause 7 is the answer to a request and cause 3 is an announcement that
//! answers nothing**, and [`Reaction`] classifies them apart
//! ([`Reaction::Answered`] and [`Reaction::Announced`]).
//!
//! # The frame
//!
//! Figure 75 is headed *"Single information object (SQ = 0)"*, prints
//! `INFORMATION OBJECT ADDRESS = 0`, and gives the body as `CP56Time2a`:
//!
//! ```text
//! C_CS_NA_1 := CP{Data unit identifier,Information object address,CP56Time2a}
//! ```
//!
//! That is 6 header + 3 information object address + 7 time = **16 octets**,
//! laid out by [`CCsNa1`]. The seven time octets are 5-101 clause **7.2.6.18**
//! (PDF page index 52, printed page 51), carried as plain fields by
//! [`Cp56Time2a`]. This module **passes the fields through**: it neither
//! polices the day of week nor clears a bit the caller set.
//!
//! # `FF`/`FFFF` is legal here, and the answer carries the station's own address
//!
//! 5-101 clause **7.2.4** (PDF page index 43, printed page 42): *"The use of the
//! common address FF or FFFF is restricted to the following ASDUs in the control
//! direction: type Identification <100> … <101> … <103> … <105>"* and *"When
//! using the common address FF or FFFF (broadcast address, request of all),
//! ACTCON, ACTTERM and the interrogated information objects (if any) are
//! returned with the specific common addresses of the controlled stations as
//! they would be when caused by commands to specific controlled stations."*
//! TS 60870-5-604 5.4.18.15 tests it for this procedure (PIXIT).
//!
//! So [`request`] takes whatever common address the caller gives it, a
//! broadcast included, and [`answer`] takes the **station's own**; the module
//! never rewrites one into the other. Correlating the answers of a broadcast is
//! the caller's, by the common address each carries.
//!
//! # What the procedure does not have
//!
//! * **No running state.** There is nothing to terminate, no lock on a second
//!   activation and no re-activation options (those are general
//!   interrogation's, and the counter procedure has none either).
//!   `ClockSynchronisation` holds the role and the addressing only, and an
//!   activation confirmation is classified by its own cause whether or not the
//!   caller remembers sending an activation (covered in `tests/cs.rs`); a
//!   station that wants correlation has the common address to do it with.
//! * **No data source.** This procedure answers with a time the caller already
//!   holds, so it takes that time as an argument instead of pulling it from a
//!   trait.
//! * **No clock and no timer.** Clause 7.6: *"Controlled stations expect the
//!   reception of clock synchronization messages within agreed time intervals.
//!   When the synchronization command does not arrive within this time interval,
//!   the controlled station sets all time-tagged information objects with a mark
//!   that the time tag may be inaccurate (invalid)."* 5-101 clause **7.4.6**
//!   (PDF page index 126, printed page 125) adds *"The summer-time bit is ignored
//!   in both controlling and controlled stations, and should be set to zero."*
//!   The module reads no clock: [`TimeValidity`] keeps the interval rule with
//!   the current time as an argument, and the caller applies its answer to the
//!   time tags it sends (see "The time tag's invalid mark" below). The
//!   `invalid` and `summer_time` fields of [`Cp56Time2a`] round-trip through
//!   every builder here; choosing between UTC and local time is the
//!   application's.
//! * **No transmit-order control.** Clause 7.6: *"This message is transmitted
//!   after any buffered time-tagged PDUs, that may be waiting for transmission.
//!   Time-tagged events that occur after the internal clock synchronization are
//!   transmitted after the `C_CS` ACTCON PDU."* No application-level transmit
//!   queue exists above [`crate::link`] in this crate, so the ordering is the
//!   caller's. [`crate::tx::respond_priority`] puts `C_CS_NA_1` in the event
//!   row of 5-101 Table 16; `iec104-tokio`'s `server::Server` keeps such a
//!   queue, first in first out within a row, so its confirmation goes out
//!   behind the events queued before it and ahead of those queued after.
//! * **No accuracy claim.** Clause 7.6: *"However, clock synchronization may be
//!   used in configurations where the maximum network delay is less than the
//!   required accuracy of the clock in the receiving station."* This module
//!   sends and classifies frames; it does not claim a synchronised clock.
//!
//! # What this module is not
//!
//! * **Not I/O, not a clock, not a socket.** Every result depends only on the
//!   arguments and the value's own state; the caller owns the connection, the local clock, the log and
//!   the retry. Frames go out through
//!   [`Session::queue_i_frame`](crate::link::Session::queue_i_frame), which holds
//!   them until the STARTDT con.
//! * **Not the setting of the clock.** [`Reaction::Requested`] says which time
//!   arrived; applying it to a clock is the application's.
//! * **Not a negative confirmation.** The type's cause list carries `<7>` with
//!   the `P/N` flag, and [`Reaction::Answered`] reports the flag of a received
//!   frame, but the builder always writes a positive confirmation: clause 7.6
//!   names no refusal and there is no data source whose readiness could fail.
//!   This is the crate's reading.
//! * **Not a check of a received `P/N` bit.** Figure 75's control-direction list
//!   prints only `<6> activation`, and clause 7.2.3's discard rule concerns
//!   undefined causes of transmission, not this bit. So
//!   [`ClockSynchronisation::on_request`] classifies an activation carrying
//!   `P/N = 1` by its cause like any other and answers positively (covered in
//!   `tests/cs.rs`).
//!
//! # The time tag's invalid mark
//!
//! Clause 7.6, verbatim: *"Controlled stations expect the reception of clock
//! synchronization messages within agreed time intervals. When the
//! synchronization command does not arrive within this time interval, the
//! controlled station sets all time-tagged information objects with a mark that
//! the time tag may be inaccurate (invalid). This mark is also set after station
//! initializiation (warm and cold boot) of controlled stations before reception
//! of a valid `C_CS` ACT PDU. Time-tagged events that occur after the reception of
//! valid `C_CS` ACT PDU are transmitted without the mark."*
//!
//! The mark is the `IV` bit of the time tag (5-101 clauses 7.2.6.18 and
//! 7.2.6.19, the `invalid` field of [`Cp56Time2a`] and [`Cp24Time2a`]).
//! [`TimeValidity`] is a controlled station's record of that rule: it starts
//! unsynchronised, is told of each valid `C_CS ACT` with the time it arrived,
//! and answers whether a time tag taken at a given instant is trustworthy.
//!
//! ```
//! use std::time::{Duration, Instant};
//! use iec104::asdu::Cp56Time2a;
//! use iec104::cs::TimeValidity;
//!
//! let boot = Instant::now(); // the caller's clock, read by the caller
//! let mut validity = TimeValidity::new(Duration::from_secs(3600));
//! assert!(!validity.time_valid(boot)); // before the first C_CS ACT
//!
//! validity.synchronised(boot + Duration::from_secs(5));
//! let tag = validity.mark(Cp56Time2a::default(), boot + Duration::from_secs(6));
//! assert!(!tag.invalid);
//!
//! // No synchronisation for the agreed hour: the mark is set again.
//! let late = boot + Duration::from_secs(5 + 3600);
//! assert!(validity.mark(Cp56Time2a::default(), late).invalid);
//! ```
//!
//! # Example
//!
//! ```
//! use iec104::asdu::{Cause, Cp56Time2a, Header, Known, TypeId};
//! use iec104::cs::{announcement, answer, request, ClockSynchronisation, Reaction};
//!
//! // The controlling station's request: 26.965 s, 16 min past 13:00 on
//! // 19 January 2001 (the worked example of Clarke/Reynders/Wright, App. D).
//! let time = Cp56Time2a {
//!     milliseconds: 26_965,
//!     minutes: 16,
//!     hours: 13,
//!     day_of_month: 19,
//!     months: 1,
//!     years: 1,
//!     ..Cp56Time2a::default()
//! };
//! let asdu = request(time, 12, 0).unwrap();
//! assert_eq!(asdu.len(), 16);
//! assert_eq!(&asdu[9..], &[0x55, 0x69, 0x10, 0x0D, 0x13, 0x01, 0x01]);
//! assert_eq!(Header::parse(&asdu).unwrap().cause, Cause::Activation);
//!
//! // The controlled station answers with the time it had *before* the
//! // correction, not with the time it was sent.
//! let before = Cp56Time2a { hours: 12, ..time };
//! let mut controlled = ClockSynchronisation::controlled(12, 0);
//! let outcome = controlled.on_request(&asdu, &Known::EVERYTHING, before).unwrap();
//! assert_eq!(outcome.reaction, Reaction::Requested { time, test: false });
//! assert_eq!(Header::parse(&outcome.send[0]).unwrap().cause, Cause::ActivationCon);
//! assert_eq!(&outcome.send[0][9..], &answer(before, 12, 0).unwrap()[9..]);
//!
//! // The answer echoes the originator address of the request it answers
//! // (5-101 clause 7.2.3), so the confirmation reaches the source that
//! // activated the procedure — even though this station's own is 0.
//! let from_another_source = request(time, 12, 42).unwrap();
//! let echoed = controlled
//!     .on_request(&from_another_source, &Known::EVERYTHING, before)
//!     .unwrap();
//! assert_eq!(Header::parse(&echoed.send[0]).unwrap().originator, 42);
//!
//! // A spontaneous clock time announces, it does not answer.
//! let spontaneous = announcement(time, 12, 0).unwrap();
//! let mut controlling = ClockSynchronisation::controlling(12, 0);
//! assert_eq!(
//!     controlling.on_response(&spontaneous, &Known::EVERYTHING).unwrap().reaction,
//!     Reaction::Announced { time }
//! );
//! assert_eq!(Header::parse(&spontaneous).unwrap().type_id, TypeId::CCsNa1);
//! ```

use core::time::Duration;
use std::time::Instant;

use crate::asdu::{
    AddressSizes, CCsNa1, Cause, Cp24Time2a, Cp56Time2a, Discard, Header, IOA_IRRELEVANT, Known,
    LayoutError, LayoutObject, TypeId, decode_asdu_with, discard_reason, encode_asdu_with,
    mirror_frame,
};

/// The type identification of the clock synchronisation command (5-101 clause
/// 7.3.4.4, figure 75).
pub const TYPE_ID: TypeId = TypeId::CCsNa1;

/// `<6> activation`: the cause of the request (figure 75's control-direction
/// list).
pub const CAUSE_ACTIVATION: Cause = Cause::Activation;

/// `<7> activation confirmation`: the cause of the controlled station's answer
/// (figure 75).
pub const CAUSE_ACTIVATION_CON: Cause = Cause::ActivationCon;

/// `<3> spontaneous`: the cause of a clock time the controlled station sends
/// on its own, which answers nothing (figure 75's caption and TS 60870-5-604
/// Table 16's ASDU-103 row).
pub const CAUSE_SPONTANEOUS: Cause = Cause::Spontaneous;

/// Builds one type-103 frame: `N = 1`, `SQ = 0`, an information object address
/// of zero (figure 75), `P/N` and `T` as given. The cause is the caller's here
/// and the clause's in every public builder.
fn frame(
    cause: Cause,
    negative: bool,
    test: bool,
    time: Cp56Time2a,
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
        value: CCsNa1 { time },
    };
    encode_asdu_with(&header, &[object], sizes)
}

/// Builds the controlling station's clock synchronisation request.
///
/// The request is the sixteen-octet `C_CS_NA_1` of 5-101 clause 7.3.4.4, with
/// cause 6 (`act`), `N = 1`, `SQ = 0` and an information object address of
/// zero (figure 75's `INFORMATION OBJECT ADDRESS = 0`), carrying `time` as its
/// seven-octet `CP56Time2a`.
///
/// The cause and the information object address are the clause's, not the
/// caller's, so a frame the standard does not list for type 103 cannot be built
/// from this API. `common_address` is the caller's, because 5-101 clause 7.2.4
/// admits the broadcast address `FF`/`FFFF` for this type (*"for example, to
/// synchronize the local clocks by a clock synchronization command"*). The
/// error is the layout layer's and cannot occur for these arguments; it is
/// propagated rather than unwrapped because nothing in `src/` panics.
///
/// # Errors
///
/// None for these arguments in the conventional address sizes; the layout
/// layer's [`LayoutError`] is passed through unchanged.
pub fn request(
    time: Cp56Time2a,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, LayoutError> {
    request_with(time, common_address, originator, AddressSizes::CONVENTIONAL)
}

/// [`request`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// [`LayoutError::Asdu`] when `common_address` does not fit the common address
/// size `sizes` fixes.
pub fn request_with(
    time: Cp56Time2a,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    frame(
        CAUSE_ACTIVATION,
        false,
        false,
        time,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the controlled station's answer: the same sixteen octets with cause 7
/// (`actcon`).
///
/// **`pre_sync_time` is the time the station had before the correction**, per
/// clause 7.6 (*"the local time before it was synchronized"*) and clause 7.6.1.
/// It is the caller's value: the module owns no clock, so it cannot read one,
/// and it must not substitute the time the request carried.
///
/// `common_address` is the station's **own**: clause 7.2.4 returns the answer to
/// a broadcast with the specific common address of the controlled station.
///
/// # Errors
///
/// None in the conventional address sizes; the layout layer's [`LayoutError`]
/// is passed through unchanged.
pub fn answer(
    pre_sync_time: Cp56Time2a,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, LayoutError> {
    answer_with(
        pre_sync_time,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`answer`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// [`LayoutError::Asdu`] when `common_address` does not fit the common address
/// size `sizes` fixes.
pub fn answer_with(
    pre_sync_time: Cp56Time2a,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    frame(
        CAUSE_ACTIVATION_CON,
        false,
        false,
        pre_sync_time,
        common_address,
        originator,
        sizes,
    )
}

/// Builds the controlled station's spontaneous clock time.
///
/// The frame is the same sixteen octets with cause 3 (`spont`), which figure
/// 75's caption permits and TS 60870-5-604 Table 16 tests (*"to indicate its
/// internal date and hour shift immediately after the hour shift or before
/// sending subsequent ASDUs with short time tag"*).
///
/// Nothing in the crate sends this by itself: which event announces the clock
/// (an hour shift, a daylight-saving change) and when is the application's.
///
/// **This is a 5-101 message, not a 5-104 one.** 104's interoperability sheet
/// (clause 9) fills the `<103>` / cause 3 box black (*"option not permitted
/// in this companion standard"*), and 104 cl.7.6 lists only `C_CS ACT` and
/// `C_CS ACTCON`. 604's test row reasons from short time tags, which 104 does
/// not permit either. A controlling station on
/// [`InteropProfile::conventional`](crate::interop::InteropProfile::conventional)
/// therefore discards it (cl.7.2.3, unknown cause); send it only to a peer
/// that has agreed to it.
///
/// # Errors
///
/// None in the conventional address sizes; the layout layer's [`LayoutError`]
/// is passed through unchanged.
pub fn announcement(
    time: Cp56Time2a,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, LayoutError> {
    announcement_with(time, common_address, originator, AddressSizes::CONVENTIONAL)
}

/// [`announcement`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// [`LayoutError::Asdu`] when `common_address` does not fit the common address
/// size `sizes` fixes.
pub fn announcement_with(
    time: Cp56Time2a,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    frame(
        CAUSE_SPONTANEOUS,
        false,
        false,
        time,
        common_address,
        originator,
        sizes,
    )
}

/// What one type-103 frame means, from the point of view of the role that
/// received it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// A clock synchronisation request arrived (cause 6). `time` is the time it
    /// carried, which is the time the controlled station has to adopt and
    /// which the answer must **not** carry back; see [`answer`].
    Requested {
        /// The time the request carried.
        time: Cp56Time2a,
        /// `T = 1`: the request was sent under test conditions (5-101
        /// cl.7.2.3, *"without controlling the process"*), so its time is not
        /// adopted; [`TimeValidity::on_outcome`] does not count it.
        test: bool,
    },
    /// An activation confirmation arrived (cause 7). `time` is the
    /// pre-synchronisation time it carried, and `negative` is its `P/N` flag
    /// (5-101 clause 7.2.3's negative confirmation, which this module does not
    /// build; see the module doc).
    Answered {
        /// The pre-synchronisation time the frame carried.
        time: Cp56Time2a,
        /// `P/N = 1`: a negative confirmation.
        negative: bool,
    },
    /// A spontaneous clock time arrived (cause 3). It answers nothing: it is the
    /// controlled station announcing its clock, per figure 75's caption.
    Announced {
        /// The time the announcement carried.
        time: Cp56Time2a,
    },
    /// Controlled station: the received ASDU had a field the station does not
    /// know, and clause 7.2.3's cause 44–47 mirror is in [`Outcome::send`].
    Refused {
        /// The mirror's cause: 44, 45, 46 or 47.
        cause: Cause,
    },
    /// Clause 7.2.3 says this ASDU is discarded and may be logged.
    Discard(Discard),
    /// Not this procedure: the type or the cause says the ASDU belongs to
    /// another one. This includes a termination or a deactivation of this
    /// type, which clause 7.6's service table does not define.
    Other,
}

/// What a received ASDU means, and what to send because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The classification of the received ASDU.
    pub reaction: Reaction,
    /// The ASDUs to send, in order. Always empty for a controlling station; for
    /// a controlled station it carries the answer or the clause 7.2.3 mirror.
    pub send: Vec<Vec<u8>>,
}

/// What can go wrong in this layer, over and above the codec's own errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsError {
    /// The entry point does not belong to this instance's role: `request` and
    /// `on_response` are the controlling station's, `answer`, `announcement` and
    /// `on_request` are the controlled station's.
    WrongRole,
    /// The ASDU itself could not be parsed; the layout/header layer's error,
    /// unchanged.
    Layout(LayoutError),
}

impl From<LayoutError> for CsError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<crate::asdu::AsduError> for CsError {
    /// The header/codec error reaches this layer through the layout layer's own
    /// wrapper, exactly as [`crate::asdu::decode_asdu`] surfaces it.
    fn from(err: crate::asdu::AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// Which side of the procedure a [`ClockSynchronisation`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The requesting side: sends the activation, answers nothing.
    Controlling,
    /// The requested side: answers with its pre-synchronisation time.
    Controlled,
}

/// One role's clock synchronisation procedure.
///
/// The role here is the *procedure's* role, not the transport's: a station that
/// is the TCP client is the controlling station (5-104 clause 7), but the same
/// station may hold the other role's instance for the reverse direction.
///
/// The role and the addressing are the whole of the state: the procedure has
/// no running activation, no lock and no termination to remember (see the
/// module doc, "What the procedure does not have").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockSynchronisation {
    role: Role,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
}

impl ClockSynchronisation {
    /// A controlling station's instance.
    #[must_use]
    pub const fn controlling(common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlling,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
        }
    }

    /// A controlled station's instance.
    #[must_use]
    pub const fn controlled(common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlled,
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

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// The controlling station's request carrying `time`.
    ///
    /// A station that is not the controlling side gets [`CsError::WrongRole`].
    /// The common address is the instance's, so a station built for the
    /// broadcast address sends a broadcast (see [`request`]).
    ///
    /// # Errors
    ///
    /// [`CsError::WrongRole`] on a controlled instance, and [`CsError::Layout`] when the
    /// common address does not fit the address sizes.
    pub fn request(&self, time: Cp56Time2a) -> Result<Vec<u8>, CsError> {
        if self.role != Role::Controlling {
            return Err(CsError::WrongRole);
        }
        Ok(request_with(time, self.ca, self.org, self.sizes)?)
    }

    /// The controlled station's answer carrying `pre_sync_time`, the time before
    /// the correction (see [`answer`]).
    ///
    /// The originator is the **instance's**; for the answer to a request this
    /// station received, clause 7.2.3 asks for that request's originator instead,
    /// which is what [`ClockSynchronisation::on_request`] does.
    ///
    /// # Errors
    ///
    /// [`CsError::WrongRole`] on a controlling instance, and [`CsError::Layout`] when the
    /// common address does not fit the address sizes.
    pub fn answer(&self, pre_sync_time: Cp56Time2a) -> Result<Vec<u8>, CsError> {
        if self.role != Role::Controlled {
            return Err(CsError::WrongRole);
        }
        Ok(answer_with(pre_sync_time, self.ca, self.org, self.sizes)?)
    }

    /// The controlled station's spontaneous clock time (see [`announcement`]).
    ///
    /// # Errors
    ///
    /// [`CsError::WrongRole`] on a controlling instance, and [`CsError::Layout`] when the
    /// common address does not fit the address sizes.
    pub fn announcement(&self, time: Cp56Time2a) -> Result<Vec<u8>, CsError> {
        if self.role != Role::Controlled {
            return Err(CsError::WrongRole);
        }
        Ok(announcement_with(time, self.ca, self.org, self.sizes)?)
    }

    /// The controlling station's decision for one received ASDU.
    ///
    /// Clause 7.2.3's discard rule runs first, exactly as it does in
    /// [`crate::init::on_asdu`], [`crate::gi`] and [`crate::ci`]. The two
    /// monitor-direction causes this procedure defines are classified apart:
    /// cause 7 is [`Reaction::Answered`], cause 3 is [`Reaction::Announced`].
    /// The returned [`Outcome::send`] is always empty.
    ///
    /// # Errors
    ///
    /// [`CsError::WrongRole`] on a controlled instance, and [`CsError::Layout`] when the
    /// header or the type-103 object cannot be parsed.
    pub fn on_response(&self, asdu: &[u8], known: &Known) -> Result<Outcome, CsError> {
        if self.role != Role::Controlling {
            return Err(CsError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if let Some(reason) = discard_reason(&header, known) {
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        if header.type_id != TYPE_ID {
            return Ok(other());
        }
        let reaction = match (header.cause, time_of(asdu, self.sizes)?) {
            (Cause::ActivationCon, Some(time)) => Reaction::Answered {
                time,
                negative: header.negative,
            },
            (Cause::Spontaneous, Some(time)) => Reaction::Announced { time },
            _ => Reaction::Other,
        };
        Ok(Outcome {
            reaction,
            send: Vec::new(),
        })
    }

    /// The controlled station's decision for one received ASDU, with the time
    /// the station had before the correction.
    ///
    /// A cause-6 activation yields [`Reaction::Requested`] carrying the time the
    /// request was sent with, and an [`Outcome::send`] holding the single
    /// answer built from `pre_sync_time`, **not** from the request's time. The
    /// answer's originator address is the **request's**, as clause 7.2.3 asks,
    /// and its common address is the station's own. No clock is set here: the
    /// caller applies the request to
    /// its own clock after telling this method what that clock read.
    ///
    /// # Errors
    ///
    /// [`CsError::WrongRole`] on a controlling instance, and [`CsError::Layout`] when the
    /// header or the type-103 object cannot be parsed, or the answer cannot be
    /// built.
    pub fn on_request(
        &self,
        asdu: &[u8],
        known: &Known,
        pre_sync_time: Cp56Time2a,
    ) -> Result<Outcome, CsError> {
        if self.role != Role::Controlled {
            return Err(CsError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if let Some(reason) = discard_reason(&header, known) {
            if let Discard::Unspecified(which) = reason {
                // Clause 7.2.3: a control-direction field the station does not
                // know is mirrored with P/N = 1 and the class's cause.
                return Ok(Outcome {
                    reaction: Reaction::Refused {
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
        if header.type_id != TYPE_ID || header.cause != CAUSE_ACTIVATION {
            return Ok(other());
        }
        // `N = 0` is clause 7.2.2's defined "ASDU contains no INFORMATION
        // OBJECT": there is no time to adopt and nothing to answer with.
        let Some(time) = time_of(asdu, self.sizes)? else {
            return Ok(other());
        };
        Ok(Outcome {
            reaction: Reaction::Requested {
                time,
                test: header.test,
            },
            // `pre_sync_time`, never the request's own time (clause 7.6), and
            // the request's originator and test bit, not the station's own
            // (clause 7.2.3).
            send: vec![frame(
                CAUSE_ACTIVATION_CON,
                false,
                header.test,
                pre_sync_time,
                self.ca,
                header.originator,
                self.sizes,
            )?],
        })
    }
}

/// A controlled station's record of clause 7.6's rule for the invalid mark of
/// its time tags.
///
/// Clause 7.6: *"When the synchronization command does not arrive within this
/// time interval, the controlled station sets all time-tagged information
/// objects with a mark that the time tag may be inaccurate (invalid). This mark
/// is also set after station initializiation (warm and cold boot) of controlled
/// stations before reception of a valid `C_CS` ACT PDU."*
///
/// A new record is **not synchronised**, which is the state after station
/// initialisation. Each valid `C_CS ACT` is reported with
/// [`TimeValidity::synchronised`] or [`TimeValidity::on_outcome`], and from
/// then on a time tag is valid until the agreed interval has passed without
/// another one. The record reads no clock: every instant is the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeValidity {
    interval: Duration,
    last: Option<Instant>,
}

impl TimeValidity {
    /// A record for the agreed re-synchronisation `interval` (clause 7.6's
    /// *"agreed time intervals"*), in the state after station initialisation:
    /// no valid `C_CS ACT` received yet, so every time tag is marked invalid.
    #[must_use]
    pub const fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
        }
    }

    /// The agreed re-synchronisation interval.
    #[must_use]
    pub const fn interval(&self) -> Duration {
        self.interval
    }

    /// The instant of the last valid `C_CS ACT`, or `None` before the first
    /// one since initialisation.
    #[must_use]
    pub const fn last_synchronised(&self) -> Option<Instant> {
        self.last
    }

    /// A valid `C_CS ACT` was received at `now` and the station's clock was
    /// set from it.
    ///
    /// Call this only for an activation the station accepted and answered with
    /// a positive `C_CS ACTCON`: clause 7.6 clears the mark on *"reception of
    /// valid `C_CS` ACT PDU"* only. [`TimeValidity::on_outcome`] makes that
    /// decision from the procedure's own classification.
    pub const fn synchronised(&mut self, now: Instant) {
        self.last = Some(now);
    }

    /// Station initialisation (a warm or cold boot, clause 7.6's *"station
    /// initializiation"*) without building a new record: time tags are marked
    /// invalid until the next valid `C_CS ACT`.
    pub const fn restart(&mut self) {
        self.last = None;
    }

    /// Reports the controlled station's [`Outcome`] of one received ASDU, from
    /// [`ClockSynchronisation::on_request`], received at `now`. Returns whether
    /// it counted as a valid `C_CS ACT`.
    ///
    /// It counts only when the reaction is [`Reaction::Requested`] (a cause-6
    /// activation with a time to adopt) with `T = 0` **and** the answer to send is a
    /// positive confirmation. A refused activation ([`Reaction::Refused`], the
    /// clause 7.2.3 mirror with `P/N = 1`), a discarded one, one of another
    /// procedure, and an answer the application turned into a negative
    /// confirmation (5-101 clause 7.2.3: *"<1> := negative confirm"*, bit 7 of
    /// the cause of transmission octet) do not count, since the station did
    /// not accept the time.
    pub fn on_outcome(&mut self, outcome: &Outcome, now: Instant) -> bool {
        let Reaction::Requested { test: false, .. } = outcome.reaction else {
            return false;
        };
        let positive = outcome
            .send
            .first()
            .and_then(|answer| answer.get(2))
            .is_some_and(|cause| cause & 0x40 == 0);
        if positive {
            self.synchronised(now);
        }
        positive
    }

    /// Whether a time tag taken at `now` is valid under clause 7.6: a valid
    /// `C_CS ACT` has been received and the agreed interval has not yet passed
    /// since the last one.
    ///
    /// The interval is measured from the last valid `C_CS ACT`; at exactly
    /// `interval` after it the synchronisation is overdue and the tag is
    /// invalid. An instant earlier than the last synchronisation counts as
    /// no time elapsed.
    #[must_use]
    pub fn time_valid(&self, now: Instant) -> bool {
        self.last
            .is_some_and(|last| now.saturating_duration_since(last) < self.interval)
    }

    /// `time` with its `IV` bit set when a time tag taken at `now` is not
    /// valid (see [`TimeValidity::time_valid`]).
    ///
    /// `now` is the instant the time tag was taken, which is when the event
    /// occurred: clause 7.6 sends *"Time-tagged events that occur after the
    /// reception of valid `C_CS` ACT PDU"* without the mark. The bit is only ever
    /// set here, never cleared: a tag the application already marked invalid
    /// stays so.
    #[must_use]
    pub fn mark(&self, time: Cp56Time2a, now: Instant) -> Cp56Time2a {
        Cp56Time2a {
            invalid: time.invalid || !self.time_valid(now),
            ..time
        }
    }

    /// [`TimeValidity::mark`] for the three-octet time tag (5-101 clause
    /// 7.2.6.19), which carries the same `IV` bit.
    #[must_use]
    pub fn mark_short(&self, time: Cp24Time2a, now: Instant) -> Cp24Time2a {
        Cp24Time2a {
            invalid: time.invalid || !self.time_valid(now),
            ..time
        }
    }
}

/// The reaction for an ASDU this procedure does not own.
const fn other() -> Outcome {
    Outcome {
        reaction: Reaction::Other,
        send: Vec::new(),
    }
}

/// The time a received type-103 ASDU carries, or `None` when it carries no
/// information object at all (clause 7.2.2's `N = 0`).
fn time_of(asdu: &[u8], sizes: AddressSizes) -> Result<Option<Cp56Time2a>, CsError> {
    Ok(decode_asdu_with::<CCsNa1>(asdu, sizes)?
        .first()
        .map(|object| object.value.time))
}
