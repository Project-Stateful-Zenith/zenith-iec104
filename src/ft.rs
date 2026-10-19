//! The file-transfer procedure: 5-104 clause **7.11** with 5-101 clause
//! **7.4.11** as the selection, and the eight ASDUs that 5-101 clause 7.3.6 plus
//! 5-104 clause 8.9 give it.
//!
//! # Clause 7.11's table names families, not types
//!
//! 5-104 clause **7.11** (PDF page index 72, printed page 71) is headed *"File
//! transfer (6.12 of IEC 60870-5-5) Control and monitor direction"* and its table
//! rows are, verbatim and in order:
//!
//! ```text
//! A_CALL_DIRECTORY.req  send     F_SC      A_DIRECTORY.req      send     F_DR
//! A_CALL_DIRECTORY.ind  receive  F_SC      A_DIRECTORY.ind      receive  F_DR
//! A_CALL_DIRECTORY.res  send     F_DR      A_SELECT_FILE.req    send     F_SC
//! A_CALL_DIRECTORY.con  receive  F_DR      A_FILE_READY.req     send     F_FR
//! A_CALL_FILE.req       send     F_SC      A_SECTION1_READY.req send     F_SR
//! A_CALL_SECTION1.req   send     F_SC      A_SEGMENT1.req       send     F_SG
//! A_LAST_SEGMENT.req    send     F_LS      A_ACK_SECTION1.req   send     F_AF
//! A_SECTIONm_READY.req  send     F_SR      A_ACK_FILE.req       send     F_AF
//! A_LAST_SECTION.req    send     F_LS
//! ```
//!
//! The ASDU-label column is a **family**, never a type number. The types are
//! 5-101 clause 7.3.6's and 5-104 clause 8.9's: `F_SC` is `<122>` [`FScNa1`],
//! `F_FR` is `<120>` [`FFrNa1`], `F_SR` is `<121>` [`FSrNa1`], `F_SG` is `<125>`
//! ([`Segment`]), `F_LS` is `<123>` [`FLsNa1`], `F_AF` is `<124>` [`FAfNa1`],
//! `F_DR` is `<126>` [`FDrTa1`]. 104's Table 6 (index 52) adds `<127>`
//! `F_SC_NB_1` (clause 8.9, figure 31, index 92), the `QueryLog`, which 5-101
//! leaves inside its `<120..127>` range but never defines.
//!
//! # The session is the caller's
//!
//! The exchange runs: call directory (`F_SC`, `SCQ` = `<0>`), directory
//! (`F_DR`, `SQ = 1`, `j` files); select file (`SCQ` `<1>`) → file ready
//! (`F_FR`); call file (`SCQ` `<2>`) → section ready (`F_SR`); call section
//! (`SCQ` `<6>`) → a number of segments (`F_SG`) → last segment (`F_LS` with
//! `LSQ` `<3>`/`<4>` and the section's `CHS`) → acknowledge section (`F_AF`,
//! `AFQ` `<3>`/`<4>`) → … → last section (`F_LS`, `LSQ` `<1>`/`<2>`) →
//! acknowledge file (`F_AF`, `AFQ` `<1>`/`<2>`). **Which section is in flight,
//! how many segments are left and what is buffered is the caller's.**
//! [`FileTransferProcedure`] holds the role, the two-direction [`Selection`] and
//! the addressing and nothing else, and [`FileTransferProcedure::on_answer`]
//! takes the request this station sent as an argument, as
//! [`crate::ts::TestProcedure::on_response`] takes the sent command. There is
//! no clock, timer, queue or schedule in this module.
//!
//! # Two directions, selected per station
//!
//! 5-104 clause **9.6** (index 114, printed page 113) carries the row *"File
//! transfer (station-specific parameter, mark \"X\" if function is used). File
//! transfer in monitor direction / File transfer in control direction /
//! Background scan (sta…)"*: **two checkboxes**, monitor and control. So
//! [`Selection`] has two named booleans, in [`crate::tx::StationFunctions`]'
//! shape, and which of the two a frame belongs to is decided by **who sends
//! it**, not by its type:
//!
//! * `F_SC` (a request), `F_AF` (an acknowledgement) and `F_SC_NB` (the
//!   `QueryLog`) are sent by the side that *asks for* or *receives* the file
//!   ([`Frame::is_receiver_side`]). In the monitor direction that is the
//!   controlling station; in the control direction it is the controlled one.
//! * `F_FR`, `F_SR`, `F_SG`, `F_LS` and `F_DR` are sent by the side that
//!   *provides* the file, which is the other one.
//!
//! This matches TS 60870-5-604: `5.4.23.1` (index 84, monitor direction) has
//! the controlling station sending the `ASDU 122` requests and the `ASDU 124`
//! acknowledgements and the controlled station sending `120`, `121`, `125`,
//! `123` and `126`; `5.4.23.10` (index 85) is the control-direction mirror
//! image. `5.4.23.15` (index 86) is the `QueryLog` case. No test of this crate
//! drives a second station, so these cases are cited, not executed.
//!
//! A station that has not selected a direction refuses to build that
//! direction's frame ([`FtError::NotSelectedDirection`]), and one that has
//! selected neither refuses the function ([`FtError::FunctionNotUsed`]). An
//! arriving frame of a direction the station does not serve gets the same
//! typed refusal.
//!
//! 5-101 clause **7.4.11** *"Selections from file transfer"* (index 130,
//! printed page 129) is, verbatim in full: *"Options of IEC 60870-5-5, 6.12:
//! `F_SC_NA_1` (Call directory) in the control direction is used. `F_DR_TA_1`
//! (Directory) in monitor direction is used."* Those are the two halves of one
//! directory exchange (the call travels to the controlled station, the
//! directory comes back), which is 604's monitor-direction case. It is not the
//! source of [`Selection`]; 104 clause 9.6's row is.
//!
//! # The APDU ceiling is the only length rule
//!
//! 5-104 index **26** (printed page 25), verbatim: *"The maximum length of the
//! ASDU is limited to 249 because the maximum value of the field length of APDU
//! is 253 (`APDUmax` = 255 minus start and length octet) and the length of the
//! control field is 4 octets."* It limits two things:
//!
//! * one `F_SG_NA_1` object carries at most **236** segment octets
//!   (`249 − 6 − 3 − NOF 2 − NOS 1 − LOS 1`): [`MAX_SEGMENT`], refused by
//!   [`segment`] with [`FtError::SegmentTooLong`];
//! * one `F_DR_TA_1` ASDU carries at most **18** files (`249 = 6 + 3 + 13 j`):
//!   [`MAX_DIRECTORY_FILES`], refused by [`directory`] with
//!   [`FtError::DirectoryTooLarge`].
//!
//! On the read side, a segment whose `LOS` disagrees with the octets present is
//! [`FtError::SegmentLengthMismatch`], one with no octets (`LOS` = 0, *"not
//! used"*, 7.2.6.36) is [`FtError::EmptySegment`], and an `F_DR_TA_1` with
//! more than 18 files is [`FtError::DirectoryTooLarge`]. No path in this module
//! panics on network input.
//!
//! # The checksum
//!
//! `CHS` is 5-101 clause **7.2.6.37** (index 58), verbatim: *"arithmetic sum
//! disregarding overflows (sum modulo 256) over all octets of a section (when
//! used in a last segment PDU) or of a complete file (when used in a last section
//! PDU)"*. [`checksum`] computes it and [`check_checksum`] compares a received
//! one, reporting [`FtError::ChecksumMismatch`]. The crate holds no file, so
//! the octets summed are the caller's; [`segment`] likewise takes the caller's
//! octet slice and writes `LOS` from its length.
//!
//! # The 44 to 47 mirror, and `<127>`'s own cause 44
//!
//! Six of the eight figures print `<13> := file transfer` followed by `<44>`
//! unknown type identification, `<45>` unknown cause of transmission, `<46>`
//! unknown common address of ASDU and `<47>` unknown information object address
//! (5-101 indices 114–119). That is 5-101 clause **7.2.3**'s mirror rule, which
//! [`crate::asdu::mirror_reply`] implements: the received ASDU comes back with
//! `P/N = 1` and the class's cause, its object area copied octet for octet.
//! `F_SC_NA_1` prints those four beside its two request causes (index 116);
//! `F_DR_TA_1` prints only `<3>` and `<5>` (index 120). **104's `<127>` prints
//! `<44> := unknown type of file`** (index 92), the *file* class of clause 8.9
//! rather than clause 7.2.3's *type identification* class, so this module does
//! not treat it as the type class and adds no class of its own for it.
//!
//! A **broadcast** common address is refused by every builder: 5-101 clause
//! 7.2.4 (index 43) permits a broadcast for `C_IC_NA_1`, `C_CI_NA_1`,
//! `C_CS_NA_1` and `C_RP_NA_1` alone. A file-transfer frame that *arrives* at
//! `FF`/`FFFF` at a controlled station is refused with the class-46 mirror, by
//! TS 60870-5-604 **5.4.10.10** (index 54): *"The Controlled station rejects
//! all other ASDU Types with a Broadcast CASDU value by mirroring the ASDU with
//! P/N = 1 negative (and with COT = 46, if supported)"*. A controlling station,
//! which receives in the monitor direction, discards it instead
//! ([`Reaction::Discard`]): only a controlled station sends the causes 44 to 47.
//!
//! # Addressing
//!
//! 5-101 clause **7.4.11.1** (index 131, printed page 130): *"Each file
//! (directory or subdirectory) is unambiguously defined by the combination of
//! the common address of the ASDU and the information object address which
//! includes the name of file as an additional information."* This crate takes
//! both addresses from the caller and never invents either.
//!
//! # Example
//!
//! A directory call, the directory that answers it, and one segment, with the
//! checksum computed and a mismatched one rejected:
//!
//! ```
//! use iec104::asdu::{Cause, Header, Known, Lof, Lsq, Nof, Nos, Scq, Sof, TypeId};
//! use iec104::ft::{
//!     check_checksum, checksum, decode_frame, last_segment, segment, DirectoryEntry,
//!     FileTransferProcedure, Frame, Reaction, Role, Selection,
//! };
//!
//! // The controlling and the controlled station both use the function in the
//! // monitor direction (5-104 cl.9.6's first checkbox).
//! let controlling = FileTransferProcedure::controlling(Selection::MONITOR, 12, 0);
//! let controlled = FileTransferProcedure::controlled(Selection::MONITOR, 12, 0);
//!
//! // A_CALL_DIRECTORY.req: F_SC_NA_1, SCQ = <0> (call directory), cause <5>.
//! let call = controlling
//!     .build(&Frame::Sc { ioa: 1, nof: Nof { value: 1 }, nos: Nos { value: 0 }, scq: Scq::default() })
//!     .unwrap();
//! assert_eq!(Header::parse(&call).unwrap().type_id, TypeId::FScNa1);
//! assert_eq!(Header::parse(&call).unwrap().cause, Cause::Request);
//! assert!(matches!(controlled.on_asdu(&call, &Known::EVERYTHING).unwrap().reaction, Reaction::Requested { .. }));
//!
//! // A_CALL_DIRECTORY.res: the controlled station's directory, SQ = 1.
//! let answer = controlled
//!     .build(&Frame::Directory {
//!         ioa: 1,
//!         cause: Cause::Request,
//!         files: vec![DirectoryEntry { nof: Nof { value: 2 }, lof: Lof { value: 40 }, sof: Sof::default(), time: Default::default() }],
//!     })
//!     .unwrap();
//! assert!(Header::parse(&answer).unwrap().sequence);
//!
//! // A_SEGMENT1.req: the caller holds the octets; this crate does not.
//! let payload = [7u8; 30];
//! let framed = segment(12, 0, 1, Nof { value: 2 }, Nos { value: 1 }, &payload).unwrap();
//! assert!(matches!(decode_frame(&framed).unwrap(), Frame::Segment { .. }));
//! assert_eq!(payload.len(), 30);
//!
//! // CHS: the sum modulo 256 over the section's octets (cl.7.2.6.37).
//! let chs = checksum(&payload);
//! assert_eq!(chs.value, 30 * 7);
//! assert!(check_checksum(&payload[1..], chs).is_err(), "one octet short");
//! let _ = last_segment(12, 0, 1, Nof { value: 2 }, Nos { value: 1 }, Lsq { value: 3 }, chs).unwrap();
//!
//! assert_eq!(controlled.role(), Role::Controlled);
//! assert_eq!(Selection::MONITOR.count(), 1);
//! ```

use crate::asdu::{
    AddressSizes, Afq, AsduError, AsduLayout, Cause, Chs, Cp56Time2a, Discard, FAfNa1, FDrTa1,
    FFrNa1, FLsNa1, FScNa1, FScNb1, FSrNa1, Frq, Header, Known, LayoutError, LayoutObject, Lof,
    Los, Lsq, Nof, Nos, Scq, Segment, Sof, Srq, TypeId, Unspecified, decode_asdu_with,
    decode_segment_with, discard_reason, encode_asdu_with, encode_segment_with, is_mirror,
    mirror_frame,
};

/// The broadcast common address of 5-101 clause 7.2.4 (index 43).
///
/// This is the value for this crate's two-octet common address. The clause's list of the types a broadcast
/// is permitted for is `C_IC_NA_1`, `C_CI_NA_1`, `C_CS_NA_1` and `C_RP_NA_1`
/// alone: **none** of `<120>`–`<127>` is on it.
#[deprecated(
    note = "the broadcast address depends on the common-address width: use AddressSizes::broadcast_common_address"
)]
pub const BROADCAST_CA: u16 = 0xFFFF;

/// The largest segment one `F_SG_NA_1` object may carry with the conventional
/// address sizes.
///
/// 5-104 index 26's 249-octet ASDU less the 6-octet header, the
/// 3-octet information object address and the element's own `NOF`/`NOS`/`LOS`.
/// Re-exported from the layout layer so the two cannot disagree.
pub const MAX_SEGMENT: usize = crate::asdu::MAX_SEGMENT;

/// The largest number of files one `F_DR_TA_1` ASDU may carry with the
/// conventional address sizes: `249 = 6 + 3 + 13 j` leaves 18. Re-exported
/// from the layout layer.
pub const MAX_DIRECTORY_FILES: usize = crate::asdu::MAX_DIRECTORY_FILES;

/// [`MAX_SEGMENT`] for the address sizes `sizes`: a narrower header and
/// address leave room for a longer segment, on both the read and the write
/// path.
#[must_use]
pub fn max_segment(sizes: AddressSizes) -> usize {
    crate::asdu::max_segment_with(sizes)
}

/// [`MAX_DIRECTORY_FILES`] for the address sizes `sizes`.
#[must_use]
pub fn max_directory_files(sizes: AddressSizes) -> usize {
    sizes
        .max_body()
        .saturating_sub(usize::from(sizes.information_object_address_octets()))
        / (Nof::LEN + Lof::LEN + Sof::LEN + Cp56Time2a::LEN)
}

/// `<5>` request: the `F_SC_NA_1` cause for the **call directory** alone
/// (figure 85, index 116: `<5> := request (only for Call Directory)`), and one
/// of `F_DR_TA_1`'s two causes.
pub const CAUSE_REQUEST: Cause = Cause::Request;

/// `<13>` file transfer: the family's cause (figures 83–88, indices 114–119,
/// and 104's figure 31, index 92).
pub const CAUSE_FILE_TRANSFER: Cause = Cause::FileTransfer;

/// `<3>` spontaneous: `F_DR_TA_1`'s first cause (figure 89, index 120:
/// `<3> := spontaneous <5> := requested`).
pub const CAUSE_SPONTANEOUS: Cause = Cause::Spontaneous;

/// `SCQ` action `<0>` of 5-101 clause 7.2.6.30: the **call directory** the
/// figure-85 heading names. The other seven action values are constants on
/// [`Scq`].
pub const SCQ_CALL_DIRECTORY: u8 = 0;

/// One `F_DR_TA_1` entry: figure 89's `Name of file or subdirectory`, `Length of
/// file`, `Status of file` and `CP56Time2a`, 13 octets.
///
/// Figure 89's file *i* belongs to information object address `A + i − 1`, which
/// is exactly what the body cursor's SQ = 1 arithmetic produces, so a
/// [`Frame::Directory`] holds only the base information object address once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// `NOF`: name of file or subdirectory (7.2.6.33).
    pub nof: Nof,
    /// `LOF`: length of file in octets (7.2.6.35).
    pub lof: Lof,
    /// `SOF`: status of file (7.2.6.38); `FOR` says whether the name is a file
    /// or a subdirectory and `LFD` whether this is the directory's last entry.
    pub sof: Sof,
    /// `CP56Time2a`: creation time of the file, or the time of the most recent
    /// change for a subdirectory (cl.7.4.11.1, index 131).
    pub time: Cp56Time2a,
}

/// One decoded file-transfer ASDU, as a value, and the input of every builder.
///
/// The variant is the *family* clause 7.11's ASDU-label column names; the type
/// identification is [`Frame::type_id`]. Every field is an argument: nothing
/// here is derived from a file, a clock or a station's configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// `F_SC_NA_1` `<122>`, figure 85 (index 116): the call directory
    /// (`SCQ` action `<0>`, cause `<5>`) and the select/call/abort requests
    /// (`SCQ` action `<1>`…`<7>`, cause `<13>`).
    Sc {
        /// Information object address (`UI24`).
        ioa: u32,
        /// `NOF`: name of file.
        nof: Nof,
        /// `NOS`: name of section.
        nos: Nos,
        /// `SCQ`: the action and the error code.
        scq: Scq,
    },
    /// `F_FR_NA_1` `<120>`, figure 83 (index 114).
    FileReady {
        /// Information object address.
        ioa: u32,
        /// `NOF`: name of file.
        nof: Nof,
        /// `LOF`: length of file.
        lof: Lof,
        /// `FRQ`: file ready qualifier.
        frq: Frq,
    },
    /// `F_SR_NA_1` `<121>`, figure 84 (index 115).
    SectionReady {
        /// Information object address.
        ioa: u32,
        /// `NOF`: name of file.
        nof: Nof,
        /// `NOS`: name of section.
        nos: Nos,
        /// `LOF`: length of the section. Figure 84's *"Length of section"* is
        /// `LOF` (7.2.6.35, three octets), not `LOS`, so the element is seven
        /// octets.
        lof: Lof,
        /// `SRQ`: section ready qualifier.
        srq: Srq,
    },
    /// `F_SG_NA_1` `<125>`, figure 88 (index 119): the variable-length element.
    Segment {
        /// Information object address.
        ioa: u32,
        /// The `NOF`/`NOS`/`LOS`/`Octet 1 … Octet n` element.
        segment: Segment,
    },
    /// `F_LS_NA_1` `<123>`, figure 86 (index 117).
    LastSection {
        /// Information object address.
        ioa: u32,
        /// `NOF`: name of file.
        nof: Nof,
        /// `NOS`: name of section.
        nos: Nos,
        /// `LSQ`: last section or segment qualifier.
        lsq: Lsq,
        /// `CHS`: checksum over the section or the file (7.2.6.37).
        chs: Chs,
    },
    /// `F_AF_NA_1` `<124>`, figure 87 (index 118).
    Ack {
        /// Information object address.
        ioa: u32,
        /// `NOF`: name of file.
        nof: Nof,
        /// `NOS`: name of section.
        nos: Nos,
        /// `AFQ`: the acknowledgement and the error code.
        afq: Afq,
    },
    /// `F_DR_TA_1` `<126>`, figure 89 (index 120): the sequence form, `j` files.
    Directory {
        /// Information object address of the first file (`A`); file *i* is at
        /// `A + i − 1`.
        ioa: u32,
        /// `<3>` spontaneous or `<5>` requested: the figure's two causes and no
        /// other (index 120).
        cause: Cause,
        /// The files, at most [`max_directory_files`] of them
        /// ([`MAX_DIRECTORY_FILES`] with the conventional address sizes).
        files: Vec<DirectoryEntry>,
    },
    /// `F_SC_NB_1` `<127>`: `QueryLog`, 5-104 clause 8.9, figure 31 (index 92).
    QueryLog {
        /// Information object address.
        ioa: u32,
        /// `NOF`: name of file (7.2.6.33 of 5-101).
        nof: Nof,
        /// `RangeStartTime`; all zeros means "from the beginning" (clause 8.9's
        /// four-row table, index 92).
        range_start: Cp56Time2a,
        /// `RangeStopTime`; all zeros means "to the end".
        range_stop: Cp56Time2a,
    },
}

impl Frame {
    /// The type identification this frame goes on the wire as.
    #[must_use]
    pub const fn type_id(&self) -> TypeId {
        match self {
            Self::Sc { .. } => TypeId::FScNa1,
            Self::FileReady { .. } => TypeId::FFrNa1,
            Self::SectionReady { .. } => TypeId::FSrNa1,
            Self::Segment { .. } => TypeId::FSgNa1,
            Self::LastSection { .. } => TypeId::FLsNa1,
            Self::Ack { .. } => TypeId::FAfNa1,
            Self::Directory { .. } => TypeId::FDrTa1,
            Self::QueryLog { .. } => TypeId::FScNb1,
        }
    }

    /// The clause's cause for this frame: `<5>` for `F_SC_NA_1`'s call directory
    /// and `<13>` for the rest of `F_SC_NA_1` (figure 85, index 116); `<13>` for
    /// `F_FR`/`F_SR`/`F_SG`/`F_LS`/`F_AF` (figures 83–87) and for 104's `<127>`
    /// (index 92); the frame's own `<3>`/`<5>` for `F_DR_TA_1` (figure 89,
    /// index 120).
    #[must_use]
    pub const fn cause(&self) -> Cause {
        match self {
            Self::Sc { scq, .. } => {
                if scq.action == SCQ_CALL_DIRECTORY {
                    CAUSE_REQUEST
                } else {
                    CAUSE_FILE_TRANSFER
                }
            }
            Self::Directory { cause, .. } => *cause,
            _ => CAUSE_FILE_TRANSFER,
        }
    }

    /// Whether the **requesting/receiving** side sends this frame (`F_SC`'s
    /// requests, `F_AF`'s acknowledgements and `F_SC_NB`'s `QueryLog`) rather
    /// than the **providing** side (`F_FR`, `F_SR`, `F_SG`, `F_LS`, `F_DR`).
    ///
    /// In the monitor direction the controlling station is the receiver side
    /// and the controlled one the provider; in the control direction it is the
    /// other way round (604 `5.4.23.1` against `5.4.23.10`, indices 84 and 85).
    #[must_use]
    pub const fn is_receiver_side(&self) -> bool {
        matches!(
            self,
            Self::Sc { .. } | Self::Ack { .. } | Self::QueryLog { .. }
        )
    }

    /// The information object address this frame carries.
    #[must_use]
    pub const fn ioa(&self) -> u32 {
        match self {
            Self::Sc { ioa, .. }
            | Self::FileReady { ioa, .. }
            | Self::SectionReady { ioa, .. }
            | Self::Segment { ioa, .. }
            | Self::LastSection { ioa, .. }
            | Self::Ack { ioa, .. }
            | Self::Directory { ioa, .. }
            | Self::QueryLog { ioa, .. } => *ioa,
        }
    }
}

/// Whether `type_id` is one of the eight file-transfer types, over the **wire
/// octet** so an unnamed [`TypeId::Other`] of 120 … 127 answers as the named
/// variant does.
#[must_use]
pub const fn is_file_type(type_id: TypeId) -> bool {
    matches!(type_id.to_u8(), 120..=127)
}

/// One side of the file transfer: the *procedure's* role, not the transport's.
///
/// 104 clause 7 makes the TCP client the controlling station, but the same
/// station may hold the other role's instance for the reverse direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The station that initiates file transfers: it sends the `F_SC` requests
    /// and the `F_AF` acknowledgements in the monitor direction, and provides the
    /// file in the control direction.
    Controlling,
    /// The station that serves them: it provides the file in the monitor
    /// direction and sends the requests and acknowledgements in the control
    /// direction.
    Controlled,
}

/// The other role: the one a received frame came from.
const fn other(role: Role) -> Role {
    match role {
        Role::Controlling => Role::Controlled,
        Role::Controlled => Role::Controlling,
    }
}

/// Which cl.9.6 direction a frame sent by `role` belongs to.
///
/// The **receiver side** (`F_SC`, `F_AF`, `F_SC_NB`) is the controlling station
/// in the monitor direction and the controlled one in the control direction;
/// the **providing** side is the other one (604's `5.4.23.1`, index 84, and
/// `5.4.23.10`, index 85).
const fn direction_of(role: Role, frame: &Frame) -> crate::asdu::Direction {
    direction_for(role, frame.is_receiver_side())
}

/// [`direction_of`] over the one bit it uses, so a frame whose only decoded
/// part is its header (a mirror, which cannot be decoded) can be placed too.
const fn direction_for(role: Role, receiver_side: bool) -> crate::asdu::Direction {
    match (role, receiver_side) {
        (Role::Controlling, true) | (Role::Controlled, false) => crate::asdu::Direction::Monitor,
        (Role::Controlling, false) | (Role::Controlled, true) => crate::asdu::Direction::Control,
    }
}

/// [`Frame::is_receiver_side`] over the wire octet: `true` for `F_SC` `<122>`,
/// `F_AF` `<124>` and `F_SC_NB` `<127>`, `false` for the other five, `None`
/// for a type outside the family.
const fn family_is_receiver_side(type_id: TypeId) -> Option<bool> {
    match type_id.to_u8() {
        122 | 124 | 127 => Some(true),
        120 | 121 | 123 | 125 | 126 => Some(false),
        _ => None,
    }
}

/// Which of the two 5-104 clause 9.6 file-transfer checkboxes a station has
/// marked.
///
/// It has [`crate::tx::StationFunctions`]' shape: named constants, a
/// `with(…)` builder, a `count()` and a `Default` that selects nothing.
///
/// The clause's row is *"File transfer (station-specific parameter, mark \"X\" if
/// function is used). File transfer in monitor direction / File transfer in
/// control direction"* (index 114, printed page 113): two boxes, not one flag.
/// 5-101 clause 7.4.11 names the directory exchange those directions carry,
/// not further selections (see the module doc).
///
/// A station that has marked neither refuses to build either direction's frame
/// ([`FtError::FunctionNotUsed`]); one that has marked a single direction
/// ([`Selection::MONITOR`] or [`Selection::CONTROL`]) refuses the other
/// ([`FtError::NotSelectedDirection`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    /// The *"File transfer in monitor direction"* checkbox.
    pub monitor: bool,
    /// The *"File transfer in control direction"* checkbox.
    pub control: bool,
}

impl Selection {
    /// Neither checkbox marked: the station refuses to build either direction and
    /// refuses every arriving frame of the family.
    pub const NONE: Self = Self {
        monitor: false,
        control: false,
    };

    /// The monitor-direction box alone: 104 clause 9.6's *"File transfer in
    /// monitor direction"* checkbox (index 114), whose case is 604's
    /// `5.4.23.1` (index 84).
    pub const MONITOR: Self = Self {
        monitor: true,
        control: false,
    };

    /// The control-direction box alone: 104 clause 9.6's *"File transfer in
    /// control direction"* checkbox (index 114), whose case is 604's
    /// `5.4.23.10` (index 85).
    pub const CONTROL: Self = Self {
        monitor: false,
        control: true,
    };

    /// Both boxes.
    pub const BOTH: Self = Self {
        monitor: true,
        control: true,
    };

    /// Whether the box for `direction` is marked. [`crate::asdu::Direction::Both`]
    /// asks for both boxes, because a station serves a frame in *one* direction
    /// and only the two named boxes have a meaning here.
    #[must_use]
    pub const fn uses(self, direction: crate::asdu::Direction) -> bool {
        match direction {
            crate::asdu::Direction::Monitor => self.monitor,
            crate::asdu::Direction::Control => self.control,
            crate::asdu::Direction::Both => self.monitor && self.control,
        }
    }

    /// The same selection with `direction`'s box set to `used`.
    #[must_use]
    pub const fn with(self, direction: crate::asdu::Direction, used: bool) -> Self {
        match direction {
            crate::asdu::Direction::Monitor => Self {
                monitor: used,
                ..self
            },
            crate::asdu::Direction::Control => Self {
                control: used,
                ..self
            },
            crate::asdu::Direction::Both => Self {
                monitor: used,
                control: used,
            },
        }
    }

    /// How many boxes are marked, `0..=2`.
    #[must_use]
    pub fn count(self) -> u8 {
        u8::from(self.monitor).saturating_add(u8::from(self.control))
    }

    /// Whether any box is marked (104 clause 9.6's *"if function is used"*).
    #[must_use]
    pub fn uses_function(self) -> bool {
        self.count() > 0
    }
}

impl Default for Selection {
    /// [`Selection::NONE`]: a station that has not said it uses file transfer
    /// does not.
    fn default() -> Self {
        Self::NONE
    }
}

/// What can go wrong in this layer, over and above the codec's own errors.
///
/// Every variant names a rule of the standard that the call would have broken. A
/// refusal the standard defines as a *frame* is not an error: the 44–47 mirror is
/// [`Outcome::send`]'s frame and [`Reaction::Refused`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FtError {
    /// The station has not marked either 5-104 clause 9.6 checkbox, so it does
    /// not run the function: it builds nothing, and an arriving frame that is
    /// not mirrored or discarded first (see [`FileTransferProcedure::on_asdu`])
    /// is refused with this error.
    FunctionNotUsed,
    /// The frame's direction is not one this station selected: only the other
    /// of 5-104 clause 9.6's two boxes is marked.
    NotSelectedDirection {
        /// The direction the frame belongs to.
        direction: crate::asdu::Direction,
    },
    /// The type identification is not a file-transfer one (`<120>`–`<127>`).
    NotThisType {
        /// The type identification the frame carried.
        type_id: TypeId,
    },
    /// The frame's cause of transmission is not one its figure or 5-104's table
    /// lists for that type: figure 85's `<5>` for the call
    /// directory and `<13>` for every other `F_SC_NA_1` (index 116), `<13>` for
    /// `F_FR`/`F_SR`/`F_SG`/`F_LS`/`F_AF` and 104's `<127>` (indices 114–119 and
    /// 92), `<3>`/`<5>` for `F_DR_TA_1` (index 120).
    CauseNotListed {
        /// The type identification the frame carried.
        type_id: TypeId,
        /// The cause it carried.
        cause: Cause,
    },
    /// The common address is the broadcast address `FF`/`FFFF`, which 5-101
    /// clause 7.2.4 (index 43) restricts to `C_IC_NA_1`, `C_CI_NA_1`,
    /// `C_CS_NA_1` and `C_RP_NA_1`; none of `<120>`–`<127>` is on that list.
    /// Returned by the builders; a broadcast frame that *arrives* is refused
    /// with the class-46 mirror instead.
    BroadcastAddress {
        /// The common address offered.
        common_address: u16,
    },
    /// A segment longer than the APDU can carry: more than [`max_segment`]
    /// octets for the address sizes in use ([`MAX_SEGMENT`] conventionally),
    /// from 5-104 index 26's 249-octet ASDU.
    SegmentTooLong {
        /// The segment length offered or received.
        len: usize,
        /// The limit that applied.
        max: usize,
    },
    /// A received segment states one length in `LOS` and carries another number
    /// of octets. `LOS` `<1..n>` is the *"number of octets of the segment"*
    /// (7.2.6.36, index 58), so the two must agree.
    SegmentLengthMismatch {
        /// The length `LOS` states.
        stated: usize,
        /// The octets actually present.
        present: usize,
    },
    /// A segment with no octets at all: `LOS` = 0 is *"<0> := not used"*
    /// (7.2.6.36, index 58), so a zero-length segment is the absence of one and
    /// not an empty one to carry. Refused on the write and on the read path
    /// alike.
    EmptySegment,
    /// An `F_DR_TA_1` with more files than the 249-octet ASDU can hold
    /// ([`max_directory_files`]; [`MAX_DIRECTORY_FILES`] conventionally).
    DirectoryTooLarge {
        /// The number of files offered or received.
        count: usize,
        /// The limit that applied.
        max: usize,
    },
    /// A checksum that does not add up: 5-101 clause 7.2.6.37's *"arithmetic sum
    /// disregarding overflows"* over the octets the caller states, against the
    /// `CHS` the frame carried. Whether the station logs it, asks for the
    /// section again or drops the transfer is the application's decision.
    ChecksumMismatch {
        /// The sum over the octets the caller handed over.
        expected: Chs,
        /// The `CHS` the frame carried.
        got: Chs,
    },
    /// The arriving frame is not the answer to the request this station sent:
    /// another information object address, another name of file where both
    /// frames carry one, or another name of section where the request named
    /// one. See [`FileTransferProcedure::on_answer`].
    EchoMismatch {
        /// The request this station sent.
        expected: Frame,
        /// The frame that arrived.
        got: Frame,
    },
    /// The ASDU itself could not be parsed. The codec's and the layout layer's
    /// errors, unchanged: a short prefix of any length, a sequence where the
    /// figure says `SQ = 0`, or an object area that is not consumed exactly.
    Layout(LayoutError),
}

impl From<LayoutError> for FtError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<AsduError> for FtError {
    fn from(err: AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// What one received frame means to the station that received it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reaction {
    /// A frame of the **requesting/receiving** side arrived (`F_SC`'s requests,
    /// `F_AF`'s acknowledgements, `F_SC_NB`'s QueryLog): the peer asks this
    /// station to serve, or tells it that what it sent has arrived.
    Requested {
        /// The frame that arrived.
        frame: Frame,
    },
    /// A frame of the **providing** side arrived (`F_FR`, `F_SR`, `F_SG`,
    /// `F_LS`, `F_DR`): the peer offers part of the file, as *its answer* to
    /// a request this station sent.
    Answered {
        /// The frame that arrived.
        frame: Frame,
    },
    /// A 5-101 clause 7.2.3 refusal, a mirror with `P/N = 1` and one of the
    /// four causes 44 to 47. Two cases land here:
    ///
    /// * an arriving **mirror of a frame this station sent** is the peer's
    ///   refusal of a field in it; nothing is sent back;
    /// * an arriving frame with a field this station does not know is refused
    ///   by this station, and the mirror goes out in [`Outcome::send`].
    Refused {
        /// The class's cause: 44, 45, 46 or 47.
        cause: Cause,
    },
    /// Clause 7.2.3 says this ASDU is discarded and may be logged.
    Discard(Discard),
    /// Not this procedure: the type is not one of `<120>`–`<127>`.
    Other,
}

/// What a received ASDU means, and what to send because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The classification of the received ASDU.
    pub reaction: Reaction,
    /// The ASDUs to send, in order. Empty except for the 44–47 mirror of a frame
    /// this station refuses, which is clause 7.2.3's own reply.
    pub send: Vec<Vec<u8>>,
}

/// One role's file transfer.
///
/// The state is the role, the [`Selection`] and the addressing, nothing else.
/// Which section is in flight, how many segments are left, what is buffered and
/// which request is outstanding is the caller's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTransferProcedure {
    role: Role,
    selection: Selection,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
}

impl FileTransferProcedure {
    /// A controlling station's instance: its clause 9.6 selection and the
    /// addressing its frames carry.
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

    /// A controlled station's instance.
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

    /// The station's two clause 9.6 checkboxes.
    #[must_use]
    pub const fn selection(&self) -> Selection {
        self.selection
    }

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// Builds one frame of this station's direction (see [`encode_frame`]).
    ///
    /// The gate is the two cl.9.6 checkboxes: a station with neither marked gets
    /// [`FtError::FunctionNotUsed`], one that serves the other direction gets
    /// [`FtError::NotSelectedDirection`]. The frame's direction follows from
    /// this station's role and [`Frame::is_receiver_side`] (who sends it, not
    /// what type it is).
    ///
    /// # Errors
    ///
    /// Returns [`FtError::FunctionNotUsed`] when neither box is marked,
    /// [`FtError::NotSelectedDirection`] when the frame's direction is not one this station
    /// serves, or [`encode_frame_with`]'s error for the frame.
    pub fn build(&self, frame: &Frame) -> Result<Vec<u8>, FtError> {
        let direction = direction_of(self.role, frame);
        if !self.selection.uses_function() {
            return Err(FtError::FunctionNotUsed);
        }
        if !self.selection.uses(direction) {
            return Err(FtError::NotSelectedDirection { direction });
        }
        encode_frame_with(self.ca, self.org, frame, self.sizes)
    }

    /// This station's decision for one received ASDU.
    ///
    /// The arriving frame was sent by the counterpart, in the other role, and
    /// its direction follows from that. A type outside `<120>`–`<127>` is
    /// [`Reaction::Other`]; for the family, in this order:
    ///
    /// 1. **A mirrored frame** (`P/N = 1` with one of the causes 44 to 47) whose
    ///    type is one **this station sends** in a direction it serves is the
    ///    peer's refusal of what this station sent: [`Reaction::Refused`] with
    ///    the class's cause and nothing to send, as [`crate::ts`] reads a
    ///    mirrored command. Any other mirror (a family the station serves in the
    ///    other direction, or a station that does not run the function) is
    ///    clause 7.2.3's discard, [`Discard::Mirror`], so two stations cannot
    ///    mirror each other. Only the header is read: a mirror is not a frame
    ///    to decode.
    /// 2. **A broadcast frame** is refused with the class-46 mirror in
    ///    [`Outcome::send`] whatever the caller's [`Known`] says (TS 60870-5-604
    ///    5.4.10.10, index 54), carrying this station's own common address.
    /// 3. **Clause 7.2.3's rule** for a frame with a field the station does not
    ///    know: [`Reaction::Refused`] with the class's cause and the mirror in
    ///    [`Outcome::send`]. Steps 2 and 3 mirror only on a **controlled**
    ///    station, which receives every frame in the control direction whichever
    ///    way the file travels; a controlling station, which receives in the
    ///    monitor direction, [`Reaction::Discard`]s with nothing sent
    ///    (cl.7.2.3; TS 60870-5-604 §5.1: *"only a controlled station is allowed
    ///    to send these COT"*).
    /// 4. **Otherwise** the frame is decoded with [`decode_frame`]'s checks, so
    ///    a short prefix of any length is a typed error. A station that marks
    ///    neither box gets [`FtError::FunctionNotUsed`], one that does not serve
    ///    the frame's direction [`FtError::NotSelectedDirection`]. A frame of
    ///    the requesting/receiving side is then [`Reaction::Requested`], one of
    ///    the providing side [`Reaction::Answered`], and [`Outcome::send`] is
    ///    empty: which frame answers which is the caller's session.
    ///
    /// # Errors
    ///
    /// Returns [`FtError::Layout`] when the header cannot be parsed; for a family frame that is
    /// neither a mirror nor refused, [`decode_frame`]'s errors, [`FtError::FunctionNotUsed`] or
    /// [`FtError::NotSelectedDirection`].
    pub fn on_asdu(&self, asdu: &[u8], known: &Known) -> Result<Outcome, FtError> {
        let header = Header::parse_with(asdu, self.sizes)?;
        if !is_file_type(header.type_id) {
            return Ok(other_outcome());
        }
        if is_mirror(&header) {
            // A mirror of a type this station sends in a direction it serves is
            // the peer's refusal of that frame. Any other mirror is discarded,
            // never answered with a mirror of its own (clause 7.2.3's third
            // log bullet).
            let ours = family_is_receiver_side(header.type_id)
                .map(|receiver_side| direction_for(self.role, receiver_side))
                .is_some_and(|direction| self.selection.uses(direction));
            if ours {
                return Ok(Outcome {
                    reaction: Reaction::Refused {
                        cause: header.cause,
                    },
                    send: Vec::new(),
                });
            }
            return Ok(Outcome {
                reaction: Reaction::Discard(Discard::Mirror),
                send: Vec::new(),
            });
        }
        // Clause 7.2.3 mirrors an ASDU received in the control direction and
        // discards one received in the monitor direction. That is the direction
        // the *frame* travelled, not the file: every frame a controlled station
        // receives came from the controlling station, in the control direction,
        // whichever way the file goes. *"ASDUs in the control direction with
        // undefined values … are mirrored by the controlled station"*, and TS
        // 60870-5-604 §5.1 (index 10): COT 44-47 *"are only defined in Monitor
        // direction (only a controlled station is allowed to send these COT)"*.
        let control_direction = self.role == Role::Controlled;
        if header.common_address == self.sizes.broadcast_common_address() {
            let which = Unspecified::CommonAddress;
            if !control_direction {
                return Ok(Outcome {
                    reaction: Reaction::Discard(Discard::Unspecified(which)),
                    send: Vec::new(),
                });
            }
            return Ok(Outcome {
                reaction: Reaction::Refused {
                    cause: which.cause(),
                },
                send: vec![mirror_frame(&header, asdu, which, self.ca, self.sizes)],
            });
        }
        if let Some(reason) = discard_reason(&header, known) {
            if let (Discard::Unspecified(which), true) = (reason, control_direction) {
                // Clause 7.2.3's table is a control-direction rule: a field the
                // station does not know is *mirrored*, never silently dropped.
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
        let frame = decode_frame_with(asdu, self.sizes)?;
        let direction = direction_of(other(self.role), &frame);
        if !self.selection.uses_function() {
            return Err(FtError::FunctionNotUsed);
        }
        if !self.selection.uses(direction) {
            return Err(FtError::NotSelectedDirection { direction });
        }
        let reaction = if frame.is_receiver_side() {
            Reaction::Requested { frame }
        } else {
            Reaction::Answered { frame }
        };
        Ok(Outcome {
            reaction,
            send: Vec::new(),
        })
    }

    /// [`FileTransferProcedure::on_asdu`] with the **request this station sent** as
    /// the expectation: an [`Reaction::Answered`]'s frame must be the answer to
    /// it, or the finding is [`FtError::EchoMismatch`].
    ///
    /// The caller remembers the transfer, so the sent request is an argument,
    /// as in [`crate::ts::TestProcedure::on_response`]. A requester cannot state
    /// the answer in advance (`F_SR`'s `LOF`/`SRQ`, `F_SG`'s octets and `F_LS`'s
    /// `CHS` are the peer's to fill in), so only what the request asked for is
    /// compared: always the information object address; the `NOF` when both
    /// frames carry one; and the `NOS` only when the request **names a
    /// section**, which is `F_SC`'s `SCQ` action `<6>` (`A_CALL_SECTION`) alone.
    /// A call file is answered by the *first* section ready, and an
    /// acknowledgement of section *m* by section *m + 1* ready or by the last
    /// section (clause 7.4.11's transfer figures, indices 131–133), so their
    /// section is the peer's to choose.
    ///
    /// # Errors
    ///
    /// Returns [`FileTransferProcedure::on_asdu`]'s errors, and [`FtError::EchoMismatch`] when
    /// an answered frame does not answer `sent`.
    pub fn on_answer(&self, asdu: &[u8], known: &Known, sent: &Frame) -> Result<Outcome, FtError> {
        let outcome = self.on_asdu(asdu, known)?;
        if let Reaction::Answered { frame } = &outcome.reaction
            && !answers(sent, frame)
        {
            return Err(FtError::EchoMismatch {
                expected: sent.clone(),
                got: frame.clone(),
            });
        }
        Ok(outcome)
    }
}

/// Whether `answered` is the answer to the request `sent`: always the same
/// information object address, the same `NOF` when **both** frames carry one,
/// and the same `NOS` when the request asked for one section **by name** (see
/// [`requested_section`]).
///
/// `F_DR` (figure 89) has no single `NOF` or `NOS`, since its element carries
/// one per file, so a directory is compared by address alone, which is what a
/// call directory or a `QueryLog` asks about. `F_FR` has a `NOF` and no `NOS`, so
/// a select file is checked down to the file's name.
fn answers(sent: &Frame, answered: &Frame) -> bool {
    if sent.ioa() != answered.ioa() {
        return false;
    }
    if let (Some(sent_nof), Some(answered_nof)) = (nof_of(sent), nof_of(answered))
        && sent_nof != answered_nof
    {
        return false;
    }
    if let Some(sent_nos) = requested_section(sent)
        && let Some(answered_nos) = nos_of(answered)
        && sent_nos != answered_nos
    {
        return false;
    }
    true
}

/// The `NOS` a request names, when it names one: only `F_SC_NA_1`'s `SCQ`
/// action `<6>` (`A_CALL_SECTION`, 5-101 clause 7.2.6.30) asks for one section
/// by its own name.
///
/// `A_CALL_FILE.req` (`SCQ` `<2>`) is answered by the file's *first* section
/// (`A_SECTION1_READY.req`, clause 7.4.11's exchange, index 131), and
/// `A_ACK_SECTIONm.req` (`F_AF`, `AFQ` `<3>`) by `A_SECTION(m+1)_READY.req` or
/// by `A_LAST_SECTION.req` (indices 132-133). A call directory and a select
/// file ask for no section at all.
const fn requested_section(frame: &Frame) -> Option<Nos> {
    match frame {
        Frame::Sc { nos, scq, .. } if scq.action == Scq::REQUEST_SECTION => Some(*nos),
        _ => None,
    }
}

/// The `NOF` a frame carries, or `None` for the one frame that carries one per
/// file ([`Frame::Directory`]).
const fn nof_of(frame: &Frame) -> Option<Nof> {
    match frame {
        Frame::Sc { nof, .. }
        | Frame::FileReady { nof, .. }
        | Frame::SectionReady { nof, .. }
        | Frame::LastSection { nof, .. }
        | Frame::Ack { nof, .. }
        | Frame::QueryLog { nof, .. } => Some(*nof),
        Frame::Segment { segment, .. } => Some(segment.nof),
        Frame::Directory { .. } => None,
    }
}

/// The `NOS` a frame carries, or `None` for the three that have none
/// (`F_FR`, `F_DR`, `F_SC_NB`).
const fn nos_of(frame: &Frame) -> Option<Nos> {
    match frame {
        Frame::Sc { nos, .. }
        | Frame::SectionReady { nos, .. }
        | Frame::LastSection { nos, .. }
        | Frame::Ack { nos, .. } => Some(*nos),
        Frame::Segment { segment, .. } => Some(segment.nos),
        Frame::FileReady { .. } | Frame::Directory { .. } | Frame::QueryLog { .. } => None,
    }
}

/// `CHS`: the checksum of 5-101 clause 7.2.6.37 (index 58).
///
/// The clause, verbatim: *"arithmetic sum
/// disregarding overflows (sum modulo 256) over all octets of a section (when
/// used in a last segment PDU) or of a complete file (when used in a last section
/// PDU)"*.
///
/// This crate holds no file, so the caller passes the octets: the section's
/// for a last segment, the whole file's for a last section.
#[must_use]
pub fn checksum(octets: &[u8]) -> Chs {
    Chs {
        value: octets
            .iter()
            .fold(0u8, |sum, octet| sum.wrapping_add(*octet)),
    }
}

/// Compares a received `CHS` with clause 7.2.6.37's sum over `octets`.
///
/// A mismatch is [`FtError::ChecksumMismatch`], for the application to act on.
///
/// # Errors
///
/// Returns [`FtError::ChecksumMismatch`] when `stated` is not the sum over `octets`.
pub fn check_checksum(octets: &[u8], stated: Chs) -> Result<(), FtError> {
    let expected = checksum(octets);
    if expected != stated {
        return Err(FtError::ChecksumMismatch {
            expected,
            got: stated,
        });
    }
    Ok(())
}

/// Builds the call directory, `A_CALL_DIRECTORY.req`.
///
/// This is clause 7.11's first row (index 72): `F_SC_NA_1` `<122>` with `SCQ`
/// action `<0>` (the figure-85 default and the heading's "Call directory") and
/// cause `<5> := request (only for Call Directory)` (figure 85, index 116).
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn call_directory(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
) -> Result<Vec<u8>, FtError> {
    encode_frame(
        common_address,
        originator,
        &Frame::Sc {
            ioa,
            nof,
            nos: Nos { value: 0 },
            scq: Scq {
                action: SCQ_CALL_DIRECTORY,
                error: 0,
            },
        },
    )
}

/// Builds one `F_SC_NA_1` `<122>` request with an explicit `SCQ` action.
///
/// The cause is `<13> := file transfer (all except for Call Directory)` (figure
/// 85, index 116): the select/call/abort family of clause 7.11's rows, whose `SCQ`
/// values are 5-101 clause 7.2.6.30's (`<1>` select file, `<2>` request file,
/// `<3>` deactivate file, `<4>` delete file, `<5>` select section, `<6>` request
/// section, `<7>` deactivate section).
///
/// An `scq` whose action is `<0>` is the **call directory** and is built with
/// cause `<5>` by [`call_directory`]; this function refuses it with
/// [`FtError::CauseNotListed`] rather than building a call directory under cause
/// `<13>`.
///
/// # Errors
///
/// Returns [`FtError::CauseNotListed`] when `scq`'s action is `<0>` (call directory), otherwise
/// [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common address,
/// or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn sc(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    nos: Nos,
    scq: Scq,
) -> Result<Vec<u8>, FtError> {
    if scq.action == SCQ_CALL_DIRECTORY {
        return Err(FtError::CauseNotListed {
            type_id: TypeId::FScNa1,
            cause: CAUSE_FILE_TRANSFER,
        });
    }
    encode_frame(
        common_address,
        originator,
        &Frame::Sc { ioa, nof, nos, scq },
    )
}

/// Builds `A_SELECT_FILE.req`: `F_SC_NA_1` with `SCQ` action `<1>`, cause
/// `<13>`.
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn select_file(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    nos: Nos,
) -> Result<Vec<u8>, FtError> {
    sc(
        common_address,
        originator,
        ioa,
        nof,
        nos,
        Scq {
            action: Scq::SELECT_FILE,
            error: 0,
        },
    )
}

/// Builds `A_CALL_FILE.req`: `F_SC_NA_1` with `SCQ` action `<2>`, cause `<13>`.
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn call_file(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    nos: Nos,
) -> Result<Vec<u8>, FtError> {
    sc(
        common_address,
        originator,
        ioa,
        nof,
        nos,
        Scq {
            action: Scq::REQUEST_FILE,
            error: 0,
        },
    )
}

/// Builds `A_CALL_SECTION.req`: `F_SC_NA_1` with `SCQ` action `<6>`, cause
/// `<13>`.
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn call_section(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    nos: Nos,
) -> Result<Vec<u8>, FtError> {
    sc(
        common_address,
        originator,
        ioa,
        nof,
        nos,
        Scq {
            action: Scq::REQUEST_SECTION,
            error: 0,
        },
    )
}

/// Builds one `F_FR_NA_1` `<120>` (`A_FILE_READY`, figure 83, index 114).
///
/// It carries the caller's file name, file length and `FRQ` (whose bit 8 is the
/// positive/negative confirm of *select*), with cause `<13> := file transfer`.
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn file_ready(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    lof: Lof,
    frq: Frq,
) -> Result<Vec<u8>, FtError> {
    encode_frame(
        common_address,
        originator,
        &Frame::FileReady { ioa, nof, lof, frq },
    )
}

/// Builds one `F_SR_NA_1` `<121>` (`A_SECTION_READY`, figure 84, index 115)
/// with cause `<13> := file transfer`.
///
/// The element is seven octets: figure 84's *"Length of section"* is `LOF` of
/// clause 7.2.6.35, three octets, not `LOS`.
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn section_ready(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    nos: Nos,
    lof: Lof,
    srq: Srq,
) -> Result<Vec<u8>, FtError> {
    encode_frame(
        common_address,
        originator,
        &Frame::SectionReady {
            ioa,
            nof,
            nos,
            lof,
            srq,
        },
    )
}

/// Builds one `F_SG_NA_1` `<125>` (`A_SEGMENTn.req`, figure 88, index 119)
/// from the **caller's** octets, with cause `<13> := file transfer`.
///
/// `LOS` is written from the slice's own length, so a caller cannot state a
/// length other than the octets it hands over; an empty slice is
/// [`FtError::EmptySegment`] (`LOS` = 0 is *"<0> := not used"*, 7.2.6.36) and a
/// slice longer than [`MAX_SEGMENT`] is [`FtError::SegmentTooLong`] rather than
/// an ASDU the APDU cannot carry (5-104 index 26).
///
/// # Errors
///
/// Returns [`FtError::EmptySegment`] for an empty `payload`, [`FtError::SegmentTooLong`] for
/// one longer than [`MAX_SEGMENT`], otherwise [`encode_frame`]'s errors:
/// [`FtError::BroadcastAddress`] for the broadcast common address, or [`FtError::Layout`] when
/// the layout layer refuses the frame.
pub fn segment(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    nos: Nos,
    payload: &[u8],
) -> Result<Vec<u8>, FtError> {
    if payload.is_empty() {
        return Err(FtError::EmptySegment);
    }
    let value = match u8::try_from(payload.len()) {
        Ok(value) if payload.len() <= MAX_SEGMENT => value,
        _ => {
            return Err(FtError::SegmentTooLong {
                len: payload.len(),
                max: MAX_SEGMENT,
            });
        }
    };
    encode_frame(
        common_address,
        originator,
        &Frame::Segment {
            ioa,
            segment: Segment {
                nof,
                nos,
                los: Los { value },
                payload: payload.to_vec(),
            },
        },
    )
}

/// Builds one `F_LS_NA_1` `<123>` (figure 86, index 117).
///
/// That is `A_LAST_SEGMENT.req` with `LSQ` `<3>`/`<4>`, or
/// `A_LAST_SECTION.req` with `LSQ` `<1>`/`<2>`, with cause
/// `<13> := file transfer` and the caller's `CHS` ([`checksum`] computes one).
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn last_segment(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    nos: Nos,
    lsq: Lsq,
    chs: Chs,
) -> Result<Vec<u8>, FtError> {
    encode_frame(
        common_address,
        originator,
        &Frame::LastSection {
            ioa,
            nof,
            nos,
            lsq,
            chs,
        },
    )
}

/// Builds one `F_AF_NA_1` `<124>` (figure 87, index 118).
///
/// That is `A_ACK_FILE.req` with `AFQ` `<1>`/`<2>`, or `A_ACK_SECTION.req`
/// with `AFQ` `<3>`/`<4>`, with cause `<13> := file transfer`. `nos` is the
/// section's name, or `<0>` for a file acknowledgement.
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn ack(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    nos: Nos,
    afq: Afq,
) -> Result<Vec<u8>, FtError> {
    encode_frame(
        common_address,
        originator,
        &Frame::Ack { ioa, nof, nos, afq },
    )
}

/// Builds one `F_DR_TA_1` `<126>` (`A_DIRECTORY.res`, figure 89, index 120)
/// as the family's `SQ = 1` sequence: one base information object address and `j`
/// files at `A + i − 1`.
///
/// `cause` is the figure's own two, `<3> := spontaneous` or `<5> := requested`;
/// anything else is [`FtError::CauseNotListed`]. More than
/// [`MAX_DIRECTORY_FILES`] files do not fit in a 249-octet ASDU and are
/// [`FtError::DirectoryTooLarge`] (5-104 index 26), and a directory with no file
/// at all is [`FtError::Layout`]'s `ObjectCountNotAllowed`. All three checks
/// are [`encode_frame`]'s, so a `Frame::Directory` handed to `encode_frame` or
/// [`FileTransferProcedure::build`] is refused the same way.
///
/// # Errors
///
/// Returns [`FtError::CauseNotListed`] for a cause other than `<3>` or `<5>`,
/// [`FtError::Layout`] for no file, [`FtError::DirectoryTooLarge`] for more than
/// [`MAX_DIRECTORY_FILES`] files, otherwise [`encode_frame`]'s errors:
/// [`FtError::BroadcastAddress`] for the broadcast common address, or [`FtError::Layout`] when
/// the layout layer refuses the frame.
pub fn directory(
    common_address: u16,
    originator: u8,
    ioa: u32,
    cause: Cause,
    files: Vec<DirectoryEntry>,
) -> Result<Vec<u8>, FtError> {
    encode_frame(
        common_address,
        originator,
        &Frame::Directory { ioa, cause, files },
    )
}

/// Builds one `F_SC_NB_1` `<127>` (the `QueryLog`, 5-104 clause 8.9's figure 31,
/// index 92) with cause `<13> := file transfer` and the caller's two
/// `CP56Time2a` range ends.
///
/// All-zero time stamps are legal and mean what figure 31's table says (index 92):
/// `RangeStartTime` zero is "from the beginning", `RangeStopTime` zero is "to the
/// end", and both zero is "all records". The table is a selection the *peer* acts
/// on, so this crate passes the values through and interprets nothing.
///
/// # Errors
///
/// Returns [`encode_frame`]'s errors: [`FtError::BroadcastAddress`] for the broadcast common
/// address, or [`FtError::Layout`] when the layout layer refuses the frame.
pub fn query_log(
    common_address: u16,
    originator: u8,
    ioa: u32,
    nof: Nof,
    range_start: Cp56Time2a,
    range_stop: Cp56Time2a,
) -> Result<Vec<u8>, FtError> {
    encode_frame(
        common_address,
        originator,
        &Frame::QueryLog {
            ioa,
            nof,
            range_start,
            range_stop,
        },
    )
}

/// One [`Frame`] as a complete ASDU, with the clause's own cause, `N` and `SQ`.
///
/// The single encoder behind every builder: each variant is written with the
/// geometry of its figure, the cause [`Frame::cause`] names, `N = 1` and
/// `SQ = 0`, except [`Frame::Directory`], whose figure 89 is `SQ = 1` with
/// `N = j`. The broadcast address is
/// [`FtError::BroadcastAddress`] for every frame of the family, and the
/// length rules of the APDU ceiling are [`FtError::SegmentTooLong`] and
/// [`FtError::DirectoryTooLarge`] before anything is written.
///
/// # Errors
///
/// As [`encode_frame_with`] with the conventional address sizes.
pub fn encode_frame(
    common_address: u16,
    originator: u8,
    frame: &Frame,
) -> Result<Vec<u8>, FtError> {
    encode_frame_with(
        common_address,
        originator,
        frame,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`encode_frame`] in the address sizes `sizes` fixes; the broadcast address
/// is that profile's.
///
/// # Errors
///
/// Returns [`FtError::BroadcastAddress`] for the profile's broadcast common address; for a
/// segment, [`FtError::EmptySegment`] or [`FtError::SegmentTooLong`]; for a directory,
/// [`FtError::CauseNotListed`], [`FtError::Layout`] for no file or
/// [`FtError::DirectoryTooLarge`]; [`FtError::Layout`] when the layout layer refuses the frame.
pub fn encode_frame_with(
    common_address: u16,
    originator: u8,
    frame: &Frame,
    sizes: AddressSizes,
) -> Result<Vec<u8>, FtError> {
    if common_address == sizes.broadcast_common_address() {
        return Err(FtError::BroadcastAddress { common_address });
    }
    let header = Header {
        type_id: frame.type_id(),
        sequence: false,
        count: 1,
        cause: frame.cause(),
        negative: false,
        test: false,
        originator,
        common_address,
    };
    match frame {
        Frame::Sc { ioa, nof, nos, scq } => encode_single(
            &header,
            *ioa,
            FScNa1 {
                nof: *nof,
                nos: *nos,
                scq: *scq,
            },
            sizes,
        ),
        Frame::FileReady { ioa, nof, lof, frq } => encode_single(
            &header,
            *ioa,
            FFrNa1 {
                nof: *nof,
                lof: *lof,
                frq: *frq,
            },
            sizes,
        ),
        Frame::SectionReady {
            ioa,
            nof,
            nos,
            lof,
            srq,
        } => encode_single(
            &header,
            *ioa,
            FSrNa1 {
                nof: *nof,
                nos: *nos,
                lof: *lof,
                srq: *srq,
            },
            sizes,
        ),
        Frame::Segment { ioa, segment } => encode_segment_frame(&header, *ioa, segment, sizes),
        Frame::LastSection {
            ioa,
            nof,
            nos,
            lsq,
            chs,
        } => encode_single(
            &header,
            *ioa,
            FLsNa1 {
                nof: *nof,
                nos: *nos,
                lsq: *lsq,
                chs: *chs,
            },
            sizes,
        ),
        Frame::Ack { ioa, nof, nos, afq } => encode_single(
            &header,
            *ioa,
            FAfNa1 {
                nof: *nof,
                nos: *nos,
                afq: *afq,
            },
            sizes,
        ),
        Frame::Directory { ioa, cause, files } => {
            encode_directory(&header, *ioa, *cause, files, sizes)
        }
        Frame::QueryLog {
            ioa,
            nof,
            range_start,
            range_stop,
        } => encode_single(
            &header,
            *ioa,
            FScNb1 {
                nof: *nof,
                range_start: *range_start,
                range_stop: *range_stop,
            },
            sizes,
        ),
    }
}

/// [`encode_frame_with`] for `F_SG_NA_1`, after the length rules of 5-104 index 26.
fn encode_segment_frame(
    header: &Header,
    ioa: u32,
    segment: &Segment,
    sizes: AddressSizes,
) -> Result<Vec<u8>, FtError> {
    if segment.payload.is_empty() {
        return Err(FtError::EmptySegment);
    }
    if segment.payload.len() > max_segment(sizes) {
        return Err(FtError::SegmentTooLong {
            len: segment.payload.len(),
            max: max_segment(sizes),
        });
    }
    Ok(encode_segment_with(header, ioa, segment, sizes)?)
}

/// One single-object frame (`N = 1`, `SQ = 0`) of the layout `A`.
fn encode_single<A: AsduLayout>(
    header: &Header,
    ioa: u32,
    value: A,
    sizes: AddressSizes,
) -> Result<Vec<u8>, FtError> {
    Ok(encode_asdu_with(
        header,
        &[LayoutObject { ioa, value }],
        sizes,
    )?)
}

/// [`encode_frame_with`] for figure 89's `F_DR_TA_1`: `SQ = 1` with `N = j`.
///
/// `header` is the frame's header; it is sent with `SQ = 1` and `N` the number of
/// files.
fn encode_directory(
    header: &Header,
    ioa: u32,
    cause: Cause,
    files: &[DirectoryEntry],
    sizes: AddressSizes,
) -> Result<Vec<u8>, FtError> {
    if !matches!(cause, CAUSE_SPONTANEOUS | CAUSE_REQUEST) {
        return Err(FtError::CauseNotListed {
            type_id: TypeId::FDrTa1,
            cause,
        });
    }
    if files.is_empty() {
        // Figure 89's element is one file, repeated `j` times; an ASDU
        // with none is clause 7.2.2's "no INFORMATION OBJECT", which is
        // not a directory (and decodes to the same refusal).
        return Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FDrTa1,
            count: 0,
        }));
    }
    let count = match u8::try_from(files.len()) {
        Ok(count) if files.len() <= max_directory_files(sizes) => count,
        _ => {
            return Err(FtError::DirectoryTooLarge {
                count: files.len(),
                max: max_directory_files(sizes),
            });
        }
    };
    let objects: Vec<LayoutObject<FDrTa1>> = files
        .iter()
        .zip(0u32..)
        .map(|(entry, i)| LayoutObject {
            ioa: ioa.wrapping_add(i),
            value: FDrTa1 {
                nof: entry.nof,
                lof: entry.lof,
                sof: entry.sof,
                time: entry.time,
            },
        })
        .collect();
    Ok(encode_asdu_with(
        &Header {
            count,
            sequence: true,
            ..*header
        },
        &objects,
        sizes,
    )?)
}

/// Decodes one file-transfer ASDU into its [`Frame`], enforcing the geometry and
/// the cause each figure prints.
///
/// `F_SG_NA_1` goes through [`decode_segment`](crate::asdu::decode_segment) (its element has no constant
/// length) and everything else through `decode_asdu`; a type outside the family
/// is [`FtError::NotThisType`]. The causes are the figures': `<5>` for the call
/// directory alone and `<13>` for every other `F_SC_NA_1`, `<3>`/`<5>` for
/// `F_DR_TA_1`, `<13>` for the rest.
///
/// The two length rules of 5-104 index 26 are enforced on the way in as well as
/// out: a segment longer than [`MAX_SEGMENT`] is [`FtError::SegmentTooLong`], one
/// whose `LOS` disagrees with the octets present is
/// [`FtError::SegmentLengthMismatch`], and a directory with more than
/// [`MAX_DIRECTORY_FILES`] files is [`FtError::DirectoryTooLarge`]. Every short
/// prefix of every type is a typed error, never a panic.
///
/// # Errors
///
/// As [`decode_frame_with`] with the conventional address sizes.
pub fn decode_frame(asdu: &[u8]) -> Result<Frame, FtError> {
    decode_frame_with(asdu, AddressSizes::CONVENTIONAL)
}

/// [`decode_frame`] in the address sizes `sizes` fixes, with that profile's
/// segment and directory limits ([`max_segment`], [`max_directory_files`]).
///
/// # Errors
///
/// Returns [`FtError::Layout`] for a header or body the layout layer cannot parse or an object
/// count the figure does not allow, [`FtError::NotThisType`] for a type outside the family,
/// [`FtError::CauseNotListed`] for a cause the figure does not print, and for a segment
/// [`FtError::EmptySegment`], [`FtError::SegmentTooLong`] or
/// [`FtError::SegmentLengthMismatch`], for a directory [`FtError::DirectoryTooLarge`].
pub fn decode_frame_with(asdu: &[u8], sizes: AddressSizes) -> Result<Frame, FtError> {
    let header = Header::parse_with(asdu, sizes)?;
    if !is_file_type(header.type_id) {
        return Err(FtError::NotThisType {
            type_id: header.type_id,
        });
    }
    match header.type_id {
        TypeId::FScNa1 => {
            let objects = decode_asdu_with::<FScNa1>(asdu, sizes)?;
            let object = single(&objects, TypeId::FScNa1)?;
            let scq = object.value.scq;
            let expected = if scq.action == SCQ_CALL_DIRECTORY {
                CAUSE_REQUEST
            } else {
                CAUSE_FILE_TRANSFER
            };
            if header.cause != expected {
                return Err(FtError::CauseNotListed {
                    type_id: TypeId::FScNa1,
                    cause: header.cause,
                });
            }
            Ok(Frame::Sc {
                ioa: object.ioa,
                nof: object.value.nof,
                nos: object.value.nos,
                scq,
            })
        }
        TypeId::FFrNa1 => {
            let objects = decode_asdu_with::<FFrNa1>(asdu, sizes)?;
            let object = single(&objects, TypeId::FFrNa1)?;
            require_cause(header.cause, TypeId::FFrNa1, CAUSE_FILE_TRANSFER)?;
            Ok(Frame::FileReady {
                ioa: object.ioa,
                nof: object.value.nof,
                lof: object.value.lof,
                frq: object.value.frq,
            })
        }
        TypeId::FSrNa1 => {
            let objects = decode_asdu_with::<FSrNa1>(asdu, sizes)?;
            let object = single(&objects, TypeId::FSrNa1)?;
            require_cause(header.cause, TypeId::FSrNa1, CAUSE_FILE_TRANSFER)?;
            Ok(Frame::SectionReady {
                ioa: object.ioa,
                nof: object.value.nof,
                nos: object.value.nos,
                lof: object.value.lof,
                srq: object.value.srq,
            })
        }
        TypeId::FSgNa1 => decode_segment_frame(&header, asdu, sizes),
        TypeId::FLsNa1 => {
            let objects = decode_asdu_with::<FLsNa1>(asdu, sizes)?;
            let object = single(&objects, TypeId::FLsNa1)?;
            require_cause(header.cause, TypeId::FLsNa1, CAUSE_FILE_TRANSFER)?;
            Ok(Frame::LastSection {
                ioa: object.ioa,
                nof: object.value.nof,
                nos: object.value.nos,
                lsq: object.value.lsq,
                chs: object.value.chs,
            })
        }
        TypeId::FAfNa1 => {
            let objects = decode_asdu_with::<FAfNa1>(asdu, sizes)?;
            let object = single(&objects, TypeId::FAfNa1)?;
            require_cause(header.cause, TypeId::FAfNa1, CAUSE_FILE_TRANSFER)?;
            Ok(Frame::Ack {
                ioa: object.ioa,
                nof: object.value.nof,
                nos: object.value.nos,
                afq: object.value.afq,
            })
        }
        TypeId::FDrTa1 => decode_directory(&header, asdu, sizes),
        TypeId::FScNb1 => {
            let objects = decode_asdu_with::<FScNb1>(asdu, sizes)?;
            let object = single(&objects, TypeId::FScNb1)?;
            require_cause(header.cause, TypeId::FScNb1, CAUSE_FILE_TRANSFER)?;
            Ok(Frame::QueryLog {
                ioa: object.ioa,
                nof: object.value.nof,
                range_start: object.value.range_start,
                range_stop: object.value.range_stop,
            })
        }
        other => Err(FtError::NotThisType { type_id: other }),
    }
}

/// [`decode_frame_with`] for `F_SG_NA_1`, whose element has no constant length.
fn decode_segment_frame(
    header: &Header,
    asdu: &[u8],
    sizes: AddressSizes,
) -> Result<Frame, FtError> {
    require_cause(header.cause, TypeId::FSgNa1, CAUSE_FILE_TRANSFER)?;
    let object = decode_segment_with(asdu, sizes)?;
    let segment = object.value;
    if segment.payload.is_empty() {
        // `LOS` = 0 is *"<0> := not used"* (7.2.6.36, index 58): there
        // is no segment of no octets to hand on.
        return Err(FtError::EmptySegment);
    }
    if segment.payload.len() > max_segment(sizes) {
        return Err(FtError::SegmentTooLong {
            len: segment.payload.len(),
            max: max_segment(sizes),
        });
    }
    if segment.stated_len() != segment.payload.len() {
        return Err(FtError::SegmentLengthMismatch {
            stated: segment.stated_len(),
            present: segment.payload.len(),
        });
    }
    Ok(Frame::Segment {
        ioa: object.ioa,
        segment,
    })
}

/// [`decode_frame_with`] for figure 89's `F_DR_TA_1`, the family's one `SQ = 1` frame.
fn decode_directory(header: &Header, asdu: &[u8], sizes: AddressSizes) -> Result<Frame, FtError> {
    if !matches!(header.cause, CAUSE_SPONTANEOUS | CAUSE_REQUEST) {
        return Err(FtError::CauseNotListed {
            type_id: TypeId::FDrTa1,
            cause: header.cause,
        });
    }
    if usize::from(header.count) > max_directory_files(sizes) {
        return Err(FtError::DirectoryTooLarge {
            count: usize::from(header.count),
            max: max_directory_files(sizes),
        });
    }
    let objects = decode_asdu_with::<FDrTa1>(asdu, sizes)?;
    let base_ioa = objects.first().map(|object| object.ioa);
    let Some(ioa) = base_ioa else {
        // `N = 0`: clause 7.2.2's "ASDU contains no INFORMATION
        // OBJECT". A directory with no file is not a directory, but
        // there is nothing to index and nothing to invent.
        return Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FDrTa1,
            count: 0,
        }));
    };
    let files = objects
        .into_iter()
        .map(|object| DirectoryEntry {
            nof: object.value.nof,
            lof: object.value.lof,
            sof: object.value.sof,
            time: object.value.time,
        })
        .collect();
    Ok(Frame::Directory {
        ioa,
        cause: header.cause,
        files,
    })
}

/// The one object of a single-object frame, or a typed error for `N = 0` and for
/// `N ≥ 2` (every figure of the family but figure 89 says *"Single information
/// object (SQ = 0)"*).
const fn single<A>(objects: &[LayoutObject<A>], type_id: TypeId) -> Result<LayoutObject<A>, FtError>
where
    A: Copy,
{
    if let [object] = objects {
        return Ok(*object);
    }
    // `N` is one octet, so the low octet is the whole count.
    let [count, ..] = objects.len().to_le_bytes();
    Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
        type_id,
        count,
    }))
}

/// The cause check of one figure: `cause` must be `expected`, or the finding is
/// [`FtError::CauseNotListed`].
fn require_cause(cause: Cause, type_id: TypeId, expected: Cause) -> Result<(), FtError> {
    if cause != expected {
        return Err(FtError::CauseNotListed { type_id, cause });
    }
    Ok(())
}

/// The outcome for an ASDU this procedure does not own.
const fn other_outcome() -> Outcome {
    Outcome {
        reaction: Reaction::Other,
        send: Vec::new(),
    }
}
