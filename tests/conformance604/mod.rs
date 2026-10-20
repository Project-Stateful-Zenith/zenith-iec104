//! The shared half of the TS 60870-5-604:2016 conformance cases.
//!
//! The entry point is `tests/conformance_604.rs`; this directory holds one
//! module per 604 table plus what they share, laid out like
//! `tests/interop/mod.rs`. Its cases are a *second harness* over the crate's
//! primitives, not new protocol code: the DUT is this library, driven in the
//! role the procedure names.
//!
//! # The two roles, and the driver for each
//!
//! - Cases that address the **controlling** station drive the interoperability
//!   harness's [`interop::Station`] against the mock's controlled side,
//!   [`MonitorPeer`], which completes the STARTDT exchange and then puts one
//!   monitor-direction ASDU on the wire. That harness is reused through
//!   `#[path]`, so it is the same driver, not a second one. The station's
//!   verdict for such an ASDU is the crate's clause 7.2.3 monitor-direction
//!   rule, `asdu::unknown::discard_reason`, reached through
//!   [`controlling_discard`].
//! - Cases that address the **controlled** station need the other role, which
//!   the interoperability harness does not have: [`ControlledStation`] is this
//!   library's controlled side on
//!   a real loopback socket (`link::Session` in `Role::Controlled` plus the
//!   application rule [`station_reply`]), and [`Peer`] is the mock *controlling*
//!   station a test drives it with.
//!
//! Nothing here is `src/`: the crate keeps no socket, no thread and no clock,
//! and every wait is a bounded read deadline, as in `tests/interop/mod.rs`.
//!
//! # Direction, and why it is a per-case decision
//!
//! §5.1 (index 10, printed 9) makes the direction part of the test: the
//! reverse direction is tested with the same procedures, the roles of
//! controlling and controlled station swapped, except that COT 44-47 exist
//! only in the monitor direction, so only a controlled station may send them.
//! Every case's doc comment names the
//! role it drives and whether that exception applies.

#![allow(dead_code)]

#[path = "../interop/mod.rs"]
pub mod interop;

pub mod acquisition;
pub mod apps;
pub mod endpoint;
pub mod scripted;
pub mod start_stop;
pub mod table10;
pub mod table11;
pub mod table12;
pub mod table13;
pub mod table14;
pub mod table15;
pub mod table16;
pub mod table17;
pub mod table17_controlling;
pub mod table17_support;
pub mod table18;
pub mod table19;
pub mod table19_controlling;
pub mod table20;
pub mod table21;
pub mod table22;
pub mod table23;
pub mod table24;
pub mod table25;
pub mod table26;

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use iec104::apci::{Apci, Apdu, SeqNo, UFunction};
use iec104::asdu::{
    Cause, Cp56Time2a, Dco, Direction, Discard, DoubleCommandState, FreezeMode, Header, Known, Nof,
    Qcc, Qoc, Qoi, Qrp, Rco, RegulatingStepState, TypeId, discard_reason, element_len,
    mirror_reply, read_ioa,
};
use iec104::framed::Decoder;
use iec104::link::{Action, Role, Session, State};

/// The broadcast common address of the conventional two-octet profile.
const BROADCAST_CA: u16 = iec104::asdu::AddressSizes::CONVENTIONAL.broadcast_common_address();

pub use interop::{deadline, parse_frame};

/// The common address of the station under test (5-101 clause 7.2.4: a station
/// address, never the broadcast `FF`/`FFFF`).
pub const CA: u16 = 1;

/// Originator address the cases' requests carry (5-101 clause 7.2.3).
pub const ORIGINATOR: u8 = 0;

/// The one information object address the station under test holds data for.
/// Everything else is clause 7.2.3's "undefined" address for it: a station's
/// address space is its own data set, not a range the standard fixes.
pub const HELD_IOA: u32 = 0x3000;

/// One ASDU with a chosen type-identification octet, cause octet, common address
/// and information object address, plus one payload octet.
///
/// These are the *octets* the codec negatives are about: an undefined type
/// identification has no layout to build from, so the header is assembled
/// through the header encoder and the address written raw, not through the
/// layout layer.
pub fn asdu(type_id: u8, cause: u8, ca: u16, ioa: u32, payload: u8) -> Vec<u8> {
    asdu_test(type_id, cause, ca, ioa, payload, false)
}

/// The same builder with 5-101 clause 7.2.3's T flag chosen, for 604 `5.4.10.5`'s
/// two rows on the T bit, 0 for an ASDU produced under normal conditions and 1
/// for one produced under test conditions (index 53, `Required` `M` and
/// `Required` `PIXIT` respectively, as the page's `Required` column reads cell
/// by cell).
pub fn asdu_test(type_id: u8, cause: u8, ca: u16, ioa: u32, payload: u8, test: bool) -> Vec<u8> {
    let mut body = Vec::with_capacity(4);
    body.extend_from_slice(&ioa.to_le_bytes()[..3]);
    body.push(payload);
    build_asdu(type_id, cause, ca, test, &body)
}

/// The same builder with the whole information object *area* given as octets
/// (the three-octet information object address plus the element octets the
/// type's layout defines), for the samples that must be well formed on the wire: 604
/// `5.4.10.10`'s four permitted broadcast types carry a `QOI`, a `QCC`, a
/// 7-octet `CP56Time2a` or a `QRP`, not the one-octet stand-in [`asdu`] writes.
///
/// [`asdu`] and [`asdu_test`] are this builder's one-object, one-octet case and
/// keep their signatures: the undefined types and causes of `5.4.10.1` and
/// `5.4.10.5` have no layout to build from, so their samples *are* raw octets.
pub fn asdu_with_body(type_id: u8, cause: u8, ca: u16, body: &[u8]) -> Vec<u8> {
    build_asdu(type_id, cause, ca, false, body)
}

/// The one header encoder behind [`asdu`], [`asdu_test`] and [`asdu_with_body`].
fn build_asdu(type_id: u8, cause: u8, ca: u16, test: bool, body: &[u8]) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::from_u8(type_id),
        sequence: false,
        count: 1,
        cause: Cause::from_u8(cause),
        negative: false,
        test,
        originator: ORIGINATOR,
        common_address: ca,
    };
    let mut out = Vec::with_capacity(Header::LEN + body.len());
    header.encode(&mut out).expect("the header encodes");
    out.extend_from_slice(body);
    out
}

/// The four ASDU types 604 `5.4.10.10` (index 54) permits the broadcast CASDU
/// on: the broadcast common address (`0xFF`, or `0xFFFF` with two octets) is
/// confined to the control direction and to types 100 (interrogation), 101
/// (counter interrogation), 103 (clock synchronisation) and 105 (reset process).
pub const BROADCAST_TYPES: [u8; 4] = [100, 101, 103, 105];

// -------------------------- well-formed samples for the type loops
//
// 604 `5.4.11.1` runs its cases over *every* supported ASDU (the block's NOTE),
// so each sample must be well formed for **its own** type, not for `C_SC_NA_1`.
// 5-101 clause 7.3 fixes each type's element length and the crate carries those
// lengths in `asdu::layout::element_len`; the two helpers below are the
// geometry, and the two cause helpers are 5-101 clause 7.3's cause per type.

/// The segment octets the `<125>` `F_SG_NA_1` sample's `LOS` states. Its
/// element is `NOF` 2 + `NOS` 1 + `LOS` 1 + the segment, so this is the `n` of
/// figure 88's segment octets 1 to n (5-101 clause 7.3.6.6, index 119).
pub const SAMPLE_SEGMENT_LEN: usize = 2;

/// The one `CP56Time2a` sample the loops use where a time tag is required:
/// Friday, 2026-09-25, 12:00:00.000, standard time, genuine and valid: a
/// value 5-101 clause 7.2.6.18's ranges all admit (`day_of_month` 25 is inside
/// `1..=31`, `months` 9 inside `1..=12`). Used for `C_CS_NA_1` `<103>` and
/// written into every time-tag position of a time-tagged sample.
pub const fn sample_time() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 0,
        minutes: 0,
        substituted: false,
        invalid: false,
        hours: 12,
        summer_time: false,
        day_of_month: 25,
        day_of_week: 5,
        months: 9,
        years: 26,
    }
}

/// One well-formed sample's element octets for `type_id`: everything after the
/// three-octet information object address, exactly as 5-101 clause 7.3 fixes it.
///
/// Zero is **not** a value every element accepts, so the zero-filled default is
/// corrected for the two field families a zero fill gets wrong:
///
/// - the four command types whose element carries a command state (`DCO` for
///   `C_DC_NA_1` `<46>` / `C_DC_TA_1` `<59>`, `RCO` for `C_RC_NA_1` `<47>` /
///   `C_RC_TA_1` `<60>`) get `DCS` 1 (OFF) / `RCS` 1 (LOWER), the first
///   *permitted* value of clause 7.2.6.16/.17 (`<0>` and `<3>` are printed "not
///   permitted", and TS 60870-5-604 Table 19 has a 604-conformant controlled
///   station answer such a command with `P/N = 1` rather than accept it);
/// - every time-tagged element gets [`sample_time`] in each of its
///   `CP56Time2a` positions, because an all-zero `CP56Time2a` carries day of
///   month 0 and months 0, outside clause 7.2.6.18's `1..=31` / `1..=12`.
///
/// The four types whose element carries a *qualifier* from a clause's own range
/// are given one: `C_IC_NA_1` `QOI` 20, `C_CI_NA_1` `QCC` 5 (`FRZ = 0`),
/// `C_RP_NA_1` `QRP` 1 (the same values `5.4.10.10`'s permitted-broadcast
/// samples use) and `C_CS_NA_1` the `CP56Time2a` of [`sample_time`].
/// `C_RD_NA_1` `<102>` has no element at all (`element_len` answers `Some(0)`),
/// and `<125>` `F_SG_NA_1`'s element is the variable-length
/// [`SAMPLE_SEGMENT_LEN`]-octet segment of figure 88.
pub fn sample_element(type_id: u8) -> Vec<u8> {
    let mut element = Vec::new();
    match TypeId::from_u8(type_id) {
        // C_IC_NA_1: QOI 20, station interrogation (5-101 cl.7.2.6.22).
        TypeId::CIcNa1 => element.push(Qoi::STATION_INTERROGATION),
        // C_CI_NA_1: QCC 5, general request counter with FRZ = 0, read
        // (5-101 cl.7.2.6.23; 0x14 would be the reserved RQT 20).
        TypeId::CCiNa1 => element.push(
            Qcc {
                rqt: Qcc::GENERAL_REQUEST,
                frz: FreezeMode::Read,
            }
            .raw(),
        ),
        // C_CS_NA_1: a CP56Time2a, Friday, 2026-09-25, 12:00:00.000 (5-101
        // cl.7.2.6.24), the loop's one time value.
        TypeId::CCsNa1 => sample_time().encode(&mut element),
        // C_RP_NA_1: QRP 1, general reset of process (5-101 cl.7.2.6.27;
        // 0x14 would be a reserved QRP).
        TypeId::CRpNa1 => element.push(Qrp::GENERAL_RESET),
        // F_SG_NA_1: figure 88's variable-length element, `NOF` 2 + `NOS` 1 +
        // `LOS` 1 + `LOS` segment octets (5-101 cl.7.3.6.6, index 119). `LOS`
        // is the segment's own octet count, as the clause's 7.2.6.36 fixes it.
        TypeId::FSgNa1 => {
            element.extend_from_slice(&[0x00, 0x01]); // NOF: file 1
            element.push(0); // NOS: section 0, "not used"
            element.push(SAMPLE_SEGMENT_LEN as u8); // LOS
            element.extend_from_slice(&[0xA5, 0x5A]); // Octet 1 … Octet n
        }
        // Every other laid-out type: `element_len` states the count. The two
        // fields a zero fill gets wrong are then written: the command state of
        // 46/47/59/60 and every `CP56Time2a` time tag.
        other => {
            let len = element_len(other).unwrap_or_else(|| {
                panic!(
                    "the sample type {} has no fixed element length to build from",
                    other.to_u8()
                )
            });
            element.resize(len, 0);
            set_command_state(other, &mut element);
            set_time_tags(other, &mut element);
        }
    }
    element
}

/// Gives the command element of `type_id` a **permitted** command state:
/// `DCO`'s `DCS` 1 (OFF) for `C_DC_NA_1` `<46>` / `C_DC_TA_1` `<59>`, `RCO`'s
/// `RCS` 1 (LOWER) for `C_RC_NA_1` `<47>` / `C_RC_TA_1` `<60>`: clause
/// 7.2.6.16/.17's first permitted value, with `QU` and `S/E` left at zero.
///
/// A no-op for every other type: no other element carries a command state.
fn set_command_state(type_id: TypeId, element: &mut [u8]) {
    match type_id {
        TypeId::CDcNa1 | TypeId::CDcTa1 => {
            element[0] = Dco {
                dcs: DoubleCommandState::Off,
                qoc: Qoc::default(),
            }
            .raw();
        }
        TypeId::CRcNa1 | TypeId::CRcTa1 => {
            element[0] = Rco {
                rcs: RegulatingStepState::Lower,
                qoc: Qoc::default(),
            }
            .raw();
        }
        _ => {}
    }
}

/// Writes [`sample_time`] into every `CP56Time2a` position of `type_id`'s
/// element, so a time-tagged sample carries a time inside 5-101 clause
/// 7.2.6.18's ranges instead of the zero fill's day of month 0 / months 0.
///
/// A no-op for an untagged type: [`time_tag_offsets`] answers nothing for it.
fn set_time_tags(type_id: TypeId, element: &mut [u8]) {
    let mut octets = Vec::with_capacity(Cp56Time2a::LEN);
    sample_time().encode(&mut octets);
    for offset in time_tag_offsets(type_id.to_u8(), element.len()) {
        element[offset..offset + Cp56Time2a::LEN].copy_from_slice(&octets);
    }
}

/// Where `type_id`'s element carries `CP56Time2a` time tags, as offsets from the
/// element's first octet (the geometric half of 5-101 clause 7.2.6.18):
///
/// - `<127>` `F_SC_NB_1` carries **two**: `NOF` (2 octets, 7.2.6.33) then
///   `RangeStartTime` and `RangeStopTime` (`src/asdu/layout/file.rs`,
///   `FScNb1`, figure 31 / index 92);
/// - every other time-tagged type carries **one**, the element's trailing seven
///   octets: the monitor types `<30..40>` (5-101 tables 8/10), the 104 command
///   types `<58..64>` (5-104 clause 8.1–8.7) and `C_TS_TA_1` `<107>`
///   (cl.8.8), and `F_DR_TA_1` `<126>`, whose `CP56Time2a` is the last field of
///   its 13-octet element (5-101 cl.7.3.6.7, figure 89 / index 120);
/// - every untagged type carries none.
pub fn time_tag_offsets(type_id: u8, element_len: usize) -> Vec<usize> {
    match type_id {
        127 => vec![Nof::LEN, Nof::LEN + Cp56Time2a::LEN],
        30..=40 | 58..=64 | 107 | 126 => vec![element_len - Cp56Time2a::LEN],
        _ => Vec::new(),
    }
}

/// Asserts that the element octets `element` of a sample for `type_id` are
/// legal values for their own type. 604 `5.4.11.1`'s loops run this check over
/// every sample they send:
///
/// - the command state of `<46>`/`<47>`/`<59>`/`<60>` is one clause 7.2.6.16/.17
///   permits, i.e. not `<0>`/`<3>` (a 604-conformant station must answer a
///   not-permitted command with `P/N = 1`, so such a sample is not a request it
///   accepts);
/// - every `CP56Time2a` of a time-tagged type is inside clause 7.2.6.18's
///   ranges, day of month `1..=31` and months `1..=12`.
///
/// The type is named in every message.
pub fn assert_sample_element_is_legal(type_id: u8, element: &[u8]) {
    match TypeId::from_u8(type_id) {
        TypeId::CDcNa1 | TypeId::CDcTa1 => {
            let state = DoubleCommandState::from_bits(element[0]);
            assert!(
                matches!(state, DoubleCommandState::Off | DoubleCommandState::On),
                "5.4.11.1 (type {type_id}): DCS {state:?} is not a permitted double command \
                 state — clause 7.2.6.16 allows only <1> OFF and <2> ON"
            );
        }
        TypeId::CRcNa1 | TypeId::CRcTa1 => {
            let state = RegulatingStepState::from_bits(element[0]);
            assert!(
                matches!(
                    state,
                    RegulatingStepState::Lower | RegulatingStepState::Higher
                ),
                "5.4.11.1 (type {type_id}): RCS {state:?} is not a permitted regulating step \
                 state — clause 7.2.6.17 allows only <1> LOWER and <2> HIGHER"
            );
        }
        _ => {}
    }
    for offset in time_tag_offsets(type_id, element.len()) {
        let time = Cp56Time2a::parse(&element[offset..offset + Cp56Time2a::LEN])
            .expect("the sample's own CP56Time2a octets");
        assert!(
            (1..=31).contains(&time.day_of_month),
            "5.4.11.1 (type {type_id}): the CP56Time2a at element offset {offset} has day of \
             month {}, outside clause 7.2.6.18's 1..=31",
            time.day_of_month
        );
        assert!(
            (1..=12).contains(&time.months),
            "5.4.11.1 (type {type_id}): the CP56Time2a at element offset {offset} has months \
             {}, outside clause 7.2.6.18's 1..=12",
            time.months
        );
    }
}

/// One well-formed sample's whole information object *area* for `type_id`: the
/// three-octet information object address `ioa` then [`sample_element`]'s
/// octets, which is what [`asdu_with_body`] takes.
pub fn sample_object_area(type_id: u8, ioa: u32) -> Vec<u8> {
    let mut area = Vec::with_capacity(3 + SAMPLE_SEGMENT_LEN);
    area.extend_from_slice(&ioa.to_le_bytes()[..3]);
    area.extend_from_slice(&sample_element(type_id));
    area
}

/// The cause of transmission a **controlling** station sends `type_id` with:
/// 5-101 clause 7.3's own line per type, not one constant for the whole set.
///
/// - `C_RD_NA_1` `<102>` is sent with `<5> := request` (index 106, the read
///   procedure's own cause), never `<6> := activation`;
/// - `F_DR_TA_1` `<126>` is sent with `<5> := requested` (index 120): it is the
///   one member of the file-transfer family whose cause list is
///   `<3> := spontaneous <5> := requested`, with **no** `<13> := file transfer`;
/// - the rest of the file-transfer family `<120..127>` is sent with
///   `<13> := file transfer`;
/// - every other control-direction type with `<6> := activation`.
pub fn control_cause(type_id: u8) -> u8 {
    match type_id {
        102 | 126 => Cause::Request.to_u8(),
        120..=127 => Cause::FileTransfer.to_u8(),
        _ => Cause::Activation.to_u8(),
    }
}

/// The cause of transmission a **controlled** station sends `type_id` with:
/// 5-101 clause 7.3's own line per type.
///
/// - `M_EI_NA_1` `<70>` is sent only with `<4> := initialized` (the end of
///   initialization), never `<3> := spontaneous`;
/// - `F_DR_TA_1` `<126>` with `<3> := spontaneous` (index 120): the
///   file-transfer family's exception, since index 120 lists only `<3>` and
///   `<5>` and no `<13>`;
/// - the rest of the file-transfer family `<120..127>` with
///   `<13> := file transfer`;
/// - every other monitor-direction type with `<3> := spontaneous`.
pub fn monitor_cause(type_id: u8) -> u8 {
    match type_id {
        70 => Cause::Initialized.to_u8(),
        126 => Cause::Spontaneous.to_u8(),
        120..=127 => Cause::FileTransfer.to_u8(),
        _ => Cause::Spontaneous.to_u8(),
    }
}

/// The **controlled** station's four answers for one received ASDU (5-101
/// clause 7.2.3's [`Known`]), from this station's own data: the standard's types
/// and causes, its own common address, and the one object address it holds.
///
/// Two of 604 `5.4.10.10`'s rows (index 54) make the common address and the
/// object address answers type-dependent, which is why this is not
/// [`controlling_profile`] with the caller's flags alone:
///
/// - the broadcast CASDU `FF FF` is a **known** address for the four system
///   types [`BROADCAST_TYPES`] names, and an undefined one for every other type
///   (604 `5.4.10.10`: any other type carrying the broadcast CASDU is refused
///   by the controlled station, which mirrors it with P/N = 1, negative);
/// - the four system types carry the *irrelevant* information object address 0
///   (5-101 clause 7.2.5), so IOA 0 is held for them.
pub fn station_profile(asdu: &[u8]) -> Result<Known, String> {
    let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
    let broadcastable = BROADCAST_TYPES.contains(&header.type_id.to_u8());
    let common_address = if header.common_address == BROADCAST_CA {
        broadcastable
    } else {
        header.common_address == CA
    };
    let addresses_known = if header.count == 0 {
        true
    } else {
        let ioa = read_ioa(&asdu[Header::LEN..]).map_err(|e| format!("the address: {e:?}"))?;
        ioa == HELD_IOA || (broadcastable && ioa == 0)
    };
    Ok(Known::standard(&header, common_address, addresses_known))
}

/// The **controlling** station's four answers for one ASDU it received in the
/// monitor direction: the standard's types and causes, its own common address,
/// and the one object address it holds.
///
/// The broadcast CASDU is never this station's own address. 604 `5.4.10.10`
/// (index 54, `Required M`): a controlling station that receives an ASDU with
/// the broadcast CASDU treats it the same as one with an undefined CASDU.
pub fn controlling_profile(asdu: &[u8]) -> Result<Known, String> {
    let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
    let addresses_known = if header.count == 0 {
        true
    } else {
        let ioa = read_ioa(&asdu[Header::LEN..]).map_err(|e| format!("the address: {e:?}"))?;
        ioa == HELD_IOA
    };
    Ok(Known::standard(
        &header,
        header.common_address == CA,
        addresses_known,
    ))
}

/// The controlling station's verdict for one ASDU it received in the monitor
/// direction: 5-101 clause 7.2.3's monitor-direction rule
/// ([`discard_reason`], the same rule every application module of `src/` applies
/// to a received ASDU) over [`controlling_profile`]. `None` means the ASDU is to
/// be processed normally; `Some` is why it is ignored.
pub fn controlling_discard(asdu: &[u8]) -> Result<Option<Discard>, String> {
    let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
    let known = controlling_profile(asdu)?;
    Ok(discard_reason(&header, &known))
}

/// Every type identification the station under test **supports** whose direction
/// is `Control` or `Both` (5-101 tables 9, 11 and 12 plus the 104 commands and
/// the file-transfer family of table 13), i.e. the ASDUs a **controlling**
/// station puts on the wire.
///
/// This is the set 604 `5.4.11.1`'s NOTE (page index 54) asks the
/// controlled-station cases to run over, as it requires the tests for every
/// supported ASDU: the harness profile is `Known::standard`, a station that
/// implements everything the standard's tables define, so "supported" is 5-104
/// clause 6's selection, [`TypeId::is_selected_104`].
///
/// The loop is over the type-identification **octet**, `0..=255`, and the
/// filter is by direction, so a type the standard defines but 104 does not
/// select stays out, as does every reserved and private octet.
pub fn control_direction_type_ids() -> Vec<u8> {
    (0..=u8::MAX)
        .filter(|raw| {
            let type_id = TypeId::from_u8(*raw);
            type_id.is_selected_104()
                && matches!(
                    type_id.direction(),
                    Some(Direction::Control | Direction::Both)
                )
        })
        .collect()
}

/// Every type identification the station under test supports whose direction is
/// `Monitor` or `Both` (5-101 tables 8, 10 and 13), i.e. the ASDUs a
/// **controlled** station puts on the wire, which is the traffic 604
/// `5.4.10.1`, `.5`, `.10` and `.11.1`'s *controlling*-station rows are about.
/// The mirror image of [`control_direction_type_ids`], same filter rule.
pub fn monitor_direction_type_ids() -> Vec<u8> {
    (0..=u8::MAX)
        .filter(|raw| {
            let type_id = TypeId::from_u8(*raw);
            type_id.is_selected_104()
                && matches!(
                    type_id.direction(),
                    Some(Direction::Monitor | Direction::Both)
                )
        })
        .collect()
}

/// The station's answer to one received I-frame: 5-101 clause 7.2.3's mirror, or
/// nothing. This is the codec rule under test, applied where a controlled
/// station's application applies it; the case asserts the octets it produces.
pub fn station_reply(asdu: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
    let known = station_profile(asdu)?;
    Ok(mirror_reply(&header, &known, &asdu[Header::LEN..]))
}

/// The control field of one whole APDU, as the harness parses it.
pub fn apci_of(frame: &[u8]) -> Result<Apci, String> {
    parse_frame(frame).map(|(apci, _)| apci)
}

/// What the controlled station observed and put on the wire, for a case's
/// assertions about things a session rule cannot see.
#[derive(Debug, Default, Clone)]
pub struct StationReport {
    /// Frames the station read, in order.
    pub received: Vec<Vec<u8>>,
    /// Frames the station put on the wire, in order.
    pub sent: Vec<Vec<u8>>,
    /// The session state after each received frame, in order: §5.3.2.70's rows
    /// are about which state a frame arrived in.
    pub states: Vec<State>,
    /// The reasons of every `Action::ActiveClose` the session raised.
    pub closes: Vec<&'static str>,
    /// The station's own unconfirmed I-frames when the peer closed (or when the
    /// station closed): clause 5.1's send buffer at the end of the exchange.
    pub outstanding_i_frames_at_eof: usize,
}

/// The application half of the controlled station under test: what it answers
/// to a received ASDU, and what it puts on the wire of its own accord.
///
/// The codec negatives of Tables 10 and 11 need only [`MirrorApp`], clause
/// 7.2.3's mirror. The procedure tables (12 onwards) plug in the crate's own
/// application modules (`gi`, `ci`, `cs`, `ct`, `rd`, `pm`, `ts`, `ft`, `tx`,
/// `init`) behind this trait, so they share the one socket loop in [`serve`].
pub trait StationApp: Send + 'static {
    /// The ASDUs to send in answer to one ASDU received in an I-frame, oldest
    /// first.
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String>;

    /// The ASDUs the application puts on the wire of its own accord (events,
    /// cyclic data, anything a test injects), polled between reads, roughly
    /// every 20 ms. The default has nothing to send.
    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        Ok(Vec::new())
    }
}

/// The application of the codec negatives: [`station_reply`], 5-101 clause
/// 7.2.3's mirror, and nothing else.
pub struct MirrorApp;

impl StationApp for MirrorApp {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        Ok(station_reply(asdu)?.into_iter().collect())
    }
}

/// The controlled station under test: this library's controlled side on a
/// loopback port, accepting one connection and answering it with
/// `link::Session` in `Role::Controlled` plus a [`StationApp`] ([`MirrorApp`]
/// unless a case plugs in its own).
pub struct ControlledStation {
    addr: SocketAddr,
    handle: JoinHandle<Result<StationReport, String>>,
}

impl ControlledStation {
    /// A station with nothing queued before STARTDT.
    pub fn start() -> Result<Self, String> {
        Self::start_with_queue(Vec::new())
    }

    /// A station holding `pre_start` ASDUs in its clause 5.3 queue: data the
    /// application handed over while data transfer was not enabled, which
    /// `Session::queue_i_frame` holds until the STARTDT con (clause 5.3: the
    /// controlled station holds back pending user data until after the
    /// STARTDT con).
    pub fn start_with_queue(pre_start: Vec<Vec<u8>>) -> Result<Self, String> {
        Self::start_app(MirrorApp, pre_start)
    }

    /// A station running `app` as its application, holding `pre_start` ASDUs in
    /// its clause 5.3 queue as [`ControlledStation::start_with_queue`] does.
    pub fn start_app(app: impl StationApp, pre_start: Vec<Vec<u8>>) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("local addr: {e}"))?;
        let handle = thread::spawn(move || match listener.accept() {
            Ok((stream, _)) => serve(stream, &pre_start, app),
            Err(e) => Err(format!("accept: {e}")),
        });
        Ok(Self { addr, handle })
    }

    /// The loopback address the station listens on.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Waits for the station thread. It ends when the peer closes the socket, or
    /// when the station itself closes it on an `ActiveClose`.
    pub fn join(self) -> Result<StationReport, String> {
        self.handle
            .join()
            .map_err(|_| "the controlled station panicked".to_string())?
    }
}

/// The station's own loop: one connection, answered from the session and the
/// station's application.
fn serve(
    mut stream: TcpStream,
    pre_start: &[Vec<u8>],
    mut app: impl StationApp,
) -> Result<StationReport, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    let mut session = Session::new(Role::Controlled);
    session.on_connection_established();
    for asdu in pre_start {
        session
            .queue_i_frame(asdu)
            .map_err(|e| format!("the clause 5.3 queue: {e:?}"))?;
    }
    let mut decoder = Decoder::new();
    let mut report = StationReport::default();
    let mut queued: VecDeque<Vec<u8>> = VecDeque::new();

    loop {
        // Whatever the application owes goes out first, oldest first. When the
        // session cannot take it (the window of k frames is full, or data
        // transfer is not started) it waits, and the loop reads on: only a
        // frame from the peer can open the window again.
        if let Some(asdu) = queued.pop_front() {
            match session.send_i_frame(&asdu) {
                Some(action) => {
                    write_action(&mut stream, &action, &mut report)?;
                    continue;
                }
                None => queued.push_front(asdu),
            }
        } else if session.user_data_allowed() {
            // What the application sends of its own accord waits for data
            // transfer (clause 5.3), like everything else it owes.
            let own = app.poll(Instant::now())?;
            if !own.is_empty() {
                queued.extend(own);
                continue;
            }
        }

        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(0) => {
                report.outstanding_i_frames_at_eof = session.outstanding_i_frames() as usize;
                return Ok(report);
            }
            Ok(n) => decoder.push(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(format!("read: {e}")),
        }

        loop {
            match decoder.next_frame_len() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {
                    let _ = decoder.next_frame();
                    continue;
                }
            }
            let frame = {
                let frame = decoder
                    .next_frame()
                    .map_err(|e| format!("framing: {e}"))?
                    .ok_or("the decoder promised a frame")?;
                frame.to_vec()
            };
            let (apci, asdu) = parse_frame(&frame)?;
            report.received.push(frame);
            if apci.is_i_format() {
                queued.extend(app.on_asdu(&asdu)?);
            }
            let actions = session.on_frame(apci);
            report.states.push(session.state());
            for action in &actions {
                if let Action::ActiveClose(why) = action {
                    report.closes.push(why);
                }
                write_action(&mut stream, action, &mut report)?;
            }
            // 604 §5.3.2.70: an I- or S-frame in a Stopped connection leads to
            // a TCP active close. The station closes the socket, which is
            // what the peer observes as EOF.
            if !report.closes.is_empty() {
                let _ = stream.shutdown(Shutdown::Both);
                report.outstanding_i_frames_at_eof = session.outstanding_i_frames() as usize;
                return Ok(report);
            }
        }
    }
}

/// Puts one action on the wire (or records nothing for `DeliverData` and
/// `ActiveClose`, which are not frames).
fn write_action(
    stream: &mut TcpStream,
    action: &Action,
    report: &mut StationReport,
) -> Result<(), String> {
    let mut octets = Vec::new();
    interop::encode_action(action, &mut octets)?;
    if octets.is_empty() {
        return Ok(());
    }
    stream
        .write_all(&octets)
        .map_err(|e| format!("write: {e}"))?;
    report.sent.push(octets);
    Ok(())
}

/// The mock **controlling** station: a socket the test writes frames on and
/// reads whole frames from, with a bounded read deadline. It invents no
/// protocol behaviour: every frame is one the case spells out.
pub struct Peer {
    stream: TcpStream,
    decoder: Decoder,
    /// Every APDU this side put on the wire, in order.
    pub sent: Vec<Vec<u8>>,
    /// Every APDU this side read, in order.
    pub received: Vec<Vec<u8>>,
}

impl Peer {
    /// Connects to the station under test.
    pub fn connect(addr: SocketAddr) -> Result<Self, String> {
        let stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("nodelay: {e}"))?;
        Ok(Self {
            stream,
            decoder: Decoder::new(),
            sent: Vec::new(),
            received: Vec::new(),
        })
    }

    fn write(&mut self, octets: &[u8]) -> Result<(), String> {
        self.stream
            .write_all(octets)
            .map_err(|e| format!("write: {e}"))?;
        self.sent.push(octets.to_vec());
        Ok(())
    }

    /// A U-format frame (clause 5, figure 8).
    pub fn send_u(&mut self, function: UFunction) -> Result<(), String> {
        let mut out = Vec::new();
        Apdu {
            apci: Apci::U(function),
            asdu: &[],
        }
        .encode(&mut out)
        .map_err(|e| format!("encode {function:?}: {e:?}"))?;
        self.write(&out)
    }

    /// An S-format frame (clause 5, figure 7).
    pub fn send_s(&mut self, nr: SeqNo) -> Result<(), String> {
        let mut out = Vec::new();
        Apdu {
            apci: Apci::S { nr },
            asdu: &[],
        }
        .encode(&mut out)
        .map_err(|e| format!("encode S({nr:?}): {e:?}"))?;
        self.write(&out)
    }

    /// An I-format frame carrying one ASDU.
    pub fn send_i(&mut self, ns: SeqNo, nr: SeqNo, asdu: &[u8]) -> Result<(), String> {
        let mut out = Vec::new();
        Apdu {
            apci: Apci::I { ns, nr },
            asdu,
        }
        .encode(&mut out)
        .map_err(|e| format!("encode I({ns:?},{nr:?}): {e:?}"))?;
        self.write(&out)
    }

    /// Reads one whole frame, failing at the deadline. A closed socket is an
    /// error too, which is how a case observes an active close.
    pub fn read_frame(&mut self, limit: Instant) -> Result<(Apci, Vec<u8>), String> {
        loop {
            match self.decoder.next_frame_len() {
                Ok(Some(_)) => {
                    let frame = {
                        let frame = self
                            .decoder
                            .next_frame()
                            .map_err(|e| format!("framing: {e}"))?
                            .ok_or("the decoder promised a frame")?;
                        frame.to_vec()
                    };
                    let (apci, asdu) = parse_frame(&frame)?;
                    self.received.push(frame);
                    return Ok((apci, asdu));
                }
                Ok(None) => {}
                Err(_) => {
                    let _ = self.decoder.next_frame();
                }
            }
            let remaining = limit.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("no frame before the deadline".into());
            }
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(|e| format!("set read timeout: {e}"))?;
            let mut buf = [0u8; 1024];
            match self.stream.read(&mut buf) {
                Ok(0) => return Err("the station closed the connection".into()),
                Ok(n) => self.decoder.push(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err("no frame before the deadline".into());
                }
                Err(e) => return Err(format!("read: {e}")),
            }
        }
    }

    /// Reads the next frame and requires it to be this U-function.
    pub fn expect_u(&mut self, function: UFunction, limit: Instant) -> Result<(), String> {
        let (apci, _) = self.read_frame(limit)?;
        if apci != Apci::U(function) {
            return Err(format!("{function:?} expected, got {apci:?}"));
        }
        Ok(())
    }

    /// Reads frames until an I-frame arrives; U- and S-frames are recorded and
    /// skipped.
    pub fn expect_i(&mut self, limit: Instant) -> Result<(Apci, Vec<u8>), String> {
        loop {
            let (apci, asdu) = self.read_frame(limit)?;
            if apci.is_i_format() {
                return Ok((apci, asdu));
            }
        }
    }

    /// The STARTDT exchange of clause 5.3: `STARTDT act` out, `STARTDT con`
    /// back.
    pub fn start_data_transfer(&mut self) -> Result<(), String> {
        self.send_u(UFunction::StartDtAct)?;
        self.expect_u(UFunction::StartDtCon, deadline(5))
    }

    /// Closes the socket, which ends the station's thread.
    pub fn close(&self) -> Result<(), String> {
        self.stream
            .shutdown(Shutdown::Both)
            .map_err(|e| format!("shutdown: {e}"))
    }
}

/// One exchange's outcome: the I-frame the station answered with, if any, and
/// everything it reported.
#[derive(Debug)]
pub struct Exchange {
    /// The station's answer, when it sent an I-frame inside the wait.
    pub reply: Option<(Apci, Vec<u8>)>,
    /// What the station observed and sent.
    pub report: StationReport,
}

/// Drives one codec-negative exchange against a fresh controlled station: the
/// STARTDT exchange, one I-frame carrying `request`, and whatever the station
/// answered with inside `wait` seconds. The peer then closes, so the station's
/// thread ends and the report is complete.
pub fn exchange(request: &[u8], wait: u64) -> Result<Exchange, String> {
    let station = ControlledStation::start()?;
    let mut peer = Peer::connect(station.addr())?;
    peer.start_data_transfer()?;
    peer.send_i(SeqNo::new(0), SeqNo::new(0), request)?;
    let reply = peer.expect_i(deadline(wait)).ok();
    peer.close()?;
    let report = station.join()?;
    Ok(Exchange { reply, report })
}

/// The same, requiring the mirror the codec negatives are about.
pub fn mirror_of(request: &[u8]) -> Result<(Apci, Vec<u8>, StationReport), String> {
    let exchange = exchange(request, 5)?;
    let Exchange { reply, report } = exchange;
    let (apci, asdu) = reply.ok_or_else(|| {
        format!(
            "5-101 cl.7.2.3: the station mirrored nothing (it sent {} frames)",
            report.sent.len()
        )
    })?;
    Ok((apci, asdu, report))
}

// ------------------------------------ the controlling station's half
//
// Each of 604's `5.4.10.1`, `5.4.10.5`, `5.4.10.10` and `5.4.11.1` carries a
// **controlling-station** row beside the controlled-station half the cases above
// drive: the controlling station ignores (or discards) any ASDU it receives that
// is undefined or unsupported, and for `5.4.10.10` it treats an ASDU with the
// broadcast CASDU as one with an undefined CASDU (index 53-54). §5.1 makes the
// direction part of the test, so
// that half needs the other role: the interoperability harness's
// [`interop::Station`] is this library as the **controlling** station, and
// [`MonitorPeer`] is a mock *controlled* peer
// that feeds it one monitor-direction ASDU. The station's verdict is the crate's
// clause 7.2.3 monitor-direction rule, `asdu::unknown::discard_reason`, which
// every application module of `src/` applies to a received ASDU.

/// What the mock controlled peer read back from the controlling station under
/// test.
#[derive(Debug, Default, Clone)]
pub struct MonitorReport {
    /// Frames the peer received from the station, in order.
    pub received: Vec<Vec<u8>>,
    /// Frames the peer put on the wire, in order.
    pub sent: Vec<Vec<u8>>,
}

/// The mock **controlled** station for the controlling-station halves of the
/// 5.4.10 and 5.4.11 rows: it completes the STARTDT exchange (cl.5.3) and then
/// puts one ASDU into the monitor direction, recording everything the station
/// under test answers with.
pub struct MonitorPeer {
    addr: SocketAddr,
    handle: JoinHandle<Result<MonitorReport, String>>,
}

impl MonitorPeer {
    /// Binds a loopback port and starts the accepting thread; `monitor` is the
    /// I-frame the peer sends once the connection is `Started`.
    pub fn start(monitor: Vec<u8>) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("local addr: {e}"))?;
        let handle = thread::spawn(move || match listener.accept() {
            Ok((stream, _)) => serve_monitor(stream, &monitor),
            Err(e) => Err(format!("accept: {e}")),
        });
        Ok(Self { addr, handle })
    }

    /// The loopback address the peer listens on.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Waits for the peer thread. It ends when the station closes the socket.
    pub fn join(self) -> Result<MonitorReport, String> {
        self.handle
            .join()
            .map_err(|_| "the monitor peer panicked".to_string())?
    }
}

/// The peer's loop: one connection, the STARTDT exchange, then one monitor ASDU.
fn serve_monitor(mut stream: TcpStream, monitor: &[u8]) -> Result<MonitorReport, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    let mut session = Session::new(Role::Controlled);
    session.on_connection_established();
    let mut decoder = Decoder::new();
    let mut report = MonitorReport::default();
    let mut monitor_sent = false;

    loop {
        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(0) => return Ok(report),
            Ok(n) => decoder.push(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(format!("read: {e}")),
        }

        loop {
            match decoder.next_frame_len() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => {
                    let _ = decoder.next_frame();
                    continue;
                }
            }
            let frame = {
                let frame = decoder
                    .next_frame()
                    .map_err(|e| format!("framing: {e}"))?
                    .ok_or("the decoder promised a frame")?;
                frame.to_vec()
            };
            let (apci, _) = parse_frame(&frame)?;
            report.received.push(frame);
            let actions = session.on_frame(apci);
            for action in &actions {
                if let Some(octets) = encode_monitor_action(action)? {
                    stream
                        .write_all(&octets)
                        .map_err(|e| format!("write: {e}"))?;
                    report.sent.push(octets);
                }
            }
            // The STARTDT con has just gone out, so the connection is `Started`
            // (cl.5.3) and the peer's one monitor ASDU can follow it.
            if !monitor_sent && apci == Apci::U(UFunction::StartDtAct) {
                let action = session
                    .send_i_frame(monitor)
                    .ok_or("the peer cannot send its ASDU before data transfer is started")?;
                let octets =
                    encode_monitor_action(&action)?.ok_or("the peer's ASDU is not a frame")?;
                stream
                    .write_all(&octets)
                    .map_err(|e| format!("write: {e}"))?;
                report.sent.push(octets);
                monitor_sent = true;
            }
        }
    }
}

/// One action as the octets the wire carries, or `None` when it is not a frame.
fn encode_monitor_action(action: &Action) -> Result<Option<Vec<u8>>, String> {
    let mut out = Vec::new();
    interop::encode_action(action, &mut out)?;
    Ok((!out.is_empty()).then_some(out))
}

/// One monitor-direction exchange's outcome for a controlling-station case: the
/// ASDU the peer sent, every APDU the station under test put on the wire, and
/// what the peer read back.
#[derive(Debug)]
pub struct ControllingExchange {
    /// The ASDU the peer put into the monitor direction.
    pub asdu: Vec<u8>,
    /// The control fields of every APDU the station under test sent, in order.
    pub sent: Vec<Apci>,
    /// What the mock controlled peer read back from the station, in order.
    pub received: Vec<Vec<u8>>,
}

/// Drives one monitor-direction exchange against the **controlling** station
/// under test: the STARTDT exchange (cl.5.3), then one I-frame carrying
/// `monitor` (an ASDU the station must ignore or discard), read within a
/// bounded wait. The station then closes, so the peer's thread ends and the
/// report is complete.
pub fn controlling_exchange(monitor: &[u8]) -> Result<ControllingExchange, String> {
    let peer = MonitorPeer::start(monitor.to_vec())?;
    let mut station = interop::Station::connect(peer.addr())?;
    let actions = station.session_mut().request_start();
    station.send_actions(&actions)?;
    let (_, asdu) = station.expect("the peer's monitor ASDU", deadline(5), |apci, _| {
        apci.is_i_format()
    })?;
    station.close()?;
    let report = peer.join()?;
    let sent = station
        .sent
        .iter()
        .filter_map(|frame| apci_of(frame).ok())
        .collect();
    Ok(ControllingExchange {
        asdu,
        sent,
        received: report.received,
    })
}
