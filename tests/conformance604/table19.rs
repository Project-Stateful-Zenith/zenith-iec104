//! 604 Table 19, *"Command transmission function conformance test
//! procedures"*, PDF page indices 70–78 (printed 69–77), procedures
//! `5.4.19.1` … `5.4.19.90`: the **controlled**-station half, and the helpers
//! both halves share. The controlling-station half is
//! [`crate::conformance604::table19_controlling`].
//!
//! Every row's `Reference` column names IEC 60870-5-101:2003 clause **7.4.7**
//! (*"Selections from command transmission"*, PDF page index 126) and IEC
//! 60870-5-5 clause 6.8; the time-tagged rows name IEC 60870-5-104:2006 clause
//! **8** (PDF page index 74) and 9.6. The rows are quoted verbatim on the tests.
//!
//! # The station under test
//!
//! The DUT is `ct::CommandTransmission` in the controlled role, plugged into
//! [`ControlledStation`] through [`CtApp`]. The application glue decides only
//! what the crate leaves to the application: which information object
//! addresses exist and which of them are controllable (project data, the
//! caller's `Known` and `CommandTransmission::refuse`), and what the process
//! does once a command has been confirmed (the return information, built by
//! `ct::return_information`, and the `ACTTERM`, built by
//! `CommandTransmission::terminate`). Every protocol decision (which frame is
//! mirrored, positive or negative, with which cause, and whether a command runs
//! at all) is the crate's `Reaction`.
//!
//! # "Every supported ASDU"
//!
//! The table's header, *"These procedures are passed only if the mandatory
//! procedures and test cases are passed for every supported ASDU according to
//! the PICS"*, and row `5.4.19.80` (*"The tests in this table are performed
//! correctly by every supported ASDU according to the PICS"*) make each case a
//! loop. The station supports every command type 5-104 clause 6 selects, in
//! both command sets: `<45>`–`<51>` for an untagged station and `<58>`–`<64>`
//! for a time-tagged one (5-104 clause 9, index 102: *"Either the ASDUs of the
//! set <45> – <51> or of the set <58> – <64> are used."*). The select-and-execute
//! rows name *"a Single, Double, Regulating step or Setpoint Command"*, so they
//! loop over the six selectable families; the direct-execute rows add
//! *"Bitstring"*, so they loop over all seven. The bitstring has no qualifier
//! and therefore no `S/E` bit (5-101 clause 7.3.2.7, figure 70, index 103).
//!
//! # Where the expected octets come from
//!
//! Each request is built octet by octet from 5-101 clause 7.3.2's layouts
//! ([`command`]), and each expected answer from the rows' own words: a
//! *mirror* is the same ASDU with only the cause octet changed ([`mirrored`]):
//! *"The Controlled station mirrors the same ASDU with COT=7"*, *"with COT=9"*,
//! *"with COT=10"*, and `P/N = 1` for *"`ACTCONneg`"*. The return information's
//! type is 5-101 clause 7.4.7's NOTE (*"a single command (type identification
//! 45) is used to control an object that is monitored as a single-point (type
//! identification 1, 2 and 30)"*, and the same for 46/3/31 and 47/5/32), and
//! its cause is the row's *"COT=11 (`RETURN_INF` caused by a remote command)"*.
//!
//! # Not automated, and why
//!
//! - *"Command execution in progress shall be completed with status change and
//!   ACTTERM … within the configured delay in the controlling station"* and the
//!   `5.4.19.40` *"configured delay in the controlling station"*: the crate
//!   keeps no clock, and the controlling station's delay is the caller's
//!   (`CommandTransmission::abandon`). The controlling half checks that the
//!   termination and the status change are classified; the delay is not the
//!   crate's to supervise.
//! - *"The Controlling station stops the Command function with an indication at
//!   user level"* (`Required` `PIXIT`): the user level is the application's. The
//!   controlling half checks the indication the crate gives (the negative
//!   `Reaction`) and that the procedure is stopped (no execute can follow).
//! - The PIXIT alternative of `5.4.19.40` (*"the Controlled station can first
//!   accept the command with a Positive ACTCON and then send a Negative
//!   Termination"*): the station under test takes the mandatory branch, the
//!   negative `ACTCON`. The alternative's frame is driven under `5.4.19.50`,
//!   where the row offers it for a not-controllable object.
//! - `5.4.19.90`, *"COMPATIBILITY WITH OTHER TEST CASES"*: the whole suite, not
//!   a case.
//!
//! # Direction
//!
//! Commands exist only in the control direction (5-101 clause 7.3.2), so
//! §5.1's swap is the other role of the same procedure, driven in
//! `table19_controlling`. No case here sends one of the COT44-47 causes; the
//! station answers with 44 and 47, which only a controlled station may send.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::conformance604::{
    CA, ControlledStation, Peer, StationApp, asdu_with_body, deadline, sample_element,
};
use iec104::apci::SeqNo;
use iec104::asdu::{
    Cause, Cp56Time2a, Diq, Direction, DoublePointState, Header, Known, LayoutObject, MDpNa1,
    MDpTb1, MSpNa1, MSpTb1, MStNa1, MStTb1, Qds, Siq, TypeId, Vti, encode_asdu, read_ioa,
};
use iec104::ct::{
    CommandMode, CommandSet, CommandTransmission, CommandValue, Family, Reaction, ReturnInfo,
    Termination, decode_command, return_information,
};
use iec104::gi::{DataSource, Interrogation, ReActivation, Scope};

// ------------------------------------------------------------ the requests

/// The seven untagged command types, `<45>`–`<51>` (5-101 clause 7.3.2).
pub const UNTAGGED: [u8; 7] = [45, 46, 47, 48, 49, 50, 51];

/// Their seven time-tagged twins, `<58>`–`<64>` (5-104 clause 8.1–8.7).
pub const TAGGED: [u8; 7] = [58, 59, 60, 61, 62, 63, 64];

/// The command types of one command set, checked against the crate's own
/// catalogue: each is selected by 5-104 clause 6 and is a control-direction
/// type, so a loop over them is a loop over "every supported ASDU".
pub fn set_types(set: CommandSet) -> [u8; 7] {
    let types = match set {
        CommandSet::Untagged => UNTAGGED,
        CommandSet::Tagged => TAGGED,
    };
    for type_id in types {
        let id = TypeId::from_u8(type_id);
        assert!(
            id.is_selected_104() && id.direction() == Some(Direction::Control),
            "type {type_id} is a 104 command type"
        );
    }
    types
}

/// Whether the type carries an `S/E` bit: every command family but the
/// bitstring, whose `C_BO_NA_1 := CP{Data unit identifier,Information object
/// address,BSI}` (figure 70) has no qualifier.
pub const fn selectable(type_id: u8) -> bool {
    !matches!(type_id, 51 | 64)
}

/// The element octet that carries the `S/E` bit (bit 8, `0x80`), counted from
/// the element's first octet: the `SCO`/`DCO`/`RCO` octet itself for the three
/// state commands (5-101 clause 7.2.6.15–.17 and .26), and the `QOS` octet after
/// the value for the set points (clause 7.2.6.39: `NVA` and `SVA` are two
/// octets, the short float four). The time-tagged twins put `CP56Time2a`
/// behind the same octets (5-104 clause 8), so the offset is the same.
pub const fn se_offset(type_id: u8) -> Option<usize> {
    match type_id {
        45 | 46 | 47 | 58 | 59 | 60 => Some(0),
        48 | 49 | 61 | 62 => Some(2),
        50 | 63 => Some(4),
        _ => None,
    }
}

/// A controllable object of the station, one per type so that the selects of a
/// loop never meet each other.
pub fn controllable(type_id: u8) -> u32 {
    0x3000 + u32::from(type_id)
}

/// An object the station has but will not control: 5.4.19.30/.50's *"not
/// controllable … Information object"*.
pub fn not_controllable(type_id: u8) -> u32 {
    0x4000 + u32::from(type_id)
}

/// An address the station has no object for: 5.4.19.30/.50's *"not existing
/// Information object"*.
pub fn not_existing(type_id: u8) -> u32 {
    0x5000 + u32::from(type_id)
}

/// An object whose execution is accepted and then fails: the station answers
/// with 5.4.19.50's PIXIT alternative, *"first accept the command with a
/// Positive ACTCON and then send a Negative Termination"*.
pub fn fails_after_accept(type_id: u8) -> u32 {
    0x6000 + u32::from(type_id)
}

/// The station's own data set: every address above but the not-existing ones.
const fn held(ioa: u32) -> bool {
    matches!(ioa >> 12, 0x3 | 0x4 | 0x6)
}

/// One `CP56Time2a` on 2026-09-25 (a Friday), for the time-tagged rows.
pub const fn time_at(hours: u8, minutes: u8, milliseconds: u16, summer_time: bool) -> Cp56Time2a {
    Cp56Time2a {
        milliseconds,
        minutes,
        substituted: false,
        invalid: false,
        hours,
        summer_time,
        day_of_month: 25,
        day_of_week: 5,
        months: 9,
        years: 26,
    }
}

/// The time tag every time-tagged request carries: `sample_element`'s
/// 12:00:00.000, standard time.
pub const fn tag_time() -> Cp56Time2a {
    time_at(12, 0, 0, false)
}

/// One command request, octet by octet: the data unit identifier (type, `VSQ`
/// with `SQ = 0` and one object, cause 6 `act`, originator, the station's
/// common address), the three-octet information object address, and the
/// type's element with a permitted command state (`sample_element`), the `S/E`
/// bit as given, and for the tagged set the time tag [`tag_time`].
pub fn command(type_id: u8, ioa: u32, select: bool) -> Vec<u8> {
    command_at(type_id, ioa, select, tag_time())
}

/// [`command`] with the time tag `time` written over the tagged set's
/// `CP56Time2a` (the element's last seven octets, 5-104 clause 8).
pub fn command_at(type_id: u8, ioa: u32, select: bool, time: Cp56Time2a) -> Vec<u8> {
    let mut element = sample_element(type_id);
    if let Some(offset) = se_offset(type_id) {
        if select {
            element[offset] |= 0x80;
        } else {
            element[offset] &= !0x80;
        }
    } else {
        assert!(!select, "type {type_id} has no S/E bit to select with");
    }
    if TAGGED.contains(&type_id) {
        let at = element.len() - Cp56Time2a::LEN;
        let mut octets = Vec::new();
        time.encode(&mut octets);
        element[at..].copy_from_slice(&octets);
    }
    let mut area = ioa.to_le_bytes()[..3].to_vec();
    area.extend_from_slice(&element);
    asdu_with_body(type_id, Cause::Activation.to_u8(), CA, &area)
}

/// The same request with another command value: `DCS`/`RCS` 1 becomes 2 (OFF to
/// ON, LOWER to HIGHER, both permitted values of 5-101 clause 7.2.6.16/.17), and
/// every other family has its first value octet's lowest bit flipped (`SCS`, the
/// low octet of `NVA`/`SVA`/the float, or of `BSI`). The `S/E` bit is kept.
pub fn altered(request: &[u8]) -> Vec<u8> {
    let mut out = request.to_vec();
    let at = Header::LEN + 3;
    match request[0] {
        46 | 47 | 59 | 60 => out[at] = (out[at] & !0x03) | 0x02,
        _ => out[at] ^= 0x01,
    }
    out
}

/// The same request with the command state written raw: `DCS`/`RCS` `0` or `3`
/// are the values 5-101 clause 7.2.6.16/.17 print *"not permitted"*.
pub fn with_state(request: &[u8], state: u8) -> Vec<u8> {
    let mut out = request.to_vec();
    let at = Header::LEN + 3;
    out[at] = (out[at] & !0x03) | state;
    out
}

/// The mirror of `request` the rows spell out: *"mirrors the same ASDU with
/// COT=…"*, so only the cause octet changes. `P/N` (bit 7 of that octet, 5-101
/// clause 7.2.3) is set for a negative answer; the test bit is kept.
pub fn mirrored(request: &[u8], cause: u8, negative: bool) -> Vec<u8> {
    let mut out = request.to_vec();
    out[2] = (request[2] & 0x80) | if negative { 0x40 } else { 0 } | cause;
    out
}

/// The cause octet's cause, without `P/N` and `T`.
pub const fn cause_of(asdu: &[u8]) -> u8 {
    asdu[2] & 0x3F
}

/// Whether `P/N = 1`.
pub const fn negative(asdu: &[u8]) -> bool {
    asdu[2] & 0x40 != 0
}

/// The monitor types 5-101 clause 7.4.7's NOTE names for a command type's
/// object (*"single-point (type identification 1, 2 and 30)"*, *"double-point
/// (type identification 3, 4 or 31)"*, *"step position information (type
/// identifications 5, 6 and 32)"*), or `None` for the set-point and bitstring
/// families, which 5-104 clause 7.7's `A_RETURN_INF` row (`M_SP, M_DP, M_ST`)
/// does not cover.
pub const fn return_types(type_id: u8) -> Option<[u8; 3]> {
    match type_id {
        45 | 58 => Some([1, 2, 30]),
        46 | 59 => Some([3, 4, 31]),
        47 | 60 => Some([5, 6, 32]),
        _ => None,
    }
}

// ------------------------------------------------------ the station's glue

/// What the station's application saw, for the rows about the process
/// (*"The value of the Object(s) does not change at all during this command
/// procedure"*).
#[derive(Debug, Default, Clone)]
pub struct CtLog {
    /// The crate's reaction to every command frame, in order.
    pub reactions: Vec<Reaction>,
    /// The objects whose command was executed: a positive execute confirmation
    /// the crate decided on, and nothing else.
    pub executed: Vec<u32>,
}

/// The controlled station's command application: `ct::CommandTransmission` in
/// the controlled role, plus the process glue the crate leaves to the caller.
pub struct CtApp {
    ct: CommandTransmission,
    wall_clock: Option<Cp56Time2a>,
    owed: VecDeque<Vec<u8>>,
    log: Arc<Mutex<CtLog>>,
}

impl CtApp {
    /// A station of `mode` using the command set `set`, terminating every
    /// family (5-101 clause 7.4.7's `ACTTERM`, and `C_SE ACTTERM` *"if
    /// supported as in the PICS"*). A select-and-execute station drops a select
    /// not executed within two seconds; a time-tagged station accepts a command
    /// up to ten seconds old (5-104 clause 8's *"maximum allowable delay"*) and
    /// its clock reads two seconds after [`tag_time`].
    pub fn new(mode: CommandMode, set: CommandSet) -> Self {
        let ct = CommandTransmission::controlled(mode, set, Termination::All, CA, 0)
            .with_select_timeout(Duration::from_secs(2))
            .with_max_command_delay(Duration::from_secs(10));
        Self {
            ct,
            wall_clock: Some(time_at(12, 0, 2_000, false)),
            owed: VecDeque::new(),
            log: Arc::default(),
        }
    }

    /// The same station with another select timeout.
    pub fn with_select_timeout(mut self, timeout: Duration) -> Self {
        self.ct = self.ct.with_select_timeout(timeout);
        self
    }

    /// The same station with another local time.
    pub const fn with_wall_clock(mut self, wall_clock: Cp56Time2a) -> Self {
        self.wall_clock = Some(wall_clock);
        self
    }

    /// The log the test reads after the station has ended.
    pub fn log(&self) -> Arc<Mutex<CtLog>> {
        Arc::clone(&self.log)
    }

    /// The return information for an executed command: the object's new state
    /// in the monitor type 5-101 clause 7.4.7's NOTE pairs with the command
    /// (untagged for the untagged set, `CP56Time2a` for the tagged one), with
    /// cause 11, *"`RETURN_INF` caused by a remote command"*. `None` for the
    /// families 5-104 clause 7.7 gives no return information.
    fn return_info(&self, asdu: &[u8]) -> Result<Option<Vec<u8>>, String> {
        let command = decode_command(asdu)
            .map_err(|e| format!("the command: {e:?}"))?
            .ok_or("not a command")?;
        let time = self.wall_clock.unwrap_or_else(tag_time);
        let tagged = command.time.is_some();
        let info = ReturnInfo::Remote;
        let frame = match command.value {
            CommandValue::Single { sco } => {
                let siq = Siq {
                    spi: sco.scs,
                    ..Default::default()
                };
                if tagged {
                    return_information(command.ioa, MSpTb1 { siq, time }, info, CA, 0)
                } else {
                    return_information(command.ioa, MSpNa1 { siq }, info, CA, 0)
                }
            }
            CommandValue::Double { dco } => {
                let diq = Diq {
                    dpi: DoublePointState::from_bits(dco.dcs.to_bits()),
                    blocked: false,
                    substituted: false,
                    not_topical: false,
                    invalid: false,
                };
                if tagged {
                    return_information(command.ioa, MDpTb1 { diq, time }, info, CA, 0)
                } else {
                    return_information(command.ioa, MDpNa1 { diq }, info, CA, 0)
                }
            }
            CommandValue::RegulatingStep { .. } => {
                let vti = Vti {
                    value: 1,
                    transient: false,
                };
                let qds = Qds::default();
                if tagged {
                    return_information(command.ioa, MStTb1 { vti, qds, time }, info, CA, 0)
                } else {
                    return_information(command.ioa, MStNa1 { vti, qds }, info, CA, 0)
                }
            }
            _ => return Ok(None),
        };
        frame
            .map(Some)
            .map_err(|e| format!("the return information: {e:?}"))
    }
}

impl StationApp for CtApp {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
        if Family::of_type(header.type_id).is_none() {
            return Ok(Vec::new());
        }
        let ioa = read_ioa(&asdu[Header::LEN..]).map_err(|e| format!("the address: {e:?}"))?;
        let known = Known::standard(&header, header.common_address == CA, held(ioa));
        let outcome = if ioa >> 12 == 0x4 && header.cause == Cause::Activation {
            // Project data: the object exists and is not controllable, so the
            // crate's refusal hook answers for it.
            self.ct.refuse(asdu)
        } else {
            self.ct
                .on_request_at(asdu, &known, Instant::now(), self.wall_clock)
        }
        .map_err(|e| format!("the command procedure: {e:?}"))?;
        let mut log = self.log.lock().expect("the log");
        log.reactions.push(outcome.reaction);
        if let Reaction::Confirmed {
            ioa,
            select: false,
            negative: false,
        } = outcome.reaction
        {
            // The crate confirmed an execute: the process acts on it.
            let fails = ioa >> 12 == 0x6;
            if !fails {
                log.executed.push(ioa);
                drop(log);
                if let Some(frame) = self.return_info(asdu)? {
                    self.owed.push_back(frame);
                }
            }
            if self.ct.is_running(ioa) {
                let term = self
                    .ct
                    .terminate(ioa, fails)
                    .map_err(|e| format!("the termination: {e:?}"))?;
                self.owed.push_back(term);
            }
        }
        Ok(outcome.send)
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        Ok(self.owed.drain(..).collect())
    }
}

// ------------------------------------------------ the controlling station

/// The mock controlling station with its own sequence numbers: every received
/// I-frame is acknowledged at once with an S-frame (5-104 clause 5.1), so the
/// station's window of k frames never fills during a loop.
pub struct Master {
    /// The socket and its record.
    pub peer: Peer,
    ns: u16,
    nr: u16,
}

impl Master {
    /// Connects and completes the STARTDT exchange (5-104 clause 5.3).
    pub fn connect(station: &ControlledStation) -> Self {
        let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");
        peer.start_data_transfer()
            .expect("5-104 cl.5.3: STARTDT act is confirmed");
        Self { peer, ns: 0, nr: 0 }
    }

    /// Sends one ASDU in an I-frame.
    pub fn send(&mut self, asdu: &[u8]) {
        self.peer
            .send_i(SeqNo::new(self.ns), SeqNo::new(self.nr), asdu)
            .expect("the I-frame goes out");
        self.ns += 1;
    }

    /// The next ASDU the station sends, within five seconds.
    pub fn recv(&mut self, what: &str) -> Vec<u8> {
        let (_, asdu) = self
            .peer
            .expect_i(deadline(5))
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        self.nr += 1;
        self.peer
            .send_s(SeqNo::new(self.nr))
            .expect("the S-frame goes out");
        asdu
    }

    /// Closes the connection.
    pub fn close(self) {
        self.peer.close().expect("the peer closes");
    }
}

/// Starts a station running `app` and returns it with the app's log.
pub fn start(app: CtApp) -> (ControlledStation, Arc<Mutex<CtLog>>) {
    let log = app.log();
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    (station, log)
}

/// Ends the exchange and returns the application's log.
pub fn finish(master: Master, station: ControlledStation, log: &Arc<Mutex<CtLog>>) -> CtLog {
    master.close();
    station.join().expect("the station ends cleanly");
    log.lock().expect("the log").clone()
}

/// Reads the two frames that follow a positive execute confirmation, in
/// whichever order they come (Table 19: *"regardless of the order in which they
/// occur"*), and asserts them: the `ACTTERM`, *"The Controlled station mirrors
/// the previous Command message with COT=10"*, and, for the families 5-104
/// clause 7.7 returns, the return information with cause 11 whose type 5-101
/// clause 7.4.7's NOTE pairs with the command.
pub fn expect_completion(master: &mut Master, execute: &[u8], row: &str) {
    let type_id = execute[0];
    let ioa = read_ioa(&execute[Header::LEN..]).expect("the request's address");
    let owed = if return_types(type_id).is_some() {
        2
    } else {
        1
    };
    let mut terminated = false;
    let mut returned = false;
    for _ in 0..owed {
        let frame = master.recv(&format!("{row} (type {type_id}): the completion"));
        if frame[0] == type_id {
            assert_eq!(
                frame,
                mirrored(execute, 10, false),
                "{row} (type {type_id}): \"mirrors the previous Command message with COT=10\""
            );
            terminated = true;
        } else {
            let types = return_types(type_id).unwrap_or_else(|| {
                panic!("{row} (type {type_id}): no return information is owed, got {frame:02x?}")
            });
            assert!(
                types.contains(&frame[0]),
                "{row} (type {type_id}): the RETURN_INF type {} is not one of cl.7.4.7's \
                 {types:?}",
                frame[0]
            );
            assert_eq!(
                cause_of(&frame),
                11,
                "{row} (type {type_id}): \"COT=11 (RETURN_INF caused by a remote command)\""
            );
            assert_eq!(
                read_ioa(&frame[Header::LEN..]).expect("the RETURN_INF address"),
                ioa,
                "{row} (type {type_id}): the RETURN_INF reports the commanded object"
            );
            returned = true;
        }
    }
    assert!(terminated, "{row} (type {type_id}): no ACTTERM");
    assert_eq!(
        returned,
        return_types(type_id).is_some(),
        "{row} (type {type_id}): the RETURN_INF"
    );
}

// ------------------------------------------------------------------- 5.4.19.1

/// 604 Table 19 (1 of 9), PDF page index 70 (printed 69), procedure
/// **`5.4.19.1`**, *"Command transmission – sequential procedure: Select and
/// Execute"*, `Reference` `IEC 60870-5-101:2003, 7.4.7`, every step `M`:
///
/// > The Controlling station sends a Single, Double, Regulating step or Setpoint
/// > Command message … with COT = 6, C_SC/DC/SE/RC_ACT, and S/E=1 (SELECT) to the
/// > Controlled station
/// >
/// > The Controlled station mirrors the same ASDU with COT=7,
/// > C_SC/DC/SE/RC_ACTCON, to the Controlling station
/// >
/// > The Controlling station sends the same Command message with COT=6,
/// > C_SC/DC/SE/RC_ACT, and S/E=0 (EXECUTE) to the Controlled station
/// >
/// > The Controlled station mirrors the same ASDU with COT=7,
/// > C_SC/DC/SE/RC_ACTCON, to the Controlling station
///
/// then *"The Controlled station generates an event (`RETURN_INF`) with COT=11"*
/// (`Required` `PICS, 9.6`, COT 11/12) and *"The Controlled station mirrors the
/// previous Command message with COT=10, `C_SC/DC/SE/RC_ACTTERM` (for SE if
/// supported as in the PICS)"* (`PICS, 9.6`, `C_SE ACTTERM used`: this station
/// uses it). Index 71 adds *"Command function EXECUTE after SELECT shall be
/// received within the configured delay in the controlled station"* (`M`): the
/// station's select timeout is two seconds and the execute follows at once.
///
/// DUT: the **controlled** station, both command sets, the six selectable
/// types of each; the object executes exactly once per type.
#[test]
fn clause_5_4_19_1_select_and_execute_every_selectable_type() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let (station, log) = start(CtApp::new(CommandMode::SelectAndExecute, set));
        let mut master = Master::connect(&station);
        let mut expected = Vec::new();
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            let ioa = controllable(type_id);
            let select = command(type_id, ioa, true);
            master.send(&select);
            assert_eq!(
                master.recv("5.4.19.1: the select's ACTCON"),
                mirrored(&select, 7, false),
                "5.4.19.1 (type {type_id}): the select is \"mirrored … with COT=7\""
            );
            let execute = command(type_id, ioa, false);
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.19.1: the execute's ACTCON"),
                mirrored(&execute, 7, false),
                "5.4.19.1 (type {type_id}): the execute is \"mirrored … with COT=7\""
            );
            expect_completion(&mut master, &execute, "5.4.19.1");
            expected.push(ioa);
        }
        let log = finish(master, station, &log);
        assert_eq!(
            log.executed, expected,
            "5.4.19.1 ({set:?}): each selected object executes once, on its execute"
        );
    }
}

/// 604 Table 19 (2 of 9), PDF page index 71 (printed 70), procedure
/// `5.4.19.1`, `Reference` `IEC 60870-5-101:2003, 7.4.7` and `7.2.1`,
/// `Required` `M`:
///
/// > If the EXECUTE message from the Controlling does not contain exactly the
/// > same information as the SELECT message, then the Controlled mirrors the same
/// > ASDU with COT=7, C_SC/DC/SE/RC_ACTCONneg (Negative ACTCON), to the
/// > Controlling station
///
/// DUT: the **controlled** station, both sets, the six selectable types. The
/// execute carries another command value than its select ([`altered`]); the
/// answer is that execute mirrored with `P/N = 1`, and nothing executes.
#[test]
fn clause_5_4_19_1_an_execute_that_differs_from_its_select_is_negative() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let (station, log) = start(CtApp::new(CommandMode::SelectAndExecute, set));
        let mut master = Master::connect(&station);
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            let ioa = controllable(type_id);
            let select = command(type_id, ioa, true);
            master.send(&select);
            assert_eq!(
                master.recv("5.4.19.1: the select's ACTCON"),
                mirrored(&select, 7, false),
                "5.4.19.1 (type {type_id}): the select is confirmed"
            );
            let execute = altered(&command(type_id, ioa, false));
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.19.1: the mismatched execute's answer"),
                mirrored(&execute, 7, true),
                "5.4.19.1 (type {type_id}): \"mirrors the same ASDU with COT=7, \
                 C_SC/DC/SE/RC_ACTCONneg\""
            );
        }
        let log = finish(master, station, &log);
        assert!(
            log.executed.is_empty(),
            "5.4.19.1 ({set:?}): a mismatched execute executes nothing: {:?}",
            log.executed
        );
    }
}

// ------------------------------------------------------------------ 5.4.19.10

/// 604 Table 19 (3 of 9), PDF page index 72 (printed 71), procedure
/// **`5.4.19.10`**, *"Command transmission – sequential procedure: Select and
/// Deactivation"*, `Reference` `IEC 60870-5-101:2003, 7.4.7`, every step `M`:
///
/// > The Controlling station sends the same Command message with COT=8,
/// > C_SC/DC/SE/RC_DEACT, and S/E=1 (SELECT) to the Controlled station
/// >
/// > The Controlled station mirrors the same ASDU with COT=9,
/// > C_SC/DC/SE/RC_DEACTCON, to the Controlling station
/// >
/// > Both the Controlling and Controlled stations have deactivated the Command
/// > transmission procedure
/// >
/// > The value of the Object(s) does not change at all during this command
/// > procedure
///
/// DUT: the **controlled** station, both sets, the six selectable types. That
/// the station *"has deactivated"* the procedure is observed on the wire: an
/// execute after the `DEACTCON` has no select to repeat and is answered with
/// the `ACTCONneg` of the select-and-execute function (the same answer
/// `5.4.25.3` asks for a direct execute of such an object). Nothing executes.
#[test]
fn clause_5_4_19_10_select_and_deactivation() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let (station, log) = start(CtApp::new(CommandMode::SelectAndExecute, set));
        let mut master = Master::connect(&station);
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            let ioa = controllable(type_id);
            let select = command(type_id, ioa, true);
            master.send(&select);
            assert_eq!(
                master.recv("5.4.19.10: the select's ACTCON"),
                mirrored(&select, 7, false),
                "5.4.19.10 (type {type_id}): the select is \"mirrored … with COT=7\""
            );
            let deact = mirrored(&select, 8, false);
            master.send(&deact);
            assert_eq!(
                master.recv("5.4.19.10: the DEACTCON"),
                mirrored(&select, 9, false),
                "5.4.19.10 (type {type_id}): \"mirrors the same ASDU with COT=9\""
            );
            let execute = command(type_id, ioa, false);
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.19.10: the execute after the deactivation"),
                mirrored(&execute, 7, true),
                "5.4.19.10 (type {type_id}): the procedure is deactivated, so an execute \
                 finds no select"
            );
        }
        let log = finish(master, station, &log);
        assert!(
            log.executed.is_empty(),
            "5.4.19.10 ({set:?}): \"The value of the Object(s) does not change at all\": {:?}",
            log.executed
        );
    }
}

// ------------------------------------------------------------------ 5.4.19.20

/// 604 Table 19 (4 of 9), PDF page index 73 (printed 72), procedure
/// **`5.4.19.20`**, *"Command transmission – sequential procedure: Direct
/// Execute"*, `Reference` `IEC 60870-5-101:2003, 7.4.7`:
///
/// > The Controlling station sends a Single, Double, Regulating step, Setpoint or
/// > Bitstring Command message … with COT = 6, C_SC/DC/SE/RC_ACT and S/E=0
/// > (EXECUTE) to the Controlled station
/// >
/// > The Controlled station mirrors the same ASDU with COT=7,
/// > C_SC/DC/SE/RC_ACTCON, to the Controlling station
///
/// (both `M`), then the `RETURN_INF` with COT 11 and the ACTTERM, *"The
/// Controlled station mirrors the previous Command message with COT=10"*
/// (`PICS, 9.6`).
///
/// DUT: the **controlled** station of the direct-execute function, both sets,
/// all seven types each (the bitstring included, as the row names it).
#[test]
fn clause_5_4_19_20_direct_execute_every_type() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let (station, log) = start(CtApp::new(CommandMode::Direct, set));
        let mut master = Master::connect(&station);
        let mut expected = Vec::new();
        for type_id in set_types(set) {
            let ioa = controllable(type_id);
            let execute = command(type_id, ioa, false);
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.19.20: the ACTCON"),
                mirrored(&execute, 7, false),
                "5.4.19.20 (type {type_id}): \"mirrors the same ASDU with COT=7\""
            );
            expect_completion(&mut master, &execute, "5.4.19.20");
            expected.push(ioa);
        }
        let log = finish(master, station, &log);
        assert_eq!(
            log.executed, expected,
            "5.4.19.20 ({set:?}): each command executes once"
        );
    }
}

// ------------------------------------------------------------------ 5.4.19.30

/// The negative answer 5.4.19.30/.50 allow for an object that does not exist:
/// the `ACTCONneg`, or *"instead mirror the same ASDU with COT=47 (unknown
/// Information Object Address) … (if supported (see PICS clause 8.5)"*.
fn assert_unknown_object_refused(answer: &[u8], request: &[u8], row: &str) {
    let type_id = request[0];
    assert!(
        answer == mirrored(request, 7, true) || answer == mirrored(request, 47, true),
        "{row} (type {type_id}): a not existing object is mirrored with P/N = 1 and COT 7 or \
         47, got {answer:02x?}"
    );
}

/// 604 Table 19 (5 of 9), PDF page index 74 (printed 73), procedure
/// **`5.4.19.30`**, *"Command transmission – sequential procedure: Select with
/// Negative Confirmation by Controlled station (Abort)"*, `Reference`
/// `IEC 60870-5-101:2003, 7.4.7` and `7.2.3`, `IEC 60870-5-104:2006, 6`:
///
/// > The Controlling station sends a Single, Double, Regulating step or Setpoint
/// > Command message … with COT = 6, C_SC/DC/SE/RC_ACT, and S/E=1 (SELECT) to the
/// > Controlled station for a not controllable or not existing Information
/// > object
/// >
/// > The Controlled station mirrors the same ASDU with COT=7,
/// > C_SC/DC/SE/RC_ACTCONneg (Negative ACTCON) to the controlling station. In
/// > case of a not existing Information object, the controlled station could
/// > instead mirror the same ASDU with COT=47 (unknown Information Object
/// > Address) to the Controlling station (if supported (see PICS clause 8.5)
/// >
/// > The value of the Object(s) does not change at all during this command
/// > procedure
///
/// DUT: the **controlled** station, both sets, the six selectable types, one
/// not-controllable and one not-existing object each. An execute that follows
/// the refused select finds no select and is refused too, so nothing executes.
#[test]
fn clause_5_4_19_30_a_select_of_a_refused_object_is_negative() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let (station, log) = start(CtApp::new(CommandMode::SelectAndExecute, set));
        let mut master = Master::connect(&station);
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            let select = command(type_id, not_controllable(type_id), true);
            master.send(&select);
            assert_eq!(
                master.recv("5.4.19.30: the not-controllable select's answer"),
                mirrored(&select, 7, true),
                "5.4.19.30 (type {type_id}): \"mirrors the same ASDU with COT=7, \
                 C_SC/DC/SE/RC_ACTCONneg\""
            );
            let execute = command(type_id, not_controllable(type_id), false);
            master.send(&execute);
            assert!(
                negative(&master.recv("5.4.19.30: the execute after the refusal")),
                "5.4.19.30 (type {type_id}): a refused select leaves nothing to execute"
            );

            let select = command(type_id, not_existing(type_id), true);
            master.send(&select);
            let answer = master.recv("5.4.19.30: the not-existing select's answer");
            assert_unknown_object_refused(&answer, &select, "5.4.19.30");
        }
        let log = finish(master, station, &log);
        assert!(
            log.executed.is_empty(),
            "5.4.19.30 ({set:?}): \"The value of the Object(s) does not change at all\": {:?}",
            log.executed
        );
    }
}

/// 604 Table 19 (5 of 9), PDF page index 74, procedure `5.4.19.30`, and (7 of
/// 9), index 76, procedure `5.4.19.50`, the same row in both, `Reference`
/// `IEC 60870-5-101:2003, 7.4.7` and `7.2.3`, `Required` `M`:
///
/// > The controlled station does not accept and responds with a P/N=1 if a not
/// > allowed command (e.g. DCO=0 or 3; RCO=0 or 3) is received
///
/// DUT: the **controlled** station, a select-and-execute station (the select
/// and the execute) and a direct-execute station (the execute), both sets. The
/// types are the four whose element carries a `DCS` or `RCS`: 46, 47, 59 and
/// 60 (5-101 clause 7.2.6.16/.17 print `<0>` and `<3>` *"not permitted"*). The
/// answer is the request mirrored with `P/N = 1`, and nothing executes.
#[test]
fn clause_5_4_19_30_and_50_a_not_allowed_command_state_is_negative() {
    for mode in [CommandMode::SelectAndExecute, CommandMode::Direct] {
        for set in [CommandSet::Untagged, CommandSet::Tagged] {
            let (station, log) = start(CtApp::new(mode, set));
            let mut master = Master::connect(&station);
            let types: Vec<u8> = set_types(set)
                .into_iter()
                .filter(|t| matches!(t, 46 | 47 | 59 | 60))
                .collect();
            assert_eq!(types.len(), 2, "two state commands per set");
            for type_id in types {
                for state in [0u8, 3] {
                    let mut requests = vec![command(type_id, controllable(type_id), false)];
                    if mode == CommandMode::SelectAndExecute {
                        requests.insert(0, command(type_id, controllable(type_id), true));
                    }
                    for request in requests {
                        let request = with_state(&request, state);
                        master.send(&request);
                        assert_eq!(
                            master.recv("5.4.19.30/.50: the not-allowed command's answer"),
                            mirrored(&request, 7, true),
                            "5.4.19.30/.50 ({mode:?}, type {type_id}, state {state}): \
                             \"responds with a P/N=1\""
                        );
                    }
                }
            }
            let log = finish(master, station, &log);
            assert!(
                log.executed.is_empty(),
                "5.4.19.30/.50 ({mode:?}, {set:?}): \"does not accept\": {:?}",
                log.executed
            );
        }
    }
}

// ------------------------------------------------------------------ 5.4.19.40

/// 604 Table 19 (6 of 9), PDF page index 75 (printed 74), procedure
/// **`5.4.19.40`**, *"Command transmission – sequential procedure: Select with
/// Negative Execute Confirmation by Controlled station if Execute is received
/// after configured delay in the controlling station"*, `Reference`
/// `IEC 60870-5-101:2003, 7.4.7`, `7.2.3`, each step `M`:
///
/// > The Controlling station sends the same Command message with COT=6,
/// > C_SC/DC/SE/RC_ACT, and S/E=0 (EXECUTE) to the Controlled station AFTER the
/// > configured delay in the controlling station
/// >
/// > The Controlled station mirrors the same ASDU with COT=7,
/// > C_SC/DC/SE/RC_ACTCONneg (Negative ACTCON) to the Controlling station
/// >
/// > The value of the Object(s) does not change at all during this command
/// > procedure
///
/// DUT: the **controlled** station, both sets, the six selectable types; its
/// configured delay is 150 ms and the executes follow 400 ms after the selects.
/// The row's PIXIT alternative (positive `ACTCON`, then a negative `ACTTERM`) is
/// not this station's choice; see the module doc.
#[test]
fn clause_5_4_19_40_an_execute_after_the_configured_delay_is_negative() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let app = CtApp::new(CommandMode::SelectAndExecute, set)
            .with_select_timeout(Duration::from_millis(150));
        let (station, log) = start(app);
        let mut master = Master::connect(&station);
        let types: Vec<u8> = set_types(set)
            .into_iter()
            .filter(|t| selectable(*t))
            .collect();
        for &type_id in &types {
            let select = command(type_id, controllable(type_id), true);
            master.send(&select);
            assert_eq!(
                master.recv("5.4.19.40: the select's ACTCON"),
                mirrored(&select, 7, false),
                "5.4.19.40 (type {type_id}): the select is confirmed"
            );
        }
        thread::sleep(Duration::from_millis(400));
        for &type_id in &types {
            let execute = command(type_id, controllable(type_id), false);
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.19.40: the late execute's answer"),
                mirrored(&execute, 7, true),
                "5.4.19.40 (type {type_id}): \"mirrors the same ASDU with COT=7, \
                 C_SC/DC/SE/RC_ACTCONneg\""
            );
        }
        let log = finish(master, station, &log);
        assert!(
            log.executed.is_empty(),
            "5.4.19.40 ({set:?}): \"The value of the Object(s) does not change at all\": {:?}",
            log.executed
        );
    }
}

// ------------------------------------------------------------------ 5.4.19.50

/// 604 Table 19 (7 of 9), PDF page index 76 (printed 75), procedure
/// **`5.4.19.50`**, *"Command transmission – sequential procedure: Direct
/// Execute with Negative Confirmation by Controlled station"*, `Reference`
/// `IEC 60870-5-101:2003, 7.4.7` and `7.2.3`, `IEC 60870-5-104:2006, 6`:
///
/// > The Controlling station sends a Single, Double, Regulating step, Setpoint or
/// > Bitstring Command message … with COT = 6, C_SC/DC/SE/RC_ACT, and S/E=0
/// > (EXECUTE) to the Controlled station for a not-controllable or not existing
/// > Information object
/// >
/// > The Controlled station mirrors the same ASDU with COT=7,
/// > C_SC/DC/SE/RC_ACTCONneg (Negative ACTCON), to the Controlling station. In
/// > case of a not existing Information object, the controlled station could
/// > instead mirror the same ASDU with COT=47 (unknown Information Object
/// > Address) to the Controlling station (if supported (see PICS clause 8.5)
/// >
/// > The Controlled station does NOT change the status of the (Process)
/// > Information Object that is associated with the command object
///
/// and the PIXIT alternative, *"in case of a not-controllable Information
/// object, the Controlled station can first accept the command with a Positive
/// ACTCON and then send a Negative Termination by mirroring the previous
/// Command message with COT=10 … and P/N=1"*.
///
/// DUT: the **controlled** station of the direct-execute function, both sets,
/// all seven types: a not-controllable object, a not-existing one, and an
/// object whose process refuses the command after the crate confirmed it (the
/// alternative, built by `CommandTransmission::terminate` with `negative`).
#[test]
fn clause_5_4_19_50_a_direct_execute_of_a_refused_object_is_negative() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let (station, log) = start(CtApp::new(CommandMode::Direct, set));
        let mut master = Master::connect(&station);
        for type_id in set_types(set) {
            let execute = command(type_id, not_controllable(type_id), false);
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.19.50: the not-controllable execute's answer"),
                mirrored(&execute, 7, true),
                "5.4.19.50 (type {type_id}): \"mirrors the same ASDU with COT=7, \
                 C_SC/DC/SE/RC_ACTCONneg\""
            );

            let execute = command(type_id, not_existing(type_id), false);
            master.send(&execute);
            let answer = master.recv("5.4.19.50: the not-existing execute's answer");
            assert_unknown_object_refused(&answer, &execute, "5.4.19.50");

            let execute = command(type_id, fails_after_accept(type_id), false);
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.19.50: the alternative's positive ACTCON"),
                mirrored(&execute, 7, false),
                "5.4.19.50 (type {type_id}): \"first accept the command with a Positive ACTCON\""
            );
            assert_eq!(
                master.recv("5.4.19.50: the alternative's negative ACTTERM"),
                mirrored(&execute, 10, true),
                "5.4.19.50 (type {type_id}): \"a Negative Termination by mirroring the previous \
                 Command message with COT=10 … and P/N=1\""
            );
        }
        let log = finish(master, station, &log);
        assert!(
            log.executed.is_empty(),
            "5.4.19.50 ({set:?}): \"does NOT change the status of the (Process) Information \
             Object\": {:?}",
            log.executed
        );
    }
}

// ------------------------------------------------------- 5.4.19.60/.70/.75

/// 604 Table 19 (8 of 9), PDF page index 77 (printed 76), procedure
/// **`5.4.19.60`**, *"Command transmission with network delay supervision –
/// sequential procedure: Command received WITHIN configured delay"*,
/// `Reference` `IEC 60870-5-104:2006, 8` and `9.6`, each step `M`:
///
/// > The Controlled station accepts the Command message if the time difference
/// > between time tag in the Command message and the local time in the
/// > Controlled station is less than or equal to the configured maximum
/// > allowable delay of commands
/// >
/// > After accepting the command, normal command processing continues (see
/// > above)
///
/// DUT: the **controlled** station of the time-tagged set, direct execute, all
/// seven types `<58>`–`<64>`. The station's maximum delay is ten seconds and
/// its clock reads exactly ten seconds after each command's tag: the row's
/// *"less than or equal to"* boundary.
#[test]
fn clause_5_4_19_60_a_command_within_the_configured_delay_is_processed() {
    let app = CtApp::new(CommandMode::Direct, CommandSet::Tagged)
        .with_wall_clock(time_at(12, 0, 10_000, false));
    let (station, log) = start(app);
    let mut master = Master::connect(&station);
    let mut expected = Vec::new();
    for type_id in set_types(CommandSet::Tagged) {
        let execute = command(type_id, controllable(type_id), false);
        master.send(&execute);
        assert_eq!(
            master.recv("5.4.19.60: the ACTCON"),
            mirrored(&execute, 7, false),
            "5.4.19.60 (type {type_id}): accepted at a delay equal to the maximum"
        );
        expect_completion(&mut master, &execute, "5.4.19.60");
        expected.push(controllable(type_id));
    }
    let log = finish(master, station, &log);
    assert_eq!(
        log.executed, expected,
        "5.4.19.60: \"normal command processing continues\""
    );
}

/// Sends every time-tagged request of `requests` to a station whose clock is
/// `wall_clock`, then a probe command whose tag equals that clock, and asserts
/// that the first answer is the probe's: the requests got **no** protocol
/// response, as 5-104 clause 8 (index 74) says, *"the controlled station does not
/// return a positive ACTCON nor a negative ACTCON"*. The station answers frames
/// in the order they arrive, so an answer to any request would come first.
/// Returns the log without the probe's own execution.
fn no_response_to(
    requests: &[Vec<u8>],
    mode: CommandMode,
    wall_clock: Cp56Time2a,
    row: &str,
) -> CtLog {
    let app = CtApp::new(mode, CommandSet::Tagged).with_wall_clock(wall_clock);
    let (station, log) = start(app);
    let mut master = Master::connect(&station);
    for request in requests {
        master.send(request);
    }
    let probe_ioa = controllable(60) + 0x100;
    let probe = command_at(60, probe_ioa, false, wall_clock);
    let probe = if mode == CommandMode::SelectAndExecute {
        let mut select = probe;
        select[Header::LEN + 3] |= 0x80;
        select
    } else {
        probe
    };
    master.send(&probe);
    assert_eq!(
        master.recv(&format!("{row}: the probe's ACTCON")),
        mirrored(&probe, 7, false),
        "{row}: the first answer is the probe's, so no request was answered"
    );
    let mut log = finish(master, station, &log);
    log.executed.retain(|ioa| *ioa != probe_ioa);
    log
}

/// 604 Table 19 (8 of 9), PDF page index 77 (printed 76), procedure
/// **`5.4.19.70`**, *"Command transmission with network delay supervision –
/// sequential procedure: Command received AFTER configured delay"*, `Reference`
/// `IEC 60870-5-104:2006, 8` and `9.6`, each step `M`:
///
/// > The Controlled station accepts the Command message if the time difference
/// > between time tag in the Command message and the local time in the
/// > Controlled station exceeds the configured maximum allowable delay of
/// > commands [and passes it to the controlled station application to identify
/// > that a command was received "too late"]
/// >
/// > [After accepting the command, NO protocol response is returned (the ASDU IS
/// > NOT MIRRORED with COT=7, C_SC/DC/SE/RC_ACTCON), to the Controlling station]
/// >
/// > [NO command process is activated in the Controlled station and therefore NO
/// > status change occurs]
///
/// DUT: the **controlled** station of the time-tagged set, all seven types as a
/// direct execute and the six selectable ones as a select, whose clock reads
/// 10.001 s after the tags: one millisecond over the ten-second maximum. The
/// application is told (`Reaction::TooLate`), nothing is answered, nothing
/// executes.
#[test]
fn clause_5_4_19_70_a_command_after_the_configured_delay_gets_no_response() {
    let late = time_at(12, 0, 10_001, false);
    for mode in [CommandMode::Direct, CommandMode::SelectAndExecute] {
        let requests: Vec<Vec<u8>> = set_types(CommandSet::Tagged)
            .into_iter()
            .filter(|t| mode == CommandMode::Direct || selectable(*t))
            .map(|t| command(t, controllable(t), mode == CommandMode::SelectAndExecute))
            .collect();
        let log = no_response_to(&requests, mode, late, "5.4.19.70");
        let too_late = log
            .reactions
            .iter()
            .filter(|r| matches!(r, Reaction::TooLate { .. }))
            .count();
        assert_eq!(
            too_late,
            requests.len(),
            "5.4.19.70 ({mode:?}): every late command reaches the application as \"too late\""
        );
        assert!(
            log.executed.is_empty(),
            "5.4.19.70 ({mode:?}): \"NO status change occurs\": {:?}",
            log.executed
        );
    }
}

/// 604 Table 19 (8 of 9), PDF page index 77 (printed 76), procedure
/// **`5.4.19.75`**, *"Command transmission – Command received with time tag in
/// the future"*, `Reference` `IEC 60870-5-104:2006, 8`, `Required` `M`:
///
/// > The Controlled station behaves in the same way as described in test case
/// > "Command received AFTER configured delay"
///
/// DUT: the **controlled** station of the time-tagged set, all seven types as a
/// direct execute, whose clock reads 11:59:49.999, 10.001 s **before** the
/// commands' 12:00:00.000 tag.
#[test]
fn clause_5_4_19_75_a_command_from_the_future_gets_no_response() {
    let early = time_at(11, 59, 49_999, false);
    let requests: Vec<Vec<u8>> = set_types(CommandSet::Tagged)
        .into_iter()
        .map(|t| command(t, controllable(t), false))
        .collect();
    let log = no_response_to(&requests, CommandMode::Direct, early, "5.4.19.75");
    assert_eq!(
        log.reactions
            .iter()
            .filter(|r| matches!(r, Reaction::TooLate { .. }))
            .count(),
        requests.len(),
        "5.4.19.75: every command from the future is treated as too late"
    );
    assert!(
        log.executed.is_empty(),
        "5.4.19.75: nothing executes: {:?}",
        log.executed
    );
}

// ------------------------------------------------------------------ 5.4.19.85

/// 604 Table 19 (9 of 9), PDF page index 78 (printed 77), procedure
/// **`5.4.19.85`**, *"Command transmission – Commands with or without time
/// tag"*, `Reference` `IEC 60870-5-104:2006, 9.5`, `Required` `PICS, 9.5`:
///
/// > Either the ASDUs of the set <45> – <51> or of the set <58> – <64> are used
/// > or configured at the same time
///
/// DUT: the **controlled** station, each set against every type of the other.
/// A type outside the station's set is one it does not implement, so the
/// expected answer is 5-101 clause 7.2.3's (index 42): *"ASDUs in the control
/// direction with undefined values in the data unit identifier … are mirrored
/// by the controlled station with bit "P/N := <1> negative confirm""* and cause
/// 44 for the type identification. Nothing executes.
#[test]
fn clause_5_4_19_85_the_other_command_set_is_not_accepted() {
    for (set, other) in [
        (CommandSet::Untagged, CommandSet::Tagged),
        (CommandSet::Tagged, CommandSet::Untagged),
    ] {
        let (station, log) = start(CtApp::new(CommandMode::Direct, set));
        let mut master = Master::connect(&station);
        for type_id in set_types(other) {
            let execute = command(type_id, controllable(type_id), false);
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.19.85: the other set's answer"),
                mirrored(&execute, 44, true),
                "5.4.19.85 ({set:?} station, type {type_id}): mirrored with cause 44, P/N = 1"
            );
        }
        let log = finish(master, station, &log);
        assert!(
            log.executed.is_empty(),
            "5.4.19.85 ({set:?}): the other set executes nothing: {:?}",
            log.executed
        );
    }
}

// ------------------------------------------------------------------ 5.4.19.86

/// The station's general interrogation data: three single points, cause 20
/// (5-101 clause 7.4.5's *"interrogated by station interrogation"*).
struct GiData;

impl DataSource for GiData {
    fn ready(&self, _scope: Scope) -> bool {
        true
    }

    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
        for ioa in 0x7001..=0x7003 {
            let header = Header {
                type_id: TypeId::MSpNa1,
                sequence: false,
                count: 1,
                cause: scope.cause(),
                negative: false,
                test: false,
                originator: 0,
                common_address: CA,
            };
            let object = LayoutObject {
                ioa,
                value: MSpNa1 {
                    siq: Siq::default(),
                },
            };
            out.push(encode_asdu(&header, &[object]).expect("the GI data builds"));
        }
    }
}

/// [`CtApp`] beside a general interrogation (`gi::Interrogation` in the
/// controlled role). The interrogation's data and termination are held back
/// until `release_after` commands have executed (or three seconds have
/// passed), so every command of the case arrives while the interrogation is
/// running.
struct GiCtApp {
    commands: CtApp,
    gi: Interrogation,
    release_after: usize,
    started: Option<Instant>,
}

impl StationApp for GiCtApp {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
        if header.type_id != TypeId::CIcNa1 {
            return self.commands.on_asdu(asdu);
        }
        let known = Known::standard(&header, header.common_address == CA, true);
        let outcome = self
            .gi
            .on_request(asdu, &known, &GiData)
            .map_err(|e| format!("the interrogation: {e:?}"))?;
        self.started = Some(Instant::now());
        Ok(outcome.send)
    }

    fn poll(&mut self, now: Instant) -> Result<Vec<Vec<u8>>, String> {
        let owed = self.commands.poll(now)?;
        if !owed.is_empty() || !self.gi.is_running(Scope::Station) {
            return Ok(owed);
        }
        let executed = self.commands.log.lock().expect("the log").executed.len();
        let waited = self
            .started
            .is_some_and(|at| now.duration_since(at) > Duration::from_secs(3));
        if executed >= self.release_after || waited {
            return self
                .gi
                .complete(&GiData)
                .map_err(|e| format!("the interrogation's end: {e:?}"));
        }
        Ok(Vec::new())
    }
}

/// 604 Table 19 (9 of 9), PDF page index 78 (printed 77), procedure
/// **`5.4.19.86`**, *"Command transmission – Command received during GI"*,
/// `Reference` `IEC 60870-5-5:1995, 5` and `IEC 60870-5-101:2003, 7.4`,
/// `Required` `PICS, 9.5`:
///
/// > Command function during a running general interrogation is processed and
/// > executed without waiting for the GI to finish. This is performed correctly
/// > by every supported ASDU according to the PICS. If ASDUs are configurable to
/// > use Select and Execute or Direct Execute, then test each ASDU at once (with
/// > Select and Execute or Direct Execute) and one ASDU with both Select and
/// > Execute and Direct Execute.
///
/// DUT: the **controlled** station, both sets. The crate's mode is a station
/// setting, so the row's two configurations are two stations: a
/// direct-execute station takes all seven types as a direct execute, and a
/// select-and-execute station takes the six selectable types by select and
/// execute and the bitstring (which has no `S/E` bit) by direct execute, the
/// row's *"one ASDU with both"*. The station interrogation is confirmed first
/// and its termination (the activation mirrored with cause 10, 5-101 clause
/// 7.4.5) must come after every command has been confirmed, terminated and
/// executed.
#[test]
fn clause_5_4_19_86_a_command_during_a_general_interrogation_is_processed() {
    for mode in [CommandMode::Direct, CommandMode::SelectAndExecute] {
        for set in [CommandSet::Untagged, CommandSet::Tagged] {
            let types = set_types(set);
            let app = GiCtApp {
                commands: CtApp::new(mode, set),
                gi: Interrogation::controlled(ReActivation::Continue, CA, 0),
                release_after: types.len(),
                started: None,
            };
            let log = app.commands.log();
            let station = ControlledStation::start_app(app, Vec::new()).expect("the station");
            let mut master = Master::connect(&station);

            // C_IC_NA_1, cause 6, IOA 0, QOI 20: station interrogation (5-101
            // cl.7.3.4.1 and 7.2.6.22).
            let gi = asdu_with_body(100, 6, CA, &[0, 0, 0, 20]);
            master.send(&gi);
            assert_eq!(
                master.recv("5.4.19.86: the GI's ACTCON"),
                mirrored(&gi, 7, false),
                "5.4.19.86 ({mode:?}, {set:?}): the interrogation is confirmed and running"
            );
            for type_id in types {
                let ioa = controllable(type_id);
                if mode == CommandMode::SelectAndExecute && selectable(type_id) {
                    let select = command(type_id, ioa, true);
                    master.send(&select);
                    assert_eq!(
                        master.recv("5.4.19.86: the select's ACTCON"),
                        mirrored(&select, 7, false),
                        "5.4.19.86 ({mode:?}, type {type_id}): the select during the GI"
                    );
                }
                let execute = command(type_id, ioa, false);
                master.send(&execute);
                assert_eq!(
                    master.recv("5.4.19.86: the execute's ACTCON"),
                    mirrored(&execute, 7, false),
                    "5.4.19.86 ({mode:?}, type {type_id}): the execute during the GI, not after it"
                );
                expect_completion(&mut master, &execute, "5.4.19.86");
            }
            for _ in 0..3 {
                let data = master.recv("5.4.19.86: the GI data");
                assert_eq!(
                    (data[0], cause_of(&data)),
                    (1, 20),
                    "5.4.19.86 ({mode:?}, {set:?}): the interrogated data follows the commands"
                );
            }
            assert_eq!(
                master.recv("5.4.19.86: the GI's ACTTERM"),
                mirrored(&gi, 10, false),
                "5.4.19.86 ({mode:?}, {set:?}): the interrogation ends after the commands"
            );
            let log = finish(master, station, &log);
            assert_eq!(
                log.executed.len(),
                types.len(),
                "5.4.19.86 ({mode:?}, {set:?}): every command executed during the GI"
            );
        }
    }
}
