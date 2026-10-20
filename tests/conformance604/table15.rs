//! 604 Table 15, *"Data acquisition through read function conformance test
//! procedures"*, PDF page index 62 (printed 61), procedures `5.4.15.1` (*"Data
//! acquisition through Read – sequential procedure"*) and `5.4.15.10`
//! (*"COMPATIBILITY WITH OTHER TEST CASES"*).
//!
//! The block's NOTE: the tests apply only to a system that supports data
//! acquisition through read. The crate supports it (`rd`), so
//! every row applies.
//!
//! # The rows, and where each one is
//!
//! | Row (description, abridged) | Required | Here |
//! | --- | --- | --- |
//! | the controlling station sends `C_RD` (ASDU 102) with COT=5 | M | [`clause_5_4_15_1_the_controlling_station_reads_every_returned_type`] |
//! | the controlled station answers with the configured ASDU | M | [`clause_5_4_15_1_the_controlled_station_answers_with_the_configured_asdu`] |
//! | values stored on the controlling station = values on the controlled station | M | both cases, one per role |
//! | every ASDU in the PICS with COT=5 | M | both cases loop over 5-101 clause 7.4.14's returned types |
//! | all applicable §5.3 items reviewed, no manual intervention | M | the whole suite |
//! | `5.4.15.10` compatibility with other test cases | M | the whole suite, as in `tests/conformance_604.rs` |
//!
//! # The type set
//!
//! The row's set, every ASDU of the PICS with cause 5, is 5-101 clause 7.4.14's list
//! (PDF page index 150) of the `M_REQ` types a controlled station may return
//! in the monitor direction, intersected with 104 clause 9's time-tag rule
//! (PDF page index 100: of the time-tagged ASDUs, 104 permits only types
//! `<30>` to `<40>`): the nine untagged types and
//! their seven `CP56Time2a` alternatives, [`RETURNED`]. The list's `<126>`
//! `F_DR_TA_1` is file transfer (Table 23) and is not driven here.
//!
//! # Direction
//!
//! Both roles are driven: the read command is the controlling station's, the
//! answer the controlled station's, and each case checks the other side's
//! half through a mock. The reverse direction of §5.1 is not otherwise
//! meaningful here: 5-101 figure 74 (index 106) defines `C_RD_NA_1` with
//! `<5> := request` in the control direction only. §5.1's COT44–47 exception
//! does not apply: no case here sends those causes.

use std::sync::{Arc, Mutex};

use crate::conformance604::acquisition::{
    LayoutVisitor, Scripted, Stored, assert_single_object, next_nr, read_i_frames, sample_value,
    started_controlling, station_i_frames, station_known, station_send, visit_monitor_layout,
};
use crate::conformance604::{
    CA, ControlledStation, ORIGINATOR, Peer, StationApp, asdu_with_body, deadline,
    sample_object_area,
};
use iec104::apci::SeqNo;
use iec104::asdu::{AsduLayout, Cause, Header, Known, LayoutObject, read_ioa};
use iec104::rd::{DataSource, RETURNED_TYPES, Reaction, Read, answer};

/// The returned types of 5-101 clause 7.4.14 (PDF page index 150) a 104 station
/// may answer a read with: `<1>`, `<3>`, `<5>`, `<7>`, `<9>`, `<11>`, `<13>`,
/// `<20>`, `<21>` and the `CP56Time2a` alternatives `<30>` to `<36>`.
const RETURNED: [u8; 16] = [1, 3, 5, 7, 9, 11, 13, 20, 21, 30, 31, 32, 33, 34, 35, 36];

/// The address the station holds the `i`-th returned type at.
const fn address(i: usize) -> u32 {
    0x4000 + i as u32
}

/// The originator address the read commands of the controlled-station case
/// carry, nonzero so its echo (5-101 clause 7.2.3) is visible.
const SOURCE: u8 = 7;

/// One read command, octet by octet from 5-101 figure 74 (clause 7.3.4.3, PDF
/// page index 106): type 102, SQ = 0 N = 1, `<5> := request`, the originator,
/// CA 1, and the three-octet address of the object to read; no element.
fn read_command(ioa: u32, originator: u8) -> Vec<u8> {
    let a = ioa.to_le_bytes();
    vec![102, 0x01, 0x05, originator, 0x01, 0x00, a[0], a[1], a[2]]
}

/// 604 Table 15, PDF page index 62 (printed 61), procedure **`5.4.15.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.3.4.3` / `IEC 60870-5-5:1995, 6.2.1`,
/// `Required` `M`:
///
/// the controlling station sends the controlled station a read command
/// (`C_RD`, type 102) with cause 5, for the ASDUs its PICS lists;
///
/// and the `M` rows that the values the controlling station receives and
/// stores should be the controlled station's actual values, and that the tests
/// run for every ASDU of the PICS that supports cause 5 (`REQ`).
///
/// DUT: the **controlling** station, `rd::Read::controlling` over
/// `interop::Station`. For each type of [`RETURNED`] it reads the object the
/// mock controlled peer holds at [`address`]; the peer records the command
/// and answers with that object, cause `<5>`, written from 5-101 clause 7.3's
/// geometry for its type (`sample_object_area`) with a value octet of 1.
///
/// Expected: every command is exactly figure 74's nine octets (index 106), and
/// every answer is `rd::Reaction::Answered` with the type and address the
/// peer used, and the value the station decodes from it (the crate's layout,
/// `asdu::decode_asdu`) is the one the peer holds.
#[test]
fn clause_5_4_15_1_the_controlling_station_reads_every_returned_type() {
    let station_answers = |command: &[u8]| -> Vec<Vec<u8>> {
        let ioa = read_ioa(&command[Header::LEN..]).expect("the command's address");
        let i = (ioa - 0x4000) as usize;
        vec![held_object(RETURNED[i], ioa)]
    };
    let (peer_app, received) = Scripted::answering(Vec::new(), Box::new(station_answers));
    let peer = ControlledStation::start_app(peer_app, Vec::new()).expect("the mock binds");
    let mut station = started_controlling(&peer).expect("the controlling station starts");
    let dut = Read::controlling(true, CA, ORIGINATOR);

    let mut answers = Vec::new();
    for i in 0..RETURNED.len() {
        let command = dut.request(address(i)).expect("the read command");
        station_send(&mut station, &command).expect("the command goes out");
        answers.extend(station_i_frames(&mut station, 1, deadline(5)).expect("the answer"));
    }
    station.close().expect("close");
    let _ = peer.join();

    let commands = received.lock().expect("the record").clone();
    assert_eq!(
        commands.len(),
        RETURNED.len(),
        "5.4.15.1: one command per object"
    );
    for (i, command) in commands.iter().enumerate() {
        assert_eq!(
            command,
            &read_command(address(i), ORIGINATOR),
            "5.4.15.1: a read command (C_RD, type 102) with cause 5, figure 74's octets"
        );
    }
    for (i, answer) in answers.iter().enumerate() {
        let type_id = RETURNED[i];
        let header = Header::parse(answer).expect("the header");
        let known = Known::standard(&header, header.common_address == CA, true);
        let outcome = dut
            .on_response(answer, &known)
            .expect("the station takes it");
        assert_eq!(
            outcome.reaction,
            Reaction::Answered {
                type_id: header.type_id,
                ioa: address(i)
            },
            "5.4.15.1 (type {type_id}): the answer to the read"
        );
        assert_eq!(
            header.type_id.to_u8(),
            type_id,
            "5.4.15.1: the type the peer holds"
        );
        assert_eq!(
            answer,
            &held_object(type_id, address(i)),
            "5.4.15.1 (type {type_id}): the octets the peer sent"
        );
        let stored = visit_monitor_layout(
            type_id,
            &mut Stored {
                asdu: answer,
                marker: 1,
            },
        )
        .expect("a layout");
        assert_eq!(
            stored,
            Ok(vec![address(i)]),
            "5.4.15.1 (type {type_id}): the values stored on the controlling station must be \
             the controlled station's actual values"
        );
    }
}

/// The mock controlled peer's object of `type_id` at `ioa`, cause `<5>`: 5-101
/// clause 7.3's geometry for its type with a value octet of 1.
fn held_object(type_id: u8, ioa: u32) -> Vec<u8> {
    let mut area = sample_object_area(type_id, ioa);
    area[3] = 1;
    asdu_with_body(type_id, Cause::Request.to_u8(), CA, &area)
}

/// The controlled station's answer for one object: `rd::answer` for the
/// visited layout, the object at `ioa` holding <code>[sample_value](1)</code>.
struct Answer<'a> {
    ioa: u32,
    command: &'a [u8],
}

impl LayoutVisitor for Answer<'_> {
    type Out = Option<Vec<u8>>;

    fn visit<A: AsduLayout + PartialEq + std::fmt::Debug + Copy + Send + 'static>(
        &mut self,
    ) -> Self::Out {
        let object = LayoutObject {
            ioa: self.ioa,
            value: sample_value::<A>(1),
        };
        answer(&object, self.command, CA).ok()
    }
}

/// The station's process image for a read: the `i`-th type of [`RETURNED`] at
/// <code>[address](i)</code>, nothing anywhere else. Each object's answer is built by
/// `rd::answer` from the command, which is how it echoes the command's
/// originator and test bit.
struct Image<'a> {
    command: &'a [u8],
}

impl DataSource for Image<'_> {
    fn object(&self, ioa: u32) -> Option<Vec<u8>> {
        let i = ioa.checked_sub(0x4000)? as usize;
        let type_id = *RETURNED.get(i)?;
        visit_monitor_layout(
            type_id,
            &mut Answer {
                ioa,
                command: self.command,
            },
        )?
    }
}

/// The controlled station under test: `rd::Read::controlled` answering from
/// [`Image`].
struct ReadApp {
    read: Read,
    requested: Arc<Mutex<Vec<u32>>>,
}

impl StationApp for ReadApp {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let outcome = self
            .read
            .on_request(asdu, &station_known(asdu)?, &Image { command: asdu })
            .map_err(|e| format!("rd: {e:?}"))?;
        if let Reaction::Requested { ioa } = outcome.reaction {
            self.requested.lock().map_err(|_| "poisoned")?.push(ioa);
        }
        Ok(outcome.send)
    }
}

/// 604 Table 15, PDF page index 62 (printed 61), procedure **`5.4.15.1`**,
/// `Reference` `IEC 60870-5-101:2003, 7.3.1` / `IEC 60870-5-101:2003, 7.4.2` /
/// `IEC 60870-5-5:1995, 6.2.1`, `Required` `M`:
///
/// the controlled station answers with the requested information object, in
/// the ASDU type configured for that object (PICS 9.5, *"Type identification
/// and cause of transmission assignments"*, lists them);
///
/// and the `M` rows on the values and on every ASDU with COT=5.
///
/// DUT: the **controlled** station, `rd::Read::controlled` answering from a
/// process image that holds the `i`-th type of [`RETURNED`] at
/// <code>[address](i)</code>. The mock controlling station reads each address with
/// figure 74's command. `rd::RETURNED_TYPES` is checked against 5-101 clause
/// 7.4.14's list first, so the loop is the standard's set.
///
/// Expected, from the standard: the answer is the ASDU configured for the
/// address (its type), with cause `<5>` (5-101 clause 7.4.14, index 150: the
/// answer is an `M_PDU` carrying cause `<5>` `REQ`), one
/// object at the address read, the value the station holds, the station's
/// common address, and the command's originator address echoed (5-101 clause
/// 7.2.3: the controlled station should return the command's originator
/// address in its monitor-direction answer).
#[test]
fn clause_5_4_15_1_the_controlled_station_answers_with_the_configured_asdu() {
    let library: Vec<u8> = RETURNED_TYPES.iter().map(|t| t.to_u8()).collect();
    assert_eq!(
        library, RETURNED,
        "5.4.15.1: rd's returned types are 5-101 cl.7.4.14's list within 104 cl.9"
    );
    let requested = Arc::new(Mutex::new(Vec::new()));
    let app = ReadApp {
        read: Read::controlled(true, CA, ORIGINATOR),
        requested: Arc::clone(&requested),
    };
    let dut = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let mut peer = Peer::connect(dut.addr()).expect("the peer connects");
    peer.start_data_transfer().expect("STARTDT");

    let mut answers = Vec::new();
    for i in 0..RETURNED.len() {
        let nr = next_nr(&peer);
        peer.send_i(SeqNo::new(i as u16), nr, &read_command(address(i), SOURCE))
            .expect("the read goes out");
        answers.extend(read_i_frames(&mut peer, 1, deadline(5)).expect("the answer"));
    }
    peer.close().expect("close");
    dut.join().expect("the station ends cleanly");

    assert_eq!(
        *requested.lock().expect("the record"),
        (0..RETURNED.len()).map(address).collect::<Vec<_>>(),
        "5.4.15.1: every command was taken as a read of its address"
    );
    for (i, reply) in answers.iter().enumerate() {
        let type_id = RETURNED[i];
        let element = &held_object(type_id, address(i))[Header::LEN + 3..];
        assert_single_object(
            "5.4.15.1",
            reply,
            type_id,
            Cause::Request,
            address(i),
            element,
        );
        assert_eq!(
            Header::parse(reply).expect("the header").originator,
            SOURCE,
            "5.4.15.1 (type {type_id}): the command's originator is echoed"
        );
    }
}
