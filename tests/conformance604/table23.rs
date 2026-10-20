//! 604 Table 23, *"File transfer procedure function conformance test
//! procedures"*, PDF page indices 84–86 (printed 83–85), procedures
//! `5.4.23.1` (monitor direction), `5.4.23.10` (control direction) and
//! `5.4.23.15` (Query Log). `5.4.23.20` is the table's `COMPATIBILITY WITH
//! OTHER TEST CASES` row, which is the whole suite rather than a case (see
//! `tests/conformance_604.rs`).
//!
//! Every row's `Reference` column is `IEC 60870-5-101:2003, 7.4.11` with
//! `IEC 60870-5-5:1995, 6.12` (no case cites 5-5 beyond the row), except the unknown-address row
//! (`IEC 60870-5-101:2003, 7.2.3`) and the Query Log rows
//! (`IEC 60870-5-104:2006, 8.9`).
//!
//! # What is the library and what is the harness
//!
//! `iec104::ft` holds the role, the two 104 clause 9.6 checkboxes and the
//! addressing, and nothing else: *"Which section is in flight, how many segments
//! are left and what is buffered is the caller's"* (its module doc). So each
//! station under test here is the crate's `FileTransferProcedure` plus a thin
//! application, [`Provider`] or [`Requester`], that
//!
//! - hands every received ASDU to `FileTransferProcedure::on_asdu` (the provider)
//!   or `on_answer` with the request it sent last (the requester), and puts
//!   `Outcome::send` (the crate's 5-101 clause 7.2.3 mirror) on the wire
//!   unchanged;
//! - builds every frame it sends with `FileTransferProcedure::build`, so the
//!   type, cause, qualifiers and the clause 9.6 direction gate are the crate's;
//! - checks every checksum with `ft::check_checksum` and computes every one it
//!   sends with `ft::checksum`;
//! - chooses **which** frame answers which from the sequence of 5-101 clause
//!   7.4.11's figures 103/104 and the 604 rows below. That choice is the only
//!   thing the harness decides, and it is the part the crate leaves to its
//!   caller.
//!
//! The mock peer ([`Mock`]) invents nothing: every ASDU it sends and every ASDU
//! it requires from the station under test is spelled out in the test, octet by
//! octet, by the helpers [`f_sc`] … [`f_sc_nb`], which assemble the fields in the
//! order 5-101 figures 83–89 (indices 114–120) and 5-104 figure 31 (index 92)
//! print them, under the conventional address profile of 104 clause 9.5
//! (originator present, two-octet common address, three-octet object address).
//! The checksums in the scripts are the sums modulo 256 of 5-101 clause
//! 7.2.6.37 worked by hand in the comments.
//!
//! # The sample PICS and PIXIT
//!
//! - Common address 1, originator 0, one file at information object address
//!   [`FILE_IOA`] with name of file `<1>` (*"transparent file"*, 5-101 clause
//!   7.4.11.1.1, index 130), nine octets in two sections of six and three
//!   octets ([`sample_file`]).
//! - Segments carry at most [`SEGMENT_OCTETS`] octets (a provider's choice, well
//!   below the 236-octet ceiling of `ft::MAX_SEGMENT`).
//! - Both clause 9.6 checkboxes are exercised, one per procedure:
//!   `Selection::MONITOR` for `5.4.23.1` and `.15`, `Selection::CONTROL` for
//!   `5.4.23.10`.
//! - PIXIT row on selecting one section (ASDU 122, `F_SC`, SCQ=5) and aborting
//!   a section (ASDU 122, `F_SC`, SCQ=7): **supported**. The
//!   requester selects section 2 after the file ready and aborts it after its
//!   section ready; the provider answers a select section with that section's
//!   section ready and sends nothing more for an aborted one.
//! - The Query Log (`5.4.23.15`) is served by the controlled station from a log
//!   of four two-octet records stamped 2026-09-01 … 04, 12:00 ([`log_records`]);
//!   104 clause 8.9's table decides which records a range selects. The file the
//!   query selects has name of file `<3>` (*"sequences of events"*, 5-101
//!   clause 7.4.11.1.1).
//!
//! # Direction
//!
//! §5.1 (index 10): the reverse direction is tested with the same procedures,
//! the roles of controlling and controlled station swapped, with one exception:
//! COT 44-47 exist only in the monitor direction, so only a controlled station
//! may send them. Table 23 already
//! carries both file directions as two procedures, so every procedure is driven
//! with **both** stations as the DUT: the library as the controlled station
//! (`ControlledStation::start_app`) against a mock controlling station, and the
//! library as the controlling station ([`ControllingDut`], the interoperability
//! harness's `interop::Station`) against a mock controlled station. The Query Log
//! is driven with the controlling station requesting and the controlled station
//! receiving only: 104 clause 8.9 (index 92) has the file transfer of
//! IEC 60870-5-101:2003, 7.4.11 begin once the controlled station has received
//! a successful query request.
//!
//! # A deviation, fixed
//!
//! `clause_5_4_23_10_the_controlling_station_does_not_mirror_an_unknown_address`
//! found that the library, as the controlling station providing a file in the
//! control direction, answered a call file with an unknown information object
//! address with a cause-47 mirror, which §5.1 reserves to the controlled
//! station. `ft` now mirrors only on the controlled station.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use iec104::apci::{Apci, Apdu, SeqNo, UFunction};
use iec104::asdu::{
    Afq, Cp56Time2a, Frq, Header, Known, Lof, Lsq, Nof, Nos, Scq, Sof, Srq, read_ioa_with,
};
use iec104::framed::Decoder;
use iec104::ft::{
    DirectoryEntry, FileTransferProcedure, Frame, Reaction, Selection, check_checksum, checksum,
};
use iec104::link::State;

use crate::conformance604::{
    CA, ControlledStation, ORIGINATOR, StationApp, interop, parse_frame, sample_time,
};

// ------------------------------------------------------------ the sample file

/// The information object address of the one file the providers hold (5-101
/// clause 7.4.11.1.1: a file, directory or subdirectory is identified uniquely
/// by its ASDU common address together with its information object address).
pub const FILE_IOA: u32 = 0x0401;

/// An address no station of these cases holds anything at.
pub const UNKNOWN_IOA: u32 = 0x0402;

/// The largest segment the sample providers send (the PIXIT's segment size).
pub const SEGMENT_OCTETS: usize = 4;

/// The six octets of section 1 of the sample file. `CHS` (5-101 clause
/// 7.2.6.37, sum modulo 256): `10+20+30+40+50+60` hex is `0x150`, so `0x50`.
pub const SECTION_1: [u8; 6] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60];

/// The three octets of section 2. `CHS`: `F0+0F+02` is `0x101`, so `0x01`.
pub const SECTION_2: [u8; 3] = [0xF0, 0x0F, 0x02];

/// One file as a provider holds it: its name and its sections, in order.
#[derive(Debug, Clone)]
pub struct StoredFile {
    /// `NOF`, 5-101 clause 7.2.6.33.
    pub nof: Nof,
    /// The sections, section 1 first (`NOS` `<1>` is the first section).
    pub sections: Vec<Vec<u8>>,
    /// The time the directory reports for the file (5-101 clause 7.4.11.1:
    /// its creation time).
    pub time: Cp56Time2a,
}

impl StoredFile {
    /// The whole file, sections concatenated.
    pub fn octets(&self) -> Vec<u8> {
        self.sections.concat()
    }

    fn section(&self, nos: Nos) -> Option<&Vec<u8>> {
        usize::from(nos.value)
            .checked_sub(1)
            .and_then(|index| self.sections.get(index))
    }
}

/// The sample PICS's file: name of file `<1>`, sections [`SECTION_1`] and
/// [`SECTION_2`], nine octets.
pub fn sample_file() -> StoredFile {
    StoredFile {
        nof: Nof { value: 1 },
        sections: vec![SECTION_1.to_vec(), SECTION_2.to_vec()],
        time: sample_time(),
    }
}

/// One `CP56Time2a` at 12:00:00.000 on a September 2026 day, standard time,
/// valid: `day` of month and its `day_of_week` (Monday 1, 5-101 clause
/// 7.2.6.18).
const fn september(day: u8, day_of_week: u8) -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 0,
        minutes: 0,
        substituted: false,
        invalid: false,
        hours: 12,
        summer_time: false,
        day_of_month: day,
        day_of_week,
        months: 9,
        years: 26,
    }
}

/// The log the Query Log cases read: four records of two octets, stamped
/// 2026-09-01 (a Tuesday, 2026-09-25 being the Friday of [`sample_time`]) to
/// 2026-09-04, 12:00.
pub fn log_records() -> Vec<(Cp56Time2a, Vec<u8>)> {
    vec![
        (september(1, 2), vec![0x01, 0x11]),
        (september(2, 3), vec![0x02, 0x22]),
        (september(3, 4), vec![0x03, 0x33]),
        (september(4, 5), vec![0x04, 0x44]),
    ]
}

/// The station's four clause 7.2.3 answers for one received ASDU: the
/// standard's types and causes, the station's own common address (that of
/// its procedure `ft`), and the one address `held` it holds a file at.
fn known_for(asdu: &[u8], ft: &FileTransferProcedure, held: u32) -> Result<Known, String> {
    let sizes = ft.address_sizes();
    let (own_ca, _) = ft.addressing();
    let header = Header::parse_with(asdu, sizes).map_err(|e| format!("the header: {e:?}"))?;
    let ioa_known = if header.count == 0 {
        true
    } else {
        read_ioa_with(&asdu[sizes.header_len()..], sizes)
            .map_err(|e| format!("the address: {e:?}"))?
            == held
    };
    Ok(Known::standard(
        &header,
        header.common_address == own_ca,
        ioa_known,
    ))
}

// ----------------------------------------------------- the two applications

/// The station that **provides** the file: the controlled station in the
/// monitor direction, the controlling one in the control direction.
pub struct Provider {
    ft: FileTransferProcedure,
    file: StoredFile,
    log: Option<Vec<(Cp56Time2a, Vec<u8>)>>,
    segment_octets: usize,
    announce: bool,
    ioa: u32,
}

impl Provider {
    /// A provider serving `file` with the crate's procedure `ft`.
    pub const fn new(ft: FileTransferProcedure, file: StoredFile) -> Self {
        Self {
            ft,
            file,
            log: None,
            segment_octets: SEGMENT_OCTETS,
            announce: false,
            ioa: FILE_IOA,
        }
    }

    /// The same provider sending the file ready of its own accord once data
    /// transfer is started: 604 `5.4.23.10`'s first row, in which the
    /// controlling station issues the file ready (ASDU 120).
    pub const fn announcing(mut self) -> Self {
        self.announce = true;
        self
    }

    /// The same provider holding `records` for the Query Log of 104 clause 8.9.
    pub fn with_log(mut self, records: Vec<(Cp56Time2a, Vec<u8>)>) -> Self {
        self.log = Some(records);
        self
    }

    /// The same provider holding its file at `ioa` instead of [`FILE_IOA`],
    /// for an address profile too narrow for that address.
    pub const fn at(mut self, ioa: u32) -> Self {
        self.ioa = ioa;
        self
    }

    /// The same provider cutting sections into segments of at most `octets`.
    pub const fn with_segment_octets(mut self, octets: usize) -> Self {
        self.segment_octets = octets;
        self
    }

    fn build(&self, frame: &Frame) -> Result<Vec<u8>, String> {
        self.ft
            .build(frame)
            .map_err(|e| format!("the provider builds {frame:?}: {e:?}"))
    }

    fn file_ready(&self) -> Result<Vec<u8>, String> {
        self.build(&Frame::FileReady {
            ioa: self.ioa,
            nof: self.file.nof,
            lof: Lof {
                value: self.file.octets().len() as u32,
            },
            frq: Frq::default(),
        })
    }

    fn section_ready(&self, nos: Nos) -> Result<Vec<u8>, String> {
        let section = self
            .file
            .section(nos)
            .ok_or_else(|| format!("no section {}", nos.value))?;
        self.build(&Frame::SectionReady {
            ioa: self.ioa,
            nof: self.file.nof,
            nos,
            lof: Lof {
                value: section.len() as u32,
            },
            srq: Srq::default(),
        })
    }

    /// Section `nos` as segments and its last segment, `LSQ` `<3>` (section
    /// transfer without deactivation) with the section's `CHS`.
    fn section(&self, nos: Nos) -> Result<Vec<Vec<u8>>, String> {
        let section = self
            .file
            .section(nos)
            .ok_or_else(|| format!("no section {}", nos.value))?
            .clone();
        let mut out = Vec::new();
        for chunk in section.chunks(self.segment_octets) {
            out.push(self.build(&Frame::Segment {
                ioa: self.ioa,
                segment: iec104::asdu::Segment {
                    nof: self.file.nof,
                    nos,
                    los: iec104::asdu::Los {
                        value: chunk.len() as u8,
                    },
                    payload: chunk.to_vec(),
                },
            })?);
        }
        out.push(self.build(&Frame::LastSection {
            ioa: self.ioa,
            nof: self.file.nof,
            nos,
            lsq: Lsq {
                value: Lsq::SECTION_WITHOUT_DEACTIVATION,
            },
            chs: checksum(&section),
        })?);
        Ok(out)
    }

    /// The answer to one request, in the order of 5-101 figures 103/104.
    fn answer(&mut self, frame: &Frame) -> Result<Vec<Vec<u8>>, String> {
        match frame {
            // A_CALL_DIRECTORY.req → A_DIRECTORY.req (figure 103).
            Frame::Sc { scq, .. } if scq.action == iec104::ft::SCQ_CALL_DIRECTORY => {
                let entry = DirectoryEntry {
                    nof: self.file.nof,
                    lof: Lof {
                        value: self.file.octets().len() as u32,
                    },
                    sof: Sof {
                        last_file_of_directory: true,
                        ..Sof::default()
                    },
                    time: self.file.time,
                };
                Ok(vec![self.build(&Frame::Directory {
                    ioa: self.ioa,
                    cause: iec104::ft::CAUSE_REQUEST,
                    files: vec![entry],
                })?])
            }
            // A_SELECT_FILE.req → A_FILE_READY.req.
            Frame::Sc { scq, .. } if scq.action == Scq::SELECT_FILE => Ok(vec![self.file_ready()?]),
            // A_CALL_FILE.req → A_SECTION1_READY.req.
            Frame::Sc { scq, .. } if scq.action == Scq::REQUEST_FILE => {
                Ok(vec![self.section_ready(Nos { value: 1 })?])
            }
            // The PIXIT's select section: that section's section ready.
            Frame::Sc { scq, nos, .. } if scq.action == Scq::SELECT_SECTION => {
                Ok(vec![self.section_ready(*nos)?])
            }
            // A_CALL_SECTIONm.req → the segments and the last segment.
            Frame::Sc { scq, nos, .. } if scq.action == Scq::REQUEST_SECTION => self.section(*nos),
            // The PIXIT's abort section: nothing more for that section.
            Frame::Sc { scq, .. } if scq.action == Scq::DEACTIVATE_SECTION => Ok(Vec::new()),
            Frame::Ack { afq, nos, .. } => match afq.action {
                // A_ACK_SECTIONm.req positive → the next section ready, or
                // A_LAST_SECTION.req (`LSQ` <1>) with the file's CHS.
                Afq::SECTION_POSITIVE => {
                    if usize::from(nos.value) < self.file.sections.len() {
                        Ok(vec![self.section_ready(Nos {
                            value: nos.value + 1,
                        })?])
                    } else {
                        Ok(vec![self.build(&Frame::LastSection {
                            ioa: self.ioa,
                            nof: self.file.nof,
                            nos: *nos,
                            lsq: Lsq {
                                value: Lsq::FILE_WITHOUT_DEACTIVATION,
                            },
                            chs: checksum(&self.file.octets()),
                        })?])
                    }
                }
                // 604: a negative acknowledgement (AFQ=4) has the same section
                // sent again.
                Afq::SECTION_NEGATIVE => self.section(*nos),
                // A_ACK_FILE.req: the transfer is over.
                _ => Ok(Vec::new()),
            },
            // 104 cl.8.9: the query pre-selects the file's content; the
            // transfer then starts with the file ready.
            Frame::QueryLog {
                nof,
                range_start,
                range_stop,
                ..
            } => {
                let records = self
                    .log
                    .as_ref()
                    .ok_or("a Query Log arrived at a station without a log")?;
                let selected = select_records(records, *range_start, *range_stop);
                self.file = StoredFile {
                    nof: *nof,
                    sections: vec![selected],
                    time: sample_time(),
                };
                Ok(vec![self.file_ready()?])
            }
            other => Err(format!("the provider has no answer for {other:?}")),
        }
    }
}

/// 104 clause 8.9's table (index 92): all records from `start` to `stop`,
/// both included (footnote a: a record stamped exactly `RangeStartTime` or
/// `RangeStopTime` is selected), an all-zero end meaning
/// "from the beginning" or "the end".
fn select_records(
    records: &[(Cp56Time2a, Vec<u8>)],
    start: Cp56Time2a,
    stop: Cp56Time2a,
) -> Vec<u8> {
    let zero = Cp56Time2a::default();
    let millis = |time: Cp56Time2a| time.millis_since_2000().unwrap_or(i64::MIN);
    records
        .iter()
        .filter(|(time, _)| start == zero || millis(*time) >= millis(start))
        .filter(|(time, _)| stop == zero || millis(*time) <= millis(stop))
        .flat_map(|(_, octets)| octets.clone())
        .collect()
}

impl StationApp for Provider {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let known = known_for(asdu, &self.ft, self.ioa)?;
        let outcome = self
            .ft
            .on_asdu(asdu, &known)
            .map_err(|e| format!("the provider's ft::on_asdu: {e:?}"))?;
        let mut out = outcome.send;
        match outcome.reaction {
            Reaction::Requested { frame } => out.extend(self.answer(&frame)?),
            Reaction::Answered { frame } => {
                return Err(format!("the provider was offered a file: {frame:?}"));
            }
            Reaction::Refused { .. } | Reaction::Discard(_) | Reaction::Other => {}
        }
        Ok(out)
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        if std::mem::take(&mut self.announce) {
            return Ok(vec![self.file_ready()?]);
        }
        Ok(Vec::new())
    }
}

/// The station that **asks for and receives** the file: the controlling
/// station in the monitor direction, the controlled one in the control
/// direction.
pub struct Requester {
    ft: FileTransferProcedure,
    opening: Option<Frame>,
    select_section: Option<Nos>,
    sent: Option<Frame>,
    section: Vec<u8>,
    file: Vec<u8>,
}

impl Requester {
    /// A requester with the crate's procedure `ft` that waits for the
    /// provider to start.
    pub const fn new(ft: FileTransferProcedure) -> Self {
        Self {
            ft,
            opening: None,
            select_section: None,
            sent: None,
            section: Vec::new(),
            file: Vec::new(),
        }
    }

    /// The same requester opening with `frame` once data transfer is started
    /// (the call directory of `5.4.23.1`, the Query Log of `5.4.23.15`).
    pub fn opening(mut self, frame: Frame) -> Self {
        self.opening = Some(frame);
        self
    }

    /// The same requester running the PIXIT row instead of the whole file:
    /// select section `nos` after the file ready, abort it after its section
    /// ready.
    pub const fn selecting_section(mut self, nos: Nos) -> Self {
        self.select_section = Some(nos);
        self
    }

    const fn request(nof: Nof, nos: Nos, action: u8) -> Frame {
        Frame::Sc {
            ioa: FILE_IOA,
            nof,
            nos,
            scq: Scq { action, error: 0 },
        }
    }

    /// The next request for one answered frame, in the order of 5-101 figures
    /// 103/104, or `None` when the frame asks for nothing.
    fn next(&mut self, frame: &Frame) -> Result<Option<Frame>, String> {
        Ok(match frame {
            Frame::Directory { files, .. } => {
                let first = files.first().ok_or("an empty directory")?;
                Some(Self::request(first.nof, Nos { value: 0 }, Scq::SELECT_FILE))
            }
            Frame::FileReady { nof, frq, .. } => {
                if frq.negative_confirm {
                    None
                } else if let Some(nos) = self.select_section {
                    Some(Self::request(*nof, nos, Scq::SELECT_SECTION))
                } else {
                    Some(Self::request(*nof, Nos { value: 0 }, Scq::REQUEST_FILE))
                }
            }
            Frame::SectionReady { nof, nos, .. } => {
                if self.select_section == Some(*nos) {
                    self.select_section = None;
                    Some(Self::request(*nof, *nos, Scq::DEACTIVATE_SECTION))
                } else {
                    self.section.clear();
                    Some(Self::request(*nof, *nos, Scq::REQUEST_SECTION))
                }
            }
            Frame::Segment { segment, .. } => {
                self.section.extend_from_slice(&segment.payload);
                None
            }
            Frame::LastSection {
                nof, nos, lsq, chs, ..
            } => match lsq.value {
                Lsq::SECTION_WITHOUT_DEACTIVATION | Lsq::SECTION_WITH_DEACTIVATION => {
                    let section = std::mem::take(&mut self.section);
                    let good = check_checksum(&section, *chs).is_ok();
                    if good {
                        self.file.extend_from_slice(&section);
                    }
                    let action = if good {
                        Afq::SECTION_POSITIVE
                    } else {
                        Afq::SECTION_NEGATIVE
                    };
                    Some(Frame::Ack {
                        ioa: FILE_IOA,
                        nof: *nof,
                        nos: *nos,
                        afq: Afq { action, error: 0 },
                    })
                }
                _ => {
                    let good = check_checksum(&self.file, *chs).is_ok();
                    let action = if good {
                        Afq::FILE_POSITIVE
                    } else {
                        Afq::FILE_NEGATIVE
                    };
                    Some(Frame::Ack {
                        ioa: FILE_IOA,
                        nof: *nof,
                        nos: Nos { value: 0 },
                        afq: Afq { action, error: 0 },
                    })
                }
            },
            other => return Err(format!("the requester has no request after {other:?}")),
        })
    }

    fn send(&mut self, frame: Frame) -> Result<Vec<u8>, String> {
        let asdu = self
            .ft
            .build(&frame)
            .map_err(|e| format!("the requester builds {frame:?}: {e:?}"))?;
        self.sent = Some(frame);
        Ok(asdu)
    }
}

impl StationApp for Requester {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let known = known_for(asdu, &self.ft, FILE_IOA)?;
        let outcome = match &self.sent {
            Some(sent) => self.ft.on_answer(asdu, &known, sent),
            None => self.ft.on_asdu(asdu, &known),
        }
        .map_err(|e| format!("the requester's ft::on_answer: {e:?}"))?;
        let mut out = outcome.send;
        match outcome.reaction {
            Reaction::Answered { frame } => {
                if let Some(next) = self.next(&frame)? {
                    out.push(self.send(next)?);
                }
            }
            Reaction::Requested { frame } => {
                return Err(format!("the requester was asked to serve: {frame:?}"));
            }
            Reaction::Refused { .. } | Reaction::Discard(_) | Reaction::Other => {}
        }
        Ok(out)
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        match self.opening.take() {
            Some(frame) => Ok(vec![self.send(frame)?]),
            None => Ok(Vec::new()),
        }
    }
}

// ------------------------------------------- the library as controlling station

/// The library as the **controlling** station under test: the interoperability
/// harness's `interop::Station` (`link::Session` in `Role::Controlling`) on a
/// thread, connecting to the mock controlled station and answering it with a
/// [`StationApp`]. It ends when the mock closes the connection.
pub struct ControllingDut {
    handle: JoinHandle<Result<(), String>>,
}

impl ControllingDut {
    /// Connects to `addr`, sends STARTDT act, and runs `app` once started.
    pub fn start(addr: SocketAddr, mut app: impl StationApp) -> Self {
        let handle = thread::spawn(move || {
            let mut station = interop::Station::connect(addr)?;
            let actions = station.session_mut().request_start();
            station.send_actions(&actions)?;
            let mut queued: VecDeque<Vec<u8>> = VecDeque::new();
            loop {
                if let Some(asdu) = queued.pop_front() {
                    match station.session_mut().send_i_frame(&asdu) {
                        Some(action) => {
                            station.send_actions(&[action])?;
                            continue;
                        }
                        None => queued.push_front(asdu),
                    }
                } else if station.session().state() == State::Started {
                    let own = app.poll(Instant::now())?;
                    if !own.is_empty() {
                        queued.extend(own);
                        continue;
                    }
                }
                match station.next(Instant::now() + Duration::from_millis(20)) {
                    Ok(Some((apci, asdu))) if apci.is_i_format() => {
                        queued.extend(app.on_asdu(&asdu)?);
                    }
                    Ok(_) => {}
                    // The mock closed the connection: the case is over.
                    Err(_) => return Ok(()),
                }
            }
        });
        Self { handle }
    }

    /// Waits for the station thread; an application error is the case's error.
    pub fn join(self) -> Result<(), String> {
        self.handle
            .join()
            .map_err(|_| "the controlling station panicked".to_string())?
    }
}

// ------------------------------------------------------------------ the mock

/// A mock station of either role, driven frame by frame from the test thread.
/// It numbers its I-frames and acknowledges by piggybacking N(R) (104 clause
/// 5.1), and otherwise sends exactly what the case spells out.
pub struct Mock {
    stream: TcpStream,
    decoder: Decoder,
    ns: SeqNo,
    nr: SeqNo,
    /// Every whole APDU the mock read, in order.
    pub received: Vec<Vec<u8>>,
}

impl Mock {
    fn from_stream(stream: TcpStream) -> Result<Self, String> {
        stream
            .set_nodelay(true)
            .map_err(|e| format!("nodelay: {e}"))?;
        Ok(Self {
            stream,
            decoder: Decoder::new(),
            ns: SeqNo::new(0),
            nr: SeqNo::new(0),
            received: Vec::new(),
        })
    }

    /// A mock controlling station connecting to the station under test.
    pub fn connect(addr: SocketAddr) -> Result<Self, String> {
        Self::from_stream(TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?)
    }

    /// A mock controlled station accepting the station under test.
    pub fn accept(listener: &TcpListener) -> Result<Self, String> {
        let (stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        Self::from_stream(stream)
    }

    fn write(&mut self, apci: Apci, asdu: &[u8]) -> Result<(), String> {
        let mut out = Vec::new();
        Apdu { apci, asdu }
            .encode(&mut out)
            .map_err(|e| format!("encode {apci:?}: {e:?}"))?;
        self.stream
            .write_all(&out)
            .map_err(|e| format!("write: {e}"))
    }

    /// A U-format frame.
    pub fn send_u(&mut self, function: UFunction) -> Result<(), String> {
        self.write(Apci::U(function), &[])
    }

    /// An S-format frame acknowledging everything received so far.
    pub fn send_s(&mut self) -> Result<(), String> {
        self.write(Apci::S { nr: self.nr }, &[])
    }

    /// An S-format frame with a chosen N(R).
    pub fn send_s_nr(&mut self, nr: u16) -> Result<(), String> {
        self.write(Apci::S { nr: SeqNo::new(nr) }, &[])
    }

    /// An I-format frame carrying `asdu`, numbered in turn.
    pub fn send_i(&mut self, asdu: &[u8]) -> Result<(), String> {
        let apci = Apci::I {
            ns: self.ns,
            nr: self.nr,
        };
        self.ns = self.ns.next();
        self.write(apci, asdu)
    }

    /// The next whole frame, `Ok(None)` at the deadline, an error once the
    /// station closed the connection.
    pub fn read_frame(&mut self, limit: Instant) -> Result<Option<(Apci, Vec<u8>)>, String> {
        loop {
            match self.decoder.next_frame_len() {
                Ok(Some(_)) => {
                    let frame = self
                        .decoder
                        .next_frame()
                        .map_err(|e| format!("framing: {e}"))?
                        .ok_or("the decoder promised a frame")?
                        .to_vec();
                    let (apci, asdu) = parse_frame(&frame)?;
                    self.received.push(frame);
                    if apci.is_i_format() {
                        self.nr = self.nr.next();
                    }
                    return Ok(Some((apci, asdu)));
                }
                Ok(None) => {}
                Err(_) => {
                    let _ = self.decoder.next_frame();
                    continue;
                }
            }
            let remaining = limit.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
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
                    return Ok(None);
                }
                Err(e) => return Err(format!("read: {e}")),
            }
        }
    }

    /// The next I-frame's ASDU within `wait`, skipping S- and U-frames.
    pub fn next_i(&mut self, wait: Duration) -> Result<Option<Vec<u8>>, String> {
        let limit = Instant::now() + wait;
        loop {
            match self.read_frame(limit)? {
                Some((apci, asdu)) if apci.is_i_format() => return Ok(Some(asdu)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }

    /// Requires the next frame to be the U-function `function`.
    pub fn expect_u(&mut self, function: UFunction, wait: Duration) -> Result<(), String> {
        match self.read_frame(Instant::now() + wait)? {
            Some((Apci::U(got), _)) if got == function => Ok(()),
            other => Err(format!("{function:?} expected, got {other:?}")),
        }
    }

    /// The STARTDT exchange as the controlling station (104 clause 5.3).
    pub fn start_as_controlling(&mut self) -> Result<(), String> {
        self.send_u(UFunction::StartDtAct)?;
        self.expect_u(UFunction::StartDtCon, Duration::from_secs(5))
    }

    /// The STARTDT exchange as the controlled station (104 clause 5.3).
    pub fn start_as_controlled(&mut self) -> Result<(), String> {
        self.expect_u(UFunction::StartDtAct, Duration::from_secs(5))?;
        self.send_u(UFunction::StartDtCon)
    }

    /// Closes the connection, which ends the station under test.
    pub fn close(&self) -> Result<(), String> {
        self.stream
            .shutdown(Shutdown::Both)
            .map_err(|e| format!("shutdown: {e}"))
    }
}

// ------------------------------------------------ the frames, from the figures

/// The data unit identifier and address of one conventional-profile ASDU
/// (5-101 figure 11 with 104 clause 9.5's two-octet cause with originator,
/// two-octet common address and three-octet object address), then `element`.
/// Common address [`CA`], originator [`ORIGINATOR`], address `ioa`.
fn wire(type_id: u8, vsq: u8, cot: u8, ioa: u32, element: &[u8]) -> Vec<u8> {
    let ca = CA.to_le_bytes();
    let mut out = vec![type_id, vsq, cot, ORIGINATOR, ca[0], ca[1]];
    out.extend_from_slice(&ioa.to_le_bytes()[..3]);
    out.extend_from_slice(element);
    out
}

/// `F_SC_NA_1` `<122>`, figure 85 (index 116): `NOF` (two octets), `NOS`, `SCQ`.
pub fn f_sc(cot: u8, ioa: u32, nof: u16, nos: u8, scq: u8) -> Vec<u8> {
    let nof = nof.to_le_bytes();
    wire(122, 0x01, cot, ioa, &[nof[0], nof[1], nos, scq])
}

/// `F_FR_NA_1` `<120>`, figure 83 (index 114): `NOF`, `LOF` (three octets),
/// `FRQ`; cause 13.
pub fn f_fr(ioa: u32, nof: u16, lof: u32, frq: u8) -> Vec<u8> {
    let nof = nof.to_le_bytes();
    let lof = lof.to_le_bytes();
    wire(
        120,
        0x01,
        13,
        ioa,
        &[nof[0], nof[1], lof[0], lof[1], lof[2], frq],
    )
}

/// `F_SR_NA_1` `<121>`, figure 84 (index 115): `NOF`, `NOS`, `LOF` (the
/// *"Length of section"*, three octets), `SRQ`; cause 13.
pub fn f_sr(nof: u16, nos: u8, lof: u32, srq: u8) -> Vec<u8> {
    let nof = nof.to_le_bytes();
    let lof = lof.to_le_bytes();
    wire(
        121,
        0x01,
        13,
        FILE_IOA,
        &[nof[0], nof[1], nos, lof[0], lof[1], lof[2], srq],
    )
}

/// `F_SG_NA_1` `<125>`, figure 88 (index 119): `NOF`, `NOS`, `LOS`, then the
/// `LOS` segment octets; cause 13.
pub fn f_sg(nof: u16, nos: u8, octets: &[u8]) -> Vec<u8> {
    let nof = nof.to_le_bytes();
    let mut element = vec![nof[0], nof[1], nos, octets.len() as u8];
    element.extend_from_slice(octets);
    wire(125, 0x01, 13, FILE_IOA, &element)
}

/// `F_LS_NA_1` `<123>`, figure 86 (index 117): `NOF`, `NOS`, `LSQ`, `CHS`;
/// cause 13.
pub fn f_ls(nof: u16, nos: u8, lsq: u8, chs: u8) -> Vec<u8> {
    let nof = nof.to_le_bytes();
    wire(123, 0x01, 13, FILE_IOA, &[nof[0], nof[1], nos, lsq, chs])
}

/// `F_AF_NA_1` `<124>`, figure 87 (index 118): `NOF`, `NOS`, `AFQ`; cause 13.
pub fn f_af(nof: u16, nos: u8, afq: u8) -> Vec<u8> {
    let nof = nof.to_le_bytes();
    wire(124, 0x01, 13, FILE_IOA, &[nof[0], nof[1], nos, afq])
}

/// `F_DR_TA_1` `<126>`, figure 89 (index 120), one file: `SQ = 1`, `N = 1`
/// (VSQ `0x81`), cause 5 (*"requested"*), `NOF`, `LOF`, `SOF`, `CP56Time2a`.
pub fn f_dr(ioa: u32, nof: u16, lof: u32, sof: u8, time: [u8; 7]) -> Vec<u8> {
    let nof = nof.to_le_bytes();
    let lof = lof.to_le_bytes();
    let mut element = vec![nof[0], nof[1], lof[0], lof[1], lof[2], sof];
    element.extend_from_slice(&time);
    wire(126, 0x81, 5, ioa, &element)
}

/// `F_SC_NB_1` `<127>`, 104 figure 31 (index 92): `NOF`, `RangeStartTime`,
/// `RangeStopTime`; cause 13.
pub fn f_sc_nb(nof: u16, start: [u8; 7], stop: [u8; 7]) -> Vec<u8> {
    let nof = nof.to_le_bytes();
    let mut element = vec![nof[0], nof[1]];
    element.extend_from_slice(&start);
    element.extend_from_slice(&stop);
    wire(127, 0x01, 13, FILE_IOA, &element)
}

/// [`sample_time`] (Friday 2026-09-25 12:00:00.000) as 5-101 figure 21's seven
/// octets: milliseconds `00 00`, minutes `00`, hours `0C`, day of month 25
/// with day of week 5 in bits 6–8 (`0x19 | 0xA0 = B9`), months `09`, years
/// `1A`.
const SAMPLE_TIME_OCTETS: [u8; 7] = [0x00, 0x00, 0x00, 0x0C, 0xB9, 0x09, 0x1A];

/// The same layout for the log's stamps, 12:00 on 2026-09-0`day`: day of
/// month in bits 1–5 and the day of week (Tuesday 2 … Friday 5) in bits 6–8.
const SEP_02: [u8; 7] = [0x00, 0x00, 0x00, 0x0C, 0x62, 0x09, 0x1A];
const SEP_03: [u8; 7] = [0x00, 0x00, 0x00, 0x0C, 0x83, 0x09, 0x1A];
const ZERO_TIME: [u8; 7] = [0; 7];

// ------------------------------------------------------------ the scripts

/// One step of a scripted exchange, seen from the mock.
#[derive(Debug, Clone)]
pub enum Step {
    /// The mock sends this ASDU.
    Mock(Vec<u8>),
    /// The station under test must send exactly this ASDU next; the text
    /// names the 604 row.
    Dut(Vec<u8>, &'static str),
    /// The station under test sends no I-frame for a while.
    Quiet(&'static str),
}

/// How long the mock waits for an I-frame the script requires.
const REPLY_WAIT: Duration = Duration::from_secs(3);

/// How long the station under test must stay silent for a [`Step::Quiet`].
const QUIET_WAIT: Duration = Duration::from_millis(300);

/// Runs `steps` on `mock`, failing at the first frame that is not the one the
/// script requires.
pub fn run(mock: &mut Mock, steps: &[Step]) -> Result<(), String> {
    for (index, step) in steps.iter().enumerate() {
        match step {
            Step::Mock(asdu) => mock.send_i(asdu)?,
            Step::Dut(want, what) => {
                let got = mock
                    .next_i(REPLY_WAIT)?
                    .ok_or_else(|| format!("step {index}, {what}: nothing arrived"))?;
                if &got != want {
                    return Err(format!(
                        "step {index}, {what}:\n want {}\n  got {}",
                        interop::encode_hex(want),
                        interop::encode_hex(&got)
                    ));
                }
            }
            Step::Quiet(what) => {
                if let Some(got) = mock.next_i(QUIET_WAIT)? {
                    return Err(format!(
                        "step {index}, {what}: the station sent {}",
                        interop::encode_hex(&got)
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Which side the station under test is in a script.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dut {
    /// The station under test provides the file.
    Provider,
    /// The station under test asks for and receives the file.
    Requester,
}

/// A step of the providing side (`F_FR`, `F_SR`, `F_SG`, `F_LS`, `F_DR`).
const fn provider(dut: Dut, asdu: Vec<u8>, what: &'static str) -> Step {
    match dut {
        Dut::Provider => Step::Dut(asdu, what),
        Dut::Requester => Step::Mock(asdu),
    }
}

/// A step of the requesting side (`F_SC`, `F_AF`, `F_SC_NB`).
const fn requester(dut: Dut, asdu: Vec<u8>, what: &'static str) -> Step {
    match dut {
        Dut::Requester => Step::Dut(asdu, what),
        Dut::Provider => Step::Mock(asdu),
    }
}

/// One section's segments, cut into [`SEGMENT_OCTETS`], and its last segment
/// (`LSQ` `<3>`) with `chs`.
fn section_steps(dut: Dut, nof: u16, nos: u8, octets: &[u8], chs: u8) -> Vec<Step> {
    let mut steps: Vec<Step> = octets
        .chunks(SEGMENT_OCTETS)
        .map(|chunk| {
            provider(
                dut,
                f_sg(nof, nos, chunk),
                "a number of segments (ASDU 125) with COT = 13",
            )
        })
        .collect();
    steps.push(provider(
        dut,
        f_ls(nof, nos, 3, chs),
        "a last segment (ASDU 123) with COT = 13, LSQ=3",
    ));
    steps
}

/// The file transfer from the call file on: every section with its call,
/// segments, last segment and acknowledgement, then the last section and the
/// acknowledge file. `sections` holds each section's octets and its `CHS`
/// worked by hand; `file_chs` is the whole file's.
///
/// With `negative`, section 1 is first acknowledged negatively and sent again,
/// as the row asks: a negative acknowledgement (AFQ=4) makes the same section
/// go out again. When the station under test provides the file the mock sends the
/// `AFQ` `<4>`; when it receives the file the mock spoils the first last
/// segment's `CHS` (one more than the sum) and the station must answer `AFQ`
/// `<4>` by itself.
fn transfer(
    dut: Dut,
    nof: u16,
    sections: &[(&[u8], u8)],
    file_chs: u8,
    negative: bool,
) -> Vec<Step> {
    let mut steps = vec![requester(
        dut,
        f_sc(13, FILE_IOA, nof, 0, 2),
        "a call file (ASDU 122) with COT = 13, SCQ=2",
    )];
    for (index, (octets, chs)) in sections.iter().enumerate() {
        let nos = index as u8 + 1;
        steps.push(provider(
            dut,
            f_sr(nof, nos, octets.len() as u32, 0),
            "a section ready (ASDU 121) with COT = 13, SRQ=0",
        ));
        steps.push(requester(
            dut,
            f_sc(13, FILE_IOA, nof, nos, 6),
            "a call section (ASDU 122) with COT = 13, SCQ=6",
        ));
        if negative && index == 0 {
            match dut {
                Dut::Provider => {
                    steps.extend(section_steps(dut, nof, nos, octets, *chs));
                    steps.push(Step::Mock(f_af(nof, nos, 4)));
                }
                Dut::Requester => {
                    let mut spoiled = section_steps(dut, nof, nos, octets, *chs);
                    spoiled.pop();
                    spoiled.push(Step::Mock(f_ls(nof, nos, 3, chs.wrapping_add(1))));
                    steps.extend(spoiled);
                    steps.push(Step::Dut(
                        f_af(nof, nos, 4),
                        "negative acknowledge (AFQ=4): the CHS does not add up",
                    ));
                }
            }
        }
        steps.extend(section_steps(dut, nof, nos, octets, *chs));
        steps.push(requester(
            dut,
            f_af(nof, nos, 3),
            "an acknowledge section (ASDU 124) with COT = 13, AFQ=3",
        ));
    }
    let last = sections.len() as u8;
    steps.push(provider(
        dut,
        f_ls(nof, last, 1, file_chs),
        "a last section (ASDU 123) with COT = 13, LSQ=1",
    ));
    steps.push(requester(
        dut,
        f_af(nof, 0, 1),
        "an acknowledge file (ASDU 124) with COT = 13, AFQ=1",
    ));
    steps
}

/// The sample file's two sections with their `CHS`: `0x50` and `0x01` (see
/// [`SECTION_1`] and [`SECTION_2`]).
fn sample_sections() -> Vec<(&'static [u8], u8)> {
    vec![(&SECTION_1[..], 0x50), (&SECTION_2[..], 0x01)]
}

/// The sample file's `CHS`: `0x150 + 0x101 = 0x251`, so `0x51`.
const SAMPLE_FILE_CHS: u8 = 0x51;

/// The opening of 604 `5.4.23.1` up to the file ready: call directory (cause
/// 5), the directory (cause 5; one file, nine octets, `SOF` `0x20` with
/// `LFD` = 1, the directory's last file, 5-101 clause 7.2.6.38), select
/// file (`SCQ` `<1>`) and file ready (`FRQ` `<0>`).
fn monitor_opening(dut: Dut) -> Vec<Step> {
    vec![
        requester(
            dut,
            f_sc(5, FILE_IOA, 1, 0, 0),
            "a call directory command (ASDU 122) with COT = 5",
        ),
        provider(
            dut,
            f_dr(FILE_IOA, 1, 9, 0x20, SAMPLE_TIME_OCTETS),
            "a file directory (ASDU 126) with COT = 5",
        ),
        requester(
            dut,
            f_sc(13, FILE_IOA, 1, 0, 1),
            "a select file (ASDU 122) with COT = 13, SCQ=1",
        ),
        provider(
            dut,
            f_fr(FILE_IOA, 1, 9, 0),
            "a file ready (ASDU 120) with COT = 13, FRQ=0",
        ),
    ]
}

/// A controlled station under test running `app` against a mock controlling
/// station that plays `steps` after the STARTDT exchange.
fn drive_controlled(app: impl StationApp, steps: &[Step]) -> Result<(), String> {
    let station = ControlledStation::start_app(app, Vec::new())?;
    let mut mock = Mock::connect(station.addr())?;
    mock.start_as_controlling()?;
    let outcome = run(&mut mock, steps);
    mock.close()?;
    verdict(outcome, station.join().map(|_| ()))
}

/// The case's verdict: the station's own error first (an application error
/// ends its thread, which the mock only sees as a closed connection), then the
/// script's.
fn verdict(script: Result<(), String>, station: Result<(), String>) -> Result<(), String> {
    match (script, station) {
        (_, Err(why)) => Err(format!("the station under test: {why}")),
        (Err(why), Ok(())) => Err(why),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// The library as the controlling station under test running `app` against a
/// mock controlled station that plays `steps` after the STARTDT exchange.
fn drive_controlling(app: impl StationApp, steps: &[Step]) -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;
    let dut = ControllingDut::start(addr, app);
    let mut mock = Mock::accept(&listener)?;
    mock.start_as_controlled()?;
    let outcome = run(&mut mock, steps);
    mock.close()?;
    verdict(outcome, dut.join())
}

const fn controlled_ft(selection: Selection) -> FileTransferProcedure {
    FileTransferProcedure::controlled(selection, CA, ORIGINATOR)
}

const fn controlling_ft(selection: Selection) -> FileTransferProcedure {
    FileTransferProcedure::controlling(selection, CA, ORIGINATOR)
}

/// The call directory the controlling requester opens `5.4.23.1` with.
fn call_directory() -> Frame {
    Frame::Sc {
        ioa: FILE_IOA,
        nof: Nof { value: 1 },
        nos: Nos { value: 0 },
        scq: Scq::default(),
    }
}

// ------------------------------------------------------------- 5.4.23.1

/// 604 Table 23 (1 of 3), PDF page index 84 (printed 83), procedure
/// **`5.4.23.1`**, *"File transfer procedure (monitor direction) – sequential
/// procedure"*, `Reference` `IEC 60870-5-101:2003, 7.4.11`. The block's NOTE
/// limits these tests to systems that support file transfer in the monitor
/// direction. Its rows, in summary, are the script's steps (→ is the
/// controlling station sending to the controlled one, ← the reverse):
///
/// 1. → call directory, ASDU 122, COT 5 (`F_SC_REQ`);
/// 2. ← file directory, ASDU 126, COT 5 (`F_DR_REQ`);
/// 3. → select file, ASDU 122, COT 13 (`F_SC_FILE`), SCQ=1;
/// 4. ← file ready, ASDU 120, COT 13 (`F_FR_FILE`), FRQ=0;
/// 5. → call file, ASDU 122, COT 13 (`F_SC_FILE`), SCQ=2;
/// 6. ← section ready, ASDU 121, COT 13 (`F_SR_FILE`), SRQ=0;
/// 7. → call section, ASDU 122, COT 13 (`F_SC_FILE`), SCQ=6;
/// 8. ← the segments, ASDU 125, COT 13 (`F_SG_FILE`);
/// 9. ← last segment, ASDU 123, COT 13 (`F_LS_FILE`), LSQ=3;
/// 10. → acknowledge section, ASDU 124, COT 13 (`F_AF_FILE`), AFQ=3; a
///     negative acknowledgement (AFQ=4) has the same section sent again;
/// 11. steps 6 to 10 repeat for every section of the file;
/// 12. ← last section, ASDU 123, COT 13, LSQ=1 (the page labels it
///     `F_AF_FILE`; the type is 123);
/// 13. (index 85) → acknowledge file, ASDU 124, COT 13 (`F_AF_FILE`), AFQ=1.
///
/// DUT: the **controlled** station, `Selection::MONITOR`, providing the sample
/// file of two sections. The mock controlling station acknowledges section 1
/// negatively once, and requires it again octet for octet.
#[test]
fn clause_5_4_23_1_the_controlled_station_provides_a_file_in_monitor_direction() {
    let dut = Dut::Provider;
    let mut steps = monitor_opening(dut);
    steps.extend(transfer(dut, 1, &sample_sections(), SAMPLE_FILE_CHS, true));
    steps.push(Step::Quiet(
        "after the acknowledge file the transfer is over",
    ));
    let app = Provider::new(controlled_ft(Selection::MONITOR), sample_file());
    drive_controlled(app, &steps).unwrap_or_else(|why| panic!("5.4.23.1: {why}"));
}

/// The same procedure, **`5.4.23.1`** (index 84), with the roles as the rows
/// name them the other way round: DUT the **controlling** station
/// (`Selection::MONITOR`), which calls the directory, selects and calls the
/// file, calls each section, checks each section's `CHS` and the file's, and
/// acknowledges. The mock controlled station spoils the first last segment's
/// `CHS`, so the station must send the negative acknowledge (`AFQ` `<4>`) of
/// its own accord and then accept the section sent again.
#[test]
fn clause_5_4_23_1_the_controlling_station_receives_a_file_in_monitor_direction() {
    let dut = Dut::Requester;
    let mut steps = monitor_opening(dut);
    steps.extend(transfer(dut, 1, &sample_sections(), SAMPLE_FILE_CHS, true));
    steps.push(Step::Quiet(
        "after the acknowledge file the transfer is over",
    ));
    let app = Requester::new(controlling_ft(Selection::MONITOR)).opening(call_directory());
    drive_controlling(app, &steps).unwrap_or_else(|why| panic!("5.4.23.1: {why}"));
}

/// 604 Table 23 (2 of 3), PDF page index 85 (printed 84), the last row of
/// **`5.4.23.1`**, `Reference` `PID`, `Required` `PIXIT`:
///
/// whether selecting one section (ASDU 122, `F_SC`, SCQ=5) and aborting a
/// section (ASDU 122, `F_SC`, SCQ=7) are supported.
///
/// The sample PIXIT marks both supported (module doc). DUT: the **controlled**
/// station, which answers the select of section 2 (`SCQ` `<5>`) with section 2's
/// section ready and, after the abort (`SCQ` `<7>`, 5-101 clause 7.2.6.30's
/// section deactivation), sends nothing more.
#[test]
fn clause_5_4_23_1_pixit_the_controlled_station_serves_select_and_abort_section() {
    let dut = Dut::Provider;
    let mut steps = monitor_opening(dut);
    steps.extend(pixit_select_and_abort(dut));
    let app = Provider::new(controlled_ft(Selection::MONITOR), sample_file());
    drive_controlled(app, &steps).unwrap_or_else(|why| panic!("5.4.23.1 PIXIT: {why}"));
}

/// The same PIXIT row of **`5.4.23.1`** (index 85) with the **controlling**
/// station as the DUT: it sends the select section and the abort section, each
/// as `F_SC_NA_1` with cause 13 and the row's `SCQ`.
#[test]
fn clause_5_4_23_1_pixit_the_controlling_station_sends_select_and_abort_section() {
    let dut = Dut::Requester;
    let mut steps = monitor_opening(dut);
    steps.extend(pixit_select_and_abort(dut));
    let app = Requester::new(controlling_ft(Selection::MONITOR))
        .opening(call_directory())
        .selecting_section(Nos { value: 2 });
    drive_controlling(app, &steps).unwrap_or_else(|why| panic!("5.4.23.1 PIXIT: {why}"));
}

/// The PIXIT row's exchange after the file ready: select section 2 (`SCQ`
/// `<5>`), its section ready (three octets), abort section 2 (`SCQ` `<7>`),
/// then silence.
fn pixit_select_and_abort(dut: Dut) -> Vec<Step> {
    vec![
        requester(
            dut,
            f_sc(13, FILE_IOA, 1, 2, 5),
            "select section (ASDU 122, F_SC, SCQ=5)",
        ),
        provider(
            dut,
            f_sr(1, 2, 3, 0),
            "the selected section's section ready (ASDU 121)",
        ),
        requester(
            dut,
            f_sc(13, FILE_IOA, 1, 2, 7),
            "abort section (ASDU 122, F_SC, SCQ=7)",
        ),
        Step::Quiet("nothing follows an aborted section"),
    ]
}

// ------------------------------------------------------------- 5.4.23.10

/// 604 Table 23 (2 of 3), PDF page index 85 (printed 84), procedure
/// **`5.4.23.10`**, *"File transfer procedure (control direction) – sequential
/// procedure"*, `Reference` `IEC 60870-5-101:2003, 7.4.11`, every row `M` for a
/// system with *File transfer in control direction* in its PICS. The rows, in
/// summary (→ is the controlling station sending to the controlled one, ← the
/// reverse):
///
/// 1. → file ready, ASDU 120, COT 13 (`F_FR_FILE`);
/// 2. ← call file, ASDU 122, COT 13 (`F_SC_FILE`), SCQ=2;
/// 3. → section ready, ASDU 121, COT 13 (`F_SR_FILE`), SRQ=0;
/// 4. ← call section, ASDU 122, COT 13 (`F_SC_FILE`), SCQ=6;
/// 5. → the segments, ASDU 125, COT 13 (`F_SG_FILE`);
/// 6. → last segment, ASDU 123, COT 13 (`F_LS_FILE`), LSQ=3;
/// 7. ← acknowledge section, ASDU 124, COT 13 (`F_AF_FILE`), AFQ=3; a
///    negative acknowledgement (AFQ=4) has the same section sent again;
/// 8. steps 3 to 7 repeat for every section of the file;
/// 9. → last section, ASDU 123, COT 13 (`F_LS_FILE`), LSQ=1;
/// 10. ← acknowledge file, ASDU 124, COT 13 (`F_AF_FILE`), AFQ=1.
///
/// DUT: the **controlled** station, `Selection::CONTROL`, receiving the sample
/// file. The mock controlling station spoils section 1's `CHS` once, so the
/// station must acknowledge it negatively (`AFQ` `<4>`) and accept it again.
#[test]
fn clause_5_4_23_10_the_controlled_station_receives_a_file_in_control_direction() {
    let dut = Dut::Requester;
    let mut steps = vec![provider(
        dut,
        f_fr(FILE_IOA, 1, 9, 0),
        "a file ready command (ASDU 120) with COT = 13",
    )];
    steps.extend(transfer(dut, 1, &sample_sections(), SAMPLE_FILE_CHS, true));
    steps.push(Step::Quiet(
        "after the acknowledge file the transfer is over",
    ));
    let app = Requester::new(controlled_ft(Selection::CONTROL));
    drive_controlled(app, &steps).unwrap_or_else(|why| panic!("5.4.23.10: {why}"));
}

/// The same procedure, **`5.4.23.10`** (index 85), with the **controlling**
/// station as the DUT (`Selection::CONTROL`): it announces the file with the
/// file ready, serves each call, and sends section 1 again on the mock's
/// negative acknowledge.
#[test]
fn clause_5_4_23_10_the_controlling_station_provides_a_file_in_control_direction() {
    let dut = Dut::Provider;
    let mut steps = vec![provider(
        dut,
        f_fr(FILE_IOA, 1, 9, 0),
        "a file ready command (ASDU 120) with COT = 13",
    )];
    steps.extend(transfer(dut, 1, &sample_sections(), SAMPLE_FILE_CHS, true));
    steps.push(Step::Quiet(
        "after the acknowledge file the transfer is over",
    ));
    let app = Provider::new(controlling_ft(Selection::CONTROL), sample_file()).announcing();
    drive_controlling(app, &steps).unwrap_or_else(|why| panic!("5.4.23.10: {why}"));
}

/// The PIXIT row of **`5.4.23.10`** (index 85, `Required` `PIXIT`), the same
/// row as `5.4.23.1`'s: are selecting one section (ASDU 122, `F_SC`, SCQ=5)
/// and aborting a section (ASDU 122, `F_SC`, SCQ=7) supported? DUT: the
/// **controlled** station, which in the control direction is the one that
/// sends both requests.
#[test]
fn clause_5_4_23_10_pixit_the_controlled_station_sends_select_and_abort_section() {
    let dut = Dut::Requester;
    let mut steps = vec![provider(dut, f_fr(FILE_IOA, 1, 9, 0), "file ready")];
    steps.extend(pixit_select_and_abort(dut));
    let app = Requester::new(controlled_ft(Selection::CONTROL)).selecting_section(Nos { value: 2 });
    drive_controlled(app, &steps).unwrap_or_else(|why| panic!("5.4.23.10 PIXIT: {why}"));
}

/// The same PIXIT row of **`5.4.23.10`** with the **controlling** station as
/// the DUT, serving the select section and the abort section.
#[test]
fn clause_5_4_23_10_pixit_the_controlling_station_serves_select_and_abort_section() {
    let dut = Dut::Provider;
    let mut steps = vec![provider(dut, f_fr(FILE_IOA, 1, 9, 0), "file ready")];
    steps.extend(pixit_select_and_abort(dut));
    let app = Provider::new(controlling_ft(Selection::CONTROL), sample_file()).announcing();
    drive_controlling(app, &steps).unwrap_or_else(|why| panic!("5.4.23.10 PIXIT: {why}"));
}

/// Whether `reply` is the refusal the unknown-address row admits for
/// `request`: the same ASDU mirrored with `P/N = 1`, and a cause of 44 (the
/// row's negative confirmation, COT=44 with P/N=1) or 47 (the row's
/// `Reference`, 5-101 clause 7.2.3, index 42, where `<47>` is the unknown
/// information object address).
fn is_negative_mirror(request: &[u8], reply: &[u8]) -> bool {
    reply.len() == request.len()
        && reply[0] == request[0]
        && reply[1] == request[1]
        && reply[2] & 0x40 != 0
        && matches!(reply[2] & 0x3F, 44 | 47)
        && reply[3..] == request[3..]
}

/// The mock's half of the unknown-address row against a controlled station:
/// send `request`, and accept only the row's reactions. Silence is the row's
/// *ignored*; an I-frame must be the negative mirror of the request (its
/// negative confirmation). A positive answer, or any other frame, fails. Then `valid`,
/// the same request at the station's own address, must be answered with
/// `answer`, so a station that ignores everything cannot pass.
fn expect_refusal(
    mock: &mut Mock,
    request: &[u8],
    valid: Vec<u8>,
    answer: Vec<u8>,
) -> Result<&'static str, String> {
    mock.send_i(request)?;
    let reaction = match mock.next_i(QUIET_WAIT)? {
        None => "ignored",
        Some(reply) if is_negative_mirror(request, &reply) => "negatively confirmed",
        Some(reply) => {
            return Err(format!(
                "neither ignored nor a P/N = 1 mirror with COT 44 or 47: sent {}, got {}",
                interop::encode_hex(request),
                interop::encode_hex(&reply)
            ));
        }
    };
    run(
        mock,
        &[
            Step::Quiet("nothing follows the refusal"),
            Step::Mock(valid),
            Step::Dut(answer, "the same request at the known address is served"),
        ],
    )?;
    Ok(reaction)
}

/// 604 Table 23 (2 of 3), PDF page index 85 (printed 84), the last row of
/// **`5.4.23.10`**, `Reference` `IEC 60870-5-101:2003, 7.2.3`, `Required` `M`:
///
/// an ASDU, sent or received, whose IOA is not configured or does not apply
/// is not accepted: it is ignored, or negatively confirmed with COT=44 and
/// P/N=1.
///
/// DUT: the **controlled** station, in both file directions. Monitor direction
/// (`Selection::MONITOR`, the provider): a select file for an address the
/// station holds no file at. Control direction (`Selection::CONTROL`, the
/// requester): a file ready for such an address. Each must be ignored or
/// refused with the `P/N = 1` mirror, never answered: the row admits cause 44,
/// and its reference, 5-101 clause 7.2.3 (index 42: the controlled station
/// mirrors a control-direction ASDU whose data unit identifier, the variable
/// structure qualifier aside, or information object address is undefined),
/// pairs the undefined address with
/// cause 47. The same request at [`FILE_IOA`] is then served, so the station is
/// seen to tell the two addresses apart.
///
/// The crate takes both of the row's paths: it *ignores* the select file (it
/// places an `F_SC_NA_1` by the direction the file travels, monitor here, and
/// discards a monitor-direction frame) and *mirrors* the file ready with cause
/// 47. Both are admitted by the row, so the test does not pin either.
#[test]
fn clause_5_4_23_10_the_controlled_station_refuses_an_unknown_address() {
    // Monitor direction: the station provides files.
    let station = ControlledStation::start_app(
        Provider::new(controlled_ft(Selection::MONITOR), sample_file()),
        Vec::new(),
    )
    .expect("the station binds");
    let mut mock = Mock::connect(station.addr()).expect("connect");
    mock.start_as_controlling().expect("STARTDT");
    let outcome = expect_refusal(
        &mut mock,
        &f_sc(13, UNKNOWN_IOA, 1, 0, 1),
        f_sc(13, FILE_IOA, 1, 0, 1),
        f_fr(FILE_IOA, 1, 9, 0),
    );
    mock.close().expect("close");
    station.join().expect("the station ends cleanly");
    outcome.unwrap_or_else(|why| panic!("5.4.23.10 (monitor direction): {why}"));

    // Control direction: the station receives files.
    let station = ControlledStation::start_app(
        Requester::new(controlled_ft(Selection::CONTROL)),
        Vec::new(),
    )
    .expect("the station binds");
    let mut mock = Mock::connect(station.addr()).expect("connect");
    mock.start_as_controlling().expect("STARTDT");
    let outcome = expect_refusal(
        &mut mock,
        &f_fr(UNKNOWN_IOA, 1, 9, 0),
        f_fr(FILE_IOA, 1, 9, 0),
        f_sc(13, FILE_IOA, 1, 0, 2),
    );
    mock.close().expect("close");
    station.join().expect("the station ends cleanly");
    outcome.unwrap_or_else(|why| panic!("5.4.23.10 (control direction): {why}"));
}

/// The same row of **`5.4.23.10`** (index 85), DUT the **controlling** station
/// receiving a file in the monitor direction (`Selection::MONITOR`): the
/// directory that answers its call directory names an address the station does
/// not know. A controlling station may not send cause 44 to 47 at all (§5.1,
/// index 10 reserves those causes to the controlled station), so of the row's
/// three reactions only *ignored* is open to it: nothing goes back,
/// and the station still takes the correct directory that follows.
#[test]
fn clause_5_4_23_10_the_controlling_station_ignores_an_unknown_address_in_monitor_direction() {
    let dut = Dut::Requester;
    let steps = vec![
        requester(
            dut,
            f_sc(5, FILE_IOA, 1, 0, 0),
            "a call directory command (ASDU 122) with COT = 5",
        ),
        Step::Mock(f_dr(UNKNOWN_IOA, 1, 9, 0x20, SAMPLE_TIME_OCTETS)),
        Step::Quiet("a directory at an unknown address is ignored"),
        Step::Mock(f_dr(FILE_IOA, 1, 9, 0x20, SAMPLE_TIME_OCTETS)),
        Step::Dut(
            f_sc(13, FILE_IOA, 1, 0, 1),
            "the correct directory is still taken: select file, SCQ=1",
        ),
    ];
    let app = Requester::new(controlling_ft(Selection::MONITOR)).opening(call_directory());
    drive_controlling(app, &steps).unwrap_or_else(|why| panic!("5.4.23.10: {why}"));
}

/// The same row of **`5.4.23.10`** (index 85), DUT the **controlling** station
/// providing a file in the control direction (`Selection::CONTROL`): after its
/// file ready, the mock controlled station calls the file at an address the
/// station holds nothing at. As above, §5.1 (index 10) leaves the controlling
/// station only *ignored*, since COT 44-47 exist in the monitor direction
/// alone and only a controlled station may send them; 5-101 clause 7.2.3
/// (index 42) has the controlled station send the mirror. The station must
/// send nothing, and still serve the
/// correct call file that follows.
///
/// `ft::FileTransferProcedure::on_asdu` once classed an `F_SC_NA_1` from the
/// controlled station as control direction (the direction the *file* travels)
/// and answered it with the cause-47 mirror, so the controlling station sent
/// `7A 01 6F 00 01 00 02 04 00 01 00 00 02`, a COT 47 that §5.1 reserves to
/// the controlled station.
#[test]
fn clause_5_4_23_10_the_controlling_station_does_not_mirror_an_unknown_address() {
    let dut = Dut::Provider;
    let steps = vec![
        provider(
            dut,
            f_fr(FILE_IOA, 1, 9, 0),
            "a file ready command (ASDU 120) with COT = 13",
        ),
        Step::Mock(f_sc(13, UNKNOWN_IOA, 1, 0, 2)),
        Step::Quiet("a controlling station sends no COT 44-47"),
        Step::Mock(f_sc(13, FILE_IOA, 1, 0, 2)),
        Step::Dut(
            f_sr(1, 1, 6, 0),
            "the correct call file is still served: section ready, SRQ=0",
        ),
    ];
    let app = Provider::new(controlling_ft(Selection::CONTROL), sample_file()).announcing();
    drive_controlling(app, &steps).unwrap_or_else(|why| panic!("5.4.23.10: {why}"));
}

// ------------------------------------------------------------- 5.4.23.15

/// One Query Log case: the row's words, `RangeStartTime` and `RangeStopTime`
/// as figure 31's octets, the records they select, and those records' `CHS`.
type QueryCase = (&'static str, [u8; 7], [u8; 7], Vec<u8>, u8);

/// The four range combinations of 604 `5.4.23.15` (index 86), each with the
/// records 104 clause 8.9's table (index 92) makes it select from
/// [`log_records`], and the selected octets' `CHS` worked by hand:
///
/// - Available / Available (09-02 to 09-03, both included by footnote a):
///   records 2 and 3, `02 22 03 33`, sum `0x5A`;
/// - 0 / Available (to 09-02): records 1 and 2, `01 11 02 22`, sum `0x36`;
/// - Available / 0 (from 09-03): records 3 and 4, `03 33 04 44`, sum `0x7E`;
/// - 0 / 0: all four, sum `0x36 + 0x7E = 0xB4`.
fn query_cases() -> Vec<QueryCase> {
    vec![
        (
            "RangeStartTime: Available, RangeStopTime: Available",
            SEP_02,
            SEP_03,
            vec![0x02, 0x22, 0x03, 0x33],
            0x5A,
        ),
        (
            "RangeStartTime: 0 (all zeros), RangeStopTime: Available",
            ZERO_TIME,
            SEP_02,
            vec![0x01, 0x11, 0x02, 0x22],
            0x36,
        ),
        (
            "RangeStartTime: Available, RangeStopTime: 0 (all zeros)",
            SEP_03,
            ZERO_TIME,
            vec![0x03, 0x33, 0x04, 0x44],
            0x7E,
        ),
        (
            "RangeStartTime: 0 (all zeros), RangeStopTime: 0 (all zeros)",
            ZERO_TIME,
            ZERO_TIME,
            vec![0x01, 0x11, 0x02, 0x22, 0x03, 0x33, 0x04, 0x44],
            0xB4,
        ),
    ]
}

/// One Query Log exchange: the query (name of file `<3>`), the file ready for
/// the selected records, and the normal transfer of one section.
fn query_steps(dut: Dut, start: [u8; 7], stop: [u8; 7], records: &[u8], chs: u8) -> Vec<Step> {
    let mut steps = vec![
        requester(
            dut,
            f_sc_nb(3, start, stop),
            "a Query Log (ASDU 127) with COT = 13 (FILE)",
        ),
        provider(
            dut,
            f_fr(FILE_IOA, 3, records.len() as u32, 0),
            "starts the normal file transfer procedure: file ready",
        ),
    ];
    steps.extend(transfer(dut, 3, &[(records, chs)], chs, false));
    steps.push(Step::Quiet("the transfer is over"));
    steps
}

/// 604 Table 23 (3 of 3), PDF page index 86 (printed 85), procedure
/// **`5.4.23.15`**, *"File transfer procedure – Query Log"*, `Reference`
/// `IEC 60870-5-104:2006, 8.9`, `Required` `PICS, 9.5`:
///
/// the requesting station sends a Query Log (ASDU 127, COT 13, FILE); the
/// receiving station picks the records in the requested range and runs the
/// ordinary file transfer procedure. The rows require all four combinations of
/// the two range ends, each one either given or all zeros:
///
/// - `RangeStartTime` given, `RangeStopTime` given;
/// - `RangeStartTime` all zeros, `RangeStopTime` given;
/// - `RangeStartTime` given, `RangeStopTime` all zeros;
/// - both all zeros.
///
/// DUT: the **controlled** station as the receiving station
/// (`Selection::MONITOR`), for all four combinations. The query arrives as the
/// crate's `Reaction::Requested` with both range ends unchanged; which records
/// they select is 104 clause 8.9's table, applied by the harness's log (the
/// crate *"interprets nothing"*, `ft::query_log`), and the transfer that follows
/// is the crate's.
#[test]
fn clause_5_4_23_15_the_controlled_station_answers_a_query_log() {
    for (what, start, stop, records, chs) in query_cases() {
        let steps = query_steps(Dut::Provider, start, stop, &records, chs);
        let app =
            Provider::new(controlled_ft(Selection::MONITOR), sample_file()).with_log(log_records());
        drive_controlled(app, &steps).unwrap_or_else(|why| panic!("5.4.23.15, {what}: {why}"));
    }
}

/// The same procedure, **`5.4.23.15`** (index 86), DUT the **controlling**
/// station as the requesting station (`Selection::MONITOR`): it sends each of
/// the four queries as 104 figure 31 prints it, with the all-zero range ends
/// written as zeros, and receives the selected records.
#[test]
fn clause_5_4_23_15_the_controlling_station_sends_a_query_log() {
    for (what, start, stop, records, chs) in query_cases() {
        let steps = query_steps(Dut::Requester, start, stop, &records, chs);
        let time = |octets: [u8; 7]| Cp56Time2a::parse(&octets).expect("seven octets");
        let app = Requester::new(controlling_ft(Selection::MONITOR)).opening(Frame::QueryLog {
            ioa: FILE_IOA,
            nof: Nof { value: 3 },
            range_start: time(start),
            range_stop: time(stop),
        });
        drive_controlling(app, &steps).unwrap_or_else(|why| panic!("5.4.23.15, {what}: {why}"));
    }
}
