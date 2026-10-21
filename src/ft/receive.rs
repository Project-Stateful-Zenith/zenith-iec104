//! The receiving side of a file transfer as a session: the state
//! [`super::FileTransferProcedure`] leaves to the caller, kept for one file or
//! one directory.
//!
//! [`Receiver`] runs 5-101 clause **7.4.11**'s transfer of one file (the
//! exchange in the module doc of [`super`], indices 131–133): select file,
//! file ready, call file, then for each section: section ready, call section,
//! its segments and its last segment, acknowledge section; and at the end the
//! last section and acknowledge file. It checks each section's and the file's
//! `CHS` (7.2.6.37, index 58) and acknowledges negatively when one does not add
//! up, which asks the provider for the section again (604 `5.4.23.1`, index
//! 84). [`DirectoryCall`] collects the answer to a call directory until the
//! entry whose `SOF` marks the last file of the directory (7.2.6.38).
//!
//! Both are sans-IO like the rest of the crate: they take the received ASDUs
//! and return the ASDUs to send. There is no clock: how long to wait for the
//! next frame is the caller's.

use super::{
    DirectoryEntry, FileTransferProcedure, Frame, FtError, Reaction, SCQ_CALL_DIRECTORY, checksum,
};
use crate::asdu::{Afq, Cause, Chs, Frq, Known, Lsq, Nof, Nos, Scq, Srq};

/// Why a transfer ended without the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The provider answered the select or the call with a negative file ready
    /// (`FRQ` `BS1`, 7.2.6.28).
    FileNotReady {
        /// The file ready qualifier it sent.
        frq: Frq,
    },
    /// The provider answered a call with a section ready that says it is not
    /// ready (`SRQ` bit 8, 7.2.6.29).
    SectionNotReady {
        /// The section.
        nos: Nos,
        /// The section ready qualifier it sent.
        srq: Srq,
    },
    /// The provider refused a request with the 5-101 clause 7.2.3 mirror.
    Refused {
        /// The class's cause: 44, 45, 46 or 47.
        cause: Cause,
    },
    /// The file's `CHS` in the last section does not add up (7.2.6.37); the
    /// negative file acknowledgement went out.
    FileChecksum {
        /// The sum over the octets received.
        expected: Chs,
        /// The `CHS` the provider sent.
        got: Chs,
    },
    /// A last section or segment frame whose `LSQ` (7.2.6.31) is none of the
    /// four values the clause defines.
    UnknownLsq(Lsq),
}

/// Where a session stands after a received ASDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress<T> {
    /// More frames are expected.
    Running,
    /// The transfer is complete.
    Complete(T),
    /// The transfer ended without a result.
    Failed(Failure),
}

/// What one received ASDU did to a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step<T> {
    /// The ASDUs to send, in order.
    pub send: Vec<Vec<u8>>,
    /// Where the session stands now.
    pub progress: Progress<T>,
}

impl<T> Step<T> {
    const fn running(send: Vec<Vec<u8>>) -> Self {
        Self {
            send,
            progress: Progress::Running,
        }
    }

    const fn failed(send: Vec<Vec<u8>>, failure: Failure) -> Self {
        Self {
            send,
            progress: Progress::Failed(failure),
        }
    }
}

/// The receiving side of one file's transfer.
///
/// In the monitor direction this is the controlling station, built on
/// [`FileTransferProcedure::controlling`]; in the control direction the
/// controlled one (604 `5.4.23.1` against `5.4.23.10`, indices 84 and 85).
#[derive(Debug, Clone)]
pub struct Receiver {
    procedure: FileTransferProcedure,
    ioa: u32,
    nof: Nof,
    sent: Option<Frame>,
    length: Option<u32>,
    file: Vec<u8>,
    section: Vec<u8>,
    done: bool,
}

impl Receiver {
    /// A session for the file `nof` at information object address `ioa`
    /// (cl.7.4.11.1, index 131: the common address and the address identify
    /// the file, the name adds to them).
    #[must_use]
    pub const fn new(procedure: FileTransferProcedure, ioa: u32, nof: Nof) -> Self {
        Self {
            procedure,
            ioa,
            nof,
            sent: None,
            length: None,
            file: Vec::new(),
            section: Vec::new(),
            done: false,
        }
    }

    /// The select file (`F_SC_NA_1`, `SCQ` `<1>`) that opens the transfer.
    ///
    /// # Errors
    ///
    /// [`FileTransferProcedure::build`]'s errors.
    pub fn start(&mut self) -> Result<Vec<u8>, FtError> {
        self.request(Scq::SELECT_FILE, Nos { value: 0 })
    }

    /// The file's length as the file ready stated it (`LOF`, 7.2.6.35), once
    /// it has arrived.
    #[must_use]
    pub const fn length(&self) -> Option<u32> {
        self.length
    }

    /// How many octets have arrived so far, in the sections acknowledged and
    /// the one in flight.
    #[must_use]
    pub const fn received(&self) -> usize {
        self.file.len().saturating_add(self.section.len())
    }

    /// Takes one received ASDU and says what to send and where the transfer
    /// stands. An ASDU that is not the answer to the last request is
    /// [`super::FileTransferProcedure::on_answer`]'s error; one that arrives
    /// after the transfer ended changes nothing.
    ///
    /// # Errors
    ///
    /// [`FileTransferProcedure::on_answer`]'s and
    /// [`FileTransferProcedure::build`]'s errors.
    pub fn on_asdu(&mut self, asdu: &[u8], known: &Known) -> Result<Step<Vec<u8>>, FtError> {
        let (Some(sent), false) = (&self.sent, self.done) else {
            return Ok(Step::running(Vec::new()));
        };
        let outcome = self.procedure.on_answer(asdu, known, sent)?;
        let frame = match outcome.reaction {
            Reaction::Answered { frame } => frame,
            Reaction::Refused { cause } => {
                self.done = true;
                return Ok(Step::failed(outcome.send, Failure::Refused { cause }));
            }
            _ => return Ok(Step::running(outcome.send)),
        };
        match frame {
            Frame::FileReady { frq, .. } if frq.negative_confirm => {
                self.done = true;
                Ok(Step::failed(Vec::new(), Failure::FileNotReady { frq }))
            }
            Frame::FileReady { lof, .. } => {
                self.length = Some(lof.value);
                let call = self.request(Scq::REQUEST_FILE, Nos { value: 0 })?;
                Ok(Step::running(vec![call]))
            }
            Frame::SectionReady { nos, srq, .. } if srq.not_ready => {
                self.done = true;
                Ok(Step::failed(
                    Vec::new(),
                    Failure::SectionNotReady { nos, srq },
                ))
            }
            Frame::SectionReady { nos, .. } => {
                self.section.clear();
                let call = self.request(Scq::REQUEST_SECTION, nos)?;
                Ok(Step::running(vec![call]))
            }
            Frame::Segment { segment, .. } => {
                self.section.extend_from_slice(&segment.payload);
                Ok(Step::running(Vec::new()))
            }
            Frame::LastSection { nos, lsq, chs, .. } => self.on_last(nos, lsq, chs),
            _ => Ok(Step::running(Vec::new())),
        }
    }

    /// The last segment of a section (`LSQ` `<3>`/`<4>`) or the last section
    /// of the file (`<1>`/`<2>`), 7.2.6.31.
    fn on_last(&mut self, nos: Nos, lsq: Lsq, chs: Chs) -> Result<Step<Vec<u8>>, FtError> {
        match lsq.value {
            Lsq::SECTION_WITHOUT_DEACTIVATION | Lsq::SECTION_WITH_DEACTIVATION => {
                let action = if checksum(&self.section) == chs {
                    self.file.append(&mut self.section);
                    Afq::SECTION_POSITIVE
                } else {
                    // A negative section acknowledgement asks for the section
                    // again (604 5.4.23.1), so its octets so far are dropped.
                    self.section.clear();
                    Afq::SECTION_NEGATIVE
                };
                Ok(Step::running(vec![self.acknowledge(nos, action)?]))
            }
            Lsq::FILE_WITHOUT_DEACTIVATION | Lsq::FILE_WITH_DEACTIVATION => {
                self.done = true;
                let expected = checksum(&self.file);
                if expected != chs {
                    let send = vec![self.acknowledge(nos, Afq::FILE_NEGATIVE)?];
                    return Ok(Step::failed(
                        send,
                        Failure::FileChecksum { expected, got: chs },
                    ));
                }
                Ok(Step {
                    send: vec![self.acknowledge(nos, Afq::FILE_POSITIVE)?],
                    progress: Progress::Complete(std::mem::take(&mut self.file)),
                })
            }
            _ => {
                self.done = true;
                Ok(Step::failed(Vec::new(), Failure::UnknownLsq(lsq)))
            }
        }
    }

    fn request(&mut self, action: u8, nos: Nos) -> Result<Vec<u8>, FtError> {
        self.send(Frame::Sc {
            ioa: self.ioa,
            nof: self.nof,
            nos,
            scq: Scq { action, error: 0 },
        })
    }

    fn acknowledge(&mut self, nos: Nos, action: u8) -> Result<Vec<u8>, FtError> {
        self.send(Frame::Ack {
            ioa: self.ioa,
            nof: self.nof,
            nos,
            afq: Afq { action, error: 0 },
        })
    }

    fn send(&mut self, frame: Frame) -> Result<Vec<u8>, FtError> {
        let asdu = self.procedure.build(&frame)?;
        self.sent = Some(frame);
        Ok(asdu)
    }
}

/// A call directory (`F_SC_NA_1`, `SCQ` `<0>`, cause `<5>`) and its answer.
///
/// The directory may span several `F_DR_TA_1` ASDUs, since at most
/// [`super::max_directory_files`] files fit in one. It ends with the entry
/// whose `SOF` has `LFD` set (7.2.6.38).
#[derive(Debug, Clone)]
pub struct DirectoryCall {
    procedure: FileTransferProcedure,
    sent: Option<Frame>,
    files: Vec<DirectoryEntry>,
    done: bool,
}

impl DirectoryCall {
    /// A call through `procedure`; [`DirectoryCall::start`] names the address.
    #[must_use]
    pub const fn new(procedure: FileTransferProcedure) -> Self {
        Self {
            procedure,
            sent: None,
            files: Vec::new(),
            done: false,
        }
    }

    /// The call directory ASDU for the directory at information object
    /// address `ioa`.
    ///
    /// # Errors
    ///
    /// [`FileTransferProcedure::build`]'s errors.
    pub fn start(&mut self, ioa: u32) -> Result<Vec<u8>, FtError> {
        let frame = Frame::Sc {
            ioa,
            nof: Nof { value: 0 },
            nos: Nos { value: 0 },
            scq: Scq {
                action: SCQ_CALL_DIRECTORY,
                error: 0,
            },
        };
        let asdu = self.procedure.build(&frame)?;
        self.sent = Some(frame);
        Ok(asdu)
    }

    /// Takes one received ASDU.
    ///
    /// # Errors
    ///
    /// [`FileTransferProcedure::on_asdu`]'s errors.
    pub fn on_asdu(
        &mut self,
        asdu: &[u8],
        known: &Known,
    ) -> Result<Step<Vec<DirectoryEntry>>, FtError> {
        if self.sent.is_none() || self.done {
            return Ok(Step::running(Vec::new()));
        }
        // Not `on_answer`: a directory over several ASDUs moves its base
        // address on with each (figure 89, index 120: file i is at A + i - 1).
        let outcome = self.procedure.on_asdu(asdu, known)?;
        match outcome.reaction {
            Reaction::Answered {
                frame: Frame::Directory { files, .. },
            } => {
                let last = files.iter().any(|f| f.sof.last_file_of_directory);
                self.files.extend(files);
                if !last {
                    return Ok(Step::running(outcome.send));
                }
                self.done = true;
                Ok(Step {
                    send: outcome.send,
                    progress: Progress::Complete(std::mem::take(&mut self.files)),
                })
            }
            Reaction::Refused { cause } => {
                self.done = true;
                Ok(Step::failed(outcome.send, Failure::Refused { cause }))
            }
            _ => Ok(Step::running(outcome.send)),
        }
    }
}
