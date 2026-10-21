//! The providing side of a file transfer as a session, the counterpart of
//! [`super::receive`].
//!
//! [`Provider`] holds one file and answers 5-101 clause **7.4.11**'s requests
//! for it (the exchange in the module doc of [`super`], indices 131–133):
//! select file with the file ready, call file with the first section ready,
//! call section with its segments and its last segment and the section's
//! `CHS` (7.2.6.37), a positive section acknowledgement with the next section
//! ready or, after the last section, the last section with the file's `CHS`,
//! and a negative one with the same section again (604 `5.4.23.1`, index 84).
//! The file acknowledgement ends it.
//!
//! In the monitor direction the provider is the controlled station; in the
//! control direction the controlling one, which opens the transfer with
//! [`Provider::announce`]'s file ready (604 `5.4.23.10`, index 85).
//!
//! [`directory`] builds the `F_DR_TA_1` frames that answer a call directory.

use super::receive::{Failure, Progress, Step};
use super::{
    DirectoryEntry, FileTransferProcedure, Frame, FtError, Reaction, checksum, max_directory_files,
    max_segment,
};
use crate::asdu::{Afq, Cause, Frq, Known, Lof, Los, Lsq, Nof, Nos, Scq, Segment, Srq};

/// The section length [`Provider::new`] starts from. A larger file gets
/// longer sections, so that it needs no more than the 255 a `NOS` can name
/// (7.2.6.34).
pub const DEFAULT_SECTION_LEN: usize = 4096;

/// The providing side of one file's transfer.
#[derive(Debug, Clone)]
pub struct Provider {
    procedure: FileTransferProcedure,
    ioa: u32,
    nof: Nof,
    file: Vec<u8>,
    section_len: usize,
    done: bool,
}

impl Provider {
    /// The file `nof` at information object address `ioa`, holding `file`.
    ///
    /// Returns `None` for a file longer than `LOF` can state (7.2.6.35,
    /// [`Lof::MAX`]).
    #[must_use]
    pub fn new(
        procedure: FileTransferProcedure,
        ioa: u32,
        nof: Nof,
        file: Vec<u8>,
    ) -> Option<Self> {
        let length = u32::try_from(file.len()).ok().filter(|l| *l <= Lof::MAX)?;
        let fitted = usize::try_from(length.div_ceil(255)).ok()?;
        Some(Self {
            procedure,
            ioa,
            nof,
            file,
            section_len: DEFAULT_SECTION_LEN.max(fitted),
            done: false,
        })
    }

    /// The information object address and the name of the file.
    #[must_use]
    pub const fn file(&self) -> (u32, Nof) {
        (self.ioa, self.nof)
    }

    /// The file ready (`F_FR_NA_1`, positive) that offers the file without a
    /// select: how the control direction's provider opens the transfer.
    ///
    /// # Errors
    ///
    /// [`FileTransferProcedure::build`]'s errors.
    pub fn announce(&self) -> Result<Vec<u8>, FtError> {
        self.procedure.build(&self.file_ready())
    }

    /// Takes one received ASDU. A request for another file, or one that
    /// arrives after the transfer ended, changes nothing.
    ///
    /// # Errors
    ///
    /// [`FileTransferProcedure::on_asdu`]'s and
    /// [`FileTransferProcedure::build`]'s errors.
    pub fn on_asdu(&mut self, asdu: &[u8], known: &Known) -> Result<Step<()>, FtError> {
        if self.done {
            return Ok(running(Vec::new()));
        }
        let outcome = self.procedure.on_asdu(asdu, known)?;
        let frame = match outcome.reaction {
            Reaction::Requested { frame } => frame,
            Reaction::Refused { cause } => {
                self.done = true;
                return Ok(Step {
                    send: outcome.send,
                    progress: Progress::Failed(Failure::Refused { cause }),
                });
            }
            _ => return Ok(running(outcome.send)),
        };
        if frame.ioa() != self.ioa || !names_file(&frame, self.nof) {
            return Ok(running(Vec::new()));
        }
        let frames = match frame {
            Frame::Sc { nos, scq, .. } => match scq.action {
                Scq::SELECT_FILE => vec![self.file_ready()],
                Scq::REQUEST_FILE => vec![self.section_ready(Nos { value: 1 })],
                Scq::SELECT_SECTION => vec![self.section_ready(nos)],
                Scq::REQUEST_SECTION => self.section(nos),
                _ => {
                    // Deactivate or delete file, deactivate section (7.2.6.30).
                    self.done = true;
                    return Ok(Step {
                        send: Vec::new(),
                        progress: Progress::Failed(Failure::Deactivated { scq }),
                    });
                }
            },
            Frame::Ack { nos, afq, .. } => match afq.action {
                Afq::SECTION_POSITIVE => vec![self.after(nos)],
                Afq::SECTION_NEGATIVE => self.section(nos),
                Afq::FILE_POSITIVE => {
                    self.done = true;
                    return Ok(Step {
                        send: Vec::new(),
                        progress: Progress::Complete(()),
                    });
                }
                _ => {
                    self.done = true;
                    return Ok(Step {
                        send: Vec::new(),
                        progress: Progress::Failed(Failure::FileRejected { afq }),
                    });
                }
            },
            _ => Vec::new(),
        };
        let send = frames
            .iter()
            .map(|frame| self.procedure.build(frame))
            .collect::<Result<_, _>>()?;
        Ok(running(send))
    }

    fn sections(&self) -> std::slice::Chunks<'_, u8> {
        self.file.chunks(self.section_len)
    }

    fn last_section(&self) -> Nos {
        let count = u8::try_from(self.sections().count()).unwrap_or(u8::MAX);
        Nos {
            value: count.max(1),
        }
    }

    /// Section `nos`'s octets: `NOS` counts from 1 (7.2.6.34). An empty file
    /// has one empty section.
    fn octets(&self, nos: Nos) -> &[u8] {
        usize::from(nos.value)
            .checked_sub(1)
            .and_then(|i| self.sections().nth(i))
            .unwrap_or_default()
    }

    fn file_ready(&self) -> Frame {
        Frame::FileReady {
            ioa: self.ioa,
            nof: self.nof,
            lof: lof(self.file.len()),
            frq: Frq::default(),
        }
    }

    fn section_ready(&self, nos: Nos) -> Frame {
        Frame::SectionReady {
            ioa: self.ioa,
            nof: self.nof,
            nos,
            lof: lof(self.octets(nos).len()),
            srq: Srq::default(),
        }
    }

    /// Section `nos` as segments, then its last segment with its `CHS`.
    fn section(&self, nos: Nos) -> Vec<Frame> {
        let octets = self.octets(nos);
        let mut frames: Vec<Frame> = octets
            .chunks(max_segment(self.procedure.address_sizes()).min(usize::from(Los::MAX)))
            .map(|chunk| Frame::Segment {
                ioa: self.ioa,
                segment: Segment {
                    nof: self.nof,
                    nos,
                    los: Los {
                        value: u8::try_from(chunk.len()).unwrap_or(Los::MAX),
                    },
                    payload: chunk.to_vec(),
                },
            })
            .collect();
        frames.push(self.last(nos, Lsq::SECTION_WITHOUT_DEACTIVATION, octets));
        frames
    }

    /// What follows a positive acknowledgement of section `nos`: the next
    /// section ready, or the last section with the file's `CHS`.
    fn after(&self, nos: Nos) -> Frame {
        match nos.value.checked_add(1) {
            Some(next) if nos.value < self.last_section().value => {
                self.section_ready(Nos { value: next })
            }
            _ => self.last(nos, Lsq::FILE_WITHOUT_DEACTIVATION, &self.file),
        }
    }

    fn last(&self, nos: Nos, lsq: u8, octets: &[u8]) -> Frame {
        Frame::LastSection {
            ioa: self.ioa,
            nof: self.nof,
            nos,
            lsq: Lsq { value: lsq },
            chs: checksum(octets),
        }
    }
}

const fn running(send: Vec<Vec<u8>>) -> Step<()> {
    Step {
        send,
        progress: Progress::Running,
    }
}

/// Whether `frame` names the file `nof`, where it carries a name at all.
fn names_file(frame: &Frame, nof: Nof) -> bool {
    match frame {
        Frame::Sc { nof: n, .. } | Frame::Ack { nof: n, .. } => *n == nof,
        _ => true,
    }
}

/// `LOF` for a length [`Provider::new`] has checked.
fn lof(len: usize) -> Lof {
    Lof {
        value: u32::try_from(len).unwrap_or(Lof::MAX),
    }
}

/// The `F_DR_TA_1` frames that answer a call directory with `files`, the
/// first at information object address `ioa` and each next one at the next
/// address (figure 89, index 120).
///
/// At most [`max_directory_files`] files go in one frame for the address
/// sizes `procedure` uses, and the last file of the whole directory gets
/// `SOF`'s `LFD` (7.2.6.38), whatever the caller set. An empty directory has
/// no frame: figure 89 carries at least one file, so how to answer a call for
/// one is the caller's.
#[must_use]
pub fn directory(
    procedure: &FileTransferProcedure,
    ioa: u32,
    files: &[DirectoryEntry],
) -> Vec<Frame> {
    let per_frame = max_directory_files(procedure.address_sizes()).max(1);
    let total = files.len();
    let mut frames = Vec::new();
    let mut base = ioa;
    let mut done = 0usize;
    for chunk in files.chunks(per_frame) {
        let mut entries = chunk.to_vec();
        done = done.saturating_add(chunk.len());
        for entry in &mut entries {
            entry.sof.last_file_of_directory = false;
        }
        if done == total
            && let Some(last) = entries.last_mut()
        {
            last.sof.last_file_of_directory = true;
        }
        frames.push(Frame::Directory {
            ioa: base,
            cause: Cause::Request,
            files: entries,
        });
        base = base.saturating_add(u32::try_from(chunk.len()).unwrap_or(u32::MAX));
    }
    frames
}
