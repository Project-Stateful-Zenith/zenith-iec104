//! Stream framing: turning a TCP byte stream into whole APDUs.
//!
//! The codec in [`crate::apci`] parses one APDU from the front of a buffer. A
//! TCP connection hands over arbitrary chunk boundaries: one `read` may carry
//! half an APDU or three APDUs. This module is the buffer between the two.
//!
//! Clause 5 says the start octet `0x68` "defines the point of start within the
//! data stream". TCP neither loses, corrupts nor reorders octets, so any other
//! octet where a frame must start means the peer is not speaking clause 5 (a
//! scanner, an HTTP request, a broken stack). The decoder reports it as
//! [`ParseError::BadStart`], which closes the connection
//! ([`crate::link::reaction`]), and discards the octets up to the next `0x68`,
//! so a caller that goes on reading is never stuck. It does not skip them
//! silently: whatever followed would be read as frames, so octets of the
//! peer's choosing would be taken for APDUs. The octets discarded are counted
//! by [`Decoder::resyncs`].
//!
//! This layer validates only the length field, which must lie between 4 and 253
//! (clause 5). Whether the control field matches the length (an I-format frame
//! always carries an ASDU, so its length is at least 5) is checked by
//! [`crate::apci::parse`], because framing does not decode control fields.

use crate::apci::{ParseError, START};
use std::fmt;
use std::io::Read;

/// Framing failures.
#[derive(Debug)]
pub enum FramingError {
    /// A frame whose start octet was present but whose length field is illegal.
    /// The offending start octet has already been dropped, so the decoder keeps
    /// making progress.
    BadFrame(ParseError),
    /// The underlying reader failed.
    Io(std::io::Error),
}

impl fmt::Display for FramingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadFrame(e) => write!(f, "malformed frame: {e:?}"),
            Self::Io(e) => write!(f, "read failed: {e}"),
        }
    }
}

impl std::error::Error for FramingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BadFrame(_) => None,
            Self::Io(e) => Some(e),
        }
    }
}

impl From<ParseError> for FramingError {
    fn from(e: ParseError) -> Self {
        Self::BadFrame(e)
    }
}

/// Result of looking at the buffered octets.
enum Scan {
    /// Not enough octets for a whole frame yet.
    NeedMore,
    /// A whole frame of this many octets is buffered.
    Frame(usize),
    /// No start octet where one belongs, or one followed by an illegal
    /// length field.
    Bad(ParseError),
}

/// Push-based APDU framer: [`push`](Decoder::push) octets from the socket,
/// then pull whole frames out with [`next_frame`](Decoder::next_frame).
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
    /// Octets at the front of `buf` already handed out as a frame.
    delivered: usize,
    resyncs: u64,
}

impl Decoder {
    /// A decoder with nothing buffered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends freshly read octets.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next whole APDU, or `None` if more octets are needed.
    ///
    /// Returns a slice into the internal buffer; it stays valid until the next
    /// call to this method or [`push`](Decoder::push).
    ///
    /// # Errors
    ///
    /// [`FramingError::BadFrame`] when the buffered octets do not start with a
    /// legal frame header; the offending octets are dropped first.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, FramingError> {
        self.drop_delivered();

        match self.scan() {
            Scan::NeedMore => Ok(None),
            Scan::Frame(len) => {
                self.delivered = len;
                Ok(self.buf.get(..len))
            }
            Scan::Bad(err) => {
                // No start octet where one belongs, or a start octet whose
                // length field is illegal, so the frame cannot be skipped
                // reliably. Drop the offending start octet, if it is one, and
                // everything up to the next one, and report the error once; a
                // caller that ignores it still advances.
                if !matches!(err, ParseError::BadStart(_)) {
                    self.buf.remove(0);
                    self.resyncs = self.resyncs.saturating_add(1);
                }
                self.resync();
                Err(FramingError::BadFrame(err))
            }
        }
    }

    /// True when no complete frame is waiting to be delivered.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        !matches!(self.scan(), Scan::Frame(_))
    }

    /// Length of the frame that is ready to be delivered, if any.
    ///
    /// Unlike [`next_frame`](Decoder::next_frame) this borrows nothing and does
    /// not consume anything, so a caller can fill the buffer until a whole frame
    /// is present and only then take it.
    ///
    /// # Errors
    ///
    /// The [`ParseError`] that [`next_frame`](Decoder::next_frame) would report
    /// for the buffered octets.
    pub fn next_frame_len(&self) -> Result<Option<usize>, ParseError> {
        match self.scan() {
            Scan::NeedMore => Ok(None),
            Scan::Frame(len) => Ok(Some(len)),
            Scan::Bad(err) => Err(err),
        }
    }

    /// Octets discarded so far while looking for the start octet, including
    /// start octets dropped because their length field was illegal.
    #[must_use]
    pub const fn resyncs(&self) -> u64 {
        self.resyncs
    }

    /// Octets buffered and not yet handed out as a frame.
    #[must_use]
    pub const fn buffered(&self) -> usize {
        self.buf.len().saturating_sub(self.delivered)
    }

    /// Drops the frame handed out by the previous `next_frame`.
    fn drop_delivered(&mut self) {
        if self.delivered > 0 {
            self.buf.drain(..self.delivered);
            self.delivered = 0;
        }
    }

    /// Discards octets up to the next start octet (clause 5).
    fn resync(&mut self) {
        match self.buf.iter().position(|&b| b == START) {
            Some(0) => {}
            Some(first) => {
                self.buf.drain(..first);
                self.count_resyncs(first);
            }
            None => {
                self.count_resyncs(self.buf.len());
                self.buf.clear();
            }
        }
    }

    /// Adds `octets` discarded octets to the resync counter.
    fn count_resyncs(&mut self, octets: usize) {
        let octets = u64::try_from(octets).unwrap_or(u64::MAX);
        self.resyncs = self.resyncs.saturating_add(octets);
    }

    /// Looks for a whole frame at the front of the buffer, after the frame
    /// already handed out. Its first octet must be the start octet (clause 5).
    fn scan(&self) -> Scan {
        let live = self.buf.get(self.delivered..).unwrap_or_default();
        match *live {
            [start, ..] if start != START => Scan::Bad(ParseError::BadStart(start)),
            [] | [_] => Scan::NeedMore,
            [start, length, ..] => match crate::apci::apdu_len(start, length) {
                Ok(total) if live.len() >= total => Scan::Frame(total),
                Ok(_) => Scan::NeedMore,
                Err(e) => Scan::Bad(e),
            },
        }
    }
}

/// APDU framer over any [`Read`] source, such as a `TcpStream`.
#[derive(Debug)]
pub struct Framed<R> {
    inner: R,
    decoder: Decoder,
    eof: bool,
    scratch: [u8; 4096],
}

impl<R: Read> Framed<R> {
    /// A framer that reads from `reader`.
    pub fn new(reader: R) -> Self {
        Self {
            inner: reader,
            decoder: Decoder::new(),
            eof: false,
            scratch: [0u8; 4096],
        }
    }

    /// Reads until a whole APDU is available, then returns it.
    ///
    /// `Ok(None)` means the stream ended. A partial frame at the end of the
    /// stream is dropped, not returned: half an APDU is not an APDU.
    ///
    /// # Errors
    ///
    /// [`FramingError::Io`] when the reader fails, and
    /// [`FramingError::BadFrame`] for a malformed frame header.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, FramingError> {
        // Fill the buffer until a whole frame is present. This loop only takes
        // immutable borrows of the decoder, so the frame it finally returns can
        // borrow the decoder for the caller.
        loop {
            match self.decoder.next_frame_len() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                // A malformed frame: let `next_frame` drop the offending octet
                // so the decoder keeps making progress, and report it.
                Err(_) => return self.decoder.next_frame(),
            }
            if self.eof {
                return Ok(None);
            }
            let read = self
                .inner
                .read(&mut self.scratch)
                .map_err(FramingError::Io)?;
            if read == 0 {
                self.eof = true;
            } else {
                let (head, _) = self.scratch.split_at(read);
                // `push` copies, so the borrow of `scratch` ends here.
                self.decoder.push(head);
            }
        }
        self.decoder.next_frame()
    }

    /// Returns the wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    /// Access to the framer state (resync counters, buffered octets).
    pub const fn decoder(&self) -> &Decoder {
        &self.decoder
    }
}
