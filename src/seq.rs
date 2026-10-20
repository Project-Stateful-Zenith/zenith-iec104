//! Sequence numbers, acknowledgement bookkeeping and the k/w window of
//! IEC 60870-5-104:2006 clauses 5.1 and 5.5.
//!
//! Clause 5.1 defines the mechanism (its wording is the basis for every rule
//! here):
//!
//! - "Both sequence numbers are sequentially increased by one for each APDU and
//!   each direction. The transmitter increases the Send Sequence Number N(S) and
//!   the receiver increases the Receive Sequence Number N(R)."
//! - "The receiving station acknowledges each APDU or a number of APDUs when it
//!   returns the Receive Sequence Number up to the number whose APDUs are
//!   properly received."
//! - "The sending station holds the APDU or APDUs in a buffer until it receives
//!   back its own Send Sequence Number as a Receive Sequence Number which is a
//!   valid acknowledge for all numbers <= the received number. Then it may
//!   delete the correctly transmitted APDUs from the buffer."
//! - "In case of longer data transmission in one direction only, an S format has
//!   to be sent in the other direction to acknowledge the APDUs before buffer
//!   overflow or time out."
//! - "After the establishment of a TCP connection, the send and receive sequence
//!   numbers are set to zero."
//!
//! Clause 5.5 defines the two window limits:
//!
//! - "The transmitter stops the transmission at k unacknowledged I format
//!   APDUs."
//! - "The receiver acknowledges at the latest after receiving w = I format
//!   APDUs". The footnote gives the reason: "Acknowledging before k is reached
//!   avoids a transmission stop."
//!
//! The exchange the two clauses describe is drawn in the standard's figures 9
//! (undisturbed sequence), 10 (acknowledged by an S format APDU), 11 (disturbed
//! sequence: a wrong N(S) is a sequence error) and 12 (time-out of a last,
//! unacknowledged I format APDU).
//!
//! This module is the bookkeeping only: no I/O, no clock, no allocation on the
//! receive path. The caller owns the wire and the timers; it feeds received
//! numbers in and asks for the numbers to stamp on outgoing frames.

use crate::apci::SeqNo;
use crate::params::{LinkParams, MODULUS, ParamError};

/// One I-format APDU that was sent and is held until its N(S) comes back as an
/// N(R) (clause 5.1's send buffer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentFrame {
    /// The N(S) this frame was stamped with.
    pub ns: SeqNo,
    /// The ASDU octets, kept so the frame can be replayed or retransmitted.
    pub asdu: Vec<u8>,
}

/// Why a received sequence number is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceError {
    /// N(S) was not the next expected number. Figure 11 (`Sequence error`)
    /// shows the station closing the connection on this.
    UnexpectedSendSequence {
        /// The receive state variable V(R): the N(S) expected next.
        expected: SeqNo,
        /// The N(S) received.
        got: SeqNo,
    },
    /// N(R) acknowledged more I-frames than this station has outstanding, or a
    /// number it never sent.
    AcknowledgedUnscheduled {
        /// The N(S) of the oldest unconfirmed I-frame, or V(S) when none is
        /// unconfirmed.
        oldest_outstanding: SeqNo,
        /// The N(R) received.
        got: SeqNo,
        /// How many I-frames were unconfirmed.
        outstanding: u16,
    },
}

/// The sequence bookkeeping of one connection.
#[derive(Debug, Clone)]
pub struct Sequence {
    v_s: SeqNo,
    v_r: SeqNo,
    buffer: Vec<SentFrame>,
    k: u16,
    w: u16,
    received_since_ack: u16,
}

impl Sequence {
    /// A fresh connection: both counters are zero (clause 5.1, "After the
    /// establishment of a TCP connection, the send and receive sequence numbers
    /// are set to zero").
    ///
    /// The parameters are validated as [`Session::with_params`](crate::link::Session::with_params)
    /// does: a k above `n - 1` would let N(S) wrap onto unacknowledged frames,
    /// and a k or w of zero never opens the window.
    ///
    /// # Errors
    ///
    /// The [`ParamError`] of [`LinkParams::validate`] for an inadmissible set.
    pub fn new(params: LinkParams) -> Result<Self, ParamError> {
        params.validate()?;
        Ok(Self::new_unchecked(params))
    }

    /// [`Sequence::new`] for parameters the caller has already validated.
    pub(crate) const fn new_unchecked(params: LinkParams) -> Self {
        Self {
            v_s: SeqNo::new(0),
            v_r: SeqNo::new(0),
            buffer: Vec::new(),
            k: params.k,
            w: params.w,
            received_since_ack: 0,
        }
    }

    /// Restarts the counters for a new connection, dropping the send buffer.
    pub fn reset(&mut self) {
        self.v_s = SeqNo::new(0);
        self.v_r = SeqNo::new(0);
        self.buffer.clear();
        self.received_since_ack = 0;
    }

    /// The next N(S) an outgoing I-frame will be stamped with.
    #[must_use]
    pub const fn v_s(&self) -> SeqNo {
        self.v_s
    }

    /// The N(R) an outgoing frame must carry: the next N(S) expected from the
    /// peer, which acknowledges every I-frame up to and including `v_r - 1`.
    #[must_use]
    pub const fn v_r(&self) -> SeqNo {
        self.v_r
    }

    /// I-frames sent and not yet acknowledged: the send buffer's length.
    #[must_use]
    pub const fn outstanding(&self) -> u16 {
        // The buffer never holds more than k <= 32767 frames (clause 5.5), so
        // its two low octets are the whole length.
        let [low, high, ..] = self.buffer.len().to_le_bytes();
        u16::from_le_bytes([low, high])
    }

    /// True while another I-frame may be sent (clause 5.5: the transmitter stops
    /// at k unacknowledged I format APDUs).
    #[must_use]
    pub const fn window_open(&self) -> bool {
        self.outstanding() < self.k
    }

    /// True when an I-frame was received since the last acknowledgement went out.
    #[must_use]
    pub const fn ack_pending(&self) -> bool {
        self.received_since_ack > 0
    }

    /// Stamps and buffers an outgoing I-frame.
    ///
    /// Returns the N(S) the caller must put in the control field, or `None` when
    /// the k window is full (clause 5.5). The frame carries N(R) = [`v_r`], so
    /// buffering one also acknowledges everything received so far.
    ///
    /// [`v_r`]: Sequence::v_r
    pub fn buffer_i_frame(&mut self, asdu: &[u8]) -> Option<SeqNo> {
        if !self.window_open() {
            return None;
        }
        let ns = self.v_s;
        self.v_s = self.v_s.next();
        self.received_since_ack = 0;
        self.buffer.push(SentFrame {
            ns,
            asdu: asdu.to_vec(),
        });
        Some(ns)
    }

    /// Feeds in the N(S) of an accepted I-frame.
    ///
    /// Returns `Some(nr)` when the w limit is reached and an acknowledgement is
    /// due now (clause 5.5: the receiver acknowledges at the latest after
    /// receiving w I format APDUs), otherwise `None`. A wrong N(S) is
    /// [`SequenceError::UnexpectedSendSequence`].
    ///
    /// # Errors
    ///
    /// [`SequenceError::UnexpectedSendSequence`] when `ns` is not the expected
    /// V(R).
    pub fn note_i_frame_received(&mut self, ns: SeqNo) -> Result<Option<SeqNo>, SequenceError> {
        if ns != self.v_r {
            return Err(SequenceError::UnexpectedSendSequence {
                expected: self.v_r,
                got: ns,
            });
        }
        self.v_r = self.v_r.next();
        self.received_since_ack = self.received_since_ack.saturating_add(1);
        if self.received_since_ack >= self.w {
            self.received_since_ack = 0;
            Ok(Some(self.v_r))
        } else {
            Ok(None)
        }
    }

    /// Feeds in the N(R) of any received frame (S format, or piggybacked on an
    /// I format) and releases the acknowledged frames from the buffer.
    ///
    /// Returns how many frames were released.
    ///
    /// # Errors
    ///
    /// [`SequenceError::AcknowledgedUnscheduled`] when `nr` acknowledges more
    /// frames than are outstanding.
    pub fn note_ack_received(&mut self, nr: SeqNo) -> Result<u16, SequenceError> {
        // The oldest number still outstanding, or the next one to send when the
        // buffer is empty: an ack of exactly that number releases nothing and is
        // legal (a station may acknowledge having received nothing yet).
        let oldest = self.buffer.first().map_or(self.v_s, |f| f.ns);
        let outstanding = self.outstanding();
        // (nr - oldest) modulo 32768: both are 15-bit, and 32768 divides 65536.
        let released = nr.get().wrapping_sub(oldest.get()) & 0x7FFF;
        if released > outstanding {
            return Err(SequenceError::AcknowledgedUnscheduled {
                oldest_outstanding: oldest,
                got: nr,
                outstanding,
            });
        }
        self.buffer.drain(0..usize::from(released));
        Ok(released)
    }

    /// Marks every received I-frame as acknowledged. Call this when putting an
    /// S-frame on the wire; returns the N(R) that frame carries.
    pub const fn acknowledge_all(&mut self) -> SeqNo {
        self.received_since_ack = 0;
        self.v_r
    }

    /// The frames still held in the send buffer, oldest first.
    #[must_use]
    pub fn outstanding_frames(&self) -> &[SentFrame] {
        &self.buffer
    }

    /// The modulus of the sequence numbers (`n` in clause 5.5).
    #[must_use]
    pub const fn modulus() -> u32 {
        MODULUS
    }
}
