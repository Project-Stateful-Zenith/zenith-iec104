//! The session state machine of one connection: the Start/Stop procedure, the
//! TESTFR keep-alive and the reaction to protocol errors, from
//! IEC 60870-5-104:2006 clauses 5.1 to 5.3.
//!
//! This is a pure state machine: it never touches a socket, a clock or the
//! codec. The caller feeds it parsed control fields ([`Apci`]) and timer
//! expiries, and performs the returned [`Action`]s. That keeps the whole
//! handshake testable without a network.
//!
//! # Start and stop (clause 5.3)
//!
//! The transitions come from clause 5.3 and its state diagrams, figure 17
//! (controlled station, printed page 41) and figure 18 (controlling station,
//! printed page 43). The prose rules the diagrams encode:
//!
//! - "When the connection is established, user data transfer is not
//!   automatically enabled from the controlled station on that connection, i.e.
//!   STOPDT is the default state when a connection is established." So a fresh
//!   session is [`State::Stopped`].
//! - "The controlling station must activate the user data transfer on a
//!   connection by sending a STARTDT act via this connection. The controlled
//!   station responds to this command with a STARTDT con."
//! - "If the STARTDT is not confirmed, the connection is closed by the
//!   controlling station." This is the t1 reaction, [`State::Terminated`].
//! - "Any pending user data in the controlled station is sent only after the
//!   STARTDT con."
//! - "The controlling station may send commands or setpoints even if it has not
//!   yet received the activation confirmation." This is why the controlling
//!   station's [`Session::user_data_allowed`] is already true in
//!   `PendingStarted`.
//! - "STOPDT act stops the transmission of I-frames immediately."
//! - "The controlling station should, however, confirm all received messages
//!   before sending STOPDT act, and the controlled station should confirm all
//!   received messages before returning STOPDT con."
//!
//! Figure 18, the controlling station, box by box:
//!
//! | Box | Arrow | Target |
//! | --- | --- | --- |
//! | `STOPPED connection` | `U-frame[]/` | itself |
//! | | `Start connection[]/Send STARTDT act` | `Pending STARTED` |
//! | | `Timeout t1[]/Active close or S-frame[]/Active close or I-frame[]/Active close` | `Connection terminated` |
//! | `Pending STARTED connection` | `U-frame[]/` | itself |
//! | | `STARTDT con[]/` | `STARTED` |
//! | | `Timeout t1[]/Active close or S-frame[]/Active close or I-frame[]/Active close` | `Connection terminated` |
//! | `STARTED connection` | `U-frame[]/ or S-frame[]/ or I-frame[]/` | itself |
//! | | `Stop connection[no unconfirmed I-frames]/Send STOPDT act` | `Pending STOPPED` |
//! | | `Stop connection[unconfirmed I-frames]/Send STOPDT act` | `Pending UNCONFIRMED STOPPED` |
//! | | `Timeout t1[]/Active close` | `Connection terminated` |
//! | `Pending STOPPED connection` | `U-frame[]/ or S-frame[]/ or I-frame[]/` | itself |
//! | | `STOPDT con[]/` | `STOPPED` |
//! | | `Timeout t1[]/Active close` | `Connection terminated` |
//! | `Pending UNCONFIRMED STOPPED connection` | `U-frame[]/ or S-frame[]/ or I-frame[]/` | itself |
//! | | `S-frame or I-frame [No unconfirmed I-frames]/` | `Pending STOPPED` |
//! | | `Timeout t1[]/Active close` | `Connection terminated` |
//!
//! Consequences the code follows:
//!
//! - **Data before STARTED closes.** Both figures leave `STOPPED` on
//!   `S-frame[]/Active close` and `I-frame[]/Active close`, and figure 18 gives
//!   `Pending STARTED` the same exits: before the STARTDT con, only U-frames
//!   belong on the connection
//!   (`tests/link.rs::a_controlling_station_closes_on_data_while_pending_started`).
//! - **The two pending stop states.** The controlling station enters
//!   `Pending UNCONFIRMED STOPPED` when its own I-frames are still outstanding,
//!   moves to `Pending STOPPED` once they are acknowledged, then waits for the
//!   STOPDT con. The controlled station (figure 17) has only the unconfirmed
//!   state, and leaves it by sending the STOPDT con. A controlling station in
//!   the unconfirmed state because it *received* the act (see "Where the
//!   standard is silent") leaves it the controlled station's way.
//! - **The figures are not symmetric.** An I-frame reaching a *controlling*
//!   station in a pending stop state is delivered and answered with an
//!   immediate S-frame. An I-frame reaching a *controlled* station in
//!   `PendingUnconfirmedStopped` closes the connection, because figure 17's box
//!   exits on `Timeout t1[]/Active close or I-frame[]/Active close` and has no
//!   I-frame self-loop.
//!
//! # Sequence numbers, acknowledgements and the k/w window
//!
//! The numbers live in [`crate::seq`], which implements clause 5.1 (V(S)/V(R),
//! acknowledgement by N(R), the send buffer) and clause 5.5 (k and w). This
//! machine drives it:
//!
//! - [`Session::send_i_frame`] stamps an outgoing I-frame, and refuses when data
//!   transfer is not enabled or the k window is full (clause 5.5: "The
//!   transmitter stops the transmission at k unacknowledged I format APDUs").
//! - A received I-frame is checked against V(R). A wrong N(S) is the sequence
//!   error of figure 11 and closes the connection.
//! - Reaching the w limit produces an S-frame, and [`Session::on_timeout`]
//!   answers t2 with the same S-frame (clause 9: t2 is the "Time-out for
//!   acknowledges in case of no data messages").
//! - An N(R), in an S-frame or on an I-frame, releases the send buffer up to
//!   that number (clause 5.1). When it empties the buffer, a pending stop moves
//!   on (figures 17/18).
//! - An N(R) outside `[oldest outstanding, V(S)]` (a frame never sent, or below
//!   the oldest frame still held) closes the connection. The standard names no
//!   reaction; closing is the answer figure 11 gives a bad N(S).
//! - t1 expiry is an active close (figures 17/18 `Timeout t1[]/Active close`;
//!   figure 12 draws the same reaction for a last, unacknowledged I format
//!   APDU). The standard defines no link-layer retransmission, so the session
//!   only closes; [`Session::retransmit`] exposes the send buffer for a caller
//!   that wants to replay it.
//!
//! # The pending user-data queue
//!
//! "Any pending user data in the controlled station is sent only after the
//! STARTDT con." The session owns that queue, because it is the only layer that
//! knows when the con went out:
//!
//! - [`Session::queue_i_frame`] holds an ASDU the application wants sent, and
//!   [`Session::pending_user_data`] reports how many are held.
//! - The queue is emitted oldest first, as far as the k window allows: after a
//!   STARTDT con goes out (a repeated STARTDT act included, since it is
//!   answered with another con), after the controlling station sends its own
//!   STARTDT act, and on every received acknowledgement, even one that released
//!   nothing. What does not fit the window stays queued; nothing is dropped.
//! - [`Session::flush_pending`] is that emission. It is public for a caller
//!   that queues into a session that is *already* allowed to send; the ordinary
//!   call there is [`Session::send_i_frame`], which queues nothing. A frame
//!   `send_i_frame` puts on the wire **overtakes** anything still queued, so a
//!   caller that mixes the two reorders its own data.
//! - A STOPDT does not clear the queue: the next STARTDT releases it (the con
//!   a controlled station sends, or the act a controlling station sends). The
//!   session clears the queue only with the connection, because clause 5.1
//!   restarts the sequence numbers at zero; a caller can still take it out
//!   with [`Session::take_pending_user_data`]. `queue_i_frame` refuses
//!   ([`QueueError::NotConnected`]) when there is no connection, and
//!   ([`QueueError::Full`]) beyond [`MAX_PENDING_USER_DATA`] ASDUs, so a peer
//!   that never sends STARTDT cannot make it grow without end.
//!
//! # The TESTFR keep-alive (clause 5.2, figures 13 and 14)
//!
//! Clause 5.2: "Unused, but open, connections may be periodically tested in
//! both directions by sending test APDUs (TESTFR = act) which are confirmed by
//! the receiving station sending TESTFR = con. Both stations may initiate the
//! test procedure after a specified period of time in which no data transfers
//! occur (time out). The reception of every frame – I frame, S frame or U
//! frame – retriggers timer t3. Station B has to supervise the connection
//! independently. However, as long as it receives test frames from station A,
//! it will not send test frames."
//!
//! - **Initiating.** [`crate::timers::Timers`] reports t3's expiry, and
//!   [`Session::on_timeout`] answers it with `TESTFR act` (figure 13: `Time-out
//!   t3` → `U (TESTFR act)`) and sets [`Session::test_pending`]. A further `T3`
//!   while that is true sends nothing: one t1 supervises one act (figure 14).
//! - **Not while the peer is testing.** Every received frame, a TESTFR act
//!   included, retriggers our t3, so a peer that keeps testing never lets our
//!   t3 expire. The scheduler's deadline does the suppressing
//!   (`tests/timers.rs::a_received_test_frame_keeps_our_own_idle_timer_alive`).
//! - **Answering.** Every received `TESTFR act` is answered with exactly one
//!   `TESTFR con`, in every live state including `Stopped`. A repeated act is
//!   the peer's t1 retransmission and is answered again. The caller arms t1 for
//!   an act it *sends*, never for the con it answers with.
//! - **The confirmation.** A `TESTFR con` ends the procedure and clears
//!   [`Session::test_pending`]. A con with no procedure in flight has no
//!   reaction in the standard and is ignored.
//! - **Figure 14's unconfirmed test** is t1 expiring over an act whose con
//!   never came, which `on_timeout(T1)` answers with `ActiveClose`.
//!
//! Only the reactions are here. When t0 to t3 are due is decided by
//! [`crate::timers::Timers`]. t0 has no reaction here, because the connection
//! attempt is the caller's socket.
//!
//! # Protocol errors in the APCI
//!
//! [`crate::apci::parse`] reports every malformed APCI as a typed
//! [`ParseError`], and [`crate::framed::Framed`] reports an illegal length field
//! from the same codec. [`reaction`] maps each to what the connection does, and
//! [`Session::on_parse_error`] applies it:
//!
//! | Parse error | Reaction | Justification |
//! | --- | --- | --- |
//! | `BadStart` | close | clause 5: "START 68H defines the point of start within the data stream"; on TCP, which neither loses nor reorders octets, another octet there means the peer is not speaking clause 5 (lib60870-C closes too) |
//! | `Incomplete` | none (wait for the promised length) | clause 5: the length field says how many octets follow |
//! | `BadLength` | active close | clause 5 bounds the field at 4…253 |
//! | `IFormatWithoutAsdu` | active close | clause 5: an I-format APDU always contains an ASDU |
//! | `BadSFormatOctet` | active close | clause 5, figure 7: S-format octets 1–2 are exactly `0x01 0x00` |
//! | `UnknownUFunction` | active close | clause 5, figure 8: six U functions, only one active |
//! | `ReservedOctetNotZero` | active close | clause 5, figures 6-8: the reserved control bits are zero |
//! | `FormatPayloadMismatch`, `AsduTooLong` | none (encoder only) | `Apdu::encode`'s own rejections; no peer can send them |
//!
//! The close rows are a decision, not a quotation: the standard names no
//! reaction for an APCI that violates clause 5. Figure 11 closes on a bad
//! sequence number and figures 17/18 close on data in `STOPPED`, and a frame
//! that cannot be decoded cannot be acknowledged either, so continuing would
//! only leave the peer's t1 to expire.
//!
//! # The S-frame before an active close
//!
//! Figures 10/11 NOTE, printed page 31: "To avoid retransmission of APDU's that
//! have already been accepted, an S-frame should, if possible, be sent prior to
//! the active close." Figure 11 draws it as `S(1) (optional)` just before
//! `Active close`. Every active close therefore emits the pending
//! acknowledgement first, through the same code that confirms received frames
//! before a stop completes. "If possible" means exactly when
//! [`Session::ack_pending`] is true. For a caller this means:
//!
//! - **`ack_pending` means "the peer has not been told".** An N(R) on an
//!   I-frame of ours acknowledges just as an S-frame does (clause 5.1), so a
//!   close right after one emits no S-frame. Two closes over the same accepted
//!   frames can therefore differ in shape.
//! - **The close is not always the last two actions.** An I-frame whose own
//!   N(R) fails the clause 5.1 check is still *accepted* first (delivered and
//!   confirmed), so its close is `[DeliverData, Send(S), ActiveClose]`: the
//!   application is handed an ASDU on a connection that closes in the same
//!   call.
//! - **[`Session::on_connection_lost`] emits no S-frame**, because the peer is
//!   gone. The acknowledgement obligation is cleared by
//!   `on_connection_established` when the sequence numbers restart (clause 5.1).
//!
//! # Where the standard is silent
//!
//! The standard describes STARTDT/STOPDT as the *controlling* station's command
//! over the monitor direction ("STARTDT (Start Data Transfer) and STOPDT (Stop
//! Data Transfer) are used by the controlling station (for example, Station
//! A), to control the data transfer from a controlled station") and never says
//! what a controlling station does when it *receives* STARTDT act or STOPDT
//! act. Figure 18 draws only `U-frame[]/` self-loops for that role, and a
//! generic U-frame self-loop cannot be the rule, since clause 5.2 requires a
//! received TESTFR act to be answered. Nor does figure 17 give its `Pending
//! UNCONFIRMED STOPPED` box an exit for a STARTDT act.
//!
//! TS 60870-5-604:2016 §5.3.2.70, its START/STOP checklist row for clause 5.3,
//! does not close the gap: its row "the controlled station explicitly disables
//! the transfer of I- and S-frames and the controlling station does not accept
//! I- or S-frames in a Pending Started connection, but only U-frames" is about
//! data frames, not about receiving the STARTDT/STOPDT U-frames. The rows it
//! does settle agree with this machine: I/S frames in a `Stopped` connection
//! are an active close, the controlled station may send U-, I- and S-frames
//! immediately after the STARTDT con, and "Send sequence number N(S) and
//! Receive Sequence number N(R) remain unchanged during the use of U-frames
//! with STARTDT / STOPDT indications" (the U-frames never touch
//! [`crate::seq`]).
//!
//! This machine acts on the function's defined effect rather than ignoring it,
//! and tests pin both choices:
//!
//! - A controlling station that receives STARTDT act confirms it. One that
//!   receives STOPDT act stops its own data transfer; it confirms at once when
//!   none of its I-frames is outstanding, and otherwise enters
//!   `PendingUnconfirmedStopped` and sends the con once they are acknowledged,
//!   as figure 17's controlled station does (the act's sender waits for it
//!   under t1). A STARTDT act arriving before that abandons the stop, as below
//!   (`tests/link.rs::a_controlling_station_confirms_a_received_stopdt_act_once_its_frames_are_acknowledged`).
//! - A controlled station that receives STARTDT act while a stop is pending
//!   confirms it and abandons the pending stop. The unconfirmed frames stay in
//!   the send buffer for the peer's N(R); only the STOPDT con obligation goes
//!   with the stop (`tests/link.rs::a_startdt_act_reverses_a_pending_stop`).

use crate::apci::{Apci, ParseError, SeqNo, UFunction};
use crate::params::{LinkParams, ParamError};
use crate::seq::{SentFrame, Sequence};
use std::collections::VecDeque;

/// Which side of the connection this session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Sends STARTDT act, owns the data transfer switch, sends commands.
    Controlling,
    /// Answers STARTDT/STOPDT, sends monitoring data once started.
    Controlled,
}

/// Connection state from the Start/Stop procedure.
///
/// The names follow figures 17 and 18; `PendingStarted` is figure 18's
/// `Pending STARTED`, where the controlling station has sent STARTDT act and
/// waits for the confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No data transfer on this connection (figures 17/18: `STOPPED`).
    Stopped,
    /// Controlling station: STARTDT act sent, confirmation outstanding.
    PendingStarted,
    /// Data transfer enabled on this connection.
    Started,
    /// Controlling station: STOPDT act sent, confirmation outstanding and no
    /// unconfirmed I-frames of ours.
    PendingStopped,
    /// STOPDT in progress with I-frames still unacknowledged.
    PendingUnconfirmedStopped,
    /// No longer exchanging data (figures 17/18: `Connection terminated`).
    Terminated,
}

/// Timer expiries the caller reports.
///
/// The *scheduling* of all four lives in [`crate::timers::Timers`]; this is what
/// it hands back and what [`Session::on_timeout`] reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Timer {
    /// Connection establishment timer (clause 9).
    T0,
    /// Timeout of a sent U-frame or I-frame that was not confirmed (figure 17/18
    /// note 2: "t1 is the timeout of a sent U-frame or I-frame").
    T1,
    /// Acknowledgement timeout (clause 9; figure 10 of clause 5.1).
    T2,
    /// Idle timeout, after which the station sends TESTFR act (clause 5.2).
    T3,
}

/// What the caller must do after feeding the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Put this control field on the wire (U- or S-format).
    Send(Apci),
    /// Put this I-format APDU on the wire: the control field is stamped with
    /// `ns`/`nr`, the payload is `asdu`. The session holds the same octets in its
    /// send buffer until `ns` comes back as an N(R) (clause 5.1).
    SendI {
        /// N(S) to stamp.
        ns: SeqNo,
        /// N(R) to stamp.
        nr: SeqNo,
        /// The ASDU the frame carries.
        asdu: Vec<u8>,
    },
    /// An I-format frame arrived and is to be handed to the application. The
    /// caller already holds the ASDU octets it passed in; only the sequence
    /// numbers are repeated here.
    DeliverData {
        /// The received frame's N(S).
        ns: SeqNo,
        /// The received frame's N(R).
        nr: SeqNo,
    },
    /// Active close, then active open if the application wants to reconnect.
    /// The string is the reason, for logging.
    ///
    /// Figures 10/11 NOTE: when frames were received and not yet confirmed, an
    /// `Action::Send(Apci::S { .. })` carrying their N(R) precedes this action.
    ActiveClose(&'static str),
}

/// Why user data was not accepted into the pending queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    /// There is no connection: none was established yet, or it has ended
    /// ([`State::Terminated`]). Establishing one clears the queue, so the frame
    /// is refused rather than silently held.
    NotConnected,
    /// The queue already holds [`MAX_PENDING_USER_DATA`] ASDUs. Clause 5.3
    /// holds the data until a STARTDT that a peer may never send, so the queue
    /// is bounded and the caller keeps the ASDU rather than having it dropped.
    Full,
}

/// The most ASDUs a connection's pending queue ([`Session::queue_i_frame`]) or
/// a redundancy group's held data takes before refusing with
/// [`QueueError::Full`].
///
/// 16384 ASDUs of at most 249 octets (clause 5, figure 4: APDU length 253
/// minus the APCI's four control octets) are about 4 MiB per connection:
/// far above any k window (at most 32767 frames in flight, typically 12), and
/// still a bound a peer that never sends STARTDT cannot push past.
pub const MAX_PENDING_USER_DATA: usize = 16_384;

/// What a connection does with one codec error: a row of the module doc's
/// reaction table, as a value the caller can inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseReaction {
    /// Not the connection's business: the framer buffers until the length
    /// field's frame has arrived. The session reports no action.
    Framing,
    /// The peer put an APCI on the wire that clause 5 does not allow (a control
    /// field or a length field outside the standard's rules). The connection is
    /// actively closed; the string is the reason for the log.
    Close(&'static str),
    /// Only `Apdu::encode` produces this, so no peer can send it. It is a
    /// caller bug; it says nothing about the connection and closes nothing.
    EncoderOnly,
}

/// The connection-level reaction to one codec error.
///
/// The table this implements is in the module doc, together with the clause
/// that justifies each row. [`Session::on_parse_error`] is the entry point.
#[must_use]
pub const fn reaction(err: ParseError) -> ParseReaction {
    match err {
        // Clause 5: "START 68H defines the point of start within the data
        // stream". TCP neither loses, corrupts nor reorders octets, so another
        // octet there is a peer not speaking clause 5, and skipping to the next
        // 68H would take the peer's following octets for frames.
        ParseError::BadStart(_) => ParseReaction::Close("start octet is not 68H"),
        // The framer owns this: a short buffer is simply waited on.
        ParseError::Incomplete { .. } => ParseReaction::Framing,
        // Clause 5's own bound: the length field is 4…253 octets.
        ParseError::BadLength(_) => ParseReaction::Close("length field outside 4..253"),
        // Clause 5: an I-format APDU always contains an ASDU.
        ParseError::IFormatWithoutAsdu(_) => ParseReaction::Close("I-format APDU without an ASDU"),
        // Clause 5, figure 7: octets 1 and 2 of an S-format APDU are exactly
        // 0x01 and 0x00.
        ParseError::BadSFormatOctet { .. } => {
            ParseReaction::Close("S-format control octets are not 0x01 0x00")
        }
        // Clause 5, figure 8: six U functions, and only one may be active.
        ParseError::UnknownUFunction(_) => ParseReaction::Close("unknown U-format function code"),
        // Clause 5, figures 7/8: the reserved control octets are zero.
        ParseError::ReservedOctetNotZero => {
            ParseReaction::Close("reserved control octets are not zero")
        }
        // Encoder-side only (`Apdu::encode`); the wire never carries them.
        ParseError::FormatPayloadMismatch(_) | ParseError::AsduTooLong(_) => {
            ParseReaction::EncoderOnly
        }
    }
}

/// The I/S/U session state machine.
#[derive(Debug)]
pub struct Session {
    role: Role,
    state: State,
    seq: Sequence,
    /// A TESTFR act of ours awaits its con (clause 5.2, figure 13). While this
    /// is true the session starts no second test procedure.
    test_pending: bool,
    /// User data the session could not put on the wire yet, oldest first
    /// (clause 5.3's pending user data). Cleared with the connection.
    pending: VecDeque<Vec<u8>>,
    /// Between [`Session::on_connection_established`] and the connection's
    /// end: `Stopped` alone does not say a TCP connection exists.
    connected: bool,
    /// A STOPDT act was *received* while I-frames of ours were outstanding, and
    /// its STOPDT con goes out once they are acknowledged (clause 5.3, figure
    /// 17). Distinguishes a controlling station answering the peer's act from
    /// one waiting for the con of its own act, since both are in
    /// `PendingUnconfirmedStopped`.
    stop_con_owed: bool,
}

impl Session {
    /// A session with the standard's default parameters (clause 9).
    #[must_use]
    pub fn new(role: Role) -> Self {
        Self {
            role,
            state: State::Stopped,
            seq: Sequence::new_unchecked(LinkParams::default()),
            test_pending: false,
            pending: VecDeque::new(),
            connected: false,
            stop_con_owed: false,
        }
    }

    /// A session with project-selected parameters (k, w, time-outs).
    ///
    /// The parameters are validated against clauses 5.5 and 9, because the
    /// sequence layer cannot work with a k or w of zero.
    ///
    /// # Errors
    ///
    /// The [`ParamError`] of [`LinkParams::validate`] for an inadmissible set.
    pub fn with_params(role: Role, params: LinkParams) -> Result<Self, ParamError> {
        params.validate()?;
        Ok(Self {
            role,
            state: State::Stopped,
            seq: Sequence::new_unchecked(params),
            test_pending: false,
            pending: VecDeque::new(),
            connected: false,
            stop_con_owed: false,
        })
    }

    /// Which side of the connection this session is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The current Start/Stop state.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// Whether a TCP connection is up: set by
    /// [`Session::on_connection_established`], cleared when the connection is
    /// lost or closed. A new session is [`State::Stopped`] but not connected.
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        self.connected
    }

    /// True while a `TESTFR act` of ours awaits its `TESTFR con` (clause 5.2,
    /// figure 13), the interval the caller supervises with t1 (figures 17/18
    /// NOTE 2). No second test procedure is started while this is true.
    #[must_use]
    pub const fn test_pending(&self) -> bool {
        self.test_pending
    }

    /// I-frames we sent that the peer has not acknowledged yet: the length of
    /// the clause 5.1 send buffer, limited by k.
    #[must_use]
    pub const fn outstanding_i_frames(&self) -> u16 {
        self.seq.outstanding()
    }

    /// The next N(S) an outgoing I-frame will carry.
    #[must_use]
    pub const fn v_s(&self) -> SeqNo {
        self.seq.v_s()
    }

    /// The N(R) an outgoing frame carries: every I-frame up to `v_r - 1` has
    /// been received correctly.
    #[must_use]
    pub const fn v_r(&self) -> SeqNo {
        self.seq.v_r()
    }

    /// True while another I-frame may be sent (data transfer enabled and the k
    /// window not full).
    #[must_use]
    pub fn can_send_i_frame(&self) -> bool {
        self.user_data_allowed() && self.seq.window_open()
    }

    /// True when an I-frame arrived after the last acknowledgement went out: the
    /// condition t2 exists for, and the "if possible" of figures 10/11's NOTE
    /// before a close.
    ///
    /// The acknowledgement that clears it may be an S-frame or the N(R) on an
    /// I-frame of ours (clause 5.1: "The receiving station acknowledges each
    /// APDU or a number of APDUs when it returns the Receive Sequence Number up
    /// to the number whose APDUs are properly received"). So "true" means "the
    /// peer has not been told about the APDUs we accepted", not "V(R) is ahead
    /// of the last S-frame we sent". A close with this flag false emits no
    /// S-frame.
    #[must_use]
    pub const fn ack_pending(&self) -> bool {
        self.seq.ack_pending()
    }

    /// The frames still held in the send buffer, oldest first.
    #[must_use]
    pub fn outstanding_frames(&self) -> &[SentFrame] {
        self.seq.outstanding_frames()
    }

    /// Stamps and buffers an outgoing I-frame.
    ///
    /// Returns the frame to put on the wire, or `None` when data transfer is not
    /// enabled in this state (clause 5.3) or the k window is full (clause 5.5).
    /// On `None` the application must queue the ASDU and retry after an
    /// acknowledgement.
    pub fn send_i_frame(&mut self, asdu: &[u8]) -> Option<Action> {
        if !self.can_send_i_frame() {
            return None;
        }
        let ns = self.seq.buffer_i_frame(asdu)?;
        Some(Action::SendI {
            ns,
            nr: self.seq.v_r(),
            asdu: asdu.to_vec(),
        })
    }

    /// Hands one monitoring-direction ASDU to the session to hold until the
    /// connection can carry it.
    ///
    /// Clause 5.3: "Any pending user data in the controlled station is sent only
    /// after the STARTDT con." Queued data is emitted by
    /// [`Session::flush_pending`] when the STARTDT con goes out, when the
    /// controlling station sends its own STARTDT act, and on every received
    /// acknowledgement, so a caller that hands data over while data transfer is
    /// inactive needs no further step.
    ///
    /// The queue holds at most [`MAX_PENDING_USER_DATA`] ASDUs; beyond that the
    /// ASDU is refused, never dropped for room. It is cleared with the
    /// connection, because the sequence numbers restart at zero (clause 5.1);
    /// see [`Session::on_connection_lost`].
    ///
    /// Returns [`QueueError::NotConnected`] when there is no connection (before
    /// the first [`Session::on_connection_established`] or after the
    /// connection's end), since establishing one would clear the queue anyway.
    ///
    /// # Errors
    ///
    /// [`QueueError::NotConnected`] when there is no connection, and
    /// [`QueueError::Full`] when the queue holds [`MAX_PENDING_USER_DATA`]
    /// ASDUs already.
    pub fn queue_i_frame(&mut self, asdu: &[u8]) -> Result<(), QueueError> {
        if !self.connected {
            return Err(QueueError::NotConnected);
        }
        if self.pending.len() >= MAX_PENDING_USER_DATA {
            return Err(QueueError::Full);
        }
        self.pending.push_back(asdu.to_vec());
        Ok(())
    }

    /// How many ASDUs are waiting for the connection to be allowed to carry them.
    #[must_use]
    pub fn pending_user_data(&self) -> usize {
        self.pending.len()
    }

    /// Takes every ASDU still waiting in the pending queue out of the session,
    /// oldest first, for a caller that moves it to another connection.
    ///
    /// This serves a redundancy group whose started connection changes (10.5:
    /// *"Care shall be taken that data are not lost during a connection
    /// switchover"*). None of it was on the wire, so no sequence number is
    /// involved.
    pub fn take_pending_user_data(&mut self) -> Vec<Vec<u8>> {
        self.pending.drain(..).collect()
    }

    /// Puts as much of the pending queue on the wire as the current state and
    /// the k window allow, oldest first, and returns the frames.
    ///
    /// The session calls this itself when data transfer becomes enabled
    /// (STARTDT con sent, STARTDT act sent) and on every received
    /// acknowledgement. A caller only needs it after queueing data into a
    /// session that is *already* allowed to send; [`Session::send_i_frame`] is
    /// the better call there, since it queues nothing.
    ///
    /// When the window is full the surplus stays queued; when the session is not
    /// allowed to send user data nothing moves at all.
    pub fn flush_pending(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        while self.can_send_i_frame() {
            let Some(asdu) = self.pending.pop_front() else {
                break;
            };
            if let Some(action) = self.send_i_frame(&asdu) {
                actions.push(action);
            } else {
                // Not reached, because the loop guard is `send_i_frame`'s guard.
                // Held back rather than dropped, because losing application
                // data to a bookkeeping mismatch is the worse failure.
                self.pending.push_front(asdu);
                break;
            }
        }
        actions
    }

    /// Replays every frame still held in the send buffer, oldest first, without
    /// touching the counters.
    ///
    /// IEC 60870-5-104 defines no retransmission at the link layer: figure 12
    /// answers an unacknowledged last I format APDU with an active close, and
    /// `on_timeout(T1)` does exactly that. This is for a caller that wants a
    /// project-level replay before closing.
    #[must_use]
    pub fn retransmit(&self) -> Vec<Action> {
        let nr = self.seq.v_r();
        self.seq
            .outstanding_frames()
            .iter()
            .map(|f| Action::SendI {
                ns: f.ns,
                nr,
                asdu: f.asdu.clone(),
            })
            .collect()
    }

    /// A TCP connection came up. Clause 5.3: STOPDT is the default state, and
    /// clause 5.1: the sequence numbers restart at zero.
    ///
    /// The pending user-data queue is cleared with it: a frame queued on the
    /// previous connection carries a place in the previous numbering, so the
    /// application supplies its data again rather than the session carrying it
    /// across.
    pub fn on_connection_established(&mut self) -> Vec<Action> {
        self.state = State::Stopped;
        self.connected = true;
        self.seq.reset();
        self.test_pending = false;
        self.stop_con_owed = false;
        self.pending.clear();
        Vec::new()
    }

    /// The TCP connection went away. Everything tied to it is dropped: the test
    /// procedure and the pending user-data queue ([`Session::queue_i_frame`]).
    ///
    /// Unlike [`Session::close`] this emits nothing: the peer is gone, so there
    /// is nobody to confirm anything to. The counters and the acknowledgement
    /// obligation stay as they are until [`Session::on_connection_established`]
    /// restarts them at zero (clause 5.1: "After the establishment of a TCP
    /// connection, the send and receive sequence numbers are set to zero"). A
    /// caller that reconnects must therefore call both, in that order.
    pub fn on_connection_lost(&mut self) -> Vec<Action> {
        self.terminate();
        Vec::new()
    }

    /// The application wants data transfer on this connection (controlling
    /// station only; the controlled station is told to start).
    pub fn request_start(&mut self) -> Vec<Action> {
        match (self.role, self.state) {
            (Role::Controlling, State::Stopped) => {
                self.state = State::PendingStarted;
                let mut actions = vec![Action::Send(Apci::U(UFunction::StartDtAct))];
                // Clause 5.3: "The controlling station may send commands or
                // setpoints even if it has not yet received the activation
                // confirmation", so its own queue goes out behind the act.
                actions.extend(self.flush_pending());
                actions
            }
            _ => Vec::new(),
        }
    }

    /// The application wants to stop data transfer on this connection
    /// (controlling station only).
    ///
    /// Clause 5.3: the controlling station confirms the messages it received
    /// before sending STOPDT act, and the action stops its own I-frame
    /// transmission immediately.
    pub fn request_stop(&mut self) -> Vec<Action> {
        match (self.role, self.state) {
            (Role::Controlling, State::Started) => {
                self.state = if self.outstanding_i_frames() == 0 {
                    State::PendingStopped
                } else {
                    State::PendingUnconfirmedStopped
                };
                let mut actions = self.confirm_received();
                actions.push(Action::Send(Apci::U(UFunction::StopDtAct)));
                actions
            }
            _ => Vec::new(),
        }
    }

    /// True in the states in which received I-frames are acknowledged: the
    /// started state and the two pending stopped states, where clause 5.3
    /// requires the station to confirm what it received before completing the
    /// stop. Before STARTDT an I-frame closes the connection instead.
    const fn user_data_acknowledgeable(&self) -> bool {
        matches!(
            self.state,
            State::Started | State::PendingStopped | State::PendingUnconfirmedStopped
        )
    }

    /// The S-frame clause 5.3 requires before a stop is completed, when frames
    /// were received and not yet confirmed. Every active close emits it too
    /// (figures 10/11 NOTE).
    ///
    /// "The controlling station should, however, confirm all received messages
    /// before sending STOPDT act, and the controlled station should confirm all
    /// received messages before returning STOPDT con", and "If unconfirmed
    /// messages exist in the controlling station, the controlled station must
    /// confirm these messages by sending an S-frame before sending out the
    /// STOPDT con."
    fn confirm_received(&mut self) -> Vec<Action> {
        if self.seq.ack_pending() {
            vec![Action::Send(Apci::S {
                nr: self.seq.acknowledge_all(),
            })]
        } else {
            Vec::new()
        }
    }

    /// Feeds one received control field.
    pub fn on_frame(&mut self, apci: Apci) -> Vec<Action> {
        if self.state == State::Terminated {
            return Vec::new();
        }
        match apci {
            Apci::U(func) => self.on_u_frame(func),
            Apci::S { nr } => self.on_s_frame(nr),
            Apci::I { ns, nr } => self.on_i_frame(ns, nr),
        }
    }

    /// Feeds a parse error the codec reported.
    ///
    /// The reaction is [`reaction`]'s; the table with its clause citations is in
    /// the module doc. An incomplete frame and encoder-only errors produce no
    /// action. A missing start octet or an APCI that violates clause 5 closes
    /// the connection, with the pending acknowledgement first.
    pub fn on_parse_error(&mut self, err: ParseError) -> Vec<Action> {
        match reaction(err) {
            ParseReaction::Close(why) => {
                if self.state == State::Terminated {
                    return Vec::new();
                }
                self.active_close(why)
            }
            ParseReaction::Framing | ParseReaction::EncoderOnly => Vec::new(),
        }
    }

    /// Reports a timer expiry.
    ///
    /// Only the reactions are here; when each timer becomes due is
    /// [`crate::timers::Timers`].
    pub fn on_timeout(&mut self, timer: Timer) -> Vec<Action> {
        match timer {
            // Figures 17/18 show `Timeout t1[]/Active close` from every live
            // state, and figure 12 draws the same reaction for a last,
            // unacknowledged I format APDU. As for every active close, the
            // pending acknowledgement goes first (figures 10/11 NOTE).
            Timer::T1 if self.state != State::Terminated => {
                self.active_close("t1 expired with no confirmation")
            }
            // t2 is the "Time-out for acknowledges in case of no data messages"
            // (clause 9): send the S-frame the w limit would have produced, if
            // anything was received since the last acknowledgement.
            Timer::T2 if self.user_data_acknowledgeable() && self.seq.ack_pending() => {
                vec![Action::Send(Apci::S {
                    nr: self.seq.acknowledge_all(),
                })]
            }
            // Clause 5.2, figure 13: `Time-out t3` → `U (TESTFR act)`. Only one
            // test procedure at a time: an act already sent is supervised by
            // t1, and a second act would run under the same single t1.
            Timer::T3 if self.state != State::Terminated && !self.test_pending => {
                self.test_pending = true;
                vec![Action::Send(Apci::U(UFunction::TestFrAct))]
            }
            _ => Vec::new(),
        }
    }

    /// May the application put user data (an I-frame) on this connection?
    ///
    /// Clause 5.3: the controlled station sends nothing but U-frames and
    /// confirmations until STARTDT con has gone out. The controlling station may
    /// send commands or setpoints before its activation confirmation arrives,
    /// but STOPDT act stops I-frame transmission immediately, in the pending
    /// stop states too.
    #[must_use]
    pub fn user_data_allowed(&self) -> bool {
        match self.role {
            Role::Controlled => self.state == State::Started,
            Role::Controlling => {
                matches!(self.state, State::PendingStarted | State::Started)
            }
        }
    }

    fn on_u_frame(&mut self, func: UFunction) -> Vec<Action> {
        match func {
            // Clause 5.2: TESTFR act is confirmed with TESTFR con in every live
            // state. A repeated act is answered too: swallowing it would leave
            // the peer's t1 to expire and close the connection.
            UFunction::TestFrAct => vec![Action::Send(Apci::U(UFunction::TestFrCon))],
            // Confirmation of a TESTFR act we sent: the procedure is over, so
            // the next idle interval may start a new one (figure 13).
            UFunction::TestFrCon => {
                self.test_pending = false;
                Vec::new()
            }

            UFunction::StartDtAct => {
                if self.role == Role::Controlled
                    && matches!(
                        self.state,
                        State::Stopped | State::PendingUnconfirmedStopped
                    )
                {
                    self.state = State::Started;
                } else if self.stop_con_owed {
                    // A controlling station told to start while it still owes
                    // the con of a received STOPDT act: the act reverses that
                    // stop as it does a controlled station's.
                    self.state = State::Started;
                }
                self.stop_con_owed = false;
                let mut actions = vec![Action::Send(Apci::U(UFunction::StartDtCon))];
                // Clause 5.3: "Any pending user data in the controlled station is
                // sent only after the STARTDT con." This is that moment.
                actions.extend(self.flush_pending());
                actions
            }

            UFunction::StopDtAct => {
                if self.outstanding_i_frames() == 0 {
                    self.state = State::Stopped;
                    let mut actions = self.confirm_received();
                    actions.push(Action::Send(Apci::U(UFunction::StopDtCon)));
                    actions
                } else {
                    // Figure 17: `STOPDT act[unconfirmed I-frames]`. The
                    // confirmation waits for our outstanding frames, in either
                    // role: the act's sender waits for it under t1.
                    self.state = State::PendingUnconfirmedStopped;
                    self.stop_con_owed = true;
                    Vec::new()
                }
            }

            UFunction::StartDtCon => {
                if self.role == Role::Controlling && self.state == State::PendingStarted {
                    self.state = State::Started;
                }
                Vec::new()
            }

            UFunction::StopDtCon => {
                if matches!(
                    self.state,
                    State::PendingStopped | State::PendingUnconfirmedStopped
                ) {
                    self.state = State::Stopped;
                    self.stop_con_owed = false;
                }
                Vec::new()
            }
        }
    }

    fn on_s_frame(&mut self, nr: SeqNo) -> Vec<Action> {
        match self.state {
            // Figures 17/18: `S-frame[]/Active close` out of STOPPED (and, in
            // figure 18, out of Pending STARTED). Before the STARTDT con only
            // U-frames belong on this connection.
            State::Stopped | State::PendingStarted => {
                self.active_close("S-frame received while data transfer is stopped")
            }
            // Otherwise it is an acknowledgement of our I-frames (clause 5.1).
            _ => self.on_acknowledgement(nr),
        }
    }

    /// Applies an N(R) from any frame and completes a pending stop when it
    /// acknowledges the last of our I-frames.
    fn on_acknowledgement(&mut self, nr: SeqNo) -> Vec<Action> {
        let had_outstanding = self.outstanding_i_frames() > 0;
        if self.seq.note_ack_received(nr).is_err() {
            return self.active_close("N(R) acknowledged an I-frame that was never sent");
        }
        let mut actions = Vec::new();
        if had_outstanding && self.outstanding_i_frames() == 0 {
            // The last of our frames is acknowledged. Figure 17: a station that
            // received STOPDT act with unconfirmed I-frames now sends the
            // confirmation (a controlling station too, when the act was the
            // peer's). Figure 18: a controlling station that sent the act
            // itself takes the `S-frame or I-frame [No unconfirmed I-frames]`
            // exit into the plain pending state and waits for STOPDT con.
            match (self.role, self.state) {
                (_, State::PendingUnconfirmedStopped) if self.stop_con_owed => {
                    self.state = State::Stopped;
                    self.stop_con_owed = false;
                    // Clause 5.3: received frames are confirmed before the con,
                    // as on the direct path.
                    actions.extend(self.confirm_received());
                    actions.push(Action::Send(Apci::U(UFunction::StopDtCon)));
                }
                (Role::Controlling, State::PendingUnconfirmedStopped) => {
                    self.state = State::PendingStopped;
                }
                _ => {}
            }
        }
        // Releasing frames reopens the clause 5.5 k window, so anything still
        // held for clause 5.3 goes out now. A no-op while nothing is queued or
        // data transfer is not enabled.
        actions.extend(self.flush_pending());
        actions
    }

    fn on_i_frame(&mut self, ns: SeqNo, nr: SeqNo) -> Vec<Action> {
        match self.state {
            State::Stopped | State::PendingStarted => {
                self.active_close("I-frame received while data transfer is stopped")
            }
            State::Started | State::PendingStopped | State::PendingUnconfirmedStopped => {
                // Figure 17's controlled-station `Pending UNCONFIRMED STOPPED
                // connection` box exits on "Timeout t1[]/Active close or
                // I-frame[]/Active close" and has no I-frame self-loop. Only
                // figure 18's controlling-station box has one, which is what
                // clause 5.3's "immediately send an S-frame upon receiving an
                // I-frame while in the Pending STOPPED state or Pending
                // UNCONFIRMED STOPPED state" is about.
                if self.role == Role::Controlled && self.state == State::PendingUnconfirmedStopped {
                    return self.active_close("I-frame received while pending unconfirmed stopped");
                }
                // Receive side first: N(S) must be the number we expect. Figure
                // 11 marks a wrong one a sequence error and closes the
                // connection.
                let Ok(ack_due) = self.seq.note_i_frame_received(ns) else {
                    return self.active_close("sequence error: unexpected N(S)");
                };
                let mut actions = vec![Action::DeliverData { ns, nr }];
                if matches!(
                    self.state,
                    State::PendingStopped | State::PendingUnconfirmedStopped
                ) {
                    // Stopping, but the peer may still send frames that were in
                    // flight: deliver them and confirm immediately (clause 5.3).
                    actions.push(Action::Send(Apci::S {
                        nr: self.seq.acknowledge_all(),
                    }));
                } else if let Some(after_w) = ack_due {
                    // Clause 5.5: the receiver acknowledges at the latest after
                    // receiving w I format APDUs.
                    actions.push(Action::Send(Apci::S { nr: after_w }));
                }
                // Finally the acknowledgement the peer sent us, which may complete
                // a pending stop.
                actions.extend(self.on_acknowledgement(nr));
                actions
            }
            State::Terminated => Vec::new(),
        }
    }

    /// Leaves the live set: no test procedure is in flight and nothing is held
    /// for a connection that is over. Every path out of the live states goes
    /// through here, so a flag or a queue cannot survive into the next
    /// connection.
    fn terminate(&mut self) {
        self.state = State::Terminated;
        self.connected = false;
        self.test_pending = false;
        self.stop_con_owed = false;
        self.pending.clear();
    }

    /// Closes the connection for the application's own reason.
    ///
    /// Emits the pending acknowledgement first when [`Session::ack_pending`] is
    /// true (figures 10/11 NOTE: "To avoid retransmission of APDU's that have
    /// already been accepted, an S-frame should, if possible, be sent prior to
    /// the active close."), then [`Action::ActiveClose`] carrying `why`, and
    /// leaves the session [`State::Terminated`]. Does nothing once it already
    /// is.
    pub fn close(&mut self, why: &'static str) -> Vec<Action> {
        if self.state == State::Terminated {
            return Vec::new();
        }
        self.active_close(why)
    }

    fn active_close(&mut self, why: &'static str) -> Vec<Action> {
        let mut actions = self.confirm_received();
        self.terminate();
        actions.push(Action::ActiveClose(why));
        actions
    }
}
