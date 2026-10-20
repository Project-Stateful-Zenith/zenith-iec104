//! The interoperability harness: one scripted scenario, driven twice.
//!
//! 104 defines no interoperability harness; what is standard here is the *wire
//! behaviour* of the scenario, and every assertion below cites the clause it
//! checks. The citations are IEC 60870-5-104:2006 unless another standard is
//! named, and the page indices are **PDF page indices** (0-based), with the
//! printed page in parentheses where it helps. The English text sits on the
//! even indices because the 2006 edition is bilingual.
//!
//! | Step | Clause | Index (printed) | What the clause gives |
//! | --- | --- | --- | --- |
//! | TCP connect | 104 cl.7.1 | 54 (53) | with a controlled station as the partner, the controlling station sets up the connection: this side opens the socket |
//! | no user data before STARTDT | 104 cl.5.3 | 38 (37) | the STARTDT/STOPDT U-procedure, figures 17/18: a fresh connection is `STOPPED` and carries no user data |
//! | STARTDT | 104 cl.5.3 | 38 (37) | `STARTDT act` → `STARTDT con`; the controlling station may send commands even before the con, the controlled station nothing |
//! | GI | 104 cl.7.5 | 64 (63) | the general-interrogation service table; the responses are the monitor ASDUs of cl.7.3.1 and the cycle closes with the termination of 5-101 cl.7.4.5 |
//! | spontaneous event | 104 cl.7.4 | 64 (63) | the acquisition-of-events service table, `M SPONT`, i.e. cause `<3>` |
//! | single command | 104 cl.7.7 | 68 (67) | the command-transmission service table; the mirror of 5-101 cl.7.4.7 with its `P/N` flag |
//! | TESTFR | 104 cl.5.2 + cl.5.1 | 34 (33) + 32 (31) | the test procedure, figures 13/14: `TESTFR act` → `con`, one procedure at a time; t2 expires first and puts the pending acknowledgement on the wire as an S-frame (figure 10 draws `Time-out t2 → S(3)`; figure 11's NOTE wants it before a close) |
//! | clean disconnect | 104 cl.7.1 + cl.5.1 + TS 60870-5-604 `5.4.13.20` | 56 (55) + 32 (31) + 59 (58) | the active-close row of cl.7.1's table, the acknowledgement that must precede it (figure 11's NOTE) and the 604 case for an active close on one connection. This scenario ends at the socket boundary, so an `Action::ActiveClose` would be the anomaly and an unacknowledged peer frame would too |
//!
//! # One scenario, two peers
//!
//! [`scenario`] is the step list and [`run`] drives it. Both entry points use
//! the same list: `tests/interop_mock.rs` runs it against the in-process
//! [`MockOutstation`], which needs no Python and no clock and is part of
//! `cargo test --all-features`; `tests/interop.rs` runs it against the real
//! peer, `c104` (iec104-python, GPLv3) started as an **external process**. No
//! code, table or vector is taken from `c104`: it is run, and its octets are
//! wire traffic.
//!
//! Nothing here is `src/`: the crate stays dependency-free with no socket, no
//! thread and no clock, and this harness is a driver around the crate's own
//! primitives: `link::Session` is the output vocabulary, `framed::Decoder`
//! splits the TCP byte stream, and every ASDU is built or decoded through the
//! layout layer.
//!
//! # The clock
//!
//! [`Station::now`] is a *synthetic* `Instant` that only [`Station::advance`]
//! moves. The crate reads no clock, so the t3 expiry of the test procedure is
//! reached by jumping this one forward, with no sleep. Real time appears only where
//! it cannot be avoided: a socket read timeout bounds every wait, so a peer that
//! stops talking fails the step instead of hanging the suite. The offline path
//! never waits at all: the mock answers every frame it is sent, and the two
//! sides are driven step by step.
//!
//! This module is compiled into both interop test binaries; each entry point
//! uses only its half of it, so dead-code analysis is off for the whole file.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use iec104::apci::{Apci, Apdu, SeqNo, UFunction, parse as parse_apci};
use iec104::asdu::{
    Cause, Header, Known, LayoutObject, MMeNb1, MSpNa1, Qds, Qoc, Sco, Siq, Sva, TypeId,
    decode_asdu, encode_asdu,
};
use iec104::ct::{
    Command, CommandMode, CommandSet, CommandTransmission, CommandValue, Reaction as CtReaction,
    Termination,
};
use iec104::framed::Decoder;
use iec104::gi::{DataSource, Interrogation, ReActivation, Scope, SecondActivation};
use iec104::link::{Action, Role, Session, State, Timer};
use iec104::params::LinkParams;
use iec104::timers::Timers;

// ------------------------------------------------------------ the scenario

/// The common address of the simulated station (cl.7.2.4: a station address,
/// never the broadcast `FF`/`FFFF`).
pub const CA: u16 = 1;
/// Originator address the scenario's requests carry (cl.7.2.3).
pub const ORIGINATOR: u8 = 0;

/// The `M_ME_NB_1` the general interrogation returns (cl.7.3.1's measured value).
pub const IOA_GI: u32 = 0x1001;
/// Its scaled value, chosen so a decoding slip changes the assertion.
pub const GI_VALUE: i16 = 4242;
/// The `M_SP_NA_1` the peer reports spontaneously (cl.7.4, cause `<3>`).
pub const IOA_SPONT: u32 = 0x1002;
/// The `C_SC_NA_1` the peer accepts (cl.7.7, cause `<6>` → `<7>`).
pub const IOA_COMMAND: u32 = 0x2001;
/// The `C_SC_NA_1` the peer refuses, which is how the mirror's `P/N` bit is
/// exercised (TS 60870-5-604 5.4.19.30/.50, the negative `ACTCON`).
pub const IOA_REFUSED: u32 = 0x2002;

/// One step of the scripted scenario. The names say which wire exchange they
/// drive; each variant's body carries the clause citation it asserts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The controlling station opened the socket (cl.7.1, index 54) and the
    /// connection is `STOPPED` (cl.5.3).
    Connected,
    /// `STARTDT act` → `STARTDT con`, then `Started` (cl.5.3, index 38).
    StartDt,
    /// `C_IC ACT` → `ACTCON` → the interrogated objects → `ACTTERM` (cl.7.5,
    /// index 64).
    GeneralInterrogation,
    /// One `M SPONT` frame, cause `<3>` (cl.7.4, index 64).
    SpontaneousEvent,
    /// One accepted `C_SC_NA_1` and its positive mirror (cl.7.7, index 68).
    SingleCommand,
    /// One refused `C_SC_NA_1` and its mirror with `P/N = 1` (cl.7.7).
    NegativeCommand,
    /// t3 expiry → `TESTFR act` → `con`; the peer's own act answered exactly
    /// once; an unsolicited `TESTFR con` ignored (cl.5.2, index 34).
    TestProcedure,
    /// Every I-frame confirmed, then the socket closed and the session
    /// `Terminated`, with no `ActiveClose` raised (cl.7.1, index 56).
    CleanDisconnect,
}

/// The scripted scenario. Both peers run exactly this list.
pub fn scenario() -> Vec<Step> {
    vec![
        Step::Connected,
        Step::StartDt,
        Step::GeneralInterrogation,
        Step::SpontaneousEvent,
        Step::SingleCommand,
        Step::NegativeCommand,
        Step::TestProcedure,
        Step::CleanDisconnect,
    ]
}

/// A bounded read deadline. Every wait has an end, so a silent peer fails the
/// step rather than hanging the suite.
pub fn deadline(secs: u64) -> Instant {
    Instant::now() + Duration::from_secs(secs)
}

// ------------------------------------------------------------- the driver

/// The controlling station: a `TcpStream`, a [`Decoder`], a [`Session`] and a
/// [`Timers`], plus the record of what went on the wire in each direction.
///
/// It turns [`Action`]s into bytes and bytes into `Session` calls; it invents
/// no protocol behaviour. `sent` / `received` hold the encoded APDUs in order,
/// which is what the c104 entry point cross-checks against the peer's own
/// capture.
#[derive(Debug)]
pub struct Station {
    stream: TcpStream,
    session: Session,
    timers: Timers,
    /// The synthetic clock the session's time-outs are measured on.
    now: Instant,
    decoder: Decoder,
    /// Every APDU this side put on the wire, in order.
    pub sent: Vec<Vec<u8>>,
    /// Every APDU this side read from the wire, in order.
    pub received: Vec<Vec<u8>>,
    /// The U-functions the peer sent, in order.
    pub peer_u: Vec<UFunction>,
    /// The reasons of every `ActiveClose` the session raised.
    pub closes: Vec<&'static str>,
    /// The actions the last received frame produced, so a step can assert on
    /// them (`DeliverData` for an I-frame, cl.5.1's acknowledgement, …).
    pub last_actions: Vec<Action>,
    /// ASDUs an earlier step read and did not consume, each with the verdict
    /// that frame's *own* actions carried: `true` when the session handed it to
    /// the application as `Action::DeliverData` (cl.5.1).
    pub stashed: VecDeque<(Vec<u8>, bool)>,
}

impl Station {
    /// Opens the TCP connection (cl.7.1, index 54: the controlling station is
    /// the one that performs the active open) and puts the session on it.
    pub fn connect(addr: SocketAddr) -> Result<Self, String> {
        let stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("nodelay: {e}"))?;
        let mut session = Session::new(Role::Controlling);
        let mut timers =
            Timers::new(LinkParams::default()).map_err(|e| format!("link parameters: {e:?}"))?;
        let now = Instant::now();
        session.on_connection_established();
        timers.connection_established(now);
        Ok(Self {
            stream,
            session,
            timers,
            now,
            decoder: Decoder::new(),
            sent: Vec::new(),
            received: Vec::new(),
            peer_u: Vec::new(),
            closes: Vec::new(),
            last_actions: Vec::new(),
            stashed: VecDeque::new(),
        })
    }

    /// The session driven by this station.
    pub const fn session(&self) -> &Session {
        &self.session
    }

    /// The session, for a step that calls it directly.
    pub const fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// The timer scheduler, for a step that clears a timer itself.
    pub const fn timers_mut(&mut self) -> &mut Timers {
        &mut self.timers
    }

    /// The synthetic clock's current reading.
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// Moves the synthetic clock forward. Nothing sleeps.
    pub fn advance(&mut self, by: Duration) {
        self.now += by;
    }

    /// Puts the session's actions on the wire (or records the close).
    pub fn send_actions(&mut self, actions: &[Action]) -> Result<(), String> {
        for action in actions {
            match action {
                // A confirmation or an S-frame supervises nothing (clause 9's
                // t1 is the time-out for sent or test APDUs), so it is written
                // without arming t1.
                Action::Send(Apci::S { .. }) => {
                    let mut out = Vec::new();
                    encode_action(action, &mut out)?;
                    self.write(&out)?;
                    self.timers.acknowledgement_sent();
                }
                Action::Send(Apci::U(
                    UFunction::TestFrCon | UFunction::StartDtCon | UFunction::StopDtCon,
                )) => {
                    let mut out = Vec::new();
                    encode_action(action, &mut out)?;
                    self.write(&out)?;
                }
                Action::Send(_) | Action::SendI { .. } => {
                    let mut out = Vec::new();
                    encode_action(action, &mut out)?;
                    self.write(&out)?;
                    // Figures 17/18 NOTE 2: t1 supervises a sent U-frame or
                    // I-frame until it is confirmed.
                    self.timers.frame_sent(self.now);
                }
                Action::ActiveClose(why) => self.closes.push(why),
                Action::DeliverData { .. } => {}
            }
        }
        Ok(())
    }

    fn write(&mut self, octets: &[u8]) -> Result<(), String> {
        self.stream
            .write_all(octets)
            .map_err(|e| format!("write: {e}"))?;
        self.sent.push(octets.to_vec());
        Ok(())
    }

    /// Reads one APDU and feeds it to the session, sending whatever the session
    /// answers with. `Ok(None)` means the bounded read ran out.
    pub fn next(&mut self, limit: Instant) -> Result<Option<(Apci, Vec<u8>)>, String> {
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
                    self.take(apci, asdu.clone())?;
                    return Ok(Some((apci, asdu)));
                }
                Ok(None) => {}
                // A malformed length field: drop the offending octet and keep
                // looking, exactly as `Framed` does (cl.5: START defines the
                // point of start within the data stream).
                Err(_) => {
                    let _ = self.decoder.next_frame();
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
                Ok(0) => return Err("the peer closed the connection early".into()),
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

    /// Feeds one decoded frame to the session and answers it.
    fn take(&mut self, apci: Apci, _asdu: Vec<u8>) -> Result<(), String> {
        // Clause 5.2: any received frame, whether I, S or U, restarts t3.
        self.timers.frame_received(self.now);
        if apci.is_i_format() {
            // Clause 5.2's acknowledgement time-out starts at the first
            // unacknowledged I-frame.
            self.timers.i_frame_received(self.now);
        }
        if let Apci::U(function) = apci {
            self.peer_u.push(function);
        }
        let actions = self.session.on_frame(apci);
        self.last_actions.clone_from(&actions);
        // Nothing is left awaiting confirmation once the send buffer is empty
        // and no act of ours is outstanding, so t1 has nothing to supervise.
        if self.session.outstanding_i_frames() == 0
            && !self.session.test_pending()
            && self.session.state() != State::PendingStarted
        {
            self.timers.confirmation_received();
        }
        self.send_actions(&actions)
    }

    /// Reads frames until one matches `want`, failing when the deadline passes.
    /// The clause each caller asserts is in its step's doc.
    pub fn expect(
        &mut self,
        what: &str,
        limit: Instant,
        want: impl Fn(Apci, &[u8]) -> bool,
    ) -> Result<(Apci, Vec<u8>), String> {
        loop {
            match self.next(limit)? {
                Some((apci, asdu)) if want(apci, &asdu) => return Ok((apci, asdu)),
                Some((apci, asdu)) => {
                    if apci.is_i_format() {
                        let delivered = self.delivered();
                        self.stashed.push_back((asdu, delivered));
                    }
                    if Instant::now() >= limit {
                        return Err(format!("{what}: not seen before the deadline"));
                    }
                }
                None => return Err(format!("{what}: not seen before the deadline")),
            }
        }
    }

    /// Reports every timer that has come due and returns what the session made
    /// of each. Nothing is written by the caller's side of the clock.
    pub fn poll_timers(&mut self) -> Result<Vec<(Timer, Vec<Action>)>, String> {
        let due = self.timers.expired(self.now);
        let mut produced = Vec::new();
        for timer in due {
            let actions = self.session.on_timeout(timer);
            self.send_actions(&actions)?;
            produced.push((timer, actions));
        }
        Ok(produced)
    }

    /// Counts the frames of a given U-function this side put on the wire.
    pub fn sent_u_count(&self, function: UFunction) -> usize {
        self.sent
            .iter()
            .filter(|octets| matches!(wire_apci(octets), Some(Apci::U(f)) if f == function))
            .count()
    }

    /// Counts the frames of a given U-function the peer sent.
    pub fn peer_u_count(&self, function: UFunction) -> usize {
        self.peer_u.iter().filter(|f| **f == function).count()
    }

    /// The N(R) of the last frame this side put on the wire that carries one:
    /// an I-frame's piggybacked acknowledgement or an S-frame (cl.5.1).
    /// `None` before anything that acknowledges has gone out.
    pub fn last_acknowledged(&self) -> Option<SeqNo> {
        self.sent
            .iter()
            .rev()
            .find_map(|octets| match wire_apci(octets) {
                Some(Apci::I { nr, .. } | Apci::S { nr }) => Some(nr),
                _ => None,
            })
    }

    /// True when the last frame's own actions handed it to the application
    /// (cl.5.1's `DeliverData`).
    fn delivered(&self) -> bool {
        self.last_actions
            .iter()
            .any(|action| matches!(action, Action::DeliverData { .. }))
    }

    /// Closes the socket. The scenario ends here, at the transport boundary.
    pub fn close(&self) -> Result<(), String> {
        self.stream
            .shutdown(Shutdown::Both)
            .map_err(|e| format!("shutdown: {e}"))
    }
}

/// Encodes one action as the octets the wire carries (I- and S/U-format).
pub fn encode_action(action: &Action, out: &mut Vec<u8>) -> Result<(), String> {
    match action {
        Action::Send(apci) => Apdu {
            apci: *apci,
            asdu: &[],
        }
        .encode(out)
        .map_err(|e| format!("encode {apci:?}: {e:?}")),
        Action::SendI { ns, nr, asdu } => Apdu {
            apci: Apci::I { ns: *ns, nr: *nr },
            asdu,
        }
        .encode(out)
        .map_err(|e| format!("encode I({ns:?},{nr:?}): {e:?}")),
        Action::DeliverData { .. } | Action::ActiveClose(_) => Ok(()),
    }
}

/// One action as the octets the wire carries.
pub fn encode_action_bytes(action: &Action) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    encode_action(action, &mut out)?;
    Ok(out)
}

/// One whole APDU into its control field and its ASDU.
pub fn parse_frame(frame: &[u8]) -> Result<(Apci, Vec<u8>), String> {
    let (apdu, used) = parse_apci(frame).map_err(|e| format!("parse {frame:02x?}: {e:?}"))?;
    if used != frame.len() {
        return Err(format!(
            "a {} octet frame decoded as {used} octets",
            frame.len()
        ));
    }
    Ok((apdu.apci, apdu.asdu.to_vec()))
}

fn wire_apci(frame: &[u8]) -> Option<Apci> {
    parse_apci(frame).ok().map(|(apdu, _)| apdu.apci)
}

// ------------------------------------------------------------- the steps

/// Drives the whole scripted scenario.
pub fn run(mut station: Station, steps: &[Step]) -> Result<Station, String> {
    for step in steps {
        match step {
            Step::Connected => connected(&station)?,
            Step::StartDt => start_dt(&mut station)?,
            Step::GeneralInterrogation => general_interrogation(&mut station)?,
            Step::SpontaneousEvent => spontaneous_event(&mut station)?,
            Step::SingleCommand => single_command(&mut station)?,
            Step::NegativeCommand => negative_command(&mut station)?,
            Step::TestProcedure => test_procedure(&mut station)?,
            Step::CleanDisconnect => clean_disconnect(&mut station)?,
        }
    }
    Ok(station)
}

/// cl.7.1 (index 54) + cl.5.3 (index 38): the socket is open and the
/// connection is `STOPPED`.
///
/// "No user data before STARTDT" is asserted here on the session's own rule
/// (`user_data_allowed()` decides whether an I-frame may go out). The mock peer
/// asserts the wire half of it, which a session rule cannot see: the
/// `MockReport` counts the I-frames this station sent before the peer reached
/// `Started`, and it must be zero.
fn connected(station: &Station) -> Result<(), String> {
    if station.session.state() != State::Stopped {
        return Err(format!(
            "cl.5.3: a fresh connection is STOPPED, not {:?}",
            station.session.state()
        ));
    }
    if station.session.user_data_allowed() {
        return Err("cl.5.3: no user data may move before STARTDT".into());
    }
    if station.session.outstanding_i_frames() != 0 {
        return Err("cl.5.1: a fresh connection starts at V(S) = 0".into());
    }
    Ok(())
}

/// cl.5.3 (index 38): the controlling station's `STARTDT act`, the peer's
/// `STARTDT con`, and `Started` with user data allowed.
fn start_dt(station: &mut Station) -> Result<(), String> {
    let actions = station.session_mut().request_start();
    if actions != vec![Action::Send(Apci::U(UFunction::StartDtAct))] {
        return Err(format!("cl.5.3: STARTDT act expected, got {actions:?}"));
    }
    station.send_actions(&actions)?;
    if station.session().state() != State::PendingStarted {
        return Err("cl.5.3: STARTDT act sent, so STARTED is pending".into());
    }
    let (apci, _) = station.expect("STARTDT con", deadline(5), |apci, _| {
        apci == Apci::U(UFunction::StartDtCon)
    })?;
    if apci != Apci::U(UFunction::StartDtCon) {
        return Err(format!("cl.5.3: STARTDT con expected, got {apci:?}"));
    }
    if station.session().state() != State::Started {
        return Err(format!(
            "cl.5.3: the con moves the connection to STARTED, not {:?}",
            station.session().state()
        ));
    }
    // The con is answered with nothing further: no acknowledgement of our
    // own, no test procedure (cl.5.3, figure 17).
    if !station.last_actions.is_empty() {
        return Err(format!(
            "cl.5.3: the STARTDT con is answered by {:?}",
            station.last_actions
        ));
    }
    if !station.session().user_data_allowed() {
        return Err("cl.5.3: data transfer is enabled by the con".into());
    }
    Ok(())
}

/// cl.7.5 (index 64) with 5-101 cl.7.4.5: `C_IC ACT` → `ACTCON` → the
/// interrogated monitor ASDUs of cl.7.3.1 → `ACTTERM`, every answer decoded and
/// asserted, and the cycle closing at the termination.
fn general_interrogation(station: &mut Station) -> Result<(), String> {
    use iec104::gi::Reaction as GiReaction;

    let mut interrogation = Interrogation::controlling(SecondActivation::Locked, CA, ORIGINATOR);
    let request = interrogation
        .request(Scope::Station)
        .map_err(|e| format!("cl.7.5: the GI request: {e:?}"))?;
    assert_request(&request, Scope::Station, Cause::Activation, false)?;
    send_i_frame(station, &request)?;

    let mut objects = 0usize;
    let mut saw_measured = false;
    let limit = deadline(5);
    let mut terminated = false;
    while !terminated {
        let (apci, asdu) = station
            .next(limit)?
            .ok_or("cl.7.5: no answer to the general interrogation")?;
        if !apci.is_i_format() {
            continue;
        }
        let header = Header::parse(&asdu).map_err(|e| format!("ASDU header: {e:?}"))?;
        match (header.type_id, header.cause) {
            (TypeId::CIcNa1, Cause::ActivationCon) => {
                assert_request(&asdu, Scope::Station, Cause::ActivationCon, false)?;
                let outcome = interrogation
                    .on_response(&asdu, &Known::EVERYTHING)
                    .map_err(|e| format!("cl.7.5: the confirmation: {e:?}"))?;
                match outcome.reaction {
                    GiReaction::ActivationConfirmed { scope, negative } => {
                        if scope != Scope::Station || negative {
                            return Err(format!("cl.7.5: {outcome:?}"));
                        }
                    }
                    other => return Err(format!("cl.7.5: the confirmation is {other:?}")),
                }
            }
            (TypeId::CIcNa1, Cause::ActivationTermination) => {
                assert_request(&asdu, Scope::Station, Cause::ActivationTermination, false)?;
                let outcome = interrogation
                    .on_response(&asdu, &Known::EVERYTHING)
                    .map_err(|e| format!("cl.7.5: the termination: {e:?}"))?;
                if outcome.reaction
                    != (GiReaction::Terminated {
                        scope: Scope::Station,
                    })
                {
                    return Err(format!("cl.7.5: the termination is {:?}", outcome.reaction));
                }
                terminated = true;
            }
            (TypeId::CIcNa1, other) => {
                return Err(format!("cl.7.5: a C_IC_NA_1 with cause {other:?}"));
            }
            (type_id, Cause::InterrogatedByStation) => {
                // cl.7.3.1: the response objects, carrying the scope's cause 20.
                if !iec104::gi::is_interrogated(type_id) {
                    return Err(format!(
                        "cl.7.3.1/7.5: type {type_id:?} is not an interrogated type"
                    ));
                }
                objects += 1;
                if type_id == TypeId::MMeNb1 {
                    let values = decode_asdu::<MMeNb1>(&asdu)
                        .map_err(|e| format!("cl.7.3.1: M_ME_NB_1: {e:?}"))?;
                    if values.len() != 1 || values[0].ioa != IOA_GI {
                        return Err(format!("cl.7.5: the measured value is {values:?}"));
                    }
                    if values[0].value.sva.value != GI_VALUE {
                        return Err(format!(
                            "cl.7.3.1: SVA {} instead of {GI_VALUE}",
                            values[0].value.sva.value
                        ));
                    }
                    saw_measured = true;
                }
            }
            (_, Cause::Spontaneous) => {
                // The peer's spontaneous event may overtake the interrogation's
                // tail; it is kept, with what this frame's own actions made of
                // it, for the step that asserts it (cl.7.4).
                let delivered = station.delivered();
                station.stashed.push_back((asdu, delivered));
            }
            (type_id, cause) => {
                return Err(format!(
                    "cl.7.5: {type_id:?} with cause {cause:?} is not part of the cycle"
                ));
            }
        }
    }
    if objects == 0 {
        return Err("cl.7.5: the interrogation returned no object".into());
    }
    if !saw_measured {
        return Err(format!(
            "cl.7.5: no M_ME_NB_1 at IOA 0x{IOA_GI:04X} came back"
        ));
    }
    if !interrogation.running().is_empty() {
        return Err("cl.7.5/5-101 cl.7.4.5: the cycle closes at the termination".into());
    }
    Ok(())
}

/// Asserts a `C_IC_NA_1` frame: type, cause, `P/N`, the irrelevant address and
/// the scope's own `QOI` (cl.7.2.6.22, index 53; figure 72).
fn assert_request(asdu: &[u8], scope: Scope, cause: Cause, negative: bool) -> Result<(), String> {
    let header = Header::parse(asdu).map_err(|e| format!("ASDU header: {e:?}"))?;
    if header.type_id != TypeId::CIcNa1
        || header.cause != cause
        || header.negative != negative
        || header.common_address != CA
        || header.sequence
        || header.count != 1
    {
        return Err(format!("cl.7.5: the C_IC_NA_1 header is {header:?}"));
    }
    let objects = decode_asdu::<iec104::asdu::CIcNa1>(asdu)
        .map_err(|e| format!("cl.7.3.4.1: C_IC_NA_1: {e:?}"))?;
    if objects.len() != 1 || objects[0].ioa != iec104::asdu::IOA_IRRELEVANT {
        return Err(format!("cl.7.2.5: the GI's address is {objects:?}"));
    }
    if objects[0].value.qoi != scope.qoi() {
        return Err(format!(
            "cl.7.2.6.22: QOI {:?} instead of {:?}",
            objects[0].value.qoi,
            scope.qoi()
        ));
    }
    Ok(())
}

/// cl.7.4 (index 64): one monitor ASDU with cause `<3>` (`A_EVENT.req`,
/// `M SPONT`), handed up as `Action::DeliverData` and decoded.
fn spontaneous_event(station: &mut Station) -> Result<(), String> {
    let limit = deadline(5);
    let (asdu, delivered) = loop {
        if let Some((asdu, delivered)) = station.stashed.pop_front() {
            if matches!(
                Header::parse(&asdu).map(|h| h.cause),
                Ok(Cause::Spontaneous)
            ) {
                break (asdu, delivered);
            }
            continue;
        }
        let (apci, asdu) = station
            .next(limit)?
            .ok_or("cl.7.4: no spontaneous ASDU arrived")?;
        if !apci.is_i_format() {
            continue;
        }
        if matches!(
            Header::parse(&asdu).map(|h| h.cause),
            Ok(Cause::Spontaneous)
        ) {
            let delivered = station.delivered();
            break (asdu, delivered);
        }
    };
    let header = Header::parse(&asdu).map_err(|e| format!("ASDU header: {e:?}"))?;
    if header.type_id != TypeId::MSpNa1 {
        return Err(format!("cl.7.4: M_SP_NA_1 expected, got {header:?}"));
    }
    if header.cause != Cause::Spontaneous || header.negative || header.common_address != CA {
        return Err(format!("cl.7.4: the header is {header:?}"));
    }
    let objects =
        decode_asdu::<MSpNa1>(&asdu).map_err(|e| format!("cl.7.3.1.1: M_SP_NA_1: {e:?}"))?;
    if objects.len() != 1 || objects[0].ioa != IOA_SPONT {
        return Err(format!("cl.7.2.5: the IOA is {objects:?}"));
    }
    if !objects[0].value.siq.spi {
        return Err("cl.7.2.6.1: SPI should be ON".into());
    }
    // cl.5.1: *this* frame, not whichever frame happened to be read last, was
    // handed to the application as `DeliverData`. A stashed event carries the
    // verdict of its own receipt, because `station.last_actions` belongs to the
    // last frame the driver read (the event may have overtaken the GI tail).
    if !delivered {
        return Err("cl.5.1: the spontaneous I-frame was not handed up as DeliverData".into());
    }
    Ok(())
}

/// cl.7.7 (index 68): an accepted `C_SC_NA_1` activation (`act`, cause `<6>`)
/// and the peer's positive mirror, told apart from the negative one by `ct`'s
/// own classification.
fn single_command(station: &mut Station) -> Result<(), String> {
    let mut transmission = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORIGINATOR,
    );
    let command = Command::new(
        IOA_COMMAND,
        CommandValue::Single {
            sco: Sco {
                scs: true,
                qoc: Qoc {
                    qu: 0,
                    select: false,
                },
            },
        },
    );
    let activation = transmission
        .execute(&command)
        .map_err(|e| format!("cl.7.7: the execute: {e:?}"))?;
    assert_command(&activation, IOA_COMMAND, Cause::Activation, false)?;
    send_i_frame(station, &activation)?;

    match command_answer(station, &mut transmission, IOA_COMMAND, false)? {
        CtReaction::Confirmed {
            ioa,
            select,
            negative,
            ..
        } => {
            if ioa != IOA_COMMAND || select || negative {
                return Err(format!(
                    "cl.7.4.7: the mirror is {ioa} select={select} neg={negative}"
                ));
            }
        }
        other => return Err(format!("cl.7.7: the positive mirror is {other:?}")),
    }
    Ok(())
}

/// cl.7.7 + TS 60870-5-604 5.4.19.30/.50: a refused `C_SC_NA_1`, answered with
/// the same command and `P/N = 1`.
fn negative_command(station: &mut Station) -> Result<(), String> {
    let mut transmission = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORIGINATOR,
    );
    let command = Command::new(
        IOA_REFUSED,
        CommandValue::Single {
            sco: Sco {
                scs: true,
                qoc: Qoc {
                    qu: 0,
                    select: false,
                },
            },
        },
    );
    let activation = transmission
        .execute(&command)
        .map_err(|e| format!("cl.7.7: the execute: {e:?}"))?;
    assert_command(&activation, IOA_REFUSED, Cause::Activation, false)?;
    send_i_frame(station, &activation)?;

    match command_answer(station, &mut transmission, IOA_REFUSED, true)? {
        CtReaction::Confirmed {
            ioa,
            select,
            negative,
            ..
        } => {
            if ioa != IOA_REFUSED || select || !negative {
                return Err(format!(
                    "5.4.19.30: the refusal's P/N is {negative} (ioa {ioa}, select {select})"
                ));
            }
        }
        other => return Err(format!("5.4.19.30: the negative mirror is {other:?}")),
    }
    Ok(())
}

/// Reads the peer's answer to one command until a confirmation (cause 7) for
/// `ioa` has been classified, then lets a termination or a return information
/// follow if the peer sends one.
fn command_answer(
    station: &mut Station,
    transmission: &mut CommandTransmission,
    ioa: u32,
    negative: bool,
) -> Result<CtReaction, String> {
    let limit = deadline(5);
    let mut confirmed = None;
    while confirmed.is_none() {
        let (apci, asdu) = station
            .next(limit)?
            .ok_or("cl.7.7: no answer to the command")?;
        if !apci.is_i_format() {
            continue;
        }
        let header = Header::parse(&asdu).map_err(|e| format!("ASDU header: {e:?}"))?;
        if !iec104::ct::is_command_type(header.type_id) {
            continue;
        }
        let outcome = transmission
            .on_response(&asdu, &Known::EVERYTHING)
            .map_err(|e| format!("cl.7.7: the command answer: {e:?}"))?;
        match outcome.reaction {
            CtReaction::Confirmed {
                ioa: answered,
                select,
                negative: flag,
                ..
            } if answered == ioa && !select && flag == negative => {
                confirmed = Some(CtReaction::Confirmed {
                    ioa,
                    select,
                    negative: flag,
                    test: false,
                });
            }
            // A termination or a return information belongs to the same
            // exchange (5-101 cl.7.4.7; TS 60870-5-604 Table 19's RETURN_INF).
            CtReaction::Terminated { .. } | CtReaction::Returned { .. } => {}
            other => {
                return Err(format!(
                    "cl.7.7: an answer this command did not ask for: {other:?}"
                ));
            }
        }
    }
    Ok(confirmed.expect("set above"))
}

/// Asserts a command ASDU's header (cl.7.3.2's layouts, indices 96–105).
fn assert_command(asdu: &[u8], ioa: u32, cause: Cause, negative: bool) -> Result<(), String> {
    let header = Header::parse(asdu).map_err(|e| format!("ASDU header: {e:?}"))?;
    if header.type_id != TypeId::CScNa1
        || header.cause != cause
        || header.negative != negative
        || header.common_address != CA
        || header.count != 1
    {
        return Err(format!("cl.7.3.2.1: the C_SC_NA_1 header is {header:?}"));
    }
    let objects = decode_asdu::<iec104::asdu::CScNa1>(asdu)
        .map_err(|e| format!("cl.7.3.2.1: C_SC_NA_1: {e:?}"))?;
    if objects.len() != 1 || objects[0].ioa != ioa {
        return Err(format!(
            "cl.7.2.5: the IOA is {objects:?}, expected 0x{ioa:04X}"
        ));
    }
    Ok(())
}

/// cl.5.2 (index 34), figures 13/14: t2 expires and puts the pending
/// acknowledgement on the wire as an S-frame (cl.5.1, 104 index 32, the NOTE
/// under figure 11), then t3 expires and `TESTFR act` goes out; the peer's
/// `TESTFR con` closes that procedure; the peer's *own* act is answered with
/// exactly one con; an unsolicited con does nothing.
fn test_procedure(station: &mut Station) -> Result<(), String> {
    // Nothing of ours is unconfirmed (cl.5.1), so two timers are armed here:
    // t3, and t2. The first I-frame the peer sent armed t2 and nothing cleared
    // it: no S-frame has gone out, and the N(R) piggybacked on our own I-frames
    // only ever acknowledged up to the frame the peer had sent *then*.
    if station.session().outstanding_i_frames() != 0 || station.session().test_pending() {
        return Err("cl.5.2: a test procedure needs a quiet connection".into());
    }
    station.timers_mut().confirmation_received();
    if !station.session().ack_pending() {
        return Err("cl.5.1: the peer's last I-frames must still await acknowledgement".into());
    }

    // Clause 5.2: t3 is the idle time-out; t2 is 10 s (clause 9), so the jump
    // past 21 s expires both, in the scheduler's order t2 then t3.
    station.advance(Duration::from_secs(21));
    let produced = station.poll_timers()?;
    let ack = produced.iter().find(|(timer, _)| *timer == Timer::T2);
    let Some((_, actions)) = ack else {
        return Err(format!("cl.5.1: t2 did not expire: {produced:?}"));
    };
    let expected = vec![Action::Send(Apci::S {
        nr: station.session().v_r(),
    })];
    if actions != &expected {
        return Err(format!(
            "cl.5.1: t2 expires into {actions:?}, not {expected:?}"
        ));
    }
    let act = produced.iter().find(|(timer, _)| *timer == Timer::T3);
    let Some((_, actions)) = act else {
        return Err(format!("cl.5.2: t3 did not expire: {produced:?}"));
    };
    if actions != &vec![Action::Send(Apci::U(UFunction::TestFrAct))] {
        return Err(format!("figure 13: t3 expires into {actions:?}"));
    }
    if !station.session().test_pending() {
        return Err("cl.5.2: figure 13's act is supervised by t1".into());
    }

    station.expect("TESTFR con", deadline(5), |apci, _| {
        apci == Apci::U(UFunction::TestFrCon)
    })?;
    if station.session().test_pending() {
        return Err("cl.5.2: the con ends the test procedure".into());
    }

    // Figure 13/14: one procedure at a time. An unsolicited con changes
    // nothing: it is the answer to an act this station never sent.
    let unsolicited = station
        .session_mut()
        .on_frame(Apci::U(UFunction::TestFrCon));
    if !unsolicited.is_empty() {
        return Err(format!(
            "cl.5.2: an unsolicited con answers {unsolicited:?}"
        ));
    }

    // The other direction: the peer's own act, answered with exactly one con.
    let limit = deadline(10);
    while station.peer_u_count(UFunction::TestFrAct) == 0 {
        if station.next(limit)?.is_none() {
            return Err("cl.5.2: the peer sent no TESTFR act".into());
        }
    }
    if station.sent_u_count(UFunction::TestFrCon) != station.peer_u_count(UFunction::TestFrAct) {
        return Err(format!(
            "cl.5.2: {} acts answered with {} cons",
            station.peer_u_count(UFunction::TestFrAct),
            station.sent_u_count(UFunction::TestFrCon)
        ));
    }
    // The peer's act is answered, and nothing of ours is left running: an act
    // that arrives unsolicited starts no procedure of this station's own.
    if station.session().test_pending() {
        return Err("cl.5.2: the peer's act left a test procedure pending".into());
    }
    Ok(())
}

/// cl.7.1 (index 56) + TS 60870-5-604 `5.4.13.20` (index 59): every I-frame the
/// peer sent is acknowledged (cl.5.1, 104 index 32's NOTE under figure 11: an
/// S-frame before the close, so nothing is left for the peer to retransmit),
/// every I-frame this side sent is confirmed, the socket is closed, and the
/// session reaches `Terminated` without an `ActiveClose`.
fn clean_disconnect(station: &mut Station) -> Result<(), String> {
    if !station.closes.is_empty() {
        return Err(format!(
            "cl.7.1: an active close was raised: {:?}",
            station.closes
        ));
    }
    if station.session().outstanding_i_frames() != 0 {
        return Err(format!(
            "cl.5.1: {} unconfirmed I-frames in the send buffer",
            station.session().outstanding_i_frames()
        ));
    }
    // cl.5.1: the last N(R) this side put on the wire (piggybacked or in an
    // S-frame) is V(R), so every I-frame the peer sent is acknowledged.
    let sent_nr = station.last_acknowledged();
    if sent_nr != Some(station.session().v_r()) {
        return Err(format!(
            "cl.5.1: the peer's frames are unacknowledged at the close: \
             last N(R) {sent_nr:?}, V(R) {:?}",
            station.session().v_r()
        ));
    }
    station.close()?;
    let actions = station.session_mut().on_connection_lost();
    if !actions.is_empty() {
        return Err(format!(
            "cl.7.1: the socket closing is not a protocol close: {actions:?}"
        ));
    }
    if station.session().state() != State::Terminated {
        return Err(format!(
            "cl.7.1: on_connection_lost leaves {:?}",
            station.session().state()
        ));
    }
    Ok(())
}

/// Puts one ASDU into the session as an I-frame and writes it.
fn send_i_frame(station: &mut Station, asdu: &[u8]) -> Result<(), String> {
    let action = station
        .session_mut()
        .send_i_frame(asdu)
        .ok_or("cl.5.3: data transfer is not allowed in this state")?;
    station.send_actions(&[action])
}

// --------------------------------------------------------- the mock peer

/// What the mock outstation observed from the wire, for the offline test's
/// assertions about things a session rule cannot see.
#[derive(Debug, Default, Clone)]
pub struct MockReport {
    /// I-frames this station sent before the mock reached `Started`: cl.5.3's
    /// rule that the controlled station holds back pending user data until
    /// after the STARTDT con, read from the other side. Must be zero.
    pub peer_i_frames_before_start: usize,
    /// Frames the mock put on the wire, in order.
    pub sent: Vec<Vec<u8>>,
    /// Frames the mock read, in order.
    pub received: Vec<Vec<u8>>,
    /// The mock's own unconfirmed I-frames when it read EOF. cl.5.1: every
    /// I-frame the mock sent was acknowledged before the peer closed, so an
    /// S-frame (or a piggybacked N(R)) really did go out. Must be zero.
    pub outstanding_i_frames_at_eof: usize,
}

/// The mock outstation: a `TcpListener` on a loopback port, accepting one
/// connection and answering from the same primitives a real controlled station
/// uses ([`Session`], [`Interrogation::controlled`],
/// [`CommandTransmission::controlled`], [`DataSource`]).
///
/// It is a peer, not a copy of `src/`: it holds the station's process image and
/// nothing else, exactly as the crate's API says a caller should.
pub struct MockOutstation {
    addr: SocketAddr,
    handle: JoinHandle<Result<MockReport, String>>,
}

impl MockOutstation {
    /// Binds a loopback port and starts the accepting thread.
    pub fn start() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("local addr: {e}"))?;
        let handle = thread::spawn(move || match listener.accept() {
            Ok((stream, _)) => serve(stream),
            Err(e) => Err(format!("accept: {e}")),
        });
        Ok(Self { addr, handle })
    }

    /// The loopback address the mock listens on.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Waits for the thread. The thread ends when the client closes the socket.
    pub fn join(self) -> Result<MockReport, String> {
        self.handle
            .join()
            .map_err(|_| "the mock outstation panicked".to_string())?
    }
}

/// The station's process image: one measured value, returned for the station
/// scope (5-101 cl.7.4.5's data, built through the layout layer as a real
/// application would).
struct MockDevice;

impl DataSource for MockDevice {
    fn ready(&self, _scope: Scope) -> bool {
        true
    }

    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
        if scope == Scope::Station {
            out.push(measured(Cause::InterrogatedByStation, IOA_GI, GI_VALUE));
        }
    }
}

/// One `M_ME_NB_1` object at `ioa`, sent with `cause`.
fn measured(cause: Cause, ioa: u32, value: i16) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MMeNb1,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: ORIGINATOR,
        common_address: CA,
    };
    encode_asdu(
        &header,
        &[LayoutObject {
            ioa,
            value: MMeNb1 {
                sva: Sva { value },
                qds: Qds::default(),
            },
        }],
    )
    .expect("the layout builds the mock's measured value")
}

/// The mock's spontaneous event: `M_SP_NA_1` at [`IOA_SPONT`], ON, cause 3.
fn spontaneous() -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MSpNa1,
        sequence: false,
        count: 1,
        cause: Cause::Spontaneous,
        negative: false,
        test: false,
        originator: ORIGINATOR,
        common_address: CA,
    };
    encode_asdu(
        &header,
        &[LayoutObject {
            ioa: IOA_SPONT,
            value: MSpNa1 {
                siq: Siq {
                    spi: true,
                    ..Default::default()
                },
            },
        }],
    )
    .expect("the layout builds the mock's spontaneous event")
}

/// One scripted frame the mock owes the peer.
enum Scripted {
    /// An I-frame carrying this ASDU, stamped by the mock's own session.
    I(Vec<u8>),
    /// A U-frame the mock sends of its own accord (cl.5.2's act).
    U(UFunction),
}

/// Runs the mock outstation on one accepted connection until the peer closes it.
fn serve(mut stream: TcpStream) -> Result<MockReport, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    let mut report = MockReport::default();
    let mut session = Session::new(Role::Controlled);
    session.on_connection_established();
    let mut decoder = Decoder::new();
    let mut interrogation = Interrogation::controlled(ReActivation::Continue, CA, ORIGINATOR);
    let mut commands = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORIGINATOR,
    );
    let device = MockDevice;
    let mut scripted: VecDeque<Scripted> = VecDeque::new();

    loop {
        // Whatever the previous exchange left owing goes first, oldest first.
        if let Some(frame) = scripted.pop_front() {
            match frame {
                Scripted::U(function) => {
                    let mut octets = Vec::new();
                    encode_action(&Action::Send(Apci::U(function)), &mut octets)?;
                    stream
                        .write_all(&octets)
                        .map_err(|e| format!("write: {e}"))?;
                    report.sent.push(octets);
                }
                Scripted::I(asdu) => match session.send_i_frame(&asdu) {
                    Some(action) => {
                        let mut octets = Vec::new();
                        encode_action(&action, &mut octets)?;
                        stream
                            .write_all(&octets)
                            .map_err(|e| format!("write: {e}"))?;
                        report.sent.push(octets);
                    }
                    // The window is full; keep it for the next pass.
                    None => scripted.push_front(Scripted::I(asdu)),
                },
            }
            continue;
        }

        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(0) => {
                // cl.5.1: the peer closed; what the mock sent must be confirmed.
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
            if apci.is_i_format() && session.state() != State::Started {
                report.peer_i_frames_before_start += 1;
            }
            if apci.is_i_format() {
                answer(
                    &asdu,
                    &session,
                    &mut interrogation,
                    &mut commands,
                    &device,
                    &mut scripted,
                )?;
            }
            let actions = session.on_frame(apci);
            for action in &actions {
                let mut octets = Vec::new();
                encode_action(action, &mut octets)?;
                stream
                    .write_all(&octets)
                    .map_err(|e| format!("write: {e}"))?;
                report.sent.push(octets);
            }
        }
    }
}

/// The application's verdict for one received I-frame.
fn answer(
    asdu: &[u8],
    session: &Session,
    interrogation: &mut Interrogation,
    commands: &mut CommandTransmission,
    device: &MockDevice,
    scripted: &mut VecDeque<Scripted>,
) -> Result<(), String> {
    let header = Header::parse(asdu).map_err(|e| format!("ASDU header: {e:?}"))?;
    match (header.type_id, header.cause) {
        // cl.7.5: the activation, then the scope's data, then the termination.
        (TypeId::CIcNa1, Cause::Activation) => {
            let outcome = interrogation
                .on_request(asdu, &Known::EVERYTHING, device)
                .map_err(|e| format!("cl.7.5: the GI: {e:?}"))?;
            for frame in &outcome.send {
                scripted.push_back(Scripted::I(frame.clone()));
            }
            for frame in interrogation
                .interrogated(device)
                .map_err(|e| format!("cl.7.5: the GI data: {e:?}"))?
            {
                scripted.push_back(Scripted::I(frame));
            }
            for frame in interrogation
                .complete(device)
                .map_err(|e| format!("cl.7.5: the GI termination: {e:?}"))?
            {
                scripted.push_back(Scripted::I(frame));
            }
            // cl.7.4: the station's own event, reported once the interrogation
            // has closed, and then cl.5.2's test act of its own accord.
            scripted.push_back(Scripted::I(spontaneous()));
            scripted.push_back(Scripted::U(UFunction::TestFrAct));
        }
        // cl.7.7: answer the command, positively where it is served and with
        // the negative mirror where the object refuses it (5.4.19.30).
        (TypeId::CScNa1, Cause::Activation) => {
            let ioa = iec104::asdu::read_ioa(&asdu[Header::LEN..])
                .map_err(|e| format!("cl.7.2.5: the IOA: {e:?}"))?;
            let outcome = if ioa == IOA_REFUSED {
                commands
                    .refuse(asdu)
                    .map_err(|e| format!("5.4.19.30: the refusal: {e:?}"))?
            } else {
                commands
                    .on_request(asdu, &Known::EVERYTHING)
                    .map_err(|e| format!("cl.7.7: the command: {e:?}"))?
            };
            for frame in &outcome.send {
                scripted.push_back(Scripted::I(frame.clone()));
            }
        }
        _ => {}
    }
    let _ = session;
    Ok(())
}

// -------------------------------------------------- the committed capture

/// One APDU the real peer, `c104` 2.2.1 (iec104-python, GPLv3), put on the wire
/// during this scenario on 2026-09-25: its positive `C_IC_NA_1 ACTCON`.
///
/// This is wire traffic, quoted the way `tests/wire_vectors.rs` quotes vendor
/// documentation: no code, table or vector is taken from the peer's source. The
/// offline suite parses it with **our** codec and asserts the values, so a bug
/// that the codec and the mock share cannot hide there.
///
/// Decoded: `68 0e` is the start octet and length, then an I-format APDU
/// (`00 00 02 00`, N(S) = 0 and N(R) = 1, the request it answers), whose ASDU is
/// `64` = `C_IC_NA_1`, VSQ `01` (SQ = 0, N = 1), COT `07` (actcon, `P/N = 0`,
/// `T = 0`), ORG `00`, CA `01 00` (common address 1, transmitted low octet
/// first, cl.7.2.4), IOA `00 00 00` (cl.7.2.5's irrelevant
/// address), QOI `14` = 20 = station (cl.7.2.6.22, figure 72).
pub const CAPTURE_PEER_ACT_CON: [u8; 16] = [
    0x68, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x64, 0x01, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14,
];

/// Re-parses the committed capture exactly as the harness parses the live
/// stream: through [`Decoder`] and [`parse_apci`]. Returns the control field and
/// the ASDU.
pub fn parse_capture(capture: &[u8]) -> Result<(Apci, Vec<u8>), String> {
    let mut decoder = Decoder::new();
    decoder.push(capture);
    let frame = {
        let frame = decoder
            .next_frame()
            .map_err(|e| format!("capture framing: {e}"))?
            .ok_or("the capture holds no complete frame")?;
        frame.to_vec()
    };
    if frame.len() != capture.len() {
        return Err(format!(
            "the capture holds {} octets and a {} octet frame",
            capture.len(),
            frame.len()
        ));
    }
    let (apci, asdu) = parse_frame(&frame)?;
    Ok((apci, asdu))
}

/// The parse the offline suite pins a real peer's octets with: our decoder must
/// see exactly the frame the wire carried, control field and ASDU both.
pub fn assert_peer_capture() -> Result<(), String> {
    let (apci, asdu) = parse_capture(&CAPTURE_PEER_ACT_CON)?;
    // The control field is pinned too, not just the payload: the capture is the
    // peer's answer to the scenario's first I-frame, so it carries N(S) = 0 and
    // N(R) = 1 (cl.5.1, the sequence numbers of figure 11).
    let expected = Apci::I {
        ns: SeqNo::new(0),
        nr: SeqNo::new(1),
    };
    if apci != expected {
        return Err(format!(
            "cl.5.1: the capture's control field is {apci:?}, not {expected:?}"
        ));
    }
    assert_request(&asdu, Scope::Station, Cause::ActivationCon, false)
}

/// Re-parses a captured byte stream into whole APDUs, as the live path does.
pub fn decode_capture(frames: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
    let mut decoder = Decoder::new();
    for frame in frames {
        decoder.push(frame);
    }
    let mut parsed = Vec::new();
    while let Ok(Some(_)) = decoder.next_frame_len() {
        let frame = {
            let frame = decoder
                .next_frame()
                .map_err(|e| format!("capture framing: {e}"))?
                .ok_or("the decoder promised a frame")?;
            frame.to_vec()
        };
        let (_, _) = parse_frame(&frame)?;
        parsed.push(frame);
    }
    Ok(parsed)
}

/// A shared place for the two entry points to put what the peer reported.
#[derive(Debug, Default)]
pub struct PeerLog {
    /// `VERSION` line the peer printed.
    pub version: String,
    /// `RX <hex>` frames: what the peer received from us.
    pub rx: Vec<Vec<u8>>,
    /// `TX <hex>` frames: what the peer sent us.
    pub tx: Vec<Vec<u8>>,
    /// Every other line the peer printed, in order.
    pub notes: Vec<String>,
    /// True once the peer printed READY: its listener is up.
    pub ready: bool,
    /// True once the peer printed DONE: the connection is over, it exits.
    pub done: bool,
    /// True once the peer reported the connection closed.
    pub closed: bool,
}

impl PeerLog {
    /// Reads the peer's stdout lines.
    pub fn absorb(&mut self, line: &str) {
        let mut parts = line.split_whitespace();
        match parts.next() {
            Some("READY") => self.ready = true,
            Some("DONE") => self.done = true,
            Some("VERSION") => self.version = line["VERSION".len()..].trim().to_string(),
            Some("RX") => {
                if let Some(hex) = parts.next()
                    && let Ok(octets) = decode_hex(hex)
                {
                    self.rx.push(octets);
                }
            }
            Some("TX") => {
                if let Some(hex) = parts.next()
                    && let Ok(octets) = decode_hex(hex)
                {
                    self.tx.push(octets);
                }
            }
            Some("STATE") => {
                if line.contains("CLOSED") {
                    self.closed = true;
                }
                self.notes.push(line.to_string());
            }
            _ => self.notes.push(line.to_string()),
        }
    }
}

/// The hex form of one APDU, for a log line.
pub fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// A tiny hex decoder for the peer's capture lines.
pub fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("odd hex length: {text}"));
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| format!("hex {text}: {e}")))
        .collect()
}

/// Holds the lines a reader thread pulled off the peer's stdout.
pub type LineSink = Arc<Mutex<PeerLog>>;
