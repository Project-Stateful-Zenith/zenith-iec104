//! Wire helpers for the procedure tables that run a request and its answers
//! (Tables 20 and 21): a counted link over [`Peer`] for the cases whose DUT is
//! the **controlled** station, and [`ScriptedPeer`], a mock controlled station
//! whose answers the case spells out, for the cases whose DUT is the
//! **controlling** station.
//!
//! Neither invents protocol behaviour. [`Link`] only counts sequence numbers so
//! the mock controlling station acknowledges what it read (5-104 clause 5.1:
//! the receive sequence number of an I-frame acknowledges every I-frame up to
//! it), and [`ScriptedPeer`] answers each I-frame it reads with the next batch
//! of ASDUs the case wrote out.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::conformance604::interop::{Station, encode_action};
use crate::conformance604::{Peer, parse_frame};
use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::framed::Decoder;
use iec104::link::{Role, Session};

/// A deadline `ms` milliseconds from now: every wait in these cases is short
/// and bounded.
pub fn soon(ms: u64) -> Instant {
    Instant::now() + Duration::from_millis(ms)
}

/// How long a case waits for a frame the standard says must come.
pub const ANSWER_MS: u64 = 2_000;

/// How long a case waits to show that a frame the standard does not draw does
/// not come.
pub const QUIET_MS: u64 = 150;

/// The mock controlling station of the controlled-station cases, with its own
/// send and receive counts so every I-frame it sends acknowledges every I-frame
/// it read (5-104 clause 5.1), and the station's window of `k` frames never
/// fills however long a case runs.
pub struct Link {
    /// The socket and its record.
    pub peer: Peer,
    ns: u16,
    nr: u16,
}

impl Link {
    /// Connects to the station and completes the STARTDT exchange (5-104
    /// clause 5.3).
    pub fn start(addr: SocketAddr) -> Result<Self, String> {
        let mut peer = Peer::connect(addr)?;
        peer.start_data_transfer()?;
        Ok(Self { peer, ns: 0, nr: 0 })
    }

    /// Sends one ASDU in an I-frame.
    pub fn send(&mut self, asdu: &[u8]) -> Result<(), String> {
        self.peer
            .send_i(SeqNo::new(self.ns), SeqNo::new(self.nr), asdu)?;
        self.ns += 1;
        Ok(())
    }

    /// Reads the next I-frame's ASDU within [`ANSWER_MS`].
    pub fn recv(&mut self) -> Result<Vec<u8>, String> {
        let (_, asdu) = self.peer.expect_i(soon(ANSWER_MS))?;
        self.nr += 1;
        Ok(asdu)
    }

    /// Reads `n` I-frames' ASDUs, in order.
    pub fn recv_n(&mut self, n: usize) -> Result<Vec<Vec<u8>>, String> {
        (0..n).map(|_| self.recv()).collect()
    }

    /// `Ok(())` when no I-frame arrives within [`QUIET_MS`]; the ASDU that did
    /// arrive otherwise.
    pub fn quiet(&mut self) -> Result<(), Vec<u8>> {
        match self.peer.expect_i(soon(QUIET_MS)) {
            Ok((_, asdu)) => {
                self.nr += 1;
                Err(asdu)
            }
            Err(_) => Ok(()),
        }
    }

    /// Acknowledges everything read so far with an S-frame and closes.
    pub fn finish(mut self) -> Result<(), String> {
        self.peer.send_s(SeqNo::new(self.nr))?;
        self.peer.close()
    }
}

/// What [`ScriptedPeer`] read from the controlling station under test.
#[derive(Debug, Default, Clone)]
pub struct ScriptedReport {
    /// The ASDU of every I-frame the station sent, in order.
    pub requests: Vec<Vec<u8>>,
}

/// A mock **controlled** station: it completes the STARTDT exchange (5-104
/// clause 5.3), then sends `initial`, then answers the n-th I-frame it reads
/// with the n-th batch of `replies`. Every ASDU it sends is one the case spelled
/// out.
pub struct ScriptedPeer {
    addr: SocketAddr,
    handle: JoinHandle<Result<ScriptedReport, String>>,
}

impl ScriptedPeer {
    /// Binds a loopback port and starts the accepting thread.
    pub fn start(initial: Vec<Vec<u8>>, replies: Vec<Vec<Vec<u8>>>) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
        let addr = listener
            .local_addr()
            .map_err(|e| format!("local addr: {e}"))?;
        let handle = thread::spawn(move || match listener.accept() {
            Ok((stream, _)) => serve(stream, &initial, replies.into()),
            Err(e) => Err(format!("accept: {e}")),
        });
        Ok(Self { addr, handle })
    }

    /// The loopback address the peer listens on.
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Waits for the peer thread, which ends when the station closes.
    pub fn join(self) -> Result<ScriptedReport, String> {
        self.handle
            .join()
            .map_err(|_| "the scripted peer panicked".to_string())?
    }
}

fn serve(
    mut stream: TcpStream,
    initial: &[Vec<u8>],
    mut replies: VecDeque<Vec<Vec<u8>>>,
) -> Result<ScriptedReport, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    let mut session = Session::new(Role::Controlled);
    session.on_connection_established();
    let mut decoder = Decoder::new();
    let mut report = ScriptedReport::default();
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
            // The station under test may reset the socket as it closes.
            Err(_) => return Ok(report),
        }
        while let Ok(Some(_)) = decoder.next_frame_len() {
            let frame = decoder
                .next_frame()
                .map_err(|e| format!("framing: {e}"))?
                .ok_or("the decoder promised a frame")?
                .to_vec();
            let (apci, asdu) = parse_frame(&frame)?;
            let mut out = Vec::new();
            for action in session.on_frame(apci) {
                encode_action(&action, &mut out)?;
            }
            let mut owed = Vec::new();
            if apci == Apci::U(UFunction::StartDtAct) {
                owed.extend(initial.iter().cloned());
            }
            if apci.is_i_format() {
                report.requests.push(asdu);
                owed.extend(replies.pop_front().unwrap_or_default());
            }
            for asdu in owed {
                let action = session
                    .send_i_frame(&asdu)
                    .ok_or("the scripted peer cannot send: window full or not started")?;
                encode_action(&action, &mut out)?;
            }
            if !out.is_empty() {
                stream.write_all(&out).map_err(|e| format!("write: {e}"))?;
            }
        }
    }
}

/// Connects the controlling station under test to `addr` and completes the
/// STARTDT exchange (5-104 clause 5.3).
pub fn started_station(addr: SocketAddr) -> Result<Station, String> {
    let mut station = Station::connect(addr)?;
    let actions = station.session_mut().request_start();
    station.send_actions(&actions)?;
    station.expect("STARTDT con", soon(ANSWER_MS), |apci, _| {
        apci == Apci::U(UFunction::StartDtCon)
    })?;
    Ok(station)
}

/// Sends one ASDU from the controlling station under test.
pub fn station_send(station: &mut Station, asdu: &[u8]) -> Result<(), String> {
    let action = station
        .session_mut()
        .send_i_frame(asdu)
        .ok_or("the station cannot send: window full or not started")?;
    station.send_actions(&[action])
}

/// Reads `n` I-frames' ASDUs at the controlling station under test, in order;
/// U- and S-frames are answered by its session and skipped.
pub fn station_recv_n(station: &mut Station, n: usize) -> Result<Vec<Vec<u8>>, String> {
    let limit = soon(ANSWER_MS);
    let mut out = Vec::new();
    while out.len() < n {
        match station.next(limit)? {
            Some((apci, asdu)) if apci.is_i_format() => out.push(asdu),
            Some(_) => {}
            None => {
                return Err(format!("{} of {n} I-frames before the deadline", out.len()));
            }
        }
    }
    Ok(out)
}
