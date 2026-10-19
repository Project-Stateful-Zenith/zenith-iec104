//! One end of a loopback TCP connection, for the procedure cases of Tables 12,
//! 22 and 24 that drive the crate's connection-level components
//! (`redundancy::RedundancyGroup`, `manager::ConnectionManager`) over real
//! sockets in lock-step, without a thread per side.
//!
//! An [`Endpoint`] invents no protocol behaviour. On the side of the station
//! under test it performs exactly the `link::Action`s the crate returned
//! ([`Endpoint::perform`]); on the side of the mock peer it puts on the wire
//! exactly the frames the case spells out ([`Endpoint::send_u`],
//! [`Endpoint::send_i`]). Both directions are recorded.
//!
//! Every wait is a bounded read deadline, as in [`crate::conformance604::Peer`];
//! the clock the crate's timers run on is the case's own `Instant`, never a
//! sleep.

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use iec104::apci::{Apci, Apdu, SeqNo, UFunction};
use iec104::framed::Decoder;
use iec104::link::Action;

use crate::conformance604::{interop, parse_frame};

/// How long [`Endpoint::quiet`] listens for a frame that must not come. Short,
/// because every frame the cases wait for is written before the check.
pub const QUIET: Duration = Duration::from_millis(150);

/// One end of a TCP connection with its own frame decoder.
pub struct Endpoint {
    stream: TcpStream,
    decoder: Decoder,
    /// Every APDU this end put on the wire, in order.
    pub sent: Vec<Vec<u8>>,
    /// Every APDU this end read, in order.
    pub received: Vec<Vec<u8>>,
    /// The reasons of every `Action::ActiveClose` this end performed.
    pub closes: Vec<&'static str>,
}

impl Endpoint {
    fn new(stream: TcpStream) -> Result<Self, String> {
        stream
            .set_nodelay(true)
            .map_err(|e| format!("nodelay: {e}"))?;
        Ok(Self {
            stream,
            decoder: Decoder::new(),
            sent: Vec::new(),
            received: Vec::new(),
            closes: Vec::new(),
        })
    }

    /// The active open of 5-104 clause 7.1 (the client, the connector).
    pub fn connect(addr: SocketAddr) -> Result<Self, String> {
        Self::new(TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?)
    }

    /// The passive side of one connection whose active open has already been
    /// made, so the accept returns at once.
    pub fn accept(listener: &TcpListener) -> Result<Self, String> {
        let (stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        Self::new(stream)
    }

    fn write(&mut self, octets: &[u8]) -> Result<(), String> {
        self.stream
            .write_all(octets)
            .map_err(|e| format!("write: {e}"))?;
        self.sent.push(octets.to_vec());
        Ok(())
    }

    /// Performs the actions the crate returned for this connection, in order:
    /// each frame goes on the wire, and an `ActiveClose` shuts the socket down
    /// (the FIN the peer observes as EOF). `DeliverData` is not a frame.
    pub fn perform(&mut self, actions: &[Action]) -> Result<(), String> {
        for action in actions {
            if let Action::ActiveClose(why) = action {
                self.closes.push(why);
                self.shutdown();
                continue;
            }
            let mut octets = Vec::new();
            interop::encode_action(action, &mut octets)?;
            if !octets.is_empty() {
                self.write(&octets)?;
            }
        }
        Ok(())
    }

    /// A U-format frame (5-104 clause 5, figure 8), spelled out by the case.
    pub fn send_u(&mut self, function: UFunction) -> Result<(), String> {
        self.send(Apci::U(function), &[])
    }

    /// An S-format frame (5-104 clause 5, figure 7), spelled out by the case.
    pub fn send_s(&mut self, nr: SeqNo) -> Result<(), String> {
        self.send(Apci::S { nr }, &[])
    }

    /// An I-format frame carrying `asdu`, numbered by the case.
    pub fn send_i(&mut self, ns: u16, nr: u16, asdu: &[u8]) -> Result<(), String> {
        self.send(
            Apci::I {
                ns: SeqNo::new(ns),
                nr: SeqNo::new(nr),
            },
            asdu,
        )
    }

    fn send(&mut self, apci: Apci, asdu: &[u8]) -> Result<(), String> {
        let mut out = Vec::new();
        Apdu { apci, asdu }
            .encode(&mut out)
            .map_err(|e| format!("encode {apci:?}: {e:?}"))?;
        self.write(&out)
    }

    /// Reads one whole frame, failing at the deadline (`"no frame before the
    /// deadline"`) or at EOF (`"the peer closed the connection"`).
    pub fn read_frame(&mut self, limit: Instant) -> Result<(Apci, Vec<u8>), String> {
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
                    return Ok((apci, asdu));
                }
                Ok(None) => {}
                Err(_) => {
                    let _ = self.decoder.next_frame();
                }
            }
            let remaining = limit.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("no frame before the deadline".into());
            }
            self.stream
                .set_read_timeout(Some(remaining))
                .map_err(|e| format!("set read timeout: {e}"))?;
            let mut buf = [0u8; 1024];
            match self.stream.read(&mut buf) {
                Ok(0) => return Err("the peer closed the connection".into()),
                Ok(n) => self.decoder.push(&buf[..n]),
                // A close with data still unread on the closing side is a RST
                // rather than a FIN (RFC 1122 4.2.2.13); it ends the
                // connection all the same.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    return Err("the peer reset the connection".into());
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err("no frame before the deadline".into());
                }
                Err(e) => return Err(format!("read: {e}")),
            }
        }
    }

    /// Reads the next frame and requires it to be this U-function.
    pub fn expect_u(&mut self, function: UFunction) -> Result<(), String> {
        let (apci, _) = self.read_frame(soon())?;
        if apci != Apci::U(function) {
            return Err(format!("{function:?} expected, got {apci:?}"));
        }
        Ok(())
    }

    /// Reads the next frame and requires it to be an I-frame.
    pub fn expect_i(&mut self) -> Result<(Apci, Vec<u8>), String> {
        let (apci, asdu) = self.read_frame(soon())?;
        if !apci.is_i_format() {
            return Err(format!("an I-frame expected, got {apci:?}"));
        }
        Ok((apci, asdu))
    }

    /// Requires the peer's active close: EOF (or the RST a close with unread
    /// data becomes) with no frame before it.
    pub fn expect_eof(&mut self) -> Result<(), String> {
        match self.read_frame(soon()) {
            Err(why)
                if why == "the peer closed the connection"
                    || why == "the peer reset the connection" =>
            {
                Ok(())
            }
            Err(why) => Err(format!("an active close expected: {why}")),
            Ok((apci, _)) => Err(format!("an active close expected, got {apci:?}")),
        }
    }

    /// Requires that no frame arrives (and the connection stays open) for
    /// [`QUIET`].
    pub fn quiet(&mut self) -> Result<(), String> {
        match self.read_frame(Instant::now() + QUIET) {
            Err(why) if why == "no frame before the deadline" => Ok(()),
            Err(why) => Err(format!("silence expected: {why}")),
            Ok((apci, _)) => Err(format!("silence expected, got {apci:?}")),
        }
    }

    /// Shuts the socket down in both directions.
    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// The deadline of a frame that is already on its way: five seconds, which a
/// loopback socket never needs.
pub fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

/// A loopback address nothing listens on, for a dial that must be refused:
/// the port is bound, read and released again.
pub fn refused_addr() -> Result<SocketAddr, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    listener
        .local_addr()
        .map_err(|e| format!("local addr: {e}"))
}
