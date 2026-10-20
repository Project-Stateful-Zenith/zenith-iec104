//! Blocking-TCP plumbing shared by the examples.
//!
//! The crate is sans-IO, so this is the part a real application writes once:
//! put the manager's actions on the socket, and feed what arrives back into
//! the manager. One thread does both, reading with a short timeout so that it
//! also gets to run the timers.

use iec104::apci::{self, Apci, Apdu};
use iec104::asdu::AddressSizes;
use iec104::diag;
use iec104::framed::{Decoder, FramingError};
use iec104::link::{Action, State};
use iec104::manager::{ConnectionManager, Directive};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// The one station each example talks to.
pub const STATION: usize = 0;

/// The address sizes from `IEC104_SIZES=ca,ioa,originator` (for example
/// `1,2,0`: one-octet common address, two-octet object address, no
/// originator), or the conventional 2,3,1 when it is not set.
pub fn address_sizes() -> Result<AddressSizes, String> {
    let Ok(spec) = std::env::var("IEC104_SIZES") else {
        return Ok(AddressSizes::CONVENTIONAL);
    };
    let fields: Vec<u8> = spec
        .split(',')
        .map(|f| f.trim().parse::<u8>())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("IEC104_SIZES: {e}"))?;
    let [ca, ioa, originator] = fields[..] else {
        return Err("IEC104_SIZES wants three fields: ca,ioa,originator".into());
    };
    AddressSizes::new(ca, ioa, originator != 0).map_err(|e| format!("IEC104_SIZES: {e:?}"))
}

/// What [`Link`] needs of its byte stream beyond `Read + Write`: the TCP
/// socket underneath, for the read timeout and Nagle. A TLS stream over TCP
/// (the `iec104-tls` examples) implements it as well as `TcpStream` does.
pub trait Socket: Read + Write {
    /// The TCP socket the stream runs on.
    fn tcp(&self) -> &TcpStream;
}

impl Socket for TcpStream {
    fn tcp(&self) -> &TcpStream {
        self
    }
}

/// One connection and the framer over it: plain TCP by default.
pub struct Link<S: Socket = TcpStream> {
    stream: Option<S>,
    decoder: Decoder,
    sizes: AddressSizes,
}

impl<S: Socket> Link<S> {
    /// A link that logs frames in the address sizes `sizes`.
    pub fn new(sizes: AddressSizes) -> Self {
        Self {
            stream: None,
            decoder: Decoder::new(),
            sizes,
        }
    }

    /// Whether a connection is attached.
    pub const fn is_up(&self) -> bool {
        self.stream.is_some()
    }

    /// Adopts a freshly connected or accepted socket and tells the manager.
    pub fn attach(
        &mut self,
        stream: S,
        manager: &mut ConnectionManager,
        now: Instant,
    ) -> Result<(), String> {
        // A short read timeout lets one thread both read and run the timers.
        let tcp = stream.tcp();
        tcp.set_read_timeout(Some(Duration::from_millis(50)))
            .map_err(|e| e.to_string())?;
        // Frames are small and every one is due now: do not let Nagle hold
        // them back waiting for more.
        tcp.set_nodelay(true).map_err(|e| e.to_string())?;
        self.stream = Some(stream);
        // Nothing from the previous connection may leak into this one.
        self.decoder = Decoder::new();
        manager
            .on_connection_established(STATION, now)
            .map_err(|e| format!("{e:?}"))
    }

    /// Drops the socket and tells the manager the connection is gone.
    pub fn detach(&mut self, manager: &mut ConnectionManager, why: &str) {
        if self.stream.take().is_some() {
            println!("connection closed: {why}");
            let _ = manager.on_connection_lost(STATION);
        }
    }

    /// Performs every directive: frames go on the wire, an active close drops
    /// the socket. `DeliverData` needs nothing here, because [`Link::receive`]
    /// hands the ASDU over itself. A failed write is a lost connection.
    pub fn perform(&mut self, manager: &mut ConnectionManager, directives: Vec<Directive>) {
        for directive in directives {
            let Directive::Actions { actions, .. } = directive else {
                continue;
            };
            for action in actions {
                let written = match &action {
                    Action::Send(apci) => self.write(*apci, &[]),
                    Action::SendI { ns, nr, asdu } => {
                        self.write(Apci::I { ns: *ns, nr: *nr }, asdu)
                    }
                    Action::DeliverData { .. } => Ok(()),
                    Action::ActiveClose(why) => {
                        self.detach(manager, why);
                        return;
                    }
                };
                if let Err(e) = written {
                    self.detach(manager, &e);
                    return;
                }
            }
        }
    }

    fn write(&mut self, apci: Apci, asdu: &[u8]) -> Result<(), String> {
        // With no connection there is nowhere to write; the manager already
        // knows it is down.
        let Some(stream) = self.stream.as_mut() else {
            return Ok(());
        };
        let mut frame = Vec::new();
        Apdu { apci, asdu }
            .encode(&mut frame)
            .map_err(|e| format!("{e:?}"))?;
        log("->", &frame, self.sizes);
        // A TLS stream's write only queues; the flush puts the frame on the wire.
        stream
            .write_all(&frame)
            .and_then(|()| stream.flush())
            .map_err(|e| e.to_string())
    }

    /// Reads what the socket has (waiting at most the read timeout), feeds each
    /// frame to the manager, and returns the ASDUs the session accepted for
    /// the application, in order.
    pub fn receive(&mut self, manager: &mut ConnectionManager, now: Instant) -> Vec<Vec<u8>> {
        let mut delivered = Vec::new();
        let Some(stream) = self.stream.as_mut() else {
            return delivered;
        };
        let mut buf = [0u8; 2048];
        match stream.read(&mut buf) {
            Ok(0) => {
                self.detach(manager, "peer closed the connection");
                return delivered;
            }
            // TCP is a byte stream: a read may hold part of a frame or
            // several frames, so the decoder buffers until each is complete.
            Ok(n) => self.decoder.push(buf.get(..n).unwrap_or_default()),
            // The read timeout: nothing arrived, which is normal.
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => {
                self.detach(manager, &e.to_string());
                return delivered;
            }
        }
        loop {
            let frame = match self.decoder.next_frame() {
                Ok(Some(frame)) => frame.to_vec(),
                Ok(None) => break,
                // A malformed frame goes to the manager, which decides
                // whether it closes the connection.
                Err(FramingError::BadFrame(e)) => {
                    let directives = manager.on_parse_error(STATION, e, now).unwrap_or_default();
                    self.perform(manager, directives);
                    continue;
                }
                Err(e) => {
                    self.detach(manager, &e.to_string());
                    break;
                }
            };
            log("<-", &frame, self.sizes);
            let directives = match apci::parse(&frame) {
                Ok((apdu, _)) => manager.on_frame(STATION, apdu.apci, now),
                Err(e) => manager.on_parse_error(STATION, e, now),
            }
            .unwrap_or_default();
            // Only an I-frame the session accepted (the manager answered it
            // with `DeliverData`) is the application's.
            let accepted = directives.iter().any(|d| {
                matches!(d, Directive::Actions { actions, .. }
                    if actions.iter().any(|a| matches!(a, Action::DeliverData { .. })))
            });
            self.perform(manager, directives);
            if accepted && let Ok((apdu, _)) = apci::parse(&frame) {
                delivered.push(apdu.asdu.to_vec());
            }
            if !self.is_up() {
                break;
            }
        }
        delivered
    }

    /// Sends one ASDU now if the k window and the state allow it, otherwise
    /// leaves it in the session's queue, which sends it as soon as they do.
    pub fn send_asdu(&mut self, manager: &mut ConnectionManager, asdu: &[u8], now: Instant) {
        match manager.send_i_frame(STATION, asdu, now) {
            Ok(Some(directive)) => self.perform(manager, vec![directive]),
            Ok(None) => {
                if let Err(e) = manager.queue_i_frame(STATION, asdu) {
                    println!("dropped an ASDU: {e:?}");
                }
            }
            Err(e) => println!("dropped an ASDU: {e:?}"),
        }
    }

    /// Ends the connection in order, as the controlling station: an S-frame
    /// for what arrived unconfirmed, then STOPDT act (clause 5.3), the wait for
    /// STOPDT con, and the active close with any last acknowledgement before
    /// it (figures 10/11 NOTE). The wait is bounded by t1: without the
    /// confirmation the session closes the connection itself. ASDUs that
    /// arrive meanwhile are acknowledged and logged, and not handed on.
    // Only the controlling examples stop data transfer; the outstations share
    // this module without it.
    #[allow(dead_code)]
    pub fn close(&mut self, manager: &mut ConnectionManager) {
        if !self.is_up() {
            return;
        }
        let stop = manager
            .request_stop(STATION, Instant::now())
            .unwrap_or_default();
        self.perform(manager, stop);
        while self.is_up() && stopping(manager) {
            let now = Instant::now();
            // The manager's clock runs the t1 of the STOPDT act. Nothing is
            // dialled any more, so a request for a connection is ignored.
            let ticked = manager
                .tick(now)
                .into_iter()
                .filter(|d| matches!(d, Directive::Actions { .. }))
                .collect();
            self.perform(manager, ticked);
            self.receive(manager, now);
        }
        if !self.is_up() {
            return;
        }
        let Ok(station) = manager.station_mut(STATION) else {
            return;
        };
        let actions = station.session_mut().close("closed by the application");
        self.perform(
            manager,
            vec![Directive::Actions {
                station: STATION,
                actions,
            }],
        );
    }
}

/// Whether the station's STOPDT act still waits for its confirmation.
#[allow(dead_code)]
fn stopping(manager: &ConnectionManager) -> bool {
    manager.station(STATION).is_ok_and(|s| {
        matches!(
            s.state(),
            State::PendingStopped | State::PendingUnconfirmedStopped
        )
    })
}

/// One human-readable line per frame (`diag::apdu`), or the raw octets.
pub fn log(direction: &str, frame: &[u8], sizes: AddressSizes) {
    match diag::apdu(frame, sizes) {
        Ok(line) => println!("{direction} {line}"),
        Err(e) => println!("{direction} {frame:02X?} ({e})"),
    }
}
