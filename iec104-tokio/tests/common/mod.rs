//! In-memory peers for the driver tests: a connector whose dials the test
//! answers, and the far end of a `tokio::io::duplex` pipe that reads and
//! writes whole APDUs.
//!
//! Every frame the tests compare against is written out from clause 5's
//! control-field layout (figures 6–8), not built with the crate's encoder.

#![allow(dead_code)]

use std::io;

use iec104::framed::Decoder;
use iec104_tokio::{Connector, Event, Events};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
use tokio::sync::{mpsc, oneshot};

/// Clause 5, figure 8: the U-format APDUs, `68 04` then the control field.
pub const STARTDT_ACT: [u8; 6] = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
pub const STARTDT_CON: [u8; 6] = [0x68, 0x04, 0x0B, 0x00, 0x00, 0x00];
pub const STOPDT_ACT: [u8; 6] = [0x68, 0x04, 0x13, 0x00, 0x00, 0x00];
pub const STOPDT_CON: [u8; 6] = [0x68, 0x04, 0x23, 0x00, 0x00, 0x00];
pub const TESTFR_ACT: [u8; 6] = [0x68, 0x04, 0x43, 0x00, 0x00, 0x00];
pub const TESTFR_CON: [u8; 6] = [0x68, 0x04, 0x83, 0x00, 0x00, 0x00];

/// Clause 5, figure 7: an S-format APDU acknowledging up to `nr`.
pub fn s_frame(nr: u16) -> Vec<u8> {
    let nr = nr << 1;
    vec![0x68, 0x04, 0x01, 0x00, nr as u8, (nr >> 8) as u8]
}

/// Clause 5, figure 6: an I-format APDU carrying `asdu`.
pub fn i_frame(ns: u16, nr: u16, asdu: &[u8]) -> Vec<u8> {
    let (ns, nr) = (ns << 1, nr << 1);
    let mut frame = vec![
        0x68,
        4 + asdu.len() as u8,
        ns as u8,
        (ns >> 8) as u8,
        nr as u8,
        (nr >> 8) as u8,
    ];
    frame.extend_from_slice(asdu);
    frame
}

/// `C_IC_NA_1`, cause 6 (activation), common address 1, IOA 0, QOI 20:
/// a station interrogation (101 cl.7.3.4.1).
pub const INTERROGATION: [u8; 10] = [0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14];

/// `M_ME_NB_1`, cause 3 (spontaneous), common address 1, IOA 100, value
/// 1000, QDS 0.
pub const MEASURAND: [u8; 12] = [
    0x0B, 0x01, 0x03, 0x00, 0x01, 0x00, 0x64, 0x00, 0x00, 0xE8, 0x03, 0x00,
];

/// One dial the driver made; the test answers it.
pub struct Dial {
    pub conn: usize,
    pub reply: oneshot::Sender<io::Result<DuplexStream>>,
}

impl Dial {
    /// Completes the dial with a fresh pipe and returns its far end.
    pub fn accept(self) -> Peer {
        let (near, far) = duplex(64 * 1024);
        self.reply.send(Ok(near)).expect("the driver is waiting");
        Peer::new(far)
    }

    /// Completes the dial with a pipe that holds only `capacity` octets in
    /// flight: a peer that stops reading blocks the driver's writes.
    pub fn accept_with_capacity(self, capacity: usize) -> Peer {
        let (near, far) = duplex(capacity);
        self.reply.send(Ok(near)).expect("the driver is waiting");
        Peer::new(far)
    }

    /// Refuses the dial, as a peer that is not listening does.
    pub fn refuse(self) {
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        self.reply
            .send(Err(refused))
            .expect("the driver is waiting");
    }
}

/// A connector that hands every dial to the test.
pub struct Dials(pub mpsc::UnboundedSender<Dial>);

impl Dials {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Dial>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self(tx), rx)
    }
}

impl Connector for Dials {
    type Stream = DuplexStream;

    async fn connect(&self, conn: usize) -> io::Result<DuplexStream> {
        let (reply, answer) = oneshot::channel();
        self.0
            .send(Dial { conn, reply })
            .map_err(|_| io::Error::other("the test is gone"))?;
        answer
            .await
            .unwrap_or_else(|_| Err(io::Error::other("the test dropped the dial")))
    }
}

/// The far end of one connection.
pub struct Peer {
    stream: DuplexStream,
    decoder: Decoder,
}

impl Peer {
    pub fn new(stream: DuplexStream) -> Self {
        Self {
            stream,
            decoder: Decoder::new(),
        }
    }

    /// A fresh pipe: the near end for [`iec104_tokio::Handle::attach`], and
    /// the peer on the far end.
    pub fn pipe() -> (DuplexStream, Self) {
        let (near, far) = duplex(64 * 1024);
        (near, Self::new(far))
    }

    /// The next whole APDU the driver wrote, or `None` once it closed.
    pub async fn frame(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(frame) = self.decoder.next_frame().expect("well framed") {
                return Some(frame.to_vec());
            }
            let mut buf = [0u8; 1024];
            match self.stream.read(&mut buf).await {
                Ok(0) | Err(_) => return None,
                Ok(n) => self.decoder.push(&buf[..n]),
            }
        }
    }

    pub async fn send(&mut self, frame: &[u8]) {
        self.stream
            .write_all(frame)
            .await
            .expect("the pipe is open");
    }
}

/// The next dial, which must come.
pub async fn next_dial(dials: &mut mpsc::UnboundedReceiver<Dial>) -> Dial {
    dials.recv().await.expect("the driver dials")
}

/// Reads events until one matches, returning it. Fails, rather than hangs,
/// when none comes within an hour. In a test that pauses the clock that is
/// an hour of the paused clock, so it fails as soon as the runtime is idle.
pub async fn until(events: &mut Events, wanted: impl Fn(&Event) -> bool + Sync) -> Event {
    let wait = async {
        loop {
            let event = events.recv().await.expect("the driver runs");
            if wanted(&event) {
                return event;
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(3600), wait)
        .await
        .expect("the event never came")
}

/// Everything already reported, without waiting.
pub fn drain(events: &mut Events) -> Vec<Event> {
    let mut seen = Vec::new();
    while let Ok(event) = events.try_recv() {
        seen.push(event);
    }
    seen
}
