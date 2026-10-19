//! The driver task: one task owns the sans-IO core; per socket a reader task
//! feeds it received bytes and a writer task puts its frames on the wire, and
//! a dial task per attempt reports back. Everything the core decides is queued
//! to the writers in order before the next event is taken, so the engine
//! never waits for a write, and a peer that stops reading holds up only its
//! own writer.

use std::future::pending;
use std::io;
use std::sync::Arc;

use iec104::apci::{self, Apci, Apdu, MAX_ASDU};
use iec104::framed::{Decoder, FramingError};
use iec104::link::{Action, State};
use iec104::redundancy::{Replay, ReplayOutcome, Routed};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep_until, timeout};

use crate::connect::{AsyncStream, Connector};
use crate::core::Core;
use crate::diagnostics::{self, Direction};
use crate::{Error, Event, Options};

/// How many unprocessed reads the engine lets the reader tasks run ahead.
const IO_QUEUE: usize = 64;

pub type Reply<T> = oneshot::Sender<Result<T, Error>>;

pub enum Command {
    Send {
        conn: usize,
        asdu: Vec<u8>,
        reply: Reply<()>,
    },
    Start {
        conn: usize,
        reply: Reply<()>,
    },
    Stop {
        conn: usize,
        reply: Reply<()>,
    },
    Close {
        conn: usize,
        reply: Reply<()>,
    },
    State {
        conn: usize,
        reply: Reply<State>,
    },
    Window {
        conn: usize,
        reply: Reply<u16>,
    },
    Attach {
        conn: Option<usize>,
        stream: Box<dyn AsyncStream>,
        reply: Reply<usize>,
    },
    Retransmit {
        failed: usize,
        replay: Replay,
        reply: Reply<ReplayOutcome>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

enum Io {
    Bytes {
        conn: usize,
        generation: u64,
        data: Vec<u8>,
    },
    Closed {
        conn: usize,
        generation: u64,
        reason: String,
    },
    Dialed {
        conn: usize,
        generation: u64,
        result: io::Result<Box<dyn AsyncStream>>,
    },
}

/// What a connection's writer task is asked to do, in order.
enum Out {
    /// Put these frames on the wire.
    Frames(Vec<u8>),
    /// Flush, shut the write half down, and stop.
    Close,
}

/// A connection's writer task and its queue.
struct Writer {
    queue: mpsc::UnboundedSender<Out>,
    task: JoinHandle<()>,
}

/// One connection's I/O: its writer, and the tasks reading and dialing.
struct Slot {
    writer: Option<Writer>,
    reader: Option<JoinHandle<()>>,
    dial: Option<JoinHandle<()>>,
    /// Bumped by every dial, attached socket and detach, so that events of an
    /// abandoned dial or a closed socket are recognised and dropped.
    generation: u64,
    decoder: Decoder,
    /// The session state last reported as [`Event::State`].
    reported: State,
}

impl Slot {
    fn new() -> Self {
        Self {
            writer: None,
            reader: None,
            dial: None,
            generation: 0,
            decoder: Decoder::new(),
            reported: State::Stopped,
        }
    }
}

/// The core's clock is the runtime's, so a paused test clock drives the
/// timers too.
fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

struct Engine<C, K> {
    core: C,
    connector: Arc<K>,
    options: Options,
    /// A redundancy group: an attached socket may take any free member.
    group: bool,
    slots: Vec<Slot>,
    events: mpsc::UnboundedSender<Event>,
    io: mpsc::Sender<Io>,
    /// The writers' reports. Unbounded, so a writer never waits on the engine:
    /// shutdown waits on the writers and does not read reports.
    reports: mpsc::UnboundedSender<Io>,
    /// Writers of closed connections still flushing their last frames; waited
    /// for at shutdown so the peer sees them.
    closing: Vec<JoinHandle<()>>,
    /// A connection was lost since the last tick. Such a connection is due
    /// at once and has no instant in `next_deadline`, so the core is ticked
    /// again before the engine sleeps.
    lost: bool,
}

pub async fn run<C: Core, K: Connector>(
    core: C,
    connector: K,
    options: Options,
    group: bool,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::UnboundedSender<Event>,
) {
    let (io, mut io_rx) = mpsc::channel(IO_QUEUE);
    let (reports, mut reports_rx) = mpsc::unbounded_channel();
    let slots = (0..core.len()).map(|_| Slot::new()).collect();
    let mut engine = Engine {
        core,
        connector: Arc::new(connector),
        options,
        group,
        slots,
        events,
        io,
        reports,
        closing: Vec::new(),
        lost: false,
    };
    loop {
        engine.tick();
        let deadline = engine.core.next_deadline();
        let wake = async {
            match deadline {
                Some(at) => sleep_until(tokio::time::Instant::from_std(at)).await,
                None => pending().await,
            }
        };
        tokio::select! {
            command = commands.recv() => if let Some(command) = command {
                if engine.command(command).await {
                    return;
                }
            } else {
                // Every handle is gone: nobody can use the connections.
                engine.shutdown().await;
                return;
            },
            // The engine holds a sender itself, so this never yields `None`.
            Some(io) = io_rx.recv() => engine.io(io),
            Some(report) = reports_rx.recv() => {
                // What the socket delivered before the writer failed comes
                // first: an acknowledgement in it changes what is unconfirmed.
                while let Ok(io) = io_rx.try_recv() {
                    engine.io(io);
                }
                engine.io(report);
            }
            () = wake => {}
        }
    }
}

impl<C: Core, K: Connector> Engine<C, K> {
    fn emit(&self, event: Event) {
        diagnostics::event(&event);
        // The application may have dropped its receiver; the driver runs on.
        let _ = self.events.send(event);
    }

    fn tick(&mut self) {
        loop {
            self.lost = false;
            let tick = self.core.tick(now());
            for conn in tick.connect {
                self.dial(conn);
            }
            self.perform(tick.routed, None);
            for switchover in tick.switchovers {
                self.emit(Event::Switchover(switchover));
            }
            self.settle(&[]);
            if !self.lost {
                break;
            }
        }
    }

    /// Runs the auto-start policy for connections that just came up (and,
    /// for a group, whenever it names no started connection), then reports
    /// every state change.
    fn settle(&mut self, established: &[usize]) {
        if self.options.auto_start {
            let starts = self.core.auto_start(established, now());
            self.perform(starts, None);
        }
        for conn in 0..self.slots.len() {
            let (Some(state), Some(slot)) = (self.core.state(conn), self.slots.get_mut(conn))
            else {
                continue;
            };
            if slot.reported != state {
                slot.reported = state;
                self.emit(Event::State { conn, state });
            }
        }
    }

    fn dial(&mut self, conn: usize) {
        let Some(slot) = self.slots.get_mut(conn) else {
            return;
        };
        // A new attempt abandons the one still in flight: its t0 expired
        // (`ConnectReason::AttemptTimedOut`), and a late success must not
        // leave two connections to one station.
        if let Some(dial) = slot.dial.take() {
            dial.abort();
        }
        slot.generation = slot.generation.wrapping_add(1);
        let generation = slot.generation;
        let connector = Arc::clone(&self.connector);
        let io = self.io.clone();
        slot.dial = Some(tokio::spawn(async move {
            let result = connector
                .connect(conn)
                .await
                .map(|stream| -> Box<dyn AsyncStream> { Box::new(stream) });
            let _ = io
                .send(Io::Dialed {
                    conn,
                    generation,
                    result,
                })
                .await;
        }));
        self.emit(Event::Connecting { conn });
    }

    /// Adopts a socket for `conn`: the core learns of it, and a reader task
    /// starts feeding its bytes in.
    fn attach(&mut self, conn: usize, stream: Box<dyn AsyncStream>) {
        let (Some(params), Some(slot)) = (self.core.params(conn), self.slots.get_mut(conn)) else {
            return;
        };
        if let Some(dial) = slot.dial.take() {
            dial.abort();
        }
        slot.generation = slot.generation.wrapping_add(1);
        let generation = slot.generation;
        let (reader, writer) = tokio::io::split(stream);
        let (queue, frames) = mpsc::unbounded_channel();
        let task = tokio::spawn(write(
            writer,
            frames,
            params.t1,
            conn,
            generation,
            self.reports.clone(),
        ));
        slot.writer = Some(Writer { queue, task });
        slot.decoder = Decoder::new();
        slot.reader = Some(tokio::spawn(read(
            reader,
            conn,
            generation,
            self.io.clone(),
        )));
        self.core.established(conn, now());
        self.emit(Event::Connected { conn });
        self.settle(&[conn]);
    }

    /// Drops `conn`'s socket and tells the core. `graceful` lets the writer
    /// put every frame queued so far on the wire, then flush and shut the
    /// write half down, so the peer sees them and then FIN; otherwise the
    /// writer is stopped where it is.
    ///
    /// The loss is reported as soon as the close is queued: the wire order is
    /// the writer's, and waiting for a peer that does not read would hold up
    /// every other connection.
    fn detach(&mut self, conn: usize, reason: String, graceful: bool) {
        let Some(slot) = self.slots.get_mut(conn) else {
            return;
        };
        let Some(writer) = slot.writer.take() else {
            return;
        };
        if graceful && writer.queue.send(Out::Close).is_ok() {
            self.closing.retain(|task| !task.is_finished());
            self.closing.push(writer.task);
        } else {
            writer.task.abort();
        }
        if let Some(reader) = slot.reader.take() {
            reader.abort();
        }
        slot.generation = slot.generation.wrapping_add(1);
        slot.decoder = Decoder::new();
        let was_started = self.core.started() == Some(conn);
        self.core.lost(conn);
        self.lost = true;
        self.emit(Event::Disconnected { conn, reason });
        if was_started {
            let unconfirmed = self.core.unconfirmed(conn);
            self.emit(Event::StartedConnectionFailed { conn, unconfirmed });
        }
    }

    /// Queues `frames` on `conn`'s writer. A writer that has stopped reports
    /// why itself (`Io::Closed`).
    fn write(&self, conn: usize, frames: Vec<u8>) {
        if frames.is_empty() {
            return;
        }
        if let Some(writer) = self.slots.get(conn).and_then(|slot| slot.writer.as_ref()) {
            let _ = writer.queue.send(Out::Frames(frames));
        }
    }

    /// Performs every action list, in order. Returns true when one of them
    /// carried `DeliverData` for `received`'s connection, i.e. the session
    /// accepted that I-frame for the application.
    fn perform(&mut self, routed: Vec<Routed>, received: Option<usize>) -> bool {
        let mut delivered = false;
        for Routed { member, actions } in routed {
            let mut frames = Vec::new();
            let mut close = None;
            for action in actions {
                let (apci, asdu) = match action {
                    Action::Send(apci) => (apci, Vec::new()),
                    Action::SendI { ns, nr, asdu } => (Apci::I { ns, nr }, asdu),
                    Action::DeliverData { .. } => {
                        delivered |= received == Some(member);
                        continue;
                    }
                    // Figures 10/11 NOTE: the S-frame the session put before
                    // the close goes out first.
                    Action::ActiveClose(why) => {
                        close = Some(why);
                        break;
                    }
                };
                let at = frames.len();
                // Cannot fail: `send_asdu` refuses an ASDU no APDU can carry.
                let encoded = Apdu { apci, asdu: &asdu }.encode(&mut frames);
                if encoded.is_ok()
                    && let Some(frame) = frames.get(at..)
                {
                    diagnostics::apdu(Direction::Sent, member, frame, self.options.sizes);
                    if self.options.trace {
                        self.emit(Event::Sent {
                            conn: member,
                            frame: frame.to_vec(),
                        });
                    }
                }
            }
            self.write(member, frames);
            if let Some(why) = close {
                self.detach(member, why.to_string(), true);
            }
        }
        delivered
    }

    fn io(&mut self, io: Io) {
        match io {
            Io::Bytes {
                conn,
                generation,
                data,
            } => {
                if self.current(conn, generation) {
                    self.received(conn, generation, &data);
                    self.settle(&[]);
                }
            }
            Io::Closed {
                conn,
                generation,
                reason,
            } => {
                if self.current(conn, generation) {
                    self.detach(conn, reason, false);
                    self.settle(&[]);
                }
            }
            Io::Dialed {
                conn,
                generation,
                result,
            } => {
                let Some(slot) = self.slots.get_mut(conn) else {
                    return;
                };
                if slot.generation != generation || slot.writer.is_some() {
                    return;
                }
                slot.dial = None;
                match result {
                    Ok(stream) => self.attach(conn, stream),
                    Err(e) => {
                        // A refused dial: the attempt's t0 stays armed and
                        // the core asks again at its expiry.
                        self.core.lost(conn);
                        self.emit(Event::ConnectFailed {
                            conn,
                            error: e.to_string(),
                        });
                    }
                }
            }
        }
    }

    /// Feeds received bytes through the framer and the core, one APDU at a
    /// time, performing each APDU's actions before the next is looked at.
    fn received(&mut self, conn: usize, generation: u64, data: &[u8]) {
        let Some(slot) = self.slots.get_mut(conn) else {
            return;
        };
        slot.decoder.push(data);
        // Stop as soon as the socket is gone: what follows it is void.
        while self.current(conn, generation) {
            let Some(slot) = self.slots.get_mut(conn) else {
                break;
            };
            let frame = match slot.decoder.next_frame() {
                Ok(Some(frame)) => frame.to_vec(),
                Ok(None) => break,
                Err(FramingError::BadFrame(e)) => {
                    let routed = self.core.on_parse_error(conn, e, now());
                    self.perform(routed, None);
                    continue;
                }
                Err(e) => {
                    self.detach(conn, e.to_string(), true);
                    break;
                }
            };
            diagnostics::apdu(Direction::Received, conn, &frame, self.options.sizes);
            if self.options.trace {
                self.emit(Event::Received {
                    conn,
                    frame: frame.clone(),
                });
            }
            match apci::parse(&frame) {
                Ok((apdu, _)) => {
                    let started = self.core.started();
                    let room = self.window(conn);
                    let routed = match self.core.on_frame(conn, apdu.apci, now()) {
                        Ok(routed) => routed,
                        Err(error) => {
                            self.emit(Event::FrameRefused { conn, error });
                            Vec::new()
                        }
                    };
                    // Only an I-frame the session accepted is the application's.
                    if self.perform(routed, Some(conn)) {
                        self.emit(Event::Asdu {
                            conn,
                            asdu: apdu.asdu.to_vec(),
                        });
                    }
                    // The N(R) of an I- or S-frame confirmed I-frames and the
                    // window has room it did not have (clauses 5.1, 5.5). A
                    // STARTDT opens the window too, but that is a state change.
                    if matches!(apdu.apci, Apci::I { .. } | Apci::S { .. })
                        && self.window(conn) > room
                    {
                        self.emit(Event::Acknowledged { conn });
                    }
                    // A STARTDT act on another connection of a controlled
                    // group closes the started one (10.7): that is a failure of
                    // the started connection as much as a lost socket is. A
                    // connection the master stopped first (10.2's manual
                    // switchover) stays open and has failed nothing.
                    if let Some(displaced) = started.filter(|&s| s != conn)
                        && self.core.started() != Some(displaced)
                        && self.core.state(displaced) == Some(State::Terminated)
                    {
                        let unconfirmed = self.core.unconfirmed(displaced);
                        self.emit(Event::StartedConnectionFailed {
                            conn: displaced,
                            unconfirmed,
                        });
                    }
                }
                Err(e) => {
                    let routed = self.core.on_parse_error(conn, e, now());
                    self.perform(routed, None);
                }
            }
        }
    }

    /// How many ASDUs `send_asdu(conn, ..)` can put on the wire at once.
    fn window(&self, conn: usize) -> u16 {
        let k = self
            .core
            .params(self.core.started().unwrap_or(conn))
            .map(|params| params.k);
        match (self.core.carrier(conn), k) {
            (Some(session), Some(k)) => crate::core::window(session, k),
            _ => 0,
        }
    }

    /// Whether `generation` is still `conn`'s socket.
    fn current(&self, conn: usize, generation: u64) -> bool {
        self.slots
            .get(conn)
            .is_some_and(|slot| slot.generation == generation)
    }

    const fn check(&self, conn: usize) -> Result<(), Error> {
        if conn < self.slots.len() {
            Ok(())
        } else {
            Err(Error::NoSuchConnection(conn))
        }
    }

    /// Carries out a handle's request. Returns true after a shutdown, when the
    /// driver task is to end.
    async fn command(&mut self, command: Command) -> bool {
        let now = now();
        match command {
            Command::Send { conn, asdu, reply } => {
                let result = self.check(conn).and_then(|()| {
                    if asdu.is_empty() || asdu.len() > MAX_ASDU {
                        Err(Error::BadAsdu(asdu.len()))
                    } else {
                        self.core.send(conn, &asdu, now)
                    }
                });
                self.answer(result, reply);
            }
            Command::Start { conn, reply } => {
                let result = self.check(conn).and_then(|()| self.core.start(conn, now));
                self.answer(result, reply);
            }
            Command::Stop { conn, reply } => {
                let result = self.check(conn).and_then(|()| self.core.stop(conn, now));
                self.answer(result, reply);
            }
            Command::Close { conn, reply } => {
                let result = match self.slots.get(conn) {
                    None => Err(Error::NoSuchConnection(conn)),
                    Some(slot) if slot.writer.is_none() => Err(Error::NotConnected(conn)),
                    Some(_) => self.core.close(conn, now),
                };
                self.answer(result, reply);
            }
            Command::State { conn, reply } => {
                let _ = reply.send(self.core.state(conn).ok_or(Error::NoSuchConnection(conn)));
            }
            Command::Window { conn, reply } => {
                let _ = reply.send(self.check(conn).map(|()| self.window(conn)));
            }
            Command::Attach {
                conn,
                stream,
                reply,
            } => match self.free_slot(conn) {
                Ok(conn) => {
                    let _ = reply.send(Ok(conn));
                    self.attach(conn, stream);
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            },
            Command::Retransmit {
                failed,
                replay,
                reply,
            } => match self
                .check(failed)
                .and_then(|()| self.core.retransmit(failed, replay, now))
            {
                Ok((outcome, routed)) => {
                    self.perform(routed, None);
                    let _ = reply.send(Ok(outcome));
                    self.settle(&[]);
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            },
            Command::Shutdown { reply } => {
                self.shutdown().await;
                let _ = reply.send(());
                return true;
            }
        }
        false
    }

    /// Performs a request's actions, then answers it.
    fn answer(&mut self, result: Result<Vec<Routed>, Error>, reply: Reply<()>) {
        match result {
            Ok(routed) => {
                self.perform(routed, None);
                let _ = reply.send(Ok(()));
                self.settle(&[]);
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    /// The connection an attached socket goes to: the one named, if it has
    /// no socket, or for a group the first member without one.
    fn free_slot(&self, conn: Option<usize>) -> Result<usize, Error> {
        match conn {
            Some(conn) => match self.slots.get(conn) {
                None => Err(Error::NoSuchConnection(conn)),
                Some(slot) if slot.writer.is_some() => Err(Error::Busy(conn)),
                Some(_) => Ok(conn),
            },
            None if !self.group => Err(Error::ConnectionRequired),
            None => self
                .slots
                .iter()
                .position(|slot| slot.writer.is_none() && slot.dial.is_none())
                .ok_or(Error::NoFreeConnection),
        }
    }

    /// Closes every connection the way the application would (the pending
    /// acknowledgement, then the active close) and abandons every dial.
    async fn shutdown(&mut self) {
        for conn in 0..self.slots.len() {
            let Some(slot) = self.slots.get_mut(conn) else {
                continue;
            };
            if let Some(dial) = slot.dial.take() {
                dial.abort();
            }
            if slot.writer.is_none() {
                continue;
            }
            match self.core.close(conn, now()) {
                Ok(routed) if !routed.is_empty() => {
                    self.perform(routed, None);
                }
                _ => {}
            }
            self.detach(conn, "driver shut down".into(), true);
        }
        // Every close is on its way; let the peers see it before the task
        // ends, for at most the longest t1. A writer still busy then (a peer
        // that reads, but slowly) is abandoned, and its last frames and FIN
        // may not reach the peer.
        let longest = (0..self.slots.len())
            .filter_map(|conn| self.core.params(conn).map(|params| params.t1))
            .max()
            .unwrap_or_default();
        let mut closing = std::mem::take(&mut self.closing);
        let all = async {
            for task in &mut closing {
                let _ = task.await;
            }
        };
        if timeout(longest, all).await.is_err() {
            for task in &closing {
                task.abort();
            }
        }
    }
}

/// A connection's writer: frames go on the wire in the order they were
/// queued. A peer that takes longer than t1 to accept them cannot confirm them
/// within t1 either, so that ends the connection (clause 5.2's t1), reported
/// to the engine like a read error.
async fn write(
    mut writer: WriteHalf<Box<dyn AsyncStream>>,
    mut queue: mpsc::UnboundedReceiver<Out>,
    t1: Duration,
    conn: usize,
    generation: u64,
    reports: mpsc::UnboundedSender<Io>,
) {
    while let Some(out) = queue.recv().await {
        let result = match out {
            // Flushed at once: a stream that buffers (TLS) would otherwise
            // hold the frames until the next write.
            Out::Frames(frames) => {
                timeout(t1, async {
                    writer.write_all(&frames).await?;
                    writer.flush().await
                })
                .await
            }
            Out::Close => {
                let _ = timeout(t1, async {
                    writer.flush().await?;
                    writer.shutdown().await
                })
                .await;
                return;
            }
        };
        let reason = match result {
            Ok(Ok(())) => continue,
            Ok(Err(e)) => e.to_string(),
            Err(_) => "write timed out (t1)".to_string(),
        };
        let _ = reports.send(Io::Closed {
            conn,
            generation,
            reason,
        });
        return;
    }
}

/// A connection's reader: every chunk the socket yields goes to the engine,
/// then the reason it ended.
async fn read(
    mut reader: ReadHalf<Box<dyn AsyncStream>>,
    conn: usize,
    generation: u64,
    io: mpsc::Sender<Io>,
) {
    let mut buf = vec![0u8; 4096];
    let reason = loop {
        match reader.read(&mut buf).await {
            Ok(0) => break "peer closed the connection".to_string(),
            Ok(n) => {
                // `read` never reports more than the buffer holds.
                let data = buf.get(..n).map(<[u8]>::to_vec).unwrap_or_default();
                let bytes = Io::Bytes {
                    conn,
                    generation,
                    data,
                };
                if io.send(bytes).await.is_err() {
                    return;
                }
            }
            Err(e) => break e.to_string(),
        }
    };
    let _ = io
        .send(Io::Closed {
            conn,
            generation,
            reason,
        })
        .await;
}
