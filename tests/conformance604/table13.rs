//! 604 Table 13, *"Redundant link conformance test procedures"*, PDF page
//! indices 58–60 (printed 57–59), procedures `5.4.13.1`, `5.4.13.10`,
//! `5.4.13.20` and `5.4.13.30`. Every row is `Required` `M` and references
//! `IEC 60870-5-104:2006, 10` (three rows add `5.3`); the rows are paraphrased
//! on the tests.
//!
//! The table's NOTE bounds all four: the tests are required only of systems
//! that support redundant connections. The crate supports them
//! through `iec104::redundancy::RedundancyGroup`, so every row applies.
//!
//! # The harness: a redundancy group on several sockets
//!
//! The shared [`ControlledStation`](crate::conformance604::ControlledStation)
//! serves one connection. Table 13's Remark is about several connections to one
//! controlled station, exactly one of them Started and the rest Stopped, so
//! this module has its
//! own station under test, [`GroupUnderTest`]: one `RedundancyGroup` served over
//! N loopback sockets by one thread, in either role.
//!
//! - As the **controlled** station it listens on one port and gives each
//!   accepted connection the lowest free member index (so the order the mock
//!   peers connect in is the member order).
//! - As the **controlling** station it dials one address per member whenever
//!   `RedundancyGroup::tick` asks for it (clause 7.1: the controlling station is
//!   the one that establishes connections), and the mock controlled
//!   stations are listeners the test accepts on.
//!
//! The protocol behaviour is the library's and nothing else: every received
//! frame goes to `RedundancyGroup::on_frame_at`, every timer to
//! `RedundancyGroup::tick` with the real clock, every action returned is put on
//! the socket of the member it is routed to, and an `Action::ActiveClose`
//! closes that socket and is reported back with
//! `RedundancyGroup::on_connection_lost`. The harness adds only what 104 leaves
//! to the application, each as an explicit [`Policy`] switch:
//!
//! - `replay`: once the group's started connection is `Started`, what a failed
//!   connection left behind is handed back with
//!   `RedundancyGroup::retransmit_unconfirmed(.., Replay::Retransmit)`: 10.5
//!   leaves the retransmission of the ASDU to the application, and 5.4.13.10
//!   resumes with the still unacknowledged application messages where that is
//!   supported and they are present;
//! - `interrogate`: a controlling station sends `gi::request` once per naming
//!   when `RedundancyGroup::follow_up` asks for the station interrogation
//!   (10.3).
//!
//! Everything else the application does (a command, an event, a Start, a Stop)
//! is a step the test performs through [`GroupUnderTest::call`], which runs a
//! closure over the group on the station's own thread and puts its routed
//! actions on the wire. The mock peers are the shared
//! [`Peer`](crate::conformance604::Peer): they invent no behaviour, every frame
//! they send is spelled out in the test.
//!
//! "Inoperable" is simulated the only way loopback allows: the mock peer stops
//! answering. A connection that is physically cut (the rows allow that the
//! close may never arrive) cannot be produced on loopback; the station's side of it is the
//! same t1 expiry and the same active close, which is what the cases observe.
//!
//! # Direction (604 §5.1)
//!
//! §5.1 swaps "Controlling" and "Controlled" for the reverse direction. Table 13
//! names both stations explicitly where a row applies to both, and those rows
//! are driven in both roles:
//!
//! | Row | Controlling DUT | Controlled DUT |
//! | --- | --- | --- |
//! | `5.4.13.1` t3 on the Started connection | yes | yes |
//! | `5.4.13.1` t3 on all Stopped connections | yes | yes |
//! | `5.4.13.10` active close after t1 (by either station as primary) | yes | yes |
//! | `5.4.13.10` `STARTDT_ACT` over a Stopped connection | yes | not applicable |
//! | `5.4.13.10` `STARTDT_CON` there, active close of the old one | not applicable | yes |
//! | `5.4.13.10` no `M_EI`, unacknowledged data, General Interrogation | yes | yes |
//! | `5.4.13.10` counters kept per TCP connection | yes | yes |
//! | `5.4.13.20` active close of an inoperable connection | yes | yes |
//! | `5.4.13.20` new Stopped connection at regular intervals | yes | not applicable |
//! | `5.4.13.30` all rows | yes (the controlling rows) | yes (the controlled rows) |
//!
//! The "not applicable" cells are not reversible, by 104 itself:
//!
//! - only the controlling station sends `STARTDT_ACT` and `STOPDT_ACT` and only the
//!   controlled station answers them: clause 10.2 rule 4 has the controlling
//!   station choose which of the N connections is Started, and clause 5.3. `RedundancyGroup::start`, `stop` and `select` refuse a
//!   controlled group with `GroupError::CannotSelect`;
//! - only the controlling station establishes connections (clause 7.1 and
//!   10.2, see the reference on the `5.4.13.20` case), so only it retries one.
//!
//! §5.1's COT44-47 exception does not apply: no case here sends those causes.
//!
//! # Not automated
//!
//! - The rows' option of a fixed configured choice between two equivalent
//!   controlling stations: two equivalent controlling stations need two
//!   stations of the same rank and a configured selection between them; 104
//!   clause 10.2 rule 7 gives each controlling station its own redundancy
//!   group, so there is one controlling station per group here and the fixed
//!   selection is configuration, not a behaviour of the group under test.
//! - The Remark's point that how operational redundant systems use the
//!   mechanism varies, and needs further testing of its own, is outside what a loopback harness can represent (separate
//!   networks, routers, physical link loss).
//!
//! # Timing
//!
//! Every case uses short time-outs from `LinkParams` (t1 of 0.6 s to 5 s, t3 of
//! 0.3 s to 30 s, per member where a case needs members to differ, as 10.7
//! allows: it recommends that t0 to t3 be settable separately for each
//! connection of a redundancy group). Lower
//! bounds on elapsed time are asserted exactly, measured from an instant the
//! test knows to precede the station's own; upper bounds are only the bounded
//! read deadlines.

use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{Cause, TypeId};
use iec104::framed::Decoder;
use iec104::gi::{self, Scope};
use iec104::init::FollowUp;
use iec104::link::{Action, Role, State};
use iec104::params::LinkParams;
use iec104::redundancy::{GroupError, RedundancyGroup, Replay, Routed, Switchover};

use crate::conformance604::{CA, HELD_IOA, ORIGINATOR, Peer, asdu, deadline, interop, parse_frame};

// ------------------------------------------------------------ the harness

/// What the application of the station under test does of its own accord,
/// beyond the steps a test performs (see the module doc).
#[derive(Debug, Clone, Copy, Default)]
pub struct Policy {
    /// Replay what a failed connection left behind on the started connection
    /// once it is `Started` (10.5, `Replay::Retransmit`).
    pub replay: bool,
    /// Controlling station only: send the station interrogation when
    /// `RedundancyGroup::follow_up` asks for it (10.3).
    pub interrogate: bool,
}

/// One frame the station under test put on the wire.
#[derive(Debug, Clone)]
pub struct Sent {
    /// The member whose socket carried it.
    pub member: usize,
    /// When the station wrote it.
    pub at: Instant,
    /// Its control field.
    pub apci: Apci,
    /// Its ASDU (empty for U- and S-frames).
    pub asdu: Vec<u8>,
}

/// Everything the station under test did, returned by
/// [`GroupUnderTest::finish`].
#[derive(Debug, Default)]
pub struct GroupReport {
    /// Every frame sent, in order.
    pub sent: Vec<Sent>,
    /// Every active close the group asked for: member, instant, reason.
    pub closes: Vec<(usize, Instant, &'static str)>,
    /// Every switchover `RedundancyGroup::tick` reported.
    pub switchovers: Vec<Switchover>,
    /// Frames the group refused (`RedundancyGroup::on_frame_at` errors).
    pub refused: Vec<(usize, Apci, GroupError)>,
    /// Controlling station: every dial, with its instant and whether the
    /// connection came up.
    pub dials: Vec<(usize, Instant, bool)>,
    /// Every ASDU the group delivered to the application, per member.
    pub delivered: Vec<(usize, Vec<u8>)>,
    /// Members whose peer closed the socket.
    pub peer_closed: Vec<usize>,
}

impl GroupReport {
    /// The frames sent on one member, in order.
    pub fn sent_on(&self, member: usize) -> Vec<&Sent> {
        self.sent.iter().filter(|s| s.member == member).collect()
    }
}

type Job = Box<dyn FnOnce(&mut RedundancyGroup, Instant) -> Vec<Routed> + Send>;

/// The redundancy group under test, served on its own thread.
pub struct GroupUnderTest {
    jobs: Sender<Job>,
    handle: JoinHandle<Result<GroupReport, String>>,
    addr: Option<SocketAddr>,
}

impl GroupUnderTest {
    /// A **controlled** station: one member per parameter set, listening on a
    /// loopback port the mock controlling stations connect to.
    pub fn controlled(params: Vec<LinkParams>, policy: Policy) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("nonblocking listener: {e}"))?;
        let addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;
        let group = RedundancyGroup::new(Role::Controlled, params)
            .map_err(|e| format!("the group: {e:?}"))?;
        Ok(Self::spawn(
            group,
            Some(listener),
            Vec::new(),
            policy,
            Some(addr),
        ))
    }

    /// A **controlling** station: one member per parameter set, member `i`
    /// dialing `targets[i]`.
    pub fn controlling(
        params: Vec<LinkParams>,
        targets: Vec<SocketAddr>,
        policy: Policy,
    ) -> Result<Self, String> {
        let group = RedundancyGroup::new(Role::Controlling, params)
            .map_err(|e| format!("the group: {e:?}"))?;
        Ok(Self::spawn(group, None, targets, policy, None))
    }

    fn spawn(
        group: RedundancyGroup,
        listener: Option<TcpListener>,
        targets: Vec<SocketAddr>,
        policy: Policy,
        addr: Option<SocketAddr>,
    ) -> Self {
        let (jobs, rx) = mpsc::channel();
        let members = group.len();
        let engine = Engine {
            group,
            conns: (0..members).map(|_| None).collect(),
            listener,
            targets,
            policy,
            report: GroupReport::default(),
            last_started: None,
            interrogated: false,
        };
        let handle = thread::spawn(move || engine.run(&rx));
        Self { jobs, handle, addr }
    }

    /// The controlled station's listening address.
    pub const fn addr(&self) -> SocketAddr {
        self.addr.expect("only a controlled station listens")
    }

    /// Runs `step` over the group on the station's thread (the application's
    /// own call into the library), puts its routed actions on the wire and
    /// returns its value.
    pub fn call<T: Send + 'static>(
        &self,
        what: &str,
        step: impl FnOnce(&mut RedundancyGroup, Instant) -> Result<(T, Vec<Routed>), GroupError>
        + Send
        + 'static,
    ) -> Result<T, String> {
        let (tx, rx) = mpsc::channel();
        let job: Job = Box::new(move |group, now| match step(group, now) {
            Ok((value, routed)) => {
                let _ = tx.send(Ok(value));
                routed
            }
            Err(e) => {
                let _ = tx.send(Err(e));
                Vec::new()
            }
        });
        self.jobs
            .send(job)
            .map_err(|_| format!("{what}: the station under test has ended"))?;
        rx.recv_timeout(Duration::from_secs(5))
            .map_err(|e| format!("{what}: no answer from the station ({e})"))?
            .map_err(|e| format!("{what}: {e:?}"))
    }

    /// Reads the group's state on its own thread.
    pub fn look<T: Send + 'static>(
        &self,
        what: &str,
        read: impl FnOnce(&RedundancyGroup) -> T + Send + 'static,
    ) -> Result<T, String> {
        self.call(what, move |group, _| Ok((read(group), Vec::new())))
    }

    /// Polls the group until `holds` is true, failing at `limit`.
    pub fn wait_until(
        &self,
        what: &str,
        limit: Instant,
        holds: impl Fn(&RedundancyGroup) -> bool + Send + Sync + Clone + 'static,
    ) -> Result<(), String> {
        loop {
            let check = holds.clone();
            if self.look(what, move |group| check(group))? {
                return Ok(());
            }
            if Instant::now() >= limit {
                return Err(format!("{what}: not reached before the deadline"));
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// The application hands one user ASDU to the group
    /// (`RedundancyGroup::send_user_data_at`), naming the started connection
    /// (or member 0 while none is named, where the group holds it).
    pub fn send(&self, asdu: Vec<u8>) -> Result<(), String> {
        self.call("send_user_data", move |group, now| {
            let index = group.started_index().unwrap_or(0);
            Ok(((), group.send_user_data_at(index, &asdu, now)?))
        })
    }

    /// Controlling station: `RedundancyGroup::start_at` on one member.
    pub fn start(&self, member: usize) -> Result<(), String> {
        self.call("start", move |group, now| {
            Ok(((), group.start_at(member, now)?))
        })
    }

    /// Controlling station: `RedundancyGroup::stop_at` on one member.
    pub fn stop(&self, member: usize) -> Result<(), String> {
        self.call("stop", move |group, now| {
            Ok(((), group.stop_at(member, now)?))
        })
    }

    /// One member's connection state.
    pub fn state(&self, member: usize) -> Result<State, String> {
        self.look("state", move |group| group.state(member))?
            .map_err(|e| format!("state: {e:?}"))
    }

    /// Ends the station's thread and returns its report.
    pub fn finish(self) -> Result<GroupReport, String> {
        drop(self.jobs);
        self.handle
            .join()
            .map_err(|_| "the station under test panicked".to_string())?
    }
}

struct Conn {
    stream: TcpStream,
    decoder: Decoder,
}

struct Engine {
    group: RedundancyGroup,
    conns: Vec<Option<Conn>>,
    listener: Option<TcpListener>,
    targets: Vec<SocketAddr>,
    policy: Policy,
    report: GroupReport,
    last_started: Option<usize>,
    interrogated: bool,
}

impl Engine {
    fn run(mut self, jobs: &Receiver<Job>) -> Result<GroupReport, String> {
        loop {
            self.accept()?;
            loop {
                match jobs.try_recv() {
                    Ok(job) => {
                        let now = Instant::now();
                        let routed = job(&mut self.group, now);
                        self.perform(routed, now)?;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        for conn in self.conns.iter_mut().flatten() {
                            let _ = conn.stream.shutdown(Shutdown::Both);
                        }
                        return Ok(self.report);
                    }
                }
            }
            self.read()?;
            self.apply_policy()?;
            let now = Instant::now();
            let outcome = self.group.tick(now);
            self.report.switchovers.extend(outcome.switchovers);
            self.perform(outcome.routed, now)?;
            for member in outcome.connect {
                self.dial(member)?;
            }
            self.apply_policy()?;
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn lost(&mut self, member: usize) -> Result<(), String> {
        if let Some(conn) = self.conns[member].take() {
            let _ = conn.stream.shutdown(Shutdown::Both);
        }
        self.group
            .on_connection_lost(member)
            .map_err(|e| format!("on_connection_lost({member}): {e:?}"))
    }

    fn established(&mut self, member: usize, stream: TcpStream) -> Result<(), String> {
        stream
            .set_nonblocking(true)
            .map_err(|e| format!("nonblocking: {e}"))?;
        stream
            .set_nodelay(true)
            .map_err(|e| format!("nodelay: {e}"))?;
        self.group
            .on_connection_established(member, Instant::now())
            .map_err(|e| format!("on_connection_established({member}): {e:?}"))?;
        self.conns[member] = Some(Conn {
            stream,
            decoder: Decoder::new(),
        });
        Ok(())
    }

    /// Controlled station: every pending connection gets the lowest free
    /// member.
    fn accept(&mut self) -> Result<(), String> {
        loop {
            let Some(listener) = &self.listener else {
                return Ok(());
            };
            match listener.accept() {
                Ok((stream, _)) => match self.conns.iter().position(Option::is_none) {
                    Some(member) => self.established(member, stream)?,
                    None => drop(stream),
                },
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(format!("accept: {e}")),
            }
        }
    }

    /// Controlling station: one dial `RedundancyGroup::tick` asked for.
    fn dial(&mut self, member: usize) -> Result<(), String> {
        let at = Instant::now();
        if let Ok(stream) =
            TcpStream::connect_timeout(&self.targets[member], Duration::from_millis(500))
        {
            self.report.dials.push((member, at, true));
            self.established(member, stream)
        } else {
            self.report.dials.push((member, at, false));
            self.group
                .on_connection_lost(member)
                .map_err(|e| format!("refused dial of {member}: {e:?}"))
        }
    }

    fn read(&mut self) -> Result<(), String> {
        for member in 0..self.conns.len() {
            let mut frames = Vec::new();
            let mut eof = false;
            if let Some(conn) = &mut self.conns[member] {
                let mut buf = [0u8; 2048];
                loop {
                    match conn.stream.read(&mut buf) {
                        Ok(0) => {
                            eof = true;
                            break;
                        }
                        Ok(n) => conn.decoder.push(&buf[..n]),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => {
                            eof = true;
                            break;
                        }
                    }
                }
                loop {
                    match conn.decoder.next_frame_len() {
                        Ok(Some(_)) => {}
                        Ok(None) => break,
                        Err(_) => {
                            let _ = conn.decoder.next_frame();
                            continue;
                        }
                    }
                    let frame = conn
                        .decoder
                        .next_frame()
                        .map_err(|e| format!("framing: {e}"))?
                        .ok_or("the decoder promised a frame")?
                        .to_vec();
                    frames.push(frame);
                }
            }
            for frame in frames {
                if self.conns[member].is_none() {
                    break;
                }
                let (apci, asdu) = parse_frame(&frame)?;
                let now = Instant::now();
                match self.group.on_frame_at(member, apci, now) {
                    Ok(routed) => {
                        let delivered = routed.iter().any(|r| {
                            r.member == member
                                && r.actions
                                    .iter()
                                    .any(|a| matches!(a, Action::DeliverData { .. }))
                        });
                        if delivered {
                            self.report.delivered.push((member, asdu));
                        }
                        self.perform(routed, now)?;
                    }
                    Err(e) => self.report.refused.push((member, apci, e)),
                }
            }
            if eof && self.conns[member].is_some() {
                self.report.peer_closed.push(member);
                self.lost(member)?;
            }
        }
        Ok(())
    }

    /// Puts routed actions on their sockets. `now` is the instant the group
    /// was called with, so the report's instants are the ones its timers were
    /// armed and checked against.
    fn perform(&mut self, routed: Vec<Routed>, now: Instant) -> Result<(), String> {
        for Routed { member, actions } in routed {
            for action in actions {
                if let Action::ActiveClose(why) = action {
                    self.report.closes.push((member, now, why));
                    self.lost(member)?;
                    continue;
                }
                let octets = interop::encode_action_bytes(&action)?;
                if octets.is_empty() {
                    continue;
                }
                let (apci, asdu) = parse_frame(&octets)?;
                let Some(conn) = &mut self.conns[member] else {
                    return Err(format!(
                        "{apci:?} routed to member {member}, which has no socket"
                    ));
                };
                if conn.stream.write_all(&octets).is_err() {
                    self.report.peer_closed.push(member);
                    self.lost(member)?;
                    continue;
                }
                self.report.sent.push(Sent {
                    member,
                    at: now,
                    apci,
                    asdu,
                });
            }
        }
        Ok(())
    }

    fn apply_policy(&mut self) -> Result<(), String> {
        let started = self.group.started_index();
        if started != self.last_started {
            self.last_started = started;
            self.interrogated = false;
        }
        let Some(index) = started else {
            return Ok(());
        };
        if self.group.state(index).map_err(|e| format!("{e:?}"))? != State::Started {
            return Ok(());
        }
        let now = Instant::now();
        if self.policy.replay {
            for member in 0..self.group.len() {
                let held = self
                    .group
                    .member(member)
                    .map_err(|e| format!("{e:?}"))?
                    .left_behind()
                    .len();
                if held > 0 {
                    let (_, routed) = self
                        .group
                        .retransmit_unconfirmed_at(member, Replay::Retransmit, now)
                        .map_err(|e| format!("replay of {member}: {e:?}"))?;
                    self.perform(routed, now)?;
                }
            }
        }
        if self.policy.interrogate
            && !self.interrogated
            && self.group.role() == Role::Controlling
            && self.group.follow_up(index).map_err(|e| format!("{e:?}"))?
                == Some(FollowUp::StationInterrogation)
        {
            let request = gi::request(Scope::Station, CA, ORIGINATOR)
                .map_err(|e| format!("the interrogation: {e:?}"))?;
            let routed = self
                .group
                .send_user_data_at(index, &request, now)
                .map_err(|e| format!("the interrogation: {e:?}"))?;
            self.interrogated = true;
            self.perform(routed, now)?;
        }
        Ok(())
    }
}

// --------------------------------------------------------- the mock peers

/// Link parameters for one member: the standard's defaults with the given
/// time-outs (t0 is 0.3 s everywhere, so a refused dial is retried quickly).
fn params(t1_ms: u64, t2_ms: u64, t3_ms: u64) -> LinkParams {
    LinkParams {
        t0: Duration::from_millis(300),
        t1: Duration::from_millis(t1_ms),
        t2: Duration::from_millis(t2_ms),
        t3: Duration::from_millis(t3_ms),
        ..LinkParams::default()
    }
}

/// Mock controlling stations for a controlled station under test: each one
/// connects only once the previous one has its member, so peer `i` is member
/// `i`.
fn connect_peers(dut: &GroupUnderTest, count: usize) -> Result<Vec<Peer>, String> {
    let mut peers = Vec::new();
    for member in 0..count {
        peers.push(Peer::connect(dut.addr())?);
        dut.wait_until("the connection is accepted", deadline(5), move |group| {
            group
                .member(member)
                .is_ok_and(|m| m.session().is_connected())
        })?;
    }
    Ok(peers)
}

/// Listeners for the mock controlled stations of a controlling station under
/// test, and their addresses (member `i` dials `addrs[i]`).
fn listeners(count: usize) -> Result<(Vec<TcpListener>, Vec<SocketAddr>), String> {
    let mut listeners = Vec::new();
    let mut addrs = Vec::new();
    for _ in 0..count {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
        addrs.push(listener.local_addr().map_err(|e| format!("addr: {e}"))?);
        listeners.push(listener);
    }
    Ok((listeners, addrs))
}

/// Accepts the station's dial on one mock controlled station.
fn accept_peer(listener: &TcpListener, limit: Instant) -> Result<Peer, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking: {e}"))?;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_nonblocking(false)
                    .map_err(|e| format!("blocking: {e}"))?;
                stream
                    .set_nodelay(true)
                    .map_err(|e| format!("nodelay: {e}"))?;
                return Ok(Peer {
                    stream,
                    decoder: Decoder::new(),
                    sent: Vec::new(),
                    received: Vec::new(),
                });
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if Instant::now() >= limit {
                    return Err("the station did not dial before the deadline".into());
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(e) => return Err(format!("accept: {e}")),
        }
    }
}

/// Reads frames until the station closes the connection, returning what came
/// before the close and the instant it was seen.
fn expect_closed(peer: &mut Peer, limit: Instant) -> Result<(Vec<Apci>, Instant), String> {
    let mut seen = Vec::new();
    loop {
        match peer.read_frame(limit) {
            Ok((apci, _)) => seen.push(apci),
            Err(e) if e.contains("closed") || e.starts_with("read:") => {
                return Ok((seen, Instant::now()));
            }
            Err(e) => return Err(format!("the connection stayed open: {e} (saw {seen:?})")),
        }
    }
}

/// Requires the station to send nothing on this connection for `quiet`.
fn expect_nothing(peer: &mut Peer, quiet: Duration) -> Result<(), String> {
    match peer.read_frame(Instant::now() + quiet) {
        Err(e) if e.contains("deadline") => Ok(()),
        Err(e) => Err(format!("expected silence, got: {e}")),
        Ok((apci, asdu)) => Err(format!("expected silence, got {apci:?} {asdu:02x?}")),
    }
}

/// One frame as a mock peer reads it: its control field and its ASDU.
type Frame = (Apci, Vec<u8>);

/// Reads frames until one satisfies `wanted`, returning the frames before it
/// and the one that matched.
fn read_until(
    peer: &mut Peer,
    limit: Instant,
    wanted: impl Fn(&Apci) -> bool,
) -> Result<(Vec<Frame>, Frame), String> {
    let mut before = Vec::new();
    loop {
        let (apci, asdu) = peer.read_frame(limit)?;
        if wanted(&apci) {
            return Ok((before, (apci, asdu)));
        }
        before.push((apci, asdu));
    }
}

/// An event of the controlled station: `M_SP_NA_1` with cause `<3>`
/// spontaneous, one object per event so each is recognisable on the wire.
fn event(n: u32) -> Vec<u8> {
    asdu(
        TypeId::MSpNa1.to_u8(),
        Cause::Spontaneous.to_u8(),
        CA,
        HELD_IOA + n,
        0x01,
    )
}

/// A command of the controlling station: `C_SC_NA_1` with cause `<6>`
/// activation, one object per command.
fn command(n: u32) -> Vec<u8> {
    asdu(
        TypeId::CScNa1.to_u8(),
        Cause::Activation.to_u8(),
        CA,
        HELD_IOA + n,
        0x01,
    )
}

const fn seq(ns: u16, nr: u16) -> (SeqNo, SeqNo) {
    (SeqNo::new(ns), SeqNo::new(nr))
}

/// The sequence numbers of an I-frame, or a panic naming what came instead.
fn numbers(apci: Apci, what: &str) -> (u16, u16) {
    match apci {
        Apci::I { ns, nr } => (ns.get(), nr.get()),
        other => panic!("{what}: an I-frame was expected, got {other:?}"),
    }
}

/// True for an `M_EI_NA_1` (type 70), the end of initialisation.
fn is_end_of_initialisation(asdu: &[u8]) -> bool {
    asdu.first() == Some(&TypeId::MEiNa1.to_u8())
}

// ------------------------------------------------------------- 5.4.13.1

/// The t3 check of `5.4.13.1`, run on every peer twice: each connection is
/// tested after t3 of silence, and again t3 after the confirmation.
/// `last_heard[i]` is an instant at or before the station last received a
/// frame on connection `i`.
fn t3_rounds(peers: &mut [Peer], mut last_heard: Vec<Instant>, t3: Duration) {
    for round in 1..=2 {
        for (member, peer) in peers.iter_mut().enumerate() {
            peer.expect_u(UFunction::TestFrAct, deadline(5))
                .unwrap_or_else(|e| {
                    panic!(
                        "5.4.13.1 (connection {member}, round {round}): no TESTFR act after t3: {e}"
                    )
                });
            let waited = last_heard[member].elapsed();
            assert!(
                waited >= t3,
                "5.4.13.1 (connection {member}, round {round}): the TESTFR act came {waited:?} \
                 after the last frame the station received, before t3 = {t3:?} of inactivity"
            );
            last_heard[member] = Instant::now();
            peer.send_u(UFunction::TestFrCon)
                .expect("the peer confirms the test");
        }
    }
}

/// 604 Table 13 (1 of 3), PDF page index 58 (printed 57), procedure
/// **`5.4.13.1`**, *"Periodic check of ALL redundant connections"*, both rows,
/// `Reference` `IEC 60870-5-104:2006, 10`, `Required` `M`:
///
/// 1. Each of the controlling and the controlled station watches the Started
///    connection for the configured idle time t3 and begins a TESTFR procedure
///    when t3 runs out; every time-out rule applies.
/// 2. Each of them does the same on every Stopped connection.
///
/// DUT: the **controlled** station, three connections, the first started by the
/// mock controlling station and two stopped. Expected values: 104 clause 10.2
/// rule 5 (every logical connection of a redundancy group shall be supervised
/// with test frames as 5.2 describes), and clause 5.2's timer: the TESTFR act
/// comes no earlier than t3 after the last received frame (any received I, S or
/// U frame restarts t3), on every
/// connection, and again t3 after the confirmation.
#[test]
fn clause_5_4_13_1_the_controlled_station_tests_every_connection_after_t3() {
    let t3 = Duration::from_millis(400);
    let p = params(2_000, 1_000, 400);
    let dut = GroupUnderTest::controlled(vec![p; 3], Policy::default()).expect("the station");
    let mut peers = connect_peers(&dut, 3).expect("three connections");

    let mut last_heard = Vec::new();
    // Connection 0 is started; its STARTDT act is the last frame the station
    // hears on it.
    last_heard.push(Instant::now());
    peers[0]
        .start_data_transfer()
        .expect("5.4.13.1: connection 0 is started");
    // Connections 1 and 2 stay stopped; a TESTFR of the peer's own is the last
    // frame the station hears on each.
    for peer in &mut peers[1..] {
        last_heard.push(Instant::now());
        peer.send_u(UFunction::TestFrAct).expect("the peer's test");
        peer.expect_u(UFunction::TestFrCon, deadline(5))
            .expect("5.2: TESTFR act is confirmed on a stopped connection");
    }

    t3_rounds(&mut peers, last_heard, t3);

    assert_eq!(
        dut.look(
            "started",
            iec104::redundancy::RedundancyGroup::started_index
        )
        .expect("look"),
        Some(0),
        "5.4.13.1: the checks change nothing about which connection is started"
    );
    let report = dut.finish().expect("the station ends cleanly");
    assert!(
        report.closes.is_empty(),
        "5.4.13.1: every test was confirmed within t1, so nothing is closed: {:?}",
        report.closes
    );
}

/// 604 Table 13 (1 of 3), PDF page index 58 (printed 57), procedure
/// **`5.4.13.1`**, the same two rows as
/// [`clause_5_4_13_1_the_controlled_station_tests_every_connection_after_t3`],
/// which apply to the controlling and the controlled station alike.
///
/// DUT: the **controlling** station, three connections to three mock
/// controlled stations, the first started by the station itself
/// (`RedundancyGroup::start`, 10.3) and two stopped. Expected values: the same
/// rule 5 and clause 5.2 t3 as the controlled case.
#[test]
fn clause_5_4_13_1_the_controlling_station_tests_every_connection_after_t3() {
    let t3 = Duration::from_millis(400);
    let p = params(2_000, 1_000, 400);
    let (listeners, addrs) = listeners(3).expect("listeners");
    let dut =
        GroupUnderTest::controlling(vec![p; 3], addrs, Policy::default()).expect("the station");
    let mut peers: Vec<Peer> = listeners
        .iter()
        .map(|l| accept_peer(l, deadline(5)).expect("the station dials every member"))
        .collect();
    dut.wait_until("all three connected", deadline(5), |g| {
        g.members().iter().all(|m| m.session().is_connected())
    })
    .expect("connected");

    dut.start(0).expect("10.3: the station starts connection 0");
    peers[0]
        .expect_u(UFunction::StartDtAct, deadline(5))
        .expect("the STARTDT act on connection 0");
    let mut last_heard = vec![Instant::now()];
    peers[0]
        .send_u(UFunction::StartDtCon)
        .expect("the peer confirms");
    for peer in &mut peers[1..] {
        last_heard.push(Instant::now());
        peer.send_u(UFunction::TestFrAct).expect("the peer's test");
        peer.expect_u(UFunction::TestFrCon, deadline(5))
            .expect("5.2: TESTFR act is confirmed on a stopped connection");
    }

    t3_rounds(&mut peers, last_heard, t3);

    assert_eq!(dut.state(0).expect("state"), State::Started);
    let report = dut.finish().expect("the station ends cleanly");
    assert!(
        report.closes.is_empty(),
        "5.4.13.1: every test was confirmed within t1, so nothing is closed: {:?}",
        report.closes
    );
}

// ------------------------------------------------------------ 5.4.13.10

/// 604 Table 13 (1 of 3), PDF page index 58 (printed 57), procedure
/// **`5.4.13.10`** (re-establishing a lost Started connection when redundant
/// connections are available, the automatic switch-over), `Reference`
/// `IEC 60870-5-104:2006, 10`, `Required` `M`, first row.
///
/// Requirement: once the Started connection has been inoperable for longer
/// than t1 permits, the primary station, controlling or controlled, starts a
/// TCP active close on it (the close may never reach the peer).
///
/// DUT: the **controlled** station as the primary station: it sends an event on
/// the started connection and the peer never acknowledges it. Expected values:
/// 104 figure 17's `Timeout t1[]/Active close` out of `STARTED connection`
/// (clause 5.3), no earlier than t1 after the I-frame; the stopped connection is
/// left alone (10.2 rule 4: the controlled station switches nothing over, so
/// no data appears on it).
#[test]
fn clause_5_4_13_10_the_controlled_station_closes_the_started_connection_after_t1() {
    let t1 = Duration::from_millis(600);
    let p = params(600, 300, 30_000);
    let dut = GroupUnderTest::controlled(vec![p; 2], Policy::default()).expect("the station");
    let mut peers = connect_peers(&dut, 2).expect("two connections");
    peers[0]
        .start_data_transfer()
        .expect("connection 0 started");

    let before = Instant::now();
    dut.send(event(1)).expect("the event");
    let (apci, asdu) = peers[0]
        .expect_i(deadline(5))
        .expect("the event on connection 0");
    assert_eq!(numbers(apci, "5.4.13.10"), (0, 0));
    assert_eq!(asdu, event(1));

    // The peer is inoperable: it never acknowledges.
    let (_, closed_at) = expect_closed(&mut peers[0], deadline(5))
        .expect("5.4.13.10: the station closes the started connection");
    let waited = closed_at - before;
    assert!(
        waited >= t1,
        "5.4.13.10: the close came {waited:?} after the unacknowledged I-frame, before t1 = {t1:?}"
    );

    // The stopped connection is alive and carries nothing.
    peers[1]
        .send_u(UFunction::TestFrAct)
        .expect("the peer's test");
    peers[1]
        .expect_u(UFunction::TestFrCon, deadline(5))
        .expect("5.4.13.10: the stopped connection is still open");

    let report = dut.finish().expect("the station ends cleanly");
    let closed: Vec<usize> = report.closes.iter().map(|c| c.0).collect();
    assert_eq!(
        closed,
        vec![0],
        "5.4.13.10: only the started connection is closed"
    );
    assert!(
        report.sent_on(1).iter().all(|s| !s.apci.is_i_format()),
        "5.4.13.10: the controlled station puts no data on a stopped connection"
    );
}

/// The controlling-station prefix of `5.4.13.10`: two connections, the first
/// started and carrying a command that is never acknowledged. Returns the
/// station, both peers (the first closed by now), the instant before the
/// command and the instant the close was seen.
///
/// Before the command the peer sends one event on connection 0, so that
/// connection's receive counter is 1 when the command goes out: a number a new
/// connection must not inherit. With [`Policy::interrogate`] the station's
/// interrogation goes out on connection 0 first and the event acknowledges it,
/// so the command is the one unacknowledged frame either way.
fn controlling_switchover(policy: Policy) -> (GroupUnderTest, Vec<Peer>, Instant, Instant) {
    let p = params(600, 300, 30_000);
    let (listeners, addrs) = listeners(2).expect("listeners");
    let dut = GroupUnderTest::controlling(vec![p; 2], addrs, policy).expect("the station");
    let mut peers: Vec<Peer> = listeners
        .iter()
        .map(|l| accept_peer(l, deadline(5)).expect("the station dials every member"))
        .collect();
    // No second connection on member 0's address: a redial is refused.
    drop(listeners);
    dut.wait_until("both connected", deadline(5), |g| {
        g.members().iter().all(|m| m.session().is_connected())
    })
    .expect("connected");

    dut.start(0).expect("10.3: the station starts connection 0");
    peers[0]
        .expect_u(UFunction::StartDtAct, deadline(5))
        .expect("the STARTDT act");
    peers[0]
        .send_u(UFunction::StartDtCon)
        .expect("the peer confirms");
    dut.wait_until("connection 0 started", deadline(5), |g| {
        g.state(0) == Ok(State::Started)
    })
    .expect("started");
    let sent = if policy.interrogate {
        let (apci, asdu) = peers[0]
            .expect_i(deadline(5))
            .expect("the interrogation on connection 0");
        assert_eq!(numbers(apci, "setup"), (0, 0));
        assert_eq!(asdu.first(), Some(&TypeId::CIcNa1.to_u8()));
        1
    } else {
        0
    };
    let (ns, nr) = seq(0, sent);
    peers[0]
        .send_i(ns, nr, &event(1))
        .expect("the peer's event");
    dut.wait_until("the event is received", deadline(5), |g| {
        g.member(0).is_ok_and(|m| m.session().v_r().get() == 1)
    })
    .expect("received");

    let before = Instant::now();
    dut.send(command(1)).expect("the command");
    let (apci, asdu) = peers[0]
        .expect_i(deadline(5))
        .expect("the command on connection 0");
    assert_eq!(numbers(apci, "5.4.13.10"), (sent, 1));
    assert_eq!(asdu, command(1));
    let (_, closed_at) = expect_closed(&mut peers[0], deadline(5))
        .expect("5.4.13.10: the station closes the started connection");
    (dut, peers, before, closed_at)
}

/// 604 Table 13 (1 of 3), PDF page index 58 (printed 57), procedure
/// **`5.4.13.10`**, first and second rows, `Reference`
/// `IEC 60870-5-104:2006, 10`, `Required` `M`:
///
/// 1. Once the Started connection has been inoperable for longer than t1
///    permits, the primary station, controlling or controlled, starts a TCP
///    active close on it (the close may never reach the peer).
/// 2. Once it sees the Started connection is gone, the controlling station
///    (where two are equivalent, it may be a fixed configured choice) makes a
///    new Started connection by sending a STARTDT act over one of the
///    redundant connections to the same controlled station that are still
///    Stopped.
///
/// DUT: the **controlling** station as the primary station: its command on the
/// started connection is never acknowledged. Expected values: figure 18's
/// `Timeout t1[]/Active close` no earlier than t1 after the command, and 104
/// clause 10.5 (index 128): when t1 has run out, one of the Stopped connections
/// is started with the STARTDT function, i.e. a `STARTDT act` on connection 1,
/// sent no earlier than the close.
#[test]
fn clause_5_4_13_10_the_controlling_station_closes_after_t1_and_starts_a_stopped_connection() {
    let t1 = Duration::from_millis(600);
    let (dut, mut peers, before, closed_at) = controlling_switchover(Policy::default());
    let waited = closed_at - before;
    assert!(
        waited >= t1,
        "5.4.13.10: the close came {waited:?} after the unacknowledged command, before t1 = {t1:?}"
    );
    let (skipped, _) = read_until(&mut peers[1], deadline(5), |apci| {
        *apci == Apci::U(UFunction::StartDtAct)
    })
    .expect("5.4.13.10: a STARTDT act over the stopped connection");
    assert!(
        skipped.is_empty(),
        "5.4.13.10: the STARTDT act is the first frame on the stopped connection: {skipped:?}"
    );
    peers[1]
        .send_u(UFunction::StartDtCon)
        .expect("the peer confirms");
    dut.wait_until("connection 1 started", deadline(5), |g| {
        g.started_index() == Some(1) && g.state(1) == Ok(State::Started)
    })
    .expect("5.4.13.10: connection 1 is the new started connection");

    let report = dut.finish().expect("the station ends cleanly");
    let close = report
        .closes
        .iter()
        .find(|c| c.0 == 0)
        .expect("the close of connection 0");
    let act = report
        .sent_on(1)
        .into_iter()
        .find(|s| s.apci == Apci::U(UFunction::StartDtAct))
        .expect("the act");
    assert!(
        act.at >= close.1,
        "5.4.13.10: the new Started connection is created after detection that the old one \
         is no longer present"
    );
    assert!(
        matches!(
            report.switchovers.first(),
            Some(Switchover::Automatic {
                failed: 0,
                started: 1,
                ..
            })
        ),
        "5.4.13.10: the switch-over is automatic, from 0 to 1: {:?}",
        report.switchovers
    );
}

/// 604 Table 13 (1 of 3), PDF page index 58 (printed 57), procedure
/// **`5.4.13.10`**, fourth and fifth rows, `Reference`
/// `IEC 60870-5-104:2006, 10` and `5.3`, `Required` `M`:
///
/// 1. After the Started connection is re-established, no `M_EI` (end of
///    initialisation) goes to the controlling station, and none is needed.
///    Normal operation resumes with the application messages still
///    unacknowledged (where supported and present), and the general
///    interrogation begins.
/// 2. The send and receive counters are not reset to 0 while the TCP
///    connection stays up: every TCP connection keeps its own counters,
///    whatever STARTDT, STOPDT or switch-over happens.
///
/// DUT: the **controlling** station, with the replay and the interrogation of
/// [`Policy`] switched on (the row's "where supported"). Expected values:
///
/// - the mock controlled station sends no `M_EI`, and the station carries on
///   without one: the unacknowledged command goes out again on connection 1
///   (10.5: the command moves to the new Started connection, for instance by
///   retransmitting the ASDU there), and the station interrogation follows
///   (10.3: the controlling station shall start a station interrogation as soon
///   as possible once one connection is Started; 10.5 gives a station
///   interrogation after a switch-over as an example): `C_IC_NA_1`, cause
///   `<6>`, `QOI` 20 (5-101 clause 7.3.4.1);
/// - both carry connection 1's own counters: `N(S)` 0 then 1 and `N(R)` 0,
///   not connection 0's `N(S)` 2 / `N(R)` 1 (10.2, index 118: the counters of
///   each connection of a redundancy group run independently of STARTDT and
///   STOPDT);
/// - the peer's first I-frame on connection 1 carries `N(S)` 0 and is
///   accepted and acknowledged with `N(R)` 1 (clause 5.1).
#[test]
fn clause_5_4_13_10_the_controlling_station_resumes_with_its_own_counters_and_interrogates() {
    let policy = Policy {
        replay: true,
        interrogate: true,
    };
    let (dut, mut peers, _, _) = controlling_switchover(policy);
    peers[1]
        .expect_u(UFunction::StartDtAct, deadline(5))
        .expect("the STARTDT act on connection 1");
    peers[1]
        .send_u(UFunction::StartDtCon)
        .expect("the peer confirms; it sends no M_EI");

    let mut data = Vec::new();
    while data.len() < 2 {
        let (apci, asdu) = peers[1]
            .expect_i(deadline(5))
            .expect("5.4.13.10: normal operation continues on connection 1");
        data.push((numbers(apci, "5.4.13.10"), asdu));
    }
    let replayed = data
        .iter()
        .find(|(_, asdu)| *asdu == command(1))
        .expect("5.4.13.10: the unacknowledged command is sent again");
    let interrogation = data
        .iter()
        .find(|(_, asdu)| asdu.first() == Some(&TypeId::CIcNa1.to_u8()))
        .expect("5.4.13.10: the General Interrogation begins");
    assert_eq!(
        interrogation.1[2],
        Cause::Activation.to_u8(),
        "5.4.13.10: the interrogation is an activation"
    );
    assert_eq!(
        *interrogation.1.last().expect("QOI"),
        20,
        "5.4.13.10: QOI 20, station interrogation"
    );
    let mut numbering: Vec<(u16, u16)> = data.iter().map(|(n, _)| *n).collect();
    numbering.sort_unstable();
    assert_eq!(
        numbering,
        vec![(0, 0), (1, 0)],
        "5.4.13.10: connection 1 numbers with its own counters, not connection 0's \
         (the replay was {:?})",
        replayed.0
    );

    let (ns, nr) = seq(0, 2);
    peers[1]
        .send_i(ns, nr, &event(2))
        .expect("the peer's first event on connection 1");
    let (_, (ack, _)) = read_until(&mut peers[1], deadline(5), |apci| {
        matches!(apci, Apci::S { .. })
    })
    .expect("5.4.13.10: the event is acknowledged");
    assert_eq!(
        ack,
        Apci::S { nr: SeqNo::new(1) },
        "5.4.13.10: connection 1's receive counter starts at its own 0"
    );

    let report = dut.finish().expect("the station ends cleanly");
    assert!(
        report
            .delivered
            .iter()
            .all(|(_, asdu)| !is_end_of_initialisation(asdu)),
        "the mock sent no M_EI"
    );
}

/// 604 Table 13 (1 of 3), PDF page index 58 (printed 57), procedure
/// **`5.4.13.10`**, third row, `Reference` `IEC 60870-5-104:2006, 10`,
/// `Required` `M`:
///
/// Requirement: the controlled station completes the new Started connection by
/// answering with a STARTDT con on the connection the STARTDT act arrived on,
/// and sends an active close on the old Started connection.
///
/// DUT: the **controlled** station. Its started connection is inoperable from
/// the controlling side (the peer has gone silent) but not yet timed out at the
/// station (t1 is 5 s, no data is outstanding), when the peer sends STARTDT act
/// on the stopped connection. Expected values: 104 clause 10.2 (index 118):
/// station B takes the connection its latest `STARTDT_ACT` arrived on as the
/// Started one, and confirms with a `STARTDT_CON`; and 10.7 (index 136): a start
/// on a new connection closes at once every connection not in the STOPPED
/// state. Hence the con on connection 1, the
/// close of connection 0 without waiting for any time-out, and the next event
/// on connection 1.
#[test]
fn clause_5_4_13_10_the_controlled_station_confirms_on_the_new_connection_and_closes_the_old() {
    let p = params(5_000, 1_000, 30_000);
    let dut = GroupUnderTest::controlled(vec![p; 2], Policy::default()).expect("the station");
    let mut peers = connect_peers(&dut, 2).expect("two connections");
    peers[0]
        .start_data_transfer()
        .expect("connection 0 started");

    let before = Instant::now();
    peers[1]
        .send_u(UFunction::StartDtAct)
        .expect("the act on connection 1");
    let (skipped, _) = read_until(&mut peers[1], deadline(5), |apci| {
        *apci == Apci::U(UFunction::StartDtCon)
    })
    .expect("5.4.13.10: STARTDT con over the connection the act came on");
    assert!(skipped.is_empty(), "nothing precedes the con: {skipped:?}");
    let (on_old, closed_at) = expect_closed(&mut peers[0], deadline(5))
        .expect("5.4.13.10: the station closes the old Started connection");
    assert!(
        on_old.iter().all(|apci| !apci.is_i_format()),
        "no data on the old connection: {on_old:?}"
    );
    assert!(
        closed_at - before < Duration::from_millis(5_000),
        "5.4.13.10: the close is the Start's, not a t1 expiry"
    );

    dut.send(event(1)).expect("the next event");
    let (apci, asdu) = peers[1]
        .expect_i(deadline(5))
        .expect("the event goes out on the new Started connection");
    assert_eq!(numbers(apci, "5.4.13.10"), (0, 0));
    assert_eq!(asdu, event(1));
    assert_eq!(
        dut.look(
            "started",
            iec104::redundancy::RedundancyGroup::started_index
        )
        .expect("look"),
        Some(1)
    );
    let report = dut.finish().expect("the station ends cleanly");
    let closed: Vec<usize> = report.closes.iter().map(|c| c.0).collect();
    assert_eq!(
        closed,
        vec![0],
        "5.4.13.10: the old Started connection is closed"
    );
}

/// 604 Table 13 (1 of 3), PDF page index 58 (printed 57), procedure
/// **`5.4.13.10`**, fourth and fifth rows (paraphrased on
/// [`clause_5_4_13_10_the_controlling_station_resumes_with_its_own_counters_and_interrogates`]),
/// `Required` `M`.
///
/// DUT: the **controlled** station, with the replay of [`Policy`] switched on
/// (the row's "where supported"). Connection 1 carries traffic first, so its
/// counters are not 0 when it is started again: the peer starts it, the
/// station sends event 1 (`N(S)` 0) and the peer command 1 (`N(S)` 0); a manual
/// switch-over (STOPDT on 1, STARTDT on 0) follows; event 2 on connection 0 is
/// never acknowledged, t1 closes connection 0, and the peer starts connection 1
/// again. Expected values:
///
/// - no `M_EI` on connection 1 (the row), only its STARTDT con and then data;
/// - event 2, which was never acknowledged, is sent again (10.6, index 132:
///   after a switch-over, user data still unconfirmed is retransmitted on the
///   new Started connection);
/// - with connection 1's own counters as they were: `N(S)` 1 (after event 1)
///   and `N(R)` 1 (after command 1), not reset to 0 and not connection 0's (the
///   fifth row; 10.2, index 118: the counters of each connection of a
///   redundancy group run independently of STARTDT and STOPDT);
/// - the peer's command 2 with `N(S)` 1 is accepted and acknowledged with
///   `N(R)` 2 (clause 5.1).
#[test]
fn clause_5_4_13_10_the_controlled_station_resumes_with_the_counters_of_the_connection() {
    let p = params(600, 300, 30_000);
    let policy = Policy {
        replay: true,
        interrogate: false,
    };
    let dut = GroupUnderTest::controlled(vec![p; 2], policy).expect("the station");
    let mut peers = connect_peers(&dut, 2).expect("two connections");

    // Connection 1 first: one event each way.
    peers[1]
        .start_data_transfer()
        .expect("connection 1 started");
    dut.send(event(1)).expect("event 1");
    let (apci, _) = peers[1].expect_i(deadline(5)).expect("event 1");
    assert_eq!(numbers(apci, "setup"), (0, 0));
    let (ns, nr) = seq(0, 1);
    peers[1].send_i(ns, nr, &command(1)).expect("command 1");
    let (_, (ack, _)) = read_until(&mut peers[1], deadline(5), |a| matches!(a, Apci::S { .. }))
        .expect("command 1 is acknowledged after t2");
    assert_eq!(ack, Apci::S { nr: SeqNo::new(1) });

    // Manual switch-over to connection 0.
    peers[1].send_u(UFunction::StopDtAct).expect("STOPDT on 1");
    peers[1]
        .expect_u(UFunction::StopDtCon, deadline(5))
        .expect("stopped");
    peers[0]
        .start_data_transfer()
        .expect("connection 0 started");

    // Event 2 on connection 0 is never acknowledged: t1 closes it.
    dut.send(event(2)).expect("event 2");
    let (apci, asdu) = peers[0].expect_i(deadline(5)).expect("event 2");
    assert_eq!(numbers(apci, "setup"), (0, 0));
    assert_eq!(asdu, event(2));
    expect_closed(&mut peers[0], deadline(5)).expect("5.4.13.10: t1 closes connection 0");

    // The controlling station starts connection 1 again.
    peers[1]
        .send_u(UFunction::StartDtAct)
        .expect("STARTDT on 1");
    let (first, _) = peers[1].read_frame(deadline(5)).expect("the answer");
    assert_eq!(
        first,
        Apci::U(UFunction::StartDtCon),
        "5.4.13.10: the STARTDT con comes first, no M_EI before it"
    );
    let (apci, asdu) = peers[1]
        .expect_i(deadline(5))
        .expect("5.4.13.10: the unacknowledged event is sent again");
    assert!(
        !is_end_of_initialisation(&asdu),
        "5.4.13.10: no M_EI is sent on the re-established Started connection"
    );
    assert_eq!(asdu, event(2), "5.4.13.10: the unacknowledged event");
    assert_eq!(
        numbers(apci, "5.4.13.10"),
        (1, 1),
        "5.4.13.10: connection 1's counters are kept, not reset to 0"
    );

    let (ns, nr) = seq(1, 2);
    peers[1].send_i(ns, nr, &command(2)).expect("command 2");
    let (_, (ack, _)) = read_until(&mut peers[1], deadline(5), |a| matches!(a, Apci::S { .. }))
        .expect("5.4.13.10: command 2 is accepted");
    assert_eq!(
        ack,
        Apci::S { nr: SeqNo::new(2) },
        "5.4.13.10: the receive counter of connection 1 continues"
    );

    let report = dut.finish().expect("the station ends cleanly");
    assert!(
        report
            .sent
            .iter()
            .all(|s| !is_end_of_initialisation(&s.asdu)),
        "5.4.13.10: no M_EI anywhere"
    );
    assert!(
        report.closes.iter().all(|c| c.0 == 0),
        "only connection 0 was closed: {:?}",
        report.closes
    );
}

// ------------------------------------------------------------ 5.4.13.20

/// 604 Table 13 (2 of 3), PDF page index 59 (printed 58), procedure
/// **`5.4.13.20`** (re-establishing a lost redundant connection), second row,
/// `Reference` `IEC 60870-5-104:2006, 10`, `Required` `M`.
///
/// Requirement: when the controlled station finds one of the redundant
/// connections, Started or Stopped, inoperable but still open, it starts a TCP
/// active close on that connection (the close may never reach the peer).
///
/// DUT: the **controlled** station. The inoperable connection is a stopped one
/// (the started case is `5.4.13.10`'s first row, above): its peer does not
/// answer the station's TESTFR act. Member 1 has a t3 of 0.3 s and a t1 of
/// 0.6 s, member 0 a t3 of 30 s (10.7: timers per connection). Expected values:
/// clause 5.2 and figure 17, `Timeout t1[]/Active close` from `STOPPED
/// connection`, no earlier than t1 after the act; the started connection stays
/// started and carries the next event (10.2 rule 3).
#[test]
fn clause_5_4_13_20_the_controlled_station_closes_an_inoperable_stopped_connection() {
    let t1 = Duration::from_millis(600);
    let dut = GroupUnderTest::controlled(
        vec![params(5_000, 1_000, 30_000), params(600, 300, 300)],
        Policy::default(),
    )
    .expect("the station");
    let mut peers = connect_peers(&dut, 2).expect("two connections");
    peers[0]
        .start_data_transfer()
        .expect("connection 0 started");

    peers[1]
        .expect_u(UFunction::TestFrAct, deadline(5))
        .expect("the station tests the stopped connection");
    // The peer is inoperable: no TESTFR con.
    let (seen, _) = expect_closed(&mut peers[1], deadline(5))
        .expect("5.4.13.20: the station closes the inoperable connection");
    assert!(seen.is_empty(), "nothing but the close: {seen:?}");

    dut.send(event(1)).expect("the event");
    let (apci, asdu) = peers[0]
        .expect_i(deadline(5))
        .expect("5.4.13.20: the started connection carries on");
    assert_eq!(numbers(apci, "5.4.13.20"), (0, 0));
    assert_eq!(asdu, event(1));

    let report = dut.finish().expect("the station ends cleanly");
    let act = report
        .sent_on(1)
        .into_iter()
        .find(|s| s.apci == Apci::U(UFunction::TestFrAct))
        .expect("the act")
        .at;
    let closes: Vec<_> = report.closes.iter().filter(|c| c.0 == 1).collect();
    assert_eq!(closes.len(), 1, "5.4.13.20: one close of connection 1");
    assert!(
        closes[0].1 - act >= t1,
        "5.4.13.20: the close came {:?} after the unanswered TESTFR act, before t1 = {t1:?}",
        closes[0].1 - act
    );
    assert!(
        report.closes.iter().all(|c| c.0 == 1),
        "5.4.13.20: the started connection is not closed: {:?}",
        report.closes
    );
    assert!(
        report.switchovers.is_empty(),
        "5.4.13.20: a stopped connection's loss is no switch-over"
    );
}

/// 604 Table 13 (2 of 3), PDF page index 59 (printed 58), procedure
/// **`5.4.13.20`**, first and third rows, `Reference`
/// `IEC 60870-5-104:2006, 10`, `Required` `M`:
///
/// 1. When the controlling station (where two are equivalent, it may be a fixed
///    configured choice) finds one of the redundant connections, Started or
///    Stopped, inoperable but still open, it starts a TCP active close on that
///    connection (the close may never reach the peer).
/// 2. It then attempts, at regular intervals, a new Stopped connection to the
///    controlled station in place of the one it closed.
///
/// DUT: the **controlling** station. The inoperable connection is a stopped
/// one whose peer does not answer the TESTFR act; its listener is gone, so the
/// station's dials are refused until it comes back. Expected values:
///
/// - figure 18's `Timeout t1[]/Active close`, no earlier than t1 after the act;
/// - 10.5 (index 128): the controlling station keeps retrying the reopen until
///   the fault is cleared and the connection is back, with t0 as the interval
///   (clause 9, *"Time-out of connection establishment"*; 10.7 sets it per
///   connection): at least two refused dials, each no earlier than t0 after
///   the one before, and a new connection once the listener is back;
/// - the new connection is a Stopped one (10.3: a newly established connection
///   always starts in the stopped state): no STARTDT act on
///   it, it answers TESTFR, and connection 0 stays the started one.
#[test]
fn clause_5_4_13_20_the_controlling_station_closes_and_reopens_an_inoperable_connection() {
    let t0 = Duration::from_millis(300);
    let t1 = Duration::from_millis(600);
    let (mut listeners, addrs) = listeners(2).expect("listeners");
    let dut = GroupUnderTest::controlling(
        vec![params(5_000, 1_000, 30_000), params(600, 300, 300)],
        addrs.clone(),
        Policy::default(),
    )
    .expect("the station");
    let mut peer0 = accept_peer(&listeners[0], deadline(5)).expect("connection 0");
    let mut peer1 = accept_peer(&listeners[1], deadline(5)).expect("connection 1");
    // The controlled station's port for connection 1 goes away.
    drop(listeners.pop());
    dut.wait_until("both connected", deadline(5), |g| {
        g.members().iter().all(|m| m.session().is_connected())
    })
    .expect("connected");
    dut.start(0).expect("the station starts connection 0");
    peer0
        .expect_u(UFunction::StartDtAct, deadline(5))
        .expect("the act");
    peer0.send_u(UFunction::StartDtCon).expect("confirmed");

    peer1
        .expect_u(UFunction::TestFrAct, deadline(5))
        .expect("the station tests the stopped connection");
    expect_closed(&mut peer1, deadline(5))
        .expect("5.4.13.20: the station closes the inoperable connection");

    // Let the station retry against the closed port for a while.
    thread::sleep(Duration::from_millis(1_200));
    let listener = TcpListener::bind(addrs[1]).expect("the port comes back");
    let mut again = accept_peer(&listener, deadline(5))
        .expect("5.4.13.20: the station creates a new connection");
    again.send_u(UFunction::TestFrAct).expect("the peer's test");
    // The station's own t3 test may come first on the new connection.
    let (skipped, _) = read_until(&mut again, deadline(5), |apci| {
        *apci == Apci::U(UFunction::TestFrCon)
    })
    .expect("5.4.13.20: the new connection is open and stopped");
    assert!(
        skipped.iter().all(|f| f.0 == Apci::U(UFunction::TestFrAct)),
        "5.4.13.20: nothing but supervision on the new Stopped connection: {skipped:?}"
    );
    assert_eq!(dut.state(1).expect("state"), State::Stopped);
    assert_eq!(
        dut.look(
            "started",
            iec104::redundancy::RedundancyGroup::started_index
        )
        .expect("look"),
        Some(0),
        "5.4.13.20: connection 0 is still the started connection"
    );

    let report = dut.finish().expect("the station ends cleanly");
    let act = report
        .sent_on(1)
        .into_iter()
        .find(|s| s.apci == Apci::U(UFunction::TestFrAct))
        .expect("the act")
        .at;
    let close = report
        .closes
        .iter()
        .find(|c| c.0 == 1)
        .expect("the close of connection 1");
    assert!(
        close.1 - act >= t1,
        "5.4.13.20: the close came {:?} after the unanswered TESTFR act, before t1 = {t1:?}",
        close.1 - act
    );
    assert!(
        report.closes.iter().all(|c| c.0 == 1),
        "5.4.13.20: the started connection is not closed: {:?}",
        report.closes
    );
    let redials: Vec<(Instant, bool)> = report
        .dials
        .iter()
        .filter(|d| d.0 == 1 && d.1 >= close.1)
        .map(|d| (d.1, d.2))
        .collect();
    let refused = redials.iter().filter(|d| !d.1).count();
    assert!(
        refused >= 2,
        "5.4.13.20: the station tries again at regular intervals: {redials:?}"
    );
    assert!(
        redials.last().is_some_and(|d| d.1),
        "5.4.13.20: the last try creates the new connection: {redials:?}"
    );
    for pair in redials.windows(2) {
        assert!(
            pair[1].0 - pair[0].0 >= t0,
            "5.4.13.20: two tries {:?} apart, closer than t0 = {t0:?}",
            pair[1].0 - pair[0].0
        );
    }
    assert!(
        report
            .sent_on(1)
            .iter()
            .all(|s| s.apci != Apci::U(UFunction::StartDtAct)),
        "5.4.13.20: the new connection is not started"
    );
}

// ------------------------------------------------------------ 5.4.13.30

/// 604 Table 13 (2 of 3 and 3 of 3), PDF page indices 59–60 (printed 58–59),
/// procedure **`5.4.13.30`** (manually switching the Started connection over
/// to another redundant Stopped connection, the manual switch-over), the rows
/// about the **controlling** station, `Reference` `IEC 60870-5-104:2006, 10`,
/// `Required` `M`:
///
/// 1. The controlling station (where two are equivalent, it may be a fixed
///    configured choice) sends a STOPDT act to the controlled station on the
///    current Started connection.
/// 2. Having sent it, the controlling station stops sending I-frames on that
///    connection, now pending STOPDT; this is optional but recommended.
/// 3. It also acknowledges, with one or more S-frames, every I-frame from the
///    controlled station still unacknowledged, within or as t2 requires.
/// 4. It makes a new Started connection by sending a STARTDT act over the
///    chosen Stopped connection to the same controlled station.
/// 5. Once the new Started connection exists, no `M_EI` (end of
///    initialisation) goes to the controlling station, and none is needed;
///    normal operation resumes.
/// 6. The send and receive counters are not reset to 0 while the TCP
///    connection stays up: every TCP connection keeps its own counters,
///    whatever STARTDT, STOPDT or switch-over happens.
///
/// DUT: the **controlling** station; the application's steps are
/// `RedundancyGroup::stop` then `RedundancyGroup::start` (10.2, index 118: a
/// manual switch-over is a `STOPDT_ACT` on the current Started connection
/// followed by a `STARTDT_ACT` on the newly chosen one). Expected values:
///
/// - the peer's event on connection 0 is acknowledged before the STOPDT act
///   (clause 5.3: the controlling station should confirm everything it has
///   received before it sends the STOPDT act);
/// - a command handed over while the stop is pending does not go out on
///   connection 0 (clause 5.3: the STOPDT act halts I-frame transmission at
///   once);
/// - an event still in flight from the peer (the row's NOTE) is acknowledged
///   at once, within t2 (clause 5.3, figure 18's pending stop);
/// - after the peer's STOPDT con, STARTDT act on connection 1, with the held
///   command behind it and connection 1's own `N(S)` 0; no `M_EI` is waited for;
/// - back on connection 0 after a second switch-over, the next command carries
///   `N(S)` 1 and `N(R)` 2: connection 0's counters, not reset.
#[test]
fn clause_5_4_13_30_the_controlling_station_switches_over_by_hand() {
    let t2 = Duration::from_millis(1_000);
    let p = params(3_000, 1_000, 30_000);
    let (listeners, addrs) = listeners(2).expect("listeners");
    let dut =
        GroupUnderTest::controlling(vec![p; 2], addrs, Policy::default()).expect("the station");
    let mut peers: Vec<Peer> = listeners
        .iter()
        .map(|l| accept_peer(l, deadline(5)).expect("the station dials every member"))
        .collect();
    dut.wait_until("both connected", deadline(5), |g| {
        g.members().iter().all(|m| m.session().is_connected())
    })
    .expect("connected");
    dut.start(0).expect("the station starts connection 0");
    peers[0]
        .expect_u(UFunction::StartDtAct, deadline(5))
        .expect("the act");
    peers[0].send_u(UFunction::StartDtCon).expect("confirmed");
    dut.wait_until("started", deadline(5), |g| g.state(0) == Ok(State::Started))
        .expect("started");

    // One command each way on connection 0, the station's acknowledged.
    dut.send(command(1)).expect("command 1");
    let (apci, _) = peers[0].expect_i(deadline(5)).expect("command 1");
    assert_eq!(numbers(apci, "setup"), (0, 0));
    peers[0].send_s(SeqNo::new(1)).expect("acknowledged");
    let (ns, nr) = seq(0, 1);
    peers[0].send_i(ns, nr, &event(1)).expect("event 1");
    dut.wait_until("event 1 received", deadline(5), |g| {
        g.member(0).is_ok_and(|m| m.session().v_r().get() == 1)
    })
    .expect("received");

    // The STOPDT act, with event 1 acknowledged first.
    dut.stop(0)
        .expect("5.4.13.30: the station stops connection 0");
    let (before, _) = read_until(&mut peers[0], deadline(5), |apci| {
        *apci == Apci::U(UFunction::StopDtAct)
    })
    .expect("5.4.13.30: STOPDT act on the current Started connection");
    let before: Vec<Apci> = before.into_iter().map(|f| f.0).collect();
    assert_eq!(
        before,
        vec![Apci::S { nr: SeqNo::new(1) }],
        "5.4.13.30: event 1 is acknowledged with an S-frame before the STOPDT act"
    );

    // Pending STOPDT: the station sends no I-frame.
    dut.send(command(2)).expect("command 2 is handed over");
    expect_nothing(&mut peers[0], Duration::from_millis(300))
        .expect("5.4.13.30: no I-frame on the connection in pending STOPDT state");

    // The NOTE's one I-frame in flight is acknowledged within t2.
    let sent = Instant::now();
    let (ns, nr) = seq(1, 1);
    peers[0].send_i(ns, nr, &event(2)).expect("event 2");
    let (skipped, (ack, _)) =
        read_until(&mut peers[0], deadline(5), |a| matches!(a, Apci::S { .. }))
            .expect("5.4.13.30: the I-frame is acknowledged");
    assert!(skipped.is_empty(), "only the S-frame: {skipped:?}");
    assert_eq!(ack, Apci::S { nr: SeqNo::new(2) });
    assert!(
        sent.elapsed() < t2,
        "5.4.13.30: acknowledged within t2 = {t2:?}"
    );

    // The STOPDT con makes connection 0 a Stopped connection.
    peers[0].send_u(UFunction::StopDtCon).expect("STOPDT con");
    dut.wait_until("stopped", deadline(5), |g| g.state(0) == Ok(State::Stopped))
        .expect("5.4.13.30: the previously Started connection is Stopped");

    // STARTDT act on the selected Stopped connection, command 2 behind it.
    dut.start(1).expect("the station starts connection 1");
    let (first, _) = peers[1].read_frame(deadline(5)).expect("the act");
    assert_eq!(
        first,
        Apci::U(UFunction::StartDtAct),
        "5.4.13.30: STARTDT act over the selected Stopped connection"
    );
    let (apci, asdu) = peers[1].expect_i(deadline(5)).expect("command 2");
    assert_eq!(asdu, command(2), "5.4.13.30: the held command follows");
    assert_eq!(
        numbers(apci, "5.4.13.30"),
        (0, 0),
        "5.4.13.30: connection 1's own counters"
    );
    peers[1]
        .send_u(UFunction::StartDtCon)
        .expect("confirmed, and no M_EI");
    dut.send(command(3)).expect("command 3");
    let (apci, _) = peers[1]
        .expect_i(deadline(5))
        .expect("5.4.13.30: normal operation continues");
    assert_eq!(numbers(apci, "5.4.13.30"), (1, 0));

    back_to_connection_zero(&dut, &mut peers);

    let report = dut.finish().expect("the station ends cleanly");
    assert!(report.closes.is_empty(), "no close: {:?}", report.closes);
}

/// The second switch-over, back to connection 0, whose counters were kept.
fn back_to_connection_zero(dut: &GroupUnderTest, peers: &mut [Peer]) {
    // Back to connection 0: its counters were kept.
    peers[1].send_s(SeqNo::new(2)).expect("acknowledged");
    dut.wait_until("acknowledged", deadline(5), |g| {
        g.member(1)
            .is_ok_and(|m| m.session().outstanding_i_frames() == 0)
    })
    .expect("acknowledged");
    dut.stop(1).expect("stop connection 1");
    peers[1]
        .expect_u(UFunction::StopDtAct, deadline(5))
        .expect("the act");
    peers[1].send_u(UFunction::StopDtCon).expect("STOPDT con");
    dut.wait_until("stopped", deadline(5), |g| g.state(1) == Ok(State::Stopped))
        .expect("stopped");
    dut.start(0).expect("start connection 0 again");
    peers[0]
        .expect_u(UFunction::StartDtAct, deadline(5))
        .expect("the act");
    peers[0].send_u(UFunction::StartDtCon).expect("confirmed");
    dut.send(command(4)).expect("command 4");
    let (apci, asdu) = peers[0].expect_i(deadline(5)).expect("command 4");
    assert_eq!(asdu, command(4));
    assert_eq!(
        numbers(apci, "5.4.13.30"),
        (1, 2),
        "5.4.13.30: connection 0's counters are not reset while it stays established"
    );
}

/// 604 Table 13 (2 of 3 and 3 of 3), PDF page indices 59–60 (printed 58–59),
/// procedure **`5.4.13.30`**, the rows about the **controlled** station,
/// `Reference` `IEC 60870-5-104:2006, 10` (and `5.3`), `Required` `M`:
///
/// 1. On receiving the STOPDT act, the controlled station too stops sending
///    I-frames on the Started connection, now pending STOPDT, before it has
///    sent the STOPDT con.
/// 2. It acknowledges, with one or more S-frames, every I-frame from the
///    controlling station still unacknowledged.
/// 3. It ends the pending STOPDT state by sending the controlling station a
///    STOPDT con, which turns the formerly Started connection into a Stopped
///    one.
/// 4. It completes the new Started connection by answering with a STARTDT con
///    on the connection the STARTDT act arrived on.
///
/// Also the rows on no `M_EI` and on the counters (paraphrased on
/// [`clause_5_4_13_30_the_controlling_station_switches_over_by_hand`]).
///
/// DUT: the **controlled** station. When the STOPDT act arrives the station has
/// two unacknowledged commands of the peer and one event of its own the peer
/// has not acknowledged (t2 is 4 s, so no S-frame goes out on its own).
/// Expected values:
///
/// - figure 17's `STOPDT act[unconfirmed I-frames]` into `Pending UNCONFIRMED
///   STOPPED connection`: no STOPDT con yet, and an event handed over now is
///   not sent (clause 5.3: the STOPDT act halts I-frame transmission at once);
/// - once the peer acknowledges the event, the station's S-frame with `N(R)` 2
///   and then the STOPDT con (clause 5.3: the controlled station should confirm
///   everything it has received before it returns the STOPDT con; figure 17,
///   `S-frame [no unconfirmed I-frames]/Send STOPDT con`);
/// - STARTDT con on connection 1, then the held event with `N(S)` 0 `N(R)` 0,
///   and no `M_EI`;
/// - after a switch-over back, the next event on connection 0 carries
///   `N(S)` 1 and `N(R)` 2: connection 0's counters, not reset.
#[test]
fn clause_5_4_13_30_the_controlled_station_follows_a_manual_switch_over() {
    let p = params(5_000, 4_000, 30_000);
    let dut = GroupUnderTest::controlled(vec![p; 2], Policy::default()).expect("the station");
    let mut peers = connect_peers(&dut, 2).expect("two connections");
    peers[0]
        .start_data_transfer()
        .expect("connection 0 started");

    dut.send(event(1)).expect("event 1");
    let (apci, _) = peers[0].expect_i(deadline(5)).expect("event 1");
    assert_eq!(numbers(apci, "setup"), (0, 0));
    for n in 0..2u16 {
        let (ns, nr) = seq(n, 0);
        peers[0]
            .send_i(ns, nr, &command(u32::from(n) + 1))
            .expect("a command, event 1 not acknowledged");
    }

    peers[0]
        .send_u(UFunction::StopDtAct)
        .expect("STOPDT act on 0");
    dut.wait_until("pending stop", deadline(5), |g| {
        g.state(0) == Ok(State::PendingUnconfirmedStopped)
    })
    .expect("5.4.13.30: connection 0 is in pending STOPDT state");
    dut.send(event(2)).expect("event 2 is handed over");
    expect_nothing(&mut peers[0], Duration::from_millis(300))
        .expect("5.4.13.30: no I-frame and no STOPDT con while event 1 is unacknowledged");

    peers[0]
        .send_s(SeqNo::new(1))
        .expect("event 1 acknowledged");
    let (before, _) = read_until(&mut peers[0], deadline(5), |apci| {
        *apci == Apci::U(UFunction::StopDtCon)
    })
    .expect("5.4.13.30: the STOPDT con");
    let before: Vec<Apci> = before.into_iter().map(|f| f.0).collect();
    assert_eq!(
        before,
        vec![Apci::S { nr: SeqNo::new(2) }],
        "5.4.13.30: both commands are acknowledged with an S-frame before the STOPDT con"
    );
    dut.wait_until("stopped", deadline(5), |g| g.state(0) == Ok(State::Stopped))
        .expect("5.4.13.30: a Stopped connection");

    peers[1]
        .send_u(UFunction::StartDtAct)
        .expect("STARTDT act on 1");
    let (first, _) = peers[1].read_frame(deadline(5)).expect("the answer");
    assert_eq!(
        first,
        Apci::U(UFunction::StartDtCon),
        "5.4.13.30: STARTDT con over the connection the act came on"
    );
    let (apci, asdu) = peers[1]
        .expect_i(deadline(5))
        .expect("5.4.13.30: normal operation continues");
    assert!(!is_end_of_initialisation(&asdu), "5.4.13.30: no M_EI");
    assert_eq!(asdu, event(2), "the held event");
    assert_eq!(
        numbers(apci, "5.4.13.30"),
        (0, 0),
        "5.4.13.30: connection 1's own counters"
    );

    // Back to connection 0.
    peers[1].send_s(SeqNo::new(1)).expect("acknowledged");
    peers[1]
        .send_u(UFunction::StopDtAct)
        .expect("STOPDT act on 1");
    peers[1]
        .expect_u(UFunction::StopDtCon, deadline(5))
        .expect("stopped");
    peers[0]
        .send_u(UFunction::StartDtAct)
        .expect("STARTDT act on 0");
    peers[0]
        .expect_u(UFunction::StartDtCon, deadline(5))
        .expect("started");
    dut.send(event(3)).expect("event 3");
    let (apci, asdu) = peers[0].expect_i(deadline(5)).expect("event 3");
    assert_eq!(asdu, event(3));
    assert_eq!(
        numbers(apci, "5.4.13.30"),
        (1, 2),
        "5.4.13.30: connection 0's counters are not reset while it stays established"
    );

    let report = dut.finish().expect("the station ends cleanly");
    assert!(report.closes.is_empty(), "no close: {:?}", report.closes);
    assert!(
        report.refused.is_empty(),
        "nothing refused: {:?}",
        report.refused
    );
    assert!(
        report
            .sent
            .iter()
            .all(|s| !is_end_of_initialisation(&s.asdu)),
        "5.4.13.30: no M_EI anywhere"
    );
}
