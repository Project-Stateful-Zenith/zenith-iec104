//! The task behind a [`super::Client`]: it owns the controlling instances of
//! the core's procedures, reads the driver's events, hands each received ASDU
//! to the procedure [`iec104::dispatch::route`] names, and answers the calls
//! waiting for it.

use iec104::asdu::{
    self, Asdu, CRpNa1, Cause, Cp56Time2a, Direction, Discard, FreezeMode, Header, IOA_IRRELEVANT,
    Known, LayoutObject, Objects, TypeId, encode_asdu_with, is_mirror, read_ioa_with,
};
use iec104::ci::{self, CounterInterrogation};
use iec104::cs::{self, ClockSynchronisation};
use iec104::ct::{self, Command, CommandMode, CommandSet, CommandTransmission};
use iec104::dispatch::{Route, route};
use iec104::gi::{self, Interrogation, Scope, SecondActivation};
use iec104::link::State;
use iec104::pm::{self, Parameter, ParameterLoading};
use iec104::rd::{self, Read};
use iec104::redundancy::{Replay, Switchover};
use iec104::ts::{self, TestProcedure};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::time::Instant;

use super::{ClientConfig, ClientError, CommandOutcome, ParameterRequest, Reply, Request, Update};
use crate::{Event, Events, Handle};

/// The connection every frame is sent on: the station of a one-station
/// manager, or any member of a group (which sends on its started one).
const CONN: usize = 0;

/// The profile the procedures check received frames against: the client
/// expects every type, cause and address its station may send.
const KNOWN: Known = Known::EVERYTHING;

/// Where a command is in its procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The select is sent; its confirmation is awaited. Nothing operated yet.
    Selecting,
    /// The execute is sent; its confirmation is awaited.
    Executing,
    /// The execute is confirmed; its termination is awaited.
    Terminating,
    /// The deactivation of a confirmed select is sent; its `DEACTCON` is
    /// awaited. Nothing operates either way.
    Deactivating,
}

impl Stage {
    /// Whether an execute went out: an answer lost from here on leaves the
    /// outcome unknown.
    const fn executed(self) -> bool {
        matches!(self, Self::Executing | Self::Terminating)
    }
}

/// Which command call is being served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    /// [`super::Client::command`]: the whole procedure, the select included
    /// where the mode has one.
    Command,
    /// [`super::Client::select`]: the select alone.
    Select,
    /// [`super::Client::execute`]: the execute of a confirmed select.
    Execute,
    /// [`super::Client::cancel`]: the deactivation of a confirmed select.
    Cancel,
}

/// Who waits for a command: a call that returns the outcome, or one that
/// returns once its step is confirmed (a select, a cancel).
enum CommandReply {
    Outcome(Reply<CommandOutcome>),
    Done(Reply<()>),
}

impl CommandReply {
    fn send(self, result: Result<CommandOutcome, ClientError>) {
        match self {
            Self::Outcome(reply) => {
                let _ = reply.send(result);
            }
            Self::Done(reply) => {
                let _ = reply.send(result.map(|_| ()));
            }
        }
    }
}

struct PendingCommand {
    command: Command,
    call: Call,
    stage: Stage,
    deadline: Instant,
    reply: CommandReply,
}

struct PendingInterrogation {
    scope: Scope,
    sent: Instant,
    confirmed: bool,
    objects: Vec<Asdu>,
    /// Empty for the client's own interrogation on a new started connection.
    replies: Vec<Reply<Vec<Asdu>>>,
    /// A deactivation sent for this scope, its deadline and its caller.
    stop: Option<(Instant, Reply<()>)>,
}

struct PendingCounter {
    request: ci::Request,
    freeze: FreezeMode,
    sent: Instant,
    confirmed: bool,
    objects: Vec<Asdu>,
    replies: Vec<Reply<Vec<Asdu>>>,
}

struct PendingParameter {
    load: ParameterRequest,
    parameter: Parameter,
    deadline: Instant,
    reply: Reply<Option<Parameter>>,
}

impl PendingParameter {
    /// Whether this request is for the parameter at `ioa` of `family`: the
    /// answers carry nothing else to match on.
    fn is_for(&self, ioa: u32, family: pm::Family) -> bool {
        self.parameter.ioa == ioa && self.parameter.family() == family
    }
}

struct PendingRead {
    ioa: u32,
    deadline: Instant,
    replies: Vec<Reply<Asdu>>,
}

struct Task {
    handle: Handle,
    config: ClientConfig,
    group: bool,
    gi: Interrogation,
    ci: CounterInterrogation,
    cs: ClockSynchronisation,
    rd: Read,
    ct: CommandTransmission,
    ts: TestProcedure,
    pm: ParameterLoading,
    /// Each connection's last reported state.
    states: Vec<State>,
    started: bool,
    waiting: Vec<Reply<()>>,
    subscribers: Vec<Subscriber>,
    /// Group members that failed while started, whose unconfirmed data waits
    /// for the next started connection ([`ClientConfig::retransmit_on_switchover`]).
    failed: Vec<usize>,
    commands: Vec<PendingCommand>,
    interrogations: Vec<PendingInterrogation>,
    counters: Vec<PendingCounter>,
    clock_sync: Option<(Instant, Reply<()>)>,
    reads: Vec<PendingRead>,
    /// The test command sent, its deadline and its caller. The confirmation
    /// names no request, only the echoed value, so one runs at a time.
    test: Option<(Instant, ts::Command, Reply<()>)>,
    /// The reset process command sent, its deadline and its caller.
    reset: Option<(Instant, Reply<()>)>,
    parameters: Vec<PendingParameter>,
}

/// One subscription's channel and the updates it missed since its last
/// delivery.
pub(super) struct Subscriber {
    sender: mpsc::Sender<Update>,
    lagged: u64,
}

impl Subscriber {
    pub(super) fn new(config: &ClientConfig) -> (Self, mpsc::Receiver<Update>) {
        // Room for `Lagged` and the update behind it, or a lagged subscriber
        // would only ever receive `Lagged`.
        let (sender, receiver) = mpsc::channel(config.update_buffer.max(2));
        (Self { sender, lagged: 0 }, receiver)
    }

    /// Delivers `update` without waiting, after the count of what was
    /// dropped before it; `false` once the receiver is gone.
    fn offer(&mut self, update: &Update) -> bool {
        if self.lagged > 0 {
            match self.sender.try_send(Update::Lagged(self.lagged)) {
                Ok(()) => self.lagged = 0,
                Err(TrySendError::Full(_)) => {
                    self.lagged = self.lagged.saturating_add(1);
                    return true;
                }
                Err(TrySendError::Closed(_)) => return false,
            }
        }
        match self.sender.try_send(update.clone()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.lagged = self.lagged.saturating_add(1);
                true
            }
            Err(TrySendError::Closed(_)) => false,
        }
    }
}

pub(super) async fn run(
    handle: Handle,
    mut events: Events,
    mut requests: mpsc::Receiver<Request>,
    config: ClientConfig,
    group: bool,
    subscribers: Vec<Subscriber>,
) {
    let (ca, org, sizes) = (config.common_address, config.originator, config.sizes);
    let mut task = Task {
        gi: Interrogation::controlling(SecondActivation::Locked, ca, org).with_address_sizes(sizes),
        ci: CounterInterrogation::controlling(config.counter_mode, ca, org)
            .with_address_sizes(sizes),
        cs: ClockSynchronisation::controlling(ca, org).with_address_sizes(sizes),
        rd: Read::controlling(true, ca, org).with_address_sizes(sizes),
        ct: CommandTransmission::controlling(
            config.command_mode,
            config.command_set,
            config.termination,
            ca,
            org,
        )
        .with_address_sizes(sizes),
        // 104 Table 4 carries `<107>` and no `<104>`: the tagged form.
        ts: TestProcedure::controlling(ts::Selection::TAGGED, ca, org).with_address_sizes(sizes),
        // 5-101 cl.7.4.9: "P_ME SPONT for local parameter change is not used."
        pm: ParameterLoading::controlling(pm::LocalChange::NotUsed, ca, org)
            .with_address_sizes(sizes),
        handle,
        config,
        group,
        states: Vec::new(),
        started: false,
        waiting: Vec::new(),
        subscribers,
        failed: Vec::new(),
        commands: Vec::new(),
        interrogations: Vec::new(),
        counters: Vec::new(),
        clock_sync: None,
        reads: Vec::new(),
        test: None,
        reset: None,
        parameters: Vec::new(),
    };
    loop {
        let deadline = task.next_deadline();
        tokio::select! {
            request = requests.recv() => if let Some(request) = request { task.on_request(request).await } else {
                // Every client is gone: nobody can call or wait any more.
                task.handle.shutdown().await;
                return;
            },
            event = events.recv() => if let Some(event) = event { task.on_event(event).await } else {
                task.fail_all(Lost::Stopped);
                return;
            },
            () = sleep_until(deadline) => task.expire(Instant::now()),
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// When an interrogation or counter interrogation sent at `sent` times out:
/// its confirmation is due within [`Timeouts::confirmation`], its termination
/// within [`Timeouts::interrogation`] of the activation.
///
/// [`Timeouts::confirmation`]: super::Timeouts::confirmation
/// [`Timeouts::interrogation`]: super::Timeouts::interrogation
fn procedure_deadline(sent: Instant, confirmed: bool, timeouts: super::Timeouts) -> Instant {
    later(
        sent,
        if confirmed {
            timeouts.interrogation
        } else {
            timeouts.confirmation.min(timeouts.interrogation)
        },
    )
}

/// About 30 years: what a timeout too long to add to an instant waits for
/// instead, as good as never (tokio's own far future).
const FAR_FUTURE: std::time::Duration = std::time::Duration::from_secs(946_080_000);

/// `from + after`, or [`FAR_FUTURE`] after `from` for an `after` too long to
/// add.
fn later(from: Instant, after: std::time::Duration) -> Instant {
    from.checked_add(after)
        .or_else(|| from.checked_add(FAR_FUTURE))
        .unwrap_or(from)
}

/// Why everything outstanding ends at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lost {
    /// No connection is started any more.
    Connection,
    /// The driver has stopped.
    Stopped,
}

impl Lost {
    /// The error of a request whose answer is lost and that operated nothing.
    const fn error(self) -> ClientError {
        match self {
            Self::Connection => ClientError::ConnectionLost,
            Self::Stopped => ClientError::Driver(crate::Error::Stopped),
        }
    }
}

impl Task {
    fn now() -> Instant {
        Instant::now()
    }

    fn next_deadline(&self) -> Option<Instant> {
        let timeouts = self.config.timeouts;
        let commands = self.commands.iter().map(|c| c.deadline);
        let interrogations = self
            .interrogations
            .iter()
            .map(|p| procedure_deadline(p.sent, p.confirmed, timeouts));
        let counters = self
            .counters
            .iter()
            .map(|p| procedure_deadline(p.sent, p.confirmed, timeouts));
        let stops = self
            .interrogations
            .iter()
            .filter_map(|p| p.stop.as_ref().map(|(deadline, _)| *deadline));
        let clock = self.clock_sync.iter().map(|(deadline, _)| *deadline);
        let reads = self.reads.iter().map(|r| r.deadline);
        let test = self.test.iter().map(|(deadline, _, _)| *deadline);
        let reset = self.reset.iter().map(|(deadline, _)| *deadline);
        let parameters = self.parameters.iter().map(|p| p.deadline);
        commands
            .chain(interrogations)
            .chain(stops)
            .chain(counters)
            .chain(clock)
            .chain(reads)
            .chain(test)
            .chain(reset)
            .chain(parameters)
            .min()
    }

    fn publish(&mut self, update: &Update) {
        self.subscribers
            .retain_mut(|subscriber| subscriber.offer(update));
    }

    async fn send(&self, frame: Vec<u8>) -> Result<(), ClientError> {
        self.handle
            .send_asdu(CONN, frame)
            .await
            .map_err(ClientError::Driver)
    }

    // ------------------------------------------------------------ requests

    async fn on_request(&mut self, request: Request) {
        match request {
            Request::WaitStarted(reply) => {
                if self.started {
                    let _ = reply.send(Ok(()));
                } else {
                    self.waiting.push(reply);
                }
            }
            Request::Subscribe(reply) => {
                let (subscriber, receiver) = Subscriber::new(&self.config);
                self.subscribers.push(subscriber);
                let _ = reply.send(Ok(receiver));
            }
            Request::Interrogate(scope, reply) => self.interrogate(scope, Some(reply)).await,
            Request::StopInterrogation(scope, reply) => self.stop_interrogation(scope, reply).await,
            Request::Counter(request, freeze, reply) => self.counter(request, freeze, reply).await,
            Request::Command(command, reply) => {
                self.command(command, Call::Command, CommandReply::Outcome(reply))
                    .await;
            }
            Request::Select(command, reply) => {
                self.command(command, Call::Select, CommandReply::Done(reply))
                    .await;
            }
            Request::Execute(command, reply) => {
                self.command(command, Call::Execute, CommandReply::Outcome(reply))
                    .await;
            }
            Request::Cancel(command, reply) => {
                self.command(command, Call::Cancel, CommandReply::Done(reply))
                    .await;
            }
            Request::ClockSync(time, reply) => self.clock_sync(time, reply).await,
            Request::Read(ioa, reply) => self.read(ioa, reply).await,
            Request::Test(tsc, time, reply) => self.test(tsc, time, reply).await,
            Request::ResetProcess(qrp, reply) => self.reset_process(qrp, reply).await,
            Request::Parameter(load, parameter, reply) => {
                self.parameter(load, parameter, reply).await;
            }
        }
    }

    /// 104 cl.7.9: `P_ME ACT`, `P_AC ACT` or `P_AC DEACT`.
    async fn parameter(
        &mut self,
        load: ParameterRequest,
        parameter: Parameter,
        reply: Reply<Option<Parameter>>,
    ) {
        if !self.started {
            let _ = reply.send(Err(ClientError::NotStarted));
            return;
        }
        if self
            .parameters
            .iter()
            .any(|p| p.is_for(parameter.ioa, parameter.family()))
        {
            let _ = reply.send(Err(ClientError::Busy));
            return;
        }
        let frame = match load {
            ParameterRequest::Load => self.pm.load(&parameter),
            ParameterRequest::Activate => self.pm.activate(&parameter),
            ParameterRequest::Deactivate => self.pm.deactivate(&parameter),
        };
        let result = match frame {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::Parameter(e)),
        };
        match result {
            Ok(()) => self.parameters.push(PendingParameter {
                load,
                parameter,
                deadline: later(Self::now(), self.config.timeouts.confirmation),
                reply,
            }),
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    /// `C_RP_NA_1` with cause 6 at address 0 (5-101 cl.7.3.4.6, figure 77).
    /// No procedure module of the core serves the reset process
    /// ([`Route::NotImplemented`]), so the frame is built from its layout.
    async fn reset_process(&mut self, qrp: asdu::Qrp, reply: Reply<()>) {
        if !self.started {
            let _ = reply.send(Err(ClientError::NotStarted));
            return;
        }
        if self.reset.is_some() {
            let _ = reply.send(Err(ClientError::Busy));
            return;
        }
        let header = Header {
            type_id: TypeId::CRpNa1,
            sequence: false,
            count: 1,
            cause: Cause::Activation,
            negative: false,
            test: false,
            originator: self.config.originator,
            common_address: self.config.common_address,
        };
        let object = LayoutObject {
            ioa: IOA_IRRELEVANT,
            value: CRpNa1 { qrp },
        };
        let result = match encode_asdu_with(&header, &[object], self.config.sizes) {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::Layout(e)),
        };
        match result {
            Ok(()) => {
                let deadline = later(Self::now(), self.config.timeouts.confirmation);
                self.reset = Some((deadline, reply));
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    async fn test(&mut self, tsc: asdu::Tsc, time: Cp56Time2a, reply: Reply<()>) {
        if !self.started {
            let _ = reply.send(Err(ClientError::NotStarted));
            return;
        }
        if self.test.is_some() {
            let _ = reply.send(Err(ClientError::Busy));
            return;
        }
        let command = ts::Command::Tagged { tsc, time };
        let result = match self.ts.request(command) {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::Test(e)),
        };
        match result {
            Ok(()) => {
                let deadline = later(Self::now(), self.config.timeouts.confirmation);
                self.test = Some((deadline, command, reply));
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    async fn interrogate(&mut self, scope: Scope, reply: Option<Reply<Vec<Asdu>>>) {
        if !self.started {
            if let Some(reply) = reply {
                let _ = reply.send(Err(ClientError::NotStarted));
            }
            return;
        }
        if let Some(pending) = self.interrogations.iter_mut().find(|p| p.scope == scope) {
            // 5-101 cl.7.4.5 locks the identical interrogation: join it.
            pending.replies.extend(reply);
            return;
        }
        let result = match self.gi.request(scope) {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::Interrogation(e)),
        };
        match result {
            Ok(()) => self.interrogations.push(PendingInterrogation {
                scope,
                sent: Self::now(),
                confirmed: false,
                objects: Vec::new(),
                replies: reply.into_iter().collect(),
                stop: None,
            }),
            Err(e) => {
                self.gi.abandon(scope);
                if let Some(reply) = reply {
                    let _ = reply.send(Err(e));
                }
            }
        }
    }

    /// TS 60870-5-604 5.4.17.50: `C_IC_DEACT` for a running interrogation.
    async fn stop_interrogation(&mut self, scope: Scope, reply: Reply<()>) {
        if !self.started {
            let _ = reply.send(Err(ClientError::NotStarted));
            return;
        }
        let Some(index) = self.interrogations.iter().position(|p| p.scope == scope) else {
            let _ = reply.send(Err(ClientError::Interrogation(gi::GiError::NotRunning)));
            return;
        };
        if self
            .interrogations
            .get(index)
            .is_some_and(|pending| pending.stop.is_some())
        {
            let _ = reply.send(Err(ClientError::Busy));
            return;
        }
        let result = match self.gi.deactivate(scope) {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::Interrogation(e)),
        };
        match result {
            Ok(()) => {
                let deadline = later(Self::now(), self.config.timeouts.confirmation);
                match self.interrogations.get_mut(index) {
                    Some(pending) => pending.stop = Some((deadline, reply)),
                    None => {
                        let _ =
                            reply.send(Err(ClientError::Interrogation(gi::GiError::NotRunning)));
                    }
                }
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    async fn counter(&mut self, request: ci::Request, freeze: FreezeMode, reply: Reply<Vec<Asdu>>) {
        if !self.started {
            let _ = reply.send(Err(ClientError::NotStarted));
            return;
        }
        if let Some(pending) = self.counters.iter_mut().find(|p| p.request == request) {
            // The answers name the request but not its qualifier's FRZ, so
            // only an identical activation can share them.
            if pending.freeze == freeze {
                pending.replies.push(reply);
            } else {
                let _ = reply.send(Err(ClientError::Busy));
            }
            return;
        }
        let result = match self.ci.request(request, freeze) {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::CounterInterrogation(e)),
        };
        match result {
            Ok(()) => self.counters.push(PendingCounter {
                request,
                freeze,
                sent: Self::now(),
                confirmed: false,
                objects: Vec::new(),
                replies: vec![reply],
            }),
            Err(e) => {
                self.ci.abandon(request);
                let _ = reply.send(Err(e));
            }
        }
    }

    async fn command(&mut self, command: Command, call: Call, reply: CommandReply) {
        if !self.started {
            reply.send(Err(ClientError::NotStarted));
            return;
        }
        if self.commands.iter().any(|c| c.command.ioa == command.ioa) {
            reply.send(Err(ClientError::Busy));
            return;
        }
        // 104 clause 9: the station uses one set; a command of the tagged set
        // takes its time tag from the configured clock unless it has one.
        let command = match (self.config.command_set, command.time, &self.config.clock) {
            (CommandSet::Tagged, None, Some(clock)) => command.with_time(clock()),
            (CommandSet::Tagged, None, None) => {
                reply.send(Err(ClientError::NoClock));
                return;
            }
            _ => command,
        };
        let (stage, frame) = match call {
            Call::Command => {
                let select = self.config.command_mode == CommandMode::SelectAndExecute
                    && command.value.supports_select();
                if select {
                    (Stage::Selecting, self.ct.select(&command))
                } else {
                    (Stage::Executing, self.ct.execute(&command))
                }
            }
            Call::Select => (Stage::Selecting, self.ct.select(&command)),
            Call::Execute => {
                // TS 60870-5-604 Table 19: the execute carries "exactly the
                // same information as the SELECT message", or the station
                // refuses it and the select is spent.
                if self
                    .ct
                    .selected()
                    .iter()
                    .any(|s| s.ioa == command.ioa && !s.state_eq(&command))
                {
                    reply.send(Err(ClientError::SelectMismatch));
                    return;
                }
                (Stage::Executing, self.ct.execute(&command))
            }
            Call::Cancel => (Stage::Deactivating, self.ct.deactivate(&command)),
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(e) => {
                // The procedure refused the call and recorded nothing, so a
                // select confirmed earlier stays.
                reply.send(Err(ClientError::Command(e)));
                return;
            }
        };
        match self.send(frame).await {
            Ok(()) => self.commands.push(PendingCommand {
                command,
                call,
                stage,
                deadline: later(Self::now(), self.config.timeouts.confirmation),
                reply,
            }),
            Err(e) => {
                // Refused before it reached the link: nothing was sent.
                self.ct.abandon(command.ioa);
                reply.send(Err(e));
            }
        }
    }

    async fn clock_sync(&mut self, time: Cp56Time2a, reply: Reply<()>) {
        if !self.started {
            let _ = reply.send(Err(ClientError::NotStarted));
            return;
        }
        if self.clock_sync.is_some() {
            let _ = reply.send(Err(ClientError::Busy));
            return;
        }
        let result = match self.cs.request(time) {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::ClockSync(e)),
        };
        match result {
            Ok(()) => {
                let deadline = later(Self::now(), self.config.timeouts.confirmation);
                self.clock_sync = Some((deadline, reply));
            }
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    async fn read(&mut self, ioa: u32, reply: Reply<Asdu>) {
        if !self.started {
            let _ = reply.send(Err(ClientError::NotStarted));
            return;
        }
        if let Some(pending) = self.reads.iter_mut().find(|r| r.ioa == ioa) {
            pending.replies.push(reply);
            return;
        }
        let result = match self.rd.request(ioa) {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::Read(e)),
        };
        match result {
            Ok(()) => self.reads.push(PendingRead {
                ioa,
                deadline: later(Self::now(), self.config.timeouts.confirmation),
                replies: vec![reply],
            }),
            Err(e) => {
                let _ = reply.send(Err(e));
            }
        }
    }

    // -------------------------------------------------------------- events

    async fn on_event(&mut self, event: Event) {
        match event {
            Event::Asdu { asdu, .. } => self.on_asdu(asdu).await,
            Event::State { conn, state } => self.set_state(conn, state).await,
            Event::Disconnected { conn, .. } => self.set_state(conn, State::Stopped).await,
            Event::StartedConnectionFailed { conn, .. } => self.on_failed(conn).await,
            Event::Switchover(switchover) => {
                let failed = match switchover {
                    Switchover::Automatic { failed, .. }
                    | Switchover::NoStoppedConnection { failed, .. }
                    | Switchover::LeftToTheControllingStation { failed, .. } => failed,
                };
                self.publish(&Update::Switchover(switchover));
                self.on_failed(failed).await;
            }
            _ => {}
        }
    }

    /// A group's started connection failed, by its t1 or otherwise, and left
    /// its unconfirmed ASDUs to the application (104 cl.10.5): replay them on
    /// the next started connection, or discard them.
    async fn on_failed(&mut self, conn: usize) {
        if !self.config.retransmit_on_switchover {
            let _ = self
                .handle
                .retransmit_unconfirmed(conn, Replay::Discard)
                .await;
        } else if self.started {
            let _ = self
                .handle
                .retransmit_unconfirmed(conn, Replay::Retransmit)
                .await;
        } else if !self.failed.contains(&conn) {
            self.failed.push(conn);
        }
    }

    async fn set_state(&mut self, conn: usize, state: State) {
        if self.states.len() <= conn {
            self.states.resize(conn.saturating_add(1), State::Stopped);
        }
        if let Some(slot) = self.states.get_mut(conn) {
            *slot = state;
        }
        let started = self.states.contains(&State::Started);
        if started == self.started {
            return;
        }
        self.started = started;
        if started {
            self.on_started().await;
        } else {
            self.publish(&Update::Stopped);
            // A group that replays a failed connection's data on the next
            // one keeps waiting for the answers that data is owed.
            if !(self.group && self.config.retransmit_on_switchover) {
                self.fail_all(Lost::Connection);
            }
        }
    }

    async fn on_started(&mut self) {
        for waiter in self.waiting.drain(..) {
            let _ = waiter.send(Ok(()));
        }
        self.publish(&Update::Started);
        for failed in std::mem::take(&mut self.failed) {
            let _ = self
                .handle
                .retransmit_unconfirmed(failed, Replay::Retransmit)
                .await;
        }
        // TS 60870-5-604 5.4.13.10: after re-establishment normal operation
        // "begins the General Interrogation procedure".
        if self.config.interrogate_on_start {
            self.interrogate(Scope::Station, None).await;
        }
    }

    async fn on_asdu(&mut self, frame: Vec<u8>) {
        let sizes = self.config.sizes;
        let Ok(header) = Header::parse_with(&frame, sizes) else {
            return;
        };
        let decoded = asdu::decode_with(&frame, sizes);
        if header.type_id.direction() == Some(Direction::Monitor) {
            let update = match &decoded {
                Ok(asdu) => Update::Data(asdu.clone()),
                Err(error) => Update::Undecodable {
                    asdu: frame.clone(),
                    error: *error,
                },
            };
            self.publish(&update);
        }
        let decoded = decoded.ok();
        match route(&header) {
            Route::Interrogation => self.on_interrogation(&frame, &header, decoded),
            Route::CounterInterrogation => self.on_counter(&frame, decoded),
            Route::Command => self.on_command(&frame, &header).await,
            Route::ClockSync => self.on_clock_sync(&frame, &header),
            Route::Read => self.on_read(&frame, decoded),
            Route::Test => self.on_test(&frame),
            Route::NotImplemented if header.type_id == TypeId::CRpNa1 => self.on_reset(&header),
            Route::Parameter => self.on_parameter(&frame, &header),
            _ => {}
        }
    }

    fn on_parameter(&mut self, frame: &[u8], header: &Header) {
        let Ok(outcome) = self.pm.on_response(frame, &KNOWN) else {
            return;
        };
        let (index, result) = match outcome.reaction {
            // The confirmation of a load or an activation carries the value
            // now in operation (5-101 cl.7.4.9).
            pm::Reaction::Confirmed {
                ioa,
                value,
                negative,
            } => {
                let Some((index, load)) = self
                    .parameters
                    .iter()
                    .enumerate()
                    .find(|(_, p)| {
                        p.is_for(ioa, value.family()) && p.load != ParameterRequest::Deactivate
                    })
                    .map(|(index, p)| (index, p.load))
                else {
                    return;
                };
                let in_operation = Parameter::new(ioa, value);
                let result = match (load, negative) {
                    (ParameterRequest::Load, false) => Ok(Some(in_operation)),
                    (ParameterRequest::Load, true) => {
                        Err(ClientError::ParameterRejected { in_operation })
                    }
                    (_, false) => Ok(None),
                    (_, true) => Err(ClientError::Rejected),
                };
                (index, result)
            }
            pm::Reaction::Deactivated { ioa, negative, .. } => {
                let Some(index) = self.parameters.iter().position(|p| {
                    p.is_for(ioa, pm::Family::Activation) && p.load == ParameterRequest::Deactivate
                }) else {
                    return;
                };
                (
                    index,
                    if negative {
                        Err(ClientError::Rejected)
                    } else {
                        Ok(None)
                    },
                )
            }
            // The procedure reports a received 44–47 mirror as a discard; its
            // type, address and cause are in the mirrored frame (5-101
            // cl.7.2.3).
            pm::Reaction::Discard(Discard::Mirror) => {
                let sizes = self.config.sizes;
                let (Some(family), Some(Ok(ioa))) = (
                    pm::Family::of_type(header.type_id),
                    frame
                        .get(sizes.header_len()..)
                        .map(|object| read_ioa_with(object, sizes)),
                ) else {
                    return;
                };
                let Some(index) = self.parameters.iter().position(|p| p.is_for(ioa, family)) else {
                    return;
                };
                (
                    index,
                    Err(ClientError::Refused {
                        cause: header.cause,
                    }),
                )
            }
            _ => return,
        };
        let pending = self.parameters.remove(index);
        let _ = pending.reply.send(result);
    }

    /// Figure 77's monitor-direction causes: `<7>` activation confirmation
    /// (`P/N` its sign, 5-101 cl.7.2.3) and the 44–47 mirror.
    fn on_reset(&mut self, header: &Header) {
        let result = if is_mirror(header) {
            Err(ClientError::Refused {
                cause: header.cause,
            })
        } else if header.cause == Cause::ActivationCon {
            if header.negative {
                Err(ClientError::Rejected)
            } else {
                Ok(())
            }
        } else {
            return;
        };
        if let Some((_, reply)) = self.reset.take() {
            let _ = reply.send(result);
        }
    }

    fn on_test(&mut self, frame: &[u8]) {
        let Some((_, sent, _)) = self.test else {
            return;
        };
        let result = match self.ts.on_response(frame, &KNOWN, sent) {
            Ok(outcome) => match outcome.reaction {
                ts::Reaction::Answered {
                    negative: false, ..
                } => Ok(()),
                ts::Reaction::Answered { negative: true, .. } => Err(ClientError::Rejected),
                ts::Reaction::Refused { cause } => Err(ClientError::Refused { cause }),
                _ => return,
            },
            // 104 cl.8.8: the confirmation echoes the TSC and the time.
            Err(e @ ts::TsError::EchoMismatch { .. }) => Err(ClientError::Test(e)),
            Err(_) => return,
        };
        if let Some((_, _, reply)) = self.test.take() {
            let _ = reply.send(result);
        }
    }

    fn on_interrogation(&mut self, frame: &[u8], header: &Header, decoded: Option<Asdu>) {
        let Ok(outcome) = self.gi.on_response(frame, &KNOWN) else {
            return;
        };
        let (scope, result) = match outcome.reaction {
            gi::Reaction::DeactivationConfirmed { scope, negative } => {
                let Some(index) = self.interrogations.iter().position(|p| p.scope == scope) else {
                    return;
                };
                // The procedure ends either way: a positive DEACTCON stops it
                // (TS 60870-5-604 5.4.17.50), a negative one says the station
                // had nothing of the scope running.
                let pending = self.interrogations.remove(index);
                self.gi.abandon(scope);
                if let Some((_, reply)) = pending.stop {
                    let _ = reply.send(if negative {
                        Err(ClientError::Rejected)
                    } else {
                        Ok(())
                    });
                }
                for reply in pending.replies {
                    let _ = reply.send(Err(ClientError::Deactivated));
                }
                return;
            }
            // The procedure reports a mirror of a running scope's frame as a
            // discard: that is the refusal of the deactivation, and the
            // interrogation goes on.
            gi::Reaction::Discard(Discard::Mirror) => {
                let scope = match decoded.map(|asdu| asdu.objects) {
                    Some(Objects::CIcNa1(objects)) => {
                        objects.first().and_then(|o| Scope::from_qoi(o.value.qoi))
                    }
                    _ => None,
                };
                if let Some(pending) = self
                    .interrogations
                    .iter_mut()
                    .find(|p| Some(p.scope) == scope)
                    && let Some((_, reply)) = pending.stop.take()
                {
                    let _ = reply.send(Err(ClientError::Refused {
                        cause: header.cause,
                    }));
                }
                return;
            }
            gi::Reaction::ActivationConfirmed {
                scope,
                negative: false,
            } => {
                if let Some(pending) = self.interrogations.iter_mut().find(|p| p.scope == scope) {
                    pending.confirmed = true;
                }
                return;
            }
            gi::Reaction::Interrogated { scope } => {
                if let (Some(pending), Some(asdu)) = (
                    self.interrogations.iter_mut().find(|p| p.scope == scope),
                    decoded,
                ) {
                    pending.objects.push(asdu);
                }
                return;
            }
            gi::Reaction::ActivationConfirmed {
                scope,
                negative: true,
            } => (scope, Err(ClientError::Rejected)),
            gi::Reaction::Terminated { scope } => (scope, Ok(())),
            gi::Reaction::Refused {
                scope: Some(scope),
                cause,
            } => (scope, Err(ClientError::Refused { cause })),
            _ => return,
        };
        let Some(index) = self.interrogations.iter().position(|p| p.scope == scope) else {
            return;
        };
        let pending = self.interrogations.remove(index);
        self.gi.abandon(scope);
        if let Some((_, reply)) = pending.stop {
            // Ended before the deactivation was answered: a mirror that
            // settles the activation refuses both, anything else leaves
            // nothing running to stop.
            let _ = reply.send(Err(match &result {
                Err(refused @ ClientError::Refused { .. }) => refused.clone(),
                _ => ClientError::Interrogation(gi::GiError::NotRunning),
            }));
        }
        for reply in pending.replies {
            let _ = reply.send(result.clone().map(|()| pending.objects.clone()));
        }
    }

    fn on_counter(&mut self, frame: &[u8], decoded: Option<Asdu>) {
        let Ok(outcome) = self.ci.on_response(frame, &KNOWN) else {
            return;
        };
        let (request, result) = match outcome.reaction {
            ci::Reaction::ActivationConfirmed {
                request,
                freeze,
                negative: false,
            } => {
                let Some(pending) = self.counters.iter_mut().find(|p| p.request == request) else {
                    return;
                };
                pending.confirmed = true;
                // 5-101 figure 95: a freeze or reset has no data and no
                // termination; its confirmation ends it.
                if freeze == FreezeMode::Read {
                    return;
                }
                (request, Ok(()))
            }
            ci::Reaction::Counted { request } => {
                if let (Some(pending), Some(asdu)) = (
                    self.counters.iter_mut().find(|p| p.request == request),
                    decoded,
                ) {
                    pending.objects.push(asdu);
                }
                return;
            }
            ci::Reaction::ActivationConfirmed {
                request,
                negative: true,
                ..
            } => (request, Err(ClientError::Rejected)),
            ci::Reaction::Terminated { request } => (request, Ok(())),
            ci::Reaction::Refused {
                activation: Some((request, _)),
                cause,
            } => (request, Err(ClientError::Refused { cause })),
            _ => return,
        };
        let Some(index) = self.counters.iter().position(|p| p.request == request) else {
            return;
        };
        let pending = self.counters.remove(index);
        self.ci.abandon(request);
        for reply in pending.replies {
            let _ = reply.send(result.clone().map(|()| pending.objects.clone()));
        }
    }

    async fn on_command(&mut self, frame: &[u8], header: &Header) {
        let Ok(outcome) = self.ct.on_response(frame, &KNOWN) else {
            return;
        };
        let (ioa, result) = match outcome.reaction {
            ct::Reaction::Confirmed {
                ioa,
                select,
                negative,
            } => {
                let Some((index, stage, call)) = self
                    .commands
                    .iter()
                    .enumerate()
                    .find(|(_, c)| c.command.ioa == ioa)
                    .map(|(index, c)| (index, c.stage, c.call))
                else {
                    return;
                };
                match (stage, select, negative) {
                    (Stage::Selecting, true, false) => {
                        if call == Call::Select {
                            // The select alone was asked for: the procedure
                            // keeps it for the execute or the cancel.
                            let pending = self.commands.remove(index);
                            pending.reply.send(Ok(CommandOutcome::Confirmed));
                        } else {
                            self.execute_selected(index).await;
                        }
                        return;
                    }
                    (Stage::Executing, false, false) => {
                        let Some(command) = self.commands.get_mut(index) else {
                            return;
                        };
                        if self.config.termination.uses(command.command.family()) {
                            command.stage = Stage::Terminating;
                            command.deadline = later(Self::now(), self.config.timeouts.termination);
                            return;
                        }
                        (ioa, Ok(CommandOutcome::Confirmed))
                    }
                    (Stage::Selecting, true, true) | (Stage::Executing, false, true) => {
                        (ioa, Err(ClientError::Rejected))
                    }
                    _ => return,
                }
            }
            ct::Reaction::Terminated { ioa, negative } => {
                let running = self
                    .commands
                    .iter()
                    .any(|c| c.command.ioa == ioa && c.stage.executed());
                if !running {
                    return;
                }
                if negative {
                    (ioa, Err(ClientError::Failed))
                } else {
                    (ioa, Ok(CommandOutcome::Terminated))
                }
            }
            ct::Reaction::Deactivated { ioa } => {
                let cancelling = self
                    .commands
                    .iter()
                    .any(|c| c.command.ioa == ioa && c.stage == Stage::Deactivating);
                if !cancelling {
                    return;
                }
                // The `P/N` bit of 5-101 cl.7.2.3, on the deactivation's
                // confirmation: a negative one refuses the deactivation.
                if header.negative {
                    (ioa, Err(ClientError::Rejected))
                } else {
                    (ioa, Ok(CommandOutcome::Confirmed))
                }
            }
            ct::Reaction::Refused { ioa, cause } => (ioa, Err(ClientError::Refused { cause })),
            ct::Reaction::NotMirrored { ioa } => (ioa, Err(ClientError::NotMirrored)),
            // The command procedure reports a received 44–47 mirror as a
            // discard and forgets the command; its cause and address are in
            // the mirrored frame (5-101 cl.7.2.3).
            ct::Reaction::Discard(Discard::Mirror) => {
                let sizes = self.config.sizes;
                let Some(object) = frame.get(sizes.header_len()..) else {
                    return;
                };
                let Ok(ioa) = read_ioa_with(object, sizes) else {
                    return;
                };
                let cause = header.cause;
                (ioa, Err(ClientError::Refused { cause }))
            }
            _ => return,
        };
        self.finish_command(ioa, result);
    }

    /// The select is confirmed: send the execute (TS 60870-5-604 5.4.19.1).
    async fn execute_selected(&mut self, index: usize) {
        let Some(command) = self.commands.get(index).map(|pending| pending.command) else {
            return;
        };
        let result = match self.ct.execute(&command) {
            Ok(frame) => self.send(frame).await,
            Err(e) => Err(ClientError::Command(e)),
        };
        match result {
            Ok(()) => {
                if let Some(pending) = self.commands.get_mut(index) {
                    pending.stage = Stage::Executing;
                    pending.deadline = later(Self::now(), self.config.timeouts.confirmation);
                }
            }
            // The execute did not go out; only the select did, which
            // operates nothing.
            Err(e) => self.finish_command(command.ioa, Err(e)),
        }
    }

    fn finish_command(&mut self, ioa: u32, result: Result<CommandOutcome, ClientError>) {
        let Some(index) = self.commands.iter().position(|c| c.command.ioa == ioa) else {
            return;
        };
        let pending = self.commands.remove(index);
        self.ct.abandon(ioa);
        pending.reply.send(result);
    }

    fn on_clock_sync(&mut self, frame: &[u8], header: &Header) {
        let Ok(outcome) = self.cs.on_response(frame, &KNOWN) else {
            return;
        };
        let result = match outcome.reaction {
            cs::Reaction::Answered {
                negative: false, ..
            } => Ok(()),
            cs::Reaction::Answered { negative: true, .. } => Err(ClientError::Rejected),
            cs::Reaction::Refused { cause } => Err(ClientError::Refused { cause }),
            // Reported as a discard, as the command procedure does.
            cs::Reaction::Discard(Discard::Mirror) => Err(ClientError::Refused {
                cause: header.cause,
            }),
            _ => return,
        };
        if let Some((_, reply)) = self.clock_sync.take() {
            let _ = reply.send(result);
        }
    }

    fn on_read(&mut self, frame: &[u8], decoded: Option<Asdu>) {
        let Ok(outcome) = self.rd.on_response(frame, &KNOWN) else {
            return;
        };
        let (ioa, result) = match (outcome.reaction, decoded) {
            (rd::Reaction::Answered { ioa, .. }, Some(asdu)) => (ioa, Ok(asdu)),
            (rd::Reaction::Refused { ioa, cause }, _) => (ioa, Err(ClientError::Refused { cause })),
            _ => return,
        };
        let Some(index) = self.reads.iter().position(|r| r.ioa == ioa) else {
            return;
        };
        for reply in self.reads.remove(index).replies {
            let _ = reply.send(result.clone());
        }
    }

    // ------------------------------------------------------------ time-outs

    fn expire(&mut self, now: Instant) {
        let timeouts = self.config.timeouts;

        let (due, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.commands)
            .into_iter()
            .partition(|c| c.deadline <= now);
        self.commands = kept;
        for command in due {
            self.ct.abandon(command.command.ioa);
            command.reply.send(Err(if command.stage.executed() {
                ClientError::OutcomeUnknown
            } else {
                ClientError::Timeout
            }));
        }

        let (due, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.interrogations)
            .into_iter()
            .partition(|p| procedure_deadline(p.sent, p.confirmed, timeouts) <= now);
        self.interrogations = kept;
        for pending in due {
            self.gi.abandon(pending.scope);
            if let Some((_, reply)) = pending.stop {
                let _ = reply.send(Err(ClientError::Timeout));
            }
            for reply in pending.replies {
                let _ = reply.send(Err(ClientError::Timeout));
            }
        }
        // An unanswered deactivation leaves the interrogation running
        // (the procedure clears a scope only at its DEACTCON).
        for pending in &mut self.interrogations {
            if pending.stop.as_ref().is_some_and(|(d, _)| *d <= now)
                && let Some((_, reply)) = pending.stop.take()
            {
                let _ = reply.send(Err(ClientError::Timeout));
            }
        }

        let (due, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.counters)
            .into_iter()
            .partition(|p| procedure_deadline(p.sent, p.confirmed, timeouts) <= now);
        self.counters = kept;
        for pending in due {
            self.ci.abandon(pending.request);
            for reply in pending.replies {
                let _ = reply.send(Err(ClientError::Timeout));
            }
        }

        if self.clock_sync.as_ref().is_some_and(|(d, _)| *d <= now)
            && let Some((_, reply)) = self.clock_sync.take()
        {
            let _ = reply.send(Err(ClientError::Timeout));
        }

        let (due, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.reads)
            .into_iter()
            .partition(|r| r.deadline <= now);
        self.reads = kept;
        for pending in due {
            for reply in pending.replies {
                let _ = reply.send(Err(ClientError::Timeout));
            }
        }

        if self.test.as_ref().is_some_and(|(d, _, _)| *d <= now)
            && let Some((_, _, reply)) = self.test.take()
        {
            let _ = reply.send(Err(ClientError::Timeout));
        }

        if self.reset.as_ref().is_some_and(|(d, _)| *d <= now)
            && let Some((_, reply)) = self.reset.take()
        {
            let _ = reply.send(Err(ClientError::OutcomeUnknown));
        }

        let (due, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut self.parameters)
            .into_iter()
            .partition(|p| p.deadline <= now);
        self.parameters = kept;
        for pending in due {
            let _ = pending.reply.send(Err(ClientError::OutcomeUnknown));
        }
    }

    /// Ends everything outstanding: the answers can no longer come.
    fn fail_all(&mut self, lost: Lost) {
        for command in self.commands.drain(..) {
            command.reply.send(Err(if command.stage.executed() {
                ClientError::OutcomeUnknown
            } else {
                lost.error()
            }));
        }
        self.ct.reset();
        for pending in self.interrogations.drain(..) {
            if let Some((_, reply)) = pending.stop {
                let _ = reply.send(Err(lost.error()));
            }
            for reply in pending.replies {
                let _ = reply.send(Err(lost.error()));
            }
        }
        self.gi.reset();
        for pending in self.counters.drain(..) {
            for reply in pending.replies {
                let _ = reply.send(Err(lost.error()));
            }
        }
        self.ci.reset();
        if let Some((_, reply)) = self.clock_sync.take() {
            let _ = reply.send(Err(lost.error()));
        }
        for pending in self.reads.drain(..) {
            for reply in pending.replies {
                let _ = reply.send(Err(lost.error()));
            }
        }
        if let Some((_, _, reply)) = self.test.take() {
            let _ = reply.send(Err(lost.error()));
        }
        if let Some((_, reply)) = self.reset.take() {
            let _ = reply.send(Err(ClientError::OutcomeUnknown));
        }
        for pending in self.parameters.drain(..) {
            let _ = pending.reply.send(Err(ClientError::OutcomeUnknown));
        }
        if lost == Lost::Stopped {
            for waiter in self.waiting.drain(..) {
                let _ = waiter.send(Err(lost.error()));
            }
        }
    }
}
