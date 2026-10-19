//! The task behind a [`super::Server`]: it owns the controlled instances of
//! the core's procedures and the image, reads the driver's events, hands each
//! received ASDU to the procedure [`iec104::dispatch::route`] names, and
//! empties the send queue into the k window.

use std::collections::BTreeMap;
use std::sync::Arc;

use iec104::asdu::{
    Cause, FreezeMode, Header, Known, Point, TimeTag, Unspecified, Value, is_mirror, mirror_frame,
};
use iec104::ci::{self, CounterInterrogation};
use iec104::cs::{self, ClockSynchronisation, TimeValidity};
use iec104::ct::{self, Command, CommandTransmission, Family};
use iec104::dispatch::{Route, not_implemented, route};
use iec104::gi::{self, Interrogation};
use iec104::init::end_of_initialisation_with;
use iec104::link::State;
use iec104::rd::Read;
use iec104::redundancy::{Replay, Switchover};
use iec104::ts::{self, TestProcedure};
use iec104::tx::Priority;
use tokio::sync::mpsc;

use super::image::{Addressing, Entry, Image, ReadSource, Sample, is_tagged, same_kind};
use super::queue::{Item, Queue};
use super::{Application, Clock, Request, ServerConfig, ServerError};
use crate::{Event, Events, Handle};

/// Every ASDU goes to the group, which sends it on its started connection.
const CONN: usize = 0;

/// An execute's operation finished.
#[derive(Clone, Copy)]
struct Operated {
    ioa: u32,
    ok: bool,
}

struct Task<A> {
    handle: Handle,
    app: Arc<A>,
    clock: Clock,
    common_address: u16,
    sizes: iec104::asdu::AddressSizes,
    max_command_delay: Option<std::time::Duration>,
    counter_mode: ci::CounterMode,
    commands: BTreeMap<u32, Family>,
    image: Image,
    queue: Queue,
    gi: Interrogation,
    ci: CounterInterrogation,
    cs: ClockSynchronisation,
    rd: Read,
    ts: TestProcedure,
    ct: CommandTransmission,
    validity: TimeValidity,
    /// Each connection's last reported state.
    states: Vec<State>,
    started: bool,
    /// Group members that failed while started, whose unconfirmed data goes
    /// out again on the next started connection.
    failed: Vec<usize>,
    operated: mpsc::UnboundedSender<Operated>,
}

fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

pub(super) async fn run<A: Application>(
    handle: Handle,
    mut events: Events,
    mut requests: mpsc::Receiver<Request>,
    config: ServerConfig,
    app: A,
) {
    let (ca, sizes) = (config.common_address, config.sizes);
    let addressing = Addressing {
        common_address: ca,
        sizes,
    };
    // 104 cl.7.6: the invalid mark is *"also set after station
    // initializiation (warm and cold boot) of controlled stations before
    // reception of a valid C_CS ACT PDU."* A new record starts in that state.
    let validity = if config.external_clock {
        // 104 cl.7.6's "clock synchronization receivers or similar
        // equipment" keep the clock: it is synchronised from the start and
        // never overdue.
        let mut validity = TimeValidity::new(std::time::Duration::MAX);
        validity.synchronised(now());
        validity
    } else {
        TimeValidity::new(config.sync_interval)
    };
    let entries = config
        .points
        .iter()
        .map(|(&ioa, point)| {
            let time =
                is_tagged(point, &point.value).then(|| validity.mark((config.clock)(), now()));
            let sample = Sample {
                value: point.value,
                quality: point.quality,
                time,
            };
            (
                ioa,
                Entry {
                    config: *point,
                    sample,
                },
            )
        })
        .collect();
    let (operated, mut operated_rx) = mpsc::unbounded_channel();
    let mut task = Task {
        handle,
        app: Arc::new(app),
        clock: Arc::clone(&config.clock),
        common_address: ca,
        sizes,
        max_command_delay: config.max_command_delay,
        counter_mode: config.counter_mode,
        commands: config.commands.clone(),
        image: Image {
            entries,
            addressing,
            frozen: Vec::new(),
        },
        queue: Queue::new(sizes, config.event_buffer),
        gi: Interrogation::controlled(config.reactivation, ca, 0).with_address_sizes(sizes),
        ci: CounterInterrogation::controlled(config.counter_mode, ca, 0).with_address_sizes(sizes),
        cs: ClockSynchronisation::controlled(ca, 0).with_address_sizes(sizes),
        rd: Read::controlled(true, ca, 0).with_address_sizes(sizes),
        ts: TestProcedure::controlled(ts::Selection::TAGGED, ca, 0).with_address_sizes(sizes),
        ct: CommandTransmission::controlled(
            config.command_mode,
            config.command_set,
            config.termination,
            ca,
            0,
        )
        .with_address_sizes(sizes)
        .with_select_timeout(config.select_timeout),
        validity,
        states: Vec::new(),
        started: false,
        failed: Vec::new(),
        operated,
    };
    if let Some(max) = config.max_command_delay {
        task.ct = task.ct.with_max_command_delay(max);
    }
    // 104 cl.7.1 figure 21 and 10.4 figure 33: the end of initialisation,
    // optional, first of all (5-101 Table 16's first row). It waits in the
    // queue for the first STARTDT (cl.5.3).
    if let Some(coi) = config.end_of_initialisation
        && let Ok(asdu) = end_of_initialisation_with(coi, ca, 0, sizes)
    {
        task.queue.frame(asdu);
    }
    loop {
        tokio::select! {
            request = requests.recv() => if let Some(request) = request { task.on_request(request) } else {
                // Every server handle is gone.
                task.handle.shutdown().await;
                return;
            },
            event = events.recv() => match event {
                Some(event) => task.on_event(event).await,
                None => return,
            },
            Some(done) = operated_rx.recv() => task.on_operated(done),
        }
        task.release().await;
    }
}

impl<A: Application> Task<A> {
    fn on_request(&mut self, request: Request) {
        match request {
            Request::Write {
                ioa,
                value,
                quality,
                time,
                event,
                reply,
            } => {
                let _ = reply.send(self.write(ioa, value, quality, time, event));
            }
            Request::Point(ioa, reply) => {
                let point = self
                    .image
                    .entries
                    .get(&ioa)
                    .map(|entry| Point {
                        ioa,
                        value: entry.sample.value,
                        quality: Some(entry.sample.quality),
                        time: entry.sample.time.map(TimeTag::Cp56),
                    })
                    .ok_or(ServerError::UnknownAddress(ioa));
                let _ = reply.send(point);
            }
            Request::Dropped(reply) => {
                let _ = reply.send(Ok(self.queue.dropped));
            }
        }
    }

    fn write(
        &mut self,
        ioa: u32,
        value: Value,
        quality: iec104::asdu::Quality,
        time: Option<iec104::asdu::Cp56Time2a>,
        event: Option<Cause>,
    ) -> Result<(), ServerError> {
        let entry = self
            .image
            .entries
            .get_mut(&ioa)
            .ok_or(ServerError::UnknownAddress(ioa))?;
        if !same_kind(&entry.config.value, &value) {
            return Err(ServerError::WrongKind(ioa));
        }
        // 104 cl.7.6: the mark describes the clock that stamped the value, so
        // it is set now, not when the event is sent.
        let time = is_tagged(&entry.config, &value).then(|| {
            let time = time.unwrap_or_else(|| (self.clock)());
            self.validity.mark(time, now())
        });
        entry.sample = super::image::Sample {
            value,
            quality,
            time,
        };
        if let Some(cause) = event
            && let Some(asdu) = self.image.event(ioa, cause).map_err(ServerError::Layout)?
        {
            self.queue.event(asdu);
        }
        Ok(())
    }

    async fn on_event(&mut self, event: Event) {
        match event {
            Event::Asdu { asdu, .. } => self.on_asdu(&asdu),
            Event::State { conn, state } => self.set_state(conn, state).await,
            Event::Disconnected { conn, .. } => self.set_state(conn, State::Stopped).await,
            Event::StartedConnectionFailed { conn, .. } => self.on_failed(conn).await,
            Event::Switchover(
                Switchover::Automatic { failed, .. }
                | Switchover::NoStoppedConnection { failed, .. }
                | Switchover::LeftToTheControllingStation { failed, .. },
            ) => self.on_failed(failed).await,
            _ => {}
        }
    }

    /// A started connection failed and left unconfirmed ASDUs behind: they go
    /// out again on the next started connection (104 cl.10.6).
    async fn on_failed(&mut self, conn: usize) {
        if self.started {
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
            // The replayed frames first, then the queue (104 cl.10.6).
            for failed in std::mem::take(&mut self.failed) {
                let _ = self
                    .handle
                    .retransmit_unconfirmed(failed, Replay::Retransmit)
                    .await;
            }
        }
    }

    fn on_asdu(&mut self, asdu: &[u8]) {
        let Ok(header) = Header::parse_with(asdu, self.sizes) else {
            return;
        };
        let own = header.common_address == self.common_address
            || header.common_address == self.sizes.broadcast_common_address();
        let known = Known::standard(&header, own, true);
        match route(&header) {
            Route::Interrogation => {
                if let Ok(outcome) = self.gi.on_request(asdu, &known, &self.image) {
                    self.stop_answers(&outcome);
                    self.send_all(outcome.send);
                    if let gi::Reaction::ActivationConfirmed {
                        negative: false, ..
                    } = outcome.reaction
                    {
                        self.queue
                            .push(Priority::Interrogation, Item::Interrogation);
                    }
                }
            }
            Route::CounterInterrogation => self.on_counter(asdu, known),
            Route::ClockSync => {
                // 104 cl.7.6: the answer carries "the local time before it
                // was synchronized".
                let before = (self.clock)();
                if let Ok(outcome) = self.cs.on_request(asdu, &known, before) {
                    let valid = self.validity.on_outcome(&outcome, now());
                    let reaction = outcome.reaction;
                    self.send_all(outcome.send);
                    if valid && let cs::Reaction::Requested { time } = reaction {
                        self.app.synchronise(time);
                    }
                }
            }
            Route::Read => {
                // Answered when handed over, from the image as it is then.
                self.queue
                    .push(Priority::Request, Item::Read(asdu.to_vec()));
            }
            Route::Test => {
                if let Ok(outcome) = self.ts.on_request(asdu, &known) {
                    self.send_all(outcome.send);
                }
            }
            Route::Command => self.on_command(asdu, &header, known),
            Route::Parameter | Route::FileTransfer | Route::NotImplemented => {
                if let Some(mirror) =
                    not_implemented(&header, asdu, self.common_address, self.sizes)
                {
                    self.queue.frame(mirror);
                }
            }
            // Monitor-direction data a controlled station does not receive.
            Route::Init | Route::Transmission | Route::Discard => {}
        }
    }

    /// Drops the rest of an interrogation's answer that the procedure has
    /// just stopped. TS 60870-5-604 5.4.17.50: after the `C_IC_DEACTCON`
    /// *"No further Information Objects that are part of the GI for that QOI
    /// are sent to the Controlling station. No Interrogation Command with
    /// COT = 10 (ACTTERM) to the Controlling station"*. A positive
    /// deactivation confirmation stops the answer of its scope. A second
    /// activation under `ReActivation::Restart` (5.4.17.30, *"Option 2: the
    /// running GI is stopped and the second GI is started"*) stops the
    /// running one with its termination, which the procedure sends itself,
    /// so its answer is dropped too.
    fn stop_answers(&mut self, outcome: &gi::Outcome) {
        match outcome.reaction {
            gi::Reaction::DeactivationConfirmed {
                scope,
                negative: false,
            } => self.queue.drop_answers(|s| s == scope),
            gi::Reaction::ActivationConfirmed {
                negative: false, ..
            } if outcome.send.iter().any(|frame| {
                Header::parse_with(frame, self.sizes)
                    .is_ok_and(|header| header.cause == Cause::ActivationTermination)
            }) =>
            {
                self.queue.drop_answers(|_| true);
            }
            _ => {}
        }
    }

    fn on_counter(&mut self, asdu: &[u8], known: Known) {
        let Ok(outcome) = self.ci.on_request(asdu, &known, &self.image) else {
            return;
        };
        self.send_all(outcome.send);
        let ci::Reaction::ActivationConfirmed {
            request,
            freeze,
            negative: false,
        } = outcome.reaction
        else {
            return;
        };
        match freeze {
            FreezeMode::Read => {
                self.queue
                    .push(Priority::Interrogation, Item::CounterInterrogation);
                return;
            }
            FreezeMode::FreezeWithoutReset => self.image.freeze(request),
            FreezeMode::FreezeWithReset => {
                self.image.freeze(request);
                self.app.reset_counters(request);
            }
            FreezeMode::Reset => self.app.reset_counters(request),
        }
        // Mode D: *"a combination of the counter command from the
        // controlling station as specified in mode C, with spontaneous
        // reporting of the integrated totals, as described in mode A"*.
        if freeze != FreezeMode::Reset
            && self.counter_mode.reports_spontaneously()
            && let Ok(frames) = self.image.frozen_events(request)
        {
            for frame in frames {
                self.queue.event(frame);
            }
        }
    }

    fn on_command(&mut self, asdu: &[u8], header: &Header, known: Known) {
        let addressed = matches!(header.cause, Cause::Activation | Cause::Deactivation)
            && !is_mirror(header)
            && header.common_address == self.common_address;
        if addressed && let Ok(Some(command)) = ct::decode_command_with(asdu, self.sizes) {
            match self.commands.get(&command.ioa) {
                // TS 60870-5-604 5.4.19.50: *"In case of a not existing
                // Information object, the controlled station could instead
                // mirror the same ASDU with COT=47"*.
                None => {
                    self.queue.frame(mirror_frame(
                        header,
                        asdu,
                        Unspecified::InformationObjectAddress,
                        self.common_address,
                        self.sizes,
                    ));
                    return;
                }
                // A command this object does not take: not controllable
                // with it, the negative confirmation of 5.4.19.50.
                Some(family) if *family != command.family() => {
                    self.refuse(asdu);
                    return;
                }
                Some(_) => {}
            }
            if header.cause == Cause::Activation && !self.app.accept(&command) {
                self.refuse(asdu);
                return;
            }
        }
        let wall_clock = self.max_command_delay.map(|_| (self.clock)());
        let Ok(outcome) = self.ct.on_request_at(asdu, &known, now(), wall_clock) else {
            return;
        };
        let reaction = outcome.reaction;
        self.send_all(outcome.send);
        if let ct::Reaction::Confirmed {
            select: false,
            negative: false,
            ..
        } = reaction
            && let Ok(Some(command)) = ct::decode_command_with(asdu, self.sizes)
        {
            self.operate(command);
        }
    }

    fn refuse(&mut self, asdu: &[u8]) {
        if let Ok(outcome) = self.ct.refuse(asdu) {
            self.send_all(outcome.send);
        }
    }

    /// Runs the application's operation in a task of its own. An operation
    /// that panics counts as failed, so its object is still terminated and
    /// released rather than held until restart.
    fn operate(&self, command: Command) {
        let app = Arc::clone(&self.app);
        let done = self.operated.clone();
        tokio::spawn(async move {
            let ok = tokio::spawn(async move { app.operate(command).await })
                .await
                .unwrap_or(false);
            let _ = done.send(Operated {
                ioa: command.ioa,
                ok,
            });
        });
    }

    /// The termination of an operated execute, where its family has one.
    fn on_operated(&mut self, done: Operated) {
        if self.ct.is_running(done.ioa)
            && let Ok(frame) = self.ct.terminate(done.ioa, !done.ok)
        {
            self.queue.frame(frame);
        }
    }

    fn send_all(&mut self, frames: Vec<Vec<u8>>) {
        for frame in frames {
            self.queue.frame(frame);
        }
    }

    /// The frames an item stands for, encoded now.
    fn expand(&mut self, item: Item) -> Vec<Vec<u8>> {
        match item {
            Item::Frame { asdu, .. } => vec![asdu],
            // Taken apart in `next_frame`.
            Item::Interrogation | Item::Answer { .. } => Vec::new(),
            Item::CounterInterrogation => self.ci.complete(&self.image).unwrap_or_default(),
            Item::Read(request) => {
                let Ok(header) = Header::parse_with(&request, self.sizes) else {
                    return Vec::new();
                };
                let own = header.common_address == self.common_address
                    || header.common_address == self.sizes.broadcast_common_address();
                let known = Known::standard(&header, own, true);
                let source = ReadSource {
                    image: &self.image,
                    originator: header.originator,
                    test: header.test,
                };
                self.rd
                    .on_request(&request, &known, &source)
                    .map(|outcome| outcome.send)
                    .unwrap_or_default()
            }
        }
    }

    /// Hands the driver what the k window has room for, one ASDU per free
    /// slot, highest row first (5-101 Table 16). Nothing goes out while no
    /// connection is started (104 cl.5.3).
    async fn release(&mut self) {
        while self.started && !self.queue.is_empty() {
            let room = match self.handle.window(CONN).await {
                Ok(room) if room > 0 => room,
                _ => return,
            };
            for _ in 0..room {
                let Some(frame) = self.next_frame() else {
                    return;
                };
                if self.handle.send_asdu(CONN, frame.clone()).await.is_err() {
                    self.queue.put_back(vec![frame]);
                    return;
                }
            }
        }
    }

    /// The next ASDU to send, one per free slot of the window.
    ///
    /// A running interrogation's data is encoded when its entry is taken
    /// (`gi::Interrogation::interrogated`) and kept as an answer at the head
    /// of the interrogation row. Each ASDU of it leaves on its own, so
    /// anything queued later in a higher row overtakes the rest (5-101
    /// Table 16: *"they must be sent in the following order regardless of
    /// which data was generated first"*). Once the last one is out, the
    /// procedure is completed and its termination follows (5-101 cl.7.4.5).
    /// Until then the procedure runs, so a deactivation or a restart stops
    /// the rest of the answer ([`Task::stop_answers`]).
    ///
    /// Any other entry that stands for several ASDUs (a counter
    /// interrogation's totals and termination) gives its first one, and the
    /// rest go back to the head of their row in their order. Each answer
    /// ASDU is encoded again from the image as it goes ([`Image::refresh`]).
    fn next_frame(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.queue.pop()? {
                Item::Interrogation => {
                    // Nothing owed: deactivated, or already taken.
                    let Some(scope) = self.gi.running().first().copied() else {
                        continue;
                    };
                    let Ok(frames) = self.gi.interrogated(&self.image) else {
                        continue;
                    };
                    self.queue.push_front(
                        Priority::Interrogation,
                        Item::Answer {
                            scope,
                            frames: frames.into(),
                        },
                    );
                }
                Item::Answer { scope, mut frames } => {
                    if let Some(frame) = frames.pop_front() {
                        self.queue
                            .push_front(Priority::Interrogation, Item::Answer { scope, frames });
                        return Some(self.image.refresh(frame));
                    }
                    if !self.gi.is_running(scope) {
                        continue;
                    }
                    // The termination, and under `ReActivation::Queue` the
                    // data and termination of the interrogation that waited
                    // (TS 60870-5-604 5.4.17.40: *"after activation
                    // termination (COT=10) the second GI is started"*). Those
                    // go to the back of the row, behind the second one's own
                    // confirmation, which was queued when it arrived (5-101
                    // Table 17: `actcon`, the objects, `actterm`).
                    let mut rest = self
                        .gi
                        .complete(&self.image)
                        .unwrap_or_default()
                        .into_iter();
                    let Some(first) = rest.next() else {
                        continue;
                    };
                    for frame in rest {
                        self.queue.frame(frame);
                    }
                    return Some(self.image.refresh(first));
                }
                item => {
                    let mut frames = self.expand(item).into_iter();
                    let Some(first) = frames.next() else {
                        continue;
                    };
                    self.queue.put_back(frames.collect());
                    return Some(self.image.refresh(first));
                }
            }
        }
    }
}
