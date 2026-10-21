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
use iec104::ft::provide::{Provider, directory};
use iec104::ft::receive::{Progress, Receiver};
use iec104::ft::{self, FileTransferProcedure, Frame, Selection};
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
use super::{Application, Clock, Request, ServedFile, ServerConfig, ServerError};
use crate::{Event, Events, Handle};

/// Every ASDU goes to the group, which sends it on its started connection.
const CONN: usize = 0;

/// An execute's operation finished.
#[derive(Clone, Copy)]
struct Operated {
    ioa: u32,
    ok: bool,
}

/// What an operation's task reports.
#[derive(Clone, Copy)]
enum Report {
    /// The operation ended in time.
    Operated(Operated),
    /// The operation outlasted [`ServerConfig::operate_timeout`]: it counts
    /// as failed, but runs on and its object stays refused.
    TimedOut(u32),
    /// A timed-out operation really ended; its result goes nowhere.
    Ended(u32),
}

/// Where an execute's [`Report`]s go, with the logical link it arrived on
/// ([`Task::link`]).
struct Done(mpsc::UnboundedSender<(u64, Report)>, u64);

impl Done {
    fn send(&self, report: Report) -> Result<(), mpsc::error::SendError<(u64, Report)>> {
        self.0.send((self.1, report))
    }
}

struct Task<A> {
    handle: Handle,
    app: Arc<A>,
    clock: Clock,
    common_address: u16,
    sizes: iec104::asdu::AddressSizes,
    max_command_delay: Option<std::time::Duration>,
    operate_timeout: Option<std::time::Duration>,
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
    /// The connections with a socket now.
    connected: Vec<usize>,
    started: bool,
    /// Group members that failed while started, whose unconfirmed data goes
    /// out again on the next started connection.
    failed: Vec<usize>,
    /// Each operation's reports with the logical link its execute arrived on.
    operated: mpsc::UnboundedSender<(u64, Report)>,
    /// The objects with operations that timed out but still run, and how
    /// many (a family without `ACTTERM` can have several): every select and
    /// execute to them is refused until the last ends, whatever the link.
    overrun: BTreeMap<u32, usize>,
    /// The logical links gone so far: an operation outliving its link
    /// (104 cl.10.2) is told apart by it.
    link: u64,
    files: BTreeMap<u32, ServedFile>,
    ft: FileTransferProcedure,
    /// The transfers under way, by the file's address.
    providers: BTreeMap<u32, Provider>,
    /// The files being uploaded, by address, with their names.
    receivers: BTreeMap<u32, (iec104::asdu::Nof, Receiver)>,
}

fn now() -> std::time::Instant {
    tokio::time::Instant::now().into_std()
}

/// 104 cl.9.6's two file-transfer boxes: the monitor direction with declared
/// files, the control direction with uploads accepted.
fn selection(config: &ServerConfig) -> Selection {
    Selection {
        monitor: !config.files.is_empty(),
        control: config.accept_uploads,
    }
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
    // 104 cl.7.6: the invalid mark also applies from a controlled station's
    // initialisation (cold or warm start) until a valid C_CS ACT PDU
    // arrives. A new record starts in that state.
    let validity = if config.external_clock {
        // A dedicated time receiver or the like (104 cl.7.6) keeps the
        // clock: it is synchronised from the start and
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
        operate_timeout: config.operate_timeout,
        counter_mode: config.counter_mode,
        commands: config.commands.clone(),
        image: Image {
            entries,
            addressing,
            frozen: Vec::new(),
        },
        queue: Queue::new(sizes, config.event_buffer, config.request_buffer),
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
        connected: Vec::new(),
        started: false,
        failed: Vec::new(),
        operated,
        overrun: BTreeMap::new(),
        link: 0,
        files: config.files.clone(),
        ft: FileTransferProcedure::controlled(selection(&config), ca, 0).with_address_sizes(sizes),
        providers: BTreeMap::new(),
        receivers: BTreeMap::new(),
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
            Some((link, report)) = operated_rx.recv() => task.on_report(link, report),
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
        let previous = std::mem::replace(
            &mut entry.sample,
            super::image::Sample {
                value,
                quality,
                time,
            },
        );
        if let Some(cause) = event {
            match self.image.event(ioa, cause) {
                Ok(Some(asdu)) => self.queue.event(asdu),
                Ok(None) => {}
                Err(e) => {
                    // A report that cannot be sent leaves the image as it was.
                    if let Some(entry) = self.image.entries.get_mut(&ioa) {
                        entry.sample = previous;
                    }
                    return Err(ServerError::Layout(e));
                }
            }
        }
        Ok(())
    }

    async fn on_event(&mut self, event: Event) {
        match event {
            Event::Asdu { asdu, .. } => self.on_asdu(&asdu),
            Event::State { conn, state } => self.set_state(conn, state).await,
            Event::Connected { conn } => self.connected.push(conn),
            Event::Disconnected { conn, .. } => {
                self.connected.retain(|c| *c != conn);
                self.set_state(conn, State::Stopped).await;
                if self.connected.is_empty() {
                    self.link_gone();
                }
            }
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

    /// No member of the group has a socket any more: the logical link (104
    /// cl.10.2) is gone, and with it the controlling station that asked. Its
    /// answers, confirmations, terminations and selects are owed to nobody,
    /// so the next one gets none of them and cannot execute a select it did
    /// not make (TS 60870-5-604 5.4.13.10 starts it with a fresh general
    /// interrogation). The events stay for it. While another member is
    /// connected the link lives on, and everything carries over (cl.10.6).
    fn link_gone(&mut self) {
        self.queue.drop_requested();
        self.gi.reset();
        self.ci.reset();
        // An execute still being operated keeps its object until it ends.
        self.ct.drop_selects();
        self.link = self.link.wrapping_add(1);
    }

    fn on_asdu(&mut self, asdu: &[u8]) {
        let Ok(header) = Header::parse_with(asdu, self.sizes) else {
            return;
        };
        // Dropped before any procedure sees it, so nothing is owed for it:
        // the controlling station's own timeout covers the missing answer.
        if self.queue.refuses_request() {
            return;
        }
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
            Route::CounterInterrogation => self.on_counter(asdu, &header, known),
            Route::ClockSync => {
                // 104 cl.7.6: the answer carries "the local time before it
                // was synchronized".
                let before = (self.clock)();
                if let Ok(outcome) = self.cs.on_request(asdu, &known, before) {
                    let valid = self.validity.on_outcome(&outcome, now());
                    let reaction = outcome.reaction;
                    self.send_all(outcome.send);
                    if valid && let cs::Reaction::Requested { time, .. } = reaction {
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
            Route::FileTransfer if !self.files.is_empty() || self.ft.selection().control => {
                self.on_file(asdu, &header, known);
            }
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
    /// just stopped. TS 60870-5-604 5.4.17.50: after the `C_IC_DEACTCON` the
    /// controlling station gets no more objects of that QOI's interrogation
    /// and no COT = 10 (`ACTTERM`). A positive
    /// deactivation confirmation stops the answer of its scope. A second
    /// activation under `ReActivation::Restart` (5.4.17.30, option 2: the
    /// running GI is abandoned and the second one begins) stops the
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

    /// 5-101 cl.7.4.11 in the monitor direction, for the declared files, and
    /// in the control direction, for uploads.
    fn on_file(&mut self, asdu: &[u8], header: &Header, known: Known) {
        let Ok(outcome) = self.ft.on_asdu(asdu, &known) else {
            return;
        };
        let frame = match outcome.reaction {
            ft::Reaction::Requested { frame } => frame,
            ft::Reaction::Answered { frame } => return self.on_upload(asdu, &frame, known),
            _ => {
                // The procedure's own refusals (a broadcast, an unknown field,
                // a direction not served).
                for mirror in outcome.send {
                    self.queue.frame(mirror);
                }
                return;
            }
        };
        if let Frame::Sc { scq, .. } = &frame
            && scq.action == ft::SCQ_CALL_DIRECTORY
        {
            for asdu in self.directory() {
                self.queue.frame(asdu);
            }
            return;
        }
        let ioa = frame.ioa();
        let Some(file) = self.files.get(&ioa) else {
            // 5-101 cl.7.2.3: no file at that address.
            self.queue.frame(mirror_frame(
                header,
                asdu,
                Unspecified::InformationObjectAddress,
                self.common_address,
                self.sizes,
            ));
            return;
        };
        let opens = matches!(&frame, Frame::Sc { scq, .. }
            if scq.action == iec104::asdu::Scq::SELECT_FILE || scq.action == iec104::asdu::Scq::REQUEST_FILE);
        if opens {
            if let Frame::Sc { nof, .. } = &frame
                && *nof != file.nof
            {
                // 7.2.6.28: a negative file ready, the file asked for is not here.
                let refusal = Frame::FileReady {
                    ioa,
                    nof: *nof,
                    lof: iec104::asdu::Lof { value: 0 },
                    frq: iec104::asdu::Frq {
                        value: 0,
                        negative_confirm: true,
                    },
                };
                if let Ok(asdu) = self.ft.build(&refusal) {
                    self.queue.frame(asdu);
                }
                return;
            }
            if let Some(provider) = Provider::new(self.ft, ioa, file.nof, file.content.to_vec()) {
                self.providers.insert(ioa, provider);
            }
        }
        let Some(provider) = self.providers.get_mut(&ioa) else {
            return;
        };
        let Ok(step) = provider.on_asdu(asdu, &known) else {
            return;
        };
        if step.progress != Progress::Running {
            self.providers.remove(&ioa);
        }
        for asdu in step.send {
            self.queue.frame(asdu);
        }
    }

    /// 5-101 cl.7.4.11 in the control direction (604 5.4.23.10): the
    /// controlling station offers a file with a file ready, the server calls
    /// it through [`Receiver`] and hands it to [`Application::received_file`]
    /// once the sections' and the file's checksums add up (7.2.6.37). A frame
    /// for an address with no offer is dropped.
    fn on_upload(&mut self, asdu: &[u8], frame: &Frame, known: Known) {
        let ioa = frame.ioa();
        if let Frame::FileReady { nof, .. } = frame {
            // A new offer at an address replaces a transfer left there.
            self.receivers
                .insert(ioa, (*nof, Receiver::new(self.ft, ioa, *nof)));
        }
        let Some((nof, receiver)) = self.receivers.get_mut(&ioa) else {
            return;
        };
        let nof = *nof;
        let Ok(step) = receiver.on_asdu(asdu, &known) else {
            return;
        };
        for asdu in step.send {
            self.queue.frame(asdu);
        }
        match step.progress {
            Progress::Running => {}
            Progress::Complete(content) => {
                self.receivers.remove(&ioa);
                self.app.received_file(ioa, nof, content);
            }
            Progress::Failed(_) => {
                self.receivers.remove(&ioa);
            }
        }
    }

    /// The declared files as `F_DR_TA_1` frames: one run of frames per run of
    /// consecutive addresses (figure 89 numbers a frame's files from its base
    /// address), with `LFD` on the last file of all (7.2.6.38).
    fn directory(&self) -> Vec<Vec<u8>> {
        let time = (self.clock)();
        let mut runs: Vec<(u32, Vec<ft::DirectoryEntry>)> = Vec::new();
        for (&ioa, file) in &self.files {
            let entry = ft::DirectoryEntry {
                nof: file.nof,
                lof: iec104::asdu::Lof {
                    value: u32::try_from(file.content.len()).unwrap_or(iec104::asdu::Lof::MAX),
                },
                sof: iec104::asdu::Sof::default(),
                time,
            };
            let next = runs
                .last()
                .and_then(|(base, entries)| base.checked_add(u32::try_from(entries.len()).ok()?));
            match runs.last_mut() {
                Some((_, entries)) if next == Some(ioa) => entries.push(entry),
                _ => runs.push((ioa, vec![entry])),
            }
        }
        let mut frames: Vec<Frame> = runs
            .iter()
            .flat_map(|(base, entries)| directory(&self.ft, *base, entries))
            .collect();
        let count = frames.len();
        for (i, frame) in frames.iter_mut().enumerate() {
            if let Frame::Directory { files, .. } = frame
                && i.saturating_add(1) < count
                && let Some(last) = files.last_mut()
            {
                last.sof.last_file_of_directory = false;
            }
        }
        frames
            .iter()
            .filter_map(|frame| self.ft.build(frame).ok())
            .collect()
    }

    fn on_counter(&mut self, asdu: &[u8], header: &Header, known: Known) {
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
            // 5-101 cl.7.2.3: a `T = 1` request tests "transmission and
            // equipment without controlling the process"; it is confirmed,
            // and no counter is frozen or reset.
            _ if header.test => return,
            FreezeMode::FreezeWithoutReset => self.image.freeze(request),
            FreezeMode::FreezeWithReset => {
                self.image.freeze(request);
                self.app.reset_counters(request);
            }
            FreezeMode::Reset => self.app.reset_counters(request),
        }
        // Mode D: mode C's counter command from the controlling station,
        // combined with mode A's spontaneous reporting of the totals.
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
                // TS 60870-5-604 5.4.19.50: for an information object that
                // does not exist, the controlled station could instead
                // return the ASDU unchanged with COT = 47.
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
                // An operation that timed out still runs: a select or execute
                // gets the same negative confirmation until it ends. A
                // deactivation goes on to the procedure, which has no select
                // there to stop (one from before the timeout was dropped with
                // it, later ones are refused) and answers a negative DEACTCON;
                // it never cancels the operation.
                Some(_)
                    if header.cause == Cause::Activation
                        && self.overrun.contains_key(&command.ioa) =>
                {
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
            ioa,
            select: false,
            negative: false,
            test,
        } = reaction
        {
            if test {
                // 5-101 cl.7.2.3: a `T = 1` frame tests "transmission and
                // equipment without controlling the process". It is not
                // operated, and the run it started ends as one that worked.
                self.on_operated(Operated { ioa, ok: true });
            } else if let Ok(Some(command)) = ct::decode_command_with(asdu, self.sizes) {
                self.operate(command);
            }
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
    ///
    /// One that outlasts [`ServerConfig::operate_timeout`] is terminated
    /// negatively but not cancelled: dropping it midway would leave the
    /// equipment in an unknown state. It runs on, its object refused, and
    /// its eventual result is discarded.
    fn operate(&self, command: Command) {
        let app = Arc::clone(&self.app);
        let done = Done(self.operated.clone(), self.link);
        let limit = self.operate_timeout;
        let ioa = command.ioa;
        tokio::spawn(async move {
            let mut operation = tokio::spawn(async move { app.operate(command).await });
            let joined = match limit {
                Some(limit) => tokio::time::timeout(limit, &mut operation).await.ok(),
                None => Some((&mut operation).await),
            };
            if let Some(joined) = joined {
                let ok = matches!(joined, Ok(true));
                let _ = done.send(Report::Operated(Operated { ioa, ok }));
            } else {
                let _ = done.send(Report::TimedOut(ioa));
                let _ = operation.await;
                let _ = done.send(Report::Ended(ioa));
            }
        });
    }

    /// An operation's report, from the link its execute arrived on or an
    /// earlier one.
    fn on_report(&mut self, link: u64, report: Report) {
        let done = match report {
            Report::Operated(done) => done,
            Report::TimedOut(ioa) => {
                let count = self.overrun.entry(ioa).or_default();
                *count = count.saturating_add(1);
                self.terminate(link, Operated { ioa, ok: false });
                // A select accepted while it ran must not outlive it: the
                // object takes no command until the operation ends.
                self.ct.abandon(ioa);
                return;
            }
            // Whatever the link: the object is free once its last operation is.
            Report::Ended(ioa) => {
                if let Some(count) = self.overrun.get_mut(&ioa) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.overrun.remove(&ioa);
                    }
                }
                return;
            }
        };
        self.terminate(link, done);
    }

    /// The termination owed for `done`, to the link its execute arrived on.
    fn terminate(&mut self, link: u64, done: Operated) {
        if link == self.link {
            self.on_operated(done);
        } else {
            self.on_operated_late(done);
        }
    }

    /// The termination of an operated execute, where its family has one.
    fn on_operated(&mut self, done: Operated) {
        if self.ct.is_running(done.ioa)
            && let Ok(frame) = self.ct.terminate(done.ioa, !done.ok)
        {
            self.queue.frame(frame);
        }
    }

    /// An execute whose link has gone finished: its object is free again, but
    /// its termination is owed to the controlling station that left, not to
    /// the one there now.
    fn on_operated_late(&mut self, done: Operated) {
        if self.ct.is_running(done.ioa) {
            let _ = self.ct.terminate(done.ioa, !done.ok);
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
                let Some((frame, event)) = self.next_frame() else {
                    return;
                };
                if self.handle.send_asdu(CONN, frame.clone()).await.is_err() {
                    if event {
                        self.queue.put_back_event(frame);
                    } else {
                        self.queue.put_back(vec![frame]);
                    }
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
    /// Table 16 fixes the sending order by row, whichever data was produced
    /// first). Once the last one is out, the
    /// procedure is completed and its termination follows (5-101 cl.7.4.5).
    /// Until then the procedure runs, so a deactivation or a restart stops
    /// the rest of the answer ([`Task::stop_answers`]).
    ///
    /// Any other entry that stands for several ASDUs (a counter
    /// interrogation's totals and termination) gives its first one, and the
    /// rest go back to the head of their row in their order. Each answer
    /// ASDU is encoded again from the image as it goes ([`Image::refresh`]).
    ///
    /// The flag says whether the ASDU is the application's events, so one
    /// whose hand-over fails goes back as events.
    fn next_frame(&mut self) -> Option<(Vec<u8>, bool)> {
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
                        return Some((self.image.refresh(frame), false));
                    }
                    if !self.gi.is_running(scope) {
                        continue;
                    }
                    // The termination, and under `ReActivation::Queue` the
                    // data and termination of the interrogation that waited
                    // (TS 60870-5-604 5.4.17.40: the second GI begins once
                    // the first's activation termination, COT = 10, is out). Those
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
                    return Some((self.image.refresh(first), false));
                }
                item => {
                    let event = matches!(item, Item::Frame { event: true, .. });
                    let mut frames = self.expand(item).into_iter();
                    let Some(first) = frames.next() else {
                        continue;
                    };
                    self.queue.put_back(frames.collect());
                    return Some((self.image.refresh(first), event));
                }
            }
        }
    }
}
