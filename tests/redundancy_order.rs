#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use iec104::apci::{Apci, ParseError, SeqNo, UFunction};
use iec104::link::{Action, MAX_PENDING_USER_DATA, QueueError, Role, State};
use iec104::params::LinkParams;
use iec104::redundancy::{GroupError, RedundancyGroup, Replay, ReplayOutcome, Routed};

struct Rng(u64);
impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
    const fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn asdu(id: u32) -> Vec<u8> {
    let [a, b, c, _] = id.to_le_bytes();
    vec![0x01, 0x01, 0x03, 0x00, 0x01, 0x00, a, b, c, 0x00]
}
const fn id_of(asdu: &[u8]) -> u32 {
    u32::from_le_bytes([asdu[6], asdu[7], asdu[8], 0])
}

#[derive(Default)]
struct Peer {
    up: bool,
    closed: bool,
    received: Vec<u32>,
    acked: usize,
}

#[derive(Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct Cfg {
    role: Role,
    fifo: bool,
    lazy: bool,
    conforming: bool,
    extra_ops: bool,
}

struct Model {
    cfg: Cfg,
    rng: Rng,
    group: RedundancyGroup,
    peers: Vec<Peer>,
    now: Instant,
    t1: Duration,
    next_id: u32,
    open: Vec<u32>,
    discarded: Vec<u32>,
    confirmed: Vec<u32>,
    sends: HashMap<u32, usize>,
    replays: HashMap<u32, usize>,
    settling: bool,
    step: usize,
    trace: Vec<String>,
    pre_left: Vec<Vec<u32>>,
    violations: Vec<(String, String)>,
}

impl Model {
    fn new(seed: u64, cfg: Cfg) -> Self {
        let mut rng = Rng(seed);
        let members = 2 + rng.below(2) as usize;
        let params = LinkParams {
            k: 1 + rng.below(3) as u16,
            w: 1,
            ..LinkParams::default()
        };
        Self {
            cfg,
            rng,
            group: RedundancyGroup::uniform(cfg.role, params, members).unwrap(),
            peers: (0..members).map(|_| Peer::default()).collect(),
            now: Instant::now(),
            t1: params.t1,
            next_id: 1,
            open: Vec::new(),
            discarded: Vec::new(),
            confirmed: Vec::new(),
            sends: HashMap::new(),
            replays: HashMap::new(),
            settling: false,
            step: 0,
            trace: vec![format!("members {members} k {}", params.k)],
            pre_left: Vec::new(),
            violations: Vec::new(),
        }
    }

    fn snapshot(&self) -> String {
        let members: Vec<String> = self
            .group
            .members()
            .iter()
            .enumerate()
            .map(|(m, member)| {
                format!(
                    "{m}:{:?} conn={} up={} closed={} left={:?} queued={:?} unconf={:?}",
                    member.state(),
                    member.session().is_connected(),
                    self.peers[m].up,
                    self.peers[m].closed,
                    member
                        .left_behind()
                        .iter()
                        .map(|a| id_of(a))
                        .collect::<Vec<_>>(),
                    member
                        .queued_user_data()
                        .iter()
                        .map(|a| id_of(a))
                        .collect::<Vec<_>>(),
                    member
                        .session()
                        .outstanding_frames()
                        .iter()
                        .map(|f| id_of(&f.asdu))
                        .collect::<Vec<_>>()
                )
            })
            .collect();
        format!(
            "started={:?} held={:?} {members:?}",
            self.group.started_index(),
            self.group
                .held_user_data()
                .iter()
                .map(|a| id_of(a))
                .collect::<Vec<_>>()
        )
    }

    fn violate(&mut self, category: &str, detail: &str) {
        let d = format!("step {}: {detail} | {}", self.step, self.snapshot());
        self.violations.push((category.to_string(), d));
    }

    fn log(&mut self, what: &str) {
        self.trace.push(format!("{}: {what}", self.step));
    }

    fn perform(&mut self, routed: Vec<Routed>, replaying: bool) {
        let pre = self.pre_left.clone();
        let post: Vec<Vec<u32>> = (0..self.peers.len()).map(|m| self.left_ids(m)).collect();
        for Routed { member, actions } in routed {
            for action in actions {
                match action {
                    Action::SendI { ns, asdu, .. } => {
                        let id = id_of(&asdu);
                        self.trace.push(format!("    wire {member}: I {id}"));
                        if !self.peers[member].up || self.peers[member].closed {
                            self.violate("send-on-down", &format!("I-frame {id} on {member}"));
                            continue;
                        }
                        if usize::from(ns.get()) != self.peers[member].received.len() {
                            self.violate("ns", &format!("N(S) out of step on {member}"));
                        }
                        if self.confirmed.contains(&id) {
                            self.violate("after-confirm", &format!("{id} sent after confirmation"));
                        }
                        if self.discarded.contains(&id) {
                            self.violate("after-discard", &format!("{id} sent after discard"));
                        }
                        let older = post
                            .iter()
                            .enumerate()
                            .flat_map(|(m, ids)| {
                                let pre_m = pre.get(m).cloned().unwrap_or_default();
                                ids.iter()
                                    .copied()
                                    .filter(move |x| m != member || pre_m.contains(x))
                            })
                            .min();
                        if let Some(older) = older
                            && !replaying
                            && !self.replays.contains_key(&id)
                            && older < id
                        {
                            self.violate(
                                "ahead-of-undecided",
                                &format!("{id} on {member} while {older} is left behind undecided"),
                            );
                        }
                        if self.cfg.fifo
                            && let Some(&last) = self.peers[member].received.last()
                            && last >= id
                        {
                            self.violate(
                                "reorder",
                                &format!(
                                    "{id} on {member} after {last}: {:?}",
                                    self.peers[member].received
                                ),
                            );
                        }
                        self.peers[member].received.push(id);
                        *self.sends.entry(id).or_default() += 1;
                        let allowed = 1 + self.replays.get(&id).copied().unwrap_or(0);
                        if self.sends[&id] > allowed {
                            self.violate(
                                "duplicate",
                                &format!("{id} sent {} times, {allowed} allowed", self.sends[&id]),
                            );
                        }
                    }
                    Action::ActiveClose(why) => {
                        self.trace.push(format!("    wire {member}: close ({why})"));
                        if self.cfg.lazy && !self.settling {
                            self.peers[member].closed = true;
                        } else {
                            self.lose(member);
                        }
                    }
                    Action::Send(apci) => {
                        self.trace.push(format!("    wire {member}: {apci:?}"));
                    }
                    Action::DeliverData { .. } => {}
                }
            }
        }
        self.mark();
    }

    fn lose(&mut self, member: usize) {
        if !self.peers[member].up {
            return;
        }
        self.peers[member] = Peer::default();
        self.log(&format!("lost {member}"));
        self.group.on_connection_lost(member).unwrap();
        self.mark();
    }

    fn establish(&mut self, member: usize) {
        self.peers[member] = Peer {
            up: true,
            ..Peer::default()
        };
        self.log(&format!("established {member}"));
        self.group
            .on_connection_established(member, self.now)
            .unwrap();
        self.mark();
    }

    fn undecided(&self) -> bool {
        self.group
            .members()
            .iter()
            .any(|m| !m.left_behind().is_empty())
    }

    fn send(&mut self) {
        let id = self.next_id;
        self.next_id += 1;
        let target = self.group.started_index().unwrap_or(0);
        match self.group.send_user_data_at(target, &asdu(id), self.now) {
            Ok(routed) => {
                self.log(&format!("send {id} via {target} ok"));
                self.open.push(id);
                self.perform(routed, false);
            }
            Err(e) => {
                self.log(&format!("send {id} via {target} refused {e:?}"));
            }
        }
    }

    fn left_ids(&self, member: usize) -> Vec<u32> {
        self.group
            .member(member)
            .unwrap()
            .left_behind()
            .iter()
            .map(|a| id_of(a))
            .collect()
    }

    fn decide_one(&mut self, member: usize, choice: Replay) -> bool {
        let held = self.left_ids(member);
        let before = self.snapshot();
        match self
            .group
            .retransmit_unconfirmed_at(member, choice, self.now)
        {
            Ok((ReplayOutcome::Retransmitted { .. }, routed)) => {
                self.log(&format!("decide {member} Retransmit {held:?}"));
                for id in &held {
                    *self.replays.entry(*id).or_default() += 1;
                }
                self.perform(routed, true);
                true
            }
            Ok((ReplayOutcome::Discarded { discarded, .. }, routed)) => {
                self.log(&format!("decide {member} Discard {held:?}"));
                if discarded != held.len() {
                    self.violate("count", "discard count");
                }
                self.open.retain(|id| !held.contains(id));
                self.discarded.extend(held);
                self.perform(routed, true);
                true
            }
            Ok((ReplayOutcome::Left { unconfirmed }, _)) => {
                if unconfirmed != held.len() {
                    self.violate("count", "leave count");
                }
                true
            }
            Err(e) => {
                self.log(&format!("decide {member} {choice:?} refused {e:?}"));
                let expected = matches!(
                    (choice, e),
                    (
                        Replay::Retransmit,
                        GroupError::NoStartedConnection
                            | GroupError::Queue(QueueError::NotConnected)
                    )
                );
                if !expected {
                    self.violate("decision-refused", &format!("{member} {choice:?}: {e:?}"));
                }
                if before != self.snapshot() {
                    self.violate(
                        "refusal-changed-state",
                        &format!("{member} {choice:?}: {e:?} before {before}"),
                    );
                }
                false
            }
        }
    }

    fn decide(&mut self, force_replay: bool) {
        let mut failed: Vec<usize> = (0..self.peers.len())
            .filter(|&m| !self.group.member(m).unwrap().left_behind().is_empty())
            .collect();
        if self.cfg.fifo || force_replay {
            failed.sort_by_key(|&m| self.left_ids(m).into_iter().min());
            if !force_replay && self.rng.below(3) == 0 {
                return;
            }
            for member in failed {
                let choice = if !force_replay && self.rng.below(4) == 0 {
                    Replay::Discard
                } else {
                    Replay::Retransmit
                };
                if !self.decide_one(member, choice) {
                    break;
                }
            }
        } else {
            for member in failed {
                let choice = match self.rng.below(3) {
                    0 => Replay::Retransmit,
                    1 => Replay::Discard,
                    _ => Replay::Leave,
                };
                self.decide_one(member, choice);
            }
        }
    }

    fn acknowledge(&mut self, member: usize) {
        if self.peers[member].closed {
            return;
        }
        let received = self.peers[member].received.len();
        let acked = self.peers[member].acked;
        if received == acked {
            return;
        }
        let nr = if self.settling {
            received
        } else {
            acked + 1 + self.rng.below((received - acked) as u64) as usize
        };
        let newly: Vec<u32> = self.peers[member].received[acked..nr].to_vec();
        let alive = matches!(
            self.group.state(member),
            Ok(State::Started | State::PendingStopped | State::PendingUnconfirmedStopped)
        );
        if !alive && self.settling {
            return;
        }
        let routed = self.group.on_frame_at(
            member,
            Apci::S {
                nr: SeqNo::new(nr as u16),
            },
            self.now,
        );
        self.log(&format!("S({nr}) on {member} -> ok={}", routed.is_ok()));
        if alive && routed.is_ok() {
            self.peers[member].acked = nr;
            for id in newly {
                self.open.retain(|&o| o != id);
                if !self.confirmed.contains(&id) {
                    self.confirmed.push(id);
                }
            }
        }
        self.perform(routed.unwrap_or_default(), false);
    }

    fn frame(&mut self, member: usize, f: UFunction) {
        if self.peers[member].closed {
            return;
        }
        let routed = self.group.on_frame_at(member, Apci::U(f), self.now);
        self.log(&format!(
            "{f:?} on {member} -> {:?}",
            routed.as_ref().map(|_| ())
        ));
        self.perform(routed.unwrap_or_default(), false);
    }

    fn peer_common(&mut self, member: usize, pick: u64) -> bool {
        match pick {
            0 if !self.peers[member].up => {
                self.establish(member);
                true
            }
            1 if self.peers[member].up && self.peers[member].closed => {
                self.lose(member);
                true
            }
            2 if self.peers[member].up => {
                self.lose(member);
                true
            }
            6 if self.peers[member].up && self.cfg.extra_ops && self.rng.below(4) == 0 => {
                self.establish(member);
                true
            }
            _ => false,
        }
    }

    fn master(&mut self) {
        let member = self.rng.below(self.peers.len() as u64) as usize;
        let pick = self.rng.below(7);
        if self.peer_common(member, pick) {
            return;
        }
        if !self.peers[member].up {
            return;
        }
        match pick {
            0 | 1 | 3 => self.frame(member, UFunction::StartDtAct),
            4 => self.frame(member, UFunction::StopDtAct),
            _ => self.acknowledge(member),
        }
    }

    fn outstation(&mut self) {
        let member = self.rng.below(self.peers.len() as u64) as usize;
        let pick = self.rng.below(7);
        if self.peer_common(member, pick) {
            return;
        }
        if !self.peers[member].up {
            return;
        }
        let con = match self.group.state(member) {
            Ok(State::PendingStarted) => Some(UFunction::StartDtCon),
            Ok(State::PendingStopped) => Some(UFunction::StopDtCon),
            Ok(State::PendingUnconfirmedStopped) if !self.cfg.conforming => {
                Some(UFunction::StopDtCon)
            }
            _ => None,
        };
        match pick {
            0 | 1 | 3 if con.is_some() => self.frame(member, con.unwrap()),
            _ => self.acknowledge(member),
        }
    }

    fn control(&mut self) {
        let member = self.rng.below(self.peers.len() as u64) as usize;
        let n = if self.cfg.extra_ops { 6 } else { 3 };
        match self.rng.below(n) {
            0 => {
                let r = self.group.start_at(member, self.now);
                self.log(&format!("start {member} -> {:?}", r.as_ref().map(|_| ())));
                self.perform(r.unwrap_or_default(), false);
            }
            1 => {
                let r = self.group.select_at(member, self.now);
                self.log(&format!("select {member} -> {:?}", r.as_ref().map(|_| ())));
                self.perform(r.unwrap_or_default(), false);
                let r = self.group.start_at(member, self.now);
                self.log(&format!("start {member} -> {:?}", r.as_ref().map(|_| ())));
                self.perform(r.unwrap_or_default(), false);
            }
            2 => {
                if let Some(started) = self.group.started_index() {
                    let r = self.group.stop_at(started, self.now);
                    self.log(&format!("stop {started} -> {:?}", r.as_ref().map(|_| ())));
                    self.perform(r.unwrap_or_default(), false);
                }
            }
            3 | 4 => {
                let r = self.group.select_at(member, self.now);
                self.log(&format!("select {member} -> {:?}", r.as_ref().map(|_| ())));
                self.perform(r.unwrap_or_default(), false);
            }
            _ => self.rare(member),
        }
    }

    fn rare(&mut self, member: usize) {
        match self.rng.below(3) {
            0 => {
                let r = self.group.close_at(member, self.now);
                self.log(&format!("close {member} -> {:?}", r.as_ref().map(|_| ())));
                self.perform(r.unwrap_or_default(), false);
            }
            1 if self.peers[member].up && !self.peers[member].closed => {
                let r = self.group.on_parse_error_at(
                    member,
                    ParseError::ReservedOctetNotZero,
                    self.now,
                );
                self.log(&format!("parse error {member}"));
                self.perform(r.unwrap_or_default(), false);
            }
            _ if self.cfg.role == Role::Controlled => {
                let r = self.group.observe_startdt_act_at(member, self.now);
                self.log(&format!("observe {member} -> {:?}", r.as_ref().map(|_| ())));
                self.perform(r.unwrap_or_default(), false);
            }
            _ => {}
        }
    }

    fn time(&mut self) {
        let jump = match self.rng.below(3) {
            0 => Duration::from_secs(1),
            1 => Duration::from_secs(11),
            _ => self.t1 + Duration::from_secs(1),
        };
        self.now += jump;
        let outcome = self.group.tick(self.now);
        self.log(&format!(
            "tick +{jump:?} switch {:?} connect {:?}",
            outcome.switchovers, outcome.connect
        ));
        self.perform(outcome.routed, false);
    }

    fn mark(&mut self) {
        self.pre_left = (0..self.peers.len()).map(|m| self.left_ids(m)).collect();
    }

    fn step(&mut self) {
        self.step += 1;
        self.mark();
        let controlling = self.cfg.role == Role::Controlling;
        match self.rng.below(12) {
            8 if self.cfg.extra_ops && !controlling => {
                let member = self.rng.below(self.peers.len() as u64) as usize;
                self.rare(member);
            }
            0..=2 | 8 => self.send(),
            3..=4 if controlling => self.control(),
            3..=6 if controlling => self.outstation(),
            3..=6 => self.master(),
            7 => self.time(),
            _ => self.decide(false),
        }
        self.check();
    }

    fn check(&mut self) {
        let states: Vec<State> = self
            .group
            .members()
            .iter()
            .map(iec104::redundancy::Member::state)
            .collect();
        let live = states
            .iter()
            .filter(|s| !matches!(s, State::Stopped | State::Terminated))
            .count();
        if live > 1 {
            self.violate("rule3", &format!("{live} live: {states:?}"));
        }
        let mut seen: HashMap<u32, Vec<String>> = HashMap::new();
        let mut in_hand = self.group.held_user_data().len();
        for a in self.group.held_user_data() {
            seen.entry(id_of(a)).or_default().push("held".into());
        }
        let mut mirror_bad = Vec::new();
        for (m, member) in self.group.members().iter().enumerate() {
            in_hand += member.left_behind().len();
            for a in member.left_behind() {
                seen.entry(id_of(a)).or_default().push(format!("left {m}"));
            }
            if member.session().is_connected() {
                in_hand += member.session().pending_user_data()
                    + member.session().outstanding_frames().len();
                if member.queued_user_data().len() != member.session().pending_user_data() {
                    mirror_bad.push(m);
                }
                for a in member.queued_user_data() {
                    seen.entry(id_of(a))
                        .or_default()
                        .push(format!("queued {m}"));
                }
                for f in member.session().outstanding_frames() {
                    seen.entry(id_of(&f.asdu))
                        .or_default()
                        .push(format!("unconf {m}"));
                }
            }
        }
        for m in mirror_bad {
            self.violate("mirror", &format!("member {m}: mirror and queue differ"));
        }
        if in_hand > MAX_PENDING_USER_DATA {
            self.violate("limit", &format!("{in_hand} in hand"));
        }
        let open = self.open.clone();
        for id in &open {
            match seen.get(id).map(Vec::len) {
                Some(1) => {}
                None => self.violate("lost", &format!("{id} is lost")),
                Some(_) => self.violate("twice", &format!("{id} is in {:?}", seen[id])),
            }
        }
        let done: Vec<u32> = self
            .discarded
            .iter()
            .chain(&self.confirmed)
            .copied()
            .collect();
        for id in done {
            if let Some(places) = seen.get(&id) {
                self.violate("done-but-present", &format!("{id} in {places:?}"));
            }
        }
        self.check_started();
    }

    fn check_started(&mut self) {
        let undecided = self.undecided();
        if let Some(started) = self.group.started_index() {
            let running = self
                .group
                .member(started)
                .unwrap()
                .session()
                .user_data_allowed();
            let session = self.group.member(started).unwrap().session();
            if session.can_send_i_frame() && session.pending_user_data() > 0 {
                self.violate(
                    "queue-stuck",
                    &format!("{started} can send, but its queue waits"),
                );
            }
            if running && !undecided && !self.group.held_user_data().is_empty() {
                self.violate("held-stuck", "held, started runs, nothing undecided");
            }
            if running && !undecided {
                let stranded: Vec<usize> = self
                    .group
                    .members()
                    .iter()
                    .enumerate()
                    .filter(|(m, member)| {
                        *m != started
                            && member.session().is_connected()
                            && member.state() == State::Stopped
                            && member.session().pending_user_data() > 0
                    })
                    .map(|(m, _)| m)
                    .collect();
                if !stranded.is_empty() {
                    self.violate("stranded-queue", &format!("queue on stopped {stranded:?}"));
                }
            }
        }
    }

    fn settle(&mut self) {
        self.settling = true;
        for m in 0..self.peers.len() {
            if self.peers[m].closed {
                self.lose(m);
            }
        }
        let target = self.rng.below(self.peers.len() as u64) as usize;
        self.log(&format!("settle on {target}"));
        for _ in 0..self.open.len() + 64 {
            self.step += 1;
            self.mark();
            if !self.peers[target].up {
                self.establish(target);
            }
            if self.cfg.role == Role::Controlled {
                if self.group.state(target) != Ok(State::Started)
                    || self.group.started_index() != Some(target)
                {
                    self.frame(target, UFunction::StartDtAct);
                }
            } else {
                match self.group.state(target) {
                    Ok(State::PendingStopped) => self.frame(target, UFunction::StopDtCon),
                    Ok(State::PendingUnconfirmedStopped) => {
                        if self.group.started_index() == Some(target) {
                            self.acknowledge(target);
                        } else {
                            self.frame(target, UFunction::StopDtCon);
                        }
                    }
                    Ok(State::Stopped) => {
                        let r = self.group.start_at(target, self.now);
                        self.log(&format!("start {target} -> {:?}", r.as_ref().map(|_| ())));
                        self.perform(r.unwrap_or_default(), false);
                    }
                    Ok(State::PendingStarted) => self.frame(target, UFunction::StartDtCon),
                    Ok(State::Started) if self.group.started_index() != Some(target) => {
                        let r = self.group.select_at(target, self.now);
                        self.log(&format!("select {target} -> {:?}", r.as_ref().map(|_| ())));
                        self.perform(r.unwrap_or_default(), false);
                    }
                    _ => {}
                }
            }
            self.decide(true);
            if self.peers[target].up {
                self.acknowledge(target);
            }
            if self.step.is_multiple_of(8) {
                self.now += self.t1 + Duration::from_secs(1);
                let outcome = self.group.tick(self.now);
                self.perform(outcome.routed, false);
            }
            self.check();
            if self.open.is_empty() {
                return;
            }
        }
        self.violate(
            "never-delivered",
            &format!("settled on {target}, open {:?}", self.open),
        );
    }
}

fn campaign(cfg: Cfg) {
    let mut found: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for seed in 1..=SEEDS {
        let mut model = Model::new(seed, cfg);
        for _ in 0..STEPS {
            model.step();
            if !model.violations.is_empty() {
                break;
            }
        }
        if model.violations.is_empty() {
            model.settle();
        }
        if let Some((category, detail)) = model.violations.into_iter().next() {
            let tail: Vec<String> = model.trace.iter().rev().take(40).rev().cloned().collect();
            let entry = found
                .entry(category)
                .or_insert_with(|| (0, format!("seed {seed}: {detail}\n  {}", tail.join("\n  "))));
            entry.0 += 1;
        }
    }
    let report: Vec<String> = found
        .iter()
        .map(|(category, (seeds, first))| format!("{category} in {seeds} seeds, first {first}"))
        .collect();
    assert!(report.is_empty(), "{}", report.join("\n"));
}

const SEEDS: u64 = 1000;
const STEPS: usize = 250;

#[test]
fn a_controlled_group_with_starts_stops_and_losses() {
    campaign(Cfg {
        role: Role::Controlled,
        fifo: true,
        lazy: false,
        conforming: true,
        extra_ops: false,
    });
}

#[test]
fn a_controlling_group_with_starts_stops_and_losses() {
    campaign(Cfg {
        role: Role::Controlling,
        fifo: true,
        lazy: false,
        conforming: true,
        extra_ops: false,
    });
}

#[test]
fn a_controlled_group_with_observed_acts_closes_and_parse_errors() {
    campaign(Cfg {
        role: Role::Controlled,
        fifo: true,
        lazy: false,
        conforming: true,
        extra_ops: true,
    });
}

#[test]
fn a_controlling_group_with_selects_closes_and_parse_errors() {
    campaign(Cfg {
        role: Role::Controlling,
        fifo: true,
        lazy: false,
        conforming: true,
        extra_ops: true,
    });
}

#[test]
fn a_controlled_group_whose_losses_are_reported_late() {
    campaign(Cfg {
        role: Role::Controlled,
        fifo: true,
        lazy: true,
        conforming: true,
        extra_ops: true,
    });
}

#[test]
fn a_controlling_group_whose_losses_are_reported_late() {
    campaign(Cfg {
        role: Role::Controlling,
        fifo: true,
        lazy: true,
        conforming: true,
        extra_ops: true,
    });
}

#[test]
fn a_controlled_group_with_decisions_in_any_order() {
    campaign(Cfg {
        role: Role::Controlled,
        fifo: false,
        lazy: true,
        conforming: true,
        extra_ops: true,
    });
}

#[test]
fn a_controlling_group_with_decisions_in_any_order() {
    campaign(Cfg {
        role: Role::Controlling,
        fifo: false,
        lazy: true,
        conforming: true,
        extra_ops: true,
    });
}

#[test]
fn a_controlling_group_against_a_peer_that_confirms_a_stop_without_acknowledging() {
    campaign(Cfg {
        role: Role::Controlling,
        fifo: true,
        lazy: false,
        conforming: false,
        extra_ops: true,
    });
}
