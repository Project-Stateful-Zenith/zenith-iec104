//! A randomized model test of a redundancy group (104 clause 10), in both
//! roles. Thousands of random sequences mix the application's sends and replay
//! decisions; starts and stops (the master's STARTDT/STOPDT acts for a
//! controlled station, the application's own `start`/`select`/`stop` for a
//! controlling one, with the outstation's confirmations); acknowledgements;
//! lost and re-established connections; and expiring timers (a t1 on the
//! started connection is the controlling station's switchover). After every
//! step, the test checks the three properties clause 10.5 and 10.6 ask for:
//!
//! - **Nothing is lost** (10.5 requires that a switch to another connection
//!   lose no data): every ASDU handed to the group that the
//!   master has not confirmed and the application has not discarded is in
//!   exactly one place: held by the group, queued on a connection, sent and
//!   unconfirmed on a live connection, or left behind by a failed one.
//! - **Nothing is sent twice** beyond 10.6's replay: an ASDU reaches the wire
//!   once, plus once per replay that carried it, and never after the master
//!   confirmed it.
//! - **Nothing is reordered** by the group: with an application that decides
//!   on every failure before it sends anything new, each connection carries
//!   the ASDUs in the order they were handed over.
//!
//! The generator is a seeded LCG, so a failure names its seed and step and
//! replays exactly.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::link::{Action, Role, State};
use iec104::params::LinkParams;
use iec104::redundancy::{RedundancyGroup, Replay, ReplayOutcome, Routed};

/// A small deterministic generator (Knuth's MMIX LCG).
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

/// The ASDU carrying `id`: a single-point information, cause 3, IOA `id`.
fn asdu(id: u32) -> Vec<u8> {
    let [a, b, c, _] = id.to_le_bytes();
    vec![0x01, 0x01, 0x03, 0x00, 0x01, 0x00, a, b, c, 0x00]
}

const fn id_of(asdu: &[u8]) -> u32 {
    u32::from_le_bytes([asdu[6], asdu[7], asdu[8], 0])
}

/// The master's end of one connection.
#[derive(Default)]
struct Peer {
    up: bool,
    /// The ids received on this connection, in N(S) order.
    received: Vec<u32>,
    /// How many of them the master has acknowledged.
    acked: usize,
}

struct Model {
    role: Role,
    rng: Rng,
    group: RedundancyGroup,
    peers: Vec<Peer>,
    now: Instant,
    t1: Duration,
    next_id: u32,
    /// Handed to the group and neither confirmed nor discarded.
    open: Vec<u32>,
    discarded: Vec<u32>,
    confirmed: Vec<u32>,
    sends: HashMap<u32, usize>,
    replays: HashMap<u32, usize>,
    /// The application decides on every failure before it sends again; each
    /// connection's order is checked.
    orderly: bool,
    /// Every decision is a replay (the orderly application, and settling).
    replay_all: bool,
    /// The settle phase is running: the master only does what brings data
    /// through.
    settling: bool,
    seed: u64,
    step: usize,
    stats: Stats,
}

/// What a run exercised, so the test can tell a vacuous model from a
/// passing one.
#[derive(Default, Clone, Copy, Debug)]
struct Stats {
    sent: usize,
    confirmed: usize,
    failures: usize,
    replays: usize,
    discards: usize,
}

impl std::ops::AddAssign for Stats {
    fn add_assign(&mut self, other: Self) {
        self.sent += other.sent;
        self.confirmed += other.confirmed;
        self.failures += other.failures;
        self.replays += other.replays;
        self.discards += other.discards;
    }
}

impl Model {
    fn new(seed: u64, orderly: bool, role: Role) -> Self {
        let mut rng = Rng(seed);
        let members = 2 + rng.below(2) as usize;
        let params = LinkParams {
            k: 1 + rng.below(3) as u16,
            w: 1,
            ..LinkParams::default()
        };
        Self {
            role,
            rng,
            group: RedundancyGroup::uniform(role, params, members).unwrap(),
            peers: (0..members).map(|_| Peer::default()).collect(),
            now: Instant::now(),
            t1: params.t1,
            next_id: 1,
            open: Vec::new(),
            discarded: Vec::new(),
            confirmed: Vec::new(),
            sends: HashMap::new(),
            replays: HashMap::new(),
            orderly,
            replay_all: orderly,
            settling: false,
            seed,
            step: 0,
            stats: Stats::default(),
        }
    }

    fn fail(&self, what: &str) -> ! {
        panic!("seed {} step {}: {what}", self.seed, self.step)
    }

    /// Puts one member's actions on its wire, as the driver does: an active
    /// close ends the connection, reported lost at once.
    fn perform(&mut self, routed: Vec<Routed>) {
        for Routed { member, actions } in routed {
            for action in actions {
                match action {
                    Action::SendI { ns, asdu, .. } => {
                        let id = id_of(&asdu);
                        let peer = &mut self.peers[member];
                        if !peer.up {
                            self.fail(&format!(
                                "I-frame {id} on connection {member}, which is down"
                            ));
                        }
                        if usize::from(ns.get()) != peer.received.len() {
                            self.fail("N(S) out of step");
                        }
                        if self.confirmed.contains(&id) {
                            self.fail(&format!("{id} sent again after it was confirmed"));
                        }
                        peer.received.push(id);
                        self.stats.sent += 1;
                        *self.sends.entry(id).or_default() += 1;
                        let allowed = 1 + self.replays.get(&id).copied().unwrap_or(0);
                        if self.sends[&id] > allowed {
                            self.fail(&format!(
                                "{id} sent {} times, {allowed} allowed",
                                self.sends[&id]
                            ));
                        }
                    }
                    Action::ActiveClose(_) => self.lose(member),
                    _ => {}
                }
            }
        }
    }

    fn lose(&mut self, member: usize) {
        if !self.peers[member].up {
            return;
        }
        self.peers[member] = Peer::default();
        self.stats.failures += 1;
        self.group.on_connection_lost(member).unwrap();
    }

    fn started_and_running(&self) -> Option<usize> {
        let started = self.group.started_index()?;
        (self.group.state(started) == Ok(State::Started)).then_some(started)
    }

    fn undecided(&self) -> bool {
        self.group
            .members()
            .iter()
            .any(|m| !m.left_behind().is_empty())
    }

    fn send(&mut self) {
        if self.orderly && (self.undecided() || self.started_and_running().is_none()) {
            return;
        }
        let id = self.next_id;
        self.next_id += 1;
        // Refused (no started connection yet): the application keeps it.
        if let Ok(routed) = self.group.send_user_data_at(0, &asdu(id), self.now) {
            self.open.push(id);
            self.perform(routed);
        }
    }

    fn decide(&mut self) {
        let failed: Vec<usize> = (0..self.peers.len())
            .filter(|&m| !self.group.member(m).unwrap().left_behind().is_empty())
            .collect();
        for member in failed {
            let choice = if self.replay_all {
                Replay::Retransmit
            } else {
                match self.rng.below(3) {
                    0 => Replay::Retransmit,
                    1 => Replay::Discard,
                    _ => Replay::Leave,
                }
            };
            let held: Vec<u32> = self
                .group
                .member(member)
                .unwrap()
                .left_behind()
                .iter()
                .map(|a| id_of(a))
                .collect();
            if choice == Replay::Retransmit && self.started_and_running().is_none() {
                continue;
            }
            match self
                .group
                .retransmit_unconfirmed_at(member, choice, self.now)
            {
                Ok((ReplayOutcome::Retransmitted { .. }, routed)) => {
                    self.stats.replays += 1;
                    for id in &held {
                        *self.replays.entry(*id).or_default() += 1;
                    }
                    self.perform(routed);
                }
                Ok((ReplayOutcome::Discarded { discarded, .. }, routed)) => {
                    if discarded != held.len() {
                        self.fail("discard count");
                    }
                    self.stats.discards += 1;
                    self.open.retain(|id| !held.contains(id));
                    self.discarded.extend(held);
                    self.perform(routed);
                }
                Ok((ReplayOutcome::Left { unconfirmed }, _)) => {
                    if unconfirmed != held.len() {
                        self.fail("leave count");
                    }
                }
                Err(e) => self.fail(&format!("decision on {member} refused: {e:?}")),
            }
        }
    }

    fn master(&mut self) {
        if self.role == Role::Controlling {
            return self.outstation();
        }
        let member = self.rng.below(self.peers.len() as u64) as usize;
        match self.rng.below(6) {
            0 if !self.peers[member].up => {
                self.peers[member].up = true;
                self.group
                    .on_connection_established(member, self.now)
                    .unwrap();
            }
            0 | 1 if self.peers[member].up => {
                let routed = self
                    .group
                    .on_frame_at(member, Apci::U(UFunction::StartDtAct), self.now)
                    .unwrap_or_default();
                self.perform(routed);
            }
            2 if self.peers[member].up => {
                let routed = self
                    .group
                    .on_frame_at(member, Apci::U(UFunction::StopDtAct), self.now)
                    .unwrap_or_default();
                self.perform(routed);
            }
            3 | 4 if self.peers[member].up => {
                // Acknowledge everything received on this connection.
                let peer = &self.peers[member];
                let nr = peer.received.len();
                let newly: Vec<u32> = peer.received[peer.acked..].to_vec();
                if newly.is_empty() {
                    return;
                }
                let alive = matches!(
                    self.group.state(member),
                    Ok(State::Started | State::PendingStopped | State::PendingUnconfirmedStopped)
                );
                let routed = self.group.on_frame_at(
                    member,
                    Apci::S {
                        nr: SeqNo::new(nr as u16),
                    },
                    self.now,
                );
                if alive && routed.is_ok() {
                    self.peers[member].acked = nr;
                    for id in newly {
                        self.open.retain(|&o| o != id);
                        if !self.confirmed.contains(&id) {
                            self.stats.confirmed += 1;
                            self.confirmed.push(id);
                        }
                    }
                }
                self.perform(routed.unwrap_or_default());
            }
            5 if self.peers[member].up => self.lose(member),
            _ => {}
        }
    }

    /// Acknowledges everything `member`'s peer received, as far as the group
    /// accepts the S-frame.
    fn acknowledge(&mut self, member: usize) {
        let peer = &self.peers[member];
        let nr = peer.received.len();
        let newly: Vec<u32> = peer.received[peer.acked..].to_vec();
        if newly.is_empty() {
            return;
        }
        let alive = matches!(
            self.group.state(member),
            Ok(State::Started | State::PendingStopped | State::PendingUnconfirmedStopped)
        );
        // The random master may send an S-frame the state does not allow (a
        // failure the group must handle); settling only sends allowed ones.
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
        if alive && routed.is_ok() {
            self.peers[member].acked = nr;
            for id in newly {
                self.open.retain(|&o| o != id);
                if !self.confirmed.contains(&id) {
                    self.stats.confirmed += 1;
                    self.confirmed.push(id);
                }
            }
        }
        self.perform(routed.unwrap_or_default());
    }

    /// The controlling station's peer: connections come and go, and the
    /// outstation confirms our acts and acknowledges our data.
    fn outstation(&mut self) {
        let member = self.rng.below(self.peers.len() as u64) as usize;
        let con = match self.group.state(member) {
            Ok(State::PendingStarted) => Some(UFunction::StartDtCon),
            Ok(State::PendingStopped) => Some(UFunction::StopDtCon),
            _ => None,
        };
        match self.rng.below(5) {
            0 if !self.peers[member].up => {
                self.peers[member].up = true;
                self.group
                    .on_connection_established(member, self.now)
                    .unwrap();
            }
            0 | 1 if self.peers[member].up && con.is_some() => {
                let routed = self
                    .group
                    .on_frame_at(member, Apci::U(con.unwrap()), self.now)
                    .unwrap_or_default();
                self.perform(routed);
            }
            2 | 3 if self.peers[member].up => self.acknowledge(member),
            4 if self.peers[member].up => self.lose(member),
            _ => {}
        }
    }

    /// The controlling station's application: 10.3's start, 10.2's manual
    /// switchover (stop, then select and start another), and plain starts.
    fn control(&mut self) {
        let member = self.rng.below(self.peers.len() as u64) as usize;
        let routed = match self.rng.below(3) {
            0 => self.group.start_at(member, self.now),
            1 => {
                let _ = self.group.select(member);
                self.group.start_at(member, self.now)
            }
            _ => match self.group.started_index() {
                Some(started) => self.group.stop_at(started, self.now),
                None => return,
            },
        };
        self.perform(routed.unwrap_or_default());
    }

    fn time(&mut self) {
        let jump = match self.rng.below(3) {
            0 => Duration::from_secs(1),
            1 => Duration::from_secs(11),
            _ => self.t1 + Duration::from_secs(1),
        };
        self.now += jump;
        let outcome = self.group.tick(self.now);
        self.perform(outcome.routed);
    }

    fn step(&mut self) {
        self.step += 1;
        match self.rng.below(10) {
            0..=2 => self.send(),
            3..=4 if self.role == Role::Controlling => self.control(),
            3..=6 => self.master(),
            7 => self.time(),
            _ => self.decide(),
        }
        if self.orderly {
            self.decide();
        }
        self.check();
    }

    /// Where each open ASDU is, and that it is there exactly once.
    fn check(&self) {
        let mut seen: HashMap<u32, Vec<String>> = HashMap::new();
        let mut note = |ids: Vec<u32>, place: String| {
            for id in ids {
                seen.entry(id).or_default().push(place.clone());
            }
        };
        note(
            self.group
                .held_user_data()
                .iter()
                .map(|a| id_of(a))
                .collect(),
            "held".into(),
        );
        for (m, member) in self.group.members().iter().enumerate() {
            note(
                member.left_behind().iter().map(|a| id_of(a)).collect(),
                format!("left behind by {m}"),
            );
            if member.session().is_connected() {
                if member.queued_user_data().len() != member.session().pending_user_data() {
                    self.fail(&format!("member {m}: mirror and queue differ"));
                }
                note(
                    member.queued_user_data().iter().map(|a| id_of(a)).collect(),
                    format!("queued on {m}"),
                );
                note(
                    member
                        .session()
                        .outstanding_frames()
                        .iter()
                        .map(|f| id_of(&f.asdu))
                        .collect(),
                    format!("unconfirmed on {m}"),
                );
            }
        }
        for id in &self.open {
            match seen.get(id).map(Vec::len) {
                Some(1) => {}
                None => self.fail(&format!("{id} is lost")),
                Some(_) => self.fail(&format!("{id} is in {:?}", seen[id])),
            }
        }
        for id in self.discarded.iter().chain(&self.confirmed) {
            if let Some(places) = seen.get(id) {
                // A confirmed ASDU could be left behind only if it was confirmed
                // on one connection and also replayed. The send check already
                // forbids that, so any place is an error.
                self.fail(&format!("{id} is done but still in {places:?}"));
            }
        }
        if self.orderly {
            for (m, peer) in self.peers.iter().enumerate() {
                if peer.received.windows(2).any(|w| w[0] >= w[1]) {
                    self.fail(&format!("connection {m} carried {:?}", peer.received));
                }
            }
        }
    }
}

impl Model {
    /// The master settles on one connection: it is up and started, the
    /// application replays every failure onto it, and everything received is
    /// acknowledged. Then every open ASDU must have been delivered; data
    /// stranded on some other, live, connection would still be open.
    fn settle(&mut self) {
        let target = self.rng.below(self.peers.len() as u64) as usize;
        if !self.peers[target].up {
            self.peers[target].up = true;
            self.group
                .on_connection_established(target, self.now)
                .unwrap();
        }
        if self.role == Role::Controlled {
            let routed = self
                .group
                .on_frame_at(target, Apci::U(UFunction::StartDtAct), self.now)
                .unwrap_or_default();
            self.perform(routed);
        } else {
            self.switch_over_to(target);
        }
        self.settling = true;
        // Data held behind an undecided replay (10.6) reaches the target as
        // one backlog, which a k of 1 drains slowly between t1s: a round per
        // open ASDU, and a margin.
        for _ in 0..self.open.len() + 64 {
            self.step += 1;
            if !self.peers[target].up {
                self.peers[target].up = true;
                self.group
                    .on_connection_established(target, self.now)
                    .unwrap();
            }
            if self.role == Role::Controlled && self.group.state(target) != Ok(State::Started) {
                let routed = self
                    .group
                    .on_frame_at(target, Apci::U(UFunction::StartDtAct), self.now)
                    .unwrap_or_default();
                self.perform(routed);
            }
            if self.role == Role::Controlling && self.peers[target].up {
                // Walk the target to Started: a stop still pending is confirmed,
                // a stopped connection is started, a start is confirmed.
                let routed = match self.group.state(target) {
                    Ok(State::PendingStopped) => {
                        self.group
                            .on_frame_at(target, Apci::U(UFunction::StopDtCon), self.now)
                    }
                    Ok(State::PendingUnconfirmedStopped) => {
                        self.acknowledge(target);
                        Ok(Vec::new())
                    }
                    Ok(State::Stopped) => {
                        let _ = self.group.select(target);
                        self.group.start_at(target, self.now)
                    }
                    Ok(State::PendingStarted) => {
                        self.group
                            .on_frame_at(target, Apci::U(UFunction::StartDtCon), self.now)
                    }
                    _ => Ok(Vec::new()),
                };
                self.perform(routed.unwrap_or_default());
            }
            self.replay_all = true;
            self.decide();
            if self.peers[target].up {
                self.acknowledge(target);
            }
            // A connection stuck stopping on the side (its acknowledgements
            // refused on a connection that is not the started one) ends at its
            // own t1, and what it held is captured for the replay.
            if self.step.is_multiple_of(8) {
                self.now += self.t1 + Duration::from_secs(1);
                let outcome = self.group.tick(self.now);
                self.perform(outcome.routed);
            }
            self.check();
            if self.open.is_empty() {
                return;
            }
        }
        let members: Vec<String> = self
            .group
            .members()
            .iter()
            .enumerate()
            .map(|(m, member)| {
                format!(
                    "{m}: {:?} up={} left={} queued={} unconfirmed={}",
                    member.state(),
                    self.peers[m].up,
                    member.left_behind().len(),
                    member.queued_user_data().len(),
                    member.session().outstanding_frames().len()
                )
            })
            .collect();
        self.fail(&format!(
            "settled on {target}, but {:?} never went out; started {:?}, held {}, {members:?}",
            self.open,
            self.group.started_index(),
            self.group.held_user_data().len()
        ));
    }

    /// A controlling master moves data transfer to `target`: 10.2's manual
    /// switchover away from another started connection, then the start.
    fn switch_over_to(&mut self, target: usize) {
        let running = matches!(
            self.group.state(target),
            Ok(State::Started | State::PendingStarted)
        );
        if !running || self.group.started_index() != Some(target) {
            if let Some(other) = self.group.started_index().filter(|&o| o != target) {
                // 10.2's manual switchover: stop, confirmed, then start.
                let routed = self.group.stop_at(other, self.now).unwrap_or_default();
                self.perform(routed);
                if self.peers[other].up {
                    self.acknowledge(other);
                    let routed = self
                        .group
                        .on_frame_at(other, Apci::U(UFunction::StopDtCon), self.now)
                        .unwrap_or_default();
                    self.perform(routed);
                }
            }
            if running {
                // Running, but not the one the group names (a `select`):
                // name it again.
                let _ = self.group.select(target);
            } else {
                let routed = self.group.start_at(target, self.now).unwrap_or_default();
                self.perform(routed);
            }
        }
        if self.group.state(target) == Ok(State::PendingStarted) {
            let routed = self
                .group
                .on_frame_at(target, Apci::U(UFunction::StartDtCon), self.now)
                .unwrap_or_default();
            self.perform(routed);
        }
    }
}

fn run(orderly: bool, role: Role) -> Stats {
    let mut total = Stats::default();
    for seed in 1..=3000u64 {
        let mut model = Model::new(seed, orderly, role);
        for _ in 0..200 {
            model.step();
        }
        model.settle();
        total += model.stats;
    }
    total
}

/// The runs must have exercised what they check: a model that never fails a
/// connection or never replays proves nothing. The floors are about half of
/// what the runs do.
fn exercised(stats: Stats, sent: usize, replays: usize) {
    assert!(stats.sent > sent, "{stats:?}");
    assert!(stats.confirmed > sent / 2, "{stats:?}");
    assert!(stats.failures > 5_000, "{stats:?}");
    assert!(stats.replays > replays, "{stats:?}");
}
/// A controlled station, any application behaviour: nothing is lost and
/// nothing is sent twice.
#[test]
fn a_controlled_group_loses_and_duplicates_nothing() {
    let stats = run(false, Role::Controlled);
    exercised(stats, 10_000, 1_000);
    assert!(stats.discards > 1_000, "{stats:?}");
}

/// A controlled station whose application replays every failure before it
/// sends again: each connection also carries the data in order.
#[test]
fn a_controlled_group_keeps_the_order_for_a_prompt_application() {
    exercised(run(true, Role::Controlled), 10_000, 2_000);
}

/// A controlling station, any application behaviour.
#[test]
fn a_controlling_group_loses_and_duplicates_nothing() {
    let stats = run(false, Role::Controlling);
    exercised(stats, 10_000, 500);
    assert!(stats.discards > 1_000, "{stats:?}");
}

/// A controlling station whose application replays promptly: in order.
#[test]
fn a_controlling_group_keeps_the_order_for_a_prompt_application() {
    exercised(run(true, Role::Controlling), 2_000, 500);
}
