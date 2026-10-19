//! The sans-IO core the engine drives: a [`ConnectionManager`] (one
//! connection per station) or a [`RedundancyGroup`] (one station's redundant
//! connections), behind one interface indexed by connection.

use std::time::Instant;

use iec104::apci::{Apci, ParseError};
use iec104::link::{Action, Role, Session, State};
use iec104::manager::{ConnectionManager, Directive};
use iec104::params::LinkParams;
use iec104::redundancy::{RedundancyGroup, Replay, ReplayOutcome, Routed, Switchover};

use crate::Error;

/// The reason a connection manager's station reports in
/// `Event::Disconnected` after an application close or a shutdown. (A
/// redundancy group closes with its own reasons.)
pub const CLOSED_BY_APPLICATION: &str = "closed by the application";

/// What one tick asks of the engine.
#[derive(Default)]
pub struct Tick {
    /// Connections to dial now.
    pub connect: Vec<usize>,
    /// Actions of expired timers, per connection, in order.
    pub routed: Vec<Routed>,
    /// Group only: switchovers a failed started connection caused (10.5).
    pub switchovers: Vec<Switchover>,
}

pub trait Core: Send + 'static {
    fn len(&self) -> usize;
    /// `None` when `conn` names no connection.
    fn params(&self, conn: usize) -> Option<LinkParams>;
    /// `None` when `conn` names no connection.
    fn state(&self, conn: usize) -> Option<State>;
    fn tick(&mut self, now: Instant) -> Tick;
    fn next_deadline(&self) -> Option<Instant>;
    fn established(&mut self, conn: usize, now: Instant);
    fn lost(&mut self, conn: usize);
    /// The frame's actions, or why the core refused the frame.
    fn on_frame(&mut self, conn: usize, apci: Apci, now: Instant) -> Result<Vec<Routed>, Error>;
    fn on_parse_error(&mut self, conn: usize, error: ParseError, now: Instant) -> Vec<Routed>;
    fn send(&mut self, conn: usize, asdu: &[u8], now: Instant) -> Result<Vec<Routed>, Error>;
    fn start(&mut self, conn: usize, now: Instant) -> Result<Vec<Routed>, Error>;
    fn stop(&mut self, conn: usize, now: Instant) -> Result<Vec<Routed>, Error>;
    fn close(&mut self, conn: usize, now: Instant) -> Result<Vec<Routed>, Error>;
    fn retransmit(
        &mut self,
        failed: usize,
        replay: Replay,
        now: Instant,
    ) -> Result<(ReplayOutcome, Vec<Routed>), Error>;
    /// Group only: the started connection.
    fn started(&self) -> Option<usize>;
    /// Group only: how many ASDUs a failed connection holds for the replay.
    fn unconfirmed(&mut self, conn: usize) -> usize;
    /// The starts the auto-start policy asks for, given the connections that
    /// have just come up.
    fn auto_start(&mut self, established: &[usize], now: Instant) -> Vec<Routed>;
    /// The session user data sent through `conn` goes to, if it can carry
    /// any: the station's own for a manager, the started member's for a
    /// group (rule 3), `None` while a group names no started connection.
    fn carrier(&self, conn: usize) -> Option<&Session>;
}

/// How many more ASDUs `session` can put on the wire at once: the k window
/// (clause 5.5) less what is unconfirmed and what already waits in its
/// clause 5.3 queue, and none unless data transfer is on.
pub fn window(session: &Session, k: u16) -> u16 {
    if session.state() != State::Started {
        return 0;
    }
    let taken =
        usize::from(session.outstanding_i_frames()).saturating_add(session.pending_user_data());
    k.saturating_sub(u16::try_from(taken).unwrap_or(u16::MAX))
}

fn routed(directives: Vec<Directive>) -> Vec<Routed> {
    directives
        .into_iter()
        .filter_map(|directive| match directive {
            Directive::Actions { station, actions } => Some(Routed {
                member: station,
                actions,
            }),
            Directive::Connect { .. } => None,
        })
        .collect()
}

fn one(member: usize, actions: Vec<Action>) -> Vec<Routed> {
    if actions.is_empty() {
        Vec::new()
    } else {
        vec![Routed { member, actions }]
    }
}

/// The session answers a start or stop it cannot perform with no action at
/// all; the handle's caller is told why instead.
trait Expect {
    fn expect(&self, conn: usize, wanted: State) -> Result<(), Error>;
}

impl Expect for ConnectionManager {
    fn expect(&self, conn: usize, wanted: State) -> Result<(), Error> {
        let station = self.station(conn)?;
        if !station.is_connected() {
            return Err(Error::NotConnected(conn));
        }
        match station.state() {
            state if state == wanted => Ok(()),
            state => Err(Error::InvalidState { conn, state }),
        }
    }
}

impl Core for ConnectionManager {
    fn len(&self) -> usize {
        Self::len(self)
    }

    fn params(&self, conn: usize) -> Option<LinkParams> {
        self.stations().get(conn).map(|station| *station.params())
    }

    fn state(&self, conn: usize) -> Option<State> {
        self.stations()
            .get(conn)
            .map(iec104::manager::Station::state)
    }

    fn tick(&mut self, now: Instant) -> Tick {
        let mut tick = Tick::default();
        for directive in Self::tick(self, now) {
            match directive {
                // `ConnectReason::AttemptTimedOut` asks to abandon the dial in
                // flight; the engine abandons it on every new attempt anyway.
                Directive::Connect { station, .. } => tick.connect.push(station),
                Directive::Actions { station, actions } => tick.routed.push(Routed {
                    member: station,
                    actions,
                }),
            }
        }
        tick
    }

    fn next_deadline(&self) -> Option<Instant> {
        Self::next_deadline(self)
    }

    fn established(&mut self, conn: usize, now: Instant) {
        let _ = self.on_connection_established(conn, now);
    }

    fn lost(&mut self, conn: usize) {
        let _ = self.on_connection_lost(conn);
    }

    fn on_frame(&mut self, conn: usize, apci: Apci, now: Instant) -> Result<Vec<Routed>, Error> {
        Ok(routed(Self::on_frame(self, conn, apci, now)?))
    }

    fn on_parse_error(&mut self, conn: usize, error: ParseError, now: Instant) -> Vec<Routed> {
        routed(Self::on_parse_error(self, conn, error, now).unwrap_or_default())
    }

    fn send(&mut self, conn: usize, asdu: &[u8], now: Instant) -> Result<Vec<Routed>, Error> {
        if let Some(directive) = self.send_i_frame(conn, asdu, now)? {
            Ok(routed(vec![directive]))
        } else {
            // Not allowed yet or the k window is full: the session's queue
            // sends it as soon as it may (clause 5.3, 5.5).
            self.queue_i_frame(conn, asdu)?;
            Ok(Vec::new())
        }
    }

    fn start(&mut self, conn: usize, now: Instant) -> Result<Vec<Routed>, Error> {
        self.expect(conn, State::Stopped)?;
        Ok(routed(self.request_start(conn, now)?))
    }

    fn stop(&mut self, conn: usize, now: Instant) -> Result<Vec<Routed>, Error> {
        self.expect(conn, State::Started)?;
        Ok(routed(self.request_stop(conn, now)?))
    }

    fn close(&mut self, conn: usize, _now: Instant) -> Result<Vec<Routed>, Error> {
        let station = self.station_mut(conn)?;
        if !station.is_connected() {
            return Err(Error::NotConnected(conn));
        }
        Ok(one(
            conn,
            station.session_mut().close(CLOSED_BY_APPLICATION),
        ))
    }

    fn retransmit(
        &mut self,
        _failed: usize,
        _replay: Replay,
        _now: Instant,
    ) -> Result<(ReplayOutcome, Vec<Routed>), Error> {
        Err(Error::NotARedundancyGroup)
    }

    fn started(&self) -> Option<usize> {
        None
    }

    fn unconfirmed(&mut self, _conn: usize) -> usize {
        0
    }

    fn carrier(&self, conn: usize) -> Option<&Session> {
        self.stations()
            .get(conn)
            .map(iec104::manager::Station::session)
    }

    fn auto_start(&mut self, established: &[usize], now: Instant) -> Vec<Routed> {
        if self.role() != Role::Controlling {
            return Vec::new();
        }
        established
            .iter()
            .flat_map(|&conn| routed(self.request_start(conn, now).unwrap_or_default()))
            .collect()
    }
}

impl Core for RedundancyGroup {
    fn len(&self) -> usize {
        Self::len(self)
    }

    fn params(&self, conn: usize) -> Option<LinkParams> {
        self.members().get(conn).map(|member| *member.params())
    }

    fn state(&self, conn: usize) -> Option<State> {
        self.members()
            .get(conn)
            .map(iec104::redundancy::Member::state)
    }

    fn tick(&mut self, now: Instant) -> Tick {
        let outcome = Self::tick(self, now);
        Tick {
            connect: outcome.connect,
            routed: outcome.routed,
            switchovers: outcome.switchovers,
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        Self::next_deadline(self)
    }

    fn established(&mut self, conn: usize, now: Instant) {
        let _ = self.on_connection_established(conn, now);
    }

    fn lost(&mut self, conn: usize) {
        let _ = self.on_connection_lost(conn);
    }

    fn on_frame(&mut self, conn: usize, apci: Apci, now: Instant) -> Result<Vec<Routed>, Error> {
        // An I- or S-frame on a connection that is not the started one is
        // refused and not acknowledged (10.5, 10.6): nothing to perform, and
        // the engine reports the refusal.
        Ok(self.on_frame_at(conn, apci, now)?)
    }

    fn on_parse_error(&mut self, conn: usize, error: ParseError, now: Instant) -> Vec<Routed> {
        self.on_parse_error_at(conn, error, now).unwrap_or_default()
    }

    fn send(&mut self, _conn: usize, asdu: &[u8], now: Instant) -> Result<Vec<Routed>, Error> {
        // Rule 3: user data goes on the started connection; during a
        // switchover the group holds it for the next one.
        let target = self.started_index().unwrap_or(0);
        Ok(self.send_user_data_at(target, asdu, now)?)
    }

    fn start(&mut self, conn: usize, now: Instant) -> Result<Vec<Routed>, Error> {
        Ok(self.start_at(conn, now)?)
    }

    fn stop(&mut self, conn: usize, now: Instant) -> Result<Vec<Routed>, Error> {
        Ok(self.stop_at(conn, now)?)
    }

    fn close(&mut self, conn: usize, now: Instant) -> Result<Vec<Routed>, Error> {
        Ok(self.close_at(conn, now)?)
    }

    fn retransmit(
        &mut self,
        failed: usize,
        replay: Replay,
        now: Instant,
    ) -> Result<(ReplayOutcome, Vec<Routed>), Error> {
        Ok(self.retransmit_unconfirmed_at(failed, replay, now)?)
    }

    fn started(&self) -> Option<usize> {
        self.started_index()
    }

    fn unconfirmed(&mut self, conn: usize) -> usize {
        // `Leave` only counts: it records no decision, so the application's
        // own replay or discard still follows.
        match self.retransmit_unconfirmed(conn, Replay::Leave) {
            Ok(ReplayOutcome::Left { unconfirmed }) => unconfirmed,
            _ => 0,
        }
    }

    fn carrier(&self, _conn: usize) -> Option<&Session> {
        // During a switchover the group holds user data itself (10.5): there
        // is no window until a connection is named.
        let started = self.started_index()?;
        if self.held_user_data().is_empty() {
            self.members()
                .get(started)
                .map(iec104::redundancy::Member::session)
        } else {
            None
        }
    }

    fn auto_start(&mut self, _established: &[usize], now: Instant) -> Vec<Routed> {
        // 10.3: one connection is changed into the started state; the group
        // names none after the first connection or a failure.
        if self.role() != Role::Controlling || self.started_index().is_some() {
            return Vec::new();
        }
        let candidate = self
            .members()
            .iter()
            .position(|m| m.session().is_connected() && m.state() == State::Stopped);
        candidate.map_or_else(Vec::new, |conn| {
            self.start_at(conn, now).unwrap_or_default()
        })
    }
}
