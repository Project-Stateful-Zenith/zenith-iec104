//! The controlling station: it dials (clause 7.1), starts data transfer and
//! redials a lost connection every t0 (clause 10.5).

use iec104::link::Role;
use iec104::manager::ConnectionManager;
use iec104::redundancy::RedundancyGroup;

use crate::{Connector, Error, Events, Handle, Options};

/// Runs a controlling [`ConnectionManager`] (one connection per station) on
/// the current Tokio runtime.
///
/// Station `i` is dialed through `connector.connect(i)` whenever the manager
/// asks, and a new attempt abandons one still in flight when its t0 expired
/// (`ConnectReason::AttemptTimedOut`). A manager of the controlled role is
/// [`Error::WrongRole`]: that station listens ([`crate::outstation`]).
///
/// # Errors
///
/// [`Error::WrongRole`] when the manager is of the controlled role.
pub fn spawn<K: Connector>(
    manager: ConnectionManager,
    connector: K,
    options: Options,
) -> Result<(Handle, Events), Error> {
    if manager.role() != Role::Controlling {
        return Err(Error::WrongRole);
    }
    Ok(crate::spawn(manager, connector, options, false))
}

/// Runs a controlling [`RedundancyGroup`] (N connections to one station, one
/// of them started, clause 10) on the current Tokio runtime.
///
/// Member `i` is dialed through `connector.connect(i)`. With
/// [`Options::auto_start`], whenever the group names no started connection
/// (at the first connection, or after a lost or closed one) the
/// lowest-numbered member that is up and stopped is started (10.3). A t1 on
/// the started connection is the group's own switchover, reported as
/// [`crate::Event::Switchover`].
///
/// # Errors
///
/// [`Error::WrongRole`] when the group is of the controlled role.
pub fn spawn_redundant<K: Connector>(
    group: RedundancyGroup,
    connector: K,
    options: Options,
) -> Result<(Handle, Events), Error> {
    if group.role() != Role::Controlling {
        return Err(Error::WrongRole);
    }
    Ok(crate::spawn(group, connector, options, true))
}
