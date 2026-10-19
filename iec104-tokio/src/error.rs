use std::fmt;

use iec104::manager::ManagerError;
use iec104::redundancy::GroupError;

/// Why a [`crate::Handle`] request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The driver task has ended: a handle shut it down
    /// ([`crate::Handle::shutdown`]), or the task ended otherwise (it
    /// panicked, or its runtime shut down).
    Stopped,
    /// The connection manager refused the call.
    Manager(ManagerError),
    /// The redundancy group refused the call.
    Group(GroupError),
    /// The index names no connection of this driver.
    NoSuchConnection(usize),
    /// The connection has no socket.
    NotConnected(usize),
    /// The connection is not in the state the request needs: a start needs a
    /// stopped connection, a stop a started one (clause 5.3).
    InvalidState {
        /// The connection named.
        conn: usize,
        /// Its state.
        state: iec104::link::State,
    },
    /// [`crate::Handle::attach`]: the connection already has a socket.
    Busy(usize),
    /// [`crate::Handle::attach`] without an index: every connection of the
    /// group already has a socket.
    NoFreeConnection,
    /// [`crate::Handle::attach`] without an index on a driver with one
    /// connection per station, where the index names the station.
    ConnectionRequired,
    /// The ASDU is empty or longer than an APDU can carry (clause 5: at most
    /// 249 octets, [`iec104::apci::MAX_ASDU`]).
    BadAsdu(usize),
    /// The call only exists for a redundancy group.
    NotARedundancyGroup,
    /// The core was built for the other role.
    WrongRole,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => f.write_str("the driver has stopped"),
            Self::Manager(e) => write!(f, "connection manager: {e:?}"),
            Self::Group(e) => write!(f, "redundancy group: {e:?}"),
            Self::NoSuchConnection(i) => write!(f, "no connection {i}"),
            Self::NotConnected(i) => write!(f, "connection {i} is not connected"),
            Self::InvalidState { conn, state } => {
                write!(f, "connection {conn} is {state:?}")
            }
            Self::Busy(i) => write!(f, "connection {i} already has a socket"),
            Self::NoFreeConnection => f.write_str("every connection already has a socket"),
            Self::ConnectionRequired => f.write_str("name the station to attach to"),
            Self::BadAsdu(len) => write!(f, "an ASDU of {len} octets does not fit an APDU"),
            Self::NotARedundancyGroup => f.write_str("only a redundancy group does that"),
            Self::WrongRole => f.write_str("the core was built for the other role"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ManagerError> for Error {
    fn from(e: ManagerError) -> Self {
        Self::Manager(e)
    }
}

impl From<GroupError> for Error {
    fn from(e: GroupError) -> Self {
        Self::Group(e)
    }
}
