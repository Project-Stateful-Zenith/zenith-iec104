use iec104::link::State;
use iec104::redundancy::{Replay, ReplayOutcome};
use tokio::sync::{mpsc, oneshot};

use crate::Error;
use crate::connect::AsyncStream;
use crate::engine::{Command, Reply};

/// The application's side of a running driver. Cheap to clone; the driver
/// shuts down when the last handle is dropped.
///
/// `conn` is the connection's index: the station of a
/// [`ConnectionManager`](iec104::manager::ConnectionManager), or the member
/// of a [`RedundancyGroup`](iec104::redundancy::RedundancyGroup).
#[derive(Clone)]
pub struct Handle {
    pub(crate) commands: mpsc::Sender<Command>,
}

impl Handle {
    async fn request<T>(&self, command: impl FnOnce(Reply<T>) -> Command) -> Result<T, Error> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(command(reply))
            .await
            .map_err(|_| Error::Stopped)?;
        answer.await.map_err(|_| Error::Stopped)?
    }

    /// Sends one ASDU as an I-frame, or leaves it in the session's queue when
    /// data transfer is not enabled yet or the k window is full (clause 5.3,
    /// 5.5); the session sends it as soon as it may.
    ///
    /// `Ok` means the session took the ASDU, not that the peer confirmed it.
    /// What a manager station's session still holds when its connection is
    /// lost, queued or unconfirmed, goes with it (clause 5.1 restarts the
    /// numbering on the next connection); resend what matters after a
    /// reconnect.
    ///
    /// On a redundancy group `conn` must name a member but does not choose
    /// the connection: user data goes on the group's started connection
    /// (rule 3). Before the first start it is refused; between a failure and
    /// the next start the group holds it (10.5). A failed connection's
    /// unconfirmed data waits for [`Handle::retransmit_unconfirmed`].
    ///
    /// # Errors
    ///
    /// [`Error::BadAsdu`] for an ASDU no APDU can carry,
    /// [`Error::NoSuchConnection`] for an unknown `conn`, the core's refusal
    /// ([`Error::Manager`], [`Error::Group`]), and [`Error::Stopped`] once
    /// the driver has ended.
    pub async fn send_asdu(&self, conn: usize, asdu: impl Into<Vec<u8>>) -> Result<(), Error> {
        let asdu = asdu.into();
        self.request(|reply| Command::Send { conn, asdu, reply })
            .await
    }

    /// Sends STARTDT act on `conn` (clause 5.3; for a group, 10.3's start,
    /// which closes any other connection that is not stopped, 10.7). A
    /// connection without a socket, or not stopped, is refused.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchConnection`], [`Error::NotConnected`] or
    /// [`Error::InvalidState`] for a refused start, the core's own refusal
    /// ([`Error::Manager`], [`Error::Group`]), and [`Error::Stopped`] once
    /// the driver has ended.
    pub async fn start(&self, conn: usize) -> Result<(), Error> {
        self.request(|reply| Command::Start { conn, reply }).await
    }

    /// Sends STOPDT act on `conn` (clause 5.3), after the S-frame that
    /// confirms what was received. A connection that is not started is
    /// refused.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchConnection`], [`Error::NotConnected`] or
    /// [`Error::InvalidState`] for a refused stop, the core's own refusal
    /// ([`Error::Manager`], [`Error::Group`]), and [`Error::Stopped`] once
    /// the driver has ended.
    pub async fn stop(&self, conn: usize) -> Result<(), Error> {
        self.request(|reply| Command::Stop { conn, reply }).await
    }

    /// Actively closes `conn`: the pending acknowledgement goes out first
    /// (figures 10/11 NOTE), then the socket is shut down. A controlling
    /// station dials it again (clause 10.5's reopening).
    ///
    /// Closing a group's started connection is the application's connection
    /// change (figure 37): the group names none, and user data is refused
    /// until another is started, which [`crate::Options::auto_start`] does
    /// at once on a controlling station.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchConnection`] for an unknown `conn`,
    /// [`Error::NotConnected`] for one without a socket, the core's refusal
    /// ([`Error::Manager`], [`Error::Group`]), and [`Error::Stopped`] once
    /// the driver has ended.
    pub async fn close(&self, conn: usize) -> Result<(), Error> {
        self.request(|reply| Command::Close { conn, reply }).await
    }

    /// The connection's state (figures 17/18).
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchConnection`] for an unknown `conn`, and
    /// [`Error::Stopped`] once the driver has ended.
    pub async fn state(&self, conn: usize) -> Result<State, Error> {
        self.request(|reply| Command::State { conn, reply }).await
    }

    /// How many ASDUs [`Handle::send_asdu`] on `conn` can put on the wire at
    /// once: the k window (clause 5.5) less the I-frames the peer has not
    /// confirmed and the ASDUs already waiting in the session's clause 5.3
    /// queue. 0 while data transfer is not on, and on a redundancy group
    /// while it names no started connection or holds data for the next one
    /// (10.5); a group answers for its started connection whatever `conn`
    /// names.
    ///
    /// An application that keeps its own send queue (to order what it sends,
    /// as 5-101 Table 16 asks of a controlled station) hands over no more
    /// than this and waits for [`crate::Event::Acknowledged`].
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchConnection`] for an unknown `conn`, and
    /// [`Error::Stopped`] once the driver has ended.
    pub async fn window(&self, conn: usize) -> Result<u16, Error> {
        self.request(|reply| Command::Window { conn, reply }).await
    }

    /// Hands the driver a socket the application opened or accepted itself
    /// (a TLS stream, say) and returns the connection it now carries.
    ///
    /// `Some(conn)` names that connection; `None` takes the first member of a
    /// redundancy group that has no socket and is not dialing, and is
    /// [`Error::ConnectionRequired`] on a connection manager.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchConnection`] for an unknown `conn`, [`Error::Busy`]
    /// when it already has a socket, [`Error::NoFreeConnection`] or
    /// [`Error::ConnectionRequired`] without an index, and
    /// [`Error::Stopped`] once the driver has ended.
    pub async fn attach<S: AsyncStream>(
        &self,
        conn: Option<usize>,
        stream: S,
    ) -> Result<usize, Error> {
        let stream = Box::new(stream);
        self.request(|reply| Command::Attach {
            conn,
            stream,
            reply,
        })
        .await
    }

    /// Redundancy group only: what to do with the data a failed connection
    /// left unconfirmed (10.5, 10.6): replay it on the started connection,
    /// discard it, or only count it. The group keeps it until you replay or
    /// discard it; see
    /// [`RedundancyGroup::retransmit_unconfirmed`](iec104::redundancy::RedundancyGroup::retransmit_unconfirmed).
    ///
    /// # Errors
    ///
    /// [`Error::NotARedundancyGroup`] on a connection manager,
    /// [`Error::NoSuchConnection`] for an unknown `failed`, the group's
    /// refusal ([`Error::Group`]), and [`Error::Stopped`] once the driver has
    /// ended.
    pub async fn retransmit_unconfirmed(
        &self,
        failed: usize,
        replay: Replay,
    ) -> Result<ReplayOutcome, Error> {
        self.request(|reply| Command::Retransmit {
            failed,
            replay,
            reply,
        })
        .await
    }

    /// Closes every connection as [`Handle::close`] does, stops the driver
    /// and waits for it. Other handles get [`Error::Stopped`] afterwards.
    pub async fn shutdown(&self) {
        let (reply, done) = oneshot::channel();
        if self
            .commands
            .send(Command::Shutdown { reply })
            .await
            .is_ok()
        {
            let _ = done.await;
        }
    }
}
