//! The controlled station: it listens (clause 7.1) and answers the STARTDT act
//! of whichever connection its master starts (10.4).

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use iec104::link::Role;
use iec104::redundancy::RedundancyGroup;
use tokio::net::{TcpListener, TcpStream};

use crate::{Error, Events, Handle, NoConnector, Options};

/// Runs a controlled [`RedundancyGroup`] on the current Tokio runtime.
///
/// Every connection a master opens takes a free member: one member for a
/// single connection, N for clause 10's redundant ones. The connection the
/// master last sent STARTDT act on is the started one (10.2, rule 4), and user
/// data from [`Handle::send_asdu`] goes there. One group is one master's
/// process image (rule 7); run one driver per master.
///
/// Sockets come from [`serve`], [`serve_routed`] or [`Handle::attach`] with
/// `None`. A group of the controlling role is [`Error::WrongRole`].
///
/// # Errors
///
/// [`Error::WrongRole`] when the group is of the controlling role.
pub fn spawn(group: RedundancyGroup, options: Options) -> Result<(Handle, Events), Error> {
    if group.role() != Role::Controlled {
        return Err(Error::WrongRole);
    }
    Ok(crate::spawn(group, NoConnector, options, true))
}

/// Accepts TCP connections on `listener` and attaches each to a free member
/// of the driver behind `handle`.
///
/// A connection that finds every member taken
/// is closed at once. Returns `Ok` when the driver refuses an attach for any
/// reason but a full group (it has stopped, or `handle` is not an
/// outstation's). An accept error does not end it: a connection that failed
/// before it was accepted is skipped, and on any other error (out of file
/// descriptors, say) it waits a moment and accepts again.
///
/// Every connection goes to the one group, so this serves one master (rule
/// 7). With several masters on one listener, use [`serve_routed`]: otherwise a
/// second master's STARTDT act closes the first one's started connection
/// (10.7).
///
/// Every host that reaches the listener is accepted: plain 104 authenticates
/// nobody, and any peer that connects can send STARTDT act and so take the
/// data transfer from the master (10.7). Restrict who can connect with
/// [`serve_routed`] (a `route` that refuses unknown addresses), with a
/// firewall, or with TLS (`iec104-tls`).
///
/// # Errors
///
/// None: it returns `Ok` when the driver refuses an attach, and handles
/// every accept error itself.
pub async fn serve(listener: TcpListener, handle: Handle) -> io::Result<()> {
    loop {
        let (stream, _peer) = accept(&listener).await;
        // Latency only; a socket that refuses it still carries the protocol.
        let _ = stream.set_nodelay(true);
        match handle.attach(None, stream).await {
            Ok(_) | Err(Error::NoFreeConnection) => {}
            Err(_) => return Ok(()),
        }
    }
}

/// Accepts TCP connections on `listener` and hands each to the driver `route`
/// picks for its peer address.
///
/// One driver, and so one redundancy group, per
/// master (10.2 rule 7: *"each controlling station must be assigned to a
/// different redundancy group"*). A connection `route` refuses (`None`), or
/// whose driver has every member taken or has stopped, is closed at once.
/// Accept errors are handled as in [`serve`], so this never returns.
///
/// `route` is also where unknown peers are kept out: plain 104 authenticates
/// nobody, so return `None` for any address that is not a known master's.
/// The address is only as good as the network it comes over; for more, use
/// TLS (`iec104-tls`).
///
/// # Errors
///
/// None: accept errors are handled as in [`serve`], and it never returns.
pub async fn serve_routed(
    listener: TcpListener,
    route: impl Fn(SocketAddr) -> Option<Handle>,
) -> io::Result<()> {
    loop {
        let (stream, peer) = accept(&listener).await;
        let _ = stream.set_nodelay(true);
        if let Some(handle) = route(peer) {
            let _ = handle.attach(None, stream).await;
        }
    }
}

/// The pause after an accept error that is not one connection's own (out of
/// file descriptors, say), before accepting again.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The next accepted connection. Returning an accept error would let any peer
/// that can use up the station's descriptors stop it taking masters for good,
/// so errors are waited out instead.
async fn accept(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(accepted) => return accepted,
            // One connection's failure (reset before it was accepted) is
            // nothing to the listener.
            Err(e) if is_connection_error(&e) => {}
            // Out of descriptors, buffers or memory: pause, then accept again.
            Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
        }
    }
}

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    )
}
