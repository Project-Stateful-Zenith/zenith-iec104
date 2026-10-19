use std::future::Future;
use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

/// A byte stream the driver can carry a connection over: TCP, TLS on top of
/// it, or an in-memory [`tokio::io::duplex`] pipe in tests.
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncStream for T {}

/// Opens the controlling station's connections (clause 7.1: *"The
/// controlling station is equivalent to the client (connector)"*).
///
/// The driver calls [`Connector::connect`] whenever the core asks for a
/// connection and drops the future unfinished when the attempt's t0 expires,
/// so an implementation needs no timeout of its own.
pub trait Connector: Send + Sync + 'static {
    /// The stream a successful dial yields.
    type Stream: AsyncStream;

    /// Dials connection `conn`: the station of a connection manager, or the
    /// member of a redundancy group.
    fn connect(&self, conn: usize) -> impl Future<Output = io::Result<Self::Stream>> + Send;
}

/// Plain TCP, one address per connection.
#[derive(Debug, Clone)]
pub struct TcpConnector {
    addresses: Vec<String>,
}

impl TcpConnector {
    /// Connection `i` dials `addresses[i]` (`host:port`; the standard's port
    /// is 2404, [`iec104::params::PORT`]).
    #[must_use]
    pub const fn new(addresses: Vec<String>) -> Self {
        Self { addresses }
    }
}

impl Connector for TcpConnector {
    type Stream = TcpStream;

    async fn connect(&self, conn: usize) -> io::Result<TcpStream> {
        let address = self
            .addresses
            .get(conn)
            .ok_or_else(|| io::Error::other(format!("no address for connection {conn}")))?;
        let stream = TcpStream::connect(address.as_str()).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }
}

/// The connector of a driver that never dials: a controlled station's
/// connections are the ones it accepts (clause 7.1).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoConnector;

impl Connector for NoConnector {
    type Stream = TcpStream;

    fn connect(&self, _conn: usize) -> impl Future<Output = io::Result<TcpStream>> + Send {
        std::future::ready(Err(io::Error::other("a controlled station does not dial")))
    }
}
