//! Blocking TLS over `std::net::TcpStream`.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Instant;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConnection, Connection, ProtocolVersion, ServerConnection};

use crate::Renewal;
use crate::config::TlsConfig;

/// A mutually authenticated TLS session over TCP: `Read + Write`, so the
/// blocking drivers carry 104 over it unchanged.
///
/// Reads and writes follow the TCP socket's timeouts ([`TlsStream::get_ref`]
/// to set them). A read that times out mid-record keeps what arrived and
/// continues on the next call. A write returns once its data is queued, sending
/// what the write timeout allows; [`flush`](Write::flush) to wait until all of
/// it is out. After a write or flush fails with any error but `WouldBlock` or
/// `TimedOut` the session is unusable.
pub struct TlsStream {
    conn: Connection,
    sock: TcpStream,
    renewal: Renewal,
}

impl std::fmt::Debug for TlsStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsStream")
            .field("sock", &self.sock)
            .field("version", &self.conn.protocol_version())
            .finish_non_exhaustive()
    }
}

/// Dials `address` (`host:port`; the port commonly used for 104 over TLS is
/// [`DEFAULT_TLS_PORT`](crate::DEFAULT_TLS_PORT)) and runs the client
/// handshake. The server's certificate must name `host` unless
/// [`verify_server_name`](crate::TlsConfigBuilder::verify_server_name) is off.
///
/// # Errors
///
/// Returns an error when `address` has no valid host or does not resolve,
/// when no resolved address accepts the TCP connection, or when the TLS
/// handshake fails or times out.
pub fn connect(address: &str, config: &TlsConfig) -> io::Result<TlsStream> {
    let name = crate::host(address)?;
    let mut last = io::Error::other(format!("{address} resolves to no address"));
    for resolved in address.to_socket_addrs()? {
        match TcpStream::connect_timeout(&resolved, config.handshake_timeout) {
            Ok(tcp) => return connect_over(tcp, name, config),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Runs the client handshake over a TCP connection the caller opened.
/// `server_name` is the DNS name or IP address the server's certificate must
/// carry.
///
/// # Errors
///
/// Returns an error when `server_name` is no valid name, or when the TLS
/// handshake fails or times out.
pub fn connect_over(
    tcp: TcpStream,
    server_name: &str,
    config: &TlsConfig,
) -> io::Result<TlsStream> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let conn = ClientConnection::new(config.client.clone(), name).map_err(io::Error::other)?;
    TlsStream::handshake(conn.into(), tcp, config)
}

/// Runs the server handshake on an accepted TCP connection. The client must
/// present a certificate the configuration accepts.
///
/// With TLS 1.3 a client learns that its certificate was refused only after
/// its own handshake finished: its [`connect`] succeeds, and its first read
/// fails with the server's alert.
///
/// # Errors
///
/// Returns an error when the TLS handshake fails or times out.
pub fn accept(tcp: TcpStream, config: &TlsConfig) -> io::Result<TlsStream> {
    let conn = ServerConnection::new(config.server.clone()).map_err(io::Error::other)?;
    TlsStream::handshake(conn.into(), tcp, config)
}

impl TlsStream {
    fn handshake(
        mut conn: Connection,
        mut sock: TcpStream,
        config: &TlsConfig,
    ) -> io::Result<Self> {
        let timeouts = (sock.read_timeout()?, sock.write_timeout()?);
        let deadline = Instant::now()
            .checked_add(config.handshake_timeout)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS handshake timeout too long",
                )
            })?;
        let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out");
        let expired = |e: &io::Error| {
            matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            )
        };
        // Driven step by step rather than with `complete_io`, which keeps
        // reading as long as each read brings a byte: a peer trickling one
        // octet at a time would hold the handshake open forever. Every read and
        // write gets only the time left until the deadline.
        while conn.is_handshaking() {
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or_else(timed_out)?;
            sock.set_read_timeout(Some(left))?;
            sock.set_write_timeout(Some(left))?;
            while conn.wants_write() {
                match conn.write_tls(&mut sock) {
                    Ok(_) => {}
                    Err(e) if expired(&e) => return Err(timed_out()),
                    Err(e) => return Err(e),
                }
            }
            if !conn.is_handshaking() {
                break;
            }
            match conn.read_tls(&mut sock) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed the connection during the TLS handshake",
                    ));
                }
                Ok(_) => {
                    if let Err(e) = conn.process_new_packets() {
                        // The alert rustls queued goes to the peer, as
                        // `complete_io` would send it.
                        let _ = conn.write_tls(&mut sock);
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                }
                Err(e) if expired(&e) => return Err(timed_out()),
                Err(e) => return Err(e),
            }
        }
        while conn.wants_write() {
            conn.write_tls(&mut sock)?;
        }
        sock.set_read_timeout(timeouts.0)?;
        sock.set_write_timeout(timeouts.1)?;
        Ok(Self {
            conn,
            sock,
            renewal: Renewal::new(config.key_update_interval),
        })
    }

    /// The TCP socket, to set timeouts or read addresses. Reading or writing
    /// it directly breaks the session.
    #[must_use]
    pub const fn get_ref(&self) -> &TcpStream {
        &self.sock
    }

    /// The peer's certificate chain as it sent it, leaf first: its identity,
    /// for the application to log or authorise.
    #[must_use]
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.conn.peer_certificates()
    }

    /// The negotiated TLS version.
    #[must_use]
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.conn.protocol_version()
    }

    /// The negotiated cipher suite.
    #[must_use]
    pub fn cipher_suite(&self) -> Option<rustls::CipherSuite> {
        self.conn.negotiated_cipher_suite().map(|s| s.suite())
    }

    /// Sends a TLS 1.3 `KeyUpdate` now, asking the peer to update too (RFC 8446
    /// 4.6.3).
    ///
    /// # Errors
    ///
    /// On TLS 1.2 there is no such message; this returns an error. It also
    /// returns the error of writing the message to the socket.
    pub fn update_keys(&mut self) -> io::Result<()> {
        self.conn.refresh_traffic_keys().map_err(io::Error::other)?;
        self.renewal.done();
        self.flush_tls()
    }

    /// Sends `close_notify` and shuts the TCP connection down.
    ///
    /// # Errors
    ///
    /// Returns the error of writing `close_notify` to the socket.
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        let flushed = self.flush_tls();
        let _ = self.sock.shutdown(Shutdown::Both);
        flushed
    }

    fn renew_if_due(&mut self) -> io::Result<()> {
        if self.renewal.due(self.conn.protocol_version()) {
            self.update_keys()?;
        }
        Ok(())
    }

    fn flush_tls(&mut self) -> io::Result<()> {
        // The socket timeout bounds each send, and a send that moved any byte
        // succeeds: this bounds the whole flush against a peer draining slowly.
        let deadline = self
            .sock
            .write_timeout()?
            .and_then(|timeout| Instant::now().checked_add(timeout));
        while self.conn.wants_write() {
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                // The rest stays queued for the next write, flush or read.
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Whatever the session queued (a KeyUpdate the peer asked for) first.
        // A send that only timed out does not stop the read: two stations
        // both stuck writing must still drain each other.
        match self.flush_tls() {
            Err(e)
                if !matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(e);
            }
            _ => {}
        }
        // The socket timeout bounds each pass; this bounds the whole read, so a
        // peer trickling a record one octet at a time cannot hold it forever.
        let deadline = self
            .sock
            .read_timeout()?
            .and_then(|timeout| Instant::now().checked_add(timeout));
        while self.conn.wants_read() {
            // Only a pass that neither read nor wrote ends the wait: one that
            // only wrote (an alert rustls queued) still owes a read.
            if self.conn.complete_io(&mut self.sock)? == (0, 0) {
                break;
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                // No plaintext yet: the reader reports `WouldBlock`, as the
                // socket's own timeout does on Unix.
                break;
            }
        }
        self.conn.reader().read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // What an earlier write left queued goes first; its error, if any, is
        // reported here, before `buf` is taken.
        self.flush_tls()?;
        self.renew_if_due()?;
        let n = self.conn.writer().write(buf)?;
        // `buf` is queued and will go out: reporting a failed send now would
        // make the caller write it twice. The next write, flush or read
        // retries the send and reports what still fails.
        let _ = self.flush_tls();
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.conn.writer().flush()?;
        self.flush_tls()?;
        self.sock.flush()
    }
}
