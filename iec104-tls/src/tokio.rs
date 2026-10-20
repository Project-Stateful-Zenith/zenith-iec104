//! Async TLS over Tokio (`tokio` feature).
//!
//! The same [`TlsConfig`] through
//! [tokio-rustls](https://docs.rs/tokio-rustls), and the pieces that plug it
//! into [`iec104_tokio`]'s drivers: a [`TlsConnector`] for
//! [`iec104_tokio::master`], and [`serve`] / [`serve_routed`] for
//! [`iec104_tokio::outstation`]. A [`iec104_tokio::client::Client`] dials with
//! the same [`TlsConnector`], and a [`iec104_tokio::server::Server`] is served
//! through its [`handle`](iec104_tokio::server::Server::handle).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use ::tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use ::tokio::net::{TcpListener, TcpStream};
use ::tokio::time::timeout;
use iec104_tokio::{Connector, Handle};
use rustls::ProtocolVersion;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::{TlsAcceptor, TlsConnector as RustlsConnector};

use crate::{Renewal, TlsConfig};

/// An async mutually authenticated TLS session over TCP:
/// `AsyncRead + AsyncWrite + Unpin + Send`, so it is an
/// [`iec104_tokio::AsyncStream`].
///
/// With a [key-update interval](crate::TlsConfigBuilder::key_update_interval),
/// the `KeyUpdate` goes out ahead of the first write after the interval.
#[derive(Debug)]
pub struct TlsStream {
    inner: tokio_rustls::TlsStream<TcpStream>,
    renewal: Renewal,
}

impl TlsStream {
    fn common(&self) -> &rustls::CommonState {
        self.inner.get_ref().1
    }

    /// The TCP socket underneath.
    pub fn get_ref(&self) -> &TcpStream {
        self.inner.get_ref().0
    }

    /// The peer's certificate chain, leaf first: its identity, for the
    /// application to log or authorise.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.common().peer_certificates()
    }

    /// The negotiated TLS version.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.common().protocol_version()
    }

    /// The negotiated cipher suite.
    pub fn cipher_suite(&self) -> Option<rustls::CipherSuite> {
        self.common().negotiated_cipher_suite().map(|s| s.suite())
    }

    /// Queues a TLS 1.3 `KeyUpdate` that asks the peer to update too (RFC 8446
    /// 4.6.3); it goes out with the next write or flush.
    ///
    /// # Errors
    ///
    /// On TLS 1.2 there is no such message; this returns an error.
    pub fn update_keys(&mut self) -> io::Result<()> {
        let refreshed = match &mut self.inner {
            tokio_rustls::TlsStream::Client(s) => s.get_mut().1.refresh_traffic_keys(),
            tokio_rustls::TlsStream::Server(s) => s.get_mut().1.refresh_traffic_keys(),
        };
        refreshed.map_err(io::Error::other)?;
        self.renewal.done();
        Ok(())
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.renewal.due(self.protocol_version()) {
            self.update_keys()?;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn handshake_timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")
}

/// Dials `address` (`host:port`) and runs the client handshake; the server's
/// certificate must name `host` unless
/// [`verify_server_name`](crate::TlsConfigBuilder::verify_server_name) is off.
///
/// # Errors
///
/// Returns an error when `address` has no valid host, when the TCP connect
/// fails or times out, or when the TLS handshake fails or times out.
pub async fn connect(address: &str, config: &TlsConfig) -> io::Result<TlsStream> {
    let name = crate::host(address)?;
    let tcp = timeout(config.handshake_timeout, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out"))??;
    connect_over(tcp, name, config).await
}

/// Runs the client handshake over a TCP connection the caller opened.
///
/// # Errors
///
/// Returns an error when `server_name` is no valid name, or when the TLS
/// handshake fails or times out.
pub async fn connect_over(
    tcp: TcpStream,
    server_name: &str,
    config: &TlsConfig,
) -> io::Result<TlsStream> {
    let _ = tcp.set_nodelay(true);
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let connector = RustlsConnector::from(config.client.clone());
    let stream = timeout(
        config.handshake_timeout,
        connector.connect(name.clone(), tcp),
    )
    .await
    .map_err(|_| handshake_timed_out())??;
    crate::verify::check_resumed(stream.get_ref().1, config, Some(&name))?;
    Ok(TlsStream {
        inner: stream.into(),
        renewal: Renewal::new(config.key_update_interval),
    })
}

/// Runs the server handshake on an accepted TCP connection; the client must
/// present a certificate the configuration accepts.
///
/// # Errors
///
/// Returns an error when the TLS handshake fails or times out.
pub async fn accept(tcp: TcpStream, config: &TlsConfig) -> io::Result<TlsStream> {
    let _ = tcp.set_nodelay(true);
    let acceptor = TlsAcceptor::from(config.server.clone());
    let stream = timeout(config.handshake_timeout, acceptor.accept(tcp))
        .await
        .map_err(|_| handshake_timed_out())??;
    crate::verify::check_resumed(stream.get_ref().1, config, None)?;
    Ok(TlsStream {
        inner: stream.into(),
        renewal: Renewal::new(config.key_update_interval),
    })
}

/// A [`Connector`] for [`iec104_tokio::master`].
///
/// Connection `i` dials `addresses[i]` (`host:port`) over TLS. The driver reports a refused
/// handshake as `Event::ConnectFailed` with the TLS error's text, and dials
/// again when t0 expires.
#[derive(Debug, Clone)]
pub struct TlsConnector {
    config: TlsConfig,
    addresses: Vec<String>,
}

impl TlsConnector {
    /// Connection `i` dials `addresses[i]`, and the server must present a
    /// certificate for its host.
    #[must_use]
    pub const fn new(config: TlsConfig, addresses: Vec<String>) -> Self {
        Self { config, addresses }
    }
}

impl Connector for TlsConnector {
    type Stream = TlsStream;

    async fn connect(&self, conn: usize) -> io::Result<TlsStream> {
        let address = self
            .addresses
            .get(conn)
            .ok_or_else(|| io::Error::other(format!("no address for connection {conn}")))?;
        connect(address, &self.config).await
    }
}

/// Accepts TCP connections on `listener` and serves them over TLS.
///
/// Runs each one's TLS handshake in a
/// task of its own (a slow peer holds up no other), and attaches each
/// authenticated stream to a free member of the driver behind `handle`, as
/// [`iec104_tokio::outstation::serve`] does for plain TCP. A connection that
/// finds every member taken is closed.
///
/// Every failed handshake (an untrusted or revoked certificate, a peer not
/// on the allow-list, no common version or suite, a timeout) is passed to
/// `refused` with the peer's address, and the connection is dropped. What to
/// log is the application's call ([`crate::tls_error`] gives the TLS error).
///
/// At most [`MAX_HANDSHAKES`] handshakes run at once, and at most
/// [`MAX_HANDSHAKES_PER_ADDRESS`] of one peer address. An accept error never
/// ends the loop: one connection's failure is skipped, and a shortage of
/// descriptors or memory is waited out, so peers that cannot authenticate
/// cannot stop the outstation. Returns when the driver has stopped (noticed at
/// the next attach).
///
/// # Errors
///
/// None: every accept error is handled inside the loop, so it only ever
/// returns `Ok`.
pub async fn serve(
    listener: TcpListener,
    config: TlsConfig,
    handle: Handle,
    refused: impl Fn(SocketAddr, io::Error) + Send + Sync + 'static,
) -> io::Result<()> {
    let handle_for_route = handle.clone();
    serve_inner(
        listener,
        config,
        move |_, _| Some(handle_for_route.clone()),
        refused,
        true,
    )
    .await
}

/// Accepts TLS connections on `listener`, each to the driver `route` picks.
///
/// Hands each authenticated stream
/// to the driver `route` picks for its peer address and certificate chain
/// (leaf first): one driver, and so one redundancy group, per master (clause
/// 10.2 rule 7). Routing on the certificate lets the application tie a
/// master's identity, not only its address, to its process image. A
/// connection `route` refuses (`None`) is closed; failed handshakes go to
/// `refused` as in [`serve`], and accept errors are handled as there. Runs
/// until its task is dropped.
///
/// # Errors
///
/// None: every accept error is handled inside the loop, so it only ever
/// returns `Ok`.
pub async fn serve_routed(
    listener: TcpListener,
    config: TlsConfig,
    route: impl Fn(SocketAddr, &[CertificateDer<'static>]) -> Option<Handle> + Send + Sync + 'static,
    refused: impl Fn(SocketAddr, io::Error) + Send + Sync + 'static,
) -> io::Result<()> {
    serve_inner(listener, config, route, refused, false).await
}

/// How many TLS handshakes an accept loop runs at once. Each lasts at most
/// the configured handshake timeout; further connections wait in the
/// listen backlog.
pub const MAX_HANDSHAKES: usize = 64;

/// How many of those handshakes one peer IP address may hold.
///
/// A connection beyond it is closed at once and passed to `refused`, so one host that opens
/// connections and stays silent cannot hold every slot and lock the master out.
/// Peers with many addresses can still fill [`MAX_HANDSHAKES`].
pub const MAX_HANDSHAKES_PER_ADDRESS: usize = 4;

/// One handshake slot of a peer address, given back when dropped.
struct AddressSlot {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    address: IpAddr,
}

impl AddressSlot {
    fn take(counts: &Arc<Mutex<HashMap<IpAddr, usize>>>, address: IpAddr) -> Option<Self> {
        let mut map = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = map.entry(address).or_default();
        let free = *count < MAX_HANDSHAKES_PER_ADDRESS;
        if free {
            *count = count.saturating_add(1);
        }
        drop(map);
        free.then(|| Self {
            counts: counts.clone(),
            address,
        })
    }
}

impl Drop for AddressSlot {
    fn drop(&mut self) {
        let mut map = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = map.get_mut(&self.address) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.address);
            }
        }
    }
}

/// The pause after an accept error that is not one connection's own (out of
/// file descriptors, say), before accepting again.
const ACCEPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(100);

fn is_connection_error(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
    )
}

async fn serve_inner(
    listener: TcpListener,
    config: TlsConfig,
    route: impl Fn(SocketAddr, &[CertificateDer<'static>]) -> Option<Handle> + Send + Sync + 'static,
    refused: impl Fn(SocketAddr, io::Error) + Send + Sync + 'static,
    stop_with_driver: bool,
) -> io::Result<()> {
    let route = Arc::new(route);
    let refused = Arc::new(refused);
    let stopped = Arc::new(::tokio::sync::Notify::new());
    let handshakes = Arc::new(::tokio::sync::Semaphore::new(MAX_HANDSHAKES));
    let per_address = Arc::new(Mutex::new(HashMap::new()));
    loop {
        // At most MAX_HANDSHAKES unauthenticated peers at a time: the rest
        // wait in the listen backlog.
        let permit = ::tokio::select! {
            // The semaphore is never closed; were it, there would be no
            // handshake slot left, so the loop ends as on a stop.
            permit = handshakes.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => return Ok(()),
            },
            () = stopped.notified() => return Ok(()),
        };
        let accepted = ::tokio::select! {
            accepted = listener.accept() => accepted,
            () = stopped.notified() => return Ok(()),
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            // One connection's failure (reset before it was accepted) is
            // nothing to the listener.
            Err(e) if is_connection_error(&e) => continue,
            // Out of descriptors, buffers or memory: pause, then accept again.
            // Returning would let any peer that can open connections stop the
            // outstation.
            Err(_) => {
                ::tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let Some(slot) = AddressSlot::take(&per_address, peer.ip()) else {
            refused(
                peer,
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "too many TLS handshakes from this address",
                ),
            );
            continue;
        };
        let (config, route, refused, stopped) = (
            config.clone(),
            route.clone(),
            refused.clone(),
            stopped.clone(),
        );
        ::tokio::spawn(async move {
            let handshake = accept(tcp, &config).await;
            drop((permit, slot));
            let stream = match handshake {
                Ok(stream) => stream,
                Err(e) => return refused(peer, e),
            };
            let certs = stream.peer_certificates().unwrap_or_default().to_vec();
            let Some(handle) = route(peer, &certs) else {
                return;
            };
            match handle.attach(None, stream).await {
                Err(iec104_tokio::Error::Stopped) if stop_with_driver => stopped.notify_one(),
                _ => {}
            }
        });
    }
}
