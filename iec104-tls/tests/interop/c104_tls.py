#!/usr/bin/env python3
"""A c104 peer over TLS, for the iec104-tls interop tests (tests/c104.rs).

`c104` is iec104-python (Fraunhofer FIT), GPLv3, wrapping lib60870-C with
mbedTLS. The peer is **run as an external process and nothing else**: this
script only drives c104's public API (`c104.TransportSecurity`), and nothing
of it enters the crate.

Two modes:

- `server`: a controlled station on --port with one measured value,
  `M_ME_NB_1` 4242 at IOA 0x1001, which a station interrogation returns.
- `client`: a controlling station that connects to --port, starts data
  transfer and runs one station interrogation.

TLS: this end's --cert/--key, the --ca that must have signed the peer, and
optionally --allow (only that peer certificate is accepted), --no-validate
(no chain validation), --tls (1.2 or 1.3, both min and max), --renegotiate
(seconds between TLS 1.2 renegotiations; c104 accepts 5 minutes to 1 day).

c104 2.2.1's client cannot validate a server's chain at all: its mbedTLS
(3.6.3 or later) refuses to verify a certificate when no hostname was set
("Certificate verification without having set hostname", -0x5D80), and c104
sets none. The interop tests (tests/c104.rs) therefore run only the server
mode.

The protocol on stdout, one flushed line each:

    VERSION <c104 version> python <version>   once, first
    READY                                     server: the listener is up
    CONNECT <ip>                              server: a client connected (TCP)
    RX <hex> / TX <hex>                       one APDU received / sent
    STATE <c104 connection state>             client: every state change
    RESULT <request> <True|False>             client: c104's verdict
    DONE                                      the scenario is over

Exit code 0: the scenario ran. 4: the client never reached OPEN (a refused
handshake, typically). Anything else is a failure reported on stderr.
"""

import argparse
import datetime
import importlib.metadata
import signal
import sys
import threading
import time

try:
    import c104
except ImportError as error:  # reported by the harness, not swallowed
    print(f"ERROR cannot import c104: {error}", file=sys.stderr, flush=True)
    raise SystemExit(3)

COMMON_ADDRESS = 1
IOA_GI = 0x1001
GI_VALUE = 4242

PRINT_LOCK = threading.Lock()


def emit(line: str) -> None:
    with PRINT_LOCK:
        print(line, flush=True)


def transport(args) -> c104.TransportSecurity:
    tls = c104.TransportSecurity(validate=not args.no_validate, only_known=args.allow is not None)
    tls.set_certificate(cert=args.cert, key=args.key)
    tls.set_ca_certificate(cert=args.ca)
    if args.allow is not None:
        tls.add_allowed_remote_certificate(cert=args.allow)
    if args.tls is not None:
        version = {"1.2": c104.TlsVersion.TLS_1_2, "1.3": c104.TlsVersion.TLS_1_3}[args.tls]
        tls.set_version(min=version, max=version)
    if args.renegotiate is not None:
        tls.set_renegotiation_time(interval=datetime.timedelta(seconds=args.renegotiate))
    return tls


def server(args) -> int:
    srv = c104.Server(ip="127.0.0.1", port=args.port, tick_rate_ms=50, max_connections=1,
                      transport_security=transport(args))
    srv.protocol_parameters.keep_alive_interval = 2
    station = srv.add_station(COMMON_ADDRESS)
    measured = station.add_point(io_address=IOA_GI, type=c104.Type.M_ME_NB_1)
    measured.value = c104.Int16(GI_VALUE)

    def connected(server: c104.Server, ip: str) -> bool:
        emit(f"CONNECT {ip}")
        return True

    def raw(direction: str):
        def callback(server: c104.Server, data: bytes) -> None:
            emit(f"{direction} {bytes(data).hex()}")
        return callback

    srv.on_connect(connected)
    srv.on_receive_raw(raw("RX"))
    srv.on_send_raw(raw("TX"))

    def shutdown(signum, frame):  # noqa: ARG001
        srv.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    srv.start()
    if not srv.is_running:
        print("ERROR the server did not start", file=sys.stderr, flush=True)
        return 3
    emit("READY")
    time.sleep(args.timeout)
    srv.stop()
    emit("DONE")
    return 0


def client(args) -> int:
    cl = c104.Client(tick_rate_ms=50, command_timeout_ms=3000, transport_security=transport(args))
    connection = cl.add_connection(ip="127.0.0.1", port=args.port, init=c104.Init.NONE)

    def raw(direction: str):
        def callback(connection: c104.Connection, data: bytes) -> None:
            emit(f"{direction} {bytes(data).hex()}")
        return callback

    def state(connection: c104.Connection, state: c104.ConnectionState) -> None:
        emit(f"STATE {state}")

    connection.on_receive_raw(raw("RX"))
    connection.on_send_raw(raw("TX"))
    connection.on_state_change(state)
    connection.add_station(common_address=COMMON_ADDRESS)
    cl.start()
    deadline = time.monotonic() + args.timeout
    while connection.state != c104.ConnectionState.OPEN:
        if connection.state == c104.ConnectionState.OPEN_MUTED:
            connection.unmute()
        if time.monotonic() > deadline:
            cl.stop()
            emit("DONE")
            print(f"ERROR never started: {connection.state}", file=sys.stderr, flush=True)
            return 4
        time.sleep(0.05)
    emit("RESULT startdt True")
    emit(f"RESULT interrogation {connection.interrogation(common_address=COMMON_ADDRESS)}")
    time.sleep(args.linger)
    emit(f"RESULT still_open {connection.state == c104.ConnectionState.OPEN}")
    cl.stop()
    emit("DONE")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["server", "client"])
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--allow")
    parser.add_argument("--no-validate", action="store_true",
                        help="skip chain validation (c104's validate=False); --allow still applies")
    parser.add_argument("--tls", choices=["1.2", "1.3"])
    parser.add_argument("--renegotiate", type=float)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--linger", type=float, default=0.0,
                        help="client: seconds to stay connected after the interrogation")
    args = parser.parse_args()
    emit(f"VERSION c104 {importlib.metadata.version('c104')} python {sys.version.split()[0]}")
    return server(args) if args.mode == "server" else client(args)


if __name__ == "__main__":
    raise SystemExit(main())
