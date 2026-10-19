#!/usr/bin/env python3
"""The real peer for the interop scenario: an IEC 60870-5-104 outstation run
under `c104`.

`c104` is iec104-python (Fraunhofer FIT), GPLv3; it wraps lib60870-C. The
licence boundary of this crate is a hard one: the peer is **run as an external
process and nothing else**. Nothing here is copied into the repository, and no
code, table or vector of this file's dependency is taken from its source. This
script only *drives* its public API; the octets it puts on the wire are wire
traffic and may be quoted as byte vectors.

It is the controlled station of the scripted scenario in
`tests/interop/mod.rs`: the controlling station (our crate) connects, STARTDTs,
interrogates, receives one spontaneous event, sends one accepted and one refused
single command, answers/asks the test procedure, and closes the socket cleanly.

The protocol on stdout is the harness's readiness-and-capture channel:

    VERSION <c104 version> python <version>   once, first
    READY                                     the listener is up
    RX <hex>                                  one APDU this peer received
    TX <hex>                                  one APDU this peer sent
    NOTE <c104 explain_bytes text>            the human-readable form of the last APDU
    CONNECT <ip>                              the client connected
    STATE OPEN|CLOSED <name>                  a connection state change
    DONE rx=<n> tx=<n>                        the connection is over; the peer exits

Every line is flushed, because the harness reads them as they appear and waits
for READY with a deadline. Exit code 0 means the scenario ran; any other code is
a failure the harness reports with this script's stderr.

Usage: peer.py --port <n> [--ip 127.0.0.1] [--common-address 1]
"""

import argparse
import importlib.metadata
import os
import signal
import sys
import threading
import time

try:
    import c104
except ImportError as error:  # reported by the harness, not swallowed
    print(f"ERROR cannot import c104: {error}", file=sys.stderr, flush=True)
    raise SystemExit(3)

# The scenario's addressing, mirrored from tests/interop/mod.rs. These are the
# peer's *configuration*, agreed with the harness, not protocol constants.
COMMON_ADDRESS = 1
IOA_GI = 0x1001  # M_ME_NB_1, the interrogated measured value
GI_VALUE = 4242
IOA_SPONT = 0x1002  # M_SP_NA_1, reported with cause <3>
IOA_COMMAND = 0x2001  # C_SC_NA_1, accepted
IOA_REFUSED = 0x2002  # C_SC_NA_1, refused with P/N = 1

PRINT_LOCK = threading.Lock()
COUNTS = {"RX": 0, "TX": 0}


def emit(line: str) -> None:
    """One protocol line, flushed so the harness sees it immediately."""
    with PRINT_LOCK:
        print(line, flush=True)


def raw(callable_name: str, direction: str):
    """Wraps an `on_receive_raw` / `on_send_raw` callback into the log."""
    def callback(server: c104.Server, data: bytes) -> None:
        COUNTS[direction] += 1
        emit(f"{direction} {bytes(data).hex()}")
        try:
            emit(f"NOTE {c104.explain_bytes(bytes(data))}")
        except Exception:  # noqa: BLE001 - explain_bytes is diagnostics only
            pass
    callback.__name__ = callable_name
    return callback


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--common-address", type=int, default=COMMON_ADDRESS)
    parser.add_argument("--timeout", type=float, default=120.0,
                        help="hard deadline for the whole scenario, in seconds")
    args = parser.parse_args()

    version = importlib.metadata.version("c104")
    emit(f"VERSION c104 {version} python {sys.version.split()[0]}")

    server = c104.Server(ip=args.ip, port=args.port, tick_rate_ms=50, max_connections=1)
    # t3 of clause 5.2, in seconds: short, so the peer really does ask its own
    # test question within the scenario instead of after it.
    server.protocol_parameters.keep_alive_interval = 2

    station = server.add_station(args.common_address)
    if station is None:
        print("ERROR add_station returned None", file=sys.stderr, flush=True)
        return 3

    # The measured value the general interrogation answers with (cl.7.5).
    # Assigning it only sets the process image the interrogation reads.
    measured = station.add_point(io_address=IOA_GI, type=c104.Type.M_ME_NB_1)
    if measured is None:
        print("ERROR add_point(M_ME_NB_1) returned None", file=sys.stderr, flush=True)
        return 3
    measured.value = c104.Int16(GI_VALUE)

    # The spontaneous event (cl.7.4, cause <3>). The timer fires every 1.5 s;
    # `report_once` sends the event once and does nothing after that.
    spont = station.add_point(io_address=IOA_SPONT, type=c104.Type.M_SP_NA_1)
    if spont is None:
        print("ERROR add_point(M_SP_NA_1) returned None", file=sys.stderr, flush=True)
        return 3
    spont.value = False
    reported = threading.Event()

    def report_once(point: c104.Point) -> None:
        if reported.is_set():
            return
        point.value = True
        # cl.7.4: the station's own event, reported with cause <3>. The peer's
        # public API sends it explicitly; assigning the value alone only
        # updates the process image. `transmit` returns False while the
        # connection cannot carry user data (no STARTDT yet, window full), so
        # the one-shot only counts as spent once it really went out. Otherwise
        # the event would be dropped on a slow box and the scenario would fail
        # with "cl.7.4: no spontaneous ASDU arrived".
        if point.transmit(c104.Cot.SPONTANEOUS):
            reported.set()

    spont.on_timer(report_once, 1500)

    # The accepted single command (cl.7.7).
    command = station.add_point(
        io_address=IOA_COMMAND,
        type=c104.Type.C_SC_NA_1,
        command_mode=c104.CommandMode.DIRECT,
    )
    if command is None:
        print("ERROR add_point(C_SC_NA_1 accepted) returned None", file=sys.stderr, flush=True)
        return 3

    # The refused one: this point's process image answers FAILURE, which is
    # 5.4.19.30's negative ACTCON: the only way the mirror's P/N bit is
    # exercised against a real peer.
    refused = station.add_point(
        io_address=IOA_REFUSED,
        type=c104.Type.C_SC_NA_1,
        command_mode=c104.CommandMode.DIRECT,
    )
    if refused is None:
        print("ERROR add_point(C_SC_NA_1 refused) returned None", file=sys.stderr, flush=True)
        return 3

    def refuse(point: c104.Point, previous_info: c104.Information, message: c104.IncomingMessage) -> c104.ResponseState:
        return c104.ResponseState.FAILURE

    refused.on_receive(refuse)

    def connected(server: c104.Server, ip: str) -> bool:
        emit(f"CONNECT {ip}")
        return True

    server.on_connect(connected)
    server.on_receive_raw(raw("on_receive_raw", "RX"))
    server.on_send_raw(raw("on_send_raw", "TX"))

    def shutdown(signum, frame):  # noqa: ARG001
        emit(f"STATE CLOSED signal {signum}")
        server.stop()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    server.start()
    if not server.is_running:
        print("ERROR the server did not start", file=sys.stderr, flush=True)
        return 3
    emit("READY")

    # The scenario ends when the client closes the socket; the peer reports the
    # state change and then leaves. Bounded by --timeout so a peer the harness
    # forgets to talk to still exits.
    deadline = time.monotonic() + args.timeout
    saw_open = False
    while time.monotonic() < deadline:
        open_now = server.open_connection_count + server.active_connection_count
        if open_now > 0 and not saw_open:
            saw_open = True
            emit("STATE OPEN")
        elif saw_open and open_now == 0:
            emit("STATE CLOSED")
            break
        time.sleep(0.05)

    counted_rx = COUNTS["RX"]
    counted_tx = COUNTS["TX"]
    emit(f"DONE rx={counted_rx} tx={counted_tx}")
    server.stop()
    return 0


if __name__ == "__main__":
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    raise SystemExit(main())