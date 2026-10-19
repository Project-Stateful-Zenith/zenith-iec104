#!/usr/bin/env python3
"""A c104 controlling station (master) for the outstation interop tests.

`c104` is iec104-python (Fraunhofer FIT), GPLv3, wrapping lib60870-C. As with
`peer.py`, the peer is **run as an external process and nothing else**: this
script only drives c104's public API, and nothing of it enters the crate.

It connects to an outstation, starts data transfer, and sends one of each
request c104's client offers, waiting for each answer: a station
interrogation, a counter interrogation, a read, a single command (direct), a
test command and a clock synchronisation. Then it closes the connection.

The protocol on stdout, one flushed line each:

    VERSION <c104 version> python <version>   once, first
    RX <hex>                                  one APDU this peer received
    TX <hex>                                  one APDU this peer sent
    RESULT <request> <True|False>             c104's verdict on one request
    VALUE read <value>                        the value the read brought back
    DONE                                      the scenario is over

Exit code 0 means the scenario ran (whatever the verdicts); anything else is a
failure the harness reports with stderr.

Usage: client.py --port <n> [--ip 127.0.0.1] [--common-address 1]
"""

import argparse
import importlib.metadata
import sys
import threading
import time

import c104

# The objects the outstation under test serves (tests/station/mod.rs, and
# iec104-tokio/tests/station/mod.rs for the async one).
IOA_READ = 0x0102  # M_ME_NB_1, answered to a read
IOA_COMMAND = 0x0500  # C_SC_NA_1, executed directly


PRINT_LOCK = threading.Lock()


def emit(line: str) -> None:
    """One protocol line, flushed; c104's callbacks run on its own thread."""
    with PRINT_LOCK:
        print(line, flush=True)


def raw(direction: str):
    """An `on_receive_raw` / `on_send_raw` callback; c104 checks the
    parameter names and annotations."""
    def callback(connection: c104.Connection, data: bytes) -> None:
        emit(f"{direction} {bytes(data).hex()}")
    return callback


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--common-address", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    emit(f"VERSION c104 {importlib.metadata.version('c104')} python {sys.version.split()[0]}")

    client = c104.Client(tick_rate_ms=50, command_timeout_ms=3000)
    # Init.NONE: the requests are this script's, one at a time, not c104's
    # automatic ones on connect.
    connection = client.add_connection(ip=args.ip, port=args.port, init=c104.Init.NONE)
    if connection is None:
        print("ERROR add_connection returned None", file=sys.stderr, flush=True)
        return 3
    connection.on_receive_raw(raw("RX"))
    connection.on_send_raw(raw("TX"))

    station = connection.add_station(common_address=args.common_address)
    measured = station.add_point(io_address=IOA_READ, type=c104.Type.M_ME_NB_1)
    command = station.add_point(io_address=IOA_COMMAND, type=c104.Type.C_SC_NA_1)
    if measured is None or command is None:
        print("ERROR add_point returned None", file=sys.stderr, flush=True)
        return 3

    client.start()
    deadline = time.monotonic() + args.timeout
    open_states = (c104.ConnectionState.OPEN, c104.ConnectionState.OPEN_MUTED)
    while connection.state not in open_states:
        if time.monotonic() > deadline:
            print(f"ERROR never connected: {connection.state}", file=sys.stderr, flush=True)
            return 4
        time.sleep(0.05)
    # c104 sends STARTDT act on its own (clause 5.3); a muted connection is
    # asked to.
    if connection.state == c104.ConnectionState.OPEN_MUTED:
        connection.unmute()
    while connection.state != c104.ConnectionState.OPEN:
        if time.monotonic() > deadline:
            print(f"ERROR never started: {connection.state}", file=sys.stderr, flush=True)
            return 4
        time.sleep(0.05)
    emit("RESULT startdt True")

    ca = args.common_address
    emit(f"RESULT interrogation {connection.interrogation(common_address=ca)}")
    emit(f"RESULT counter_interrogation {connection.counter_interrogation(common_address=ca)}")
    emit(f"RESULT read {measured.read()}")
    command.value = True
    emit(f"RESULT single_command {command.transmit(cause=c104.Cot.ACTIVATION)}")
    emit(f"RESULT test {connection.test(common_address=ca, with_time=True)}")
    emit(f"RESULT clock_sync {connection.clock_sync(common_address=ca)}")
    emit(f"VALUE read {measured.value}")

    client.stop()
    emit("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
