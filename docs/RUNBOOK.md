# Runbook: driving the crate and reading its diagnostics

The core crate (`iec104`) is a *library*: it holds no socket, no clock and no
thread, and it prints nothing. The `src/diag.rs` module turns the values a caller already
holds into one line and hands it back as a `String`, with no sink. Everything below
is a line `diag` prints and a name the crate already defines; nothing here is
a second copy of a table.

The tests that pin these lines are `tests/diag.rs`, and the test
`the_runbook_quotes_the_line_the_formatter_prints_for_a_real_peer_frame` reads
this file back, so a line quoted here that the formatter no longer prints fails
the suite.

## A log line, verbatim

The frame below is the committed real-peer capture in `tests/interop/mod.rs`
(a `c104` peer answering the interop scenario's first I-frame), octet for octet:

```
68 0e 00 00 02 00 64 01 07 00 01 00 00 00 00 14
```

`diag::apdu(&CAPTURE_PEER_ACT_CON, AddressSizes::CONVENTIONAL)` prints exactly:

```
I N(S)=0 N(R)=1 | C_IC_NA_1(100) SQ=0 N=1 cause=actcon(7) P/N=0 T=0 ORG=0 CA=1 | IOA=0
```

Read it left to right: the control field of 5-104 clause 5 (`I` format, figure
6's `N(S)` and `N(R)`), then the ASDU header (the type's name and number from
5-101 table 8, the VSQ (`SQ`, `N`), the cause of transmission with table 14's
mnemonic, the `P/N` and `T` flags, the originator and the common address), and
last the first information object address.

## The control field

`diag::control` takes a parsed `apci::Apci` and prints one of three shapes,
following the three formats of 5-104 clause 5, figures 6–8 (PDF page index 28,
printed 27):

| `Apci` | line |
| --- | --- |
| `I { ns, nr }` | `I N(S)=3 N(R)=7` |
| `S { nr }` | `S N(R)=7` |
| `U(function)` | `U STARTDT act` |

The six U-format names are figure 8's own labels, reached through
`diag::u_function` because no value in `src/apci.rs` carries them (the module
holds the six octet codes only, `UFunction::code`):

```
STARTDT act   STARTDT con   STOPDT act   STOPDT con   TESTFR act   TESTFR con
```

## The ASDU header

`diag::header(&header, sizes)` prints the fields of 5-101 clauses 7.2.1–7.2.4:

```
M_ME_NB_1(11) SQ=0 N=1 cause=spont(3) P/N=0 T=0 ORG=0 CA=1
<name>(<type>) SQ=<0|1> N=<count> cause=<mnemonic>(<n>) P/N=<0|1> T=<0|1> ORG=<org> CA=<ca>
```

- The name is `TypeId::name`, the catalogue of 5-101 tables 8–13 (index 31,
  printed 30). An unnamed range reads `reserved`, `private`, `routing (private)`
  or `not defined`.
- The cause is `Cause::mnemonic` beside `Cause::to_u8`'s folded number. A cause
  `Cause::mnemonic` has no mnemonic for prints its number alone: the reserved
  range (`cause=14` for `<14..19>`), the private range, and the four replies 44
  to 47 (`cause=44`). The numbered interrogation/counter families print table
  14's own `inro1`…`inro16` / `reqco1`…`reqco4` (`cause=inro1(21)`,
  `cause=reqco1(38)`); `tests/standard_conformance.rs` pins every row.
- `P/N` and `T` are figure 14's `P/N` and `T` bits (index 37, printed 36): `0` is
  clause 7.2.3's *"positive confirm"* / *"no test"*, `1` the negative confirm /
  test.
- `ORG` is the cause field's originator octet, present or absent per profile. A
  profile without it prints `ORG=-`. 5-104 clause 9.5 (index 98, printed 97)
  says *"Originator address is set to zero if not used"*, so printing `0` there
  would be indistinguishable from clause 7.2.3's real `<0> := default`.

## Addresses and the profile

Nothing on the wire says which address widths the two stations agreed, so a log
reader needs the profile beside the line. `diag::address_sizes` prints it, from
the four *"system-specific parameter"* rows of 5-104 clause 9.5 (index 98,
printed 97) and 5-101 clauses 7.2.3–7.2.5:

```
CA 2 octets, IOA 3 octets, originator present
```

That is `AddressSizes::CONVENTIONAL`: originator present, common address two
octets (5-101 cl.7.2.4, index 42, printed 41), information object address three
octets (cl.7.2.5, index 43, printed 42). The one value 104 clause 9.5 calls
fixed is the frame size: *"The maximum length of APDU for both directions is
253. It is a fixed system parameter."* That is `apci::MAX_LENGTH`.

`diag::information_object_address(objects, sizes)` reads the address at the head
of an object area at the profile's width with `asdu::read_ioa_with` and prints
`IOA=4097`. For an SQ = 1 sequence that is the base address, the only one on the
wire (5-101 clause 7.2.2.1). A buffer narrower than the profile is the codec's
own `AsduError::TooShort`, never a widened read.

## The timers

`diag::timers(&params)` prints one connection's parameters: 5-104 clause 9's
time-out table (index 114, printed 113) and its k/w row. `LinkParams::default`
is the table's *"Default value"* column:

```
t0=30 s t1=15 s t2=10 s t3=20 s k=12 w=8 port=2404
```

Clause 10.7, *State transition diagrams* (index 136, printed 135), asks for the
per-connection detail, and its sentence stands in the redundant-connection case
it is written for: *"It should be possible to set the values of the timers t0 to
t3 individually for each connection within a redundancy group."* So print the
line per connection, not once for a process.

The table scales t0–t2 in whole seconds, but a time-out is a `Duration` here, so
a sub-second part prints exactly (`t1=1.5 s`, `t2=0.5 s`) instead of being
rounded down to a `t2=0 s` that `LinkParams::validate` would refuse.

## Discarded ASDUs

`diag::discard(discard)` writes the three bullets of 5-101 clause 7.2.3's
communications error log (index 42, printed 41) from the value
`asdu::discard_reason` already returns:

```
discarded: type identification (cause 44)
discarded: cause of transmission (cause 45)
discarded: common address of ASDU (cause 46)
discarded: information object address (cause 47)
discarded: mirrored ASDU
```

The first four are `Discard::Unspecified`'s classes in the clause's table order,
each with the cause its own table pairs with the field. The fifth is
`Discard::Mirror`, the clause's *"mirrored ASDUs due to unknown numbers in the
control direction (type identifications 45 to 51)"*.

## Driving the crate, and where the line plugs in

The core does not open the socket for you. 5-104 clause 7.1 (index 54, printed
53) says who does: *"Connection establishment is performed by"*, in its first
bullet, *"the controlling station in case of a controlled station as a
partner"*. The shape of a caller is:

1. `link::Session::new(role)` (or `with_params`) per connection, with its
   `params::LinkParams`; `manager::ConnectionManager` holds several such
   stations at once if you have more than one (`manager::StationConfig`).
2. Your own `TcpStream`: feed the bytes through `framed::Decoder`, hand each
   APDU to `Session::on_frame` (control field) and the ASDU octets to whatever
   application layer owns the process image.
3. `diag::apdu(&frame, sizes)` on the raw frame is the log line. Call it
   before or beside `on_frame`, on the same octets, so the line can never
   describe a different frame than the one the session saw. It formats exactly
   one frame: hand it a buffer holding more and it returns
   `diag::Error::TrailingOctets` rather than dropping octets it never read.
4. `Session::on_timeout(Timer::…)` for the timers `timers::Timers` reports; a
   `Directive::Connect` from `manager::ConnectionManager::tick` is the ask for a
   dial, not a dial.

What the core crate deliberately leaves to the caller, and what this runbook
does not promise: the socket, the process image, the clock (`Instant` is always
passed in), the print sink, and the reconnect policy beyond t0.

`iec104-tokio` is such a caller, so with it most of that list is done for you.
Its drivers (`master::spawn`, `outstation::spawn`) own the sockets, the timers
and the loop above; `client::Client` runs the controlling station's procedures
and `client::ProcessImage` keeps the latest value of every point the station
sent; `server::Server` is a controlled station that answers from a process
image the application writes. With its `log` or `tracing` feature the driver
prints the lines of the next section itself.

## The Tokio driver's log lines

`iec104-tokio` writes the same lines itself when built with its `log` or
`tracing` feature (both off by default; the core stays without dependencies).
Every line has the target `iec104_tokio` and names its connection: a `log`
record's message starts with `conn=<n> `, a `tracing` event carries `conn` as
a field. APDUs are formatted with `diag::apdu` in the profile of
`Options::sizes`, which `client::ClientConfig::sizes` and
`server::ServerConfig::sizes` set for the client and the server; a frame it
cannot format prints the error and the octets in hex instead.

| Text | Level | When |
| --- | --- | --- |
| `sent: <diag::apdu line>` | debug | an APDU handed to the connection's writer |
| `received: <diag::apdu line>` | debug | an APDU read from the connection |
| `connecting` | debug | `Event::Connecting` |
| `connect failed: <error>` | warn | `Event::ConnectFailed` |
| `connected` | info | `Event::Connected` |
| `disconnected: <reason>` | info | `Event::Disconnected` |
| `state: <state>` | info | `Event::State` (the `link::State` name) |
| `frame refused: <error>` | warn | `Event::FrameRefused` |
| `switchover: <switchover>` | warn | `Event::Switchover`, on the failed connection |
| `started connection failed, <n> unconfirmed` | warn | `Event::StartedConnectionFailed` |

`Event::Asdu`, `Event::Acknowledged`, `Event::Sent` and `Event::Received` write
no line of their own: the frame behind each is already a `sent:` or `received:`
line, and those lines do not depend on `Options::trace`.

A controlling station dialing one station and starting data transfer (5-104
clause 5.3, figure 18) writes, level first:

```
DEBUG conn=0 connecting
INFO  conn=0 connected
DEBUG conn=0 sent: U STARTDT act
INFO  conn=0 state: PendingStarted
DEBUG conn=0 received: U STARTDT con
INFO  conn=0 state: Started
```

The `sent:` and `received:` texts are the control field lines above (figure 8's
`STARTDT act` and `STARTDT con`). `iec104-tokio/tests/log_lines.rs` and
`tracing_events.rs` capture this exchange through each crate and fail if this
block no longer quotes it.
