# zenith-iec104

A Rust library for IEC 60870-5-104, the protocol SCADA control centres use to
talk to substations and other remote stations over TCP. It covers both ends:
the controlling station (master) and the controlled station (outstation).

| Crate | Use |
| --- | --- |
| `iec104` | the protocol core: APCI framing, sequence numbers and the k/w window, the t0 to t3 timers, ASDU encoding and decoding, and every application procedure |
| `iec104-tokio` | async drivers on Tokio, and a procedure-level `Client` and `Server` built on them |
| `iec104-tls` | IEC 104 over mutual TLS on rustls, blocking and async |

## How it is built

`iec104` is **sans-IO**. It opens no sockets, reads no clock, spawns no
threads and has no dependencies: you hand it the bytes you received and the
current time, and it returns the frames to send and the ASDUs for the
application. That keeps it testable byte for byte and usable from any
transport. `iec104-tokio` and `iec104-tls` are such transports.

What the protocol covers:

- **Link layer**: I, S and U frames, STARTDT/STOPDT, TESTFR, the k and w
  window and the t0 to t3 timers of 104 clause 5, for one connection or a
  redundancy group of several (clause 10), with switchover and replay of
  unconfirmed data.
- **ASDUs**: every type of 101 clause 7.3 and 104 clause 8, with time tags,
  1 to 3 octet object addresses and 1 or 2 octet common addresses.
- **Procedures**: station initialisation, general and counter
  interrogation, clock synchronisation, direct and select-before-operate
  commands (with time tags), read, parameter loading, the test command,
  cyclic, background and spontaneous transmission, and file transfer.
- **Client and server**: the controlling station's procedures as async
  calls with a process image, and an outstation that answers from its own
  process image in the priority order of 101 Table 16.

## Example

```rust
use std::time::SystemTime;

use iec104::asdu::Cp56Time2a;
use iec104::gi::Scope;
use iec104_tokio::TcpConnector;
use iec104_tokio::client::{Client, ClientConfig, Update};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Station at 192.0.2.10, common address 1, port 2404.
    let connector = TcpConnector::new(vec!["192.0.2.10:2404".into()]);
    let client = Client::connect(connector, ClientConfig::new(1)).await?;
    let mut updates = client.subscribe().await?;

    // Everything the station holds, then its clock.
    for asdu in client.interrogate(Scope::Station).await? {
        println!("{:?}", asdu.objects);
    }
    client
        .sync_clock(Cp56Time2a::from_system_time(SystemTime::now())?)
        .await?;

    // What the station sends from now on.
    while let Some(update) = updates.recv().await {
        if let Update::Data(asdu) = update {
            println!("{} {:?}", asdu.header.cause.mnemonic(), asdu.objects);
        }
    }
    Ok(())
}
```

## Command-line examples

```sh
# A blocking outstation, and a master that interrogates it and logs what it sends
cargo run --example outstation -- 127.0.0.1:2404
cargo run --example master -- 127.0.0.1:2404 30

# One station interrogation, or one direct command, then exit
cargo run --example interrogation -- 127.0.0.1:2404
cargo run --example command -- 127.0.0.1:2404 4001 on

# The procedure-level server and client on Tokio
cargo run -p iec104-tokio --example server -- 127.0.0.1:2404
cargo run -p iec104-tokio --example client -- 127.0.0.1:2404 4001 on
```

## Build

```sh
cargo build --workspace
cargo test --workspace --all-features
```

Rust 1.88 or newer. The tests run against values taken from the standards
and in-process peers; no hardware is needed. Interop suites against
[lib60870-C](https://github.com/mz-automation/lib60870) and
[c104](https://github.com/Fraunhofer-FIT-DIEN/iec104-python) are ignored by
default; `scripts/interop.sh` builds the peers and runs them.

## Disclaimer

> [!WARNING]
> This project is an independent implementation of IEC 60870-5-104, written
> from the published standards. No text of the standards and no code of
> other implementations is contained in this repository; the interop peers
> run as separate processes.
>
> This project is not affiliated with, endorsed by or supported by the IEC.
> `iec104-tls` follows the IEC 62351-3 profile as secondary sources describe
> it and claims no conformance to IEC 62351.
>
> The software is provided "as is", without warranty of any kind. Use it at
> your own risk, especially when sending commands to equipment.

## License

Apache-2.0, see [LICENSE](LICENSE).
Copyright 2026 Project-Stateful-Zenith Contributors.
