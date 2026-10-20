# lib60870-C test peers

Two small C programs, written for this crate's interop tests, built against
[lib60870-C](https://github.com/mz-automation/lib60870) (GPLv3). They run as
separate processes over TCP; no lib60870 code is part of this crate.

- `full_server.c`: an outstation serving interrogation, counter
  interrogation, read, clock sync, commands, parameters, the test command, a
  file (IOA 30000, two 400-octet sections) and one redundancy group.
- `full_client.c`: a master that sends one of each request to an
  outstation and prints every ASDU it gets back.

Build them with `scripts/interop-setup.sh`, which clones lib60870 at the
checked commit (`7a388e3e133999e1ca77ba7521d55d074b7cd2bc`) and puts the peers
in `target/interop/bin/`. The suites find them there. Then run:

```sh
cargo test --test lib60870 -- --ignored --test-threads=1                   # the core
cargo test -p iec104-tokio --test lib60870 -- --ignored --test-threads=1   # the async drivers
cargo test -p iec104-tls --test lib60870 -- --ignored --test-threads=1     # over TLS
```

or `scripts/interop.sh` for every interop suite at once. To use peers built
elsewhere, set `IEC104_LIB60870_SERVER` and `IEC104_LIB60870_CLIENT` to their
paths.
