# zenith-iec104

IEC 60870-5-104 for Rust, for both the controlling and the controlled station.

| Crate | Use |
| --- | --- |
| `iec104` | sans-IO protocol core, no dependencies |
| `iec104-tokio` | async drivers, a `Client` and a `Server` on Tokio |
| `iec104-tls` | IEC 104 over mutual TLS, blocking and async |

## Install

```toml
[dependencies]
iec104 = { git = "https://github.com/Project-Stateful-Zenith/zenith-iec104", branch = "main" }
iec104-tokio = { git = "https://github.com/Project-Stateful-Zenith/zenith-iec104", branch = "main" }
```

Requires Rust 1.88 or later.

## Quick start

```sh
cargo run --example outstation -- 127.0.0.1:2404
cargo run --example master -- 127.0.0.1:2404 30
```

## Documentation

```sh
cargo doc --no-deps --all-features --open
```

## License

Apache-2.0. See [LICENSE](LICENSE).
