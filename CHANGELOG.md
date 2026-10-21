# Changelog

All notable changes to the three crates (`iec104`, `iec104-tokio` and
`iec104-tls`, which share one version) are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `ft::receive`: the receiving side of a file transfer as a session.
  `Receiver` runs one file from select file to the file acknowledgement,
  checks each section's and the file's checksum, and asks for a section
  again when its checksum does not add up. `DirectoryCall` collects a
  directory over as many `F_DR_TA_1` ASDUs as it takes. Both stay sans-IO.

### Changed

- `iec104-tls` no longer depends on `iec104` for its blocking API. With the
  `tokio` feature, `iec104` still comes in through `iec104-tokio` (#59).

### Fixed

- Three conformance tests no longer wait one second per request for an
  answer that never comes. They now check what the test station sent, which
  takes `cargo test --workspace --all-features` from about 48 s to about
  20 s (#60).
- On Windows, a blocking `iec104-tls` write or flush that ran into the
  socket's write timeout could corrupt the TLS session: the timed-out send
  may already have sent part of its data, and that part went out again. The
  peer then failed with `DecryptError`, and the socket could fail later reads
  with os error 10060. Sends under a write timeout now run non-blocking under
  the stream's own deadline and never time out partway.
- Conformance and `iec104-tls` tests that failed on Windows because the
  loopback buffers more than they assumed, or because a close with unread
  data resets the connection, now pass there.

## [0.32.1] - 2026-10-20

The first tagged release of the public repository.

### Added

- CI runs `cargo fmt`, clippy, rustdoc and the full test suite on stable and
  on the 1.88 MSRV.

### Fixed

- `iec104-tokio` passes clippy 1.99 with the `log` and `tracing` features
  off.

[Unreleased]: https://github.com/Project-Stateful-Zenith/zenith-iec104/compare/v0.32.1...HEAD
[0.32.1]: https://github.com/Project-Stateful-Zenith/zenith-iec104/releases/tag/v0.32.1
