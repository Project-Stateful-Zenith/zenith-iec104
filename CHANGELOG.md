# Changelog

All notable changes to the three crates (`iec104`, `iec104-tokio` and
`iec104-tls`, which share one version) are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.36.0] - 2026-10-21

### Added

- `iec104-tokio`'s `Server` receives uploaded files: with
  `ServerConfig::accept_uploads`, a file the controlling station offers with
  a file ready is called and acknowledged through `ft::receive`, and handed
  to the new `Application::received_file` once its checksums add up.
  Without it nothing changes: the cause 44 mirror (#69).

## [0.35.0] - 2026-10-21

### Added

- `iec104-tokio`'s `Server` serves files: `ServerConfig::file` declares one
  at an address, the directory lists the declared files, and select and
  call file transfer them through `ft::provide`. A request for an address
  without a file gets the cause 47 mirror, one for another name a negative
  file ready. Without declared files nothing changes: the cause 44 mirror
  (#66).
- `ServerError::FileTooLong` for a declared file longer than `LOF` can
  state; a file at address 0 is `ServerError::IrrelevantAddress` (#66).
- `ft::provide`: the providing side of a file transfer as a session.
  `Provider` holds one file and answers select file, call file and call
  section with its sections, segments and checksums, sends a section again
  after a negative acknowledgement, and opens the control direction with
  `announce`. `directory` builds the `F_DR_TA_1` frames that answer a call
  directory, split by what an ASDU holds, with `LFD` on the last file
  (#65).

### Changed

- `ft::receive::Receiver` takes a file ready before `start`: the
  controlling station's offer that opens the control direction (#65).
- `ft::receive::Failure` has two more variants for the providing side,
  `Deactivated` and `FileRejected`. A `match` on it needs arms for them
  (#65).

## [0.34.0] - 2026-10-21

### Added

- An interop test runs `ft::receive::Receiver` against lib60870's file
  server (#63).

### Changed

- `ft::receive::DirectoryCall` completes with `DirectoryFile`s: each entry
  with the information object address of its file, which a `Receiver` for
  that file needs. It completed with bare `DirectoryEntry`s, which dropped
  the address (#63).

## [0.33.0] - 2026-10-21

### Added

- `ft::receive`: the receiving side of a file transfer as a session.
  `Receiver` runs one file from select file to the file acknowledgement,
  checks each section's and the file's checksum, and asks for a section
  again when its checksum does not add up. `DirectoryCall` collects a
  directory over as many `F_DR_TA_1` ASDUs as it takes. Both stay sans-IO
  (#61).

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

[Unreleased]: https://github.com/Project-Stateful-Zenith/zenith-iec104/compare/v0.36.0...HEAD
[0.36.0]: https://github.com/Project-Stateful-Zenith/zenith-iec104/compare/v0.35.0...v0.36.0
[0.35.0]: https://github.com/Project-Stateful-Zenith/zenith-iec104/compare/v0.34.0...v0.35.0
[0.34.0]: https://github.com/Project-Stateful-Zenith/zenith-iec104/compare/v0.33.0...v0.34.0
[0.33.0]: https://github.com/Project-Stateful-Zenith/zenith-iec104/compare/v0.32.1...v0.33.0
[0.32.1]: https://github.com/Project-Stateful-Zenith/zenith-iec104/releases/tag/v0.32.1
