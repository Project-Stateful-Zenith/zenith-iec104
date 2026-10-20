# Changelog

All notable changes to the three crates (`iec104`, `iec104-tokio` and
`iec104-tls`, which share one version) are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the versions
follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- `iec104-tls` no longer depends on `iec104` for its blocking API. With the
  `tokio` feature, `iec104` still comes in through `iec104-tokio` (#59).

### Fixed

- Three conformance tests no longer wait one second per request for an
  answer that never comes. They now check what the test station sent, which
  takes `cargo test --workspace --all-features` from about 48 s to about
  20 s (#60).

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
