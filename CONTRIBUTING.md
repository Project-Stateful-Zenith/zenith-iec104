# Contributing

Issues and pull requests are welcome. For a security problem, don't open an
issue: see [SECURITY.md](SECURITY.md).

## Before you open a pull request

Run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets
cargo clippy --workspace --all-targets --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
cargo test --workspace --all-features
```

CI pins clippy to Rust 1.99.0 (`.github/workflows/ci.yml`). The workspace
denies `clippy::pedantic` and `clippy::nursery`, and nursery lints change
from one release to the next, so a newer clippy can report errors that CI
does not. Use `cargo +1.99.0 clippy …` to see exactly what CI sees. Moving
the pin to a newer release is its own pull request, which fixes whatever the
new clippy finds.

The crates build on Rust 1.88 (the MSRV), and CI runs the tests on 1.88 as
well as on stable.

## The lint policy

Library code may not `unwrap`, `expect`, `panic`, index, slice strings,
convert with `as` or do unchecked arithmetic; `Cargo.toml` lists every lint
the workspace denies. Test code may unwrap, expect, panic and index
(`clippy.toml`). If a lint is wrong for one line, allow it on that line with
a comment saying why, rather than for a whole module.

## Tests

- A change to protocol behaviour comes with a test, and the test or the code
  cites the clause, table or figure of the standard it comes from (for
  example `104 cl.5.2` or `604 Table 11`).
- Describe what a standard requires in your own words. Don't copy its text
  into the repository: the IEC standards are copyrighted. Titles, column
  headers and value names may be quoted as labels.
- Tests must not wait on wall-clock time to show that something does not
  happen. Check what the code under test recorded, or use paused time.
- The interop suites against lib60870-C and c104 are ignored by default.
  `scripts/interop.sh` builds the peers and runs them; it needs git, make,
  gcc, curl, tar, sha256sum and python3. `scripts/stress.sh` runs one test
  binary many times at once to bring out races.

## Generated code

`src/asdu/layout/control.rs` and `src/asdu/layout/monitor.rs` are generated.
Change `gen/control.py` or `gen/monitor.py`, then regenerate:

```sh
python3 gen/control.py > src/asdu/layout/control.rs && cargo fmt
python3 gen/monitor.py > src/asdu/layout/monitor.rs && cargo fmt
```

Regenerating an unchanged generator must leave the file byte for byte the
same.

## Commits

One change per commit. The subject line names the area and says what
changed, for example `ct: report the P/N bit of a DEACTCON in
Reaction::Deactivated`. Add `(#N)` when it closes issue N. Put the reason in
the commit body when the diff doesn't make it obvious. Add user-visible
changes to `CHANGELOG.md` under `Unreleased`.

By contributing you agree that your contribution is licensed under
Apache-2.0, as the rest of the project is.
