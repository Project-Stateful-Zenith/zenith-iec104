//! TS 60870-5-604:2016 §5.4, the conformance test procedures.
//!
//! 604 is the conformance **test specification** for IEC 60870-5-104: its §5.4
//! carries the test procedures a station is run through, each row in the shape
//! `No. / Test / Description / Reference / Required` (the `Required` column is
//! `M` for the mandatory rows, and the `Reference` column names the 101 or 104
//! clause the case comes from; each case cites that clause beside the 604
//! procedure number).
//!
//! # The document's real shape
//!
//! **17 tables, `5.4.10` … `5.4.26`, carrying 84 numbered procedures** (counted
//! per page with `PyMuPDF` on 2026-09-25; a search for `5.4.1` also matches
//! `5.4.10`, so count per table, not by prefix):
//!
//! | Table | Function | Procedure numbers | Index (printed) |
//! | --- | --- | --- | --- |
//! | 10 | Data unit identifier | `5.4.10.1`, `.5`, `.10` | 53–54 (52–53) |
//! | 11 | Information object address | `5.4.11.1` | 54 (53) |
//! | 12 | Station initialisation | `5.4.12.1` … `.40` | 55–57 (54–56) |
//! | 13 | Redundant link | `5.4.13.1` … `.30` | 58–60 (57–59) |
//! | 14 | Cyclic data transmission | `5.4.14.1`, `.10` | 61 (60) |
//! | 15 | Data acquisition through read | `5.4.15.1`, `.10` | 62 (61) |
//! | 16 | Acquisition of events | `5.4.16.1`, `.10` | 63 (62) |
//! | 17 | General interrogation | `5.4.17.1` … `.60` | 64–68 (63–67) |
//! | 18 | Clock synchronisation | `5.4.18.1` … `.20` | 69 (68) |
//! | 19 | Command transmission | `5.4.19.1` … `.90` | 70–78 (69–77) |
//! | 20 | Transmission of integrated totals | `5.4.20.1` … `.40` | 78–81 (77–80) |
//! | 21 | Parameter loading | `5.4.21.1` … `.20` | 82 (81) |
//! | 22 | Test procedure function | `5.4.22.1`, `.10` | 83 (82) |
//! | 23 | File transfer procedure | `5.4.23.1` … `.20` | 84–86 (83–85) |
//! | 24 | Additional conformance test procedures | `5.4.24.1` … `.30` | 87 (86) |
//! | 25 | **Negative** conformance test procedures | `5.4.25.1` … `.50` | 88 (87) |
//! | 26 | PIXIT related conformance test procedures | `5.4.26.1` … `.153` | 89 (88) |
//!
//! Every §5.4 page is `rot=0`, A4 portrait (`595x842`), and its rows come out as
//! clean text from a plain `pymupdf` `get_text()`: no page image and no OCR is
//! needed.
//!
//! Page indices here are **PDF page indices** (0-based). 604 is English-only
//! and single-text, so its indices are the printed page number plus one.
//!
//! # What these cases are, and what they are not
//!
//! A 604 case is a *second harness* over the crate's primitives, not new
//! protocol code: the DUT is this library, driven in the role the procedure
//! names.
//!
//! - A case that addresses the **controlling** station drives
//!   `interop::Station` (the interoperability harness's driver) against the
//!   mock's controlled side.
//! - A case that addresses the **controlled** station drives this library's
//!   controlled side (`link::Session` in `Role::Controlled` plus the
//!   application rule `asdu::unknown::mirror_reply`) against
//!   [`conformance604::Peer`], a mock controlling station.
//!
//! §5.1 (index 10, printed 9) makes the direction part of the test: the
//! reverse direction is tested with the same procedures, the roles of
//! controlling and controlled station swapped, except that COT 44-47 exist
//! only in the monitor direction, so only a controlled station may send them.
//! Every case's doc comment says which
//! role it drives and whether that exception applies.
//!
//! Twelve tables (12 and 15 to 25) end with a `COMPATIBILITY WITH OTHER TEST
//! CASES` row (e.g. `5.4.25.50`); Tables 10, 11, 13, 14 and 26 do not. Such a
//! row asserts that nothing in §5.3 broke, which in Rust is the whole suite,
//! not a new test, so it has no case here.
//!
//! # Running it
//!
//! ```text
//! cargo test --test conformance_604
//! ```
//!
//! The offline path has no waits beyond the bounded read deadlines: the mock
//! controlling station drives both sides step by step.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::string_slice
)]

#[path = "conformance604/mod.rs"]
mod conformance604;
