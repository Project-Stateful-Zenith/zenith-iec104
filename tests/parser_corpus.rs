//! The parser-hardening corpus.
//!
//! One corpus over every entry point the crate exposes to network octets: the
//! APCI codec, the stream framer, the ASDU header and body cursor (including the
//! sized `_with` forms for configurable address sizes), the per-type layout
//! decoders, the 41 element parsers, and the application modules' reception
//! entry points. Every case is a **seed** (a committed byte vector whose source
//! is named where it is defined) expanded deterministically in this file: every
//! prefix of every seed, every single-octet value at every position of the
//! smaller seeds, and one minimal frame per laid-out type built through
//! [`layout_for`] / [`element_len`]. Each case is *also* driven through the five
//! sized entry points under each of the **twelve** legal address profiles, and
//! the width sweep of
//! [`every_address_profile_round_trips_a_minimal_frame_of_every_type`] carries a
//! minimal frame of every laid-out type under every one of them, asserting the
//! decoded **values** and that every prefix below a frame's own geometry is a
//! typed error. Nothing large is committed, no binary blob is created, and no
//! fuzzing dependency is used: the corpus is a small generated list, and a
//! failure reproduces from the seed, the profile and the position.
//!
//! **What the corpus asserts.** Three things, over every case:
//!
//! 1. **No panic.** Every call runs under [`std::panic::catch_unwind`] with a
//!    recording panic hook, so a panic names the entry point and the seed
//!    instead of flooding stderr. The crate's contract is that every path out
//!    of the parser is a typed error (`ParseError`, `AsduError`, `LayoutError`,
//!    `FramingError`); a panic is a failure, full stop.
//! 2. **No unbounded allocation.** A counting [`GlobalAlloc`] on this test
//!    binary measures the octets a single case allocates, and a case may not
//!    allocate more than [`ALLOC_FACTOR`] times its own input length plus
//!    [`ALLOC_SLACK`] octets. The only reception allocation in `src/` sized by
//!    a value read off the wire, rather than by the input's own length, is
//!    `Vec::with_capacity(usize::from(header.count))` in
//!    `src/asdu/layout/mod.rs`, which the bound covers.
//! 3. **The clause's bounds.** The invariants of IEC 60870-5-104:2006 clause 5
//!    and IEC 60870-5-101:2003 clauses 7.2.2–7.2.5 are asserted on the seeds
//!    and on the adversarial cases, with the sentence quoted in the test that
//!    asserts it.
//!
//! **Completeness is mechanical.** [`ENTRY_POINTS`] is the list of entry points
//! the corpus claims to drive. [`the_corpus_drives_every_entry_point_it_lists`]
//! **derives** the reception entry points from the text of the `src/` files
//! named in [`SOURCE_FILES`] at test time (every `pub fn` taking `&[u8]` and
//! every `pub fn on_frame`, minus the send-side and builder functions of
//! [`EXCLUDED_ENTRY_POINTS`], plus the octet-free [`ACCESSOR_ENTRY_POINTS`]),
//! asserts that set equal to [`ENTRY_POINTS`], and asserts that every listed
//! name was driven. So a `pub fn` taking `&[u8]` that is added to one of those
//! files without being listed and driven fails the corpus under its own name.
//! Files outside [`SOURCE_FILES`] are not scanned; the element parsers of
//! `src/asdu/elements/` are checked the same way against [`ELEMENT_FILES`].
//! The `match` in [`typed_decode`] names every [`TypeId`] variant with no
//! wildcard arm, so a type identification added to `src/asdu/types.rs` without
//! a corpus arm is a compile error rather than a silent gap.
//!
//! Sources cited per test: IEC 60870-5-104:2006 clause 5 (PDF page index 26,
//! printed 25, and index 28, printed 27), IEC 60870-5-101:2003 clause 7.2.2 /
//! 7.2.2.1 (index 34, printed 33 and index 35, printed 34) and clause 7.2.5
//! (index 44, printed 43). The seeds are Beckhoff's published TF6500 samples
//! (the same bytes `tests/wire_vectors.rs` pins), the raw byte stream printed in
//! Clarke/Reynders/Wright, *Practical Modern SCADA Protocols* Appendix D
//! `Communication 2`, and the committed real-peer frame
//! `interop::CAPTURE_PEER_ACT_CON` (`tests/interop/mod.rs`).

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::string_slice
)]

use std::alloc::{GlobalAlloc, Layout as AllocLayout, System};
use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::panic::{self, AssertUnwindSafe};

use iec104::apci::{self, Apci, ParseError, SeqNo, UFunction};
use iec104::asdu::elements::{
    Afq, Bcr, Bsi, Chs, Coi, Cp16Time2a, Cp24Time2a, Cp56Time2a, Dco, Diq, Fbp, Frq, Lof, Los, Lsq,
    Nof, Nos, Nva, Oci, Qcc, Qdp, Qds, Qoc, Qoi, Qos, Qpa, Qpm, Qrp, R32, Rco, Scd, Sco, Scq, Sep,
    Siq, Sof, Spe, Srq, Sva, Tsc, Vti,
};
use iec104::asdu::layout::{
    AsduLayout, CONTROL_LAYOUTS, FILE_LAYOUTS, Layout, LayoutObject, MONITOR_LAYOUTS, Segment,
    Sequence,
};
use iec104::asdu::{
    AddressSizes, BodyReader, CBoNa1, CBoTa1, CCdNa1, CCiNa1, CCsNa1, CDcNa1, CDcTa1, CIcNa1,
    CRcNa1, CRcTa1, CRdNa1, CRpNa1, CScNa1, CScTa1, CSeNa1, CSeNb1, CSeNc1, CSeTa1, CSeTb1, CSeTc1,
    CTsNa1, CTsTa1, Cause, FAfNa1, FDrTa1, FFrNa1, FLsNa1, FScNa1, FScNb1, FSrNa1, Header, Known,
    MBoNa1, MBoTa1, MBoTb1, MDpNa1, MDpTa1, MDpTb1, MEiNa1, MEpTa1, MEpTb1, MEpTc1, MEpTd1, MEpTe1,
    MEpTf1, MItNa1, MItTa1, MItTb1, MMeNa1, MMeNb1, MMeNc1, MMeNd1, MMeTa1, MMeTb1, MMeTc1, MMeTd1,
    MMeTe1, MMeTf1, MPsNa1, MSpNa1, MSpTa1, MSpTb1, MStNa1, MStTa1, MStTb1, PAcNa1, PMeNa1, PMeNb1,
    PMeNc1, TypeId, decode_asdu, decode_asdu_with, decode_segment, decode_segment_with,
    element_len, layout_for, read_ioa_with, write_ioa_with,
};
use iec104::params::LinkParams;
use iec104::{ci, cs, ct, framed, ft, gi, init, link, pm, rd, redundancy, ts, tx};

// --------------------------------------------------------------- the allocator

thread_local! {
    /// Octets allocated on this thread since the last reset.
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
    /// Entry points driven on this thread.
    static REACHED: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    /// Payload and location of the last panic caught on this thread.
    static LAST_PANIC: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Counts the octets this test binary allocates, per thread so the test
/// harness's own parallelism cannot pollute a measurement.
struct CountingAlloc;

unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: AllocLayout) -> *mut u8 {
        let _ = ALLOCATED.try_with(|c| c.set(c.get().saturating_add(layout.size())));
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: AllocLayout) -> *mut u8 {
        let _ = ALLOCATED.try_with(|c| c.set(c.get().saturating_add(layout.size())));
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: AllocLayout, new_size: usize) -> *mut u8 {
        let _ = ALLOCATED.try_with(|c| c.set(c.get().saturating_add(new_size)));
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: AllocLayout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: CountingAlloc = CountingAlloc;

/// The largest multiple of the input length a single case may allocate.
///
/// Measured over the whole corpus (run with `--test-threads=1`), exactly
/// **two** cases exceed 1 KiB, and both are a 6-octet header whose VSQ claims
/// 127 objects (the masked `UI7` ceiling of 5-101 cl.7.2.2) with no body to
/// fill them. `M_ME_NB_1` allocates **1 679** octets and the 13-octet
/// `LayoutObject<FDrTa1>` directory **3 711** octets. Both are carried by
/// [`ALLOC_SLACK`] (the second is 88.5 % of its 4 192-octet bound, 481 octets
/// of headroom), **not** by this factor: 16 × 6 octets is 96. The factor is the
/// scale guard for a real 249-octet ASDU, where a wire length that reached an
/// allocation without a bound would be hundreds of octets per input octet and
/// fail it loudly.
const ALLOC_FACTOR: usize = 16;

/// The fixed allowance every case gets on top of [`ALLOC_FACTOR`] × input.
///
/// `127 * size_of::<LayoutObject<FDrTa1>>()`, the largest allocation
/// `src/asdu/layout/mod.rs`'s `Vec::with_capacity(usize::from(header.count))`
/// can take from the wire, must stay under this.
/// [`a_wire_length_cannot_size_an_allocation`] asserts it, so a growth of the
/// directory's layout object fails under that struct's own name rather than as
/// a spurious `allocated N octets` from [`drive`].
const ALLOC_SLACK: usize = 4096;

/// Every entry point this corpus claims to drive.
///
/// A name here is a claim: [`the_corpus_drives_every_entry_point_it_lists`]
/// fails when one of them is never reached, and asserts this list **set-equal**
/// to the set [`derived_reception_entry_points`] reads out of `src/` at test
/// time (plus [`ACCESSOR_ENTRY_POINTS`]). So a parse entry point added to one of
/// [`SOURCE_FILES`] that takes `&[u8]` and is neither driven nor named in
/// [`EXCLUDED_ENTRY_POINTS`] fails under its own name, and a function removed
/// from `src/` fails the equality too.
///
/// The **derived** set is mechanical: it is the `pub fn`s of `src/` that bear the
/// octet-slice signature, read out of the file text at test time, so a new one is
/// caught without anyone editing this list. The two **hand lists** are not.
/// [`ACCESSOR_ENTRY_POINTS`] and [`EXCLUDED_ENTRY_POINTS`] are maintained by
/// hand. The test asserts that each accessor exists as a `pub fn` of
/// [`SOURCE_FILES`] and each exclusion as an octet-taking `pub fn` there, and
/// nothing more: that a name is **correctly classified** is not checked,
/// because no reader of `src/` can infer intent. Listing a
/// reception entry point in [`EXCLUDED_ENTRY_POINTS`] therefore hides it, which
/// is the escape hatch the exclusion rule in that list's doc comment closes.
const ENTRY_POINTS: &[&str] = &[
    "apci::apdu_len",
    "apci::parse",
    "asdu::Header::parse",
    "asdu::Header::parse_with",
    "asdu::body::BodyReader::finish",
    "asdu::body::BodyReader::from_asdu",
    "asdu::body::BodyReader::new",
    "asdu::body::BodyReader::next_object",
    "asdu::body::BodyReader::with_sizes",
    "asdu::decoded::decode",
    "asdu::decoded::decode_with",
    "asdu::layout::decode_asdu",
    "asdu::layout::decode_asdu_with",
    "asdu::layout::element_len",
    "asdu::layout::file::Segment::parse",
    "asdu::layout::file::decode_segment",
    "asdu::layout::file::decode_segment_with",
    "asdu::layout::layout_for",
    "asdu::read_ioa",
    "asdu::read_ioa_with",
    "asdu::unknown::classify",
    "asdu::unknown::discard_reason",
    "asdu::unknown::mirror_frame",
    "asdu::unknown::mirror_reply",
    "asdu::unknown::mirror_reply_with",
    "asdu::write_ioa_checked",
    "ci::CounterInterrogation::on_request",
    "ci::CounterInterrogation::on_response",
    "cs::ClockSynchronisation::on_request",
    "cs::ClockSynchronisation::on_response",
    "ct::CommandTransmission::on_request",
    "ct::CommandTransmission::on_request_at",
    "ct::CommandTransmission::on_response",
    "ct::CommandTransmission::refuse",
    "ct::decode_command",
    "ct::decode_command_with",
    "framed::Decoder::buffered",
    "framed::Decoder::is_idle",
    "framed::Decoder::next_frame",
    "framed::Decoder::next_frame_len",
    "framed::Decoder::push",
    "framed::Decoder::resyncs",
    "framed::Framed::next_frame",
    "dispatch::not_implemented",
    "diag::apdu",
    "diag::information_object_address",
    "ft::FileTransferProcedure::on_answer",
    "ft::FileTransferProcedure::on_asdu",
    "ft::decode_frame",
    "ft::decode_frame_with",
    "gi::Interrogation::on_request",
    "gi::Interrogation::on_response",
    "init::on_asdu",
    "init::on_asdu_with",
    "link::Session::on_frame",
    "manager::ConnectionManager::on_frame",
    "pm::ParameterLoading::on_request",
    "pm::ParameterLoading::on_response",
    "pm::ParameterLoading::refuse",
    "rd::Read::answer",
    "rd::Read::on_request",
    "rd::Read::on_response",
    "rd::answer",
    "rd::answer_with",
    "rd::refusal",
    "rd::refusal_with",
    "redundancy::RedundancyGroup::on_frame",
    "redundancy::RedundancyGroup::send_user_data_at",
    "ts::TestProcedure::answer",
    "ts::TestProcedure::on_request",
    "ts::TestProcedure::on_response",
    "ts::answer",
    "ts::answer_with",
    "ts::refusal",
    "ts::refusal_with",
    "tx::Transmission::on_response",
    "tx::append_objects",
];

/// The parser-layer entry points that take **no** octet slice, so [`derived_reception_entry_points`] cannot see them by signature:
/// `Decoder`'s and `BodyReader`'s state accessors, `layout_for` / `element_len`,
/// the header's length arithmetic and the unknown-type classifiers.
/// [`the_corpus_drives_every_entry_point_it_lists`] asserts each is a `pub fn`
/// of [`SOURCE_FILES`] (so a rename fails) and that the corpus drove it.
const ACCESSOR_ENTRY_POINTS: &[&str] = &[
    "apci::apdu_len",
    "asdu::body::BodyReader::finish",
    "asdu::body::BodyReader::next_object",
    "asdu::layout::element_len",
    "asdu::layout::layout_for",
    "asdu::unknown::classify",
    "asdu::unknown::discard_reason",
    "asdu::write_ioa_checked",
    "framed::Decoder::buffered",
    "framed::Decoder::is_idle",
    "framed::Decoder::next_frame",
    "framed::Decoder::next_frame_len",
    "framed::Decoder::resyncs",
    "framed::Framed::next_frame",
];

/// `pub fn`s that take `&[u8]` but are **not** reception entry points: the
/// senders, builders and checksum helpers the wire-slice signature rule also
/// matches. Each carries the one-line reason it is driven out of the corpus's
/// reception sweep; their own unit tests stay where they are.
///
/// **The exclusion rule.** A function whose `&[u8]` argument is read as a
/// **received frame** (it reaches `Header::parse`, `apci::parse`, a `decode_*`
/// or an element `parse` on that slice) is never excludable, however much it
/// then builds out of what it read. Only these three kinds may be listed:
/// a pure builder that encodes into an owned buffer, a sender that hands the
/// slice to the connection without reading it as a frame, and a checksum
/// arithmetic helper. "It builds the answer" is not a reason to exclude a
/// function that parses the frame it answers.
///
/// This is a **hand list**: [`derived_reception_entry_points`] asserts each name
/// exists as an octet-taking `pub fn` of [`SOURCE_FILES`], but neither it nor
/// [`the_corpus_drives_every_entry_point_it_lists`] can check that a row is
/// *correctly* classified (no reader of `src/` infers intent; see
/// [`ENTRY_POINTS`]). The rule is enforced by reading each row against `src/`.
const EXCLUDED_ENTRY_POINTS: &[(&str, &str)] = &[
    (
        "ft::check_checksum",
        "checks a received CHS, but takes the stated value as a second argument rather than a frame",
    ),
    (
        "ft::checksum",
        "computes the CHS of a payload — a builder, not a parser",
    ),
    (
        "ft::segment",
        "builds an `F_SG` frame from a payload — a builder",
    ),
    (
        "link::Session::send_i_frame",
        "frames a payload onward — send side, not reception",
    ),
    (
        "link::Session::queue_i_frame",
        "queues a payload for sending — send side, not reception",
    ),
    (
        "manager::ConnectionManager::send_i_frame",
        "frames a payload onward on a station's connection — send side",
    ),
    (
        "manager::ConnectionManager::queue_i_frame",
        "queues a payload on a station's connection — send side",
    ),
    (
        "redundancy::RedundancyGroup::send_user_data",
        "routes a payload onto the started connection — send side",
    ),
    (
        "seq::Sequence::buffer_i_frame",
        "buffers an outbound I-frame in the send window — send side",
    ),
];

// ------------------------------------------------------- the source derivation

/// One `src/` file the completeness derivation reads.
struct SourceFile {
    /// The module path its functions are named under.
    module: &'static str,
    /// The file's own text, read at compile time, so the derivation cannot drift
    /// from the code it is checking.
    text: &'static str,
}

/// The `src/` files the derivation scans: the codec, framer, ASDU and
/// application modules with reception entry points, the log formatter
/// (`src/diag.rs`, which reads a whole APDU) and the connection manager
/// (`src/manager.rs`, whose `on_frame` takes a received control field), plus
/// `src/seq.rs` (whose `Sequence::buffer_i_frame` the wire-slice rule also
/// matches).
const SOURCE_FILES: &[SourceFile] = &[
    SourceFile {
        module: "apci",
        text: include_str!("../src/apci.rs"),
    },
    SourceFile {
        module: "framed",
        text: include_str!("../src/framed.rs"),
    },
    SourceFile {
        module: "dispatch",
        text: include_str!("../src/dispatch.rs"),
    },
    SourceFile {
        module: "asdu",
        text: include_str!("../src/asdu/mod.rs"),
    },
    SourceFile {
        module: "asdu::body",
        text: include_str!("../src/asdu/body.rs"),
    },
    SourceFile {
        module: "asdu::decoded",
        text: include_str!("../src/asdu/decoded.rs"),
    },
    SourceFile {
        module: "asdu::layout",
        text: include_str!("../src/asdu/layout/mod.rs"),
    },
    SourceFile {
        module: "asdu::layout::file",
        text: include_str!("../src/asdu/layout/file.rs"),
    },
    SourceFile {
        module: "asdu::unknown",
        text: include_str!("../src/asdu/unknown.rs"),
    },
    SourceFile {
        module: "init",
        text: include_str!("../src/init.rs"),
    },
    SourceFile {
        module: "gi",
        text: include_str!("../src/gi.rs"),
    },
    SourceFile {
        module: "ci",
        text: include_str!("../src/ci.rs"),
    },
    SourceFile {
        module: "cs",
        text: include_str!("../src/cs.rs"),
    },
    SourceFile {
        module: "ct",
        text: include_str!("../src/ct.rs"),
    },
    SourceFile {
        module: "pm",
        text: include_str!("../src/pm.rs"),
    },
    SourceFile {
        module: "tx",
        text: include_str!("../src/tx.rs"),
    },
    SourceFile {
        module: "rd",
        text: include_str!("../src/rd.rs"),
    },
    SourceFile {
        module: "ts",
        text: include_str!("../src/ts.rs"),
    },
    SourceFile {
        module: "ft",
        text: include_str!("../src/ft.rs"),
    },
    SourceFile {
        module: "link",
        text: include_str!("../src/link.rs"),
    },
    SourceFile {
        module: "redundancy",
        text: include_str!("../src/redundancy.rs"),
    },
    SourceFile {
        module: "seq",
        text: include_str!("../src/seq.rs"),
    },
    SourceFile {
        module: "diag",
        text: include_str!("../src/diag.rs"),
    },
    SourceFile {
        module: "manager",
        text: include_str!("../src/manager.rs"),
    },
];

/// The element files: their `pub fn parse` is keyed by the `impl` type, which is
/// what [`ELEMENT_PARSER_NAMES`] has to name.
const ELEMENT_FILES: &[&str] = &[
    include_str!("../src/asdu/elements/status.rs"),
    include_str!("../src/asdu/elements/value.rs"),
    include_str!("../src/asdu/elements/time.rs"),
    include_str!("../src/asdu/elements/command.rs"),
    include_str!("../src/asdu/elements/qualifier.rs"),
    include_str!("../src/asdu/elements/file.rs"),
];

/// One `pub fn` [`scan_pub_fns`] found.
struct FoundFn {
    /// The `impl` type it is defined in, if it is a method.
    owner: Option<String>,
    /// Its name.
    name: String,
    /// Its parameter list, verbatim.
    params: String,
}

/// The octet-consuming reception entry points `src/` exposes: every `pub fn`
/// whose parameter list takes a `&[u8]`, every `pub fn on_frame`, minus
/// [`EXCLUDED_ENTRY_POINTS`]. Derived from [`SOURCE_FILES`] at test time: this
/// is the corpus's completeness mechanism, not a comment.
fn derived_reception_entry_points() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for file in SOURCE_FILES {
        for found in scan_pub_fns(file.text) {
            if found.name == "on_frame" || has_octet_slice(&found.params) {
                names.insert(qualify(file.module, found.owner.as_deref(), &found.name));
            }
        }
    }
    for (name, reason) in EXCLUDED_ENTRY_POINTS {
        assert!(
            names.remove(*name),
            "{name} is excluded for \"{reason}\" but src/ has no such octet-taking `pub fn`"
        );
    }
    names
}

/// The element parser types `src/asdu/elements/` exposes: every `impl` block
/// that carries a `pub fn parse`, keyed by its type.
fn derived_element_parsers() -> BTreeSet<String> {
    let mut types = BTreeSet::new();
    for text in ELEMENT_FILES {
        for found in scan_pub_fns(text) {
            if found.name == "parse"
                && let Some(owner) = found.owner
            {
                types.insert(owner);
            }
        }
    }
    types
}

/// Every `pub fn` name of [`SOURCE_FILES`], owner-qualified: what
/// [`ACCESSOR_ENTRY_POINTS`] is checked against.
fn every_pub_fn_name() -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for file in SOURCE_FILES {
        for found in scan_pub_fns(file.text) {
            names.insert(qualify(file.module, found.owner.as_deref(), &found.name));
        }
    }
    names
}

/// `module::owner::name`, or `module::name` for a free function.
fn qualify(module: &str, owner: Option<&str>, name: &str) -> String {
    owner.map_or_else(
        || format!("{module}::{name}"),
        |owner| format!("{module}::{owner}::{name}"),
    )
}

/// Whether a parameter list takes a byte slice: `&[u8]`, `&'a [u8]` or
/// `&mut [u8]`. `Vec<u8>` and `&mut Vec<u8>` are deliberately not matched: the
/// reception entry points hand over octets, they do not receive a buffer to
/// fill.
fn has_octet_slice(params: &str) -> bool {
    let compact: String = params.chars().filter(|c| !c.is_whitespace()).collect();
    let mut rest = compact.as_str();
    while let Some(index) = rest.find("[u8]") {
        let before = &rest[..index];
        let stem = before.strip_suffix("mut").unwrap_or(before);
        if stem.ends_with('&') {
            return true;
        }
        if let Some(amp) = stem.rfind('&') {
            let lifetime = &stem[amp + 1..];
            if let Some(name) = lifetime.strip_prefix('\'')
                && !name.is_empty()
                && name.chars().all(|c| c.is_alphanumeric() || c == '_')
            {
                return true;
            }
        }
        rest = &rest[index + 4..];
    }
    false
}

/// The index just past the (nested) block comment that opens at `i`.
fn skip_block_comment(text: &str, i: usize) -> usize {
    let bytes = text.as_bytes();
    let mut j = i + 2;
    let mut level = 1usize;
    while j < bytes.len() && level > 0 {
        if text[j..].starts_with("/*") {
            level += 1;
            j += 2;
        } else if text[j..].starts_with("*/") {
            level -= 1;
            j += 2;
        } else {
            j += 1;
        }
    }
    j
}

/// The index just past the string literal whose opening quote is at `i`.
const fn skip_string(bytes: &[u8], i: usize) -> usize {
    let mut j = i + 1;
    while j < bytes.len() {
        if bytes[j] == b'\\' {
            j += 2;
        } else if bytes[j] == b'"' {
            j += 1;
            break;
        } else {
            j += 1;
        }
    }
    j
}

/// Scans a Rust file for its `pub fn`s, tracking the `impl` type each is defined
/// in. Comments, string literals and block-comment nesting are skipped, and the
/// `impl` stack is popped on the closing brace at its own depth, so a brace or
/// an `impl` inside text cannot shift an owner.
fn scan_pub_fns(text: &str) -> Vec<FoundFn> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut depth: usize = 0;
    let mut impls: Vec<(usize, String)> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let rest = &text[i..];
        if rest.starts_with("//") {
            i += rest.find('\n').unwrap_or(rest.len());
            continue;
        }
        if rest.starts_with("/*") {
            i = skip_block_comment(text, i);
            continue;
        }
        match bytes[i] {
            b'"' => {
                i = skip_string(bytes, i);
                continue;
            }
            b'{' => {
                depth += 1;
                i += 1;
                continue;
            }
            b'}' => {
                loop {
                    match impls.last().map(|(open, _)| *open) {
                        Some(open) if open >= depth => {
                            impls.pop();
                        }
                        _ => break,
                    }
                }
                depth = depth.saturating_sub(1);
                i += 1;
                continue;
            }
            _ => {}
        }
        if word_at(text, i, "impl") {
            let mut j = skip_ws(text, i + 4);
            if bytes.get(j) == Some(&b'<') {
                j = skip_ws(text, skip_angle(text, j));
            }
            let (head, after_head) = read_path(text, j);
            let mut k = skip_ws(text, after_head);
            let mut owner = head;
            if word_at(text, k, "for") {
                let (trait_owner, after_trait) = read_path(text, skip_ws(text, k + 3));
                owner = trait_owner;
                k = skip_ws(text, after_trait);
            }
            if bytes.get(k) == Some(&b'<') {
                k = skip_ws(text, skip_angle(text, k));
            }
            if !owner.is_empty() && bytes.get(k) == Some(&b'{') {
                impls.push((depth, owner));
            }
            i += 4;
            continue;
        }
        if word_at(text, i, "pub") {
            let mut j = skip_ws(text, i + 3);
            if word_at(text, j, "const") {
                j = skip_ws(text, j + 5);
            }
            if word_at(text, j, "fn") {
                let name_start = skip_ws(text, j + 2);
                let (name, after_name) = read_ident(text, name_start);
                let mut paren = skip_ws(text, after_name);
                if bytes.get(paren) == Some(&b'<') {
                    paren = skip_ws(text, skip_angle(text, paren));
                }
                if bytes.get(paren) == Some(&b'(') {
                    let close = matching_paren(text, paren);
                    let owner = impls
                        .iter()
                        .rev()
                        .find(|(open, _)| *open < depth)
                        .map(|(_, owner)| owner.clone());
                    found.push(FoundFn {
                        owner,
                        name,
                        params: text[paren + 1..close].to_string(),
                    });
                }
                i = paren.max(i + 1);
                continue;
            }
        }
        i += 1;
    }
    found
}

/// Whether `text[i..]` starts with the whole word `word`.
fn word_at(text: &str, i: usize, word: &str) -> bool {
    let bytes = text.as_bytes();
    if !text[i..].starts_with(word) {
        return false;
    }
    let before = i == 0 || !is_ident_byte(bytes[i - 1]);
    let after = match bytes.get(i + word.len()) {
        Some(&b) => !is_ident_byte(b),
        None => true,
    };
    before && after
}

/// Whether `b` can appear in a Rust identifier.
const fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The index of the first non-whitespace byte at or after `i`.
const fn skip_ws(text: &str, mut i: usize) -> usize {
    let bytes = text.as_bytes();
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// The index just past the `>` balancing the `<` at `i`.
const fn skip_angle(text: &str, i: usize) -> usize {
    let bytes = text.as_bytes();
    let mut j = i;
    let mut level = 0usize;
    while j < bytes.len() {
        match bytes[j] {
            b'<' => level += 1,
            b'>' => {
                level -= 1;
                if level == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    j
}

/// The index just past the `)` balancing the `(` at `i`.
const fn matching_paren(text: &str, i: usize) -> usize {
    let bytes = text.as_bytes();
    let mut j = i;
    let mut level = 0usize;
    while j < bytes.len() {
        match bytes[j] {
            b'(' => level += 1,
            b')' => {
                level -= 1;
                if level == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    j
}

/// Reads an identifier at `i`, returning it and the index after it.
fn read_ident(text: &str, i: usize) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut j = i;
    while j < bytes.len() && is_ident_byte(bytes[j]) {
        j += 1;
    }
    (text[i..j].to_string(), j)
}

/// Reads a `::`-separated path at `i`, returning it and the index after it.
fn read_path(text: &str, i: usize) -> (String, usize) {
    let bytes = text.as_bytes();
    let mut j = i;
    while j < bytes.len() && (is_ident_byte(bytes[j]) || bytes[j] == b':') {
        j += 1;
    }
    (text[i..j].to_string(), j)
}

// ------------------------------------------------------------------ the guard

/// Installs the recording panic hook once.
fn install_panic_hook() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        panic::set_hook(Box::new(|info| {
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .map(|text| (*text).to_string())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic payload>".to_string());
            let location = info
                .location()
                .map_or_else(|| "<unknown location>".to_string(), |at| format!("{at}"));
            let note = format!("{payload} (at {location})");
            let _ = LAST_PANIC.try_with(|slot| {
                if let Ok(mut slot) = slot.try_borrow_mut() {
                    *slot = Some(note.clone());
                }
            });
            // The hook is the only place a caught panic is reported: the test
            // harness captures stderr per test and prints it when the test
            // fails, so the entry point and the seed are visible in the failure.
            eprintln!("parser corpus: panic caught: {note}");
        }));
    });
}

/// Records that `entry` was driven, then runs `f` under the panic guard and the
/// allocation bound. A panic in `f` fails the test with the case named.
fn drive<T>(entry: &'static str, case: &str, input_len: usize, f: impl FnOnce() -> T) -> T {
    install_panic_hook();
    REACHED.with(|reached| reached.borrow_mut().push(entry));
    let before = ALLOCATED.with(Cell::get);
    let outcome = panic::catch_unwind(AssertUnwindSafe(f));
    let after = ALLOCATED.with(Cell::get);
    let Ok(out) = outcome else {
        let note = LAST_PANIC
            .with(|slot| slot.borrow_mut().take())
            .unwrap_or_else(|| "<panic payload not recorded>".to_string());
        panic!("{entry} panicked on {case}: {note}");
    };
    let used = after.saturating_sub(before);
    let limit = ALLOC_FACTOR
        .saturating_mul(input_len)
        .saturating_add(ALLOC_SLACK);
    assert!(
        used <= limit,
        "{entry} on {case} allocated {used} octets from {input_len} input octets (limit {limit})"
    );
    out
}

// --------------------------------------------------------------------- seeds

/// One committed seed frame.
struct Seed {
    /// Where the octets come from, for the failure message.
    name: &'static str,
    /// The seed itself.
    bytes: &'static [u8],
    /// `Some(n)` when the whole seed is one well-formed APDU of `n` octets, and
    /// then every proper prefix must be a typed `Incomplete` and the whole must
    /// parse. `None` for a raw octet stream that is not one whole APDU.
    apdu: Option<usize>,
}

/// Beckhoff Information System, *TF6500 `TwinCAT` 3 IEC 60870-5-10x*, "Simple
/// samples and explanations", sample 1: a counter-interrogation command.
const BECKHOFF_1: &[u8] = &[
    0x68, 0x0E, 0x4E, 0x14, 0x7C, 0x00, 0x65, 0x01, 0x0A, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x05,
];

/// Beckhoff, sample 2: seven spontaneous scaled measured values.
const BECKHOFF_2: &[u8] = &[
    0x68, 0x34, 0x5A, 0x14, 0x7C, 0x00, 0x0B, 0x07, 0x03, 0x00, 0x0C, 0x00, 0x10, 0x30, 0x00, 0xBE,
    0x09, 0x00, 0x11, 0x30, 0x00, 0x90, 0x09, 0x00, 0x0E, 0x30, 0x00, 0x75, 0x00, 0x00, 0x28, 0x30,
    0x00, 0x25, 0x09, 0x00, 0x29, 0x30, 0x00, 0x75, 0x00, 0x00, 0x0F, 0x30, 0x00, 0x0F, 0x0A, 0x00,
    0x2E, 0x30, 0x00, 0xAE, 0x05, 0x00,
];

/// Beckhoff, sample 3: an S-format acknowledgement.
const BECKHOFF_3: &[u8] = &[0x68, 0x04, 0x01, 0x00, 0x7E, 0x14];

/// A U-format frame, `STARTDT act`: its control field is 104 clause 5's
/// figure 8 (index 28, printed 27), framed per clause 5 (index 26, printed 25)
/// as `68H` + a length of `4` + the four control octets.
const STARTDT_ACT: &[u8] = &[0x68, 0x04, 0x07, 0x00, 0x00, 0x00];

/// Clarke/Reynders/Wright, *Practical Modern SCADA Protocols*, Appendix D
/// "Communication 2": the raw octet stream as printed, two 101 frames back to
/// back followed by trailing octets. It is **not** one 104 APDU but the
/// framing fixture: octets that begin with `68` and are not a frame must be a
/// typed error or a resync, never a panic.
const BOOK_STREAM: &[u8] = &[
    0x68, 0x0B, 0x0B, 0x68, 0x73, 0x02, 0x01, 0x64, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x14, 0xEF,
    0x16, 0xE5, 0x68, 0x25, 0x25, 0x68, 0x53, 0x02, 0x01, 0x0B, 0x05, 0x14, 0x01, 0x01, 0x00, 0x05,
    0x12, 0x00, 0x00, 0x01, 0x00, 0x01, 0x74, 0x0D, 0x00, 0x01, 0x00, 0x02, 0x0B, 0x00, 0x00, 0x02,
    0x00, 0x02, 0x01, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0xAA, 0x16,
];

/// The committed real-peer frame: `c104` 2.2.1's positive `C_IC_NA_1 ACTCON`,
/// quoted octet for octet from `interop::CAPTURE_PEER_ACT_CON` in
/// `tests/interop/mod.rs` (wire traffic, no peer source).
const CAPTURE_PEER_ACT_CON: &[u8] = &[
    0x68, 0x0E, 0x00, 0x00, 0x02, 0x00, 0x64, 0x01, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14,
];

/// Every seed the corpus expands.
const SEEDS: &[Seed] = &[
    Seed {
        name: "Beckhoff sample 1 (counter interrogation)",
        bytes: BECKHOFF_1,
        apdu: Some(16),
    },
    Seed {
        name: "Beckhoff sample 2 (7 spontaneous measured values)",
        bytes: BECKHOFF_2,
        apdu: Some(54),
    },
    Seed {
        name: "Beckhoff sample 3 (S-format ack)",
        bytes: BECKHOFF_3,
        apdu: Some(6),
    },
    Seed {
        name: "STARTDT act (U-format, clause 5 figure 8)",
        bytes: STARTDT_ACT,
        apdu: Some(6),
    },
    Seed {
        name: "Clarke/Reynders/Wright Appendix D communication 2 stream",
        bytes: BOOK_STREAM,
        apdu: None,
    },
    Seed {
        name: "interop::CAPTURE_PEER_ACT_CON (real peer, C_IC_NA_1 ACTCON)",
        bytes: CAPTURE_PEER_ACT_CON,
        apdu: Some(16),
    },
];

/// The seeds the flip sweep expands. Smaller on purpose: the sweep is
/// positions × 256, so it is kept to the frames whose expansion stays cheap.
const FLIP_SEEDS: &[&Seed] = &[
    &SEEDS[0],
    &SEEDS[2],
    &SEEDS[3],
    &SEEDS[5],
    &Seed {
        name: "one minimal C_IC_NA_1 frame",
        bytes: &[
            0x68, 0x0E, 0x01, 0x00, 0x03, 0x00, 0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x14,
        ],
        apdu: Some(16),
    },
];

// ------------------------------------------------------------- entry points

/// Drives every entry point that takes raw octets on one buffer.
fn drive_frame_entry_points(case: &str, input: &[u8]) {
    let len = input.len();
    let start = input.first().copied().unwrap_or(0);
    let length = input.get(1).copied().unwrap_or(0);

    drive("apci::apdu_len", case, len, || {
        let _ = apci::apdu_len(start, length);
    });
    let parsed = drive("apci::parse", case, len, || apci::parse(input));
    if let Ok((apdu, used)) = parsed {
        assert!(
            used <= len,
            "{case}: apci::parse consumed {used} octets of a {len}-octet buffer"
        );
        // 104 cl.5 (index 26): "The maximum length of the ASDU is limited to
        // 249 because the maximum value of the field length of APDU is 253
        // (APDUmax = 255 minus start and length octet) and the length of the
        // control field is 4 octets."
        assert!(
            apdu.asdu.len() <= apci::MAX_ASDU,
            "{case}: an APDU carried a {} octet ASDU (clause 5 caps it at {})",
            apdu.asdu.len(),
            apci::MAX_ASDU
        );
    }
    let asdu: &[u8] = match parsed {
        Ok((apdu, _)) => apdu.asdu,
        Err(_) => input,
    };
    let type_id = match asdu.first() {
        Some(&first) => TypeId::from_u8(first),
        None => TypeId::Other(0),
    };

    drive("asdu::Header::parse", case, asdu.len(), || {
        let _ = Header::parse(asdu);
    });
    drive("asdu::read_ioa", case, asdu.len(), || {
        let _ = iec104::asdu::read_ioa(asdu);
    });
    drive("asdu::write_ioa_checked", case, 0, || {
        let mut out = Vec::new();
        let _ =
            iec104::asdu::write_ioa_checked(&mut out, u32::from_le_bytes([start, length, 0, 0]));
    });
    drive("asdu::layout::layout_for", case, asdu.len(), || {
        let _ = layout_for(type_id);
    });
    drive("asdu::layout::element_len", case, asdu.len(), || {
        let _ = element_len(type_id);
    });
    // The **conventional** wrappers of the two layout decoders, driven under
    // their own names: their `_with` forms are what `typed_decode` reaches, and
    // a corpus that recorded the plain name for a `_with` call would report an
    // entry point as covered that nothing called.
    drive("asdu::layout::decode_asdu", case, asdu.len(), || {
        let _ = decode_asdu::<MMeNb1>(asdu);
    });
    // The any-type decoder picks the layout from the octets themselves, so a
    // corrupted type identification reaches every layout in turn.
    drive("asdu::decoded::decode", case, asdu.len(), || {
        let _ = iec104::asdu::decode(asdu);
    });
    // Appended to a well formed spontaneous M_ME_NB_1 ASDU and the other way
    // round: whatever the octets, nothing is appended, or the result still
    // decodes (TS 60870-5-604 5.4.16.1's packing never builds a bad ASDU).
    drive("tx::append_objects", case, asdu.len(), || {
        let sizes = iec104::asdu::AddressSizes::CONVENTIONAL;
        let seed = [11, 1, 3, 0, 1, 0, 0x64, 0, 0, 0xe8, 0x03, 0];
        let mut onto_seed = seed.to_vec();
        if tx::append_objects(&mut onto_seed, asdu, sizes) {
            assert!(iec104::asdu::decode_with(&onto_seed, sizes).is_ok());
        }
        let mut onto_input = asdu.to_vec();
        if tx::append_objects(&mut onto_input, &seed, sizes) {
            assert!(iec104::asdu::decode_with(&onto_input, sizes).is_ok());
        }
    });
    drive(
        "asdu::layout::file::decode_segment",
        case,
        asdu.len(),
        || {
            let _ = decode_segment(asdu);
        },
    );

    drive_body_reader(case, asdu);

    drive_typed_decode(case, asdu);

    drive_framed(case, input);

    let apci = match parsed {
        Ok((frame, _)) => frame.apci,
        Err(_) => Apci::U(UFunction::TestFrAct),
    };
    drive_link_entry_points(case, apci);
    drive_sized_entry_points(case, input);
}

/// Drives the body cursor over the ASDU.
fn drive_body_reader(case: &str, asdu: &[u8]) {
    let header = Header::parse(asdu).ok();
    drive(
        "asdu::body::BodyReader::from_asdu",
        case,
        asdu.len(),
        || {
            let _ = BodyReader::from_asdu(asdu);
        },
    );
    if let Some(header) = header {
        drive("asdu::body::BodyReader::new", case, asdu.len(), || {
            let _ = BodyReader::new(header, &asdu[Header::LEN.min(asdu.len())..]);
        });
        // The element length the body cursor is given: the type's own layout,
        // or 0 for the one variable-length type (it is refused by
        // `decode_segment`'s own path anyway, never by a guessed number).
        let step = element_len(header.type_id).unwrap_or(0);
        drive(
            "asdu::body::BodyReader::next_object",
            case,
            asdu.len(),
            || {
                if let Ok(mut body) = BodyReader::from_asdu(asdu) {
                    for _ in 0..=usize::from(header.count) {
                        match body.next_object(step) {
                            Ok(Some(_)) => {}
                            _ => break,
                        }
                    }
                }
            },
        );
        drive("asdu::body::BodyReader::finish", case, asdu.len(), || {
            if let Ok(body) = BodyReader::from_asdu(asdu) {
                let _ = body.finish();
            }
        });
    }
}

/// Drives the framing decoder and the framed reader over the raw octets.
fn drive_framed(case: &str, input: &[u8]) {
    let len = input.len();
    let mut decoder = framed::Decoder::new();
    drive("framed::Decoder::push", case, len, || decoder.push(input));
    for _ in 0..=len {
        let step = drive("framed::Decoder::next_frame", case, len, || {
            decoder.next_frame().map(|frame| frame.map(<[u8]>::len))
        });
        drive("framed::Decoder::next_frame_len", case, len, || {
            let _ = decoder.next_frame_len();
        });
        drive("framed::Decoder::is_idle", case, len, || {
            let _ = decoder.is_idle();
        });
        drive("framed::Decoder::buffered", case, len, || {
            let _ = decoder.buffered();
        });
        drive("framed::Decoder::resyncs", case, len, || {
            let _ = decoder.resyncs();
        });
        match step {
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    drive("framed::Framed::next_frame", case, len, || {
        let mut framed = framed::Framed::new(input);
        for _ in 0..=len {
            match framed.next_frame() {
                Ok(Some(_)) => {}
                _ => break,
            }
        }
    });
}

/// Drives the five sized (`_with`) entry points over **every** legal address
/// profile on one buffer.
///
/// The conventional names of these five are driven by the rest of the corpus;
/// these are the ones a configured profile goes through, and a case that is a
/// typed error under the conventional profile must stay a typed error (never a
/// panic, never an unbounded allocation) under each of the other eleven. A
/// narrower header moves the object area, which is exactly where a width
/// misread would surface.
fn drive_sized_entry_points(case: &str, input: &[u8]) {
    let len = input.len();
    for sizes in every_profile() {
        drive("asdu::Header::parse_with", case, len, || {
            let _ = Header::parse_with(input, sizes);
        });
        drive("asdu::read_ioa_with", case, len, || {
            let _ = read_ioa_with(input, sizes);
        });
        if let Ok(header) = Header::parse_with(input, sizes) {
            let header_len = sizes.header_len();
            drive("asdu::body::BodyReader::with_sizes", case, len, || {
                let _ = BodyReader::with_sizes(header, &input[header_len..], sizes);
            });
        }
        drive("asdu::layout::decode_asdu_with", case, len, || {
            let _ = decode_asdu_with::<MMeNb1>(input, sizes);
        });
        drive("asdu::decoded::decode_with", case, len, || {
            let _ = iec104::asdu::decode_with(input, sizes);
        });
        drive("asdu::layout::file::decode_segment_with", case, len, || {
            let _ = decode_segment_with(input, sizes);
        });
        // The log formatter reads a whole APDU off the wire, and the IOA line
        // an object area; both must be typed errors on anything malformed.
        drive("diag::apdu", case, len, || {
            let _ = iec104::diag::apdu(input, sizes);
        });
        drive("diag::information_object_address", case, len, || {
            let _ = iec104::diag::information_object_address(input, sizes);
        });
    }
}

/// The one exhaustive dispatch over [`TypeId`]: every named type is decoded
/// with its own layout. A variant added to `TypeId` without an arm here does
/// not compile, which is the corpus's completeness mechanism for the type
/// table.
fn typed_decode(
    type_id: TypeId,
    asdu: &[u8],
    sizes: AddressSizes,
) -> Option<Result<usize, String>> {
    Some(match type_id {
        TypeId::MSpNa1 => objects::<MSpNa1>(asdu, sizes),
        TypeId::MSpTa1 => objects::<MSpTa1>(asdu, sizes),
        TypeId::MDpNa1 => objects::<MDpNa1>(asdu, sizes),
        TypeId::MDpTa1 => objects::<MDpTa1>(asdu, sizes),
        TypeId::MStNa1 => objects::<MStNa1>(asdu, sizes),
        TypeId::MStTa1 => objects::<MStTa1>(asdu, sizes),
        TypeId::MBoNa1 => objects::<MBoNa1>(asdu, sizes),
        TypeId::MBoTa1 => objects::<MBoTa1>(asdu, sizes),
        TypeId::MMeNa1 => objects::<MMeNa1>(asdu, sizes),
        TypeId::MMeTa1 => objects::<MMeTa1>(asdu, sizes),
        TypeId::MMeNb1 => objects::<MMeNb1>(asdu, sizes),
        TypeId::MMeTb1 => objects::<MMeTb1>(asdu, sizes),
        TypeId::MMeNc1 => objects::<MMeNc1>(asdu, sizes),
        TypeId::MMeTc1 => objects::<MMeTc1>(asdu, sizes),
        TypeId::MItNa1 => objects::<MItNa1>(asdu, sizes),
        TypeId::MItTa1 => objects::<MItTa1>(asdu, sizes),
        TypeId::MEpTa1 => objects::<MEpTa1>(asdu, sizes),
        TypeId::MEpTb1 => objects::<MEpTb1>(asdu, sizes),
        TypeId::MEpTc1 => objects::<MEpTc1>(asdu, sizes),
        TypeId::MPsNa1 => objects::<MPsNa1>(asdu, sizes),
        TypeId::MMeNd1 => objects::<MMeNd1>(asdu, sizes),
        TypeId::MSpTb1 => objects::<MSpTb1>(asdu, sizes),
        TypeId::MDpTb1 => objects::<MDpTb1>(asdu, sizes),
        TypeId::MStTb1 => objects::<MStTb1>(asdu, sizes),
        TypeId::MBoTb1 => objects::<MBoTb1>(asdu, sizes),
        TypeId::MMeTd1 => objects::<MMeTd1>(asdu, sizes),
        TypeId::MMeTe1 => objects::<MMeTe1>(asdu, sizes),
        TypeId::MMeTf1 => objects::<MMeTf1>(asdu, sizes),
        TypeId::MItTb1 => objects::<MItTb1>(asdu, sizes),
        TypeId::MEpTd1 => objects::<MEpTd1>(asdu, sizes),
        TypeId::MEpTe1 => objects::<MEpTe1>(asdu, sizes),
        TypeId::MEpTf1 => objects::<MEpTf1>(asdu, sizes),
        TypeId::CScNa1 => objects::<CScNa1>(asdu, sizes),
        TypeId::CDcNa1 => objects::<CDcNa1>(asdu, sizes),
        TypeId::CRcNa1 => objects::<CRcNa1>(asdu, sizes),
        TypeId::CSeNa1 => objects::<CSeNa1>(asdu, sizes),
        TypeId::CSeNb1 => objects::<CSeNb1>(asdu, sizes),
        TypeId::CSeNc1 => objects::<CSeNc1>(asdu, sizes),
        TypeId::CBoNa1 => objects::<CBoNa1>(asdu, sizes),
        TypeId::CScTa1 => objects::<CScTa1>(asdu, sizes),
        TypeId::CDcTa1 => objects::<CDcTa1>(asdu, sizes),
        TypeId::CRcTa1 => objects::<CRcTa1>(asdu, sizes),
        TypeId::CSeTa1 => objects::<CSeTa1>(asdu, sizes),
        TypeId::CSeTb1 => objects::<CSeTb1>(asdu, sizes),
        TypeId::CSeTc1 => objects::<CSeTc1>(asdu, sizes),
        TypeId::CBoTa1 => objects::<CBoTa1>(asdu, sizes),
        TypeId::MEiNa1 => objects::<MEiNa1>(asdu, sizes),
        TypeId::CIcNa1 => objects::<CIcNa1>(asdu, sizes),
        TypeId::CCiNa1 => objects::<CCiNa1>(asdu, sizes),
        TypeId::CRdNa1 => objects::<CRdNa1>(asdu, sizes),
        TypeId::CCsNa1 => objects::<CCsNa1>(asdu, sizes),
        TypeId::CTsNa1 => objects::<CTsNa1>(asdu, sizes),
        TypeId::CRpNa1 => objects::<CRpNa1>(asdu, sizes),
        TypeId::CCdNa1 => objects::<CCdNa1>(asdu, sizes),
        TypeId::CTsTa1 => objects::<CTsTa1>(asdu, sizes),
        TypeId::PMeNa1 => objects::<PMeNa1>(asdu, sizes),
        TypeId::PMeNb1 => objects::<PMeNb1>(asdu, sizes),
        TypeId::PMeNc1 => objects::<PMeNc1>(asdu, sizes),
        TypeId::PAcNa1 => objects::<PAcNa1>(asdu, sizes),
        TypeId::FFrNa1 => objects::<FFrNa1>(asdu, sizes),
        TypeId::FSrNa1 => objects::<FSrNa1>(asdu, sizes),
        TypeId::FScNa1 => objects::<FScNa1>(asdu, sizes),
        TypeId::FLsNa1 => objects::<FLsNa1>(asdu, sizes),
        TypeId::FAfNa1 => objects::<FAfNa1>(asdu, sizes),
        TypeId::FSgNa1 => decode_segment_with(asdu, sizes)
            .map(|_| 1)
            .map_err(|error| format!("{error:?}")),
        TypeId::FDrTa1 => objects::<FDrTa1>(asdu, sizes),
        TypeId::FScNb1 => objects::<FScNb1>(asdu, sizes),
        TypeId::Other(_) => return None,
    })
}

/// The object count of a successful decode, or the typed error's `Debug`.
fn objects<A: AsduLayout>(asdu: &[u8], sizes: AddressSizes) -> Result<usize, String> {
    decode_asdu_with::<A>(asdu, sizes)
        .map(|objects| objects.len())
        .map_err(|error| format!("{error:?}"))
}

/// Drives the two layout entry points and the type's own decoder on `asdu`.
fn drive_typed_decode(case: &str, asdu: &[u8]) {
    let type_id = match asdu.first() {
        Some(&first) => TypeId::from_u8(first),
        None => TypeId::Other(0),
    };
    let entry = match type_id {
        TypeId::Other(_) => return,
        TypeId::FSgNa1 => "asdu::layout::file::decode_segment_with",
        _ => "asdu::layout::decode_asdu_with",
    };
    drive(entry, case, asdu.len(), || {
        let _ = typed_decode(type_id, asdu, AddressSizes::CONVENTIONAL);
    });
}

/// Drives the session-layer reception entry points with one control field.
fn drive_link_entry_points(case: &str, apci: Apci) {
    let mut session = link::Session::new(link::Role::Controlling);
    drive("link::Session::on_frame", case, 0, || {
        let _ = session.on_frame(apci);
    });
    if let Ok(mut group) =
        redundancy::RedundancyGroup::new(link::Role::Controlling, vec![LinkParams::default()])
    {
        drive("redundancy::RedundancyGroup::on_frame", case, 0, || {
            let _ = group.on_frame(0, apci);
        });
    }
    if let Ok(mut manager) = iec104::manager::ConnectionManager::new(
        link::Role::Controlling,
        vec![iec104::manager::StationConfig::new(LinkParams::default())],
    ) {
        let now = std::time::Instant::now();
        manager.tick(now);
        let _ = manager.on_connection_established(0, now);
        drive("manager::ConnectionManager::on_frame", case, 0, || {
            let _ = manager.on_frame(0, apci, now);
        });
    }
}

/// A data source that returns nothing: the corpus is about the parsers, not
/// about what a station would answer.
struct NoData;

impl gi::DataSource for NoData {
    fn ready(&self, _scope: gi::Scope) -> bool {
        false
    }

    fn interrogated(&self, _scope: gi::Scope, _out: &mut Vec<Vec<u8>>) {}
}

impl ci::CounterSource for NoData {
    fn ready(&self, _request: ci::Request) -> bool {
        false
    }

    fn totals(&self, _request: ci::Request, _out: &mut Vec<Vec<u8>>) {}
}

impl rd::DataSource for NoData {
    fn object(&self, _ioa: u32) -> Option<Vec<u8>> {
        None
    }
}

/// Drives the application modules' reception entry points on one ASDU.
fn drive_app_entry_points(case: &str, asdu: &[u8]) {
    let len = asdu.len();
    let header = Header::parse(asdu).ok();
    let known = header.map_or(Known::NOTHING, |header| {
        Known::standard(&header, true, true)
    });
    let source = NoData;

    drive("init::on_asdu", case, len, || {
        let _ = init::on_asdu(asdu, &known);
    });

    drive_group_and_interrogations(case, asdu, known, &source);

    let Ok(pre_sync) = Cp56Time2a::parse(&[0u8; 7]) else {
        return;
    };
    let clock = cs::ClockSynchronisation::controlled(1, 0);
    drive("cs::ClockSynchronisation::on_request", case, len, || {
        let _ = clock.on_request(asdu, &known, pre_sync);
    });
    let clock_controlling = cs::ClockSynchronisation::controlling(1, 0);
    drive("cs::ClockSynchronisation::on_response", case, len, || {
        let _ = clock_controlling.on_response(asdu, &known);
    });

    drive_commands(case, asdu, known);

    let parameter = pm::Parameter::new(
        1,
        pm::ParameterValue::Scaled {
            sva: Sva::from_raw(0),
            qpm: Qpm::from_raw(0),
        },
    );
    let loading = pm::ParameterLoading::controlled(pm::LocalChange::NotUsed, 1, 0);
    drive("pm::ParameterLoading::on_request", case, len, || {
        let _ = loading.on_request(asdu, &known);
    });
    drive("pm::ParameterLoading::refuse", case, len, || {
        let _ = loading.refuse(asdu, &parameter);
    });
    let pm_controlling = pm::ParameterLoading::controlling(pm::LocalChange::NotUsed, 1, 0);
    drive("pm::ParameterLoading::on_response", case, len, || {
        let _ = pm_controlling.on_response(asdu, &known);
    });

    let transmission = tx::Transmission::controlling(1, 0);
    drive("tx::Transmission::on_response", case, len, || {
        let _ = transmission.on_response(asdu, &known);
    });

    let read = rd::Read::controlled(true, 1, 0);
    drive("rd::Read::on_request", case, len, || {
        let _ = read.on_request(asdu, &known, &source);
    });
    let rd_controlling = rd::Read::controlling(true, 1, 0);
    drive("rd::Read::on_response", case, len, || {
        let _ = rd_controlling.on_response(asdu, &known);
    });
    // `rd::answer` and `Read::answer` take the **returned object** as well as the
    // received command, so the corpus decodes the minimal `M_SP_NA_1` frame into
    // one: `M_SP_NA_1` is the first of `rd`'s `RETURNED_TYPES`, and the minimal
    // frame's information object address is not the irrelevant `<0>`. The object
    // is built outside the `drive` call so the decode's own allocation is not
    // charged to the case.
    let returnable = decode_asdu::<MSpNa1>(&minimal_asdu(
        TypeId::MSpNa1,
        layout_for(TypeId::MSpNa1).expect("the M_SP_NA_1 layout is in the table"),
    ))
    .expect("the minimal M_SP_NA_1 decodes");
    let object = &returnable[0];
    drive("rd::answer", case, len, || {
        let _ = rd::answer(object, asdu, 1);
    });
    drive("rd::Read::answer", case, len, || {
        let _ = read.answer(object, asdu);
    });
    drive("rd::refusal", case, len, || {
        let _ = rd::refusal(asdu, &known, 1);
    });

    drive_test_and_file_transfer(case, asdu, known);

    if let Some(header) = header {
        drive("dispatch::not_implemented", case, len, || {
            let _ = iec104::dispatch::not_implemented(&header, asdu, 1, AddressSizes::CONVENTIONAL);
        });
        drive("asdu::unknown::classify", case, len, || {
            let _ = iec104::asdu::classify(&known);
        });
        drive("asdu::unknown::discard_reason", case, len, || {
            let _ = iec104::asdu::discard_reason(&header, &known);
        });
        let body = &asdu[Header::LEN.min(asdu.len())..];
        drive("asdu::unknown::mirror_reply", case, len, || {
            let _ = iec104::asdu::mirror_reply(&header, &known, body);
        });
    }

    drive_sized_app_entry_points(case, asdu, object);
}

/// Drives the redundancy group, interrogation and counter interrogation
/// entry points on one ASDU.
fn drive_group_and_interrogations(case: &str, asdu: &[u8], known: Known, source: &NoData) {
    let len = asdu.len();
    if let Ok(mut group) =
        redundancy::RedundancyGroup::new(link::Role::Controlled, vec![LinkParams::default()])
    {
        let now = std::time::Instant::now();
        let _ = group.on_connection_established(0, now);
        let _ = group.on_frame_at(0, Apci::U(UFunction::StartDtAct), now);
        drive(
            "redundancy::RedundancyGroup::send_user_data_at",
            case,
            len,
            || {
                let _ = group.send_user_data_at(0, asdu, now);
            },
        );
    }

    let mut interrogation = gi::Interrogation::controlled(gi::ReActivation::Continue, 1, 0);
    drive("gi::Interrogation::on_request", case, len, || {
        let _ = interrogation.on_request(asdu, &known, source);
    });
    let mut gi_controlling = gi::Interrogation::controlling(gi::SecondActivation::Locked, 1, 0);
    drive("gi::Interrogation::on_response", case, len, || {
        let _ = gi_controlling.on_response(asdu, &known);
    });

    let mut counters =
        ci::CounterInterrogation::controlled(ci::CounterMode::FreezeAndTransmit, 1, 0);
    drive("ci::CounterInterrogation::on_request", case, len, || {
        let _ = counters.on_request(asdu, &known, source);
    });
    let mut ci_controlling =
        ci::CounterInterrogation::controlling(ci::CounterMode::FreezeAndTransmit, 1, 0);
    drive("ci::CounterInterrogation::on_response", case, len, || {
        let _ = ci_controlling.on_response(asdu, &known);
    });
}

/// Drives the command transmission entry points on one ASDU.
fn drive_commands(case: &str, asdu: &[u8], known: Known) {
    let len = asdu.len();
    let mut commands = ct::CommandTransmission::controlled(
        ct::CommandMode::Direct,
        ct::CommandSet::Untagged,
        ct::Termination::All,
        1,
        0,
    );
    drive("ct::CommandTransmission::on_request", case, len, || {
        let _ = commands.on_request(asdu, &known);
    });
    drive("ct::CommandTransmission::refuse", case, len, || {
        let _ = commands.refuse(asdu);
    });
    let mut supervised = ct::CommandTransmission::controlled(
        ct::CommandMode::SelectAndExecute,
        ct::CommandSet::Tagged,
        ct::Termination::All,
        1,
        0,
    )
    .with_select_timeout(std::time::Duration::from_secs(10))
    .with_max_command_delay(std::time::Duration::from_secs(5));
    let now = std::time::Instant::now();
    drive("ct::CommandTransmission::on_request_at", case, len, || {
        let _ = supervised.on_request_at(asdu, &known, now, Some(Cp56Time2a::default()));
    });
    drive("ct::decode_command", case, len, || {
        let _ = ct::decode_command(asdu);
    });
    let narrow = AddressSizes::new(1, 2, false).expect("a valid profile");
    drive("ct::decode_command_with", case, len, || {
        let _ = ct::decode_command_with(asdu, narrow);
    });
    let mut command_controlling = ct::CommandTransmission::controlling(
        ct::CommandMode::Direct,
        ct::CommandSet::Untagged,
        ct::Termination::All,
        1,
        0,
    );
    drive("ct::CommandTransmission::on_response", case, len, || {
        let _ = command_controlling.on_response(asdu, &known);
    });
}

/// Drives the test procedure and file transfer entry points on one ASDU.
fn drive_test_and_file_transfer(case: &str, asdu: &[u8], known: Known) {
    let len = asdu.len();
    let test_procedure = ts::TestProcedure::controlled(ts::Selection::default(), 1, 0);
    drive("ts::TestProcedure::on_request", case, len, || {
        let _ = test_procedure.on_request(asdu, &known);
    });
    let ts_controlling = ts::TestProcedure::controlling(ts::Selection::default(), 1, 0);
    let sent = ts::Command::Untagged { fbp: Fbp };
    drive("ts::TestProcedure::on_response", case, len, || {
        let _ = ts_controlling.on_response(asdu, &known, sent);
    });
    // The test procedure's two answer entry points (5-101 cl.7.2.4's *"the
    // specific defined COMMON ADDRESS (station address)"*): `answer` reads the
    // received command, so the instance must have the procedure **marked used**
    // or `TestProcedure::answer` returns `FunctionNotUsed` before it parses.
    let answering = ts::TestProcedure::controlled(ts::Selection::default().with_used(true), 1, 0);
    drive("ts::answer", case, len, || {
        let _ = ts::answer(asdu, 1);
    });
    drive("ts::refusal", case, len, || {
        let _ = ts::refusal(asdu, &known, 1);
    });
    drive("ts::TestProcedure::answer", case, len, || {
        let _ = answering.answer(asdu);
    });

    let file_transfer = ft::FileTransferProcedure::controlled(ft::Selection::BOTH, 1, 0);
    drive("ft::FileTransferProcedure::on_asdu", case, len, || {
        let _ = file_transfer.on_asdu(asdu, &known);
    });
    // `decode_frame` and the segment parser are public reception entry points of
    // their own: `on_asdu` reaches them along the family path, but driving them
    // directly is what covers the type ids and prefixes `on_asdu` never decodes.
    drive("ft::decode_frame", case, len, || {
        let _ = ft::decode_frame(asdu);
    });
    drive("asdu::layout::file::Segment::parse", case, len, || {
        let _ = Segment::parse(asdu);
    });
    // `on_answer` compares the arriving frame against the request it answers, so
    // it needs a `Frame`. The minimal directory decodes to one, and a directory
    // is compared by information object address alone (see `ft::answers`), which
    // is what keeps the answer path reachable for every case.
    let sent_frame = ft::decode_frame(&minimal_asdu(
        TypeId::FDrTa1,
        layout_for(TypeId::FDrTa1).expect("the directory has a layout"),
    ))
    .expect("the minimal directory decodes to a frame");
    drive("ft::FileTransferProcedure::on_answer", case, len, || {
        let _ = file_transfer.on_answer(asdu, &known, &sent_frame);
    });
}

/// The same reception paths under a narrow address profile (one-octet common
/// address, two-octet object address, no originator), so the `_with` entry
/// points and the procedures' `with_address_sizes` paths see every case too.
fn drive_sized_app_entry_points(
    case: &str,
    asdu: &[u8],
    object: &iec104::asdu::LayoutObject<MSpNa1>,
) {
    let len = asdu.len();
    let sizes = AddressSizes::new(1, 2, false).expect("a valid profile");
    let header = Header::parse_with(asdu, sizes).ok();
    let known = header.map_or(Known::NOTHING, |header| {
        Known::standard(&header, true, true)
    });
    let source = NoData;

    drive("init::on_asdu_with", case, len, || {
        let _ = init::on_asdu_with(asdu, &known, sizes);
    });
    drive("rd::answer_with", case, len, || {
        let _ = rd::answer_with(object, asdu, 1, sizes);
    });
    drive("rd::refusal_with", case, len, || {
        let _ = rd::refusal_with(asdu, &known, 1, sizes);
    });
    drive("ts::answer_with", case, len, || {
        let _ = ts::answer_with(asdu, 1, sizes);
    });
    drive("ts::refusal_with", case, len, || {
        let _ = ts::refusal_with(asdu, &known, 1, sizes);
    });
    drive("ft::decode_frame_with", case, len, || {
        let _ = ft::decode_frame_with(asdu, sizes);
    });
    if let Some(header) = header {
        let body = &asdu[sizes.header_len().min(asdu.len())..];
        drive("asdu::unknown::mirror_reply_with", case, len, || {
            let _ = iec104::asdu::mirror_reply_with(&header, &known, body, sizes);
        });
        drive("asdu::unknown::mirror_frame", case, len, || {
            let _ = iec104::asdu::mirror_frame(
                &header,
                asdu,
                iec104::asdu::Unspecified::CommonAddress,
                1,
                sizes,
            );
        });
    }

    // Every procedure's reception path with the profile set on the instance.
    let mut gi =
        gi::Interrogation::controlled(gi::ReActivation::Continue, 1, 0).with_address_sizes(sizes);
    drive("gi::Interrogation::on_request", case, len, || {
        let _ = gi.on_request(asdu, &known, &source);
    });
    let mut ci = ci::CounterInterrogation::controlled(ci::CounterMode::FreezeAndTransmit, 1, 0)
        .with_address_sizes(sizes);
    drive("ci::CounterInterrogation::on_request", case, len, || {
        let _ = ci.on_request(asdu, &known, &source);
    });
    let cs = cs::ClockSynchronisation::controlled(1, 0).with_address_sizes(sizes);
    drive("cs::ClockSynchronisation::on_request", case, len, || {
        let _ = cs.on_request(asdu, &known, Cp56Time2a::default());
    });
    let read = rd::Read::controlled(true, 1, 0).with_address_sizes(sizes);
    drive("rd::Read::on_request", case, len, || {
        let _ = read.on_request(asdu, &known, &source);
    });
    let test = ts::TestProcedure::controlled(ts::Selection::default().with_used(true), 1, 0)
        .with_address_sizes(sizes);
    drive("ts::TestProcedure::on_request", case, len, || {
        let _ = test.on_request(asdu, &known);
    });
    let ft =
        ft::FileTransferProcedure::controlled(ft::Selection::BOTH, 1, 0).with_address_sizes(sizes);
    drive("ft::FileTransferProcedure::on_asdu", case, len, || {
        let _ = ft.on_asdu(asdu, &known);
    });
    let mut commands = ct::CommandTransmission::controlled(
        ct::CommandMode::SelectAndExecute,
        ct::CommandSet::Untagged,
        ct::Termination::All,
        1,
        0,
    )
    .with_address_sizes(sizes);
    drive("ct::CommandTransmission::on_request", case, len, || {
        let _ = commands.on_request(asdu, &known);
    });
    let loading =
        pm::ParameterLoading::controlled(pm::LocalChange::NotUsed, 1, 0).with_address_sizes(sizes);
    drive("pm::ParameterLoading::on_request", case, len, || {
        let _ = loading.on_request(asdu, &known);
    });
    let transmission = tx::Transmission::controlling(1, 0).with_address_sizes(sizes);
    drive("tx::Transmission::on_response", case, len, || {
        let _ = transmission.on_response(asdu, &known);
    });
}

// -------------------------------------------------------- the element parsers

/// Every element type with a `pub fn parse`, and the count the corpus claims.
///
/// Adding an element parser to `src/asdu/elements/` without adding it here is
/// what the count assertion below is for; the list *is* the corpus's claim.
macro_rules! element_parsers {
    ($($ty:ty),* $(,)?) => {
        /// Every element parser the corpus drives, by type name.
        const ELEMENT_PARSER_NAMES: &[&str] = &[$(stringify!($ty)),*];

        /// Drives `T::parse` over every prefix of a `T::LEN`-octet buffer and
        /// then every one of the 256 octet values at every position. Returns
        /// the number of cases driven.
        #[allow(clippy::needless_range_loop)]
        fn drive_element_parsers() -> usize {
            let mut drives = 0usize;
            $(
                {
                    const LEN: usize = <$ty>::LEN;
                    let mut buf = vec![0u8; LEN];
                    for (index, octet) in buf.iter_mut().enumerate() {
                        *octet = ((index as u8) << 4) | 0x03;
                    }
                    for cut in 0..=LEN {
                        drives += 1;
                        drive(
                            "elements::parse",
                            stringify!($ty),
                            cut,
                            || { let _ = <$ty>::parse(&buf[..cut]); },
                        );
                    }
                    for position in 0..LEN {
                        let original = buf[position];
                        for value in 0u16..=255 {
                            drives += 1;
                            buf[position] = value as u8;
                            drive(
                                "elements::parse",
                                stringify!($ty),
                                LEN,
                                || { let _ = <$ty>::parse(&buf); },
                            );
                        }
                        buf[position] = original;
                    }
                }
            )*
            drives
        }
    };
}

element_parsers!(
    Qoc, Sco, Dco, Rco, Qos, Frq, Srq, Scq, Lsq, Afq, Nof, Nos, Lof, Los, Chs, Sof, Coi, Qoi, Qcc,
    Qpm, Qpa, Qrp, Qds, Siq, Diq, Qdp, Vti, Sep, Spe, Oci, Bsi, Scd, Cp56Time2a, Cp24Time2a,
    Cp16Time2a, Nva, Sva, R32, Bcr, Fbp, Tsc,
);

// ------------------------------------------------------------- the corpus

/// Every legal address profile the checked constructor accepts: 1 or 2 CA
/// octets × 1, 2 or 3 IOA octets × originator present or absent.
///
/// The three widths are *"system-specific parameter[s]"* of 5-104 cl.9.5
/// (index 98): *"One octet"* / *"Two octets"* for the common address,
/// *"One octet"* / *"Structured"* + *"Two octets"* / *"Unstructured"* +
/// *"Three octets"* for the information object address (the two words are the
/// sheet's names for those forms), *"One octet"* / *"Two octets (with
/// originator address)"* for the cause. 5-101 cl.7.2.4 (index 42) and
/// cl.7.2.5 (index 43) call each length *"a parameter which is fixed per
/// system"*. **12** combinations.
fn every_profile() -> Vec<AddressSizes> {
    let mut profiles = Vec::new();
    for common_address_octets in 1..=2u8 {
        for information_object_address_octets in 1..=3u8 {
            for originator_address in [false, true] {
                profiles.push(
                    AddressSizes::new(
                        common_address_octets,
                        information_object_address_octets,
                        originator_address,
                    )
                    .expect("the sweep's three widths are the legal ones"),
                );
            }
        }
    }
    profiles
}

/// The minimal well-formed ASDU of one laid-out type: a valid 6-octet header,
/// one information object, and an element of the type's own length. The
/// element is all zero except for the `FBP` of the two test commands (see
/// [`minimal_asdu_with`]); the geometry is what is under test.
fn minimal_asdu(type_id: TypeId, layout: &Layout) -> Vec<u8> {
    minimal_asdu_with(type_id, layout, AddressSizes::CONVENTIONAL)
}

/// The same minimal frame built under a configured profile: the header is
/// [`AddressSizes::header_len`] octets, the address
/// [`AddressSizes::information_object_address_octets`] octets (the originator
/// octet is only present when the profile carries one: 104 cl.9.5's *"Two
/// octets (with originator address)"*).
fn minimal_asdu_with(type_id: TypeId, layout: &Layout, sizes: AddressSizes) -> Vec<u8> {
    let header = Header {
        type_id,
        sequence: matches!(layout.sequence, Sequence::Required),
        count: 1,
        cause: Cause::Spontaneous,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
    };
    let mut asdu = Vec::new();
    header
        .encode_with(&mut asdu, sizes)
        .expect("the minimal frame's CA 1 fits every profile's common address");
    write_ioa_with(&mut asdu, 1, sizes);
    if layout.variable {
        // `F_SG_NA_1`: NOF (2), NOS (1), LOS (1), one payload octet.
        asdu.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0xAA]);
    } else {
        asdu.resize(asdu.len() + layout.element_len, 0x00);
        // `FBP` has exactly one legal wire value (5-101 cl.7.2.6.14's
        // `UI16[1..16]<55AAH>`), so for the two test commands that carry it
        // (types 104 and 107, whose layouts name it first) the minimal frame
        // writes `AA 55`, low octet first, instead of two zero octets.
        if matches!(layout.type_id, TypeId::CTsNa1 | TypeId::CTsTa1) {
            let second =
                sizes.header_len() + usize::from(sizes.information_object_address_octets()) + 1;
            if let Some(first) = asdu.get_mut(second - 1) {
                *first = 0xAA;
            }
            if let Some(second) = asdu.get_mut(second) {
                *second = 0x55;
            }
        }
    }
    asdu
}

/// Every laid-out type of the three tables, in one list.
fn laid_out() -> Vec<(TypeId, &'static Layout)> {
    MONITOR_LAYOUTS
        .iter()
        .chain(CONTROL_LAYOUTS)
        .chain(FILE_LAYOUTS)
        .map(|layout| (layout.type_id, layout))
        .collect()
}

/// 104 cl.5, index 26 (printed 25): *"START 68H defines the point of start
/// within the data stream."* and *"The length of the APDU defines the length of
/// the body of the APDU, which consists of the four control field octets of the
/// APCI plus the ASDU. … The maximum length of the ASDU is limited to 249
/// because the maximum value of the field length of APDU is 253 (`APDUmax` = 255
/// minus start and length octet) and the length of the control field is 4
/// octets."*
///
/// Seeds: Beckhoff samples 1–3, `STARTDT act`, the Clarke/Reynders/Wright
/// stream and the committed real-peer capture (see their definitions above).
#[test]
fn every_prefix_of_every_seed_is_a_typed_error() {
    // The clause's own bound, for all 256 length octets: 4..=253 is a frame,
    // anything else is a typed error and never a length to trust.
    for length in 0u16..=255 {
        match apci::apdu_len(apci::START, length as u8) {
            Ok(total) => {
                assert!(
                    (u16::from(apci::MIN_LENGTH)..=u16::from(apci::MAX_LENGTH)).contains(&length),
                    "apdu_len accepted length {length}"
                );
                assert_eq!(total, 2 + length as usize);
            }
            Err(ParseError::BadLength(got)) => {
                assert_eq!(got, length as u8);
                assert!(
                    !(u16::from(apci::MIN_LENGTH)..=u16::from(apci::MAX_LENGTH)).contains(&length),
                    "apdu_len refused length {length}"
                );
            }
            Err(other) => panic!("apdu_len(0x68, {length}) gave {other:?}"),
        }
    }
    assert_eq!(apci::apdu_len(0x00, 4), Err(ParseError::BadStart(0x00)));

    let mut prefix_inputs = 0usize;
    for seed in SEEDS {
        for cut in 0..=seed.bytes.len() {
            prefix_inputs += 1;
            let case = format!("{} cut at {cut}", seed.name);
            let prefix = &seed.bytes[..cut];
            drive_frame_entry_points(&case, prefix);

            let parsed = apci::parse(prefix);
            match (seed.apdu, parsed) {
                (Some(total), Ok((_, used))) => {
                    assert_eq!(cut, seed.bytes.len(), "{case}: a short prefix parsed");
                    assert_eq!(used, total, "{case}: the whole seed parses to {used}");
                }
                (Some(total), Err(error)) => {
                    assert!(
                        cut < seed.bytes.len(),
                        "{case}: the whole seed failed: {error:?}"
                    );
                    let wanted = if cut < 2 { 2 } else { total };
                    match error {
                        ParseError::Incomplete { needed, have } => {
                            assert_eq!(have, cut, "{case}");
                            assert_eq!(needed, wanted, "{case}");
                        }
                        other => panic!("{case}: expected Incomplete, got {other:?}"),
                    }
                }
                (None, Ok((_, used))) => assert!(used <= cut, "{case}: consumed beyond the buffer"),
                (None, Err(_)) => {}
            }

            // The ASDU-level entry points, driven on the payload the frame
            // carries (or on the raw octets when framing refused them).
            let asdu: &[u8] = match apci::parse(prefix) {
                Ok((apdu, _)) => apdu.asdu,
                Err(_) => prefix,
            };
            drive_app_entry_points(&case, asdu);
        }
    }

    assert_eq!(
        prefix_inputs, 165,
        "the six seeds expand to 165 prefix inputs (17 + 55 + 7 + 7 + 62 + 17)"
    );

    // 104 cl.5, index 28 (printed 27): "I format APDUs always contain an ASDU."
    // A length of 4 leaves room for the control field alone, so an I-format
    // frame that claims one is refused rather than read past its own end.
    let short_i = [0x68, 0x04, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        apci::parse(&short_i),
        Err(ParseError::IFormatWithoutAsdu(0x04))
    );
}

/// 104 cl.5, index 28 (printed 27): *"Control field octet 1 bit 1 = 0 defines
/// the I format. I format APDUs always contain an ASDU."*; *"Control field
/// octet 1 bit 1 = 1 and bit 2 = 0 defines the S format. S format APDUs consist
/// of the APCI only."*; *"Control field octet 1 bit 1 = 1 and bit 2 = 1 defines
/// the U format. U format APDUs consist of the APCI only."*; *"Only one
/// function – TESTFR, STOPDT or STARTDT – may be active at the same time."*
///
/// The flip sweep over [`FLIP_SEEDS`], named so an edit to any of them is
/// visible: Beckhoff sample 1 (the counter-interrogation command), Beckhoff
/// sample 3 (the S-format ack), `STARTDT act` (a U-format frame), the committed
/// real-peer capture `interop::CAPTURE_PEER_ACT_CON`, and one hand-built minimal
/// `C_IC_NA_1` frame (see their definitions above). Every one of the 256 octet
/// values at every position of each. No value may panic, and every accepted
/// frame must still obey the clause: an S- or U-format frame carries no ASDU.
#[test]
fn every_octet_position_flipped_is_a_typed_error() {
    let mut flip_inputs = 0usize;
    for seed in FLIP_SEEDS {
        for position in 0..seed.bytes.len() {
            let mut buf = seed.bytes.to_vec();
            for value in 0u16..=255 {
                flip_inputs += 1;
                buf[position] = value as u8;
                let case = format!("{} position {position} = {value:#04X}", seed.name);
                drive_frame_entry_points(&case, &buf);

                if let Ok((apdu, used)) = apci::parse(&buf) {
                    assert!(used <= buf.len(), "{case}: consumed beyond the buffer");
                    match apdu.apci {
                        Apci::I { .. } => assert!(
                            !apdu.asdu.is_empty(),
                            "{case}: an I-format APDU carried no ASDU"
                        ),
                        Apci::S { .. } | Apci::U(_) => assert!(
                            apdu.asdu.is_empty(),
                            "{case}: an S/U-format APDU carried {} ASDU octets",
                            apdu.asdu.len()
                        ),
                    }
                    if let Apci::U(function) = apdu.apci {
                        // One function per frame: the code is exactly one of
                        // the six, which the decoder already enforced.
                        let code = function.code();
                        assert_eq!(code.count_ones(), 3, "{case}: U code {code:#04X}");
                    }
                }

                // The application layer sees the same octets.
                let asdu: &[u8] = match apci::parse(&buf) {
                    Ok((apdu, _)) => apdu.asdu,
                    Err(_) => &buf,
                };
                drive_app_entry_points(&case, asdu);
            }
        }
    }
    assert_eq!(
        flip_inputs, 15_360,
        "the five flip seeds hold 60 positions at 256 values each"
    );
}

/// 101 cl.7.2.2, index 34 (printed 33): *"VARIABLE STRUCTURE QUALIFIER :=
/// CP8{number, SQ}"*; *"number=N := UI7[1..7]<0..127>"*; *"<0> := ASDU contains
/// no INFORMATION OBJECT"*. And 101 cl.7.2.5, index 44 (printed 43):
/// *"INFORMATION OBJECT ADDRESS := UI24[1..24]<0..16777215>"*.
///
/// One minimal well-formed frame per laid-out type, built through
/// [`layout_for`] / [`element_len`] rather than stored, so every layout and
/// every element parser of the type is reached through the public decode paths.
#[test]
fn every_laid_out_type_has_a_minimal_frame_the_corpus_drives() {
    assert_eq!(MONITOR_LAYOUTS.len(), 32, "clause 7.3.1 monitor layouts");
    assert_eq!(CONTROL_LAYOUTS.len(), 27, "clauses 7.3.2–7.3.5 layouts");
    assert_eq!(FILE_LAYOUTS.len(), 8, "clause 7.3.6 layouts");

    let laid_out = laid_out();
    assert_eq!(laid_out.len(), 67, "the three tables hold 67 types");
    let mut seen = Vec::new();
    for (type_id, layout) in &laid_out {
        assert!(
            !seen.contains(type_id),
            "{type_id:?} appears in two layout tables"
        );
        seen.push(*type_id);
        // `layout_for` is the one lookup over all three tables.
        let found = layout_for(*type_id).unwrap_or_else(|| panic!("no layout for {type_id:?}"));
        assert_eq!(
            found, *layout,
            "{type_id:?}: the lookup disagrees with the table"
        );

        let asdu = minimal_asdu(*type_id, layout);
        let case = format!("minimal {type_id:?}");
        drive_typed_decode(&case, &asdu);
        assert_eq!(
            typed_decode(*type_id, &asdu, AddressSizes::CONVENTIONAL),
            Some(Ok(1)),
            "{case}: a minimal frame of one object must decode to one object"
        );
        drive_frame_entry_points(&case, &asdu);
    }

    // The variable-length type has no `element_len` (7.3.6.6's "Octet 1 …
    // Octet n") and is read through its own entry point.
    assert_eq!(element_len(TypeId::FSgNa1), None);
    assert_eq!(element_len(TypeId::Other(0)), None);
    assert_eq!(element_len(TypeId::MMeNb1), Some(3));
    assert_eq!(element_len(TypeId::FDrTa1), Some(13));

    // The header's own geometry: a `count` above 127 cannot be expressed,
    // because the VSQ octet's top bit is `SQ`, not a number bit.
    let high = Header::parse(&[0xFF, 0xFF, 0x00, 0x00, 0x01, 0x00]).expect("six octets");
    assert!(high.sequence, "bit 7 of the VSQ is SQ");
    assert_eq!(high.count, 127, "UI7[1..7] caps the object count at 127");
    // The IOA is three octets: two are a typed short read, never an index.
    assert!(iec104::asdu::read_ioa(&[0x00, 0x00]).is_err());
    assert_eq!(iec104::asdu::read_ioa(&[0x00, 0x00, 0x00]), Ok(0));
    assert_eq!(iec104::asdu::read_ioa(&[0xFF, 0xFF, 0xFF]), Ok(0x00FF_FFFF));
}

/// The width sweep over every legal address profile.
///
/// 104 cl.9.5 (index 98) lists the common address (*"One octet"* / *"Two
/// octets"*), the information object address (*"One octet"* / *"Two octets"* /
/// *"Three octets"*) and the cause of transmission (*"One octet"* / *"Two octets
/// (with originator address). Originator address is set to zero if not used"*)
/// as *"system-specific parameter"*; 5-101 cl.7.2.4 (index 42) and cl.7.2.5
/// (index 43) call each length *"a parameter which is fixed per system"*.
///
/// Every one of the twelve combinations the checked constructor accepts carries
/// a minimal frame of **every** laid-out type. The frame round-trips through
/// [`decode_asdu_with`] / [`decode_segment_with`] to the values that went in
/// (the address is asserted as the object's own IOA, which a corpus that only
/// bounds panics and allocations would not catch if the width were misread),
/// and every proper prefix of that frame is a **typed error**, never a panic and
/// never an over-allocation (`drive`'s bound).
#[test]
fn every_address_profile_round_trips_a_minimal_frame_of_every_type() {
    let profiles = every_profile();
    assert_eq!(
        profiles.len(),
        12,
        "1|2 CA octets × 1|2|3 IOA octets × originator present|absent"
    );

    let mut cases = 0usize;
    let mut prefixes = 0usize;
    let mut typed_errors = 0usize;
    for (type_id, layout) in &laid_out() {
        let entry = match type_id {
            TypeId::FSgNa1 => "asdu::layout::file::decode_segment_with",
            _ => "asdu::layout::decode_asdu_with",
        };
        for sizes in &profiles {
            cases += 1;
            let asdu = minimal_asdu_with(*type_id, layout, *sizes);
            let case = format!("minimal {type_id:?} {sizes:?}");
            assert_eq!(
                asdu.len(),
                sizes.header_len()
                    + usize::from(sizes.information_object_address_octets())
                    + if layout.variable {
                        3 + 1 + 1
                    } else {
                        layout.element_len
                    },
                "{case}: the frame's own geometry"
            );

            let decoded = drive(entry, &case, asdu.len(), || {
                typed_decode(*type_id, &asdu, *sizes)
            });
            assert_eq!(
                decoded,
                Some(Ok(1)),
                "{case}: a minimal frame of one object must decode to one object"
            );

            // The header round-trips through the profile's own width.
            let header = Header::parse_with(&asdu, *sizes).expect("the built header parses");
            assert_eq!(header.type_id, *type_id, "{case}");
            assert_eq!(header.cause, Cause::Spontaneous, "{case}");
            assert_eq!(header.count, 1, "{case}");
            assert_eq!(header.common_address, 1, "{case}");
            assert_eq!(
                header.originator, 0,
                "{case}: a profile without the originator octet reports zero (104 cl.9.5)"
            );

            // The object's address is read at the profile's own width.
            let body = &asdu[sizes.header_len()..];
            assert_eq!(
                read_ioa_with(body, *sizes),
                Ok(1),
                "{case}: the object's IOA"
            );

            // Every proper prefix is a typed error, with `<125>`'s one documented
            // qualification: its element length comes from the ASDU's own length
            // (figure 88's `Octet 1 … Octet n`), so a prefix that still holds the
            // four-octet segment prefix is a *shorter payload* this geometry
            // layer reads literally (the `LOS`-vs-payload rule is 5-101
            // cl.7.2.6.36's and lives in `src/ft.rs`). Every prefix **below**
            // that boundary is a typed error, and the boundary itself is
            // asserted rather than assumed.
            let boundary = sizes.header_len()
                + usize::from(sizes.information_object_address_octets())
                + Segment::PREFIX_LEN;
            let mut prefix_cases = 0usize;
            for cut in 0..asdu.len() {
                prefix_cases += 1;
                let got = drive(entry, &format!("{case} cut at {cut}"), cut, || {
                    typed_decode(*type_id, &asdu[..cut], *sizes)
                });
                if layout.variable && cut >= boundary {
                    assert_eq!(
                        got,
                        Some(Ok(1)),
                        "{case} cut at {cut}: a `<125>` prefix above the segment prefix \
                         is a shorter payload the geometry layer reads literally"
                    );
                } else {
                    assert!(
                        matches!(got, Some(Err(_))),
                        "{case} cut at {cut} decoded to {got:?}"
                    );
                    typed_errors += 1;
                }
            }
            assert_eq!(
                prefix_cases,
                asdu.len(),
                "{case}: every proper prefix of the frame"
            );
            prefixes += prefix_cases;
        }
    }
    assert_eq!(cases, 67 * 12, "67 laid-out types × 12 profiles");
    // Every case drives at least one typed error (the empty prefix, which no
    // header can parse), so this is a real count and not a `> 0` on a sum that
    // could not be zero.
    assert!(
        typed_errors >= cases,
        "{typed_errors} typed errors over {cases} cases and {prefixes} prefixes"
    );
}

/// 101 cl.7.2.6, indices 46–59 (printed 45–58): the 40 information elements,
/// plus 104 clause 8.8's `TSC`. For each `parse`, every short prefix must be a
/// typed error (the crate's own rule for network input), and every octet value
/// at every position of a full element must be a value, not a panic.
#[test]
fn every_element_parser_reports_short_prefixes_as_typed_errors() {
    // The element list is checked against `src/asdu/elements/` at test time: an
    // `impl` block that gains a `pub fn parse` and is not named here fails.
    let derived = derived_element_parsers();
    let listed: BTreeSet<&str> = ELEMENT_PARSER_NAMES.iter().copied().collect();
    let expected: BTreeSet<&str> = derived.iter().map(String::as_str).collect();
    assert_eq!(
        expected, listed,
        "the element parsers `src/asdu/elements/` exposes and the corpus's list disagree"
    );
    assert_eq!(
        listed.len(),
        41,
        "the corpus claims every element parser of the crate"
    );
    assert_eq!(
        drive_element_parsers(),
        18_031,
        "41 parsers: 111 prefix cases (Σ LEN + 1) and 17 920 flips (Σ LEN × 256)"
    );
}

/// 104 cl.5, index 26 (printed 25): *"The maximum length of the ASDU is limited
/// to 249 because the maximum value of the field length of APDU is 253 (`APDUmax`
/// = 255 minus start and length octet) and the length of the control field is 4
/// octets."* No octet the length field can carry may size an allocation on its
/// own: the length octet flip is the case this asserts, and the same bound is
/// re-checked on a header whose `count` is the 127-object `UI7` ceiling.
#[test]
fn a_wire_length_cannot_size_an_allocation() {
    let mut length_inputs = 0usize;
    for length in 0u16..=255 {
        length_inputs += 1;
        // Start octet plus the length field plus the largest body the field
        // could ever promise (253 octets of junk).
        let mut buf = vec![apci::START, length as u8];
        buf.extend(std::iter::repeat_n(0xFF, usize::from(apci::MAX_LENGTH)));
        let case = format!("length octet {length}");
        drive_frame_entry_points(&case, &buf);
        let asdu: &[u8] = match apci::parse(&buf) {
            Ok((apdu, _)) => apdu.asdu,
            Err(_) => &buf,
        };
        drive_app_entry_points(&case, asdu);
    }

    // The worst case the layout layer can be handed: a 6-octet header whose
    // VSQ claims 127 objects. The count is a `u8` read straight off the wire
    // and `decode_asdu` takes `Vec::with_capacity(usize::from(header.count))`
    // from it *before* a single object is read, so this (not the 249-octet
    // frame) is the allocation the bound of `drive` exists for. It stays
    // bounded because the count is a `UI7` and the object type is fixed.
    let header_only = vec![TypeId::MMeNb1.to_u8(), 0x7F, 0x03, 0x00, 0x01, 0x00];
    assert_eq!(header_only.len(), Header::LEN);
    let decoded = drive(
        "asdu::layout::decode_asdu",
        "127-object header with no body",
        header_only.len(),
        || typed_decode(TypeId::MMeNb1, &header_only, AddressSizes::CONVENTIONAL),
    );
    assert!(
        matches!(decoded, Some(Err(_))),
        "127 claimed objects over no body must be a typed error, got {decoded:?}"
    );
    // The time-tagged directory is the widest object of all (13 octets): the
    // same claim, allocated for the same way. Measured, this is the corpus's
    // largest allocation: 3 711 octets from a 6-octet input, 88.5 % of the
    // 4 192-octet bound `drive` computes. `ALLOC_SLACK` carries this case.
    let wide = vec![TypeId::FDrTa1.to_u8(), 0xFF, 0x03, 0x00, 0x01, 0x00];
    let decoded = drive(
        "asdu::layout::decode_asdu",
        "127-object F_DR_TA_1 header with no body",
        wide.len(),
        || typed_decode(TypeId::FDrTa1, &wide, AddressSizes::CONVENTIONAL),
    );
    assert!(matches!(decoded, Some(Err(_))), "got {decoded:?}");

    // The bound of `ALLOC_SLACK` named by the struct that fills it: the widest
    // wire-sized allocation `src/asdu/layout/mod.rs` can take is 127 of these,
    // so growing `LayoutObject<FDrTa1>` fails here, in the struct's own name,
    // rather than as a spurious "allocated N octets" on a six-octet input.
    let widest = 127 * std::mem::size_of::<LayoutObject<FDrTa1>>();
    assert!(
        widest <= ALLOC_SLACK,
        "127 LayoutObject<FDrTa1> values are {widest} octets, over ALLOC_SLACK ({ALLOC_SLACK})"
    );

    // The other end of the same bound: as many objects as a 249-octet ASDU can
    // hold: 40 `M_ME_NB_1` objects, 6 + 40 × 6 = 246 octets. The 41st would
    // need 252, past clause 5's ASDU limit, so 40 is the ceiling this asserts.
    let mut maximal = vec![TypeId::MMeNb1.to_u8(), 40, 0x03, 0x00, 0x01, 0x00];
    for object in 0..40u8 {
        maximal.extend_from_slice(&[object, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }
    assert_eq!(maximal.len(), 246);
    assert!(maximal.len() <= apci::MAX_ASDU);
    assert!(maximal.len() + 6 > apci::MAX_ASDU);
    assert_eq!(
        typed_decode(TypeId::MMeNb1, &maximal, AddressSizes::CONVENTIONAL),
        Some(Ok(40))
    );
    assert_eq!(length_inputs, 256, "every value the length octet can carry");
}

/// The corpus drives the application modules too. The seeds and one flip sweep
/// go through every reception entry point of `src/{init,gi,ci,cs,ct,pm,tx,rd,
/// ts,ft}.rs`, `src/link.rs` and `src/redundancy.rs`; 101 cl.7.2.5's *"ASDUs
/// with undefined values of INFORMATION OBJECT ADDRESS are discarded by
/// controlling stations"* is a decision these modules take, so a truncated or
/// adversarial ASDU must reach them as a typed error, never as a panic.
#[test]
fn the_application_entry_points_never_panic_on_adversarial_asdus() {
    for seed in SEEDS {
        for cut in 0..=seed.bytes.len() {
            let asdu: &[u8] = match apci::parse(&seed.bytes[..cut]) {
                Ok((apdu, _)) => apdu.asdu,
                Err(_) => &seed.bytes[..cut],
            };
            let case = format!("{} cut at {cut}", seed.name);
            drive_app_entry_points(&case, asdu);
        }
    }
    // A frame that is entirely the header, and one that is entirely junk:
    // both reach every module with no object area at all.
    for case in ["six octets of header", "one octet"] {
        let asdu: &[u8] = match case {
            "six octets of header" => &[0x64, 0x01, 0x06, 0x00, 0x01, 0x00],
            _ => &[0x64],
        };
        drive_app_entry_points(case, asdu);
    }
}

/// The corpus's completeness gate. It drives each entry point once (the codec
/// and ASDU layer on the committed capture, the element parsers over the whole
/// list, the layouts over the minimal frames, the application modules on the
/// capture's ASDU) and then fails if a name in [`ENTRY_POINTS`] was never
/// reached, or if a file of [`SOURCE_FILES`] exposes a reception entry point
/// the list does not name.
#[test]
fn the_corpus_drives_every_entry_point_it_lists() {
    let laid_out = laid_out();
    for (type_id, layout) in &laid_out {
        let asdu = minimal_asdu(*type_id, layout);
        drive_typed_decode(&format!("completeness {type_id:?}"), &asdu);
    }
    let _ = drive_element_parsers();
    drive_frame_entry_points("capture", CAPTURE_PEER_ACT_CON);
    let capture_asdu = match apci::parse(CAPTURE_PEER_ACT_CON) {
        Ok((apdu, _)) => apdu.asdu,
        Err(_) => CAPTURE_PEER_ACT_CON,
    };
    drive_app_entry_points("capture", capture_asdu);
    drive_link_entry_points("capture", Apci::U(iec104::apci::UFunction::StartDtAct));

    // The completeness mechanism: the set the corpus lists must equal the set
    // the scanned `src/` files say exists: every `pub fn` that takes `&[u8]`,
    // every `pub fn on_frame`, minus the senders, builders and checksum helpers of
    // `EXCLUDED_ENTRY_POINTS`, plus the octet-free accessors of
    // `ACCESSOR_ENTRY_POINTS`.
    let pub_fns = every_pub_fn_name();
    let mut derived = derived_reception_entry_points();
    for name in ACCESSOR_ENTRY_POINTS {
        assert!(
            pub_fns.contains(*name),
            "the corpus lists the accessor {name}, which no `src/` file defines as a `pub fn`"
        );
        derived.insert((*name).to_string());
    }
    let listed: BTreeSet<String> = ENTRY_POINTS
        .iter()
        .map(|name| (*name).to_string())
        .collect();
    let missing: Vec<&String> = derived.difference(&listed).collect();
    let extra: Vec<&String> = listed.difference(&derived).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "the entry-point list and `src/` disagree — in `src/` but not driven: {missing:?}; listed but absent from `src/`: {extra:?}"
    );

    REACHED.with(|reached| {
        let reached = reached.borrow();
        for name in ENTRY_POINTS {
            assert!(
                reached.iter().any(|driven| driven == name),
                "the corpus lists {name} but never drives it"
            );
        }
    });
}

/// The seeds are what the corpus is worth. This pins five of the seeds the
/// sweeps expand: Beckhoff *TF6500 `TwinCAT` 3 IEC 60870-5-10x* samples 1–3 (published
/// vendor APDUs, the same bytes `tests/wire_vectors.rs` pins), the committed
/// real-peer frame `interop::CAPTURE_PEER_ACT_CON`, and the raw byte stream
/// printed in Clarke/Reynders/Wright Appendix D `Communication 2`. A seed
/// edited into different bytes fails here rather than quietly weakening every
/// sweep above. None of the five is a frame a clause of the standard printed.
#[test]
fn the_seeds_are_the_documented_frames() {
    let (apdu, used) = apci::parse(BECKHOFF_1).expect("Beckhoff sample 1 parses");
    assert_eq!(used, 16);
    assert_eq!(
        apdu.apci,
        Apci::I {
            ns: SeqNo::new(2599),
            nr: SeqNo::new(62)
        }
    );
    let header = Header::parse(apdu.asdu).expect("sample 1 header");
    assert_eq!(header.type_id, TypeId::CCiNa1);
    assert_eq!(header.count, 1);
    assert_eq!(header.common_address, 12);

    let (apdu, used) = apci::parse(BECKHOFF_2).expect("Beckhoff sample 2 parses");
    assert_eq!(used, 54);
    let header = Header::parse(apdu.asdu).expect("sample 2 header");
    assert_eq!(header.type_id, TypeId::MMeNb1);
    assert_eq!(header.count, 7);
    assert_eq!(header.cause, Cause::Spontaneous);
    assert_eq!(apdu.asdu.len(), 6 + 7 * 6);

    let (apdu, used) = apci::parse(BECKHOFF_3).expect("Beckhoff sample 3 parses");
    assert_eq!(used, 6);
    assert_eq!(
        apdu.apci,
        Apci::S {
            nr: SeqNo::new(2623)
        }
    );
    assert_eq!(apdu.asdu, []);

    let (apdu, used) = apci::parse(CAPTURE_PEER_ACT_CON).expect("the capture parses");
    assert_eq!(used, 16);
    assert_eq!(
        apdu.apci,
        Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(1)
        }
    );

    // The raw stream is not one APDU: the framing layer must resynchronise,
    // never lose progress, whatever the octets say.
    let mut decoder = framed::Decoder::new();
    decoder.push(BOOK_STREAM);
    let mut frames = 0usize;
    while let Ok(Some(frame)) = decoder.next_frame() {
        frames += 1;
        assert_ne!(frame, []);
        assert!(
            frames <= BOOK_STREAM.len(),
            "the decoder yielded more frames than octets"
        );
    }
    assert!(
        decoder.resyncs() > 0,
        "the stream is 101 FT1.2 frames (`68 L L 68 … 16`, `E5` at the end), not 104 APDUs, so the decoder must resynchronise"
    );
}
