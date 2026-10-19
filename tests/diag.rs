//! The diagnostics layer (`iec104::diag`): the standard's own words for a frame.
//!
//! Every test names the clause it pins and quotes the sentence it read, with
//! the PDF page index (and printed page) where it stands. The sources are
//! 5-104 clause 5's figures 4–8, 5-101 clause 7.2.1/table 8, clause 7.2.3 with
//! figure 14 and table 14, clauses 7.2.4 and 7.2.5, and 5-104 clause 9.5 and
//! its time-out table.
//!
//! The printed lines are pinned as literals, because operators and
//! `docs/RUNBOOK.md` read them verbatim.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::string_slice
)]

use iec104::apci::{Apci, ParseError, SeqNo, UFunction};
use iec104::asdu::{AddressSizes, AsduError, Cause, Discard, Header, TypeId, Unspecified};
use iec104::diag::{self, Error};
use iec104::params::LinkParams;

#[path = "interop/mod.rs"]
mod interop;

/// A header with the conventional profile's widths and the fields a caller
/// hands in. Individual tests override what they are about.
const fn header(type_id: TypeId, cause: Cause) -> Header {
    Header {
        type_id,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
    }
}

// ---------------------------------------------------------------------------
// cl.5: the frame level, the I/S/U formats and the six U-function names
// ---------------------------------------------------------------------------

/// 5-104 clause 5, figures 6–8 (index 28, printed 27): *"Three types of control
/// field formats are used to perform numbered information transfer (I format),
/// numbered supervisory functions (S format) and unnumbered control functions
/// (U format)."* Figure 8 spells the six U functions `STARTDT act`,
/// `STARTDT con`, `STOPDT act`, `STOPDT con`, `TESTFR act` and `TESTFR con`.
/// No value in `src/apci.rs` carries these names.
#[test]
fn clause_5_the_frame_level_names_the_six_u_functions_and_the_three_formats() {
    // Figure 8's six names, exactly as the figure's own labels run them.
    assert_eq!(diag::u_function(UFunction::StartDtAct), "STARTDT act");
    assert_eq!(diag::u_function(UFunction::StartDtCon), "STARTDT con");
    assert_eq!(diag::u_function(UFunction::StopDtAct), "STOPDT act");
    assert_eq!(diag::u_function(UFunction::StopDtCon), "STOPDT con");
    assert_eq!(diag::u_function(UFunction::TestFrAct), "TESTFR act");
    assert_eq!(diag::u_function(UFunction::TestFrCon), "TESTFR con");

    // Figure 6: octets 1/3/4 are labelled `Send Sequence Number N(S)` and
    // `Receive Sequence Number N(R)` (LSB/MSB); figure 7: `Receive Sequence
    // Number N(R)`.
    let i = Apci::I {
        ns: SeqNo::new(3),
        nr: SeqNo::new(7),
    };
    let s = Apci::S { nr: SeqNo::new(7) };
    assert_eq!(diag::control(i), "I N(S)=3 N(R)=7");
    assert_eq!(diag::control(s), "S N(R)=7");
    assert_eq!(
        diag::control(Apci::U(UFunction::StartDtAct)),
        "U STARTDT act"
    );
    assert_eq!(diag::control(Apci::U(UFunction::TestFrCon)), "U TESTFR con");
}

// ---------------------------------------------------------------------------
// cl.7.2.1: the ASDU names the line prints
// ---------------------------------------------------------------------------

/// 5-101 clause 7.2.1, table 8 (index 31, printed 30): *"`<11>` := measured
/// value, scaled value  `M_ME_NB_1`"*. The line prints `TypeId::name`'s answer,
/// never the Rust variant name a `{:?}` would print.
#[test]
fn clause_7_2_1_the_line_prints_the_standards_asdu_names() {
    assert_eq!(
        diag::header(
            &header(TypeId::from_u8(11), Cause::Spontaneous),
            AddressSizes::CONVENTIONAL
        ),
        "M_ME_NB_1(11) SQ=0 N=1 cause=spont(3) P/N=0 T=0 ORG=0 CA=1"
    );
    // Table 8's first entry, and clause 7.2.1's frame-level answer.
    assert_eq!(
        diag::header(
            &header(TypeId::from_u8(1), Cause::Spontaneous),
            AddressSizes::CONVENTIONAL
        ),
        "M_SP_NA_1(1) SQ=0 N=1 cause=spont(3) P/N=0 T=0 ORG=0 CA=1"
    );
    // Table 13's file-transfer family (index 34, printed 33).
    assert_eq!(
        diag::header(
            &header(TypeId::from_u8(126), Cause::Spontaneous),
            AddressSizes::CONVENTIONAL
        ),
        "F_DR_TA_1(126) SQ=0 N=1 cause=spont(3) P/N=0 T=0 ORG=0 CA=1"
    );
    // An unnamed range: clause 7.2.1 (index 31) leaves `<136..255>` *"for
    // special use (private range)"*, and `TypeId::name` says `private`.
    assert_eq!(
        diag::header(
            &header(TypeId::Other(200), Cause::Spontaneous),
            AddressSizes::CONVENTIONAL
        ),
        "private(200) SQ=0 N=1 cause=spont(3) P/N=0 T=0 ORG=0 CA=1"
    );
}

// ---------------------------------------------------------------------------
// cl.7.2.3 / table 14: the cause column
// ---------------------------------------------------------------------------

/// 5-101 table 14 (index 41, printed 40): *"`<1>` := periodic, cyclic
/// per/cyc"*, *"`<3>` := spontaneous  spont"*. The mnemonic is
/// `Cause::mnemonic`'s, and the number beside it is `Cause::to_u8`'s, which
/// folds the numbered families of clause 7.2.3's own range (index 38, printed
/// 37: *"`<20>` := interrogated by station interrogation  inrogen"*).
#[test]
fn clause_7_2_3_the_cause_column_is_the_tables_mnemonic_beside_its_number() {
    assert_eq!(
        diag::header(
            &header(TypeId::from_u8(9), Cause::Periodic),
            AddressSizes::CONVENTIONAL
        ),
        "M_ME_NA_1(9) SQ=0 N=1 cause=per/cyc(1) P/N=0 T=0 ORG=0 CA=1"
    );
    assert_eq!(
        diag::header(
            &header(TypeId::from_u8(9), Cause::InterrogatedByStation),
            AddressSizes::CONVENTIONAL
        ),
        "M_ME_NA_1(9) SQ=0 N=1 cause=inrogen(20) P/N=0 T=0 ORG=0 CA=1"
    );
    // The numbered family folds to its number (`to_u8`), and the mnemonic is
    // table 14's own for that number.
    assert_eq!(
        diag::header(
            &header(TypeId::from_u8(9), Cause::InterrogatedByGroup(1)),
            AddressSizes::CONVENTIONAL
        ),
        "M_ME_NA_1(9) SQ=0 N=1 cause=inro1(21) P/N=0 T=0 ORG=0 CA=1"
    );
    // A cause the standard does not name (`<14..19>` are reserved): the number
    // alone, for `Cause::mnemonic` answers `""`.
    assert_eq!(
        diag::header(
            &header(TypeId::from_u8(9), Cause::Reserved(14)),
            AddressSizes::CONVENTIONAL
        ),
        "M_ME_NA_1(9) SQ=0 N=1 cause=14 P/N=0 T=0 ORG=0 CA=1"
    );
}

/// 5-101 figure 14 (index 37, printed 36) labels the octet `T`, `P/N` and
/// `Originator address optional per system`, and index 38 (printed 37) reads
/// the two flags: *"`<0>` := positive confirm / `<1>` := negative confirm"* and
/// *"T = test … `<0>` := no test / `<1>` := test"*. A profile without the
/// originator octet prints `ORG=-`: 5-104 clause 9.5 (index 98, printed 97)
/// says *"Originator address is set to zero if not used"*, so a `0` there would
/// read as clause 7.2.3's real `<0> := default` rather than as an absent field.
#[test]
fn clause_7_2_3_the_pn_and_test_flags_and_the_optional_originator_octet() {
    let mut h = header(TypeId::from_u8(9), Cause::Spontaneous);
    h.negative = true;
    h.test = true;
    h.originator = 23;
    h.sequence = true;
    h.count = 7;
    assert_eq!(
        diag::header(&h, AddressSizes::CONVENTIONAL),
        "M_ME_NA_1(9) SQ=1 N=7 cause=spont(3) P/N=1 T=1 ORG=23 CA=1"
    );

    h.originator = 0;
    let narrow = AddressSizes::new(1, 1, false).expect("CA 1, IOA 1, no originator");
    assert_eq!(
        diag::header(&h, narrow),
        "M_ME_NA_1(9) SQ=1 N=7 cause=spont(3) P/N=1 T=1 ORG=- CA=1"
    );
}

// ---------------------------------------------------------------------------
// cl.7.2.4 / cl.7.2.5 / 104 cl.9.5: the addresses and their widths
// ---------------------------------------------------------------------------

/// 5-101 clause 7.2.4 (index 42, printed 41): *"The length of the COMMON
/// ADDRESS (one or two octets) is a parameter which is fixed per system."*
/// Clause 7.2.5 (index 43, printed 42): *"The length of the INFORMATION OBJECT
/// ADDRESS (one, two or three octets) is a parameter which is fixed per
/// system."* 5-104 clause 9.5 (index 98, printed 97) lists all four as
/// *"system-specific parameter"* and fixes exactly one value: *"The maximum
/// length of APDU for both directions is 253. It is a fixed system
/// parameter."*
#[test]
fn clause_7_2_4_and_7_2_5_the_address_widths_are_a_line_of_their_own() {
    assert_eq!(
        diag::address_sizes(AddressSizes::CONVENTIONAL),
        "CA 2 octets, IOA 3 octets, originator present"
    );
    let narrow = AddressSizes::new(1, 1, false).expect("CA 1, IOA 1, no originator");
    assert_eq!(
        diag::address_sizes(narrow),
        "CA 1 octet, IOA 1 octet, originator absent"
    );
    // The one fixed value of clause 9.5, from the codec's own constant.
    assert_eq!(iec104::apci::MAX_LENGTH, 253);
}

/// 5-101 clause 7.2.5 (index 43, printed 42): *"INFORMATION OBJECT ADDRESS :=
/// UI8[1..8]<0..255>"*, figure 19, *"`<0>` := INFORMATION OBJECT ADDRESS is
/// irrelevant"*. The line reads the field with `asdu::read_ioa_with`, at the
/// width the profile fixes. A shorter buffer is a typed `TooShort`, never a
/// widened read.
#[test]
fn clause_7_2_5_the_information_object_address_is_read_at_the_profiles_width() {
    assert_eq!(
        diag::information_object_address(&[0x01, 0x10, 0x00, 0x00], AddressSizes::CONVENTIONAL),
        Ok("IOA=4097".to_string())
    );
    let narrow = AddressSizes::new(1, 1, false).expect("CA 1, IOA 1, no originator");
    assert_eq!(
        diag::information_object_address(&[0x07], narrow),
        Ok("IOA=7".to_string())
    );
    assert_eq!(
        diag::information_object_address(&[0x07], AddressSizes::CONVENTIONAL),
        Err(Error::Asdu(AsduError::TooShort { need: 3, have: 1 }))
    );
}

// ---------------------------------------------------------------------------
// cl.7.2.3: the communications error log; 104 cl.9: the time-outs
// ---------------------------------------------------------------------------

/// 5-101 clause 7.2.3 (index 42, printed 41): *"A controlling station may
/// monitor for and maintain a communications error log reporting each time
/// that the following ASDUs are received: ASDUs in the monitor direction with
/// undefined values in the data unit identifier (except the variable structure
/// qualifier); ASDUs in the monitor direction with undefined values of
/// information object address; mirrored ASDUs due to unknown numbers in the
/// control direction (type identifications 45 to 51)."* The three bullets are
/// the four classes of `Discard::Unspecified` (the first bullet names the
/// identifier's three fields) plus `Discard::Mirror`, and their causes are the
/// clause's own 44–47.
#[test]
fn clause_7_2_3_the_communications_error_log_line() {
    assert_eq!(
        diag::discard(Discard::Unspecified(Unspecified::TypeIdentification)),
        "discarded: type identification (cause 44)"
    );
    assert_eq!(
        diag::discard(Discard::Unspecified(Unspecified::CauseOfTransmission)),
        "discarded: cause of transmission (cause 45)"
    );
    assert_eq!(
        diag::discard(Discard::Unspecified(Unspecified::CommonAddress)),
        "discarded: common address of ASDU (cause 46)"
    );
    assert_eq!(
        diag::discard(Discard::Unspecified(Unspecified::InformationObjectAddress)),
        "discarded: information object address (cause 47)"
    );
    assert_eq!(diag::discard(Discard::Mirror), "discarded: mirrored ASDU");
}

/// 5-104 clause 9's time-out table (index 114, printed 113): *"t0 30 s
/// Time-out of connection establishment … t1 15 s Time-out of send or test
/// APDUs … t2 10 s Time-out for acknowledges in case of no data messages
/// t2 < t1 … t3 20 s Time-out for sending test frames in case of a long idle
/// state"*, and its k/w row *"k 12 APDUs … w 8 APDUs"*.
#[test]
fn clause_9_the_timeouts_are_the_tables_own_line() {
    assert_eq!(
        diag::timers(&LinkParams::default()),
        "t0=30 s t1=15 s t2=10 s t3=20 s k=12 w=8 port=2404"
    );
    let custom = LinkParams {
        t0: std::time::Duration::from_secs(5),
        t3: std::time::Duration::from_secs(48 * 60 * 60),
        ..LinkParams::default()
    };
    assert_eq!(
        diag::timers(&custom),
        "t0=5 s t1=15 s t2=10 s t3=172800 s k=12 w=8 port=2404"
    );
}

/// The line must never round a configured value into one the crate would
/// reject. `LinkParams { t1: 1500 ms, t2: 500 ms, ..default }` satisfies
/// clause 9's `t2 < t1` and its *"Maximum range for timeouts t0 to t2: 1 s to
/// 255 s"* (index 114, printed 113; `params::LinkParams::validate` answers
/// `Ok(())`), yet `as_secs` alone would print `t2=0 s`, a zero the same
/// `validate` refuses. A sub-second part is therefore printed exactly; a whole
/// number of seconds keeps the table's own `15 s` shape.
#[test]
fn clause_9_a_sub_second_timeout_is_printed_exactly_and_never_rounded_to_zero() {
    let sub = LinkParams {
        t1: std::time::Duration::from_millis(1500),
        t2: std::time::Duration::from_millis(500),
        ..LinkParams::default()
    };
    assert_eq!(
        sub.validate(),
        Ok(()),
        "1500 ms / 500 ms must be a configuration clause 9 allows"
    );
    assert_eq!(
        diag::timers(&sub),
        "t0=30 s t1=1.5 s t2=0.5 s t3=20 s k=12 w=8 port=2404"
    );
}

// ---------------------------------------------------------------------------
// cl.5: the whole frame in one line
// ---------------------------------------------------------------------------

/// 5-104 clause 5, figures 4 and 5 (index 26, printed 25): *"START 68H defines
/// the point of start within the data stream. The length of the APDU defines
/// the length of the body of the APDU, which consists of the four control field
/// octets of the APCI plus the ASDU."* `apdu` formats one complete frame: the
/// control field, the ASDU header and the first information object address.
#[test]
fn clause_5_one_line_for_a_whole_frame() {
    // A U-format frame: no ASDU.
    assert_eq!(
        diag::apdu(
            &[0x68, 0x04, 0x07, 0x00, 0x00, 0x00],
            AddressSizes::CONVENTIONAL
        ),
        Ok("U STARTDT act".to_string())
    );
    // An S-format frame: no ASDU.
    assert_eq!(
        diag::apdu(
            &[0x68, 0x04, 0x01, 0x00, 0x00, 0x00],
            AddressSizes::CONVENTIONAL
        ),
        Ok("S N(R)=0".to_string())
    );
    // An I-format frame: control field, header and first address.
    let i_frame = [
        0x68, 0x0e, 0x00, 0x00, 0x02, 0x00, 0x64, 0x01, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x14,
    ];
    assert_eq!(
        diag::apdu(&i_frame, AddressSizes::CONVENTIONAL),
        Ok("I N(S)=0 N(R)=1 | C_IC_NA_1(100) SQ=0 N=1 cause=actcon(7) P/N=0 T=0 ORG=0 CA=1 | IOA=0"
            .to_string())
    );
}

/// The formatter's failures are the codec's own, carried as values and never
/// panicked over: clause 5 (index 26, printed 25) bounds the length field
/// (*"max. 253"*, and at least the four control field octets), and a header
/// shorter than the profile's `header_len` is `AsduError::TooShort`.
#[test]
fn a_malformed_frame_is_a_typed_error_and_not_a_panic() {
    assert_eq!(
        diag::apdu(&[0x68, 0x02, 0x00, 0x00], AddressSizes::CONVENTIONAL),
        Err(Error::Apci(ParseError::BadLength(2)))
    );
    // An I-format frame whose ASDU is one octet: no room for the header.
    assert_eq!(
        diag::apdu(
            &[0x68, 0x05, 0x00, 0x00, 0x00, 0x00, 0x64],
            AddressSizes::CONVENTIONAL
        ),
        Err(Error::Asdu(AsduError::TooShort { need: 6, have: 1 }))
    );
}

/// `apdu` formats *one* frame, so octets past the first frame's own end are a
/// refusal, not silently dropped. The length field is 5-104 clause 5's own
/// frame bound (figure 5, index 26, printed 25: *"The length of the APDU
/// defines the length of the body of the APDU"*); a buffer holding two frames
/// back to back is two frames, and `apci::parse` reports the first as complete
/// while returning a consumed count of 6. Formatting one and discarding the
/// rest would print a line for octets it never read.
#[test]
fn clause_5_trailing_octets_are_a_typed_refusal_not_silently_dropped() {
    // Two U-format frames back to back: the parse of the first consumes 6 of 12.
    assert_eq!(
        diag::apdu(
            &[
                0x68, 0x04, 0x07, 0x00, 0x00, 0x00, 0x68, 0x04, 0x0b, 0x00, 0x00, 0x00
            ],
            AddressSizes::CONVENTIONAL
        ),
        Err(Error::TrailingOctets { frame: 6, have: 12 })
    );
    // One whole frame plus two octets that belong to no frame at all.
    assert_eq!(
        diag::apdu(
            &[0x68, 0x04, 0x07, 0x00, 0x00, 0x00, 0xff, 0xff],
            AddressSizes::CONVENTIONAL
        ),
        Err(Error::TrailingOctets { frame: 6, have: 8 })
    );
}

// ---------------------------------------------------------------------------
// the runbook document is pinned by the formatter, not the other way round
// ---------------------------------------------------------------------------

/// `docs/RUNBOOK.md` quotes the line the formatter prints for a frame captured
/// from a real peer, and the test reads the document back to prove it still
/// does. A runbook that quotes a
/// line the formatter does not print is worse than no runbook.
#[test]
fn the_runbook_quotes_the_line_the_formatter_prints_for_a_real_peer_frame() {
    let line = diag::apdu(&interop::CAPTURE_PEER_ACT_CON, AddressSizes::CONVENTIONAL)
        .expect("the committed capture is a whole frame");
    assert_eq!(
        line,
        "I N(S)=0 N(R)=1 | C_IC_NA_1(100) SQ=0 N=1 cause=actcon(7) P/N=0 T=0 ORG=0 CA=1 | IOA=0"
    );
    let runbook = include_str!("../docs/RUNBOOK.md");
    assert!(
        runbook.contains(&line),
        "docs/RUNBOOK.md no longer quotes the line the formatter prints:\n{line}"
    );
}
