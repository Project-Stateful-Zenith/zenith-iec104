//! The file-transfer ASDUs and their procedure: 5-101 clause 7.3.6 (types
//! 120–126, figures 83–89 on PDF page indices 114–120 of the committed copy)
//! plus 5-104 clause 8.9's `F_SC_NB_1` `<127>` (figure 31, index 92), driven
//! through the clause 7.11 procedure of `src/ft.rs`.
//!
//! Every number asserted below is read from a figure, and the tables name the
//! index. The definition lines, verbatim:
//!
//! ```text
//! fig  idx  type  ASDU        definition line                                            element
//! 83  114   120  F_FR_NA_1   CP{…,Name of file,Length of file,FRQ}                      2+3+1 = 6
//! 84  115   121  F_SR_NA_1   CP{…,Name of file,Name of section,Length of section,SRQ}   2+1+3+1 = 7
//! 85  116   122  F_SC_NA_1   CP{…,Name of file,Name of section,SCQ}                     2+1+1 = 4
//! 86  117   123  F_LS_NA_1   CP{…,Name of file,Name of section,LSQ,Checksum}            2+1+1+1 = 5
//! 87  118   124  F_AF_NA_1   CP{…,Name of file,Name of section,AFQ}                     2+1+1 = 4
//! 88  119   125  F_SG_NA_1   CP{…,Name of file,Name of section,Length of segment,Segment}
//!                                                                                      4 + LOS
//! 89  120   126  F_DR_TA_1   CP{…,j(Name of file,Length of file,Status of file,
//!                             CP56Time2a)}                                               13 j
//! 31   92   127  F_SC_NB_1   CP{…,Name of file,CP56Time2a (RangeStartTime),
//!                             CP56Time2a (RangeStopTime)}                                2+7+7 = 16
//! ```
//!
//! **`F_SR_NA_1`'s element is seven octets, not five.** Figure 84 (index 115)
//! prints four rows: Name of file (7.2.6.33), Name of section (7.2.6.34),
//! *Length of section* (**7.2.6.35**, which is `LOF`, three octets; not `LOS`,
//! which is 7.2.6.36 and belongs to figure 88) and SRQ. Its definition line is
//! `CP{Data unit identifier,Information object address,Name of file,Name of
//! section,Length of section,SRQ}`. Two plus one plus three plus one is seven.
//!
//! The APDU ceiling the figures live under is 5-104 index 26 (printed page 25),
//! verbatim: *"The maximum length of the ASDU is limited to 249 because the
//! maximum value of the field length of APDU is 253 (`APDUmax` = 255 minus start
//! and length octet)."* It bounds a segment at 236 octets and a directory at 18
//! files, and both are asserted below on the build path and on the decode path.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use iec104::asdu::{
    Afq, AsduError, Cause, Chs, Cp56Time2a, Discard, FDrTa1, FILE_LAYOUTS, FSrNa1, Frq, Header,
    Known, LayoutError, Lof, Los, Lsq, Nof, Nos, ObjectCount, Scq, Segment, Sequence, Sof, Srq,
    TypeId, decode_asdu, decode_segment, element_len, layout_for,
};
use iec104::ft::{
    DirectoryEntry, FileTransferProcedure, Frame, FtError, MAX_DIRECTORY_FILES, MAX_SEGMENT,
    Reaction, Role, Selection, ack, call_directory, call_file, call_section, check_checksum,
    checksum, decode_frame, directory, encode_frame, file_ready, is_file_type, last_segment,
    query_log, sc, section_ready, segment, select_file,
};

/// The broadcast common address of the conventional two-octet profile.
const BROADCAST_CA: u16 = iec104::asdu::AddressSizes::CONVENTIONAL.broadcast_common_address();

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
        .collect()
}

/// The clause's own header, built by hand so a test can state a count, a
/// sequence bit or a cause the builders would refuse.
fn header(type_id: TypeId, count: u8, sequence: bool, cause: Cause, ca: u16) -> Vec<u8> {
    let mut out = Vec::new();
    Header {
        type_id,
        sequence,
        count,
        cause,
        negative: false,
        test: false,
        originator: 0,
        common_address: ca,
    }
    .encode(&mut out);
    out
}

const fn nof(value: u16) -> Nof {
    Nof { value }
}

const fn nos(value: u8) -> Nos {
    Nos { value }
}

fn entry(name: u16, length: u32) -> DirectoryEntry {
    DirectoryEntry {
        nof: nof(name),
        lof: Lof { value: length },
        sof: Sof::default(),
        time: Cp56Time2a::default(),
    }
}

/// One frame of each of the eight types, for the round-trip and truncation
/// sweeps. Every field is a value the figures allow.
fn the_eight_frames() -> Vec<Frame> {
    vec![
        Frame::Sc {
            ioa: 5,
            nof: nof(0x1234),
            nos: nos(3),
            scq: Scq {
                action: Scq::REQUEST_SECTION,
                error: 0,
            },
        },
        Frame::FileReady {
            ioa: 5,
            nof: nof(0x1234),
            lof: Lof { value: 0x0001_0203 },
            frq: Frq {
                value: 5,
                negative_confirm: false,
            },
        },
        Frame::SectionReady {
            ioa: 5,
            nof: nof(0x1234),
            nos: nos(3),
            lof: Lof { value: 0x0000_FF00 },
            srq: Srq {
                value: 0,
                not_ready: true,
            },
        },
        Frame::Segment {
            ioa: 5,
            segment: Segment {
                nof: nof(0x1234),
                nos: nos(3),
                los: Los { value: 4 },
                payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
        },
        Frame::LastSection {
            ioa: 5,
            nof: nof(0x1234),
            nos: nos(3),
            lsq: Lsq {
                value: Lsq::SECTION_WITH_DEACTIVATION,
            },
            chs: Chs { value: 0x5A },
        },
        Frame::Ack {
            ioa: 5,
            nof: nof(0x1234),
            nos: nos(3),
            afq: Afq {
                action: Afq::SECTION_POSITIVE,
                error: 0,
            },
        },
        Frame::Directory {
            ioa: 100,
            cause: Cause::Spontaneous,
            files: vec![entry(1, 10), entry(2, 20), entry(3, 30)],
        },
        Frame::QueryLog {
            ioa: 5,
            nof: nof(0x1234),
            range_start: Cp56Time2a::default(),
            range_stop: Cp56Time2a::default(),
        },
    ]
}

/// Every builder of the family, so a rule can be asserted against all eight.
fn every_builder(ca: u16) -> Vec<(&'static str, Result<Vec<u8>, FtError>)> {
    vec![
        ("call_directory", call_directory(ca, 0, 1, nof(1))),
        ("select_file", select_file(ca, 0, 1, nof(1), nos(0))),
        ("call_file", call_file(ca, 0, 1, nof(1), nos(0))),
        ("call_section", call_section(ca, 0, 1, nof(1), nos(1))),
        (
            "file_ready",
            file_ready(ca, 0, 1, nof(1), Lof { value: 1 }, Frq::default()),
        ),
        (
            "section_ready",
            section_ready(ca, 0, 1, nof(1), nos(1), Lof { value: 1 }, Srq::default()),
        ),
        ("segment", segment(ca, 0, 1, nof(1), nos(1), &[0u8; 4])),
        (
            "last_segment",
            last_segment(ca, 0, 1, nof(1), nos(1), Lsq { value: 1 }, Chs { value: 0 }),
        ),
        (
            "ack",
            ack(
                ca,
                0,
                1,
                nof(1),
                nos(1),
                Afq {
                    action: 1,
                    error: 0,
                },
            ),
        ),
        (
            "directory",
            directory(ca, 0, 1, Cause::Spontaneous, vec![entry(1, 1)]),
        ),
        (
            "query_log",
            query_log(
                ca,
                0,
                1,
                nof(1),
                Cp56Time2a::default(),
                Cp56Time2a::default(),
            ),
        ),
    ]
}

// ---------------------------------------------------------------- the family

/// Clause 7.3.6's range 120–126 plus 104's `<127>`: eight types, and the wire
/// octet decides, so an unnamed `Other` of 120 answers as `FFrNa1` does.
#[test]
fn the_family_is_the_eight_types_of_the_two_clauses() {
    for octet in 120..=127u8 {
        assert!(is_file_type(TypeId::Other(octet)), "{octet}");
    }
    for octet in [0u8, 1, 36, 100, 119, 128, 255] {
        assert!(!is_file_type(TypeId::Other(octet)), "{octet}");
    }
    assert_eq!(
        the_eight_frames()
            .iter()
            .map(Frame::type_id)
            .collect::<Vec<_>>(),
        vec![
            TypeId::FScNa1,
            TypeId::FFrNa1,
            TypeId::FSrNa1,
            TypeId::FSgNa1,
            TypeId::FLsNa1,
            TypeId::FAfNa1,
            TypeId::FDrTa1,
            TypeId::FScNb1,
        ]
    );
    // Type identifications 120–127 in the catalogue's own numbering.
    for (type_id, octet) in [
        (TypeId::FFrNa1, 120u8),
        (TypeId::FSrNa1, 121),
        (TypeId::FScNa1, 122),
        (TypeId::FLsNa1, 123),
        (TypeId::FAfNa1, 124),
        (TypeId::FSgNa1, 125),
        (TypeId::FDrTa1, 126),
        (TypeId::FScNb1, 127),
    ] {
        assert_eq!(type_id.to_u8(), octet);
    }
}

/// The eight rows are the figures' definition lines, element octet by element
/// octet: 6, 7, 4, 5, 4, variable, 13 and 16.
#[test]
fn the_eight_rows_are_the_figures_definition_lines() {
    assert_eq!(FILE_LAYOUTS.len(), 8);
    for (type_id, octets) in [
        (TypeId::FFrNa1, 6usize),
        (TypeId::FSrNa1, 7),
        (TypeId::FScNa1, 4),
        (TypeId::FLsNa1, 5),
        (TypeId::FAfNa1, 4),
        (TypeId::FDrTa1, 13),
        (TypeId::FScNb1, 16),
    ] {
        let layout = layout_for(type_id).expect("a file-transfer layout");
        assert!(!layout.variable, "{}", type_id.name());
        assert_eq!(layout.element_len, octets, "{}", type_id.name());
        assert_eq!(element_len(type_id), Some(octets), "{}", type_id.name());
    }
    // The rows are in type order, one per identification.
    assert_eq!(
        FILE_LAYOUTS
            .iter()
            .map(|row| row.type_id.to_u8())
            .collect::<Vec<_>>(),
        (120..=127).collect::<Vec<_>>()
    );
}

/// The easy one to get wrong: figure 84's *"Length of section"* is `LOF`
/// (7.2.6.35, `UI24`), not `LOS` (7.2.6.36, `UI8`), so the element is
/// 2 + 1 + 3 + 1 = 7 and not 5.
#[test]
fn the_section_ready_element_is_seven_octets_not_five() {
    assert_eq!(Lof::LEN, 3, "7.2.6.35 is a UI24");
    assert_eq!(Los::LEN, 1, "7.2.6.36 is a UI8");
    let asdu = section_ready(
        12,
        0,
        5,
        nof(0x1234),
        nos(3),
        Lof { value: 0x0001_0203 },
        Srq::default(),
    )
    .unwrap();
    // Header 6 + information object address 3 + element 7.
    assert_eq!(asdu.len(), Header::LEN + 3 + 7);
    assert_eq!(element_len(TypeId::FSrNa1), Some(7));
    let object = decode_asdu::<FSrNa1>(&asdu).unwrap();
    assert_eq!(object[0].value.lof, Lof { value: 0x0001_0203 });
}

/// `<125>` is the family's one variable-length element, so its row says
/// `variable` and there is no number to answer with. `MAX_SEGMENT` is the
/// 249-octet ceiling less the header, the address and the element's own prefix.
#[test]
fn the_segment_element_length_is_not_a_constant() {
    let layout = layout_for(TypeId::FSgNa1).unwrap();
    assert!(layout.variable);
    assert_eq!(element_len(TypeId::FSgNa1), None);
    assert_eq!(MAX_SEGMENT, 249 - Header::LEN - 3 - 2 - 1 - 1);
    assert_eq!(MAX_SEGMENT, 236);
    assert!(
        MAX_SEGMENT < usize::from(Los::MAX),
        "LOS's own ceiling is looser"
    );
    // The type has no `AsduLayout` implementor at all, so the generic codec
    // cannot even be asked for it: the row is the only record of the geometry,
    // and `element_len` refuses to invent a number.
    assert_eq!(FILE_LAYOUTS.iter().filter(|row| row.variable).count(), 1);
    assert_eq!(
        FILE_LAYOUTS
            .iter()
            .find(|row| row.variable)
            .unwrap()
            .type_id,
        TypeId::FSgNa1
    );
}

/// `F_DR_TA_1` is the family's only sequence form (figure 89's heading is
/// *"Sequence of information elements in a single information object (SQ = 1)"*),
/// and that is its only form at all; the other seven are single-object.
#[test]
fn the_directory_is_the_familys_only_sequence_form() {
    assert_eq!(
        layout_for(TypeId::FDrTa1).unwrap().sequence,
        Sequence::Required,
        "figure 89 defines SQ = 1 and nothing else"
    );
    assert_eq!(
        layout_for(TypeId::FDrTa1).unwrap().count,
        ObjectCount::Multiple
    );
    for type_id in [
        TypeId::FFrNa1,
        TypeId::FSrNa1,
        TypeId::FScNa1,
        TypeId::FLsNa1,
        TypeId::FAfNa1,
        TypeId::FSgNa1,
        TypeId::FScNb1,
    ] {
        let layout = layout_for(type_id).unwrap();
        assert_eq!(layout.sequence, Sequence::NotDefined, "{}", type_id.name());
        assert_eq!(layout.count, ObjectCount::Single, "{}", type_id.name());
    }
    // A sequence form on a type whose figure says SQ = 0 is refused.
    let mut asdu = file_ready(12, 0, 5, nof(1), Lof { value: 2 }, Frq::default()).unwrap();
    asdu[1] |= 0x80;
    assert_eq!(
        decode_frame(&asdu),
        Err(FtError::Layout(LayoutError::SequenceNotAllowed {
            type_id: TypeId::FFrNa1
        }))
    );
}

/// Figure 89 defines the sequence and nothing else, so an `F_DR_TA_1` with
/// `SQ = 0` puts **one** information object address on the wire for what the
/// figure makes `j` elements: read as `SQ = 0` every file after the first is
/// silently lost. The layer refuses the frame instead.
#[test]
fn a_directory_without_the_sequence_bit_is_refused() {
    // Two 13-octet elements in one `SQ = 0` body, at the addresses 100 and 900:
    // header 6 + (address 3 + element 13) × 2.
    let mut asdu = header(TypeId::FDrTa1, 2, false, Cause::Spontaneous, 12);
    asdu.extend_from_slice(&hex("64 00 00 01 00 0A 00 00 00 00 00 00 00 00 00 00"));
    asdu.extend_from_slice(&hex("84 03 00 02 00 14 00 00 00 00 00 00 00 00 00 00"));
    let refusal = Err(FtError::Layout(LayoutError::SequenceRequired {
        type_id: TypeId::FDrTa1,
    }));
    assert_eq!(decode_frame(&asdu), refusal);
    // The generic path the ft layer calls says the same, so no caller can reach
    // a directory that dropped its files.
    assert_eq!(
        decode_asdu::<FDrTa1>(&asdu),
        Err(LayoutError::SequenceRequired {
            type_id: TypeId::FDrTa1
        })
    );
    // With SQ = 1 and the **same** element octets there is nothing to read: the
    // one address 100 is the base and the two elements are the files 1 and 2.
    let mut sequenced = asdu.clone();
    sequenced[1] |= 0x80;
    sequenced.drain(22..25);
    let objects = decode_asdu::<FDrTa1>(&sequenced).unwrap();
    assert_eq!(
        objects.iter().map(|object| object.ioa).collect::<Vec<_>>(),
        vec![100, 101]
    );
    assert_eq!(
        objects
            .iter()
            .map(|object| object.value.nof.value)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(decode_frame(&sequenced).is_ok());
}

/// More than one information object where the figure says *"Single information
/// object (SQ = 0)"*.
#[test]
fn two_objects_are_refused_for_a_single_object_type() {
    let mut asdu = file_ready(12, 0, 5, nof(1), Lof { value: 2 }, Frq::default()).unwrap();
    asdu[1] = (asdu[1] & 0x80) | 2;
    assert_eq!(
        decode_frame(&asdu),
        Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FFrNa1,
            count: 2
        }))
    );
}

// ---------------------------------------------------------------- the shapes

/// Every frame the eight builders produce decodes back to the value it was
/// built from, and its ASDU is exactly the figure's octet count.
#[test]
fn every_one_of_the_eight_round_trips() {
    for frame in the_eight_frames() {
        let asdu = encode_frame(12, 7, &frame).unwrap();
        assert_eq!(decode_frame(&asdu).unwrap(), frame, "{:?}", frame.type_id());
        // VSQ: one object, and SQ = 1 for the directory alone.
        let parsed = Header::parse(&asdu).unwrap();
        assert_eq!(parsed.common_address, 12);
        assert_eq!(parsed.originator, 7);
        assert!(!parsed.negative);
        assert_eq!(parsed.sequence, matches!(frame, Frame::Directory { .. }));
        assert_eq!(parsed.cause, frame.cause());
        if let Frame::Directory { files, .. } = &frame {
            assert_eq!(usize::from(parsed.count), files.len());
        } else {
            assert_eq!(parsed.count, 1);
        }
    }
}

/// The fixed seven are `6 + 3 + element_len` octets, and the segment is
/// `6 + 3 + 4 + LOS`.
#[test]
fn every_asdu_is_the_figures_octet_count() {
    for frame in the_eight_frames() {
        let asdu = encode_frame(12, 0, &frame).unwrap();
        let expected = match &frame {
            Frame::Segment { segment, .. } => {
                Header::LEN + 3 + Segment::PREFIX_LEN + segment.payload.len()
            }
            Frame::Directory { files, .. } => Header::LEN + 3 + 13 * files.len(),
            other => Header::LEN + 3 + element_len(other.type_id()).unwrap(),
        };
        assert_eq!(asdu.len(), expected, "{:?}", frame.type_id());
    }
}

/// Figure 89: *"Belongs to information object address A"* for file 1 and
/// `A + j − 1` for file `j`: the SQ = 1 arithmetic, spelled out.
#[test]
fn the_directory_puts_file_i_at_a_plus_i_minus_one() {
    let asdu = directory(
        12,
        0,
        100,
        Cause::Spontaneous,
        vec![entry(1, 10), entry(2, 20), entry(3, 30)],
    )
    .unwrap();
    let objects = decode_asdu::<FDrTa1>(&asdu).unwrap();
    assert_eq!(
        objects.iter().map(|object| object.ioa).collect::<Vec<_>>(),
        vec![100, 101, 102]
    );
    assert_eq!(
        objects
            .iter()
            .map(|object| object.value.nof.value)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(Header::parse(&asdu).unwrap().sequence);
}

/// The element's multi-octet fields are little-endian: `NOF` a `UI16`, `LOF` a
/// `UI24` (7.2.6.33, 7.2.6.35).
#[test]
fn the_names_and_lengths_are_little_endian() {
    let asdu = file_ready(
        12,
        0,
        5,
        nof(0x1234),
        Lof { value: 0x0001_0203 },
        Frq::default(),
    )
    .unwrap();
    // Header 6, address 3, then NOF 34 12, LOF 03 02 01, FRQ 00.
    assert_eq!(&asdu[9..15], &hex("34 12 03 02 01 00"));
}

/// Every type of the family on the wire, octet for octet (the header's own
/// fields, the information object address and the element), against the figure
/// that defines it. The literal is the standard's statement and not this crate's
/// own encoder run twice: a symmetric bug in `encode_frame`/`decode_frame` is
/// exactly what `encode → decode` cannot catch.
///
/// Figure 85's two request forms are both here: the call directory is cause
/// `<5>` with `SCQ` = `<0>`, every other `F_SC_NA_1` is cause `<13>`.
#[test]
fn every_type_carries_the_octets_its_figure_prints() {
    let cases = figure_cases();
    for (label, octet, asdu, literal) in cases {
        let expected = hex(literal);
        assert_eq!(asdu, expected, "{label}");
        assert_eq!(
            Header::parse(&asdu).unwrap().type_id.to_u8(),
            octet,
            "{label}"
        );
        assert_eq!(
            decode_frame(&asdu).unwrap().type_id().to_u8(),
            octet,
            "{label}"
        );
        // And the decoder reads back exactly those octets, not a longer ASDU.
        assert_eq!(
            asdu,
            encode_frame(12, 0, &decode_frame(&asdu).unwrap()).unwrap()
        );
    }
}

/// Every file transfer type with the octets its figure prints: (label, type
/// identification, the ASDU built, the figure's octets).
fn figure_cases() -> [(&'static str, u8, Vec<u8>, &'static str); 9] {
    [
        (
            "F_FR_NA_1 <120>, figure 83, index 114",
            120,
            file_ready(
                12,
                0,
                5,
                nof(0x1234),
                Lof { value: 0x0001_0203 },
                Frq::default(),
            )
            .unwrap(),
            // header 6: type 78, VSQ 01 (SQ = 0, N = 1), COT 0D (<13>), ORG 00,
            // CA 0C 00 | address 05 00 00 | element 6: NOF 34 12, LOF 03 02 01,
            // FRQ 00.
            "78 01 0D 00 0C 00 05 00 00 34 12 03 02 01 00",
        ),
        (
            "F_SR_NA_1 <121>, figure 84, index 115",
            121,
            section_ready(
                12,
                0,
                5,
                nof(0x1234),
                nos(3),
                Lof { value: 0x0000_FF00 },
                Srq {
                    value: 0,
                    not_ready: true,
                },
            )
            .unwrap(),
            // element 7 (not 5; `LOF` is three octets): NOF 34 12, NOS 03, LOF
            // 00 FF 00, SRQ 80 (bit 8 = section not ready to load).
            "79 01 0D 00 0C 00 05 00 00 34 12 03 00 FF 00 80",
        ),
        (
            "F_SC_NA_1 <122>, figure 85, index 116 — call directory",
            122,
            call_directory(12, 0, 5, nof(0x1234)).unwrap(),
            // cause <5> (request, only for Call Directory), SCQ 00 (<0>).
            "7A 01 05 00 0C 00 05 00 00 34 12 00 00",
        ),
        (
            "F_SC_NA_1 <122>, figure 85, index 116 — call section",
            122,
            call_section(12, 0, 5, nof(0x1234), nos(3)).unwrap(),
            // cause <13> and SCQ 06 (request section, 7.2.6.30).
            "7A 01 0D 00 0C 00 05 00 00 34 12 03 06",
        ),
        (
            "F_LS_NA_1 <123>, figure 86, index 117",
            123,
            last_segment(
                12,
                0,
                5,
                nof(0x1234),
                nos(3),
                Lsq {
                    value: Lsq::SECTION_WITH_DEACTIVATION,
                },
                Chs { value: 0x5A },
            )
            .unwrap(),
            // element 5: NOF 34 12, NOS 03, LSQ 04 (section, with
            // deactivation), CHS 5A.
            "7B 01 0D 00 0C 00 05 00 00 34 12 03 04 5A",
        ),
        (
            "F_AF_NA_1 <124>, figure 87, index 118",
            124,
            ack(
                12,
                0,
                5,
                nof(0x1234),
                nos(3),
                Afq {
                    action: Afq::SECTION_POSITIVE,
                    error: 0,
                },
            )
            .unwrap(),
            // element 4: NOF 34 12, NOS 03, AFQ 03 (positive acknowledge of
            // section transfer).
            "7C 01 0D 00 0C 00 05 00 00 34 12 03 03",
        ),
        (
            "F_SG_NA_1 <125>, figure 88, index 119",
            125,
            segment(12, 0, 5, nof(0x1234), nos(3), &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap(),
            // variable element: NOF 34 12, NOS 03, LOS 04, then the four
            // segment octets: 6 + 3 + 4 + 4 = 17.
            "7D 01 0D 00 0C 00 05 00 00 34 12 03 04 DE AD BE EF",
        ),
        (
            "F_DR_TA_1 <126>, figure 89, index 120",
            126,
            directory(12, 0, 100, Cause::Spontaneous, two_files()).unwrap(),
            // VSQ 82: SQ = 1, N = 2. Cause 03 (<3> spontaneous). The base
            // address 64 00 00 (100) and then two 13-octet files: file 1 is
            // NOF 01 00, LOF 0A 00 00, SOF 21 (status 1 + LFD) and seven zeros;
            // file 2 is NOF 02 00, LOF 14 00 00, SOF 42 (status 2 + FOR) and
            // seven zeros. File 2's address (101) is not on the wire.
            "7E 82 03 00 0C 00 64 00 00 01 00 0A 00 00 21 00 00 00 00 00 00 00 \
             02 00 14 00 00 42 00 00 00 00 00 00 00",
        ),
        (
            "F_SC_NB_1 <127>, 104 clause 8.9, figure 31, index 92",
            127,
            query_log(12, 0, 5, nof(0x1234), Cp56Time2a::default(), stop_time()).unwrap(),
            // element 16: NOF 34 12, RangeStartTime seven zeros (from the
            // beginning), RangeStopTime 34 12 00 00 00 01 16.
            "7F 01 0D 00 0C 00 05 00 00 34 12 00 00 00 00 00 00 00 \
             34 12 00 00 00 01 16",
        ),
    ]
}

/// The `RangeStopTime` of the `F_SC_NB_1` case.
fn stop_time() -> Cp56Time2a {
    Cp56Time2a::parse(&hex("34 12 00 00 00 01 16")).unwrap()
}

/// The two files of the `F_DR_TA_1` case.
fn two_files() -> Vec<DirectoryEntry> {
    vec![
        DirectoryEntry {
            nof: nof(1),
            lof: Lof { value: 10 },
            sof: Sof {
                status: 1,
                last_file_of_directory: true,
                name_defines_subdirectory: false,
                transfer_active: false,
            },
            time: Cp56Time2a::default(),
        },
        DirectoryEntry {
            nof: nof(2),
            lof: Lof { value: 20 },
            sof: Sof {
                status: 2,
                last_file_of_directory: false,
                name_defines_subdirectory: true,
                transfer_active: false,
            },
            time: Cp56Time2a::default(),
        },
    ]
}

/// The segment's octets survive byte for byte, and `LOS` is written from the
/// caller's slice, so a caller cannot state a length other than it hands over.
#[test]
fn the_segment_payload_is_written_and_read_back_octet_for_octet() {
    let payload: Vec<u8> = (0..=235u8).collect();
    let asdu = segment(12, 0, 5, nof(1), nos(1), &payload).unwrap();
    let object = decode_segment(&asdu).unwrap();
    assert_eq!(object.value.payload, payload);
    assert_eq!(object.value.stated_len(), payload.len());
    assert_eq!(usize::from(asdu[12]), payload.len() % 256);
    assert_eq!(
        decode_frame(&asdu).unwrap(),
        Frame::Segment {
            ioa: 5,
            segment: object.value
        }
    );
}

/// The two `SCQ`-bearing builders below `call_directory`, and the `F_SC_NA_1`
/// causes of figure 85 (index 116): `<5> := request (only for Call Directory)`,
/// `<13> := file transfer (all except for Call Directory)`.
#[test]
fn the_call_directory_is_cause_five_and_everything_else_cause_thirteen() {
    let call = call_directory(12, 0, 5, nof(1)).unwrap();
    assert_eq!(Header::parse(&call).unwrap().cause, Cause::Request);
    assert_eq!(Header::parse(&call).unwrap().type_id, TypeId::FScNa1);
    // SCQ action <0>: the figure's own default, which is the call directory.
    // Header 6 + address 3 + NOF 2 + NOS 1 = the SCQ octet at index 12.
    assert_eq!(call.len(), 6 + 3 + 4);
    assert_eq!(call[12], 0);

    for built in [
        select_file(12, 0, 5, nof(1), nos(1)).unwrap(),
        call_file(12, 0, 5, nof(1), nos(1)).unwrap(),
        call_section(12, 0, 5, nof(1), nos(1)).unwrap(),
    ] {
        assert_eq!(Header::parse(&built).unwrap().cause, Cause::FileTransfer);
    }
    // The three actions are 1, 2 and 6 (7.2.6.30), in the element's last octet.
    assert_eq!(
        select_file(12, 0, 5, nof(1), nos(1)).unwrap()[12],
        Scq::SELECT_FILE
    );
    assert_eq!(
        call_file(12, 0, 5, nof(1), nos(1)).unwrap()[12],
        Scq::REQUEST_FILE
    );
    assert_eq!(
        call_section(12, 0, 5, nof(1), nos(1)).unwrap()[12],
        Scq::REQUEST_SECTION
    );

    // A call directory under cause <13> does not exist: `sc()` refuses action 0.
    assert_eq!(
        sc(12, 0, 5, nof(1), nos(0), Scq::default()),
        Err(FtError::CauseNotListed {
            type_id: TypeId::FScNa1,
            cause: Cause::FileTransfer
        })
    );
    // And a decoded call directory under cause <13> is refused too.
    let mut wrong = call;
    wrong[2] = Cause::FileTransfer.to_u8();
    assert_eq!(
        decode_frame(&wrong),
        Err(FtError::CauseNotListed {
            type_id: TypeId::FScNa1,
            cause: Cause::FileTransfer
        })
    );
}

/// Figure 89 (index 120) prints exactly `<3> := spontaneous` and `<5> :=
/// requested` for type 126, and no others.
#[test]
fn the_directory_carries_only_its_two_causes() {
    for cause in [Cause::Spontaneous, Cause::Request] {
        let asdu = directory(12, 0, 100, cause, vec![entry(1, 1)]).unwrap();
        assert_eq!(Header::parse(&asdu).unwrap().cause, cause);
        assert_eq!(decode_frame(&asdu).unwrap().cause(), cause);
    }
    assert_eq!(
        directory(12, 0, 100, Cause::FileTransfer, vec![entry(1, 1)]),
        Err(FtError::CauseNotListed {
            type_id: TypeId::FDrTa1,
            cause: Cause::FileTransfer
        })
    );
    let mut wrong = directory(12, 0, 100, Cause::Spontaneous, vec![entry(1, 1)]).unwrap();
    wrong[2] = Cause::FileTransfer.to_u8();
    assert_eq!(
        decode_frame(&wrong),
        Err(FtError::CauseNotListed {
            type_id: TypeId::FDrTa1,
            cause: Cause::FileTransfer
        })
    );
}

/// The directory's other two rules (cause `<3>`/`<5>` and at least one file)
/// belong to the encoder, not to one builder: a `Frame::Directory` handed
/// straight to [`encode_frame`] or to [`FileTransferProcedure::build`] is
/// refused exactly as [`directory`] refuses it.
#[test]
fn a_directory_is_built_only_with_its_two_causes_and_at_least_one_file() {
    let station = FileTransferProcedure::controlling(Selection::BOTH, 12, 0);
    for cause in [Cause::FileTransfer, Cause::Activation] {
        let refusal = Err(FtError::CauseNotListed {
            type_id: TypeId::FDrTa1,
            cause,
        });
        assert_eq!(
            encode_frame(
                12,
                0,
                &Frame::Directory {
                    ioa: 100,
                    cause,
                    files: vec![entry(1, 10)]
                }
            ),
            refusal,
            "encode_frame, cause {cause:?}"
        );
        assert_eq!(
            station.build(&Frame::Directory {
                ioa: 100,
                cause,
                files: vec![entry(1, 10)]
            }),
            Err(FtError::CauseNotListed {
                type_id: TypeId::FDrTa1,
                cause
            }),
            "build, cause {cause:?}"
        );
        assert_eq!(
            directory(12, 0, 100, cause, vec![entry(1, 10)]),
            Err(FtError::CauseNotListed {
                type_id: TypeId::FDrTa1,
                cause
            }),
            "the builder, cause {cause:?}"
        );
    }

    // `N = 0`: figure 89's element is one file repeated `j` times, and a
    // directory with no file is clause 7.2.2's "no INFORMATION OBJECT".
    let empty = Frame::Directory {
        ioa: 100,
        cause: Cause::Spontaneous,
        files: Vec::new(),
    };
    assert_eq!(
        encode_frame(12, 0, &empty),
        Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FDrTa1,
            count: 0
        }))
    );
    assert_eq!(
        station.build(&empty),
        Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FDrTa1,
            count: 0
        }))
    );
    assert_eq!(
        directory(12, 0, 100, Cause::Spontaneous, Vec::new()),
        Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FDrTa1,
            count: 0
        }))
    );
}

/// 104's figure 31 (index 92) prints `<44> := unknown type **of file**`: the
/// *file* class of clause 8.9, not clause 7.2.3's *type identification* class.
/// So a `<127>` carrying 44 is a cause the figure does not list, not a mirror
/// this procedure invents a 48th class for.
#[test]
fn the_query_log_cause_forty_four_is_the_files_own_class() {
    let asdu = query_log(
        12,
        0,
        5,
        nof(1),
        Cp56Time2a::default(),
        Cp56Time2a::default(),
    )
    .unwrap();
    assert_eq!(Header::parse(&asdu).unwrap().cause, Cause::FileTransfer);
    assert_eq!(asdu.len(), Header::LEN + 3 + 16);

    let mut unknown_file = asdu;
    unknown_file[2] = Cause::UnknownTypeId.to_u8();
    assert_eq!(
        decode_frame(&unknown_file),
        Err(FtError::CauseNotListed {
            type_id: TypeId::FScNb1,
            cause: Cause::UnknownTypeId
        })
    );
    // With `P/N = 1` it is a mirror, and `<127>` is a type the controlling
    // station **sends** in the monitor direction, so a mirror of it is the
    // peer's refusal of a QueryLog this station sent: the requesting side's
    // answer, not a discard. The octet is the same 44 either way; only the
    // direction decides which rule reads it.
    let station = FileTransferProcedure::controlling(Selection::MONITOR, 12, 0);
    unknown_file[2] = Cause::UnknownTypeId.to_u8() | 0x40;
    assert_eq!(
        station
            .on_asdu(&unknown_file, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Refused {
            cause: Cause::UnknownTypeId
        }
    );
    // The controlled station does not send `<127>` in the monitor direction, so
    // the same mirror is not its refusal to report and is discarded.
    assert_eq!(
        FileTransferProcedure::controlled(Selection::MONITOR, 12, 0)
            .on_asdu(&unknown_file, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Discard(Discard::Mirror)
    );
}

/// Figure 31's four-row table, index 92: the two `CP56Time2a` range ends are
/// passed through and all zeros means "all records". This crate interprets
/// neither.
#[test]
fn the_query_log_carries_the_two_range_ends_unchanged() {
    let start = Cp56Time2a::default();
    let stop = Cp56Time2a::parse(&hex("34 12 00 00 00 01 16")).unwrap();
    assert_ne!(start, stop);
    let asdu = query_log(12, 0, 5, nof(1), start, stop).unwrap();
    let Frame::QueryLog {
        ioa,
        nof: name,
        range_start,
        range_stop,
    } = decode_frame(&asdu).unwrap()
    else {
        panic!("a QueryLog");
    };
    assert_eq!(ioa, 5);
    assert_eq!(name, nof(1));
    assert_eq!(range_start, start);
    assert_eq!(range_stop, stop);
}

// ------------------------------------------------------------ the APDU ceiling

/// 5-104 index 26: one `F_SG_NA_1` object carries at most 236 segment octets, on
/// the build path by [`FtError::SegmentTooLong`]. On the decode path the same
/// ceiling is enforced by the codec itself: the body budget of 243 octets leaves
/// `243 − 3 − 4 = 236` for the payload, so a segment that claims more than that
/// is [`AsduError::BodyTooLong`] before this layer sees it.
#[test]
fn a_segment_beyond_the_apdu_ceiling_is_refused_on_build_and_on_decode() {
    let longest = vec![0u8; MAX_SEGMENT];
    let asdu = segment(12, 0, 5, nof(1), nos(1), &longest).unwrap();
    assert_eq!(asdu.len(), 249, "the longest ASDU the APDU can carry");
    assert_eq!(decode_frame(&asdu).unwrap().ioa(), 5);

    let too_long = vec![0u8; MAX_SEGMENT + 1];
    assert_eq!(
        segment(12, 0, 5, nof(1), nos(1), &too_long),
        Err(FtError::SegmentTooLong {
            len: 237,
            max: MAX_SEGMENT
        })
    );

    // The same on the way in: a frame that states a longer element than the
    // codec's budget allows is rejected by the codec, never half-read.
    let mut oversize = segment(12, 0, 5, nof(1), nos(1), &[0u8; 4]).unwrap();
    oversize[12] = 237;
    oversize.extend_from_slice(&[0u8; 240]);
    match decode_frame(&oversize) {
        Err(FtError::Layout(LayoutError::Asdu(AsduError::BodyTooLong { .. }))) => {}
        other => panic!("the codec's own ceiling, not {other:?}"),
    }
    // And an ASDU of 250 octets cannot exist at all.
    let mut oversize = segment(12, 0, 5, nof(1), nos(1), &vec![0u8; MAX_SEGMENT]).unwrap();
    oversize.push(0);
    match decode_frame(&oversize) {
        Err(FtError::Layout(LayoutError::Asdu(_))) => {}
        other => panic!("the codec's own ceiling, not {other:?}"),
    }
}

/// 5-104 index 26 again: `249 = 6 + 3 + 13 j` leaves 18 files, and the 19th is
/// what fails.
#[test]
fn a_directory_beyond_the_apdu_ceiling_is_refused_on_build_and_on_decode() {
    let files: Vec<DirectoryEntry> = (0..MAX_DIRECTORY_FILES)
        .map(|i| entry(i as u16, 1))
        .collect();
    let asdu = directory(12, 0, 100, Cause::Spontaneous, files).unwrap();
    assert_eq!(asdu.len(), 6 + 3 + 13 * 18);
    assert!(asdu.len() <= 249);
    assert_eq!(
        usize::from(Header::parse(&asdu).unwrap().count),
        MAX_DIRECTORY_FILES
    );
    assert_eq!(MAX_DIRECTORY_FILES, (249 - 6 - 3) / 13);

    let mut nineteen = asdu;
    nineteen[1] = (nineteen[1] & 0x80) | 0x13;
    nineteen.extend_from_slice(&[0u8; 13]);
    assert_eq!(
        decode_frame(&nineteen),
        Err(FtError::DirectoryTooLarge {
            count: 19,
            max: MAX_DIRECTORY_FILES
        })
    );
}

/// A directory with `N = 0` is clause 7.2.2's *"ASDU contains no INFORMATION
/// OBJECT"*: there is no file to index and nothing is invented. Trailing octets
/// under `N = 0` are the codec's own `ObjectsNotExhausted`.
#[test]
fn a_directory_with_no_information_object_is_not_a_directory() {
    let asdu = header(TypeId::FDrTa1, 0, true, Cause::Spontaneous, 12);
    assert_eq!(
        decode_frame(&asdu),
        Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FDrTa1,
            count: 0
        }))
    );
    let mut with_body = asdu;
    with_body.extend_from_slice(&hex("64 00 00"));
    match decode_frame(&with_body) {
        Err(FtError::Layout(LayoutError::Asdu(AsduError::ObjectsNotExhausted {
            count: 0,
            remaining: 3,
        }))) => {}
        other => panic!("the codec's own rule, not {other:?}"),
    }
}

/// `LOS` is *"the number of octets of the segment"* (7.2.6.36), so a stated
/// length that disagrees with the octets present is an error on **every**
/// prefix length.
#[test]
fn a_segment_whose_los_disagrees_with_its_octets_is_a_finding() {
    let payload = vec![0xAAu8; 30];
    let asdu = segment(12, 0, 5, nof(1), nos(1), &payload).unwrap();
    assert_eq!(decode_frame(&asdu).unwrap().ioa(), 5);
    for stated in [0u8, 1, 5, 29, 31, 40, 236] {
        let mut wrong = asdu.clone();
        wrong[12] = stated;
        assert_eq!(
            decode_frame(&wrong),
            Err(FtError::SegmentLengthMismatch {
                stated: usize::from(stated),
                present: 30
            }),
            "LOS = {stated}"
        );
    }
}

/// `LOS` = 0 is *"<0> := not used"* (7.2.6.36, index 58): a segment with no
/// octets is refused on both paths, and the element writer refuses the two
/// lengths `LOS` cannot state rather than clamping one.
#[test]
fn an_empty_segment_is_not_a_segment() {
    assert_eq!(
        segment(12, 0, 5, nof(1), nos(1), &[]),
        Err(FtError::EmptySegment)
    );
    let nothing = Segment {
        nof: nof(1),
        nos: nos(1),
        los: Los { value: 0 },
        payload: Vec::new(),
    };
    let frame = Frame::Segment {
        ioa: 5,
        segment: nothing.clone(),
    };
    assert_eq!(encode_frame(12, 0, &frame), Err(FtError::EmptySegment));
    assert_eq!(
        FileTransferProcedure::controlling(Selection::BOTH, 12, 0).build(&frame),
        Err(FtError::EmptySegment)
    );
    // On the way in: the header, the address and `NOF`/`NOS`/`LOS` with no
    // octet after them is an ASDU of thirteen octets and is refused.
    let empty = hex("7D 01 0D 00 0C 00 05 00 00 01 00 01 00");
    assert_eq!(empty.len(), Header::LEN + 3 + Segment::PREFIX_LEN);
    assert_eq!(decode_frame(&empty), Err(FtError::EmptySegment));
    // The geometry layer reads the octets it is given; the writer will not
    // produce an element nobody has.
    assert!(decode_segment(&empty).is_ok());
    assert_eq!(
        nothing.element(),
        Err(LayoutError::EmptySegment {
            type_id: TypeId::FSgNa1
        })
    );

    // A `LOS` the payload contradicts is the other end: `LOS` is one octet and
    // [`MAX_SEGMENT`] is 236, so a 237-octet payload is refused rather than
    // clamped to 255 or truncated.
    let too_long = Segment {
        nof: nof(1),
        nos: nos(1),
        los: Los { value: 0 },
        payload: vec![0u8; MAX_SEGMENT + 1],
    };
    assert_eq!(
        too_long.element(),
        Err(LayoutError::SegmentTooLong {
            len: MAX_SEGMENT + 1,
            max: MAX_SEGMENT
        })
    );
    // The longest legal element is `4 + 236` octets and its `LOS` octet is 236.
    let longest = Segment {
        nof: nof(1),
        nos: nos(1),
        los: Los { value: 0 },
        payload: vec![0u8; MAX_SEGMENT],
    };
    let element = longest.element().unwrap();
    assert_eq!(element.len(), Segment::PREFIX_LEN + MAX_SEGMENT);
    assert_eq!(element[Segment::PREFIX_LEN - 1], MAX_SEGMENT as u8);
}

/// Every ASDU of the family, cut at every length, is a typed error: no path in
/// this layer panics on network input.
#[test]
fn every_prefix_of_every_frame_is_a_typed_error() {
    for frame in the_eight_frames() {
        let asdu = encode_frame(12, 0, &frame).unwrap();
        for len in 0..asdu.len() {
            let prefix = &asdu[..len];
            assert!(
                decode_frame(prefix).is_err(),
                "{:?} cut at {len}",
                frame.type_id()
            );
            assert!(Header::parse(prefix).is_err() || len >= Header::LEN);
        }
    }
}

// ------------------------------------------------------------------ the CHS

/// 5-101 clause 7.2.6.37, verbatim: *"arithmetic sum disregarding overflows (sum
/// modulo 256) over all octets of a section … or of a complete file"*.
#[test]
fn the_checksum_is_the_sum_modulo_two_hundred_and_fifty_six() {
    assert_eq!(checksum(&[]).value, 0);
    assert_eq!(checksum(&[1, 2, 3]).value, 6);
    assert_eq!(
        checksum(&[0xFF, 0x02]).value,
        1,
        "the overflow is disregarded"
    );
    assert_eq!(checksum(&[0xFF; 300]).value, 212, "300 × 255 modulo 256");
    let octets: Vec<u8> = (0..=255u8).collect();
    assert_eq!(checksum(&octets).value, 0x80);
    assert_eq!(Chs::LEN, 1);
}

/// A mismatch is a typed error, not a panic and not a silent pass.
#[test]
fn a_checksum_that_does_not_add_up_is_a_finding() {
    let octets = [1u8, 2, 3, 4];
    let right = checksum(&octets);
    assert_eq!(right.value, 10);
    assert_eq!(check_checksum(&octets, right), Ok(()));
    assert_eq!(
        check_checksum(&octets, Chs { value: 11 }),
        Err(FtError::ChecksumMismatch {
            expected: Chs { value: 10 },
            got: Chs { value: 11 }
        })
    );
    // One octet short of the section the checksum was taken over.
    assert!(check_checksum(&octets[1..], right).is_err());
    // And the frame that carries it: the caller computes, this crate compares.
    let asdu = last_segment(12, 0, 5, nof(1), nos(1), Lsq { value: 1 }, right).unwrap();
    let Frame::LastSection { chs, .. } = decode_frame(&asdu).unwrap() else {
        panic!("a last section");
    };
    assert_eq!(check_checksum(&octets, chs), Ok(()));
}

// --------------------------------------------------------------- the address

/// 5-101 clause 7.2.4 (index 43) permits a broadcast for `C_IC_NA_1`,
/// `C_CI_NA_1`, `C_CS_NA_1` and `C_RP_NA_1` alone. None of `<120>`–`<127>` is
/// on that list, so every builder refuses the address and says why.
#[test]
fn the_broadcast_address_is_refused_by_every_builder() {
    assert_eq!(BROADCAST_CA, 0xFFFF);
    for (name, built) in every_builder(BROADCAST_CA) {
        assert_eq!(
            built,
            Err(FtError::BroadcastAddress {
                common_address: BROADCAST_CA
            }),
            "{name}"
        );
    }
    // A station's own address is fine, in every builder.
    for (name, built) in every_builder(12) {
        assert!(built.is_ok(), "{name}");
    }
}

/// A file-transfer frame that *arrives* at `FF`/`FFFF` is refused with the
/// class-46 mirror, by TS 60870-5-604 5.4.10.10 (index 54): *"The Controlled
/// station rejects all other ASDU Types with a Broadcast CASDU value by
/// mirroring the ASDU with P/N = 1 negative (and with COT = 46, if supported)"*.
#[test]
fn a_broadcast_file_frame_is_refused_with_the_class_forty_six_mirror() {
    let station = FileTransferProcedure::controlled(Selection::MONITOR, 12, 0);
    let mut asdu = directory(12, 0, 100, Cause::Spontaneous, vec![entry(1, 1)]).unwrap();
    asdu[4..6].copy_from_slice(&BROADCAST_CA.to_le_bytes());
    let outcome = station.on_asdu(&asdu, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            cause: Cause::UnknownCommonAddress
        }
    );
    assert_eq!(outcome.send.len(), 1);
    let mirror = Header::parse(&outcome.send[0]).unwrap();
    assert_eq!(mirror.cause, Cause::UnknownCommonAddress);
    assert!(mirror.negative, "P/N = 1");
    assert_eq!(mirror.common_address, 12, "the station's own address");
    assert_eq!(
        &outcome.send[0][Header::LEN..],
        &asdu[Header::LEN..],
        "the object area is copied octet for octet"
    );
}

/// Clause 7.2.3's table is a rule about fields the station does not know: the
/// ASDU comes back mirrored with the class's cause, never silently dropped.
#[test]
fn a_field_the_station_does_not_know_is_mirrored_and_not_dropped() {
    let station = FileTransferProcedure::controlled(Selection::BOTH, 12, 0);
    let asdu = file_ready(12, 0, 5, nof(1), Lof { value: 2 }, Frq::default()).unwrap();
    let known = Known {
        type_id: true,
        cause: true,
        common_address: false,
        information_object_address: true,
    };
    let outcome = station.on_asdu(&asdu, &known).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            cause: Cause::UnknownCommonAddress
        }
    );
    assert_eq!(outcome.send.len(), 1);
    // Cause 44 comes first for a station that knows nothing at all.
    let nothing = station.on_asdu(&asdu, &Known::NOTHING).unwrap();
    assert_eq!(
        nothing.reaction,
        Reaction::Refused {
            cause: Cause::UnknownTypeId
        }
    );
}

/// A mirrored ASDU that is a refusal of what **this** station sent is
/// [`Reaction::Refused`] (the shape of `src/ts.rs`'s `on_response`), the only
/// way the requesting side ever hears why its frame was refused. A mirror of a
/// family this station serves in the other direction is another station's
/// refusal and is discarded, not answered, so two stations cannot mirror each
/// other forever.
#[test]
fn a_mirrored_frame_is_the_refusal_of_what_this_station_sent() {
    let causes = [
        Cause::UnknownTypeId,
        Cause::UnknownCause,
        Cause::UnknownCommonAddress,
        Cause::UnknownInformationObjectAddress,
    ];

    // In the monitor direction the controlling station sends `F_SC` (its call
    // directory, select file, call file, call section), `F_AF` and `F_SC_NB`.
    let controlling = FileTransferProcedure::controlling(Selection::MONITOR, 12, 0);
    let controlled = FileTransferProcedure::controlled(Selection::MONITOR, 12, 0);
    let mut asked = call_directory(12, 0, 5, nof(1)).unwrap();
    for cause in causes {
        // P/N is bit 7 of the cause-of-transmission octet (index 2); SQ, which
        // is bit 8 of the VSQ octet, is a different field entirely.
        asked[2] = cause.to_u8() | 0x40;
        let outcome = controlling.on_asdu(&asked, &Known::EVERYTHING).unwrap();
        assert_eq!(outcome.reaction, Reaction::Refused { cause }, "{cause:?}");
        assert!(
            outcome.send.is_empty(),
            "a refusal is not answered with a mirror of its own"
        );
        // The controlled station is the *provider* in the monitor direction: it
        // did not send that `F_SC`, so the mirror is not its refusal.
        assert_eq!(
            controlled
                .on_asdu(&asked, &Known::EVERYTHING)
                .unwrap()
                .reaction,
            Reaction::Discard(Discard::Mirror),
            "{cause:?}"
        );
    }

    // `F_DR` is the other way round: the controlled station sends it in the
    // monitor direction, so the mirror is *its* peer's refusal.
    let mut mirror = directory(12, 0, 100, Cause::Spontaneous, vec![entry(1, 1)]).unwrap();
    mirror[2] = Cause::UnknownTypeId.to_u8() | 0x40;
    assert_eq!(
        controlled
            .on_asdu(&mirror, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Refused {
            cause: Cause::UnknownTypeId
        }
    );
    assert_eq!(
        controlling
            .on_asdu(&mirror, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Discard(Discard::Mirror)
    );

    // A station that runs neither direction serves no family, so every mirror
    // is discarded.
    let none = FileTransferProcedure::controlling(Selection::NONE, 12, 0);
    assert_eq!(
        none.on_asdu(&asked, &Known::EVERYTHING).unwrap().reaction,
        Reaction::Discard(Discard::Mirror)
    );
    assert_eq!(
        none.on_asdu(&mirror, &Known::EVERYTHING).unwrap().reaction,
        Reaction::Discard(Discard::Mirror)
    );
}

/// An ASDU of another family is not this procedure's business.
#[test]
fn an_asdu_of_another_type_is_other() {
    let station = FileTransferProcedure::controlled(Selection::BOTH, 12, 0);
    let asdu = hex("01 01 03 00 0C 00 10 30 00 01 00");
    assert_eq!(
        station.on_asdu(&asdu, &Known::EVERYTHING).unwrap().reaction,
        Reaction::Other
    );
    assert_eq!(Header::parse(&asdu).unwrap().type_id, TypeId::MSpNa1);
    // ... and not a frame this layer can decode either.
    assert_eq!(
        decode_frame(&asdu),
        Err(FtError::NotThisType {
            type_id: TypeId::MSpNa1
        })
    );
}

// ------------------------------------------------------------- the directions

/// 5-104 clause 9.6 (index 114) carries **two** file-transfer checkboxes, and
/// which one a frame belongs to is decided by who sends it, as TS
/// 60870-5-604's `5.4.23.1` (index 84, monitor direction) and `5.4.23.10`
/// (index 85, control direction) spell out.
#[test]
fn the_direction_is_decided_by_who_sends_the_frame() {
    // The matrix the two 604 cases spell out: in the monitor
    // direction the controlling station sends the F_SC requests and the F_AF
    // acknowledgements and the controlled station sends the rest.
    let monitor_only = Selection::MONITOR;
    let controlling = FileTransferProcedure::controlling(monitor_only, 12, 0);
    let controlled = FileTransferProcedure::controlled(monitor_only, 12, 0);

    for frame in [
        Frame::Sc {
            ioa: 1,
            nof: nof(1),
            nos: nos(0),
            scq: Scq::default(),
        },
        Frame::Ack {
            ioa: 1,
            nof: nof(1),
            nos: nos(1),
            afq: Afq {
                action: Afq::SECTION_POSITIVE,
                error: 0,
            },
        },
        Frame::QueryLog {
            ioa: 1,
            nof: nof(1),
            range_start: Cp56Time2a::default(),
            range_stop: Cp56Time2a::default(),
        },
    ] {
        assert!(controlling.build(&frame).is_ok(), "{:?}", frame.type_id());
        assert_eq!(
            controlled.build(&frame),
            Err(FtError::NotSelectedDirection {
                direction: iec104::asdu::Direction::Control
            }),
            "{:?}",
            frame.type_id()
        );
    }
    for frame in the_eight_frames()
        .into_iter()
        .filter(|frame| !frame.is_receiver_side())
    {
        assert!(controlled.build(&frame).is_ok(), "{:?}", frame.type_id());
        assert_eq!(
            controlling.build(&frame),
            Err(FtError::NotSelectedDirection {
                direction: iec104::asdu::Direction::Control
            }),
            "{:?}",
            frame.type_id()
        );
    }

    // The control direction is the mirror image: the controlling station
    // provides the file and the controlled one requests and acknowledges it.
    let control_only = Selection::CONTROL;
    let controlling = FileTransferProcedure::controlling(control_only, 12, 0);
    let controlled = FileTransferProcedure::controlled(control_only, 12, 0);
    assert!(
        controlling.build(&the_eight_frames()[1]).is_ok(),
        "F_FR in the control direction"
    );
    assert_eq!(
        controlling.build(&the_eight_frames()[0]),
        Err(FtError::NotSelectedDirection {
            direction: iec104::asdu::Direction::Monitor
        })
    );
    assert!(
        controlled.build(&the_eight_frames()[0]).is_ok(),
        "F_SC in the control direction"
    );
    assert_eq!(
        controlled.build(&the_eight_frames()[1]),
        Err(FtError::NotSelectedDirection {
            direction: iec104::asdu::Direction::Monitor
        }),
        "the controlled station provides the file in the monitor direction"
    );

    // A received frame is the counterpart's, and is refused the same way: the
    // controlled station is the one that sends the segments in the monitor
    // direction, so a segment offered *to* it would have to come from the
    // controlling station, which is the control direction and not selected.
    let controlled = FileTransferProcedure::controlled(monitor_only, 12, 0);
    let offered = segment(12, 0, 5, nof(1), nos(1), &[0u8; 4]).unwrap();
    assert_eq!(
        controlled.on_asdu(&offered, &Known::EVERYTHING),
        Err(FtError::NotSelectedDirection {
            direction: iec104::asdu::Direction::Control
        })
    );
    // The controlling station is the one that may receive it, and reads it as
    // the answer it is.
    assert!(matches!(
        FileTransferProcedure::controlling(monitor_only, 12, 0)
            .on_asdu(&offered, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Answered { .. }
    ));
    let asked = call_directory(12, 0, 5, nof(1)).unwrap();
    assert!(matches!(
        controlled
            .on_asdu(&asked, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Requested { .. }
    ));
}

/// A station that has marked neither box (5-104 clause 9.6's *"if function is
/// used"*) builds nothing and answers nothing.
#[test]
fn a_station_with_no_direction_selected_refuses_the_function() {
    let station = FileTransferProcedure::controlling(Selection::NONE, 12, 0);
    assert_eq!(
        station.build(&the_eight_frames()[0]),
        Err(FtError::FunctionNotUsed)
    );
    let asdu = call_directory(12, 0, 5, nof(1)).unwrap();
    assert_eq!(
        station.on_asdu(&asdu, &Known::EVERYTHING),
        Err(FtError::FunctionNotUsed)
    );
}

/// `Selection` is a value in `StationFunctions`' shape: named constants, a
/// `with`, a `uses`, a `count` and a `Default` of nothing.
#[test]
fn the_selection_is_a_two_checkbox_value() {
    use iec104::asdu::Direction::{Both, Control, Monitor};

    assert_eq!(Selection::default(), Selection::NONE);
    assert_eq!(Selection::NONE.count(), 0);
    assert_eq!(Selection::MONITOR.count(), 1);
    assert_eq!(Selection::CONTROL.count(), 1);
    assert_eq!(Selection::BOTH.count(), 2);
    assert!(!Selection::NONE.uses_function());
    assert!(Selection::MONITOR.uses_function());

    assert!(
        Selection::BOTH.uses(Monitor)
            && Selection::BOTH.uses(Control)
            && Selection::BOTH.uses(Both)
    );
    assert!(Selection::MONITOR.uses(Monitor) && !Selection::MONITOR.uses(Control));
    assert_eq!(Selection::NONE.with(Monitor, true), Selection::MONITOR);
    assert_eq!(Selection::MONITOR.with(Monitor, false), Selection::NONE);
    assert_eq!(Selection::NONE.with(Control, true), Selection::CONTROL);
    assert_eq!(Selection::MONITOR.with(Both, true), Selection::BOTH);
    assert_eq!(Selection::BOTH.with(Control, false), Selection::MONITOR);
}

/// The role and the addressing are what the instance holds, and nothing else:
/// which section is in flight is the caller's, so the procedure is `Copy` and
/// a second instance built from the same values is equal to the first.
#[test]
fn the_procedure_holds_only_the_role_the_selection_and_the_addressing() {
    let one = FileTransferProcedure::controlling(Selection::MONITOR, 12, 7);
    let two = one;
    assert_eq!(one, two);
    assert_eq!(one.role(), Role::Controlling);
    assert_eq!(
        FileTransferProcedure::controlled(Selection::MONITOR, 12, 7).role(),
        Role::Controlled
    );
    assert_eq!(one.selection(), Selection::MONITOR);
    assert_eq!(one.addressing(), (12, 7));
    let asdu = one.build(&the_eight_frames()[0]).unwrap();
    let header = Header::parse(&asdu).unwrap();
    assert_eq!((header.common_address, header.originator), (12, 7));
}

/// The **request this station sent** is the argument, and the answer is checked
/// against what it asked for: the information object address always, the name of
/// file when both frames carry one, and the name of section only when the
/// request named one (`A_CALL_SECTION`). The answer itself cannot be stated in
/// advance: its `LOF`/`SRQ`, its octets and its `CHS` are the peer's to fill in,
/// and so is the section a call file or a section acknowledgement is answered
/// with (clause 7.4.11's own exchange, indices 131–133).
#[test]
fn the_answer_must_be_the_answer_to_the_request_this_station_sent() {
    let known = Known::EVERYTHING;
    // The station that asks for a section is the controlling one in the monitor
    // direction, so its peer's frames arrive as `Answered`.
    let station = FileTransferProcedure::controlling(Selection::MONITOR, 12, 0);

    // A_CALL_FILE.req (SCQ = <2>, NOS <0>) is answered by A_SECTION1_READY, the
    // file's *first* section, so the answer's NOS is the peer's to state (it is
    // the very pair the scripted exchange below sends). What the call asked for
    // is the file.
    let sent = call_file(12, 0, 5, nof(1), nos(0)).unwrap();
    let sent_frame = decode_frame(&sent).unwrap();
    let answer =
        section_ready(12, 0, 5, nof(1), nos(1), Lof { value: 30 }, Srq::default()).unwrap();
    assert!(station.on_answer(&answer, &known, &sent_frame).is_ok());

    // The same section ready under another name of file is not the answer...
    let other_file =
        section_ready(12, 0, 5, nof(2), nos(1), Lof { value: 30 }, Srq::default()).unwrap();
    assert_eq!(
        station.on_answer(&other_file, &known, &sent_frame),
        Err(FtError::EchoMismatch {
            expected: sent_frame.clone(),
            got: decode_frame(&other_file).unwrap()
        })
    );

    // ... and another address is not the answer either.
    let elsewhere =
        section_ready(12, 0, 6, nof(1), nos(1), Lof { value: 30 }, Srq::default()).unwrap();
    assert!(matches!(
        station.on_answer(&elsewhere, &known, &sent_frame),
        Err(FtError::EchoMismatch { .. })
    ));

    // A_ACK_SECTION1.req (F_AF, AFQ <3>, NOS 1) is answered by section 2 ready or
    // by the last section, so neither the answer's NOS nor its type is the
    // caller's to demand.
    let sent = ack(
        12,
        0,
        5,
        nof(1),
        nos(1),
        Afq {
            action: Afq::SECTION_POSITIVE,
            error: 0,
        },
    )
    .unwrap();
    let sent_frame = decode_frame(&sent).unwrap();
    let next_section =
        section_ready(12, 0, 5, nof(1), nos(2), Lof { value: 30 }, Srq::default()).unwrap();
    assert!(
        station
            .on_answer(&next_section, &known, &sent_frame)
            .is_ok()
    );
    let last = last_segment(
        12,
        0,
        5,
        nof(1),
        nos(2),
        Lsq {
            value: Lsq::SECTION_WITH_DEACTIVATION,
        },
        checksum(&[0u8; 4]),
    )
    .unwrap();
    assert!(station.on_answer(&last, &known, &sent_frame).is_ok());
    // The name of file is still checked on that path.
    let other_file = last_segment(
        12,
        0,
        5,
        nof(2),
        nos(2),
        Lsq {
            value: Lsq::SECTION_WITH_DEACTIVATION,
        },
        checksum(&[0u8; 4]),
    )
    .unwrap();
    assert!(matches!(
        station.on_answer(&other_file, &known, &sent_frame),
        Err(FtError::EchoMismatch { .. })
    ));

    // A_CALL_SECTION.req *does* name a section, and `F_SG` carries both names,
    // so its section is checked.
    let sent = call_section(12, 0, 1, nof(1), nos(1)).unwrap();
    let sent_frame = decode_frame(&sent).unwrap();
    let payload = [7u8; 4];
    let right = segment(12, 0, 1, nof(1), nos(1), &payload).unwrap();
    assert!(station.on_answer(&right, &known, &sent_frame).is_ok());
    let wrong_section = segment(12, 0, 1, nof(1), nos(2), &payload).unwrap();
    assert!(matches!(
        station.on_answer(&wrong_section, &known, &sent_frame),
        Err(FtError::EchoMismatch { .. })
    ));
    let wrong_file = segment(12, 0, 1, nof(2), nos(1), &payload).unwrap();
    assert!(matches!(
        station.on_answer(&wrong_file, &known, &sent_frame),
        Err(FtError::EchoMismatch { .. })
    ));

    // A_CALL_DIRECTORY.req is answered by the directory, whose element carries
    // one name of file *per file*: the address is what is compared, so any
    // listing at that address answers the call.
    let sent = call_directory(12, 0, 1, nof(0)).unwrap();
    let sent_frame = decode_frame(&sent).unwrap();
    let listing = directory(12, 0, 1, Cause::Request, vec![entry(9, 10), entry(8, 20)]).unwrap();
    assert!(station.on_answer(&listing, &known, &sent_frame).is_ok());
    let elsewhere = directory(12, 0, 2, Cause::Request, vec![entry(1, 10)]).unwrap();
    assert!(matches!(
        station.on_answer(&elsewhere, &known, &sent_frame),
        Err(FtError::EchoMismatch { .. })
    ));

    // A frame that is not an answer at all is not an echo failure: a request
    // arriving at the station that serves the file is `Requested`, and nothing
    // is compared.
    let controlled = FileTransferProcedure::controlled(Selection::MONITOR, 12, 0);
    let asked = call_directory(12, 0, 1, nof(1)).unwrap();
    assert!(controlled.on_answer(&asked, &known, &sent_frame).is_ok());
}

// ------------------------------------------------------------ the procedure

/// Clause 7.11's exchange, run end to end between the two roles, with **every
/// step's octets asserted**: call directory, directory, select file, file
/// ready, call file, section ready, call section, two segments, last segment
/// (`LSQ` `<3>`/`<4>`), acknowledge section (`AFQ` `<3>`/`<4>`), last section
/// (`LSQ` `<1>`/`<2>`) and acknowledge file (`AFQ` `<1>`/`<2>`). An exchange
/// that only asserts reactions cannot see a symmetric encoder bug.
#[test]
fn the_scripted_exchange_of_clause_seven_eleven() {
    let controlling = FileTransferProcedure::controlling(Selection::MONITOR, 12, 0);
    let controlled = FileTransferProcedure::controlled(Selection::MONITOR, 12, 0);
    let known = Known::EVERYTHING;

    // `true` is the controlling station sending, `false` the controlled one.
    let steps: Vec<(bool, Vec<u8>, &str)> = vec![
        (
            true,
            call_directory(12, 0, 1, nof(1)).unwrap(),
            // cause <5>, SCQ 00, the figure's defaults for a call directory.
            "7A 01 05 00 0C 00 01 00 00 01 00 00 00",
        ),
        (
            false,
            directory(12, 0, 1, Cause::Request, vec![entry(1, 30)]).unwrap(),
            // SQ = 1, N = 1, cause <5> requested, one 13-octet file at A = 1.
            "7E 81 05 00 0C 00 01 00 00 01 00 1E 00 00 00 00 00 00 00 00 00 00",
        ),
        (
            true,
            select_file(12, 0, 1, nof(1), nos(0)).unwrap(),
            "7A 01 0D 00 0C 00 01 00 00 01 00 00 01",
        ),
        (
            false,
            file_ready(12, 0, 1, nof(1), Lof { value: 30 }, Frq::default()).unwrap(),
            // `LOF` 1E 00 00 (30) and the positive confirm FRQ 00.
            "78 01 0D 00 0C 00 01 00 00 01 00 1E 00 00 00",
        ),
        (
            true,
            call_file(12, 0, 1, nof(1), nos(0)).unwrap(),
            "7A 01 0D 00 0C 00 01 00 00 01 00 00 02",
        ),
        (
            false,
            section_ready(12, 0, 1, nof(1), nos(1), Lof { value: 30 }, Srq::default()).unwrap(),
            // seven-octet element: NOF 01 00, NOS 01, LOF 1E 00 00, SRQ 00.
            "79 01 0D 00 0C 00 01 00 00 01 00 01 1E 00 00 00",
        ),
        (
            true,
            call_section(12, 0, 1, nof(1), nos(1)).unwrap(),
            "7A 01 0D 00 0C 00 01 00 00 01 00 01 06",
        ),
    ];
    for (from_controlling, asdu, literal) in steps {
        assert_eq!(asdu, hex(literal), "clause 7.11's own octets");
        let outcome = if from_controlling {
            controlled.on_asdu(&asdu, &known).unwrap()
        } else {
            controlling.on_asdu(&asdu, &known).unwrap()
        };
        assert_eq!(
            outcome.reaction
                == Reaction::Requested {
                    frame: decode_frame(&asdu).unwrap()
                },
            from_controlling,
            "the side that sends a request is the receiver side"
        );
        assert!(
            outcome.send.is_empty(),
            "the answer is the caller's to send"
        );
    }

    transfer_the_section(&controlling, &controlled, known);
}

/// The second half of clause 7.11's exchange: the section's segments, its last
/// segment, the acknowledgements and the last section.
fn transfer_the_section(
    controlling: &FileTransferProcedure,
    controlled: &FileTransferProcedure,
    known: Known,
) {
    // The section: two segments of fifteen octets, then a last segment with the
    // section's checksum (`LSQ` <4> = section transfer with deactivation).
    let payload = [3u8; 30];
    let segments = [
        (
            segment(12, 0, 1, nof(1), nos(1), &payload[..15]).unwrap(),
            // LOS 0F (15) and fifteen 03 octets: 6 + 3 + 4 + 15 = 28.
            "7D 01 0D 00 0C 00 01 00 00 01 00 01 0F \
             03 03 03 03 03 03 03 03 03 03 03 03 03 03 03",
        ),
        (
            segment(12, 0, 1, nof(1), nos(1), &payload[15..]).unwrap(),
            "7D 01 0D 00 0C 00 01 00 00 01 00 01 0F \
             03 03 03 03 03 03 03 03 03 03 03 03 03 03 03",
        ),
    ];
    for (asdu, literal) in segments {
        assert_eq!(asdu, hex(literal), "a segment of A_SEGMENTn.req");
        let outcome = controlling.on_asdu(&asdu, &known).unwrap();
        assert!(matches!(outcome.reaction, Reaction::Answered { .. }));
    }
    let last = last_segment(
        12,
        0,
        1,
        nof(1),
        nos(1),
        Lsq {
            value: Lsq::SECTION_WITH_DEACTIVATION,
        },
        checksum(&payload),
    )
    .unwrap();
    // CHS 5A is 30 × 3 modulo 256 and LSQ 04 is <4> := section transfer with
    // deactivation (7.2.6.31).
    assert_eq!(last, hex("7B 01 0D 00 0C 00 01 00 00 01 00 01 04 5A"));
    let outcome = controlling.on_asdu(&last, &known).unwrap();
    let Reaction::Answered { frame } = outcome.reaction else {
        panic!("an answered last segment");
    };
    let Frame::LastSection { chs, lsq, .. } = frame else {
        panic!("a last section");
    };
    assert_eq!(check_checksum(&payload, chs), Ok(()));
    assert_eq!(lsq.value, Lsq::SECTION_WITH_DEACTIVATION);

    // ... and the acknowledgement travels back the other way.
    let section_ack = ack(
        12,
        0,
        1,
        nof(1),
        nos(1),
        Afq {
            action: Afq::SECTION_POSITIVE,
            error: 0,
        },
    )
    .unwrap();
    assert_eq!(section_ack, hex("7C 01 0D 00 0C 00 01 00 00 01 00 01 03"));
    let outcome = controlled.on_asdu(&section_ack, &known).unwrap();
    assert!(matches!(outcome.reaction, Reaction::Requested { .. }));

    // A_LAST_SECTION.req: the file's last section, `LSQ` <1> = file transfer
    // without deactivation (7.2.6.31), the same section checksum.
    let last_section = last_segment(
        12,
        0,
        1,
        nof(1),
        nos(1),
        Lsq {
            value: Lsq::FILE_WITHOUT_DEACTIVATION,
        },
        checksum(&payload),
    )
    .unwrap();
    assert_eq!(
        last_section,
        hex("7B 01 0D 00 0C 00 01 00 00 01 00 01 01 5A")
    );
    let outcome = controlling.on_asdu(&last_section, &known).unwrap();
    assert!(matches!(outcome.reaction, Reaction::Answered { .. }));

    // A_ACK_FILE.req: `AFQ` <1> = positive acknowledge of file transfer, and
    // the file's name of section is the figure's own <0>.
    let file_ack = ack(
        12,
        0,
        1,
        nof(1),
        nos(0),
        Afq {
            action: Afq::FILE_POSITIVE,
            error: 0,
        },
    )
    .unwrap();
    assert_eq!(file_ack, hex("7C 01 0D 00 0C 00 01 00 00 01 00 00 01"));
    let outcome = controlled.on_asdu(&file_ack, &known).unwrap();
    assert!(matches!(outcome.reaction, Reaction::Requested { .. }));
}

/// `F_SG_NA_1`'s element has no constant length, so it is read through its own
/// entry point: the generic decoder refuses it and `decode_segment` reads it.
#[test]
fn the_segment_is_read_through_its_own_entry_point() {
    let asdu = segment(12, 0, 5, nof(1), nos(1), &[0u8; 4]).unwrap();
    assert_eq!(decode_segment(&asdu).unwrap().value.payload.len(), 4);
    assert!(matches!(decode_frame(&asdu), Ok(Frame::Segment { .. })));
    // The element's own octets are the fixed prefix plus the payload.
    assert_eq!(Segment::PREFIX_LEN, 4);
    let element = &asdu[9..];
    assert_eq!(element.len(), 4 + 4);
    assert_eq!(element[3], 4, "LOS");
}

/// A single-object frame whose VSQ count is not one is refused rather than
/// half-read, including the `N = 0` case.
#[test]
fn a_single_object_frame_with_no_object_is_refused() {
    let asdu = header(TypeId::FFrNa1, 0, false, Cause::FileTransfer, 12);
    assert_eq!(
        decode_frame(&asdu),
        Err(FtError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::FFrNa1,
            count: 0
        }))
    );
    // With object octets left over under `N = 0`, the codec says so first.
    let mut with_body = asdu;
    with_body.extend_from_slice(&hex("05 00 00 01 00 00"));
    match decode_frame(&with_body) {
        Err(FtError::Layout(LayoutError::Asdu(AsduError::ObjectsNotExhausted {
            count: 0,
            remaining: 6,
        }))) => {}
        other => panic!("the codec's own rule, not {other:?}"),
    }
}

/// The generic codec's errors are carried, not replaced: a `decode_frame` of a
/// frame the layout layer rejects is that same rejection.
#[test]
fn the_layout_layers_errors_are_carried_through() {
    // An object area that does not divide into the promised objects.
    let mut asdu = file_ready(12, 0, 5, nof(1), Lof { value: 2 }, Frq::default()).unwrap();
    asdu.push(0);
    match decode_frame(&asdu) {
        Err(FtError::Layout(LayoutError::Asdu(AsduError::ObjectsNotExhausted {
            count: 1,
            remaining: 1,
        }))) => {}
        other => panic!("a carried codec error, not {other:?}"),
    }
    // A type identification outside the catalogue is not this layer's.
    assert_eq!(
        decode_frame(&hex("C8 01 03 00 0C 00 10 30 00 01")),
        Err(FtError::NotThisType {
            type_id: TypeId::Other(200)
        })
    );
}

/// Clause 7.2.3 mirrors only in the control direction. A file-ready frame the
/// controlled station sends is monitor direction, so the controlling station
/// discards one with an unknown field or a broadcast address and sends nothing.
#[test]
fn a_monitor_direction_frame_is_discarded_not_mirrored() {
    let station = FileTransferProcedure::controlling(Selection::MONITOR, 12, 0);
    let asdu = file_ready(12, 0, 5, nof(1), Lof { value: 2 }, Frq::default()).unwrap();
    let ca_unknown = Known {
        common_address: false,
        ..Known::EVERYTHING
    };
    let outcome = station.on_asdu(&asdu, &ca_unknown).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Discard(Discard::Unspecified(
            iec104::asdu::Unspecified::CommonAddress
        ))
    );
    assert!(
        outcome.send.is_empty(),
        "nothing goes back to the outstation"
    );

    let mut broadcast = asdu;
    broadcast[4..6].copy_from_slice(&BROADCAST_CA.to_le_bytes());
    let outcome = station.on_asdu(&broadcast, &Known::EVERYTHING).unwrap();
    assert!(matches!(outcome.reaction, Reaction::Discard(_)));
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
}

/// Clause 7.2.3's mirror follows the direction the **frame** travelled, not the
/// file. *"ASDUs in the control direction with undefined values in the data
/// unit identifier (except the variable structure qualifier) and the
/// information object address are mirrored by the controlled station"*, and TS
/// 60870-5-604 §5.1 (index 10): COT 44-47 *"are only defined in Monitor
/// direction (only a controlled station is allowed to send these COT)"*.
///
/// A call file (`F_SC_NA_1`) at an unknown address is mirrored with cause 47
/// by a controlled station serving the monitor direction, and discarded, with
/// nothing sent, by a controlling station serving the control direction
/// (TS 60870-5-604 5.4.23.10, index 85).
#[test]
fn only_the_controlled_station_mirrors_a_file_frame_whatever_way_the_file_goes() {
    let asdu = call_file(12, 0, 5, nof(1), nos(0)).unwrap();
    let ioa_unknown = Known {
        information_object_address: false,
        ..Known::EVERYTHING
    };

    let controlled = FileTransferProcedure::controlled(Selection::MONITOR, 12, 0);
    let outcome = controlled.on_asdu(&asdu, &ioa_unknown).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            cause: Cause::UnknownInformationObjectAddress
        }
    );
    assert_eq!(outcome.send.len(), 1, "the cause-47 mirror goes back");
    let mirror = Header::parse(&outcome.send[0]).unwrap();
    assert!(mirror.negative, "P/N = 1");
    assert_eq!(mirror.cause, Cause::UnknownInformationObjectAddress);

    let controlling = FileTransferProcedure::controlling(Selection::CONTROL, 12, 0);
    let outcome = controlling.on_asdu(&asdu, &ioa_unknown).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Discard(Discard::Unspecified(
            iec104::asdu::Unspecified::InformationObjectAddress
        ))
    );
    assert!(
        outcome.send.is_empty(),
        "a controlling station sends no COT 44-47"
    );
}
