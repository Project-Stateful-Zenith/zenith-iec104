//! The ASDU body codec: the object area behind the 6-octet header.
//!
//! Sources: IEC 60870-5-101:2003 clause 7.2.2 /
//! figure 12 (the variable structure qualifier: `N` and `SQ`), clause 7.2.2.1
//! (SQ = 0 addresses each object, SQ = 1 addresses a sequence by its base
//! address, each following element taking the next address, one higher than
//! the one before, with only one
//! INFORMATION OBJECT on the wire), clause 7.2.5 / figure 21 (the `UI24`
//! information object address, `<0> := INFORMATION OBJECT ADDRESS is
//! irrelevant`), and IEC 60870-5-104:2006 clause 5 (max ASDU 249 octets).
//!
//! Sample 2 of `tests/wire_vectors.rs` is the Beckhoff vector this file
//! round-trips: a 7-object `M_ME_NB_1` ASDU whose elements are 3 octets each
//! (`SVA` 2 octets + `QDS` 1 octet, 5-101 cl.7.3.1.11, figure 37). The body
//! cursor does not know element geometry (that lives in the element and layout
//! layers), so it is told `3` here.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used)]

use iec104::apci;
use iec104::asdu::{
    AsduError, BodyReader, Cause, Header, IOA_IRRELEVANT, MAX_BODY, MAX_IOA, Object, TypeId,
    encode_body, write_ioa, write_ioa_checked,
};

fn hex(s: &str) -> Vec<u8> {
    s.split_whitespace()
        .map(|b| u8::from_str_radix(b, 16).expect("hex byte"))
        .collect()
}

/// The complete Beckhoff sample-2 APDU.
fn sample_2() -> Vec<u8> {
    hex(
        "68 34 5A 14 7C 00 0B 07 03 00 0C 00 10 30 00 BE 09 00 11 30 00 90 09 00 \
         0E 30 00 75 00 00 28 30 00 25 09 00 29 30 00 75 00 00 0F 30 00 0F 0A 00 \
         2E 30 00 AE 05 00",
    )
}

/// The ASDU of the Beckhoff sample-2 APDU (past the 6-octet APCI).
fn sample_2_asdu() -> Vec<u8> {
    let bytes = sample_2();
    let (apdu, _) = apci::parse(&bytes).expect("parse");
    apdu.asdu.to_vec()
}

const fn header(sequence: bool, count: u8) -> Header {
    Header {
        type_id: TypeId::MMeNb1,
        sequence,
        count,
        cause: Cause::Spontaneous,
        negative: false,
        test: false,
        originator: 0,
        common_address: 12,
    }
}

// ---------------------------------------------------------------------------
// SQ = 0: one information object address per object
// ---------------------------------------------------------------------------

/// 5-101 cl.7.2.2.1: with SQ = 0 every element carries its own information
/// object address; the Beckhoff vector carries 7
/// `M_ME_NB_1` objects of 3 octets each.
#[test]
fn sq0_decodes_every_object_of_the_beckhoff_vector() {
    let asdu = sample_2_asdu();
    let mut body = BodyReader::from_asdu(&asdu).expect("body");

    assert_eq!(body.header().count, 7);
    assert!(!body.header().sequence);
    assert_eq!(body.objects_left(), 7);
    assert_eq!(body.remaining(), 7 * 6);

    let expected: [(u32, [u8; 3]); 7] = [
        (0x3010, [0xBE, 0x09, 0x00]),
        (0x3011, [0x90, 0x09, 0x00]),
        (0x300E, [0x75, 0x00, 0x00]),
        (0x3028, [0x25, 0x09, 0x00]),
        (0x3029, [0x75, 0x00, 0x00]),
        (0x300F, [0x0F, 0x0A, 0x00]),
        (0x302E, [0xAE, 0x05, 0x00]),
    ];

    for (ioa, element) in expected {
        let object = body
            .next_object(3)
            .expect("no error")
            .expect("an object in range");
        assert_eq!(object.ioa, ioa, "IOA of object {ioa:#06x}");
        assert_eq!(object.element, element, "element of object {ioa:#06x}");
    }
    assert_eq!(body.next_object(3).expect("no error"), None);
    assert_eq!(body.objects_left(), 0);
    body.finish().expect("the area is consumed exactly");
}

/// The writer reproduces the Beckhoff object area octet for octet.
#[test]
fn sq0_re_encoding_reproduces_the_wire_octets() {
    let asdu = sample_2_asdu();
    let h = Header::parse(&asdu).expect("header");
    let mut body = BodyReader::from_asdu(&asdu).expect("body");

    let mut objects = Vec::new();
    while let Some(object) = body.next_object(3).expect("no error") {
        objects.push(object);
    }

    assert_eq!(
        encode_body(&h, &objects).expect("encode"),
        asdu[Header::LEN..],
        "round-trip of the object area"
    );
}

// ---------------------------------------------------------------------------
// SQ = 1: a sequence addressed by its base IOA
// ---------------------------------------------------------------------------

/// 5-101 cl.7.2.2.1: a sequence occupies a single information object in the
/// ASDU, and the elements are at base + i.
#[test]
fn sq1_yields_the_base_address_and_the_following_ones() {
    // Base 0x3010, three 3-octet elements, ONE IOA on the wire.
    let mut object_area = hex("10 30 00");
    object_area.extend_from_slice(&hex("01 00 00"));
    object_area.extend_from_slice(&hex("02 00 00"));
    object_area.extend_from_slice(&hex("03 00 00"));
    assert_eq!(object_area.len(), 3 + 3 * 3);

    let h = header(true, 3);
    let mut body = BodyReader::new(h, &object_area);

    let mut ioas = Vec::new();
    let mut objects = Vec::new();
    while let Some(object) = body.next_object(3).expect("no error") {
        ioas.push(object.ioa);
        objects.push(object);
    }
    assert_eq!(ioas, vec![0x3010, 0x3011, 0x3012]);
    body.finish().expect("the area is consumed exactly");

    // Re-encoding writes the base address only once.
    assert_eq!(encode_body(&h, &objects).expect("encode"), object_area);
}

/// The wire really carries one IOA: three elements cost 3 + 3 * 3 octets.
#[test]
fn sq1_does_not_read_an_ioa_per_element() {
    let object_area = hex("10 30 00 01 02 03 04 05 06 07 08 09");
    let mut body = BodyReader::new(header(true, 3), &object_area);
    let first = body.next_object(3).expect("no error").expect("object");
    assert_eq!(first.ioa, 0x3010);
    assert_eq!(first.element, &[1, 2, 3]);
    assert_eq!(body.remaining(), 6, "one base IOA, then bare elements");
}

/// 5-101 cl.7.2.5, figure 21: the address is
/// `UI24` little-endian, so the low octet comes first.
#[test]
fn the_ioa_is_little_endian_ui24() {
    let object_area = hex("FF 00 00 00 00 00");
    let mut body = BodyReader::new(header(false, 1), &object_area);
    let object = body.next_object(3).expect("no error").expect("object");
    assert_eq!(object.ioa, 0x0000_00FF);
}

// ---------------------------------------------------------------------------
// N = 0 and IOA 0
// ---------------------------------------------------------------------------

/// 5-101 cl.7.2.2: `<0> := ASDU contains no INFORMATION OBJECT`. A count of 0
/// is legal, yields no objects and is not an error.
#[test]
fn a_zero_object_count_yields_nothing() {
    let mut body = BodyReader::new(header(false, 0), &[]);
    assert_eq!(body.objects_left(), 0);
    assert_eq!(body.next_object(3).expect("count 0 is legal"), None);
    body.finish().expect("empty area consumed exactly");
}

/// An ASDU that promises no object has no octets to spend on one.
#[test]
fn a_zero_object_count_with_a_trailing_octet_is_rejected() {
    let mut body = BodyReader::new(header(false, 0), &[0x00]);
    assert_eq!(body.next_object(3).expect("no object"), None);
    assert_eq!(
        body.finish(),
        Err(AsduError::ObjectsNotExhausted {
            count: 0,
            remaining: 1
        })
    );
}

/// 5-101 cl.7.2.5: an ASDU for which the information object address has no
/// relevance (is unused) carries zero there. IOA 0 is a legal address that
/// round-trips.
#[test]
fn ioa_zero_is_legal_and_named_irrelevant() {
    assert_eq!(IOA_IRRELEVANT, 0);
    let h = header(false, 1);
    let object = Object {
        ioa: IOA_IRRELEVANT,
        element: &[0xAA, 0xBB, 0xCC],
    };
    let body = encode_body(&h, &[object]).expect("encode");
    assert_eq!(body, hex("00 00 00 AA BB CC"));

    let mut reader = BodyReader::new(h, &body);
    assert_eq!(
        reader.next_object(3).expect("no error").expect("object"),
        object
    );
    reader.finish().expect("consumed");
    // 5-101 cl.7.2.5 also says a controlling station discards an ASDU whose IOA
    // is undefined for the type. That decision belongs to the application
    // layer, so this crate only makes the value nameable.
    assert_eq!(MAX_IOA, 16_777_215);
}

// ---------------------------------------------------------------------------
// The exact-remaining-octets check
// ---------------------------------------------------------------------------

/// A cursor asked for more element octets than the area holds must name both
/// numbers rather than read short.
#[test]
fn a_truncated_element_is_a_typed_error() {
    // One object: IOA + 2 of the 3 element octets.
    let object_area = hex("10 30 00 AA BB");
    let mut body = BodyReader::new(header(false, 1), &object_area);
    assert_eq!(
        body.next_object(3),
        Err(AsduError::TruncatedElement {
            index: 0,
            need: 3,
            have: 2
        })
    );
}

/// The address itself can be cut off; that is the same class of error.
#[test]
fn a_truncated_ioa_is_a_typed_error() {
    let object_area = hex("10 30");
    let mut body = BodyReader::new(header(false, 1), &object_area);
    assert_eq!(
        body.next_object(3),
        Err(AsduError::TruncatedElement {
            index: 0,
            need: 3,
            have: 2
        })
    );

    let mut empty = BodyReader::new(header(false, 2), &[]);
    assert_eq!(
        empty.next_object(3),
        Err(AsduError::TruncatedElement {
            index: 0,
            need: 3,
            have: 0
        })
    );
}

/// An object area with octets left over cannot be attributed to any promised
/// object, so it is a typed error rather than silently dropped.
#[test]
fn an_object_area_that_does_not_divide_into_the_promised_objects_is_rejected() {
    let mut object_area = sample_2_asdu()[Header::LEN..].to_vec();
    object_area.push(0x00);
    let mut body = BodyReader::new(header(false, 7), &object_area);
    for _ in 0..7 {
        body.next_object(3).expect("no error").expect("object");
    }
    assert_eq!(
        body.finish(),
        Err(AsduError::ObjectsNotExhausted {
            count: 7,
            remaining: 1
        })
    );
}

/// A caller that stops early leaves octets behind; `finish` is what says so.
#[test]
fn finish_reports_the_objects_a_caller_never_read() {
    let object_area = hex("10 30 00 AA BB CC 11 30 00 DD EE FF");
    let mut body = BodyReader::new(header(false, 2), &object_area);
    body.next_object(3).expect("no error").expect("object");
    assert_eq!(
        body.finish(),
        Err(AsduError::ObjectsNotExhausted {
            count: 2,
            remaining: 6
        })
    );
}

/// Every prefix of a valid ASDU is a typed error: never a panic, and never a
/// silent short read.
#[test]
fn every_prefix_of_a_valid_asdu_is_a_typed_error() {
    let asdu = sample_2_asdu();
    for cut in 0..asdu.len() {
        let prefix = &asdu[..cut];
        match BodyReader::from_asdu(prefix) {
            Err(AsduError::TooShort { .. }) => assert!(cut < Header::LEN, "cut {cut}"),
            Err(other) => panic!("cut {cut}: unexpected {other:?}"),
            Ok(mut body) => {
                // Walk as far as the prefix allows; the walk must end in a
                // truncation, because the header promises 7 objects and a
                // shorter area cannot hold them.
                loop {
                    match body.next_object(3) {
                        Ok(Some(_)) => {}
                        Err(AsduError::TruncatedElement { .. }) => break,
                        other => panic!("cut {cut}: expected a truncation, got {other:?}"),
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The SQ = 1 arithmetic's own edge cases
// ---------------------------------------------------------------------------

/// A base address near the top of the `UI24` range cannot be incremented
/// without leaving it, so the sequence is rejected rather than wrapped.
#[test]
fn an_out_of_range_sequence_address_is_a_typed_error() {
    let object_area = hex("FF FF FF 01 02 03 04 05 06");
    let mut body = BodyReader::new(header(true, 2), &object_area);
    assert_eq!(
        body.next_object(3).expect("no error").expect("object").ioa,
        MAX_IOA
    );
    assert_eq!(
        body.next_object(3),
        Err(AsduError::IoaOutOfRange { ioa: MAX_IOA + 1 })
    );
}

/// The writer refuses an address wider than `UI24` rather than truncating it.
#[test]
fn a_written_address_beyond_ui24_is_rejected() {
    let h = header(false, 1);
    let object = Object {
        ioa: MAX_IOA + 1,
        element: &[0x00, 0x00, 0x00],
    };
    assert_eq!(
        encode_body(&h, &[object]),
        Err(AsduError::IoaOutOfRange { ioa: MAX_IOA + 1 })
    );
}

/// 5-101 cl.7.2.2.1 requires the sequence's elements to be equal
/// combinations of information elements, so unequal element lengths cannot be encoded.
#[test]
fn a_sequence_with_unequal_element_lengths_is_rejected() {
    let h = header(true, 2);
    let objects = [
        Object {
            ioa: 0x3010,
            element: &[1, 2, 3],
        },
        Object {
            ioa: 0x3011,
            element: &[1, 2],
        },
    ];
    assert_eq!(
        encode_body(&h, &objects),
        Err(AsduError::ElementLengthMismatch {
            index: 1,
            expected: 3,
            got: 2
        })
    );
}

/// The equality rule is not an SQ = 1 quirk: clause 7.2.2.1 says an SQ = 0 ASDU
/// holds one or more information objects, all of them **equal**.
#[test]
fn a_sq0_body_with_unequal_elements_is_rejected() {
    let h = header(false, 2);
    let objects = [
        Object {
            ioa: 0x3010,
            element: &[1, 2, 3],
        },
        Object {
            ioa: 0x3011,
            element: &[4, 5],
        },
    ];
    assert_eq!(
        encode_body(&h, &objects),
        Err(AsduError::ElementLengthMismatch {
            index: 1,
            expected: 3,
            got: 2
        })
    );
}

/// Like `encode_body`, the reader will not split one ASDU into objects of
/// different element lengths. The length is not on the wire, so those objects
/// could not have been encoded in the first place.
#[test]
fn the_reader_rejects_a_varying_element_length() {
    let object_area = hex("10 30 00 AA BB CC 11 30 00 DD EE FF");
    let mut body = BodyReader::new(header(false, 2), &object_area);
    body.next_object(3).expect("no error").expect("object");
    assert_eq!(
        body.next_object(2),
        Err(AsduError::ElementLengthMismatch {
            index: 1,
            expected: 3,
            got: 2
        })
    );
}

/// A read and a SQ = 1 write of the same impossible sequence must report the
/// same error class, not two different ones.
#[test]
fn a_sequence_address_leaving_ui24_is_the_same_error_on_both_paths() {
    let object_area = hex("FF FF FF 01 02 03 04 05 06");
    let mut body = BodyReader::new(header(true, 2), &object_area);
    body.next_object(3).expect("no error").expect("object");
    let read = body.next_object(3).expect_err("out of range");

    let h = header(true, 2);
    let objects = [
        Object {
            ioa: MAX_IOA,
            element: &[0x01, 0x02, 0x03],
        },
        // In range for the field, but base + 1 is not an address any more.
        Object {
            ioa: 0,
            element: &[0x04, 0x05, 0x06],
        },
    ];
    let written = encode_body(&h, &objects).expect_err("out of range");

    assert_eq!(
        read, written,
        "the reader and the writer must agree on the error class"
    );
    assert_eq!(read, AsduError::IoaOutOfRange { ioa: MAX_IOA + 1 });
}

/// The checked address writer refuses what the field cannot hold; the raw field
/// writer truncates, and its doc says so (5-101 cl.7.2.5).
#[test]
fn the_checked_address_writer_refuses_an_out_of_range_address() {
    let mut out = Vec::new();
    write_ioa_checked(&mut out, MAX_IOA).expect("the maximum is legal");
    assert_eq!(out, hex("FF FF FF"));

    assert_eq!(
        write_ioa_checked(&mut Vec::new(), MAX_IOA + 1),
        Err(AsduError::IoaOutOfRange { ioa: MAX_IOA + 1 })
    );

    let mut raw = Vec::new();
    write_ioa(&mut raw, 0x01FF_FFFF);
    assert_eq!(raw, hex("FF FF FF"), "the raw writer truncates");
}

/// A sequence whose addresses are not consecutive from the base cannot be
/// expressed on the wire, where only the base address is written.
#[test]
fn a_sequence_whose_addresses_are_not_consecutive_is_rejected() {
    let h = header(true, 2);
    let objects = [
        Object {
            ioa: 0x3010,
            element: &[1, 2, 3],
        },
        Object {
            ioa: 0x3015,
            element: &[4, 5, 6],
        },
    ];
    assert_eq!(
        encode_body(&h, &objects),
        Err(AsduError::SequenceNotContiguous {
            index: 1,
            expected: 0x3011,
            got: 0x3015
        })
    );
}

// ---------------------------------------------------------------------------
// Sizes
// ---------------------------------------------------------------------------

/// A body must agree with the count the header promises.
#[test]
fn a_body_whose_object_count_disagrees_with_the_header_is_rejected() {
    let h = header(false, 2);
    let objects = [Object {
        ioa: 1,
        element: &[0x00, 0x00, 0x00],
    }];
    assert_eq!(
        encode_body(&h, &objects),
        Err(AsduError::ObjectCountMismatch {
            header: 2,
            objects: 1
        })
    );
}

/// 5-104 clause 5: the ASDU may be exactly 249 octets, an object area of 243.
#[test]
fn an_asdu_of_exactly_the_maximum_length_is_legal() {
    let h = header(true, 80);
    let element = [0u8; 3];
    let objects: Vec<Object<'_>> = (0..80)
        .map(|i| Object {
            ioa: 0x1000 + i,
            element: &element,
        })
        .collect();
    let body = encode_body(&h, &objects).expect("249-octet ASDU is legal");
    assert_eq!(body.len(), MAX_BODY);
    assert_eq!(body.len() + Header::LEN, apci::MAX_ASDU);

    let mut reader = BodyReader::new(h, &body);
    assert_eq!(reader.objects_left(), 80);
    while reader.next_object(3).expect("no error").is_some() {}
    reader.finish().expect("consumed");
}

/// One element too many overflows the ASDU and is rejected by name.
#[test]
fn an_element_that_overflows_the_asdu_is_rejected() {
    let h = header(true, 81);
    let element = [0u8; 3];
    let objects: Vec<Object<'_>> = (0..81)
        .map(|i| Object {
            ioa: 0x1000 + i,
            element: &element,
        })
        .collect();
    let body = encode_body(&h, &objects);
    assert_eq!(
        body,
        Err(AsduError::BodyTooLong {
            len: MAX_BODY + 3,
            max: MAX_BODY
        })
    );
}
