//! Configurable ASDU address sizes.
//!
//! The ASDU address widths are **system parameters**, not a clause's content:
//! 5-101 cl.7.2.3 (PDF page index 38, printed 37) defines the originator address
//! as `UI8[9..16]<0..255>` inside a cause field that figure 14 labels
//! *"Originator address optional per system"*; cl.7.2.4 (index 42) says of the
//! common address *"The length of the COMMON ADDRESS (one or two octets) is a
//! parameter which is fixed per system."*; cl.7.2.5 (index 43) says of the
//! information object address *"The length of the INFORMATION OBJECT ADDRESS
//! (one, two or three octets) is a parameter which is fixed per system."*; and
//! 104 cl.9.5 (index 98) lists all of them as *"system-specific parameter"* with
//! the options spelled out (*"One octet"* / *"Two octets"* for the CA;
//! *"One octet"* / *"Two octets"* / *"Three octets"* for the IOA; *"One octet"*
//! / *"Two octets (with originator address). Originator address is set to zero
//! if not used"* for the COT), while calling only the APDU length fixed (*"The
//! maximum length of APDU for both directions is 253. It is a fixed system
//! parameter."*).
//!
//! [`AddressSizes`] carries the three choices. [`AddressSizes::CONVENTIONAL`]
//! (originator present, CA two octets, IOA three octets: the example the
//! 104 cl.9.5 sheet marks) is the default, and the plain names (`Header::parse`,
//! `encode_body`, `decode_asdu`, ...) are wrappers that use it. These tests pin
//! both: the wrappers are byte-for-byte and value-for-value the `_with` calls,
//! and each of the twelve legal combinations round-trips a real frame.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use iec104::asdu::layout::{AsduLayout, LayoutError, MAX_SEGMENT, Segment};
use iec104::asdu::{
    AddressSizes, AsduError, BodyReader, Cause, Header, MAX_BODY, MAX_IOA, MMeNb1, Object, TypeId,
    decode_asdu, decode_asdu_with, decode_segment, decode_segment_with, encode_body,
    encode_body_with, read_ioa, read_ioa_with, write_ioa_checked, write_ioa_checked_with,
    write_ioa_with,
};

/// Every legal profile the checked constructor accepts: 1 or 2 CA octets × 1, 2
/// or 3 IOA octets × originator present or absent. These are the twelve
/// combinations of 5-101 cl.7.2.3–7.2.5 and 104 cl.9.5.
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
                    .expect("the three widths of the sweep are the legal ones"),
                );
            }
        }
    }
    profiles
}

/// The header the round-trip tests build with: `M_ME_NB_1`, two objects, a
/// cause with both flags, an originator and a CA that fits one octet.
const fn sample_header() -> Header {
    Header {
        type_id: TypeId::MMeNb1,
        sequence: false,
        count: 2,
        cause: Cause::Spontaneous,
        negative: true,
        test: false,
        originator: 7,
        common_address: 0x0007,
    }
}

/// Why the widths must be configured rather than guessed: the conventional
/// parser cannot read a profile whose header is narrower, and with one octet
/// too many it reads the CA **past** the header.
#[test]
fn the_conventional_parser_cannot_read_a_narrower_header() {
    // A five-octet header: type (1), VSQ (1), COT (1), originator (1), CA (1).
    // That is 104 cl.9.5's *"Two octets (with originator address)"* cause
    // beside a *"One octet"* CA.
    let five = [TypeId::MSpNa1.to_u8(), 0x01, 0x03, 0x00, 0x0C];
    assert_eq!(
        Header::parse(&five),
        Err(AsduError::TooShort { need: 6, have: 5 }),
        "the conventional header is six octets, whatever the frame carries"
    );

    // The same frame plus one body octet: the CA is read out of the two octets
    // at 4..6, i.e. one octet past a five-octet header.
    let six = [TypeId::MSpNa1.to_u8(), 0x01, 0x03, 0x00, 0x0C, 0xAA];
    let header = Header::parse(&six).expect("six octets parse conventionally");
    assert_eq!(
        header.common_address, 0xAA0C,
        "the conventional parser takes the CA's second octet from the body"
    );

    // And the address field: a two-octet IOA is a short read under UI24.
    assert_eq!(
        read_ioa(&[0x01, 0x00]),
        Err(AsduError::TooShort { need: 3, have: 2 })
    );
    assert_eq!(
        read_ioa_with(&[0x01, 0x00], AddressSizes::new(2, 2, true).unwrap()),
        Ok(1)
    );
}

/// The conventional names and their `_with` forms are the same code path: with
/// [`AddressSizes::CONVENTIONAL`] the header and the body encode the
/// conventional octets, and the two decoded forms are equal values. The octets
/// are pinned as **literals**: the wrapper equality alone is definitional
/// (`Header::encode` *is* `encode_with(…, CONVENTIONAL)`), and a definitional
/// equality cannot fail.
///
/// The vendor-published `C_CI_NA_1` header of `tests/wire_vectors.rs` (Beckhoff
/// sample 1) is the second, independent pin: its six octets are read back as
/// the values that document states.
#[test]
fn the_conventional_names_and_the_sized_names_agree_byte_for_byte() {
    let header = sample_header();

    let mut plain = Vec::new();
    header.encode(&mut plain);
    let mut sized = Vec::new();
    header
        .encode_with(&mut sized, AddressSizes::CONVENTIONAL)
        .expect("CA 7 fits two octets");
    assert_eq!(plain, sized, "the conventional header's octets");
    // The conventional header's literal octets:
    // `type` 0x0B (`M_ME_NB_1` 11), `VSQ` 0x02 (count 2), `COT` 0x43
    // (spontaneous 3 with the negative bit 0x40), originator 7, CA 7
    // little-endian.
    assert_eq!(
        plain,
        vec![0x0B, 0x02, 0x43, 0x07, 0x07, 0x00],
        "the conventional header's octets, as before WP-27"
    );
    // The vendor-published header of `tests/wire_vectors.rs` sample 1 (Beckhoff
    // TF6500: type 0x65 `C_CI_NA_1`, VSQ 0x01, COT 0x0A activation termination,
    // originator 0, CA `0C 00` = 12) is read back as that document states it.
    let vendor = [
        TypeId::CCiNa1.to_u8(),
        0x01,
        Cause::ActivationTermination.to_u8(),
        0x00,
        0x0C,
        0x00,
    ];
    assert_eq!(
        Header::parse(&vendor),
        Ok(Header {
            type_id: TypeId::CCiNa1,
            sequence: false,
            count: 1,
            cause: Cause::ActivationTermination,
            negative: false,
            test: false,
            originator: 0,
            common_address: 12,
        }),
        "a pre-WP-27 vendor vector, decoded by the landed reader"
    );
    assert_eq!(
        Header::parse_with(&vendor, AddressSizes::CONVENTIONAL),
        Header::parse(&vendor)
    );
    assert_eq!(plain.len(), Header::LEN);
    assert_eq!(Header::LEN, AddressSizes::CONVENTIONAL.header_len());
    assert_eq!(Header::parse(&sized), Ok(header));
    assert_eq!(
        Header::parse_with(&sized, AddressSizes::CONVENTIONAL),
        Ok(header)
    );

    let elements: [&[u8]; 2] = [&[0x0A, 0x00, 0x00], &[0x0B, 0x00, 0x00]];
    let objects = [
        Object {
            ioa: 0x0000_0100,
            element: elements[0],
        },
        Object {
            ioa: 0x0000_0101,
            element: elements[1],
        },
    ];
    let plain_body = encode_body(&header, &objects).expect("the conventional body");
    let sized_body = encode_body_with(&header, &objects, AddressSizes::CONVENTIONAL)
        .expect("the conventional body through the sized writer");
    assert_eq!(plain_body, sized_body, "the conventional body's octets");
    // The literal body run: `IOA 0x000100` little-endian, its element, then
    // `IOA 0x000101` and its element (5-101 cl.7.2.5, SQ = 0).
    assert_eq!(
        plain_body,
        vec![
            0x00, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x01, 0x01, 0x00, 0x0B, 0x00, 0x00
        ],
        "the conventional body's octets, as before WP-27"
    );

    let mut plain_frame = plain.clone();
    plain_frame.extend_from_slice(&plain_body);
    let mut sized_frame = sized.clone();
    sized_frame.extend_from_slice(&sized_body);
    assert_eq!(plain_frame, sized_frame);

    let plain_objects = decode_asdu::<MMeNb1>(&plain_frame).expect("the conventional decode");
    let sized_objects = decode_asdu_with::<MMeNb1>(&plain_frame, AddressSizes::CONVENTIONAL)
        .expect("the conventional decode through the sized reader");
    assert_eq!(plain_objects, sized_objects);
    assert_eq!(plain_objects.len(), 2);
    assert_eq!(plain_objects[0].ioa, 0x0000_0100);
    assert_eq!(plain_objects[1].ioa, 0x0000_0101);

    // The address read/write helpers agree the same way.
    let mut ioa_out = Vec::new();
    write_ioa_with(&mut ioa_out, 0x0000_0123, AddressSizes::CONVENTIONAL);
    assert_eq!(ioa_out, vec![0x23, 0x01, 0x00]);
    assert_eq!(
        read_ioa_with(&ioa_out, AddressSizes::CONVENTIONAL),
        read_ioa(&ioa_out)
    );
    assert_eq!(
        write_ioa_checked_with(&mut Vec::new(), MAX_IOA + 1, AddressSizes::CONVENTIONAL),
        write_ioa_checked(&mut Vec::new(), MAX_IOA + 1)
    );

    // The profile constants follow `Header::LEN`'s conventional profile.
    assert_eq!(AddressSizes::CONVENTIONAL.max_ioa(), MAX_IOA);
    assert_eq!(AddressSizes::CONVENTIONAL.max_body(), MAX_BODY);
    assert_eq!(AddressSizes::default(), AddressSizes::CONVENTIONAL);
}

/// Every legal combination carries a real two-object `M_ME_NB_1` frame: the
/// header encodes at the profile's own width, the object area follows, and
/// `decode_asdu_with` returns the same addresses and elements. They are
/// asserted as the decoded **values**, because a misread width would still be a
/// well-typed result.
#[test]
fn every_legal_profile_round_trips_a_two_object_frame() {
    let profiles = every_profile();
    assert_eq!(
        profiles.len(),
        12,
        "1|2 CA octets × 1|2|3 IOA octets × originator present|absent"
    );

    let header = sample_header();
    let elements: [&[u8]; 2] = [&[0x0A, 0x00, 0x00], &[0x0B, 0x00, 0x00]];
    let objects = [
        Object {
            ioa: 0x0000_0009,
            element: elements[0],
        },
        Object {
            ioa: 0x0000_000A,
            element: elements[1],
        },
    ];

    for sizes in &profiles {
        let case = format!("{sizes:?}");
        assert_eq!(
            sizes.header_len(),
            3 + usize::from(sizes.originator_address())
                + usize::from(sizes.common_address_octets()),
            "{case}: the header's own geometry"
        );
        assert_eq!(sizes.max_body(), 249 - sizes.header_len(), "{case}");
        assert_eq!(
            sizes.max_common_address(),
            if sizes.common_address_octets() == 1 {
                0xFF
            } else {
                0xFFFF
            },
            "{case}"
        );

        let body = encode_body_with(&header, &objects, *sizes).expect("the body fits the profile");
        let mut frame = Vec::new();
        header
            .encode_with(&mut frame, *sizes)
            .expect("CA 7 fits every profile's common address");
        assert_eq!(frame.len(), sizes.header_len(), "{case}");
        frame.extend_from_slice(&body);

        // The address went on the wire in the profile's own width.
        let width = usize::from(sizes.information_object_address_octets());
        assert_eq!(
            &body[..width],
            &0x0000_0009u32.to_le_bytes()[..width],
            "{case}"
        );

        let decoded = decode_asdu_with::<MMeNb1>(&frame, *sizes).expect("the frame decodes");
        assert_eq!(decoded.len(), 2, "{case}");
        assert_eq!(decoded[0].ioa, 0x0000_0009, "{case}: the first address");
        assert_eq!(decoded[1].ioa, 0x0000_000A, "{case}: the second address");
        // The element octets survive the decode: re-encoding the value gives the
        // octets the frame carries, which is the byte-level half of the
        // round-trip.
        for (object, element) in decoded.iter().zip(elements) {
            let mut back = Vec::new();
            object.value.encode(&mut back);
            assert_eq!(back, element, "{case}: the decoded element's octets");
        }

        // The header round-trips through the profile's own width.
        let read = Header::parse_with(&frame, *sizes).expect("the built header parses");
        assert_eq!(read.type_id, header.type_id, "{case}");
        assert_eq!(read.count, 2, "{case}");
        assert_eq!(read.cause, header.cause, "{case}");
        assert_eq!(read.negative, header.negative, "{case}");
        assert_eq!(read.common_address, header.common_address, "{case}");
        assert_eq!(
            read.originator,
            if sizes.originator_address() {
                header.originator
            } else {
                0
            },
            "{case}: 104 cl.9.5's \"Originator address is set to zero if not used\""
        );

        // The body cursor, told the same profile, walks the body identically.
        let mut cursor = BodyReader::with_sizes(read, &frame[sizes.header_len()..], *sizes);
        let mut ioas = Vec::new();
        while let Some(object) = cursor.next_object(3).expect("a well-formed object") {
            ioas.push(object.ioa);
        }
        cursor.finish().expect("the body is consumed exactly");
        assert_eq!(ioas, [0x0000_0009, 0x0000_000A], "{case}");
    }
}

/// The constructor is the only way to a non-conventional profile and it refuses
/// a width the standard does not define (5-101 cl.7.2.4–7.2.5, figures 17–21).
#[test]
fn the_constructor_refuses_a_width_the_standard_does_not_define() {
    for (ca, ioa) in [(0u8, 3u8), (3, 3), (2, 0), (2, 4), (0, 0), (255, 255)] {
        assert_eq!(
            AddressSizes::new(ca, ioa, true),
            Err(AsduError::InvalidAddressSizes {
                common_address_octets: ca,
                information_object_address_octets: ioa,
            }),
            "CA {ca} octets / IOA {ioa} octets is not a legal profile"
        );
    }
    for (ca, ioa) in [(1u8, 1u8), (1, 2), (1, 3), (2, 1), (2, 2), (2, 3)] {
        for originator in [false, true] {
            assert!(
                AddressSizes::new(ca, ioa, originator).is_ok(),
                "CA {ca} / IOA {ioa} / originator {originator} is legal"
            );
        }
    }
}

/// A value the configured width cannot carry is a typed error **naming the
/// width**, never a silent truncation (5-101 cl.7.2.4–7.2.5).
#[test]
fn an_address_past_the_profile_is_refused_with_the_width_it_names() {
    // One octet: `UI8[1..8]<0..255>` (cl.7.2.5, figure 19).
    let one = AddressSizes::new(1, 1, true).expect("legal");
    assert_eq!(one.max_ioa(), 255);
    let mut out = vec![0xEE];
    assert_eq!(
        write_ioa_checked_with(&mut out, 256, one),
        Err(AsduError::IoaOutOfRangeForWidth { ioa: 256, max: 255 })
    );
    assert_eq!(out, vec![0xEE], "a refused address writes nothing");
    assert_eq!(write_ioa_checked_with(&mut out, 255, one), Ok(()));
    assert_eq!(out, vec![0xEE, 0xFF]);

    // Two octets: `UI16[1..16]<0..65535>` (figure 20).
    let two = AddressSizes::new(2, 2, true).expect("legal");
    assert_eq!(two.max_ioa(), 65_535);
    assert_eq!(
        write_ioa_checked_with(&mut Vec::new(), 65_536, two),
        Err(AsduError::IoaOutOfRangeForWidth {
            ioa: 65_536,
            max: 65_535
        })
    );
    let mut three_of_two = Vec::new();
    write_ioa_checked_with(&mut three_of_two, 0x0000_0102, two).expect("fits");
    assert_eq!(three_of_two, vec![0x02, 0x01]);

    // Three octets: the conventional profile reports `IoaOutOfRange`, the
    // variant the plain writer uses, with the same bound `16777215` (5-101
    // cl.7.2.5, figure 21).
    assert_eq!(
        write_ioa_checked_with(&mut Vec::new(), MAX_IOA + 1, AddressSizes::CONVENTIONAL),
        Err(AsduError::IoaOutOfRange { ioa: MAX_IOA + 1 })
    );
    assert_eq!(
        write_ioa_checked(&mut Vec::new(), MAX_IOA + 1),
        Err(AsduError::IoaOutOfRange { ioa: MAX_IOA + 1 })
    );
}

/// The writer checks the profile's other two bounds too: the common address
/// (`UI8[1..8]<0..255>` with one octet, cl.7.2.4 figure 17) and the per-profile
/// body budget of the 249-octet ASDU (5-104 cl.5, index 26).
#[test]
fn the_writer_refuses_a_common_address_and_a_body_the_profile_cannot_hold() {
    let one_octet_ca = AddressSizes::new(1, 1, false).expect("legal");
    assert_eq!(one_octet_ca.header_len(), 4);
    assert_eq!(one_octet_ca.max_body(), 245);

    let mut header = sample_header();
    header.common_address = 256;
    assert_eq!(
        header.encode_with(&mut Vec::new(), one_octet_ca),
        Err(AsduError::CommonAddressOutOfRange {
            common_address: 256,
            max: 255
        })
    );
    header.common_address = 255;
    assert!(
        header.encode_with(&mut Vec::new(), one_octet_ca).is_ok(),
        "255 is `COMMON ADDRESS := UI8[1..8]<0..255>`'s global address"
    );

    // The body budget is the profile's own: a narrower header leaves more room.
    let wide = AddressSizes::new(2, 3, true).expect("legal");
    assert_eq!(wide.max_body(), MAX_BODY);
    let element = [0x00u8; 246];
    let objects = [Object {
        ioa: 1,
        element: &element,
    }];
    let mut body_header = sample_header();
    body_header.count = 1;
    assert_eq!(
        encode_body_with(&body_header, &objects, one_octet_ca),
        Err(AsduError::BodyTooLong { len: 247, max: 245 })
    );
    // The same object is over the conventional budget as well, but reported
    // against the conventional bound: the two budgets differ, so this is not
    // one constant.
    assert_eq!(
        encode_body_with(&body_header, &objects, wide),
        Err(AsduError::BodyTooLong { len: 249, max: 243 })
    );
}

/// A CA or an IOA **wider** than the configured profile is simply not a legal
/// ASDU of that profile: the parser reads exactly the configured octets, so the
/// frame shows up as an over-long or truncated body. That is a typed error
/// variant, asserted as the variant and not merely as `is_err()`.
#[test]
fn a_wider_address_than_the_profile_is_not_a_legal_asdu() {
    // A conventional frame: six-octet header, three-octet IOA, three-octet
    // element. Read as a one-octet-CA profile the CA is one octet and the body
    // one octet longer than the count can claim.
    let header = Header {
        type_id: TypeId::MMeNb1,
        sequence: false,
        count: 1,
        cause: Cause::Spontaneous,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
    };
    let mut conventional = Vec::new();
    header.encode(&mut conventional);
    conventional.extend_from_slice(&[0x01, 0x00, 0x00, 0x00, 0x00, 0x00]);
    assert_eq!(conventional.len(), 12);
    assert_eq!(decode_asdu::<MMeNb1>(&conventional).map(|o| o.len()), Ok(1));

    let narrow_ca = AddressSizes::new(1, 3, true).expect("legal");
    assert_eq!(narrow_ca.header_len(), 5);
    assert_eq!(
        decode_asdu_with::<MMeNb1>(&conventional, narrow_ca),
        Err(iec104::asdu::LayoutError::Asdu(
            AsduError::ObjectsNotExhausted {
                count: 1,
                remaining: 1
            }
        )),
        "the two-octet CA made the body one octet too long for its object"
    );

    // The other direction: a one-octet-CA frame's three-octet address read as a
    // one-octet address leaves a body too short for the element.
    let mut narrow = Vec::new();
    let narrow_header = header;
    narrow_header
        .encode_with(&mut narrow, narrow_ca)
        .expect("CA 1 fits one octet");
    write_ioa_with(&mut narrow, 0x0001_0203, narrow_ca);
    assert_eq!(narrow.len(), 8);
    assert_eq!(
        decode_asdu_with::<MMeNb1>(&narrow, AddressSizes::CONVENTIONAL),
        Err(iec104::asdu::LayoutError::Asdu(
            AsduError::TruncatedElement {
                index: 0,
                need: 3,
                have: 2
            }
        )),
        "the one-octet CA left the conventional reader two body octets short"
    );

    // The three-octet-IOA profile reading the same frame keeps its address
    // whole, so this is a width fact and not a length check.
    assert_eq!(
        read_ioa_with(&narrow[narrow_ca.header_len()..], narrow_ca),
        Ok(0x01_0203)
    );
    let mut written = Vec::new();
    write_ioa_with(&mut written, 0x01_0203, narrow_ca);
    assert_eq!(written, vec![0x03, 0x02, 0x01]);
}

/// One `F_SG_NA_1` frame of `sizes`'s own geometry: the profile's header, its
/// address, the segment prefix (`NOF` at two octets, then `NOS`, then `LOS` =
/// the payload's own length) and `payload` octets behind it.
///
/// The payload is written by hand rather than through [`Segment::encode`]
/// because the point of the exercise is a payload the writer would refuse: the
/// reader's ceiling is what is under test.
fn segment_frame(sizes: AddressSizes, payload: usize) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::FSgNa1,
        sequence: false,
        count: 1,
        cause: Cause::Spontaneous,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
    };
    let mut frame = Vec::new();
    header
        .encode_with(&mut frame, sizes)
        .expect("CA 1 fits every legal profile");
    write_ioa_with(&mut frame, 1, sizes);
    frame.push(0x00); // NOF, high octet
    frame.push(0x00); // NOF, low octet
    frame.push(0x00); // NOS
    frame.push(payload as u8); // LOS
    frame.extend(std::iter::repeat_n(0xAA, payload));
    frame
}

/// `decode_segment` reports the **object area's** budget,
/// `AddressSizes::max_body()`, never the whole 249-octet ASDU.
///
/// `max` is `information_object_address_octets + Segment::PREFIX_LEN +
/// max_segment`, which is `max_body()` for every profile; for the conventional
/// profile that is 243 (`3 + Segment::PREFIX_LEN + MAX_SEGMENT`). Adding the
/// header length a second time would report the whole ASDU, `249`, as if it
/// were the area, and this test would catch it.
#[test]
fn the_segment_reader_reports_the_profiles_own_body_budget() {
    // Conventional: six-octet header, three-octet IOA, four-octet segment
    // prefix, MAX_SEGMENT + 1 = 237 payload octets. 6 + 3 + 4 + 237 = 250
    // octets on the wire, so the object area is 244. `AsduError::BodyTooLong`
    // is documented as the object area against the profile's budget
    // (5-104 cl.5: "The maximum length of the ASDU is limited to 249", less
    // the header), so both numbers are object areas, as the writer reports
    // them (`src/asdu/body.rs`): 244 against 243.
    let conventional = segment_frame(AddressSizes::CONVENTIONAL, MAX_SEGMENT + 1);
    assert_eq!(conventional.len(), 250);
    assert_eq!(AddressSizes::CONVENTIONAL.max_body(), 243);
    assert_eq!(
        decode_segment(&conventional),
        Err(LayoutError::Asdu(AsduError::BodyTooLong {
            len: 244,
            max: 243
        })),
        "the conventional reader's bound is the object area, 249 − 6 = 243"
    );
    assert_eq!(
        decode_segment_with(&conventional, AddressSizes::CONVENTIONAL),
        decode_segment(&conventional),
        "the conventional name and its `_with` form report the same bound"
    );

    // A one-octet CA with the originator present: header 3 + 1 + 1 = 5 octets,
    // so the profile's area is 249 − 5 = 244 and its segment ceiling is
    // 249 − 5 − 3 − 4 = 237 payload octets. A 250-octet frame leaves an object
    // area of 245 octets, 238 of them payload: one past the ceiling.
    let narrow_with_originator = AddressSizes::new(1, 3, true).expect("legal");
    assert_eq!(narrow_with_originator.header_len(), 5);
    assert_eq!(narrow_with_originator.max_body(), 244);
    let frame = segment_frame(narrow_with_originator, MAX_SEGMENT + 2);
    assert_eq!(frame.len(), 250);
    assert_eq!(
        decode_segment_with(&frame, narrow_with_originator),
        Err(LayoutError::Asdu(AsduError::BodyTooLong {
            len: 245,
            max: 244
        })),
        "a five-octet header leaves a 244-octet area, not 249 and not 245"
    );

    // The same CA with no originator: header 3 + 0 + 1 = 4 octets, area
    // 249 − 4 = 245. Pinned so the two budgets are visibly different numbers.
    let narrow = AddressSizes::new(1, 3, false).expect("legal");
    assert_eq!(narrow.header_len(), 4);
    assert_eq!(narrow.max_body(), 245);
    let frame = segment_frame(narrow, MAX_SEGMENT + 3);
    assert_eq!(frame.len(), 250);
    assert_eq!(
        decode_segment_with(&frame, narrow),
        Err(LayoutError::Asdu(AsduError::BodyTooLong {
            len: 246,
            max: 245
        }))
    );

    // And the bound is the profile's own value in every case, not a constant:
    // one payload octet past each profile's ceiling reports exactly that
    // profile's `max_body()`.
    for sizes in every_profile() {
        let case = format!("{sizes:?}");
        let ioa_octets = usize::from(sizes.information_object_address_octets());
        let max_segment =
            iec104::apci::MAX_ASDU - sizes.header_len() - ioa_octets - Segment::PREFIX_LEN;
        let frame = segment_frame(sizes, max_segment + 1);
        assert_eq!(frame.len(), 250, "{case}");
        assert_eq!(
            decode_segment_with(&frame, sizes),
            Err(LayoutError::Asdu(AsduError::BodyTooLong {
                len: 250 - sizes.header_len(),
                max: sizes.max_body(),
            })),
            "{case}: the reader's bound is the profile's own `max_body()`"
        );
    }
}

/// The write path takes the profile as the read path does: a narrow profile's
/// frame built by `encode_asdu_with` is the one `decode_asdu_with` reads back.
#[test]
fn encode_asdu_with_is_the_counterpart_of_decode_asdu_with() {
    use iec104::asdu::{CIcNa1, Cause, LayoutObject, Qoi, decode_asdu_with, encode_asdu_with};
    let sizes = AddressSizes::new(1, 2, false).unwrap();
    let header = Header {
        type_id: TypeId::CIcNa1,
        sequence: false,
        count: 1,
        cause: Cause::Activation,
        negative: false,
        test: false,
        originator: 0,
        common_address: 7,
    };
    let objects = [LayoutObject {
        ioa: 0,
        value: CIcNa1 {
            qoi: Qoi { value: 20 },
        },
    }];
    let frame = encode_asdu_with(&header, &objects, sizes).expect("builds");
    assert_eq!(frame, [100, 0x01, 6, 7, 0, 0, 20], "4 header + 2 IOA + QOI");
    assert_eq!(decode_asdu_with::<CIcNa1>(&frame, sizes).unwrap(), objects);
}

/// A header the octets cannot carry is refused, not masked into another one.
#[test]
fn a_header_the_octets_cannot_carry_is_refused() {
    use iec104::asdu::Cause;
    let header = Header {
        type_id: TypeId::MSpNa1,
        sequence: true,
        count: 128,
        cause: Cause::Spontaneous,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
    };
    let mut out = Vec::new();
    assert_eq!(
        header.encode_with(&mut out, AddressSizes::CONVENTIONAL),
        Err(AsduError::CountOutOfRange { count: 128 })
    );
    for cause in [
        Cause::Reserved(3),
        Cause::Reserved(200),
        Cause::Private(5),
        Cause::InterrogatedByGroup(0),
        Cause::InterrogatedByGroup(17),
        Cause::RequestedByCounterGroup(5),
    ] {
        let header = Header {
            count: 1,
            cause,
            ..header
        };
        assert_eq!(
            header.encode_with(&mut out, AddressSizes::CONVENTIONAL),
            Err(AsduError::CauseNotEncodable { cause }),
            "{cause:?}"
        );
    }
    assert!(out.is_empty(), "nothing is written for a refused header");

    // The genuine reserved and private values still go out as themselves.
    for cause in [Cause::Reserved(14), Cause::Private(48)] {
        let header = Header {
            count: 1,
            cause,
            ..header
        };
        assert!(
            header
                .encode_with(&mut out, AddressSizes::CONVENTIONAL)
                .is_ok()
        );
    }
}

// ------------------------------------------ the procedures under a profile

/// One-octet common address, two-octet object address, no originator: the
/// narrowest header the standard allows, and a common one on real systems.
fn narrow() -> AddressSizes {
    AddressSizes::new(1, 2, false).unwrap()
}

/// A general interrogation runs end to end with both stations on the narrow
/// profile, and every frame on the wire is in that profile.
#[test]
fn a_general_interrogation_runs_under_a_narrow_profile() {
    use iec104::asdu::{Known, LayoutObject, MMeNb1, Qds, Sva, encode_asdu_with};
    use iec104::gi::{DataSource, Interrogation, ReActivation, Reaction, Scope, SecondActivation};

    struct One;
    impl DataSource for One {
        fn ready(&self, _: Scope) -> bool {
            true
        }
        fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
            let header = Header {
                type_id: TypeId::MMeNb1,
                sequence: false,
                count: 1,
                cause: scope.cause(),
                negative: false,
                test: false,
                originator: 0,
                common_address: 7,
            };
            let object = LayoutObject {
                ioa: 0x0102,
                value: MMeNb1 {
                    sva: Sva { value: 42 },
                    qds: Qds::default(),
                },
            };
            out.push(encode_asdu_with(&header, &[object], narrow()).unwrap());
        }
    }

    let sizes = narrow();
    let mut master =
        Interrogation::controlling(SecondActivation::Locked, 7, 0).with_address_sizes(sizes);
    let mut station =
        Interrogation::controlled(ReActivation::Continue, 7, 0).with_address_sizes(sizes);

    let act = master.request(Scope::Station).unwrap();
    assert_eq!(act, [100, 0x01, 6, 7, 0, 0, 20], "4 header + 2 IOA + QOI");

    let confirmed = station.on_request(&act, &Known::EVERYTHING, &One).unwrap();
    assert_eq!(confirmed.send, [[100, 0x01, 7, 7, 0, 0, 20]]);
    let mut frames = confirmed.send;
    frames.extend(station.interrogated(&One).unwrap());
    frames.extend(station.complete(&One).unwrap());

    let reactions: Vec<Reaction> = frames
        .iter()
        .map(|f| master.on_response(f, &Known::EVERYTHING).unwrap().reaction)
        .collect();
    assert_eq!(
        reactions,
        [
            Reaction::ActivationConfirmed {
                scope: Scope::Station,
                negative: false
            },
            Reaction::Interrogated {
                scope: Scope::Station
            },
            Reaction::Terminated {
                scope: Scope::Station
            },
        ]
    );
}

/// A select-before-operate command under the narrow profile, and its mirror.
#[test]
fn a_command_runs_under_a_narrow_profile() {
    use iec104::asdu::{Known, Qoc, Sco};
    use iec104::ct::{
        Command, CommandMode, CommandSet, CommandTransmission, CommandValue, Reaction, Termination,
    };
    let sizes = narrow();
    let new = |controlled: bool| {
        let station = if controlled {
            CommandTransmission::controlled
        } else {
            CommandTransmission::controlling
        };
        station(
            CommandMode::SelectAndExecute,
            CommandSet::Untagged,
            Termination::All,
            7,
            0,
        )
        .with_address_sizes(sizes)
    };
    let (mut master, mut station) = (new(false), new(true));
    let command = Command::new(
        0x0203,
        CommandValue::Single {
            sco: Sco {
                scs: true,
                qoc: Qoc {
                    qu: 0,
                    select: true,
                },
            },
        },
    );
    let select = master.select(&command).unwrap();
    assert_eq!(select, [45, 0x01, 6, 7, 0x03, 0x02, 0x81]);
    let outcome = station.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x0203,
            select: true,
            negative: false
        }
    );
    assert_eq!(outcome.send, [[45, 0x01, 7, 7, 0x03, 0x02, 0x81]]);
    assert!(matches!(
        master
            .on_response(&outcome.send[0], &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Confirmed {
            select: true,
            negative: false,
            ..
        }
    ));
}

/// The broadcast common address is the profile's: `FF` with one octet.
#[test]
fn the_broadcast_address_follows_the_common_address_width() {
    use iec104::asdu::Known;
    struct Nothing;
    impl iec104::rd::DataSource for Nothing {
        fn object(&self, _: u32) -> Option<Vec<u8>> {
            None
        }
    }

    let sizes = narrow();
    assert_eq!(sizes.broadcast_common_address(), 0xFF);
    assert_eq!(
        AddressSizes::CONVENTIONAL.broadcast_common_address(),
        0xFFFF
    );

    // A read command is never broadcast: `FF` is refused on a one-octet
    // profile, and 255 is an ordinary station address on the conventional one.
    assert!(matches!(
        iec104::rd::request_with(0x0102, 0xFF, 0, sizes),
        Err(iec104::rd::RdError::BroadcastAddress {
            common_address: 0xFF
        })
    ));
    assert!(iec104::rd::request(0x0102, 0xFF, 0).is_ok());

    // And a broadcast read that arrives is mirrored with cause 46.
    let read = iec104::rd::Read::controlled(true, 7, 0).with_address_sizes(sizes);
    let broadcast = [102, 0x01, 5, 0xFF, 0x02, 0x01];
    let outcome = read
        .on_request(&broadcast, &Known::EVERYTHING, &Nothing)
        .unwrap();
    assert_eq!(outcome.send, [[102, 0x01, 0x40 | 0x2E, 7, 0x02, 0x01]]);
}

/// Clock synchronisation under the narrow profile: request and answer.
#[test]
fn clock_synchronisation_runs_under_a_narrow_profile() {
    use iec104::asdu::{Cp56Time2a, Known};
    use iec104::cs::{ClockSynchronisation, Reaction};
    let sizes = narrow();
    let master = ClockSynchronisation::controlling(7, 0).with_address_sizes(sizes);
    let station = ClockSynchronisation::controlled(7, 0).with_address_sizes(sizes);
    let request = master.request(Cp56Time2a::default()).unwrap();
    assert_eq!(request.len(), 4 + 2 + 7, "4 header + 2 IOA + CP56Time2a");
    let answered = station
        .on_request(&request, &Known::EVERYTHING, Cp56Time2a::default())
        .unwrap();
    assert_eq!(answered.send[0].len(), 4 + 2 + 7);
    assert!(matches!(
        master
            .on_response(&answered.send[0], &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Answered {
            negative: false,
            ..
        }
    ));
}

/// A narrow profile leaves room for a longer file segment, and the write path
/// uses it as the read path does: the longest segment the profile allows
/// round-trips, one octet more is refused.
#[test]
fn the_segment_limit_follows_the_profile_on_both_paths() {
    use iec104::asdu::elements::{Los, Nof, Nos};
    use iec104::asdu::{MAX_SEGMENT, max_segment_with};
    use iec104::ft::{Frame, FtError, decode_frame_with, encode_frame_with};
    let sizes = narrow();
    let max = max_segment_with(sizes);
    assert_eq!(max, 249 - 4 - 2 - 4);
    assert_eq!(max_segment_with(AddressSizes::CONVENTIONAL), MAX_SEGMENT);
    assert!(max > MAX_SEGMENT);

    let frame = |len: usize| Frame::Segment {
        ioa: 0x0102,
        segment: Segment {
            nof: Nof { value: 1 },
            nos: Nos { value: 1 },
            los: Los { value: len as u8 },
            payload: vec![0xA5; len],
        },
    };
    let asdu = encode_frame_with(7, 0, &frame(max), sizes).expect("the longest segment");
    assert_eq!(asdu.len(), 249);
    assert_eq!(decode_frame_with(&asdu, sizes).unwrap(), frame(max));
    assert!(matches!(
        encode_frame_with(7, 0, &frame(max + 1), sizes),
        Err(FtError::SegmentTooLong { .. })
    ));
}
