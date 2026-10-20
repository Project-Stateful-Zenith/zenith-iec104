//! The two rules of IEC 60870-5-101:2003 clause 7.2.3: an ASDU in the
//! **control** direction with an undefined value in the data unit identifier or
//! the information object address is mirrored by the controlled station with
//! `P/N = 1` and the cause 44/45/46/47; an ASDU in the **monitor** direction with
//! one of those undefined fields is discarded and may be logged, and receiving
//! one must leave the handling of later messages unaffected.
//!
//! The clause's own table (PDF page index 42, printed page 41) is what the tests
//! below walk, one row at a time, plus the two sentences that decide the API:
//! precedence among the four classes is this crate's decision (the clause orders
//! nothing), and the clause expressly leaves the variable structure qualifier
//! out, so `SQ` and `N` stay the codec's own
//! business and are not a 48th cause.
//!
//! Nothing here parses an ASDU through the layout layer except where a test
//! deliberately checks that the payload survives: the rule is about octets.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used)]

use iec104::asdu::{
    CATALOGUE, CScNa1, Cause, Discard, Header, Known, LayoutError, TypeId, Unspecified,
    cause_is_defined, classify, decode_asdu, discard_reason, is_mirror, mirror_header,
    mirror_reply, type_is_defined,
};

/// A `C_SC_NA_1` (type 45, clause 7.3.2.1): SQ = 0, one object, cause `act`,
/// CA 12, IOA 0x3000, one `SCO` octet. Header and whole ASDU.
fn command_asdu() -> (Header, Vec<u8>) {
    let asdu = vec![
        0x2D, 0x01, 0x06, 0x00, 0x0C, 0x00, // data unit identifier
        0x00, 0x30, 0x00, // information object address
        0x01, // SCO
    ];
    let header = Header::parse(&asdu).expect("header");
    (header, asdu)
}

/// [`Known::EVERYTHING`] with one field flipped to `false`.
const fn unknown(field: Unspecified) -> Known {
    let mut known = Known::EVERYTHING;
    match field {
        Unspecified::TypeIdentification => known.type_id = false,
        Unspecified::CauseOfTransmission => known.cause = false,
        Unspecified::CommonAddress => known.common_address = false,
        Unspecified::InformationObjectAddress => known.information_object_address = false,
    }
    known
}

/// The four rows of clause 7.2.3's table, each reported on its own and with the
/// cause the table pairs with it.
#[test]
fn the_four_classes_report_their_own_cause() {
    let (header, _) = command_asdu();

    // A station that implements what the standard defines knows every field of
    // this ASDU, so nothing is reported.
    assert_eq!(Known::standard(&header, true, true), Known::EVERYTHING);
    assert_eq!(classify(&Known::EVERYTHING), None);

    let expected = [
        (Unspecified::TypeIdentification, 44, "type identification"),
        (
            Unspecified::CauseOfTransmission,
            45,
            "cause of transmission",
        ),
        (Unspecified::CommonAddress, 46, "common address of ASDU"),
        (
            Unspecified::InformationObjectAddress,
            47,
            "information object address",
        ),
    ];
    assert_eq!(Unspecified::ALL.len(), expected.len());

    for (index, (class, cause, field)) in expected.iter().enumerate() {
        assert_eq!(Unspecified::ALL[index], *class, "the table's own order");
        assert_eq!(class.cause().to_u8(), *cause, "clause 7.2.3's table");
        assert_eq!(class.field(), *field, "the clause's field name");
        assert_eq!(
            classify(&unknown(*class)),
            Some(*class),
            "one undefined field is that field's class"
        );
    }

    // The four causes are the four "unknown …" replies of 5-101 table 14.
    assert_eq!(Cause::from_u8(44), Cause::UnknownTypeId);
    assert_eq!(Cause::from_u8(47), Cause::UnknownInformationObjectAddress);
}

/// The clause orders nothing, so the crate does: the table's order. A station
/// that reports 44 for an ASDU whose cause is also undefined is conformant
/// either way; what matters is that the choice is pinned.
#[test]
fn the_classes_are_reported_in_the_clause_tables_order() {
    let (header, _) = command_asdu();

    assert_eq!(
        classify(&Known::NOTHING),
        Some(Unspecified::TypeIdentification)
    );

    let mut known = Known::standard(&header, true, true);
    known.type_id = false;
    assert_eq!(classify(&known), Some(Unspecified::TypeIdentification));

    known.type_id = true;
    known.cause = false;
    known.common_address = false;
    known.information_object_address = false;
    assert_eq!(classify(&known), Some(Unspecified::CauseOfTransmission));

    known.cause = true;
    assert_eq!(classify(&known), Some(Unspecified::CommonAddress));

    known.common_address = true;
    assert_eq!(
        classify(&known),
        Some(Unspecified::InformationObjectAddress)
    );

    known.information_object_address = true;
    assert_eq!(classify(&known), None);
}

/// "Mirrored", not rebuilt: the type identification and the VSQ are echoed, the
/// cause becomes the class's own with `P/N = 1`, the originator address and the
/// common address are echoed (the clause asks the controlled station to return
/// the originator address in its response), and the object area comes back octet for
/// octet.
#[test]
fn the_mirror_echoes_the_header_and_copies_the_object_area() {
    let (header, asdu) = command_asdu();

    for class in Unspecified::ALL {
        let known = unknown(class);
        let reply = mirror_reply(&header, &known, &asdu[Header::LEN..]).expect("an undefined ASDU");
        assert_eq!(reply.len(), asdu.len(), "nothing added, nothing dropped");

        assert_eq!(reply[0], asdu[0], "the type identification is echoed");
        assert_eq!(reply[1], asdu[1], "the VSQ is echoed");
        assert_eq!(
            reply[2],
            class.cause().to_u8() | 0x40,
            "the class's cause with P/N = 1 (and T echoed as 0)"
        );
        assert_eq!(reply[3], asdu[3], "the originator address is echoed");
        assert_eq!(&reply[4..6], &asdu[4..6], "the common address is echoed");
        assert_eq!(
            &reply[Header::LEN..],
            &asdu[Header::LEN..],
            "the object area is copied, never re-encoded"
        );

        let mirrored = Header::parse(&reply).expect("echoed header");
        assert_eq!(
            mirrored,
            mirror_header(&header, class),
            "mirror_header is exactly the header that goes out"
        );
        assert_eq!(mirrored.type_id, TypeId::CScNa1);
        assert_eq!(mirrored.count, 1);
        assert_eq!(mirrored.common_address, 12);
        assert!(mirrored.negative, "clause 7.2.3: P/N := <1>");
        assert_eq!(mirrored.cause, class.cause());

        // The payload is still the ASDU it was, so the mirror decodes.
        let objects = decode_asdu::<CScNa1>(&reply).expect("the mirror still decodes");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].ioa, 0x3000);
        assert!(objects[0].value.sco.scs);
    }
}

/// The pass-through rule: a type identification this crate has no layout for is
/// exactly the case the clause mirrors, so the payload must survive. This holds
/// for every one of the 256 possible first octets.
#[test]
fn an_undefined_type_identification_keeps_the_payload_untouched() {
    let mut mirrored_unknown = 0;
    for octet in 0..=255u8 {
        let asdu = vec![octet, 0x01, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x30, 0x00, 0x01];
        let header = Header::parse(&asdu).expect("header");
        let known = Known {
            type_id: false,
            ..Known::EVERYTHING
        };

        let reply = mirror_reply(&header, &known, &asdu[Header::LEN..]).expect("mirrored");
        assert_eq!(reply[0], octet, "the octet is echoed, not normalised");
        assert_eq!(
            reply[2],
            Cause::UnknownTypeId.to_u8() | 0x40,
            "unknown type identification = 44"
        );
        assert_eq!(
            &reply[Header::LEN..],
            &asdu[Header::LEN..],
            "payload untouched for type octet {octet:#04X}"
        );

        if TypeId::from_u8(octet).info().is_none() {
            mirrored_unknown += 1;
            // And the typed reader refuses it as an error rather than panicking.
            assert!(matches!(
                decode_asdu::<CScNa1>(&asdu),
                Err(LayoutError::TypeMismatch { .. })
            ));
        }
    }
    assert!(mirrored_unknown > 0, "the sweep must cover type octets");
}

/// Every type octet against every cause octet: no panic, and a payload that is
/// never lost whatever the station answers.
#[test]
fn every_type_and_cause_octet_classifies_without_panicking() {
    for type_octet in 0..=255u8 {
        for cause_octet in 0..=255u8 {
            for known in [Known::EVERYTHING, Known::NOTHING] {
                let asdu = vec![type_octet, 0x00, cause_octet, 0x00, 0x0C, 0x00];
                let header = Header::parse(&asdu).expect("header");

                let _ = classify(&known);
                let _ = discard_reason(&header, &known);
                let _ = is_mirror(&header);
                if let Some(reply) = mirror_reply(&header, &known, &[]) {
                    assert_eq!(reply.len(), Header::LEN, "an empty body stays empty");
                    assert!(reply[2] & 0x40 != 0, "every mirror is a negative confirm");
                }
            }
        }
    }
}

/// The monitor direction's rule: discard, with the reason the clause's log
/// bullets name, and process everything else.
#[test]
fn the_monitor_direction_discards_with_the_undefined_field_named() {
    let (header, _) = command_asdu();

    assert_eq!(discard_reason(&header, &Known::EVERYTHING), None);

    for class in Unspecified::ALL {
        assert_eq!(
            discard_reason(&header, &unknown(class)),
            Some(Discard::Unspecified(class)),
            "the log bullet names the field"
        );
    }

    assert_eq!(
        discard_reason(&header, &Known::NOTHING),
        Some(Discard::Unspecified(Unspecified::TypeIdentification)),
        "the same precedence as classify"
    );
}

/// A mirrored ASDU is never mirrored back: it is a reply, and the clause's third
/// log bullet is what happens to it. A negative confirmation with a *defined*
/// cause, by contrast, is an ordinary reply that this module leaves alone.
#[test]
fn a_mirror_is_logged_and_never_mirrored_back() {
    let (header, asdu) = command_asdu();
    let reply = mirror_reply(
        &header,
        &unknown(Unspecified::CommonAddress),
        &asdu[Header::LEN..],
    )
    .expect("mirrored");
    let mirrored = Header::parse(&reply).expect("header");

    assert!(is_mirror(&mirrored), "P/N = 1 with cause 46 is a mirror");
    assert_eq!(mirror_reply(&mirrored, &Known::EVERYTHING, &[]), None);
    assert_eq!(mirror_reply(&mirrored, &Known::NOTHING, &[]), None);
    assert_eq!(
        discard_reason(&mirrored, &Known::EVERYTHING),
        Some(Discard::Mirror),
        "knowledge does not matter: it is the shape that says mirror"
    );
    assert!(mirrored.type_id.is_confirmed(), "the 45–51 command types");

    // A negative confirmation of a command is actcon with P/N = 1, cause 7.
    // That is a defined cause, so not a mirror, and nothing this module
    // discards. The control-direction entry point is for requests, so a
    // station that knows the fields leaves it alone either way.
    let mut negative_confirm = mirrored;
    negative_confirm.cause = Cause::ActivationCon;
    negative_confirm.negative = true;
    assert!(!is_mirror(&negative_confirm));
    assert_eq!(discard_reason(&negative_confirm, &Known::EVERYTHING), None);
    assert_eq!(
        mirror_reply(&negative_confirm, &Known::EVERYTHING, &[]),
        None
    );

    // And a positive confirmation is not a mirror either.
    negative_confirm.negative = false;
    assert!(!is_mirror(&negative_confirm));
    assert_eq!(discard_reason(&negative_confirm, &Known::EVERYTHING), None);
}

/// Receiving such an ASDU must leave the handling of later messages
/// unaffected: the decision is a pure function of one header, so a discarded ASDU
/// leaves nothing behind.
#[test]
fn a_discarded_asdu_does_not_affect_the_next_one() {
    let stream: Vec<Vec<u8>> = vec![
        // An ASDU of a type identification this station does not implement.
        vec![0x00, 0x01, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x30, 0x00, 0x01],
        // A second one it knows.
        vec![0x2D, 0x01, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x30, 0x00, 0x01],
    ];
    let mut processed = Vec::new();
    let mut discarded = Vec::new();
    for frame in &stream {
        let header = Header::parse(frame).expect("header");
        // The station implements what the standard defines; the first frame's
        // type identification (0) is not one of them.
        let known = Known::standard(&header, true, true);
        match discard_reason(&header, &known) {
            Some(reason) => discarded.push(reason),
            None => processed.push(decode_asdu::<CScNa1>(frame).expect("the known ASDU decodes")),
        }
    }

    assert_eq!(
        discarded,
        vec![Discard::Unspecified(Unspecified::TypeIdentification)],
        "the unknown ASDU is discarded, once"
    );
    assert_eq!(processed.len(), 1, "and the next message is processed");
    assert_eq!(processed[0][0].ioa, 0x3000);

    // The proof that nothing carried over: the second message is the same value
    // it is on its own, after the discarded one has been through the decision.
    let second = stream.last().expect("frames");
    let header = Header::parse(second).expect("header");
    assert_eq!(
        discard_reason(&header, &Known::standard(&header, true, true)),
        None
    );
    assert_eq!(
        decode_asdu::<CScNa1>(second).expect("decodes"),
        processed[0]
    );
}

/// The VSQ is excluded in terms: `SQ` and `N` are ranges (clause 7.2.2.1), not
/// undefined values, so they are not one of the four classes. The layer that
/// does own them still reports them.
#[test]
fn the_variable_structure_qualifier_is_not_one_of_the_four_classes() {
    // SQ = 1, N = 127: the widest the field can be.
    let asdu = vec![0x2D, 0xFF, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x30, 0x00, 0x01];
    let header = Header::parse(&asdu).expect("header");
    assert!(header.sequence);
    assert_eq!(header.count, 127);

    assert_eq!(classify(&Known::EVERYTHING), None);
    assert_eq!(
        classify(&Known::NOTHING),
        Some(Unspecified::TypeIdentification)
    );
    assert_eq!(
        discard_reason(&header, &Known::EVERYTHING),
        None,
        "a VSQ value is not a reason to discard per clause 7.2.3"
    );

    // The layout layer is what refuses a sequence for a type that has none.
    assert_eq!(
        decode_asdu::<CScNa1>(&asdu),
        Err(LayoutError::SequenceNotAllowed {
            type_id: TypeId::CScNa1
        })
    );
    // …and the codec refuses an ASDU that is too short for its header.
    assert!(Header::parse(&asdu[..5]).is_err());
}

/// The two helpers are the standard's own answers, counted over the octet range
/// rather than asserted one value at a time.
#[test]
fn the_defined_sets_are_the_catalogues_own() {
    for octet in 0..=255u8 {
        let id = TypeId::from_u8(octet);
        assert_eq!(
            type_is_defined(id),
            id.info().is_some(),
            "definition is the catalogue's own membership"
        );
    }
    assert_eq!(
        (0..=255u8)
            .filter(|octet| type_is_defined(TypeId::from_u8(*octet)))
            .count(),
        CATALOGUE.len(),
        "every catalogue entry is reachable from its octet"
    );

    // 5-101 table 14: the range 1–47 less the eight reserved numbers 14–19,
    // 42 and 43, which leaves 39 named values; `<0>` is not used, 48–63 private.
    assert_eq!(
        (0..=63u8)
            .filter(|raw| cause_is_defined(Cause::from_u8(*raw)))
            .count(),
        39,
        "39 = 47 values in 1..=47, less 14–19, 42 and 43"
    );
    for raw in [0u8, 14, 15, 16, 17, 18, 19, 42, 43] {
        assert!(
            !cause_is_defined(Cause::from_u8(raw)),
            "cause {raw} is not defined"
        );
    }
    for raw in [1u8, 13, 20, 21, 36, 37, 41, 44, 45, 46, 47] {
        assert!(cause_is_defined(Cause::from_u8(raw)), "cause {raw}");
    }
    for raw in 48..=63u8 {
        assert!(
            !cause_is_defined(Cause::from_u8(raw)),
            "cause {raw} is private range, agreed by the system user"
        );
    }
}

/// [`Known::standard`] is the starting point for a station that implements
/// exactly what the standard's tables define: the two identifier answers come
/// from the tables, the two project-data answers from the caller.
#[test]
fn the_standard_profile_answers_from_the_catalogues() {
    let (header, _) = command_asdu();
    assert_eq!(Known::standard(&header, true, true), Known::EVERYTHING);
    assert_eq!(classify(&Known::standard(&header, true, true)), None);

    // A private-range type identification (clause 7.2.1.1: `<128..255>`) is
    // not the standard's to define, so that profile calls it undefined and the
    // mirror reports 44 (clause 7.2.3).
    let private = vec![0x81u8, 0x01, 0x03, 0x00, 0x0C, 0x00];
    let header = Header::parse(&private).expect("header");
    assert_eq!(header.type_id, TypeId::Other(129));
    let known = Known::standard(&header, true, true);
    assert!(!known.type_id, "128–255 is agreed, not defined");
    assert_eq!(classify(&known), Some(Unspecified::TypeIdentification));
    assert_eq!(
        mirror_reply(&header, &known, &[]).expect("mirrored")[2],
        Cause::UnknownTypeId.to_u8() | 0x40
    );

    // A reserved cause of transmission (17) is the second class.
    let reserved_cause = vec![0x2Du8, 0x01, 0x11, 0x00, 0x0C, 0x00];
    let header = Header::parse(&reserved_cause).expect("header");
    assert!(!cause_is_defined(header.cause));
    assert_eq!(
        classify(&Known::standard(&header, true, true)),
        Some(Unspecified::CauseOfTransmission)
    );

    // The two project-data answers are the caller's, and it can override any
    // answer when its profile is not the standard's: this station does accept
    // the cause, but the common address is not one of its own.
    let known = Known {
        cause: true,
        common_address: false,
        ..Known::standard(&header, true, true)
    };
    assert_eq!(classify(&known), Some(Unspecified::CommonAddress));
}
