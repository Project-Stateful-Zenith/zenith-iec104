//! The read command and data acquisition by polling: `C_RD_NA_1` `<102>`,
//! whose information object address *is* the object it asks for, and the
//! monitor-direction answer clause 7.4.14 defines.
//!
//! The clause citations are 5-104 cl.7.2 (PDF page index 64, printed page 63)
//! with its four-row service table and its cyclic-requests warning, cl.9 (page
//! index 100, printed 99) for the set `<30>`–`<40>`, cl.9.6 (page index 108,
//! printed 107) for the *"Read procedure"* checkbox, and Table 4 with Table 2's
//! NOTE (page index 52, printed 51); 5-101 cl.7.2.3 (page index 38, printed 37),
//! cl.7.2.4 (page index 43, printed 42), cl.7.2.5 with figure 21 (page index 44,
//! printed 43), cl.7.3.4.3 with figure 74 (page index 106, printed 105), table
//! 14 (page index 41, printed 40), cl.7.4.2 (page index 122, printed 121) and
//! cl.7.4.14 with figure 109 and the returned-type list (pages index 149 and
//! 150, printed 148 and 149).
//!
//! The two roles are driven against each other wherever the exchange is the
//! point: a command one role built, an answer the other built, and the mirror a
//! station with no data for the address returns.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::as_conversions)]

use std::collections::BTreeMap;

use iec104::asdu::{
    Bcr, Cause, Cp24Time2a, Cp56Time2a, Discard, Header, Known, LayoutObject, MItNa1, MItTb1,
    MMeNa1, MSpNa1, MSpTa1, Nva, Qds, Siq, TypeId, Unspecified, encode_asdu, is_mirror,
};
use iec104::rd::{
    CAUSE_REQUEST, DataSource, RETURNED_TAGGED, RETURNED_TYPES, RETURNED_UNTAGGED, RdError,
    Reaction, Read, Role, TYPE_ID, answer, is_cp24_form, is_returned, refusal, request,
};

/// The broadcast common address of the conventional two-octet profile.
const BROADCAST_CA: u16 = iec104::asdu::AddressSizes::CONVENTIONAL.broadcast_common_address();

const CA: u16 = 12;
const ORG: u8 = 0;

/// The object address every test reads: it is the whole payload of the command
/// and the address of the answer (5-101 cl.7.2.5, figure 74).
const IOA: u32 = 0x3010;

/// The octets of the read command (figure 74, PDF page index 106): the 6-octet
/// header, then the three-octet information object address and **nothing
/// else**. The type's definition line is
/// `C_RD_NA_1 := CP{Data unit identifier,Information object address}`.
const COMMAND_OCTETS: [u8; 9] = [
    0x66, 0x01, 0x05, 0x00, 0x0C, 0x00, // type 102, VSQ, COT <5>, ORG, CA
    0x10, 0x30, 0x00, // INFORMATION OBJECT ADDRESS := 0x3010
];

/// The octets of the answer to it: `M_ME_NA_1` (type 9) with cause `<5>` at the
/// **same** address, per 5-101 cl.7.4.14's figure 109 and index 150's
/// *"transmit it as an `M_PDU` with the cause of transmission `<5>` REQ"*.
const ANSWER_OCTETS: [u8; 12] = [
    0x09, 0x01, 0x05, 0x00, 0x0C, 0x00, 0x10, 0x30, 0x00, // type 9, cause <5>
    0x00, 0x20, // NVA 0x2000
    0x00, // QDS, all quality bits clear
];

/// The measured value that answer carries.
fn measured() -> MMeNa1 {
    MMeNa1 {
        nva: Nva { value: 0x2000 },
        qds: Qds::default(),
    }
}

/// The twelve-octet answer with the header fields a `DataSource` has to echo or
/// address chosen by the caller, for the checks on a source's frame: the
/// originator address, the `T` bit, the `P/N` bit and the common address.
fn sourced(originator: u8, test: bool, negative: bool, common_address: u16) -> Vec<u8> {
    encode_asdu(
        &Header {
            type_id: TypeId::MMeNa1,
            sequence: false,
            count: 1,
            cause: CAUSE_REQUEST,
            negative,
            test,
            originator,
            common_address,
        },
        &[LayoutObject {
            ioa: IOA,
            value: measured(),
        }],
    )
    .expect("a monitor ASDU")
}

// ---------------------------------------------------------------- helpers

/// The header of a whole ASDU.
fn header_of(asdu: &[u8]) -> Header {
    Header::parse(asdu).expect("a whole ASDU")
}

/// A type-102 ASDU built by hand, for the frames this module deliberately does
/// not build: another cause, a test bit, no object at all, a mirror.
fn handmade_command(cause: Cause, originator: u8, test: bool, common_address: u16) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::CRdNa1,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test,
        originator,
        common_address,
    };
    encode_asdu(
        &header,
        &[LayoutObject {
            ioa: IOA,
            value: iec104::asdu::CRdNa1,
        }],
    )
    .expect("a type-102 ASDU")
}

/// A type-102 ASDU built by hand at `ioa`, for the two address values a command
/// may not carry: the irrelevant `<0>` and the broadcast common address.
fn command_at(ioa: u32, cause: Cause, originator: u8, common_address: u16) -> Vec<u8> {
    encode_asdu(
        &Header {
            type_id: TypeId::CRdNa1,
            sequence: false,
            count: 1,
            cause,
            negative: false,
            test: false,
            originator,
            common_address,
        },
        &[LayoutObject {
            ioa,
            value: iec104::asdu::CRdNa1,
        }],
    )
    .expect("a type-102 ASDU")
}

/// A monitor ASDU of the measured type at `ioa`.
fn object_at(ioa: u32) -> Vec<u8> {
    encode_asdu(
        &Header {
            type_id: TypeId::MMeNa1,
            sequence: false,
            count: 1,
            cause: CAUSE_REQUEST,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa,
            value: measured(),
        }],
    )
    .expect("a monitor ASDU")
}

/// The mirror clause 7.4.14's closing sentence names: the received command with
/// `P/N = 1` and the class's cause, everything else echoed. This is 5-101
/// cl.7.2.3's rule, implemented in `src/asdu/unknown.rs`.
fn handmade_mirror(asdu: &[u8], cause: Cause) -> Vec<u8> {
    let mut out = Vec::new();
    Header {
        cause,
        negative: true,
        ..header_of(asdu)
    }
    .encode(&mut out);
    out.extend_from_slice(&asdu[Header::LEN..]);
    out
}

/// A station with data for exactly one address.
struct Image(Vec<u8>);

impl DataSource for Image {
    fn object(&self, ioa: u32) -> Option<Vec<u8>> {
        (ioa == IOA).then(|| self.0.clone())
    }
}

/// A station with no process data at all: clause 7.4.14's *"unknown (not
/// defined) in the controlled station"* for the address class.
struct Empty;

impl DataSource for Empty {
    fn object(&self, _ioa: u32) -> Option<Vec<u8>> {
        None
    }
}

/// A station whose process image answers with whatever frame it was built
/// around, so the checks on a source's frame can be driven.
struct Says(Vec<u8>);

impl DataSource for Says {
    fn object(&self, _ioa: u32) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

// ------------------------------------------------------------ the command

#[test]
fn request_is_the_address_and_nothing_else() {
    // Figure 74 (5-101 cl.7.3.4.3, PDF page index 106, printed page 105):
    // `C_RD_NA_1 := CP{Data unit identifier,Information object address}`, with
    // the control-direction cause list `<5> := request` and nothing else.
    let asdu = request(IOA, CA, ORG).expect("a read command");
    assert_eq!(asdu, COMMAND_OCTETS, "figure 74's nine octets");
    assert_eq!(asdu.len(), 9, "6 header + 3 address, no element");
    assert_eq!(
        TYPE_ID.to_u8(),
        102,
        "figure 74's type-identification row 0 1 1 0 0 1 1 0"
    );
    assert_eq!(asdu[0], 102);
    // Table 14 (index 41, printed page 40): "<5> := request or requested".
    assert_eq!(asdu[2], CAUSE_REQUEST.to_u8(), "the cause octet");
    assert_eq!(asdu[2], 5);
    assert_eq!(CAUSE_REQUEST.mnemonic(), "req");

    let header = header_of(&asdu);
    assert_eq!(header.type_id, TypeId::CRdNa1);
    assert_eq!(header.cause, Cause::Request);
    assert_eq!(header.count, 1, "figure 74 is headed SQ = 0, N = 1");
    assert!(!header.sequence);
    assert!(!header.negative);
    assert!(!header.test, "a normal read is not a test frame");
    assert_eq!(header.common_address, CA);
    assert_eq!(header.originator, ORG);
    assert_eq!(
        &asdu[Header::LEN..],
        &[0x10, 0x30, 0x00],
        "the whole payload"
    );
    // The type's element part is empty: `LEN` 0, the case the body cursor's
    // `next_object(0)` path yields.
    assert_eq!(iec104::asdu::element_len(TypeId::CRdNa1), Some(0));
}

#[test]
fn request_refuses_the_irrelevant_address() {
    // 5-101 cl.7.2.5 (index 44, printed page 43): "<0> := INFORMATION OBJECT
    // ADDRESS is irrelevant", and the same page's exception sentence makes a
    // read's address its object, so <0> names nothing.
    assert_eq!(
        request(0, CA, ORG),
        Err(RdError::IrrelevantAddress { ioa: 0 })
    );
}

#[test]
fn request_refuses_the_broadcast_address() {
    // 5-101 cl.7.2.4 (index 43, printed page 42): "The use of the common
    // address FF or FFFF is restricted to the following ASDUs in the control
    // direction: type Identification <100> ... <101> ... <103> ... <105>".
    // Type 102 is not on that list.
    assert_eq!(BROADCAST_CA, 0xFFFF);
    assert_eq!(
        request(IOA, BROADCAST_CA, ORG),
        Err(RdError::BroadcastAddress {
            common_address: BROADCAST_CA
        })
    );
}

#[test]
fn repeating_a_read_is_the_callers_and_not_a_refusal() {
    // 5-104 cl.7.2 (index 64): "The requesting of data by cyclic requests is
    // permitted, but should be avoided." That is a warning about *read
    // requests* repeated in a cycle. It is not a typed refusal, and not a rule
    // about cl.7.3's cyclic transmission (`src/tx.rs`). The crate schedules
    // nothing, so two identical reads build the same frame twice.
    let first = request(IOA, CA, ORG).expect("a read command");
    let second = request(IOA, CA, ORG).expect("a second read command");
    assert_eq!(first, second);
}

// ------------------------------------------------------- the returned set

#[test]
fn the_returned_set_is_index_150_crossed_with_clause_9() {
    // 5-101 cl.7.4.14, PDF page index 150 (printed 149): "The following ASDUs
    // M_REQ may be returned in the monitor direction:", then nine untagged
    // types and seven "or" alternatives.
    assert_eq!(RETURNED_UNTAGGED.len(), 9);
    assert_eq!(
        RETURNED_UNTAGGED.map(TypeId::to_u8),
        [1, 3, 5, 7, 9, 11, 13, 20, 21]
    );
    // 5-104 cl.9 (index 100, printed 99): "In this companion standard only the
    // use of the set <30> - <40> for ASDUs with time tag is permitted."
    assert_eq!(RETURNED_TAGGED.len(), 7);
    assert_eq!(
        RETURNED_TAGGED.map(TypeId::to_u8),
        [30, 31, 32, 33, 34, 35, 36]
    );
    assert_eq!(RETURNED_TYPES.len(), 16);
    assert_eq!(
        RETURNED_TYPES.map(TypeId::to_u8),
        [1, 3, 5, 7, 9, 11, 13, 20, 21, 30, 31, 32, 33, 34, 35, 36]
    );
    for type_id in RETURNED_TYPES {
        assert!(is_returned(type_id), "{type_id:?} is on the list");
    }
    // The clause-9 sentence strikes the CP24Time2a forms out of a 104 answer.
    for type_id in [
        TypeId::MSpTa1,
        TypeId::MDpTa1,
        TypeId::MStTa1,
        TypeId::MBoTa1,
        TypeId::MMeTa1,
        TypeId::MMeTb1,
        TypeId::MMeTc1,
    ] {
        assert!(is_cp24_form(type_id), "{type_id:?} is a CP24Time2a form");
        assert!(!is_returned(type_id), "{type_id:?} is not a 104 answer");
    }
    // <37>-<40> are inside cl.9's permitted set but absent from index 150's
    // returned list; <126> F_DR_TA_1 is the file-transfer directory type; and
    // the integrated totals of <15> are on neither list.
    for type_id in [
        TypeId::MItTb1,
        TypeId::MEpTd1,
        TypeId::MEpTe1,
        TypeId::MEpTf1,
        TypeId::MItNa1,
        TypeId::Other(126),
    ] {
        assert!(!is_returned(type_id), "{type_id:?} is not returned");
        assert!(!is_cp24_form(type_id), "{type_id:?} is not a CP24 form");
    }
    // The test is over the type's **wire octet**, so an unnamed `TypeId::Other`
    // of a returned number answers as the named variant does, and one of a
    // `CP24Time2a` form takes the tag's refusal rather than the type's.
    assert!(is_returned(TypeId::Other(9)), "Other(9) is <9> M_ME_NA_1");
    assert!(
        is_returned(TypeId::Other(30)),
        "Other(30) is <30> M_SP_TB_1"
    );
    assert!(!is_returned(TypeId::Other(2)), "Other(2) is the CP24 <2>");
    assert!(is_cp24_form(TypeId::Other(2)), "Other(2) is a CP24 form");
    assert!(is_cp24_form(TypeId::Other(14)), "Other(14) is <14>");
}

#[test]
fn every_returned_type_has_a_landed_layout() {
    // The answer is built through the layout layer, so each of the sixteen
    // numbers must have its geometry in `src/asdu/layout/`. A returned type
    // without one could not be encoded at all.
    for type_id in RETURNED_TYPES {
        assert!(
            iec104::asdu::element_len(type_id).is_some(),
            "{type_id:?} has a layout"
        );
        assert!(iec104::asdu::layout_for(type_id).is_some());
    }
}

// ------------------------------------------------------------- the answer

#[test]
fn answer_is_the_monitor_object_at_the_command_address() {
    // 5-101 cl.7.4.14, figure 109 (index 149): `C_RD_NA_1 <5> REQ` out and
    // `M_ <5> REQ` back: two different type identifications, both with cause
    // <5>.
    let command = request(IOA, CA, ORG).expect("a read command");
    let reply = answer(
        &LayoutObject {
            ioa: IOA,
            value: measured(),
        },
        &command,
        CA,
    )
    .expect("an answer");
    assert_eq!(reply, ANSWER_OCTETS);
    assert_eq!(reply.len(), 12);

    let header = header_of(&reply);
    assert_eq!(header.type_id, TypeId::MMeNa1);
    assert_ne!(header.type_id, TypeId::CRdNa1, "not the command's type");
    assert_eq!(header.cause, Cause::Request, "cause <5> on the answer");
    assert_eq!(reply[2], 5, "the cause octet, literally");
    assert!(!header.negative);
    assert_eq!(header.originator, ORG);
    assert_eq!(header.common_address, CA);
    assert_eq!(&reply[Header::LEN..Header::LEN + 3], &[0x10, 0x30, 0x00]);
}

#[test]
fn the_answer_echoes_the_originator_address_and_the_test_bit() {
    // 5-101 cl.7.2.3 (index 38, printed page 37): "the controlled station
    // should echo this originator address in the response in the monitor
    // direction."
    let command = handmade_command(CAUSE_REQUEST, 42, true, CA);
    let reply = answer(
        &LayoutObject {
            ioa: IOA,
            value: measured(),
        },
        &command,
        CA,
    )
    .expect("an answer");
    let header = header_of(&reply);
    assert_eq!(header.originator, 42, "the request's originator");
    assert!(header.test, "the request's test bit");
    assert_eq!(reply[3], 42);
    assert_eq!(reply[2] & 0x80, 0x80, "T is bit 8 of the COT octet");
}

#[test]
fn the_positive_answer_is_never_the_mirror() {
    // 104 Table 4 (index 52, printed 51) prints <102> *without* the CON mark
    // that <100>, <101>, <103>, <105> and <107> carry. So a positive answer is
    // not the command mirrored, and the monitor direction carries no type-102
    // frame but the 44-47 mirror.
    let command = request(IOA, CA, ORG).expect("a read command");
    let reply = answer(
        &LayoutObject {
            ioa: IOA,
            value: measured(),
        },
        &command,
        CA,
    )
    .expect("an answer");
    assert!(!is_mirror(&header_of(&reply)));
    assert!(!header_of(&reply).negative);
}

#[test]
fn answer_refuses_a_frame_that_is_not_the_command() {
    let other_type = encode_asdu(
        &Header {
            type_id: TypeId::MMeNa1,
            sequence: false,
            count: 1,
            cause: CAUSE_REQUEST,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA,
            value: measured(),
        }],
    )
    .expect("a monitor ASDU");
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &other_type,
            CA
        ),
        Err(RdError::NotThisType {
            type_id: TypeId::MMeNa1
        })
    );

    // Figure 74 lists one control-direction cause: <5>. A type-102 frame with
    // another cause is not the command.
    let activation = handmade_command(Cause::Activation, ORG, false, CA);
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &activation,
            CA
        ),
        Err(RdError::CauseNotListed {
            cause: Cause::Activation
        })
    );
}

#[test]
fn answer_refuses_another_address_and_the_irrelevant_one() {
    let command = request(IOA, CA, ORG).expect("a read command");
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: IOA + 1,
                value: measured()
            },
            &command,
            CA
        ),
        Err(RdError::AddressMismatch {
            asked: IOA,
            got: IOA + 1
        })
    );
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: 0,
                value: measured()
            },
            &command,
            CA
        ),
        Err(RdError::IrrelevantAddress { ioa: 0 })
    );
}

#[test]
fn answer_refuses_a_type_index_150_does_not_return() {
    let command = request(IOA, CA, ORG).expect("a read command");
    // <15> M_IT_NA_1 is on neither index 150's list nor cl.9's tagged set.
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: IOA,
                value: MItNa1 {
                    bcr: Bcr::default()
                }
            },
            &command,
            CA
        ),
        Err(RdError::NotReturnedType {
            type_id: TypeId::MItNa1
        })
    );
    // <37> M_IT_TB_1 is inside cl.9's permitted set <30>-<40> but absent from
    // the returned list, so it is the list's rule and not the tag's.
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: IOA,
                value: MItTb1 {
                    bcr: Bcr::default(),
                    time: Cp56Time2a::default()
                }
            },
            &command,
            CA
        ),
        Err(RdError::NotReturnedType {
            type_id: TypeId::MItTb1
        })
    );
}

#[test]
fn answer_refuses_a_cp24_tagged_twin() {
    // Index 150's or-columns print <2> M_SP_TA_1 as an alternative; 104 cl.9
    // (index 100) strikes every CP24Time2a form out: "only the use of the set
    // <30> - <40> for ASDUs with time tag is permitted".
    let command = request(IOA, CA, ORG).expect("a read command");
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: IOA,
                value: MSpTa1 {
                    siq: Siq::default(),
                    time: Cp24Time2a::default()
                }
            },
            &command,
            CA
        ),
        Err(RdError::TagNotPermitted {
            type_id: TypeId::MSpTa1
        })
    );
}

#[test]
fn answer_refuses_a_command_with_no_object() {
    // The read's information object address *is* the object it asks for
    // (5-101 cl.7.2.5, index 44), so a command with `N = 0` (cl.7.2.2) names
    // nothing to answer. That is a typed error, not a twelve-octet positive
    // frame.
    let empty = Header {
        type_id: TypeId::CRdNa1,
        sequence: false,
        count: 0,
        cause: CAUSE_REQUEST,
        negative: false,
        test: false,
        originator: ORG,
        common_address: CA,
    };
    let mut command = Vec::new();
    empty.encode(&mut command);
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &command,
            CA
        ),
        Err(RdError::NoObjectInCommand)
    );
    assert_eq!(
        Read::controlled(true, CA, ORG).answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &command
        ),
        Err(RdError::NoObjectInCommand)
    );
}

#[test]
fn answer_refuses_a_broadcast_command() {
    // 5-101 cl.7.2.4 (index 43): the broadcast FF/FFFF is restricted to types
    // <100>, <101>, <103> and <105>, and type 102 is not on the list. So a
    // broadcast read command that arrives is refused with the class-46 mirror
    // (TS 60870-5-604 5.4.10.10) rather than answered with an object.
    let command = handmade_command(CAUSE_REQUEST, ORG, false, BROADCAST_CA);
    assert_eq!(
        answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &command,
            CA
        ),
        Err(RdError::BroadcastAddress {
            common_address: BROADCAST_CA
        })
    );
    assert_eq!(
        Read::controlled(true, CA, ORG).answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &command
        ),
        Err(RdError::BroadcastAddress {
            common_address: BROADCAST_CA
        })
    );
}

// ------------------------------------------------------------- the refusal

#[test]
fn answer_refuses_the_broadcast_station_address() {
    // Cl.7.2.4 (index 43) answers a control-direction ASDU with "the specific
    // defined COMMON ADDRESS (station address)": a monitor ASDU at FF/FFFF is
    // not the answer that clause defines, so `answer` refuses to build one,
    // exactly as `request` refuses the broadcast address on the command side.
    let command = request(IOA, CA, ORG).expect("a read command");
    let object = LayoutObject {
        ioa: IOA,
        value: measured(),
    };
    assert_eq!(
        answer(&object, &command, BROADCAST_CA),
        Err(RdError::BroadcastAddress {
            common_address: BROADCAST_CA
        })
    );
    assert_eq!(
        Read::controlled(true, BROADCAST_CA, ORG).answer(&object, &command),
        Err(RdError::BroadcastAddress {
            common_address: BROADCAST_CA
        })
    );
}

#[test]
fn refusal_is_the_command_mirrored_with_pn_one() {
    // 5-101 cl.7.4.14 (index 150): "If the values in the data unit identifier
    // (except the variable structure qualifier) and the information object
    // address of the read command are unknown (not defined) in the controlled
    // station, the mirrored C_RD_NA_1 with the cause of transmission <44 - 47>
    // is returned". This is 5-101 cl.7.2.3's rule (index 42), implemented in
    // `src/asdu/unknown.rs`.
    let command = request(IOA, CA, ORG).expect("a read command");

    let mirror = refusal(&command, &Known::NOTHING, CA)
        .expect("a mirror")
        .expect("the type identification is the first unknown class");
    assert_eq!(
        mirror,
        [0x66, 0x01, 0x6C, 0x00, 0x0C, 0x00, 0x10, 0x30, 0x00],
        "cause 44 | P/N, everything else echoed"
    );
    assert_eq!(mirror[2], Cause::UnknownTypeId.to_u8() | 0x40);
    let header = header_of(&mirror);
    assert!(header.negative);
    assert_eq!(header.type_id, TypeId::CRdNa1);
    assert!(is_mirror(&header));
    assert_eq!(&mirror[Header::LEN..], &command[Header::LEN..]);

    // The address class alone: cause 47.
    let only_address = Known {
        information_object_address: false,
        ..Known::EVERYTHING
    };
    let mirror = refusal(&command, &only_address, CA)
        .expect("a mirror")
        .expect("47");
    assert_eq!(mirror[2], 0x6F);
    assert_eq!(
        mirror[2],
        Cause::UnknownInformationObjectAddress.to_u8() | 0x40
    );

    // A station that knows every field has nothing to refuse.
    assert_eq!(refusal(&command, &Known::EVERYTHING, CA), Ok(None));
}

#[test]
fn refusal_refuses_a_frame_that_is_not_a_read_command() {
    let monitor = encode_asdu(
        &Header {
            type_id: TypeId::MMeNa1,
            sequence: false,
            count: 1,
            cause: CAUSE_REQUEST,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA,
            value: measured(),
        }],
    )
    .expect("a monitor ASDU");
    assert_eq!(
        refusal(&monitor, &Known::NOTHING, CA),
        Err(RdError::NotThisType {
            type_id: TypeId::MMeNa1
        })
    );
    assert_eq!(
        refusal(
            &handmade_command(Cause::Activation, ORG, false, CA),
            &Known::NOTHING,
            CA
        ),
        Err(RdError::CauseNotListed {
            cause: Cause::Activation
        })
    );
}

#[test]
fn refusal_refuses_the_broadcast_and_the_irrelevant_address() {
    // TS 60870-5-604 5.4.10.10 (index 54): "The Controlled station rejects all
    // other ASDU Types with a Broadcast CASDU value by mirroring the ASDU with
    // P/N = 1 negative (and with COT = 46, if supported)". That holds whatever
    // the profile says, so the mirror entry point carries the rule itself.
    let broadcast = command_at(IOA, CAUSE_REQUEST, ORG, BROADCAST_CA);
    let mirror = refusal(&broadcast, &Known::EVERYTHING, CA)
        .expect("a mirror")
        .expect("a broadcast read is refused whatever the profile says");
    assert_eq!(
        mirror,
        [0x66, 0x01, 0x6E, 0x00, 0x0C, 0x00, 0x10, 0x30, 0x00],
        "cause 46 | P/N, the station's own address, everything else echoed"
    );
    assert_eq!(header_of(&mirror).common_address, CA);
    assert_eq!(&mirror[Header::LEN..], &broadcast[Header::LEN..]);

    // 5-101 cl.7.2.5 (index 44): "`<0>` := INFORMATION OBJECT ADDRESS is
    // irrelevant". A read's address *is* its object, so no station holds one
    // there: the answer is the unknown-address mirror (cause 47), not
    // `Ok(None)` for the caller to answer with an object.
    let irrelevant = command_at(0, CAUSE_REQUEST, ORG, CA);
    let mirror = refusal(&irrelevant, &Known::EVERYTHING, CA)
        .expect("a mirror")
        .expect("an irrelevant address is no station's object");
    assert_eq!(
        mirror[2],
        Cause::UnknownInformationObjectAddress.to_u8() | 0x40
    );
    assert_eq!(header_of(&mirror).common_address, CA);
    assert_eq!(&mirror[Header::LEN..], &[0x00, 0x00, 0x00]);
}

#[test]
fn refusal_reports_the_profile_class_before_the_irrelevant_address() {
    // Clause 7.2.3's table order is the report order: 44 (type identification),
    // 45 (cause of transmission), 46 (common address), 47 (information object
    // address). The `<0>` rule only decides the *address class*, so it is
    // consulted once the profile has no earlier class to report. A command at
    // address `<0>` whose type identification the station does not know is
    // therefore the class-44 mirror, and the two public entry points agree on
    // it: `refusal` and `Read::on_request` answer the same frame the same way.
    let command = command_at(0, CAUSE_REQUEST, ORG, CA);
    let profile = Known {
        type_id: false,
        ..Known::EVERYTHING
    };
    let mirror = refusal(&command, &profile, CA)
        .expect("a mirror")
        .expect("an unknown type identification is refused");
    assert_eq!(
        mirror[2],
        Cause::UnknownTypeId.to_u8() | 0x40,
        "cause 44 with P/N, the first class the profile reports"
    );
    assert_eq!(mirror[2], 0x6C);

    let serving = Read::controlled(true, CA, ORG);
    let outcome = serving
        .on_request(&command, &profile, &Says(object_at(0)))
        .expect("a mirror");
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0,
            cause: Cause::UnknownTypeId
        },
        "the same frame, the same class as `refusal`"
    );
    assert_eq!(outcome.send.len(), 1);
    assert_eq!(outcome.send[0][2], 0x6C);
    assert_eq!(outcome.send, [mirror]);
}

// --------------------------------------------------------------- the roles

#[test]
fn on_response_routes_the_command_the_answer_and_the_mirror() {
    let asking = Read::controlling(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    let reply = answer(
        &LayoutObject {
            ioa: IOA,
            value: measured(),
        },
        &command,
        CA,
    )
    .expect("an answer");
    let mirror = handmade_mirror(&command, Cause::UnknownInformationObjectAddress);

    // A command seen on the requesting side is still a command.
    assert_eq!(
        asking
            .on_response(&command, &Known::EVERYTHING)
            .expect("routed")
            .reaction,
        Reaction::Requested { ioa: IOA }
    );
    // ... the object is the answer ...
    assert_eq!(
        asking
            .on_response(&reply, &Known::EVERYTHING)
            .expect("routed")
            .reaction,
        Reaction::Answered {
            type_id: TypeId::MMeNa1,
            ioa: IOA
        }
    );
    // ... and the 44-47 mirror is the refusal, not a discard: cl.7.2.3's
    // monitor-direction log list names "mirrored ASDUs due to unknown numbers in
    // the control direction (type identifications 45 to 51)", which is not 102.
    assert_eq!(
        asking
            .on_response(&mirror, &Known::EVERYTHING)
            .expect("routed")
            .reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: Cause::UnknownInformationObjectAddress
        }
    );
    assert_eq!(
        asking
            .on_response(&mirror, &Known::EVERYTHING)
            .expect("routed")
            .send,
        [] as [std::vec::Vec<u8>; 0]
    );

    // A spontaneous ASDU of a returned type is not a read answer: cause <3>
    // belongs to event transmission (`src/tx.rs`).
    let spontaneous = encode_asdu(
        &Header {
            type_id: TypeId::MSpNa1,
            sequence: false,
            count: 1,
            cause: Cause::Spontaneous,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA,
            value: MSpNa1 {
                siq: Siq::default(),
            },
        }],
    )
    .expect("a spontaneous ASDU");
    assert_eq!(
        asking
            .on_response(&spontaneous, &Known::EVERYTHING)
            .expect("routed")
            .reaction,
        Reaction::Other
    );
}

#[test]
fn on_response_runs_the_discard_rule_first_for_the_monitor_direction() {
    // 5-101 cl.7.2.3 (index 42): "ASDUs in the monitor direction with undefined
    // values in the data unit identifier ... are discarded by controlling
    // stations". The caller's `Known` is that answer.
    let asking = Read::controlling(true, CA, ORG);
    let reply = answer(
        &LayoutObject {
            ioa: IOA,
            value: measured(),
        },
        &request(IOA, CA, ORG).expect("a read command"),
        CA,
    )
    .expect("an answer");
    assert_eq!(
        asking
            .on_response(&reply, &Known::NOTHING)
            .expect("routed")
            .reaction,
        Reaction::Discard(Discard::Unspecified(Unspecified::TypeIdentification))
    );
    // An unknown common address is discarded the same way.
    let foreign = Known {
        common_address: false,
        ..Known::EVERYTHING
    };
    assert_eq!(
        asking
            .on_response(&reply, &foreign)
            .expect("routed")
            .reaction,
        Reaction::Discard(Discard::Unspecified(Unspecified::CommonAddress))
    );
}

#[test]
fn on_request_answers_the_command_with_the_sources_object() {
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    let source = Image(ANSWER_OCTETS.to_vec());
    let outcome = serving
        .on_request(&command, &Known::EVERYTHING, &source)
        .expect("an answer");
    assert_eq!(outcome.reaction, Reaction::Requested { ioa: IOA });
    assert_eq!(outcome.send.len(), 1);
    assert_eq!(outcome.send[0], ANSWER_OCTETS);
    // The same frame `answer` builds from the same command.
    assert_eq!(
        outcome.send[0],
        answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &command,
            CA
        )
        .expect("an answer")
    );
}

#[test]
fn on_request_mirrors_the_class_the_station_does_not_know() {
    // Clause 7.2.3's table is headed "in the control direction": a field the
    // station does not know is *mirrored*, never discarded.
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    let source = Image(ANSWER_OCTETS.to_vec());

    let cases = [
        (Known::NOTHING, Cause::UnknownTypeId, 0x6C),
        (
            Known {
                cause: false,
                ..Known::EVERYTHING
            },
            Cause::UnknownCause,
            0x6D,
        ),
        (
            Known {
                common_address: false,
                ..Known::EVERYTHING
            },
            Cause::UnknownCommonAddress,
            0x6E,
        ),
        (
            Known {
                information_object_address: false,
                ..Known::EVERYTHING
            },
            Cause::UnknownInformationObjectAddress,
            0x6F,
        ),
    ];
    for (profile, cause, octet) in cases {
        let outcome = serving
            .on_request(&command, &profile, &source)
            .expect("a mirror");
        assert_eq!(outcome.reaction, Reaction::Refused { ioa: IOA, cause });
        assert_eq!(outcome.send.len(), 1);
        assert_eq!(outcome.send[0][2], octet, "the cause octet of {cause:?}");
        assert!(is_mirror(&header_of(&outcome.send[0])));
        assert_eq!(&outcome.send[0][Header::LEN..], &command[Header::LEN..]);
    }
}

#[test]
fn on_request_mirrors_an_address_the_station_has_no_data_for() {
    // Clause 7.4.14's address class, reached from the process image rather than
    // from the caller's profile: the source returns None.
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    let outcome = serving
        .on_request(&command, &Known::EVERYTHING, &Empty)
        .expect("a mirror");
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: Cause::UnknownInformationObjectAddress
        }
    );
    assert_eq!(outcome.send[0][2], 0x6F);
}

#[test]
fn on_request_mirrors_the_irrelevant_address() {
    // 5-101 cl.7.2.5 (index 44): the field's *"irrelevant"* value names nothing
    // to read, so a command that arrives with it is clause 7.4.14's unknown
    // address class, mirrored with cause 47. The source is not asked, so a
    // station cannot be made to answer at address `<0>`.
    let serving = Read::controlled(true, CA, ORG);
    let command = command_at(0, CAUSE_REQUEST, ORG, CA);
    let outcome = serving
        .on_request(&command, &Known::EVERYTHING, &Says(object_at(0)))
        .expect("a mirror");
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0,
            cause: Cause::UnknownInformationObjectAddress
        }
    );
    assert_eq!(outcome.send.len(), 1);
    assert_eq!(outcome.send[0][2], 0x6F, "cause 47 with P/N");
    assert_eq!(
        &outcome.send[0][Header::LEN..],
        &[0x00, 0x00, 0x00],
        "the received address is echoed, not the source's object"
    );
}

#[test]
fn on_request_refuses_a_broadcast_read_with_the_class_46_mirror() {
    // TS 60870-5-604 5.4.10.10 (PDF page index 54): "The Controlled station
    // rejects all other ASDU Types with a Broadcast CASDU value by mirroring the
    // ASDU with P/N = 1 negative (and with COT = 46, if supported)". The check
    // reads the header itself, so it holds whatever the caller's Known says.
    // `src/ct.rs` and `src/pm.rs` run the same rule for their own types.
    let serving = Read::controlled(true, CA, ORG);
    let command = handmade_command(CAUSE_REQUEST, ORG, false, BROADCAST_CA);
    let source = Image(ANSWER_OCTETS.to_vec());
    for profile in [
        Known::EVERYTHING,
        Known::NOTHING,
        Known {
            type_id: false,
            cause: false,
            information_object_address: false,
            ..Known::EVERYTHING
        },
    ] {
        let outcome = serving
            .on_request(&command, &profile, &source)
            .expect("a mirror");
        assert_eq!(
            outcome.reaction,
            Reaction::Refused {
                ioa: IOA,
                cause: Cause::UnknownCommonAddress
            },
            "class 46 under {profile:?}"
        );
        assert_eq!(outcome.send.len(), 1);
        assert_eq!(outcome.send[0][2], 0x6E, "cause 46 with P/N");
        let header = header_of(&outcome.send[0]);
        assert!(is_mirror(&header));
        assert_eq!(header.type_id, TYPE_ID);
        // Cl.7.2.4's "specific defined COMMON ADDRESS (station address)", not
        // the broadcast address it arrived with.
        assert_eq!(header.common_address, CA);
        assert_eq!(&outcome.send[0][Header::LEN..], &command[Header::LEN..]);
    }
}

#[test]
fn the_mirror_carries_the_stations_own_common_address() {
    // 5-101 cl.7.2.4 (index 43): an ASDU in the control direction is answered
    // with "the specific defined COMMON ADDRESS (station address)", not the
    // address it arrived with. `src/ct.rs`'s `refuse_frame` sets `self.ca` the
    // same way.
    let serving = Read::controlled(true, CA, ORG);
    let foreign = handmade_command(CAUSE_REQUEST, ORG, false, 99);
    let profile = Known {
        common_address: false,
        ..Known::EVERYTHING
    };
    let outcome = serving
        .on_request(&foreign, &profile, &Image(ANSWER_OCTETS.to_vec()))
        .expect("a mirror");
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: Cause::UnknownCommonAddress
        }
    );
    assert_eq!(header_of(&outcome.send[0]).common_address, CA);

    // The free function takes the station's address the same way.
    let mirror = refusal(&foreign, &profile, CA)
        .expect("a mirror")
        .expect("the common-address class");
    assert_eq!(header_of(&mirror).common_address, CA);
    assert_eq!(&mirror[Header::LEN..], &foreign[Header::LEN..]);
}

#[test]
fn on_request_discards_a_mirror_a_peer_sent() {
    // 5-101 cl.7.2.3's third log bullet: a mirrored ASDU is logged, not
    // mirrored back; otherwise two stations mirror each other for ever.
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    let mirror = handmade_mirror(&command, Cause::UnknownTypeId);
    let outcome = serving
        .on_request(&mirror, &Known::EVERYTHING, &Image(ANSWER_OCTETS.to_vec()))
        .expect("routed");
    assert_eq!(outcome.reaction, Reaction::Discard(Discard::Mirror));
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
}

#[test]
fn on_request_refuses_a_frame_that_is_not_the_command() {
    let serving = Read::controlled(true, CA, ORG);
    let source = Image(ANSWER_OCTETS.to_vec());
    // Another cause on type 102: figure 74 lists <5> alone.
    assert_eq!(
        serving
            .on_request(
                &handmade_command(Cause::Activation, ORG, false, CA),
                &Known::EVERYTHING,
                &source
            )
            .expect("routed")
            .reaction,
        Reaction::Other
    );
    // Another type: a spontaneous ASDU (event transmission, `src/tx.rs`)
    // answers nothing here.
    let spontaneous = encode_asdu(
        &Header {
            type_id: TypeId::MSpNa1,
            sequence: false,
            count: 1,
            cause: Cause::Spontaneous,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA,
            value: MSpNa1 {
                siq: Siq::default(),
            },
        }],
    )
    .expect("a spontaneous ASDU");
    assert_eq!(
        serving
            .on_request(&spontaneous, &Known::EVERYTHING, &source)
            .expect("routed")
            .reaction,
        Reaction::Other
    );
    // A command carrying no object at all (cl.7.2.2's `N = 0`) names nothing to
    // read.
    let empty = Header {
        type_id: TypeId::CRdNa1,
        sequence: false,
        count: 0,
        cause: CAUSE_REQUEST,
        negative: false,
        test: false,
        originator: ORG,
        common_address: CA,
    };
    let mut asdu = Vec::new();
    empty.encode(&mut asdu);
    assert_eq!(
        serving
            .on_request(&asdu, &Known::EVERYTHING, &source)
            .expect("routed")
            .reaction,
        Reaction::Other
    );
}

// --------------------------------------------- the source's frame is checked

#[test]
fn a_source_frame_with_a_wrong_cause_is_refused() {
    // Clause 7.4.14: the returned object goes out "with the cause of
    // transmission <5> REQ".
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    let frame = encode_asdu(
        &Header {
            type_id: TypeId::MMeNa1,
            sequence: false,
            count: 1,
            cause: Cause::Spontaneous,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA,
            value: measured(),
        }],
    )
    .expect("a monitor ASDU");
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &Says(frame))
            .expect_err("a wrong cause"),
        RdError::WrongCause {
            got: Cause::Spontaneous
        }
    );
}

#[test]
fn a_source_frame_at_another_address_or_of_another_type_is_refused() {
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");

    let elsewhere = encode_asdu(
        &Header {
            type_id: TypeId::MMeNa1,
            sequence: false,
            count: 1,
            cause: CAUSE_REQUEST,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA + 1,
            value: measured(),
        }],
    )
    .expect("a monitor ASDU");
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &Says(elsewhere))
            .expect_err("another address"),
        RdError::AddressMismatch {
            asked: IOA,
            got: IOA + 1
        }
    );

    let counted = encode_asdu(
        &Header {
            type_id: TypeId::MItNa1,
            sequence: false,
            count: 1,
            cause: CAUSE_REQUEST,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA,
            value: MItNa1 {
                bcr: Bcr::default(),
            },
        }],
    )
    .expect("a monitor ASDU");
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &Says(counted))
            .expect_err("another type"),
        RdError::NotReturnedType {
            type_id: TypeId::MItNa1
        }
    );

    let tagged = encode_asdu(
        &Header {
            type_id: TypeId::MSpTa1,
            sequence: false,
            count: 1,
            cause: CAUSE_REQUEST,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA,
            value: MSpTa1 {
                siq: Siq::default(),
                time: Cp24Time2a::default(),
            },
        }],
    )
    .expect("a monitor ASDU");
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &Says(tagged))
            .expect_err("a CP24 tag"),
        RdError::TagNotPermitted {
            type_id: TypeId::MSpTa1
        }
    );
}

#[test]
fn a_source_frame_that_does_not_echo_the_originator_is_refused() {
    // 5-101 cl.7.2.3 (index 38): "the controlled station should echo this
    // originator address in the response in the monitor direction".
    let serving = Read::controlled(true, CA, ORG);
    let command = handmade_command(CAUSE_REQUEST, 42, false, CA);
    assert_eq!(
        serving
            .on_request(
                &command,
                &Known::EVERYTHING,
                &Says(sourced(0, false, false, CA))
            )
            .expect_err("another originator"),
        RdError::OriginatorMismatch {
            command: 42,
            answer: 0
        }
    );
}

#[test]
fn a_source_frame_that_does_not_echo_the_test_bit_is_refused() {
    // The same echo, applied to the T bit.
    let serving = Read::controlled(true, CA, ORG);
    let command = handmade_command(CAUSE_REQUEST, ORG, true, CA);
    assert_eq!(
        serving
            .on_request(
                &command,
                &Known::EVERYTHING,
                &Says(sourced(ORG, false, false, CA))
            )
            .expect_err("another T bit"),
        RdError::TestMismatch {
            command: true,
            answer: false
        }
    );
}

#[test]
fn a_source_frame_at_another_common_address_is_refused() {
    // Cl.7.2.4: the answer carries the "specific defined COMMON ADDRESS
    // (station address)". A source frame at another station's address is not
    // this station's answer.
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    assert_eq!(
        serving
            .on_request(
                &command,
                &Known::EVERYTHING,
                &Says(sourced(ORG, false, false, 99))
            )
            .expect_err("another common address"),
        RdError::WrongCommonAddress { got: 99 }
    );
}

#[test]
fn a_negative_source_frame_is_refused() {
    // Cl.7.4.14's answer is the requested object; the negative confirmation is
    // the refusal's own frame, built by this module and never by the source.
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    assert_eq!(
        serving
            .on_request(
                &command,
                &Known::EVERYTHING,
                &Says(sourced(ORG, false, true, CA))
            )
            .expect_err("a negative answer"),
        RdError::NegativeAnswer
    );
}

#[test]
fn a_source_frame_without_the_one_object_is_refused() {
    // Figure 74 defines C_RD_NA_1 as SQ = 0, N = 1, and cl.7.4.14 returns *the*
    // information object that was specified: a sequence, or a count other than
    // one, is not that answer.
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    let none = Header {
        type_id: TypeId::MMeNa1,
        sequence: false,
        count: 0,
        cause: CAUSE_REQUEST,
        negative: false,
        test: false,
        originator: ORG,
        common_address: CA,
    };
    let mut frame = Vec::new();
    none.encode(&mut frame);
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &Says(frame))
            .expect_err("no object"),
        RdError::WrongObjectCount {
            sequence: false,
            count: 0
        }
    );
    let mut frame = Vec::new();
    Header {
        sequence: true,
        count: 2,
        ..none
    }
    .encode(&mut frame);
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &Says(frame))
            .expect_err("a sequence of two"),
        RdError::WrongObjectCount {
            sequence: true,
            count: 2
        }
    );
}

// --------------------------------------------------------- roles and gates

#[test]
fn the_entry_points_are_bound_to_a_role() {
    let asking = Read::controlling(true, CA, ORG);
    let serving = Read::controlled(true, CA, ORG);
    assert_eq!(asking.role(), Role::Controlling);
    assert_eq!(serving.role(), Role::Controlled);
    assert_eq!(asking.addressing(), (CA, ORG));

    let command = request(IOA, CA, ORG).expect("a read command");
    assert_eq!(
        serving.on_response(&command, &Known::EVERYTHING),
        Err(RdError::WrongRole)
    );
    assert_eq!(
        asking.on_request(&command, &Known::EVERYTHING, &Empty),
        Err(RdError::WrongRole)
    );
    assert_eq!(
        serving.request(IOA),
        Err(RdError::WrongRole),
        "the command is the controlling station's"
    );
    assert_eq!(
        asking.answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &command
        ),
        Err(RdError::WrongRole),
        "the answer is the controlled station's"
    );
}

#[test]
fn the_station_selection_gates_the_procedure() {
    // 104 cl.9.6 (index 108, printed 107): "Read procedure (station-specific
    // parameter, mark \"X\" ...)".
    let off = Read::controlling(false, CA, ORG);
    assert!(!off.uses_read());
    assert_eq!(off.request(IOA), Err(RdError::FunctionNotUsed));

    let serving = Read::controlled(false, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    assert_eq!(
        serving.answer(
            &LayoutObject {
                ioa: IOA,
                value: measured()
            },
            &command
        ),
        Err(RdError::FunctionNotUsed)
    );
    let refused = serving
        .on_request(&command, &Known::EVERYTHING, &Empty)
        .expect("answered, not an error");
    assert_eq!(
        refused.reaction,
        Reaction::Refused {
            ioa: IOA,
            cause: Cause::UnknownTypeId
        },
        "a station that does not use the function mirrors the command"
    );
    assert_eq!(refused.send.len(), 1);
    let mirror = Header::parse(&refused.send[0]).expect("header");
    assert!(mirror.negative, "P/N = 1");
    assert_eq!(mirror.cause, Cause::UnknownTypeId);
    assert_eq!(&refused.send[0][Header::LEN..], &command[Header::LEN..]);
    // But a frame of another procedure is still simply not this one.
    let spontaneous = encode_asdu(
        &Header {
            type_id: TypeId::MSpNa1,
            sequence: false,
            count: 1,
            cause: Cause::Spontaneous,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA,
            value: MSpNa1 {
                siq: Siq::default(),
            },
        }],
    )
    .expect("a spontaneous ASDU");
    assert_eq!(
        serving
            .on_request(&spontaneous, &Known::EVERYTHING, &Empty)
            .expect("routed")
            .reaction,
        Reaction::Other
    );
}

// ---------------------------------------------------- prefixes and no panics

#[test]
fn every_short_prefix_is_a_typed_error() {
    let asking = Read::controlling(true, CA, ORG);
    let serving = Read::controlled(true, CA, ORG);
    let source = Image(ANSWER_OCTETS.to_vec());
    let command = request(IOA, CA, ORG).expect("a read command");
    let reply = answer(
        &LayoutObject {
            ioa: IOA,
            value: measured(),
        },
        &command,
        CA,
    )
    .expect("an answer");
    let mirror = handmade_mirror(&command, Cause::UnknownTypeId);

    // Nothing shorter than the six-octet header is an ASDU at all.
    for asdu in [&command, &reply, &mirror] {
        for cut in 0..Header::LEN {
            let prefix = &asdu[..cut];
            assert!(
                Header::parse(prefix).is_err(),
                "a {cut}-octet prefix has no header"
            );
            assert!(
                asking.on_response(prefix, &Known::EVERYTHING).is_err(),
                "on_response must refuse a {cut}-octet prefix"
            );
            assert!(
                serving
                    .on_request(prefix, &Known::EVERYTHING, &source)
                    .is_err(),
                "on_request must refuse a {cut}-octet prefix"
            );
            assert!(refusal(prefix, &Known::NOTHING, CA).is_err());
        }
    }

    // A whole header whose object area is short is a typed truncation, never a
    // classification: the address is a `UI24` of three octets (5-101 cl.7.2.5,
    // figure 21, index 44) and a returned type's element has its own length.
    for cut in Header::LEN..command.len() {
        let prefix = &command[..cut];
        assert!(
            matches!(
                asking.on_response(prefix, &Known::EVERYTHING),
                Err(RdError::Layout(_))
            ),
            "a {cut}-octet command on the requesting side"
        );
        assert!(
            matches!(
                serving.on_request(prefix, &Known::EVERYTHING, &source),
                Err(RdError::Layout(_))
            ),
            "a {cut}-octet command on the requested side"
        );
        assert!(
            matches!(
                refusal(prefix, &Known::NOTHING, CA),
                Err(RdError::Layout(_))
            ),
            "a {cut}-octet command is never mirrored"
        );
    }
    for cut in Header::LEN..reply.len() {
        assert!(
            matches!(
                asking.on_response(&reply[..cut], &Known::EVERYTHING),
                Err(RdError::Layout(_))
            ),
            "a {cut}-octet answer"
        );
    }
    for cut in Header::LEN..mirror.len() {
        assert!(
            matches!(
                asking.on_response(&mirror[..cut], &Known::EVERYTHING),
                Err(RdError::Layout(_))
            ),
            "a {cut}-octet mirror"
        );
        assert!(
            matches!(
                serving.on_request(&mirror[..cut], &Known::EVERYTHING, &source),
                Err(RdError::Layout(_))
            ),
            "a {cut}-octet mirror on the requested side"
        );
    }
}

#[test]
fn no_frame_a_source_can_return_panics_the_walk() {
    // A source whose frame is a prefix of a real answer is a typed error on
    // every length: never a panic, and never a frame on the wire.
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    for cut in 0..ANSWER_OCTETS.len() {
        let frame = ANSWER_OCTETS[..cut].to_vec();
        assert!(
            serving
                .on_request(&command, &Known::EVERYTHING, &Says(frame))
                .is_err(),
            "a {cut}-octet source frame"
        );
    }
    // The whole frame is answered unchanged.
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &Says(ANSWER_OCTETS.to_vec()))
            .expect("an answer")
            .send[0],
        ANSWER_OCTETS
    );
}

#[test]
fn the_read_map_of_addresses_is_the_applications() {
    struct MapSource(BTreeMap<u32, Vec<u8>>);
    impl DataSource for MapSource {
        fn object(&self, ioa: u32) -> Option<Vec<u8>> {
            self.0.get(&ioa).cloned()
        }
    }

    // The crate holds no image: two sources with different maps answer the same
    // command differently, and nothing in the module remembers either answer.
    let serving = Read::controlled(true, CA, ORG);
    let command = request(IOA, CA, ORG).expect("a read command");
    let mut map = BTreeMap::new();
    map.insert(IOA, ANSWER_OCTETS.to_vec());
    let source = MapSource(map);
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &source)
            .expect("an answer")
            .send[0],
        ANSWER_OCTETS
    );
    assert_eq!(
        serving
            .on_request(&command, &Known::EVERYTHING, &Empty)
            .expect("a mirror")
            .send[0][2],
        0x6F
    );
}
