//! The application test procedure: 5-104 clause 7.10's `C_TS ACT` /
//! `C_TS ACTCON` exchange in both of its forms.
//!
//! The clause citations are 5-104 cl.7.10 (PDF page index 72, printed page 71),
//! cl.8.8 (page index 90, printed 89), cl.9.6's *"Test procedure"* checkbox
//! (page index 112, printed 111), Table 4 (page index 52, printed 51), the
//! clause-9 type/cause matrix (page index 106, printed 105) with its legend on
//! page index 104, and the PICS page (page index 102, printed 101); 5-101
//! cl.7.3.4.5 with figure 76 (page index 108, printed 107), cl.7.2.6.14 (page
//! index 51, printed 50), cl.7.2.3 (page index 38, printed 37), cl.7.2.4 (page
//! index 43, printed 42), cl.7.2.5 (page index 44, printed 43), Table 11 (page
//! index 33, printed 32), cl.7.4.10 (page index 130, printed 129) and Table 16
//! (page index 121, printed 120); and TS 60870-5-604 Table 22's rows 5.4.22.1
//! and 5.4.22.10 (page index 83, printed 82), its Table 7 rows 5.3.7.70/71
//! (page index 45, printed 44) and clause 5.4.10.10 (page index 54, printed 53).
//!
//! These tests drive the two roles against each other, so every assertion is
//! about a frame one role sent and the other classified.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::as_conversions)]

use iec104::asdu::{
    CCiNa1, CTsNa1, CTsTa1, Cause, Cp56Time2a, Discard, Fbp, Header, IOA_IRRELEVANT, Known,
    LayoutError, LayoutObject, Qcc, Tsc, TypeId, Unspecified, decode_asdu, element_len,
    encode_asdu,
};
use iec104::ts::{
    CAUSE_ACTIVATION, CAUSE_ACTIVATION_CON, Command, Form, Reaction, Role, Selection,
    TYPE_ID_TAGGED, TYPE_ID_UNTAGGED, TestProcedure, TsError, Unsupported, answer, form_of,
    is_test_type, refusal, request, request_tagged, request_untagged,
};

/// The broadcast common address of the conventional two-octet profile.
const BROADCAST_CA: u16 = iec104::asdu::AddressSizes::CONVENTIONAL.broadcast_common_address();

const CA: u16 = 12;

/// The worked example of Clarke/Reynders/Wright, *Practical Modern SCADA
/// Protocols*, Appendix D: 26.965 s, 16 min past 13:00, 19 January 2001. These
/// are the same seven octets `tests/cs.rs` and `tests/elements_time.rs` pin.
const WORKED_OCTETS: [u8; 7] = [0x55, 0x69, 0x10, 0x0D, 0x13, 0x01, 0x01];

/// That example as a value.
fn worked() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 26_965,
        minutes: 16,
        hours: 13,
        day_of_month: 19,
        months: 1,
        years: 1,
        ..Cp56Time2a::default()
    }
}

/// A chosen test sequence counter (104 cl.8.8 leaves the TSC value to the
/// requesting station).
const fn tsc() -> Tsc {
    Tsc::from_raw(7)
}

/// The tagged command this station sends.
fn tagged_value() -> Command {
    Command::Tagged {
        tsc: tsc(),
        time: worked(),
    }
}

/// The untagged command: its whole element is the constant `FBP`.
const fn untagged_value() -> Command {
    Command::Untagged { fbp: Fbp }
}

// ---------------------------------------------------------------- helpers

/// The header of a whole ASDU.
fn header_of(asdu: &[u8]) -> Header {
    Header::parse(asdu).expect("a whole ASDU")
}

/// A test frame built by hand, for the frames the module deliberately does not
/// build: another cause, another `FBP`, a negative confirmation, the test bit.
fn handmade_tagged(
    cause: Cause,
    tsc_value: Tsc,
    time: Cp56Time2a,
    common_address: u16,
    negative: bool,
    test: bool,
    originator: u8,
) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::CTsTa1,
        sequence: false,
        count: 1,
        cause,
        negative,
        test,
        originator,
        common_address,
    };
    encode_asdu(
        &header,
        &[LayoutObject {
            ioa: IOA_IRRELEVANT,
            value: CTsTa1 {
                tsc: tsc_value,
                time,
            },
        }],
    )
    .expect("the layout builds it")
}

/// The untagged twin of [`handmade_tagged`], with the `FBP` octets given
/// directly so an illegal pattern can be put on the wire.
fn handmade_untagged_raw(
    cause: Cause,
    fbp_octets: [u8; 2],
    common_address: u16,
    negative: bool,
) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::CTsNa1,
        sequence: false,
        count: 1,
        cause,
        negative,
        test: false,
        originator: 0,
        common_address,
    };
    let mut frame = Vec::new();
    header.encode(&mut frame).expect("the header encodes");
    frame.extend_from_slice(&[0x00, 0x00, 0x00]);
    frame.extend_from_slice(&fbp_octets);
    frame
}

/// A whole ASDU of another type, for the "not this procedure" paths.
fn another_type() -> Vec<u8> {
    encode_asdu(
        &Header {
            type_id: TypeId::CCiNa1,
            sequence: false,
            count: 1,
            cause: Cause::Activation,
            negative: false,
            test: false,
            originator: 0,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: IOA_IRRELEVANT,
            value: CCiNa1 {
                qcc: Qcc::default(),
            },
        }],
    )
    .expect("the layout builds it")
}

/// A copy of `frame` whose cause octet reads `cause` (and no other change).
fn with_cause(frame: &[u8], cause: Cause) -> Vec<u8> {
    let mut copy = frame.to_vec();
    copy[2] = (copy[2] & 0xC0) | cause.to_u8();
    copy
}

/// A copy of `frame` whose `N` field reads `count`.
fn with_count(frame: &[u8], count: u8) -> Vec<u8> {
    let mut copy = frame.to_vec();
    copy[1] = (copy[1] & 0x80) | (count & 0x7F);
    copy
}

// ------------------------------------------------------- the frame geometry

/// 5-101 cl.7.3.4.5, figure 76 (index 108): **eleven octets**, `N = 1`,
/// `SQ = 0`, the figure's `INFORMATION OBJECT ADDRESS = 0`, and the two `FBP`
/// octets of cl.7.2.6.14 (index 51) in the order `AA 55`.
#[test]
fn the_untagged_command_is_the_eleven_octets_of_figure_76() {
    let asdu = request_untagged(CA, 0).expect("the layout builds it");
    assert_eq!(asdu.len(), 11, "6 header + 3 IOA + 2 FBP");
    assert_eq!(
        asdu,
        vec![
            0x68, 0x01, 0x06, 0x00, 0x0C, 0x00, // type 104, VSQ 00 000 001, act, org 0, CA 12
            0x00, 0x00, 0x00, // INFORMATION OBJECT ADDRESS = 0 (figure 76's field row)
            0xAA, 0x55, // FBP = 55AAH, little-endian
        ]
    );

    let header = header_of(&asdu);
    assert_eq!(header.type_id, TypeId::CTsNa1);
    assert_eq!(header.type_id.to_u8(), 104);
    assert_eq!(header.cause, Cause::Activation);
    assert_eq!(header.count, 1);
    assert!(!header.sequence);
    assert!(!header.negative);
    assert!(!header.test);

    // Figure 76's definition line: `C_TS_NA_1 := CP{Data unit identifier,
    // Information object address,FBP}`: the whole element is that pattern.
    assert_eq!(&asdu[9..], &Fbp::VALUE.to_le_bytes());
    assert_eq!(
        &asdu[9..],
        &[0xAA, 0x55],
        "the figure's bit rows: 10101010 then 01010101"
    );
}

/// 5-104 cl.8.8, figure 30 (index 90): **eighteen octets**, `N = 1`, `SQ = 0`,
/// the figure's information object address 0, the caller's `TSC` and the seven
/// `CP56Time2a` octets.
#[test]
fn the_tagged_command_is_the_eighteen_octets_of_figure_30() {
    let asdu = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    assert_eq!(asdu.len(), 18, "6 header + 3 IOA + 2 TSC + 7 time");
    assert_eq!(
        asdu,
        vec![
            0x6B, 0x01, 0x06, 0x00, 0x0C, 0x00, // type 107, VSQ 00 000 001, act, org 0, CA 12
            0x00, 0x00, 0x00, // INFORMATION OBJECT ADDRESS = 0 (figure 30's field row)
            0x07, 0x00, // TSC = 7, little-endian  UI16[1..16]<0..65535>
            0x55, 0x69, 0x10, 0x0D, 0x13, 0x01, 0x01, // CP56Time2a
        ]
    );

    let header = header_of(&asdu);
    assert_eq!(header.type_id, TypeId::CTsTa1);
    assert_eq!(header.type_id.to_u8(), 107);
    assert_eq!(header.cause, Cause::Activation);
    assert_eq!(header.common_address, CA);
    assert_eq!(&asdu[9..11], &[0x07, 0x00], "TSC");
    assert_eq!(&asdu[11..], &WORKED_OCTETS, "CP56Time2a");

    // Figure 30's definition line, read back through the layout layer.
    let object = decode_asdu::<CTsTa1>(&asdu)
        .expect("a type-107 ASDU")
        .first()
        .expect("one information object")
        .value;
    assert_eq!(object.tsc, tsc());
    assert_eq!(object.time, worked());
}

#[test]
fn the_two_types_are_104_and_107_with_two_and_nine_octet_elements() {
    assert_eq!(TYPE_ID_UNTAGGED, TypeId::CTsNa1);
    assert_eq!(TYPE_ID_TAGGED, TypeId::CTsTa1);
    assert_eq!(TypeId::CTsNa1.to_u8(), 104);
    assert_eq!(TypeId::CTsTa1.to_u8(), 107);
    assert_eq!(element_len(TypeId::CTsNa1), Some(Fbp::LEN));
    assert_eq!(
        element_len(TypeId::CTsTa1),
        Some(Tsc::LEN + Cp56Time2a::LEN)
    );
    assert_eq!(Fbp::LEN, 2);
    assert_eq!(Tsc::LEN, 2);
    assert_eq!(Cp56Time2a::LEN, 7);
    assert_eq!(CAUSE_ACTIVATION, Cause::Activation);
    assert_eq!(CAUSE_ACTIVATION_CON, Cause::ActivationCon);
    assert_eq!(form_of(TypeId::CTsNa1), Some(Form::Untagged));
    assert_eq!(form_of(TypeId::CTsTa1), Some(Form::Tagged));
    assert_eq!(form_of(TypeId::CCsNa1), None);
    assert!(is_test_type(TypeId::CTsNa1) && is_test_type(TypeId::CTsTa1));
    assert!(!is_test_type(TypeId::CCsNa1));
    assert_eq!(Form::Untagged.type_id(), TypeId::CTsNa1);
    assert_eq!(Form::Tagged.type_id(), TypeId::CTsTa1);
    assert_eq!(Form::Untagged.other(), Form::Tagged);

    // 5-104 Table 4 (index 52) carries `CON <107>` and no `<104>` row; the
    // clause-9 matrix (index 106) black-boxes the `<104>` row. The catalogue
    // already records the reading.
    assert!(!TypeId::CTsNa1.is_selected_104());
    assert!(TypeId::CTsTa1.is_selected_104());
    assert!(TypeId::CTsNa1.is_confirmed() && TypeId::CTsTa1.is_confirmed());
}

/// 104 Table 2's NOTE (index 52): an ASDU marked CON in the control direction
/// may come back mirrored in the monitor direction, its cause of transmission
/// changed. The confirmation is therefore the same octets with the cause
/// octet moved to 7 and **nothing else changed** (5-101 Table 11 / 104 Table 4's
/// `CON` mark).
#[test]
fn the_confirmation_is_the_command_with_the_cause_octet_moved() {
    for (command, form) in [
        (untagged_value(), Form::Untagged),
        (tagged_value(), Form::Tagged),
    ] {
        let built = request(command, CA, 0).expect("the layout builds it");
        let mirrored = answer(&built, CA).expect("a test command is this procedure's");

        assert_eq!(mirrored.len(), built.len());
        assert_eq!(header_of(&mirrored).type_id, form.type_id());
        assert_eq!(header_of(&mirrored).cause, CAUSE_ACTIVATION_CON);
        assert_eq!(header_of(&mirrored).cause.to_u8(), 7, "figure 30: <7>");
        assert_eq!(header_of(&mirrored).count, 1);
        assert!(!header_of(&mirrored).negative);

        for octet in 0..built.len() {
            if octet != 2 {
                assert_eq!(
                    mirrored[octet], built[octet],
                    "octet {octet} of the {form:?} mirror is unchanged"
                );
            }
        }
        assert_eq!(mirrored[2], 0x07, "the cause octet itself");

        // The same value, read back: the element is the one that was sent.
        let given = if form == Form::Untagged {
            let value = decode_asdu::<CTsNa1>(&mirrored)
                .expect("type 104")
                .remove(0)
                .value;
            Command::Untagged { fbp: value.fbp }
        } else {
            let value = decode_asdu::<CTsTa1>(&mirrored)
                .expect("type 107")
                .remove(0)
                .value;
            Command::Tagged {
                tsc: value.tsc,
                time: value.time,
            }
        };
        assert_eq!(given, command);
    }
}

#[test]
fn the_untagged_confirmation_is_the_eleven_octets_byte_for_byte() {
    let built = request_untagged(CA, 0).expect("the layout builds it");
    let mirrored = answer(&built, CA).expect("a test command");
    assert_eq!(
        mirrored,
        vec![
            0x68, 0x01, 0x07, 0x00, 0x0C, 0x00, // only octet 2: cause 6 -> 7
            0x00, 0x00, 0x00, 0xAA, 0x55,
        ]
    );
}

#[test]
fn the_tagged_confirmation_is_the_eighteen_octets_byte_for_byte() {
    let built = request_tagged(tsc(), worked(), CA, 42).expect("the layout builds it");
    let mirrored = answer(&built, CA).expect("a test command");
    assert_eq!(
        mirrored,
        vec![
            0x6B, 0x01, 0x07, 0x2A, 0x0C, 0x00, // cause 7, the request's originator 42
            0x00, 0x00, 0x00, 0x07, 0x00, 0x55, 0x69, 0x10, 0x0D, 0x13, 0x01, 0x01,
        ]
    );
}

/// The echo the clause states: the response shall carry the request's TSC and
/// exactly the request's time, and TS 60870-5-604 Table 22 has the primary
/// station detect a TSC that does not match (`5.4.22.1`, index 83, required
/// `M`). A
/// mismatch is the typed error [`TsError::EchoMismatch`], never an
/// [`Reaction::Answered`].
#[test]
fn the_echo_of_the_tagged_form_is_checked() {
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let good = answer(
        &request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it"),
        CA,
    )
    .expect("a test command");
    assert_eq!(
        controlling
            .on_response(&good, &Known::EVERYTHING, tagged_value())
            .expect("the echo matches")
            .reaction,
        Reaction::Answered {
            command: tagged_value(),
            negative: false
        }
    );

    // A different TSC.
    let other_tsc = Tsc::from_raw(8);
    let got_tsc = answer(
        &request_tagged(other_tsc, worked(), CA, 0).expect("the layout builds it"),
        CA,
    )
    .expect("a test command");
    assert_eq!(
        controlling.on_response(&got_tsc, &Known::EVERYTHING, tagged_value()),
        Err(TsError::EchoMismatch {
            sent: tagged_value(),
            got: Command::Tagged {
                tsc: other_tsc,
                time: worked()
            },
        })
    );

    // A different time.
    let other_time = Cp56Time2a {
        milliseconds: 26_966,
        ..worked()
    };
    let got_time = answer(
        &request_tagged(tsc(), other_time, CA, 0).expect("the layout builds it"),
        CA,
    )
    .expect("a test command");
    assert!(matches!(
        controlling.on_response(&got_time, &Known::EVERYTHING, tagged_value()),
        Err(TsError::EchoMismatch { .. })
    ));

    // The answer to the *same* value of the other form is not an echo either.
    let untagged = answer(&request_untagged(CA, 0).expect("the layout builds it"), CA)
        .expect("a test command");
    assert!(
        controlling
            .on_response(&untagged, &Known::EVERYTHING, tagged_value())
            .is_err()
    );
}

/// A hand-built `C_TS_NA_1` whose `FBP` is not `55AAH` is
/// <code>[LayoutError::Asdu]([AsduError::FixedPatternMismatch])</code> on the way in,
/// on every path that reads it.
#[test]
fn a_fixed_pattern_that_is_not_55aa_is_a_layout_error() {
    let wrong = handmade_untagged_raw(Cause::Activation, [0x00, 0x00], CA, false);
    assert_eq!(wrong.len(), 11);
    let controlled = TestProcedure::controlled(Selection::UNTAGGED, CA, 0);
    let controlling = TestProcedure::controlling(Selection::UNTAGGED, CA, 0);

    for result in [
        controlled.on_request(&wrong, &Known::EVERYTHING).err(),
        controlling
            .on_response(
                &with_cause(&wrong, CAUSE_ACTIVATION_CON),
                &Known::EVERYTHING,
                untagged_value(),
            )
            .err(),
        answer(&wrong, CA).err(),
        refusal(&wrong, &Known::EVERYTHING, CA).err(),
    ] {
        assert!(
            matches!(
                result,
                Some(TsError::Layout(LayoutError::Asdu(
                    iec104::asdu::AsduError::FixedPatternMismatch {
                        expected: Fbp::VALUE,
                        got: 0
                    }
                )))
            ),
            "a non-55AAH FBP must be the element's own error, got {result:?}"
        );
    }

    // And the element layer accepts nothing else: `Fbp::parse` of the constant's
    // little-endian octets (`AA 55`) is the only accepted pair.
    assert!(Fbp::parse(&[0xAA, 0x55]).is_ok());
    assert!(Fbp::parse(&[0x55, 0xAA]).is_err());
}

#[test]
fn the_confirmation_echoes_the_originator_address_and_the_test_bit() {
    // 5-101 cl.7.2.3 (index 38): the source of a command-direction ASDU should
    // put its originator address in it, and the controlled station should
    // return that same originator address in its monitor-direction response.
    // The station's own originator is 0 here and the
    // request's is 42, so the two cannot be confused.
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    let activating = handmade_tagged(Cause::Activation, tsc(), worked(), CA, false, true, 42);
    let outcome = controlled
        .on_request(&activating, &Known::EVERYTHING)
        .expect("a request is this procedure's");
    let reply = header_of(&outcome.send[0]);
    assert_eq!(reply.originator, 42);
    assert_ne!(reply.originator, 0);
    assert!(
        reply.test,
        "the T bit is echoed with the originator address"
    );
    assert_eq!(reply.common_address, CA, "the station's own address");
    assert_eq!(reply.cause, Cause::ActivationCon);
    assert_eq!(
        outcome.send[0],
        answer(&activating, CA).expect("a test command")
    );

    // The untagged form echoes both as well.
    let controlled = TestProcedure::controlled(Selection::UNTAGGED, CA, 0);
    let activating = {
        let mut copy = request_untagged(CA, 42).expect("the layout builds it");
        copy[2] |= 0x80;
        copy
    };
    let outcome = controlled
        .on_request(&activating, &Known::EVERYTHING)
        .expect("a request is this procedure's");
    assert_eq!(header_of(&outcome.send[0]).originator, 42);
    assert!(header_of(&outcome.send[0]).test);
}

// ------------------------------------------------- the addressing rules

/// 5-101 cl.7.2.4 (index 43) restricts the broadcast address to types `<100>`,
/// `<101>`, `<103>` and `<105>`; neither test command is on the list, and TS
/// 60870-5-604 5.4.10.10 (index 54) is the receiving side's rule.
#[test]
fn a_broadcast_test_command_is_refused_by_the_builders() {
    for built in [
        request_untagged(0xFFFF, 0),
        request(untagged_value(), 0xFFFF, 0),
        request_tagged(tsc(), worked(), 0xFFFF, 0),
        request(tagged_value(), 0xFFFF, 0),
    ] {
        assert_eq!(
            built,
            Err(TsError::BroadcastAddress {
                common_address: BROADCAST_CA
            })
        );
    }
    assert_eq!(BROADCAST_CA, 0xFFFF);

    // The command is fine; the *answer* refuses to be built at the broadcast
    // address, and refuses a command that carried it.
    let command = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    assert_eq!(
        answer(&command, BROADCAST_CA),
        Err(TsError::BroadcastAddress {
            common_address: BROADCAST_CA
        })
    );
    let broadcast = {
        let mut copy = command;
        copy[4] = 0xFF;
        copy[5] = 0xFF;
        copy
    };
    assert_eq!(
        answer(&broadcast, CA),
        Err(TsError::BroadcastAddress {
            common_address: BROADCAST_CA
        })
    );
}

#[test]
fn a_broadcast_command_that_arrives_is_mirrored_with_cause_46() {
    // 5-101 cl.7.2.4 and TS 60870-5-604 5.4.10.10: the controlled station
    // refuses any other type carrying the broadcast CASDU by mirroring it with
    // P/N = 1, negative (and with COT = 46 where supported). The reply
    // carries the station's own address, whatever the caller's `Known` says.
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    let broadcast = {
        let mut copy = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
        copy[4] = 0xFF;
        copy[5] = 0xFF;
        copy
    };
    let outcome = controlled
        .on_request(&broadcast, &Known::EVERYTHING)
        .expect("a whole ASDU");
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            cause: Cause::UnknownCommonAddress
        }
    );
    let mirrored = header_of(&outcome.send[0]);
    assert!(mirrored.negative, "P/N = 1");
    assert_eq!(mirrored.cause.to_u8(), 46);
    assert_eq!(mirrored.common_address, CA);
    assert_eq!(mirrored.type_id, TypeId::CTsTa1);
    assert_eq!(&outcome.send[0][Header::LEN..], &broadcast[Header::LEN..]);

    // Under the same `Known::EVERYTHING`, the same frame at the station's own
    // address is answered positively: the broadcast rule is the header's, not
    // the profile's.
    let plain = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    assert_eq!(
        controlled
            .on_request(&plain, &Known::EVERYTHING)
            .expect("a whole ASDU")
            .reaction,
        Reaction::Requested {
            command: tagged_value()
        }
    );
}

/// A test command's information object address **is** zero (figure 76's
/// `INFORMATION OBJECT ADDRESS = 0`, 5-101 cl.7.2.5: an ASDU for which the
/// address has no relevance (is unused) carries zero there). The
/// read procedure's `<0>` refusal is the opposite rule and must not be copied
/// here.
#[test]
fn the_irrelevant_address_zero_is_the_standards_own_frame() {
    for command in [
        request_untagged(CA, 0).expect("the layout builds it"),
        request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it"),
    ] {
        assert_eq!(
            &command[6..9],
            &[0x00, 0x00, 0x00],
            "figure 76/30's field row"
        );
    }

    let untagged = request_untagged(CA, 0).expect("the layout builds it");
    assert_eq!(
        refusal(&untagged, &Known::EVERYTHING, CA),
        Ok(None),
        "a command at <0> is nothing to mirror"
    );
    let controlled = TestProcedure::controlled(Selection::UNTAGGED, CA, 0);
    let outcome = controlled
        .on_request(&untagged, &Known::EVERYTHING)
        .expect("a request is this procedure's");
    assert_eq!(
        outcome.reaction,
        Reaction::Requested {
            command: untagged_value()
        }
    );
    assert_eq!(outcome.send.len(), 1);
}

// ----------------------------------------------------------- clause 7.2.3

#[test]
fn the_44_47_mirror_answers_an_unknown_field() {
    // Figures 76 and 30 both print <44>–<47> for exactly this; the class order
    // is 5-101 cl.7.2.3's table order.
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    let command = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");

    let outcome = controlled
        .on_request(&command, &Known::NOTHING)
        .expect("a whole ASDU");
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            cause: Cause::UnknownTypeId
        }
    );
    assert_eq!(outcome.send[0][2], 0x40 | 0x2C, "P/N = 1 and cause 44");
    assert_eq!(&outcome.send[0][Header::LEN..], &command[Header::LEN..]);

    let foreign = Known {
        type_id: true,
        cause: true,
        common_address: false,
        information_object_address: true,
    };
    assert_eq!(
        controlled
            .on_request(&command, &foreign)
            .expect("a whole ASDU")
            .reaction,
        Reaction::Refused {
            cause: Cause::UnknownCommonAddress
        }
    );

    // The same frame under a profile that knows everything is answered, not
    // mirrored: a positive ACTCON is never the mirror.
    let answered = controlled
        .on_request(&command, &Known::EVERYTHING)
        .expect("a whole ASDU");
    assert!(!header_of(&answered.send[0]).negative);
    assert_eq!(answered.send[0][2], 0x07);

    // The free entry point agrees with the instance for every class.
    for (known, cause) in [
        (Known::NOTHING, Cause::UnknownTypeId),
        (foreign, Cause::UnknownCommonAddress),
    ] {
        let mirrored = refusal(&command, &known, CA)
            .expect("a test command")
            .expect("a field the station does not know");
        assert_eq!(mirrored[2], 0x40 | cause.to_u8());
        assert_eq!(mirrored, {
            let mut expected = command.clone();
            expected[2] = 0x40 | cause.to_u8();
            expected
        });
    }
    assert_eq!(refusal(&command, &Known::EVERYTHING, CA), Ok(None));
}

#[test]
fn the_discard_rule_runs_before_the_type_is_examined() {
    let command = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);

    // An undefined common address under a profile that knows the type, the
    // cause and the information object address: clause 7.2.3's third class.
    let foreign = Known {
        type_id: true,
        cause: true,
        common_address: false,
        information_object_address: true,
    };
    let outcome = controlling
        .on_response(&command, &foreign, tagged_value())
        .expect("a whole ASDU");
    assert_eq!(
        outcome.reaction,
        Reaction::Discard(Discard::Unspecified(Unspecified::CommonAddress))
    );
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);

    // A mirror is discarded, not answered, on the *controlled* side: two
    // stations cannot mirror each other.
    let mirrored = {
        let mut copy = command;
        copy[2] = 0x40 | 0x2F;
        copy
    };
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    let outcome = controlled
        .on_request(&mirrored, &Known::EVERYTHING)
        .expect("a whole ASDU");
    assert_eq!(outcome.reaction, Reaction::Discard(Discard::Mirror));
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
}

#[test]
fn a_received_mirror_is_the_refusal_on_the_controlling_side() {
    // The controlling station asked for an answer and got its own command
    // mirrored back with P/N = 1: clause 7.2.3's refusal, with the class's
    // cause. It is *not* a discard; it is the reply that was asked for.
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let mirrored = {
        let mut copy = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
        copy[2] = 0x40 | 0x2E;
        copy
    };
    let outcome = controlling
        .on_response(&mirrored, &Known::EVERYTHING, tagged_value())
        .expect("a whole ASDU");
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            cause: Cause::UnknownCommonAddress
        }
    );
    assert!(outcome.send.is_empty(), "nothing is mirrored back");
}

// ------------------------------------------------------ the reception role

#[test]
fn the_reception_routes_the_request_the_confirmation_and_other_types() {
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);

    let command = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    assert_eq!(
        controlled
            .on_request(&command, &Known::EVERYTHING)
            .expect("a whole ASDU")
            .reaction,
        Reaction::Requested {
            command: tagged_value()
        }
    );
    let confirmation = answer(&command, CA).expect("a test command");
    assert_eq!(
        controlling
            .on_response(&confirmation, &Known::EVERYTHING, tagged_value())
            .expect("a whole ASDU")
            .reaction,
        Reaction::Answered {
            command: tagged_value(),
            negative: false
        }
    );

    // A cause-6 command received by the controlling station and a cause-7
    // confirmation received by the controlled station are both Other: the
    // direction is the figure's, not the type's.
    assert_eq!(
        controlling
            .on_response(&command, &Known::EVERYTHING, tagged_value())
            .expect("a whole ASDU")
            .reaction,
        Reaction::Other
    );
    assert_eq!(
        controlled
            .on_request(&confirmation, &Known::EVERYTHING)
            .expect("a whole ASDU")
            .reaction,
        Reaction::Other
    );

    // Another type is Other on both sides.
    let other = another_type();
    assert_eq!(
        controlling
            .on_response(&other, &Known::EVERYTHING, tagged_value())
            .expect("a whole ASDU")
            .reaction,
        Reaction::Other
    );
    assert_eq!(
        controlled
            .on_request(&other, &Known::EVERYTHING)
            .expect("a whole ASDU")
            .reaction,
        Reaction::Other
    );
}

/// The trap a test command shares with the read procedure: a **spontaneous**
/// ASDU of the same type (cause `<3>`) answers nothing and must not be mistaken
/// for a confirmation. Causes `<1>`/`<2>`/`<3>` belong to [`iec104::tx`].
#[test]
fn a_spontaneous_asdu_is_not_a_confirmation() {
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    for cause in [Cause::Periodic, Cause::BackgroundScan, Cause::Spontaneous] {
        let frame = handmade_tagged(cause, tsc(), worked(), CA, false, false, 0);
        let outcome = controlling
            .on_response(&frame, &Known::EVERYTHING, tagged_value())
            .expect("a whole ASDU");
        assert_eq!(outcome.reaction, Reaction::Other, "{cause:?}");
        assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
    }
}

#[test]
fn a_test_type_with_another_cause_is_not_this_procedure() {
    // Clause 7.10's table has one act and one actcon: no termination, no
    // deactivation, no request. A frame of either type carrying one is Other on
    // both sides, and `answer` refuses to mirror it.
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    for cause in [
        Cause::Deactivation,
        Cause::DeactivationCon,
        Cause::ActivationTermination,
        Cause::Request,
    ] {
        let frame = handmade_tagged(cause, tsc(), worked(), CA, false, false, 0);
        assert_eq!(
            controlling
                .on_response(&frame, &Known::EVERYTHING, tagged_value())
                .expect("a whole ASDU")
                .reaction,
            Reaction::Other,
            "{cause:?}"
        );
        assert_eq!(
            controlled
                .on_request(&frame, &Known::EVERYTHING)
                .expect("a whole ASDU")
                .reaction,
            Reaction::Other,
            "{cause:?}"
        );
        assert_eq!(answer(&frame, CA), Err(TsError::CauseNotListed { cause }));
        assert_eq!(
            refusal(&frame, &Known::EVERYTHING, CA),
            Err(TsError::CauseNotListed { cause })
        );
    }
}

#[test]
fn a_frame_of_no_other_type_is_the_not_this_type_error_on_the_builders() {
    let other = another_type();
    assert_eq!(
        answer(&other, CA),
        Err(TsError::NotThisType {
            type_id: TypeId::CCiNa1
        })
    );
    assert_eq!(
        refusal(&other, &Known::EVERYTHING, CA),
        Err(TsError::NotThisType {
            type_id: TypeId::CCiNa1
        })
    );
}

#[test]
fn a_command_with_no_information_object_is_nothing_to_answer() {
    // 5-101 cl.7.2.2's `<0> := ASDU contains no INFORMATION OBJECT`: the
    // six-octet ASDU with nothing after the header. Both figures define
    // `Single information object (SQ = 0)`, so there is no value to echo.
    let empty = {
        let header = Header {
            type_id: TypeId::CTsTa1,
            sequence: false,
            count: 0,
            cause: Cause::Activation,
            negative: false,
            test: false,
            originator: 0,
            common_address: CA,
        };
        let mut frame = Vec::new();
        header.encode(&mut frame).expect("the header encodes");
        frame
    };
    assert_eq!(empty.len(), Header::LEN);
    assert_eq!(header_of(&empty).count, 0);
    assert_eq!(
        decode_asdu::<CTsTa1>(&empty).expect("a whole ASDU"),
        [] as [iec104::asdu::LayoutObject<iec104::asdu::CTsTa1>; 0]
    );

    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    assert_eq!(
        controlled
            .on_request(&empty, &Known::EVERYTHING)
            .expect("a whole ASDU")
            .reaction,
        Reaction::Other
    );
    assert_eq!(answer(&empty, CA), Err(TsError::NoObjectInCommand));

    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let empty_answer = with_cause(&empty, CAUSE_ACTIVATION_CON);
    assert_eq!(
        controlling
            .on_response(&empty_answer, &Known::EVERYTHING, tagged_value())
            .expect("a whole ASDU")
            .reaction,
        Reaction::Other
    );

    // A header that says `<0>` and then carries a body is not that ASDU: the
    // element layer's own rule is the typed error, on every path.
    let command = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    let inconsistent = with_count(&command, 0);
    assert!(matches!(
        decode_asdu::<CTsTa1>(&inconsistent),
        Err(LayoutError::Asdu(
            iec104::asdu::AsduError::ObjectsNotExhausted { .. }
        ))
    ));
    assert!(matches!(answer(&inconsistent, CA), Err(TsError::Layout(_))));
    assert!(matches!(
        controlled.on_request(&inconsistent, &Known::EVERYTHING),
        Err(TsError::Layout(_))
    ));
}

// --------------------------------------------------- the station selection

/// A controlled station answers a test command it does not serve with the
/// cause-44 mirror, so the peer is not left waiting for a confirmation.
fn assert_unsupported(station: &TestProcedure, command: &[u8], reason: Unsupported) {
    let outcome = station
        .on_request(command, &Known::EVERYTHING)
        .expect("answered, not an error");
    assert_eq!(outcome.reaction, Reaction::Unsupported { reason });
    assert_eq!(outcome.send.len(), 1);
    let mirror = &outcome.send[0];
    let header = header_of(mirror);
    assert_eq!(header.cause, Cause::UnknownTypeId);
    assert!(header.negative, "P/N = 1");
    assert_eq!(header.type_id, header_of(command).type_id);
    assert_eq!(
        &mirror[Header::LEN..],
        &command[Header::LEN..],
        "objects mirrored"
    );
}

#[test]
fn the_station_selection_gates_the_builders_and_the_reception() {
    // 104 cl.9.6's "Test procedure" checkbox (index 112, printed page 111) is
    // not marked: nothing is built and nothing is answered.
    let none = TestProcedure::controlling(Selection::NONE, CA, 0);
    assert_eq!(none.selection(), Selection::NONE);
    assert!(!none.selection().uses());
    assert_eq!(none.request(tagged_value()), Err(TsError::FunctionNotUsed));
    let none = TestProcedure::controlled(Selection::NONE, CA, 0);
    assert_eq!(
        none.answer(&request_tagged(tsc(), worked(), CA, 0).unwrap()),
        Err(TsError::FunctionNotUsed)
    );
    assert_unsupported(
        &none,
        &request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it"),
        Unsupported::FunctionNotUsed,
    );
    let controlling = TestProcedure::controlling(Selection::NONE, CA, 0);
    assert_eq!(
        controlling.on_response(
            &answer(
                &request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it"),
                CA
            )
            .expect("a test command"),
            &Known::EVERYTHING,
            tagged_value()
        ),
        Err(TsError::FunctionNotUsed)
    );

    // Marked, and the builders work.
    assert!(
        TestProcedure::controlling(Selection::TAGGED, CA, 0)
            .request(tagged_value())
            .is_ok()
    );
    assert_eq!(Selection::default(), Selection::NONE);
    assert_eq!(Selection::NONE.with_used(true), Selection::TAGGED);
    assert_eq!(
        Selection::TAGGED.with_form(Form::Untagged),
        Selection::UNTAGGED
    );
}

/// 104 Table 4 (index 52) carries `CON <107>` and no `<104>` row, and the
/// clause-9 matrix (index 106) marks the untagged row as an option this
/// companion standard does not permit; 5-101 Table 11 (index 33) marks
/// `CON <104>` and reserves `<107..109>`. So the form is a value, and the other
/// form is refused.
#[test]
fn the_form_selection_refuses_the_other_form() {
    let packet_104 = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    assert!(packet_104.request(tagged_value()).is_ok());
    assert_eq!(
        packet_104.request(untagged_value()),
        Err(TsError::NotSelectedForm {
            type_id: TypeId::CTsNa1
        })
    );

    let packet_101 = TestProcedure::controlling(Selection::UNTAGGED, CA, 0);
    assert!(packet_101.request(untagged_value()).is_ok());
    assert_eq!(
        packet_101.request(tagged_value()),
        Err(TsError::NotSelectedForm {
            type_id: TypeId::CTsTa1
        })
    );

    // The reception side refuses it too: a 104 station does not answer a 101
    // station's untagged command.
    let service_104 = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    let untagged = request_untagged(CA, 0).expect("the layout builds it");
    assert_unsupported(&service_104, &untagged, Unsupported::OtherForm);
    assert_eq!(
        service_104.answer(&untagged),
        Err(TsError::NotSelectedForm {
            type_id: TypeId::CTsNa1
        })
    );

    // And the controlling side: an untagged confirmation at a tagged station.
    let untagged_answer = answer(&untagged, CA).expect("a test command");
    assert_eq!(
        packet_104.on_response(&untagged_answer, &Known::EVERYTHING, tagged_value()),
        Err(TsError::NotSelectedForm {
            type_id: TypeId::CTsNa1
        })
    );

    let packet_101 = TestProcedure::controlling(Selection::UNTAGGED, CA, 0);
    assert_eq!(
        packet_101.on_response(&untagged_answer, &Known::EVERYTHING, untagged_value()),
        Ok(iec104::ts::Outcome {
            reaction: Reaction::Answered {
                command: untagged_value(),
                negative: false
            },
            send: Vec::new()
        })
    );
    assert!(packet_101.request(untagged_value()).is_ok());
}

// ----------------------------------------------------- errors and guards

#[test]
fn every_short_prefix_of_every_frame_is_a_typed_error() {
    let untagged = request_untagged(CA, 42).expect("the layout builds it");
    let tagged = request_tagged(tsc(), worked(), CA, 42).expect("the layout builds it");
    let untagged_answer = answer(&untagged, CA).expect("a test command");
    let tagged_answer = answer(&tagged, CA).expect("a test command");

    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    let controlling_untagged = TestProcedure::controlling(Selection::UNTAGGED, CA, 0);
    let controlled_untagged = TestProcedure::controlled(Selection::UNTAGGED, CA, 0);

    // Each role is swept over the frames of its own direction and form: a prefix
    // of the other form's frame that is long enough to parse is
    // `NotSelectedForm`, which is the tested rule above, not a truncation.
    for (frame, controlled) in [(&tagged, &controlled), (&untagged, &controlled_untagged)] {
        for len in 0..frame.len() {
            let prefix = &frame[..len];
            assert!(
                matches!(controlled_used(controlled, prefix), Err(TsError::Layout(_))),
                "a {len}-octet prefix of a {}-octet request must be a typed error",
                frame.len()
            );
        }
    }
    for (frame, controlling) in [
        (&tagged_answer, &controlling),
        (&untagged_answer, &controlling_untagged),
    ] {
        for len in 0..frame.len() {
            let prefix = &frame[..len];
            let sent = if frame.len() == tagged_answer.len() {
                tagged_value()
            } else {
                untagged_value()
            };
            assert!(
                matches!(
                    controlling.on_response(prefix, &Known::EVERYTHING, sent),
                    Err(TsError::Layout(_))
                ),
                "a {len}-octet prefix of a {}-octet answer must be a typed error",
                frame.len()
            );
        }
    }
    // The free builders see the same.
    for frame in [&untagged, &tagged] {
        for len in 0..frame.len() {
            assert!(matches!(answer(&frame[..len], CA), Err(TsError::Layout(_))));
            assert!(matches!(
                refusal(&frame[..len], &Known::EVERYTHING, CA),
                Err(TsError::Layout(_))
            ));
        }
    }
}

/// [`TestProcedure::on_request`] for the frame's own form: the sweep helper of
/// the truncation test, where the form is the frame's rather than a choice.
fn controlled_used(
    controlled: &TestProcedure,
    prefix: &[u8],
) -> Result<iec104::ts::Outcome, TsError> {
    controlled.on_request(prefix, &Known::EVERYTHING)
}

#[test]
fn the_role_guards_hold_on_every_entry_point() {
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    let command = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");

    assert_eq!(controlling.role(), Role::Controlling);
    assert_eq!(controlled.role(), Role::Controlled);
    assert_eq!(controlled.request(tagged_value()), Err(TsError::WrongRole));
    assert_eq!(controlling.answer(&command), Err(TsError::WrongRole));
    assert_eq!(
        controlled.on_response(
            &answer(&command, CA).expect("a test command"),
            &Known::EVERYTHING,
            tagged_value()
        ),
        Err(TsError::WrongRole)
    );
    assert_eq!(
        controlling.on_request(&command, &Known::EVERYTHING),
        Err(TsError::WrongRole)
    );

    // The entry points of the right role do not fail for these arguments.
    assert!(controlling.request(tagged_value()).is_ok());
    assert!(controlled.answer(&command).is_ok());
}

#[test]
fn the_two_addressing_rules_are_typed_errors() {
    // Clause 7.3.1, both figures and the control layouts: `Single information
    // object (SQ = 0)` with `N = 1`. The layout layer's `check_layout` enforces
    // both rules for the 27 control, system and parameter types, on the read
    // and the write side.
    let command = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    let confirmation = answer(&command, CA).expect("a test command");
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);

    let two_objects = with_count(&confirmation, 2);
    assert_eq!(
        decode_asdu::<CTsTa1>(&two_objects).unwrap_err(),
        LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::CTsTa1,
            count: 2
        }
    );
    assert_eq!(
        controlling.on_response(&two_objects, &Known::EVERYTHING, tagged_value()),
        Err(TsError::Layout(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::CTsTa1,
            count: 2
        }))
    );
    assert!(matches!(
        controlled.on_request(&with_count(&command, 2), &Known::EVERYTHING),
        Err(TsError::Layout(LayoutError::ObjectCountNotAllowed { .. }))
    ));

    // A time-tagged type has no `j(...)` form, so `SQ = 1` is the other rule,
    // and it holds whether the count is one or many.
    for count in [1, 2] {
        let mut sequence = confirmation.clone();
        sequence[1] |= 0x80;
        sequence[1] = (sequence[1] & 0x80) | (count & 0x7F);
        assert_eq!(
            decode_asdu::<CTsTa1>(&sequence).unwrap_err(),
            LayoutError::SequenceNotAllowed {
                type_id: TypeId::CTsTa1
            }
        );
        assert!(matches!(
            controlling.on_response(&sequence, &Known::EVERYTHING, tagged_value()),
            Err(TsError::Layout(LayoutError::SequenceNotAllowed { .. }))
        ));
    }
}

// ------------------------------------------------------- the close of the
// ------------------------------------------------------- scripted exchange

/// The whole procedure, both roles, asserting the octets at each step. It
/// follows the two conformance rows that corroborate the echo and the
/// mismatch rule (TS 60870-5-604 Table 22, `5.4.22.1` and `5.4.22.10`, index 83,
/// printed page 82).
#[test]
fn the_scripted_exchange_of_5_4_22_1() {
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);

    // The primary station sends a test command (ASDU 107) with COT = 6,
    // `C_TS_ACT`, with a TSC of its own choosing.
    let command = controlling
        .request(tagged_value())
        .expect("the activating role");
    assert_eq!(
        command,
        vec![
            0x6B, 0x01, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x55, 0x69, 0x10,
            0x0D, 0x13, 0x01, 0x01,
        ]
    );

    // The secondary station returns the same test command (ASDU 107) with
    // COT = 7, `C_TS_ACTCON`, carrying the request's TSC and exactly the
    // request's time.
    let outcome = controlled
        .on_request(&command, &Known::EVERYTHING)
        .expect("a request is this procedure's");
    assert_eq!(
        outcome.reaction,
        Reaction::Requested {
            command: tagged_value()
        }
    );
    let mut frames = outcome.send.into_iter();
    let confirmation = frames.next().expect("the confirmation");
    assert!(
        frames.next().is_none(),
        "clause 7.10's table has no third frame: no ACTTERM"
    );
    assert_eq!(
        confirmation,
        vec![
            0x6B, 0x01, 0x07, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x55, 0x69, 0x10,
            0x0D, 0x13, 0x01, 0x01,
        ]
    );

    // The primary station detects a TSC that does not match.
    let answered = controlling
        .on_response(&confirmation, &Known::EVERYTHING, tagged_value())
        .expect("the echo matches");
    assert_eq!(
        answered.reaction,
        Reaction::Answered {
            command: tagged_value(),
            negative: false
        }
    );
    assert!(
        answered.send.is_empty(),
        "the requesting side sends nothing more"
    );

    let mismatched = answer(
        &request_tagged(Tsc::from_raw(1), worked(), CA, 0).expect("the layout builds it"),
        CA,
    )
    .expect("a test command");
    assert!(matches!(
        controlling.on_response(&mismatched, &Known::EVERYTHING, tagged_value()),
        Err(TsError::EchoMismatch { .. })
    ));
}

#[test]
fn the_addressing_accessors_report_what_was_built() {
    let controlling = TestProcedure::controlling(Selection::TAGGED, 0x000C, 3);
    assert_eq!(controlling.role(), Role::Controlling);
    assert_eq!(controlling.addressing(), (0x000C, 3));
    assert_eq!(controlling.selection(), Selection::TAGGED);
    let built = controlling
        .request(tagged_value())
        .expect("the activating role");
    assert_eq!(header_of(&built).originator, 3);
    assert_eq!(header_of(&built).common_address, 0x000C);

    let controlled = TestProcedure::controlled(Selection::UNTAGGED, CA, 7);
    assert_eq!(controlled.role(), Role::Controlled);
    assert_eq!(controlled.addressing(), (CA, 7));
    let built = controlled
        .answer(&request_untagged(CA, 42).expect("the layout builds it"))
        .expect("the answering role");
    assert_eq!(
        header_of(&built).originator,
        42,
        "the answer echoes the command's originator, not the instance's"
    );
    assert_eq!(header_of(&built).common_address, CA);

    // The free builders take the caller's addressing too.
    let free = request(tagged_value(), 5, 9).expect("the layout builds it");
    assert_eq!(header_of(&free).common_address, 5);
    assert_eq!(header_of(&free).originator, 9);
}

/// Other command types are not test commands: the types this procedure owns
/// are exactly 104 and 107.
#[test]
fn the_procedure_owns_exactly_the_two_test_types() {
    for type_id in [
        TypeId::CCsNa1,
        TypeId::CIcNa1,
        TypeId::CRdNa1,
        TypeId::Other(99),
    ] {
        assert!(!is_test_type(type_id), "{type_id:?}");
        assert_eq!(form_of(type_id), None);
    }
    // The test is over the wire octet, so an unnamed variant of 104 or 107
    // answers exactly as the named one does.
    assert_eq!(TypeId::Other(104).to_u8(), 104);
    assert!(is_test_type(TypeId::Other(104)));
    assert!(is_test_type(TypeId::Other(107)));
    assert!(!is_test_type(TypeId::Other(105)));
    assert!(!is_test_type(TypeId::Other(106)));
}

// ---------------------------- negative confirmations, mirrors and the gates

/// 5-101 cl.7.2.3 (index 38): the P/N bit says whether the confirmation of an
/// activation the primary application function asked for is positive or
/// negative; 104 Table 2's NOTE (index 52) calls the mirrored ASDUs
/// positive/negative acknowledgements. A negative `ACTCON` carries the same
/// element as the positive one and differs only in that bit, so the outcome has
/// to carry the bit: a negative confirmation must never come back as the
/// positive one.
#[test]
fn a_negative_confirmation_is_not_the_positive_one() {
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let positive = controlling
        .on_response(
            &answer(
                &request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it"),
                CA,
            )
            .expect("a test command"),
            &Known::EVERYTHING,
            tagged_value(),
        )
        .expect("the echo matches");
    assert_eq!(
        positive.reaction,
        Reaction::Answered {
            command: tagged_value(),
            negative: false
        }
    );

    // The same element, the same cause `<7>`, `P/N = 1`: cause 7 with a defined
    // cause is not the 44–47 mirror, it is the negative verification.
    let negative = handmade_tagged(Cause::ActivationCon, tsc(), worked(), CA, true, false, 0);
    assert!(header_of(&negative).negative);
    assert_eq!(header_of(&negative).cause, CAUSE_ACTIVATION_CON);
    let outcome = controlling
        .on_response(&negative, &Known::EVERYTHING, tagged_value())
        .expect("the echo matches");
    assert_eq!(
        outcome.reaction,
        Reaction::Answered {
            command: tagged_value(),
            negative: true
        }
    );
    assert_ne!(
        outcome.reaction, positive.reaction,
        "a negative confirmation is never the positive one"
    );

    // The untagged form behaves the same way.
    let controlling = TestProcedure::controlling(Selection::UNTAGGED, CA, 0);
    let negative = handmade_untagged_raw(Cause::ActivationCon, [0xAA, 0x55], CA, true);
    assert_eq!(
        controlling
            .on_response(&negative, &Known::EVERYTHING, untagged_value())
            .expect("the echo matches")
            .reaction,
        Reaction::Answered {
            command: untagged_value(),
            negative: true
        }
    );
}

/// [`TestProcedure::on_response`] walks a mirrored frame's object area against
/// the type's own geometry before naming it, exactly as
/// [`TestProcedure::on_request`] walks its own mirror, so every short prefix is a
/// typed error rather than a `Refused` classification.
#[test]
fn every_short_prefix_of_a_mirror_is_a_typed_error_on_response() {
    let controlling = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let controlling_untagged = TestProcedure::controlling(Selection::UNTAGGED, CA, 0);

    let mut mirrored_tagged = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    mirrored_tagged[2] = 0x40 | 0x2C;
    let mut mirrored_untagged = request_untagged(CA, 0).expect("the layout builds it");
    mirrored_untagged[2] = 0x40 | 0x2C;

    for (frame, station, sent) in [
        (&mirrored_tagged, &controlling, tagged_value()),
        (&mirrored_untagged, &controlling_untagged, untagged_value()),
    ] {
        assert!(header_of(frame).negative, "P/N = 1");
        assert_eq!(header_of(frame).cause, Cause::UnknownTypeId);
        for len in 0..frame.len() {
            assert!(
                matches!(
                    station.on_response(&frame[..len], &Known::EVERYTHING, sent),
                    Err(TsError::Layout(_))
                ),
                "a {len}-octet prefix of a {}-octet mirrored command must be a typed error",
                frame.len()
            );
        }
        // The whole frame is the refusal it is meant to be.
        assert_eq!(
            station
                .on_response(frame, &Known::EVERYTHING, sent)
                .expect("a whole ASDU")
                .reaction,
            Reaction::Refused {
                cause: Cause::UnknownTypeId
            }
        );
    }
}

/// The answer is the received frame **mirrored**, not re-encoded. 104 Table 2's
/// NOTE (index 52): the `CON` ASDU is mirrored with its cause of transmission
/// changed, and nothing else changes. A test command's information object
/// address is `<0>` by definition (figure 76's field row), but the field belongs
/// to the received frame and must come back as it arrived.
#[test]
fn the_answer_echoes_a_command_address_that_is_not_zero() {
    let ioa: u32 = 5;

    let tagged = encode_asdu(
        &Header {
            type_id: TypeId::CTsTa1,
            sequence: false,
            count: 1,
            cause: CAUSE_ACTIVATION,
            negative: false,
            test: false,
            originator: 7,
            common_address: CA,
        },
        &[LayoutObject {
            ioa,
            value: CTsTa1 {
                tsc: tsc(),
                time: worked(),
            },
        }],
    )
    .expect("the layout builds it");
    assert_eq!(
        &tagged[6..9],
        &[0x05, 0x00, 0x00],
        "IOA 5, not the figure's 0"
    );
    let answered = answer(&tagged, CA).expect("a test command");
    assert_eq!(answered.len(), tagged.len());
    for octet in 0..tagged.len() {
        if octet != 2 {
            assert_eq!(
                answered[octet], tagged[octet],
                "octet {octet} of the answer is unchanged"
            );
        }
    }
    assert_eq!(answered[2], 0x07, "the cause octet itself");
    assert_eq!(&answered[6..9], &[0x05, 0x00, 0x00]);

    let untagged = encode_asdu(
        &Header {
            type_id: TypeId::CTsNa1,
            sequence: false,
            count: 1,
            cause: CAUSE_ACTIVATION,
            negative: false,
            test: false,
            originator: 7,
            common_address: CA,
        },
        &[LayoutObject {
            ioa,
            value: CTsNa1 { fbp: Fbp },
        }],
    )
    .expect("the layout builds it");
    let answered = answer(&untagged, CA).expect("a test command");
    assert_eq!(answered, {
        let mut expected = untagged;
        expected[2] = 0x07;
        expected
    });

    // The reception path puts exactly that frame in `Outcome::send`.
    let controlled = TestProcedure::controlled(Selection::TAGGED, CA, 0);
    assert_eq!(
        controlled
            .on_request(&tagged, &Known::EVERYTHING)
            .expect("a whole ASDU")
            .send,
        vec![answer(&tagged, CA).expect("a test command")]
    );
}

/// The clause 9.6 checkbox gate runs **before** the form gate, on both reception
/// paths and before a mirror is named (as [`TestProcedure::request`]'s does): a
/// station that does not use the test procedure has no selected form to report
/// the other one against, so either form is
/// [`TsError::FunctionNotUsed`].
#[test]
fn a_station_that_does_not_use_the_function_reports_that_for_either_form() {
    let none_controlling = TestProcedure::controlling(Selection::NONE, CA, 0);
    let none_controlled = TestProcedure::controlled(Selection::NONE, CA, 0);

    let tagged_command = request_tagged(tsc(), worked(), CA, 0).expect("the layout builds it");
    let untagged_command = request_untagged(CA, 0).expect("the layout builds it");
    let tagged_answer = answer(&tagged_command, CA).expect("a test command");
    let untagged_answer = answer(&untagged_command, CA).expect("a test command");

    for (command, answer) in [
        (&tagged_command, &tagged_answer),
        (&untagged_command, &untagged_answer),
    ] {
        assert_unsupported(&none_controlled, command, Unsupported::FunctionNotUsed);
        assert_eq!(
            none_controlling.on_response(
                answer,
                &Known::EVERYTHING,
                Command::Untagged { fbp: Fbp }
            ),
            Err(TsError::FunctionNotUsed),
            "on_response, {}",
            header_of(answer).type_id.to_u8()
        );
    }

    // A mirror arriving at a station that does not use the procedure is the same
    // error, not a `Refused` classification.
    let mut mirrored = tagged_command.clone();
    mirrored[2] = 0x40 | 0x2E;
    assert_eq!(
        none_controlling.on_response(&mirrored, &Known::EVERYTHING, tagged_value()),
        Err(TsError::FunctionNotUsed)
    );

    // And the builders report it too: `request` is the same gate.
    assert_eq!(
        none_controlling.request(tagged_value()),
        Err(TsError::FunctionNotUsed)
    );
    assert_eq!(
        none_controlling.request(untagged_value()),
        Err(TsError::FunctionNotUsed)
    );
    assert_eq!(
        none_controlled.answer(&tagged_command),
        Err(TsError::FunctionNotUsed)
    );
}

/// The controlled station's confirmation is built with its own address sizes,
/// not the conventional ones: with a one-octet cause, a two-octet IOA and no
/// originator, the eight-octet command is answered, not a truncation error.
#[test]
fn the_confirmation_uses_the_stations_address_sizes() {
    let sizes = iec104::asdu::AddressSizes::new(1, 2, false).expect("valid sizes");
    let controlling =
        TestProcedure::controlling(Selection::UNTAGGED, 7, 0).with_address_sizes(sizes);
    let controlled = TestProcedure::controlled(Selection::UNTAGGED, 7, 0).with_address_sizes(sizes);

    let command = controlling
        .request(untagged_value())
        .expect("the layout builds it");
    assert_eq!(command, [104, 1, 6, 7, 0, 0, 0xAA, 0x55]);

    let outcome = controlled
        .on_request(&command, &Known::EVERYTHING)
        .expect("a request is this procedure's");
    assert_eq!(
        outcome.reaction,
        Reaction::Requested {
            command: untagged_value()
        }
    );
    assert_eq!(outcome.send, [vec![104, 1, 7, 7, 0, 0, 0xAA, 0x55]]);
}
