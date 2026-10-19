//! Clock synchronisation: `C_CS_NA_1`, the pre-synchronisation answer, the
//! spontaneous monitor-direction use of the same type, and the time fields the
//! codec carries.
//!
//! The clause citations are 5-104 cl.7.6 (PDF page index 66, printed page 65)
//! and cl.7.6.1 (page index 68, printed 67); 5-101 cl.7.3.4.4 (figure 75, page
//! index 107, printed 106), cl.7.2.6.18 (page index 52, printed 51), cl.7.2.4
//! (page index 43, printed 42), cl.7.2.3 (page index 38, printed 37) and
//! cl.7.4.6 (page index 126, printed 125); and TS 60870-5-604 Table 18 (page
//! index 69, printed 68) with Table 16's ASDU-103 row (page index 63, printed
//! 62).
//!
//! These tests drive the two roles against each other, so every assertion is
//! about a frame one role sent and the other classified.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used, clippy::indexing_slicing, clippy::as_conversions)]

use std::time::{Duration, Instant};

use iec104::asdu::{
    CCiNa1, CCsNa1, Cause, Cp24Time2a, Cp56Time2a, Discard, Header, IOA_IRRELEVANT, Known,
    LayoutObject, Qcc, TypeId, decode_asdu, encode_asdu,
};
use iec104::cs::{
    CAUSE_ACTIVATION, CAUSE_ACTIVATION_CON, CAUSE_SPONTANEOUS, ClockSynchronisation, CsError,
    Reaction, Role, TYPE_ID, TimeValidity, announcement, answer, request,
};

const CA: u16 = 12;

/// The worked example of Clarke/Reynders/Wright, *Practical Modern SCADA
/// Protocols*, Appendix D: 26.965 s, 16 min past 13:00, 19 January 2001, day of
/// week not used, encoded as `55 69 10 0D 13 01 01`. The crate's time codec
/// pins it in `tests/elements_time.rs`; here it is the whole body of a type-103
/// frame.
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

// ---------------------------------------------------------------- helpers

/// The header of a whole ASDU.
fn header_of(asdu: &[u8]) -> Header {
    Header::parse(asdu).expect("a whole ASDU")
}

/// The `CP56Time2a` a type-103 frame carries, read back through the layout.
fn time_of(asdu: &[u8]) -> Cp56Time2a {
    decode_asdu::<CCsNa1>(asdu)
        .expect("a type-103 ASDU")
        .first()
        .expect("one information object")
        .value
        .time
}

/// A type-103 ASDU built by hand, for the frames this module deliberately does
/// not build: another cause, another object count, `SQ = 1`, `P/N = 1`.
fn handmade(
    cause: Cause,
    time: Cp56Time2a,
    common_address: u16,
    count: u8,
    sequence: bool,
    negative: bool,
) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::CCsNa1,
        sequence,
        count,
        cause,
        negative,
        test: false,
        originator: 0,
        common_address,
    };
    if count == 0 {
        // The writer refuses N = 0 for a single-object type; the reader must
        // still cope with one arriving, so it is written by hand.
        let mut frame = Vec::new();
        header.encode(&mut frame);
        return frame;
    }
    let objects = vec![LayoutObject {
        ioa: IOA_IRRELEVANT,
        value: CCsNa1 { time },
    }];
    encode_asdu(&header, &objects).expect("the layout builds it")
}

/// A copy of `frame` whose `N` field reads `count`.
fn with_count(frame: &[u8], count: u8) -> Vec<u8> {
    let mut copy = frame.to_vec();
    copy[1] = (copy[1] & 0x80) | (count & 0x7F);
    copy
}

/// A copy of `frame` with `SQ = 1`.
fn with_sequence(frame: &[u8]) -> Vec<u8> {
    let mut copy = frame.to_vec();
    copy[1] |= 0x80;
    copy
}

// ------------------------------------------------------- the frame geometry

/// Figure 75: sixteen octets, `N = 1`, `SQ = 0`, information object address 0,
/// and the seven time octets after it.
#[test]
fn the_request_is_the_sixteen_octets_of_figure_75() {
    let asdu = request(worked(), CA, 0).expect("the layout builds it");
    assert_eq!(asdu.len(), 16, "6 header + 3 IOA + 7 CP56Time2a");
    assert_eq!(
        asdu,
        vec![
            0x67, 0x01, 0x06, 0x00, 0x0C, 0x00, // type 103, VSQ 00 000 001, act, org 0, CA 12
            0x00, 0x00, 0x00, // INFORMATION OBJECT ADDRESS = 0
            0x55, 0x69, 0x10, 0x0D, 0x13, 0x01, 0x01, // CP56Time2a
        ]
    );

    let header = header_of(&asdu);
    assert_eq!(header.type_id, TypeId::CCsNa1);
    assert_eq!(header.type_id.to_u8(), 103);
    assert_eq!(header.cause, Cause::Activation);
    assert_eq!(header.count, 1);
    assert!(!header.sequence);
    assert!(!header.negative);
    assert!(!header.test);
    assert_eq!(header.common_address, CA);
}

#[test]
fn the_answer_and_the_announcement_differ_from_the_request_in_the_cause_octet() {
    let requested = request(worked(), CA, 0).expect("the layout builds it");
    let answered = answer(worked(), CA, 0).expect("the layout builds it");
    let announced = announcement(worked(), CA, 0).expect("the layout builds it");

    assert_eq!(answered.len(), requested.len());
    assert_eq!(announced.len(), requested.len());
    assert_eq!(
        header_of(&answered).cause,
        Cause::ActivationCon,
        "figure 75: <7> activation confirmation"
    );
    assert_eq!(
        header_of(&announced).cause,
        Cause::Spontaneous,
        "figure 75: <3> spontaneous"
    );
    assert_eq!(CAUSE_ACTIVATION, Cause::Activation);
    assert_eq!(CAUSE_ACTIVATION_CON, Cause::ActivationCon);
    assert_eq!(CAUSE_SPONTANEOUS, Cause::Spontaneous);
    assert_eq!(TYPE_ID, TypeId::CCsNa1);

    // Only octet 2 (the cause) moves between the three.
    for (other, cause) in [(&answered, 7u8), (&announced, 3u8)] {
        assert_eq!(other[2], cause, "the cause octet itself");
        for octet in 0..requested.len() {
            if octet != 2 {
                assert_eq!(other[octet], requested[octet], "octet {octet} is unchanged");
            }
        }
    }
}

#[test]
fn the_seven_time_octets_are_the_worked_example_byte_for_byte() {
    for frame in [
        request(worked(), CA, 0),
        answer(worked(), CA, 0),
        announcement(worked(), CA, 0),
    ] {
        let asdu = frame.expect("the layout builds it");
        assert_eq!(&asdu[9..16], &WORKED_OCTETS);
        assert_eq!(time_of(&asdu), worked());
    }
}

#[test]
fn the_type_is_the_catalogues_103_and_its_element_is_seven_octets() {
    assert_eq!(TypeId::CCsNa1.to_u8(), 103);
    assert_eq!(iec104::asdu::element_len(TypeId::CCsNa1), Some(7));
    assert_eq!(Cp56Time2a::LEN, 7);
}

// ------------------------------------------------- the pre-synchronisation rule

#[test]
fn the_controlled_station_answers_with_the_time_it_had_before_the_correction() {
    // 5-104 cl.7.6: the ACTCON "contains the local time before it was
    // synchronized". The request is sent at 13:16, the station's own clock read
    // 12:16 before the correction is applied.
    let sent = worked();
    let before = Cp56Time2a {
        hours: 12,
        invalid: true,
        ..sent
    };
    let requested = request(sent, CA, 0).expect("the layout builds it");

    let controlled = ClockSynchronisation::controlled(CA, 0);
    let outcome = controlled
        .on_request(&requested, &Known::EVERYTHING, before)
        .expect("a request is this procedure's");

    assert_eq!(
        outcome.reaction,
        Reaction::Requested {
            time: sent,
            test: false
        }
    );
    assert_eq!(
        outcome.send.len(),
        1,
        "one answer, and no termination follows"
    );
    assert_eq!(header_of(&outcome.send[0]).cause, Cause::ActivationCon);
    assert_eq!(
        time_of(&outcome.send[0]),
        before,
        "the answer carries the pre-sync time, not the request's"
    );
    assert_ne!(
        time_of(&outcome.send[0]),
        time_of(&requested),
        "the request's own time must not come back"
    );
    assert_eq!(
        outcome.send[0],
        answer(before, CA, 0).expect("the layout builds it"),
        "the outcome's frame is the answer builder's"
    );
}

#[test]
fn a_broadcast_request_keeps_the_broadcast_address() {
    // 5-101 cl.7.2.4 lists type <103> among the ASDUs the broadcast address may
    // be used with, and names this procedure as its example.
    for broadcast in [0xFF_u16, 0xFFFF] {
        let asdu = request(worked(), broadcast, 0).expect("the layout builds it");
        assert_eq!(header_of(&asdu).common_address, broadcast);
    }
    let station = ClockSynchronisation::controlling(0xFFFF, 0);
    let asdu = station.request(worked()).expect("the activating role");
    assert_eq!(header_of(&asdu).common_address, 0xFFFF);
}

#[test]
fn the_answer_to_a_broadcast_carries_the_stations_own_address() {
    // "ACTCON … are returned with the specific common addresses of the
    // controlled stations" (cl.7.2.4). The module never rewrites one into the
    // other, so the request's broadcast is still on the request and the
    // station's own address is on the answer.
    let broadcast = request(worked(), 0xFFFF, 0).expect("the layout builds it");
    let before = Cp56Time2a {
        hours: 11,
        ..worked()
    };
    let controlled = ClockSynchronisation::controlled(CA, 0);
    let outcome = controlled
        .on_request(&broadcast, &Known::EVERYTHING, before)
        .expect("a request is this procedure's");

    assert_eq!(header_of(&outcome.send[0]).common_address, CA);
    assert_ne!(header_of(&outcome.send[0]).common_address, 0xFFFF);
    assert_eq!(header_of(&broadcast).common_address, 0xFFFF);
}

#[test]
fn the_answer_echoes_the_originator_address_of_the_request() {
    // 5-101 cl.7.2.3: "the information source should set the originator address
    // of the ASDUs in the command direction, and the controlled station should
    // echo this originator address in the response in the monitor direction",
    // because "the returned information is only of importance for the source
    // which initiated the request or the command". TS 60870-5-604 Table 18's row
    // 5.4.18.1 calls this frame a mirror of ASDU 103. The station's own
    // originator is 0 here and the request's is 42, so the two cannot be
    // confused.
    let activation = request(worked(), CA, 42).expect("the layout builds it");
    let before = Cp56Time2a {
        hours: 12,
        ..worked()
    };
    let controlled = ClockSynchronisation::controlled(CA, 0);
    let outcome = controlled
        .on_request(&activation, &Known::EVERYTHING, before)
        .expect("a request is this procedure's");

    assert_eq!(header_of(&activation).originator, 42);
    assert_eq!(header_of(&outcome.send[0]).originator, 42);
    assert_ne!(header_of(&outcome.send[0]).originator, 0);
    // The answer is otherwise the pre-sync answer builder's frame, whose
    // originator is whatever the caller passed.
    assert_eq!(
        outcome.send[0],
        answer(before, CA, 42).expect("the layout builds it")
    );
}

/// 5-101 cl.7.2.3: the `T` bit marks an ASDU *"generated during test
/// conditions"*, used *"to test transmission and equipment without
/// controlling the process"*. The answer to a `T = 1` request echoes it, the
/// reaction reports it, and the clock is not counted as synchronised.
#[test]
fn a_test_request_is_answered_under_test_and_does_not_synchronise() {
    let mut activation = request(worked(), CA, 0).expect("the layout builds it");
    activation[2] |= 0x80;
    let controlled = ClockSynchronisation::controlled(CA, 0);
    let outcome = controlled
        .on_request(&activation, &Known::EVERYTHING, worked())
        .expect("a request is this procedure's");

    assert_eq!(
        outcome.reaction,
        Reaction::Requested {
            time: worked(),
            test: true
        }
    );
    assert!(header_of(&outcome.send[0]).test, "the answer echoes T = 1");
    let mut validity = TimeValidity::new(Duration::from_secs(60));
    assert!(!validity.on_outcome(&outcome, Instant::now()));
    assert_eq!(validity.last_synchronised(), None);
}

// -------------------------------------------------- the reception classification

#[test]
fn a_spontaneous_clock_time_announces_and_never_answers() {
    // Figure 75's caption and TS 60870-5-604 Table 16's ASDU-103 row: cause 3 is
    // an announcement, not an answer to a request.
    let announced = announcement(worked(), CA, 0).expect("the layout builds it");
    let controlling = ClockSynchronisation::controlling(CA, 0);
    let outcome = controlling
        .on_response(&announced, &Known::EVERYTHING)
        .expect("a type-103 frame of this direction");

    assert_eq!(outcome.reaction, Reaction::Announced { time: worked() });
    assert!(outcome.send.is_empty(), "an announcement answers nothing");
    assert_ne!(
        outcome.reaction,
        Reaction::Answered {
            time: worked(),
            negative: false
        },
        "cause 3 is not cause 7"
    );
}

#[test]
fn the_answer_is_classified_by_its_cause_alone() {
    // There is no running activation to correlate against: cl.7.6 defines no
    // termination, no lock and no re-activation options, so this procedure keeps
    // no state and an answer is classified by its own cause. A station that
    // wants correlation has the common address to do it with (the module doc
    // says so, and this test pins it).
    let answered = answer(worked(), CA, 0).expect("the layout builds it");
    let controlling = ClockSynchronisation::controlling(CA, 0);
    let outcome = controlling
        .on_response(&answered, &Known::EVERYTHING)
        .expect("a type-103 frame of this direction");

    assert_eq!(
        outcome.reaction,
        Reaction::Answered {
            time: worked(),
            negative: false
        }
    );
    assert!(
        outcome.send.is_empty(),
        "the controlling station confirms nothing"
    );
}

#[test]
fn a_negative_confirmation_reports_its_flag() {
    // 5-101 cl.7.2.3's negative confirmation: `<7>` with `P/N = 1`. This
    // procedure builds none (see the module doc) but it must classify a peer's.
    let frame = handmade(Cause::ActivationCon, worked(), CA, 1, false, true);
    let controlling = ClockSynchronisation::controlling(CA, 0);
    let outcome = controlling
        .on_response(&frame, &Known::EVERYTHING)
        .expect("a type-103 frame of this direction");
    assert_eq!(
        outcome.reaction,
        Reaction::Answered {
            time: worked(),
            negative: true
        }
    );
}

#[test]
fn a_negative_activation_is_still_classified_as_a_request() {
    // 5-101 cl.7.2.3: "The P/N-bit indicates the positive or negative
    // confirmation of activation requested by the primary application function.
    // In the case of irrelevance, the P/N-bit is zero." Figure 75's
    // control-direction list prints only "<6> activation", so a negative
    // activation is a value this type does not define, and the clause's discard
    // rule is about undefined *causes of transmission* for a type
    // identification, not about this bit. The module therefore reads the cause,
    // reports the time and answers positively; this test pins that reading
    // rather than leaving it to be discovered.
    let frame = handmade(Cause::Activation, worked(), CA, 1, false, true);
    let before = Cp56Time2a {
        hours: 11,
        ..worked()
    };
    let controlled = ClockSynchronisation::controlled(CA, 0);
    let outcome = controlled
        .on_request(&frame, &Known::EVERYTHING, before)
        .expect("a type-103 frame of this direction");

    assert_eq!(
        outcome.reaction,
        Reaction::Requested {
            time: worked(),
            test: false
        }
    );
    assert_eq!(header_of(&outcome.send[0]).cause, CAUSE_ACTIVATION_CON);
    assert!(
        !header_of(&outcome.send[0]).negative,
        "the module builds no negative confirmation"
    );
}

#[test]
fn a_request_received_by_the_controlling_station_is_not_this_procedure() {
    let requested = request(worked(), CA, 0).expect("the layout builds it");
    let controlling = ClockSynchronisation::controlling(CA, 0);
    assert_eq!(
        controlling
            .on_response(&requested, &Known::EVERYTHING)
            .expect("a type-103 frame")
            .reaction,
        Reaction::Other,
        "cause 6 is the control direction, which a controlling station does not receive"
    );
}

#[test]
fn an_answer_received_by_the_controlled_station_is_not_this_procedure() {
    let answered = answer(worked(), CA, 0).expect("the layout builds it");
    let controlled = ClockSynchronisation::controlled(CA, 0);
    assert_eq!(
        controlled
            .on_request(&answered, &Known::EVERYTHING, worked())
            .expect("a type-103 frame")
            .reaction,
        Reaction::Other
    );
}

#[test]
fn a_termination_or_a_deactivation_of_this_type_is_not_this_procedure() {
    // Clause 7.6's service table has four rows and no termination and no
    // deactivation; figure 75's type list prints no <10>.
    for cause in [
        Cause::ActivationTermination,
        Cause::Deactivation,
        Cause::DeactivationCon,
    ] {
        let frame = handmade(cause, worked(), CA, 1, false, false);
        let controlling = ClockSynchronisation::controlling(CA, 0);
        let controlled = ClockSynchronisation::controlled(CA, 0);
        assert_eq!(
            controlling
                .on_response(&frame, &Known::EVERYTHING)
                .expect("a type-103 frame")
                .reaction,
            Reaction::Other,
            "{cause:?} is not a clock synchronisation frame"
        );
        assert_eq!(
            controlled
                .on_request(&frame, &Known::EVERYTHING, worked())
                .expect("a type-103 frame")
                .reaction,
            Reaction::Other
        );
    }
}

#[test]
fn an_asdu_of_another_type_is_other() {
    let other = encode_asdu(
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
    .expect("the layout builds it");

    let controlling = ClockSynchronisation::controlling(CA, 0);
    let controlled = ClockSynchronisation::controlled(CA, 0);
    assert_eq!(
        controlling
            .on_response(&other, &Known::EVERYTHING)
            .expect("a whole ASDU")
            .reaction,
        Reaction::Other
    );
    assert_eq!(
        controlled
            .on_request(&other, &Known::EVERYTHING, worked())
            .expect("a whole ASDU")
            .reaction,
        Reaction::Other
    );
}

#[test]
fn a_type_103_frame_with_no_information_object_is_other() {
    // Clause 7.2.2's `<0> := ASDU contains no INFORMATION OBJECT`: there is no
    // time to adopt and nothing to answer with.
    let frame = handmade(Cause::Activation, worked(), CA, 0, false, false);
    assert_eq!(header_of(&frame).count, 0);
    assert_eq!(
        decode_asdu::<CCsNa1>(&frame).expect("a whole ASDU"),
        [] as [iec104::asdu::LayoutObject<iec104::asdu::CCsNa1>; 0]
    );

    let controlled = ClockSynchronisation::controlled(CA, 0);
    assert_eq!(
        controlled
            .on_request(&frame, &Known::EVERYTHING, worked())
            .expect("a type-103 frame")
            .reaction,
        Reaction::Other
    );
}

// ------------------------------------------------------------- clause 7.2.3

#[test]
fn the_discard_rule_runs_before_the_type_is_examined() {
    let frame = request(worked(), CA, 0).expect("the layout builds it");
    let controlled = ClockSynchronisation::controlled(CA, 0);

    // An undefined field: clause 7.2.3's first class wins, cause 44.
    let outcome = controlled
        .on_request(&frame, &Known::NOTHING, worked())
        .expect("a whole ASDU");
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            cause: Cause::UnknownTypeId
        }
    );
    assert_eq!(outcome.send.len(), 1, "mirrored, not dropped");
    let mirror = Header::parse(&outcome.send[0]).expect("header");
    assert!(mirror.negative, "P/N = 1");
    assert_eq!(mirror.cause, Cause::UnknownTypeId);
    assert_eq!(&outcome.send[0][Header::LEN..], &frame[Header::LEN..]);

    // A common address that is not one of the station's own.
    let foreign = Known {
        type_id: true,
        cause: true,
        common_address: false,
        information_object_address: true,
    };
    assert_eq!(
        controlled
            .on_request(&frame, &foreign, worked())
            .expect("a whole ASDU")
            .reaction,
        Reaction::Refused {
            cause: Cause::UnknownCommonAddress
        }
    );
}

#[test]
fn a_mirror_is_discarded_and_not_answered() {
    // Clause 7.2.3's mirror: `P/N = 1` with one of the four causes 44 to 47.
    // Here it is the mirror of a type-103 frame (cl.7.2.4's list includes
    // <103>), which must not be answered with a second answer.
    let mirror = handmade(
        Cause::UnknownInformationObjectAddress,
        worked(),
        CA,
        1,
        false,
        true,
    );
    let controlling = ClockSynchronisation::controlling(CA, 0);
    let outcome = controlling
        .on_response(&mirror, &Known::EVERYTHING)
        .expect("a whole ASDU");
    assert_eq!(outcome.reaction, Reaction::Discard(Discard::Mirror));
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
}

// ----------------------------------------------------- errors, never panics

#[test]
fn every_short_prefix_of_every_frame_is_a_typed_error() {
    let requested = request(worked(), CA, 0).expect("the layout builds it");
    let answered = answer(worked(), CA, 0).expect("the layout builds it");
    let announced = announcement(worked(), CA, 0).expect("the layout builds it");
    let controlling = ClockSynchronisation::controlling(CA, 0);
    let controlled = ClockSynchronisation::controlled(CA, 0);

    // Each role is swept over the frames of its own direction, the frames it
    // can classify at all. A prefix of the *other* direction's frame that is
    // long enough to parse is `Other` by its cause, which is the tested rule
    // above, not an error.
    for frame in [&requested] {
        for len in 0..frame.len() {
            let prefix = &frame[..len];
            assert!(
                matches!(
                    controlled.on_request(prefix, &Known::EVERYTHING, worked()),
                    Err(CsError::Layout(_))
                ),
                "a {len}-octet prefix of a {}-octet request must be a typed error",
                frame.len()
            );
        }
    }
    for frame in [&answered, &announced] {
        for len in 0..frame.len() {
            let prefix = &frame[..len];
            assert!(
                matches!(
                    controlling.on_response(prefix, &Known::EVERYTHING),
                    Err(CsError::Layout(_))
                ),
                "a {len}-octet prefix of a {}-octet frame must be a typed error",
                frame.len()
            );
        }
    }
}

#[test]
fn the_two_addressing_rules_are_typed_errors() {
    // Clause 7.3.1: this type is "Single information object (SQ = 0)" and has no
    // sequence form.
    let whole = request(worked(), CA, 0).expect("the layout builds it");
    let controlling = ClockSynchronisation::controlling(CA, 0);

    let two_objects = with_count(&whole, 2);
    assert!(matches!(
        controlling.on_response(&two_objects, &Known::EVERYTHING),
        Err(CsError::Layout(_))
    ));

    let sequence = with_sequence(&whole);
    assert!(matches!(
        controlling.on_response(&sequence, &Known::EVERYTHING),
        Err(CsError::Layout(_))
    ));
}

#[test]
fn the_role_guards_hold_on_every_entry_point() {
    let controlling = ClockSynchronisation::controlling(CA, 0);
    let controlled = ClockSynchronisation::controlled(CA, 0);
    let frame = request(worked(), CA, 0).expect("the layout builds it");

    assert_eq!(
        controlled.on_response(&frame, &Known::EVERYTHING),
        Err(CsError::WrongRole)
    );
    assert_eq!(
        controlling.on_request(&frame, &Known::EVERYTHING, worked()),
        Err(CsError::WrongRole)
    );
    assert_eq!(controlled.request(worked()), Err(CsError::WrongRole));
    assert_eq!(controlling.answer(worked()), Err(CsError::WrongRole));
    assert_eq!(controlling.announcement(worked()), Err(CsError::WrongRole));

    // The builders of the right role do not fail for these arguments.
    assert!(controlling.request(worked()).is_ok());
    assert!(controlled.answer(worked()).is_ok());
    assert!(controlled.announcement(worked()).is_ok());
}

// ------------------------------------------------------------- the time fields

#[test]
fn the_day_of_week_is_carried_unchanged() {
    // 5-101 cl.7.2.6.18: day of week is <0> not used and <1..7> Monday…Sunday,
    // "used (optional)". This module passes the field through rather than
    // policing it.
    for day in [0_u8, 1, 7] {
        let time = Cp56Time2a {
            day_of_week: day,
            ..worked()
        };
        for frame in [
            request(time, CA, 0),
            answer(time, CA, 0),
            announcement(time, CA, 0),
        ] {
            let asdu = frame.expect("the layout builds it");
            assert_eq!(time_of(&asdu).day_of_week, day);
        }
    }
    // And the octet itself: Sunday is bits 6..8 of octet 5.
    let sunday = Cp56Time2a {
        day_of_week: 7,
        ..worked()
    };
    let asdu = request(sunday, CA, 0).expect("the layout builds it");
    assert_eq!(asdu[13], (0x13 & 0x1F) | (7 << 5), "19 January, Sunday");
}

#[test]
fn the_invalid_and_summer_time_bits_are_carried() {
    // 5-101 cl.7.4.6: "Bit IV is set to 1 if the clock is not synchronized for a
    // specific period of time" and "The summer-time bit is ignored in both
    // controlling and controlled stations, and should be set to zero." The
    // marking is the application's, but the bits must survive the frame.
    let time = Cp56Time2a {
        invalid: true,
        summer_time: true,
        substituted: true,
        ..worked()
    };
    for frame in [
        request(time, CA, 0),
        answer(time, CA, 0),
        announcement(time, CA, 0),
    ] {
        let asdu = frame.expect("the layout builds it");
        assert_eq!(time_of(&asdu), time);
        assert_eq!(asdu[11] & 0x80, 0x80, "IV is bit 8 of the minutes octet");
        assert_eq!(asdu[11] & 0x40, 0x40, "RES1/GEN is bit 7 of it");
        assert_eq!(asdu[12] & 0x80, 0x80, "SU is bit 8 of the hours octet");
    }
}

// --------------------------------------------------------- the scripted exchange

#[test]
fn the_scripted_exchange() {
    // The controlling station synchronises the controlled station's clock at
    // 13:16; the controlled station's clock read 12:16 and comes back before the
    // correction. Two frames, and nothing else.
    let controlling = ClockSynchronisation::controlling(CA, 0);
    let controlled = ClockSynchronisation::controlled(CA, 0);

    let sent = worked();
    let request_frame = controlling.request(sent).expect("the activating role");
    assert_eq!(header_of(&request_frame).cause, Cause::Activation);

    let before = Cp56Time2a { hours: 12, ..sent };
    let request_outcome = controlled
        .on_request(&request_frame, &Known::EVERYTHING, before)
        .expect("a request is this procedure's");
    assert_eq!(
        request_outcome.reaction,
        Reaction::Requested {
            time: sent,
            test: false
        }
    );

    let mut frames = request_outcome.send.into_iter();
    let answer_frame = frames.next().expect("the answer");
    assert!(
        frames.next().is_none(),
        "clause 7.6's table has no third frame: no ACTTERM"
    );

    let answer_outcome = controlling
        .on_response(&answer_frame, &Known::EVERYTHING)
        .expect("an answer is this direction's");
    assert_eq!(
        answer_outcome.reaction,
        Reaction::Answered {
            time: before,
            negative: false
        }
    );
    assert!(
        answer_outcome.send.is_empty(),
        "the controlling station sends nothing more"
    );
    assert_eq!(header_of(&answer_frame).type_id, TypeId::CCsNa1);
}

#[test]
fn the_addressing_accessors_report_what_was_built() {
    let controlling = ClockSynchronisation::controlling(0xFFFF, 3);
    assert_eq!(controlling.role(), Role::Controlling);
    assert_eq!(controlling.addressing(), (0xFFFF, 3));

    let controlled = ClockSynchronisation::controlled(CA, 7);
    assert_eq!(controlled.role(), Role::Controlled);
    assert_eq!(controlled.addressing(), (CA, 7));

    // The originator travels with the frame, and the instance's addressing is
    // what every frame it builds carries.
    let asdu = controlled.answer(worked()).expect("the answering role");
    assert_eq!(header_of(&asdu).originator, 7);
    assert_eq!(header_of(&asdu).common_address, CA);
}

// ------------------------------------- clause 7.6: the time tag's invalid mark
//
// 5-104 cl.7.6 (PDF page index 66, printed page 65), verbatim: "Controlled
// stations expect the reception of clock synchronization messages within agreed
// time intervals. When the synchronization command does not arrive within this
// time interval, the controlled station sets all time-tagged information objects
// with a mark that the time tag may be inaccurate (invalid). This mark is also
// set after station initializiation (warm and cold boot) of controlled stations
// before reception of a valid C_CS ACT PDU. Time-tagged events that occur after
// the reception of valid C_CS ACT PDU are transmitted without the mark."
//
// The mark is the IV bit: 5-101 cl.7.2.6.18 (PDF page index 52, printed 51)
// lists CP56Time2a's fields as "milliseconds,minutes,RES1,invalid,...", so the
// third octet is the six minute bits, then RES1 (bit 7), then IV (bit 8). The
// worked example's third octet 0x10 (16 minutes) therefore reads 0x90 with
// the mark, and CP24Time2a (cl.7.2.6.19, "milliseconds,minutes, RES1,invalid")
// carries the same octet.

/// The agreed interval of these tests. Clause 7.6 leaves its value to
/// agreement; one hour is an arbitrary choice.
const AGREED: Duration = Duration::from_secs(3600);

/// A controlled station's outcome for the valid request of these tests.
fn accepted_request() -> iec104::cs::Outcome {
    let frame = request(worked(), CA, 0).expect("the layout builds it");
    ClockSynchronisation::controlled(CA, 0)
        .on_request(&frame, &Known::EVERYTHING, worked())
        .expect("a valid activation")
}

/// The seven octets `time` encodes to.
fn octets(time: Cp56Time2a) -> Vec<u8> {
    let mut out = Vec::new();
    time.encode(&mut out);
    out
}

/// Clause 7.6: "This mark is also set after station initializiation ... before
/// reception of a valid `C_CS` ACT PDU." A new record is the state after a boot.
#[test]
fn every_time_tag_is_marked_invalid_before_the_first_synchronisation() {
    let boot = Instant::now();
    let validity = TimeValidity::new(AGREED);
    assert_eq!(validity.last_synchronised(), None);
    assert!(!validity.time_valid(boot));
    assert!(!validity.time_valid(boot + Duration::from_secs(10 * 3600)));

    let marked = validity.mark(worked(), boot);
    assert_eq!(
        octets(marked),
        [0x55, 0x69, 0x90, 0x0D, 0x13, 0x01, 0x01],
        "cl.7.2.6.18: IV is bit 8 of the minutes octet"
    );
    let short = Cp24Time2a {
        milliseconds: 26_965,
        minutes: 16,
        ..Cp24Time2a::default()
    };
    let mut out = Vec::new();
    validity.mark_short(short, boot).encode(&mut out);
    assert_eq!(out, [0x55, 0x69, 0x90], "cl.7.2.6.19: the same octet");
}

/// Clause 7.6: "Time-tagged events that occur after the reception of valid
/// `C_CS` ACT PDU are transmitted without the mark."
#[test]
fn a_positive_synchronisation_clears_the_mark() {
    let boot = Instant::now();
    let synced = boot + Duration::from_secs(30);
    let mut validity = TimeValidity::new(AGREED);

    let outcome = accepted_request();
    assert!(matches!(outcome.reaction, Reaction::Requested { .. }));
    assert!(validity.on_outcome(&outcome, synced), "a valid C_CS ACT");
    assert_eq!(validity.last_synchronised(), Some(synced));

    assert!(validity.time_valid(synced));
    assert_eq!(octets(validity.mark(worked(), synced)), WORKED_OCTETS);
    assert!(
        validity.time_valid(synced + Duration::from_secs(1)),
        "an event right after the synchronisation"
    );

    // The record only sets the mark: a tag the application marked stays so.
    let already = Cp56Time2a {
        invalid: true,
        ..worked()
    };
    assert!(validity.mark(already, synced).invalid);
}

/// Clause 7.6: "When the synchronization command does not arrive within this
/// time interval, the controlled station sets all time-tagged information
/// objects with a mark". The next valid `C_CS` ACT clears it again.
#[test]
fn the_mark_returns_once_the_agreed_interval_passes_without_a_synchronisation() {
    let boot = Instant::now();
    let synced = boot + Duration::from_secs(30);
    let mut validity = TimeValidity::new(AGREED);
    validity.synchronised(synced);

    let just_within = (synced + AGREED)
        .checked_sub(Duration::from_millis(1))
        .unwrap();
    assert!(validity.time_valid(just_within));
    assert!(!validity.mark(worked(), just_within).invalid);

    let overdue = synced + AGREED;
    assert!(!validity.time_valid(overdue));
    assert!(validity.mark(worked(), overdue).invalid);
    assert!(!validity.time_valid(overdue + AGREED));

    // A synchronisation that arrives late clears the mark from then on.
    let resynced = overdue + Duration::from_secs(60);
    assert!(validity.on_outcome(&accepted_request(), resynced));
    assert!(validity.time_valid(resynced));
    assert!(!validity.time_valid(resynced + AGREED));
}

/// Clause 7.6 clears the mark on "reception of valid `C_CS` ACT PDU" only. An
/// activation the station refused (the cl.7.2.3 mirror, 5-101 PDF page index
/// 38, printed 37), one with no time in it (cl.7.2.2's `N = 0`), a frame that
/// is not an activation, and an activation the station answered with
/// "<1> := negative confirm" (5-101 cl.7.2.3, bit 7 of the cause octet) leave
/// the time tags marked.
#[test]
fn a_refused_or_negative_synchronisation_does_not_count() {
    let boot = Instant::now();
    let now = boot + Duration::from_secs(30);
    let controlled = ClockSynchronisation::controlled(CA, 0);
    let frame = request(worked(), CA, 0).expect("the layout builds it");
    let mut validity = TimeValidity::new(AGREED);

    // Unknown type identification: mirrored with cause 44.
    let refused = controlled
        .on_request(&frame, &Known::NOTHING, worked())
        .expect("a whole ASDU");
    assert!(matches!(refused.reaction, Reaction::Refused { .. }));
    assert!(!validity.on_outcome(&refused, now));

    // Unknown common address: mirrored with cause 46.
    let foreign = Known {
        type_id: true,
        cause: true,
        common_address: false,
        information_object_address: true,
    };
    let refused = controlled
        .on_request(&frame, &foreign, worked())
        .expect("a whole ASDU");
    assert!(matches!(refused.reaction, Reaction::Refused { .. }));
    assert!(!validity.on_outcome(&refused, now));

    // No information object, so no time to adopt.
    let empty = handmade(Cause::Activation, worked(), CA, 0, false, false);
    let other = controlled
        .on_request(&empty, &Known::EVERYTHING, worked())
        .expect("a whole ASDU");
    assert_eq!(other.reaction, Reaction::Other);
    assert!(!validity.on_outcome(&other, now));

    // A confirmation arriving at the controlled station is not an activation.
    let confirmation = answer(worked(), CA, 0).expect("the layout builds it");
    let other = controlled
        .on_request(&confirmation, &Known::EVERYTHING, worked())
        .expect("a whole ASDU");
    assert_eq!(other.reaction, Reaction::Other);
    assert!(!validity.on_outcome(&other, now));

    // The application declined the time and answers negatively.
    let mut declined = accepted_request();
    declined.send[0][2] |= 0x40;
    assert!(header_of(&declined.send[0]).negative);
    assert!(!validity.on_outcome(&declined, now));

    assert_eq!(validity.last_synchronised(), None);
    assert!(!validity.time_valid(now));
}

/// Clause 7.6: the mark "is also set after station initializiation (warm and
/// cold boot)", even when the station was synchronised before it.
#[test]
fn a_restart_marks_the_time_tags_again() {
    let boot = Instant::now();
    let mut validity = TimeValidity::new(AGREED);
    validity.synchronised(boot);
    assert!(validity.time_valid(boot + Duration::from_secs(1)));

    validity.restart();
    assert_eq!(validity.last_synchronised(), None);
    assert!(!validity.time_valid(boot + Duration::from_secs(1)));
    assert_eq!(validity, TimeValidity::new(AGREED));
}
