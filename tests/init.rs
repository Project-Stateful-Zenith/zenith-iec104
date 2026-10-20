//! Station initialisation: the controlled station's `M_EI_NA_1`
//! (type 70, cause `<4> initialized`, `COI`) and the controlling station's
//! reaction to it.
//!
//! The clause citations are 5-101 cl.7.3.3.1 (the layout and its one cause,
//! PDF page index 104), cl.7.2.6.21 (`COI`'s bits, page index 53) and cl.7.4
//! with Table 16 (all application functions available after initialization, and
//! type 70 first in the controlled station's send order, page index 121);
//! 5-104 cl.7.1 (page indices 53–56) is the TCP-level half and defines no ASDU.
//!
//! These tests hold the frame to its ten octets, the `COI` flag to bit 8, the
//! reception decision to clause 7.2.3's order, and the follow-up step to a
//! value.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::expect_used)]

use iec104::asdu::{
    Cause, Coi, Discard, Header, IOA_IRRELEVANT, Known, LayoutError, TypeId, Unspecified,
    decode_asdu,
};
use iec104::init::{CAUSE, FollowUp, Reaction, TYPE_ID, end_of_initialisation, on_asdu};

/// The frame the controlled station sends, from a known `COI`.
fn frame(coi: Coi) -> Vec<u8> {
    end_of_initialisation(coi, 12, 0).expect("the builder's own failure modes cannot occur")
}

/// A remote reset with the local parameters unchanged.
const fn coi() -> Coi {
    Coi {
        cause: Coi::REMOTE_RESET,
        changed_local_parameters: false,
    }
}

/// The ten octets, one field at a time: type 70, VSQ `0x01` (SQ = 0, N = 1),
/// COT 4 with P/N = 0 and T = 0, originator, CA little-endian, IOA zero
/// (5-101 cl.7.3.3.1's `INFORMATION OBJECT ADDRESS = 0`), then the COI octet.
#[test]
fn the_end_of_initialisation_has_its_ten_octets() {
    let asdu = frame(coi());

    assert_eq!(asdu.len(), Header::LEN + 3 + Coi::LEN, "header, IOA, COI");
    assert_eq!(asdu[0], TYPE_ID.to_u8());
    assert_eq!(asdu[0], TypeId::MEiNa1.to_u8(), "type 70, one copy");
    assert_eq!(asdu[0], 70);
    assert_eq!(asdu[1], 0x01, "SQ = 0, N = 1");
    assert_eq!(asdu[2], CAUSE.to_u8());
    assert_eq!(asdu[2], Cause::Initialized.to_u8());
    assert_eq!(asdu[2] & 0xC0, 0, "P/N = 0 and T = 0");
    assert_eq!(asdu[3], 0x00, "the default originator address");
    assert_eq!(&asdu[4..6], &12u16.to_le_bytes(), "CA little-endian");
    assert_eq!(
        &asdu[6..9],
        &[0x00, 0x00, 0x00],
        "IOA = 0, it is irrelevant"
    );
    assert_eq!(asdu[9], coi().raw());

    // The originator address is the caller's: 5-101 cl.7.2.3's page index 38
    // rule is that a controlled station echoes it, and a controlling station
    // sets it when it commands.
    let asdu = end_of_initialisation(coi(), 0x1234, 7).expect("frame");
    let header = Header::parse(&asdu).expect("header");
    assert_eq!(header.originator, 7);
    assert_eq!(header.common_address, 0x1234);
}

/// And it reads back as the same values, through the `M_EI_NA_1` layout of
/// `iec104::asdu`.
#[test]
fn the_frame_decodes_to_the_values_it_was_built_from() {
    for changed in [false, true] {
        for cause in [
            Coi::LOCAL_POWER_ON,
            Coi::LOCAL_MANUAL_RESET,
            Coi::REMOTE_RESET,
        ] {
            let coi = Coi {
                cause,
                changed_local_parameters: changed,
            };
            let asdu = frame(coi);

            let header = Header::parse(&asdu).expect("header");
            assert_eq!(header.type_id, TypeId::MEiNa1);
            assert!(!header.sequence, "single information object (SQ = 0)");
            assert_eq!(header.count, 1);
            assert_eq!(header.cause, Cause::Initialized);
            assert!(!header.negative);
            assert!(!header.test);
            assert_eq!(header.common_address, 12);

            let objects = decode_asdu::<iec104::asdu::MEiNa1>(&asdu).expect("decodes");
            assert_eq!(objects.len(), 1);
            assert_eq!(objects[0].ioa, IOA_IRRELEVANT);
            assert_eq!(objects[0].value.coi, coi);

            // And the reception path agrees with the codec.
            assert_eq!(
                on_asdu(&asdu, &Known::EVERYTHING),
                Ok(Reaction::EndOfInitialisation(coi))
            );
        }
    }
}

/// `COI`'s flag is bit 8 of its own octet, not a high bit of the cause: the
/// seven-bit cause cannot spill into it, and `127`, the top of the standard's
/// `<32..127>` private range, still fits (5-101 cl.7.2.6.21).
#[test]
fn the_coi_flag_is_the_high_bit_of_its_own_octet() {
    let plain = Coi {
        cause: Coi::LOCAL_MANUAL_RESET,
        changed_local_parameters: false,
    };
    let changed = Coi {
        cause: Coi::LOCAL_MANUAL_RESET,
        changed_local_parameters: true,
    };
    assert_eq!(frame(plain)[9], 0x01);
    assert_eq!(frame(changed)[9], 0x81);
    assert_eq!(plain.raw() | 0x80, changed.raw());

    // `<32..127>` is the private range and stays inside seven bits.
    let private = Coi {
        cause: 127,
        changed_local_parameters: false,
    };
    assert_eq!(frame(private)[9], 0x7F);
    assert_eq!(
        Coi::from_raw(frame(private)[9]),
        private,
        "and it round-trips"
    );
}

/// Only cause 4 is listed for type 70, and the builder writes it, so a frame
/// outside the clause's own cause list cannot be built from this API. A type 70
/// ASDU arriving with another cause is simply not this procedure.
#[test]
fn a_type_70_asdu_with_another_cause_is_not_this_procedure() {
    let mut asdu = frame(coi());
    asdu[2] = Cause::Spontaneous.to_u8();
    assert_eq!(
        on_asdu(&asdu, &Known::EVERYTHING),
        Ok(Reaction::Other),
        "clause 7.3.3.1 lists <4> and nothing else for type 70"
    );

    // The same for a type that is not 70 at all.
    let mut other = frame(coi());
    other[0] = TypeId::CCsNa1.to_u8();
    assert_eq!(on_asdu(&other, &Known::EVERYTHING), Ok(Reaction::Other));

    // And the builder's cause is the clause's, not a parameter.
    assert_eq!(frame(coi())[2], 4);
}

/// Clause 7.2.3 runs first: an ASDU whose fields the station does not know is
/// discarded (and may be logged) whichever type it carries, and a mirror is
/// never treated as a request.
#[test]
fn the_discard_rule_runs_before_the_type_is_examined() {
    let asdu = frame(coi());

    assert_eq!(
        on_asdu(&asdu, &Known::NOTHING),
        Ok(Reaction::Discard(Discard::Unspecified(
            Unspecified::TypeIdentification
        )))
    );

    let mut known = Known::EVERYTHING;
    known.information_object_address = false;
    assert_eq!(
        on_asdu(&asdu, &known),
        Ok(Reaction::Discard(Discard::Unspecified(
            Unspecified::InformationObjectAddress
        )))
    );

    // A mirrored ASDU (P/N = 1, cause 44–47) is the clause's third log bullet,
    // and a station that knows every field still does not mirror it back.
    let mut mirrored = asdu;
    mirrored[2] = Cause::UnknownTypeId.to_u8() | 0x40;
    assert_eq!(
        on_asdu(&mirrored, &Known::EVERYTHING),
        Ok(Reaction::Discard(Discard::Mirror))
    );
}

/// The follow-up step is a value with a name, because general interrogation
/// (`iec104::gi`) owns the request and redundancy (`iec104::redundancy`) owns
/// which connection acts in a redundancy group.
#[test]
fn the_controlling_stations_next_step_is_a_value() {
    let reaction = on_asdu(&frame(coi()), &Known::EVERYTHING).expect("reaction");
    assert_eq!(
        reaction.follow_up(),
        Some(FollowUp::StationInterrogation),
        "5-101 cl.7.4: all application functions are available afterwards"
    );

    assert_eq!(Reaction::Other.follow_up(), None);
    assert_eq!(Reaction::Discard(Discard::Mirror).follow_up(), None);
}

/// A malformed or unfitting ASDU is a typed error, never a panic: the header
/// must be there, and the layout's own rules still apply to the object count.
#[test]
fn a_malformed_frame_is_a_typed_error() {
    for len in 0..Header::LEN {
        let short = vec![0u8; len];
        assert!(matches!(
            on_asdu(&short, &Known::EVERYTHING),
            Err(LayoutError::Asdu(_))
        ));
    }

    // N = 2 for a type whose figure says "Single information object (SQ = 0)".
    let mut asdu = frame(coi());
    asdu[1] = 0x02;
    assert_eq!(
        on_asdu(&asdu, &Known::EVERYTHING),
        Err(LayoutError::ObjectCountNotAllowed {
            type_id: TypeId::MEiNa1,
            count: 2
        })
    );

    // SQ = 1, which type 70's definition line does not allow (it has no
    // `j(...)` sequence form).
    let mut asdu = frame(coi());
    asdu[1] = 0x81;
    assert_eq!(
        on_asdu(&asdu, &Known::EVERYTHING),
        Err(LayoutError::SequenceNotAllowed {
            type_id: TypeId::MEiNa1
        })
    );
}

/// The end of initialisation is data in the monitor direction, so it goes
/// through the session's pending queue and out behind the STARTDT con. This is
/// the crate's own statement of 5-104 clause 5.3's rule that, once the
/// controlled station has initialised, a STARTDT must always come before any
/// data exchange starts.
#[test]
fn the_frame_is_data_the_session_queues_until_started() {
    use iec104::link::{Role, Session};

    let asdu = frame(coi());

    let mut controlled = Session::new(Role::Controlled);
    controlled.on_connection_established();
    assert!(
        !controlled.user_data_allowed(),
        "STOPDT is the default state"
    );
    controlled
        .queue_i_frame(&asdu)
        .expect("queued, not dropped");
    assert_eq!(controlled.pending_user_data(), 1);

    let mut controlling = Session::new(Role::Controlling);
    controlling.on_connection_established();
    controlling.on_frame(iec104::apci::Apci::U(iec104::apci::UFunction::StartDtAct));
    // The controlled station answers STARTDT act with the con and then releases
    // the queue, which is where the end of initialisation goes out.
    let actions = controlled.on_frame(iec104::apci::Apci::U(iec104::apci::UFunction::StartDtAct));
    assert!(controlled.user_data_allowed());
    let sent = actions
        .iter()
        .find_map(|action| match action {
            iec104::link::Action::SendI { asdu, .. } => Some(asdu.clone()),
            _ => None,
        })
        .expect("the queued end of initialisation goes out behind the con");
    assert_eq!(sent, asdu, "and it is the same octets");
}
