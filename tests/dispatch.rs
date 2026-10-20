//! `dispatch::route` names one owner per ASDU, and `not_implemented` is the
//! single answer for a type no procedure serves.

use iec104::asdu::{AddressSizes, CATALOGUE, Cause, Direction, Header, TypeId};
use iec104::dispatch::{Route, not_implemented, route};

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

/// Every control-direction type 104 defines has an owner or is answered as
/// not implemented; none is silently discarded.
#[test]
fn every_control_type_has_an_owner_or_is_refused() {
    for info in CATALOGUE {
        let type_id = TypeId::from_u8(info.id);
        if type_id.direction() != Some(Direction::Control) {
            continue;
        }
        let owner = route(&header(type_id, Cause::Activation));
        assert_ne!(owner, Route::Discard, "{}", type_id.name());
    }
}

#[test]
fn the_control_types_go_to_their_procedures() {
    for (type_id, owner) in [
        (TypeId::CScNa1, Route::Command),
        (TypeId::CSeTc1, Route::Command),
        (TypeId::CIcNa1, Route::Interrogation),
        (TypeId::CCiNa1, Route::CounterInterrogation),
        (TypeId::CRdNa1, Route::Read),
        (TypeId::CCsNa1, Route::ClockSync),
        (TypeId::CTsTa1, Route::Test),
        (TypeId::PMeNb1, Route::Parameter),
        (TypeId::PAcNa1, Route::Parameter),
        (TypeId::FScNa1, Route::FileTransfer),
        (TypeId::MEiNa1, Route::Init),
        (TypeId::CRpNa1, Route::NotImplemented),
    ] {
        assert_eq!(
            route(&header(type_id, Cause::Activation)),
            owner,
            "{}",
            type_id.name()
        );
    }
    // Their confirmations and mirrors go to the same place.
    assert_eq!(
        route(&header(TypeId::CIcNa1, Cause::ActivationTermination)),
        Route::Interrogation
    );
    assert_eq!(
        route(&header(TypeId::CScNa1, Cause::UnknownCommonAddress)),
        Route::Command
    );
}

#[test]
fn monitor_data_goes_where_its_cause_says() {
    let spontaneous = |type_id| route(&header(type_id, Cause::Spontaneous));
    assert_eq!(spontaneous(TypeId::MSpTb1), Route::Transmission);
    assert_eq!(spontaneous(TypeId::MItTb1), Route::Transmission);
    for (cause, owner) in [
        (Cause::Periodic, Route::Transmission),
        (Cause::BackgroundScan, Route::Transmission),
        (Cause::InterrogatedByGroup(3), Route::Interrogation),
        (
            Cause::RequestedByCounterGroup(2),
            Route::CounterInterrogation,
        ),
        (Cause::Request, Route::Read),
        (Cause::ReturnInfoLocal, Route::Command),
        (Cause::Activation, Route::Discard),
    ] {
        assert_eq!(route(&header(TypeId::MMeNa1, cause)), owner, "{cause:?}");
    }
    // A parameter reported by an interrogation is the interrogation's.
    assert_eq!(
        route(&header(TypeId::PMeNa1, Cause::InterrogatedByStation)),
        Route::Interrogation
    );
}

/// One mirror, with cause 44 and the station's own address, for a control
/// type no procedure serves; nothing for a mirror or for monitor data.
#[test]
fn not_implemented_is_one_cause_44_mirror() {
    let sizes = AddressSizes::CONVENTIONAL;
    let reset = header(TypeId::CRpNa1, Cause::Activation);
    let mut asdu = Vec::new();
    reset.encode(&mut asdu).expect("the header encodes");
    asdu.extend_from_slice(&[0, 0, 0, 1]); // IOA 0, QRP 1
    let mirror = not_implemented(&reset, &asdu, 7, sizes).expect("answered");
    let answer = Header::parse(&mirror).unwrap();
    assert_eq!(answer.cause, Cause::UnknownTypeId);
    assert!(answer.negative);
    assert_eq!(answer.common_address, 7);
    assert_eq!(&mirror[Header::LEN..], &asdu[Header::LEN..]);

    assert_eq!(
        not_implemented(&answer, &mirror, 7, sizes),
        None,
        "never mirror a mirror"
    );
    let monitor = header(TypeId::MSpNa1, Cause::Spontaneous);
    assert_eq!(not_implemented(&monitor, &asdu, 7, sizes), None);
}
