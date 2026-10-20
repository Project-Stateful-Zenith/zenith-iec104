//! Command transmission (`iec104::ct`): the seven command families of 5-101 clause
//! 7.3.2 and their 5-104 twins, the `S/E` bit, the mirrored confirmation, the
//! select's deactivation, the termination and the return information.
//!
//! The clause citations are 5-104 cl.7.7 (the service table, PDF page index 68),
//! cl.8.1–8.7 (the seven time-tagged layouts, page indices 76–88), cl.9 ("Either
//! the ASDUs of the set `<45>` – `<51>` or of the set `<58>` – `<64>` are used.",
//! page index 102) and Table 2 (the mirror NOTEs, page index 50); 5-101 cl.7.3.2
//! with figures 64–70 (the per-type cause lists, page indices 99–103), cl.7.4.7
//! (which procedures are used, page index 126), cl.7.2.3 (line 30) and
//! cl.7.2.6.26 (`QOC`, page index 55); and TS 60870-5-604 Table 19
//! (PDF page indices 70–76) for the whole negative-path model.
//!
//! The second half drives the two roles against each other, so every assertion
//! is about a frame one role sent and the other classified. The scripted
//! exchange is the acceptance test.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use std::time::{Duration, Instant};

use iec104::asdu::{
    AsduLayout, Bsi, Cause, CommandQualifier, Cp56Time2a, Dco, Diq, Discard, DoubleCommandState,
    DoublePointState, Header, Known, LayoutObject, MDpNa1, MDpTb1, MMeNa1, MMeNb1, MSpNa1, MSpTb1,
    MStNa1, MStTb1, Nva, Qds, Qoc, Qos, R32, Rco, RegulatingStepState, Sco, Siq, Sva, TypeId,
    Unspecified, Vti, decode_asdu, encode_asdu,
};
use iec104::ct::{
    CAUSE_ACTIVATION_CON, CAUSE_ACTIVATION_TERM, CAUSE_DEACTIVATION, CAUSE_DEACTIVATION_CON,
    Command, CommandMode, CommandSet, CommandTransmission, CommandValue, CtError, Family, Outcome,
    RETURN_TYPES, Reaction, ReturnInfo, Role, Termination, activation, confirmation, deactivation,
    deactivation_confirmation, is_command_type, is_return_type, monitored_types,
    return_information, termination,
};

/// The broadcast common address of the conventional two-octet profile.
const BROADCAST_CA: u16 = iec104::asdu::AddressSizes::CONVENTIONAL.broadcast_common_address();

const CA: u16 = 12;
const ORG: u8 = 7;

// ---------------------------------------------------------------- helpers

/// The cause of a frame, parsed out of its header.
fn cause_of(frame: &[u8]) -> Cause {
    Header::parse(frame).expect("a built frame parses").cause
}

/// The header of a built frame.
fn header_of(frame: &[u8]) -> Header {
    Header::parse(frame).expect("a built frame parses")
}

/// An untagged single command: `SCS` as given, `QU = 1`, `S/E` as given.
const fn single(ioa: u32, scs: bool, select: bool) -> Command {
    Command::new(
        ioa,
        CommandValue::Single {
            sco: Sco {
                scs,
                qoc: Qoc { qu: 1, select },
            },
        },
    )
}

/// An untagged double command with the state as given.
const fn double(ioa: u32, dcs: DoubleCommandState, select: bool) -> Command {
    Command::new(
        ioa,
        CommandValue::Double {
            dco: Dco {
                dcs,
                qoc: Qoc { qu: 2, select },
            },
        },
    )
}

/// An untagged regulating step command with the state as given.
const fn step(ioa: u32, rcs: RegulatingStepState, select: bool) -> Command {
    Command::new(
        ioa,
        CommandValue::RegulatingStep {
            rco: Rco {
                rcs,
                qoc: Qoc { qu: 0, select },
            },
        },
    )
}

/// An untagged normalized set-point command.
const fn normalized(ioa: u32, value: i16, select: bool) -> Command {
    Command::new(
        ioa,
        CommandValue::SetPointNormalized {
            nva: Nva { value },
            qos: Qos { ql: 0, select },
        },
    )
}

/// A time tag with recognisable, valid field values.
fn time() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 1234,
        minutes: 30,
        hours: 12,
        day_of_month: 4,
        day_of_week: 3,
        months: 6,
        years: 26,
        ..Default::default()
    }
}

/// One command per family, untagged, all with `S/E = 0`.
fn every_family() -> Vec<Command> {
    let mut commands = vec![
        single(0x1001, true, false),
        double(0x1002, DoubleCommandState::On, false),
        step(0x1003, RegulatingStepState::Higher, false),
        normalized(0x1004, 0x1234, false),
        Command::new(
            0x1005,
            CommandValue::SetPointScaled {
                sva: Sva { value: -5 },
                qos: Qos {
                    ql: 1,
                    select: false,
                },
            },
        ),
        Command::new(
            0x1006,
            CommandValue::SetPointFloat {
                r32: R32 { value: 1.5 },
                qos: Qos {
                    ql: 2,
                    select: false,
                },
            },
        ),
        Command::new(
            0x1007,
            CommandValue::Bitstring {
                bsi: Bsi { bits: 0xDEAD_BEEF },
            },
        ),
    ];
    commands.push(single(0x1008, false, false));
    commands
}

/// A single-point information ASDU for a return information.
fn returned(ioa: u32, info: ReturnInfo) -> Vec<u8> {
    return_information(
        ioa,
        MSpNa1 {
            siq: Siq {
                spi: true,
                ..Default::default()
            },
        },
        info,
        CA,
        ORG,
    )
    .expect("M_SP_NA_1 is a return type")
}

// ------------------------------------------------- the layout and the causes

#[test]
fn every_family_maps_to_its_two_type_identifications() {
    // 5-101 clause 7.3.2's figures 64–70 and 5-104 clause 8's figures 23–29.
    let expected = [
        (Family::Single, 45u8, 58u8),
        (Family::Double, 46, 59),
        (Family::RegulatingStep, 47, 60),
        (Family::SetPointNormalized, 48, 61),
        (Family::SetPointScaled, 49, 62),
        (Family::SetPointFloat, 50, 63),
        (Family::Bitstring, 51, 64),
    ];
    assert_eq!(Family::ALL.len(), 7);
    for (family, untagged, tagged) in expected {
        assert_eq!(family.untagged().to_u8(), untagged);
        assert_eq!(family.tagged().to_u8(), tagged);
        assert_eq!(family.type_id(CommandSet::Untagged), family.untagged());
        assert_eq!(family.type_id(CommandSet::Tagged), family.tagged());
        assert_eq!(
            Family::of_type(family.untagged()),
            Some((family, CommandSet::Untagged))
        );
        assert_eq!(
            Family::of_type(family.tagged()),
            Some((family, CommandSet::Tagged))
        );
        assert!(is_command_type(family.untagged()));
        assert!(is_command_type(family.tagged()));
        assert_ne!(family.name(), "");
    }
    // The untagged set is 45–51, the tagged one 58–64, and nothing is in both.
    for raw in 0..=255u8 {
        let type_id = TypeId::from_u8(raw);
        let untagged = CommandSet::Untagged.contains(type_id);
        let tagged = CommandSet::Tagged.contains(type_id);
        assert!(!(untagged && tagged), "type {raw} is in both sets");
        assert_eq!(untagged || tagged, is_command_type(type_id));
        if untagged {
            assert!((45..=51).contains(&raw), "type {raw} is not in <45>–<51>");
        }
        if tagged {
            assert!((58..=64).contains(&raw), "type {raw} is not in <58>–<64>");
        }
    }
}

#[test]
fn the_five_causes_are_the_clauses() {
    // Figure 64's control-direction list: <6> activation, <8> deactivation;
    // monitor direction: <7>, <9>, <10>.
    assert_eq!(iec104::ct::CAUSE_ACTIVATION.to_u8(), 6);
    assert_eq!(iec104::ct::CAUSE_ACTIVATION.mnemonic(), "act");
    assert_eq!(CAUSE_ACTIVATION_CON.to_u8(), 7);
    assert_eq!(CAUSE_ACTIVATION_CON.mnemonic(), "actcon");
    assert_eq!(CAUSE_DEACTIVATION.to_u8(), 8);
    assert_eq!(CAUSE_DEACTIVATION.mnemonic(), "deact");
    assert_eq!(CAUSE_DEACTIVATION_CON.to_u8(), 9);
    assert_eq!(CAUSE_DEACTIVATION_CON.mnemonic(), "deactcon");
    assert_eq!(CAUSE_ACTIVATION_TERM.to_u8(), 10);
    assert_eq!(CAUSE_ACTIVATION_TERM.mnemonic(), "actterm");
}

// ------------------------------------------------------------- the activation

#[test]
fn activation_writes_cause_6_into_the_familys_element_layout() {
    // 5-101 figures 64–70: 6 header + 3 address + the family's element.
    let widths = [
        (single(0x1001, true, false), 1usize),
        (double(0x1002, DoubleCommandState::On, false), 1),
        (step(0x1003, RegulatingStepState::Higher, false), 1),
        (normalized(0x1004, 1, false), 3),
        (
            Command::new(
                0x1005,
                CommandValue::SetPointScaled {
                    sva: Sva { value: 1 },
                    qos: Qos {
                        ql: 0,
                        select: false,
                    },
                },
            ),
            3,
        ),
        (
            Command::new(
                0x1006,
                CommandValue::SetPointFloat {
                    r32: R32 { value: 1.0 },
                    qos: Qos {
                        ql: 0,
                        select: false,
                    },
                },
            ),
            5,
        ),
        (
            Command::new(
                0x1007,
                CommandValue::Bitstring {
                    bsi: Bsi { bits: 0 },
                },
            ),
            4,
        ),
    ];
    for (command, element_len) in widths {
        let frame = activation(&command, CA, ORG).expect("a defined command state builds");
        let header = header_of(&frame);
        assert_eq!(header.type_id, command.type_id());
        assert_eq!(header.cause, Cause::Activation);
        assert!(!header.negative, "an activation is P/N = 0");
        assert_eq!(header.count, 1);
        assert!(!header.sequence, "SQ = 0: one object per ASDU");
        assert_eq!(header.common_address, CA);
        assert_eq!(header.originator, ORG);
        assert_eq!(frame.len(), Header::LEN + 3 + element_len);
        // The information object address travels as UI24, little endian.
        assert_eq!(
            u32::from_le_bytes([frame[6], frame[7], frame[8], 0]),
            command.ioa
        );
    }
}

#[test]
fn the_tagged_set_is_the_untagged_body_plus_seven_octets() {
    // 5-104 cl.8.1: C_SC_TA_1 := CP{…, SCO, CP56Time2a}, 6 + 3 + 1 + 7 = 17.
    let untagged = single(0x1001, true, false);
    let tagged = Command::tagged(0x1001, untagged.value, time());
    let plain = activation(&untagged, CA, ORG).unwrap();
    let stamped = activation(&tagged, CA, ORG).unwrap();

    assert_eq!(plain.len(), 10);
    assert_eq!(stamped.len(), 17);
    assert_eq!(cause_of(&stamped), Cause::Activation);
    assert_eq!(header_of(&stamped).type_id, TypeId::CScTa1);
    assert_eq!(
        &stamped[1..10],
        &plain[1..10],
        "same VSQ, cause, addressing and object — only the type identification differs"
    );
    assert_eq!(
        decode_asdu::<iec104::asdu::CScTa1>(&stamped).unwrap()[0]
            .value
            .time,
        time()
    );
    assert_eq!(tagged.set(), CommandSet::Tagged);
    assert_eq!(untagged.set(), CommandSet::Untagged);
}

// ---------------------------------------------------- the mirror, positive

#[test]
fn the_confirmation_is_the_command_asdu_with_only_its_header_changed() {
    // 5-104 Table 2's NOTE and 5-101 cl.7.2.3: the reply is the ASDU mirrored.
    let command = normalized(0x2000, 0x1234, false);
    let act = activation(&command, CA, ORG).unwrap();
    let actcon = confirmation(&command, false, CA, ORG, false).unwrap();

    assert_eq!(actcon[0], act[0], "type identification");
    assert_eq!(actcon[1], act[1], "VSQ");
    assert_eq!(actcon[2], 7, "cause <7> actcon");
    assert_eq!(
        actcon[3], act[3],
        "the common address and the originator echo"
    );
    assert_eq!(&actcon[6..], &act[6..], "the object is the command's own");
    assert!(!header_of(&actcon).negative);
    assert_eq!(
        decode_asdu::<iec104::asdu::CSeNa1>(&actcon).unwrap()[0]
            .value
            .nva
            .value,
        0x1234
    );
}

#[test]
fn the_negative_confirmation_sets_only_the_pn_flag() {
    let command = single(0x2000, true, false);
    let positive = confirmation(&command, false, CA, ORG, false).unwrap();
    let negative = confirmation(&command, true, CA, ORG, false).unwrap();
    assert!(!header_of(&positive).negative);
    assert!(header_of(&negative).negative);
    assert_eq!(header_of(&negative).cause, Cause::ActivationCon);
    assert_eq!(&positive[6..], &negative[6..]);
    assert_eq!(&negative[..2], &positive[..2]);
}

#[test]
fn a_tagged_command_is_mirrored_with_its_time_tag() {
    let command = Command::tagged(0x2000, single(1, true, false).value, time());
    let sent = activation(&command, CA, ORG).unwrap();
    let mirror = confirmation(&command, false, CA, ORG, false).unwrap();
    assert_eq!(mirror.len(), 17);
    assert_eq!(&mirror[..2], &sent[..2], "same type and VSQ");
    assert_eq!(&mirror[10..], &sent[10..], "the time tag is mirrored too");
}

// ------------------------------------------------------ the return information

#[test]
fn the_return_information_carries_a_monitor_type_and_the_clauses_cause() {
    // 5-104 cl.7.7's A_RETURN_INF row: M_SP, M_DP, M_ST. The cause is 11
    // (remote), 12 (local) or 3 (spontaneous) per TS 604 Table 19.
    for (info, cause) in [
        (ReturnInfo::Remote, 11u8),
        (ReturnInfo::Local, 12),
        (ReturnInfo::Spontaneous, 3),
    ] {
        let frame = returned(0x3000, info);
        let header = header_of(&frame);
        assert_eq!(header.type_id, TypeId::MSpNa1);
        assert_eq!(header.cause.to_u8(), cause);
        assert!(!header.negative);
        assert_eq!(header.count, 1);
        assert_eq!(frame.len(), Header::LEN + 3 + 1);
        assert_eq!(return_decode(&frame), (0x3000, true));
        assert_eq!(ReturnInfo::from_cause(header.cause), Some(info));
        assert_eq!(info.cause().to_u8(), cause);
        assert_eq!(info.mnemonic(), header.cause.mnemonic());
    }
    assert_eq!(ReturnInfo::from_cause(Cause::ActivationCon), None);
}

/// The information object address and the single-point state of a built
/// `M_SP_NA_1` return information.
fn return_decode(frame: &[u8]) -> (u32, bool) {
    let object = &decode_asdu::<MSpNa1>(frame).expect("M_SP_NA_1 decodes")[0];
    (object.ioa, object.value.siq.spi)
}

#[test]
fn every_return_type_of_the_six_builds() {
    assert_eq!(RETURN_TYPES.len(), 6);
    for type_id in RETURN_TYPES {
        assert!(is_return_type(type_id));
        assert!(
            type_id.is_selected_104(),
            "{type_id:?} is in the 104 selection"
        );
    }
    // The unselected CP24Time2a twins of M_SP/M_DP/M_ST are not return types
    // here: 5-104 clause 6 does not select them.
    for raw in [2u8, 4, 6] {
        assert!(!is_return_type(TypeId::from_u8(raw)));
    }
    // And neither is anything else.
    for raw in 0..=255u8 {
        let type_id = TypeId::from_u8(raw);
        if is_return_type(type_id) {
            assert!(RETURN_TYPES.contains(&type_id));
        }
    }
}

#[test]
fn a_return_information_of_another_type_is_refused() {
    let err = return_information(
        0x3000,
        MMeNa1 {
            nva: Nva { value: 1 },
            qds: Qds::default(),
        },
        ReturnInfo::Remote,
        CA,
        ORG,
    )
    .unwrap_err();
    assert_eq!(
        err,
        CtError::NotReturnType {
            type_id: TypeId::MMeNa1
        }
    );
    assert_eq!(
        return_information(
            0x3000,
            MMeNb1 {
                sva: Sva { value: 1 },
                qds: Qds::default(),
            },
            ReturnInfo::Local,
            CA,
            ORG,
        )
        .unwrap_err(),
        CtError::NotReturnType {
            type_id: TypeId::MMeNb1
        }
    );
}

#[test]
fn every_return_layout_round_trips() {
    let single = return_information(
        0x0101,
        MSpNa1 {
            siq: Siq {
                spi: true,
                ..Default::default()
            },
        },
        ReturnInfo::Remote,
        CA,
        ORG,
    )
    .unwrap();
    let double = return_information(
        0x0102,
        MDpNa1 {
            diq: Diq {
                dpi: DoublePointState::On,
                blocked: false,
                substituted: false,
                not_topical: false,
                invalid: false,
            },
        },
        ReturnInfo::Remote,
        CA,
        ORG,
    )
    .unwrap();
    let step = return_information(
        0x0103,
        MStNa1 {
            vti: Vti {
                value: 3,
                transient: false,
            },
            qds: Qds::default(),
        },
        ReturnInfo::Remote,
        CA,
        ORG,
    )
    .unwrap();
    assert_eq!(header_of(&single).type_id, TypeId::MSpNa1);
    assert_eq!(header_of(&double).type_id, TypeId::MDpNa1);
    assert_eq!(header_of(&step).type_id, TypeId::MStNa1);
    assert_eq!(
        decode_asdu::<MDpNa1>(&double).unwrap()[0].value.diq.dpi,
        DoublePointState::On
    );
    assert_eq!(decode_asdu::<MStNa1>(&step).unwrap()[0].value.vti.value, 3);

    // The CP56Time2a forms carry the time tag of their layout.
    let tagged = return_information(
        0x0104,
        MSpTb1 {
            siq: Siq::default(),
            time: time(),
        },
        ReturnInfo::Local,
        CA,
        ORG,
    )
    .unwrap();
    assert_eq!(header_of(&tagged).type_id, TypeId::MSpTb1);
    assert_eq!(header_of(&tagged).cause, Cause::ReturnInfoLocal);
    assert_eq!(
        decode_asdu::<MSpTb1>(&tagged).unwrap()[0].value.time,
        time()
    );
    let _ = MMeNa1 {
        nva: Nva { value: 0 },
        qds: Qds::default(),
    };
    let _ = (MDpTb1::TYPE_ID, MStTb1::TYPE_ID);
}

// ------------------------------------------------- the two command sets

#[test]
fn the_two_command_sets_are_not_mixed_toward_one_station() {
    // 5-104 cl.9 and Table 2: "Either the ASDUs of the set <45>-<51> or of the
    // set <58>-<64> are used ... must not be mixed when sending to a given
    // station."
    let mut untagged = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let tagged_frame = activation(
        &Command::tagged(0x1001, single(1, true, false).value, time()),
        CA,
        ORG,
    )
    .unwrap();
    // The controlled station answers the peer (cause-44 mirror) rather than
    // leaving it waiting, and tells its caller why.
    let outcome = untagged
        .on_request(&tagged_frame, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::WrongCommandSet {
            ioa: 0x1001,
            type_id: TypeId::CScTa1,
            set: CommandSet::Untagged,
        }
    );
    assert_eq!(outcome.send.len(), 1);
    let answer = header_of(&outcome.send[0]);
    assert_eq!(answer.cause, Cause::UnknownTypeId);
    assert!(answer.negative);
    assert_eq!(answer.type_id, TypeId::CScTa1);
    assert_eq!(&outcome.send[0][6..], &tagged_frame[6..]);
    assert_eq!(untagged.selected().len(), 0, "nothing changed");
    assert_eq!(untagged.running().len(), 0, "nothing changed");

    let mut tagged = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Tagged,
        Termination::All,
        CA,
        ORG,
    );
    let untagged_frame = activation(&single(0x1001, true, false), CA, ORG).unwrap();
    assert_eq!(
        tagged
            .on_response(&untagged_frame, &Known::EVERYTHING)
            .unwrap_err(),
        CtError::WrongCommandSet {
            type_id: TypeId::CScNa1,
            set: CommandSet::Tagged,
        }
    );
    assert_eq!(
        tagged.execute(&single(0x1001, true, false)).unwrap_err(),
        CtError::WrongCommandSet {
            type_id: TypeId::CScNa1,
            set: CommandSet::Tagged,
        },
        "a station on the tagged set does not put an untagged command on the wire"
    );
}

// ------------------------------------------------------------ select/execute

#[test]
fn select_and_execute_exchange_between_the_two_roles() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let command = single(0x3000, true, false);

    // A_SELECT.req: the S/E bit is the procedure's, written by the method.
    let select = controlling.select(&command).unwrap();
    assert_eq!(cause_of(&select), Cause::Activation);
    assert_eq!(select[9] & 0x80, 0x80, "S/E = 1");
    assert!(
        controlling.is_awaiting(0x3000),
        "sent, and not yet executable: the select is not confirmed"
    );
    assert!(!controlling.is_selected(0x3000));

    // A_SELECT.ind: the controlled station mirrors it and holds the select.
    let outcome = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: false,
            test: false
        }
    );
    assert_eq!(outcome.send.len(), 1);
    let actcon = &outcome.send[0];
    assert_eq!(cause_of(actcon), Cause::ActivationCon);
    assert_eq!(&actcon[..2], &select[..2], "same type and VSQ");
    assert_eq!(
        &actcon[6..],
        &select[6..],
        "the mirror repeats the object, S/E included"
    );
    assert!(controlled.is_selected(0x3000));
    assert!(!controlled.is_running(0x3000), "a select executes nothing");

    // A_SELECT.con: the controlling station records the confirmation.
    let outcome = controlling.on_response(actcon, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: false,
            test: false
        }
    );
    assert!(
        outcome.send.is_empty(),
        "a controlling station answers nothing"
    );
    assert!(
        controlling.is_selected(0x3000),
        "the positive ACTCON is what makes the select executable (5.4.19.1)"
    );
    assert!(!controlling.is_awaiting(0x3000));

    // A_EXCO.req: the same information, S/E = 0.
    let execute = controlling.execute(&command).unwrap();
    assert_eq!(cause_of(&execute), Cause::Activation);
    assert_eq!(execute[9] & 0x80, 0x00, "S/E = 0");
    assert_eq!(
        select[9] ^ execute[9],
        0x80,
        "select and execute differ in the S/E bit alone"
    );
    assert!(!controlling.is_selected(0x3000), "the select was consumed");
    assert!(
        controlling.is_running(0x3000),
        "the procedure may still terminate"
    );

    // A_EXCO.ind: the mirror again, and now the run is recorded.
    let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: false,
            test: false
        }
    );
    assert!(!controlled.is_selected(0x3000));
    assert!(controlled.is_running(0x3000));

    terminate_and_return(&mut controlling, &mut controlled, &execute);
}

/// The second half of the select and execute exchange: the termination of
/// the executed command and its return information, after which neither side
/// holds anything.
fn terminate_and_return(
    controlling: &mut CommandTransmission,
    controlled: &mut CommandTransmission,
    execute: &[u8],
) {
    // A_COTERM: the controlled station terminates the procedure.
    let actterm = controlled.terminate(0x3000, false).unwrap();
    assert_eq!(cause_of(&actterm), Cause::ActivationTermination);
    assert_eq!(
        &actterm[6..],
        &execute[6..],
        "the termination mirrors the execute"
    );
    assert!(!controlled.is_running(0x3000));

    // ... and the controlling station closes its own state on it.
    let outcome = controlling
        .on_response(&actterm, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Terminated {
            ioa: 0x3000,
            negative: false,
        }
    );
    assert!(!controlling.is_running(0x3000));

    // A_RETURN_INF: the object's own status, which crosses the procedure in
    // either order (TS 604 Table 19 allows it before or after the ACTTERM).
    let outcome = controlling
        .on_response(&returned(0x3000, ReturnInfo::Remote), &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Returned {
            ioa: 0x3000,
            info: ReturnInfo::Remote
        }
    );
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);

    // Neither side is left holding anything.
    assert_eq!(controlling.selected(), []);
    assert_eq!(controlling.running(), []);
    assert_eq!(controlled.selected(), []);
    assert_eq!(controlled.running(), []);
}

#[test]
fn direct_execute_needs_no_select() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let command = single(0x3000, true, false);

    let execute = controlling.execute(&command).unwrap();
    assert_eq!(execute[9] & 0x80, 0x00);
    assert_eq!(controlling.running().len(), 1);
    let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: false,
            test: false
        }
    );
    assert!(controlled.is_running(0x3000));
}

#[test]
fn a_second_execute_while_the_first_runs_is_refused() {
    // TS 604 5.4.19.20: the controlled station "mirrors the previous Command
    // message with COT=10 ... ACTTERM", one termination per execute, and
    // 5.4.19.50 answers a command the object cannot take with "COT=7,
    // C_SC/DC/SE/RC_ACTCONneg". An object still operating cannot take a
    // second command whose ACTTERM it could never send.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let on = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let off = activation(&single(0x3000, false, false), CA, ORG).unwrap();
    controlled.on_request(&on, &Known::EVERYTHING).unwrap();

    let outcome = controlled.on_request(&off, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: true,
            test: false
        }
    );
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");

    // The first execute still runs and is terminated with its own value.
    let term = controlled.terminate(0x3000, false).unwrap();
    assert_eq!(
        &term[6..],
        &termination(&single(0x3000, true, false), false, CA, ORG, false).unwrap()[6..]
    );
    assert!(!controlled.is_running(0x3000));
}

#[test]
fn a_station_without_the_select_procedure_refuses_a_select() {
    // 5-101 cl.7.4.7: "The select procedure is only used in case of a select
    // and execute function."
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let command = single(0x3000, true, false);
    assert_eq!(
        controlling.select(&command).unwrap_err(),
        CtError::SelectNotAllowed {
            mode: CommandMode::Direct
        }
    );
    assert_eq!(
        controlling.deactivate(&command).unwrap_err(),
        CtError::SelectNotAllowed {
            mode: CommandMode::Direct
        }
    );

    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let select = activation(&command.with_select(true), CA, ORG).unwrap();
    // TS 60870-5-604 5.4.19.30: a select the station will not serve is answered
    // with "the same ASDU … with COT=7, C_SC/DC/SE/RC_ACTCONneg (Negative
    // ACTCON)". That is an answer, not silence and not an Err.
    let outcome = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: true,
            test: false
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::ActivationCon);
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");
    assert_eq!(
        &outcome.send[0][6..],
        &select[6..],
        "the mirror repeats the command it refuses"
    );
    assert!(!controlled.is_selected(0x3000), "and nothing is selected");
}

#[test]
fn execute_without_a_select_is_refused_by_a_select_and_execute_station() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    assert_eq!(
        controlling
            .execute(&single(0x3000, true, false))
            .unwrap_err(),
        CtError::ExecuteWithoutSelect { ioa: 0x3000 }
    );
}

#[test]
fn a_second_select_for_the_same_object_is_refused() {
    let command = single(0x3000, true, false);
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    controlling.select(&command).unwrap();
    assert_eq!(
        controlling.select(&command).unwrap_err(),
        CtError::AlreadySelected { ioa: 0x3000 }
    );

    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let select = activation(&command.with_select(true), CA, ORG).unwrap();
    controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    // The object is already selected, so this one is refused with the same
    // negative ACTCON: a wire answer, not a caller-side error.
    let outcome = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: true,
            test: false
        }
    );
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");
    assert!(
        controlled.is_selected(0x3000),
        "the first select is the one that stands"
    );
}

#[test]
fn one_select_per_object_and_two_objects_at_once() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let select_a = controlling.select(&single(0x3000, true, false)).unwrap();
    let select_b = controlling.select(&single(0x3001, false, false)).unwrap();
    assert_eq!(controlling.awaiting().len(), 2);
    assert!(controlling.is_awaiting(0x3000));
    assert!(controlling.is_awaiting(0x3001));

    // Each select has to be correctly mirrored before it may be executed
    // (TS 60870-5-604 5.4.19.1).
    for select in [&select_a, &select_b] {
        let outcome = controlled.on_request(select, &Known::EVERYTHING).unwrap();
        controlling
            .on_response(&outcome.send[0], &Known::EVERYTHING)
            .unwrap();
    }
    assert_eq!(controlling.selected().len(), 2);
    assert!(controlling.is_selected(0x3000));
    assert!(controlling.is_selected(0x3001));

    controlling.execute(&single(0x3000, true, false)).unwrap();
    assert!(!controlling.is_selected(0x3000));
    assert!(
        controlling.is_selected(0x3001),
        "the other object keeps its select"
    );
    assert_eq!(controlling.running().len(), 1);
}

// ------------------------------------------ select timeout, abandon and reset

const fn controlled_sbo() -> CommandTransmission {
    CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    )
}

const fn controlling_sbo() -> CommandTransmission {
    CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    )
}

#[test]
fn a_late_execute_is_refused_after_the_select_timeout() {
    // TS 604 5.4.19.40: an execute after the configured delay is refused.
    let t0 = Instant::now();
    let mut controlled = controlled_sbo().with_select_timeout(Duration::from_secs(10));
    let command = single(0x3000, true, false);
    let select = activation(&command.with_select(true), CA, ORG).unwrap();
    let execute = activation(&command, CA, ORG).unwrap();

    assert_eq!(controlled.expire_selections(t0), [] as [u32; 0]);
    controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(
        controlled.expire_selections(t0 + Duration::from_millis(9_999)),
        [] as [u32; 0]
    );
    assert!(controlled.is_selected(0x3000), "not lapsed yet");

    assert_eq!(
        controlled.expire_selections(t0 + Duration::from_secs(10)),
        vec![0x3000]
    );
    assert!(!controlled.is_selected(0x3000));
    let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: true,
            test: false
        }
    );
    assert!(header_of(&outcome.send[0]).negative, "ACTCONneg");
    assert!(!controlled.is_running(0x3000), "nothing executed");
}

#[test]
fn a_lapsed_select_does_not_block_a_new_select() {
    let t0 = Instant::now();
    let mut controlled = controlled_sbo().with_select_timeout(Duration::from_secs(10));
    let command = single(0x3000, true, false);
    let select = activation(&command.with_select(true), CA, ORG).unwrap();
    let execute = activation(&command, CA, ORG).unwrap();

    controlled.expire_selections(t0);
    controlled.on_request(&select, &Known::EVERYTHING).unwrap();

    let t1 = t0 + Duration::from_secs(30);
    controlled.expire_selections(t1);
    let outcome = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: false,
            test: false
        },
        "the object is selectable again"
    );

    // The new select is timed from t1, so an execute within its window runs.
    assert_eq!(
        controlled.expire_selections(t1 + Duration::from_secs(5)),
        [] as [u32; 0]
    );
    let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: false,
            test: false
        }
    );
    // An executed select leaves no deadline behind.
    assert_eq!(
        controlled.expire_selections(t1 + Duration::from_secs(60)),
        [] as [u32; 0]
    );
}

#[test]
fn a_select_accepted_before_the_clock_is_timed_from_the_first_call() {
    let t0 = Instant::now();
    let mut controlled = controlled_sbo().with_select_timeout(Duration::from_secs(10));
    let select = activation(&single(0x3000, true, true), CA, ORG).unwrap();
    controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(controlled.expire_selections(t0), [] as [u32; 0]);
    assert_eq!(
        controlled.expire_selections(t0 + Duration::from_secs(10)),
        vec![0x3000]
    );
}

#[test]
fn without_a_select_timeout_nothing_expires() {
    let t0 = Instant::now();
    let mut controlled = controlled_sbo();
    assert_eq!(controlled.select_timeout(), None);
    let select = activation(&single(0x3000, true, true), CA, ORG).unwrap();
    controlled.expire_selections(t0);
    controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(
        controlled.expire_selections(t0 + Duration::from_secs(3600)),
        [] as [u32; 0]
    );
    assert!(controlled.is_selected(0x3000));
}

#[test]
fn the_controlled_station_can_deselect_and_reset() {
    let mut controlled = controlled_sbo();
    let select_a = activation(&single(0x3000, true, true), CA, ORG).unwrap();
    let select_b = activation(&single(0x3001, true, true), CA, ORG).unwrap();
    controlled
        .on_request(&select_a, &Known::EVERYTHING)
        .unwrap();
    controlled
        .on_request(&select_b, &Known::EVERYTHING)
        .unwrap();

    assert!(controlled.abandon(0x3000));
    assert!(!controlled.abandon(0x3000), "nothing left to abandon");
    assert!(!controlled.is_selected(0x3000));
    assert!(controlled.is_selected(0x3001));
    let outcome = controlled
        .on_request(&select_a, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: false,
            test: false
        }
    );

    let execute = activation(&single(0x3001, true, false), CA, ORG).unwrap();
    controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
    assert!(controlled.is_running(0x3001));

    controlled.reset();
    assert_eq!(controlled.selected(), []);
    assert_eq!(controlled.running(), []);
    assert_eq!(
        controlled.terminate(0x3001, false).unwrap_err(),
        CtError::NotRunning { ioa: 0x3001 }
    );
    let outcome = controlled
        .on_request(&select_a, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: false,
            test: false
        },
        "a reset station accepts a new select"
    );
}

#[test]
fn the_controlling_station_can_abandon_an_unanswered_select() {
    let command = single(0x3000, true, false);
    let mut controlling = controlling_sbo();
    controlling.select(&command).unwrap();
    assert_eq!(
        controlling.select(&command).unwrap_err(),
        CtError::AlreadySelected { ioa: 0x3000 }
    );
    assert!(controlling.abandon(0x3000));
    assert!(!controlling.is_awaiting(0x3000));
    controlling.select(&command).unwrap();
    assert!(controlling.is_awaiting(0x3000));
}

#[test]
fn the_controlling_station_reset_drops_every_procedure() {
    let mut controlling = controlling_sbo();
    let mut controlled = controlled_sbo();
    let a = single(0x3000, true, false);
    let b = single(0x3001, true, false);
    let c = single(0x3002, true, false);
    for command in [&a, &b] {
        let select = controlling.select(command).unwrap();
        let outcome = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
        controlling
            .on_response(&outcome.send[0], &Known::EVERYTHING)
            .unwrap();
    }
    controlling.execute(&b).unwrap();
    controlling.select(&c).unwrap();
    assert!(controlling.is_selected(0x3000));
    assert!(controlling.is_running(0x3001));
    assert!(controlling.is_awaiting(0x3002));

    controlling.reset();
    assert_eq!(controlling.selected(), []);
    assert_eq!(controlling.running(), []);
    assert_eq!(controlling.awaiting(), []);
    controlling.select(&a).unwrap();
    controlling.select(&c).unwrap();
}

#[test]
fn the_execute_does_not_match_the_select() {
    // TS 604 Table 19: "If the EXECUTE message from the Controlling does not
    // contain exactly the same information as the SELECT message, then the
    // Controlled mirrors the same ASDU with COT=7 ... (Negative ACTCON)".
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );

    let select = controlling.select(&single(0x3000, true, false)).unwrap();
    let mirror = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    controlling
        .on_response(&mirror.send[0], &Known::EVERYTHING)
        .unwrap();
    assert!(controlled.is_selected(0x3000));

    // The same address, the same family, a different state, from a peer that
    // does not check its own execute against its select.
    let mismatch = activation(&single(0x3000, false, false), CA, ORG).unwrap();
    let outcome = controlled
        .on_request(&mismatch, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: true,
            test: false
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::ActivationCon);
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");
    assert_eq!(
        &outcome.send[0][6..],
        &mismatch[6..],
        "the mirror repeats what it received"
    );
    assert!(
        !controlled.is_running(0x3000),
        "a refused execute does not run"
    );
    assert!(!controlled.is_selected(0x3000), "and the select is spent");
}

/// 5-101 cl.7.2.3: a `T = 1` select tests "without controlling the process",
/// so a `T = 0` execute does not match it, nor a `T = 1` execute a real
/// select: either is refused like any other mismatch and spends the select.
#[test]
fn the_execute_does_not_match_a_select_with_another_test_bit() {
    let with_test = |mut frame: Vec<u8>| {
        frame[2] |= 0x80;
        frame
    };
    for (select_test, execute_test) in [(true, false), (false, true)] {
        let mut controlled = controlled_sbo();
        let mut select = activation(&single(0x3000, true, true), CA, ORG).unwrap();
        if select_test {
            select = with_test(select);
        }
        let mirror = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
        assert!(
            !header_of(&mirror.send[0]).negative,
            "the select is confirmed"
        );

        let mut execute = activation(&single(0x3000, true, false), CA, ORG).unwrap();
        if execute_test {
            execute = with_test(execute);
        }
        let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
        assert_eq!(
            outcome.reaction,
            Reaction::Confirmed {
                ioa: 0x3000,
                select: false,
                negative: true,
                test: execute_test
            }
        );
        assert!(!controlled.is_running(0x3000), "nothing runs");
        assert!(!controlled.is_selected(0x3000), "and the select is spent");
    }
}

#[test]
fn the_controlling_station_refuses_an_execute_that_is_not_its_select() {
    // TS 604 Table 19: the EXECUTE must "contain exactly the same information
    // as the SELECT message". The controlling station does not send one that
    // does not, and the select survives the refusal.
    let mut controlled = controlled_sbo();
    let mut controlling = controlling_sbo();
    let select = controlling.select(&single(0x3000, true, false)).unwrap();
    let mirror = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    controlling
        .on_response(&mirror.send[0], &Known::EVERYTHING)
        .unwrap();

    assert_eq!(
        controlling
            .execute(&single(0x3000, false, false))
            .unwrap_err(),
        CtError::ExecuteMismatch { ioa: 0x3000 }
    );
    assert!(controlling.is_selected(0x3000), "the select is kept");
    let execute = controlling.execute(&single(0x3000, true, false)).unwrap();
    assert_eq!(
        execute[9] & 0x81,
        0x01,
        "S/E = 0, SCS = 1: the select's state"
    );
}

#[test]
fn a_set_point_threadhold_value_that_differs_also_fails_the_match() {
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let select = controlling.select(&normalized(0x3000, 100, false)).unwrap();
    let mirror = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    controlling
        .on_response(&mirror.send[0], &Known::EVERYTHING)
        .unwrap();
    let execute = activation(&normalized(0x3000, 101, false), CA, ORG).unwrap();
    let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: true,
            test: false
        }
    );
}

#[test]
fn an_execute_at_a_select_and_execute_station_with_no_select_is_negative() {
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let execute = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: true,
            test: false
        }
    );
}

// --------------------------------------------------------- the negative paths

#[test]
fn a_not_allowed_double_command_is_refused_with_pn_1() {
    // TS 604 5.4.19.30/.50: "a not allowed command (e.g. DCO=0 or 3; RCO=0 or 3)".
    for dcs in [
        DoubleCommandState::NotPermitted,
        DoubleCommandState::NotPermittedAlt,
    ] {
        let command = double(0x3000, dcs, false);
        assert!(
            !command.is_command_state(),
            "{dcs:?} is not a command state"
        );
        assert_eq!(
            activation(&command, CA, ORG).unwrap_err(),
            CtError::NotACommandState { ioa: 0x3000 },
            "this station does not put a not-allowed command on the wire"
        );

        // The mirror of it is exactly what the clause asks for, though.
        let received = confirmation(&command, true, CA, ORG, false).unwrap();
        assert!(header_of(&received).negative);

        let mut controlled = CommandTransmission::controlled(
            CommandMode::Direct,
            CommandSet::Untagged,
            Termination::All,
            CA,
            ORG,
        );
        // Build the wire frame by hand: the layout layer permits the pattern,
        // which is what a peer may send.
        let frame = raw_double_command(0x3000, dcs, false);
        let outcome = controlled.on_request(&frame, &Known::EVERYTHING).unwrap();
        assert_eq!(
            outcome.reaction,
            Reaction::Confirmed {
                ioa: 0x3000,
                select: false,
                negative: true,
                test: false
            }
        );
        assert_eq!(cause_of(&outcome.send[0]), Cause::ActivationCon);
        assert!(header_of(&outcome.send[0]).negative, "P/N = 1");
        assert!(!controlled.is_running(0x3000));
    }
}

/// A `C_DC_NA_1` ASDU built straight through the layout layer, so a not-allowed
/// `DCS` reaches the wire the way a peer's would.
fn raw_double_command(ioa: u32, dcs: DoubleCommandState, select: bool) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::CDcNa1,
        sequence: false,
        count: 1,
        cause: Cause::Activation,
        negative: false,
        test: false,
        originator: ORG,
        common_address: CA,
    };
    let object = LayoutObject {
        ioa,
        value: iec104::asdu::CDcNa1 {
            dco: Dco {
                dcs,
                qoc: Qoc { qu: 2, select },
            },
        },
    };
    encode_asdu(&header, &[object]).expect("the layout writes any DCO octet")
}

#[test]
fn a_not_allowed_regulating_step_command_is_refused_with_pn_1() {
    for rcs in [
        RegulatingStepState::NotPermitted,
        RegulatingStepState::NotPermittedAlt,
    ] {
        let command = step(0x3000, rcs, false);
        assert!(!command.is_command_state());
        assert_eq!(
            activation(&command, CA, ORG).unwrap_err(),
            CtError::NotACommandState { ioa: 0x3000 }
        );
        let mut controlled = CommandTransmission::controlled(
            CommandMode::Direct,
            CommandSet::Untagged,
            Termination::All,
            CA,
            ORG,
        );
        let frame = raw_step_command(0x3000, rcs);
        let outcome = controlled.on_request(&frame, &Known::EVERYTHING).unwrap();
        assert_eq!(
            outcome.reaction,
            Reaction::Confirmed {
                ioa: 0x3000,
                select: false,
                negative: true,
                test: false
            }
        );
    }
}

/// A `C_RC_NA_1` ASDU with the `RCS` bit pattern given, through the layout.
fn raw_step_command(ioa: u32, rcs: RegulatingStepState) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::CRcNa1,
        sequence: false,
        count: 1,
        cause: Cause::Activation,
        negative: false,
        test: false,
        originator: ORG,
        common_address: CA,
    };
    let object = LayoutObject {
        ioa,
        value: iec104::asdu::CRcNa1 {
            rco: Rco {
                rcs,
                qoc: Qoc {
                    qu: 0,
                    select: false,
                },
            },
        },
    };
    encode_asdu(&header, &[object]).expect("the layout writes any RCO octet")
}

#[test]
fn a_controlling_station_does_not_build_a_not_allowed_command() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    assert_eq!(
        controlling
            .execute(&double(0x3000, DoubleCommandState::NotPermitted, false))
            .unwrap_err(),
        CtError::NotACommandState { ioa: 0x3000 }
    );
    assert_eq!(
        controlling
            .execute(&step(0x3000, RegulatingStepState::NotPermittedAlt, false))
            .unwrap_err(),
        CtError::NotACommandState { ioa: 0x3000 }
    );
}

// ---------------------------------------------------------- the deactivation

#[test]
fn the_deactivation_stops_a_select_and_changes_no_value() {
    // TS 604 5.4.19.10: "The value of the Object(s) does not change at all
    // during this command procedure"; 5-101 cl.7.4.7: "S/E of the qualifier of
    // command QOC is irrelevant in ASDUs with causes of transmission DEACT and
    // DEACTCON."
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let command = single(0x3000, true, false);

    let select = controlling.select(&command).unwrap();
    let mirror = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    controlling
        .on_response(&mirror.send[0], &Known::EVERYTHING)
        .unwrap();

    let deact = controlling.deactivate(&command).unwrap();
    assert_eq!(cause_of(&deact), Cause::Deactivation);
    assert_eq!(
        deact[6..9],
        select[6..9],
        "the deactivation carries the command's own information object address"
    );
    assert_eq!(
        deact[9] & 0x7F,
        select[9] & 0x7F,
        "and the same value: SCS, QU, and every other bit, unchanged"
    );
    assert_eq!(
        deact[9], select[9],
        "the DEACT repeats the select's own message, S/E = 1 included — \
         TS 60870-5-604 5.4.19.10's \"sends the same Command message with COT=8 … \
         and S/E=1 (SELECT)\""
    );

    let outcome = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Deactivated {
            ioa: 0x3000,
            negative: false
        }
    );
    assert_eq!(outcome.send.len(), 1);
    let deactcon = &outcome.send[0];
    assert_eq!(cause_of(deactcon), Cause::DeactivationCon);
    assert_eq!(&deactcon[..2], &deact[..2]);
    assert_eq!(
        &deactcon[6..],
        &deact[6..],
        "the DEACTCON mirrors the DEACT, value unchanged"
    );
    assert!(!controlled.is_selected(0x3000));
    assert!(!controlled.is_running(0x3000));

    // The controlling station closes its select on the DEACTCON.
    let outcome = controlling
        .on_response(deactcon, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Deactivated {
            ioa: 0x3000,
            negative: false
        }
    );
    assert!(!controlling.is_selected(0x3000));
    assert_eq!(
        cause_of(&deactivation_confirmation(&command, CA, ORG, false).unwrap()),
        Cause::DeactivationCon
    );
}

#[test]
fn a_deactivation_with_se_1_is_accepted_and_mirrored_as_it_came() {
    // The TS 604 test (5.4.19.10) sends its DEACT with S/E = 1; 5-101 cl.7.4.7
    // says the bit is irrelevant and the value must not change.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let command = single(0x3000, true, true);
    let select = activation(&command, CA, ORG).unwrap();
    assert_eq!(select[9] & 0x80, 0x80);
    // on_request sees S/E = 1 as a select; the DEACT below carries it again.
    controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    let deact = deactivation(&command, CA, ORG).unwrap();
    assert_eq!(deact[9] & 0x80, 0x80, "the S/E bit is written as given");
    let outcome = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Deactivated {
            ioa: 0x3000,
            negative: false
        }
    );
    assert_eq!(outcome.send[0][9] & 0x80, 0x80, "and echoed unchanged");
    assert_eq!(outcome.send[0][9], deact[9]);
}

#[test]
fn a_deactivation_without_a_select_is_refused() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    assert_eq!(
        controlling
            .deactivate(&single(0x3000, true, false))
            .unwrap_err(),
        CtError::DeactivationWithoutSelect { ioa: 0x3000 }
    );
    // An undirected DEACTCON moves nothing either.
    let deactcon = deactivation_confirmation(&single(0x3000, true, false), CA, ORG, false).unwrap();
    let outcome = controlling
        .on_response(&deactcon, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(outcome.reaction, Reaction::Other);
}

// ------------------------------------ the bitstring and the termination policy

#[test]
fn a_bitstring_command_has_no_qualifier_and_cannot_select() {
    // Figure 70: C_BO_NA_1 := CP{..., BSI}, with no QOC, no QOS and no S/E bit.
    // TS 604 5.4.19.1 names no bitstring command among the select and execute
    // tests.
    let bitstring = Command::new(
        0x3000,
        CommandValue::Bitstring {
            bsi: Bsi { bits: 0x0F0F_0F0F },
        },
    );
    assert!(!bitstring.value.supports_select());
    assert!(!bitstring.select());
    assert!(!bitstring.with_select(true).value.select());
    assert_eq!(bitstring.with_select(true), bitstring);

    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    assert_eq!(
        controlling.select(&bitstring).unwrap_err(),
        CtError::NotSelectable { ioa: 0x3000 }
    );
    // The direct execute is what the family has.
    let execute = controlling.execute(&bitstring).unwrap();
    assert_eq!(header_of(&execute).type_id, TypeId::CBoNa1);
    assert_eq!(&execute[9..13], &[0x0F, 0x0F, 0x0F, 0x0F]);
}

#[test]
fn a_bitstring_command_executes_at_the_controlled_station() {
    // Even at a station with the select and execute function: the family has no
    // S/E bit, so the execute is direct (TS 604 Table 19 lists "Bitstring
    // Command message" only under Direct Execute).
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let frame = activation(
        &Command::new(
            0x3000,
            CommandValue::Bitstring {
                bsi: Bsi { bits: 0x1234_5678 },
            },
        ),
        CA,
        ORG,
    )
    .unwrap();
    let outcome = controlled.on_request(&frame, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: false,
            test: false
        }
    );
    assert_eq!(outcome.send[0][9..13], [0x78, 0x56, 0x34, 0x12]);
}

#[test]
fn the_termination_policy_is_a_selection_not_a_branch() {
    // 5-101 cl.7.4.7: "C_SC, C_DC, C_RC ACT, ACTCON and ACTTERM are used." /
    // "C_SE ACTTERM may be used optionally."
    assert!(Termination::All.uses(Family::Single));
    assert!(Termination::All.uses(Family::SetPointNormalized));
    assert!(Termination::SetPointsNotTerminated.uses(Family::Single));
    assert!(!Termination::SetPointsNotTerminated.uses(Family::SetPointNormalized));
    assert!(!Termination::SetPointsNotTerminated.uses(Family::SetPointScaled));
    assert!(!Termination::SetPointsNotTerminated.uses(Family::SetPointFloat));
    // Figures 70 and 29 mark the bitstring's <10> "(opt)" exactly as they mark the
    // set-points', so it is not mandatory either; figures 64–66 print <10>
    // unqualified.
    assert!(!Termination::SetPointsNotTerminated.uses(Family::Bitstring));
    assert!(Termination::All.uses(Family::Bitstring));
    assert!(Family::SetPointFloat.is_set_point());
    assert!(Family::Bitstring.termination_is_optional());

    // The same selection, driven through the controlled station.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::SetPointsNotTerminated,
        CA,
        ORG,
    );
    let execute = activation(&normalized(0x3000, 5, false), CA, ORG).unwrap();
    let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: false,
            test: false
        }
    );
    assert!(
        !controlled.is_running(0x3000),
        "a family the station does not terminate is not held"
    );
    assert_eq!(
        controlled.terminate(0x3000, false).unwrap_err(),
        CtError::NotRunning { ioa: 0x3000 }
    );
}

#[test]
fn a_termination_the_station_does_not_use_is_refused() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::SetPointsNotTerminated,
        CA,
        ORG,
    );
    assert!(!controlling.is_running(0x3000));
    controlling.execute(&normalized(0x3000, 5, false)).unwrap();
    assert!(
        !controlling.is_running(0x3000),
        "the execute is not held for a family this station does not terminate"
    );

    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let frame = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    controlled.on_request(&frame, &Known::EVERYTHING).unwrap();
    assert!(controlled.is_running(0x3000));
    assert_eq!(
        termination(&single(0x3000, true, false), false, CA, ORG, false)
            .unwrap()
            .len(),
        10
    );
}

#[test]
fn a_negative_termination_is_the_accept_then_fail_alternative() {
    // TS 604 5.4.19.40/.50: "first accept the command with a Positive ACTCON and
    // then send a Negative Termination".
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let frame = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let outcome = controlled.on_request(&frame, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: false,
            test: false
        },
        "accepted positively"
    );
    let actterm = controlled.terminate(0x3000, true).unwrap();
    assert!(header_of(&actterm).negative, "and terminated negatively");
    assert_eq!(cause_of(&actterm), Cause::ActivationTermination);
    assert_eq!(&actterm[6..], &frame[6..], "still a mirror of the command");
}

#[test]
fn an_actterm_for_something_that_is_not_running_is_other() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let actterm = termination(&single(0x3000, true, false), false, CA, ORG, false).unwrap();
    let outcome = controlling
        .on_response(&actterm, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(outcome.reaction, Reaction::Other);
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
}

// -------------------------------------------------------- discard and role

#[test]
fn an_unknown_common_address_is_mirrored_with_cause_46() {
    // 5-101 cl.7.2.3's table (PDF page index 42): a **control-direction** ASDU
    // whose common address the station does not know is "mirrored by the
    // controlled station with bit \"P/N := <1> negative confirm\"" and cause 46.
    // TS 60870-5-604 5.4.10.10: "If COT=46 is supported, any ASDU with undefined
    // CASDU is mirrored by the controlled station with P/N = 1: negative
    // confirmation of activation using COT = 46 (unknown CASDU)".
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let frame = activation(&single(0x3000, true, false), 99, ORG).unwrap();
    let known = Known {
        common_address: false,
        ..Known::EVERYTHING
    };
    let outcome = controlled.on_request(&frame, &known).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownCommonAddress
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::UnknownCommonAddress);
    assert_eq!(
        outcome.send[0][2], 0x6E,
        "P/N = 1 and cause 46 in one octet"
    );
    let mirror = header_of(&outcome.send[0]);
    assert!(mirror.negative, "P/N = 1");
    assert_eq!(
        mirror.common_address, CA,
        "the answering station's own address"
    );
    assert_eq!(mirror.originator, ORG, "the request's originator");
    assert_eq!(
        &outcome.send[0][6..],
        &frame[6..],
        "the mirror is the ASDU it answers"
    );
    assert!(!controlled.is_selected(0x3000), "and nothing is recorded");
}

#[test]
fn an_unknown_type_identification_is_mirrored_with_cause_44() {
    // 5-101 cl.7.3 (PDF page index 59): "TYPE IDENTIFICATION numbers > 127 are
    // discarded by controlling stations (monitor direction) or mirrored with
    // CAUSE OF TRANSMISSION = 44 by controlled stations (control direction)".
    // The type has no layout to rebuild from, so the ASDU is copied octet for
    // octet (the rule of `src/asdu/unknown.rs`). Only the header changes.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let header = Header {
        type_id: TypeId::Other(200),
        sequence: false,
        count: 1,
        cause: Cause::Activation,
        negative: false,
        test: true,
        originator: ORG,
        common_address: CA,
    };
    let mut frame = Vec::new();
    header.encode(&mut frame).expect("the header encodes");
    frame.extend_from_slice(&[0x00, 0x30, 0x00, 0x01]);
    let known = Known::NOTHING;
    let outcome = controlled.on_request(&frame, &known).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownTypeId
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::UnknownTypeId);
    assert_eq!(
        outcome.send[0][2], 0xEC,
        "cause 44, P/N = 1 and T = 1 in one octet"
    );
    let mirror = header_of(&outcome.send[0]);
    assert_eq!(mirror.type_id, TypeId::Other(200), "the type is echoed");
    assert_eq!(mirror.common_address, CA);
    assert_eq!(mirror.originator, ORG);
    assert!(mirror.test, "T is echoed too");
    assert_eq!(
        &outcome.send[0][6..],
        &frame[6..],
        "an undecodable body is copied, not rebuilt"
    );
    assert!(!controlled.is_selected(0x3000));
}

#[test]
fn a_frame_whose_type_the_profile_does_not_implement_is_mirrored_with_cause_44() {
    // The same rule for a **decodable** command: a profile that answers "I do
    // not implement type 45" is mirrored with cause 44 (0x6C: P/N = 1 and
    // T = 0), not discarded, and the body is rebuilt from the decoded command
    // rather than copied.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let frame = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let known = Known {
        type_id: false,
        ..Known::EVERYTHING
    };
    let outcome = controlled.on_request(&frame, &known).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownTypeId
        }
    );
    assert_eq!(outcome.send[0][2], 0x6C, "cause 44 with P/N = 1");
    assert_eq!(outcome.send[0].len(), frame.len());
    assert_eq!(&outcome.send[0][6..], &frame[6..]);
    assert!(!controlled.is_selected(0x3000));
}

#[test]
fn a_command_to_the_broadcast_address_is_rejected_and_never_confirmed() {
    // TS 60870-5-604 5.4.10.10 (PDF page index 54): "Broadcast CASDU value
    // (0xFF<FF>) only used in control direction with ASDU Types 100
    // (Interrogation), 101 (Counter interrogation), 103 (Clock Sync) or 105
    // (Reset Process). The Controlled station rejects all other ASDU Types with
    // a Broadcast CASDU value by mirroring the ASDU with P/N = 1 negative (and
    // with COT = 46, if supported)." A command is not one of those four types.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    for command in every_family() {
        let frame = activation(&command, BROADCAST_CA, ORG).unwrap();
        // A station whose profile claims to know every common address must still
        // reject the broadcast: the check reads the header, not `Known`.
        let outcome = controlled.on_request(&frame, &Known::EVERYTHING).unwrap();
        assert_eq!(
            outcome.reaction,
            Reaction::Refused {
                ioa: command.ioa,
                cause: Cause::UnknownCommonAddress
            },
            "{:?} must not be confirmed",
            command.value.family()
        );
        assert_eq!(
            cause_of(&outcome.send[0]),
            Cause::UnknownCommonAddress,
            "{:?}",
            command.value.family()
        );
        assert_eq!(outcome.send[0][2], 0x6E, "P/N = 1, COT 46");
        let mirror = header_of(&outcome.send[0]);
        assert_eq!(mirror.common_address, CA, "the station's own address");
        assert_eq!(&outcome.send[0][6..], &frame[6..]);
        assert!(!controlled.is_selected(command.ioa));
        assert!(!controlled.is_running(command.ioa));
    }
}

#[test]
fn a_non_command_asdu_at_the_broadcast_address_falls_through_to_other() {
    // TS 60870-5-604 5.4.10.10 (PDF page index 54): the broadcast CASDU is
    // "only used in control direction with ASDU Types 100 (Interrogation), 101
    // (Counter interrogation), 103 (Clock Sync) or 105 (Reset Process)". Those
    // four are *permitted* to be broadcast, not refused: the rejection is scoped
    // to the fourteen command types. A non-command type at the broadcast address
    // (one of those four, or a monitor type) is therefore not this procedure's
    // to answer and must fall through to Reaction::Other with nothing sent,
    // exactly as it does at the station's own address.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    for type_id in [
        TypeId::CIcNa1,
        TypeId::CCiNa1,
        TypeId::CCsNa1,
        TypeId::CRpNa1,
        TypeId::MSpNa1,
    ] {
        for common_address in [BROADCAST_CA, CA] {
            let header = Header {
                type_id,
                sequence: false,
                count: 1,
                cause: Cause::Activation,
                negative: false,
                test: false,
                originator: ORG,
                common_address,
            };
            let mut frame = Vec::new();
            header.encode(&mut frame).expect("the header encodes");
            frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x14]);
            let outcome = controlled.on_request(&frame, &Known::EVERYTHING).unwrap();
            assert_eq!(
                outcome.reaction,
                Reaction::Other,
                "{type_id:?} at {common_address:#06x} is not this procedure's"
            );
            assert!(outcome.send.is_empty(), "and is answered with nothing");
        }
    }
}

#[test]
fn an_unknown_information_object_address_is_mirrored_with_cause_47() {
    // 5-101 cl.7.2.3's table (PDF page index 42): a **control-direction** ASDU
    // whose information object address the station does not know is "mirrored by
    // the controlled station with bit \"P/N := <1> negative confirm\"" and cause
    // 47. This is 604 5.4.19.30/.50's "the controlled station could instead
    // mirror the same ASDU with COT=47 (unknown Information Object Address)".
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let frame = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let known = Known {
        information_object_address: false,
        ..Known::EVERYTHING
    };
    let outcome = controlled.on_request(&frame, &known).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownInformationObjectAddress
        }
    );
    assert_eq!(
        cause_of(&outcome.send[0]),
        Cause::UnknownInformationObjectAddress
    );
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");
    assert_eq!(
        &outcome.send[0][6..],
        &frame[6..],
        "the mirror is the ASDU it answers"
    );
    assert!(!controlled.is_selected(0x3000), "and nothing is recorded");
}

#[test]
fn an_asdu_that_is_not_this_procedure_is_other() {
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    // A command ASDU with a cause figure 64 does not list in the control
    // direction: cause 3 is not one of <6>/<8>, so it is "unknown cause of
    // transmission" and clause 7.2.3's cause-45 mirror is the answer.
    let header = Header {
        type_id: TypeId::CScNa1,
        sequence: false,
        count: 1,
        cause: Cause::Spontaneous,
        negative: false,
        test: false,
        originator: ORG,
        common_address: CA,
    };
    let frame = encode_asdu(
        &header,
        &[LayoutObject {
            ioa: 0x3000,
            value: iec104::asdu::CScNa1 {
                sco: Sco {
                    scs: true,
                    qoc: Qoc {
                        qu: 0,
                        select: false,
                    },
                },
            },
        }],
    )
    .unwrap();
    let outcome = controlled.on_request(&frame, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownCause
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::UnknownCause);
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");

    // A monitor-direction ASDU on a controlling station: M_ME_NB_1 is not one of
    // 5-104 cl.7.7's three return families.
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let measured = encode_asdu(
        &Header {
            type_id: TypeId::MMeNb1,
            sequence: false,
            count: 1,
            cause: Cause::Spontaneous,
            negative: false,
            test: false,
            originator: ORG,
            common_address: CA,
        },
        &[LayoutObject {
            ioa: 0x3000,
            value: MMeNb1 {
                sva: Sva { value: 1 },
                qds: Qds::default(),
            },
        }],
    )
    .unwrap();
    assert_eq!(
        controlling
            .on_response(&measured, &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Other
    );

    // ... while M_SP_NA_1 with the same cause is the return information.
    assert_eq!(
        controlling
            .on_response(
                &returned(0x3000, ReturnInfo::Spontaneous),
                &Known::EVERYTHING
            )
            .unwrap()
            .reaction,
        Reaction::Returned {
            ioa: 0x3000,
            info: ReturnInfo::Spontaneous
        }
    );
}

#[test]
fn the_roles_do_not_use_each_others_entry_points() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    assert_eq!(controlling.role(), Role::Controlling);
    assert_eq!(
        controlling
            .on_request(
                &activation(&single(1, true, false), CA, ORG).unwrap(),
                &Known::EVERYTHING
            )
            .unwrap_err(),
        CtError::WrongRole
    );
    assert_eq!(
        controlling.terminate(1, false).unwrap_err(),
        CtError::WrongRole
    );

    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    assert_eq!(controlled.role(), Role::Controlled);
    assert_eq!(
        controlled
            .on_response(
                &activation(&single(1, true, false), CA, ORG).unwrap(),
                &Known::EVERYTHING
            )
            .unwrap_err(),
        CtError::WrongRole
    );
    assert_eq!(
        controlled.select(&single(1, true, false)).unwrap_err(),
        CtError::WrongRole
    );
    assert_eq!(
        controlled.execute(&single(1, true, false)).unwrap_err(),
        CtError::WrongRole
    );
    assert_eq!(
        controlled.deactivate(&single(1, true, false)).unwrap_err(),
        CtError::WrongRole
    );
}

// ------------------------------------------------------------ the codec layer

#[test]
fn every_family_round_trips_through_both_roles() {
    for command in every_family() {
        for tagged in [false, true] {
            let command = if tagged {
                Command::tagged(command.ioa, command.value, time())
            } else {
                command
            };
            let mut controlling = CommandTransmission::controlling(
                CommandMode::Direct,
                command.set(),
                Termination::All,
                CA,
                ORG,
            );
            let mut controlled = CommandTransmission::controlled(
                CommandMode::Direct,
                command.set(),
                Termination::All,
                CA,
                ORG,
            );
            let execute = controlling.execute(&command).unwrap();
            assert_eq!(header_of(&execute).type_id, command.type_id());
            assert_eq!(
                execute.len(),
                10 + element_extra(command.value) + if tagged { 7 } else { 0 }
            );

            let outcome = controlled.on_request(&execute, &Known::EVERYTHING).unwrap();
            assert_eq!(
                outcome.reaction,
                Reaction::Confirmed {
                    ioa: command.ioa,
                    select: false,
                    negative: false,
                    test: false
                },
                "{:?} tagged={tagged}",
                command.family()
            );
            // The mirror is the command ASDU with only its header changed.
            assert_eq!(&outcome.send[0][..2], &execute[..2]);
            assert_eq!(&outcome.send[0][6..], &execute[6..]);
            assert_eq!(cause_of(&outcome.send[0]), Cause::ActivationCon);

            // And the controlling station classifies its own mirror back.
            let back = controlling
                .on_response(&outcome.send[0], &Known::EVERYTHING)
                .unwrap();
            assert_eq!(
                back.reaction,
                Reaction::Confirmed {
                    ioa: command.ioa,
                    select: false,
                    negative: false,
                    test: false
                }
            );
            assert!(controlling.is_running(command.ioa));

            // The termination closes it on both sides.
            let actterm = controlled.terminate(command.ioa, false).unwrap();
            assert_eq!(&actterm[6..], &execute[6..]);
            assert_eq!(
                controlling
                    .on_response(&actterm, &Known::EVERYTHING)
                    .unwrap()
                    .reaction,
                Reaction::Terminated {
                    ioa: command.ioa,
                    negative: false,
                }
            );
        }
    }
}

/// The element octets of a family beyond the first one, for the length checks.
const fn element_extra(value: CommandValue) -> usize {
    match value {
        CommandValue::Single { .. }
        | CommandValue::Double { .. }
        | CommandValue::RegulatingStep { .. } => 0,
        CommandValue::SetPointNormalized { .. } | CommandValue::SetPointScaled { .. } => 2,
        CommandValue::SetPointFloat { .. } => 4,
        CommandValue::Bitstring { .. } => 3,
    }
}

#[test]
fn every_truncation_of_a_command_is_a_typed_error() {
    let frame = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    for len in 0..frame.len() {
        let err = controlling
            .on_response(&frame[..len], &Known::EVERYTHING)
            .unwrap_err();
        assert!(
            matches!(err, CtError::Layout(_)),
            "a {len}-octet prefix must be a layout error, got {err:?}"
        );
    }
    // The whole frame is accepted.
    let _ = controlling.on_response(&frame, &Known::EVERYTHING).unwrap();

    // An ASDU one octet longer than the layout allows is not.
    let mut long = frame.clone();
    long.push(0x00);
    assert!(matches!(
        controlling
            .on_response(&long, &Known::EVERYTHING)
            .unwrap_err(),
        CtError::Layout(_)
    ));
}

#[test]
fn the_monitored_type_mapping_follows_the_clause() {
    // 5-101 cl.7.4.7's NOTE: single -> M_SP, double -> M_DP, regulating step ->
    // M_ST, each with its untagged and CP56Time2a form.
    assert_eq!(
        monitored_types(Family::Single),
        [TypeId::MSpNa1, TypeId::MSpTa1, TypeId::MSpTb1]
    );
    assert_eq!(
        monitored_types(Family::Double),
        [TypeId::MDpNa1, TypeId::MDpTa1, TypeId::MDpTb1]
    );
    assert_eq!(
        monitored_types(Family::RegulatingStep),
        [TypeId::MStNa1, TypeId::MStTa1, TypeId::MStTb1]
    );
    assert_eq!(
        monitored_types(Family::SetPointFloat),
        [TypeId::MMeNc1, TypeId::MMeTc1, TypeId::MMeTf1]
    );
    // The three families the NOTE names are the ones RETURN_TYPES covers.
    for family in [Family::Single, Family::Double, Family::RegulatingStep] {
        let monitor = monitored_types(family);
        assert!(is_return_type(monitor[0]));
        assert!(is_return_type(monitor[2]));
        assert!(
            !is_return_type(monitor[1]),
            "the CP24Time2a form is not selected for 104"
        );
    }
}

#[test]
fn the_outcome_of_a_discard_carries_the_reason() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let frame = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let known = Known::NOTHING;
    let outcome: Outcome = controlling.on_response(&frame, &known).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Discard(Discard::Unspecified(Unspecified::TypeIdentification))
    );
    assert_eq!(outcome.send, [] as [std::vec::Vec<u8>; 0]);
}

// ------------------------------- echoes, refusals and the select's mirror

#[test]
fn a_mirror_echoes_the_requests_originator_and_test_bit() {
    // 5-101 cl.7.2.3 (PDF page index 38): "the information source should set the
    // originator address of the ASDUs in the command direction, and the
    // controlled station should echo this originator address in the response in
    // the monitor direction."
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        0x2A,
    );
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        0,
    );
    let command = single(0x3000, true, false);

    // A_SELECT.req from originator 0x2A.
    let select = controlling.select(&command).unwrap();
    assert_eq!(header_of(&select).originator, 0x2A);

    // The mirror carries that originator, not the controlled station's own 0,
    // and the station's own common address.
    let outcome = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    let mirror = &outcome.send[0];
    assert_eq!(
        header_of(mirror).originator,
        0x2A,
        "the request's originator, not the answering station's own"
    );
    assert_eq!(header_of(mirror).common_address, CA);
    assert!(!header_of(mirror).test);
    let confirmed = mirror.clone();
    controlling
        .on_response(&confirmed, &Known::EVERYTHING)
        .unwrap();
    assert!(controlling.is_selected(0x3000));

    // A frame generated under test conditions is answered under test
    // conditions: T = 1 travels back. T is bit 8 of the COT octet, so the
    // octet reads cause 6 with T set.
    let mut flagged = select;
    flagged[2] |= 0x80;
    assert!(header_of(&flagged).test);
    let outcome = controlled.on_request(&flagged, &Known::EVERYTHING).unwrap();
    assert!(header_of(&outcome.send[0]).test, "T is echoed too");
    assert_eq!(header_of(&outcome.send[0]).originator, 0x2A);

    // The termination echoes what the execute arrived with as well. A
    // `T = 1` execute matches only a `T = 1` select, so the object is selected
    // again under test conditions first.
    assert!(controlled.abandon(0x3000));
    let outcome = controlled.on_request(&flagged, &Known::EVERYTHING).unwrap();
    assert!(!header_of(&outcome.send[0]).negative);
    let execute = controlling.execute(&command).unwrap();
    let mut flagged = execute;
    flagged[2] |= 0x80;
    let outcome = controlled.on_request(&flagged, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: false,
            test: true
        }
    );
    let actterm = controlled.terminate(0x3000, true).unwrap();
    assert_eq!(header_of(&actterm).originator, 0x2A);
    assert!(header_of(&actterm).test);
    assert!(header_of(&actterm).negative, "P/N = 1");
}

#[test]
fn a_refused_select_is_no_select_at_all() {
    // TS 60870-5-604 5.4.19.1: "If the SELECT message from the Controlling
    // station is not correctly mirrored by the Controlled station, then the
    // Controlling station does not proceed with sending the EXECUTE message."
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let command = single(0x3000, true, false);
    let select = controlling.select(&command).unwrap();
    assert!(controlling.is_awaiting(0x3000));

    // The ACTCONneg of 5.4.19.30: cause 7 (0x07) with P/N = 1 (0x40).
    let mut refused = select;
    refused[2] = 0x07 | 0x40;
    let outcome = controlling
        .on_response(&refused, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: true,
            test: false
        }
    );
    assert!(!controlling.is_awaiting(0x3000), "the select is dropped");
    assert!(!controlling.is_selected(0x3000));
    assert_eq!(
        controlling.execute(&command).unwrap_err(),
        CtError::ExecuteWithoutSelect { ioa: 0x3000 }
    );
}

#[test]
fn a_cause_47_mirror_of_a_select_drops_it() {
    // 5.4.19.30: "the controlled station could instead mirror the same ASDU with
    // COT=47 (unknown Information Object Address)". It is a refusal like any
    // other.
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let select = controlling.select(&single(0x3000, true, false)).unwrap();
    let mut refused = select;
    refused[2] = 0x2F | 0x40; // cause 47 with P/N = 1
    let outcome = controlling
        .on_response(&refused, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(outcome.reaction, Reaction::Discard(Discard::Mirror));
    assert!(!controlling.is_awaiting(0x3000));
    assert_eq!(
        controlling
            .execute(&single(0x3000, true, false))
            .unwrap_err(),
        CtError::ExecuteWithoutSelect { ioa: 0x3000 }
    );
}

#[test]
fn a_negative_execute_confirmation_ends_the_run() {
    // 5.4.19.30 and .50: "The controlled station does not accept and responds
    // with a P/N=1"; the controlling station "stops the Command function".
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let command = single(0x3000, true, false);
    controlling.execute(&command).unwrap();
    assert!(controlling.is_running(0x3000));

    let refused = confirmation(&command, true, CA, ORG, false).unwrap();
    let outcome = controlling
        .on_response(&refused, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: true,
            test: false
        }
    );
    assert!(!controlling.is_running(0x3000), "the run is dropped");
}

#[test]
fn a_negative_termination_is_told_apart_from_a_positive_one() {
    // TS 60870-5-604 5.4.19.40/.50: "first accept the command with a Positive
    // ACTCON and then send a Negative Termination … and P/N=1".
    let mut controlling = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let command = single(0x3000, true, false);
    controlling.execute(&command).unwrap();

    let actterm = termination(&command, true, CA, ORG, false).unwrap();
    let outcome = controlling
        .on_response(&actterm, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Terminated {
            ioa: 0x3000,
            negative: true
        }
    );
    assert!(!controlling.is_running(0x3000));
}

#[test]
fn the_tagged_bitstring_has_no_deactivation() {
    // 5-104 figure 29 (PDF page index 88) gives C_BO_TA_1 no <8> and no <9>,
    // while 5-101 figure 70 (index 103) gives C_BO_NA_1 both.
    let tagged = Command::tagged(
        0x3000,
        CommandValue::Bitstring {
            bsi: Bsi { bits: 0 },
        },
        time(),
    );
    assert_eq!(
        deactivation(&tagged, CA, ORG).unwrap_err(),
        CtError::DeactivationNotDefined {
            type_id: TypeId::CBoTa1
        }
    );
    let untagged = Command::new(
        0x3000,
        CommandValue::Bitstring {
            bsi: Bsi { bits: 0 },
        },
    );
    assert!(deactivation(&untagged, CA, ORG).is_ok());

    // The controlled station answers the frame it cannot serve with clause
    // 7.2.3's cause-45 mirror.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Tagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut deact = activation(&tagged, CA, ORG).unwrap();
    deact[2] = 0x08; // cause 8 (deact), P/N = 0, T = 0
    let outcome = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownCause
        }
    );
    assert!(header_of(&outcome.send[0]).negative);
}

#[test]
fn a_deactivation_at_a_direct_station_is_refused_with_cause_45() {
    // 5-101 cl.7.4.7: "DEACT, DEACTCON is only used in case of a select and
    // execute function."
    let mut controlled = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut deact = activation(&single(0x3000, true, true), CA, ORG).unwrap();
    deact[2] = 0x08; // cause 8 (deact), P/N = 0, T = 0
    let outcome = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownCause
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::UnknownCause);
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");
}

#[test]
fn a_float_select_matches_its_execute_octet_for_octet() {
    // TS 60870-5-604 Table 19: the execute must "contain exactly the same
    // information as the SELECT message". For IEEE 754 that is the octets, not
    // `f32 ==`.
    let nan_bits = f32::from_bits(0x7FC0_0000);
    let select = CommandValue::SetPointFloat {
        r32: R32::from_raw(nan_bits),
        qos: Qos {
            ql: 0,
            select: true,
        },
    };
    let execute = CommandValue::SetPointFloat {
        r32: R32::from_raw(nan_bits),
        qos: Qos {
            ql: 0,
            select: false,
        },
    };
    assert!(
        select.state_eq(&execute),
        "the same NaN encoding is the same information"
    );
    let minus_zero = CommandValue::SetPointFloat {
        r32: R32::from_raw(-0.0),
        qos: Qos {
            ql: 0,
            select: true,
        },
    };
    let plus_zero = CommandValue::SetPointFloat {
        r32: R32::from_raw(0.0),
        qos: Qos {
            ql: 0,
            select: false,
        },
    };
    assert!(
        !minus_zero.state_eq(&plus_zero),
        "-0.0 and +0.0 are two different octet strings"
    );
}

#[test]
fn an_unsolicited_confirmation_records_nothing() {
    // The controlling station's state follows what it sent, not what arrives.
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let actcon = confirmation(&single(0x3000, true, true), false, CA, ORG, false).unwrap();
    let outcome = controlling
        .on_response(&actcon, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: false,
            test: false
        }
    );
    assert!(
        !controlling.is_selected(0x3000),
        "no select was sent, so none is recorded"
    );
    assert_eq!(
        controlling
            .execute(&single(0x3000, true, false))
            .unwrap_err(),
        CtError::ExecuteWithoutSelect { ioa: 0x3000 }
    );
}

#[test]
fn a_deactivation_must_repeat_the_select_it_stops() {
    // TS 60870-5-604 5.4.19.10: "The Controlling station sends the same Command
    // message with COT=8 … and S/E=1 (SELECT)".
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let select = controlling.select(&single(0x3000, true, false)).unwrap();
    let mirror = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    controlling
        .on_response(&mirror.send[0], &Known::EVERYTHING)
        .unwrap();

    // A different command state for the same address is not the select.
    assert_eq!(
        controlling
            .deactivate(&single(0x3000, false, false))
            .unwrap_err(),
        CtError::DeactivationMismatch { ioa: 0x3000 }
    );
    // The select's own command is, and the frame repeats it with S/E = 1.
    let deact = controlling
        .deactivate(&single(0x3000, true, false))
        .unwrap();
    assert_eq!(deact[9] & 0x80, 0x80, "S/E = 1: the select's own bit");
}

#[test]
fn the_controlled_station_answers_a_not_controllable_object() {
    // TS 60870-5-604 5.4.19.30/.50: the select or execute "for a not controllable
    // or not existing Information object" is answered with "the same ASDU with
    // COT=7, C_SC/DC/SE/RC_ACTCONneg (Negative ACTCON)". The caller decides what
    // "not controllable" means; `refuse` builds the answer.
    let controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let execute = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let outcome = controlled.refuse(&execute).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: true,
            test: false
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::ActivationCon);
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");
    assert_eq!(&outcome.send[0][6..], &execute[6..]);
    assert!(!controlled.is_running(0x3000));
}

// ------------------------------ which deactivations and mirrors are accepted

#[test]
fn the_tagged_bitstring_has_no_deactivation_confirmation() {
    // 5-104 figure 29 (PDF page index 88) lists neither cause 8 in the control
    // direction nor cause 9 in the monitor direction for C_BO_TA_1, so the
    // gate `deactivation` carries belongs on the mirror as well: a frame the
    // figure does not list cannot be built by this API.
    let tagged = Command::tagged(
        0x3000,
        CommandValue::Bitstring {
            bsi: Bsi { bits: 0 },
        },
        time(),
    );
    assert_eq!(
        deactivation_confirmation(&tagged, CA, ORG, false).unwrap_err(),
        CtError::DeactivationNotDefined {
            type_id: TypeId::CBoTa1
        }
    );
    // Its 5-101 twin does have one (figure 70, index 103), so the set decides.
    let untagged = Command::new(
        0x3000,
        CommandValue::Bitstring {
            bsi: Bsi { bits: 0 },
        },
    );
    let mirror = deactivation_confirmation(&untagged, CA, ORG, false).unwrap();
    assert_eq!(cause_of(&mirror), Cause::DeactivationCon);
}

#[test]
fn the_controlled_station_refuses_a_deactivation_that_is_not_the_select() {
    // TS 60870-5-604 5.4.19.10 (PDF page index 72): "The Controlling station
    // sends the same Command message with COT=8, C_SC/DC/SE/RC_DEACT, and
    // S/E=1 (SELECT) to the Controlled station". A DEACT that is another
    // command is refused with the same cause-45 mirror as the other DEACT
    // refusals, and the select stays outstanding.
    let mut controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut select = activation(&single(0x3000, true, true), CA, ORG).unwrap();
    select[2] = 0x06;
    let outcome = controlled.on_request(&select, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: false,
            test: false
        }
    );
    assert!(controlled.is_selected(0x3000));

    // Another family at the same address is not the selected command.
    let other = Command::new(
        0x3000,
        CommandValue::SetPointFloat {
            r32: R32::from_raw(3.5),
            qos: Qos {
                ql: 0,
                select: true,
            },
        },
    );
    let mut deact = activation(&other, CA, ORG).unwrap();
    deact[2] = 0x08; // cause 8 (deact), S/E = 1
    let outcome = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownCause
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::UnknownCause);
    assert_eq!(
        header_of(&outcome.send[0]).type_id,
        TypeId::CSeNc1,
        "the refused frame's own type is mirrored"
    );
    assert!(
        controlled.is_selected(0x3000),
        "the select survives a mismatch"
    );

    // Another state of the same family is not either.
    let mut deact = activation(&single(0x3000, false, true), CA, ORG).unwrap();
    deact[2] = 0x08;
    let outcome = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownCause
        }
    );
    assert!(controlled.is_selected(0x3000));

    // The select's own message deactivates, and clears the select.
    let mut deact = activation(&single(0x3000, true, true), CA, ORG).unwrap();
    deact[2] = 0x08;
    let outcome = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Deactivated {
            ioa: 0x3000,
            negative: false
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::DeactivationCon);
    assert!(!controlled.is_selected(0x3000));
}

#[test]
fn a_refused_deactivation_is_not_answered_with_an_activation_confirmation() {
    // 5-101 figure 64 lists <6> and <8> in the control direction and
    // <7>/<9>/<10>/44–47 in the monitor direction: there is no cause-7 answer
    // to a cause-8 request, so `refuse` follows the request's own cause.
    let controlled = CommandTransmission::controlled(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut deact = activation(&single(0x3000, true, true), CA, ORG).unwrap();
    deact[2] = 0x08;
    let outcome = controlled.refuse(&deact).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Refused {
            ioa: 0x3000,
            cause: Cause::UnknownCause
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::UnknownCause);
    assert_ne!(
        cause_of(&outcome.send[0]),
        Cause::ActivationCon,
        "a COT-8 request is not answered with COT 7"
    );
    assert!(header_of(&outcome.send[0]).negative, "P/N = 1");
    assert_eq!(&outcome.send[0][6..], &deact[6..]);

    // The activation path keeps 5.4.19.30's ACTCONneg.
    let execute = activation(&single(0x3000, true, false), CA, ORG).unwrap();
    let outcome = controlled.refuse(&execute).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: false,
            negative: true,
            test: false
        }
    );
    assert_eq!(cause_of(&outcome.send[0]), Cause::ActivationCon);
}

#[test]
fn a_select_mirror_that_differs_is_reported_not_confirmed() {
    // TS 60870-5-604 5.4.19.1: "If the SELECT message from the Controlling
    // station is not correctly mirrored by the Controlled station, then the
    // Controlling station does not proceed with sending the EXECUTE message."
    // The drop is the same as after a negative confirmation, but the caller is
    // told which of the two it was.
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let select = controlling.select(&single(0x3000, true, false)).unwrap();
    assert!(controlling.is_awaiting(0x3000));

    // The controlled station answers positively, but its mirror says OFF: not
    // the information the select carried.
    let wrong = confirmation(&single(0x3000, false, true), false, CA, ORG, false).unwrap();
    assert_ne!(
        &select[6..],
        &wrong[6..],
        "the mirror is the same ASDU with a different element"
    );
    let outcome = controlling.on_response(&wrong, &Known::EVERYTHING).unwrap();
    assert_eq!(outcome.reaction, Reaction::NotMirrored { ioa: 0x3000 });
    assert!(!controlling.is_awaiting(0x3000), "the select is dropped");
    assert!(!controlling.is_selected(0x3000));
    assert_eq!(
        controlling
            .execute(&single(0x3000, true, false))
            .unwrap_err(),
        CtError::ExecuteWithoutSelect { ioa: 0x3000 },
        "and it cannot be executed"
    );

    // A mirror that does repeat the select still confirms it.
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let sent = single(0x3000, true, false);
    let select = controlling.select(&sent).unwrap();
    assert_eq!(select[9] & 0x80, 0x80, "S/E = 1");
    let mirrored = confirmation(&sent.with_select(true), false, CA, ORG, false).unwrap();
    assert_eq!(&select[6..], &mirrored[6..], "the same information");
    let outcome = controlling
        .on_response(&mirrored, &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Confirmed {
            ioa: 0x3000,
            select: true,
            negative: false,
            test: false
        }
    );
    assert!(controlling.is_selected(0x3000));
}

// ------------------------------------ delay supervision, deactivating nothing

/// A tagged single command at `ioa`, initiated at `at`.
const fn tagged_single(ioa: u32, select: bool, at: Cp56Time2a) -> Command {
    let untagged = single(ioa, true, select);
    Command::tagged(ioa, untagged.value, at)
}

const fn controlled_tagged() -> CommandTransmission {
    CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Tagged,
        Termination::All,
        CA,
        ORG,
    )
    .with_max_command_delay(Duration::from_secs(5))
}

/// 104 cl.8: a command past the maximum allowable delay gets no protocol
/// response (neither ACTCON nor `ACTCONneg`), and nothing runs.
#[test]
fn a_command_past_the_maximum_delay_gets_no_response() {
    let mut station = controlled_tagged();
    let initiated = time();
    let frame = activation(&tagged_single(0x3000, false, initiated), CA, ORG).unwrap();
    let late = Cp56Time2a {
        milliseconds: initiated.milliseconds + 5_001,
        ..initiated
    };
    let outcome = station
        .on_request_at(&frame, &Known::EVERYTHING, Instant::now(), Some(late))
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::TooLate {
            ioa: 0x3000,
            time: initiated
        }
    );
    assert!(outcome.send.is_empty(), "no ACTCON of either sign");
    assert!(!station.is_running(0x3000));
    // The application still gets the whole command.
    let command = iec104::ct::decode_command(&frame).unwrap().unwrap();
    assert_eq!(command.ioa, 0x3000);
    assert_eq!(command.time, Some(initiated));
}

/// A tag with `IV` set, or with a field outside its clause 7.2.6.18 range, is
/// not the command's initiation time: it is refused as too late even when its
/// fields read as "now".
#[test]
fn a_command_with_an_invalid_or_malformed_tag_is_too_late() {
    let now = time();
    let invalid = Cp56Time2a {
        invalid: true,
        ..now
    };
    // Hour 30 of the day before would roll over to 06:30 of `now`'s day.
    let hour_30 = Cp56Time2a {
        hours: 30,
        day_of_month: now.day_of_month - 1,
        ..now
    };
    let six_thirty = Cp56Time2a { hours: 6, ..now };
    // April 31 would roll over to May 1.
    let april_31 = Cp56Time2a {
        day_of_month: 31,
        months: 4,
        ..now
    };
    let may_1 = Cp56Time2a {
        day_of_month: 1,
        months: 5,
        ..now
    };
    // Each wall clock is the instant its tag would read as, so only the
    // validity check can refuse it.
    for (tag, wall) in [(invalid, now), (hour_30, six_thirty), (april_31, may_1)] {
        let mut station = controlled_tagged();
        let frame = activation(&tagged_single(0x3000, false, tag), CA, ORG).unwrap();
        let outcome = station
            .on_request_at(&frame, &Known::EVERYTHING, Instant::now(), Some(wall))
            .unwrap();
        assert_eq!(
            outcome.reaction,
            Reaction::TooLate {
                ioa: 0x3000,
                time: tag
            },
            "{tag:?}"
        );
        assert!(outcome.send.is_empty(), "no ACTCON of either sign");
        assert!(!station.is_running(0x3000));
    }
}

/// Within the delay the command is served normally, and without a wall clock
/// (plain `on_request`) nothing is supervised.
#[test]
fn a_command_within_the_maximum_delay_is_served() {
    let initiated = time();
    let frame = activation(&tagged_single(0x3000, false, initiated), CA, ORG).unwrap();
    let in_time = Cp56Time2a {
        milliseconds: initiated.milliseconds + 5_000,
        ..initiated
    };
    let mut station = controlled_tagged();
    let outcome = station
        .on_request_at(&frame, &Known::EVERYTHING, Instant::now(), Some(in_time))
        .unwrap();
    assert!(matches!(
        outcome.reaction,
        Reaction::Confirmed {
            negative: false,
            ..
        }
    ));
    let mut unsupervised = controlled_tagged();
    let outcome = unsupervised.on_request(&frame, &Known::EVERYTHING).unwrap();
    assert!(matches!(outcome.reaction, Reaction::Confirmed { .. }));
}

/// The delay is measured across midnight, month and year boundaries.
#[test]
fn the_time_tag_arithmetic_crosses_calendar_boundaries() {
    let new_year = |years, months, day_of_month, hours, minutes, milliseconds| Cp56Time2a {
        years,
        months,
        day_of_month,
        hours,
        minutes,
        milliseconds,
        ..Default::default()
    };
    let before = new_year(25, 12, 31, 23, 59, 59_000);
    let after = new_year(26, 1, 1, 0, 0, 1_000);
    assert_eq!(
        after.millis_since_2000().unwrap() - before.millis_since_2000().unwrap(),
        2_000
    );
    assert_eq!(new_year(0, 1, 1, 0, 0, 0).millis_since_2000(), Some(0));
    // 2024 is a leap year: Feb 29 exists and March 1 is one day later.
    let feb29 = new_year(24, 2, 29, 0, 0, 0).millis_since_2000().unwrap();
    let mar1 = new_year(24, 3, 1, 0, 0, 0).millis_since_2000().unwrap();
    assert_eq!(mar1 - feb29, 86_400_000);
    assert_eq!(new_year(24, 13, 1, 0, 0, 0).millis_since_2000(), None);
    // Out-of-range fields are refused, not carried into the next field.
    assert_eq!(new_year(24, 10, 18, 30, 0, 0).millis_since_2000(), None);
    assert_eq!(new_year(24, 10, 0, 0, 0, 0).millis_since_2000(), None);
    assert_eq!(new_year(23, 2, 29, 0, 0, 0).millis_since_2000(), None);
    assert_eq!(new_year(24, 10, 1, 0, 60, 0).millis_since_2000(), None);
    assert_eq!(new_year(24, 10, 1, 0, 0, 60_000).millis_since_2000(), None);
}

/// A deactivation the station supports but with no select to stop is a
/// negative DEACTCON, not the cause-45 "unknown cause" mirror.
#[test]
fn deactivating_an_object_with_no_select_is_a_negative_deactcon() {
    let mut controlled = controlled_sbo();
    let command = single(0x3000, true, true);
    let deact = deactivation(&command, CA, ORG).unwrap();
    let outcome = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::NothingToDeactivate { ioa: 0x3000 }
    );
    let answer = header_of(&outcome.send[0]);
    assert_eq!(answer.cause, Cause::DeactivationCon);
    assert!(answer.negative, "P/N = 1");
}

/// `on_request_at` times a select from the moment it arrives, however long
/// ago the clock was last advanced.
#[test]
fn on_request_at_times_the_select_from_its_arrival() {
    let t0 = Instant::now();
    let mut controlled = controlled_sbo().with_select_timeout(Duration::from_secs(10));
    controlled.expire_selections(t0);
    let command = single(0x3000, true, false);
    let select = activation(&command.with_select(true), CA, ORG).unwrap();
    let arrival = t0 + Duration::from_secs(60);
    controlled
        .on_request_at(&select, &Known::EVERYTHING, arrival, None)
        .unwrap();
    assert_eq!(
        controlled.expire_selections(arrival + Duration::from_secs(9)),
        [] as [u32; 0]
    );
    assert!(controlled.is_selected(0x3000), "timed from its arrival");
}

// ------------------------------------------------------- shortcut builders

/// The activation header of every frame below: `VSQ` 1 object, cause `<6>`
/// activation, originator [`ORG`], common address [`CA`] little-endian, then
/// the three-octet address 4001 (`0x000FA1`) little-endian (5-101 cl.7.2.1 to
/// 7.2.5).
fn act_frame(type_id: u8, element: &[u8]) -> Vec<u8> {
    let mut frame = vec![type_id, 0x01, 0x06, ORG, CA as u8, 0x00, 0xA1, 0x0F, 0x00];
    frame.extend_from_slice(element);
    frame
}

/// The shortcut builders write the element each clause defines. `SCO`/`DCO`/
/// `RCO` put the state in bits 1–2 and `QOC` in bits 3–8 (`QU` `0x7C`, `S/E`
/// `0x80`, cl.7.2.6.15 to 7.2.6.17 and 7.2.6.26); the set-points are `NVA`
/// (`F16`, `0.5` is `0x4000`), `SVA` (`I16`) and IEEE 754 (`1.5` is
/// `0x3FC00000`) each followed by `QOS` `<0>`; the bitstring is `BSI`, all
/// little-endian. Type identifications 45 to 51 from 5-101 table 9.
#[test]
fn shortcut_builders_write_the_clause_elements() {
    let cases: [(Command, u8, &[u8]); 9] = [
        (Command::single(4001, true), 45, &[0x01]),
        (Command::single(4001, false), 45, &[0x00]),
        (
            Command::single(4001, true)
                .with_qualifier(CommandQualifier::ShortPulse)
                .with_select(true),
            45,
            &[0x85],
        ),
        (
            Command::double(4001, DoubleCommandState::On)
                .with_qualifier(CommandQualifier::LongPulse),
            46,
            &[0x0A],
        ),
        (
            Command::regulating_step(4001, RegulatingStepState::Higher)
                .with_qualifier(CommandQualifier::PersistentOutput),
            47,
            &[0x0E],
        ),
        (
            Command::set_point_normalized(4001, 0.5),
            48,
            &[0x00, 0x40, 0x00],
        ),
        (
            Command::set_point_scaled(4001, 1000),
            49,
            &[0xE8, 0x03, 0x00],
        ),
        (
            Command::set_point_float(4001, 1.5),
            50,
            &[0x00, 0x00, 0xC0, 0x3F, 0x00],
        ),
        (
            Command::bitstring(4001, 0x1234_5678),
            51,
            &[0x78, 0x56, 0x34, 0x12],
        ),
    ];
    for (command, type_id, element) in cases {
        assert_eq!(
            activation(&command, CA, ORG).unwrap(),
            act_frame(type_id, element),
            "{command:?}"
        );
    }
}

/// `QOS` has no `QU` (cl.7.2.6.39) and `BSI` has no qualifier, so a qualifier
/// leaves a set-point and a bitstring as they were.
#[test]
fn with_qualifier_leaves_families_without_qu_alone() {
    for command in [
        Command::set_point_scaled(4001, 7),
        Command::bitstring(4001, 1),
    ] {
        assert_eq!(command.with_qualifier(CommandQualifier::LongPulse), command);
    }
}

/// A time tag moves a command into the 5-104 set: `C_SC_TA_1` is `<58>` and its
/// object is the `SCO` followed by the seven-octet `CP56Time2a` (5-104 cl.8.1).
#[test]
fn with_time_selects_the_tagged_twin() {
    let command = Command::single(4001, true).with_time(time());
    assert_eq!(command.set(), CommandSet::Tagged);
    assert_eq!(command.type_id(), TypeId::CScTa1);
    let frame = activation(&command, CA, ORG).unwrap();
    assert_eq!(frame[0], 58);
    assert_eq!(frame[9], 0x01);
    assert_eq!(frame.len(), 9 + 1 + 7);
}

/// 5-101 cl.7.2.3: `P/N = 1` on the `DEACTCON` refuses the deactivation. The
/// station that lost the select answers so, and the controlling station
/// reports the refusal rather than a deactivation.
#[test]
fn a_negative_deactcon_is_reported_as_negative() {
    let mut controlling = CommandTransmission::controlling(
        CommandMode::SelectAndExecute,
        CommandSet::Untagged,
        Termination::All,
        CA,
        ORG,
    );
    let mut controlled = controlled_sbo();
    let command = single(0x3000, true, true);
    let select = controlling.select(&command).unwrap();
    let mirror = controlled_sbo()
        .on_request(&select, &Known::EVERYTHING)
        .unwrap();
    controlling
        .on_response(&mirror.send[0], &Known::EVERYTHING)
        .unwrap();
    // `controlled` never saw the select: it answers the DEACT negatively.
    let deact = controlling.deactivate(&command).unwrap();
    let answer = controlled.on_request(&deact, &Known::EVERYTHING).unwrap();
    let outcome = controlling
        .on_response(&answer.send[0], &Known::EVERYTHING)
        .unwrap();
    assert_eq!(
        outcome.reaction,
        Reaction::Deactivated {
            ioa: 0x3000,
            negative: true
        }
    );
    assert!(!controlling.is_selected(0x3000));
}
