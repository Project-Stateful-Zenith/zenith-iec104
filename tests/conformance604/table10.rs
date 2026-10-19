//! 604 Table 10, *"Data unit identifier conformance test procedures"* (1 of 2
//! and 2 of 2), PDF page indices 53–54 (printed 52–53), procedures `5.4.10.1`,
//! `5.4.10.5` and `5.4.10.10`.
//!
//! The rows are quoted verbatim from the pages named on each test. The
//! `Reference` column is `IEC 60870-5-101:2003` clause 7.3 for the type
//! identification, 7.2.3 for the cause of transmission and 7.2.4 for the common
//! address of ASDU.
//!
//! # Direction
//!
//! Each of the three procedures carries **two** mandatory halves, and §5.1
//! (index 10, printed 9) makes the direction part of the test: *"For testing
//! reverse direction, the same test procedures apply in the opposite direction
//! (replace "Controlling" with "Controlled" and vice versa), except for COT44-47
//! which are only defined in Monitor direction"*:
//!
//! - the **controlled**-station half (`COT44-47`, the mirror of 5-101 clause
//!   7.2.3) is driven over a real loopback socket by [`ControlledStation`], the
//!   role 5-101 clause 7.2.3 gives the mirror to ("mirrored by the controlled
//!   station with bit `P/N := <1>` negative confirm");
//! - the **controlling**-station half (*"Any undefined or not supported ASDU
//!   received by the controlling station is ignored (or discarded)"* on
//!   `5.4.10.1` and `.5`, *"The Controlling station handles any received ASDU
//!   with a Broadcast CASDU as an ASDU with an undefined CASDU"* on `.10`) is
//!   driven by the interoperability harness's [`interop::Station`] against the mock
//!   [`MonitorPeer`], and the station's verdict is the crate's monitor-direction
//!   rule, `asdu::unknown::discard_reason`.
//!
//! The broadcast CASDU cases tell a permitted type from a refused one, and the
//! irrelevant information object address 0 is a known address for the four
//! system types. The controlling-half samples of `.1`, `.5` and `.10` are the
//! **monitor**-direction ASDUs the rows are about (undefined types 41/42/43
//! with COT 3, `M_SP_NA_1` with the three undefined causes 14/15/43,
//! `M_SP_NA_1` at `FF FF`), the NOTEs' *"at least three"* applies to those rows
//! too, and the permitted-broadcast samples are built well formed (`QOI` 20,
//! `QCC` 5, a 7-octet `CP56Time2a`, `QRP` 1).
//!
//! The DUT is `asdu::unknown::mirror_reply` (the codec's clause 7.2.3 rule)
//! and, for the controlling half, `asdu::unknown::discard_reason`, driven over
//! a real loopback socket through `link::Session`, so each reply crosses a
//! wire end to end.

use crate::conformance604::{
    BROADCAST_TYPES, CA, HELD_IOA, ORIGINATOR, apci_of, asdu, asdu_test, asdu_with_body,
    controlling_discard, controlling_exchange, exchange, mirror_of,
};
use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{
    Cause, Cp56Time2a, Direction, Discard, FreezeMode, Header, Qcc, Qoi, Qrp, TypeId, Unspecified,
    cause_is_defined, type_is_defined,
};

/// The information object area 604 `5.4.10.10`'s permitted-broadcast samples
/// carry: the *irrelevant* information object address 0 of the four system types
/// (5-101 clause 7.2.5) followed by the one qualifier octet (`C_IC_NA_1`'s
/// `QOI`, `C_CI_NA_1`'s `QCC`, `C_RP_NA_1`'s `QRP`) or the 7-octet `CP56Time2a`
/// `C_CS_NA_1` carries, each value from its clause's own range.
fn broadcast_object_area(type_id: u8) -> Vec<u8> {
    // IOA 0: the address the standard calls *irrelevant* for these types, and
    // the one `station_profile` holds for them.
    let mut body = vec![0, 0, 0];
    match type_id {
        // C_IC_NA_1: QOI 20, station interrogation (5-101 cl.7.2.6.22).
        100 => body.push(Qoi::STATION_INTERROGATION),
        // C_CI_NA_1: QCC 5, general request counter with FRZ = 0, read
        // (5-101 cl.7.2.6.23; 0x14 would be the reserved RQT 20).
        101 => body.push(
            Qcc {
                rqt: Qcc::GENERAL_REQUEST,
                frz: FreezeMode::Read,
            }
            .raw(),
        ),
        // C_CS_NA_1: a CP56Time2a, Friday, 2026-09-25, 12:00:00.000, standard
        // time, genuine and valid (5-101 cl.7.2.6.24).
        103 => Cp56Time2a {
            milliseconds: 0,
            minutes: 0,
            substituted: false,
            invalid: false,
            hours: 12,
            summer_time: false,
            day_of_month: 25,
            day_of_week: 5,
            months: 9,
            years: 26,
        }
        .encode(&mut body),
        // C_RP_NA_1: QRP 1, general reset of process (5-101 cl.7.2.6.27;
        // 0x14 would be a reserved QRP).
        105 => body.push(Qrp::GENERAL_RESET),
        other => panic!("5.4.10.10: BROADCAST_TYPES is 100/101/103/105, not {other}"),
    }
    body
}

/// 604 Table 10 (1 of 2), PDF page index 53 (printed 52), procedure
/// **`5.4.10.1`**, `Test` column *"TYPE IDENTIFICATION"*, `Reference`
/// `IEC 60870-5-101:2003, 7.3`, `Required` `PICS, 9.5`, mandatory (`M`):
///
/// > If COT = 44 is supported, any undefined or not supported ASDU is mirrored
/// > by the controlled station with P/N = 1: negative confirmation of
/// > activation using COT = 44 (unknown type identification)
///
/// and the row's own NOTE, same page: *"These tests are performed correctly for
/// at least three undefined or not supported ASDUs. The test should include at
/// least one undefined ASDU. … Undefined ASDU = ASDU which is not defined by the
/// standard."*
///
/// DUT: the **controlled** station. The three type identifications 41, 42 and 43
/// are the standard's reserved gap 5-101 clause 7.2.1.1's `<41..44>`, so each is
/// undefined by the standard's own tables: `TypeId::info()` is `None` and
/// `type_is_defined` answers `false` for it. Three undefined ASDUs satisfy the
/// NOTE's "at least three undefined"; its *"If possible, the test should include
/// at least one ASDU defined in the standard, but not supported by the DUT"* is
/// **not possible** with this harness: the profile is `Known::standard`, a
/// station that implements everything the standard's tables define, so no ASDU
/// defined by the standard is unsupported here.
#[test]
fn clause_5_4_10_1_an_undefined_type_is_mirrored_with_cause_44() {
    // The row's NOTE: at least three undefined ASDUs. Each is a reserved type
    // identification of 5-101 clause 7.2.1.1, with cause 6 (activation), CA 1, a
    // held address and one payload octet that must survive the mirror unchanged.
    for type_id in [41u8, 42, 43] {
        assert!(
            !type_is_defined(TypeId::from_u8(type_id)),
            "5.4.10.1: type {type_id} must be one of the standard's reserved gaps"
        );
        let request = asdu(type_id, Cause::Activation.to_u8(), CA, HELD_IOA, 0xA5);
        let (apci, reply, report) =
            mirror_of(&request).unwrap_or_else(|why| panic!("5.4.10.1 (type {type_id}): {why}"));

        let header = Header::parse(&reply).expect("the mirror's header");
        assert_eq!(
            header.type_id.to_u8(),
            type_id,
            "5.4.10.1 (type {type_id}): the type identification is mirrored, not replaced"
        );
        assert_eq!(
            header.cause,
            Cause::UnknownTypeId,
            "5.4.10.1 (type {type_id}): \"using COT = 44 (unknown type identification)\""
        );
        assert_eq!(
            header.cause.to_u8(),
            44,
            "5.4.10.1 (type {type_id}): COT = 44"
        );
        assert!(
            header.negative,
            "5.4.10.1 (type {type_id}): \"mirrored … with P/N = 1\""
        );
        assert_eq!(
            header.common_address, CA,
            "5.4.10.1 (type {type_id}): the common address is echoed"
        );
        assert_eq!(
            header.originator, ORIGINATOR,
            "5.4.10.1 (type {type_id}): the originator address is echoed"
        );
        // "Mirrored" is a copy of the received ASDU, never a rebuild: an
        // undefined type has no layout to rebuild from, and 5-101 clause 7.2.3's
        // word is "mirrored".
        assert_eq!(
            &reply[Header::LEN..],
            &request[Header::LEN..],
            "5.4.10.1 (type {type_id}): the object area is copied octet for octet"
        );
        assert_eq!(
            apci,
            Apci::I {
                ns: SeqNo::new(0),
                nr: SeqNo::new(1)
            },
            "5.4.10.1 (type {type_id}): the mirror is the station's first I-frame and acknowledges ours"
        );
        assert_eq!(
            report.sent.len(),
            2,
            "5.4.10.1 (type {type_id}): the STARTDT con and the mirror, and nothing else"
        );
    }
}

/// The **controlling** station's half of the same procedure, same page,
/// `Required` `PIXIT`:
///
/// > Any undefined or not supported ASDU received by the controlling station is
/// > ignored (or discarded)
///
/// DUT: the **controlling** station. The same reserved type identifications (41,
/// 42 and 43, per the block's NOTE's *"at least three undefined or not supported
/// ASDUs"*, which sits under this row too) arrive in the monitor direction,
/// carried on COT 3 (`spont`), a cause of the monitor direction only, so the
/// sample is the traffic the row is about and not a control-direction ASDU fed
/// to a monitor-direction rule. The station's clause 7.2.3 verdict is
/// [`discard_reason`](iec104::asdu::discard_reason)'s
/// [`Discard::Unspecified`] with the type identification class, and no I-frame
/// goes back: the monitor direction mirrors nothing (5-101 clause 7.2.3's
/// table is the *control* direction's rule).
#[test]
fn clause_5_4_10_1_an_undefined_type_in_the_monitor_direction_is_discarded() {
    for type_id in [41u8, 42, 43] {
        assert!(
            !type_is_defined(TypeId::from_u8(type_id)),
            "5.4.10.1 (type {type_id}): the sample must be undefined by the standard's tables"
        );
        let monitor = asdu(type_id, Cause::Spontaneous.to_u8(), CA, HELD_IOA, 0xA5);
        let exchange = controlling_exchange(&monitor)
            .unwrap_or_else(|why| panic!("5.4.10.1 (type {type_id}): {why}"));
        assert_eq!(
            controlling_discard(&exchange.asdu).expect("the controlling station's answers"),
            Some(Discard::Unspecified(Unspecified::TypeIdentification)),
            "5.4.10.1 (type {type_id}): \"Any undefined or not supported ASDU received by the \
             controlling station is ignored (or discarded)\""
        );
        assert!(
            !exchange.sent.iter().any(|apci| apci.is_i_format()),
            "5.4.10.1 (type {type_id}): the discarded ASDU is not answered with an I-frame: {:?}",
            exchange.sent
        );
    }
}

/// 604 Table 10 (1 of 2), PDF page index 53 (printed 52), procedure
/// **`5.4.10.5`**, `Test` column *"CAUSE OF TRANSMISSION"*, `Reference`
/// `IEC 60870-5-101:2003, 7.2.3`, `Required` `PICS, 9.5`, mandatory (`M`):
///
/// > If COT=45 is supported, any undefined or not supported ASDU is mirrored by
/// > the controlled station with P/N = 1: negative confirmation of activation
/// > using COT = 45 (unknown cause of transmission)
///
/// and the row *"Originator address is zero or the applicable Originator
/// address"*, same page, same `Reference`; the NOTE wants *"at least three
/// undefined or not supported COTs"*, where *"Undefined COT = COT which is not
/// defined by the standard"*.
///
/// DUT: the **controlled** station. The causes 14, 15 and 43 are three of 5-101
/// table 14's reserved values (14–19 and 42–43), so `cause_is_defined` answers
/// `false` for each while the type identification (45, `C_SC_NA_1`) is one the
/// station implements. Three undefined causes satisfy the NOTE; its *"if
/// possible, one COT defined in the standard, but not supported by the DUT"* is
/// **not possible** here, because this harness's profile implements every cause
/// the standard's table defines.
#[test]
fn clause_5_4_10_5_an_undefined_cause_is_mirrored_with_cause_45() {
    // The row's NOTE: at least three undefined COTs. Each is a reserved value of
    // 5-101 table 14, carried on a defined type (45, C_SC_NA_1).
    for cause in [14u8, 15, 43] {
        assert!(
            !cause_is_defined(Cause::from_u8(cause)),
            "5.4.10.5: cause {cause} must be one of table 14's reserved values"
        );
        let request = asdu(0x2D, cause, CA, HELD_IOA, 0x01);
        let (_, reply, _) =
            mirror_of(&request).unwrap_or_else(|why| panic!("5.4.10.5 (cause {cause}): {why}"));

        let header = Header::parse(&reply).expect("the mirror's header");
        assert_eq!(
            header.type_id.to_u8(),
            0x2D,
            "5.4.10.5 (cause {cause}): the type identification is mirrored"
        );
        assert_eq!(
            header.cause,
            Cause::UnknownCause,
            "5.4.10.5 (cause {cause}): \"using COT = 45 (unknown cause of transmission)\""
        );
        assert_eq!(
            header.cause.to_u8(),
            45,
            "5.4.10.5 (cause {cause}): COT = 45"
        );
        assert!(
            header.negative,
            "5.4.10.5 (cause {cause}): \"mirrored … with P/N = 1\""
        );
        assert_eq!(
            header.originator, ORIGINATOR,
            "5.4.10.5 (cause {cause}): \"Originator address is zero or the applicable Originator \
             address\""
        );
        assert_eq!(
            &reply[Header::LEN..],
            &request[Header::LEN..],
            "5.4.10.5 (cause {cause}): the object area is copied octet for octet"
        );
    }
}

/// 604 Table 10 (1 of 2), PDF page index 53 (printed 52), procedure
/// **`5.4.10.5`**, `Test` column *"CAUSE OF TRANSMISSION"* (`test bit`), the
/// rows *"Test bit = 0: ASDU generated during normal conditions"* (`Required`
/// `M`) and *"Test bit = 1: ASDU generated during test conditions"*
/// (`Required` `PIXIT`), the page's `Required` column read cell by cell:
///
/// > Test bit = 0: ASDU generated during normal conditions
///
/// > Test bit = 1: ASDU generated during test conditions
///
/// DUT: the **controlled** station, and the observable is 5-101 clause 7.2.3's
/// T flag in the mirror: the clause's reply is *"mirrored"*, so the received
/// T flag comes back unchanged. The same undefined cause (15) is used for both
/// cases, so only the flag differs.
#[test]
fn clause_5_4_10_5_the_test_bit_is_echoed_in_the_mirror() {
    for test in [false, true] {
        let request = asdu_test(0x2D, 15, CA, HELD_IOA, 0x01, test);
        let (_, reply, _) = mirror_of(&request)
            .unwrap_or_else(|why| panic!("5.4.10.5 (Test bit = {}): {why}", u8::from(test)));

        let header = Header::parse(&reply).expect("the mirror's header");
        assert_eq!(
            header.test,
            test,
            "5.4.10.5 (Test bit = {}): the T flag is echoed in the mirror",
            u8::from(test)
        );
        assert_eq!(
            header.cause,
            Cause::UnknownCause,
            "5.4.10.5 (Test bit = {}): still the undefined cause's mirror",
            u8::from(test)
        );
    }
}

/// The **controlling** station's half of the same procedure, same page,
/// `Required` `PICS, 9.5` (the page's `Required` column for this row, which the
/// block's trailing `M` cell does not reach):
///
/// > Any message received by the controlling station containing an undefined or
/// > not supported COT is ignored (or discarded)
///
/// DUT: the **controlling** station. The ASDUs whose causes (14, 15 and 43, per
/// the block's NOTE, which sits under this row too) are three of 5-101 table
/// 14's reserved values arrive in the monitor direction. They carry `M_SP_NA_1`
/// (1), a **monitor**-direction type, so the sample is what a controlled
/// station actually sends, not a `C_SC_NA_1` command fed to a monitor-direction
/// rule. The station's verdict is [`Discard::Unspecified`] with the cause class,
/// and no I-frame goes back.
#[test]
fn clause_5_4_10_5_an_undefined_cause_in_the_monitor_direction_is_discarded() {
    assert_eq!(
        TypeId::from_u8(0x01).direction(),
        Some(Direction::Monitor),
        "5.4.10.5: the sample type must be a monitor-direction ASDU"
    );
    for cause in [14u8, 15, 43] {
        assert!(
            !cause_is_defined(Cause::from_u8(cause)),
            "5.4.10.5 (cause {cause}): the sample must be undefined by table 14"
        );
        let monitor = asdu(0x01, cause, CA, HELD_IOA, 0x01);
        let exchange = controlling_exchange(&monitor)
            .unwrap_or_else(|why| panic!("5.4.10.5 (cause {cause}): {why}"));
        assert_eq!(
            controlling_discard(&exchange.asdu).expect("the controlling station's answers"),
            Some(Discard::Unspecified(Unspecified::CauseOfTransmission)),
            "5.4.10.5 (cause {cause}): \"Any message received by the controlling station \
             containing an undefined or not supported COT is ignored (or discarded)\""
        );
        assert!(
            !exchange.sent.iter().any(|apci| apci.is_i_format()),
            "5.4.10.5 (cause {cause}): the discarded ASDU is not answered with an I-frame: {:?}",
            exchange.sent
        );
    }
}

/// 604 Table 10 (2 of 2), PDF page index 54 (printed 53), procedure
/// **`5.4.10.10`**, `Test` column *"COMMON ADDRESS of ASDU"*, `Reference`
/// `IEC 60870-5-101:2003, 7.2.4`, `Required` `PICS, 9.5`, mandatory (`M`):
///
/// > If COT=46 is supported, any ASDU with undefined CASDU is mirrored by the
/// > controlled station with P/N = 1: negative confirmation of activation using
/// > COT = 46 (unknown CASDU)
///
/// and the second of the block's rows, same page:
///
/// > The Controlled station rejects all other ASDU Types with a Broadcast CASDU
/// > value by mirroring the ASDU with P/N = 1 negative (and with COT = 46, if
/// > supported)
///
/// DUT: the **controlled** station, both halves. The station's own common
/// address is 1, so 9999 is undefined for it; and `C_SC_NA_1` (45) is not one of
/// the four types the broadcast address is allowed on, so the broadcast address
/// `FF FF` is refused the same way (5-101 clause 7.2.4's "specific defined
/// COMMON ADDRESS (station address)" read from the controlled side).
#[test]
fn clause_5_4_10_10_an_undefined_common_address_is_mirrored_with_cause_46() {
    // An address that is not the station's own.
    let request = asdu(0x2D, Cause::Activation.to_u8(), 9999, HELD_IOA, 0x01);
    let (_, reply, _) = mirror_of(&request).unwrap_or_else(|why| panic!("5.4.10.10: {why}"));

    let header = Header::parse(&reply).expect("the mirror's header");
    assert_eq!(
        header.common_address, 9999,
        "5.4.10.10: the common address is mirrored"
    );
    assert_eq!(
        header.cause.to_u8(),
        46,
        "5.4.10.10: \"using COT = 46 (unknown CASDU)\""
    );
    assert!(header.negative, "5.4.10.10: \"mirrored … with P/N = 1\"");

    // The broadcast half: 0xFF<FF> on a type that is not 100, 101, 103 or 105.
    let broadcast = asdu(0x2D, Cause::Activation.to_u8(), 0xFFFF, HELD_IOA, 0x01);
    let (_, reply, _) = mirror_of(&broadcast).unwrap_or_else(|why| panic!("5.4.10.10: {why}"));
    let header = Header::parse(&reply).expect("the mirror's header");
    assert_eq!(
        header.common_address, 0xFFFF,
        "5.4.10.10: the broadcast address is mirrored"
    );
    assert_eq!(
        header.cause.to_u8(),
        46,
        "5.4.10.10: \"mirroring the ASDU with P/N = 1 negative (and with COT = 46, if supported)\""
    );
    assert!(
        header.negative,
        "5.4.10.10: the broadcast refusal is negative"
    );
}

/// 604 Table 10 (2 of 2), PDF page index 54 (printed 53), procedure
/// **`5.4.10.10`**, `Test` column *"COMMON ADDRESS of ASDU"*, `Required` `PIXIT`:
///
/// > Broadcast CASDU value (0xFF<FF>) only used in control direction with ASDU
/// > Types 100 (Interrogation), 101 (Counter interrogation), 103 (Clock Sync) or
/// > 105 (Reset Process).
///
/// DUT: the **controlled** station. Each of the four system types carries the
/// *irrelevant* information object address 0 (5-101 clause 7.2.5), so at the
/// broadcast address it is a **known** common address and a **known** object:
/// the station answers nothing. Without this case, a profile that answered
/// "unknown address" for `FF FF` at every type would pass, because the broadcast
/// permission and the broadcast refusal would be the same code path.
///
/// Each sample is built **well formed** from the type's own layout, because the
/// claim is that a permitted broadcast is accepted: `C_IC_NA_1` carries
/// `QOI = 20` (station interrogation), `C_CI_NA_1` `QCC = 5` (general request
/// counter, `FRZ = 0`, 5-101 clause 7.2.6.23), `C_CS_NA_1` a 7-octet
/// `CP56Time2a` (5-101 clause 7.2.6.24) and `C_RP_NA_1` `QRP = 1` (general reset
/// of process, clause 7.2.6.27). The one-octet stand-in `asdu()` writes is
/// malformed for 103 in particular, whose object area is seven octets.
#[test]
fn clause_5_4_10_10_a_broadcast_casdu_on_a_permitted_type_is_not_rejected() {
    for type_id in BROADCAST_TYPES {
        let request = asdu_with_body(
            type_id,
            Cause::Activation.to_u8(),
            0xFFFF,
            &broadcast_object_area(type_id),
        );
        let exchange =
            exchange(&request, 1).unwrap_or_else(|why| panic!("5.4.10.10 (type {type_id}): {why}"));
        assert!(
            exchange.reply.is_none(),
            "5.4.10.10 (type {type_id}): a permitted broadcast ASDU is not mirrored: {:?}",
            exchange.reply
        );
        assert_eq!(
            exchange
                .report
                .sent
                .iter()
                .map(|frame| apci_of(frame).expect("a sent frame"))
                .collect::<Vec<_>>(),
            vec![Apci::U(UFunction::StartDtCon)],
            "5.4.10.10 (type {type_id}): the STARTDT con and nothing else"
        );
    }
}

/// The other half of the broadcast rows, same page: the *irrelevant* information
/// object address 0 (5-101 clause 7.2.5) is a **known** address for the four
/// system types at the station's own common address too, so a `C_IC_NA_1` the
/// station is asked for is not mirrored.
///
/// Without this, `station_profile`'s IOA-0 exception would only be reachable at
/// the broadcast address, and a station that treated the irrelevant address as
/// undefined would still pass the case above.
#[test]
fn clause_5_4_10_10_a_system_type_at_the_stations_own_address_is_not_mirrored() {
    let request = asdu(100, Cause::Activation.to_u8(), CA, 0, 0x14);
    let exchange = exchange(&request, 1).unwrap_or_else(|why| panic!("5.4.10.10 (own CA): {why}"));
    assert!(
        exchange.reply.is_none(),
        "5.4.10.10: C_IC_NA_1 at the station's own address with IOA 0 is not mirrored: {:?}",
        exchange.reply
    );
    assert_eq!(
        exchange
            .report
            .sent
            .iter()
            .map(|frame| apci_of(frame).expect("a sent frame"))
            .collect::<Vec<_>>(),
        vec![Apci::U(UFunction::StartDtCon)],
        "5.4.10.10: the STARTDT con and nothing else"
    );
}

/// The **controlling** station's half of the broadcast rows, same page,
/// `Required` `M`:
///
/// > The Controlling station handles any received ASDU with a Broadcast CASDU as
/// > an ASDU with an undefined CASDU
///
/// DUT: the **controlling** station. `M_SP_NA_1` (1), a **monitor**-direction
/// type so that the sample is the traffic a controlled station actually sends,
/// is addressed to `FF FF` and arrives in the monitor direction; the station's
/// verdict is [`Discard::Unspecified`] with the common-address class, and no
/// I-frame goes back. The cause is COT 3 (`spont`), a monitor-direction cause.
#[test]
fn clause_5_4_10_10_a_broadcast_casdu_in_the_monitor_direction_is_discarded() {
    assert_eq!(
        TypeId::from_u8(0x01).direction(),
        Some(Direction::Monitor),
        "5.4.10.10: the sample type must be a monitor-direction ASDU"
    );
    let monitor = asdu(0x01, Cause::Spontaneous.to_u8(), 0xFFFF, HELD_IOA, 0x01);
    let exchange = controlling_exchange(&monitor).unwrap_or_else(|why| panic!("5.4.10.10: {why}"));
    assert_eq!(
        controlling_discard(&exchange.asdu).expect("the controlling station's answers"),
        Some(Discard::Unspecified(Unspecified::CommonAddress)),
        "5.4.10.10: \"The Controlling station handles any received ASDU with a Broadcast CASDU as \
         an ASDU with an undefined CASDU\""
    );
    assert!(
        !exchange.sent.iter().any(|apci| apci.is_i_format()),
        "5.4.10.10: the discarded ASDU is not answered with an I-frame: {:?}",
        exchange.sent
    );
}
