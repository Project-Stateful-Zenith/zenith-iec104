//! 604 Table 25, *"Negative conformance test procedures"*, PDF page index 88
//! (printed 87), procedures `5.4.25.1` … `5.4.25.4`. Every row's `Required`
//! column reads `PIXIT`; `5.4.25.50` (*"COMPATIBILITY WITH OTHER TEST CASES"*,
//! `M`) is the whole suite, not a case.
//!
//! # `5.4.25.1`: not automated here
//!
//! > Establishing a connection by the controlling station having an IP address
//! > that is not known in the controlled station is not possible
//!
//! The crate's core opens and accepts no socket (it does no I/O at all), so the
//! station's list of known addresses and the refusal of any other one are the
//! transport's. The Tokio driver has the hook: `iec104_tokio::outstation::
//! serve_routed` hands each accepted connection's peer address to the
//! application's `route`, and closes a connection `route` refuses (`None`) at
//! once. That driver is a separate crate this suite does not depend on, so the
//! row is not driven here. The TLS crate's allow-list is a list of peer
//! **certificates**, not of IP addresses, so it is not this row either.
//!
//! # `5.4.25.4` and the summer-time bit
//!
//! The row's command half is driven below: the crate compares a command's time
//! tag with the station's clock as standard time, so both `SU` bits are taken
//! into account. Its event half (*"The time stamp of an event is recalculated and
//! the summer time bit is taken into account"*) is partly the application's:
//! the crate has no time zone and no calendar clock, so it cannot recalculate a
//! time stamp; what it owes is to carry the `SU` bit both ways unchanged, which
//! is what the event cases check.
//!
//! # Direction
//!
//! `5.4.25.2` and `5.4.25.4`'s events are driven in both roles. `5.4.25.3` and
//! `5.4.25.4`'s commands are about the station that receives a command, which
//! is the controlled one (5-101 clause 7.3.2: commands exist only in the
//! control direction); the controlling station's own side of `5.4.25.3` is
//! checked as well. No case sends one of the COT44-47 causes.

use std::time::Instant;

use crate::conformance604::table19::{
    CtApp, Master, command, command_at, controllable, mirrored, selectable, set_types, start,
    time_at,
};
use crate::conformance604::table19_controlling::{Dut, ScriptPeer};
use crate::conformance604::{
    CA, ControlledStation, StationApp, asdu_with_body, controlling_discard, controlling_exchange,
};
use iec104::asdu::{
    Cause, Cp56Time2a, Header, LayoutObject, MMeNb1, MSpTb1, Qds, Siq, Sva, TypeId, decode_asdu,
    encode_asdu,
};
use iec104::ct::{CommandMode, CommandSet, CtError, decode_command};

// ------------------------------------------------------------------ 5.4.25.2

/// The 32 combinations of the five quality bits, in the order of 5-101 clause
/// 7.2.6.3's `QDS := CP8{OV,RES,BL,SB,NT,IV}`: bit 0 of `n` is `OV`, then `BL`,
/// `SB`, `NT` and `IV`.
const fn qds(n: u8) -> Qds {
    Qds {
        overflow: n & 0x01 != 0,
        blocked: n & 0x02 != 0,
        substituted: n & 0x04 != 0,
        not_topical: n & 0x08 != 0,
        invalid: n & 0x10 != 0,
    }
}

/// The `QDS` octet clause 7.2.6.3 fixes for combination `n`: `OV :=
/// BS1[1]` (`0x01`), `RES := BS3[2..4]<0>`, `BL := BS1[5]` (`0x10`), `SB :=
/// BS1[6]` (`0x20`), `NT := BS1[7]` (`0x40`), `IV := BS1[8]` (`0x80`).
const fn qds_octet(n: u8) -> u8 {
    (n & 0x01) | ((n & 0x1E) << 3)
}

/// The information object address of combination `n`.
fn quality_ioa(n: u8) -> u32 {
    0x3000 + u32::from(n)
}

/// A controlled station whose application sends one `M_ME_NB_1` (5-101 clause
/// 7.3.1.11) with 32 objects, one per quality combination, built by the crate's
/// layout layer.
struct QualityApp {
    sent: bool,
}

impl StationApp for QualityApp {
    fn on_asdu(&mut self, _asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        Ok(Vec::new())
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        if self.sent {
            return Ok(Vec::new());
        }
        self.sent = true;
        let header = Header {
            type_id: TypeId::MMeNb1,
            sequence: false,
            count: 32,
            cause: Cause::Spontaneous,
            negative: false,
            test: false,
            originator: 0,
            common_address: CA,
        };
        let objects: Vec<LayoutObject<MMeNb1>> = (0..32)
            .map(|n| LayoutObject {
                ioa: quality_ioa(n),
                value: MMeNb1 {
                    sva: Sva { value: 0 },
                    qds: qds(n),
                },
            })
            .collect();
        Ok(vec![
            encode_asdu(&header, &objects).map_err(|e| format!("M_ME_NB_1: {e:?}"))?,
        ])
    }
}

/// 604 Table 25, PDF page index 88 (printed 87), procedure **`5.4.25.2`**,
/// *"Quality descriptor"*, `Required` `PIXIT`:
///
/// > The quality descriptor consist of five defined quality bits which can be
/// > set independently from each other
///
/// (5-101 clause 7.2.6.3, PDF page index 46: *"The quality descriptor consists
/// of five defined quality bits which may be set independently from each
/// other."*). DUT: the **controlled** station, which sends all 32 combinations
/// in one `M_ME_NB_1`; each object's `QDS` octet on the wire must be exactly
/// [`qds_octet`], the clause's bit positions, with the reserved bits 2–4 zero.
#[test]
fn clause_5_4_25_2_the_controlled_station_sets_each_quality_bit_independently() {
    let station = ControlledStation::start_app(QualityApp { sent: false }, Vec::new())
        .expect("the station binds");
    let mut master = Master::connect(&station);
    let asdu = master.recv("5.4.25.2: the measured values");
    master.close();
    station.join().expect("the station ends cleanly");

    assert_eq!(
        &asdu[..Header::LEN],
        &[11, 32, 3, 0, 1, 0],
        "5.4.25.2: M_ME_NB_1, SQ = 0 with 32 objects, spontaneous, common address 1"
    );
    // SQ = 0: each object is IOA (3 octets), SVA (2), QDS (1).
    let objects = &asdu[Header::LEN..];
    assert_eq!(objects.len(), 32 * 6, "5.4.25.2: 32 objects of six octets");
    for n in 0..32u8 {
        let object = &objects[usize::from(n) * 6..usize::from(n) * 6 + 6];
        assert_eq!(
            &object[..3],
            &quality_ioa(n).to_le_bytes()[..3],
            "5.4.25.2: the address of combination {n}"
        );
        assert_eq!(
            object[5],
            qds_octet(n),
            "5.4.25.2: combination {n:05b} (IV NT SB BL OV) sets exactly its own bits"
        );
    }
}

/// The same row, **controlling** station: the mock controlled station sends the
/// same 32 combinations, octet by octet from clause 7.2.6.3, and the crate
/// reads each of the five bits on its own. The ASDU is processed, not
/// discarded (5-101 clause 7.2.3).
#[test]
fn clause_5_4_25_2_the_controlling_station_reads_each_quality_bit_independently() {
    let mut body = Vec::new();
    for n in 0..32u8 {
        body.extend_from_slice(&quality_ioa(n).to_le_bytes()[..3]);
        body.extend_from_slice(&[0x00, 0x00, qds_octet(n)]);
    }
    let mut asdu = asdu_with_body(11, 3, CA, &body);
    asdu[1] = 32; // VSQ: SQ = 0, 32 objects
    let exchange = controlling_exchange(&asdu).expect("the monitor exchange");
    assert_eq!(exchange.asdu, asdu, "5.4.25.2: the ASDU arrived as sent");
    assert_eq!(
        controlling_discard(&exchange.asdu).expect("the verdict"),
        None,
        "5.4.25.2: the ASDU is processed"
    );
    let objects = decode_asdu::<MMeNb1>(&exchange.asdu).expect("M_ME_NB_1 decodes");
    assert_eq!(objects.len(), 32);
    for (n, object) in (0..32u8).zip(&objects) {
        assert_eq!(object.ioa, quality_ioa(n));
        assert_eq!(
            object.value.qds,
            qds(n),
            "5.4.25.2: combination {n:05b} (IV NT SB BL OV) reads back bit for bit"
        );
    }
}

// ------------------------------------------------------------------ 5.4.25.3

/// 604 Table 25, PDF page index 88 (printed 87), procedure **`5.4.25.3`**,
/// *"Command transmission"*, `Required` `PIXIT`:
///
/// > Direct Execute commands sent to an object configured as Select before
/// > Operate command are answered with ACT_CON_NEG and not executed by the
/// > controlled station
///
/// DUT: the **controlled** select-and-execute station, both sets, the six
/// selectable types: an execute with no select before it is mirrored with cause
/// 7 and `P/N = 1`, and nothing executes. The bitstring (`<51>`, `<64>`) has no
/// `S/E` bit (5-101 figure 70), so it cannot be configured as select before
/// operate and is not part of the row.
#[test]
fn clause_5_4_25_3_a_direct_execute_of_a_select_before_operate_object_is_negative() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let (station, log) = start(CtApp::new(CommandMode::SelectAndExecute, set));
        let mut master = Master::connect(&station);
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            let execute = command(type_id, controllable(type_id), false);
            master.send(&execute);
            assert_eq!(
                master.recv("5.4.25.3: the answer"),
                mirrored(&execute, 7, true),
                "5.4.25.3 (type {type_id}): \"answered with ACT_CON_NEG\""
            );
        }
        let log = crate::conformance604::table19::finish(master, station, &log);
        assert!(
            log.executed.is_empty(),
            "5.4.25.3 ({set:?}): \"not executed by the controlled station\": {:?}",
            log.executed
        );
    }
}

/// The same row seen from the **controlling** station: a station configured
/// for select before operate does not send a direct execute of a selectable
/// type at all. The crate refuses to build it, and the peer receives nothing.
#[test]
fn clause_5_4_25_3_the_controlling_station_does_not_direct_execute_a_select_before_operate_object()
{
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let peer = ScriptPeer::start(Box::new(|_: &[u8]| Vec::new()));
        let mut dut = Dut::open(&peer, CommandMode::SelectAndExecute, set);
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            let ioa = controllable(type_id);
            let command = decode_command(&command(type_id, ioa, false))
                .expect("decodes")
                .expect("a command");
            assert_eq!(
                dut.ct.execute(&command),
                Err(CtError::ExecuteWithoutSelect { ioa }),
                "5.4.25.3 (type {type_id}): no direct execute of a select-before-operate object"
            );
        }
        assert!(
            dut.close(peer).is_empty(),
            "5.4.25.3 ({set:?}): nothing went out"
        );
    }
}

// ------------------------------------------------------------------ 5.4.25.4

/// Whether a time-tagged direct-execute station whose clock reads `wall` (and
/// whose maximum command delay is ten seconds) accepts each of the seven
/// time-tagged commands tagged `tag`, one answer per type.
///
/// After each command a probe follows whose tag equals the station's clock
/// exactly; the answers up to the probe's `ACTCON` show whether the command
/// was answered (accepted) or not (5-104 clause 8: no answer at all). The
/// application's record of executed objects must agree.
fn accepted(tag: Cp56Time2a, wall: Cp56Time2a) -> Vec<bool> {
    let (station, log) =
        start(CtApp::new(CommandMode::Direct, CommandSet::Tagged).with_wall_clock(wall));
    let mut master = Master::connect(&station);
    let mut verdicts = Vec::new();
    for type_id in set_types(CommandSet::Tagged) {
        let request = command_at(type_id, controllable(type_id), false, tag);
        let probe = command_at(type_id, controllable(type_id) + 0x100, false, wall);
        master.send(&request);
        master.send(&probe);
        let mut answered = false;
        loop {
            let asdu = master.recv("5.4.25.4: the answers up to the probe's");
            if asdu == mirrored(&probe, 7, false) {
                break;
            }
            answered |= asdu == mirrored(&request, 7, false);
        }
        verdicts.push(answered);
    }
    let log = crate::conformance604::table19::finish(master, station, &log);
    for (type_id, verdict) in set_types(CommandSet::Tagged).into_iter().zip(&verdicts) {
        assert_eq!(
            log.executed.contains(&controllable(type_id)),
            *verdict,
            "5.4.25.4 (type {type_id}): the execution agrees with the answer"
        );
    }
    verdicts
}

/// 604 Table 25, PDF page index 88 (printed 87), procedure **`5.4.25.4`**,
/// *"Summer time – Summer time bit is taken into account when using commands
/// and events"*, `Required` `PIXIT`:
///
/// > A command using summer time bit shall be used to either accept or ignore
/// > the command based on its configured acceptable delay for command
/// > transmission
///
/// with the row's second example, *"A command sent with SU-bit =1 (in summer
/// time) and time 15:00:000 is NOT executed (ignored) by the DUT when its time is
/// 14:00:000 in summer time"*, and the row's combinations *"sending station not
/// in summer time, receiving station not in summer time"* and *"sending station
/// in summer time, receiving station in summer time"* at a delay of two seconds
/// (inside the station's ten-second maximum, 5-104 clause 8).
///
/// DUT: the **controlled** station, the seven time-tagged types. These are the
/// combinations where both clocks keep the same time, so the `SU` bit changes
/// nothing: the crate passes them.
#[test]
fn clause_5_4_25_4_a_command_in_the_stations_own_time_is_judged_by_its_delay() {
    assert_eq!(
        accepted(time_at(12, 0, 0, false), time_at(12, 0, 2_000, false)),
        vec![true; 7],
        "5.4.25.4: not in summer time on both sides, two seconds late: executed"
    );
    assert_eq!(
        accepted(time_at(13, 0, 0, true), time_at(13, 0, 2_000, true)),
        vec![true; 7],
        "5.4.25.4: in summer time on both sides, two seconds late: executed"
    );
    assert_eq!(
        accepted(time_at(15, 0, 0, true), time_at(14, 0, 0, true)),
        vec![false; 7],
        "5.4.25.4, the second example: SU = 1 15:00 at a DUT on 14:00 summer time is ignored"
    );
}

/// The same row, the combinations across the summer-time change, where the
/// `SU` bit decides: 15:00 summer time is 14:00 standard time (one hour
/// ahead), so
///
/// - the row's first example, *"A command sent with SU-bit =1 (in summer time)
///   and time 15:00:000 is executed by the DUT when its time is 14:00:000 not in
///   summer time"*;
/// - *"sending station not in summer time, receiving station in summer time"*:
///   tagged 12:00:00 standard at a DUT reading 13:00:02 summer time, two
///   seconds later;
/// - *"sending station in summer time, receiving station not in summer time"*:
///   tagged 13:00:00 summer time at a DUT reading 12:00:02 standard time;
///
/// are all executed, and a command tagged 12:00:00 **summer** time (11:00:00
/// standard) at a DUT reading 12:00:02 standard time is an hour late and is
/// ignored.
///
/// DUT: the **controlled** station, the seven time-tagged types.
///
/// `CommandTransmission::on_request_at` compares the tag with the station's
/// clock as standard time (`Cp56Time2a::standard_millis_since_2000`). Before
/// it did, it ignored the `SU` bit: each of the first three commands was judged
/// an hour off and ignored, and the fourth two seconds late and executed.
#[test]
fn clause_5_4_25_4_a_command_across_the_summer_time_change_is_judged_in_one_time() {
    assert_eq!(
        accepted(time_at(15, 0, 0, true), time_at(14, 0, 0, false)),
        vec![true; 7],
        "5.4.25.4, the first example: SU = 1 15:00 at a DUT on 14:00 standard time is executed"
    );
    assert_eq!(
        accepted(time_at(12, 0, 0, false), time_at(13, 0, 2_000, true)),
        vec![true; 7],
        "5.4.25.4: sender not in summer time, receiver in summer time, two seconds late"
    );
    assert_eq!(
        accepted(time_at(13, 0, 0, true), time_at(12, 0, 2_000, false)),
        vec![true; 7],
        "5.4.25.4: sender in summer time, receiver not in summer time, two seconds late"
    );
    assert_eq!(
        accepted(time_at(12, 0, 0, true), time_at(12, 0, 2_000, false)),
        vec![false; 7],
        "5.4.25.4: 12:00 summer time is 11:00 standard time, an hour late at 12:00:02"
    );
}

/// A controlled station whose application sends one `M_SP_TB_1` (5-101 clause
/// 7.3.1.22) at address `0x3000`, `SPI` ON, cause 3, with the time tag `time`.
struct EventApp {
    time: Cp56Time2a,
    sent: bool,
}

impl StationApp for EventApp {
    fn on_asdu(&mut self, _asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        Ok(Vec::new())
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        if self.sent {
            return Ok(Vec::new());
        }
        self.sent = true;
        let header = Header {
            type_id: TypeId::MSpTb1,
            sequence: false,
            count: 1,
            cause: Cause::Spontaneous,
            negative: false,
            test: false,
            originator: 0,
            common_address: CA,
        };
        let object = LayoutObject {
            ioa: 0x3000,
            value: MSpTb1 {
                siq: Siq {
                    spi: true,
                    ..Default::default()
                },
                time: self.time,
            },
        };
        Ok(vec![
            encode_asdu(&header, &[object]).map_err(|e| format!("M_SP_TB_1: {e:?}"))?,
        ])
    }
}

/// The octets 5-101 clause 7.2.6.18 fixes for 15:00:00.000 on Friday
/// 2026-09-25, with `SU` as given: milliseconds `00 00`, minutes `00`, hours 15
/// (`0x0F`) with `SU` in bit 8 (`0x80`), day of month 25 with day of week 5 in
/// bits 6–8 (`0xB9`), months `09`, years 26 (`0x1A`).
const fn event_time_octets(summer_time: bool) -> [u8; 7] {
    let hours = 0x0F | if summer_time { 0x80 } else { 0 };
    [0x00, 0x00, 0x00, hours, 0xB9, 0x09, 0x1A]
}

/// 604 Table 25, PDF page index 88, procedure `5.4.25.4`, the event half:
///
/// > The time stamp of an event is recalculated and the summer time bit is
/// > taken into account to define the valid time stamp for the receiving
/// > station.
///
/// DUT: the **controlled** station sending an event, both `SU` states. The
/// recalculation is the receiver's; what the sender owes is the `SU` bit in its
/// place (5-101 clause 7.2.6.18: *"The summer-time bit SU may optionally be used
/// as an additional information to indicate the presently valid time (standard
/// or summer-time)."*, PDF page index 52), which the octets on the wire must
/// carry.
#[test]
fn clause_5_4_25_4_the_controlled_station_sends_the_summer_time_bit_of_an_event() {
    for summer_time in [false, true] {
        let app = EventApp {
            time: time_at(15, 0, 0, summer_time),
            sent: false,
        };
        let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
        let mut master = Master::connect(&station);
        let asdu = master.recv("5.4.25.4: the event");
        master.close();
        station.join().expect("the station ends cleanly");
        assert_eq!(asdu[0], 30, "5.4.25.4: M_SP_TB_1");
        assert_eq!(
            asdu[asdu.len() - 7..],
            event_time_octets(summer_time),
            "5.4.25.4 (SU = {summer_time}): the time tag carries the SU bit"
        );
    }
}

/// The same, **controlling** station: the mock controlled station sends the
/// event octet by octet in both `SU` states, and the crate reads the bit back
/// with the time as sent, so the application that recalculates the time stamp
/// has it.
#[test]
fn clause_5_4_25_4_the_controlling_station_reads_the_summer_time_bit_of_an_event() {
    for summer_time in [false, true] {
        let mut body = vec![0x00, 0x30, 0x00, 0x01];
        body.extend_from_slice(&event_time_octets(summer_time));
        let asdu = asdu_with_body(30, 3, CA, &body);
        let exchange = controlling_exchange(&asdu).expect("the monitor exchange");
        assert_eq!(
            controlling_discard(&exchange.asdu).expect("the verdict"),
            None,
            "5.4.25.4: the event is processed"
        );
        let objects = decode_asdu::<MSpTb1>(&exchange.asdu).expect("M_SP_TB_1 decodes");
        assert_eq!(
            objects[0].value.time,
            time_at(15, 0, 0, summer_time),
            "5.4.25.4 (SU = {summer_time}): the time tag and its SU bit read back"
        );
    }
}
