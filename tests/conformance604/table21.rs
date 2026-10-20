//! 604 Table 21, *"Parameter loading function conformance test procedures"*,
//! PDF page index 82 (printed 81): procedures `5.4.21.1`, `5.4.21.10`,
//! `5.4.21.15` and `5.4.21.20`. The rows' `Reference` column names
//! `IEC 60870-5-5:1995, 6.10.1`, `IEC 60870-5-101:2003, 7.4.9` (the selection
//! from parameter loading), `7.2.6.25` (`QPA`) and `8.5, 8.6` (the ASDU set).
//!
//! # What is the library's, and what is the application's
//!
//! The library's part is `pm`: it classifies a received `P_ME`/`P_AC` (5-101
//! clause 7.3.5), decides which answer the standard draws, and builds it. The
//! **value now in operation** is the application's: 5-101 clause 7.4.9 says the
//! `ACTCON` carries whichever value of the parameter, new or old, is in
//! operation, and the crate keeps no parameter state. So the controlled
//! station under test runs [`ParamApp`], glue that stores the value `pm` reports
//! as loaded and hands back the stored value when `pm` reports a load it must
//! not activate. The decisions (accept, refuse as infeasible, refuse a `QPA`)
//! and the frames are the library's.
//!
//! The station holds one parameter per type and kind of parameter (`KPA`
//! `<1>` to `<4>`, 5-101 clause 7.2.6.24) at [`HELD_IOA`]; `P_AC_NA_1` addresses
//! that object too, or address 0 for `QPA = <1>` (clause 7.2.6.25: that value
//! switches the previously loaded parameters as a whole, at address 0).
//!
//! # Direction
//!
//! Each procedure is driven with the library as the **controlled** station (a
//! `ControlledStation` running [`ParamApp`], against the mock controlling
//! station `Peer`) and, per §5.1, as the **controlling** station
//! (`interop::Station` running `pm`, against the mock controlled station
//! `ScriptedPeer`). 5.4.21.15 allows cause 44 in the answer; the library
//! answers with cause 7 there, so §5.1's exception is not reached.
//!
//! # Not automated
//!
//! - The row that the values the controlling station receives and stores
//!   should be the controlled station's actual values (`M`): storing is the controlling station's application. The
//!   controlling-station cases check that the library reports the value the
//!   confirmation carried, which is what such an application stores.
//! - `5.4.21.10`'s allowance to skip the test when every value of the
//!   supported parameters counts as valid: which values beyond the
//!   standard's own rule are feasible is the device's. The cases drive the one
//!   rule the row states for every station (a negative threshold value or
//!   smoothing factor).
//! - `5.4.21.20`, *"COMPATIBILITY WITH OTHER TEST CASES"*: the whole suite, not a
//!   case (see `tests/conformance_604.rs`).

use std::sync::{Arc, Mutex};

use crate::conformance604::scripted::{
    Link, ScriptedPeer, started_station, station_recv_n, station_send,
};
use crate::conformance604::{
    CA, ControlledStation, HELD_IOA, ORIGINATOR, StationApp, asdu_with_body, station_reply,
};
use iec104::asdu::{Header, Known, Nva, Qpa, Qpm, R32, Sva, TypeId, read_ioa};
use iec104::pm::{
    LocalChange, Parameter, ParameterLoading, ParameterValue, PmError, Reaction, is_parameter_type,
};

/// The P/N bit of the cause-of-transmission octet (5-101 clause 7.2.3: bit 7,
/// `<1>` negative confirmation).
const PN: u8 = 0x40;

/// The three parameter-of-measured-values types (5-101 clause 7.3.5.1 to
/// 7.3.5.3): `P_ME_NA_1`, `P_ME_NB_1`, `P_ME_NC_1`.
const P_ME_TYPES: [u8; 3] = [110, 111, 112];

/// The four kinds of parameter of 5-101 clause 7.2.6.24: `<1>` threshold value,
/// `<2>` smoothing factor, `<3>` low limit, `<4>` high limit.
const KINDS: [u8; 4] = [1, 2, 3, 4];

/// One value of a `P_ME` type: `n` picks a number from which the element is
/// written. The value octets come from the element definitions, not the crate:
/// `NVA` is an `F16` (clause 7.2.6.6), `SVA` an `I16` (7.2.6.7), both two
/// octets, least significant first; `R32` is an IEEE 754 single (7.2.6.8),
/// four octets, least significant first.
#[derive(Debug, Clone, Copy)]
struct Value {
    type_id: u8,
    kpa: u8,
    n: i16,
}

impl Value {
    fn float(self) -> f32 {
        f32::from(self.n) / 4.0
    }

    /// The element octets: the value then `QPM`, whose `KPA` is bits 1 to 6 and
    /// whose `LPC` and `POP` are zero (clause 7.2.6.24: the standard does not
    /// use them and sets both to zero).
    fn octets(self) -> Vec<u8> {
        let mut out = match self.type_id {
            110 | 111 => self.n.to_le_bytes().to_vec(),
            112 => self.float().to_le_bytes().to_vec(),
            other => panic!("not a P_ME type: {other}"),
        };
        out.push(self.kpa);
        out
    }

    /// The same value as the library's typed element, for its reactions.
    fn typed(self) -> ParameterValue {
        let qpm = Qpm {
            kpa: self.kpa,
            ..Qpm::default()
        };
        match self.type_id {
            110 => ParameterValue::Normalized {
                nva: Nva { value: self.n },
                qpm,
            },
            111 => ParameterValue::Scaled {
                sva: Sva { value: self.n },
                qpm,
            },
            _ => ParameterValue::Float {
                r32: R32 {
                    value: self.float(),
                },
                qpm,
            },
        }
    }
}

/// The value the station holds for `type_id`/`kpa` before any load.
fn initial(type_id: u8, kpa: u8) -> Value {
    Value {
        type_id,
        kpa,
        n: 100 * i16::from(kpa),
    }
}

/// A new, positive value for `type_id`/`kpa`, distinct from [`initial`].
fn fresh(type_id: u8, kpa: u8, round: i16) -> Value {
    Value {
        type_id,
        kpa,
        n: 1_000 * round + i16::from(kpa),
    }
}

/// One `P_ME` ASDU as 5-101 figures 79 to 81 draw it: `SQ = 0`, `N = 1`, the
/// cause octet given (P/N included), the common address, the three-octet
/// information object address, the value and `QPM`.
fn p_me(cause: u8, value: Value) -> Vec<u8> {
    let mut body = HELD_IOA.to_le_bytes()[..3].to_vec();
    body.extend(value.octets());
    with_flags(
        asdu_with_body(value.type_id, cause & 0x3F, CA, &body),
        cause,
    )
}

/// Writes the `P/N` and `T` bits of the cause octet `cause` (5-101 clause
/// 7.2.3: bits 7 and 8) into the ASDU's third octet, which the header builder
/// takes as a cause of transmission only.
fn with_flags(mut asdu: Vec<u8>, cause: u8) -> Vec<u8> {
    asdu[2] |= cause & 0xC0;
    asdu
}

/// One `P_AC_NA_1` ASDU as 5-101 figure 82 draws it: the information object
/// address and the `QPA` octet.
fn p_ac(cause: u8, ioa: u32, qpa: u8) -> Vec<u8> {
    let mut body = ioa.to_le_bytes()[..3].to_vec();
    body.push(qpa);
    asdu_with_body(113, cause, CA, &body)
}

/// The station's answers for a received parameter ASDU: the standard's types
/// and causes, its own common address, and the objects it holds, [`HELD_IOA`]
/// plus address 0 for a `P_AC_NA_1` (clause 7.2.6.25's `QPA = <1>` addresses
/// object 0).
fn param_known(asdu: &[u8]) -> Result<Known, String> {
    let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
    let ioa = read_ioa(&asdu[Header::LEN..]).map_err(|e| format!("the address: {e:?}"))?;
    Ok(Known::standard(
        &header,
        header.common_address == CA,
        ioa == HELD_IOA || (header.type_id == TypeId::PAcNa1 && ioa == 0),
    ))
}

// ------------------------------------------ the controlled station's glue

/// The controlled station's application for Table 21: the library's `pm`
/// answers every parameter ASDU. The glue keeps the values in operation (the
/// crate keeps none), updates one when `pm` reports it loaded, and answers a
/// load `pm` reports infeasible through `pm`'s own refusal with the value still
/// in operation.
pub struct ParamApp {
    pm: ParameterLoading,
    image: Vec<Parameter>,
    log: Arc<Mutex<Vec<Reaction>>>,
}

impl ParamApp {
    fn new() -> (Self, Arc<Mutex<Vec<Reaction>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let image = P_ME_TYPES
            .iter()
            .flat_map(|&t| KINDS.iter().map(move |&k| initial(t, k)))
            .map(|v| Parameter::new(HELD_IOA, v.typed()))
            .collect();
        let app = Self {
            pm: ParameterLoading::controlled(LocalChange::NotUsed, CA, ORIGINATOR),
            image,
            log: Arc::clone(&log),
        };
        (app, log)
    }

    /// The slot of the parameter of `value`'s type and kind.
    fn slot(&mut self, value: ParameterValue) -> Option<&mut Parameter> {
        let kpa = value.qpm().map(|q| q.kpa);
        self.image
            .iter_mut()
            .find(|p| p.type_id() == value.type_id() && p.qpm().map(|q| q.kpa) == kpa)
    }
}

impl StationApp for ParamApp {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
        if !is_parameter_type(header.type_id) {
            return Ok(station_reply(asdu)?.into_iter().collect());
        }
        let outcome = self
            .pm
            .on_request(asdu, &param_known(asdu)?)
            .map_err(|e| format!("pm: {e:?}"))?;
        self.log
            .lock()
            .expect("the log")
            .push(outcome.reaction.clone());
        match outcome.reaction {
            Reaction::Loaded { value, .. } => {
                let slot = self.slot(value).ok_or("no such parameter")?;
                slot.value = value;
                Ok(outcome.send)
            }
            Reaction::Infeasible { value, .. } => {
                let old = *self.slot(value).ok_or("no such parameter")?;
                let refusal = self
                    .pm
                    .refuse(asdu, &old)
                    .map_err(|e| format!("pm: {e:?}"))?;
                Ok(refusal.send)
            }
            _ => Ok(outcome.send),
        }
    }
}

/// Starts a controlled station running [`ParamApp`] and connects the mock
/// controlling station to it.
fn controlled() -> (ControlledStation, Link, Arc<Mutex<Vec<Reaction>>>) {
    let (app, log) = ParamApp::new();
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let link = Link::start(station.addr()).expect("the controlling station starts");
    (station, link, log)
}

/// Closes the link and waits for the station, failing on its own error.
fn end(station: ControlledStation, link: Link) {
    link.finish().expect("the peer closes");
    station.join().expect("the station ends cleanly");
}

// ------------------------------------------------------------- 5.4.21.1

/// 604 Table 21, PDF page index 82 (printed 81), procedure **`5.4.21.1`**,
/// *"Parameter loading – sequential procedure: Load and activate parameter"*,
/// every row `Required` `M`:
///
/// - the controlling station sends a parameter command (an ASDU its PICS
///   lists) to the controlled station with cause 6 (`ACT`);
/// - once checked as feasible and valid, the parameter is loaded and takes
///   effect at once;
/// - the controlled station mirrors the ASDU back with cause 7, positive
///   (`ACTCONpos`), carrying the parameter value now in operation, which here
///   is the new value, not the old one;
/// - that value in the `ACTCON` equals the parameter the controlled station
///   operates with (checked for plausibility);
/// - the tests run for every ASDU of the PICS that supports the cause in
///   question, and for each supported parameter (threshold, smoothing factor,
///   high and low limit).
///
/// DUT: the **controlled** station. Every `P_ME` type (110, 111, 112) with every
/// kind of parameter (`KPA` 1 to 4), then `P_AC_NA_1` with `QPA = <3>`, the one
/// value clause 7.4.9 selects. Each confirmation is the request's own octets
/// with the cause octet 7 (`P/N = 0`); the library reports each load with the
/// value it confirms, which is the value the application puts in operation.
#[test]
fn clause_5_4_21_1_a_loaded_parameter_is_confirmed_with_the_new_value() {
    let (station, mut link, log) = controlled();
    let mut loads = Vec::new();
    for type_id in P_ME_TYPES {
        for kpa in KINDS {
            let what = format!("5.4.21.1 (type {type_id}, KPA {kpa})");
            let value = fresh(type_id, kpa, 1);
            link.send(&p_me(6, value)).expect("P_ME ACT");
            assert_eq!(
                link.recv().expect("the confirmation"),
                p_me(7, value),
                "{what}: the same ASDU with COT = 7, P/N = 0, carrying the new value"
            );
            loads.push(Reaction::Loaded {
                ioa: HELD_IOA,
                value: value.typed(),
            });
        }
    }
    link.send(&p_ac(6, HELD_IOA, 3)).expect("P_AC ACT");
    assert_eq!(
        link.recv().expect("the confirmation"),
        p_ac(7, HELD_IOA, 3),
        "5.4.21.1 (type 113, QPA 3): the same ASDU with COT = 7, P/N = 0"
    );
    assert_eq!(link.quiet(), Ok(()), "5.4.21.1: one answer per command");
    end(station, link);

    let log = log.lock().expect("the log");
    assert_eq!(
        log[..loads.len()],
        loads[..],
        "5.4.21.1: the value in operation is the value the ACTCON carried"
    );
    assert_eq!(
        log[loads.len()],
        Reaction::Activated {
            ioa: HELD_IOA,
            qpa: Qpa { value: 3 },
        }
    );
}

/// 604 `5.4.21.1` in the reverse direction (§5.1), index 82, the row about the
/// **controlling** station (`M`): it sends a parameter command (an ASDU its
/// PICS lists) to the controlled station with cause 6 (`ACT`), and takes the `ACTCONpos` carrying the new value.
///
/// DUT: the **controlling** station, every `P_ME` type with every `KPA`, then
/// `P_AC_NA_1` with `QPA = <3>`. What goes on the wire is compared octet for
/// octet with figures 79 to 82; the library reports each confirmation as
/// positive with the value it carried, which is what its application stores.
#[test]
fn clause_5_4_21_1_the_controlling_station_loads_and_takes_the_confirmation() {
    let values: Vec<Value> = P_ME_TYPES
        .iter()
        .flat_map(|&t| KINDS.iter().map(move |&k| fresh(t, k, 2)))
        .collect();
    let mut replies: Vec<Vec<Vec<u8>>> = values.iter().map(|&v| vec![p_me(7, v)]).collect();
    replies.push(vec![p_ac(7, HELD_IOA, 3)]);
    let peer = ScriptedPeer::start(Vec::new(), replies).expect("the peer binds");
    let mut station = started_station(peer.addr()).expect("the station starts");
    let pm = ParameterLoading::controlling(LocalChange::NotUsed, CA, ORIGINATOR);

    for &value in &values {
        let what = format!("5.4.21.1 (type {}, KPA {})", value.type_id, value.kpa);
        let load = pm
            .load(&Parameter::new(HELD_IOA, value.typed()))
            .expect("pm builds the load");
        station_send(&mut station, &load).expect("the load goes out");
        let answer = station_recv_n(&mut station, 1).expect("the confirmation");
        let known = param_known(&answer[0]).expect("the answers");
        assert_eq!(
            pm.on_response(&answer[0], &known).expect("pm").reaction,
            Reaction::Confirmed {
                ioa: HELD_IOA,
                value: value.typed(),
                negative: false,
            },
            "{what}: ACTCONpos with the new value"
        );
    }
    let activation = Parameter::new(
        HELD_IOA,
        ParameterValue::Activation {
            qpa: Qpa { value: 3 },
        },
    );
    let act = pm.activate(&activation).expect("pm builds the activation");
    station_send(&mut station, &act).expect("the activation goes out");
    let answer = station_recv_n(&mut station, 1).expect("the confirmation");
    assert_eq!(
        pm.on_response(&answer[0], &param_known(&answer[0]).expect("known"))
            .expect("pm")
            .reaction,
        Reaction::Confirmed {
            ioa: HELD_IOA,
            value: activation.value,
            negative: false,
        },
        "5.4.21.1 (type 113, QPA 3): ACTCONpos"
    );
    station.close().expect("the station closes");
    let report = peer.join().expect("the peer ends");

    let mut want: Vec<Vec<u8>> = values.iter().map(|&v| p_me(6, v)).collect();
    want.push(p_ac(6, HELD_IOA, 3));
    assert_eq!(
        report.requests, want,
        "5.4.21.1: every command is figure 79 to 82's frame with COT = 6"
    );
}

// ------------------------------------------------------------- 5.4.21.10

/// 604 Table 21, PDF page index 82 (printed 81), procedure **`5.4.21.10`**,
/// *"Parameter loading – sequential procedure: Load and activate parameter with
/// Negative Confirmation by Controlled station"*, every row `Required` `PICS,
/// 9.6 Parameter loading, supported parameters`:
///
/// - the parameter is loaded but, after the feasibility and validity check,
///   cannot take effect at once; a negative threshold value or smoothing
///   factor is always invalid and never activated;
/// - the controlled station mirrors the ASDU back with cause 7, negative
///   (`ACTCONneg`), meaning the parameter was not loaded and/or not activated;
///   the value it carries is the old one still in operation, not the refused
///   one.
///
/// DUT: the **controlled** station. For every `P_ME` type, a negative
/// threshold value (`KPA 1`) and a negative smoothing factor (`KPA 2`) are
/// answered with the same ASDU, cause 7 with `P/N = 1`, carrying the value in
/// operation: first the station's initial value, then, after a positive value
/// has been loaded, that newly loaded one (the "old" value is whatever is in
/// operation when the refused load arrives).
#[test]
fn clause_5_4_21_10_a_negative_threshold_or_smoothing_factor_is_refused_with_the_old_value() {
    let (station, mut link, log) = controlled();
    for type_id in P_ME_TYPES {
        for kpa in [1, 2] {
            let what = format!("5.4.21.10 (type {type_id}, KPA {kpa})");
            let negative = Value {
                type_id,
                kpa,
                n: -8,
            };
            link.send(&p_me(6, negative)).expect("P_ME ACT");
            assert_eq!(
                link.recv().expect("the confirmation"),
                p_me(7 | PN, initial(type_id, kpa)),
                "{what}: ACTCONneg carrying the initial value in operation"
            );

            let loaded = fresh(type_id, kpa, 3);
            link.send(&p_me(6, loaded)).expect("P_ME ACT");
            assert_eq!(
                link.recv().expect("the confirmation"),
                p_me(7, loaded),
                "{what}: a positive value is loaded"
            );
            link.send(&p_me(6, negative)).expect("P_ME ACT");
            assert_eq!(
                link.recv().expect("the confirmation"),
                p_me(7 | PN, loaded),
                "{what}: ACTCONneg carrying the value loaded since"
            );
        }
    }
    assert_eq!(link.quiet(), Ok(()), "5.4.21.10: one answer per command");
    end(station, link);
    let infeasible = log
        .lock()
        .expect("the log")
        .iter()
        .filter(|r| matches!(r, Reaction::Infeasible { .. }))
        .count();
    assert_eq!(
        infeasible,
        2 * 2 * P_ME_TYPES.len(),
        "5.4.21.10: the library refuses every negative threshold and smoothing factor"
    );
}

/// 604 `5.4.21.10` in the reverse direction (§5.1), index 82: the
/// **controlling** station sends the load and takes the `ACTCONneg` whose value
/// is the *"old"* one.
///
/// DUT: the **controlling** station, a negative threshold value of every `P_ME`
/// type. The load is figure 79 to 81's frame; the library reports the answer as
/// a negative confirmation carrying the old value, not the one it sent.
#[test]
fn clause_5_4_21_10_the_controlling_station_takes_the_negative_confirmation() {
    let negatives: Vec<Value> = P_ME_TYPES
        .iter()
        .map(|&type_id| Value {
            type_id,
            kpa: 1,
            n: -8,
        })
        .collect();
    let replies = negatives
        .iter()
        .map(|v| vec![p_me(7 | PN, initial(v.type_id, v.kpa))])
        .collect();
    let peer = ScriptedPeer::start(Vec::new(), replies).expect("the peer binds");
    let mut station = started_station(peer.addr()).expect("the station starts");
    let pm = ParameterLoading::controlling(LocalChange::NotUsed, CA, ORIGINATOR);
    for &value in &negatives {
        let load = pm
            .load(&Parameter::new(HELD_IOA, value.typed()))
            .expect("pm builds the load");
        station_send(&mut station, &load).expect("the load goes out");
        let answer = station_recv_n(&mut station, 1).expect("the confirmation");
        assert_eq!(
            pm.on_response(&answer[0], &param_known(&answer[0]).expect("known"))
                .expect("pm")
                .reaction,
            Reaction::Confirmed {
                ioa: HELD_IOA,
                value: initial(value.type_id, value.kpa).typed(),
                negative: true,
            },
            "5.4.21.10 (type {}): ACTCONneg with the old value",
            value.type_id
        );
    }
    station.close().expect("the station closes");
    let report = peer.join().expect("the peer ends");
    assert_eq!(
        report.requests,
        negatives.iter().map(|&v| p_me(6, v)).collect::<Vec<_>>(),
        "5.4.21.10: the loads as figures 79 to 81 draw them"
    );
}

// ------------------------------------------------------------- 5.4.21.15

/// 604 Table 21, PDF page index 82 (printed 81), procedure **`5.4.21.15`**,
/// *"Parameter loading – Parameter activation"*, `Reference`
/// `IEC 60870-5-101:2003, 7.2.6.25`, `Required` `M`:
///
/// the controlled station rejects every parameter activation command (type
/// 113) whose `QPA` is 1 or 2, mirroring the ASDU back to the controlling
/// station with `P/N = <1>` (negative), and with cause 44 if it supports that;
///
/// DUT: the **controlled** station. `QPA = <1>` addresses object 0 and
/// `QPA = <2>` the addressed object (clause 7.2.6.25). Each answer is the same
/// ASDU with `P/N = 1` and cause 7 or 44 (the row allows either), every other
/// octet unchanged.
#[test]
fn clause_5_4_21_15_a_parameter_activation_with_qpa_1_or_2_is_rejected() {
    let (station, mut link, _) = controlled();
    for (ioa, qpa) in [(0, 1), (HELD_IOA, 2)] {
        let what = format!("5.4.21.15 (QPA {qpa})");
        let request = p_ac(6, ioa, qpa);
        link.send(&request).expect("P_AC ACT");
        let reply = link.recv().expect("the rejection");
        assert_eq!(reply.len(), request.len(), "{what}: the same ASDU");
        assert_ne!(reply[2] & PN, 0, "{what}: P/N = <1> negative");
        assert!(
            [7, 44].contains(&(reply[2] & 0x3F)),
            "{what}: COT 7, or 44 if supported; got {}",
            reply[2] & 0x3F
        );
        assert_eq!(reply[2] & 0x80, request[2] & 0x80, "{what}: the T bit");
        assert_eq!(reply[..2], request[..2], "{what}: type and VSQ");
        assert_eq!(reply[3..], request[3..], "{what}: the rest of the ASDU");
    }
    end(station, link);
}

/// 604 `5.4.21.15` in the reverse direction (§5.1), index 82: a **controlling**
/// station does not send what the controlled station must reject. 5-101 clause
/// 7.2.6.25 footnotes `<1>` and `<2>` as unused by the companion standard and
/// reserved for future parameter loading functions, and clause 7.4.9 selects `QPA := <3>` only, so the library
/// refuses to build `P_AC_NA_1` with `QPA` 1 or 2.
#[test]
fn clause_5_4_21_15_the_controlling_station_sends_no_qpa_1_or_2() {
    let pm = ParameterLoading::controlling(LocalChange::NotUsed, CA, ORIGINATOR);
    for qpa in [1, 2] {
        let parameter = Parameter::new(
            HELD_IOA,
            ParameterValue::Activation {
                qpa: Qpa { value: qpa },
            },
        );
        assert_eq!(
            pm.activate(&parameter),
            Err(PmError::QpaNotUsed { value: qpa }),
            "5.4.21.15 (QPA {qpa})"
        );
    }
}
