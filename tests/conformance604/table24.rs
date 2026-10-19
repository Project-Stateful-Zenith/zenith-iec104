//! 604 Table 24, *"Additional conformance test procedures"*, PDF page index 87
//! (printed 86), procedures `5.4.24.1`, `.10`, `.20` and `.30`.
//!
//! Each case quotes the rows it drives verbatim with their `Reference` and
//! `Required` columns.
//!
//! # The station under test
//!
//! - `5.4.24.1` (out of service behaviour) is about the connection: the DUT is
//!   `manager::ConnectionManager`, the crate's station table with its t0 retry,
//!   in each role, with `gi::Interrogation` as the *"active Basic application
//!   function"* the row names. The group of `redundancy` is Table 12's DUT for
//!   the same kind of loss (`table12`, `5.4.12.30`); the manager is the
//!   non-redundant component a single-connection application uses.
//! - `5.4.24.10` (miscellaneous) is clause 7.2.3's negative confirmation: for
//!   the controlled station, `dispatch::route` and `dispatch::not_implemented`
//!   (a basic application function the crate does not implement, `C_RP_NA_1`)
//!   and `ts::TestProcedure` (one it implements but the station does not use),
//!   through [`ProcedureApp`]; for the controlling station, the `on_response`
//!   of `ts` and `gi`.
//!
//! # Direction
//!
//! `5.4.24.1` is driven in both roles. `5.4.24.10`'s first row is the
//! controlled station's cause-44 mirror, which §5.1 excepts from the swap
//! (*"except for COT44-47 which are only defined in Monitor direction (only a
//! controlled station is allowed to send these COT)"*), so its reverse is not
//! driven; its second row is the controlling station's detection of that
//! mirror, driven as written.
//!
//! # Rows with no case here, and why
//!
//! - **`5.4.24.1`, the two rows on *"main voltage supply interruptions"***
//!   (`Required` `M`): *"System is able to start automatically without any
//!   manual assistance"*. Not automatable here: a supply interruption is a
//!   property of the device and its power-up sequence, and a sans-IO library
//!   has no process to restart. What a restarted application does next is
//!   Table 12's `5.4.12.1` and `5.4.12.10`, which are driven.
//! - **`5.4.24.1`, a disconnection with no FIN** (a cable pulled): the loss is
//!   then only detected by t1 or t3, which is `5.4.12.30`'s case (Table 12).
//!   The cases below disconnect at the TCP level, which the caller's socket
//!   reports at once.
//! - **`5.4.24.10`'s *"(optionally) shows this on an HMI or a test tool"***:
//!   the display is the application's; the crate's part is the detection, which
//!   is asserted.
//! - **`5.4.24.20` Time invalid** (`Reference` `IEC 60870-5-104:2006, 7.6`,
//!   `Required` `PIXIT`): *"After receipt of an ASDU with time stamp marked
//!   invalid (IV=1) the controlling station immediately initiates a Clock
//!   synchronisation procedure (if supported) after the Clock synchronisation
//!   procedure has been completed as part of the Initialisation procedure"*.
//!   Not applicable to this crate as a library rule: no module of `src/`
//!   decides to synchronise on a received `IV = 1`. `src/cs.rs` states the
//!   division, *"setting `IV`, running the re-sync interval and choosing between
//!   UTC and local time are the application's"*; the crate supplies the parts
//!   (the `invalid` field of every decoded `CP56Time2a`, and
//!   `cs::ClockSynchronisation::request`), and the trigger is the PIXIT's
//!   application choice. A test that made the decision itself would be testing
//!   its own glue, not the library.
//! - **`5.4.24.30` COMPATIBILITY WITH OTHER TEST CASES**: the whole suite, not a
//!   case (see `tests/conformance_604.rs`).

use std::net::TcpListener;
use std::time::{Duration, Instant};

use iec104::apci::{Apci, UFunction};
use iec104::asdu::{Cause, Known, Tsc};
use iec104::gi::{Interrogation, ReActivation, Reaction as GiReaction, Scope, SecondActivation};
use iec104::link::Role;
use iec104::manager::{ConnectReason, ConnectionManager, Directive, StationConfig};
use iec104::params::LinkParams;
use iec104::ts::{Command, Reaction as TsReaction, Selection, TestProcedure};

use crate::conformance604::apps::{
    COT_OCTET, OnePoint, PN_BIT, ProcedureApp, TIME, gi_activation, gi_frame, test_command,
};
use crate::conformance604::endpoint::Endpoint;
use crate::conformance604::{CA, ControlledStation, ORIGINATOR, Peer, deadline, interop};

/// Performs the manager's directives for station 0 on its socket.
fn perform(dut: &mut Endpoint, directives: Vec<Directive>) -> Result<(), String> {
    for directive in directives {
        match directive {
            Directive::Actions {
                station: 0,
                actions,
            } => dut.perform(&actions)?,
            other => return Err(format!("an unexpected directive: {other:?}")),
        }
    }
    Ok(())
}

/// Reads one frame on the station's socket and feeds it to the manager.
fn feed(
    manager: &mut ConnectionManager,
    dut: &mut Endpoint,
    now: Instant,
) -> Result<(Apci, Vec<u8>), String> {
    let (apci, asdu) = dut.read_frame(crate::conformance604::endpoint::soon())?;
    let directives = manager
        .on_frame(0, apci, now)
        .map_err(|e| format!("the manager refused {apci:?}: {e:?}"))?;
    perform(dut, directives)?;
    Ok((apci, asdu))
}

/// The rows of **`5.4.24.1`** the two cases below drive, PDF page index 87
/// (printed 86), each `Required` `M`:
///
/// > Behaviour on disconnection of the physical communication to the Controlled
/// > system. System is able to connect automatically without any manual
/// > assistance
///
/// > Behaviour on disconnection of the physical communication to the Controlling
/// > system. System is able to connect automatically without any manual
/// > assistance
///
/// > These tests are performed correctly in the situation when there is no
/// > active Basic application function and when there is an active Basic
/// > application function (for example a running General Interrogation).
///
/// (the last with `Reference` `IEC 60870-5-104:2006, 5.3`). Each case runs
/// twice: with no procedure running when the connection is lost, and with a
/// station interrogation confirmed and not yet terminated.
const BAF_STATES: [bool; 2] = [false, true];

/// **`5.4.24.1`** (rows above), DUT: the **controlling** station, a
/// `ConnectionManager` of one station. The mock controlled station drops the
/// TCP connection; the manager asks for a new one on its own (clause 10.5,
/// index 128: *"reopening is regularly retried by the controlling station
/// until the error has been corrected and the connection is re-established"*),
/// the start is repeated (clause 5.3: a new connection is Stopped) and a new
/// station interrogation goes out, the old one dropped with
/// `gi::Interrogation::reset` as its doc prescribes for a connection loss.
#[test]
fn clause_5_4_24_1_the_controlling_station_reconnects_by_itself() {
    for active in BAF_STATES {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the mock binds");
        let addr = listener.local_addr().unwrap();
        let start = Instant::now();
        let mut manager = ConnectionManager::new(
            Role::Controlling,
            vec![StationConfig::new(LinkParams::default())],
        )
        .unwrap();
        let mut gi = Interrogation::controlling(SecondActivation::Locked, CA, ORIGINATOR);

        let mut reasons = Vec::new();
        for connection in 0..2u32 {
            // A connection lost before its attempt's t0 ran out is dialed
            // again when it does: one t0 after the previous attempt.
            let now = start + LinkParams::default().t0 * connection;
            if connection > 0 {
                assert!(
                    manager
                        .tick(now.checked_sub(Duration::from_millis(1)).unwrap())
                        .is_empty(),
                    "5.4.24.1 (BAF active: {active}): not dialed again within t0"
                );
            }
            let dial = manager.tick(now);
            let [
                Directive::Connect {
                    station: 0, reason, ..
                },
            ] = dial.as_slice()
            else {
                panic!("5.4.24.1 (BAF active: {active}): a dial expected, got {dial:?}");
            };
            reasons.push(*reason);
            let mut dut = Endpoint::connect(addr).expect("the dial succeeds");
            let mut mock = Endpoint::accept(&listener).unwrap();
            manager.on_connection_established(0, now).unwrap();
            let directives = manager.request_start(0, now).unwrap();
            perform(&mut dut, directives).unwrap();
            mock.expect_u(UFunction::StartDtAct).unwrap();
            mock.send_u(UFunction::StartDtCon).unwrap();
            feed(&mut manager, &mut dut, now).unwrap();

            let request = gi
                .request(Scope::Station)
                .unwrap_or_else(|e| panic!("5.4.24.1 (BAF active: {active}): {e:?}"));
            let directive = manager.send_i_frame(0, &request, now).unwrap();
            perform(&mut dut, directive.into_iter().collect()).unwrap();
            let (_, asdu) = mock.expect_i().unwrap();
            assert_eq!(
                asdu,
                gi_activation(),
                "5.4.24.1 (BAF active: {active}, connection {connection}): the interrogation \
                 goes out"
            );
            if connection == 1 {
                break;
            }
            if active {
                mock.send_i(0, 1, &gi_frame(7)).unwrap();
                let (_, asdu) = feed(&mut manager, &mut dut, now).unwrap();
                let outcome = gi.on_response(&asdu, &Known::EVERYTHING).unwrap();
                assert_eq!(
                    outcome.reaction,
                    GiReaction::ActivationConfirmed {
                        scope: Scope::Station,
                        negative: false
                    }
                );
                assert!(gi.is_running(Scope::Station), "the BAF is active");
            }
            // The disconnection: the peer's side of the TCP connection goes.
            mock.shutdown();
            assert!(
                dut.read_frame(crate::conformance604::endpoint::soon())
                    .is_err()
            );
            manager.on_connection_lost(0).unwrap();
            gi.reset();
        }
        assert_eq!(
            reasons,
            vec![ConnectReason::FirstAttempt, ConnectReason::ConnectionLost],
            "5.4.24.1 (BAF active: {active}): \"able to connect automatically without any \
             manual assistance\""
        );
    }
}

/// **`5.4.24.1`** (rows above), DUT: the **controlled** station, a
/// `ConnectionManager` of one station in `Role::Controlled` with
/// `gi::Interrogation`. Clause 7.1 makes the controlled station the listener
/// (*"the controlled station to the server (listener)"*, index 54), so it
/// never dials (`tick` asks for nothing) and its automatic reconnection is
/// taking the controlling station's next connection: a new STARTDT is answered
/// and a new station interrogation runs to its termination. With the BAF
/// active, the first interrogation was confirmed and its data not yet sent when
/// the connection went; `gi::Interrogation::reset` drops it, as its doc
/// prescribes for a connection loss.
#[test]
fn clause_5_4_24_1_the_controlled_station_takes_the_next_connection() {
    for active in BAF_STATES {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the station binds");
        let addr = listener.local_addr().unwrap();
        let now = Instant::now();
        let mut manager = ConnectionManager::new(
            Role::Controlled,
            vec![StationConfig::new(LinkParams::default())],
        )
        .unwrap();
        let mut gi = Interrogation::controlled(ReActivation::Continue, CA, ORIGINATOR);

        for connection in 0..2 {
            assert!(
                manager.tick(now).is_empty(),
                "5.4.24.1: the controlled station never dials (104 clause 7.1)"
            );
            let mut mock = Endpoint::connect(addr).unwrap();
            let mut dut = Endpoint::accept(&listener).unwrap();
            manager.on_connection_established(0, now).unwrap();
            mock.send_u(UFunction::StartDtAct).unwrap();
            feed(&mut manager, &mut dut, now).unwrap();
            mock.expect_u(UFunction::StartDtCon).unwrap_or_else(|why| {
                panic!("5.4.24.1 (BAF active: {active}, connection {connection}): {why}")
            });

            mock.send_i(0, 0, &gi_activation()).unwrap();
            let (_, asdu) = feed(&mut manager, &mut dut, now).unwrap();
            let outcome = gi
                .on_request(&asdu, &Known::EVERYTHING, &OnePoint)
                .unwrap_or_else(|e| panic!("5.4.24.1 (BAF active: {active}): {e:?}"));
            let mut answers = outcome.send;
            let last = connection == 1;
            if last || !active {
                answers.extend(gi.complete(&OnePoint).unwrap());
            }
            for answer in &answers {
                let directive = manager.send_i_frame(0, answer, now).unwrap();
                perform(&mut dut, directive.into_iter().collect()).unwrap();
            }
            let mut causes = Vec::new();
            for _ in 0..answers.len() {
                causes.push(mock.expect_i().unwrap().1[COT_OCTET]);
            }
            let expected = if last || !active {
                vec![7, 20, 10]
            } else {
                vec![7]
            };
            assert_eq!(
                causes, expected,
                "5.4.24.1 (BAF active: {active}, connection {connection})"
            );
            if last {
                break;
            }
            assert_eq!(gi.is_running(Scope::Station), active, "the BAF state");
            // The disconnection: the peer's side of the TCP connection goes.
            mock.shutdown();
            assert!(
                dut.read_frame(crate::conformance604::endpoint::soon())
                    .is_err()
            );
            manager.on_connection_lost(0).unwrap();
            gi.reset();
        }
    }
}

/// `C_RP_NA_1` activation, written out from 5-101 clause 7.3.4.6 (figure 77):
/// type `105`, `N = 1`, cause `<6>`, originator, common address, information
/// object address `0`, `QRP` `<1>` *general reset of process* (clause 7.2.6.27).
fn reset_process() -> Vec<u8> {
    let [ca_lo, ca_hi] = CA.to_le_bytes();
    vec![105, 0x01, 6, ORIGINATOR, ca_lo, ca_hi, 0, 0, 0, 1]
}

/// Clause 7.2.3's cause-44 mirror of `request`, written out: the same octets
/// with the cause octet's cause `44` and `P/N = 1` (index 38: *"mirrored by the
/// controlled station with bit “P/N := <1> negative confirm”"*, the table's
/// `type identification | 44`).
fn mirror_44(request: &[u8]) -> Vec<u8> {
    let mut mirror = request.to_vec();
    mirror[COT_OCTET] = 0x2C | PN_BIT;
    mirror
}

/// 604 Table 24, PDF page index 87 (printed 86), procedure **`5.4.24.10`**,
/// *"Miscellaneous"*, first row, `Reference` `IEC 60870-5-101:2003, 7.2.3`,
/// `Required` `M`:
///
/// > The controlled station responds with P/N=1negative (with COT = 44, if
/// > supported) if a BAF is not implemented or used
///
/// DUT: the **controlled** station, [`ProcedureApp`] routing through
/// `dispatch::route`. Two samples, one for each half of *"not implemented or
/// used"*: `C_RP_NA_1` (reset process), which the crate does not implement
/// (`dispatch::Route::NotImplemented`, answered by
/// `dispatch::not_implemented`), and `C_TS_TA_1` at a station whose 104
/// clause 9.6 *"Test procedure"* box is not marked (`ts::Selection::NONE`,
/// answered by `ts::TestProcedure::on_request`). Each answer is the request
/// mirrored with cause 44 and `P/N = 1`.
#[test]
fn clause_5_4_24_10_the_controlled_station_mirrors_an_unserved_baf_with_cause_44() {
    let station = ControlledStation::start_app(ProcedureApp::new(Selection::NONE), Vec::new())
        .expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");
    peer.start_data_transfer().unwrap();

    let samples = [
        ("C_RP_NA_1, not implemented", reset_process()),
        ("C_TS_TA_1, not used", test_command(6, 0x0001, TIME)),
    ];
    for (n, (what, request)) in samples.iter().enumerate() {
        let n = n as u16;
        peer.send_i(
            iec104::apci::SeqNo::new(n),
            iec104::apci::SeqNo::new(n),
            request,
        )
        .unwrap();
        let (_, answer) = peer
            .expect_i(deadline(5))
            .unwrap_or_else(|why| panic!("5.4.24.10 ({what}): {why}"));
        assert_eq!(
            answer,
            mirror_44(request),
            "5.4.24.10 ({what}): \"responds with P/N=1negative (with COT = 44, if supported)\""
        );
    }
    peer.close().unwrap();
    let report = station.join().expect("the station ends cleanly");
    assert!(report.closes.is_empty(), "5.4.24.10: {:?}", report.closes);
}

/// 604 Table 24, PDF page index 87 (printed 86), procedure **`5.4.24.10`**,
/// second row, `Reference` `IEC 60870-5-101:2003, 7.2.3`, `Required` `M`:
///
/// > The controlling station detects the receipt of a P/N=1 negative and
/// > (optionally) shows this on an HMI or a test tool
///
/// DUT: the **controlling** station, `interop::Station` with the
/// `on_response` of `ts::TestProcedure` and `gi::Interrogation`. The mock
/// controlled station answers a `C_TS_ACT` with the cause-44 mirror, a second
/// one with a negative `C_TS_ACTCON` (cause `<7>`, `P/N = 1`), and a
/// `C_IC_ACT` with the cause-44 mirror. Each is detected as negative: a
/// refusal naming cause 44, or an answer with `negative: true`.
#[test]
fn clause_5_4_24_10_the_controlling_station_detects_a_negative_confirmation() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("the mock binds");
    let mut station =
        interop::Station::connect(listener.local_addr().unwrap()).expect("the station dials");
    let mut mock = Endpoint::accept(&listener).expect("the mock accepts");
    let actions = station.session_mut().request_start();
    station.send_actions(&actions).unwrap();
    mock.expect_u(UFunction::StartDtAct).unwrap();
    mock.send_u(UFunction::StartDtCon).unwrap();
    station
        .expect("the con", deadline(5), |apci, _| {
            apci == Apci::U(UFunction::StartDtCon)
        })
        .unwrap();

    let ts = TestProcedure::controlling(Selection::TAGGED, CA, ORIGINATOR);
    let mut gi = Interrogation::controlling(SecondActivation::Locked, CA, ORIGINATOR);
    let time = iec104::asdu::Cp56Time2a::parse(&TIME).unwrap();
    let command = |tsc| Command::Tagged {
        tsc: Tsc::from_raw(tsc),
        time,
    };
    let mut negative_actcon = test_command(7, 2, TIME);
    negative_actcon[COT_OCTET] |= PN_BIT;

    let mut exchange = |n: u16, request: Vec<u8>, answer: Vec<u8>| -> Vec<u8> {
        let action = station.session_mut().send_i_frame(&request).unwrap();
        station.send_actions(&[action]).unwrap();
        let (_, on_wire) = mock.expect_i().unwrap();
        assert_eq!(on_wire, request);
        mock.send_i(n, n + 1, &answer).unwrap();
        station
            .expect("the answer", deadline(5), |apci, _| apci.is_i_format())
            .unwrap()
            .1
    };

    let request = ts.request(command(1)).unwrap();
    let answer = exchange(0, request.clone(), mirror_44(&request));
    assert_eq!(
        ts.on_response(&answer, &Known::EVERYTHING, command(1))
            .map(|o| o.reaction),
        Ok(TsReaction::Refused {
            cause: Cause::UnknownTypeId
        }),
        "5.4.24.10: the cause-44 mirror of C_TS_ACT is detected"
    );

    let request = ts.request(command(2)).unwrap();
    let answer = exchange(1, request, negative_actcon);
    assert_eq!(
        ts.on_response(&answer, &Known::EVERYTHING, command(2))
            .map(|o| o.reaction),
        Ok(TsReaction::Answered {
            command: command(2),
            negative: true
        }),
        "5.4.24.10: the negative C_TS_ACTCON is detected"
    );

    let request = gi.request(Scope::Station).unwrap();
    let answer = exchange(2, request.clone(), mirror_44(&request));
    assert_eq!(
        gi.on_response(&answer, &Known::EVERYTHING)
            .map(|o| o.reaction),
        Ok(GiReaction::Refused {
            scope: Some(Scope::Station),
            cause: Cause::UnknownTypeId
        }),
        "5.4.24.10: the cause-44 mirror of C_IC_ACT is detected"
    );
    station.close().unwrap();
}
