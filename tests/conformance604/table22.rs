//! 604 Table 22, *"Test procedure function conformance test procedures"*, PDF
//! page index 83 (printed 82), procedures `5.4.22.1` and `5.4.22.10`.
//!
//! The block's NOTE: *"The following tests are only required for systems
//! supporting Test procedure. If ‘M’ is mentioned, the test case is mandatory
//! for systems with the relevant Test procedure options marked in the PICS"*.
//! The crate supports it in both forms (`src/ts.rs`); the cases run the 104
//! profile's `C_TS_TA_1` `<107>` (`ts::Selection::TAGGED`), the only test
//! command 104 Table 4 carries.
//!
//! The rows' `Reference` column is `IEC 60870-5-104:2006, 8.8` and
//! `IEC 60870-5-101:2003, 7.4.10`. Clause 8.8 (index 90), verbatim: *"The
//! requesting station may choose any value of TSC. The TSC in the response
//! shall match the request, and the time in the response shall also exactly
//! match the time in the request."* Every expected frame is written out octet
//! by octet from figure 30 ([`test_command`]), never built by `src/ts.rs`.
//!
//! # The station under test, in each direction
//!
//! The DUT is `ts::TestProcedure`: its `on_request` answers a command, its
//! `request` builds one and its `on_response` checks the echo. Its role is the
//! *procedure's* (`src/ts.rs`: *"the same station may hold the other role's
//! instance for the reverse direction"*), and 104 clause 9.6 lets a station use
//! the test procedure *"in the standard direction"*, *"in the reverse
//! direction"* or *"in both directions"* (index 112). §5.1 makes the reverse
//! direction part of the test, so the row's primary and secondary are each
//! driven as both transport roles:
//!
//! | Primary (sends `C_TS_ACT`) | Secondary (answers `C_TS_ACTCON`) | DUT |
//! | --- | --- | --- |
//! | mock controlling station | controlled station | the secondary |
//! | controlling station | mock controlled station | the primary |
//! | controlled station | mock controlling station | the primary |
//! | mock controlled station | controlling station | the secondary |
//!
//! No case sends a cause 44–47.
//!
//! # Rows with no case here, and why
//!
//! - **`5.4.22.1`, `Required` `PIXIT`**: *"The Test command is sent at the
//!   configured interval period"* (`Reference` `PID`). Not applicable to this
//!   crate: `src/ts.rs` *"schedules nothing, holds no timer and reads no
//!   clock"*; the interval is the application's configuration.
//! - **`5.4.22.10` COMPATIBILITY WITH OTHER TEST CASES**: the whole suite, not a
//!   case (see `tests/conformance_604.rs`).

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{Cp56Time2a, Known, Tsc};
use iec104::ts::{Command, Reaction, Selection, TestProcedure, TsError};

use crate::conformance604::apps::{ProcedureApp, TIME, TIME_PLUS_1MS, test_command};
use crate::conformance604::endpoint::Endpoint;
use crate::conformance604::{
    CA, ControlledStation, MonitorPeer, ORIGINATOR, Peer, StationApp, deadline, interop,
};

/// The two test sequence counters the cases pick: *"The Primary station may
/// choose any value of TSC"*, so one in the middle of `UI16` and its top.
const TSCS: [u16; 2] = [0x1234, 0xFFFF];

/// [`TIME`] as the crate's `CP56Time2a` value, for the `ts::Command` the
/// primary builds from: parsed from the written-out octets, not constructed.
fn time() -> Cp56Time2a {
    Cp56Time2a::parse(&TIME).expect("TIME is a valid CP56Time2a")
}

/// The command a primary sends with counter `tsc` at [`TIME`].
fn command(tsc: u16) -> Command {
    Command::Tagged {
        tsc: Tsc::from_raw(tsc),
        time: time(),
    }
}

/// 604 Table 22, PDF page index 83 (printed 82), procedure **`5.4.22.1`**,
/// *"Test procedure – sequential procedure"*, the secondary station's row,
/// `Reference` `IEC 60870-5-104:2006, 8.8` / `IEC 60870-5-101:2003, 7.4.10`,
/// `Required` `M`:
///
/// > The Secondary station sends the same Test command (ASDU 107) with COT =
/// > 7, C_TS_ACTCON, to the Primary station. The TSC in the response shall
/// > match the request, and the time in the response shall also exactly match
/// > the time in the request
///
/// DUT: the **controlled** station as the secondary, `ts::TestProcedure`
/// through [`ProcedureApp`]. The mock controlling station sends two commands
/// with different counters; each confirmation is the command octet for octet
/// with cause `<7>` in place of `<6>` (figure 30's cause list).
#[test]
fn clause_5_4_22_1_the_controlled_station_echoes_the_test_command() {
    let station = ControlledStation::start_app(ProcedureApp::new(Selection::TAGGED), Vec::new())
        .expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");
    peer.start_data_transfer().expect("the STARTDT exchange");

    for (n, tsc) in TSCS.into_iter().enumerate() {
        let n = n as u16;
        peer.send_i(SeqNo::new(n), SeqNo::new(n), &test_command(6, tsc, TIME))
            .unwrap();
        let (apci, asdu) = peer
            .expect_i(deadline(5))
            .unwrap_or_else(|why| panic!("5.4.22.1 (TSC {tsc:#06x}): {why}"));
        assert_eq!(
            asdu,
            test_command(7, tsc, TIME),
            "5.4.22.1 (TSC {tsc:#06x}): \"the same Test command (ASDU 107) with COT = 7\", \
             TSC and time unchanged"
        );
        assert_eq!(
            apci,
            Apci::I {
                ns: SeqNo::new(n),
                nr: SeqNo::new(n + 1)
            }
        );
    }
    peer.close().unwrap();
    let report = station.join().expect("the station ends cleanly");
    assert!(report.closes.is_empty(), "5.4.22.1: {:?}", report.closes);
}

/// What the primary made of each confirmation, in order:
/// `ts::TestProcedure::on_response`'s verdict.
type Verdicts = Arc<Mutex<Vec<Result<Reaction, TsError>>>>;

/// 604 Table 22, PDF page index 83 (printed 82), procedure **`5.4.22.1`**, the
/// primary station's rows, `Reference` `IEC 60870-5-104:2006, 8.8` /
/// `IEC 60870-5-101:2003, 7.4.10`, each `Required` `M`:
///
/// > The Primary station sends a Test command (ASDU 107) with COT = 6,
/// > C_TS_ACT, to the Secondary station. The Primary station may choose any
/// > value of TSC
///
/// > Mismatching values of TSC are detected by the Primary station
///
/// DUT: the **controlling** station as the primary, `interop::Station` with
/// `ts::TestProcedure::controlling`. The mock controlled station answers the
/// first command with the exact echo, the second with the counter plus one,
/// and the third with the time one millisecond later (clause 8.8's *"the time
/// in the response shall also exactly match"*). The first is an answer, the
/// other two are `TsError::EchoMismatch`.
#[test]
fn clause_5_4_22_1_the_controlling_station_sends_c_ts_act_and_detects_a_mismatch() {
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

    let primary = TestProcedure::controlling(Selection::TAGGED, CA, ORIGINATOR);
    let tsc = TSCS[0];
    // (the counter the command carries, the confirmation the mock sends back)
    let exchanges = [
        (tsc, test_command(7, tsc, TIME)),
        (tsc + 1, test_command(7, tsc + 2, TIME)),
        (tsc + 2, test_command(7, tsc + 2, TIME_PLUS_1MS)),
    ];
    let mut verdicts = Vec::new();
    for (n, (sent, confirmation)) in exchanges.iter().enumerate() {
        let n = n as u16;
        let request = primary.request(command(*sent)).expect("the command");
        let action = station
            .session_mut()
            .send_i_frame(&request)
            .expect("a started connection");
        station.send_actions(&[action]).unwrap();

        let (_, on_wire) = mock.expect_i().expect("the C_TS_ACT");
        assert_eq!(
            on_wire,
            test_command(6, *sent, TIME),
            "5.4.22.1: \"a Test command (ASDU 107) with COT = 6, C_TS_ACT\", TSC {sent:#06x}"
        );
        mock.send_i(n, n + 1, confirmation).unwrap();
        let (_, asdu) = station
            .expect("the C_TS_ACTCON", deadline(5), |apci, _| apci.is_i_format())
            .unwrap();
        verdicts.push(
            primary
                .on_response(&asdu, &Known::EVERYTHING, command(*sent))
                .map(|outcome| outcome.reaction),
        );
    }
    station.close().unwrap();

    assert_eq!(
        verdicts[0],
        Ok(Reaction::Answered {
            command: command(tsc),
            negative: false
        }),
        "5.4.22.1: the exact echo is the confirmation"
    );
    assert!(
        matches!(verdicts[1], Err(TsError::EchoMismatch { .. })),
        "5.4.22.1: \"Mismatching values of TSC are detected by the Primary station\": {:?}",
        verdicts[1]
    );
    assert!(
        matches!(verdicts[2], Err(TsError::EchoMismatch { .. })),
        "5.4.22.1: \"the time in the response shall also exactly match the time in the \
         request\": {:?}",
        verdicts[2]
    );
}

/// The controlled station's application when it is the test procedure's
/// **primary** (the reverse direction): it sends one command per counter of
/// [`TSCS`], the next once the previous one is confirmed, and records
/// `ts::TestProcedure::on_response`'s verdict for each confirmation.
struct ReversePrimary {
    procedure: TestProcedure,
    counters: Vec<u16>,
    awaiting: Option<u16>,
    verdicts: Verdicts,
}

impl ReversePrimary {
    fn next(&mut self) -> Result<Vec<Vec<u8>>, String> {
        if self.counters.is_empty() {
            return Ok(Vec::new());
        }
        let tsc = self.counters.remove(0);
        self.awaiting = Some(tsc);
        Ok(vec![
            self.procedure
                .request(command(tsc))
                .map_err(|e| format!("ts: {e:?}"))?,
        ])
    }
}

impl StationApp for ReversePrimary {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let sent = self
            .awaiting
            .take()
            .ok_or("a confirmation nobody awaited")?;
        let verdict = self
            .procedure
            .on_response(asdu, &Known::EVERYTHING, command(sent))
            .map(|outcome| outcome.reaction);
        self.verdicts.lock().unwrap().push(verdict);
        self.next()
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        if self.awaiting.is_none() && self.verdicts.lock().unwrap().is_empty() {
            self.next()
        } else {
            Ok(Vec::new())
        }
    }
}

/// 604 Table 22, PDF page index 83 (printed 82), procedure **`5.4.22.1`**, the
/// same primary rows in the **reverse direction** (§5.1: *"replace
/// "Controlling" with "Controlled" and vice versa"*):
///
/// > The Primary station sends a Test command (ASDU 107) with COT = 6,
/// > C_TS_ACT, to the Secondary station. The Primary station may choose any
/// > value of TSC
///
/// > Mismatching values of TSC are detected by the Primary station
///
/// DUT: the **controlled** station as the primary, `ts::TestProcedure` in the
/// procedure's controlling role on the controlled station's session
/// ([`ReversePrimary`]). The mock controlling station confirms the first
/// command exactly and the second with another counter.
#[test]
fn clause_5_4_22_1_reverse_the_controlled_station_as_primary_detects_a_mismatch() {
    let verdicts: Verdicts = Arc::default();
    let app = ReversePrimary {
        procedure: TestProcedure::controlling(Selection::TAGGED, CA, ORIGINATOR),
        counters: TSCS.to_vec(),
        awaiting: None,
        verdicts: Arc::clone(&verdicts),
    };
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");
    peer.start_data_transfer().expect("the STARTDT exchange");

    let confirmations = [
        test_command(7, TSCS[0], TIME),
        test_command(7, TSCS[1] - 1, TIME),
    ];
    for (n, (tsc, confirmation)) in TSCS.into_iter().zip(confirmations).enumerate() {
        let n = n as u16;
        let (_, asdu) = peer
            .expect_i(deadline(5))
            .unwrap_or_else(|why| panic!("5.4.22.1 reverse (TSC {tsc:#06x}): {why}"));
        assert_eq!(
            asdu,
            test_command(6, tsc, TIME),
            "5.4.22.1 reverse: \"a Test command (ASDU 107) with COT = 6, C_TS_ACT\""
        );
        peer.send_i(SeqNo::new(n), SeqNo::new(n + 1), &confirmation)
            .unwrap();
    }
    // The second verdict is recorded when the station reads the second
    // confirmation; an acknowledgement round trip orders the check after it.
    peer.send_u(UFunction::TestFrAct).unwrap();
    peer.expect_u(UFunction::TestFrCon, deadline(5)).unwrap();
    peer.close().unwrap();
    station.join().expect("the station ends cleanly");

    let verdicts = verdicts.lock().unwrap().clone();
    assert_eq!(
        verdicts,
        vec![
            Ok(Reaction::Answered {
                command: command(TSCS[0]),
                negative: false
            }),
            Err(TsError::EchoMismatch {
                sent: command(TSCS[1]),
                got: command(TSCS[1] - 1)
            }),
        ],
        "5.4.22.1 reverse: the echo is accepted, the mismatching TSC is detected"
    );
}

/// 604 Table 22, PDF page index 83 (printed 82), procedure **`5.4.22.1`**, the
/// secondary station's row in the **reverse direction**:
///
/// > The Secondary station sends the same Test command (ASDU 107) with COT =
/// > 7, C_TS_ACTCON, to the Primary station. The TSC in the response shall
/// > match the request, and the time in the response shall also exactly match
/// > the time in the request
///
/// DUT: the **controlling** station as the secondary, `interop::Station` with
/// `ts::TestProcedure::controlled`. The mock controlled station sends the
/// command right after the STARTDT con.
#[test]
fn clause_5_4_22_1_reverse_the_controlling_station_echoes_the_test_command() {
    let tsc = TSCS[1];
    let peer = MonitorPeer::start(test_command(6, tsc, TIME)).expect("the mock binds");
    let mut station = interop::Station::connect(peer.addr()).expect("the station connects");
    let actions = station.session_mut().request_start();
    station.send_actions(&actions).unwrap();
    let (_, asdu) = station
        .expect("the C_TS_ACT", deadline(5), |apci, _| apci.is_i_format())
        .expect("the mock's command arrives");

    let secondary = TestProcedure::controlled(Selection::TAGGED, CA, ORIGINATOR);
    let outcome = secondary
        .on_request(&asdu, &Known::EVERYTHING)
        .expect("the controlling station reads the command");
    assert_eq!(
        outcome.reaction,
        Reaction::Requested {
            command: command(tsc)
        }
    );
    for answer in &outcome.send {
        let action = station
            .session_mut()
            .send_i_frame(answer)
            .expect("a started connection");
        station.send_actions(&[action]).unwrap();
    }
    station.close().unwrap();

    let report = peer.join().expect("the mock ends cleanly");
    let answers: Vec<Vec<u8>> = report
        .received
        .iter()
        .filter_map(|frame| interop::parse_frame(frame).ok())
        .filter(|(apci, _)| apci.is_i_format())
        .map(|(_, asdu)| asdu)
        .collect();
    assert_eq!(
        answers,
        vec![test_command(7, tsc, TIME)],
        "5.4.22.1 reverse: \"the same Test command (ASDU 107) with COT = 7\""
    );
}
