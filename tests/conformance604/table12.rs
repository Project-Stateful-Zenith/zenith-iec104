//! 604 Table 12, *"Station initialisation function conformance test
//! procedures"* (1 of 3 to 3 of 3), PDF page indices 55–57 (printed 54–56),
//! procedures `5.4.12.1`, `.10`, `.20`, `.21`, `.30` and `.40`.
//!
//! Each case quotes the rows it drives verbatim and names the 104 clause of
//! each row's `Reference` column. 104 page indices are PDF page indices of the
//! bilingual 2006 edition (printed page plus one on the English pages): clause
//! 7.1 is index 54 (printed 53), figure 20 index 58 (57), figure 21 index 60
//! (59), clause 5.3 index 38 (37), figure 12 index 34 (33), figure 14 index 36
//! (35), the clause 9 time-out table index 114 (113), clause 10.3 index 120
//! (119).
//!
//! # The station under test
//!
//! Station initialisation is where the crate's connection-level components
//! meet its application modules, so the DUT is whichever component of `src/`
//! makes the decision the row is about:
//!
//! - `redundancy::RedundancyGroup` for the number of connections to a
//!   controlled station, which one carries the STARTDT act (`start`), the
//!   station interrogation that follows the start (`follow_up`, clause 10.3),
//!   the t0/t1/t3 supervision (`tick`) and the replay of what a lost
//!   connection left unconfirmed (`retransmit_unconfirmed`). A group of one
//!   connection is 604 `5.4.12.30`'s *"when no other connections are
//!   available"*.
//! - `link::Session` in `Role::Controlled` (through [`ControlledStation`]) with
//!   `init::end_of_initialisation` held in its clause 5.3 queue, and
//!   [`ProcedureApp`], which hands each ASDU to the module `dispatch::route`
//!   names (`gi::Interrogation` here).
//! - `init::on_asdu` and its `FollowUp` for the controlling station's answer to
//!   an end of initialisation.
//!
//! The group and the mock peer are driven in lock-step over loopback sockets
//! ([`Endpoint`]); the crate's timers run on the case's own `Instant`, so t0,
//! t1 and t3 expire without a sleep.
//!
//! # Direction
//!
//! Station initialisation is not symmetric in 104: clause 7.1 fixes *"The
//! controlling station is equivalent to the client (connector), the controlled
//! station to the server (listener)"* (index 54). The rows that name a role
//! for a TCP act (creating connections, retrying them, waiting for them) are
//! therefore driven in that role only, and §5.1's swap does not apply to them.
//! The rows that are the same rule for either side are driven in both roles:
//! `5.4.12.30`'s *"the Primary station (whether Controlling or Controlled)"*
//! and its secondary station. No case sends a cause 44–47.
//!
//! # Rows with no case here, and why
//!
//! - **`5.4.12.10`, `Required` `PIXIT`**: *"The Controlled station only allows
//!   Active TCP connections from configured Controlling stations (optional, for
//!   security reasons)"*, and the same row in `5.4.12.20` (`Required` `M`,
//!   *"(optional, for security reasons)"*). Not applicable to this crate: the
//!   core holds no socket and never sees a peer address (the listener and its
//!   accept are the caller's), so the filter is
//!   the application's configuration, not a rule of the library.
//! - **`5.4.12.20` Remote initialisation of the controlled station** and
//!   **`5.4.12.21` Reset of pending information with time tag of the event
//!   buffer**. Their NOTE (index 56): *"The following tests are only required
//!   for systems supporting Remote initialization."* The crate does not support
//!   it: `C_RP_NA_1` `<105>` is `dispatch::Route::NotImplemented` ("A type no
//!   module serves: `C_RP_NA_1`, `C_CD_NA_1`, ..."), and `src/init.rs` says of
//!   figure 22's `Reset_Process` *"This module implements neither."* What such a
//!   station must do instead is 604 `5.4.24.10`'s *"The controlled station
//!   responds with P/N=1negative (with COT = 44, if supported) if a BAF is not
//!   implemented or used"*, which Table 24's module drives with a `C_RP_NA_1`
//!   `QRP = 1` (`table24::clause_5_4_24_10_...`). A station that restarts
//!   itself after a reset is device behaviour in any case (*"reset of layer 7
//!   and User processes"*), outside a sans-IO library.
//! - **`5.4.12.1`, `.10`: *"After its power on, hardware reset or warm
//!   boot"***. A power cycle is not something a test of a library can perform.
//!   The cases start where the rows' observable behaviour starts: a freshly
//!   constructed component, which is what an application builds after a boot.
//! - **`5.4.12.40` COMPATIBILITY WITH OTHER TEST CASES**: the whole suite, not a
//!   case (see `tests/conformance_604.rs`).

use std::net::TcpListener;
use std::time::{Duration, Instant};

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{Coi, Known};
use iec104::gi::{Interrogation, Scope, SecondActivation};
use iec104::init::{self, FollowUp, Reaction as InitReaction};
use iec104::link::{Action, Role, State};
use iec104::params::LinkParams;
use iec104::redundancy::{EndInit, GroupError, RedundancyGroup, Replay, Routed, Switchover};
use iec104::ts::Selection;

use crate::conformance604::apps::{COT_OCTET, ProcedureApp, gi_activation, gi_frame, single_point};
use crate::conformance604::endpoint::{Endpoint, QUIET, refused_addr, soon};
use crate::conformance604::{
    CA, ControlledStation, MonitorPeer, ORIGINATOR, Peer, deadline, interop,
};
use iec104::asdu::Cause;

/// The clause 9 defaults (index 114): `t0 30 s`, `t1 15 s`, `t3 20 s`. Every
/// timer case below reads its expiries off these.
fn params() -> LinkParams {
    LinkParams::default()
}

/// Performs every member's actions on that member's socket.
fn perform(ends: &mut [Endpoint], routed: Vec<Routed>) -> Result<(), String> {
    for Routed { member, actions } in routed {
        ends.get_mut(member)
            .ok_or_else(|| format!("no socket for member {member}"))?
            .perform(&actions)?;
    }
    Ok(())
}

/// Reads one frame on member `index`'s socket and feeds it to the group,
/// performing whatever the group answers.
fn feed(
    group: &mut RedundancyGroup,
    ends: &mut [Endpoint],
    index: usize,
    now: Instant,
) -> Result<(Apci, Vec<u8>), String> {
    let (apci, asdu) = ends[index].read_frame(soon())?;
    let routed = group
        .on_frame_at(index, apci, now)
        .map_err(|e| format!("the group refused {apci:?}: {e:?}"))?;
    perform(ends, routed)?;
    Ok((apci, asdu))
}

/// True when some member's actions close its connection.
fn closes(routed: &[Routed]) -> bool {
    routed.iter().any(|r| {
        r.actions
            .iter()
            .any(|a| matches!(a, Action::ActiveClose(_)))
    })
}

/// 604 Table 12 (1 of 3), PDF page index 55 (printed 54), procedure
/// **`5.4.12.1`**, *"Local Initialisation of the Controlling station:
/// (re-)boot"*, the controlling station's three rows, each `Required` `M`:
///
/// > After its power on, hardware reset or warm boot, the Controlling station
/// > (which may be configured as a fixed selection in case of two equivalent
/// > Controlling stations) starts to create the number of configured Stopped
/// > connections (a TCP connection in STOPDT state) to each configured
/// > Controlled station
///
/// (`Reference` `IEC 60870-5-104:2006, 7.1`)
///
/// > During or after the creation of one or more new Stopped connections, the
/// > Controlling station initiates the creation of exactly one Started
/// > connection to each configured Controlled station by sending a
/// > STARTDT_ACT. This STARTDT_ACT is sent over the Stopped connection that is
/// > configured as the preferred Started connection (if multiple Stopped
/// > connections to the same Controlled station are available) to that
/// > Controlled station
///
/// (`Reference` `IEC 60870-5-104:2006, 5.3`)
///
/// > The Controlling station finishes the Station initialisation by starting
/// > the update of its internal process representation by issuing a General
/// > Interrogation command C_IC_ACT to each Controlled station
///
/// (`Reference` `IEC 60870-5-104:2006, 7.1`)
///
/// DUT: the **controlling** station, one `RedundancyGroup` per configured
/// controlled station: station A with two configured connections (preferred:
/// the second), station B with one. The expected frames come from the rows and
/// the figures: the STARTDT act of clause 5.3 on the preferred connection only,
/// and 5-101 figure 72's `C_IC_NA_1` with cause `<6>` and `QOI` 20 (written out
/// in [`gi_activation`]) once the start is complete. Clause 10.3 (index 120):
/// *"The controlling station shall initiate a station interrogation procedure
/// as soon as possible after the completion of making one of the connections
/// in started state"*, so no interrogation is issued while the start is still
/// pending.
#[test]
fn clause_5_4_12_1_the_controlling_station_starts_one_connection_per_station_and_interrogates() {
    // (configured connections, the preferred one) per controlled station.
    let configured = [(2usize, 1usize), (1, 0)];
    let now = Instant::now();

    for (station, &(connections, preferred)) in configured.iter().enumerate() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("the mock binds");
        let addr = listener.local_addr().expect("the mock's address");
        let mut group = RedundancyGroup::new(Role::Controlling, vec![params(); connections])
            .expect("the group accepts the clause 9 defaults");

        // "starts to create the number of configured Stopped connections".
        let dials = group.tick(now).connect;
        assert_eq!(
            dials,
            (0..connections).collect::<Vec<_>>(),
            "5.4.12.1 (station {station}): one TCP connection per configured connection"
        );
        let mut dut = Vec::new();
        let mut mock = Vec::new();
        for index in dials {
            dut.push(Endpoint::connect(addr).expect("the dial succeeds"));
            mock.push(Endpoint::accept(&listener).expect("the mock accepts"));
            group
                .on_connection_established(index, now)
                .expect("the connection is reported");
        }
        for index in 0..connections {
            assert_eq!(
                group.state(index).unwrap(),
                State::Stopped,
                "5.4.12.1 (station {station}): \"(a TCP connection in STOPDT state)\""
            );
            assert_eq!(
                group.follow_up(index).unwrap(),
                None,
                "5.4.12.1 (station {station}): no interrogation before a start"
            );
        }

        // "exactly one Started connection ... over the Stopped connection that
        // is configured as the preferred Started connection".
        let routed = group.start_at(preferred, now).expect("the group starts");
        assert_eq!(
            routed,
            vec![Routed {
                member: preferred,
                actions: vec![Action::Send(Apci::U(UFunction::StartDtAct))]
            }],
            "5.4.12.1 (station {station}): one STARTDT_ACT, on the preferred connection"
        );
        perform(&mut dut, routed).unwrap();
        mock[preferred]
            .expect_u(UFunction::StartDtAct)
            .expect("the STARTDT act arrives on the preferred connection");
        assert_eq!(
            group.follow_up(preferred).unwrap(),
            None,
            "5.4.12.1 (station {station}): the interrogation follows the *completion* of the start"
        );
        mock[preferred]
            .send_u(UFunction::StartDtCon)
            .expect("the mock confirms");
        feed(&mut group, &mut dut, preferred, now).expect("the con reaches the group");
        assert_eq!(group.state(preferred).unwrap(), State::Started);
        assert_eq!(group.started_index(), Some(preferred));

        // "by issuing a General Interrogation command C_IC_ACT".
        for index in 0..connections {
            let expected = (index == preferred).then_some(FollowUp::StationInterrogation);
            assert_eq!(
                group.follow_up(index).unwrap(),
                expected,
                "5.4.12.1 (station {station}, connection {index}): the interrogation is the \
                 started connection's"
            );
        }
        let mut gi = Interrogation::controlling(SecondActivation::Locked, CA, ORIGINATOR);
        let request = gi.request(Scope::Station).expect("the GI request");
        let routed = group
            .send_user_data_at(preferred, &request, now)
            .expect("the started connection carries it");
        perform(&mut dut, routed).unwrap();
        let (apci, asdu) = mock[preferred].expect_i().expect("the C_IC_ACT arrives");
        assert_eq!(
            apci,
            Apci::I {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0)
            },
            "5.4.12.1 (station {station}): the connection's first I-frame"
        );
        assert_eq!(
            asdu,
            gi_activation(),
            "5.4.12.1 (station {station}): C_IC_ACT, QOI 20 (5-101 figure 72)"
        );

        // Every other connection stayed a Stopped connection with nothing on it.
        for index in (0..connections).filter(|&i| i != preferred) {
            mock[index]
                .quiet()
                .unwrap_or_else(|why| panic!("5.4.12.1 (station {station}, {index}): {why}"));
            assert_eq!(mock[index].received, [] as [std::vec::Vec<u8>; 0]);
            assert_eq!(group.state(index).unwrap(), State::Stopped);
        }
    }
}

/// 604 Table 12 (1 of 3), PDF page index 55 (printed 54), procedure
/// **`5.4.12.1`**, the controlled station's two rows, each `Required` `M`:
///
/// > Each Controlled station enables the Stopped connection over which the
/// > STARTDT_ACT was received by sending a STARTDT_CON over that same
/// > connection to the Controlling station
///
/// (`Reference` `IEC 60870-5-104:2006, 5.3`)
///
/// > Each Controlled station updates the Controlling station with the requested
/// > actual process information in the General interrogation cycle. The normal
/// > telecontrol operations may begin
///
/// (`Reference` `IEC 60870-5-104:2006, 7.1`)
///
/// DUT: the **controlled** station, a `RedundancyGroup` of two connections
/// (clause 10.4, index 124: *"no user data is transmitted from the controlled
/// station until started state on one connection is established"*) with
/// [`ProcedureApp`]'s `gi::Interrogation`. The mock controlling station opens
/// both connections and starts the second. The expected cycle is 5-101 clause
/// 7.4.5's: `C_IC ACTCON` (cause `<7>`), the interrogated object (cause `<20>`),
/// `C_IC ACTTERM` (cause `<10>`), all on the connection that was started.
#[test]
fn clause_5_4_12_1_the_controlled_station_answers_on_the_connection_that_was_started() {
    const STARTED: usize = 1;
    let listener = TcpListener::bind("127.0.0.1:0").expect("the station binds");
    let addr = listener.local_addr().expect("the station's address");
    let now = Instant::now();
    let mut group = RedundancyGroup::new(Role::Controlled, vec![params(); 2]).unwrap();
    let mut app = ProcedureApp::new(Selection::TAGGED);
    let mut mock = Vec::new();
    let mut dut = Vec::new();
    for index in 0..2 {
        mock.push(Endpoint::connect(addr).expect("the mock dials"));
        dut.push(Endpoint::accept(&listener).expect("the station accepts"));
        group.on_connection_established(index, now).unwrap();
    }

    mock[STARTED].send_u(UFunction::StartDtAct).unwrap();
    feed(&mut group, &mut dut, STARTED, now).expect("the act reaches the group");
    mock[STARTED]
        .expect_u(UFunction::StartDtCon)
        .expect("5.4.12.1: \"a STARTDT_CON over that same connection\"");
    assert_eq!(group.started_index(), Some(STARTED));

    mock[STARTED].send_i(0, 0, &gi_activation()).unwrap();
    let (_, asdu) = feed(&mut group, &mut dut, STARTED, now).expect("the GI arrives");
    for answer in app.answer(&asdu).expect("the application answers") {
        let routed = group
            .send_user_data_at(STARTED, &answer, now)
            .expect("the started connection carries the answer");
        perform(&mut dut, routed).unwrap();
    }

    let mut causes = Vec::new();
    for _ in 0..3 {
        let (_, asdu) = mock[STARTED].expect_i().expect("the GI cycle");
        causes.push(asdu[COT_OCTET]);
    }
    assert_eq!(
        causes,
        vec![7, 20, 10],
        "5.4.12.1: \"updates the Controlling station with the requested actual process \
         information in the General interrogation cycle\" (actcon, <20> data, actterm)"
    );
    assert_eq!(
        mock[STARTED].received.last().map(|f| f[6..].to_vec()),
        Some(gi_frame(10)),
        "5.4.12.1: the cycle closes with C_IC ACTTERM, QOI 20"
    );
    mock[0]
        .quiet()
        .expect("5.4.12.1: the connection that was not started carries nothing");
    assert_eq!(mock[0].received, [] as [std::vec::Vec<u8>; 0]);
}

/// 604 Table 12 (1 of 3), PDF page index 55 (printed 54), procedure
/// **`5.4.12.10`**, *"Local initialisation of the Controlled station:
/// (re-)boot"*:
///
/// > After power on, hardware reset or warm boot the Controlled station waits
/// > for the establishment of one or (optional) more TCP connections from the
/// > Controlling station(s) after its transport provider (the TCP stack) and
/// > internal application components are initialised
///
/// (`Reference` `IEC 60870-5-104:2006, 7.1`, `Required` `M`)
///
/// > The Controlled station finishes the creation of exactly one Started
/// > connection by sending a STARTDT_CON after receiving a STARTDT_ACT from the
/// > Controlling station
///
/// (`Reference` `IEC 60870-5-104:2006, 7.1`, `Required` `M`)
///
/// > The Controlled station finishes its local initialisation by sending the
/// > M_EI (End of initialisation) to the Controlling station
///
/// (`Reference` `IEC 60870-5-104:2006, 7.1`, `Required` `PICS, 9.5` *"System
/// info in monitor direction"*)
///
/// > The Controlled station starts the General interrogation procedure to update
/// > the Controlling station with the actual process information after receipt
/// > of the General Interrogation command C_IC_ACT. The normal telecontrol
/// > operations may begin
///
/// (`Reference` `IEC 60870-5-104:2006, 7.1`, `Required` `M`)
///
/// DUT: the **controlled** station, `link::Session` with the end of
/// initialisation handed over at start-up (`init::end_of_initialisation`, COI
/// `<0>` *local power switch on*), which clause 5.3's queue holds until the
/// STARTDT con, and [`ProcedureApp`]'s `gi::Interrogation`. Figure 21 (index
/// 60) draws the order: `STARTDT act`, `STARTDT con`, then the optional
/// `<SEND=M_EI>`, then *"Following function: general interrogation"*. The
/// expected `M_EI_NA_1` is written out from 5-101 clause 7.3.3.1 (index 104):
/// type `70`, `N = 1`, cause `<4> := initialized`, information object address
/// `0`, `COI` `00`.
#[test]
fn clause_5_4_12_10_the_controlled_station_starts_sends_m_ei_and_answers_the_gi() {
    let coi = Coi {
        cause: Coi::LOCAL_POWER_ON,
        changed_local_parameters: false,
    };
    let m_ei = init::end_of_initialisation(coi, CA, ORIGINATOR).expect("the M_EI");
    let station = ControlledStation::start_app(ProcedureApp::new(Selection::TAGGED), vec![m_ei])
        .expect("the station binds");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");

    // "waits": an established connection carries nothing before the STARTDT.
    assert_eq!(
        peer.read_frame(Instant::now() + QUIET).unwrap_err(),
        "no frame before the deadline",
        "5.4.12.10: the station waits for the controlling station"
    );

    peer.send_u(UFunction::StartDtAct).unwrap();
    peer.expect_u(UFunction::StartDtCon, deadline(5))
        .expect("5.4.12.10: \"sending a STARTDT_CON after receiving a STARTDT_ACT\"");

    let (apci, asdu) = peer.expect_i(deadline(5)).expect("the M_EI");
    let [ca_lo, ca_hi] = CA.to_le_bytes();
    assert_eq!(
        asdu,
        vec![70, 0x01, 4, ORIGINATOR, ca_lo, ca_hi, 0, 0, 0, 0x00],
        "5.4.12.10: \"sending the M_EI (End of initialisation)\" (5-101 7.3.3.1, COI 0)"
    );
    assert_eq!(
        apci,
        Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0)
        },
        "5.4.12.10: the M_EI is the station's first I-frame, right after the con"
    );

    peer.send_i(SeqNo::new(0), SeqNo::new(1), &gi_activation())
        .unwrap();
    let mut causes = Vec::new();
    for _ in 0..3 {
        let (_, asdu) = peer.expect_i(deadline(5)).expect("the GI cycle");
        causes.push(asdu[COT_OCTET]);
    }
    assert_eq!(
        causes,
        vec![7, 20, 10],
        "5.4.12.10: \"starts the General interrogation procedure ... after receipt of the \
         General Interrogation command C_IC_ACT\""
    );
    peer.close().unwrap();

    let report = station.join().expect("the station ends cleanly");
    assert!(report.closes.is_empty(), "5.4.12.10: {:?}", report.closes);
    assert_eq!(
        report.sent.len(),
        5,
        "5.4.12.10: STARTDT con, M_EI, actcon, data, actterm and nothing else"
    );
}

/// The controlling station's side of the same row of **`5.4.12.10`** (index 55):
/// the `M_EI` is sent *"because it allows the Controlled station to distinguish
/// between this initiated local initialisation and other connection
/// establishment procedures like lost connections"*, and the row after it has
/// the controlling station's `C_IC_ACT` start the interrogation.
///
/// DUT: the **controlling** station, `interop::Station` with `init::on_asdu`
/// and its `FollowUp`. The mock controlled station sends 5-101 clause
/// 7.3.3.1's `M_EI_NA_1` (written out: cause `<4>`, `COI` `<1>` *local manual
/// reset*, clause 7.2.6.21) right after the STARTDT con; the station reads it as an end of initialisation and answers
/// with the station interrogation 104 figure 21 draws as the *"Following
/// function"*.
#[test]
fn clause_5_4_12_10_the_controlling_station_answers_m_ei_with_a_station_interrogation() {
    let [ca_lo, ca_hi] = CA.to_le_bytes();
    let m_ei = vec![
        70,
        0x01,
        4,
        ORIGINATOR,
        ca_lo,
        ca_hi,
        0,
        0,
        0,
        Coi::LOCAL_MANUAL_RESET,
    ];
    let peer = MonitorPeer::start(m_ei).expect("the mock binds");
    let mut station = interop::Station::connect(peer.addr()).expect("the station connects");
    let actions = station.session_mut().request_start();
    station.send_actions(&actions).unwrap();
    let (_, asdu) = station
        .expect("the M_EI", deadline(5), |apci, _| apci.is_i_format())
        .expect("the mock's M_EI arrives");

    let reaction = init::on_asdu(&asdu, &Known::EVERYTHING).expect("init reads it");
    assert_eq!(
        reaction,
        InitReaction::EndOfInitialisation(Coi {
            cause: Coi::LOCAL_MANUAL_RESET,
            changed_local_parameters: false
        }),
        "5.4.12.10: the controlling station recognises the end of initialisation"
    );
    assert_eq!(
        reaction.follow_up(),
        Some(FollowUp::StationInterrogation),
        "5.4.12.10: the end of initialisation is followed by the general interrogation"
    );
    let mut gi = Interrogation::controlling(SecondActivation::Locked, CA, ORIGINATOR);
    let request = gi.request(Scope::Station).expect("the GI request");
    let action = station
        .session_mut()
        .send_i_frame(&request)
        .expect("a started connection carries it");
    station.send_actions(&[action]).unwrap();
    station.close().unwrap();

    let report = peer.join().expect("the mock ends cleanly");
    let (_, sent) = report
        .received
        .iter()
        .filter_map(|frame| interop::parse_frame(frame).ok())
        .find(|(apci, _)| apci.is_i_format())
        .expect("5.4.12.10: the controlling station sent the interrogation");
    assert_eq!(
        sent,
        gi_activation(),
        "5.4.12.10: C_IC_ACT, QOI 20 (5-101 figure 72)"
    );
}

/// A started connection between the station under test (a group of one
/// connection, `role`) and a mock peer, established and started at `now`.
struct Link {
    group: RedundancyGroup,
    dut: Vec<Endpoint>,
    mock: Endpoint,
    listener: TcpListener,
    now: Instant,
}

/// Builds a [`Link`]: the controlling station dials and starts (clause 7.1,
/// clause 5.3); the controlled station accepts and is started by the mock.
fn started_link(role: Role) -> Link {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let now = Instant::now();
    let mut group = RedundancyGroup::new(role, vec![params()]).unwrap();
    let (dut, mut mock) = match role {
        Role::Controlling => {
            assert_eq!(group.tick(now).connect, vec![0]);
            let dut = Endpoint::connect(addr).unwrap();
            (dut, Endpoint::accept(&listener).unwrap())
        }
        Role::Controlled => {
            let mock = Endpoint::connect(addr).unwrap();
            (Endpoint::accept(&listener).unwrap(), mock)
        }
    };
    let mut dut = vec![dut];
    group.on_connection_established(0, now).unwrap();
    match role {
        Role::Controlling => {
            let routed = group.start_at(0, now).unwrap();
            perform(&mut dut, routed).unwrap();
            mock.expect_u(UFunction::StartDtAct).unwrap();
            mock.send_u(UFunction::StartDtCon).unwrap();
            feed(&mut group, &mut dut, 0, now).unwrap();
        }
        Role::Controlled => {
            mock.send_u(UFunction::StartDtAct).unwrap();
            feed(&mut group, &mut dut, 0, now).unwrap();
            mock.expect_u(UFunction::StartDtCon).unwrap();
        }
    }
    assert_eq!(group.state(0).unwrap(), State::Started);
    Link {
        group,
        dut,
        mock,
        listener,
        now,
    }
}

/// The user data the station under test sends in `role`: a station
/// interrogation from the controlling station, a spontaneous single point from
/// the controlled one.
fn user_data(role: Role) -> Vec<u8> {
    match role {
        Role::Controlling => gi_activation(),
        Role::Controlled => single_point(Cause::Spontaneous),
    }
}

/// 604 Table 12 (3 of 3), PDF page index 57 (printed 56), procedure
/// **`5.4.12.30`**, *"Re-establishing a lost Started connection between the
/// Controlling and the Controlled station when no other connections are
/// available"*, first row, `Reference` `IEC 60870-5-104:2006, 5.3`, `Required`
/// `M`:
///
/// > After the Started connection is inoperable for a longer period than
/// > time-out (t 1 ) allows, the Primary station (whether Controlling or
/// > Controlled) initiates a TCP active close on the Started connection (which
/// > may never arrive)
///
/// DUT: the station that sent the unconfirmed I-frame (the primary), in
/// `role`. The mock never confirms it. Figure 12 (index 34) draws the rule:
/// `Time-out t1` then `Active close`; t1 is 15 s (clause 9's default, index
/// 114), so one second before it nothing closes and at it the connection is
/// closed and the peer reads the FIN.
fn primary_closes_after_t1(role: Role) {
    let mut link = started_link(role);
    let t1 = params().t1;
    let routed = link
        .group
        .send_user_data_at(0, &user_data(role), link.now)
        .unwrap();
    perform(&mut link.dut, routed).unwrap();
    link.mock.expect_i().expect("the primary's I-frame");

    let early = link
        .group
        .tick((link.now + t1).checked_sub(Duration::from_secs(1)).unwrap());
    assert!(
        !closes(&early.routed),
        "5.4.12.30 ({role:?}): nothing closes before t1: {early:?}"
    );
    let due = link.group.tick(link.now + t1);
    assert!(
        closes(&due.routed),
        "5.4.12.30 ({role:?}): \"initiates a TCP active close\" at t1: {due:?}"
    );
    perform(&mut link.dut, due.routed).unwrap();
    assert_eq!(
        link.dut[0].closes,
        vec!["t1 expired with no confirmation"],
        "5.4.12.30 ({role:?})"
    );
    link.mock
        .expect_eof()
        .unwrap_or_else(|why| panic!("5.4.12.30 ({role:?}): {why}"));
}

/// [`primary_closes_after_t1`] with the **controlling** station as the primary.
#[test]
fn clause_5_4_12_30_the_controlling_station_as_primary_closes_after_t1() {
    primary_closes_after_t1(Role::Controlling);
}

/// [`primary_closes_after_t1`] with the **controlled** station as the primary:
/// the row's *"(whether Controlling or Controlled)"*.
#[test]
fn clause_5_4_12_30_the_controlled_station_as_primary_closes_after_t1() {
    primary_closes_after_t1(Role::Controlled);
}

/// 604 Table 12 (3 of 3), PDF page index 57 (printed 56), procedure
/// **`5.4.12.30`**, second row, `Reference` `IEC 60870-5-104:2006, 5.3`,
/// `Required` `M`:
///
/// > After detecting that the Started connection is inoperable and not yet
/// > closed, the Secondary station initiates a TCP active close on the Started
/// > connection (which may never arrive). Both sides of the inoperable Started
/// > connection have been closed now and the Started connection is no longer
/// > present
///
/// DUT: the station with nothing of its own outstanding (the secondary), in
/// `role`. 104 clause 5.2 (index 34): *"Station B has to supervise the
/// connection independently"*; figure 14 (index 36) draws how it detects an
/// inoperable connection: `Time-out t3`, `U (TESTFR act)`, no con, `Time-out
/// t1`, `Active close`. With clause 9's defaults (t3 20 s, t1 15 s) the act is
/// due at 20 s and the close at 35 s.
fn secondary_closes_after_t3_and_t1(role: Role) {
    let mut link = started_link(role);
    let p = params();
    let second = Duration::from_secs(1);

    let idle = link
        .group
        .tick((link.now + p.t3).checked_sub(second).unwrap());
    assert!(idle.routed.is_empty(), "5.4.12.30 ({role:?}): {idle:?}");
    let test = link.group.tick(link.now + p.t3);
    assert_eq!(
        test.routed,
        vec![Routed {
            member: 0,
            actions: vec![Action::Send(Apci::U(UFunction::TestFrAct))]
        }],
        "5.4.12.30 ({role:?}): figure 14's TESTFR act at t3"
    );
    perform(&mut link.dut, test.routed).unwrap();
    link.mock.expect_u(UFunction::TestFrAct).unwrap();

    let early = link
        .group
        .tick((link.now + p.t3 + p.t1).checked_sub(second).unwrap());
    assert!(!closes(&early.routed), "5.4.12.30 ({role:?}): {early:?}");
    let due = link.group.tick(link.now + p.t3 + p.t1);
    assert!(
        closes(&due.routed),
        "5.4.12.30 ({role:?}): \"the Secondary station initiates a TCP active close\": {due:?}"
    );
    perform(&mut link.dut, due.routed).unwrap();
    link.mock
        .expect_eof()
        .unwrap_or_else(|why| panic!("5.4.12.30 ({role:?}): {why}"));
}

/// [`secondary_closes_after_t3_and_t1`] with the **controlling** station as the
/// secondary.
#[test]
fn clause_5_4_12_30_the_controlling_station_as_secondary_closes_an_inoperable_connection() {
    secondary_closes_after_t3_and_t1(Role::Controlling);
}

/// [`secondary_closes_after_t3_and_t1`] with the **controlled** station as the
/// secondary.
#[test]
fn clause_5_4_12_30_the_controlled_station_as_secondary_closes_an_inoperable_connection() {
    secondary_closes_after_t3_and_t1(Role::Controlled);
}

/// 604 Table 12 (3 of 3), PDF page index 57 (printed 56), procedure
/// **`5.4.12.30`**, the controlling station's rows, `Reference`
/// `IEC 60870-5-104:2006, 5.3`, `Required` `M`:
///
/// > After detecting that the Started connection is no longer present, the
/// > Controlling station (which may be configured as a fixed selection in case
/// > of two equivalent Controlling stations) tries to create a new Stopped
/// > connection to the Controlled station at regular intervals
///
/// > After the creation of the new Stopped connection, the Controlling station
/// > initiates the creation of the new Started connection to the Controlled
/// > station by sending a STARTDT_ACT over the new established Stopped
/// > connection
///
/// and the last row's *"Normal operation continues ... and begins the General
/// Interrogation procedure"*.
///
/// DUT: the **controlling** station, a `RedundancyGroup` of one connection.
/// The started connection is lost to t1 (the case above), the first new dial
/// is refused, and the station tries again on its own. The row asks for
/// *"regular intervals"* and 104 fixes no value: figure 21's footnote (index
/// 60) is *"The timer t 0 specifies when open is cancelled, and not when open
/// is retried."* The interval asserted below (one attempt per t0, 30 s, no
/// busy retry) is the crate's documented policy (`src/manager.rs`, *"one
/// attempt per station per t0 expiry, no backoff, no attempt limit"*). The
/// connection here is lost to t1 before its attempt's t0 ran out, so the
/// first new attempt comes when that t0 does (a lost connection is dialed
/// again once per t0, not at once). What the row requires is that the
/// attempts repeat without manual assistance, which the second and third
/// attempts show. The station interrogation after the new
/// start is clause 10.3's `follow_up`; the interrogation of the lost
/// connection is dropped with `gi::Interrogation::reset`, the call its doc
/// names for a connection loss.
#[test]
fn clause_5_4_12_30_the_controlling_station_reconnects_restarts_and_interrogates() {
    let mut link = started_link(Role::Controlling);
    let p = params();
    let mut gi = Interrogation::controlling(SecondActivation::Locked, CA, ORIGINATOR);
    let request = gi.request(Scope::Station).unwrap();
    let routed = link.group.send_user_data_at(0, &request, link.now).unwrap();
    perform(&mut link.dut, routed).unwrap();
    link.mock.expect_i().unwrap();

    // The started connection is lost (t1, as in the case above).
    let lost_at = link.now + p.t1;
    let due = link.group.tick(lost_at);
    assert!(closes(&due.routed));
    perform(&mut link.dut, due.routed).unwrap();
    link.mock.expect_eof().unwrap();
    link.group.on_connection_lost(0).unwrap();
    gi.reset();

    // "tries to create a new Stopped connection ... at regular intervals".
    // Lost before its attempt's t0 ran out: dialed again when it does.
    assert!(
        link.group.tick(lost_at).connect.is_empty(),
        "5.4.12.30: not dialed again within the attempt's t0"
    );
    let reopen = link.now + p.t0;
    let first = link.group.tick(reopen);
    assert_eq!(
        first.connect,
        vec![0],
        "5.4.12.30: the lost connection is dialed again without manual assistance"
    );
    assert!(
        Endpoint::connect(refused_addr().unwrap()).is_err(),
        "the first new dial is refused"
    );
    link.group.on_connection_lost(0).unwrap();
    let busy = link.group.tick(reopen + Duration::from_secs(1));
    assert!(
        busy.connect.is_empty(),
        "5.4.12.30: a refused dial is not retried in a busy loop"
    );
    let second = link.group.tick(reopen + p.t0);
    assert_eq!(second.connect, vec![0], "5.4.12.30: the second attempt");
    assert!(Endpoint::connect(refused_addr().unwrap()).is_err());
    link.group.on_connection_lost(0).unwrap();
    let third = link.group.tick(reopen + p.t0 + p.t0);
    assert_eq!(
        third.connect,
        vec![0],
        "5.4.12.30: the third attempt, one interval after the second"
    );

    let now = reopen + p.t0 + p.t0;
    let addr = link.listener.local_addr().unwrap();
    let mut dut = vec![Endpoint::connect(addr).expect("the controlled station listens again")];
    let mut mock = Endpoint::accept(&link.listener).unwrap();
    link.group.on_connection_established(0, now).unwrap();
    assert_eq!(link.group.state(0).unwrap(), State::Stopped);
    assert_eq!(link.group.follow_up(0).unwrap(), None);

    // "by sending a STARTDT_ACT over the new established Stopped connection".
    let routed = link.group.start_at(0, now).unwrap();
    perform(&mut dut, routed).unwrap();
    mock.expect_u(UFunction::StartDtAct)
        .expect("5.4.12.30: the STARTDT_ACT goes over the new connection");
    mock.send_u(UFunction::StartDtCon).unwrap();
    feed(&mut link.group, &mut dut, 0, now).unwrap();

    // "and begins the General Interrogation procedure".
    assert_eq!(
        link.group.follow_up(0).unwrap(),
        Some(FollowUp::StationInterrogation),
        "5.4.12.30: the new Started connection is followed by the interrogation"
    );
    let request = gi.request(Scope::Station).expect("a fresh interrogation");
    let routed = link.group.send_user_data_at(0, &request, now).unwrap();
    perform(&mut dut, routed).unwrap();
    let (apci, asdu) = mock.expect_i().unwrap();
    assert_eq!(asdu, gi_activation(), "5.4.12.30: C_IC_ACT, QOI 20");
    assert_eq!(
        apci,
        Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0)
        },
        "5.4.12.30: a new connection numbers from zero (104 clause 5.1)"
    );
}

/// 604 Table 12 (3 of 3), PDF page index 57 (printed 56), procedure
/// **`5.4.12.30`**, the controlled station's rows, each `Required` `M`:
///
/// > The Controlled station finishes the creation of the new Started connection
/// > by sending a STARTDT_CON over that same connection over which the
/// > STARTDT_ACT was received to the Controlling station
///
/// (`Reference` `IEC 60870-5-104:2006, 5.3`)
///
/// > After re-establishment of the connection between Controlling and
/// > Controlled station, no M_EI (End of initialisation) is sent (nor needed) to
/// > the Controlling station. Normal operation continues with the application
/// > messages that have not yet been acknowledged (if supported and if
/// > available) and begins the General Interrogation procedure
///
/// DUT: the **controlled** station, a `RedundancyGroup` of one connection. Its
/// spontaneous event is left unconfirmed, t1 closes the connection, and the
/// mock opens a new one. The group issues no end of initialisation for a
/// controlled station (`endinit` refuses it, clause 10.3's ENDINIT is the
/// initialisation *"of the controlling station"*), so nothing but the STARTDT
/// con goes out before the application decides the replay; the unacknowledged
/// event then goes out again on the new connection
/// (`retransmit_unconfirmed`, `Replay::Retransmit`), numbered from zero, and a
/// station interrogation is answered as usual.
#[test]
fn clause_5_4_12_30_the_controlled_station_restarts_without_m_ei_and_replays() {
    let mut link = started_link(Role::Controlled);
    let p = params();
    let mut app = ProcedureApp::new(Selection::TAGGED);
    let event = single_point(Cause::Spontaneous);
    let routed = link.group.send_user_data_at(0, &event, link.now).unwrap();
    perform(&mut link.dut, routed).unwrap();
    link.mock.expect_i().unwrap();

    let lost_at = link.now + p.t1;
    let due = link.group.tick(lost_at);
    assert!(closes(&due.routed));
    assert_eq!(
        due.switchovers,
        vec![Switchover::LeftToTheControllingStation {
            failed: 0,
            unconfirmed: 1
        }],
        "5.4.12.30: the controlled station waits for the controlling station"
    );
    perform(&mut link.dut, due.routed).unwrap();
    link.mock.expect_eof().unwrap();
    link.group.on_connection_lost(0).unwrap();
    app.connection_lost();
    assert!(
        link.group.tick(lost_at + p.t0).connect.is_empty(),
        "5.4.12.30: only the controlling station dials (104 clause 7.1)"
    );

    // The controlling station's new connection, and its STARTDT act.
    let now = lost_at + p.t0;
    let addr = link.listener.local_addr().unwrap();
    let mut mock = Endpoint::connect(addr).unwrap();
    let mut dut = vec![Endpoint::accept(&link.listener).unwrap()];
    link.group.on_connection_established(0, now).unwrap();
    mock.send_u(UFunction::StartDtAct).unwrap();
    feed(&mut link.group, &mut dut, 0, now).unwrap();
    mock.expect_u(UFunction::StartDtCon)
        .expect("5.4.12.30: \"a STARTDT_CON over that same connection\"");

    // "no M_EI ... is sent".
    assert_eq!(
        link.group.endinit(EndInit {
            reverse_direction_data: true,
            coi: Coi::default(),
            common_address: CA,
            originator: ORIGINATOR,
        }),
        Err(GroupError::CannotSelect),
        "5.4.12.30: the controlled group issues no end of initialisation"
    );
    mock.quiet()
        .expect("5.4.12.30: nothing follows the con of its own accord, no M_EI");

    // "continues with the application messages that have not yet been
    // acknowledged".
    let (_, routed) = link
        .group
        .retransmit_unconfirmed_at(0, Replay::Retransmit, now)
        .expect("the unacknowledged event is replayed");
    perform(&mut dut, routed).unwrap();
    let (apci, asdu) = mock.expect_i().unwrap();
    assert_eq!(
        asdu, event,
        "5.4.12.30: the unacknowledged event, unchanged"
    );
    assert_eq!(
        apci,
        Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0)
        },
        "5.4.12.30: numbered on the new connection (104 clause 5.1)"
    );

    // "and begins the General Interrogation procedure".
    mock.send_i(0, 1, &gi_activation()).unwrap();
    let (_, asdu) = feed(&mut link.group, &mut dut, 0, now).unwrap();
    for answer in app.answer(&asdu).unwrap() {
        let routed = link.group.send_user_data_at(0, &answer, now).unwrap();
        perform(&mut dut, routed).unwrap();
    }
    let mut causes = Vec::new();
    for _ in 0..3 {
        causes.push(mock.expect_i().unwrap().1[COT_OCTET]);
    }
    assert_eq!(causes, vec![7, 20, 10], "5.4.12.30: the GI cycle");
}
