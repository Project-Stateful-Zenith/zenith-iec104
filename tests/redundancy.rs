//! The redundancy group: the model and the seven general rules of
//! IEC 60870-5-104:2006 clause 10, the station initialisation of
//! clauses 10.3 (figure 32) and 10.4 (figure 33), the user-data routing and
//! t1-driven switchover of clauses 10.5 (figure 34) and 10.6 (figure 35), and
//! clause 10.7's state-transition diagrams (figures 36 and 37) with the close
//! rule, the manual switchover and the asymmetric `t1`.
//!
//! The clause citations are 5-104 cl.10 "Redundant connections" with 10.1
//! General and 10.2 General requirements (PDF page index 116, printed page 115)
//! and the seven general rules with 10.2's naming and selection sentences (page
//! index 118, printed 117); 10.3 Initialisation of controlling station (index
//! 120, printed 119) with figure 32 (index 122, printed 121; its NOTE is on the
//! same page); 10.4 Initialisation of controlled station (index 124, printed
//! 123) with figure 33 (index 126, printed 125); 10.5 User data from
//! controlling station (index 128, printed 127) with figure 34 (index 130,
//! printed 129); and 10.6 User data from controlled station (index 132, printed
//! 131) with figure 35 (index 134, printed 133); 10.7 State transition diagrams
//! (index 136, printed 135) with figure 36, the controlled station's (index 138,
//! printed 137) and figure 37, the controlling station's (index 140, printed
//! 139); cl.7.1's *"Connection establishment is performed by the controlling
//! station in case of a controlled station as a partner"* (page index 54,
//! printed 53); cl.5.3 for STARTDT/STOPDT as the selection mechanism and
//! cl.5.2 for the TESTFR supervision of rule 5; 5-101 cl.7.2.6.21 for the `COI` the ENDINIT carries;
//! and TS 60870-5-604 Table 13, *"Redundant link conformance test procedures"*
//! (page indices 58–60, printed 57–59), whose four cases `5.4.13.1`,
//! `5.4.13.10`, `5.4.13.20` and `5.4.13.30` each cite *"IEC 60870-5-104:2006,
//! 10"*.
//!
//! Most tests name the rule or clause they pin. The group is a value with no I/O: the
//! caller owns the TCP connections (cl.7.1), the clock (`Instant`s injected into
//! the members' `Timers`) and the process image (rule 6).

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]

use std::time::{Duration, Instant};

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{Cause, Coi, Header, TypeId};
use iec104::gi::{self, Scope};
use iec104::init::{FollowUp, end_of_initialisation};
use iec104::link::{Action, MAX_PENDING_USER_DATA, QueueError, Role, State, Timer};
use iec104::params::{LinkParams, ParamError};
use iec104::redundancy::{
    EndInit, GroupError, RedundancyGroup, Replay, ReplayOutcome, Switchover, TickOutcome,
    TimeoutOutcome,
};

/// The ASDU a calling station sends: `C_IC_NA_1`, cause 6 (activation), common
/// address 12, information object address 0, `QOI` 20: the station
/// interrogation 5-104 clause 10.3 asks for *"as soon as possible after the
/// completion of making one of the connections in started state"*.
fn station_interrogation() -> Vec<u8> {
    vec![0x64, 0x01, 0x06, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x14]
}

/// The I-frames a list of actions wants sent, as `(N(S), N(R), ASDU)`.
fn sent_i(actions: &[Action]) -> Vec<(u16, u16, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::SendI { ns, nr, asdu } => Some((ns.get(), nr.get(), asdu.clone())),
            _ => None,
        })
        .collect()
}

/// The U-function the actions want sent, if any.
fn sent_u(actions: &[Action]) -> Option<UFunction> {
    actions.iter().find_map(|a| match a {
        Action::Send(Apci::U(f)) => Some(*f),
        _ => None,
    })
}

/// A controlling-station group of `count` members that share the default link
/// parameters, with member `started` selected as the started connection.
fn controlling_group(count: usize, started: usize) -> RedundancyGroup {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), count).expect("group");
    group
        .select(started)
        .expect("the selection is the caller's");
    group
}

/// Drives one member of a controlling group through the STARTDT procedure of
/// clause 5.3, so its session is in the started state.
fn start_member(group: &mut RedundancyGroup, index: usize) {
    let member = group.member_mut(index).expect("a member");
    member.session_mut().on_connection_established();
    let actions = member.session_mut().request_start();
    assert_eq!(
        sent_u(&actions),
        Some(UFunction::StartDtAct),
        "figure 37's `Start connection[]/Send STARTDT act`"
    );
    member
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.state(index), Ok(State::Started));
}

// ------------------------------------------------------------------- rule 1

/// Rule 1: *"The controlling and controlled station shall be able to handle
/// multiple (N) logical connections."*
#[test]
fn rule_1_the_group_handles_multiple_logical_connections() {
    let group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 3).expect("a group");
    assert_eq!(group.len(), 3);
    assert!(!group.is_empty());
    assert_eq!(group.members().len(), 3);
    assert_eq!(group.role(), Role::Controlling);

    // N is the parameter list's length, and every member is addressable.
    for index in 0..3 {
        assert_eq!(group.state(index), Ok(State::Stopped), "member {index}");
        assert_eq!(group.member(index).expect("a member").params().k, 12);
    }

    // One connection is the standard's case (10.1: *"mainly focuses on the use
    // of a single TCP connection"*), and it is a group of one here.
    let single =
        RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 1).expect("a group");
    assert_eq!(single.len(), 1);
    assert_eq!(single.state(0), Ok(State::Stopped));
}

/// Rule 1, second half: each logical connection is its own state machine with
/// its own time-outs. 10.2's *"Send and receive counters on each connection
/// within a redundancy group continue their functionality independently of the
/// use of STARTDT/STOPDT"* needs separate counters, and clause 10.7's *"set the
/// values of the timers t0 to t3 individually for each connection"* needs
/// separate schedulers.
#[test]
fn rule_1_every_member_is_a_session_with_its_own_timers() {
    let group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("a group");
    let mut group = group;
    let start = Instant::now();

    // Arming member 0's t3 does not arm member 1's.
    group
        .member_mut(0)
        .expect("a member")
        .timers_mut()
        .connection_established(start);
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .timers()
            .deadline(Timer::T3),
        Some(start + LinkParams::default().t3)
    );
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .timers()
            .deadline(Timer::T3),
        None,
        "each connection has its own scheduler"
    );
}

// ------------------------------------------------------------------- rule 2

/// Rule 2: *"The N logical connections represent one redundancy group."*
#[test]
fn rule_2_the_n_connections_represent_one_group() {
    let group =
        RedundancyGroup::new(Role::Controlling, vec![LinkParams::default(); 4]).expect("a group");
    assert_eq!(group.len(), 4);
    // The group is the members: the same connection is reachable by index and
    // through the slice, and it is one member, not a copy.
    assert_eq!(group.members()[2].state(), State::Stopped);
    assert_eq!(group.state(2), Ok(group.members()[2].state()));
}

/// Rule 2, the other way round: zero logical connections are not one redundancy
/// group, so the constructor refuses rather than building a group that can
/// select and route nothing.
#[test]
fn rule_2_a_group_with_no_members_is_refused() {
    assert_eq!(
        RedundancyGroup::new(Role::Controlling, Vec::new()).err(),
        Some(GroupError::NoMembers)
    );
    assert_eq!(
        RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 0).err(),
        Some(GroupError::NoMembers)
    );
}

// ------------------------------------------------------------------- rule 3

/// Rule 3: *"Only one logical connection is in the started state and
/// sending/receiving user data at a time for one redundancy group."* No started
/// connection means nobody may carry user data.
#[test]
fn rule_3_no_started_connection_carries_no_user_data() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("a group");
    assert_eq!(group.started(), Err(GroupError::NoStartedConnection));
    assert_eq!(group.started_index(), None);
    assert_eq!(group.route(0), Err(GroupError::NoStartedConnection));
    assert_eq!(
        group.send_user_data(0, &station_interrogation()).err(),
        Some(GroupError::NoStartedConnection)
    );
}

/// Rule 3: naming a member that is not the started connection is a typed
/// refusal. The group does not quietly route it to the one that *is* started.
#[test]
fn rule_3_only_the_started_connection_may_carry_user_data() {
    let group = controlling_group(2, 0);
    assert_eq!(group.started(), Ok(0));
    assert_eq!(group.route(0), Ok(0));
    assert_eq!(
        group.route(1),
        Err(GroupError::NotStartedConnection { index: 1 })
    );

    let mut group = group;
    assert_eq!(
        group.send_user_data(1, &station_interrogation()).err(),
        Some(GroupError::NotStartedConnection { index: 1 })
    );
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .outstanding_i_frames(),
        0
    );
}

/// Rule 3: user data leaves on the started connection and on no other.
#[test]
fn rule_3_user_data_goes_out_on_exactly_one_connection() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);

    let action = group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection takes it")
        .expect("its state allows user data");
    assert_eq!(
        action,
        Action::SendI {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0),
            asdu: station_interrogation(),
        }
    );

    // The stopped connection saw none of it.
    let other = group.member(1).expect("a member").session();
    assert_eq!(other.v_s().get(), 0);
    assert_eq!(other.v_r().get(), 0);
    assert_eq!(other.outstanding_i_frames(), 0);
    assert_eq!(other.pending_user_data(), 0);
}

/// Rule 3 as the requirement *"no duplicate delivery of the same ASDU across
/// the group"*: one ASDU offered twice reaches the wire
/// once per offer, on one connection, and a second connection never gets a copy
/// of it.
#[test]
fn rule_3_the_same_asdu_offered_twice_reaches_one_connection() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);

    let mut sent = Vec::new();
    for _ in 0..2 {
        let action = group
            .send_user_data(0, &station_interrogation())
            .expect("the started connection takes it")
            .expect("its state allows user data");
        sent.extend(sent_i(std::slice::from_ref(&action)));
    }
    assert_eq!(
        sent,
        vec![
            (0, 0, station_interrogation()),
            (1, 0, station_interrogation())
        ]
    );
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .outstanding_i_frames(),
        0,
        "the stopped connection never carries a copy"
    );
}

/// Rule 3: when the started connection cannot put the ASDU on the wire yet, it
/// is held by *that* connection's clause 5.3 queue. The group holds no queue
/// and no second connection picks it up.
#[test]
fn rule_3_data_waits_in_the_connection_that_will_carry_it() {
    let mut group = controlling_group(2, 0);
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_connection_established();

    // The STARTDT act has not gone out yet, so the selected connection is still
    // `Stopped` and clause 5.3 holds the data.
    assert_eq!(group.state(0), Ok(State::Stopped));
    assert_eq!(group.send_user_data(0, &station_interrogation()), Ok(None));
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        1
    );
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .pending_user_data(),
        0
    );

    // The STARTDT act releases it, together with the act itself (clause 5.3:
    // "The controlling station may send commands or setpoints even if it has not
    // yet received the activation confirmation").
    let actions = group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .request_start();
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(sent_i(&actions), vec![(0, 0, station_interrogation())]);
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        0
    );
}

/// Rule 3: a connection that is gone carries nothing, and the group does not
/// hold the ASDU for it either: it comes back as the link layer's own refusal.
#[test]
fn rule_3_a_terminated_connection_refuses_the_data() {
    let mut group = controlling_group(2, 0);
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_connection_lost();
    assert_eq!(group.state(0), Ok(State::Terminated));
    assert_eq!(
        group.send_user_data(0, &station_interrogation()).err(),
        Some(GroupError::Queue(QueueError::NotConnected))
    );
}

/// Rule 3 is about members, so a name that is no member of the group is its own
/// typed refusal, in that order.
#[test]
fn rule_3_a_member_index_out_of_range_is_a_typed_refusal() {
    let group = controlling_group(2, 0);
    let out_of_range = GroupError::MemberIndexOutOfRange {
        index: 2,
        members: 2,
    };
    assert_eq!(group.member(2).err(), Some(out_of_range));
    assert_eq!(group.state(2).err(), Some(out_of_range));
    assert_eq!(group.route(2).err(), Some(out_of_range));

    let mut group = group;
    assert_eq!(group.member_mut(2).err(), Some(out_of_range));
    assert_eq!(group.select(2).err(), Some(out_of_range));
    assert_eq!(
        group.send_user_data(2, &station_interrogation()).err(),
        Some(out_of_range)
    );
}

// ------------------------------------------------------------------- rule 4

/// Rule 4: *"The controlling station decides which one of the N connections is
/// be in started state."*
#[test]
fn rule_4_the_controlling_station_decides() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 3).expect("a group");
    assert_eq!(group.started(), Err(GroupError::NoStartedConnection));

    group.select(1).expect("the controlling station selects");
    assert_eq!(group.started(), Ok(1));
    assert_eq!(group.started_index(), Some(1));
    assert_eq!(group.route(1), Ok(1));

    // A second decision moves the naming; nothing else changes, because the
    // STARTDT/STOPDT procedures across members are 10.3–10.7.
    group.select(2).expect("a new decision");
    assert_eq!(group.started(), Ok(2));
    assert_eq!(
        group.route(0),
        Err(GroupError::NotStartedConnection { index: 0 })
    );
    assert_eq!(group.state(1), Ok(State::Stopped));
}

/// Rule 4: *"the selection and switchover of the started connection is always
/// initiated by the controlling station"* (index 118). A controlled station
/// does not select at all.
#[test]
fn rule_4_a_controlled_station_does_not_select() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 3).expect("a group");
    assert_eq!(group.select(0), Err(GroupError::CannotSelect));
    assert_eq!(group.select(1), Err(GroupError::CannotSelect));
    assert_eq!(group.started_index(), None);
}

/// Rule 4: a controlling station's naming is its own decision, not something it
/// takes from a peer's `STARTDT_ACT`.
#[test]
fn rule_4_a_controlling_station_does_not_take_its_naming_from_an_act() {
    let mut group = controlling_group(2, 0);
    assert_eq!(group.observe_startdt_act(1), Err(GroupError::CannotSelect));
    assert_eq!(group.started(), Ok(0));
}

/// Rule 4's controlled half, verbatim: *"The controlled station (station B)
/// always understands the connection on which it last received a `STARTDT_ACT` as
/// the started connection."* The naming is positional, not stateful.
#[test]
fn rule_4_the_controlled_station_names_the_last_connection_it_saw_an_act_on() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 3).expect("a group");
    assert_eq!(group.started(), Err(GroupError::NoStartedConnection));

    group.observe_startdt_act(1).expect("an act arrived on 1");
    assert_eq!(group.started(), Ok(1));
    group.observe_startdt_act(2).expect("an act arrived on 2");
    assert_eq!(group.started(), Ok(2));
    assert_eq!(
        group.route(1),
        Err(GroupError::NotStartedConnection { index: 1 })
    );

    // A repeated act on the same connection names the same connection again:
    // clause 5.3 answers every STARTDT act with a STARTDT con, a
    // retransmission included, so this is not a refusal.
    group.observe_startdt_act(2).expect("a repeated act");
    assert_eq!(group.started(), Ok(2));
}

/// Rule 4: naming the connection that already is the group's is the "already in
/// the state the caller asks for" refusal, and it reports the member's own state
/// (the only place a connection state lives).
#[test]
fn rule_4_naming_the_connection_already_selected_is_refused() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    assert_eq!(group.state(0), Ok(State::Started));
    assert_eq!(
        group.select(0),
        Err(GroupError::AlreadyInState {
            index: 0,
            state: State::Started,
        })
    );
    // The other connection is a new decision, not a refusal.
    group.select(1).expect("a new decision");
    assert_eq!(group.started(), Ok(1));
}

// ------------------------------------------------------------------- rule 5

/// Rule 5: *"All logical connections of a redundancy group shall be supervised
/// by test frames as described in 5.2."* TS 60870-5-604 `5.4.13.1` (index 58,
/// *"Periodic check of ALL redundant connections"*) makes the same point: t3 runs
/// on the started connection **and on all the stopped connections**.
#[test]
fn rule_5_every_connection_is_supervised_by_its_own_test_frames() {
    let params = LinkParams::default();
    let mut group = RedundancyGroup::uniform(Role::Controlling, params, 3).expect("a group");
    group.select(0).expect("a selection");
    let start = Instant::now();

    for index in 0..group.len() {
        let member = group.member_mut(index).expect("a member");
        member.session_mut().on_connection_established();
        member.timers_mut().connection_established(start);
    }

    for index in 0..group.len() {
        let member = group.member_mut(index).expect("a member");
        assert_eq!(
            member.session().state(),
            State::Stopped,
            "connection {index} still tests while stopped (clause 5.2: \"Unused, \
             but open, connections may be periodically tested\")"
        );
        assert_eq!(
            member.timers_mut().expired(start + params.t3),
            vec![Timer::T3],
            "t3 on connection {index}"
        );
        let actions = member.session_mut().on_timeout(Timer::T3);
        assert_eq!(sent_u(&actions), Some(UFunction::TestFrAct));
    }
}

/// 10.2: *"Send and receive counters on each connection within a redundancy
/// group continue their functionality independently of the use of
/// STARTDT/STOPDT."* The started connection's counters survive a full
/// STOPDT→STARTDT cycle; the stopped connection keeps its own at zero.
///
/// TS 60870-5-604's `5.4.13.10` (page index 58, the automatic switch-over case)
/// corroborates the sentence: *"The send- and receive counters are not reset to
/// \"0\" as long as the TCP connection is established."*
#[test]
fn the_counters_of_each_connection_stay_independent() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);

    // N(S) leaves zero on the started connection, and only there.
    group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("an I-frame");
    assert_eq!(group.member(0).expect("a member").session().v_s().get(), 1);
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 0);

    // One I-frame arrives from the peer on the same connection: its N(R) 1
    // acknowledges the frame we sent, and V(R) moves to 1. Neither counter is
    // reset by the STOPDT/STARTDT that follows.
    let actions = group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(1),
        });
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::DeliverData { .. })),
        "the peer's frame is delivered"
    );
    assert_eq!(group.member(0).expect("a member").session().v_r().get(), 1);

    // A full STOPDT cycle: STOPDT act out, STOPDT con in.
    let member = group.member_mut(0).expect("a member");
    let actions = member.session_mut().request_stop();
    assert_eq!(
        sent_u(&actions),
        Some(UFunction::StopDtAct),
        "figure 18's `Stop connection[]/Send STOPDT act`"
    );
    member.session_mut().on_frame(Apci::U(UFunction::StopDtCon));
    assert_eq!(group.state(0), Ok(State::Stopped));

    // ... and a new STARTDT cycle, back to the started state.
    let member = group.member_mut(0).expect("a member");
    let actions = member.session_mut().request_start();
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    member
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.state(0), Ok(State::Started));

    // The counters continue `their functionality independently of the use of
    // STARTDT/STOPDT`: the next frame is N(S) 1, not N(S) 0, and V(R) is still
    // the 1 the peer's earlier frame left (TS 60870-5-604 5.4.13.10: they are
    // not reset as long as the TCP connection is established, and no
    // `on_connection_established` ran here).
    let action = group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("an I-frame");
    let sent = sent_i(std::slice::from_ref(&action));
    assert_eq!(sent[0].0, 1, "N(S) continues across STOPDT/STARTDT");
    assert_eq!(group.member(0).expect("a member").session().v_s().get(), 2);
    assert_eq!(group.member(0).expect("a member").session().v_r().get(), 1);

    // The stopped connection carried none of it: its counters are still zero,
    // and an I-frame arriving there is clause 5.3's `I-frame[]/Active close`
    // (figure 18), which leaves that receive counter exactly where it was.
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 0);
    let actions = group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0),
        });
    assert!(
        actions.iter().any(|a| matches!(a, Action::ActiveClose(_))),
        "clause 5.3 closes a connection that receives I-frames while stopped"
    );
    assert_eq!(group.member(1).expect("a member").session().v_r().get(), 0);
}

/// Rule 5 with clause 10.7's words (index 136): *"It should be possible to set
/// the values of the timers t0 to t3 individually for each connection within a
/// redundancy group."* Each member carries its own parameters, so two members of
/// one group may run different `t1`. The same clause's *asymmetric* `t1` is the
/// case of *"shorter t1 in the controlling station than in the controlled
/// station"*, i.e. between the two stations of a group, not between two members
/// of one station's group. What a group *does* when a member's `t1` expires is
/// 10.7's behaviour, pinned by
/// [`clause_10_7_the_asymmetric_t1_switches_over_on_the_shorter_timeout`].
#[test]
fn rule_5_each_connection_carries_its_own_time_outs() {
    let fast = LinkParams {
        t1: Duration::from_secs(5),
        t2: Duration::from_secs(1),
        ..LinkParams::default()
    };
    let slow = LinkParams {
        t1: Duration::from_secs(15),
        ..LinkParams::default()
    };
    let mut group = RedundancyGroup::new(Role::Controlling, vec![fast, slow]).expect("a group");
    assert_eq!(group.member(0).expect("a member").params().t1, fast.t1);
    assert_eq!(group.member(1).expect("a member").params().t1, slow.t1);

    let start = Instant::now();
    for index in 0..group.len() {
        group
            .member_mut(index)
            .expect("a member")
            .timers_mut()
            .frame_sent(start);
    }
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .timers()
            .deadline(Timer::T1),
        Some(start + Duration::from_secs(5))
    );
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .timers()
            .deadline(Timer::T1),
        Some(start + Duration::from_secs(15)),
        "two members of one group carry different t1 (10.7, index 136: \"set the \
         values of the timers t0 to t3 individually for each connection\")"
    );
}

// ------------------------------------------------------------------- rule 6

/// Rule 6: *"A redundancy group shall rely upon only one process image
/// (database/event buffer)."* The image is the caller's: the group routes the
/// octets it is handed, byte for byte, and stores none of them; `src/rd.rs` and
/// `src/gi.rs` take their data the same way.
#[test]
fn rule_6_the_group_holds_no_process_image() {
    let mut group = controlling_group(1, 0);
    start_member(&mut group, 0);

    let first = station_interrogation();
    let action = group
        .send_user_data(0, &first)
        .expect("the started connection")
        .expect("an I-frame");
    assert_eq!(
        sent_i(std::slice::from_ref(&action)),
        vec![(0, 0, first.clone())]
    );
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        0,
        "the group kept no copy of what it routed"
    );

    // A second ASDU from the caller goes out as the caller wrote it: the group
    // has no buffer of its own to enrich or reorder it in.
    let second = vec![0x64, 0x01, 0x07, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x14];
    let action = group
        .send_user_data(0, &second)
        .expect("the started connection")
        .expect("an I-frame");
    assert_eq!(sent_i(std::slice::from_ref(&action)), vec![(1, 0, second)]);
}

// ------------------------------------------------------------------- rule 7

/// Rule 7: *"If more than one controlling station need to access the same
/// controlled station simultaneously, each controlling station must be assigned
/// to a different redundancy group (process image)."* Two groups are two
/// independent process images and two independent sets of counters.
#[test]
fn rule_7_each_controlling_station_gets_its_own_group() {
    let mut first = controlling_group(1, 0);
    let mut second = controlling_group(1, 0);
    start_member(&mut first, 0);
    start_member(&mut second, 0);

    first
        .send_user_data(0, &station_interrogation())
        .expect("the first group's started connection")
        .expect("an I-frame");

    assert_eq!(first.member(0).expect("a member").session().v_s().get(), 1);
    assert_eq!(second.member(0).expect("a member").session().v_s().get(), 0);
    assert_eq!(
        second
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        0
    );
    assert_eq!(second.started(), Ok(0));
}

// ---------------------------------------------- the group's own construction

/// The link layer's own refusals are passed through rather than re-invented: a
/// parameter set the standard's ranges reject fails at construction, so no
/// member ever exists with an inadmissible k, w, t0–t3.
#[test]
fn a_member_with_inadmissible_parameters_is_refused() {
    let bad_k = LinkParams {
        k: 0,
        ..LinkParams::default()
    };
    assert_eq!(
        RedundancyGroup::new(Role::Controlling, vec![bad_k]).err(),
        Some(GroupError::Params(ParamError::KOutOfRange(0)))
    );
    assert_eq!(
        RedundancyGroup::uniform(Role::Controlled, bad_k, 1).err(),
        Some(GroupError::Params(ParamError::KOutOfRange(0)))
    );

    // A group of two members is refused when the second set is inadmissible:
    // the group is not built half-valid.
    let bad_t2 = LinkParams {
        t1: Duration::from_secs(5),
        t2: Duration::from_secs(5),
        ..LinkParams::default()
    };
    assert_eq!(
        RedundancyGroup::new(Role::Controlling, vec![LinkParams::default(), bad_t2]).err(),
        Some(GroupError::Params(ParamError::T2NotLessThanT1 {
            t1: 5,
            t2: 5
        }))
    );
}

// ---------------------------------------------------------- 10.3 (figure 32)

/// 10.3's `ENDINIT.req` as the caller's typed parameter. Figure 32 (index 122,
/// printed 121) prints the primitive as `A_ENDINIT.req` and `<SEND=M_EI>` with
/// `(optional)`. The ASDU itself is built by `init::end_of_initialisation`
/// (`src/init.rs`); this is only the parameter.
const fn endinit(reverse_direction_data: bool) -> EndInit {
    EndInit {
        reverse_direction_data,
        coi: Coi {
            cause: Coi::LOCAL_MANUAL_RESET,
            changed_local_parameters: false,
        },
        common_address: 12,
        originator: 0,
    }
}

/// 10.3, verbatim (PDF page index 120, printed 119): *"After connection
/// establishment, the stopped state is always default, and one of the
/// connections (e.g. connection 1) is therefore changed from the stopped into
/// the started state to enable user data transfer on this connection."*
///
/// Figure 32 (index 122) draws the change as *"send STARTDT"* / `U (STARTDT
/// act)` on the one connection, *"receive STARTDT"* / `U (STARTDT con)` on the
/// other station, and the box `STARTED`. Establishment itself is clause 7.1's
/// and stays the caller's ([`Session::on_connection_established`]); stopped is
/// the state the group finds afterwards.
#[test]
fn clause_10_3_the_stopped_state_is_the_default_after_establishment() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 3).expect("a group");

    // The connections come up, here in a different order than their indices,
    // per figure 32's NOTE below.
    for index in [2, 0, 1] {
        group
            .member_mut(index)
            .expect("a member")
            .session_mut()
            .on_connection_established();
    }
    for index in 0..group.len() {
        assert_eq!(group.state(index), Ok(State::Stopped), "member {index}");
    }
    assert_eq!(group.started(), Err(GroupError::NoStartedConnection));

    // One connection is changed from the stopped into the started state: the
    // STARTDT act of clause 5.3, through that member's own `request_start`.
    let actions = group
        .start(1)
        .expect("the controlling station starts one connection");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(sent_i(&actions), Vec::new(), "the act is the whole of it");
    assert_eq!(group.state(1), Ok(State::PendingStarted));
    assert_eq!(
        group.started(),
        Ok(1),
        "the group names the connection it started"
    );

    // `U (STARTDT con)` comes back: the connection is in the started state.
    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.state(1), Ok(State::Started));
}

/// 10.3's one connection, against rule 3 (index 118): *"Only one logical
/// connection is in the started state and sending/receiving user data at a time
/// for one redundancy group."* The group starts the connection it is asked to
/// start and leaves the other N-1 in the stopped state, sending no act for
/// them.
#[test]
fn clause_10_3_only_one_connection_is_started() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 3).expect("a group");
    for index in 0..group.len() {
        group
            .member_mut(index)
            .expect("a member")
            .session_mut()
            .on_connection_established();
    }

    let actions = group.start(2).expect("one connection is started");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    group
        .member_mut(2)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));

    let started: Vec<usize> = (0..group.len())
        .filter(|&index| group.state(index) == Ok(State::Started))
        .collect();
    assert_eq!(
        started,
        vec![2],
        "exactly one connection is in the started state"
    );
    assert_eq!(group.started(), Ok(2));
    assert_eq!(group.route(2), Ok(2));
    assert_eq!(
        group.route(0),
        Err(GroupError::NotStartedConnection { index: 0 })
    );
    assert_eq!(
        group.route(1),
        Err(GroupError::NotStartedConnection { index: 1 })
    );

    // The other two connections never saw an act: each is where the group left
    // it, with its own session untouched.
    for index in [0, 1] {
        let session = group.member(index).expect("a member").session();
        assert_eq!(session.state(), State::Stopped, "member {index}");
        assert!(!session.user_data_allowed(), "member {index}");
        assert_eq!(session.v_s().get(), 0);
    }
}

/// 10.3, verbatim (index 120): *"The ENDINIT.req (optional but recommended,
/// Figures 32 and 33) may always be useful to advise the other station that the
/// sending station is now ready to respond to an interrogation request. In case
/// of initialisation of the controlling station, it is only issued if data in
/// the reverse direction is defined."*
///
/// The frame is the `M_EI_NA_1` of `init::end_of_initialisation`, handed to
/// the started connection exactly as any other user ASDU is (rule 3). The
/// group invents no second frame of its own.
#[test]
fn clause_10_3_endinit_is_issued_only_if_the_reverse_direction_is_defined() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("a group");
    for index in 0..group.len() {
        group
            .member_mut(index)
            .expect("a member")
            .session_mut()
            .on_connection_established();
    }

    // Before any start: nothing is issued when the reverse direction is not
    // defined, and a defined one has no started connection to go out on.
    assert_eq!(group.endinit(endinit(false)), Ok(None));
    assert_eq!(
        group.endinit(endinit(true)),
        Err(GroupError::NoStartedConnection)
    );

    let actions = group.start(0).expect("one connection is started");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));

    // Not defined: no frame goes out, on any connection.
    assert_eq!(group.endinit(endinit(false)), Ok(None));
    let member = group.member(0).expect("a member").session();
    assert_eq!(member.pending_user_data(), 0);
    assert_eq!(member.v_s().get(), 0);

    // Defined: the ENDINIT goes out on the started connection, and it is
    // `end_of_initialisation`'s frame, byte for byte.
    let expected = end_of_initialisation(endinit(true).coi, 12, 0).expect("the frame");
    let action = group
        .endinit(endinit(true))
        .expect("issued")
        .expect("an I-frame");
    assert_eq!(
        action,
        Action::SendI {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0),
            asdu: expected.clone(),
        }
    );
    let header = Header::parse(&expected).expect("a header");
    assert_eq!(header.type_id, TypeId::MEiNa1);
    assert_eq!(header.cause, Cause::Initialized);
    assert_eq!(header.common_address, 12);
    assert_eq!(group.member(0).expect("a member").session().v_s().get(), 1);
    assert_eq!(
        group.member(1).expect("a member").session().v_s().get(),
        0,
        "the stopped connection carries no ENDINIT"
    );
}

/// 10.3, verbatim (index 120): *"The controlling station shall initiate a
/// station interrogation procedure as soon as possible after the completion of
/// making one of the connections in started state as shown in Figures 32 and
/// 33."* Figure 32 (index 122) prints it as the box *"Following function:
/// Station interrogation"*.
///
/// The value is `init::FollowUp::StationInterrogation`; the request it names is
/// `gi::request`.
#[test]
fn clause_10_3_the_station_interrogation_follows_the_first_started_connection() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 3).expect("a group");
    for index in 0..group.len() {
        group
            .member_mut(index)
            .expect("a member")
            .session_mut()
            .on_connection_established();
    }

    let actions = group.start(0).expect("one connection is started");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    // The act is out, the confirmation is not: the connection has not completed
    // its start, so no interrogation is due yet.
    assert_eq!(group.state(0), Ok(State::PendingStarted));
    assert_eq!(group.follow_up(0), Ok(None));

    // `U (STARTDT con)` completes the start: now the interrogation is due, and
    // only on the one connection, "one of the connections ... in started state".
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.state(0), Ok(State::Started));
    assert_eq!(group.follow_up(0), Ok(Some(FollowUp::StationInterrogation)));
    assert_eq!(group.follow_up(1), Ok(None));
    assert_eq!(group.follow_up(2), Ok(None));

    // The follow-up names the request the caller performs: `gi::request`'s
    // activation.
    assert_eq!(
        gi::request(Scope::Station, 12, 0).expect("the request"),
        station_interrogation()
    );
}

/// Rule 4 (index 118, printed 117): *"The controlling station decides which one
/// of the N connections is be in started state."* 10.3 (index 120, printed
/// 119): *"After connection establishment, the stopped state is always default,
/// and one of the connections (e.g. connection 1) is therefore changed from the
/// stopped into the started state to enable user data transfer on this
/// connection."*
///
/// The decision and the procedure that carries it out are one flow, not two:
/// [`RedundancyGroup::select`] names the connection and
/// [`RedundancyGroup::start`] puts the naming into effect. A group whose
/// `select` has just named a connection whose session is still `Stopped` must
/// therefore still send that connection's STARTDT act; the refusal is the
/// *second* start, on a session that has left `Stopped`. This is also the flow
/// the suite's own [`controlling_group`] helper is built by.
#[test]
fn clause_10_3_start_carries_out_the_selection() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("a group");
    for index in 0..group.len() {
        group
            .member_mut(index)
            .expect("a member")
            .session_mut()
            .on_connection_established();
    }
    assert_eq!(group.state(1), Ok(State::Stopped), "stopped is the default");

    // Rule 4's decision is the caller's, and it comes before the procedure.
    group.select(1).expect("the controlling station decides");
    assert_eq!(group.started(), Ok(1));

    // `start` carries the selection out: the act goes out on that connection.
    let actions = group.start(1).expect("the selection is carried out");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(group.state(1), Ok(State::PendingStarted));
    assert_eq!(group.started(), Ok(1));

    // Now that the session has left `Stopped`, a second start is the refusal.
    assert_eq!(
        group.start(1),
        Err(GroupError::AlreadyInState {
            index: 1,
            state: State::PendingStarted,
        })
    );
}

/// 10.3's change (*"is therefore changed from the stopped into the started
/// state"*) is a change, so a second start of the connection that already is
/// the group's is the "already in the state the caller asks for" refusal, with
/// the member's own state, before and after the confirmation. A controlled
/// station starts nothing of its own: rule 4's *"the selection and switchover
/// of the started connection is always initiated by the controlling station"*
/// (index 118), and its initialisation is 10.4.
#[test]
fn clause_10_3_a_second_start_on_the_started_connection_is_refused() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("a group");
    for index in 0..group.len() {
        group
            .member_mut(index)
            .expect("a member")
            .session_mut()
            .on_connection_established();
    }

    group.start(1).expect("the first start");
    assert_eq!(
        group.start(1),
        Err(GroupError::AlreadyInState {
            index: 1,
            state: State::PendingStarted,
        })
    );
    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.state(1), Ok(State::Started));
    assert_eq!(
        group.start(1),
        Err(GroupError::AlreadyInState {
            index: 1,
            state: State::Started,
        })
    );

    // A name that is no member of the group is its own refusal, in that order.
    let out_of_range = GroupError::MemberIndexOutOfRange {
        index: 2,
        members: 2,
    };
    assert_eq!(group.start(2).err(), Some(out_of_range));
    assert_eq!(group.follow_up(2).err(), Some(out_of_range));

    // The controlled station's initialisation is 10.4
    // (`RedundancyGroup::on_startdt_act`): it starts no connection of its own,
    // so it is refused.
    let mut controlled =
        RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 2).expect("a group");
    assert_eq!(controlled.start(0), Err(GroupError::CannotSelect));
    assert_eq!(controlled.start(1), Err(GroupError::CannotSelect));
    assert_eq!(controlled.started_index(), None);
}

/// Figure 32's NOTE, verbatim (index 122, printed 121): *"The sequential
/// interrelationship between the procedures on the connections is not fixed.
/// For example, establishment of the connections may be started and go on in
/// parallel."* The group's API therefore imposes no establishment order: it
/// starts whichever connection the caller has brought up, whatever its index,
/// and leaves the others alone.
#[test]
fn clause_10_3_figure_32_note_the_group_imposes_no_establishment_order() {
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 3).expect("a group");

    // Only the last connection is up: the first two are still being opened, in
    // parallel with it.
    group
        .member_mut(2)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    assert_eq!(group.state(0), Ok(State::Stopped));
    assert_eq!(group.state(1), Ok(State::Stopped));

    let actions = group
        .start(2)
        .expect("the connection that is up is the one that starts");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    group
        .member_mut(2)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));

    assert_eq!(group.started(), Ok(2));
    assert_eq!(group.state(2), Ok(State::Started));
    assert_eq!(group.follow_up(2), Ok(Some(FollowUp::StationInterrogation)));

    // The two connections that are not up yet were never touched by the group:
    // no act was sent for them, and their sessions are where the caller left
    // them.
    for index in [0, 1] {
        let member = group.member(index).expect("a member");
        assert_eq!(member.session().state(), State::Stopped, "member {index}");
        assert_eq!(member.session().v_s().get(), 0);
        assert_eq!(member.session().pending_user_data(), 0);
    }
}

// ---------------------------------------------------------- 10.4 (figure 33)

/// A controlled-station group of `count` members that share the default link
/// parameters, with no `STARTDT_ACT` received yet on any of them.
fn controlled_group(count: usize) -> RedundancyGroup {
    RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), count).expect("group")
}

/// The ASDU a controlled station sends: `M_SP_NA_1` (type 1), cause 3
/// (`spont`), common address 12, information object address 0, single point on:
/// monitoring-direction user data, which 10.4 (index 124) holds until one
/// connection is started.
fn monitoring_data() -> Vec<u8> {
    vec![0x01, 0x01, 0x03, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x01]
}

/// Brings every connection of the group up, as clause 7.1 has the controlling
/// station do: *"Connection establishment is performed by the controlling
/// station in the case of a controlled station as a partner"* (index 118;
/// index 54 for the 7.1 wording).
fn establish_all(group: &mut RedundancyGroup) {
    for index in 0..group.len() {
        group
            .member_mut(index)
            .expect("a member")
            .session_mut()
            .on_connection_established();
    }
}

/// 10.4, verbatim (PDF page index 124, printed 123): *"After restart of the
/// controlled station, the connections are established according to 7.1, but no
/// user data is transmitted from the controlled station until started state on
/// one connection is established."*
///
/// The whole subsection is on that page; figure 33 (index 126, printed 125)
/// draws the sequence. Established connections are `Stopped` (clause 5.3, index
/// 38: *"STOPDT is the default state when a connection is established"*), so the
/// group names no started one and every route refuses.
#[test]
fn clause_10_4_no_user_data_before_one_connection_is_started() {
    let mut group = controlled_group(3);
    establish_all(&mut group);

    assert_eq!(group.role(), Role::Controlled);
    assert_eq!(group.started(), Err(GroupError::NoStartedConnection));
    assert_eq!(group.started_index(), None);
    assert_eq!(group.route(0), Err(GroupError::NoStartedConnection));

    // Monitoring data offered before the peer's act is refused and held
    // nowhere: the group keeps no queue and none of its connections took it.
    assert_eq!(
        group.send_user_data(0, &monitoring_data()).err(),
        Some(GroupError::NoStartedConnection)
    );
    for index in 0..group.len() {
        let session = group.member(index).expect("a member").session();
        assert_eq!(session.state(), State::Stopped, "member {index}");
        assert_eq!(session.pending_user_data(), 0, "member {index}");
        assert_eq!(session.v_s().get(), 0, "member {index}");
    }
}

/// Rule 4's controlled half, verbatim (index 118, printed 117): *"The
/// controlled station (station B) always understands the connection on which it
/// last received a `STARTDT_ACT` as the started connection. It confirms the
/// activation request by issuing a `STARTDT_CON`."* 10.4 (index 124) is that
/// station's initialisation, and figure 33 (index 126) draws the step as
/// `receive STARTDT` / `U (STARTDT act)`.
///
/// The naming is positional, not stateful: a second act on another member moves
/// it, and a repeated act on the same member names that member again.
#[test]
fn clause_10_4_the_last_act_names_the_started_connection() {
    let mut group = controlled_group(3);
    establish_all(&mut group);
    assert_eq!(group.started(), Err(GroupError::NoStartedConnection));

    let actions = group.on_startdt_act(1).expect("an act arrived on 1");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(group.state(1), Ok(State::Started));
    assert_eq!(group.started(), Ok(1));
    assert_eq!(group.route(1), Ok(1));

    // A second act, on another member, is the last one received: it moves the
    // group's naming. 10.7's close rule (index 136) closes the connection left
    // behind with it (*"Any connection that is not in the STOPPED state is
    // immediately closed at the event of a Start on a new connection."*), so the
    // connection that was started is terminated, and it is not the group's
    // started connection any more either way.
    let actions = group.on_startdt_act(2).expect("an act arrived on 2");
    assert!(
        matches!(actions.first(), Some(Action::ActiveClose(_))),
        "figure 36's `STARTDT act[]/Close other not stopped connection(s)/Send STARTDT con`"
    );
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(group.started(), Ok(2));
    assert_eq!(
        group.state(1),
        Ok(State::Terminated),
        "the connection the naming moved away from is closed"
    );
    assert_eq!(
        group.route(1),
        Err(GroupError::NotStartedConnection { index: 1 })
    );
    assert_eq!(group.route(2), Ok(2));

    // A repeated act on the connection that is already the group's names it
    // again: clause 5.3 answers every STARTDT act with a STARTDT con,
    // retransmissions included.
    let actions = group.on_startdt_act(2).expect("a repeated act");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(group.started(), Ok(2));
    assert_eq!(group.state(2), Ok(State::Started));
}

/// The confirmation is the connection's own, clause 5.3 (index 38, printed 37):
/// *"The controlled station responds to this command with a STARTDT con."* 10.2
/// (index 118): *"It confirms the activation request by issuing a `STARTDT_CON`."*
///
/// `on_startdt_act` feeds the received frame to the member's session: the act's
/// whole answer on the wire is the member's `Session::on_frame` answer, so the group invents no frame of its
/// own. A controlling station takes its naming from its own decision instead
/// (rule 4, index 118: *"the selection and switchover of the started connection
/// is always initiated by the controlling station"*).
#[test]
fn clause_10_4_the_confirmation_is_the_sessions_startdt_con() {
    let mut group = controlled_group(2);
    establish_all(&mut group);

    // `observe_startdt_act` only records the naming and sends nothing: it is
    // the group's bookkeeping, not the connection's answer, and no frame has
    // been fed to the session.
    group.observe_startdt_act(0).expect("the positional naming");
    assert_eq!(group.started(), Ok(0));
    assert_eq!(group.state(0), Ok(State::Stopped), "no frame was fed");

    // Feeding the frame produces exactly the session's answer, `U (STARTDT
    // con)`, and the connection reaches the started state.
    let actions = group.on_startdt_act(0).expect("the act arrived on 0");
    assert_eq!(actions, vec![Action::Send(Apci::U(UFunction::StartDtCon))]);
    assert_eq!(group.state(0), Ok(State::Started));
    assert_eq!(group.started(), Ok(0));

    // The other member saw nothing: the act arrived on one connection only.
    assert_eq!(group.state(1), Ok(State::Stopped));
    assert_eq!(group.member(1).expect("a member").session().v_r().get(), 0);

    // A controlling group does not take its naming from a received act, and the
    // frame is not fed to the session either.
    let mut controlling = controlling_group(2, 0);
    assert_eq!(controlling.on_startdt_act(1), Err(GroupError::CannotSelect));
    assert_eq!(controlling.started(), Ok(0));
    assert_eq!(controlling.state(1), Ok(State::Stopped));
}

/// What a controlled group must not do. 10.2 (index 118): *"the selection and
/// switchover of the started connection is always initiated by the controlling
/// station"*; 10.3 (index 120, printed 119): *"In case of initialisation of the
/// controlling station, it is only issued if data in the reverse direction is
/// defined"*. 10.3's procedure and its condition are the controlling station's,
/// so a controlled group selects nothing, starts nothing, issues no
/// `ENDINIT.req` of its own and runs no station interrogation.
///
/// The refusals are the role's, not a state's: they hold before the peer's act
/// and after it.
#[test]
fn clause_10_4_a_controlled_group_runs_no_controlling_station_procedure() {
    let mut group = controlled_group(2);
    establish_all(&mut group);

    assert_eq!(group.select(0), Err(GroupError::CannotSelect));
    assert_eq!(group.start(0), Err(GroupError::CannotSelect));
    assert_eq!(group.endinit(endinit(false)), Err(GroupError::CannotSelect));
    assert_eq!(group.endinit(endinit(true)), Err(GroupError::CannotSelect));
    assert_eq!(group.follow_up(0), Err(GroupError::CannotSelect));
    assert_eq!(group.started_index(), None);

    // Nothing was issued on any member and none left the stopped state, not even
    // when `ENDINIT.req`'s reverse-direction condition is true.
    for index in 0..group.len() {
        let session = group.member(index).expect("a member").session();
        assert_eq!(session.state(), State::Stopped, "member {index}");
        assert_eq!(session.pending_user_data(), 0, "member {index}");
        assert_eq!(session.v_s().get(), 0, "member {index}");
    }

    // One connection is the started one now: the procedures are still the
    // controlling station's.
    let actions = group.on_startdt_act(1).expect("an act arrived on 1");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(group.started(), Ok(1));
    assert_eq!(group.select(1), Err(GroupError::CannotSelect));
    assert_eq!(group.start(1), Err(GroupError::CannotSelect));
    assert_eq!(group.endinit(endinit(true)), Err(GroupError::CannotSelect));
    assert_eq!(group.follow_up(1), Err(GroupError::CannotSelect));

    // A name that is no member of the group is its own refusal, in that order.
    let out_of_range = GroupError::MemberIndexOutOfRange {
        index: 2,
        members: 2,
    };
    assert_eq!(group.on_startdt_act(2).err(), Some(out_of_range));
}

/// Clause 5.3, verbatim (index 38, printed 37): *"Any pending user data in the
/// controlled station is sent only after the STARTDT con."* The controlled
/// station's monitoring data is handed to the group like any other user ASDU
/// (rule 3) and waits in **that** connection's own clause 5.3 queue (never in
/// the group and never in a second member) until the connection answers the
/// act.
#[test]
fn clause_10_4_monitoring_data_is_sent_only_after_the_startdt_con() {
    let mut group = controlled_group(2);
    establish_all(&mut group);

    // The group names the connection but the act has not reached it: the data is
    // held by the connection that will carry it.
    group.observe_startdt_act(1).expect("the positional naming");
    assert_eq!(group.send_user_data(1, &monitoring_data()), Ok(None));
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .pending_user_data(),
        1
    );
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        0
    );

    // The act arrives: the connection answers `U (STARTDT con)` (figure 33,
    // index 126) and only then puts the held ASDU on the wire: the con first.
    let actions = group.on_startdt_act(1).expect("an act arrived on 1");
    assert_eq!(
        actions,
        vec![
            Action::Send(Apci::U(UFunction::StartDtCon)),
            Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: monitoring_data(),
            },
        ]
    );
    assert_eq!(group.state(1), Ok(State::Started));
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .pending_user_data(),
        0
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 1);
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        0,
        "the stopped connection carried none of it"
    );
}

// -------------------------------------------------- 10.5/10.6 (figures 34/35)

/// A controlling-station group whose member 0 is the started connection and
/// whose member 1 is an established, stopped one: the state figure 34's
/// (index 130, printed 129) switchover starts from.
fn group_with_a_standby_member() -> RedundancyGroup {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    group
}

/// The ASDU of one action, if it is an I-frame.
fn asdu_of(action: &Action) -> Option<Vec<u8>> {
    match action {
        Action::SendI { asdu, .. } => Some(asdu.clone()),
        _ => None,
    }
}

/// 10.5, verbatim (PDF page index 128, printed 127): *"If communication fails
/// on the currently started connection (e.g. connection m) when the controlling
/// station attempts to transmit user data (e.g. a command ASDU), a connection
/// switchover will be performed (preferably automatic). … When transmission
/// timeout (t1) has elapsed, one of the stopped connections (connection n) is
/// started using the STARTDT function, The command is then directed to the new
/// started connection"*.
///
/// Figure 34 (index 130) draws the sequence as `COMMAND (example)` / `Timeout
/// t1` / `U (STARTDT act)` / `U (STARTDT con)` / `COMMAND (repeated)`.
#[test]
fn clause_10_5_the_t1_on_the_started_connection_switches_over() {
    let mut group = group_with_a_standby_member();
    assert_eq!(group.started(), Ok(0));

    // The command that could not go out: it sits in the failed connection's own
    // send buffer, unconfirmed.
    let action = group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection takes it")
        .expect("its state allows user data");
    assert_eq!(sent_i(&[action]), vec![(0, 0, station_interrogation())]);

    // t1 expires on the started connection: the group's switchover trigger.
    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1,
        })
    );
    // The connection's own t1 reaction first (figure 34's `Timeout t1` /
    // `active close`), then the STARTDT act of clause 5.3 on the connection
    // that takes over.
    assert!(
        outcome
            .actions
            .iter()
            .any(|a| matches!(a, Action::ActiveClose(_))),
        "the failed connection is closed"
    );
    assert_eq!(sent_u(&outcome.actions), Some(UFunction::StartDtAct));
    assert_eq!(group.state(0), Ok(State::Terminated));
    assert_eq!(group.started(), Ok(1));
    assert_eq!(group.state(1), Ok(State::PendingStarted));
    assert_eq!(
        group.route(0),
        Err(GroupError::NotStartedConnection { index: 0 })
    );
    assert_eq!(group.route(1), Ok(1));

    // *"Any subsequent user data (e.g. events) are now transmitted on the new
    // started connection."*
    let action = group
        .send_user_data(1, &monitoring_data())
        .expect("the new started connection takes it")
        .expect("the act is out, so the controlling station may send");
    assert_eq!(sent_i(&[action]), vec![(0, 0, monitoring_data())]);

    // *"Care shall be taken that data are not lost during a connection
    // switchover, for example by doing a station interrogation procedure after
    // a switchover has been performed."* 10.3's follow-up value is that step,
    // once the new connection has completed its start.
    assert_eq!(group.follow_up(1), Ok(None));
    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.state(1), Ok(State::Started));
    assert_eq!(group.follow_up(1), Ok(Some(FollowUp::StationInterrogation)));
}

/// 10.5, verbatim (index 128): *"A connection switchover will also be performed
/// whenever a `TESTFR_ACT` on the started connection fails and hence reports a
/// communication error on this connection."*
///
/// The failure is the t1 that supervises that act expiring with no `TESTFR con`:
/// figure 14's unconfirmed act ending in `Time-out t1` → `Active close`
/// (`src/link.rs`). `Session::test_pending` is the procedure in flight.
#[test]
fn clause_10_5_a_failed_testfr_act_on_the_started_connection_switches_over() {
    let mut group = group_with_a_standby_member();

    // Rule 5's supervision: t3 expires and the connection sends `TESTFR act`.
    let actions = group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_timeout(Timer::T3);
    assert_eq!(sent_u(&actions), Some(UFunction::TestFrAct));
    assert!(group.member(0).expect("a member").session().test_pending());

    // The act is not confirmed: its t1 expires and the group switches over.
    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 0,
        })
    );
    assert_eq!(sent_u(&outcome.actions), Some(UFunction::StartDtAct));
    assert!(!group.member(0).expect("a member").session().test_pending());
    assert_eq!(group.state(0), Ok(State::Terminated));
    assert_eq!(group.started(), Ok(1));
}

/// A controlling group dials a member whose connection was lost less than t0
/// after its attempt began only when that t0 runs out (clause 10.5's
/// reopening is *"regularly retried"*; clause 9's t0 is the *"Time-out of
/// connection establishment"*), so a peer that closes every connection at
/// once gets one attempt per t0, as the connection manager gives it.
#[test]
fn clause_10_5_a_member_lost_within_t0_is_dialed_again_after_t0() {
    let start = Instant::now();
    let t0 = LinkParams::default().t0;
    let mut group = RedundancyGroup::new(Role::Controlling, vec![LinkParams::default()]).unwrap();
    assert_eq!(group.tick(start).connect, vec![0]);
    let up = start + Duration::from_millis(10);
    group.on_connection_established(0, up).unwrap();
    group.on_connection_lost(0).unwrap();
    assert!(
        group.tick(up).connect.is_empty(),
        "not dialed again within t0"
    );
    assert_eq!(group.next_deadline(), Some(start + t0));
    assert_eq!(group.tick(start + t0).connect, vec![0]);
}

/// 10.5, verbatim (index 128): *"The failed connection is eventually closed by
/// both sides, and reopening is regularly retried by the controlling station
/// until the error has been corrected and the connection is re-established."*
/// Figure 34 (index 130) draws the close as `active close` / `<CTL=FIN>` /
/// `CLOSED` and the retry as `Timeout t0` / `active close`.
///
/// The group's half of the close is the connection's own t1 reaction; reopening
/// is the caller's, because the crate owns no socket (clause 7.1, index 54;
/// `iec104::manager` is the connection manager that retries). TS 60870-5-604's `5.4.13.20` (index 59,
/// printed 58) puts the retry with the caller too: *"The Controlling station
/// tries at regular intervals to create a new Stopped connection for the now
/// closed inoperable connection to the Controlled station."*
#[test]
fn clause_10_5_the_failed_connection_is_closed_and_reopening_is_the_callers() {
    let mut group = group_with_a_standby_member();
    group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("an I-frame");

    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert!(
        outcome
            .actions
            .iter()
            .any(|a| matches!(a, Action::ActiveClose(_))),
        "figures 17/18's `Timeout t1[]/Active close` is the failed connection's close"
    );
    assert_eq!(group.state(0), Ok(State::Terminated));

    // Only the takeover was started; nothing reopened the failed connection and
    // nothing armed a new attempt (that is figure 34's `Timeout t0`, the
    // caller's own step).
    assert_eq!(
        group.state(1),
        Ok(State::PendingStarted),
        "only the takeover was started"
    );
    // TS 60870-5-604 5.4.13.10 (index 58): *"The send- and receive counters are
    // not reset to \"0\" as long as the TCP connection is established."* The
    // close did not reset them either.
    assert_eq!(group.member(0).expect("a member").session().v_s().get(), 1);
    assert_eq!(group.member(0).expect("a member").session().v_r().get(), 0);

    // The caller's own reopen: clause 5.1 restarts the numbering there.
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    assert_eq!(group.state(0), Ok(State::Stopped));
    assert_eq!(group.member(0).expect("a member").session().v_s().get(), 0);
}

/// 10.5, verbatim (index 128): *"The command is then directed to the new
/// started connection, either by re-transmitting the ASDU on this connection or
/// by terminating the ongoing application function and reinitiating it towards
/// the new connection (it is left to the application if the ESDU is
/// retransmitted)."* 10.6, verbatim (index 132, printed 131): *"In general, any
/// unconfirmed user data will be retransmitted on the new started connection
/// after a connection switchover has been performed, including potential
/// unconfirmed ACTCONs or ACTTERMs."* Figure 35 (index 134, printed 133) draws
/// it as `Connection switchover` / `EVENT (retransmitted)`.
///
/// The decision is the application's and the group reports what it did as a
/// value: `Left` leaves the ASDU in the failed connection's send buffer,
/// `Retransmit` puts it on the group's started connection, re-stamped with
/// *that* connection's own `N(S)`, because each TCP connection maintains its
/// own counters (5.4.13.10, index 58; 10.2, index 118).
#[test]
fn clause_10_5_the_esdu_is_retransmitted_or_left_to_the_application() {
    let mut group = group_with_a_standby_member();
    group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("an I-frame");
    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1,
        })
    );

    // Left to the application: nothing is re-sent and nothing is dropped.
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Ok(ReplayOutcome::Left { unconfirmed: 1 })
    );
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .outstanding_frames()
            .len(),
        1,
        "the ASDU is still in the failed connection's send buffer"
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 0);

    // Retransmit: the ASDU goes out on the new started connection.
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: vec![Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: station_interrogation(),
            }],
            queued: 0,
        })
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 1);
    assert_eq!(
        group.member(0).expect("a member").session().v_s().get(),
        1,
        "the failed connection's own counters are not moved by the replay"
    );

    // The group does not replay onto the connection the data came from: there
    // is no second connection to carry it, so the call is refused.
    let mut same = controlling_group(1, 0);
    start_member(&mut same, 0);
    same.send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("an I-frame");
    assert_eq!(
        same.retransmit_unconfirmed(0, Replay::Retransmit),
        Err(GroupError::StillStartedConnection { index: 0 })
    );
}

/// 10.5, verbatim (index 128): *"If communication fails on the currently
/// started connection"*: the trigger is that connection and no other. A t1 on
/// a stopped connection is that connection's own failure: it closes, and the
/// group's naming does not move. A t1 on a connection that is already
/// terminated is not a failure at all, and t2/t3 stay the connection's own
/// reactions (clause 5.1 / clause 5.2).
#[test]
fn clause_10_5_a_t1_off_the_started_connection_is_not_a_switchover() {
    let mut group = group_with_a_standby_member();

    let outcome = group
        .on_timeout(1, Timer::T1)
        .expect("member 1 has a session");
    assert_eq!(outcome.switchover, None);
    assert!(
        outcome
            .actions
            .iter()
            .any(|a| matches!(a, Action::ActiveClose(_)))
    );
    assert_eq!(group.state(1), Ok(State::Terminated));
    assert_eq!(group.started(), Ok(0), "the naming does not move");
    assert_eq!(group.state(0), Ok(State::Started));

    // Already terminated: nothing left to close and nothing to switch over.
    assert_eq!(
        group.on_timeout(1, Timer::T1),
        Ok(TimeoutOutcome {
            actions: Vec::new(),
            switchover: None,
        })
    );

    // t3 is the connection's own TESTFR procedure (clause 5.2, rule 5).
    let outcome = group
        .on_timeout(0, Timer::T3)
        .expect("member 0 has a session");
    assert_eq!(outcome.switchover, None);
    assert_eq!(sent_u(&outcome.actions), Some(UFunction::TestFrAct));
}

/// 10.5, verbatim (index 128): *"one of the stopped connections (connection n)
/// is started using the STARTDT function"*. When no stopped connection is left
/// to take over, the group starts none, names no new connection and reports it
/// rather than picking one that is already in use.
///
/// TS 60870-5-604 `5.4.13.20` (index 59) is the corroborating case: the
/// inoperable connection is closed and *"The Controlling station tries at
/// regular intervals to create a new Stopped connection"*. The retry is the
/// caller's (the caller owns the sockets; `iec104::manager` drives the retry).
#[test]
fn clause_10_5_no_stopped_connection_is_left_to_take_over() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    start_member(&mut group, 1);
    assert_eq!(group.state(1), Ok(State::Started));

    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::NoStoppedConnection {
            failed: 0,
            unconfirmed: 0,
        })
    );
    assert_eq!(
        sent_u(&outcome.actions),
        None,
        "there is no stopped connection left to start"
    );
    assert_eq!(
        group.started(),
        Err(GroupError::NoStartedConnection),
        "the failed connection is no longer the started one, and no new one is named"
    );
    assert_eq!(
        group.state(1),
        Ok(State::Started),
        "the connection that is not stopped is not touched"
    );
}

/// 10.5, verbatim (index 128): *"The controlled station shall only acknowledge
/// user data received on the connection on which it last received a `STARTDT_ACT`
/// (the started connection)."* 10.6, verbatim (index 132): *"The controlling
/// station shall not acknowledge user data received on a connection which is
/// not started."*
///
/// The group is the layer that knows which connection is the started one, so it
/// is the layer that refuses an I- or S-frame on any other: the frame is not fed
/// to that connection's session, so nothing is acknowledged there and its
/// receive counter stays where it was. U-frames stay the connection's own on
/// every member, because rule 5 supervises the stopped connections too (clause
/// 5.2).
#[test]
fn clause_10_6_only_the_started_connection_is_acknowledged() {
    let mut group = controlled_group(2);
    establish_all(&mut group);
    let actions = group.on_startdt_act(1).expect("an act arrived on 1");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(group.started(), Ok(1));

    // Data on the stopped connection is refused, not acknowledged.
    assert_eq!(
        group.on_frame(
            0,
            Apci::I {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0)
            }
        ),
        Err(GroupError::NotStartedConnection { index: 0 })
    );
    assert_eq!(
        group.on_frame(0, Apci::S { nr: SeqNo::new(0) }),
        Err(GroupError::NotStartedConnection { index: 0 })
    );
    assert_eq!(group.state(0), Ok(State::Stopped));
    assert_eq!(group.member(0).expect("a member").session().v_r().get(), 0);

    // The started connection receives and acknowledges user data as usual.
    let actions = group
        .on_frame(
            1,
            Apci::I {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
            },
        )
        .expect("the started connection");
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::DeliverData { .. }))
    );
    assert_eq!(group.member(1).expect("a member").session().v_r().get(), 1);

    // A U-frame is the connection's own on every member.
    let actions = group
        .on_frame(0, Apci::U(UFunction::TestFrAct))
        .expect("a stopped connection is supervised too");
    assert_eq!(actions, vec![Action::Send(Apci::U(UFunction::TestFrCon))]);
}

/// 10.6, verbatim (index 132): *"If communication fails on the started
/// connection when the controlled station attempts to transmit user data (e.g.
/// an event ASDU), the controlling station shall detect the failure and perform
/// a connection switchover before the ASDU can be retransmitted on one of the
/// previously stopped connections. … A `STARTDT_ACT` will eventually be received
/// on one of the stopped connections (connection m) as a result of a timeout
/// (t1) in the controlling station to a TESTFR frame on the currently started
/// but failed connection. The selected stopped connection now becomes the new
/// started connection, and the pending event is retransmitted on this
/// connection."*
///
/// A controlled station starts no connection of its own (rule 4, index 118:
/// *"the selection and switchover of the started connection is always initiated
/// by the controlling station"*): it reports the failure and its naming moves
/// when the peer's act arrives on a stopped member (10.4, index 124).
#[test]
fn clause_10_6_the_controlling_station_starts_the_new_connection() {
    let mut group = controlled_group(2);
    establish_all(&mut group);
    group.on_startdt_act(0).expect("an act arrived on 0");
    assert_eq!(group.started(), Ok(0));

    // The event the controlled station attempts to transmit: on the started
    // connection and unconfirmed.
    let action = group
        .send_user_data(0, &monitoring_data())
        .expect("the started connection")
        .expect("an I-frame");
    assert_eq!(sent_i(&[action]), vec![(0, 0, monitoring_data())]);

    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::LeftToTheControllingStation {
            failed: 0,
            unconfirmed: 1,
        })
    );
    assert_eq!(
        sent_u(&outcome.actions),
        None,
        "a controlled station sends no STARTDT act of its own"
    );
    assert_eq!(group.state(0), Ok(State::Terminated));

    // The peer's act arrives on the stopped connection: it becomes the new
    // started connection, and the pending event is retransmitted on it.
    let actions = group.on_startdt_act(1).expect("an act arrived on 1");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert_eq!(group.started(), Ok(1));
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: vec![Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: monitoring_data(),
            }],
            queued: 0,
        })
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 1);
}

/// The requirement *"no duplicate delivery of the same ASDU across the group"*
/// (10.5/10.6, indices 128/132): one ASDU handed to the
/// group once reaches the wire on exactly one connection, before and after a
/// switchover, and the switchover itself re-sends nothing.
#[test]
fn clause_10_5_one_asdu_reaches_one_connection_across_a_switchover() {
    let mut group = group_with_a_standby_member();
    let mut wire: Vec<(usize, Vec<u8>)> = Vec::new();

    let first = station_interrogation();
    let action = group
        .send_user_data(0, &first)
        .expect("the started connection")
        .expect("an I-frame");
    wire.push((0, asdu_of(&action).expect("an I-frame")));

    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        sent_i(&outcome.actions),
        Vec::new(),
        "the switchover re-sends nothing on its own"
    );

    let second = monitoring_data();
    let action = group
        .send_user_data(1, &second)
        .expect("the new started connection")
        .expect("an I-frame");
    wire.push((1, asdu_of(&action).expect("an I-frame")));

    assert_eq!(wire, vec![(0, first.clone()), (1, second.clone())]);
    // Each connection holds exactly the ASDU it carries, and the failed one
    // holds no copy of what the new one sent.
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .outstanding_frames()[0]
            .asdu,
        first
    );
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .outstanding_frames()
            .len(),
        1
    );
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .outstanding_frames()
            .len(),
        1
    );
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .pending_user_data(),
        0
    );
}

/// 10.2, verbatim (index 118, printed 117): *"Send and receive counters on each
/// connection within a redundancy group continue their functionality
/// independently of the use of STARTDT/STOPDT."* TS 60870-5-604 `5.4.13.10`
/// (index 58, printed 57) extends it to the switchover: *"The send- and receive
/// counters are not reset to \"0\" as long as the TCP connection is established.
/// Each TCP connection, not affected by STARTDT and STOPDT procedures or
/// switch-over procedures, maintains its send- and receive counter."*
///
/// So a standby connection that has carried frames of its own before it takes
/// over keeps its numbering, and the connection that takes over does not inherit
/// the failed one's.
#[test]
fn clause_10_5_each_connection_keeps_its_own_counters_across_a_switchover() {
    let mut group = group_with_a_standby_member();

    // Member 1 carries frames of its own before it is ever the group's started
    // connection, then is stopped again. All of it goes through its own
    // session, because the group names member 0.
    let standby = group.member_mut(1).expect("a member").session_mut();
    assert_eq!(
        sent_u(&standby.request_start()),
        Some(UFunction::StartDtAct)
    );
    standby.on_frame(Apci::U(UFunction::StartDtCon));
    assert!(standby.send_i_frame(&monitoring_data()).is_some());
    assert_eq!(sent_u(&standby.request_stop()), Some(UFunction::StopDtAct));
    standby.on_frame(Apci::S { nr: SeqNo::new(1) });
    standby.on_frame(Apci::U(UFunction::StopDtCon));
    assert_eq!(standby.state(), State::Stopped);
    assert_eq!(standby.v_s().get(), 1);

    // The failed connection has counters of its own, too.
    group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("an I-frame");
    assert_eq!(group.member(0).expect("a member").session().v_s().get(), 1);

    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1,
        })
    );
    // The takeover did not reset the new started connection's counters ...
    assert_eq!(
        group.member(1).expect("a member").session().v_s().get(),
        1,
        "the switchover does not reset the new connection's counters"
    );
    // ... and the next frame continues its own numbering, not the failed
    // connection's.
    let action = group
        .send_user_data(1, &monitoring_data())
        .expect("the new started connection")
        .expect("an I-frame");
    assert_eq!(sent_i(&[action]), vec![(1, 0, monitoring_data())]);
    assert_eq!(group.member(0).expect("a member").session().v_s().get(), 1);
}

/// The timeout and frame paths are member-addressed, so a name that is no member
/// of the group is their own typed refusal, before any state is touched.
#[test]
fn the_timeout_paths_refuse_a_name_that_is_no_member() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    let out_of_range = GroupError::MemberIndexOutOfRange {
        index: 2,
        members: 2,
    };

    assert_eq!(group.on_timeout(2, Timer::T1).err(), Some(out_of_range));
    assert_eq!(
        group.on_frame(2, Apci::S { nr: SeqNo::new(0) }).err(),
        Some(out_of_range)
    );
    assert_eq!(
        group.retransmit_unconfirmed(2, Replay::Leave).err(),
        Some(out_of_range)
    );
    assert_eq!(
        group.retransmit_unconfirmed(2, Replay::Retransmit).err(),
        Some(out_of_range)
    );
    assert_eq!(group.state(0), Ok(State::Started), "nothing was touched");
}

/// A controlling-station group of two connections: the started member 0 has a
/// k = 1 window (so it holds the next ASDU in its own clause 5.3 queue), and
/// member 1 is an established, stopped connection with the standard window.
///
/// The two parameter sets are clause 10.7's *"individually for each connection"*
/// itself: the failed connection's narrow window does not narrow the one that
/// takes over.
fn group_with_a_one_frame_window() -> RedundancyGroup {
    let mut group = RedundancyGroup::new(
        Role::Controlling,
        vec![
            LinkParams {
                k: 1,
                ..LinkParams::default()
            },
            LinkParams::default(),
        ],
    )
    .expect("group");
    group.select(0).expect("the selection is the caller's");
    start_member(&mut group, 0);
    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    group
}

/// 10.5, verbatim (index 128, printed 127): *"it is left to the application if
/// the ESDU is retransmitted"*, together with the group's own requirement,
/// *"one ASDU handed to the group once reaches the wire on exactly one
/// connection, before and after a switchover"*.
///
/// The application's decision is carried out once: after a `Retransmit` the
/// failed connection's record says so ([`iec104::redundancy::Member::replayed`])
/// and every further call for that member is
/// [`GroupError::AlreadyRetransmitted`], so a caller that repeats the call (a
/// retry loop, say) cannot put a second copy of the same ASDU on the wire.
#[test]
fn clause_10_5_a_failed_connections_data_is_replayed_only_once() {
    let mut group = group_with_a_standby_member();
    group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("an I-frame");
    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1,
        })
    );

    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: vec![Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: station_interrogation(),
            }],
            queued: 0,
        })
    );
    assert!(group.member(0).expect("a member").replayed());
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .outstanding_frames()
            .len(),
        1
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 1);

    // The same decision again: refused, and nothing moves on either connection.
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Err(GroupError::AlreadyRetransmitted { index: 0 })
    );
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Err(GroupError::AlreadyRetransmitted { index: 0 }),
        "there is nothing left to leave: the data is on the new connection"
    );
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .outstanding_frames()
            .len(),
        1,
        "the replayed ASDU is on the new connection exactly once"
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 1);
    assert_eq!(
        group
            .member(1)
            .expect("a member")
            .session()
            .pending_user_data(),
        0
    );
}

/// 10.5, verbatim (index 128, printed 127): *"Care shall be taken that data are
/// not lost during a connection switchover, for example by doing a station
/// interrogation procedure after a switchover has been performed."*
///
/// With the k window full (k = 1) the second ASDU waits in the started
/// connection's **own** clause 5.3 queue, and that queue is cleared with the
/// connection (clause 5.1). The group mirrors it
/// ([`iec104::redundancy::Member::queued_user_data`]), counts it in the
/// switchover report, and the replay puts it on the new started connection
/// together with the ASDU that was already on the wire.
#[test]
fn clause_10_5_a_failed_connections_queued_data_is_not_lost() {
    let mut group = group_with_a_one_frame_window();
    let first = station_interrogation();
    let second = monitoring_data();

    assert!(
        group
            .send_user_data(0, &first)
            .expect("the started connection")
            .is_some()
    );
    assert!(
        group
            .send_user_data(0, &second)
            .expect("the started connection")
            .is_none(),
        "the k = 1 window is full, so the ASDU waits in the connection's own queue"
    );
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        1
    );
    assert_eq!(
        group.member(0).expect("a member").queued_user_data(),
        vec![second.clone()]
    );

    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 2,
        }),
        "the queued ASDU is counted with the one on the wire"
    );
    // Clause 5.1 takes the session's own queue with the connection ...
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        0
    );
    // ... the group's mirror stays, so the data is not lost silently.
    assert_eq!(
        group.member(0).expect("a member").queued_user_data(),
        vec![second.clone()]
    );

    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: vec![
                Action::SendI {
                    ns: SeqNo::new(0),
                    nr: SeqNo::new(0),
                    asdu: first.clone(),
                },
                Action::SendI {
                    ns: SeqNo::new(1),
                    nr: SeqNo::new(0),
                    asdu: second.clone(),
                },
            ],
            queued: 0,
        })
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 2);
    assert_eq!(
        group.member(0).expect("a member").session().v_s().get(),
        1,
        "the failed connection's own counters are untouched (5.4.13.10)"
    );
    assert_eq!(
        group.member(0).expect("a member").queued_user_data(),
        Vec::<Vec<u8>>::new()
    );
}

/// The group's limit counts a failed connection's data once: after the
/// capture it is in [`iec104::redundancy::Member::left_behind`], and the
/// connection's queue mirror and send buffer are stale copies of it. The
/// group then holds new data until what it really holds reaches
/// [`MAX_PENDING_USER_DATA`].
#[test]
fn the_group_limit_counts_a_failed_connections_data_once() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    let asdu = station_interrogation();
    let sent = MAX_PENDING_USER_DATA / 2 + 1;
    for _ in 0..sent {
        group.send_user_data(0, &asdu).expect("below the limit");
    }

    group.on_connection_lost(0).expect("member 0");
    assert_eq!(group.member(0).expect("a member").left_behind().len(), sent);
    for _ in sent..MAX_PENDING_USER_DATA {
        assert_eq!(
            group.send_user_data(0, &asdu),
            Ok(None),
            "held for the next connection named"
        );
    }
    assert_eq!(group.held_user_data().len(), MAX_PENDING_USER_DATA - sent);
    assert_eq!(
        group.send_user_data(0, &asdu),
        Err(GroupError::Queue(QueueError::Full))
    );
}

/// A failed connection re-established by hand (not through the group) keeps
/// its stale queue mirror until it is named; the limit counts what its session
/// really holds, so the left-behind data still counts once.
#[test]
fn the_group_limit_ignores_the_stale_mirror_of_a_reestablished_connection() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    let asdu = station_interrogation();
    let sent = 1000;
    for _ in 0..sent {
        group.send_user_data(0, &asdu).expect("below the limit");
    }
    group.on_connection_lost(0).expect("member 0");
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_connection_established();

    let mut accepted = 0;
    while group.send_user_data(1, &asdu).is_ok() {
        accepted += 1;
    }
    assert_eq!(accepted, MAX_PENDING_USER_DATA - sent);
}

/// The mirror is dropped entry by entry as the data goes out, so the replay of a
/// failed connection never offers an ASDU twice. This is the same *"one ASDU …
/// on exactly one connection"* requirement of 10.5 (index 128), read from the
/// send buffer instead of the queue.
#[test]
fn clause_10_5_the_mirror_never_replays_data_that_has_gone_out() {
    let mut group = group_with_a_one_frame_window();
    let first = station_interrogation();
    let second = monitoring_data();
    group
        .send_user_data(0, &first)
        .expect("the started connection")
        .expect("an I-frame");
    assert!(
        group
            .send_user_data(0, &second)
            .expect("the started connection")
            .is_none()
    );
    assert_eq!(
        group.member(0).expect("a member").queued_user_data(),
        vec![second.clone()]
    );

    // The peer acknowledges the first ASDU: clause 5.5's window reopens and the
    // connection flushes its own queue, so the ASDU is on the wire now.
    let actions = group
        .on_frame(0, Apci::S { nr: SeqNo::new(1) })
        .expect("the started connection");
    assert_eq!(sent_i(&actions), vec![(1, 0, second.clone())]);
    assert!(
        group
            .member(0)
            .expect("a member")
            .queued_user_data()
            .is_empty(),
        "the mirror holds nothing the connection has already sent"
    );

    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1,
        }),
        "only the frame still in the send buffer is unconfirmed: the mirror added no \
         second copy of the ASDU that flushed"
    );
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: vec![Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: second.clone(),
            }],
            queued: 0,
        }),
        "the ASDU that flushed into the send buffer is replayed once, not twice"
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 1);
}

/// The record of a replay belongs to one failure on one connection. A connection
/// that has failed is only `Stopped` again after the caller re-established it
/// (clause 5.1), so naming it again ([`RedundancyGroup::start`]) is the group's
/// observable form of a fresh connection, and the record and the mirror of the
/// dead connection's queue are dropped with it.
#[test]
fn clause_10_5_a_re_established_connection_is_replayable_again() {
    let mut group = group_with_a_standby_member();
    let first = station_interrogation();
    group
        .send_user_data(0, &first)
        .expect("the started connection")
        .expect("an I-frame");
    group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    group
        .retransmit_unconfirmed(0, Replay::Retransmit)
        .expect("the failed connection's data");
    assert!(group.member(0).expect("a member").replayed());
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Err(GroupError::AlreadyRetransmitted { index: 0 })
    );

    // The caller re-establishes the failed connection (clause 5.1) and starts it
    // again: the record is cleared with the naming.
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    assert_eq!(group.state(0), Ok(State::Stopped));
    group
        .start(0)
        .expect("a re-established connection may be started again");
    assert!(!group.member(0).expect("a member").replayed());
    assert_eq!(
        group.member(0).expect("a member").queued_user_data(),
        Vec::<Vec<u8>>::new()
    );

    // And the data a *still* unconfirmed connection holds is replayable on its own
    // account, per 10.6 (index 132): *"any unconfirmed user data will be
    // retransmitted on the new started connection"*.
    assert_eq!(
        group.retransmit_unconfirmed(1, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: vec![Action::SendI {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
                asdu: first,
            }],
            queued: 0,
        })
    );
    assert_eq!(group.member(0).expect("a member").session().v_s().get(), 1);
}

/// 10.6, verbatim (index 132, printed 131): *"In general, any unconfirmed user
/// data will be retransmitted on the new started connection after a connection
/// switchover has been performed, including potential unconfirmed ACTCONs or
/// ACTTERMs."* And 10.5 (index 128, printed 127): *"Care shall be taken that
/// data are not lost during a connection switchover"*.
///
/// A repeated `STARTDT_ACT` on the connection that already is the group's is
/// clause 5.3's retransmission of the act, answered with a `STARTDT_CON`; the
/// connection keeps its queue. Naming the same member again is therefore no
/// re-establishment, and the group's mirror of that queue must not be dropped
/// with it: the ASDU the controlled station queued stays visible to the
/// switchover report and to the replay. This is the controlled-station side of
/// 10.6: member 0 has the narrow window (k = 1) that holds the second event,
/// and member 1 is the established, stopped connection with the standard window
/// that takes over.
#[test]
fn clause_10_6_a_repeated_act_does_not_lose_the_controlled_stations_queue() {
    let mut group = RedundancyGroup::new(
        Role::Controlled,
        vec![
            LinkParams {
                k: 1,
                ..LinkParams::default()
            },
            LinkParams::default(),
        ],
    )
    .expect("group");
    establish_all(&mut group);
    let first = monitoring_data();
    let second = station_interrogation();

    assert_eq!(
        sent_u(&group.on_startdt_act(0).expect("an act arrived on 0")),
        Some(UFunction::StartDtCon)
    );
    assert_eq!(group.state(0), Ok(State::Started));
    assert!(
        group
            .send_user_data(0, &first)
            .expect("the started connection")
            .is_some()
    );
    assert!(
        group
            .send_user_data(0, &second)
            .expect("the started connection")
            .is_none(),
        "the k = 1 window is full, so the second ASDU waits in the connection's queue"
    );
    assert_eq!(
        group.member(0).expect("a member").queued_user_data(),
        vec![second.clone()]
    );

    // The peer retransmits the act on the same connection: clause 5.3 answers it
    // with another con and the connection keeps its queue, so the group's mirror
    // of that queue must stay too.
    assert_eq!(
        sent_u(&group.on_startdt_act(0).expect("the repeated act")),
        Some(UFunction::StartDtCon)
    );
    assert_eq!(
        group.started_index(),
        Some(0),
        "the same connection is named"
    );
    assert_eq!(
        group.member(0).expect("a member").queued_user_data().len(),
        1,
        "a repeated act is no re-establishment: the queued ASDU stays in the mirror"
    );
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .pending_user_data(),
        1,
        "the connection's own queue still holds it"
    );

    // Now the started connection fails; the controlled station reports the
    // failure to its peer instead of switching over (rule 4).
    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::LeftToTheControllingStation {
            failed: 0,
            unconfirmed: 2,
        }),
        "the ASDU on the wire and the one in the mirror are both counted"
    );

    // The peer's act on the stopped connection names it, and the pending event
    // is retransmitted on it.
    assert_eq!(
        sent_u(&group.on_startdt_act(1).expect("an act arrived on 1")),
        Some(UFunction::StartDtCon)
    );
    assert_eq!(group.started_index(), Some(1));
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Ok(ReplayOutcome::Retransmitted {
            actions: vec![
                Action::SendI {
                    ns: SeqNo::new(0),
                    nr: SeqNo::new(0),
                    asdu: first.clone(),
                },
                Action::SendI {
                    ns: SeqNo::new(1),
                    nr: SeqNo::new(0),
                    asdu: second.clone(),
                },
            ],
            queued: 0,
        }),
        "the queued ASDU reaches the new started connection instead of being lost"
    );
    assert_eq!(group.member(1).expect("a member").session().v_s().get(), 2);
}

// ------------------------------------------------------ 10.7 (figures 36/37)

/// The S-frames a list of actions wants sent, as `N(R)`: the acknowledgement
/// figures 10/11's NOTE puts before an active close, and clause 5.3 puts before
/// a stop is completed.
fn sent_s(actions: &[Action]) -> Vec<u16> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(Apci::S { nr }) => Some(nr.get()),
            _ => None,
        })
        .collect()
}

/// The connections that are not in the `STOPPED` state and not terminated, for
/// rule 3 (index 118): *"Only one logical connection is in the started state and
/// sending/receiving user data at a time for one redundancy group."*
fn live_states(group: &RedundancyGroup) -> Vec<(usize, State)> {
    (0..group.len())
        .filter_map(|index| {
            let state = group.state(index).expect("a member");
            match state {
                State::Stopped | State::Terminated => None,
                other => Some((index, other)),
            }
        })
        .collect()
}

/// 10.7, verbatim (PDF page index 136, printed 135): *"Any connection that is
/// not in the STOPPED state is immediately closed at the event of a Start on a
/// new connection."*
///
/// This is the group's central rule, and the one a naive group implementation
/// gets wrong: starting a new connection **closes the connection that was started
/// before it** instead of leaving two live connections behind. Figure 36 (index
/// 138) prints it as its `STARTDT act[]/Close other not stopped connection(s)/
/// Send STARTDT con` transition, figure 37 (index 140) as `Start connection[]/
/// Send STARTDT act`.
#[test]
fn clause_10_7_a_start_on_a_new_connection_closes_the_connection_that_was_started() {
    let mut group = group_with_a_standby_member();
    assert_eq!(group.state(0), Ok(State::Started));
    assert_eq!(group.state(1), Ok(State::Stopped));
    assert_eq!(group.started_index(), Some(0));

    let actions = group.start(1).expect("the new connection starts");

    // The close comes first, in member order, exactly as figure 36's transition
    // prints it, and it is the connection's own active close.
    assert!(
        matches!(actions.first(), Some(Action::ActiveClose(_))),
        "the connection left behind is closed before the new act goes out"
    );
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(
        group.state(0),
        Ok(State::Terminated),
        "the connection that was started is not in the STOPPED state, so it is closed"
    );
    assert_eq!(group.started_index(), Some(1));
    assert_eq!(group.state(1), Ok(State::PendingStarted));
    assert_eq!(
        live_states(&group),
        vec![(1, State::PendingStarted)],
        "one started connection: a naive group would leave two"
    );
}

/// 10.7's close rule closes a connection that is **not** the group's named one
/// too. The sentence says any connection not in the STOPPED state, and a
/// connection whose `STARTDT act` is still on its way is `PendingStarted`, not
/// stopped.
#[test]
fn clause_10_7_the_close_rule_reaches_a_connection_that_is_only_pending() {
    let mut group = controlling_group(2, 0);
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    // The standby connection is up too, so it can take over.
    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_connection_established();

    let actions = group.start(0).expect("member 0 starts");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(group.state(0), Ok(State::PendingStarted));

    let actions = group.start(1).expect("member 1 starts");
    assert!(
        matches!(actions.first(), Some(Action::ActiveClose(_))),
        "PendingStarted is not STOPPED, so member 0 is closed too"
    );
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(group.state(0), Ok(State::Terminated));
    assert_eq!(group.state(1), Ok(State::PendingStarted));
    assert_eq!(live_states(&group), vec![(1, State::PendingStarted)]);
}

/// 10.7's close rule is not only `start`'s: 10.5's automatic switchover starts a
/// new connection too (index 128: *"one of the stopped connections (connection n)
/// is started using the STARTDT function"*), so that Start closes the members
/// that are not stopped just the same. A connection the caller has brought up
/// straight through `Member::session_mut`, bypassing the group, is exactly such
/// a member: it is not the group's started connection and it is not `Stopped`
/// either.
#[test]
fn clause_10_7_the_automatic_switchover_closes_the_members_that_are_not_stopped() {
    let mut group = controlling_group(3, 0);
    start_member(&mut group, 0);
    for standby in [1, 2] {
        group
            .member_mut(standby)
            .expect("a member")
            .session_mut()
            .on_connection_established();
    }

    // Member 2 is brought up by the caller's own calls and never named: its
    // session is `PendingStarted`.
    let actions = group
        .member_mut(2)
        .expect("a member")
        .session_mut()
        .request_start();
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(group.state(2), Ok(State::PendingStarted));

    // t1 on the started connection: member 1 is the stopped one that takes
    // over, and member 2 (not stopped) is closed by 10.7's rule.
    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 0,
        })
    );
    assert_eq!(
        group.state(2),
        Ok(State::Terminated),
        "a Start on a new connection closes the members that are not stopped"
    );
    assert_eq!(group.started_index(), Some(1));
    assert_eq!(live_states(&group), vec![(1, State::PendingStarted)]);
}

/// Figures 10/11's NOTE (printed page 31): *"To avoid retransmission of APDU's
/// that have already been accepted, an S-frame should, if possible, be sent
/// prior to the active close."* 10.7's close is the connection's own close, so
/// the acknowledgement the peer is owed is emitted before it. The ordering comes
/// from the session's close; the group adds nothing of its own.
#[test]
fn clause_10_7_the_close_acknowledges_received_frames_first() {
    let mut group = group_with_a_standby_member();

    // The peer's I-frame arrives on the started connection and is not yet
    // acknowledged.
    let delivered = group
        .on_frame(
            0,
            Apci::I {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0),
            },
        )
        .expect("the started connection takes I-frames");
    assert!(
        delivered
            .iter()
            .any(|a| matches!(a, Action::DeliverData { .. }))
    );
    assert!(group.member(0).expect("a member").session().ack_pending());

    let actions = group.start(1).expect("the new connection starts");
    let close_at = actions
        .iter()
        .position(|a| matches!(a, Action::ActiveClose(_)))
        .expect("the connection left behind is closed");
    assert_eq!(
        sent_s(&actions[..close_at]),
        vec![1],
        "the S-frame carrying N(R) = 1 precedes the active close"
    );
    assert_eq!(
        sent_u(&actions),
        Some(UFunction::StartDtAct),
        "and the new connection's act follows the close"
    );
}

/// 10.2, verbatim (index 118, printed 117): *"Manual connection switchover can
/// be performed by first issuing a `STOPDT_ACT` on the currently started
/// connection and then a `STARTDT_ACT` on the selected new started connection.
/// This will gracefully terminate data transfer on the first connection before
/// it is resumed on the new connection."*
///
/// The switchover is the **two requests it is**: a `switch()` that hid the
/// `STOPDT_ACT` would be the wrong shape, so the STOPDT is visible in the first
/// call and the connection is `Stopped` again (the peer's `STOPDT con`) before
/// the second one starts. Figure 37 (index 140) draws the two as `Stop
/// connection[…]` and `Start connection[]/Send STARTDT act`.
#[test]
fn clause_10_7_manual_switchover_is_a_stop_then_a_start() {
    let mut group = group_with_a_standby_member();
    assert_eq!(group.started_index(), Some(0));

    // The first request: STOPDT_ACT on the currently started connection.
    let stopping = group.stop(0).expect("the started connection stops");
    assert_eq!(
        sent_u(&stopping),
        Some(UFunction::StopDtAct),
        "the STOPDT_ACT is the first request, not hidden in a switch()"
    );
    assert_eq!(group.state(0), Ok(State::PendingStopped));
    assert_eq!(
        group.started_index(),
        Some(0),
        "the naming moves with the second request"
    );

    // The peer's STOPDT_CON: clause 5.3 completes the stop, and 5.4.13.30's own
    // step is what `transforms the previously Started connection to a Stopped
    // connection`.
    let con = group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StopDtCon));
    assert_eq!(con, Vec::<iec104::link::Action>::new());
    assert_eq!(group.state(0), Ok(State::Stopped));

    // The second request: STARTDT_ACT on the selected new connection.
    let starting = group.start(1).expect("the selected connection starts");
    assert_eq!(sent_u(&starting), Some(UFunction::StartDtAct));
    assert!(
        !starting.iter().any(|a| matches!(a, Action::ActiveClose(_))),
        "the graceful stop left nothing for 10.7's close rule to close"
    );
    assert_eq!(group.started_index(), Some(1));
    assert_eq!(
        group.state(0),
        Ok(State::Stopped),
        "the connection that was switched away from stays stopped"
    );
    assert_eq!(live_states(&group), vec![(1, State::PendingStarted)]);
}

/// TS 60870-5-604 `5.4.13.30` *"Manual switching over the Started connection to
/// another redundant Stopped connection: (manual switch-over)"* (indices 59–60,
/// printed 58–59), step by step: the `STOPDT_ACT`, the pending STOPDT state, the
/// controlled station *"acknowledges all yet unacknowledged I-frames from the
/// Controlling station with one or more S-frames"*, the `STOPDT_CON` that
/// *"transforms the previously Started connection to a Stopped connection"*, and
/// only then the `STARTDT_ACT` *"over the selected Stopped connection"*.
#[test]
fn ts_604_5_4_13_30_the_steps_of_a_manual_switchover() {
    let mut group = group_with_a_standby_member();

    // An unconfirmed I-frame of ours on the started connection.
    group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("its state allows user data");
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .outstanding_i_frames(),
        1
    );

    // Figure 37: `Stop connection[unconfirmed I-frames]/Send STOPDT act`. The
    // act goes out and the connection is in the pending STOPDT state.
    let actions = group.stop(0).expect("the started connection stops");
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtAct));
    assert_eq!(group.state(0), Ok(State::PendingUnconfirmedStopped));

    // The peer acknowledges the unacknowledged I-frame with an S-frame: figure
    // 37's `S-frame or I-frame [No unconfirmed I-frames]/` exit into the plain
    // pending STOPDT box.
    let actions = group
        .on_frame(0, Apci::S { nr: SeqNo::new(1) })
        .expect("the started connection takes S-frames");
    assert_eq!(actions, Vec::<iec104::link::Action>::new());
    assert_eq!(group.state(0), Ok(State::PendingStopped));

    // The STOPDT_CON stops it, and the STARTDT_ACT moves the start.
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StopDtCon));
    assert_eq!(group.state(0), Ok(State::Stopped));
    let actions = group
        .start(1)
        .expect("the selected stopped connection starts");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(group.started_index(), Some(1));
    assert_eq!(live_states(&group), vec![(1, State::PendingStarted)]);
}

/// The two refusals the first request of the manual switchover can produce, and
/// their order: 10.2 (index 118) has the *Controlling* station issue the
/// `STOPDT_ACT` *"on the currently started connection"* (rule 4's *"the selection
/// and switchover of the started connection is always initiated by the
/// controlling station"*), and figure 37 (index 140) draws the stop out of the
/// `STARTED connection` box, so a connection that is not started has no such
/// transition to take.
#[test]
fn clause_10_7_the_stop_is_the_controlling_stations_request_on_the_started_connection() {
    // A controlled station issues no STOPDT_ACT of its own.
    let mut controlled = controlled_group(2);
    establish_all(&mut controlled);
    assert_eq!(controlled.stop(0), Err(GroupError::CannotSelect));

    // A name that is not the group's started connection.
    let mut group = controlling_group(2, 0);
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    assert_eq!(
        group.stop(1),
        Err(GroupError::NotStartedConnection { index: 1 })
    );

    // The started connection, but not in the state figure 37's stop leaves.
    assert_eq!(
        group.stop(0),
        Err(GroupError::AlreadyInState {
            index: 0,
            state: State::Stopped,
        })
    );
    assert_eq!(
        group.stop(9),
        Err(GroupError::MemberIndexOutOfRange {
            index: 9,
            members: 2,
        })
    );

    // The act goes out once; a second stop of a connection that is already
    // pending its STOPDT_CON is its own refusal.
    group.start(0).expect("the started connection");
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(
        sent_u(&group.stop(0).expect("the first stop")),
        Some(UFunction::StopDtAct)
    );
    assert_eq!(
        group.stop(0),
        Err(GroupError::AlreadyInState {
            index: 0,
            state: State::PendingStopped,
        })
    );
}

/// 10.7, verbatim (index 136, printed 135): *"This means that asymmetric timeouts
/// t1 can also be used (and t2 correspondingly), i.e. shorter t1 in the
/// controlling station than in the controlled station to reduce switchover
/// time."* And: *"It should be possible to set the values of the timers t0 to
/// t3 individually for each connection within a redundancy group."*
///
/// No code is needed for the asymmetry: each member carries its own `Timers`
/// built from its own `LinkParams`, so the controlling station's `t1 = 5 s` is
/// due while the controlled station's `t1 = 15 s` is not. **The switchover rides
/// on the shorter t1**: the controlling station switches over at 5 s, and the
/// controlled station does not switch over at all (rule 4, index 118).
#[test]
fn clause_10_7_the_asymmetric_t1_switches_over_on_the_shorter_timeout() {
    let fast = LinkParams {
        t1: Duration::from_secs(5),
        t2: Duration::from_secs(1),
        ..LinkParams::default()
    };
    let slow = LinkParams {
        t1: Duration::from_secs(15),
        t2: Duration::from_secs(1),
        ..LinkParams::default()
    };
    let now = Instant::now();

    let mut controlling = RedundancyGroup::uniform(Role::Controlling, fast, 2).expect("a group");
    let mut controlled = RedundancyGroup::uniform(Role::Controlled, slow, 2).expect("a group");
    for group in [&mut controlling, &mut controlled] {
        for index in 0..group.len() {
            group
                .member_mut(index)
                .expect("a member")
                .session_mut()
                .on_connection_established();
        }
    }

    // The controlling station starts member 0 (10.3) and the controlled one
    // answers the act on the same connection (10.4).
    let actions = controlling
        .start(0)
        .expect("the controlling station starts 0");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    controlling
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(controlling.state(0), Ok(State::Started));
    assert_eq!(
        sent_u(&controlled.on_startdt_act(0).expect("the act arrived on 0")),
        Some(UFunction::StartDtCon)
    );
    assert_eq!(controlled.state(0), Ok(State::Started));

    arm_each_t1(&mut controlling, &mut controlled, now);

    // At five seconds the controlling station's t1 is due and the controlled
    // station's is not: the switchover happens at 5 s and never at 15 s.
    assert_eq!(
        controlled
            .member_mut(0)
            .expect("a member")
            .timers_mut()
            .expired(now + Duration::from_secs(5)),
        Vec::new(),
        "the controlled station's t1 = 15 s is not due at 5 s"
    );
    assert_eq!(
        controlling
            .member_mut(0)
            .expect("a member")
            .timers_mut()
            .expired(now + Duration::from_secs(5)),
        vec![Timer::T1]
    );
    let outcome = controlling
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 0,
        }),
        "the switchover is the controlling station's, on its own 5 s t1"
    );
    assert_eq!(controlling.state(0), Ok(State::Terminated));
    assert_eq!(controlling.state(1), Ok(State::PendingStarted));

    // The controlled station's own t1 only comes due at 15 s, and even then it
    // performs no switchover of its own: rule 4 leaves that to the controlling
    // station.
    assert_eq!(
        controlled
            .member_mut(0)
            .expect("a member")
            .timers_mut()
            .expired(now + Duration::from_secs(15)),
        vec![Timer::T1]
    );
    let outcome = controlled
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::LeftToTheControllingStation {
            failed: 0,
            unconfirmed: 0,
        })
    );
}

/// Arms t1 on each group's started member 0 at `now`: 5 s for the controlling
/// station, 15 s for the controlled one, each from its own `LinkParams`.
fn arm_each_t1(controlling: &mut RedundancyGroup, controlled: &mut RedundancyGroup, now: Instant) {
    // An unconfirmed U-frame or I-frame on each started connection arms that
    // connection's own t1.
    for group in [&mut *controlling, &mut *controlled] {
        group
            .member_mut(0)
            .expect("a member")
            .timers_mut()
            .frame_sent(now);
    }
    assert_eq!(
        controlling
            .member(0)
            .expect("a member")
            .params()
            .t1
            .as_secs(),
        5
    );
    assert_eq!(
        controlled
            .member(0)
            .expect("a member")
            .params()
            .t1
            .as_secs(),
        15
    );
    assert_eq!(
        controlling
            .member(0)
            .expect("a member")
            .timers()
            .deadline(Timer::T1),
        Some(now + Duration::from_secs(5))
    );
    assert_eq!(
        controlled
            .member(0)
            .expect("a member")
            .timers()
            .deadline(Timer::T1),
        Some(now + Duration::from_secs(15))
    );
}

/// Figure 36, *"State transition diagram for redundant connections (controlled
/// station)"* (index 138, printed 137), box by box. Its boxes are `STOPPED
/// connection`, `STARTED connection`, `Pending UNCONFIRMED STOPPED connection`
/// and the two terminals `Connection established` and `Connection terminated`;
/// every one of them is a [`State`] value read through `Member::state`, and no
/// second state enum exists.
#[test]
fn clause_10_7_figure_36_the_boxes_of_the_controlled_station() {
    let mut group = controlled_group(2);
    establish_all(&mut group);

    // `Connection established` -> `STOPPED connection`.
    assert_eq!(group.state(0), Ok(State::Stopped));

    // `STARTDT act[]/Close other not stopped connection(s)/Send STARTDT con`
    // into `STARTED connection`. Member 1 is stopped, so there is nothing to
    // close on this transition.
    let actions = group.on_startdt_act(0).expect("the act arrived on 0");
    assert_eq!(actions, vec![Action::Send(Apci::U(UFunction::StartDtCon))]);
    assert_eq!(group.state(0), Ok(State::Started));

    // `STOPDT act[unconfirmed I-frames]` into `Pending UNCONFIRMED STOPPED
    // connection`: the controlled station has an I-frame of its own that is not
    // acknowledged, so no `STOPDT con` goes out yet.
    group
        .send_user_data(0, &monitoring_data())
        .expect("the started connection")
        .expect("its state allows user data");
    assert_eq!(
        group
            .member(0)
            .expect("a member")
            .session()
            .outstanding_i_frames(),
        1
    );
    let actions = group
        .on_frame(0, Apci::U(UFunction::StopDtAct))
        .expect("the started connection takes U-frames");
    assert!(
        actions.is_empty(),
        "the STOPDT con waits for the unconfirmed I-frame"
    );
    assert_eq!(group.state(0), Ok(State::PendingUnconfirmedStopped));

    // `S-frame [no unconfirmed I-frames]/Send STOPDT con` back into `STOPPED
    // connection`.
    let actions = group
        .on_frame(0, Apci::S { nr: SeqNo::new(1) })
        .expect("the started connection takes S-frames");
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtCon));
    assert_eq!(group.state(0), Ok(State::Stopped));

    // `Timeout t1[]/Active close or I-frame[]/Active close` into `Connection
    // terminated`, through the connection's own active close (here the
    // connection change of figure 37's twin transition).
    assert_eq!(
        sent_u(&group.on_startdt_act(0).expect("the second act")),
        Some(UFunction::StartDtCon)
    );
    let actions = group.close(0).expect("the connection change");
    assert!(matches!(actions.as_slice(), [Action::ActiveClose(_)]));
    assert_eq!(group.state(0), Ok(State::Terminated));
}

/// Figure 37, *"State transition diagram for redundant connections (controlling
/// station)"* (index 140, printed 139), box by box: `STOPPED connection`,
/// `Pending STARTED connection`, `STARTED connection`, `Pending STOPPED
/// connection`, `Pending UNCONFIRMED STOPPED connection` and the `Connection
/// terminated` terminal, each of them a [`State`] value.
#[test]
fn clause_10_7_figure_37_the_boxes_of_the_controlling_station() {
    let mut group = controlling_group(2, 0);
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    // The standby connection is up too, so it can take over.
    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_connection_established();

    // `Connection established` -> `STOPPED connection`.
    assert_eq!(group.state(0), Ok(State::Stopped));

    // `Start connection[]/Send STARTDT act` -> `Pending STARTED connection`.
    let actions = group.start(0).expect("the connection starts");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    assert_eq!(group.state(0), Ok(State::PendingStarted));

    // `STARTDT con[]` -> `STARTED connection`.
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.state(0), Ok(State::Started));

    // `Stop connection[no unconfirmed I-frames]/Send STOPDT act` -> `Pending
    // STOPPED connection`, and `STOPDT con[]` back into `STOPPED connection`.
    let actions = group.stop(0).expect("the connection stops");
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtAct));
    assert_eq!(group.state(0), Ok(State::PendingStopped));
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StopDtCon));
    assert_eq!(group.state(0), Ok(State::Stopped));

    // `Stop connection[unconfirmed I-frames]/Send STOPDT act` -> `Pending
    // UNCONFIRMED STOPPED connection`.
    assert_eq!(
        sent_u(&group.start(0).expect("the connection starts again")),
        Some(UFunction::StartDtAct)
    );
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("its state allows user data");
    let actions = group.stop(0).expect("the connection stops");
    assert_eq!(sent_u(&actions), Some(UFunction::StopDtAct));
    assert_eq!(group.state(0), Ok(State::PendingUnconfirmedStopped));

    // `Timeout t1[]/Active close` -> `Connection terminated` (and 10.5's
    // switchover for the group, the standby member 1 taking over).
    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1,
        })
    );
    assert_eq!(group.state(0), Ok(State::Terminated));
    assert_eq!(group.started_index(), Some(1));
}

/// Figure 37's `User application requests connection change[]/Active close`
/// (index 140), the one transition clause 10 draws that figures 17/18 do not,
/// and figure 36's incoming `Close initiated by another connection[]/` (index
/// 138). 10.7 (index 136) makes it the second form of a manual switchover:
/// *"Manual switchover is initiated by the user application either by a Stop on
/// the started connection followed by a Start on another connection, or simply
/// by issuing a connection change request."*
///
/// TS 60870-5-604 `5.4.13.20` (index 59, printed 58) is why there is no role
/// guard: *"either"* station *"initiates a TCP active close on the inoperable
/// connection (which may never arrive)"*.
#[test]
fn clause_10_7_the_connection_change_is_an_active_close() {
    let mut group = group_with_a_standby_member();
    assert_eq!(group.started_index(), Some(0));

    let actions = group.close(0).expect("the connection change");
    assert!(matches!(actions.as_slice(), [Action::ActiveClose(_)]));
    assert_eq!(group.state(0), Ok(State::Terminated));
    assert_eq!(
        group.started_index(),
        None,
        "a terminated connection is not the started connection"
    );
    assert_eq!(group.started(), Err(GroupError::NoStartedConnection));
    assert_eq!(
        group.route(1),
        Err(GroupError::NoStartedConnection),
        "the group names no started connection, so nothing may carry user data"
    );

    // Nothing left to close, and a name that is no member.
    assert_eq!(
        group.close(0),
        Err(GroupError::AlreadyInState {
            index: 0,
            state: State::Terminated,
        })
    );
    assert_eq!(
        group.close(9),
        Err(GroupError::MemberIndexOutOfRange {
            index: 9,
            members: 2,
        })
    );

    // A controlled station closes an inoperable stopped member just the same,
    // and leaves the other connection where it is.
    let mut controlled = controlled_group(2);
    establish_all(&mut controlled);
    let actions = controlled
        .close(1)
        .expect("either role closes an inoperable member");
    assert!(matches!(actions.as_slice(), [Action::ActiveClose(_)]));
    assert_eq!(controlled.state(1), Ok(State::Terminated));
    assert_eq!(controlled.state(0), Ok(State::Stopped));
    assert_eq!(controlled.started_index(), None);
}

/// TS 60870-5-604 Table 13 (indices 58–60, printed 57–59), `5.4.13.1`
/// *"Periodic check of ALL redundant connections"* (index 58): the inactivity
/// time t3 runs on *"the Started connection"* **and** on *"all the Stopped
/// connections"*, each starting its own TESTFR procedure. This is clause 10.2's
/// rule 5 (*"All logical connections of a redundancy group shall be supervised
/// by test frames as described in 5.2."*) at group level, where a t3 is
/// supervision and never 10.5's switchover trigger.
#[test]
fn ts_604_5_4_13_1_the_periodic_check_runs_on_every_connection() {
    let params = LinkParams::default();
    let mut group = controlling_group(3, 0);
    let now = Instant::now();
    for index in 0..group.len() {
        let member = group.member_mut(index).expect("a member");
        member.session_mut().on_connection_established();
        member.timers_mut().connection_established(now);
    }

    // One connection is started (10.3); the other two stay stopped.
    let actions = group.start(0).expect("one connection is started");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtAct));
    group
        .member_mut(0)
        .expect("a member")
        .session_mut()
        .on_frame(Apci::U(UFunction::StartDtCon));
    assert_eq!(group.state(0), Ok(State::Started));

    for index in 0..group.len() {
        assert_eq!(
            group
                .member_mut(index)
                .expect("a member")
                .timers_mut()
                .expired(now + params.t3),
            vec![Timer::T3],
            "t3 on connection {index}, started or stopped"
        );
        let outcome = group
            .on_timeout(index, Timer::T3)
            .unwrap_or_else(|e| panic!("member {index} has a session: {e:?}"));
        assert_eq!(sent_u(&outcome.actions), Some(UFunction::TestFrAct));
        assert_eq!(
            outcome.switchover, None,
            "the supervision of a connection is not a switchover"
        );
        group
            .member_mut(index)
            .expect("a member")
            .session_mut()
            .on_frame(Apci::U(UFunction::TestFrCon));
        assert!(
            !group
                .member(index)
                .expect("a member")
                .session()
                .test_pending()
        );
    }
    assert_eq!(live_states(&group), vec![(0, State::Started)]);
}

/// A member whose connection was never established is `Stopped` like a live
/// standby, but neither a switchover nor a Start may use it.
#[test]
fn a_member_that_was_never_connected_is_not_a_standby() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    group
        .send_user_data(0, &station_interrogation())
        .expect("the started connection")
        .expect("its state allows user data");

    let outcome = group
        .on_timeout(0, Timer::T1)
        .expect("member 0 has a session");
    assert!(
        matches!(
            outcome.switchover,
            Some(Switchover::NoStoppedConnection { failed: 0, .. })
        ),
        "member 1 has no connection to switch to, got {:?}",
        outcome.switchover
    );
    assert_eq!(group.start(1), Err(GroupError::NotConnected { index: 1 }));

    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    assert!(group.start(1).is_ok());
}

/// 10.5: *"Care shall be taken that data are not lost during a connection
/// switchover."* When the started connection fails on a controlled station,
/// the group stops naming it, holds the data raised in the gap, and hands it
/// to the next connection the peer starts, right behind its STARTDT con.
#[test]
fn clause_10_5_data_raised_during_a_switchover_is_held_and_delivered() {
    let mut group = controlled_group(2);
    establish_all(&mut group);
    group.on_startdt_act(0).expect("an act arrived on 0");
    let outcome = group.on_timeout(0, Timer::T1).expect("member 0");
    assert!(matches!(
        outcome.switchover,
        Some(Switchover::LeftToTheControllingStation { failed: 0, .. })
    ));
    assert_eq!(group.started(), Err(GroupError::NoStartedConnection));

    let event = station_interrogation();
    assert_eq!(
        group.send_user_data(0, &event),
        Ok(None),
        "held, not refused"
    );
    assert_eq!(group.held_user_data(), std::slice::from_ref(&event));

    let actions = group
        .on_startdt_act(1)
        .expect("the peer starts connection 1");
    assert_eq!(sent_u(&actions), Some(UFunction::StartDtCon));
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::SendI { asdu, .. } if *asdu == event)),
        "the held event goes out on the new connection: {actions:?}"
    );
    assert_eq!(group.held_user_data(), Vec::<Vec<u8>>::new());
}

/// The timer-aware entry points run the members' timers themselves and route
/// every action to its member: a t1 on the started connection found by
/// `tick` is 10.5's switchover, with the failed member's close and the new
/// member's STARTDT act reported separately.
#[test]
fn the_routed_entry_points_run_the_timers_and_route_the_actions() {
    use iec104::redundancy::Routed;
    let t0 = Instant::now();
    let t1 = LinkParams::default().t1;
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_established(1, t0).unwrap();

    let routed = group.start_at(0, t0).unwrap();
    assert_eq!(
        routed,
        [Routed {
            member: 0,
            actions: vec![Action::Send(Apci::U(UFunction::StartDtAct))]
        }]
    );
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t0)
        .unwrap();
    let sent = group
        .send_user_data_at(0, &station_interrogation(), t0)
        .unwrap();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].member, 0);

    // Nobody confirms the I-frame: the group's own t1 fires.
    assert_eq!(
        group.tick((t0 + t1).checked_sub(Duration::from_millis(1)).unwrap()),
        TickOutcome::default()
    );
    let outcome = group.tick(t0 + t1);
    assert!(matches!(
        outcome.switchovers[..],
        [Switchover::Automatic {
            failed: 0,
            started: 1,
            ..
        }]
    ));
    assert!(outcome.routed.iter().any(|r| {
        r.member == 0
            && r.actions
                .iter()
                .any(|a| matches!(a, Action::ActiveClose(_)))
    }));
    assert!(
        outcome
            .routed
            .iter()
            .any(|r| r.member == 1 && r.actions == [Action::Send(Apci::U(UFunction::StartDtAct))])
    );
    assert_eq!(group.started(), Ok(1));
}

/// 10.7's close rule through the routed API: the close of the running
/// connection and the new connection's act come back under their own members.
#[test]
fn a_routed_start_separates_the_close_from_the_act() {
    let t0 = Instant::now();
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_established(1, t0).unwrap();
    group.start_at(0, t0).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t0)
        .unwrap();
    group.stop_at(0, t0).unwrap();
    let routed = group.start_at(1, t0).unwrap();
    let members: Vec<usize> = routed.iter().map(|r| r.member).collect();
    assert_eq!(members, [0, 1], "{routed:?}");
    assert!(matches!(
        routed[0].actions.last(),
        Some(Action::ActiveClose(reason)) if *reason == iec104::redundancy::CLOSED_BY_START
    ));
}

/// A controlling group asks for each member's connection, once per t0, and
/// again after one is lost (10.5's reopening).
#[test]
fn the_tick_asks_for_each_members_connection_once_per_t0() {
    let t0 = Instant::now();
    let dial = LinkParams::default().t0;
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    assert_eq!(group.tick(t0).connect, [0, 1]);
    assert!(group.tick(t0).connect.is_empty(), "one attempt at a time");
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_lost(1).unwrap(); // member 1's dial was refused
    assert_eq!(
        group
            .tick((t0 + dial).checked_sub(Duration::from_millis(1)).unwrap())
            .connect,
        Vec::<usize>::new()
    );
    assert_eq!(group.tick(t0 + dial).connect, [1]);

    group.on_connection_lost(0).unwrap(); // an established connection went away
    assert_eq!(group.tick(t0 + dial).connect, [0]);

    let controlled = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 2)
        .expect("group")
        .tick(t0);
    assert!(
        controlled.connect.is_empty(),
        "a controlled station listens"
    );
}

/// `next_deadline` is the soonest timer the group's `tick` would react to:
/// a dialing member's t0 (clause 10.7: t0 per connection) or a connected
/// member's t3 (clause 5.2), from clause 9's defaults of 30 s and 20 s.
#[test]
fn next_deadline_is_the_soonest_members_timer() {
    let t0 = Instant::now();
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    assert_eq!(group.next_deadline(), None, "never ticked: due at once");
    assert_eq!(group.tick(t0).connect, [0, 1]);
    assert_eq!(group.next_deadline(), Some(t0 + Duration::from_secs(30)));

    let up = t0 + Duration::from_secs(1);
    group.on_connection_established(1, up).unwrap();
    assert_eq!(group.next_deadline(), Some(up + Duration::from_secs(20)));

    let controlled =
        RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 2).expect("group");
    assert_eq!(
        controlled.next_deadline(),
        None,
        "a controlled station listens"
    );
}

/// Each member keeps its own parameters (clause 10.7, index 136: *"It should be
/// possible to set the values of the timers t0 to t3 individually for each
/// connection"*), so the soonest deadline is the member with the shorter t3.
#[test]
fn next_deadline_honours_each_members_own_timers() {
    let t0 = Instant::now();
    let short = LinkParams {
        t3: Duration::from_secs(5),
        ..LinkParams::default()
    };
    let mut group =
        RedundancyGroup::new(Role::Controlled, vec![LinkParams::default(), short]).expect("group");
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_established(1, t0).unwrap();
    assert_eq!(group.next_deadline(), Some(t0 + Duration::from_secs(5)));
}

/// A started connection its own session closed (figure 11's sequence error,
/// `Active close`) is no longer the started connection once the caller
/// reports the socket gone (rule 3), and the user data handed over meanwhile
/// is held for the next one (10.5, index 128: *"Care shall be taken that data
/// are not lost during a connection switchover"*).
#[test]
fn a_started_connection_closed_by_its_own_session_drops_the_naming_when_lost() {
    let t0 = Instant::now();
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_established(1, t0).unwrap();
    group.start_at(0, t0).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t0)
        .unwrap();

    // N(S) 5 where 0 is expected: a sequence error, and the session closes.
    let routed = group
        .on_frame_at(
            0,
            Apci::I {
                ns: SeqNo::new(5),
                nr: SeqNo::new(0),
            },
            t0,
        )
        .unwrap();
    assert!(matches!(
        routed[0].actions.last(),
        Some(Action::ActiveClose(_))
    ));
    group.on_connection_lost(0).unwrap();

    assert_eq!(group.started_index(), None);
    assert_eq!(
        group
            .send_user_data_at(0, &station_interrogation(), t0)
            .unwrap(),
        Vec::<iec104::redundancy::Routed>::new()
    );
    assert_eq!(group.held_user_data(), [station_interrogation()]);
}

/// A connection its own session closed leaves no timer behind: clause 5.1
/// makes a re-established connection a fresh one, so the t1 of an I-frame the
/// old connection never had confirmed does not close the new one (figures
/// 17/18's `Timeout t1[]/Active close` supervises frames of *this*
/// connection).
#[test]
fn a_re_established_member_inherits_no_timer_from_the_closed_connection() {
    let t0 = Instant::now();
    let t1 = LinkParams::default().t1;
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_established(1, t0).unwrap();
    group.start_at(0, t0).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t0)
        .unwrap();
    // An I-frame nobody confirms arms t1; then a sequence error closes the
    // connection from its own session.
    group
        .send_user_data_at(0, &station_interrogation(), t0)
        .unwrap();
    group
        .on_frame_at(
            0,
            Apci::I {
                ns: SeqNo::new(5),
                nr: SeqNo::new(0),
            },
            t0,
        )
        .unwrap();
    group.on_connection_lost(0).unwrap();

    let again = t0 + Duration::from_secs(1);
    group.on_connection_established(0, again).unwrap();
    assert_eq!(group.member(0).unwrap().timers().deadline(Timer::T1), None);
    let outcome = group.tick(t0 + t1);
    assert!(
        !outcome.routed.iter().any(|r| r.member == 0),
        "the fresh connection is left alone: {outcome:?}"
    );
}

/// A member whose session closed itself still has the caller's socket until
/// the caller reports it gone: `tick` asks for no second connection in the
/// meantime (one connection per member, 10.2), and once the loss is reported
/// the reopening of a connection that lasted longer than t0 is immediate
/// (10.5: *"reopening is regularly retried"*), not a t0 later. The connection
/// manager behaves the same way.
#[test]
fn a_self_closed_member_is_not_dialed_until_its_socket_is_reported_gone() {
    let t0 = Instant::now();
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    group.tick(t0);
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_established(1, t0).unwrap();
    group.start_at(0, t0).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t0)
        .unwrap();
    // A sequence error: the session closes itself.
    group
        .on_frame_at(
            0,
            Apci::I {
                ns: SeqNo::new(5),
                nr: SeqNo::new(0),
            },
            t0,
        )
        .unwrap();
    assert!(
        group.tick(t0).connect.is_empty(),
        "its socket is still open"
    );
    assert_eq!(
        group.next_deadline(),
        group.member(1).unwrap().timers().next_deadline()
    );

    // The caller reports the socket gone after the connection's t0.
    let later = t0 + LinkParams::default().t0 + Duration::from_secs(1);
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.tick(later).connect, [0], "reopened at once");
}

/// 10.5 (index 128): *"Care shall be taken that data are not lost during a
/// connection switchover"*. This holds also when the failed connection is
/// reopened before the caller replays its data: the fresh session's send buffer starts
/// empty (clause 5.1), but the group keeps the unconfirmed ASDU, and the
/// replay (10.6) puts it on the new started connection.
#[test]
fn clause_10_5_unconfirmed_data_survives_the_reopening_of_the_failed_connection() {
    let t0 = Instant::now();
    let t1 = LinkParams::default().t1;
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_established(1, t0).unwrap();
    group.start_at(0, t0).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t0)
        .unwrap();
    group
        .send_user_data_at(0, &station_interrogation(), t0)
        .unwrap();

    // t1: member 0 fails and member 1 is started in its place.
    let outcome = group.tick(t0 + t1);
    assert_eq!(
        outcome.switchovers,
        [Switchover::Automatic {
            failed: 0,
            started: 1,
            unconfirmed: 1
        }]
    );
    group.on_connection_lost(0).unwrap();
    group
        .on_frame_at(1, Apci::U(UFunction::StartDtCon), t0 + t1)
        .unwrap();
    // The reopening comes before the replay.
    group.on_connection_established(0, t0 + t1).unwrap();

    let (outcome, _) = group
        .retransmit_unconfirmed_at(0, Replay::Retransmit, t0 + t1)
        .unwrap();
    let ReplayOutcome::Retransmitted { actions, queued } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(queued, 0);
    assert_eq!(sent_i(&actions), [(0, 0, station_interrogation())]);
}

/// A started member the caller drives by hand ([`Member::session_mut`])
/// whose session closes itself is no longer the started one once the caller
/// reports the loss (rule 3), and user data waits in the group (10.5).
#[test]
fn a_hand_driven_self_closed_started_member_is_unnamed_when_lost() {
    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    // A sequence error: the session closes itself.
    group
        .on_frame(
            0,
            Apci::I {
                ns: SeqNo::new(5),
                nr: SeqNo::new(0),
            },
        )
        .unwrap();
    assert_eq!(group.state(0), Ok(State::Terminated));
    group.on_connection_lost(0).unwrap();
    assert_eq!(group.started_index(), None);
    assert_eq!(group.send_user_data(0, &station_interrogation()), Ok(None));
    assert_eq!(group.held_user_data(), [station_interrogation()]);
}

/// 10.5/10.6 when the failed member is itself the one started next (the
/// only member left, or an outstation whose master reconnects on the same
/// member): the data its failed connection left unconfirmed is still the
/// group's, and the replay puts it on the member's new connection, once.
#[test]
fn clause_10_6_the_failed_member_started_again_replays_its_earlier_data() {
    let t0 = Instant::now();
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    group.on_connection_established(0, t0).unwrap();
    group.start_at(0, t0).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t0)
        .unwrap();
    group
        .send_user_data_at(0, &station_interrogation(), t0)
        .unwrap();
    group.on_connection_lost(0).unwrap();

    // Reopened and started again before the application replays.
    group.on_connection_established(0, t0).unwrap();
    group.start_at(0, t0).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t0)
        .unwrap();
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Ok(ReplayOutcome::Left { unconfirmed: 1 })
    );
    let (outcome, _) = group
        .retransmit_unconfirmed_at(0, Replay::Retransmit, t0)
        .unwrap();
    let ReplayOutcome::Retransmitted { actions, queued } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(queued, 0);
    // N(S) 0 on the new connection (clause 5.1): it is the new connection's frame.
    assert_eq!(sent_i(&actions), [(0, 0, station_interrogation())]);
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Retransmit),
        Err(GroupError::AlreadyRetransmitted { index: 0 }),
        "once, and the live connection's own frames are not replayed"
    );

    // A later failure of the same member can be replayed again.
    group.on_connection_lost(0).unwrap();
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Ok(ReplayOutcome::Left { unconfirmed: 1 })
    );
}

/// Brings up connection `index` of an outstation group and has the master
/// start it (the peer's STARTDT act).
fn outstation_started(group: &mut RedundancyGroup, index: usize, t: Instant) {
    group.on_connection_established(index, t).unwrap();
    group
        .on_frame_at(index, Apci::U(UFunction::StartDtAct), t)
        .unwrap();
}

/// A controlled-station group of two connections with k = 1 and w = 1.
fn small_window_outstation() -> RedundancyGroup {
    let params = LinkParams {
        k: 1,
        w: 1,
        ..LinkParams::default()
    };
    RedundancyGroup::uniform(Role::Controlled, params, 2).expect("group")
}

/// 10.5 (index 128): *"Care shall be taken that data are not lost during a
/// connection switchover"*. The data a failed connection leaves is both what
/// its send buffer never had confirmed and what still waited in its clause 5.3
/// queue (a full k window, clause 5.5). All of it is counted and all of it is
/// replayed, also when the master reconnects on the same member and starts it.
#[test]
fn clause_10_5_the_queued_data_of_a_failed_connection_is_replayed_too() {
    let t = Instant::now();
    let mut group = small_window_outstation();
    outstation_started(&mut group, 0, t);
    let (a, b) = (station_interrogation(), {
        let mut b = station_interrogation();
        b[9] = 21; // QOI 21: group 1
        b
    });
    assert!(
        group.send_user_data(0, &a).unwrap().is_some(),
        "on the wire"
    );
    assert!(
        group.send_user_data(0, &b).unwrap().is_none(),
        "k = 1: queued"
    );
    group.on_connection_lost(0).unwrap();
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Ok(ReplayOutcome::Left { unconfirmed: 2 })
    );

    outstation_started(&mut group, 0, t);
    let ReplayOutcome::Retransmitted { actions, queued } =
        group.retransmit_unconfirmed(0, Replay::Retransmit).unwrap()
    else {
        panic!("a replay");
    };
    // A goes out (N(S) 0 on the new connection); B waits for the window.
    assert_eq!(sent_i(&actions), [(0, 0, a)]);
    assert_eq!(queued, 1);
    assert_eq!(group.member(0).unwrap().session().pending_user_data(), 1);
}

/// 10.5: the application may instead *"terminate the ongoing application
/// function and reinitiate it towards the new connection"*. `Discard` says so:
/// the failed connection's data is dropped, and a later failure counts and
/// replays only its own.
#[test]
fn clause_10_5_discarded_data_is_not_counted_or_replayed_later() {
    let t = Instant::now();
    let mut group = small_window_outstation();
    outstation_started(&mut group, 0, t);
    group.send_user_data(0, &station_interrogation()).unwrap();
    group.on_connection_lost(0).unwrap();
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Discard),
        Ok(ReplayOutcome::Discarded {
            discarded: 1,
            actions: Vec::new(),
        })
    );

    // The next connection's frame is confirmed, and that connection fails too.
    outstation_started(&mut group, 0, t);
    group.send_user_data(0, &station_interrogation()).unwrap();
    group.on_frame(0, Apci::S { nr: SeqNo::new(1) }).unwrap();
    group.on_connection_lost(0).unwrap();
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Ok(ReplayOutcome::Left { unconfirmed: 0 }),
        "nothing of the discarded failure, nothing of the confirmed frame"
    );
}

/// `Leave` only counts. What it leaves stays until the application replays or
/// discards it, also across later failures, which add their own.
#[test]
fn leave_keeps_the_data_for_a_later_decision() {
    let t = Instant::now();
    let mut group = small_window_outstation();
    outstation_started(&mut group, 0, t);
    group.send_user_data(0, &station_interrogation()).unwrap();
    group.on_connection_lost(0).unwrap();
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Ok(ReplayOutcome::Left { unconfirmed: 1 })
    );
    outstation_started(&mut group, 0, t);
    group.send_user_data(0, &station_interrogation()).unwrap();
    group.on_connection_lost(0).unwrap();
    assert_eq!(
        group.member(0).unwrap().left_behind().len(),
        2,
        "one ASDU per failure, each captured once"
    );
}

/// 10.2's manual switchover (*"first issuing a `STOPDT_ACT` on the currently
/// started connection and then a `STARTDT_ACT` on the selected new started
/// connection"*) with user data handed over between the two: it waited in the
/// stopped connection's clause 5.3 queue, never went out, and moves with the
/// naming (10.5: *"Care shall be taken that data are not lost during a
/// connection switchover"*). It leaves right behind the new STARTDT act (the
/// controlling station may send before the con, clause 5.3) and nowhere else.
#[test]
fn clause_10_2_data_queued_during_a_manual_switchover_moves_to_the_new_connection() {
    let t = Instant::now();
    let mut group =
        RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).expect("group");
    group.on_connection_established(0, t).unwrap();
    group.on_connection_established(1, t).unwrap();
    group.start_at(0, t).unwrap();
    group
        .on_frame_at(0, Apci::U(UFunction::StartDtCon), t)
        .unwrap();
    group.stop_at(0, t).unwrap();
    // STOPDT act out: data transfer is stopped, so the ASDU is queued on 0.
    assert_eq!(
        group
            .send_user_data_at(0, &station_interrogation(), t)
            .unwrap(),
        Vec::<iec104::redundancy::Routed>::new()
    );
    group
        .on_frame_at(0, Apci::U(UFunction::StopDtCon), t)
        .unwrap();

    let routed = group.start_at(1, t).unwrap();
    assert_eq!(routed.len(), 1, "{routed:?}");
    assert_eq!(routed[0].member, 1);
    assert_eq!(
        sent_u(&routed[0].actions),
        Some(UFunction::StartDtAct),
        "the act first"
    );
    assert_eq!(
        sent_i(&routed[0].actions),
        [(0, 0, station_interrogation())]
    );
    assert_eq!(group.member(0).unwrap().session().pending_user_data(), 0);
    assert_eq!(
        group.member(0).unwrap().queued_user_data(),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Ok(ReplayOutcome::Left { unconfirmed: 0 }),
        "nothing left behind on 0"
    );
}

/// A session the caller closed by hand ([`Member::session_mut`]) has left what
/// it held before its loss is reported: the decision counts all of it, and a
/// discard drops all of it: nothing comes back with the later loss.
#[test]
fn a_decision_on_a_hand_closed_session_covers_its_queue() {
    let t = Instant::now();
    let mut group = small_window_outstation();
    outstation_started(&mut group, 0, t);
    group.send_user_data(0, &station_interrogation()).unwrap(); // on the wire
    group.send_user_data(0, &station_interrogation()).unwrap(); // queued, k = 1
    group.member_mut(0).unwrap().session_mut().close("by hand");
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Leave),
        Ok(ReplayOutcome::Left { unconfirmed: 2 })
    );
    assert_eq!(
        group.retransmit_unconfirmed(0, Replay::Discard),
        Ok(ReplayOutcome::Discarded {
            discarded: 2,
            actions: Vec::new(),
        })
    );
    group.on_connection_lost(0).unwrap();
    assert_eq!(
        group.member(0).unwrap().left_behind(),
        Vec::<Vec<u8>>::new()
    );
}

/// A STARTDT act on a connection that is already over (its session closed,
/// its loss not yet reported) names nothing, and the user data the group
/// holds between a failure and the next start (10.5) stays held.
#[test]
fn an_act_on_a_closed_connection_names_nothing_and_keeps_the_held_data() {
    let t = Instant::now();
    let mut group = small_window_outstation();
    outstation_started(&mut group, 0, t);
    group.send_user_data(0, &station_interrogation()).unwrap();
    // t1: the started connection fails; the controlled station waits for the
    // master to start another (rule 4).
    group.on_timeout(0, Timer::T1).unwrap();
    assert!(
        group
            .send_user_data(0, &station_interrogation())
            .unwrap()
            .is_none()
    );
    assert_eq!(group.held_user_data().len(), 1);

    assert_eq!(
        group.on_frame(0, Apci::U(UFunction::StartDtAct)),
        Err(GroupError::NotConnected { index: 0 })
    );
    assert_eq!(group.started_index(), None);
    assert_eq!(group.held_user_data().len(), 1);
}

/// A codec error on a group's connection goes through the group: clause 5's
/// S-format rule (figure 7: octets 1 and 2 are 0x01 and 0x00) broken on the
/// started connection closes it, and what it held is captured for 10.5's
/// replay at once, as for every other close. A framing condition (half an
/// APDU, the framer's business) does nothing.
#[test]
fn a_parse_error_on_the_started_connection_closes_it_through_the_group() {
    use iec104::apci::ParseError;
    let t = Instant::now();
    let mut group = small_window_outstation();
    outstation_started(&mut group, 0, t);
    group.send_user_data(0, &station_interrogation()).unwrap();

    assert_eq!(
        group.on_parse_error_at(0, ParseError::Incomplete { needed: 2, have: 1 }, t),
        Ok(Vec::new())
    );
    let routed = group
        .on_parse_error_at(
            0,
            ParseError::BadSFormatOctet {
                octet1: 0x01,
                octet2: 0x01,
            },
            t,
        )
        .unwrap();
    assert_eq!(routed.len(), 1);
    assert_eq!(
        routed[0].actions,
        [Action::ActiveClose(
            "S-format control octets are not 0x01 0x00"
        )]
    );
    assert_eq!(group.state(0), Ok(State::Terminated));
    assert_eq!(
        group.member(0).unwrap().left_behind(),
        [station_interrogation()],
        "captured at the close, before the loss is reported"
    );
}

/// 10.6, verbatim (index 132): *"any unconfirmed user data will be
/// retransmitted on the new started connection after a connection switchover
/// has been performed"*. What the failed connection left unconfirmed is older
/// than the data the group held while no connection was started, so on the new
/// connection the replay goes first and the held data behind it.
#[test]
fn clause_10_6_the_replay_goes_out_before_the_held_data() {
    let a1 = station_interrogation();
    let mut d2 = station_interrogation();
    d2[9] = 0x15;

    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    group
        .send_user_data(0, &a1)
        .expect("the started connection")
        .expect("an I-frame");
    let outcome = group.on_timeout(0, Timer::T1).expect("member 0");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::NoStoppedConnection {
            failed: 0,
            unconfirmed: 1,
        })
    );
    assert_eq!(group.send_user_data(0, &d2), Ok(None), "held by the group");

    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    let now = Instant::now();
    let mut wire = Vec::new();
    for routed in group.start_at(1, now).expect("member 1 is stopped") {
        wire.extend(sent_i(&routed.actions));
    }
    let (_, routed) = group
        .retransmit_unconfirmed_at(0, Replay::Retransmit, now)
        .expect("member 1 is started");
    for routed in routed {
        wire.extend(sent_i(&routed.actions));
    }
    let asdus: Vec<Vec<u8>> = wire.into_iter().map(|(_, _, asdu)| asdu).collect();
    assert_eq!(asdus, vec![a1, d2], "the replay first, then the held data");
}

/// 10.5: *"Care shall be taken that data are not lost during a connection
/// switchover"*, and 10.6 keeps it in order. `Discard` releases the data the
/// group held onto the started connection, which already runs (clause 5.3:
/// STARTDT con received), so it goes out with the decision and not at a later
/// acknowledgement, and data sent after it queues behind it.
#[test]
fn clause_10_5_discard_sends_the_held_data_before_newer_data() {
    let a1 = station_interrogation();
    let mut d2 = station_interrogation();
    d2[9] = 0x15;
    let mut d3 = station_interrogation();
    d3[9] = 0x16;

    let mut group = controlling_group(2, 0);
    start_member(&mut group, 0);
    group
        .send_user_data(0, &a1)
        .expect("the started connection")
        .expect("an I-frame");
    let outcome = group.on_timeout(0, Timer::T1).expect("member 0");
    assert_eq!(
        outcome.switchover,
        Some(Switchover::NoStoppedConnection {
            failed: 0,
            unconfirmed: 1,
        })
    );
    assert_eq!(group.send_user_data(0, &d2), Ok(None), "held by the group");

    group
        .member_mut(1)
        .expect("a member")
        .session_mut()
        .on_connection_established();
    let now = Instant::now();
    let mut wire = Vec::new();
    for routed in group.start_at(1, now).expect("member 1 is stopped") {
        wire.extend(sent_i(&routed.actions));
    }
    for routed in group
        .on_frame_at(1, Apci::U(UFunction::StartDtCon), now)
        .expect("member 1")
    {
        wire.extend(sent_i(&routed.actions));
    }
    let (outcome, routed) = group
        .retransmit_unconfirmed_at(0, Replay::Discard, now)
        .expect("member 0 failed");
    for routed in routed {
        wire.extend(sent_i(&routed.actions));
    }
    assert!(
        matches!(outcome, ReplayOutcome::Discarded { discarded: 1, ref actions } if actions.len() == 1),
        "the released data is returned"
    );
    for routed in group.send_user_data_at(1, &d3, now).expect("member 1") {
        wire.extend(sent_i(&routed.actions));
    }
    let asdus: Vec<Vec<u8>> = wire.into_iter().map(|(_, _, asdu)| asdu).collect();
    assert_eq!(
        asdus,
        vec![d2, d3],
        "the held data first, then the newer data"
    );
}
