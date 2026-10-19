//! The interoperability scenario offline, against a mock outstation.
//!
//! The scenario itself (and every clause citation behind it) is
//! `tests/interop/mod.rs`. This entry point runs it against
//! [`interop::MockOutstation`], so `cargo test --all-features` covers the whole
//! exchange on a box with no Python at all. The same step list runs against the
//! real peer `c104` in `tests/interop.rs`, which is `#[ignore]`d.
//!
//! The mock is a peer, not a fixture: it accepts a real TCP connection and
//! answers from the same primitives a controlled station would use
//! (`link::Session`, `gi::Interrogation`, `ct::CommandTransmission`).

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::string_slice
)]

#[path = "interop/mod.rs"]
mod interop;

/// cl.7.1 (index 54), cl.5.3 (index 38), cl.7.5 (index 64), cl.7.4 (index 64),
/// cl.7.7 (index 68), cl.5.2 (index 34) and cl.7.1's active-close row
/// (index 56): the whole scripted scenario, offline.
#[test]
fn the_scripted_scenario_passes_against_the_mock_outstation() {
    let peer = interop::MockOutstation::start().expect("the mock binds a loopback port");
    let address = peer.addr();
    let station = interop::Station::connect(address).expect("the controlling station connects");
    let station = match interop::run(station, &interop::scenario()) {
        Ok(station) => station,
        Err(why) => panic!("the scenario failed: {why}"),
    };
    let report = peer.join().expect("the mock outstation ends cleanly");

    // cl.5.3: no user data crossed the wire before the STARTDT act. This is the
    // half of the rule a session-level assertion cannot see, and it is why the
    // mock keeps its own frame log.
    assert_eq!(
        report.peer_i_frames_before_start, 0,
        "cl.5.3: no I-frame may go out before STARTDT"
    );
    assert!(report.received.len() > 5, "the peer saw the scenario");
    assert!(
        !report.sent.is_empty(),
        "the peer answered the scenario's requests"
    );
    // cl.5.1 (104 index 32, the NOTE under figure 11): every I-frame the mock
    // sent is acknowledged by the time the socket closes, so the S-frame t2
    // produced really did go out: the mock's send buffer is empty at EOF.
    assert_eq!(
        report.outstanding_i_frames_at_eof, 0,
        "cl.5.1: the peer's I-frames are all acknowledged before the close"
    );
    // cl.5.3: the very first frame on the wire is the STARTDT act. No user
    // data moved before it.
    assert_eq!(
        interop::parse_frame(&report.received[0]).expect("the first received frame"),
        (
            iec104::apci::Apci::U(iec104::apci::UFunction::StartDtAct),
            Vec::new()
        ),
        "cl.5.3: STARTDT act is the first frame"
    );

    // cl.7.1 (index 56) + TS 60870-5-604 5.4.13.20: the scenario ended at the
    // socket boundary, so no ActiveClose was ever raised. The clean close is
    // asserted inside the step and again here on the returned station.
    assert!(station.closes.is_empty(), "cl.7.1: no active close");
    assert_eq!(
        station.session().state(),
        iec104::link::State::Terminated,
        "cl.7.1: the connection is terminated"
    );
}

/// The committed real-peer capture: `c104` 2.2.1's positive `C_IC_NA_1 ACTCON`,
/// parsed with **our** codec. The live cross-check lives in `tests/interop.rs`;
/// this pins one real frame in the offline suite so a bug that the codec and
/// the mock share cannot hide.
///
/// cl.7.5 (index 64) and cl.7.2.6.22 (index 53): type 100, cause 7, `P/N = 0`,
/// common address 1, the irrelevant information object address and `QOI` 20.
#[test]
fn the_committed_capture_is_a_real_peers_actcon() {
    interop::assert_peer_capture().expect("the capture decodes with our codec");
}
