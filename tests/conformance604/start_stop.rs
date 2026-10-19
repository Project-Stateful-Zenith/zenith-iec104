//! 604 Table 2 (4 of 5), PDF page index 15 (printed 14), checklist entry
//! **`5.3.2.70`**, *"TRANSMISSION CONTROL USING START/STOP"*.
//!
//! This is a §5.3 verification row, not a §5.4 procedure, so its tests are named
//! `clause_5_3_2_70_…` rather than `clause_5_4_…`. Every row it carries is
//! `Required = M` and references `IEC 60870-5-104:2006, 5.3`; the rows the cases
//! below quote are quoted verbatim from the page.
//!
//! The crate implements four rows of this entry. This module is those four, each driven over a real socket against the controlled station under
//! test.
//!
//! # Direction
//!
//! All four drive the **controlled** station: three of the rows are explicitly
//! about it, and the fourth (the sequence numbers) is the same rule in either
//! direction. §5.1's COT44-47 exception does not apply: no case here sends one
//! of those four causes.

use crate::conformance604::{CA, ControlledStation, HELD_IOA, Peer, apci_of, asdu, deadline};
use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::Cause;
use iec104::link::State;

/// 604 Table 2 (4 of 5), PDF page index 15 (printed 14), row **`5.3.2.70`**,
/// `Reference` `IEC 60870-5-104:2006, 5.3`, `Required` `M`:
///
/// > After a TCP connection has been established, initially a Stopped connection
/// > is created (a Stopped connection is an open ("established") TCP connection
/// > that is in confirmed STOPDT state) and allows the exchange of U-frames in
/// > controlling and controlled direction
///
/// DUT: the **controlled** station. `Session::new(Role::Controlled)` starts in
/// `Stopped`, and a U-frame is answered from every live state, so this test
/// drives the **controlling-initiated** exchange (the peer's `TESTFR act`, the
/// station's `TESTFR con`) before any STARTDT. The row's *"in controlling and
/// controlled direction"* would also need the station to **initiate** a
/// U-frame, which takes a clock, and this harness has none. A
/// **controlled-initiated** U-frame (the station's own `TESTFR act` and the
/// peer's `con`) is therefore **not verified here**.
#[test]
fn clause_5_3_2_70_a_stopped_connection_exchanges_u_frames() {
    let station = ControlledStation::start().expect("the station binds a loopback port");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");

    // Controlling direction out, controlled direction back, while stopped.
    peer.send_u(UFunction::TestFrAct)
        .expect("the test act goes out");
    peer.expect_u(UFunction::TestFrCon, deadline(5))
        .expect("the station answers TESTFR act with TESTFR con");
    peer.close().expect("the peer closes");

    let report = station.join().expect("the station ends cleanly");
    assert_eq!(
        report.states,
        vec![State::Stopped],
        "5.3.2.70: the U-frame exchange leaves the connection in the Stopped state"
    );
    assert_eq!(
        report.received.len(),
        1,
        "5.3.2.70: exactly the one act arrived"
    );
}

/// 604 Table 2 (4 of 5), PDF page index 15 (printed 14), row **`5.3.2.70`**,
/// `Reference` `IEC 60870-5-104:2006, 5.3`, `Required` `M`:
///
/// > The receipt of I- and S-frames in a Stopped connection results in a TCP
/// > Active close (TCP Control field FIN).
///
/// DUT: the **controlled** station. The I-frame is sent before any STARTDT, so
/// the station is in `Stopped` when it arrives; the observable is the FIN, which
/// the peer sees as EOF, and the reason the session recorded.
#[test]
fn clause_5_3_2_70_an_i_frame_in_a_stopped_connection_is_actively_closed() {
    let station = ControlledStation::start().expect("the station binds a loopback port");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");

    // A `C_SC_NA_1` the station knows in every field, so clause 7.2.3's rule
    // would mirror nothing; only the state it arrives in is wrong.
    let request = asdu(0x2D, Cause::Activation.to_u8(), CA, HELD_IOA, 0x01);
    peer.send_i(SeqNo::new(0), SeqNo::new(0), &request)
        .expect("the I-frame goes out");

    // The observable the row names is the TCP Active close, which the peer sees
    // as EOF (`Peer::read_frame`'s `Ok(0)` branch). Asserting only `is_err()`
    // would also pass on a five-second silent time-out, which is no close at all.
    let answer = peer.read_frame(deadline(5));
    assert_eq!(
        answer.unwrap_err(),
        "the station closed the connection",
        "5.3.2.70: the active close reaches the peer as EOF, not a silent time-out"
    );
    let report = station.join().expect("the station ends cleanly");
    assert_eq!(
        report.closes,
        vec!["I-frame received while data transfer is stopped"],
        "5.3.2.70: \"results in a TCP Active close\""
    );
    assert!(
        report.sent.is_empty(),
        "5.3.2.70: the active close carries no frame of its own"
    );
}

/// 604 Table 2 (4 of 5), PDF page index 15 (printed 14), row **`5.3.2.70`**,
/// `Reference` `IEC 60870-5-104:2006, 5.3`, `Required` `M`:
///
/// > The receipt of I- and S-frames in a Stopped connection results in a TCP
/// > Active close (TCP Control field FIN).
///
/// DUT: the **controlled** station, for the S-frame half of the row (the case
/// above is the I-frame half). An `S(N(R) = 0)` sent before any STARTDT arrives
/// in `Stopped`; the observable is the FIN, which the peer sees as EOF, and the
/// reason the session recorded.
#[test]
fn clause_5_3_2_70_an_s_frame_in_a_stopped_connection_is_actively_closed() {
    let station = ControlledStation::start().expect("the station binds a loopback port");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");

    peer.send_s(SeqNo::new(0)).expect("the S-frame goes out");

    let answer = peer.read_frame(deadline(5));
    assert_eq!(
        answer.unwrap_err(),
        "the station closed the connection",
        "5.3.2.70: the active close reaches the peer as EOF, not a silent time-out"
    );
    let report = station.join().expect("the station ends cleanly");
    assert_eq!(
        report.closes,
        vec!["S-frame received while data transfer is stopped"],
        "5.3.2.70: \"results in a TCP Active close\""
    );
    assert!(
        report.sent.is_empty(),
        "5.3.2.70: the active close carries no frame of its own"
    );
}

/// 604 Table 2 (4 of 5), PDF page index 15 (printed 14), row **`5.3.2.70`**,
/// `Reference` `IEC 60870-5-104:2006, 5.3`, `Required` `M`:
///
/// > After the controlling station has received STARTDT_CON, the Started
/// > connection is created and the controlled station may sent U-, I-, and S-
/// > frames immediately after the STARTDT_CON. Controlled and controlling
/// > stations are allowed to send U-, I-, and S- frames
///
/// DUT: the **controlled** station. Data handed over while data transfer was not
/// enabled is held (`Session::queue_i_frame`, clause 5.3: *"Any pending user data
/// in the controlled station is sent only after the STARTDT con"*) and goes out
/// right behind the con (the session flushes its queue when it sends the con).
#[test]
fn clause_5_3_2_70_user_data_queued_before_start_goes_out_after_the_con() {
    // A `M_SP_NA_1` (type 1, 5-101 clause 7.3.1.1) reported spontaneously: one
    // object, one SIQ octet.
    let queued = asdu(0x01, Cause::Spontaneous.to_u8(), CA, HELD_IOA, 0x01);
    let station = ControlledStation::start_with_queue(vec![queued.clone()])
        .expect("the station binds a loopback port");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");

    peer.send_u(UFunction::StartDtAct)
        .expect("the STARTDT act goes out");
    peer.expect_u(UFunction::StartDtCon, deadline(5))
        .expect("the station answers STARTDT act with STARTDT con");

    let (apci, answer) = peer
        .expect_i(deadline(5))
        .expect("the queued data goes out");
    assert_eq!(
        answer, queued,
        "5.3.2.70: the queued ASDU is sent unchanged"
    );
    assert_eq!(
        apci,
        Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(0)
        },
        "5.3.2.70: it is the station's first I-frame"
    );
    peer.close().expect("the peer closes");

    let report = station.join().expect("the station ends cleanly");
    let order: Vec<Apci> = report
        .sent
        .iter()
        .map(|frame| apci_of(frame).expect("a frame the station sent"))
        .collect();
    assert_eq!(
        order,
        vec![
            Apci::U(UFunction::StartDtCon),
            Apci::I {
                ns: SeqNo::new(0),
                nr: SeqNo::new(0)
            }
        ],
        "5.3.2.70: \"the controlled station may sent U-, I-, and S- frames immediately after the STARTDT_CON\""
    );
}

/// 604 Table 2 (4 of 5), PDF page index 15 (printed 14), row **`5.3.2.70`**,
/// `Reference` `IEC 60870-5-104:2006, 5.3`, `Required` `M`:
///
/// > Send sequence number N(S) and Receive Sequence number N(R) remain unchanged
/// > during the use of U-frames with STARTDT / STOPDT indications
///
/// DUT: the **controlled** station. Two I-frames are sent with a full
/// STOPDT/STARTDT round trip between them; the sequence numbers of the station's
/// own I-frames continue where they left off, so the U-frames moved nothing.
#[test]
fn clause_5_3_2_70_u_frames_leave_the_sequence_numbers_unchanged() {
    let station = ControlledStation::start().expect("the station binds a loopback port");
    let mut peer = Peer::connect(station.addr()).expect("the controlling station connects");
    peer.start_data_transfer()
        .expect("the STARTDT exchange succeeds");

    // An address the station does not hold: each request is mirrored back, which
    // gives this case an I-frame to read a sequence number off.
    let unknown = |ioa| asdu(0x2D, Cause::Activation.to_u8(), CA, ioa, 0x01);

    peer.send_i(SeqNo::new(0), SeqNo::new(0), &unknown(HELD_IOA + 1))
        .expect("the first I-frame goes out");
    let (first, _) = peer.expect_i(deadline(5)).expect("the first mirror");
    assert_eq!(
        first,
        Apci::I {
            ns: SeqNo::new(0),
            nr: SeqNo::new(1)
        },
        "5.3.2.70: the station's first I-frame is N(S) = 0 and acknowledges ours"
    );

    // Confirm the station's I-frame, so the STOPDT below completes at once.
    peer.send_s(SeqNo::new(1))
        .expect("the acknowledgement goes out");
    peer.send_u(UFunction::StopDtAct)
        .expect("the STOPDT act goes out");
    peer.expect_u(UFunction::StopDtCon, deadline(5))
        .expect("the station completes the stop");
    peer.send_u(UFunction::StartDtAct)
        .expect("the second STARTDT act goes out");
    peer.expect_u(UFunction::StartDtCon, deadline(5))
        .expect("the station restarts data transfer");

    peer.send_i(SeqNo::new(1), SeqNo::new(1), &unknown(HELD_IOA + 2))
        .expect("the second I-frame goes out");
    let (second, _) = peer.expect_i(deadline(5)).expect("the second mirror");
    assert_eq!(
        second,
        Apci::I {
            ns: SeqNo::new(1),
            nr: SeqNo::new(2)
        },
        "5.3.2.70: N(S) and N(R) continued across the U-frames, unchanged by them"
    );

    peer.close().expect("the peer closes");
    let report = station.join().expect("the station ends cleanly");
    assert!(
        report.closes.is_empty(),
        "5.3.2.70: nothing closed the connection: {:?}",
        report.closes
    );
    assert!(
        report.states.contains(&State::Stopped),
        "5.3.2.70: the STOPDT act did return the connection to Stopped"
    );
}
