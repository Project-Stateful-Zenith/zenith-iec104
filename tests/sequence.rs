//! Sequence numbers, acknowledgement and the k/w window.
//!
//! Each test names the clause it pins: IEC 60870-5-104:2006 clause 5.1
//! (sequence numbers, acknowledgement by N(R), the send buffer, counters
//! restart at zero after connection establishment) and clause 5.5 (k and w).
//! The scripted exchanges in `figures_9_to_12_*` reproduce the standard's own
//! worked diagrams.

use iec104::apci::SeqNo;
use iec104::params::LinkParams;
use iec104::seq::{Sequence, SequenceError};

/// The standard's defaults with k and w overridden.
fn params(k: u16, w: u16) -> LinkParams {
    LinkParams {
        k,
        w,
        ..LinkParams::default()
    }
}

fn seq(k: u16, w: u16) -> Sequence {
    let p = params(k, w);
    assert!(p.validate().is_ok(), "test parameters must be admissible");
    Sequence::new(p)
}

const fn n(v: u16) -> SeqNo {
    SeqNo::new(v)
}

#[test]
fn counters_start_at_zero_after_connection_establishment() {
    // clause 5.1: "After the establishment of a TCP connection, the send and
    // receive sequence numbers are set to zero."
    let mut s = seq(12, 8);
    assert_eq!(s.v_s(), n(0));
    assert_eq!(s.v_r(), n(0));

    // Sending and then re-establishing resets both again.
    s.buffer_i_frame(&[0x01]).unwrap();
    s.note_i_frame_received(n(0)).unwrap();
    s.reset();
    assert_eq!(s.v_s(), n(0));
    assert_eq!(s.v_r(), n(0));
    assert_eq!(s.outstanding(), 0);
}

#[test]
fn a_sent_frame_is_stamped_with_ns_and_carries_the_acknowledgement_number() {
    // clause 5.1: the transmitter increases N(S); the N(R) of an outgoing frame
    // acknowledges everything properly received.
    let mut s = seq(12, 8);
    assert_eq!(s.buffer_i_frame(&[0xAA]).unwrap(), n(0));
    assert_eq!(s.v_s(), n(1));
    assert_eq!(s.v_r(), n(0));

    s.note_i_frame_received(n(0)).unwrap();
    assert_eq!(s.v_r(), n(1), "one I-frame received, so N(R) is now 1");
    assert_eq!(s.buffer_i_frame(&[0xBB]).unwrap(), n(1));
}

#[test]
fn the_transmitter_stops_at_k_unacknowledged_frames_and_resumes_on_ack() {
    // clause 5.5: "The transmitter stops the transmission at k unacknowledged
    // I format APDUs."
    let mut s = seq(4, 3);
    for expected in 0..4 {
        assert_eq!(
            s.buffer_i_frame(&[0x01]).unwrap(),
            n(expected),
            "frame {expected} is still inside the window"
        );
    }
    assert_eq!(s.outstanding(), 4);
    assert!(!s.window_open(), "k = 4 means the window is full");
    assert_eq!(s.buffer_i_frame(&[0x01]), None, "the 5th frame is refused");

    // Acknowledge all four; the window reopens.
    assert_eq!(s.note_ack_received(n(4)).unwrap(), 4);
    assert_eq!(s.outstanding(), 0);
    assert!(s.window_open());
    assert_eq!(s.buffer_i_frame(&[0x01]).unwrap(), n(4));
}

#[test]
fn a_partial_acknowledgement_only_releases_what_it_covers() {
    // clause 5.1: N(R) is "a valid acknowledge for all numbers <= the received
    // number", so the frames above it stay in the buffer.
    let mut s = seq(12, 8);
    for _ in 0..3 {
        s.buffer_i_frame(&[0x01]).unwrap();
    }
    assert_eq!(s.note_ack_received(n(2)).unwrap(), 2);
    assert_eq!(s.outstanding(), 1);
    assert_eq!(s.outstanding_frames()[0].ns, n(2));

    assert_eq!(s.note_ack_received(n(3)).unwrap(), 1);
    assert_eq!(s.outstanding(), 0);
    assert_eq!(s.outstanding_frames(), []);
    assert_eq!(
        s.note_ack_received(n(3)).unwrap(),
        0,
        "a repeat ack is a no-op"
    );
}

#[test]
fn the_receiver_acknowledges_after_w_received_frames() {
    // clause 5.5: "The receiver acknowledges at the latest after receiving w
    // I format APDUs". The standard's footnote adds "Acknowledging before k
    // is reached avoids a transmission stop."
    let mut s = seq(12, 3);
    assert_eq!(s.note_i_frame_received(n(0)).unwrap(), None);
    assert_eq!(s.note_i_frame_received(n(1)).unwrap(), None);
    assert!(s.ack_pending());

    let due = s.note_i_frame_received(n(2)).unwrap();
    assert_eq!(due, Some(n(3)), "w reached: emit S(3)");
    assert!(!s.ack_pending(), "the acknowledgement clears the counter");

    assert_eq!(s.note_i_frame_received(n(3)).unwrap(), None);
}

#[test]
fn an_w_triggered_acknowledgement_is_piggybackable_by_a_sent_frame() {
    // Sending an I-frame carries our current N(R), which acknowledges the
    // received frames just as an S-frame does.
    let mut s = seq(12, 2);
    s.note_i_frame_received(n(0)).unwrap();
    assert!(s.ack_pending());
    s.buffer_i_frame(&[0x01]).unwrap();
    assert!(!s.ack_pending(), "the sent frame carried N(R) = 1");
    assert_eq!(s.v_r(), n(1));
}

#[test]
fn a_wrong_ns_is_a_sequence_error() {
    // Figure 11 (`Erreur de séquence`): station A sends I(2,0) where I(1,..)
    // was expected and the connection is closed.
    let mut s = seq(12, 8);
    s.note_i_frame_received(n(0)).unwrap();
    let err = s.note_i_frame_received(n(2)).unwrap_err();
    assert_eq!(
        err,
        SequenceError::UnexpectedSendSequence {
            expected: n(1),
            got: n(2)
        }
    );
    assert_eq!(s.v_r(), n(1), "the wrong frame does not advance V(R)");
}

#[test]
fn an_acknowledgement_for_an_unsent_frame_is_rejected() {
    // clause 5.1: N(R) acknowledges "the number whose APDUs are properly
    // received", and a number we never sent cannot be valid.
    let mut s = seq(12, 8);
    s.buffer_i_frame(&[0x01]).unwrap();
    let err = s.note_ack_received(n(3)).unwrap_err();
    assert_eq!(
        err,
        SequenceError::AcknowledgedUnscheduled {
            oldest_outstanding: n(0),
            got: n(3),
            outstanding: 1,
        }
    );
    assert_eq!(s.outstanding(), 1, "nothing is released on an invalid ack");
}

#[test]
fn the_15_bit_wrap_does_not_lose_an_acknowledgement() {
    // The counter is 15 bits wide, so 32767 + 1 is 0 (clause 5.5: "modulo n
    // operation", n = 32768). An N(R) of 0 must acknowledge the frames numbered
    // 32766 and 32767: the wrap is a number, not a reset.
    let mut s = seq(12, 8);
    for _ in 0..32766 {
        let ns = s.buffer_i_frame(&[0x01]).unwrap();
        s.note_ack_received(ns.next()).unwrap();
    }
    assert_eq!(s.v_s(), n(32766));
    assert_eq!(s.v_r(), n(0), "nothing was received on this side yet");

    assert_eq!(s.buffer_i_frame(&[0x01]).unwrap(), n(32766));
    assert_eq!(s.buffer_i_frame(&[0x01]).unwrap(), n(32767));
    assert_eq!(s.v_s(), n(0), "V(S) wrapped to zero");
    assert_eq!(s.outstanding(), 2);

    assert_eq!(s.note_ack_received(n(0)).unwrap(), 2);
    assert_eq!(s.outstanding(), 0);
    assert_eq!(s.buffer_i_frame(&[0x01]).unwrap(), n(0));
}

#[test]
fn an_acknowledgement_across_the_wrap_releases_the_right_frames() {
    // The same wrap from the receiving side: N(R) = 1 while our buffer holds
    // 32766 and 32767 releases both, and N(R) = 0 then releases nothing more.
    let mut s = seq(12, 8);
    for _ in 0..32766 {
        let ns = s.buffer_i_frame(&[0x01]).unwrap();
        s.note_ack_received(ns.next()).unwrap();
    }
    s.buffer_i_frame(&[0x01]).unwrap();
    s.buffer_i_frame(&[0x01]).unwrap();
    assert_eq!(s.note_ack_received(n(0)).unwrap(), 2);
    assert_eq!(s.note_ack_received(n(0)).unwrap(), 0);
    assert_eq!(
        s.note_ack_received(n(1)),
        Err(SequenceError::AcknowledgedUnscheduled {
            oldest_outstanding: n(0),
            got: n(1),
            outstanding: 0,
        })
    );
}

#[test]
fn a_received_frame_carries_its_own_acknowledgement_of_our_frames() {
    // Figure 9: station B answers I(0,0) I(1,0) I(2,0) with I(0,3). The N(R) of
    // a received frame is processed exactly like an S-frame's; here with two
    // frames outstanding and N(R) = 2.
    let mut s = seq(12, 8);
    s.buffer_i_frame(&[0x01]).unwrap();
    s.buffer_i_frame(&[0x02]).unwrap();
    assert_eq!(s.outstanding(), 2);

    s.note_i_frame_received(n(0)).unwrap();
    assert_eq!(s.note_ack_received(n(2)).unwrap(), 2);
    assert_eq!(s.outstanding(), 0);
}

#[test]
fn figures_9_and_10_undisturbed_sequences_of_station_a() {
    // Figure 9 (`Figure 9 – Undisturbed sequences of numbered I format APDUs`):
    // A sends I(0,0) I(1,0) I(2,0); B answers I(0,3), so A's V(S) is 3 and its
    // V(R) is 1 after that answer. Figure 10 is the same run acknowledged by an
    // S format APDU instead (S(3)), which releases all three frames.
    let mut a = seq(12, 8);
    assert_eq!(a.buffer_i_frame(b"I(0,0)").unwrap(), n(0));
    assert_eq!(a.buffer_i_frame(b"I(1,0)").unwrap(), n(1));
    assert_eq!(a.buffer_i_frame(b"I(2,0)").unwrap(), n(2));
    assert_eq!(a.v_s(), n(3));
    assert_eq!(a.outstanding(), 3);

    // Station B's answer: I(0,3) means B's own N(S) = 0 and N(R) = 3.
    a.note_i_frame_received(n(0)).unwrap();
    assert_eq!(a.v_r(), n(1));
    assert_eq!(a.note_ack_received(n(3)).unwrap(), 3);
    assert_eq!(a.outstanding(), 0);

    // Figure 10's variant: the same three frames, acknowledged by S(3).
    let mut a = seq(12, 8);
    for _ in 0..3 {
        a.buffer_i_frame(b"I").unwrap();
    }
    assert_eq!(a.note_ack_received(n(3)).unwrap(), 3);
    assert_eq!(a.v_s(), n(3), "V(S) is not rewound by an acknowledgement");
}

#[test]
fn figure_11_a_disturbed_sequence_is_rejected() {
    // Figure 11 (`Séquence perturbée`): A sends I(0,0) and then I(2,0), so the
    // second number skips one, and the diagram marks a sequence error.
    let mut b = seq(12, 8);
    b.note_i_frame_received(n(0)).unwrap();
    assert!(b.note_i_frame_received(n(2)).is_err());
}

#[test]
fn figure_12_an_unacknowledged_last_frame_leaves_the_buffer_held() {
    // Figure 12 is the time-out case: the last I format APDU was never
    // acknowledged, so the buffer still holds it. The reaction to t1 belongs to
    // the session (`iec104::timers`, `iec104::link`); the sequence layer's part
    // is that the frame is still there to release.
    let mut a = seq(12, 8);
    a.buffer_i_frame(b"I(0,0)").unwrap();
    a.note_ack_received(n(1)).unwrap();
    a.buffer_i_frame(b"I(1,0)").unwrap();
    assert_eq!(a.outstanding(), 1);
    assert_eq!(a.outstanding_frames()[0].ns, n(1));
    assert_eq!(a.outstanding_frames()[0].asdu, b"I(1,0)");
}

#[test]
fn the_default_parameters_are_the_standard_ones() {
    // clause 5.5 and clause 9: k = 12 and w = 8 are the default values.
    let s = Sequence::new(LinkParams::default());
    assert_eq!(s.v_s(), n(0));
    assert_eq!(Sequence::modulus(), 32768);
    assert_eq!(LinkParams::default().k, 12);
    assert_eq!(LinkParams::default().w, 8);
}
