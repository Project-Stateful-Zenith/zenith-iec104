//! Stream framing of APDUs.
//!
//! IEC 60870-5-104 clause 5: `START = 0x68` marks where a frame begins in the
//! stream, and the following octet carries the number of octets after
//! it. TCP delivers arbitrary chunk boundaries, so the framing layer has to
//! buffer until a whole APDU is present. An octet where a start octet belongs
//! is reported as `BadStart`, for the connection to close on (`link::reaction`),
//! and discarded up to the next start octet, so a caller that goes on reading
//! is never stuck on it.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions
)]

use iec104::apci::ParseError;

use iec104::apci::{self, Apci};
use iec104::framed::{Decoder, Framed, FramingError};
use std::io::{Cursor, Read};

/// One I-format APDU carrying a dummy ASDU, encoded by the codec so the
/// test cannot disagree with the encoder about the byte layout.
fn frame(ns: u16, nr: u16, asdu: &[u8]) -> Vec<u8> {
    let i_frame = apci::Apdu {
        apci: Apci::I {
            ns: apci::SeqNo::new(ns),
            nr: apci::SeqNo::new(nr),
        },
        asdu,
    };
    let mut out = Vec::new();
    i_frame.encode(&mut out).unwrap();
    out
}

fn start_frame() -> Vec<u8> {
    let mut out = Vec::new();
    apci::Apdu {
        apci: Apci::U(apci::UFunction::StartDtAct),
        asdu: &[],
    }
    .encode(&mut out)
    .unwrap();
    out
}

#[test]
fn complete_frame_in_one_write() {
    let mut d = Decoder::new();
    let f = frame(0, 0, &[1, 2, 3]);
    d.push(&f);
    assert_eq!(d.next_frame().unwrap(), Some(&f[..]));
    assert_eq!(d.next_frame().unwrap(), None);
}

#[test]
fn coalesced_frames_come_out_in_order() {
    let mut d = Decoder::new();
    let a = frame(0, 0, &[1, 2, 3]);
    let b = start_frame();
    let c = frame(1, 0, &[9]);
    let mut stream = Vec::new();
    stream.extend_from_slice(&a);
    stream.extend_from_slice(&b);
    stream.extend_from_slice(&c);
    d.push(&stream);

    assert_eq!(d.next_frame().unwrap(), Some(&a[..]));
    assert_eq!(d.next_frame().unwrap(), Some(&b[..]));
    assert_eq!(d.next_frame().unwrap(), Some(&c[..]));
    assert_eq!(d.next_frame().unwrap(), None);
}

#[test]
fn frame_split_at_every_boundary_is_reassembled() {
    let a = frame(0, 0, &[1, 2, 3]);
    let b = frame(1, 0, &[4, 5]);
    let mut stream = Vec::new();
    stream.extend_from_slice(&a);
    stream.extend_from_slice(&b);

    // Feed the stream in two chunks, moving the split through every position.
    for split in 0..=stream.len() {
        let mut d = Decoder::new();
        d.push(&stream[..split]);
        let mut got: Vec<Vec<u8>> = Vec::new();
        while let Some(f) = d.next_frame().unwrap() {
            got.push(f.to_vec());
        }
        // Only frames fully inside the first chunk may have come out yet.
        assert_eq!(got, expected_prefix(&stream, split), "split at {split}");

        d.push(&stream[split..]);
        while let Some(f) = d.next_frame().unwrap() {
            got.push(f.to_vec());
        }
        assert_eq!(got, vec![a.clone(), b.clone()], "split at {split}");
    }
}

/// The frames that are byte-complete within the first `n` octets of `stream`.
fn expected_prefix(stream: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + 2 <= n {
        let total = 2 + stream[off + 1] as usize;
        if off + total <= n {
            out.push(stream[off..off + total].to_vec());
        }
        off += total;
    }
    out
}

#[test]
fn byte_at_a_time_feeding_yields_each_frame_once() {
    let mut d = Decoder::new();
    let a = frame(0, 0, &[1, 2, 3]);
    let b = start_frame();
    let mut out: Vec<Vec<u8>> = Vec::new();
    for byte in a.iter().chain(b.iter()) {
        d.push(&[*byte]);
        while let Some(f) = d.next_frame().unwrap() {
            out.push(f.to_vec());
        }
    }
    assert_eq!(out, vec![a, b]);
}

#[test]
fn junk_before_the_start_octet_is_reported_then_discarded() {
    let mut d = Decoder::new();
    let f = frame(0, 0, &[1, 2, 3]);
    // Junk that cannot be mistaken for a start octet or a length field.
    d.push(&[0x00, 0xFF, 0x12]);
    d.push(&f);
    // Clause 5: the frame starts with 68H; the first octet here is 00H.
    match d.next_frame() {
        Err(FramingError::BadFrame(ParseError::BadStart(0x00))) => {}
        other => panic!("expected BadStart(0x00), got {other:?}"),
    }
    assert_eq!(d.next_frame().unwrap(), Some(&f[..]));
    assert_eq!(d.next_frame().unwrap(), None);
    assert_eq!(d.resyncs(), 3, "the three junk octets were discarded");
}

#[test]
fn a_stray_start_octet_with_a_plausible_length_makes_the_framer_wait() {
    // The format has no checksum, so `0x68 0x68` is indistinguishable from the
    // header of a frame whose length field announces 104 octets. The framer therefore waits for the promised
    // length instead of discarding it. Recovering from a peer that
    // desynchronises like this is the connection layer's job (timers t1/t2 in
    // `iec104::timers`).
    let mut d = Decoder::new();
    d.push(&[0x68, 0x68, 0x00]);
    let f = frame(0, 0, &[1, 2, 3]);
    d.push(&f);
    assert_eq!(d.next_frame().unwrap(), None);
    assert_eq!(
        d.buffered(),
        12,
        "the octets are held until the promised length arrives"
    );
}

#[test]
fn illegal_length_is_reported_and_the_decoder_makes_progress() {
    let mut d = Decoder::new();
    // start + length 3 (below the control-field minimum of 4)
    d.push(&[0x68, 0x03, 0x00, 0x00, 0x00]);
    match d.next_frame() {
        Err(FramingError::BadFrame(_)) => {}
        other => panic!("expected a framing error, got {other:?}"),
    }
    // The offending frame was dropped, so the next call is not stuck on it.
    let f = frame(0, 0, &[7]);
    d.push(&f);
    assert_eq!(d.next_frame().unwrap(), Some(&f[..]));
}

#[test]
fn partial_frame_returns_none_until_it_is_complete() {
    let mut d = Decoder::new();
    let f = frame(0, 0, &[1, 2, 3, 4, 5]);
    d.push(&f[..f.len() - 1]);
    assert_eq!(d.next_frame().unwrap(), None);
    assert!(d.is_idle());
    d.push(&f[f.len() - 1..]);
    assert_eq!(d.next_frame().unwrap(), Some(&f[..]));
}

#[test]
fn framed_reader_over_a_small_chunk_reader_yields_whole_frames() {
    // A reader that hands out at most 3 octets per call exercises the buffering.
    struct Dribble {
        data: Vec<u8>,
        pos: usize,
    }
    impl Read for Dribble {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = buf.len().min(3).min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    let a = frame(0, 0, &[1, 2, 3]);
    let b = frame(1, 0, &[4, 5]);
    let mut stream = Vec::new();
    stream.extend_from_slice(&a);
    stream.extend_from_slice(&b);

    let mut f = Framed::new(Dribble {
        data: stream,
        pos: 0,
    });
    let mut got: Vec<Vec<u8>> = Vec::new();
    while let Some(frame) = f.next_frame().unwrap() {
        got.push(frame.to_vec());
    }
    assert_eq!(got, vec![a, b]);
}

#[test]
fn framed_reader_reports_io_errors() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "gone",
            ))
        }
    }
    let mut f = Framed::new(Broken);
    match f.next_frame() {
        Err(FramingError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
        other => panic!("expected an io error, got {other:?}"),
    }
}

#[test]
fn framed_reader_returns_none_at_end_of_stream_with_nothing_buffered() {
    let mut f = Framed::new(Cursor::new(Vec::new()));
    assert_eq!(f.next_frame().unwrap(), None);
}

/// A junk octet between frames, with the next frame arriving in pieces, is
/// skipped: the reader does not report end of stream while the stream lives.
#[test]
fn framed_reader_reports_junk_between_frames_without_ending_the_stream() {
    struct Chunks(Vec<Vec<u8>>);
    impl Read for Chunks {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() {
                return Ok(0);
            }
            let chunk = self.0.remove(0);
            buf[..chunk.len()].copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }
    let first = frame(0, 0, &[1, 2, 3]);
    let second = frame(1, 0, &[4, 5, 6]);
    let (head, tail) = second.split_at(3);
    let mut junk_then_half = first.clone();
    junk_then_half.push(0xAA);
    junk_then_half.extend_from_slice(head);

    let mut framed = Framed::new(Chunks(vec![junk_then_half, tail.to_vec()]));
    assert_eq!(framed.next_frame().unwrap(), Some(&first[..]));
    match framed.next_frame() {
        Err(FramingError::BadFrame(ParseError::BadStart(0xAA))) => {}
        other => panic!("expected BadStart(0xAA), got {other:?}"),
    }
    assert_eq!(framed.next_frame().unwrap(), Some(&second[..]));
    assert_eq!(framed.next_frame().unwrap(), None);
    assert_eq!(framed.decoder().resyncs(), 1);
}

/// Junk in front of a whole frame: `next_frame_len` reports it, `is_idle`
/// says no frame is ready, and `next_frame` reports it once, discards it and
/// then yields the frame.
#[test]
fn a_frame_behind_junk_comes_after_the_junk_is_reported() {
    let whole = frame(0, 0, &[1]);
    let mut decoder = Decoder::new();
    decoder.push(&[0x00, 0xAA]);
    decoder.push(&whole);
    assert!(decoder.is_idle());
    assert_eq!(decoder.next_frame_len(), Err(ParseError::BadStart(0x00)));
    assert!(matches!(
        decoder.next_frame(),
        Err(FramingError::BadFrame(ParseError::BadStart(0x00)))
    ));
    assert_eq!(decoder.next_frame_len(), Ok(Some(whole.len())));
    assert_eq!(decoder.next_frame().unwrap(), Some(&whole[..]));
}
