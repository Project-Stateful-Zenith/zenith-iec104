//! The receiving side's session, `iec104::ft::receive`, driven through 5-101
//! clause 7.4.11's transfer of a file (indices 131–133) against a provider
//! built on the controlled station's procedure, in the monitor direction of
//! TS 60870-5-604 `5.4.23.1` (index 84).

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use iec104::asdu::{
    Afq, Cause, Chs, Cp56Time2a, Frq, Header, Known, Lof, Los, Lsq, Nof, Nos, Scq, Segment, Sof,
    Srq,
};
use iec104::ft::receive::{DirectoryCall, Failure, Progress, Receiver};
use iec104::ft::{
    DirectoryEntry, FileTransferProcedure, Frame, FtError, Selection, checksum, decode_frame,
};

const CA: u16 = 12;
const IOA: u32 = 0x00_10_00;
const NOF: Nof = Nof { value: 7 };

const fn receiver() -> Receiver {
    Receiver::new(
        FileTransferProcedure::controlling(Selection::MONITOR, CA, 0),
        IOA,
        NOF,
    )
}

/// The providing side: the controlled station in the monitor direction.
const fn provider() -> FileTransferProcedure {
    FileTransferProcedure::controlled(Selection::MONITOR, CA, 0)
}

fn send(frame: &Frame) -> Vec<u8> {
    provider().build(frame).unwrap()
}

fn file_ready(lof: u32, negative: bool) -> Vec<u8> {
    send(&Frame::FileReady {
        ioa: IOA,
        nof: NOF,
        lof: Lof { value: lof },
        frq: Frq {
            value: 0,
            negative_confirm: negative,
        },
    })
}

fn section_ready(nos: u8, lof: u32, not_ready: bool) -> Vec<u8> {
    send(&Frame::SectionReady {
        ioa: IOA,
        nof: NOF,
        nos: Nos { value: nos },
        lof: Lof { value: lof },
        srq: Srq {
            value: 0,
            not_ready,
        },
    })
}

fn segment(nos: u8, payload: &[u8]) -> Vec<u8> {
    send(&Frame::Segment {
        ioa: IOA,
        segment: Segment {
            nof: NOF,
            nos: Nos { value: nos },
            los: Los {
                value: payload.len() as u8,
            },
            payload: payload.to_vec(),
        },
    })
}

fn last(nos: u8, lsq: u8, chs: Chs) -> Vec<u8> {
    send(&Frame::LastSection {
        ioa: IOA,
        nof: NOF,
        nos: Nos { value: nos },
        lsq: Lsq { value: lsq },
        chs,
    })
}

/// The one ASDU a step sent, decoded.
fn sent(step_send: &[Vec<u8>]) -> Frame {
    assert_eq!(step_send.len(), 1, "one ASDU per step");
    decode_frame(step_send.first().unwrap()).unwrap()
}

fn sc_action(frame: &Frame) -> (u8, u8) {
    match frame {
        Frame::Sc { scq, nos, .. } => (scq.action, nos.value),
        other => panic!("expected F_SC, got {other:?}"),
    }
}

fn afq_action(frame: &Frame) -> (u8, u8) {
    match frame {
        Frame::Ack { afq, nos, .. } => (afq.action, nos.value),
        other => panic!("expected F_AF, got {other:?}"),
    }
}

/// Sends one section in segments of at most `chunk` octets and its last
/// segment, and returns what the receiver sent for the last segment.
fn deliver_section(rx: &mut Receiver, nos: u8, octets: &[u8], chs: Chs) -> Frame {
    for chunk in octets.chunks(100) {
        let step = rx
            .on_asdu(&segment(nos, chunk), &Known::EVERYTHING)
            .unwrap();
        assert!(step.send.is_empty(), "a segment is not answered");
        assert_eq!(step.progress, Progress::Running);
    }
    let step = rx
        .on_asdu(
            &last(nos, Lsq::SECTION_WITHOUT_DEACTIVATION, chs),
            &Known::EVERYTHING,
        )
        .unwrap();
    assert_eq!(step.progress, Progress::Running);
    sent(&step.send)
}

#[test]
fn transfers_a_file_of_two_sections() {
    let file: Vec<u8> = (0..300u16).map(|i| (i % 251) as u8).collect();
    let (one, two) = file.split_at(200);
    let mut rx = receiver();

    // A_SELECT_FILE.req: F_SC_NA_1, SCQ <1>, cause <13>.
    let select = rx.start().unwrap();
    assert_eq!(Header::parse(&select).unwrap().cause, Cause::FileTransfer);
    assert_eq!(
        sc_action(&decode_frame(&select).unwrap()),
        (Scq::SELECT_FILE, 0)
    );

    // A_FILE_READY.req answers with LOF; the receiver calls the file (SCQ <2>).
    let step = rx
        .on_asdu(&file_ready(300, false), &Known::EVERYTHING)
        .unwrap();
    assert_eq!(sc_action(&sent(&step.send)), (Scq::REQUEST_FILE, 0));
    assert_eq!(rx.length(), Some(300));

    // Section 1: ready, called by name (SCQ <6>), delivered, acknowledged (AFQ <3>).
    let step = rx
        .on_asdu(&section_ready(1, 200, false), &Known::EVERYTHING)
        .unwrap();
    assert_eq!(sc_action(&sent(&step.send)), (Scq::REQUEST_SECTION, 1));
    let ack = deliver_section(&mut rx, 1, one, checksum(one));
    assert_eq!(afq_action(&ack), (Afq::SECTION_POSITIVE, 1));
    assert_eq!(rx.received(), 200);

    // Section 2 likewise.
    let step = rx
        .on_asdu(&section_ready(2, 100, false), &Known::EVERYTHING)
        .unwrap();
    assert_eq!(sc_action(&sent(&step.send)), (Scq::REQUEST_SECTION, 2));
    let ack = deliver_section(&mut rx, 2, two, checksum(two));
    assert_eq!(afq_action(&ack), (Afq::SECTION_POSITIVE, 2));

    // A_LAST_SECTION.req with the file's CHS (7.2.6.37) closes it: AFQ <1>.
    let step = rx
        .on_asdu(
            &last(2, Lsq::FILE_WITHOUT_DEACTIVATION, checksum(&file)),
            &Known::EVERYTHING,
        )
        .unwrap();
    assert_eq!(afq_action(&sent(&step.send)), (Afq::FILE_POSITIVE, 2));
    assert_eq!(step.progress, Progress::Complete(file));

    // Anything after the end changes nothing.
    let late = rx
        .on_asdu(&file_ready(1, false), &Known::EVERYTHING)
        .unwrap();
    assert!(late.send.is_empty(), "nothing after the end");
    assert_eq!(late.progress, Progress::Running);
}

#[test]
fn a_section_that_does_not_add_up_is_asked_for_again() {
    let file = [5u8; 50];
    let mut rx = receiver();
    rx.start().unwrap();
    rx.on_asdu(&file_ready(50, false), &Known::EVERYTHING)
        .unwrap();
    rx.on_asdu(&section_ready(1, 50, false), &Known::EVERYTHING)
        .unwrap();

    // 7.2.6.37's sum is off by one: AFQ <4>, the negative section
    // acknowledgement, and 604 5.4.23.1's repeat of the section.
    let wrong = Chs {
        value: checksum(&file).value.wrapping_add(1),
    };
    let ack = deliver_section(&mut rx, 1, &file, wrong);
    assert_eq!(afq_action(&ack), (Afq::SECTION_NEGATIVE, 1));
    assert_eq!(rx.received(), 0, "the bad section's octets are dropped");

    let ack = deliver_section(&mut rx, 1, &file, checksum(&file));
    assert_eq!(afq_action(&ack), (Afq::SECTION_POSITIVE, 1));
    let step = rx
        .on_asdu(
            &last(1, Lsq::FILE_WITH_DEACTIVATION, checksum(&file)),
            &Known::EVERYTHING,
        )
        .unwrap();
    assert_eq!(step.progress, Progress::Complete(file.to_vec()));
}

#[test]
fn a_file_that_does_not_add_up_fails_with_a_negative_acknowledgement() {
    let file = [9u8; 20];
    let mut rx = receiver();
    rx.start().unwrap();
    rx.on_asdu(&file_ready(20, false), &Known::EVERYTHING)
        .unwrap();
    rx.on_asdu(&section_ready(1, 20, false), &Known::EVERYTHING)
        .unwrap();
    deliver_section(&mut rx, 1, &file, checksum(&file));

    let got = Chs { value: 0 };
    let step = rx
        .on_asdu(
            &last(1, Lsq::FILE_WITHOUT_DEACTIVATION, got),
            &Known::EVERYTHING,
        )
        .unwrap();
    assert_eq!(afq_action(&sent(&step.send)), (Afq::FILE_NEGATIVE, 1));
    assert_eq!(
        step.progress,
        Progress::Failed(Failure::FileChecksum {
            expected: checksum(&file),
            got
        })
    );
}

#[test]
fn a_negative_file_ready_or_a_section_not_ready_ends_the_transfer() {
    // FRQ BS1 (7.2.6.28): the file is not ready.
    let mut rx = receiver();
    rx.start().unwrap();
    let step = rx
        .on_asdu(&file_ready(0, true), &Known::EVERYTHING)
        .unwrap();
    assert!(step.send.is_empty(), "a refusal is not answered");
    assert!(matches!(
        step.progress,
        Progress::Failed(Failure::FileNotReady { .. })
    ));

    // SRQ bit 8 (7.2.6.29): the section is not ready.
    let mut rx = receiver();
    rx.start().unwrap();
    rx.on_asdu(&file_ready(10, false), &Known::EVERYTHING)
        .unwrap();
    let step = rx
        .on_asdu(&section_ready(1, 10, true), &Known::EVERYTHING)
        .unwrap();
    assert!(matches!(
        step.progress,
        Progress::Failed(Failure::SectionNotReady {
            nos: Nos { value: 1 },
            ..
        })
    ));
}

#[test]
fn a_mirrored_request_is_the_providers_refusal() {
    // 5-101 cl.7.2.3: the select comes back with P/N = 1 and cause 47.
    let mut rx = receiver();
    let mut mirror = rx.start().unwrap();
    mirror[2] = 0x6F; // P/N = 1, cause 47
    let step = rx.on_asdu(&mirror, &Known::EVERYTHING).unwrap();
    assert!(step.send.is_empty(), "a mirror is not answered");
    assert_eq!(
        step.progress,
        Progress::Failed(Failure::Refused {
            cause: Cause::UnknownInformationObjectAddress
        })
    );
}

#[test]
fn an_answer_to_another_file_is_an_echo_mismatch() {
    let mut rx = receiver();
    rx.start().unwrap();
    let other = send(&Frame::FileReady {
        ioa: IOA,
        nof: Nof { value: 8 },
        lof: Lof { value: 1 },
        frq: Frq::default(),
    });
    assert!(matches!(
        rx.on_asdu(&other, &Known::EVERYTHING),
        Err(FtError::EchoMismatch { .. })
    ));
}

#[test]
fn a_directory_spans_asdus_until_the_last_file() {
    let entry = |nof: u16, last: bool| DirectoryEntry {
        nof: Nof { value: nof },
        lof: Lof {
            value: u32::from(nof) * 10,
        },
        sof: Sof {
            last_file_of_directory: last,
            ..Sof::default()
        },
        time: Cp56Time2a::default(),
    };
    let mut call = DirectoryCall::new(FileTransferProcedure::controlling(
        Selection::MONITOR,
        CA,
        0,
    ));
    // A_CALL_DIRECTORY.req: SCQ <0>, cause <5> (figure 85, index 116).
    let request = call.start(IOA).unwrap();
    assert_eq!(Header::parse(&request).unwrap().cause, Cause::Request);

    let first = send(&Frame::Directory {
        ioa: IOA,
        cause: Cause::Request,
        files: vec![entry(1, false), entry(2, false)],
    });
    let step = call.on_asdu(&first, &Known::EVERYTHING).unwrap();
    assert_eq!(step.progress, Progress::Running);

    // SOF's LFD (7.2.6.38) marks the directory's last entry.
    let second = send(&Frame::Directory {
        ioa: IOA + 2,
        cause: Cause::Request,
        files: vec![entry(3, true)],
    });
    let step = call.on_asdu(&second, &Known::EVERYTHING).unwrap();
    assert_eq!(
        step.progress,
        Progress::Complete(vec![entry(1, false), entry(2, false), entry(3, true)])
    );
}
