//! The providing side's session, `iec104::ft::provide`, against the receiving
//! side's, `iec104::ft::receive`: 5-101 clause 7.4.11's transfer (indices
//! 131–133) in the monitor direction (604 `5.4.23.1`, index 84) and the control
//! direction (`5.4.23.10`, index 85), and the directory of figure 89.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use iec104::asdu::{Afq, Cp56Time2a, Known, Lof, Lsq, Nof, Nos, Scq, Sof};
use iec104::ft::provide::{DEFAULT_SECTION_LEN, Provider, directory};
use iec104::ft::receive::{DirectoryCall, Failure, Progress, Receiver};
use iec104::ft::{DirectoryEntry, FileTransferProcedure, Frame, Selection, decode_frame};

const CA: u16 = 3;
const IOA: u32 = 500;
const NOF: Nof = Nof { value: 2 };

fn file(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 7 % 256) as u8).collect()
}

/// Delivers frames between the two sessions until neither has anything left
/// to send. `tamper` may change an ASDU on its way to the receiver.
fn pump(
    rx: &mut Receiver,
    tx: &mut Provider,
    to_provider: Vec<Vec<u8>>,
    to_receiver: Vec<Vec<u8>>,
    mut tamper: impl FnMut(&mut Vec<u8>),
) -> (Progress<Vec<u8>>, Progress<()>, Vec<Frame>) {
    let mut seen = Vec::new();
    let mut rx_progress = Progress::Running;
    let mut tx_progress = Progress::Running;
    let mut for_tx = to_provider;
    let mut for_rx = to_receiver;
    while !for_tx.is_empty() || !for_rx.is_empty() {
        for asdu in std::mem::take(&mut for_tx) {
            let step = tx.on_asdu(&asdu, &Known::EVERYTHING).unwrap();
            for_rx.extend(step.send);
            if step.progress != Progress::Running {
                tx_progress = step.progress;
            }
        }
        for mut asdu in std::mem::take(&mut for_rx) {
            seen.push(decode_frame(&asdu).unwrap());
            tamper(&mut asdu);
            let step = rx.on_asdu(&asdu, &Known::EVERYTHING).unwrap();
            for_tx.extend(step.send);
            if step.progress != Progress::Running {
                rx_progress = step.progress;
            }
        }
    }
    (rx_progress, tx_progress, seen)
}

#[test]
fn monitor_direction_the_controlled_station_provides() {
    let content = file(10_000);
    let mut tx = Provider::new(
        FileTransferProcedure::controlled(Selection::MONITOR, CA, 0),
        IOA,
        NOF,
        content.clone(),
    )
    .unwrap();
    let mut rx = Receiver::new(
        FileTransferProcedure::controlling(Selection::MONITOR, CA, 0),
        IOA,
        NOF,
    );
    let select = rx.start().unwrap();
    let (got, sent, seen) = pump(&mut rx, &mut tx, vec![select], Vec::new(), |_| {});
    assert_eq!(got, Progress::Complete(content));
    assert_eq!(sent, Progress::Complete(()));
    // 10 000 octets in sections of DEFAULT_SECTION_LEN: three sections ready.
    let sections = seen
        .iter()
        .filter(|f| matches!(f, Frame::SectionReady { .. }))
        .count();
    assert_eq!(sections, 10_000_usize.div_ceil(DEFAULT_SECTION_LEN));
}

#[test]
fn control_direction_the_controlling_station_announces_and_provides() {
    let content = file(700);
    let mut tx = Provider::new(
        FileTransferProcedure::controlling(Selection::CONTROL, CA, 0),
        IOA,
        NOF,
        content.clone(),
    )
    .unwrap();
    // The controlled station's receiver has sent nothing: the file ready
    // opens the transfer (604 5.4.23.10).
    let mut rx = Receiver::new(
        FileTransferProcedure::controlled(Selection::CONTROL, CA, 0),
        IOA,
        NOF,
    );
    let offer = tx.announce().unwrap();
    let (got, sent, _) = pump(&mut rx, &mut tx, Vec::new(), vec![offer], |_| {});
    assert_eq!(got, Progress::Complete(content));
    assert_eq!(sent, Progress::Complete(()));
}

#[test]
fn a_section_spoiled_on_the_way_is_sent_again() {
    let content = file(300);
    let mut tx = Provider::new(
        FileTransferProcedure::controlled(Selection::MONITOR, CA, 0),
        IOA,
        NOF,
        content.clone(),
    )
    .unwrap();
    let mut rx = Receiver::new(
        FileTransferProcedure::controlling(Selection::MONITOR, CA, 0),
        IOA,
        NOF,
    );
    let select = rx.start().unwrap();
    // Flip the last octet of the first segment once: the section's CHS
    // (7.2.6.37) no longer adds up, AFQ <4> asks for it again (604 5.4.23.1).
    let mut spoiled = false;
    let (got, sent, seen) = pump(&mut rx, &mut tx, vec![select], Vec::new(), |asdu| {
        if !spoiled && asdu[0] == 125 {
            *asdu.last_mut().unwrap() ^= 0xFF;
            spoiled = true;
        }
    });
    assert_eq!(got, Progress::Complete(content));
    assert_eq!(sent, Progress::Complete(()));
    let section_ends = seen
        .iter()
        .filter(|f| {
            matches!(f, Frame::LastSection { lsq, .. } if lsq.value == Lsq::SECTION_WITHOUT_DEACTIVATION)
        })
        .count();
    assert_eq!(section_ends, 2, "the one section, twice");
}

#[test]
fn a_large_file_fits_in_255_sections() {
    let len = 255 * DEFAULT_SECTION_LEN + 1;
    let content = file(len);
    let mut tx = Provider::new(
        FileTransferProcedure::controlled(Selection::MONITOR, CA, 0),
        IOA,
        NOF,
        content.clone(),
    )
    .unwrap();
    let mut rx = Receiver::new(
        FileTransferProcedure::controlling(Selection::MONITOR, CA, 0),
        IOA,
        NOF,
    );
    let select = rx.start().unwrap();
    let (got, _, seen) = pump(&mut rx, &mut tx, vec![select], Vec::new(), |_| {});
    assert_eq!(got, Progress::Complete(content));
    // NOS is one octet (7.2.6.34): no section beyond 255.
    let last = seen
        .iter()
        .filter_map(|f| match f {
            Frame::SectionReady { nos, .. } => Some(nos.value),
            _ => None,
        })
        .max();
    assert_eq!(last, Some(255));
}

#[test]
fn a_file_longer_than_lof_is_refused() {
    let procedure = FileTransferProcedure::controlled(Selection::MONITOR, CA, 0);
    let too_long = vec![0; Lof::MAX as usize + 1];
    assert!(Provider::new(procedure, IOA, NOF, too_long).is_none());
}

fn request(frame: &Frame) -> Vec<u8> {
    FileTransferProcedure::controlling(Selection::MONITOR, CA, 0)
        .build(frame)
        .unwrap()
}

#[test]
fn deactivation_and_a_negative_file_acknowledgement_end_it() {
    let provider = || {
        Provider::new(
            FileTransferProcedure::controlled(Selection::MONITOR, CA, 0),
            IOA,
            NOF,
            file(10),
        )
        .unwrap()
    };
    // SCQ <3>, deactivate file (7.2.6.30).
    let mut tx = provider();
    let scq = Scq {
        action: Scq::DEACTIVATE_FILE,
        error: 0,
    };
    let deactivate = request(&Frame::Sc {
        ioa: IOA,
        nof: NOF,
        nos: Nos { value: 0 },
        scq,
    });
    let step = tx.on_asdu(&deactivate, &Known::EVERYTHING).unwrap();
    assert_eq!(
        step.progress,
        Progress::Failed(Failure::Deactivated { scq })
    );

    // AFQ <2>, negative file acknowledgement (7.2.6.32).
    let mut tx = provider();
    let afq = Afq {
        action: Afq::FILE_NEGATIVE,
        error: 0,
    };
    let reject = request(&Frame::Ack {
        ioa: IOA,
        nof: NOF,
        nos: Nos { value: 1 },
        afq,
    });
    let step = tx.on_asdu(&reject, &Known::EVERYTHING).unwrap();
    assert_eq!(
        step.progress,
        Progress::Failed(Failure::FileRejected { afq })
    );
}

#[test]
fn a_request_for_another_file_is_not_answered() {
    let mut tx = Provider::new(
        FileTransferProcedure::controlled(Selection::MONITOR, CA, 0),
        IOA,
        NOF,
        file(10),
    )
    .unwrap();
    let other = request(&Frame::Sc {
        ioa: IOA,
        nof: Nof { value: 9 },
        nos: Nos { value: 0 },
        scq: Scq {
            action: Scq::SELECT_FILE,
            error: 0,
        },
    });
    let step = tx.on_asdu(&other, &Known::EVERYTHING).unwrap();
    assert_eq!(step.send.len(), 0);
    assert_eq!(step.progress, Progress::Running);
}

#[test]
fn a_directory_is_split_and_closed_with_lfd() {
    let controlled = FileTransferProcedure::controlled(Selection::MONITOR, CA, 0);
    let entries: Vec<DirectoryEntry> = (1..=40u16)
        .map(|n| DirectoryEntry {
            nof: Nof { value: n },
            lof: Lof { value: 1 },
            sof: Sof::default(),
            time: Cp56Time2a::default(),
        })
        .collect();
    // 18 files fit in one ASDU with the conventional sizes (index 26):
    // 18 + 18 + 4, each numbered from its own base address (figure 89).
    let frames = directory(&controlled, IOA, &entries);
    let shape: Vec<(u32, usize)> = frames
        .iter()
        .map(|f| match f {
            Frame::Directory { ioa, files, .. } => (*ioa, files.len()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(shape, [(IOA, 18), (IOA + 18, 18), (IOA + 36, 4)]);

    let mut call = DirectoryCall::new(FileTransferProcedure::controlling(
        Selection::MONITOR,
        CA,
        0,
    ));
    call.start(IOA).unwrap();
    let mut listed = None;
    for frame in &frames {
        let step = call
            .on_asdu(&controlled.build(frame).unwrap(), &Known::EVERYTHING)
            .unwrap();
        if let Progress::Complete(files) = step.progress {
            listed = Some(files);
        }
    }
    let listed = listed.expect("LFD on the 40th file ends the directory");
    assert_eq!(listed.len(), 40);
    assert!(
        listed
            .iter()
            .enumerate()
            .all(|(i, f)| f.ioa == IOA + i as u32 && f.entry.nof.value == i as u16 + 1)
    );
    assert_eq!(
        listed
            .iter()
            .filter(|f| f.entry.sof.last_file_of_directory)
            .count(),
        1
    );

    // Figure 89 carries at least one file: an empty directory has no frame.
    assert!(directory(&controlled, IOA, &[]).is_empty(), "no F_DR_TA_1");
}
