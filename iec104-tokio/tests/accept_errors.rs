//! The plain TCP accept loops against an accept error. Out of file
//! descriptors, `accept` fails while the connection waits in the listen
//! backlog; the loop must wait and accept again, not return, or any peer that
//! can use up the station's descriptors stops it taking masters for good.
//!
//! Descriptor exhaustion is process-wide, so this file is its own test binary
//! with one test that runs the cases one after another. Linux only: it lowers
//! its own soft limit with `prlimit` (util-linux).
#![cfg(target_os = "linux")]
// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

mod common;

use std::fs::File;
use std::time::Duration;

use common::{STARTDT_ACT, STARTDT_CON};
use iec104::link::Role;
use iec104::params::LinkParams;
use iec104::redundancy::RedundancyGroup;
use iec104_tokio::{Handle, Options, outstation};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// The soft limit the test lowers itself to, so that using up every
/// descriptor takes a moment and little memory.
const SOFT_LIMIT: u32 = 1024;

fn driver() -> Handle {
    let group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 1).unwrap();
    outstation::spawn(group, Options::default()).unwrap().0
}

fn lower_soft_limit() {
    let status = std::process::Command::new("prlimit")
        .arg("--pid")
        .arg(std::process::id().to_string())
        .arg(format!("--nofile={SOFT_LIMIT}:"))
        .status()
        .expect("prlimit (util-linux) runs");
    assert!(status.success(), "prlimit lowers the soft limit");
}

/// Opens descriptors until the process has none left, then gives one back.
fn use_up_descriptors() -> Vec<File> {
    let mut held = Vec::new();
    while let Ok(file) = File::open("/dev/null") {
        held.push(file);
        assert!(held.len() <= SOFT_LIMIT as usize, "the limit holds");
    }
    held.pop();
    held
}

/// Connects a master while the station has no descriptor left: the
/// connection is complete in the backlog, and the station's `accept` fails
/// with EMFILE. The loop must still be running a while later, and must
/// accept and answer the master once descriptors are free again.
async fn survives_exhaustion(
    listener: TcpListener,
    served: impl FnOnce(TcpListener) -> JoinHandle<std::io::Result<()>>,
) {
    let address = listener.local_addr().unwrap();
    let served = served(listener);
    let held = use_up_descriptors();
    // Takes the last descriptor.
    let mut master = TcpStream::connect(address).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !served.is_finished(),
        "the accept loop returned: {:?}",
        served.await.unwrap()
    );

    drop(held);
    master.write_all(&STARTDT_ACT).await.unwrap();
    let mut answer = [0u8; 6];
    tokio::time::timeout(Duration::from_secs(5), master.read_exact(&mut answer))
        .await
        .expect("answered in time once descriptors are free")
        .unwrap();
    // 104 cl.5.3: STARTDT con is 68 04 0B 00 00 00.
    assert_eq!(answer, STARTDT_CON);
    served.abort();
}

#[tokio::test]
async fn accept_loops_survive_descriptor_exhaustion() {
    lower_soft_limit();

    let handle = driver();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    survives_exhaustion(listener, |listener| {
        tokio::spawn(outstation::serve(listener, handle.clone()))
    })
    .await;
    handle.shutdown().await;

    let handle = driver();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let routed = handle.clone();
    survives_exhaustion(listener, move |listener| {
        tokio::spawn(outstation::serve_routed(listener, move |_peer| {
            Some(routed.clone())
        }))
    })
    .await;
    handle.shutdown().await;
}
