//! A controlling station (master) over blocking TCP that only listens: it
//! connects to an RTU (retrying every t0), starts data transfer, and prints
//! every spontaneous ASDU (cause `<3>`) it receives, decoded object by object.
//! Reconnects on loss.
//!
//! ```text
//! cargo run --example spontaneous -- 192.0.2.10:2404 [seconds]
//! ```
//!
//! It sends no interrogation, so it sees only changes, not the RTU's full
//! process image; `master` shows the interrogation. Against the `outstation`
//! example, one spontaneous measured value arrives every five seconds. Set
//! `IEC104_SIZES=1,2,0` (common address, object address, originator) for a
//! non-default profile.

// A master that only listens never sends an ASDU of its own, so the shared
// glue's `send_asdu` is unused here.
#[allow(dead_code)]
mod common;
mod decode;

use common::{Link, STATION};
use iec104::asdu::Known;
use iec104::link::Role;
use iec104::manager::{ConnectionManager, Directive, StationConfig};
use iec104::params::LinkParams;
use iec104::tx::{Reaction, Transmission};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2404".into());
    let run_for = args
        .next()
        .map(|s| s.parse::<u64>().map(Duration::from_secs));
    let run_for = run_for.transpose().map_err(|e| e.to_string())?;
    let start = Instant::now();

    let sizes = common::address_sizes()?;
    let params = LinkParams::default();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![StationConfig::new(params)])
        .map_err(|e| format!("{e:?}"))?;
    let mut link = Link::new(sizes);
    // The controlling side only classifies what arrives, so its addressing
    // is never used.
    let tx = Transmission::controlling(0, 0).with_address_sizes(sizes);

    while run_for.is_none_or(|d| start.elapsed() < d) {
        let now = Instant::now();

        // The clock: t0–t3, and the manager's request for a connection.
        for directive in manager.tick(now) {
            match directive {
                Directive::Connect { attempt, .. } => {
                    println!("connecting to {address} (attempt {attempt})");
                    match connect(&address, params.t0) {
                        Ok(stream) => {
                            link.attach(stream, &mut manager, now)?;
                            let start = manager.request_start(STATION, now);
                            link.perform(&mut manager, start.unwrap_or_default());
                        }
                        // t0 stays armed, so the manager asks again when it
                        // expires.
                        Err(e) => println!("connect failed: {e}"),
                    }
                }
                actions @ Directive::Actions { .. } => link.perform(&mut manager, vec![actions]),
            }
        }

        if !link.is_up() {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }

        for asdu in link.receive(&mut manager, now) {
            match tx.on_response(&asdu, &Known::EVERYTHING) {
                Ok(outcome) => match outcome.reaction {
                    Reaction::Spontaneous { .. } => {
                        decode::print_objects(&asdu, sizes);
                    }
                    Reaction::Discard(why) => println!("   discarded: {why:?}"),
                    // Cyclic, background scan, end of initialisation and the
                    // rest: the frame log above already shows them.
                    _ => {}
                },
                Err(e) => println!("   not understood: {e:?}"),
            }
        }
    }
    link.close(&mut manager);
    Ok(())
}

/// Connects to the first address `address` resolves to that answers within
/// `timeout` (t0).
fn connect(address: &str, timeout: Duration) -> std::io::Result<TcpStream> {
    let mut last = std::io::Error::other("no address");
    for resolved in address.to_socket_addrs()? {
        match TcpStream::connect_timeout(&resolved, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = e,
        }
    }
    Err(last)
}
