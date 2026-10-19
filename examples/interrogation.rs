//! A controlling station (master) over blocking TCP that reads an RTU's whole
//! process image once: it connects (retrying every t0), starts data transfer,
//! sends a station interrogation (`C_IC_NA_1`, QOI 20) and prints every object
//! of the answer, decoded. It exits at the termination (`ACTTERM`), or with an
//! error if the RTU refuses.
//!
//! ```text
//! cargo run --example interrogation -- 192.0.2.10:2404 [common-address] [seconds]
//! ```
//!
//! The common address is the RTU's (default 1); `seconds` bounds the whole run.
//! A connection lost before the termination voids the interrogation, which is
//! sent again on the next connection. Against the `outstation` example the
//! answer is three scaled measured values. Set `IEC104_SIZES=1,2,0` (common
//! address, object address, originator) for a non-default profile.

mod common;
mod decode;

use common::{Link, STATION};
use iec104::asdu::Known;
use iec104::gi::{Interrogation, Reaction, Scope, SecondActivation};
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, Directive, StationConfig};
use iec104::params::LinkParams;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2404".into());
    let ca = match args.next() {
        Some(ca) => ca
            .parse::<u16>()
            .map_err(|e| format!("common address: {e}"))?,
        None => 1,
    };
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
    let mut gi =
        Interrogation::controlling(SecondActivation::Locked, ca, 0).with_address_sizes(sizes);
    let mut gi_sent = false;
    let mut objects = 0_usize;

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
            // An interrogation cut off by a lost connection is void; the
            // next connection starts it again.
            gi.reset();
            gi_sent = false;
            objects = 0;
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }

        for asdu in link.receive(&mut manager, now) {
            match gi.on_response(&asdu, &Known::EVERYTHING) {
                Ok(outcome) => match outcome.reaction {
                    Reaction::ActivationConfirmed {
                        negative: false, ..
                    } => println!("   interrogation confirmed"),
                    Reaction::ActivationConfirmed { negative: true, .. } => {
                        link.close(&mut manager);
                        return Err("the RTU refused the interrogation (negative ACTCON)".into());
                    }
                    Reaction::Interrogated { .. } => {
                        objects = objects.saturating_add(decode::print_objects(&asdu, sizes));
                    }
                    Reaction::Terminated { .. } => {
                        println!("interrogation complete: {objects} objects");
                        link.close(&mut manager);
                        return Ok(());
                    }
                    Reaction::Refused { cause, .. } => {
                        link.close(&mut manager);
                        return Err(format!("the RTU refused the interrogation: {cause:?}"));
                    }
                    Reaction::Discard(why) => println!("   discarded: {why:?}"),
                    // Spontaneous data and the rest: the frame log shows them.
                    _ => {}
                },
                Err(e) => println!("   not understood: {e:?}"),
            }
        }

        // Once STARTDT is confirmed, interrogate the whole station.
        let started = manager
            .station(STATION)
            .is_ok_and(|s| s.state() == State::Started);
        if started && !gi_sent {
            match gi.request(Scope::Station) {
                Ok(asdu) => link.send_asdu(&mut manager, &asdu, now),
                Err(e) => {
                    link.close(&mut manager);
                    return Err(format!("cannot interrogate: {e:?}"));
                }
            }
            gi_sent = true;
        }
    }
    link.close(&mut manager);
    Err("no termination before the deadline".into())
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
