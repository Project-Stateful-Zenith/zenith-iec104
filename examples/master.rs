//! A minimal controlling station (master) over blocking TCP.
//!
//! Connects (retrying every t0), starts data transfer, runs one station
//! interrogation, then logs whatever the outstation sends. Reconnects on loss.
//!
//! The crate does no I/O itself. The loop below has three jobs, in this order:
//! run the manager's clock (`tick`), feed it what arrived on the socket
//! (`Link::receive`), and hand it the ASDUs the application wants to send
//! (`Link::send_asdu`). Everything the manager answers is a list of actions
//! for `Link::perform` to put on the wire. The socket side lives in
//! `common/mod.rs`.
//!
//! ```text
//! cargo run --example master -- 127.0.0.1:2404 [seconds]
//! ```
//!
//! Pair it with `cargo run --example outstation`. Set `IEC104_SIZES=1,2,0`
//! (common address, object address, originator) for a non-default profile.

mod common;

use common::{Link, STATION};
use iec104::asdu::Known;
use iec104::gi::{Interrogation, Reaction, Scope, SecondActivation};
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, Directive, StationConfig};
use iec104::params::LinkParams;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// The outstation's common address.
const CA: u16 = 1;

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2404".into());
    let run_for = args
        .next()
        .map(|s| s.parse::<u64>().map(Duration::from_secs));
    let run_for = run_for.transpose().map_err(|e| e.to_string())?;
    let start = Instant::now();

    // Both ends must agree on the address sizes; they are not negotiated.
    let sizes = common::address_sizes()?;
    // The defaults of the clause 9 interoperability list: t0 to t3, k and w.
    let params = LinkParams::default();
    // The manager owns the protocol state of each configured connection. A
    // controlling manager is the one that dials (clause 7.1), so its `tick`
    // asks for a connection whenever none is up.
    let mut manager = ConnectionManager::new(Role::Controlling, vec![StationConfig::new(params)])
        .map_err(|e| format!("{e:?}"))?;
    let mut link = Link::new(sizes);
    // The general interrogation procedure, kept apart from the link: it builds
    // the request and follows the confirmation, the data and the termination.
    // `Locked` refuses a second identical interrogation while one is running
    // (5-101 clause 7.4.5).
    let mut gi =
        Interrogation::controlling(SecondActivation::Locked, CA, 0).with_address_sizes(sizes);
    let mut gi_sent = false;

    while run_for.is_none_or(|d| start.elapsed() < d) {
        let now = Instant::now();

        // The clock: `tick` reports the timers (t0 to t3) that expired, as
        // actions to perform, and asks for a connection when none is up. A
        // fresh connection is stopped (clause 5.3): nothing but U-frames flows
        // until the controlling station sends STARTDT act, so ask for it at once.
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
                        // t0 stays armed, so the manager asks again when it expires.
                        Err(e) => println!("connect failed: {e}"),
                    }
                }
                actions @ Directive::Actions { .. } => link.perform(&mut manager, vec![actions]),
            }
        }

        if !link.is_up() {
            // Everything tied to the old connection is void (604 5.4.13.10:
            // a fresh interrogation follows every reconnect). Sleep briefly so
            // the loop does not spin while it waits for the next dial.
            gi.reset();
            gi_sent = false;
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }

        // Every ASDU the session accepted goes to the interrogation procedure,
        // which recognises its confirmation, its data (`Interrogated`) and its
        // termination. Anything else, such as a spontaneous change, is
        // `Reaction::Other`. `Link` has already logged every frame, so only the
        // procedure's milestones are printed here. `Known::EVERYTHING` says this
        // station knows every type, cause and address; a real one answers those
        // from its configuration, and clause 7.2.3 then discards what it does
        // not know.
        for asdu in link.receive(&mut manager, now) {
            match gi.on_response(&asdu, &Known::EVERYTHING) {
                Ok(outcome) => match outcome.reaction {
                    Reaction::ActivationConfirmed { negative, .. } => {
                        println!("   interrogation confirmed (negative: {negative})");
                    }
                    Reaction::Terminated { .. } => println!("   interrogation complete"),
                    Reaction::Refused { cause, .. } => {
                        println!("   interrogation refused: {cause:?}");
                    }
                    _ => {}
                },
                Err(e) => println!("   not understood: {e:?}"),
            }
        }

        // Once STARTDT is confirmed, interrogate the whole station once. The
        // interrogation is how a master learns the current state of every
        // point before it relies on spontaneous changes.
        let started = manager
            .station(STATION)
            .is_ok_and(|s| s.state() == State::Started);
        if started && !gi_sent {
            match gi.request(Scope::Station) {
                Ok(asdu) => link.send_asdu(&mut manager, &asdu, now),
                Err(e) => println!("cannot interrogate: {e:?}"),
            }
            gi_sent = true;
        }
    }
    link.close(&mut manager);
    Ok(())
}

/// Dials `address`, trying each resolved address in turn, each for at most
/// `timeout`.
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
