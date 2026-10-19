//! A minimal controlling station (master) over blocking TLS: the TLS twin of
//! the core crate's `examples/master.rs`.
//!
//! Connects with mutual TLS (retrying every t0), starts data transfer, runs
//! one station interrogation, then logs whatever the outstation sends.
//! Reconnects on loss.
//!
//! ```text
//! cargo run -p iec104-tls --example tls_master -- \
//!     127.0.0.1:19998 master.crt master.key ca.crt [seconds]
//! ```
//!
//! Pair it with `tls_outstation`; `scripts/tls-test-pki.sh` makes a
//! throwaway CA and the two certificates (see the README's TLS section). The server's
//! certificate must name the host dialed (here `127.0.0.1`) unless
//! `IEC104_TLS_NO_NAME_CHECK=1`. `IEC104_TLS_CRL` and `IEC104_TLS_PEER` add a
//! CRL and an allow-listed peer certificate. Set `IEC104_SIZES=1,2,0`
//! (common address, object address, originator) for a non-default profile.

mod tls_common;

use iec104::asdu::Known;
use iec104::gi::{Interrogation, Reaction, Scope, SecondActivation};
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, Directive, StationConfig};
use iec104::params::LinkParams;
use std::time::{Duration, Instant};
use tls_common::common::{self, Link, STATION};

/// The outstation's common address.
const CA: u16 = 1;

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:19998".into());
    let tls = tls_common::config(&mut args)?;
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
        Interrogation::controlling(SecondActivation::Locked, CA, 0).with_address_sizes(sizes);
    let mut gi_sent = false;

    while run_for.is_none_or(|d| start.elapsed() < d) {
        let now = Instant::now();

        // The clock: t0–t3, and the manager's request for a connection.
        for directive in manager.tick(now) {
            match directive {
                Directive::Connect { attempt, .. } => {
                    println!("connecting to {address} (attempt {attempt})");
                    match iec104_tls::connect(&address, &tls) {
                        Ok(stream) => {
                            println!("{}", tls_common::describe(&stream));
                            link.attach(stream, &mut manager, now)?;
                            let start = manager.request_start(STATION, now);
                            link.perform(&mut manager, start.unwrap_or_default());
                        }
                        // t0 stays armed, so the manager asks again when it
                        // expires. A refused handshake is a security event:
                        // report it with the TLS error.
                        Err(e) => match iec104_tls::tls_error(&e) {
                            Some(tls) => println!("TLS handshake refused: {tls}"),
                            None => println!("connect failed: {e}"),
                        },
                    }
                }
                actions @ Directive::Actions { .. } => link.perform(&mut manager, vec![actions]),
            }
        }

        if !link.is_up() {
            // Everything tied to the old connection is void (604 5.4.13.10:
            // a fresh interrogation follows every reconnect).
            gi.reset();
            gi_sent = false;
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }

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

        // Once STARTDT is confirmed, interrogate the whole station once.
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
