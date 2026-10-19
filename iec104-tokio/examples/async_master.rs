//! A minimal controlling station (master) on the Tokio driver.
//!
//! The async twin of `examples/master.rs`: connects (retrying every t0),
//! starts data transfer, runs one station interrogation per connection, then
//! logs whatever the outstation sends. Reconnects on loss.
//!
//! ```text
//! cargo run -p iec104-tokio --example async_master -- 127.0.0.1:2404 [seconds]
//! ```
//!
//! Pair it with either outstation example. Set `IEC104_SIZES=1,2,0` (common
//! address, object address, originator) for a non-default profile.

mod common;

use std::time::Duration;

use iec104::asdu::Known;
use iec104::gi::{Interrogation, Reaction, Scope, SecondActivation};
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104_tokio::{Event, Options, TcpConnector, master};

/// The outstation's common address.
const CA: u16 = 1;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2404".into());
    let run_for = match args.next() {
        Some(secs) => Some(Duration::from_secs(
            secs.parse::<u64>().map_err(|e| e.to_string())?,
        )),
        None => None,
    };

    let sizes = common::address_sizes()?;
    let manager = ConnectionManager::new(
        Role::Controlling,
        vec![StationConfig::new(LinkParams::default())],
    )
    .map_err(|e| format!("{e:?}"))?;
    let options = Options {
        trace: true,
        ..Options::default()
    };
    let (handle, mut events) = master::spawn(manager, TcpConnector::new(vec![address]), options)
        .map_err(|e| e.to_string())?;
    let mut gi =
        Interrogation::controlling(SecondActivation::Locked, CA, 0).with_address_sizes(sizes);

    let deadline = async {
        match run_for {
            Some(d) => tokio::time::sleep(d).await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(deadline);
    loop {
        let event = tokio::select! {
            event = events.recv() => match event {
                Some(event) => event,
                None => return Ok(()),
            },
            () = &mut deadline => break,
        };
        common::log(&event, sizes);
        match event {
            // Once STARTDT is confirmed, interrogate the whole station.
            // Everything tied to an old connection is void (604 5.4.13.10:
            // a fresh interrogation follows every reconnect).
            Event::State {
                conn,
                state: State::Started,
            } => {
                gi.reset();
                match gi.request(Scope::Station) {
                    Ok(asdu) => {
                        if let Err(e) = handle.send_asdu(conn, asdu).await {
                            println!("cannot interrogate: {e}");
                        }
                    }
                    Err(e) => println!("cannot interrogate: {e:?}"),
                }
            }
            Event::Asdu { asdu, .. } => match gi.on_response(&asdu, &Known::EVERYTHING) {
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
            },
            _ => {}
        }
    }
    handle.shutdown().await;
    Ok(())
}
