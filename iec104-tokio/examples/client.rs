//! The procedure-level client: interrogate a station, synchronise its clock,
//! optionally send one command, then print what the station sends for ten
//! seconds.
//!
//! ```text
//! cargo run -p iec104-tokio --example client -- 127.0.0.1:2404 [ioa on|off]
//! ```
//!
//! Pair it with the core crate's `outstation` example, which answers
//! interrogations and direct commands. That example does not serve clock
//! synchronisation and mirrors it back with cause 44, so expect the clock
//! synchronisation to be reported as refused there. The `server` example
//! answers it, and takes commands at address 4001. Set `IEC104_SIZES=1,2,0`
//! (common address, object address, originator) for a non-default profile.

mod common;

use std::time::{Duration, SystemTime};

use iec104::asdu::{CommandQualifier, Cp56Time2a};
use iec104::ct::Command;
use iec104::gi::Scope;
use iec104_tokio::TcpConnector;
use iec104_tokio::client::{Client, ClientConfig, Update};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2404".into());
    let command = match (args.next(), args.next().as_deref()) {
        (Some(ioa), Some(state @ ("on" | "off"))) => {
            let ioa = ioa.parse::<u32>().map_err(|e| format!("ioa: {e}"))?;
            Some(Command::single(ioa, state == "on").with_qualifier(CommandQualifier::ShortPulse))
        }
        (None, _) => None,
        _ => return Err("usage: client <address> [ioa on|off]".into()),
    };

    let config = ClientConfig {
        sizes: common::address_sizes()?,
        // This example interrogates on its own below.
        interrogate_on_start: false,
        ..ClientConfig::new(1)
    };
    let connector = TcpConnector::new(vec![address.clone()]);
    println!("connecting to {address}");
    let client = tokio::time::timeout(Duration::from_secs(60), Client::connect(connector, config))
        .await
        .map_err(|_| "not started within a minute")?
        .map_err(|e| e.to_string())?;
    let mut updates = client.subscribe().await.map_err(|e| e.to_string())?;

    let image = client
        .interrogate(Scope::Station)
        .await
        .map_err(|e| e.to_string())?;
    println!("station interrogation: {} ASDUs", image.len());
    for asdu in &image {
        println!("   {:?}", asdu.objects);
    }

    // The time tag is UTC. Set `summer_time` here if the station keeps local
    // summer time.
    let now = Cp56Time2a::from_system_time(SystemTime::now()).map_err(|e| e.to_string())?;
    match client.sync_clock(now).await {
        Ok(()) => println!("clock synchronised to {now:?}"),
        Err(e) => println!("clock synchronisation failed: {e}"),
    }

    if let Some(command) = command {
        match client.command(command).await {
            Ok(outcome) => println!("command {outcome:?}"),
            Err(e) => println!("command failed: {e}"),
        }
    }

    println!("listening for ten seconds");
    let listen = async {
        while let Some(update) = updates.recv().await {
            match update {
                Update::Data(asdu) => println!(
                    "   {} {}: {:?}",
                    asdu.header.cause.mnemonic(),
                    asdu.header.type_id.name(),
                    asdu.objects
                ),
                other => println!("   {other:?}"),
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_secs(10), listen).await;
    client.shutdown().await;
    Ok(())
}
