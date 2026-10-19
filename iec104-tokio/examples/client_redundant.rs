//! The procedure-level client over a redundancy group of two connections
//! (104 clause 10): one station, two connections, one of them started.
//!
//! Dials both addresses, interrogates the station on the started connection,
//! then closes that connection to show the switchover: the client starts the
//! other one, runs its station interrogation there (TS 60870-5-604 5.4.13.10)
//! and dials the closed one again. Prints every update until `seconds` have
//! passed.
//!
//! ```text
//! cargo run -p iec104-tokio --example client_redundant -- \
//!     127.0.0.1:2404 127.0.0.1:2404 [seconds]
//! ```
//!
//! Pair it with `async_outstation` and a group of two:
//! `cargo run -p iec104-tokio --example async_outstation -- 127.0.0.1:2404 2`.
//! Both connections may go to the same address (one outstation accepting
//! two), or to two addresses of one station. `seconds` (default 15) is how
//! long to listen after the switchover. Set `IEC104_SIZES=1,2,0` (common
//! address, object address, originator) for a non-default profile.

mod common;

use std::time::Duration;

use iec104::gi::Scope;
use iec104::link::State;
use iec104_tokio::TcpConnector;
use iec104_tokio::client::{Client, ClientConfig, Update};

/// The connections in the group.
const MEMBERS: usize = 2;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: client_redundant <address> <address> [seconds]";
    let (Some(first), Some(second)) = (args.next(), args.next()) else {
        return Err(usage.into());
    };
    let listen_for = match args.next() {
        Some(secs) => Duration::from_secs(secs.parse().map_err(|e| format!("seconds: {e}"))?),
        None => Duration::from_secs(15),
    };

    // `interrogate_on_start` stays on: the client interrogates the station on
    // every newly started connection, the one after the switchover included.
    // The call below joins the first of those rather than sending a second
    // activation (5-101 cl.7.4.5 locks the identical interrogation).
    let config = ClientConfig {
        sizes: common::address_sizes()?,
        ..ClientConfig::new(1)
    };
    // Member `i` dials `addresses[i]`.
    let connector = TcpConnector::new(vec![first.clone(), second.clone()]);
    println!("connecting to {first} and {second} as one redundancy group");
    let client = tokio::time::timeout(
        Duration::from_secs(60),
        Client::connect_redundant(connector, MEMBERS, config),
    )
    .await
    .map_err(|_| "not started within a minute")?
    .map_err(|e| e.to_string())?;
    let mut updates = client.subscribe().await.map_err(|e| e.to_string())?;

    let started = started_member(&client).await?;
    println!("connection {started} is started");
    let image = client
        .interrogate(Scope::Station)
        .await
        .map_err(|e| e.to_string())?;
    println!("station interrogation: {} ASDUs", image.len());
    for asdu in &image {
        println!("   {:?}", asdu.objects);
    }

    // The application's connection change (104 figure 37): closing the
    // started connection leaves the group with none, and the client starts
    // the other member at once.
    println!("closing connection {started} to switch over");
    client
        .handle()
        .close(started)
        .await
        .map_err(|e| e.to_string())?;

    println!("listening for {} seconds", listen_for.as_secs());
    let listen = async {
        while let Some(update) = updates.recv().await {
            match update {
                Update::Data(asdu) => println!(
                    "   {} {}: {:?}",
                    asdu.header.cause.mnemonic(),
                    asdu.header.type_id.name(),
                    asdu.objects
                ),
                Update::Started => match started_member(&client).await {
                    Ok(conn) => println!("   started: connection {conn}"),
                    Err(e) => println!("   started: {e}"),
                },
                other => println!("   {other:?}"),
            }
        }
    };
    let _ = tokio::time::timeout(listen_for, listen).await;
    client.shutdown().await;
    Ok(())
}

/// The member the group has started, if one is.
async fn started_member(client: &Client) -> Result<usize, String> {
    for conn in 0..MEMBERS {
        let state = client
            .handle()
            .state(conn)
            .await
            .map_err(|e| e.to_string())?;
        if state == State::Started {
            return Ok(conn);
        }
    }
    Err("no connection is started".into())
}
