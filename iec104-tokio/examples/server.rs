//! A controlled station on the procedure-level server.
//!
//! The same station as `async_outstation.rs`, without the procedure code:
//! three scaled measured values at 100 to 102 (group 1) and a switch at 4001
//! (a single point that takes single commands, so the `client` example can
//! operate it). The server answers interrogations, reads, counter
//! interrogations, clock synchronisations and test commands from its image;
//! this program only writes the values, reports a change of point 100 every
//! five seconds, and operates the switch.
//!
//! ```text
//! cargo run -p iec104-tokio --example server -- 0.0.0.0:2404 [connections]
//! ```
//!
//! `connections` (default 1) is the size of the redundancy group (104 clause
//! 10). Set `IEC104_SIZES=1,2,0` (common address, object address,
//! originator) for a non-default profile.

mod common;

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use iec104::asdu::{Cause, Quality, Value};
use iec104::ct::{Command, CommandValue, Family};
use iec104_tokio::server::{Application, PointConfig, Server, ServerConfig};
use tokio::net::TcpListener;

/// This station's common address.
const CA: u16 = 1;

/// The switch: a command to 4001 moves it, and its new position is
/// reported as return information (5-101 cl.7.4.7, cause 11).
struct Switch {
    server: Arc<OnceLock<Server>>,
}

impl Application for Switch {
    fn accept(&self, command: &Command) -> bool {
        println!("command {command:?}");
        true
    }

    async fn operate(&self, command: Command) -> bool {
        let CommandValue::Single { sco } = command.value else {
            return false;
        };
        // The switch takes a moment to move.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let Some(server) = self.server.get() else {
            return false;
        };
        server
            .report_with(
                4001,
                Value::Single(sco.scs),
                Quality::default(),
                None,
                Cause::ReturnInfoRemote,
            )
            .await
            .is_ok()
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2404".into());
    let members = args
        .next()
        .map(|n| n.parse::<usize>().map_err(|e| e.to_string()))
        .transpose()?
        .unwrap_or(1);

    let mut config = ServerConfig::new(CA)
        .point(4001, PointConfig::new(Value::Single(false)))
        .command(4001, Family::Single);
    for (ioa, value) in [(100, 1000), (101, 2000), (102, 3000)] {
        config = config.point(
            ioa,
            PointConfig::new(Value::Scaled(value)).untagged().group(1),
        );
    }
    config.sizes = common::address_sizes()?;
    config.members = members;

    let cell = Arc::new(OnceLock::new());
    let server = Server::spawn(
        config,
        Switch {
            server: Arc::clone(&cell),
        },
    )
    .map_err(|e| e.to_string())?;
    let _ = cell.set(server.clone());

    let listener = TcpListener::bind(&address)
        .await
        .map_err(|e| e.to_string())?;
    println!("listening on {address} ({members} connection(s))");
    tokio::spawn(server.clone().serve(listener));

    // A spontaneous change every five seconds (104 cl.7.4). Before a master
    // starts data transfer the server keeps it (104 cl.5.3).
    let mut value: i16 = 1000;
    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;
        value = value.wrapping_add(1);
        server
            .report(100, Value::Scaled(value), Quality::default(), None)
            .await
            .map_err(|e| e.to_string())?;
    }
}
