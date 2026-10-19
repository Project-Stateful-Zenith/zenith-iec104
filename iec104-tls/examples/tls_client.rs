//! The procedure-level client over mutual TLS: the TLS twin of
//! `iec104-tokio`'s `client` example.
//!
//! Dials with [`iec104_tls::tokio::TlsConnector`] (redialing every t0 until
//! the handshake and STARTDT succeed), runs a station interrogation, then
//! prints what the station sends.
//!
//! ```text
//! cargo run -p iec104-tls --example tls_client -- \
//!     127.0.0.1:19998 master.crt master.key ca.crt [seconds]
//! ```
//!
//! Pair it with `tls_outstation`; `scripts/tls-test-pki.sh` makes a
//! throwaway CA and the two certificates (see the README's TLS section). The
//! server's certificate must name the host dialed (here `127.0.0.1`) unless
//! `IEC104_TLS_NO_NAME_CHECK=1`. `IEC104_TLS_CRL` and `IEC104_TLS_PEER` add a
//! CRL and an allow-listed peer certificate. `seconds` (default 10) is how
//! long to listen after the interrogation. Set `IEC104_SIZES=1,2,0` (common
//! address, object address, originator) for a non-default profile.

// The blocking glue in there is for the other TLS examples; this one only
// needs the configuration and the address profile.
#[allow(dead_code)]
mod tls_common;

use std::time::Duration;

use iec104::gi::Scope;
use iec104_tls::tokio::TlsConnector;
use iec104_tokio::client::{Client, ClientConfig, Update};
use tls_common::common;

/// The outstation's common address.
const CA: u16 = 1;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:19998".into());
    let tls = tls_common::config(&mut args)?;
    let listen_for = match args.next() {
        Some(secs) => Duration::from_secs(secs.parse().map_err(|e| format!("seconds: {e}"))?),
        None => Duration::from_secs(10),
    };

    let config = ClientConfig {
        sizes: common::address_sizes()?,
        // This example interrogates on its own below.
        interrogate_on_start: false,
        ..ClientConfig::new(CA)
    };
    // Connection 0 dials the one address. A refused handshake is redialed at
    // t0 like a refused TCP connection; `connect` waits through it.
    let connector = TlsConnector::new(tls, vec![address.clone()]);
    println!("connecting to {address} over TLS");
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
                other => println!("   {other:?}"),
            }
        }
    };
    let _ = tokio::time::timeout(listen_for, listen).await;
    client.shutdown().await;
    Ok(())
}
