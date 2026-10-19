//! What the async examples share: the address profile from `IEC104_SIZES`,
//! and one log line per frame.

use iec104::asdu::AddressSizes;
use iec104::diag;
use iec104_tokio::Event;

/// The address sizes from `IEC104_SIZES=ca,ioa,originator` (for example
/// `1,2,0`: one-octet common address, two-octet object address, no
/// originator), or the conventional 2,3,1 when it is not set.
pub fn address_sizes() -> Result<AddressSizes, String> {
    let Ok(spec) = std::env::var("IEC104_SIZES") else {
        return Ok(AddressSizes::CONVENTIONAL);
    };
    let fields: Vec<u8> = spec
        .split(',')
        .map(|f| f.trim().parse::<u8>())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("IEC104_SIZES: {e}"))?;
    let [ca, ioa, originator] = fields[..] else {
        return Err("IEC104_SIZES wants three fields: ca,ioa,originator".into());
    };
    AddressSizes::new(ca, ioa, originator != 0).map_err(|e| format!("IEC104_SIZES: {e:?}"))
}

/// Prints the connection events and every traced frame (`diag::apdu`).
// The client example sees no driver events; the others share this module
// with it.
#[allow(dead_code)]
pub fn log(event: &Event, sizes: AddressSizes) {
    let frame = |direction: &str, frame: &[u8]| match diag::apdu(frame, sizes) {
        Ok(line) => println!("{direction} {line}"),
        Err(e) => println!("{direction} {frame:02X?} ({e})"),
    };
    match event {
        Event::Sent { frame: f, .. } => frame("->", f),
        Event::Received { frame: f, .. } => frame("<-", f),
        Event::Connecting { conn } => println!("connecting ({conn})"),
        Event::ConnectFailed { error, .. } => println!("connect failed: {error}"),
        Event::Connected { conn } => println!("connected ({conn})"),
        Event::Disconnected { reason, .. } => println!("connection closed: {reason}"),
        Event::Switchover(switchover) => println!("switchover: {switchover:?}"),
        Event::FrameRefused { conn, error } => println!("refused a frame on {conn}: {error}"),
        Event::StartedConnectionFailed { conn, unconfirmed } => {
            println!("started connection {conn} failed ({unconfirmed} unconfirmed)");
        }
        _ => {}
    }
}
