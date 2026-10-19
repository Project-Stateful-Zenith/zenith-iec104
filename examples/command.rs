//! A controlling station (master) over blocking TCP that sends one command and
//! waits for its end: it connects (retrying every t0), starts data transfer,
//! sends the command as a direct execute and exits at the termination
//! (`ACTTERM`), or with an error if the RTU refuses it.
//!
//! ```text
//! cargo run --example command -- 192.0.2.10:2404 <ioa> <on|off|number> [common-address]
//! ```
//!
//! `on` and `off` send a single command (`C_SC_NA_1`) with a short pulse; a
//! number sends a set-point with a short floating point value (`C_SE_NC_1`).
//! The common address is the RTU's (default 1). The `outstation` example
//! accepts both. Only the mirror of the command sent ends the run; every other
//! ASDU is printed decoded. Set `IEC104_SIZES=1,2,0` (common address, object
//! address, originator) for a non-default profile.

mod common;

use common::{Link, STATION};
use iec104::asdu::{self, CommandQualifier, Known};
use iec104::ct::{
    self, Command, CommandMode, CommandSet, CommandTransmission, Reaction, Termination,
};
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, Directive, StationConfig};
use iec104::params::LinkParams;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

fn main() -> Result<(), String> {
    let (address, command, ca) = parse_args()?;
    let start = Instant::now();

    let sizes = common::address_sizes()?;
    let params = LinkParams::default();
    let mut manager = ConnectionManager::new(Role::Controlling, vec![StationConfig::new(params)])
        .map_err(|e| format!("{e:?}"))?;
    let mut link = Link::new(sizes);
    // A direct execute of the untagged set, terminated for every family. A
    // station configured for select and execute takes
    // `CommandMode::SelectAndExecute` and a `ct.select(&command)` first.
    let mut ct = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        ca,
        0,
    )
    .with_address_sizes(sizes);
    let mut sent = false;

    while start.elapsed() < Duration::from_secs(60) {
        // A command cut off by a lost connection has an unknown outcome: stop
        // before the tick asks for a new connection, rather than send it twice.
        if command_interrupted(sent, link.is_up()) {
            return Err("the connection was lost before the termination; outcome unknown".into());
        }
        let now = Instant::now();

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
                        Err(e) => println!("connect failed: {e}"),
                    }
                }
                actions @ Directive::Actions { .. } => link.perform(&mut manager, vec![actions]),
            }
        }

        if !link.is_up() {
            // Not connected yet (a lost command already stopped the run at
            // the top of the loop): wait for the manager's next dial.
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }

        for frame in link.receive(&mut manager, now) {
            match matches_command_response(&frame, &command, ca, sizes) {
                Ok(true) if sent => {}
                // Not the command's: spontaneous data, return information and
                // the like.
                Ok(_) => {
                    print_decoded(&frame, sizes);
                    continue;
                }
                Err(e) => {
                    println!("   not understood: {e}");
                    continue;
                }
            }
            match ct.on_response(&frame, &Known::EVERYTHING) {
                Ok(outcome) => match outcome.reaction {
                    Reaction::Confirmed {
                        negative: false, ..
                    } => println!("   command confirmed"),
                    Reaction::Confirmed { negative: true, .. } => {
                        link.close(&mut manager);
                        return Err("the RTU refused the command (negative ACTCON)".into());
                    }
                    Reaction::Terminated { negative, .. } => {
                        link.close(&mut manager);
                        return if negative {
                            Err("the RTU ended the command negatively".into())
                        } else {
                            println!("command complete");
                            Ok(())
                        };
                    }
                    Reaction::Refused { cause, .. } => {
                        link.close(&mut manager);
                        return Err(format!("the RTU refused the command: {cause:?}"));
                    }
                    _ => print_decoded(&frame, sizes),
                },
                Err(e) => println!("   not understood: {e:?}"),
            }
        }

        let started = manager
            .station(STATION)
            .is_ok_and(|s| s.state() == State::Started);
        if started && !sent {
            match ct.execute(&command) {
                Ok(frame) => link.send_asdu(&mut manager, &frame, now),
                Err(e) => {
                    link.close(&mut manager);
                    return Err(format!("cannot send the command: {e:?}"));
                }
            }
            sent = true;
        }
    }
    link.close(&mut manager);
    Err("no termination within a minute".into())
}

/// Reads `<address> <ioa> <on|off|number> [common-address]` from the command line.
fn parse_args() -> Result<(String, Command, u16), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2404".into());
    let ioa = args
        .next()
        .ok_or("usage: command <address> <ioa> <on|off|number> [common-address]")?
        .parse::<u32>()
        .map_err(|e| format!("object address: {e}"))?;
    let command = match args.next().as_deref() {
        Some("on") => Command::single(ioa, true).with_qualifier(CommandQualifier::ShortPulse),
        Some("off") => Command::single(ioa, false).with_qualifier(CommandQualifier::ShortPulse),
        Some(number) => {
            let value = number
                .parse::<f32>()
                .map_err(|e| format!("set-point value: {e}"))?;
            Command::set_point_float(ioa, value)
        }
        None => return Err("missing the command: on, off or a number".into()),
    };
    let ca = match args.next() {
        Some(ca) => ca
            .parse::<u16>()
            .map_err(|e| format!("common address: {e}"))?,
        None => 1,
    };
    Ok((address, command, ca))
}

/// A sent command whose connection is gone has an unknown outcome. Check this
/// before the manager's next tick, which otherwise starts another connection.
const fn command_interrupted(sent: bool, connected: bool) -> bool {
    sent && !connected
}

/// Only a mirror of the command we sent can complete or refuse this run.
/// A station can also send unrelated command answers on this connection.
fn matches_command_response(
    frame: &[u8],
    sent: &Command,
    ca: u16,
    sizes: asdu::AddressSizes,
) -> Result<bool, String> {
    let header = asdu::Header::parse_with(frame, sizes).map_err(|e| format!("{e:?}"))?;
    if header.type_id != sent.type_id()
        || header.common_address != ca
        || header.originator != 0
        || header.test
        || !matches!(
            header.cause,
            asdu::Cause::ActivationCon
                | asdu::Cause::ActivationTermination
                | asdu::Cause::UnknownTypeId
                | asdu::Cause::UnknownCause
                | asdu::Cause::UnknownCommonAddress
                | asdu::Cause::UnknownInformationObjectAddress
        )
    {
        return Ok(false);
    }
    let received = ct::decode_command_with(frame, sizes).map_err(|e| format!("{e:?}"))?;
    Ok(received.is_some_and(|received| {
        received.ioa == sent.ioa && !received.select() && received.state_eq(sent)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Frames use the conventional 5-104 layout. The IOAs and causes come from
    // the two-station trace: an unrelated 2811 ACTCON, then a 4091 ACTCON.
    // 60.0 is IEEE 754 little-endian 00 00 70 42 (5-101 cl.7.2.6.8).
    #[test]
    fn lost_command_must_stop_before_reconnect() {
        assert!(!command_interrupted(false, false)); // Initial connection may retry.
        assert!(!command_interrupted(true, true));
        assert!(command_interrupted(true, false)); // No second dial after an execute.
    }

    #[test]
    fn only_the_sent_command_mirror_is_a_reply() {
        let sent = Command::set_point_float(4091, 60.0);
        let sizes = asdu::AddressSizes::CONVENTIONAL;
        let other_ioa = [
            50, 1, 0x47, 0, 0x6e, 0x1f, 0xfb, 0x0a, 0, 0, 0, 0x70, 0x42, 0,
        ];
        let other_value = [50, 1, 7, 0, 0x6e, 0x1f, 0xfb, 0x0f, 0, 0, 0, 0, 0, 0];
        let same_command = [50, 1, 7, 0, 0x6e, 0x1f, 0xfb, 0x0f, 0, 0, 0, 0x70, 0x42, 0];
        let refused_command = [
            50, 1, 0x47, 0, 0x6e, 0x1f, 0xfb, 0x0f, 0, 0, 0, 0x70, 0x42, 0,
        ];
        let mut completed_command = same_command;
        completed_command[2] = 10; // ACTTERM from the same IOA and value.
        let mut other_originator = same_command;
        other_originator[3] = 1;
        let mut other_cause = same_command;
        other_cause[2] = 6; // An activation is not a response.
        let interrogation = [100, 1, 7, 0, 0x6e, 0x1f, 0, 0, 0, 20];
        assert!(!matches_command_response(&other_ioa, &sent, 8046, sizes).unwrap());
        assert!(!matches_command_response(&other_value, &sent, 8046, sizes).unwrap());
        assert!(!matches_command_response(&other_originator, &sent, 8046, sizes).unwrap());
        assert!(!matches_command_response(&other_cause, &sent, 8046, sizes).unwrap());
        assert!(!matches_command_response(&interrogation, &sent, 8046, sizes).unwrap());
        assert!(matches_command_response(&same_command, &sent, 8046, sizes).unwrap());
        assert!(matches_command_response(&refused_command, &sent, 8046, sizes).unwrap());
        assert!(matches_command_response(&completed_command, &sent, 8046, sizes).unwrap());
    }
}

/// Prints an ASDU with `asdu::decode_with`, which picks the layout from the
/// type identification.
fn print_decoded(frame: &[u8], sizes: asdu::AddressSizes) {
    match asdu::decode_with(frame, sizes) {
        Ok(decoded) => println!(
            "   {} {}: {:?}",
            decoded.header.cause.mnemonic(),
            decoded.header.type_id.name(),
            decoded.objects
        ),
        Err(e) => println!("   not decoded: {e:?}"),
    }
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
