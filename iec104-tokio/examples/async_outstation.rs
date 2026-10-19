//! A minimal controlled station (outstation) on the Tokio driver.
//!
//! The async twin of `examples/outstation.rs`: listens for a master, answers
//! station and group interrogations from three scaled measured values, and
//! reports one of them spontaneously every few seconds. Any other request is
//! mirrored back as unknown (cause 44).
//!
//! ```text
//! cargo run -p iec104-tokio --example async_outstation -- 0.0.0.0:2404 [connections]
//! ```
//!
//! `connections` (default 1) is the size of the redundancy group: a master
//! may open that many connections and start any one of them (104 clause 10).
//! Set `IEC104_SIZES=1,2,0` (common address, object address, originator) for a
//! non-default profile.

mod common;

use std::cell::RefCell;
use std::time::Duration;

use iec104::asdu::{
    AddressSizes, Cause, Header, Known, LayoutObject, MMeNb1, Qds, Sva, TypeId, encode_asdu_with,
};
use iec104::dispatch::{Route, not_implemented, route};
use iec104::gi::{DataSource, Interrogation, ReActivation, Reaction, Scope};
use iec104::link::{Role, State};
use iec104::params::LinkParams;
use iec104::redundancy::{RedundancyGroup, Replay};
use iec104_tokio::{Event, Handle, Options, outstation};
use tokio::net::TcpListener;

/// This station's common address.
const CA: u16 = 1;

/// The process image: three scaled values at IOA 100..=102, all in group 1.
struct Points {
    values: RefCell<[i16; 3]>,
    sizes: AddressSizes,
}

impl Points {
    /// `None` only if the objects do not fit one ASDU, which three never do.
    fn asdu(&self, cause: Cause, ioas: &[u32]) -> Option<Vec<u8>> {
        let values = self.values.borrow();
        let objects: Vec<LayoutObject<MMeNb1>> = (100..)
            .zip(values.iter())
            .filter(|(ioa, _)| ioas.contains(ioa))
            .map(|(ioa, &value)| LayoutObject {
                ioa,
                value: MMeNb1 {
                    sva: Sva { value },
                    qds: Qds::default(),
                },
            })
            .collect();
        let header = Header {
            type_id: TypeId::MMeNb1,
            sequence: false,
            count: u8::try_from(objects.len()).ok()?,
            cause,
            negative: false,
            test: false,
            originator: 0,
            common_address: CA,
        };
        encode_asdu_with(&header, &objects, self.sizes).ok()
    }
}

impl DataSource for Points {
    fn ready(&self, _scope: Scope) -> bool {
        true
    }

    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
        if matches!(scope, Scope::Station | Scope::Group(1)) {
            out.extend(self.asdu(scope.cause(), &[100, 101, 102]));
        }
    }
}

async fn send_all(handle: &Handle, frames: Vec<Vec<u8>>) {
    for frame in frames {
        if let Err(e) = handle.send_asdu(0, frame).await {
            println!("dropped an ASDU: {e}");
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:2404".into());
    let connections = match args.next() {
        Some(n) => n.parse::<usize>().map_err(|e| e.to_string())?,
        None => 1,
    };
    let sizes = common::address_sizes()?;
    let listener = TcpListener::bind(&address)
        .await
        .map_err(|e| e.to_string())?;
    println!("listening on {address}");

    let group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), connections)
        .map_err(|e| format!("{e:?}"))?;
    let options = Options {
        trace: true,
        ..Options::default()
    };
    let (handle, mut events) = outstation::spawn(group, options).map_err(|e| e.to_string())?;
    tokio::spawn(outstation::serve(listener, handle.clone()));

    let points = Points {
        values: RefCell::new([1000, 2000, 3000]),
        sizes,
    };
    let mut gi = Interrogation::controlled(ReActivation::Continue, CA, 0).with_address_sizes(sizes);
    // The member the master started, if any (10.2, rule 4).
    let mut started: Option<usize> = None;
    // Connections that failed while started, with data to replay once the
    // master has started another (10.5, 10.6).
    let mut to_replay: Vec<usize> = Vec::new();
    let mut report = tokio::time::interval(Duration::from_secs(5));

    loop {
        let event = tokio::select! {
            event = events.recv() => match event {
                Some(event) => event,
                None => return Ok(()),
            },
            _ = report.tick() => {
                // A spontaneous change every five seconds once data transfer runs.
                if started.is_some() {
                    if let Some(value) = points.values.borrow_mut().first_mut() {
                        *value = value.wrapping_add(1);
                    }
                    if let Some(asdu) = points.asdu(Cause::Spontaneous, &[100]) {
                        send_all(&handle, vec![asdu]).await;
                    }
                }
                continue;
            }
        };
        common::log(&event, sizes);
        match event {
            Event::State { conn, state } => {
                if state == State::Started {
                    started = Some(conn);
                    // The unconfirmed data goes out on the new started
                    // connection; the group keeps it until it is replayed or
                    // discarded, so every failure is decided on.
                    for failed in std::mem::take(&mut to_replay) {
                        match handle
                            .retransmit_unconfirmed(failed, Replay::Retransmit)
                            .await
                        {
                            Ok(outcome) => println!("   replayed {failed}: {outcome:?}"),
                            Err(e) => println!("   replay of {failed}: {e}"),
                        }
                    }
                } else if started == Some(conn) {
                    started = None;
                    gi.reset();
                }
            }
            Event::StartedConnectionFailed { conn, unconfirmed } if unconfirmed > 0 => {
                to_replay.push(conn);
            }
            Event::Asdu { asdu, .. } => {
                let Ok(header) = Header::parse_with(&asdu, sizes) else {
                    continue;
                };
                // One owner per ASDU: this station serves interrogations and
                // answers every other control-direction type as not implemented.
                if route(&header) != Route::Interrogation {
                    let mirror = not_implemented(&header, &asdu, CA, sizes);
                    send_all(&handle, mirror.into_iter().collect()).await;
                    continue;
                }
                match gi.on_request(&asdu, &Known::EVERYTHING, &points) {
                    Ok(outcome) => {
                        let mut frames = outcome.send;
                        if let Reaction::ActivationConfirmed {
                            negative: false, ..
                        } = outcome.reaction
                        {
                            // The data, then the termination (101 cl.7.4.5).
                            frames.extend(gi.interrogated(&points).unwrap_or_default());
                            frames.extend(gi.complete(&points).unwrap_or_default());
                        }
                        send_all(&handle, frames).await;
                    }
                    Err(e) => println!("   not understood: {e:?}"),
                }
            }
            _ => {}
        }
    }
}
