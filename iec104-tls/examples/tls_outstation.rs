//! A minimal controlled station (outstation) over blocking TLS: the TLS twin
//! of the core crate's `examples/outstation.rs`.
//!
//! Listens for one master at a time and requires a client certificate the CA
//! vouches for. Answers station and group interrogations from three scaled
//! measured values, and reports one of them spontaneously every few seconds.
//! Any other request is mirrored back as unknown (cause 44).
//!
//! ```text
//! cargo run -p iec104-tls --example tls_outstation -- \
//!     127.0.0.1:19998 outstation.crt outstation.key ca.crt
//! ```
//!
//! `IEC104_TLS_CRL` and `IEC104_TLS_PEER` add a CRL and an allow-listed
//! master certificate. Set `IEC104_SIZES=1,2,0` (common address, object
//! address, originator) for a non-default profile.

mod tls_common;

use iec104::asdu::{
    AddressSizes, Cause, Header, Known, LayoutObject, MMeNb1, Qds, Sva, TypeId, encode_asdu_with,
};
use iec104::dispatch::{Route, not_implemented, route};
use iec104::gi::{DataSource, Interrogation, ReActivation, Reaction, Scope};
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use std::cell::RefCell;
use std::net::TcpListener;
use std::time::{Duration, Instant};
use tls_common::common::{self, Link, STATION};

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

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let address = args.next().unwrap_or_else(|| "127.0.0.1:19998".into());
    let tls = tls_common::config(&mut args)?;
    let sizes = common::address_sizes()?;
    let listener = TcpListener::bind(&address).map_err(|e| e.to_string())?;
    println!("listening on {address}");

    let mut manager = ConnectionManager::new(
        Role::Controlled,
        vec![StationConfig::new(LinkParams::default())],
    )
    .map_err(|e| format!("{e:?}"))?;
    let points = Points {
        values: RefCell::new([1000, 2000, 3000]),
        sizes,
    };
    let mut link = Link::new(sizes);
    let mut gi = Interrogation::controlled(ReActivation::Continue, CA, 0).with_address_sizes(sizes);
    let mut last_report: Option<Instant> = None;

    loop {
        if !link.is_up() {
            gi.reset();
            let (stream, peer) = listener.accept().map_err(|e| e.to_string())?;
            let stream = match iec104_tls::accept(stream, &tls) {
                Ok(stream) => stream,
                // A refused handshake is a security event: report who and why.
                Err(e) => {
                    match iec104_tls::tls_error(&e) {
                        Some(tls) => println!("{peer}: TLS handshake refused: {tls}"),
                        None => println!("{peer}: TLS handshake failed: {e}"),
                    }
                    continue;
                }
            };
            println!(
                "master connected from {peer}: {}",
                tls_common::describe(&stream)
            );
            link.attach(stream, &mut manager, Instant::now())?;
        }
        let now = Instant::now();
        let expired = manager.tick(now);
        link.perform(&mut manager, expired);

        for asdu in link.receive(&mut manager, now) {
            let Ok(header) = Header::parse_with(&asdu, sizes) else {
                continue;
            };
            // One owner per ASDU: this station serves interrogations and
            // answers every other control-direction type as not implemented.
            if route(&header) != Route::Interrogation {
                if let Some(mirror) = not_implemented(&header, &asdu, CA, sizes) {
                    link.send_asdu(&mut manager, &mirror, now);
                }
                continue;
            }
            match gi.on_request(&asdu, &Known::EVERYTHING, &points) {
                Ok(outcome) => {
                    for frame in &outcome.send {
                        link.send_asdu(&mut manager, frame, now);
                    }
                    if let Reaction::ActivationConfirmed {
                        negative: false, ..
                    } = outcome.reaction
                    {
                        // The data, then the termination (101 cl.7.4.5).
                        let mut frames = gi.interrogated(&points).unwrap_or_default();
                        frames.extend(gi.complete(&points).unwrap_or_default());
                        for frame in &frames {
                            link.send_asdu(&mut manager, frame, now);
                        }
                    }
                }
                Err(e) => println!("   not understood: {e:?}"),
            }
        }

        // A spontaneous change every five seconds once data transfer runs.
        let started = manager
            .station(STATION)
            .is_ok_and(|s| s.state() == State::Started);
        if started && last_report.is_none_or(|t| now.duration_since(t) >= Duration::from_secs(5)) {
            last_report = Some(now);
            if let Some(value) = points.values.borrow_mut().first_mut() {
                *value = value.wrapping_add(1);
            }
            if let Some(asdu) = points.asdu(Cause::Spontaneous, &[100]) {
                link.send_asdu(&mut manager, &asdu, now);
            }
        }
    }
}
