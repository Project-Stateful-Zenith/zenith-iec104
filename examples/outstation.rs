//! A minimal controlled station (outstation) over blocking TCP.
//!
//! Listens for one master at a time, answers station and group interrogations
//! from three scaled measured values, and reports one of them spontaneously
//! every few seconds. Direct commands of the untagged set (`<45>` to `<51>`)
//! are confirmed, printed and terminated; they change nothing. Any other
//! request is mirrored back as unknown (cause 44).
//!
//! ```text
//! cargo run --example outstation -- 0.0.0.0:2404
//! ```
//!
//! Set `IEC104_SIZES=1,2,0` (common address, object address, originator) for a
//! non-default profile.
//!
//! The crate does no I/O itself. The loop below runs the manager's clock
//! (`tick`), feeds it what arrived on the socket (`Link::receive`), answers
//! each delivered ASDU, and sends the spontaneous data. The socket side lives
//! in `common/mod.rs`.

mod common;

use common::{Link, STATION};
use iec104::asdu::{
    self, AddressSizes, Cause, Header, Known, LayoutObject, MMeNb1, Qds, Sva, TypeId,
    encode_asdu_with,
};
use iec104::ct::{self, CommandMode, CommandSet, CommandTransmission, Termination};
use iec104::dispatch::{Route, not_implemented, route};
use iec104::gi::{DataSource, Interrogation, ReActivation, Reaction, Scope};
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use std::cell::RefCell;
use std::net::TcpListener;
use std::time::{Duration, Instant};

/// This station's common address.
const CA: u16 = 1;

/// The process image: three scaled values at IOA 100..=102, all in group 1.
///
/// `RefCell` because the interrogation reads the image through `&self`
/// ([`DataSource`]) while the main loop also changes it.
struct Points {
    values: RefCell<[i16; 3]>,
    sizes: AddressSizes,
}

impl Points {
    /// One `M_ME_NB_1` (scaled measured value) ASDU carrying the points at
    /// `ioas`, sent with `cause`: spontaneous (3) for a change, or the
    /// interrogation's own cause (20 for the station, 21 to 36 for groups 1 to
    /// 16) when it answers one. `SQ = 0`: each object carries its own address.
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

/// What the interrogation procedure asks of the station's data.
impl DataSource for Points {
    /// The image is always in memory. A station that is still starting up
    /// answers `false`, and the procedure confirms negatively (5-101 clause
    /// 7.4.5).
    fn ready(&self, _scope: Scope) -> bool {
        true
    }

    /// The ASDUs for `scope`. Every point is in group 1, so an interrogation
    /// of any other group has no data and is only confirmed and terminated.
    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
        if matches!(scope, Scope::Station | Scope::Group(1)) {
            out.extend(self.asdu(scope.cause(), &[100, 101, 102]));
        }
    }
}

fn main() -> Result<(), String> {
    let address = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2404".into());
    let sizes = common::address_sizes()?;
    let listener = TcpListener::bind(&address).map_err(|e| e.to_string())?;
    println!("listening on {address}");

    // A controlled manager never dials: clause 7.1 makes the outstation the
    // listener, so each connection comes from `accept` below.
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
    // The general interrogation procedure. `Continue` is the first of the
    // re-activation options in 5-101 Table 17: a second identical request
    // while one is running is confirmed negatively and the first continues.
    let mut gi = Interrogation::controlled(ReActivation::Continue, CA, 0).with_address_sizes(sizes);
    // Command transmission: direct execute only, the untagged set, and every
    // family terminated (5-101 cl.7.4.7).
    let mut commands = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        0,
    )
    .with_address_sizes(sizes);
    let mut last_report: Option<Instant> = None;

    loop {
        // One master at a time: wait for the next one once the link is down.
        // A running interrogation belongs to the old connection, so drop it.
        if !link.is_up() {
            gi.reset();
            commands.reset();
            let (stream, peer) = listener.accept().map_err(|e| e.to_string())?;
            println!("master connected from {peer}");
            link.attach(stream, &mut manager, Instant::now())?;
        }
        // The clock: timers (t1 to t3) that expired become actions, such as a
        // TESTFR act after t3 of silence or an S-frame acknowledgement at t2.
        let now = Instant::now();
        let expired = manager.tick(now);
        link.perform(&mut manager, expired);

        for asdu in link.receive(&mut manager, now) {
            let Ok(header) = Header::parse_with(&asdu, sizes) else {
                continue;
            };
            // One owner per ASDU: this station serves interrogations and
            // commands and answers every other control-direction type as not
            // implemented.
            if route(&header) == Route::Command {
                execute(&mut commands, &asdu, sizes, |frame| {
                    link.send_asdu(&mut manager, frame, now);
                });
                continue;
            }
            if route(&header) != Route::Interrogation {
                if let Some(mirror) = not_implemented(&header, &asdu, CA, sizes) {
                    link.send_asdu(&mut manager, &mirror, now);
                }
                continue;
            }
            match gi.on_request(&asdu, &Known::EVERYTHING, &points) {
                Ok(outcome) => {
                    // The confirmation (or refusal) the procedure wants sent.
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
        // Before STARTDT the session would only queue it (clause 5.3).
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

/// Answers one command: the confirmation the procedure writes, then, for an
/// accepted execute, the termination. A real station would operate the output
/// between the two.
fn execute(
    commands: &mut CommandTransmission,
    frame: &[u8],
    sizes: AddressSizes,
    mut send: impl FnMut(&[u8]),
) {
    let outcome = match commands.on_request(frame, &Known::EVERYTHING) {
        Ok(outcome) => outcome,
        Err(e) => {
            println!("   not understood: {e:?}");
            return;
        }
    };
    for answer in &outcome.send {
        send(answer);
    }
    if let ct::Reaction::Confirmed {
        ioa,
        select: false,
        negative: false,
    } = outcome.reaction
    {
        if let Ok(command) = asdu::decode_with(frame, sizes) {
            println!("   executing {:?}", command.objects);
        }
        if commands.is_running(ioa) {
            match commands.terminate(ioa, false) {
                Ok(termination) => send(&termination),
                Err(e) => println!("   cannot terminate: {e:?}"),
            }
        }
    }
}
