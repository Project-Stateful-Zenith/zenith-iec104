//! The core's controlled station over blocking TCP, serving one master for
//! the interop tests: every procedure behind `dispatch::route`, from one small
//! process image, driven through the connection manager.
//!
//! - GI: `M_ME_NB_1` 1234 at IOA 0x0102. CI: `M_IT_NA_1` 4711 at IOA 0x0200.
//! - A read of any IOA: `M_ME_NB_1` -77 at that IOA.
//! - Commands confirmed and terminated; parameters, the test command and
//!   clock synchronisation answered; anything else mirrored as unknown.

#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::Child;
use std::time::{Duration, Instant};

use iec104::apci::{self, Apci, Apdu};
use iec104::asdu::{AddressSizes, Cp56Time2a, Known, Sva};
use iec104::framed::Decoder;
use iec104::link::{Action, Role};
use iec104::manager::{ConnectionManager, Directive, StationConfig};
use iec104::params::LinkParams;

pub const CA: u16 = 1;

fn write(stream: &mut TcpStream, actions: &[Action]) {
    for action in actions {
        let (apci, asdu): (Apci, &[u8]) = match action {
            Action::Send(apci) => (*apci, &[]),
            Action::SendI { ns, nr, asdu } => (Apci::I { ns: *ns, nr: *nr }, asdu),
            Action::DeliverData { .. } => continue,
            Action::ActiveClose(why) => panic!("the connection closed: {why}"),
        };
        let mut frame = Vec::new();
        Apdu { apci, asdu }.encode(&mut frame).unwrap();
        stream.write_all(&frame).unwrap();
    }
}

fn now_tag() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 12_345,
        minutes: 30,
        hours: 12,
        day_of_month: 26,
        months: 9,
        years: 26,
        ..Default::default()
    }
}

/// An `M_ME_NB_1` or `M_IT_NA_1` ASDU of one object.
pub fn monitor(
    type_id: iec104::asdu::TypeId,
    cause: iec104::asdu::Cause,
    ioa: u32,
    value: i32,
) -> Vec<u8> {
    use iec104::asdu::{Bcr, Header, LayoutObject, MItNa1, MMeNb1, Qds, TypeId, encode_asdu};
    let header = Header {
        type_id,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: 0,
        common_address: CA,
    };
    match type_id {
        TypeId::MItNa1 => encode_asdu(
            &header,
            &[LayoutObject {
                ioa,
                value: MItNa1 {
                    bcr: Bcr {
                        reading: value,
                        ..Bcr::default()
                    },
                },
            }],
        ),
        _ => encode_asdu(
            &header,
            &[LayoutObject {
                ioa,
                value: MMeNb1 {
                    sva: Sva {
                        value: value as i16,
                    },
                    qds: Qds::default(),
                },
            }],
        ),
    }
    .unwrap()
}

struct Process;

impl iec104::gi::DataSource for Process {
    fn ready(&self, _: iec104::gi::Scope) -> bool {
        true
    }
    fn interrogated(&self, scope: iec104::gi::Scope, out: &mut Vec<Vec<u8>>) {
        out.push(monitor(
            iec104::asdu::TypeId::MMeNb1,
            scope.cause(),
            0x0102,
            1234,
        ));
    }
}

impl iec104::ci::CounterSource for Process {
    fn ready(&self, _: iec104::ci::Request) -> bool {
        true
    }
    fn totals(&self, request: iec104::ci::Request, out: &mut Vec<Vec<u8>>) {
        out.push(monitor(
            iec104::asdu::TypeId::MItNa1,
            request.cause(),
            0x0200,
            4711,
        ));
    }
}

impl iec104::rd::DataSource for Process {
    fn object(&self, ioa: u32) -> Option<Vec<u8>> {
        Some(monitor(
            iec104::asdu::TypeId::MMeNb1,
            iec104::asdu::Cause::Request,
            ioa,
            -77,
        ))
    }
}

/// The station's procedures, one for each route `dispatch::route` names.
struct Procedures {
    gi: iec104::gi::Interrogation,
    ci: iec104::ci::CounterInterrogation,
    read: iec104::rd::Read,
    ct: iec104::ct::CommandTransmission,
    pm: iec104::pm::ParameterLoading,
    ts: iec104::ts::TestProcedure,
    cs: iec104::cs::ClockSynchronisation,
}

impl Procedures {
    /// Every procedure for station `CA`, commands executed in `commands` mode.
    const fn new(commands: iec104::ct::CommandMode) -> Self {
        use iec104::{ci, cs, ct, gi, pm, rd, ts};
        Self {
            gi: gi::Interrogation::controlled(gi::ReActivation::Continue, CA, 0),
            ci: ci::CounterInterrogation::controlled(ci::CounterMode::FreezeAndTransmit, CA, 0),
            read: rd::Read::controlled(true, CA, 0),
            ct: ct::CommandTransmission::controlled(
                commands,
                ct::CommandSet::Untagged,
                ct::Termination::All,
                CA,
                0,
            ),
            pm: pm::ParameterLoading::controlled(pm::LocalChange::NotUsed, CA, 0),
            ts: ts::TestProcedure::controlled(ts::Selection::TAGGED, CA, 0),
            cs: cs::ClockSynchronisation::controlled(CA, 0),
        }
    }

    /// The answers to one accepted ASDU, from the one procedure its type and
    /// cause route it to.
    fn answer(&mut self, asdu: &[u8], out: &mut Vec<Vec<u8>>) {
        use iec104::asdu::Header;
        use iec104::dispatch::{Route, not_implemented, route};
        use iec104::{ct, gi};

        let process = Process;
        let known = Known::EVERYTHING;
        let header = Header::parse(asdu).unwrap();
        match route(&header) {
            Route::Interrogation => {
                let outcome = self.gi.on_request(asdu, &known, &process).unwrap();
                out.extend(outcome.send);
                if let gi::Reaction::ActivationConfirmed {
                    negative: false, ..
                } = outcome.reaction
                {
                    out.extend(self.gi.interrogated(&process).unwrap());
                    out.extend(self.gi.complete(&process).unwrap());
                }
            }
            Route::CounterInterrogation => {
                let outcome = self.ci.on_request(asdu, &known, &process).unwrap();
                out.extend(outcome.send);
                if self.ci.awaiting_data() {
                    out.extend(self.ci.interrogated(&process).unwrap());
                    out.extend(self.ci.complete(&process).unwrap());
                }
            }
            Route::Read => out.extend(self.read.on_request(asdu, &known, &process).unwrap().send),
            Route::Command => {
                let outcome = self.ct.on_request(asdu, &known).unwrap();
                out.extend(outcome.send);
                if let ct::Reaction::Confirmed {
                    ioa,
                    select: false,
                    negative: false,
                    ..
                } = outcome.reaction
                {
                    // The application acts on the command, then terminates it.
                    out.push(self.ct.terminate(ioa, false).unwrap());
                }
            }
            Route::Parameter => out.extend(self.pm.on_request(asdu, &known).unwrap().send),
            Route::Test => out.extend(self.ts.on_request(asdu, &known).unwrap().send),
            Route::ClockSync => {
                out.extend(self.cs.on_request(asdu, &known, now_tag()).unwrap().send);
            }
            // No procedure serves it: 5-101 cl.7.2.3's cause-44 mirror.
            _ => out.extend(not_implemented(&header, asdu, CA, AddressSizes::default())),
        }
    }
}

/// Accepts one master on `listener` and serves it until `peer` exits or
/// `deadline` passes. Commands are executed in `commands` mode.
pub fn serve(
    listener: &TcpListener,
    peer: &mut Child,
    commands: iec104::ct::CommandMode,
    deadline: Duration,
) {
    let (stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let mut stream = stream;
    let mut decoder = Decoder::new();
    let mut manager = ConnectionManager::new(
        Role::Controlled,
        vec![StationConfig::new(LinkParams::default())],
    )
    .unwrap();
    manager
        .on_connection_established(0, Instant::now())
        .unwrap();

    let mut procedures = Procedures::new(commands);

    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if peer.try_wait().unwrap().is_some() {
            break;
        }
        let now = Instant::now();
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut buf = [0u8; 4096];
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => decoder.push(&buf[..n]),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break,
        }
        let ticked = manager.tick(now);
        for directive in ticked {
            if let Directive::Actions { actions, .. } = directive {
                write(&mut stream, &actions);
            }
        }
        while let Some(frame) = decoder.next_frame().unwrap() {
            let frame = frame.to_vec();
            let (parsed, _) = apci::parse(&frame).unwrap();
            let directives = manager.on_frame(0, parsed.apci, now).unwrap();
            let accepted = directives.iter().any(|d| {
                matches!(d, Directive::Actions { actions, .. }
                    if actions.iter().any(|a| matches!(a, Action::DeliverData { .. })))
            });
            for directive in directives {
                if let Directive::Actions { actions, .. } = directive {
                    write(&mut stream, &actions);
                }
            }
            // Only an I-frame the session accepted is the application's.
            if accepted {
                procedures.answer(parsed.asdu, &mut out);
            }
        }
        for asdu in out {
            match manager.send_i_frame(0, &asdu, now).unwrap() {
                Some(Directive::Actions { actions, .. }) => write(&mut stream, &actions),
                _ => manager.queue_i_frame(0, &asdu).unwrap(),
            }
        }
    }
}
