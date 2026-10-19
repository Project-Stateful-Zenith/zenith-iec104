//! The controlled station the outstation interop tests serve: every
//! procedure, behind `dispatch::route`, from one small process image.
//!
//! - GI: `M_ME_NB_1` 1234 at IOA 0x0102.
//! - CI: `M_IT_NA_1` 4711 at IOA 0x0200.
//! - A read of any IOA: `M_ME_NB_1` -77 at that IOA.
//! - Commands: confirmed and terminated. Parameters, the test command and
//!   clock synchronisation: answered.
//! - Anything else: mirrored as unknown (cause 44).

#![allow(dead_code)]

use iec104::asdu::{
    AddressSizes, Bcr, Cause, Cp56Time2a, Header, Known, LayoutObject, MItNa1, MMeNb1, Qds, Sva,
    TypeId, encode_asdu,
};
use iec104::dispatch::{Route, not_implemented, route};
use iec104::{ci, cs, ct, gi, pm, rd, ts};

pub const CA: u16 = 1;

fn monitor(type_id: TypeId, cause: Cause, ioa: u32, value: i32) -> Vec<u8> {
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

impl gi::DataSource for Process {
    fn ready(&self, _: gi::Scope) -> bool {
        true
    }
    fn interrogated(&self, scope: gi::Scope, out: &mut Vec<Vec<u8>>) {
        out.push(monitor(TypeId::MMeNb1, scope.cause(), 0x0102, 1234));
    }
}

impl ci::CounterSource for Process {
    fn ready(&self, _: ci::Request) -> bool {
        true
    }
    fn totals(&self, request: ci::Request, out: &mut Vec<Vec<u8>>) {
        out.push(monitor(TypeId::MItNa1, request.cause(), 0x0200, 4711));
    }
}

impl rd::DataSource for Process {
    fn object(&self, ioa: u32) -> Option<Vec<u8>> {
        Some(monitor(TypeId::MMeNb1, Cause::Request, ioa, -77))
    }
}

/// The clock the station reports on a clock synchronisation.
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

/// Every procedure's controlled half.
pub struct Station {
    gi: gi::Interrogation,
    ci: ci::CounterInterrogation,
    read: rd::Read,
    ct: ct::CommandTransmission,
    pm: pm::ParameterLoading,
    ts: ts::TestProcedure,
    cs: cs::ClockSynchronisation,
}

impl Station {
    pub const fn new(commands: ct::CommandMode) -> Self {
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

    /// The ASDUs that answer one received ASDU, in order.
    pub fn answer(&mut self, asdu: &[u8]) -> Vec<Vec<u8>> {
        let known = Known::EVERYTHING;
        let process = Process;
        let mut out = Vec::new();
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
            _ => out.extend(not_implemented(&header, asdu, CA, AddressSizes::default())),
        }
        out
    }
}
