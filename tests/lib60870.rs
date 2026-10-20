//! Every procedure against a real 104 stack, in both roles: lib60870-C (MZ
//! Automation, GPLv3) run as an **external process** over TCP. No code of it
//! is linked or copied; the peers are two small C programs built against it
//! (`tests/lib60870/`).
//!
//! - Our controlling station against its outstation: counter interrogation,
//!   read, a set-point, a parameter, the test command, clock sync, a file
//!   transfer and a redundancy-group switchover.
//! - Our controlled station, routed by `dispatch::route`, against its master:
//!   one of every request, and a type we do not serve.
//!
//! Ignored by default. `scripts/interop.sh` builds the peers and runs this
//! with the others; by hand, after `scripts/interop-setup.sh`:
//!
//! ```text
//! cargo test --test lib60870 -- --ignored --test-threads=1
//! ```
//!
//! `IEC104_LIB60870_SERVER` / `IEC104_LIB60870_CLIENT` point at peers built
//! elsewhere; `IEC104_LIB60870_VERBOSE=1` shows the peer's own log.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use iec104::apci::{self, Apci, Apdu};
use iec104::asdu::elements::{Afq, Nof, Nos};
use iec104::asdu::{Cp56Time2a, Known, Qos, Sva, Tsc};
use iec104::framed::Decoder;
use iec104::link::{Action, Role, State};
use iec104::manager::{ConnectionManager, Directive, StationConfig};
use iec104::params::LinkParams;
use iec104::redundancy::{RedundancyGroup, Routed};

mod station;

use station::CA;

/// The peer process, killed when the test ends.
struct Peer(Child);

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The peer binary: `$var` if set, else what `scripts/interop-setup.sh` built.
fn peer_binary(var: &str, name: &str) -> std::path::PathBuf {
    let path = std::env::var_os(var).map_or_else(
        || {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/interop/bin")
                .join(name)
        },
        std::path::PathBuf::from,
    );
    assert!(
        path.exists(),
        "no lib60870 peer at {}: run scripts/interop-setup.sh, or set {var}",
        path.display()
    );
    path
}

/// Starts lib60870's outstation (`full_server`) on `port`; it exits after 30 s.
fn spawn(port: u16) -> Peer {
    let path = peer_binary("IEC104_LIB60870_SERVER", "full_server");
    let child = Command::new(path)
        .args([port.to_string(), "30".into()])
        .stdout(
            if std::env::var("IEC104_LIB60870_VERBOSE").is_ok_and(|v| v == "1") {
                Stdio::inherit()
            } else {
                Stdio::null()
            },
        )
        .spawn()
        .expect("the peer starts");
    Peer(child)
}

/// Connects to the peer, retrying while it starts up.
fn dial(port: u16) -> TcpStream {
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .unwrap();
                return stream;
            }
            Err(_) if Instant::now() < until => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("cannot reach the peer: {e}"),
        }
    }
}

/// Puts the frames among `actions` on the wire.
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

/// Reads what arrived, returning each APDU as its control field and ASDU.
fn read_frames(stream: &mut TcpStream, decoder: &mut Decoder) -> Vec<(Apci, Vec<u8>)> {
    let mut buf = [0u8; 4096];
    match stream.read(&mut buf) {
        Ok(0) => panic!("the peer closed the connection"),
        Ok(n) => decoder.push(&buf[..n]),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
        Err(e) => panic!("read: {e}"),
    }
    let mut frames = Vec::new();
    while let Some(frame) = decoder.next_frame().expect("well framed") {
        let (apdu, _) = apci::parse(frame).expect("a valid APDU");
        frames.push((apdu.apci, apdu.asdu.to_vec()));
    }
    frames
}

/// One started connection driven through the connection manager.
struct Master {
    stream: TcpStream,
    decoder: Decoder,
    manager: ConnectionManager,
}

impl Master {
    fn start(port: u16) -> Self {
        let now = Instant::now();
        let mut manager = ConnectionManager::new(
            Role::Controlling,
            vec![StationConfig::new(LinkParams::default())],
        )
        .unwrap();
        manager.tick(now);
        let stream = dial(port);
        manager.on_connection_established(0, now).unwrap();
        let mut master = Self {
            stream,
            decoder: Decoder::new(),
            manager,
        };
        let start = master.manager.request_start(0, now).unwrap();
        master.perform(start);
        master.collect(
            |_| false,
            |m| m.manager.station(0).unwrap().state() == State::Started,
        );
        master
    }

    /// Writes the frames the manager asked for.
    fn perform(&mut self, directives: Vec<Directive>) {
        for directive in directives {
            if let Directive::Actions { actions, .. } = directive {
                write(&mut self.stream, &actions);
            }
        }
    }

    /// Sends one ASDU as an I-frame; the tests never fill the k window.
    fn send(&mut self, asdu: &[u8]) {
        let directive = self
            .manager
            .send_i_frame(0, asdu, Instant::now())
            .unwrap()
            .expect("the window is open");
        self.perform(vec![directive]);
    }

    /// Collects delivered ASDUs until `done_asdu` accepts one or `done_state`
    /// holds, failing after five seconds.
    fn collect(
        &mut self,
        mut done_asdu: impl FnMut(&[u8]) -> bool,
        done_state: impl Fn(&Self) -> bool,
    ) -> Vec<Vec<u8>> {
        let until = Instant::now() + Duration::from_secs(5);
        let mut delivered = Vec::new();
        while Instant::now() < until {
            let now = Instant::now();
            let ticked = self.manager.tick(now);
            self.perform(ticked);
            for (apci, asdu) in read_frames(&mut self.stream, &mut self.decoder) {
                let directives = self.manager.on_frame(0, apci, now).unwrap();
                let accepted = directives.iter().any(|d| {
                    matches!(d, Directive::Actions { actions, .. }
                        if actions.iter().any(|a| matches!(a, Action::DeliverData { .. })))
                });
                self.perform(directives);
                if accepted {
                    let done = done_asdu(&asdu);
                    delivered.push(asdu);
                    if done {
                        return delivered;
                    }
                }
            }
            if done_state(self) {
                return delivered;
            }
        }
        panic!("timed out; delivered so far: {delivered:02X?}");
    }

    /// Collects delivered ASDUs until `done` accepts one.
    fn until(&mut self, done: impl FnMut(&[u8]) -> bool) -> Vec<Vec<u8>> {
        self.collect(done, |_| false)
    }
}

/// A fixed, valid `CP56Time2a` for the time-tagged requests.
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

/// 101 cl.7.4.8: a general counter request is confirmed, answered with the
/// peer's one integrated total and terminated, in that order.
#[test]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
fn counter_interrogation() {
    use iec104::asdu::FreezeMode;
    use iec104::ci::{CounterInterrogation, CounterMode, Reaction, Request};
    let _peer = spawn(24101);
    let mut master = Master::start(24101);
    let mut ci = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    master.send(&ci.request(Request::General, FreezeMode::Read).unwrap());
    let mut reactions = Vec::new();
    master.until(|asdu| {
        let reaction = ci.on_response(asdu, &Known::EVERYTHING).unwrap().reaction;
        let done = matches!(reaction, Reaction::Terminated { .. });
        reactions.push(reaction);
        done
    });
    assert_eq!(
        reactions,
        [
            Reaction::ActivationConfirmed {
                request: Request::General,
                freeze: FreezeMode::Read,
                negative: false
            },
            Reaction::Counted {
                request: Request::General
            },
            Reaction::Terminated {
                request: Request::General
            },
        ]
    );
}

/// 101 cl.7.4.14: a read of IOA 0x0102 is answered with an `M_ME_NB_1` at
/// that address (the peer's read handler answers every IOA).
#[test]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
fn read_command() {
    use iec104::asdu::TypeId;
    use iec104::rd::{Reaction, Read};
    let _peer = spawn(24102);
    let mut master = Master::start(24102);
    let read = Read::controlling(true, CA, 0);
    master.send(&read.request(0x0102).unwrap());
    let answers = master.until(|asdu| {
        matches!(
            read.on_response(asdu, &Known::EVERYTHING).unwrap().reaction,
            Reaction::Answered { .. }
        )
    });
    assert_eq!(
        read.on_response(answers.last().unwrap(), &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Answered {
            type_id: TypeId::MMeNb1,
            ioa: 0x0102
        }
    );
}

/// 101 cl.7.4.7: a direct scaled set-point is confirmed and terminated (the
/// peer mirrors it with cause 7, then cause 10).
#[test]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
fn set_point_command() {
    use iec104::ct::{
        Command, CommandMode, CommandSet, CommandTransmission, CommandValue, Reaction, Termination,
    };
    let _peer = spawn(24103);
    let mut master = Master::start(24103);
    let mut ct = CommandTransmission::controlling(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        CA,
        0,
    );
    let command = Command::new(
        0x0300,
        CommandValue::SetPointScaled {
            sva: Sva { value: -1234 },
            qos: Qos {
                ql: 0,
                select: false,
            },
        },
    );
    master.send(&ct.execute(&command).unwrap());
    let mut reactions = Vec::new();
    master.until(|asdu| {
        let reaction = ct.on_response(asdu, &Known::EVERYTHING).unwrap().reaction;
        let done = matches!(reaction, Reaction::Terminated { .. });
        reactions.push(reaction);
        done
    });
    assert!(matches!(
        reactions[..],
        [
            Reaction::Confirmed {
                ioa: 0x0300,
                select: false,
                negative: false
            },
            Reaction::Terminated { ioa: 0x0300, .. }
        ]
    ));
}

/// 101 cl.7.4.9: a scaled parameter is confirmed with the value it carried;
/// parameter loading has no termination.
#[test]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
fn parameter_loading() {
    use iec104::asdu::Qpm;
    use iec104::pm::{LocalChange, Parameter, ParameterLoading, ParameterValue, Reaction};
    let _peer = spawn(24104);
    let mut master = Master::start(24104);
    let pm = ParameterLoading::controlling(LocalChange::NotUsed, CA, 0);
    let value = ParameterValue::Scaled {
        sva: Sva { value: 250 },
        qpm: Qpm::from_raw(1),
    };
    master.send(&pm.load(&Parameter::new(0x0400, value)).unwrap());
    let answers = master.until(|asdu| {
        matches!(
            pm.on_response(asdu, &Known::EVERYTHING).unwrap().reaction,
            Reaction::Confirmed { .. }
        )
    });
    assert_eq!(
        pm.on_response(answers.last().unwrap(), &Known::EVERYTHING)
            .unwrap()
            .reaction,
        Reaction::Confirmed {
            ioa: 0x0400,
            value,
            negative: false
        }
    );
}

/// 104 cl.7.10's time-tagged test command and 101 cl.7.4.6's clock
/// synchronisation, each answered positively.
#[test]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
fn test_command_and_clock_synchronisation() {
    use iec104::cs::{self, ClockSynchronisation};
    use iec104::ts::{self, Command, Selection, TestProcedure};
    let _peer = spawn(24105);
    let mut master = Master::start(24105);

    let test = TestProcedure::controlling(Selection::TAGGED, CA, 0);
    let sent = Command::Tagged {
        tsc: Tsc { value: 4242 },
        time: now_tag(),
    };
    master.send(&test.request(sent).unwrap());
    master.until(|asdu| {
        matches!(
            test.on_response(asdu, &Known::EVERYTHING, sent)
                .unwrap()
                .reaction,
            ts::Reaction::Answered {
                negative: false,
                ..
            }
        )
    });

    let clock = ClockSynchronisation::controlling(CA, 0);
    master.send(&clock.request(now_tag()).unwrap());
    master.until(|asdu| {
        matches!(
            clock
                .on_response(asdu, &Known::EVERYTHING)
                .unwrap()
                .reaction,
            cs::Reaction::Answered {
                negative: false,
                ..
            }
        )
    });
}

/// 101 cl.7.4.11 against lib60870's file server: select, call the file, call
/// each section, collect its segments, check each section's and the file's
/// checksum, and acknowledge. The file is the peer's: two sections of 400
/// octets, octet `i` of section `n` being `i * (n + 1)` (`full_server.c`).
#[test]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
fn file_transfer() {
    use iec104::ft::{Frame, ack, call_file, call_section, checksum, decode_frame, select_file};
    let _peer = spawn(24106);
    let mut master = Master::start(24106);
    let (ioa, nof) = (30000, Nof { value: 1 });
    let mut file = Vec::new();
    let mut section = Vec::new();
    master.send(&select_file(CA, 0, ioa, nof, Nos { value: 0 }).unwrap());
    let mut next: Option<Vec<u8>> = None;
    let mut done = false;
    while !done {
        if let Some(asdu) = next.take() {
            master.send(&asdu);
        }
        let asdu = master.until(|_| true).pop().unwrap();
        match decode_frame(&asdu).expect("a file-transfer frame") {
            Frame::FileReady { frq, .. } => {
                assert!(!frq.negative_confirm, "the file is ready");
                next = Some(call_file(CA, 0, ioa, nof, Nos { value: 0 }).unwrap());
            }
            Frame::SectionReady { nos, .. } => {
                next = Some(call_section(CA, 0, ioa, nof, nos).unwrap());
            }
            Frame::Segment { segment, .. } => section.extend_from_slice(segment.payload()),
            Frame::LastSection { nos, lsq, chs, .. } => match lsq.value {
                // Last segment of a section: its checksum, then the section ACK.
                3 => {
                    assert_eq!(checksum(&section), chs, "section {} checksum", nos.value);
                    file.append(&mut section);
                    let afq = Afq {
                        action: 3,
                        error: 0,
                    };
                    next = Some(ack(CA, 0, ioa, nof, nos, afq).unwrap());
                }
                // Last section of the file: the file's checksum, then the file ACK.
                1 => {
                    assert_eq!(checksum(&file), chs, "file checksum");
                    let afq = Afq {
                        action: 1,
                        error: 0,
                    };
                    master.send(&ack(CA, 0, ioa, nof, nos, afq).unwrap());
                    done = true;
                }
                other => panic!("unexpected LSQ {other}"),
            },
            other => panic!("unexpected frame {other:?}"),
        }
    }
    let expected: Vec<u8> = (0..2u32)
        .flat_map(|n| (0..400u32).map(move |i| (i * (n + 1)) as u8))
        .collect();
    assert_eq!(file, expected, "all 800 octets, in order");
}

/// 104 clause 10 against lib60870's single redundancy group: two connections,
/// one started; a manual switchover (stop 0, start 1) moves the data to 1.
#[test]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
fn redundancy_switchover() {
    use iec104::gi::{Interrogation, Reaction, Scope, SecondActivation};
    let _peer = spawn(24107);
    let t0 = Instant::now();
    let mut group = RedundancyGroup::uniform(Role::Controlling, LinkParams::default(), 2).unwrap();
    let mut streams = [dial(24107), dial(24107)];
    let mut decoders = [Decoder::new(), Decoder::new()];
    group.on_connection_established(0, t0).unwrap();
    group.on_connection_established(1, t0).unwrap();

    let perform = |streams: &mut [TcpStream; 2], routed: Vec<Routed>| {
        for Routed { member, actions } in routed {
            write(&mut streams[member], &actions);
        }
    };
    // Pumps both connections until `done` accepts a delivered ASDU of `on`.
    let pump = |group: &mut RedundancyGroup,
                streams: &mut [TcpStream; 2],
                decoders: &mut [Decoder; 2],
                on: usize,
                done: &mut dyn FnMut(&[u8]) -> bool| {
        let until = Instant::now() + Duration::from_secs(5);
        while Instant::now() < until {
            let now = Instant::now();
            let tick = group.tick(now);
            for Routed { member, actions } in tick.routed {
                write(&mut streams[member], &actions);
            }
            for member in 0..2 {
                for (apci, asdu) in read_frames(&mut streams[member], &mut decoders[member]) {
                    let routed = group.on_frame_at(member, apci, now).unwrap();
                    for Routed { member, actions } in routed {
                        write(&mut streams[member], &actions);
                    }
                    if member == on && matches!(apci, Apci::I { .. }) && done(&asdu) {
                        return;
                    }
                    if member == on && asdu.is_empty() && done(&[]) {
                        return;
                    }
                }
            }
        }
        panic!("timed out on connection {on}");
    };

    let mut gi = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut interrogate = |group: &mut RedundancyGroup,
                           streams: &mut [TcpStream; 2],
                           decoders: &mut [Decoder; 2],
                           on: usize| {
        let act = gi.request(Scope::Station).unwrap();
        perform(
            streams,
            group.send_user_data_at(on, &act, Instant::now()).unwrap(),
        );
        let mut data = 0;
        pump(group, streams, decoders, on, &mut |asdu| {
            match gi.on_response(asdu, &Known::EVERYTHING).map(|o| o.reaction) {
                Ok(Reaction::Interrogated { .. }) => data += 1,
                Ok(Reaction::Terminated { .. }) => return true,
                _ => {}
            }
            false
        });
        data
    };

    // Start connection 0; the peer's STARTDT con arrives on 0. The peer's GI
    // returns one object, so each interrogation counts 1.
    perform(&mut streams, group.start_at(0, t0).unwrap());
    pump(&mut group, &mut streams, &mut decoders, 0, &mut |_| true);
    assert_eq!(interrogate(&mut group, &mut streams, &mut decoders, 0), 1);

    // Manual switchover (figure 37): STOPDT on 0, then STARTDT on 1.
    perform(&mut streams, group.stop_at(0, Instant::now()).unwrap());
    pump(&mut group, &mut streams, &mut decoders, 0, &mut |_| true);
    assert_eq!(group.state(0), Ok(State::Stopped));
    perform(&mut streams, group.start_at(1, Instant::now()).unwrap());
    pump(&mut group, &mut streams, &mut decoders, 1, &mut |_| true);
    assert_eq!(group.state(1), Ok(State::Started));
    assert_eq!(interrogate(&mut group, &mut streams, &mut decoders, 1), 1);
}

// ------------------------------------------ the outstation, a lib60870 master

/// Every procedure's controlled station, behind `dispatch::route`, serving a
/// lib60870 master that sends GI, CI, a read, a select-before-operate single
/// command and set-point, a parameter, a test command, a clock
/// synchronisation and a reset-process command this station does not serve.
///
/// The expected lines are the peer's log format (`full_client.c`). The values
/// are the station's (`tests/station/mod.rs`): 1234 at IOA 258 (0x0102) for
/// GI, 4711 at IOA 512 (0x0200) for CI, -77 for the read. The unserved
/// `C_RP_NA_1` (105) comes back as 5-101 cl.7.2.3's cause-44 mirror.
#[test]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
fn the_outstation_serves_a_lib60870_master() {
    use std::net::TcpListener;

    let port = 24110;
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let client = peer_binary("IEC104_LIB60870_CLIENT", "full_client");
    let mut peer = Command::new(client)
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the peer starts");
    station::serve(
        &listener,
        &mut peer,
        iec104::ct::CommandMode::SelectAndExecute,
        Duration::from_secs(15),
    );
    let output = peer.wait_with_output().unwrap();
    let log = String::from_utf8_lossy(&output.stdout);
    println!("{log}");
    for expected in [
        "got type=100 cot=7 neg=0",
        "got type=11 cot=20 neg=0 n=1 ioa=258 value=1234",
        "got type=100 cot=10 neg=0",
        "got type=101 cot=7 neg=0",
        "got type=15 cot=37 neg=0 n=1 ioa=512 total=4711",
        "got type=101 cot=10 neg=0",
        "got type=11 cot=5 neg=0 n=1 ioa=258 value=-77",
        "got type=45 cot=7 neg=0",
        "got type=45 cot=10 neg=0",
        "got type=49 cot=7 neg=0",
        "got type=49 cot=10 neg=0",
        "got type=111 cot=7 neg=0",
        "got type=107 cot=7 neg=0",
        "got type=103 cot=7 neg=0",
        "got type=105 cot=44 neg=1",
        "done",
    ] {
        assert!(
            log.contains(expected),
            "missing `{expected}` in the peer's log"
        );
    }
    assert_eq!(
        log.matches("got type=45 cot=7 neg=0").count(),
        2,
        "select and execute both confirmed"
    );
}
