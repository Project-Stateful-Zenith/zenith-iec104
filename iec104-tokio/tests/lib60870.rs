//! The Tokio drivers against lib60870-C (MZ Automation, GPLv3), run as an
//! **external process** over TCP. The peers are the core crate's
//! `tests/lib60870/` ones, used as they are. No code of it is linked or
//! copied.
//!
//! - The async master against lib60870's outstation: counter interrogation,
//!   a set-point command, and a redundancy-group manual switchover.
//! - The procedure-level client against the same outstation: one of every
//!   call it offers.
//! - The async outstation, routed by `dispatch::route`, against lib60870's
//!   master: one of every request, and a type it does not serve.
//! - The server against the same master: the same requests, answered from
//!   its process image.
//!
//! The tests run on Tokio's multi-threaded runtime, as an application would,
//! so the drivers' tasks run in parallel against a real peer. Most other
//! async tests run on one thread, which their paused clock needs.
//!
//! Ignored by default. `scripts/interop.sh` builds the peers and runs this
//! with the others; by hand, after `scripts/interop-setup.sh`:
//!
//! ```text
//! cargo test -p iec104-tokio --test lib60870 -- --ignored --test-threads=1
//! ```
//!
//! `IEC104_LIB60870_SERVER` / `IEC104_LIB60870_CLIENT` point at peers built
//! elsewhere; `IEC104_LIB60870_VERBOSE=1` shows the peer's own log.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::as_conversions,
    clippy::cast_possible_truncation
)]

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use iec104::asdu::{Known, Qos, Sva};
use iec104::ct::CommandMode;
use iec104::link::{Role, State};
use iec104::manager::{ConnectionManager, StationConfig};
use iec104::params::LinkParams;
use iec104::redundancy::RedundancyGroup;
use iec104_tokio::{Event, Events, Handle, Options, TcpConnector, master, outstation};

mod station;

use station::{CA, Station};

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
                .join("..")
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

fn spawn_server(port: u16) -> Peer {
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

/// A t0 of 1 s (clause 9's minimum), so a dial that races the peer's listen
/// is retried at once rather than after the default 30 s.
fn params() -> LinkParams {
    LinkParams {
        t0: Duration::from_secs(1),
        ..LinkParams::default()
    }
}

async fn started(events: &mut Events, conn: usize) {
    until(events, |e| {
        *e == Event::State {
            conn,
            state: State::Started,
        }
    })
    .await;
}

async fn until(events: &mut Events, wanted: impl Fn(&Event) -> bool + Sync) -> Event {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let event = events.recv().await.expect("the driver runs");
            if wanted(&event) {
                return event;
            }
        }
    })
    .await
    .expect("in time")
}

/// Delivered ASDUs until `done` accepts one.
async fn collect(events: &mut Events, mut done: impl FnMut(&[u8]) -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await.expect("the driver runs") {
                Event::Asdu { asdu, .. } if done(&asdu) => return,
                Event::Disconnected { reason, .. } => panic!("the connection closed: {reason}"),
                _ => {}
            }
        }
    })
    .await
    .expect("the answer arrives in time");
}

/// A started connection to lib60870's outstation on `port`.
async fn one_master(port: u16) -> (Handle, Events) {
    let manager =
        ConnectionManager::new(Role::Controlling, vec![StationConfig::new(params())]).unwrap();
    let connector = TcpConnector::new(vec![format!("127.0.0.1:{port}")]);
    let (handle, mut events) = master::spawn(manager, connector, Options::default()).unwrap();
    started(&mut events, 0).await;
    (handle, events)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
async fn counter_interrogation() {
    use iec104::asdu::FreezeMode;
    use iec104::ci::{CounterInterrogation, CounterMode, Reaction, Request};
    let _peer = spawn_server(24201);
    let (handle, mut events) = one_master(24201).await;
    let mut ci = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, 0);
    handle
        .send_asdu(0, ci.request(Request::General, FreezeMode::Read).unwrap())
        .await
        .unwrap();
    let mut reactions = Vec::new();
    collect(&mut events, |asdu| {
        let reaction = ci.on_response(asdu, &Known::EVERYTHING).unwrap().reaction;
        let done = matches!(reaction, Reaction::Terminated { .. });
        reactions.push(reaction);
        done
    })
    .await;
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
    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
async fn set_point_command() {
    use iec104::ct::{
        Command, CommandMode, CommandSet, CommandTransmission, CommandValue, Reaction, Termination,
    };
    let _peer = spawn_server(24202);
    let (handle, mut events) = one_master(24202).await;
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
    handle
        .send_asdu(0, ct.execute(&command).unwrap())
        .await
        .unwrap();
    let mut reactions = Vec::new();
    collect(&mut events, |asdu| {
        let reaction = ct.on_response(asdu, &Known::EVERYTHING).unwrap().reaction;
        let done = matches!(reaction, Reaction::Terminated { .. });
        reactions.push(reaction);
        done
    })
    .await;
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
    handle.shutdown().await;
}

/// 104 clause 10 against lib60870's single redundancy group: two connections,
/// the first one started (10.3); a manual switchover (stop 0, start 1,
/// 10.2) moves the interrogation to the second.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
async fn redundancy_switchover() {
    use iec104::gi::{Interrogation, Reaction, Scope, SecondActivation};
    let _peer = spawn_server(24203);
    let group = RedundancyGroup::new(Role::Controlling, vec![params(), params()]).unwrap();
    let address = "127.0.0.1:24203".to_string();
    let connector = TcpConnector::new(vec![address.clone(), address]);
    // Started by hand: the two dials race, and the test starts member 0.
    let options = Options {
        auto_start: false,
        ..Options::default()
    };
    let (handle, mut events) = master::spawn_redundant(group, connector, options).unwrap();
    let mut up = [false; 2];
    while up != [true; 2] {
        if let Event::Connected { conn } =
            until(&mut events, |e| matches!(e, Event::Connected { .. })).await
        {
            up[conn] = true;
        }
    }
    handle.start(0).await.unwrap();
    started(&mut events, 0).await;

    let mut gi = Interrogation::controlling(SecondActivation::Locked, CA, 0);
    let mut interrogate = async |events: &mut Events, on: usize| {
        handle
            .send_asdu(0, gi.request(Scope::Station).unwrap())
            .await
            .unwrap();
        let mut data = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Event::Asdu { conn, asdu } = events.recv().await.unwrap() {
                    match gi
                        .on_response(&asdu, &Known::EVERYTHING)
                        .map(|o| o.reaction)
                    {
                        Ok(Reaction::Interrogated { .. }) => data.push(conn),
                        Ok(Reaction::Terminated { .. }) => return,
                        _ => {}
                    }
                }
            }
        })
        .await
        .expect("the interrogation completes");
        assert_eq!(data, [on], "the data came on connection {on}");
    };
    interrogate(&mut events, 0).await;

    handle.stop(0).await.unwrap();
    until(&mut events, |e| {
        *e == Event::State {
            conn: 0,
            state: State::Stopped,
        }
    })
    .await;
    handle.start(1).await.unwrap();
    started(&mut events, 1).await;
    interrogate(&mut events, 1).await;
    handle.shutdown().await;
}

// ------------------------------------------ the outstation, a lib60870 master

/// Every procedure's controlled station, behind `dispatch::route`, on the
/// async outstation, serving a lib60870 master that sends GI, CI, a read, a
/// select-before-operate single command and set-point, a parameter, a test
/// command, a clock synchronisation and a reset-process command this station
/// does not serve.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
async fn the_async_outstation_serves_a_lib60870_master() {
    let port = 24210;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    let group = RedundancyGroup::uniform(Role::Controlled, LinkParams::default(), 1).unwrap();
    let (handle, mut events) = outstation::spawn(group, Options::default()).unwrap();
    tokio::spawn(outstation::serve(listener, handle.clone()));

    let client = peer_binary("IEC104_LIB60870_CLIENT", "full_client");
    let mut peer = Command::new(client)
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the peer starts");
    let mut station = Station::new(CommandMode::SelectAndExecute);

    let until = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut poll = tokio::time::interval(Duration::from_millis(50));
    while tokio::time::Instant::now() < until {
        let event = tokio::select! {
            event = events.recv() => event.expect("the driver runs"),
            _ = poll.tick() => {
                if peer.try_wait().unwrap().is_some() {
                    break;
                }
                continue;
            }
        };
        let Event::Asdu { asdu, .. } = event else {
            continue;
        };
        for answer in station.answer(&asdu) {
            handle.send_asdu(0, answer).await.unwrap();
        }
    }
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
    handle.shutdown().await;
}

/// The client against lib60870's outstation, one call of each kind. The
/// expected values are the peer's own (`tests/lib60870/full_server.c`): a
/// station interrogation answered with a scaled value of 1234 at 0x0102, a
/// general counter request with a reading of 4711 at 0x0200, a read answered
/// with a scaled value of -77, commands confirmed and terminated, and a clock
/// synchronisation confirmed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
async fn client_runs_every_procedure() {
    use iec104::asdu::{Cp56Time2a, FreezeMode, Objects};
    use iec104::ci::Request;
    use iec104::ct::Command;
    use iec104::gi::Scope;
    use iec104_tokio::client::{Client, ClientConfig, CommandOutcome};

    let _peer = spawn_server(24220);
    let config = ClientConfig {
        link: params(),
        interrogate_on_start: false,
        ..ClientConfig::new(CA)
    };
    let connector = TcpConnector::new(vec!["127.0.0.1:24220".into()]);
    let client = tokio::time::timeout(Duration::from_secs(10), Client::connect(connector, config))
        .await
        .expect("started in time")
        .unwrap();

    let image = client.interrogate(Scope::Station).await.unwrap();
    let [asdu] = image.as_slice() else {
        panic!("one ASDU, got {image:?}");
    };
    let Objects::MMeNb1(objects) = &asdu.objects else {
        panic!("not M_ME_NB_1: {:?}", asdu.objects.type_id());
    };
    assert_eq!((objects[0].ioa, objects[0].value.sva.value), (0x0102, 1234));

    let totals = client
        .counter_interrogate(Request::General, FreezeMode::Read)
        .await
        .unwrap();
    let Objects::MItNa1(objects) = &totals[0].objects else {
        panic!("not M_IT_NA_1: {:?}", totals[0].objects.type_id());
    };
    assert_eq!(
        (objects[0].ioa, objects[0].value.bcr.reading),
        (0x0200, 4711)
    );

    assert_eq!(
        client
            .command(Command::set_point_scaled(0x0300, -1234))
            .await,
        Ok(CommandOutcome::Terminated)
    );
    assert_eq!(
        client.command(Command::single(0x0301, true)).await,
        Ok(CommandOutcome::Terminated)
    );

    let read = client.read(0x0400).await.unwrap();
    let Objects::MMeNb1(objects) = &read.objects else {
        panic!("not M_ME_NB_1: {:?}", read.objects.type_id());
    };
    assert_eq!((objects[0].ioa, objects[0].value.sva.value), (0x0400, -77));

    // 2026-09-28 12:34:56.789 (5-101 cl.7.2.6.18).
    let time = Cp56Time2a::parse(&[0xD5, 0xDD, 34, 12, 0x20 | 0x1C, 9, 26]).unwrap();
    assert_eq!(client.sync_clock(time).await, Ok(()));

    client.shutdown().await;
}

// ------------------------------------------------ the server, a lib60870 master

/// The server's application for [`the_server_serves_a_lib60870_master`]:
/// every command operates at once.
struct Operates;

impl iec104_tokio::server::Application for Operates {
    fn operate(&self, _command: iec104::ct::Command) -> impl Future<Output = bool> + Send {
        std::future::ready(true)
    }
}

/// The server against the lib60870 master `tests/lib60870/full_client.c`,
/// which sends the requests listed with
/// [`the_async_outstation_serves_a_lib60870_master`]. The server holds a
/// scaled value 1234 at address 258 (`0x0102`) and a counter 4711 at 512
/// (`0x0200`), takes a single command at `0x0500` and a scaled set-point at
/// `0x0300` (select and execute), and serves neither parameter loading nor
/// the reset process. The expected lines are the peer's own printout of what
/// it received: the end of initialisation, the interrogations with their
/// confirmations and terminations, the read, both commands' confirmations and
/// terminations, the test and the clock synchronisation's confirmations, and
/// the cause 44 mirror for the parameter and the reset process.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the lib60870 peer (see this file's module doc)"]
async fn the_server_serves_a_lib60870_master() {
    use iec104::asdu::Value;
    use iec104::ct::Family;
    use iec104_tokio::server::{PointConfig, Server, ServerConfig};

    let port = 24212;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .unwrap();
    let mut config = ServerConfig::new(CA)
        .point(0x0102, PointConfig::new(Value::Scaled(1234)).untagged())
        .point(
            0x0200,
            PointConfig::new(Value::Counter {
                reading: 4711,
                sequence: 0,
                carry: false,
                adjusted: false,
            })
            .untagged(),
        )
        .command(0x0500, Family::Single)
        .command(0x0300, Family::SetPointScaled);
    config.command_mode = CommandMode::SelectAndExecute;
    let server = Server::spawn(config, Operates).unwrap();
    tokio::spawn(server.clone().serve(listener));

    let client = peer_binary("IEC104_LIB60870_CLIENT", "full_client");
    let peer = Command::new(client)
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("the peer starts");
    let output = tokio::task::spawn_blocking(move || peer.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    let log = String::from_utf8_lossy(&output.stdout);
    println!("{log}");
    for expected in [
        "got type=70 cot=4 neg=0",
        "got type=100 cot=7 neg=0",
        "got type=11 cot=20 neg=0 n=1 ioa=258 value=1234",
        "got type=100 cot=10 neg=0",
        "got type=101 cot=7 neg=0",
        "got type=15 cot=37 neg=0 n=1 ioa=512 total=4711",
        "got type=101 cot=10 neg=0",
        "got type=11 cot=5 neg=0 n=1 ioa=258 value=1234",
        "got type=45 cot=7 neg=0",
        "got type=45 cot=10 neg=0",
        "got type=49 cot=7 neg=0",
        "got type=49 cot=10 neg=0",
        "got type=111 cot=44 neg=1",
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
    server.shutdown().await;
}
