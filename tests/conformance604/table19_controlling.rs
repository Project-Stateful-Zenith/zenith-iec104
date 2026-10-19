//! 604 Table 19, *"Command transmission function conformance test
//! procedures"*, PDF page indices 70–78 (printed 69–77): the
//! **controlling**-station half. The rows, the command sets and the octet
//! builders are those of [`crate::conformance604::table19`].
//!
//! # The station under test
//!
//! The DUT is the interoperability harness's `interop::Station` (this library's
//! `link::Session` in `Role::Controlling`) with `ct::CommandTransmission` in the
//! controlling role deciding what goes on the wire and what each answer means.
//! The mock controlled station, [`ScriptPeer`], answers from a script the case
//! writes out: every frame it sends is spelled from the row (the request
//! mirrored with the row's cause, or a return information built octet by octet
//! from 5-101 clause 7.3.1), never produced by the crate's controlled role.
//!
//! # Direction
//!
//! §5.1 swaps the roles; a command is only ever sent by the controlling station
//! (5-101 clause 7.3.2), so this is the procedure seen from the other end, not
//! commands in the monitor direction. The mock sends cause 47 in
//! `5.4.19.30`; that is a monitor-direction cause, as §5.1's COT44-47 exception
//! requires.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::conformance604::interop::Station;
use crate::conformance604::table19::{
    TAGGED, command, command_at, controllable, fails_after_accept, mirrored, not_controllable,
    not_existing, return_types, selectable, set_types, tag_time, time_at,
};
use crate::conformance604::{CA, asdu_with_body, deadline, parse_frame};
use iec104::apci::{Apci, UFunction};
use iec104::asdu::{Cp56Time2a, Discard, Header, Known, read_ioa};
use iec104::ct::{
    Command, CommandMode, CommandSet, CommandTransmission, CtError, Reaction, ReturnInfo,
    Termination, decode_command,
};
use iec104::framed::Decoder;
use iec104::gi::{Interrogation, Reaction as GiReaction, Scope, SecondActivation};
use iec104::link::{Role, Session};

// ----------------------------------------------------------- the mock peer

/// What the mock controlled station answers to one ASDU it received.
pub type Script = Box<dyn FnMut(&[u8]) -> Vec<Vec<u8>> + Send>;

/// The mock **controlled** station: it completes the STARTDT exchange (5-104
/// clause 5.3) with its own `link::Session`, and answers every ASDU it receives
/// with the frames its [`Script`] spells out. It records every ASDU it
/// received.
pub struct ScriptPeer {
    addr: SocketAddr,
    handle: JoinHandle<Result<Vec<Vec<u8>>, String>>,
}

impl ScriptPeer {
    /// Binds a loopback port and starts the accepting thread.
    pub fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let handle = thread::spawn(move || match listener.accept() {
            Ok((stream, _)) => serve_script(stream, script),
            Err(e) => Err(format!("accept: {e}")),
        });
        Self { addr, handle }
    }

    /// Waits for the thread, which ends when the station closes the socket,
    /// and returns the ASDUs the peer received.
    pub fn join(self) -> Vec<Vec<u8>> {
        self.handle
            .join()
            .expect("the script peer panicked")
            .expect("the script peer ends cleanly")
    }
}

/// The peer's loop: its session answers the frames, its script the ASDUs.
fn serve_script(mut stream: TcpStream, mut script: Script) -> Result<Vec<Vec<u8>>, String> {
    stream
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    let mut session = Session::new(Role::Controlled);
    session.on_connection_established();
    let mut decoder = Decoder::new();
    let mut received = Vec::new();
    let mut owed: Vec<Vec<u8>> = Vec::new();
    loop {
        // What the script owes goes out while the window allows it.
        while let Some(asdu) = owed.first() {
            let Some(action) = session.send_i_frame(asdu) else {
                break;
            };
            write(&mut stream, &action)?;
            owed.remove(0);
        }
        let mut buf = [0u8; 1024];
        match stream.read(&mut buf) {
            Ok(0) => return Ok(received),
            Ok(n) => decoder.push(&buf[..n]),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(format!("read: {e}")),
        }
        while let Some(frame) = decoder
            .next_frame()
            .map_err(|e| format!("framing: {e}"))?
            .map(<[u8]>::to_vec)
        {
            let (apci, asdu) = parse_frame(&frame)?;
            for action in session.on_frame(apci) {
                write(&mut stream, &action)?;
            }
            if apci.is_i_format() {
                owed.extend(script(&asdu));
                received.push(asdu);
            }
        }
    }
}

fn write(stream: &mut TcpStream, action: &iec104::link::Action) -> Result<(), String> {
    let mut octets = Vec::new();
    crate::conformance604::interop::encode_action(action, &mut octets)?;
    if !octets.is_empty() {
        stream
            .write_all(&octets)
            .map_err(|e| format!("write: {e}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------- the DUT

/// The controlling station under test: the harness's driver plus the crate's
/// command procedure.
pub struct Dut {
    station: Station,
    /// The command procedure in the controlling role.
    pub ct: CommandTransmission,
}

impl Dut {
    /// Connects to `peer` and completes the STARTDT exchange (5-104 clause
    /// 5.3), as a station of `mode` using the command set `set`.
    pub fn open(peer: &ScriptPeer, mode: CommandMode, set: CommandSet) -> Self {
        let mut station = Station::connect(peer.addr).expect("the DUT connects");
        let actions = station.session_mut().request_start();
        station.send_actions(&actions).expect("STARTDT act");
        station
            .expect("STARTDT con", deadline(5), |apci, _| {
                apci == Apci::U(UFunction::StartDtCon)
            })
            .expect("5-104 cl.5.3: the STARTDT exchange");
        let ct = CommandTransmission::controlling(mode, set, Termination::All, CA, 0);
        Self { station, ct }
    }

    /// Puts one ASDU the crate built on the wire.
    pub fn send(&mut self, asdu: &[u8]) {
        let action = self
            .station
            .session_mut()
            .send_i_frame(asdu)
            .expect("5-104 cl.5.3: data transfer is started");
        self.station.send_actions(&[action]).expect("the I-frame");
    }

    /// The next ASDU the peer sent.
    pub fn next(&mut self, what: &str) -> Vec<u8> {
        self.station
            .expect(what, deadline(5), |apci, _| apci.is_i_format())
            .unwrap_or_else(|e| panic!("{e}"))
            .1
    }

    /// The crate's reading of the next ASDU the peer sent. The station's own
    /// profile: its common address, every object address.
    pub fn react(&mut self, what: &str) -> Reaction {
        let asdu = self.next(what);
        let header = Header::parse(&asdu).expect("the answer's header");
        let known = Known::standard(&header, header.common_address == CA, true);
        self.ct
            .on_response(&asdu, &known)
            .unwrap_or_else(|e| panic!("{what}: {e:?}"))
            .reaction
    }

    /// Closes the connection and returns what the peer received.
    pub fn close(self, peer: ScriptPeer) -> Vec<Vec<u8>> {
        self.station.close().expect("the DUT closes");
        peer.join()
    }
}

/// The command value [`command`] spells for `type_id` at `ioa`, as the
/// application hands it to the crate.
fn value(type_id: u8, ioa: u32) -> Command {
    decode_command(&command(type_id, ioa, false))
        .expect("the request decodes")
        .expect("the request is a command")
}

// ------------------------------------------------------- the peer's frames

/// Whether a request carries `S/E = 1`: the type's `S/E` octet (5-101 clause
/// 7.2.6.26/.39), bit 8.
fn is_select(request: &[u8]) -> bool {
    crate::conformance604::table19::se_offset(request[0])
        .is_some_and(|at| request[Header::LEN + 3 + at] & 0x80 != 0)
}

/// The return information for a command request, octet by octet (5-101 clause
/// 7.3.1): `M_SP_NA_1` with `SPI` ON (`0x01`), `M_DP_NA_1` with `DPI` ON
/// (`0x02`), `M_ST_NA_1` with `VTI` 1 and `QDS` 0, or their `CP56Time2a`
/// forms 30, 31 and 32 with [`tag_time`] behind the element, at the command's
/// address and with `cause`. `None` for the families 5-104 clause 7.7 does not
/// return.
fn return_frame(request: &[u8], cause: u8) -> Option<Vec<u8>> {
    let types = return_types(request[0])?;
    let tagged = TAGGED.contains(&request[0]);
    let type_id = if tagged { types[2] } else { types[0] };
    let mut body = request[Header::LEN..Header::LEN + 3].to_vec();
    match types[0] {
        1 => body.push(0x01),
        3 => body.push(0x02),
        _ => body.extend_from_slice(&[0x01, 0x00]),
    }
    if tagged {
        tag_time().encode(&mut body);
    }
    Some(asdu_with_body(type_id, cause, CA, &body))
}

/// The cause and the order the peer's return information takes for one type:
/// the row permits *"COT=3, 11, or 12"* and *"regardless of the order in which
/// they occur"*, so the types rotate through the three causes and alternate
/// the order.
fn return_plan(type_id: u8) -> (u8, bool) {
    (
        [11, 12, 3][usize::from(type_id % 3)],
        type_id.is_multiple_of(2),
    )
}

/// The script of a positive controlled station: a select is mirrored with
/// cause 7; an execute is mirrored with cause 7 and followed by its `ACTTERM`
/// (cause 10) and its return information in [`return_plan`]'s order; a
/// deactivation is mirrored with cause 9.
fn positive_script() -> Script {
    Box::new(|request: &[u8]| match request[2] & 0x3F {
        6 if is_select(request) => vec![mirrored(request, 7, false)],
        6 => {
            let (cause, returned_first) = return_plan(request[0]);
            let mut out = vec![mirrored(request, 7, false)];
            let term = mirrored(request, 10, false);
            match return_frame(request, cause) {
                Some(info) if returned_first => out.extend([info, term]),
                Some(info) => out.extend([term, info]),
                None => out.push(term),
            }
            out
        }
        8 => vec![mirrored(request, 9, false)],
        _ => Vec::new(),
    })
}

/// Reads the answers that complete an execute (its `ACTTERM`, and the return
/// information where one is owed, in either order) and asserts the crate's
/// reading of each.
fn expect_completion(dut: &mut Dut, type_id: u8, ioa: u32, row: &str) {
    let (cause, _) = return_plan(type_id);
    let owed = if return_types(type_id).is_some() {
        2
    } else {
        1
    };
    let mut seen = Vec::new();
    for _ in 0..owed {
        seen.push(dut.react(&format!("{row} (type {type_id}): the completion")));
    }
    assert!(
        seen.contains(&Reaction::Terminated {
            ioa,
            negative: false
        }),
        "{row} (type {type_id}): the ACTTERM is classified as the end, got {seen:?}"
    );
    if return_types(type_id).is_some() {
        let info = ReturnInfo::from_cause(iec104::asdu::Cause::from_u8(cause))
            .expect("3, 11 and 12 are return causes");
        assert!(
            seen.contains(&Reaction::Returned { ioa, info }),
            "{row} (type {type_id}): the RETURN_INF with COT {cause} is the status change, got \
             {seen:?}"
        );
    }
    assert!(
        !dut.ct.is_running(ioa) && !dut.ct.is_selected(ioa),
        "{row} (type {type_id}): nothing is left outstanding"
    );
}

// ------------------------------------------------------------------- 5.4.19.1

/// 604 Table 19 (1 of 9), PDF page index 70 (printed 69), procedure
/// **`5.4.19.1`**, *"Select and Execute"*, `Reference` `IEC 60870-5-101:2003,
/// 7.4.7`, the controlling station's steps (`M`):
///
/// > The Controlling station sends a Single, Double, Regulating step or Setpoint
/// > Command message … with COT = 6, C_SC/DC/SE/RC_ACT, and S/E=1 (SELECT) to the
/// > Controlled station
/// >
/// > The Controlling station sends the same Command message with COT=6,
/// > C_SC/DC/SE/RC_ACT, and S/E=0 (EXECUTE) to the Controlled station
///
/// and *"The Controlling station performs an overall check on the correct
/// command procedure and corresponding status change, regardless of the order
/// in which they occur"*, with the `RETURN_INF` sent *"with COT=3, 11, or 12"*.
///
/// DUT: the **controlling** station, both sets, the six selectable types. The
/// select and the execute on the wire are [`command`]'s octets with `S/E` 1 and
/// 0; the peer mirrors each and sends the `ACTTERM` and a return information,
/// its cause and position rotating per type ([`return_plan`]).
#[test]
fn clause_5_4_19_1_the_controlling_station_selects_and_executes() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let peer = ScriptPeer::start(positive_script());
        let mut dut = Dut::open(&peer, CommandMode::SelectAndExecute, set);
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            let ioa = controllable(type_id);
            let select = dut.ct.select(&value(type_id, ioa)).expect("the select");
            assert_eq!(
                select,
                command(type_id, ioa, true),
                "5.4.19.1 (type {type_id}): \"with COT = 6 … and S/E=1 (SELECT)\""
            );
            dut.send(&select);
            assert_eq!(
                dut.react("5.4.19.1: the select's ACTCON"),
                Reaction::Confirmed {
                    ioa,
                    select: true,
                    negative: false
                },
                "5.4.19.1 (type {type_id}): the mirrored select"
            );
            let execute = dut.ct.execute(&value(type_id, ioa)).expect("the execute");
            assert_eq!(
                execute,
                command(type_id, ioa, false),
                "5.4.19.1 (type {type_id}): \"the same Command message with COT=6 … and S/E=0\""
            );
            dut.send(&execute);
            assert_eq!(
                dut.react("5.4.19.1: the execute's ACTCON"),
                Reaction::Confirmed {
                    ioa,
                    select: false,
                    negative: false
                },
                "5.4.19.1 (type {type_id}): the mirrored execute"
            );
            expect_completion(&mut dut, type_id, ioa, "5.4.19.1");
        }
        dut.close(peer);
    }
}

/// 604 Table 19 (2 of 9), PDF page index 71 (printed 70), procedure
/// `5.4.19.1`, `Reference` `IEC 60870-5-101:2003, 7.4.7` and `7.2.1`,
/// `Required` `M`:
///
/// > If the SELECT message from the Controlling station is not correctly
/// > mirrored by the Controlled station, then the Controlling station does not
/// > proceed with sending the EXECUTE message
///
/// DUT: the **controlling** station, both sets, the six selectable types. The
/// peer confirms each select with another command value ([`altered`]); the
/// crate reports the broken mirror and refuses the execute, and the peer
/// receives nothing but the selects.
///
/// [`altered`]: crate::conformance604::table19::altered
#[test]
fn clause_5_4_19_1_a_select_not_correctly_mirrored_is_not_executed() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let script: Script = Box::new(|request: &[u8]| {
            vec![crate::conformance604::table19::altered(&mirrored(
                request, 7, false,
            ))]
        });
        let peer = ScriptPeer::start(script);
        let mut dut = Dut::open(&peer, CommandMode::SelectAndExecute, set);
        let types: Vec<u8> = set_types(set)
            .into_iter()
            .filter(|t| selectable(*t))
            .collect();
        for &type_id in &types {
            let ioa = controllable(type_id);
            let select = dut.ct.select(&value(type_id, ioa)).expect("the select");
            dut.send(&select);
            assert_eq!(
                dut.react("5.4.19.1: the wrong mirror"),
                Reaction::NotMirrored { ioa },
                "5.4.19.1 (type {type_id}): the mirror does not repeat the select"
            );
            assert_eq!(
                dut.ct.execute(&value(type_id, ioa)),
                Err(CtError::ExecuteWithoutSelect { ioa }),
                "5.4.19.1 (type {type_id}): \"does not proceed with sending the EXECUTE message\""
            );
        }
        let received = dut.close(peer);
        assert_eq!(
            received.len(),
            types.len(),
            "5.4.19.1 ({set:?}): the peer received the selects and nothing else"
        );
        assert!(
            received.iter().all(|asdu| is_select(asdu)),
            "5.4.19.1 ({set:?}): no execute went out"
        );
    }
}

// ------------------------------------------------------------------ 5.4.19.10

/// 604 Table 19 (3 of 9), PDF page index 72 (printed 71), procedure
/// **`5.4.19.10`**, *"Select and Deactivation"*, `Reference`
/// `IEC 60870-5-101:2003, 7.4.7`, `Required` `M`:
///
/// > The Controlling station sends the same Command message with COT=8,
/// > C_SC/DC/SE/RC_DEACT, and S/E=1 (SELECT) to the Controlled station
/// >
/// > Both the Controlling and Controlled stations have deactivated the Command
/// > transmission procedure
///
/// DUT: the **controlling** station, both sets, the six selectable types. The
/// deactivation on the wire is the select with only its cause changed to 8;
/// after the peer's `DEACTCON` (cause 9) the crate holds no select and refuses
/// an execute.
#[test]
fn clause_5_4_19_10_the_controlling_station_deactivates_a_select() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let peer = ScriptPeer::start(positive_script());
        let mut dut = Dut::open(&peer, CommandMode::SelectAndExecute, set);
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            let ioa = controllable(type_id);
            let select = dut.ct.select(&value(type_id, ioa)).expect("the select");
            dut.send(&select);
            assert!(matches!(
                dut.react("5.4.19.10: the select's ACTCON"),
                Reaction::Confirmed {
                    select: true,
                    negative: false,
                    ..
                }
            ));
            let deact = dut.ct.deactivate(&value(type_id, ioa)).expect("the DEACT");
            assert_eq!(
                deact,
                mirrored(&command(type_id, ioa, true), 8, false),
                "5.4.19.10 (type {type_id}): \"the same Command message with COT=8 … and S/E=1\""
            );
            dut.send(&deact);
            assert_eq!(
                dut.react("5.4.19.10: the DEACTCON"),
                Reaction::Deactivated { ioa },
                "5.4.19.10 (type {type_id}): the DEACTCON"
            );
            assert!(
                !dut.ct.is_selected(ioa),
                "5.4.19.10 (type {type_id}): \"have deactivated the Command transmission procedure\""
            );
            assert_eq!(
                dut.ct.execute(&value(type_id, ioa)),
                Err(CtError::ExecuteWithoutSelect { ioa }),
                "5.4.19.10 (type {type_id}): nothing is left to execute"
            );
        }
        dut.close(peer);
    }
}

// ------------------------------------------------------------------ 5.4.19.20

/// 604 Table 19 (4 of 9), PDF page index 73 (printed 72), procedure
/// **`5.4.19.20`**, *"Direct Execute"*, `Reference` `IEC 60870-5-101:2003,
/// 7.4.7`, `Required` `M`:
///
/// > The Controlling station sends a Single, Double, Regulating step, Setpoint or
/// > Bitstring Command message … with COT = 6, C_SC/DC/SE/RC_ACT and S/E=0
/// > (EXECUTE) to the Controlled station
///
/// DUT: the **controlling** station of the direct-execute function, both sets,
/// all seven types. The peer mirrors, terminates and returns as in
/// `5.4.19.1`.
#[test]
fn clause_5_4_19_20_the_controlling_station_executes_directly() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let peer = ScriptPeer::start(positive_script());
        let mut dut = Dut::open(&peer, CommandMode::Direct, set);
        for type_id in set_types(set) {
            let ioa = controllable(type_id);
            let execute = dut.ct.execute(&value(type_id, ioa)).expect("the execute");
            assert_eq!(
                execute,
                command(type_id, ioa, false),
                "5.4.19.20 (type {type_id}): \"with COT = 6 … and S/E=0 (EXECUTE)\""
            );
            dut.send(&execute);
            assert_eq!(
                dut.react("5.4.19.20: the ACTCON"),
                Reaction::Confirmed {
                    ioa,
                    select: false,
                    negative: false
                },
                "5.4.19.20 (type {type_id}): the mirrored execute"
            );
            expect_completion(&mut dut, type_id, ioa, "5.4.19.20");
        }
        dut.close(peer);
    }
}

// ------------------------------------------------------------------ 5.4.19.30

/// 604 Table 19 (5 of 9), PDF page index 74 (printed 73), procedure
/// **`5.4.19.30`**, *"Select with Negative Confirmation by Controlled station
/// (Abort)"*, `Reference` `IEC 60870-5-101:2003, 7.4.7`:
///
/// > The Controlling station stops the Command function with an indication at
/// > user level
///
/// (`Required` `PIXIT`), after the controlled station's *"`C_SC/DC/SE/RC_ACTCONneg`
/// (Negative ACTCON)"* or, for a not existing object, its mirror *"with COT=47
/// (unknown Information Object Address)"*.
///
/// DUT: the **controlling** station, both sets, the six selectable types, one
/// select answered each way. The indication the crate gives is the negative
/// confirmation (or clause 7.2.3's discard of the cause-47 mirror); the command
/// function is stopped: no select is left and no execute can be sent.
#[test]
fn clause_5_4_19_30_a_negative_select_confirmation_stops_the_command() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let script: Script = Box::new(|request: &[u8]| {
            let ioa = read_ioa(&request[Header::LEN..]).expect("the address");
            let cause = if ioa >> 12 == 0x5 { 47 } else { 7 };
            vec![mirrored(request, cause, true)]
        });
        let peer = ScriptPeer::start(script);
        let mut dut = Dut::open(&peer, CommandMode::SelectAndExecute, set);
        for type_id in set_types(set).into_iter().filter(|t| selectable(*t)) {
            for (ioa, expected) in [
                (
                    not_controllable(type_id),
                    Reaction::Confirmed {
                        ioa: not_controllable(type_id),
                        select: true,
                        negative: true,
                    },
                ),
                (not_existing(type_id), Reaction::Discard(Discard::Mirror)),
            ] {
                let select = dut.ct.select(&value(type_id, ioa)).expect("the select");
                dut.send(&select);
                assert_eq!(
                    dut.react("5.4.19.30: the negative answer"),
                    expected,
                    "5.4.19.30 (type {type_id}, IOA {ioa:#x}): the indication"
                );
                assert!(
                    !dut.ct.is_awaiting(ioa) && !dut.ct.is_selected(ioa),
                    "5.4.19.30 (type {type_id}): \"stops the Command function\""
                );
                assert_eq!(
                    dut.ct.execute(&value(type_id, ioa)),
                    Err(CtError::ExecuteWithoutSelect { ioa }),
                    "5.4.19.30 (type {type_id}): no execute follows a refused select"
                );
            }
        }
        dut.close(peer);
    }
}

// ------------------------------------------------------------ 5.4.19.40/.50

/// 604 Table 19 (6 of 9), PDF page index 75 (printed 74), procedure
/// **`5.4.19.40`**, and (7 of 9), index 76, procedure **`5.4.19.50`**,
/// `Reference` `IEC 60870-5-101:2003, 7.4.7` and `7.2.3`: the controlled
/// station answers the execute with *"COT=7, `C_SC/DC/SE/RC_ACTCONneg` (Negative
/// ACTCON)"*, or (PIXIT) *"first accept the command with a Positive ACTCON and
/// then send a Negative Termination by mirroring the previous Command message
/// with COT=10 … and P/N=1"*, and
///
/// > The Controlling station stops the Command function with an indication at
/// > user level
///
/// (`Required` `PIXIT`). DUT: the **controlling** station, both sets, as a
/// select-and-execute station (the six selectable types, select first:
/// `5.4.19.40`) and as a direct-execute station (all seven: `5.4.19.50`). Each
/// execute is refused once each way; the crate reports the negative answer and
/// nothing is left running.
#[test]
fn clause_5_4_19_40_and_50_a_refused_execute_stops_the_command() {
    let script = || -> Script {
        Box::new(|request: &[u8]| {
            let ioa = read_ioa(&request[Header::LEN..]).expect("the address");
            match (request[2] & 0x3F, is_select(request), ioa >> 12) {
                (6, true, _) => vec![mirrored(request, 7, false)],
                (6, false, 0x6) => vec![mirrored(request, 7, false), mirrored(request, 10, true)],
                (6, false, _) => vec![mirrored(request, 7, true)],
                _ => Vec::new(),
            }
        })
    };
    for mode in [CommandMode::SelectAndExecute, CommandMode::Direct] {
        for set in [CommandSet::Untagged, CommandSet::Tagged] {
            let peer = ScriptPeer::start(script());
            let mut dut = Dut::open(&peer, mode, set);
            for type_id in set_types(set) {
                if mode == CommandMode::SelectAndExecute && !selectable(type_id) {
                    continue;
                }
                for ioa in [not_controllable(type_id), fails_after_accept(type_id)] {
                    let command = value(type_id, ioa);
                    if mode == CommandMode::SelectAndExecute {
                        let select = dut.ct.select(&command).expect("the select");
                        dut.send(&select);
                        assert!(matches!(
                            dut.react("5.4.19.40: the select's ACTCON"),
                            Reaction::Confirmed {
                                select: true,
                                negative: false,
                                ..
                            }
                        ));
                    }
                    let execute = dut.ct.execute(&command).expect("the execute");
                    dut.send(&execute);
                    let first = dut.react("5.4.19.40/.50: the execute's ACTCON");
                    if ioa >> 12 == 0x6 {
                        assert_eq!(
                            first,
                            Reaction::Confirmed {
                                ioa,
                                select: false,
                                negative: false
                            },
                            "5.4.19.40/.50 ({mode:?}, type {type_id}): the positive ACTCON"
                        );
                        assert_eq!(
                            dut.react("5.4.19.40/.50: the negative ACTTERM"),
                            Reaction::Terminated {
                                ioa,
                                negative: true
                            },
                            "5.4.19.40/.50 ({mode:?}, type {type_id}): the negative termination \
                             is told apart from a positive one"
                        );
                    } else {
                        assert_eq!(
                            first,
                            Reaction::Confirmed {
                                ioa,
                                select: false,
                                negative: true
                            },
                            "5.4.19.40/.50 ({mode:?}, type {type_id}): the ACTCONneg"
                        );
                    }
                    assert!(
                        !dut.ct.is_running(ioa),
                        "5.4.19.40/.50 ({mode:?}, type {type_id}): \"stops the Command function\""
                    );
                }
            }
            dut.close(peer);
        }
    }
}

// ------------------------------------------------------------------ 5.4.19.60

/// 604 Table 19 (8 of 9), PDF page index 77 (printed 76), procedure
/// **`5.4.19.60`**, *"Command transmission with network delay supervision"*,
/// `Reference` `IEC 60870-5-104:2006, 8`, `Required` `M`:
///
/// > The Controlling station sends a Single, Double, Regulating step, Setpoint or
/// > Bitstring Command message with time tag (look at PICS for the supported
/// > ASDU's with time tag CP56Time2a) containing the time of command initiation
/// > to the Controlled station
/// >
/// > The time label in the Command message from the Controlling station
/// > represents the time of initiation (plausibility test)
///
/// DUT: the **controlling** station of the time-tagged set, all seven types as a
/// direct execute and the six selectable ones as a select. The application
/// initiates each command at 12:34:56.789 on 2026-09-25 and the crate must put
/// exactly that time on the wire: 5-101 clause 7.2.6.18's octets, milliseconds
/// `56789` = `D5 DD` (low octet first), minutes `22`, hours `0C`, day of month
/// 25 with day of week 5 (Friday) in bits 6–8 = `B9`, months `09`, years `1A`.
#[test]
fn clause_5_4_19_60_the_time_tag_is_the_time_of_initiation() {
    const OCTETS: [u8; 7] = [0xD5, 0xDD, 0x22, 0x0C, 0xB9, 0x09, 0x1A];

    let initiated: Cp56Time2a = time_at(12, 34, 56_789, false);
    for mode in [CommandMode::Direct, CommandMode::SelectAndExecute] {
        let peer = ScriptPeer::start(Box::new(|_: &[u8]| Vec::new()));
        let mut dut = Dut::open(&peer, mode, CommandSet::Tagged);
        let mut sent = Vec::new();
        for type_id in set_types(CommandSet::Tagged) {
            let select = mode == CommandMode::SelectAndExecute;
            if select && !selectable(type_id) {
                continue;
            }
            let ioa = controllable(type_id);
            let mut command = value(type_id, ioa);
            command.time = Some(initiated);
            let frame = if select {
                dut.ct.select(&command)
            } else {
                dut.ct.execute(&command)
            }
            .expect("the command");
            assert_eq!(
                frame[frame.len() - 7..],
                OCTETS,
                "5.4.19.60 ({mode:?}, type {type_id}): the tag is the time of initiation"
            );
            assert_eq!(
                frame,
                command_at(type_id, ioa, select, initiated),
                "5.4.19.60 ({mode:?}, type {type_id}): the whole command"
            );
            dut.send(&frame);
            sent.push(frame);
        }
        let received = dut.close(peer);
        assert_eq!(
            received, sent,
            "5.4.19.60 ({mode:?}): the peer received the tagged commands as built"
        );
    }
}

// ------------------------------------------------------------------ 5.4.19.85

/// 604 Table 19 (9 of 9), PDF page index 78 (printed 77), procedure
/// **`5.4.19.85`**, `Reference` `IEC 60870-5-104:2006, 9.5`, `Required`
/// `PICS, 9.5`:
///
/// > Either the ASDUs of the set <45> – <51> or of the set <58> – <64> are used
/// > or configured at the same time
///
/// and 5-104 Table 2's sentence (PDF page index 50): *"Process information in
/// control direction may be sent with or without a time tag but must not be
/// mixed when sending to a given station."* DUT: the **controlling** station,
/// each set against every type of the other, as a select and as an execute:
/// the crate refuses to build the command, and the peer receives nothing.
#[test]
fn clause_5_4_19_85_the_controlling_station_does_not_mix_the_sets() {
    for (set, other) in [
        (CommandSet::Untagged, CommandSet::Tagged),
        (CommandSet::Tagged, CommandSet::Untagged),
    ] {
        for mode in [CommandMode::Direct, CommandMode::SelectAndExecute] {
            let peer = ScriptPeer::start(Box::new(|_: &[u8]| Vec::new()));
            let mut dut = Dut::open(&peer, mode, set);
            for type_id in set_types(other) {
                let command = value(type_id, controllable(type_id));
                let built = if mode == CommandMode::SelectAndExecute && selectable(type_id) {
                    dut.ct.select(&command)
                } else {
                    dut.ct.execute(&command)
                };
                assert!(
                    matches!(built, Err(CtError::WrongCommandSet { .. })),
                    "5.4.19.85 ({set:?} station, {mode:?}, type {type_id}): refused, got \
                     {built:?}"
                );
            }
            assert!(
                dut.close(peer).is_empty(),
                "5.4.19.85 ({set:?}, {mode:?}): nothing of the other set went out"
            );
        }
    }
}

// ------------------------------------------------------------------ 5.4.19.86

/// 604 Table 19 (9 of 9), PDF page index 78 (printed 77), procedure
/// **`5.4.19.86`**, *"Command received during GI"*, `Reference`
/// `IEC 60870-5-5:1995, 5` and `IEC 60870-5-101:2003, 7.4`, `Required`
/// `PICS, 9.5`:
///
/// > Command function during a running general interrogation is processed and
/// > executed without waiting for the GI to finish.
///
/// DUT: the **controlling** station, both sets, all seven types as a direct
/// execute, each sent and completed while its own station interrogation
/// (`gi::Interrogation` in the controlling role) is running: the peer holds the
/// interrogated data and the `C_IC ACTTERM` back until the last command has
/// completed. The crate classifies every command answer while the
/// interrogation is still running, and the interrogation ends afterwards.
#[test]
fn clause_5_4_19_86_the_controlling_station_commands_during_its_interrogation() {
    for set in [CommandSet::Untagged, CommandSet::Tagged] {
        let last = set_types(set)[6];
        let mut gi_request: Option<Vec<u8>> = None;
        let mut commands = positive_script();
        let script: Script = Box::new(move |request: &[u8]| {
            if request[0] == 100 {
                gi_request = Some(request.to_vec());
                return vec![mirrored(request, 7, false)];
            }
            let mut out = commands(request);
            if request[0] == last {
                // The interrogation ends only now: one single point with
                // cause 20, then the activation mirrored with cause 10.
                out.push(asdu_with_body(1, 20, CA, &[0x01, 0x70, 0x00, 0x00]));
                out.push(mirrored(gi_request.as_ref().expect("the GI"), 10, false));
            }
            out
        });
        let peer = ScriptPeer::start(script);
        let mut dut = Dut::open(&peer, CommandMode::Direct, set);
        let mut gi = Interrogation::controlling(SecondActivation::Locked, CA, 0);
        let request = gi.request(Scope::Station).expect("the GI request");
        dut.send(&request);
        let confirmation = dut.next("5.4.19.86: the GI's ACTCON");
        let header = Header::parse(&confirmation).expect("the header");
        let known = Known::standard(&header, true, true);
        assert!(matches!(
            gi.on_response(&confirmation, &known)
                .expect("the GI ACTCON")
                .reaction,
            GiReaction::ActivationConfirmed {
                negative: false,
                ..
            }
        ));
        for type_id in set_types(set) {
            assert!(
                gi.is_running(Scope::Station),
                "5.4.19.86 ({set:?}, type {type_id}): the interrogation is running"
            );
            let ioa = controllable(type_id);
            let execute = dut.ct.execute(&value(type_id, ioa)).expect("the execute");
            dut.send(&execute);
            assert_eq!(
                dut.react("5.4.19.86: the ACTCON"),
                Reaction::Confirmed {
                    ioa,
                    select: false,
                    negative: false
                },
                "5.4.19.86 ({set:?}, type {type_id}): processed during the GI"
            );
            expect_completion(&mut dut, type_id, ioa, "5.4.19.86");
        }
        assert!(
            gi.is_running(Scope::Station),
            "5.4.19.86 ({set:?}): every command completed while the GI ran"
        );
        for expected in ["the GI data", "the GI's ACTTERM"] {
            let asdu = dut.next(&format!("5.4.19.86: {expected}"));
            let header = Header::parse(&asdu).expect("the header");
            let known = Known::standard(&header, true, true);
            gi.on_response(&asdu, &known).expect("the GI answer");
        }
        assert!(
            !gi.is_running(Scope::Station),
            "5.4.19.86 ({set:?}): the interrogation ends after the commands"
        );
        dut.close(peer);
    }
}
