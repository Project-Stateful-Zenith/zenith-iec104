//! 604 Table 26, *"PIXIT related conformance test procedures"*, PDF page index
//! 89 (printed 88), procedure numbers `5.4.26.1` … `.4`, `.50` … `.53`, `.100`
//! … `.103` and `.150` … `.153`.
//!
//! # The table is a form
//!
//! Unlike Tables 10 to 25, Table 26 prints no test at all. Its heading line
//! offers it for PIXIT-specific test procedures and lets it be skipped when
//! there are none, and its sixteen rows are empty apart from their numbers, four
//! `Function` rows (`5.4.26.1`, `.50`, `.100`, `.150`) each followed by three
//! test rows, and a `Reference` column that reads `PIXIT, section` on every row.
//! The table has no `COMPATIBILITY WITH OTHER TEST CASES` row.
//!
//! So the rows are filled in here, for the PIXIT of this library, with four
//! functions whose values the PIXIT has to state because the standard leaves
//! them to the project, and which the library takes as configuration:
//!
//! | Function | 104 clause | Library configuration |
//! | --- | --- | --- |
//! | `5.4.26.1` ASDU address field sizes | 9.5 | `asdu::AddressSizes` |
//! | `5.4.26.50` k and w | 5.5, 9.6 | `params::LinkParams::{k, w}` |
//! | `5.4.26.100` time-outs t1, t2, t3 | 5.2, 9.6 | `params::LinkParams::{t1, t2, t3}` |
//! | `5.4.26.150` longest file segment in one APDU | 5, 9.5 | `ft::max_segment(AddressSizes)` |
//!
//! §5.1 (index 10) defines `PIXIT` in the `Required` column: the test case is
//! mandatory when the PIXIT enables or describes the function, and the
//! PIXIT's user or owner must verify such test cases before testing starts.
//! The functions above are all described in this
//! sample PIXIT, so all twelve test rows are run.
//!
//! # The sample PIXIT
//!
//! - **Address sizes** (104 clause 9.5, index 98, *"system-specific
//!   parameter"*): the sample system uses the conventional profile, cause of
//!   transmission two octets with originator address, common address two
//!   octets, information object address three octets. Every case of
//!   `5.4.26.1` and `.150` also runs over the **other eleven** legal profiles
//!   (common address 1 or 2 octets, object address 1, 2 or 3, originator
//!   present or not), since 604 Table 1 asks for 5.3 and 5.4 to be run once
//!   or more for every supported parameter value, and the library supports all
//!   twelve. Common address `0x21` / `0x2132` and object address `0xA5` /
//!   `0xA5B6` / `0xA5B6C7` by width ([`addresses`]), so a wrong octet order
//!   shows; originator address 7 when present.
//! - **k = 3, w = 2** (104 clause 9.6's defaults are 12 and 8; the clause 5.5
//!   recommendation that w stay at or below two-thirds of k holds).
//! - **t0 = 10 s, t1 = 4 s, t2 = 2 s, t3 = 6 s** (clause 9.6's defaults are 30,
//!   15, 10 and 20 s; `t2 < t1` holds). The values differ from the defaults so
//!   that a station ignoring its configuration fails.
//! - **File transfer segments** as long as the profile allows.
//!
//! Nothing here needs manual or physical setup, so no row is marked not
//! applicable.
//!
//! # The station under test
//!
//! [`PixitDut`] is this library in either role with the sample PIXIT: a
//! `link::Session::with_params`, a `timers::Timers` over the same
//! `LinkParams`, the crate's `timers::Supervisor` keeping them in step, and an
//! application ASDU handler, on one end of a loopback socket. It runs on the
//! test thread with a **synthetic clock** the test advances, as
//! `interop::Station` does, so the time-out cases wait for nothing: the core
//! takes time as a parameter (104's timers are the caller's clock). The mock
//! peer is table 23's [`Mock`], which numbers its I-frames and otherwise sends
//! only what the case spells out.
//!
//! Every case runs with the library as the **controlled** and as the
//! **controlling** station (§5.1, index 10), except the unknown-address row
//! `5.4.26.4`, whose cause 47 §5.1 reserves to the controlled station.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::rc::Rc;
use std::time::{Duration, Instant};

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{AddressSizes, Header, Known, Nof, Nos, Qoc, Sco, read_ioa_with};
use iec104::ct::{
    Command, CommandMode, CommandSet, CommandTransmission, CommandValue, Reaction, Termination,
};
use iec104::framed::Decoder;
use iec104::ft::{FileTransferProcedure, Frame, FtError, Selection};
use iec104::link::{Action, Role, Session};
use iec104::params::LinkParams;
use iec104::timers::{Supervision, Supervisor, Timers};

use crate::conformance604::table23::{Mock, Provider, StoredFile};
use crate::conformance604::{StationApp, interop, parse_frame, sample_time};

// ---------------------------------------------------------- the sample PIXIT

/// The sample PIXIT's link parameters: k = 3, w = 2, t0 = 10 s, t1 = 4 s,
/// t2 = 2 s, t3 = 6 s, port 2404.
pub const fn pixit_params() -> LinkParams {
    LinkParams {
        port: 2404,
        k: 3,
        w: 2,
        t0: Duration::from_secs(10),
        t1: Duration::from_secs(4),
        t2: Duration::from_secs(2),
        t3: Duration::from_secs(6),
    }
}

/// The originator address the sample system's stations carry when the profile
/// has one (5-101 clause 7.2.3, figure 14).
const ORG: u8 = 7;

/// Every legal address profile: common address 1 or 2 octets × object address
/// 1, 2 or 3 octets × originator present or absent (5-101 clauses 7.2.3–7.2.5,
/// 104 clause 9.5). The sample system's own, the conventional one, is among
/// them.
fn every_profile() -> Vec<AddressSizes> {
    let mut profiles = Vec::new();
    for ca in 1..=2u8 {
        for ioa in 1..=3u8 {
            for originator in [false, true] {
                profiles.push(AddressSizes::new(ca, ioa, originator).expect("a legal width"));
            }
        }
    }
    profiles
}

/// The common address and the one object address the sample station holds, for
/// the widths of `sizes`: every octet different, so a wrong order or a wrong
/// width shows.
const fn addresses(sizes: AddressSizes) -> (u16, u32) {
    let ca = if sizes.common_address_octets() == 1 {
        0x21
    } else {
        0x2132
    };
    let ioa = match sizes.information_object_address_octets() {
        1 => 0xA5,
        2 => 0xA5B6,
        _ => 0x00A5_B6C7,
    };
    (ca, ioa)
}

/// One single-object ASDU as 5-101 figure 11 lays it out, field by field, with
/// the widths of `sizes`: type identification, variable structure qualifier
/// (`SQ = 0`, one object), cause of transmission, the originator address if the
/// profile has one (figure 14), the common address low octet first (figures
/// 17/18), the object address low octet first (figures 19–21), then `element`.
fn wire(sizes: AddressSizes, type_id: u8, cot: u8, ca: u16, ioa: u32, element: &[u8]) -> Vec<u8> {
    let mut out = vec![type_id, 0x01, cot];
    if sizes.originator_address() {
        out.push(ORG);
    }
    out.extend_from_slice(&ca.to_le_bytes()[..usize::from(sizes.common_address_octets())]);
    out.extend_from_slice(
        &ioa.to_le_bytes()[..usize::from(sizes.information_object_address_octets())],
    );
    out.extend_from_slice(element);
    out
}

/// A profile's name for the messages.
fn name(sizes: AddressSizes) -> String {
    format!(
        "CA {} octet(s), IOA {} octet(s), originator {}",
        sizes.common_address_octets(),
        sizes.information_object_address_octets(),
        if sizes.originator_address() {
            "present"
        } else {
            "absent"
        }
    )
}

// ------------------------------------------------------- the station under test

/// The application half of a [`PixitDut`]: the ASDUs to send for one ASDU the
/// session delivered.
type App = Box<dyn FnMut(&[u8]) -> Result<Vec<Vec<u8>>, String>>;

/// An application that answers nothing.
fn silent() -> App {
    Box::new(|_| Ok(Vec::new()))
}

/// This library as the station under test with the sample PIXIT, driven from
/// the test thread on a synthetic clock (see the module doc).
pub struct PixitDut {
    stream: TcpStream,
    decoder: Decoder,
    session: Session,
    timers: Timers,
    supervisor: Supervisor,
    now: Instant,
    app: App,
    queued: VecDeque<Vec<u8>>,
    /// The reasons of every `Action::ActiveClose` the session raised.
    pub closes: Vec<&'static str>,
}

impl PixitDut {
    fn new(stream: TcpStream, role: Role, params: LinkParams, app: App) -> Result<Self, String> {
        stream
            .set_nodelay(true)
            .map_err(|e| format!("nodelay: {e}"))?;
        let mut session =
            Session::with_params(role, params).map_err(|e| format!("the PIXIT: {e:?}"))?;
        let mut timers = Timers::new(params).map_err(|e| format!("the PIXIT: {e:?}"))?;
        let now = Instant::now();
        session.on_connection_established();
        timers.connection_established(now);
        Ok(Self {
            stream,
            decoder: Decoder::new(),
            session,
            timers,
            supervisor: Supervisor::default(),
            now,
            app,
            queued: VecDeque::new(),
            closes: Vec::new(),
        })
    }

    /// Whether the session closed the connection.
    pub const fn closed(&self) -> bool {
        !self.closes.is_empty()
    }

    /// Hands `actions` to the timer supervisor and puts them on the wire; an
    /// active close shuts the socket.
    fn perform(&mut self, actions: &[Action], before: Supervision) -> Result<(), String> {
        self.supervisor
            .apply(&mut self.timers, &self.session, self.now, actions, before);
        for action in actions {
            if let Action::ActiveClose(why) = action {
                self.closes.push(why);
                let _ = self.stream.shutdown(Shutdown::Both);
                continue;
            }
            let octets = interop::encode_action_bytes(action)?;
            if !octets.is_empty() {
                self.stream
                    .write_all(&octets)
                    .map_err(|e| format!("write: {e}"))?;
            }
        }
        Ok(())
    }

    /// Sends what the application owes, as far as the session's window allows.
    fn flush(&mut self) -> Result<(), String> {
        while let Some(asdu) = self.queued.front().cloned() {
            if self.closed() || !self.session.user_data_allowed() {
                break;
            }
            let before = Supervision::of(&self.session);
            match self.session.send_i_frame(&asdu) {
                Some(action) => {
                    self.perform(&[action], before)?;
                    self.queued.pop_front();
                }
                None => break,
            }
        }
        Ok(())
    }

    /// Queues user data of the station's own (an event, a command) and sends
    /// what the window allows.
    pub fn inject(&mut self, asdu: Vec<u8>) -> Result<(), String> {
        self.queued.push_back(asdu);
        self.flush()
    }

    /// The controlling station's STARTDT act (104 clause 5.3).
    pub fn request_start(&mut self) -> Result<(), String> {
        let before = Supervision::of(&self.session);
        let actions = self.session.request_start();
        self.perform(&actions, before)
    }

    /// Reads and handles every frame the peer has sent, until the socket has
    /// been quiet for a moment.
    pub fn pump(&mut self) -> Result<(), String> {
        loop {
            while let Ok(Some(_)) = self.decoder.next_frame_len() {
                let frame = self
                    .decoder
                    .next_frame()
                    .map_err(|e| format!("framing: {e}"))?
                    .ok_or("the decoder promised a frame")?
                    .to_vec();
                let (apci, asdu) = parse_frame(&frame)?;
                self.take(apci, &asdu)?;
            }
            if self.closed() {
                return Ok(());
            }
            self.stream
                .set_read_timeout(Some(Duration::from_millis(20)))
                .map_err(|e| format!("set read timeout: {e}"))?;
            let mut buf = [0u8; 1024];
            match self.stream.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => self.decoder.push(&buf[..n]),
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(());
                }
                Err(e) => return Err(format!("read: {e}")),
            }
        }
    }

    /// One received frame: the timers first (clause 5.2: any received frame
    /// restarts t3), then the session, then the
    /// application for delivered user data.
    fn take(&mut self, apci: Apci, asdu: &[u8]) -> Result<(), String> {
        self.timers.frame_received(self.now);
        if apci.is_i_format() {
            self.timers.i_frame_received(self.now);
        }
        let before = Supervision::of(&self.session);
        let actions = self.session.on_frame(apci);
        self.perform(&actions, before)?;
        if actions
            .iter()
            .any(|action| matches!(action, Action::DeliverData { .. }))
        {
            let replies = (self.app)(asdu)?;
            self.queued.extend(replies);
        }
        self.flush()
    }

    /// Moves the synthetic clock on by `by` and reports every time-out that
    /// came due to the session.
    pub fn advance(&mut self, by: Duration) -> Result<(), String> {
        self.now += by;
        for timer in self.timers.expired(self.now) {
            let before = Supervision::of(&self.session);
            let actions = self.session.on_timeout(timer);
            self.perform(&actions, before)?;
        }
        self.flush()
    }
}

/// A station under test in `role` with `params` and `app`, and the mock peer
/// of the other role, connected over loopback, data transfer started (104
/// clause 5.3).
fn started(role: Role, params: LinkParams, app: App) -> Result<(PixitDut, Mock), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;
    match role {
        Role::Controlled => {
            let mut mock = Mock::connect(addr)?;
            let (stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
            let mut dut = PixitDut::new(stream, role, params, app)?;
            mock.send_u(UFunction::StartDtAct)?;
            dut.pump()?;
            mock.expect_u(UFunction::StartDtCon, Duration::from_secs(2))?;
            Ok((dut, mock))
        }
        Role::Controlling => {
            let stream = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
            let mut mock = Mock::accept(&listener)?;
            let mut dut = PixitDut::new(stream, role, params, app)?;
            dut.request_start()?;
            mock.expect_u(UFunction::StartDtAct, Duration::from_secs(2))?;
            mock.send_u(UFunction::StartDtCon)?;
            dut.pump()?;
            Ok((dut, mock))
        }
    }
}

/// How long a "nothing arrives" check waits on the real clock. The synthetic
/// clock does not move meanwhile.
const QUIET: Duration = Duration::from_millis(150);

/// Requires the next frame the mock reads to be `want`.
fn expect(mock: &mut Mock, want: Apci, what: &str) -> Result<(), String> {
    match mock.read_frame(Instant::now() + Duration::from_secs(2))? {
        Some((got, _)) if got == want => Ok(()),
        other => Err(format!("{what}: {want:?} expected, got {other:?}")),
    }
}

/// Requires the mock to read nothing for [`QUIET`].
fn expect_nothing(mock: &mut Mock, what: &str) -> Result<(), String> {
    match mock.read_frame(Instant::now() + QUIET)? {
        None => Ok(()),
        Some((apci, _)) => Err(format!("{what}: the station sent {apci:?}")),
    }
}

/// An I-frame with the given sequence numbers, as the mock reads it.
const fn i_frame(ns: u16, nr: u16) -> Apci {
    Apci::I {
        ns: SeqNo::new(ns),
        nr: SeqNo::new(nr),
    }
}

/// A user-data ASDU the station under test sends of its own accord: a
/// spontaneous single point (`M_SP_NA_1`, cause 3) from the controlled station,
/// a single command activation (`C_SC_NA_1`, cause 6) from the controlling one,
/// conventional profile. The session does not read it.
fn own_asdu(role: Role, n: u8) -> Vec<u8> {
    match role {
        Role::Controlled => vec![1, 0x01, 3, 0, 1, 0, n, 0, 0, 0x01],
        Role::Controlling => vec![45, 0x01, 6, 0, 1, 0, n, 0, 0, 0x01],
    }
}

/// A user-data ASDU the mock sends to the station under test: the other
/// role's [`own_asdu`].
fn peer_asdu(dut: Role, n: u8) -> Vec<u8> {
    match dut {
        Role::Controlled => own_asdu(Role::Controlling, n),
        Role::Controlling => own_asdu(Role::Controlled, n),
    }
}

const ROLES: [Role; 2] = [Role::Controlled, Role::Controlling];

// ----------------------------------------------- 5.4.26.1 address field sizes

/// The controlled station's application for `5.4.26.1`: the crate's command
/// procedure in the profile `sizes` (direct execute, untagged commands, every
/// command terminated), holding the one object of [`addresses`]. A positive
/// confirmation of an execute is followed by its termination (5-101 clause
/// 7.4.7's direct command: `ACT`, `ACTCON`, `ACTTERM`).
fn command_station(sizes: AddressSizes) -> App {
    let (ca, held) = addresses(sizes);
    let mut ct = CommandTransmission::controlled(
        CommandMode::Direct,
        CommandSet::Untagged,
        Termination::All,
        ca,
        ORG,
    )
    .with_address_sizes(sizes);
    Box::new(move |asdu| {
        let known = known(asdu, sizes, ca, held)?;
        let outcome = ct
            .on_request(asdu, &known)
            .map_err(|e| format!("ct::on_request: {e:?}"))?;
        let mut out = outcome.send;
        if let Reaction::Confirmed {
            ioa,
            select: false,
            negative: false,
            ..
        } = outcome.reaction
        {
            out.push(
                ct.terminate(ioa, false)
                    .map_err(|e| format!("ct::terminate: {e:?}"))?,
            );
        }
        Ok(out)
    })
}

/// The four clause 7.2.3 answers in the profile `sizes`: the standard's types
/// and causes, the common address `ca` and the one object address `held`.
fn known(asdu: &[u8], sizes: AddressSizes, ca: u16, held: u32) -> Result<Known, String> {
    let header = Header::parse_with(asdu, sizes).map_err(|e| format!("the header: {e:?}"))?;
    let ioa = read_ioa_with(&asdu[sizes.header_len()..], sizes)
        .map_err(|e| format!("the address: {e:?}"))?;
    Ok(Known::standard(
        &header,
        header.common_address == ca,
        ioa == held,
    ))
}

/// `SCO` of a single command, ON, execute, no qualifier: `SCS` = 1 in bit 1,
/// `QU` = 0, `S/E` = 0 (5-101 clause 7.2.6.15), so `0x01`.
const SCO_ON_EXECUTE: u8 = 0x01;

/// 604 Table 26, PDF page index 89 (printed 88), row **`5.4.26.1`**, the first
/// `Function` row, filled in with *"ASDU address field sizes"*, `Reference`
/// `PIXIT, section` (the sample PIXIT's address sizes, module doc) and 104
/// clause 9.5 (index 98): cause of transmission *"One octet"* / *"Two octets
/// (with originator address)"*, common address *"One octet"* / *"Two
/// octets"*, information object address *"One octet"* / *"Two octets"* /
/// *"Three octets"*.
///
/// Row **`5.4.26.2`**: *the controlled station answers a command in the
/// configured address sizes*. DUT: the **controlled** station, in each of the
/// twelve profiles. The mock sends a single command (`C_SC_NA_1` `<45>`, cause
/// 6) laid out with the profile's widths; the station must answer with the
/// activation confirmation (cause 7) and the termination (cause 10), each the
/// command mirrored in the same widths with the originator address echoed
/// (5-101 clause 7.2.3: the originator address routes the mirrored ASDUs back
/// to whichever source activated the procedure).
#[test]
fn clause_5_4_26_2_the_controlled_station_answers_in_every_address_profile() {
    for sizes in every_profile() {
        let (ca, ioa) = addresses(sizes);
        let run = || -> Result<(), String> {
            let (mut dut, mut mock) =
                started(Role::Controlled, pixit_params(), command_station(sizes))?;
            mock.send_i(&wire(sizes, 45, 6, ca, ioa, &[SCO_ON_EXECUTE]))?;
            dut.pump()?;
            for (cot, what) in [(7, "ACTCON"), (10, "ACTTERM")] {
                let got = mock.next_i(Duration::from_secs(2))?.ok_or(what)?;
                let want = wire(sizes, 45, cot, ca, ioa, &[SCO_ON_EXECUTE]);
                if got != want {
                    return Err(format!(
                        "{what}: want {}, got {}",
                        interop::encode_hex(&want),
                        interop::encode_hex(&got)
                    ));
                }
            }
            Ok(())
        };
        run().unwrap_or_else(|why| panic!("5.4.26.2 ({}): {why}", name(sizes)));
    }
}

/// Row **`5.4.26.3`** of the `5.4.26.1` function (index 89): *the controlling
/// station sends a command in the configured address sizes and accepts the
/// answers in them*. DUT: the **controlling** station, in each of the twelve
/// profiles: its command activation must be `C_SC_NA_1`, cause 6, in the
/// profile's widths, and it must read the mock's confirmation and termination
/// in those widths as the positive confirmation and the termination of the
/// command it sent (5-101 clause 7.4.7).
#[test]
fn clause_5_4_26_3_the_controlling_station_commands_in_every_address_profile() {
    for sizes in every_profile() {
        let (ca, ioa) = addresses(sizes);
        let run = || -> Result<(), String> {
            let ct = Rc::new(RefCell::new(
                CommandTransmission::controlling(
                    CommandMode::Direct,
                    CommandSet::Untagged,
                    Termination::All,
                    ca,
                    ORG,
                )
                .with_address_sizes(sizes),
            ));
            let reactions = Rc::new(RefCell::new(Vec::new()));
            let app: App = {
                let (ct, reactions) = (ct.clone(), reactions.clone());
                Box::new(move |asdu| {
                    let known = known(asdu, sizes, ca, ioa)?;
                    let outcome = ct
                        .borrow_mut()
                        .on_response(asdu, &known)
                        .map_err(|e| format!("ct::on_response: {e:?}"))?;
                    reactions.borrow_mut().push(outcome.reaction);
                    Ok(outcome.send)
                })
            };
            let (mut dut, mut mock) = started(Role::Controlling, pixit_params(), app)?;
            let command = Command::new(
                ioa,
                CommandValue::Single {
                    sco: Sco {
                        scs: true,
                        qoc: Qoc {
                            qu: 0,
                            select: false,
                        },
                    },
                },
            );
            let act = ct
                .borrow_mut()
                .execute(&command)
                .map_err(|e| format!("ct::execute: {e:?}"))?;
            dut.inject(act)?;
            let got = mock
                .next_i(Duration::from_secs(2))?
                .ok_or("no activation")?;
            let want = wire(sizes, 45, 6, ca, ioa, &[SCO_ON_EXECUTE]);
            if got != want {
                return Err(format!(
                    "ACT: want {}, got {}",
                    interop::encode_hex(&want),
                    interop::encode_hex(&got)
                ));
            }
            mock.send_i(&wire(sizes, 45, 7, ca, ioa, &[SCO_ON_EXECUTE]))?;
            mock.send_i(&wire(sizes, 45, 10, ca, ioa, &[SCO_ON_EXECUTE]))?;
            dut.pump()?;
            let seen = reactions.borrow().clone();
            let expected = [
                Reaction::Confirmed {
                    ioa,
                    select: false,
                    negative: false,
                    test: false,
                },
                Reaction::Terminated {
                    ioa,
                    negative: false,
                },
            ];
            if seen != expected {
                return Err(format!("reactions: want {expected:?}, got {seen:?}"));
            }
            Ok(())
        };
        run().unwrap_or_else(|why| panic!("5.4.26.3 ({}): {why}", name(sizes)));
    }
}

/// Row **`5.4.26.4`** of the `5.4.26.1` function (index 89): *an object
/// address the station does not hold is refused in the configured address
/// sizes*. DUT: the **controlled** station only, in each of the twelve
/// profiles: cause 47 is one §5.1 (index 10) reserves to it. A command to an
/// address one below the held one must come back mirrored in the profile's
/// widths with `P/N = 1` and cause 47 (5-101 clause 7.2.3, index 42: `<47>`,
/// unknown information object address), so `0x40 | 47 = 0x6F` in the cause
/// octet.
#[test]
fn clause_5_4_26_4_an_unknown_object_address_is_mirrored_in_every_address_profile() {
    for sizes in every_profile() {
        let (ca, ioa) = addresses(sizes);
        let run = || -> Result<(), String> {
            let (mut dut, mut mock) =
                started(Role::Controlled, pixit_params(), command_station(sizes))?;
            mock.send_i(&wire(sizes, 45, 6, ca, ioa - 1, &[SCO_ON_EXECUTE]))?;
            dut.pump()?;
            let got = mock.next_i(Duration::from_secs(2))?.ok_or("no mirror")?;
            let want = wire(sizes, 45, 0x6F, ca, ioa - 1, &[SCO_ON_EXECUTE]);
            if got != want {
                return Err(format!(
                    "want {}, got {}",
                    interop::encode_hex(&want),
                    interop::encode_hex(&got)
                ));
            }
            Ok(())
        };
        run().unwrap_or_else(|why| panic!("5.4.26.4 ({}): {why}", name(sizes)));
    }
}

// ---------------------------------------------------------- 5.4.26.50 k and w

/// 604 Table 26, PDF page index 89 (printed 88), row **`5.4.26.50`**, the
/// second `Function` row, filled in with *"k and w"*, `Reference` `PIXIT,
/// section` (the sample PIXIT's k = 3, w = 2) and 104 clause 5.5.
///
/// Row **`5.4.26.51`**: *the transmitter stops at k unacknowledged I-frames*.
/// 104 clause 5.5 (index 44): a transmitter stops sending once k I format
/// APDUs are unacknowledged. DUT: each role in turn,
/// with five ASDUs of its own to send and a mock that acknowledges nothing:
/// exactly three I-frames (N(S) 0, 1, 2) go out, then nothing.
#[test]
fn clause_5_4_26_51_the_transmitter_stops_at_k_unacknowledged_frames() {
    for role in ROLES {
        let run = || -> Result<(), String> {
            let (mut dut, mut mock) = started(role, pixit_params(), silent())?;
            for n in 0..5 {
                dut.inject(own_asdu(role, n))?;
            }
            for ns in 0..3 {
                expect(&mut mock, i_frame(ns, 0), "an I-frame inside the window")?;
            }
            expect_nothing(&mut mock, "k = 3 frames are unacknowledged")
        };
        run().unwrap_or_else(|why| panic!("5.4.26.51 ({role:?}): {why}"));
    }
}

/// Row **`5.4.26.52`** of the `5.4.26.50` function (index 89): *the receiver
/// acknowledges at the latest after w I-frames*. 104 clause 9.6 (index 114),
/// the row of w: the receiver acknowledges no later than after w I format
/// APDUs. DUT: each role in turn, with an application that sends
/// nothing and a synthetic clock that never reaches t2: after one I-frame
/// nothing comes back; after the second (w = 2), the S-frame with N(R) = 2.
#[test]
fn clause_5_4_26_52_the_receiver_acknowledges_after_w_frames() {
    for role in ROLES {
        let run = || -> Result<(), String> {
            let (mut dut, mut mock) = started(role, pixit_params(), silent())?;
            mock.send_i(&peer_asdu(role, 0))?;
            dut.pump()?;
            expect_nothing(&mut mock, "one I-frame is fewer than w = 2")?;
            mock.send_i(&peer_asdu(role, 1))?;
            dut.pump()?;
            expect(
                &mut mock,
                Apci::S { nr: SeqNo::new(2) },
                "the S-frame after w = 2 I-frames",
            )
        };
        run().unwrap_or_else(|why| panic!("5.4.26.52 ({role:?}): {why}"));
    }
}

/// Row **`5.4.26.53`** of the `5.4.26.50` function (index 89): *an
/// acknowledgement reopens the window by as many frames as it confirms*. 104
/// clause 5.5 counts k over *unacknowledged* I-frames, so after the three of
/// `5.4.26.51` an S-frame with N(R) = 1 lets exactly one more out (N(S) 3),
/// and N(R) = 4 the last one (N(S) 4). DUT: each role in turn.
#[test]
fn clause_5_4_26_53_an_acknowledgement_reopens_the_window() {
    for role in ROLES {
        let run = || -> Result<(), String> {
            let (mut dut, mut mock) = started(role, pixit_params(), silent())?;
            for n in 0..5 {
                dut.inject(own_asdu(role, n))?;
            }
            for ns in 0..3 {
                expect(&mut mock, i_frame(ns, 0), "an I-frame inside the window")?;
            }
            mock.send_s_nr(1)?;
            dut.pump()?;
            expect(&mut mock, i_frame(3, 0), "N(R) = 1 frees one place")?;
            expect_nothing(&mut mock, "the window is full again")?;
            mock.send_s_nr(4)?;
            dut.pump()?;
            expect(&mut mock, i_frame(4, 0), "N(R) = 4 frees the rest")?;
            expect_nothing(&mut mock, "all five are sent")
        };
        run().unwrap_or_else(|why| panic!("5.4.26.53 ({role:?}): {why}"));
    }
}

// ----------------------------------------------------- 5.4.26.100 time-outs

/// One second: the resolution of 104 clause 9.6's time-outs (*"accuracy 1 s"*),
/// and the margin the "not before" checks leave.
const SECOND: Duration = Duration::from_secs(1);

/// The longest the mock waits to see a close it expects.
const CLOSE_WAIT: Duration = Duration::from_secs(2);

/// Whether the mock sees the connection closed within `wait` (a close is seen
/// at once; only an open connection takes the whole wait).
fn connection_closed(mock: &mut Mock, wait: Duration) -> bool {
    let limit = Instant::now() + wait;
    loop {
        match mock.read_frame(limit) {
            Err(_) => return true,
            Ok(None) => return false,
            Ok(Some(_)) => {}
        }
    }
}

/// 604 Table 26, PDF page index 89 (printed 88), row **`5.4.26.100`**, the
/// third `Function` row, filled in with *"time-outs t1, t2, t3"*, `Reference`
/// `PIXIT, section` (the sample PIXIT's t1 = 4 s, t2 = 2 s, t3 = 6 s) and the
/// time-out rows of 104 clause 9.6 (index 114): t1 bounds the wait for a sent
/// or test APDU, t2 bounds the wait before acknowledging when no data message
/// carries the acknowledgement (with `t2 < t1`), and t3 is the idle time
/// after which test frames are sent.
///
/// Row **`5.4.26.101`**: *an unconfirmed I-frame closes the connection at t1*.
/// Figures 17/18 NOTE 2 (indices 42 and 44): t1 times out a sent U-frame or
/// I-frame;
/// its expiry is `Active close`. DUT: each role in turn. It sends one I-frame
/// the mock never acknowledges: one second before t1 the connection is still
/// open, at t1 it is closed.
#[test]
fn clause_5_4_26_101_an_unconfirmed_frame_closes_the_connection_at_t1() {
    for role in ROLES {
        let run = || -> Result<(), String> {
            let t1 = pixit_params().t1;
            let (mut dut, mut mock) = started(role, pixit_params(), silent())?;
            dut.inject(own_asdu(role, 0))?;
            expect(&mut mock, i_frame(0, 0), "the unconfirmed I-frame")?;
            dut.advance(t1.checked_sub(SECOND).unwrap())?;
            if dut.closed() || connection_closed(&mut mock, QUIET) {
                return Err("closed before t1".into());
            }
            dut.advance(SECOND)?;
            if !dut.closed() || !connection_closed(&mut mock, CLOSE_WAIT) {
                return Err("still open at t1".into());
            }
            Ok(())
        };
        run().unwrap_or_else(|why| panic!("5.4.26.101 ({role:?}): {why}"));
    }
}

/// The same row, **`5.4.26.101`**, for the other frame t1 supervises: the
/// controlling station's `STARTDT act` (figures 15/16 mark `Time-out t1` on
/// it). DUT: the **controlling** station; the mock never confirms.
#[test]
fn clause_5_4_26_101_an_unconfirmed_startdt_closes_the_connection_at_t1() {
    let t1 = pixit_params().t1;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let stream = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let mut mock = Mock::accept(&listener).expect("accept");
    let mut dut = PixitDut::new(stream, Role::Controlling, pixit_params(), silent()).expect("DUT");
    dut.request_start().expect("STARTDT act");
    mock.expect_u(UFunction::StartDtAct, Duration::from_secs(2))
        .expect("5.4.26.101: STARTDT act");
    dut.advance(t1.checked_sub(SECOND).unwrap())
        .expect("advance");
    assert!(
        !dut.closed() && !connection_closed(&mut mock, QUIET),
        "5.4.26.101: closed before t1"
    );
    dut.advance(SECOND).expect("advance");
    assert!(
        dut.closed() && connection_closed(&mut mock, CLOSE_WAIT),
        "5.4.26.101: still open at t1"
    );
}

/// Row **`5.4.26.102`** of the `5.4.26.100` function (index 89): *fewer than
/// w received I-frames are acknowledged at t2*. DUT: each role in turn. One
/// I-frame arrives (w = 2 is not reached): one second before t2 nothing has
/// gone back, at t2 the S-frame with N(R) = 1.
#[test]
fn clause_5_4_26_102_a_lone_frame_is_acknowledged_at_t2() {
    for role in ROLES {
        let run = || -> Result<(), String> {
            let t2 = pixit_params().t2;
            let (mut dut, mut mock) = started(role, pixit_params(), silent())?;
            mock.send_i(&peer_asdu(role, 0))?;
            dut.pump()?;
            dut.advance(t2.checked_sub(SECOND).unwrap())?;
            expect_nothing(&mut mock, "one second before t2")?;
            dut.advance(SECOND)?;
            expect(
                &mut mock,
                Apci::S { nr: SeqNo::new(1) },
                "the S-frame at t2",
            )
        };
        run().unwrap_or_else(|why| panic!("5.4.26.102 ({role:?}): {why}"));
    }
}

/// Row **`5.4.26.103`** of the `5.4.26.100` function (index 89): *an idle
/// connection is tested at t3, and the confirmed test keeps it open*. 104
/// clause 5.2 (index 34): receiving any frame, I, S or U, restarts t3;
/// figure 13 draws `Time-out t3` → `U (TESTFR act)`.
/// DUT: each role in turn. One second before t3 nothing goes out; at t3 the
/// `TESTFR act`; the mock confirms, and a further t1 later the connection is
/// still open (the confirmation ended t1's supervision).
#[test]
fn clause_5_4_26_103_an_idle_connection_is_tested_at_t3() {
    for role in ROLES {
        let run = || -> Result<(), String> {
            let params = pixit_params();
            let (mut dut, mut mock) = started(role, params, silent())?;
            dut.advance(params.t3.checked_sub(SECOND).unwrap())?;
            expect_nothing(&mut mock, "one second before t3")?;
            dut.advance(SECOND)?;
            expect(&mut mock, Apci::U(UFunction::TestFrAct), "TESTFR act at t3")?;
            mock.send_u(UFunction::TestFrCon)?;
            dut.pump()?;
            dut.advance(params.t1)?;
            if dut.closed() {
                return Err(format!("closed after a confirmed test: {:?}", dut.closes));
            }
            Ok(())
        };
        run().unwrap_or_else(|why| panic!("5.4.26.103 ({role:?}): {why}"));
    }
}

// ------------------------------------------ 5.4.26.150 the longest segment

/// The longest `F_SG_NA_1` segment a profile allows, worked from the texts:
/// 104 clause 5 (index 26) caps the ASDU at 249 octets, less the data unit identifier (type 1, qualifier 1, cause 1, the
/// originator 0 or 1, the common address 1 or 2), the object address (1, 2 or
/// 3) and figure 88's `NOF` (2), `NOS` (1) and `LOS` (1) (5-101 index 119).
fn longest_segment(sizes: AddressSizes) -> usize {
    let identifier =
        3 + usize::from(sizes.originator_address()) + usize::from(sizes.common_address_octets());
    249 - identifier - usize::from(sizes.information_object_address_octets()) - 4
}

/// A file of one section exactly `len` octets long, name of file `<1>`.
fn one_section_file(len: usize) -> StoredFile {
    StoredFile {
        nof: Nof { value: 1 },
        sections: vec![(0..len).map(|i| i as u8).collect()],
        time: sample_time(),
    }
}

/// Table 23's [`Provider`] in the profile `sizes`, in `role`, holding a
/// one-section file of `len` octets at the profile's object address and cutting
/// it into segments of `segment` octets.
fn segment_provider(role: Role, sizes: AddressSizes, len: usize, segment: usize) -> App {
    let (ca, ioa) = addresses(sizes);
    let ft = match role {
        Role::Controlled => FileTransferProcedure::controlled(Selection::MONITOR, ca, ORG),
        Role::Controlling => FileTransferProcedure::controlling(Selection::CONTROL, ca, ORG),
    }
    .with_address_sizes(sizes);
    let mut provider = Provider::new(ft, one_section_file(len))
        .at(ioa)
        .with_segment_octets(segment);
    Box::new(move |asdu| provider.on_asdu(asdu))
}

/// The call section (`F_SC_NA_1`, cause 13, name of file `<1>`, section `<1>`,
/// `SCQ` `<6>`) in the profile `sizes`, figure 85's element: `NOF` `01 00`,
/// `NOS` `01`, `SCQ` `06`.
fn call_section(sizes: AddressSizes) -> Vec<u8> {
    let (ca, ioa) = addresses(sizes);
    wire(sizes, 122, 13, ca, ioa, &[0x01, 0x00, 0x01, 0x06])
}

/// The station under test in `role` and `sizes` answers a call section of a
/// section of [`longest_segment`] octets; the first frame it sends must be one
/// segment carrying the whole section in an APDU of length 253.
fn longest_segment_on_the_wire(role: Role, sizes: AddressSizes) -> Result<(), String> {
    let longest = longest_segment(sizes);
    let (mut dut, mut mock) = started(
        role,
        pixit_params(),
        segment_provider(role, sizes, longest, longest),
    )?;
    mock.send_i(&call_section(sizes))?;
    dut.pump()?;
    let asdu = mock.next_i(Duration::from_secs(2))?.ok_or("no segment")?;
    let frame = mock.received.last().ok_or("no frame")?.clone();
    // 104 clause 5: start octet 68H, then the APDU length, whose maximum is
    // 253 (index 26: the APDU length field is at most 253).
    if frame[0] != 0x68 || frame[1] != 253 {
        return Err(format!(
            "the segment's APDU starts {:02X} {:02X}, not 68 FD",
            frame[0], frame[1]
        ));
    }
    let (ca, ioa) = addresses(sizes);
    let mut element = vec![0x01, 0x00, 0x01, longest as u8];
    element.extend((0..longest).map(|i| i as u8));
    let want = wire(sizes, 125, 13, ca, ioa, &element);
    if asdu != want {
        return Err(format!(
            "want {}, got {}",
            interop::encode_hex(&want),
            interop::encode_hex(&asdu)
        ));
    }
    Ok(())
}

/// 604 Table 26, PDF page index 89 (printed 88), row **`5.4.26.150`**, the
/// fourth `Function` row, filled in with *"the longest file segment in one
/// APDU"*, `Reference` `PIXIT, section` (the sample PIXIT's segment size, as
/// long as the profile allows), 104 clause 5 (index 26) and 5-101 figure 88.
///
/// Row **`5.4.26.151`**: *the controlled station sends a segment that fills
/// the APDU*. DUT: the **controlled** station providing a file in the monitor
/// direction, in each of the twelve profiles: 240 octets under the narrowest
/// profile down to 236 under the conventional one ([`longest_segment`]), each
/// in an APDU of exactly 253 octets.
#[test]
fn clause_5_4_26_151_the_controlled_station_fills_the_apdu_with_a_segment() {
    for sizes in every_profile() {
        longest_segment_on_the_wire(Role::Controlled, sizes)
            .unwrap_or_else(|why| panic!("5.4.26.151 ({}): {why}", name(sizes)));
    }
}

/// Row **`5.4.26.152`** of the `5.4.26.150` function (index 89): *the
/// controlling station sends a segment that fills the APDU*. DUT: the
/// **controlling** station providing a file in the control direction, in each
/// of the twelve profiles, the same lengths as `5.4.26.151`.
#[test]
fn clause_5_4_26_152_the_controlling_station_fills_the_apdu_with_a_segment() {
    for sizes in every_profile() {
        longest_segment_on_the_wire(Role::Controlling, sizes)
            .unwrap_or_else(|why| panic!("5.4.26.152 ({}): {why}", name(sizes)));
    }
}

/// Row **`5.4.26.153`** of the `5.4.26.150` function (index 89): *a segment
/// one octet longer than the profile allows is not sent*. An APDU of 254 would
/// break 104 clause 5's 253, so the library must refuse to build it: in each
/// of the twelve profiles and both roles, `FileTransferProcedure::build`
/// answers `FtError::SegmentTooLong` with the limit [`longest_segment`]
/// worked out, and the station under test, asked for such a section, puts no
/// I-frame on the wire.
#[test]
fn clause_5_4_26_153_a_segment_beyond_the_apdu_is_not_sent() {
    for sizes in every_profile() {
        for role in ROLES {
            let longest = longest_segment(sizes);
            let (ca, ioa) = addresses(sizes);
            let ft = match role {
                Role::Controlled => FileTransferProcedure::controlled(Selection::MONITOR, ca, ORG),
                Role::Controlling => {
                    FileTransferProcedure::controlling(Selection::CONTROL, ca, ORG)
                }
            }
            .with_address_sizes(sizes);
            let too_long = Frame::Segment {
                ioa,
                segment: iec104::asdu::Segment {
                    nof: Nof { value: 1 },
                    nos: Nos { value: 1 },
                    los: iec104::asdu::Los {
                        value: (longest + 1) as u8,
                    },
                    payload: vec![0; longest + 1],
                },
            };
            assert_eq!(
                ft.build(&too_long),
                Err(FtError::SegmentTooLong {
                    len: longest + 1,
                    max: longest
                }),
                "5.4.26.153 ({}, {role:?}): the builder's refusal",
                name(sizes)
            );

            let (mut dut, mut mock) = started(
                role,
                pixit_params(),
                segment_provider(role, sizes, longest + 1, longest + 1),
            )
            .unwrap_or_else(|why| panic!("5.4.26.153 ({}, {role:?}): {why}", name(sizes)));
            mock.send_i(&call_section(sizes)).expect("the call section");
            let refused = dut.pump();
            assert!(
                matches!(&refused, Err(why) if why.contains("SegmentTooLong")),
                "5.4.26.153 ({}, {role:?}): the station's application is refused the segment, \
                 got {refused:?}",
                name(sizes)
            );
            assert_eq!(
                mock.next_i(QUIET).expect("the mock reads"),
                None,
                "5.4.26.153 ({}, {role:?}): no I-frame goes out",
                name(sizes)
            );
        }
    }
}
