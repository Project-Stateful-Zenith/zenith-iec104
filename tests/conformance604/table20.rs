//! 604 Table 20, *"Transmission of integrated totals (telecounting) function
//! conformance test procedures"*, PDF page indices 78–81 (printed 77–80):
//! procedures `5.4.20.1` (mode A, index 78), `5.4.20.10` (mode B, index 79),
//! `5.4.20.20` (mode C, index 80), `5.4.20.30` (mode D, index 81) and
//! `5.4.20.40` (compatibility, index 81–82). Every row's `Reference` column
//! names `IEC 60870-5-101:2003, 7.4.8` (with `IEC 60870-5-5:1995, 6.9.1`), and
//! the rows about the ASDU set name `IEC 60870-5-101:2003, 8.5, 8.6`.
//!
//! # What is the library's, and what is the application's
//!
//! The library's part of the function is `ci` (the `C_CI_NA_1` exchange, 5-101
//! clause 7.4.8) and `tx` (the spontaneous `M_IT` of modes A and D, 5-104
//! clause 7.4). The **counter model** itself (5-101 figure 92: actual value,
//! freeze, frozen value, reset) is project data the crate leaves to the
//! application (`ci::CounterSource`), so the controlled station under test runs
//! a small figure 92 model, [`Model`], as glue. What a case asserts about the
//! library is therefore:
//!
//! - the frames the procedure draws: the confirmation mirrors the request's
//!   `QCC` with cause 7, the objects of a collection carry cause 37 to 41, the
//!   termination mirrors the request with cause 10, a memorize ends at its
//!   confirmation, the answers carry the station's own common address;
//! - that the application is handed the request's own `RQT` and `FRZ` (the
//!   `ci::Reaction` the library returns), so a freeze touches only the counters
//!   the `RQT` names;
//! - that the values the application supplies reach the wire unchanged.
//!
//! The rows 604 marks *"(plausibility test)"* about the counter **value** (an
//! increment or an integrated total) and the `BCR` **sequence number** `SQ`
//! changing each interval are properties of the counter model, not of the
//! library: they are observed on the wire where the model makes them visible,
//! and each case says so. The *"configured intervals"* rows (the local clock of
//! modes A and B, the controlling station's interrogation period of modes B to
//! D) are a device's configuration; the library reads no clock. The harness's
//! local clock (mode A) is [`LocalFreeze`], and the controlling-station cases
//! show only that the procedure can be repeated, which is what an interval
//! needs from the library.
//!
//! # Direction
//!
//! §5.1 swaps the roles for the reverse direction, so each mode is driven with
//! the library as the **controlled** station (a `ControlledStation` running
//! [`CounterApp`], against the mock controlling station `Peer`) and as the
//! **controlling** station (`interop::Station` running `ci` and `tx`, against
//! the mock controlled station `ScriptedPeer`). No case sends cause 44 to 47,
//! so §5.1's exception does not apply.
//!
//! # Not automated
//!
//! - The rows' expectation that the values the controlling station receives
//!   and stores should match the controlled station's actual values (`M` in
//!   modes A, C, D, `PIXIT` in mode B): storing is the controlling
//!   station's application. The controlling-station cases check that the
//!   library decodes the values exactly as they were sent, which is all the
//!   library holds.
//! - `5.4.20.40`, *"COMPATIBILITY WITH OTHER TEST CASES"*: it asserts that
//!   nothing in §5.3 broke while this table ran, which is the whole suite, not a
//!   case (see `tests/conformance_604.rs`).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::conformance604::scripted::{
    Link, ScriptedPeer, started_station, station_recv_n, station_send,
};
use crate::conformance604::{
    CA, ControlledStation, ORIGINATOR, StationApp, asdu_with_body, sample_time, station_profile,
    station_reply,
};
use iec104::asdu::{
    Bcr, Cause, Cp56Time2a, FreezeMode, Header, Known, LayoutObject, MItNa1, MItTb1, TypeId,
    decode_asdu, encode_asdu,
};
use iec104::ci::{
    COUNTER_TYPES, CiError, CounterInterrogation, CounterMode, CounterSource, Reaction, Request,
};
use iec104::tx::{self, Function, ProjectList, StationFunctions, Transmission};

/// The broadcast common address of the two-octet profile (5-101 clause 7.2.4),
/// which 604 `5.4.10.10` permits with type 101.
const BROADCAST: u16 = 0xFFFF;

/// The `QCC` octet of 5-101 clause 7.2.6.23, written from the clause and not
/// through the crate: `RQT := UI6[1..6]`, `FRZ := UI2[7..8]`.
const fn qcc(rqt: u8, frz: u8) -> u8 {
    rqt | (frz << 6)
}

/// One `C_CI_NA_1` as 5-101 clause 7.3.4.2 (figure 73) draws it: `SQ = 0`,
/// `N = 1`, the cause given, `INFORMATION OBJECT ADDRESS = 0` and the `QCC`
/// octet. Built octet by octet, so it is the standard's frame and not the
/// crate's.
fn c_ci(cause: u8, ca: u16, qcc: u8) -> Vec<u8> {
    asdu_with_body(101, cause, ca, &[0, 0, 0, qcc])
}

// ------------------------------------------------------ the counter model

/// One counter of the station's figure 92 model, and its place in the counter
/// groups (5-101 clause 7.4.8 leaves it to the controlled station to define
/// which integrated-total addresses belong to which group).
#[derive(Debug, Clone, Copy)]
struct Counter {
    ioa: u32,
    group: u8,
    /// `M_IT_TB_1` (37) when true, `M_IT_NA_1` (15) otherwise: the two `M_IT`
    /// types 5-104 clause 9 selects.
    tagged: bool,
    actual: i32,
    frozen: i32,
    sq: u8,
}

/// The station's counters: one per counter group 1 to 4, alternating the two
/// `M_IT` types, each with its own actual and frozen value so a case can tell
/// which ones a freeze touched.
const COUNTERS: [Counter; 4] = [
    Counter {
        ioa: 0x4001,
        group: 1,
        tagged: false,
        actual: 1_000,
        frozen: 100,
        sq: 0,
    },
    Counter {
        ioa: 0x4002,
        group: 2,
        tagged: true,
        actual: 2_000,
        frozen: 200,
        sq: 0,
    },
    Counter {
        ioa: 0x4003,
        group: 3,
        tagged: false,
        actual: 3_000,
        frozen: 300,
        sq: 0,
    },
    Counter {
        ioa: 0x4004,
        group: 4,
        tagged: true,
        actual: 4_000,
        frozen: 400,
        sq: 0,
    },
];

/// The configured counter at `ioa`.
fn counter(ioa: u32) -> Counter {
    *COUNTERS
        .iter()
        .find(|c| c.ioa == ioa)
        .unwrap_or_else(|| panic!("no counter at {ioa:#x}"))
}

/// The configured counters `request` names, in address order.
fn members(request: Request) -> Vec<Counter> {
    COUNTERS
        .iter()
        .filter(|c| request.group_number().is_none_or(|g| c.group == g))
        .copied()
        .collect()
}

/// 5-101 figure 92, *"General counter model"*, as the harness's application:
/// the actual values can be copied into frozen values from time to time, either
/// on a freeze command from a controlling station or on the device's own
/// initiative; after a freeze the actual value is either set back to zero
/// (incremental information) or keeps running unreset (integrated totals). The
/// `SQ` of a counter moves on with every value it memorises.
struct Model {
    counters: Vec<Counter>,
}

impl Model {
    fn new() -> Self {
        Self {
            counters: COUNTERS.to_vec(),
        }
    }

    /// Applies `freeze` to the counters `request` names and to no other (5-101
    /// clause 7.4.8: `FRZ` acts only on the counters `RQT` selects, and leaves
    /// every other counter alone).
    /// Answers whether a new frozen value was memorised.
    fn memorise(&mut self, request: Request, freeze: FreezeMode) -> bool {
        let group = request.group_number();
        for c in self
            .counters
            .iter_mut()
            .filter(|c| group.is_none_or(|g| c.group == g))
        {
            match freeze {
                FreezeMode::Read => {}
                FreezeMode::FreezeWithoutReset => {
                    c.frozen = c.actual;
                    c.sq = (c.sq + 1) & 0x1F;
                }
                FreezeMode::FreezeWithReset => {
                    c.frozen = c.actual;
                    c.actual = 0;
                    c.sq = (c.sq + 1) & 0x1F;
                }
                FreezeMode::Reset => c.actual = 0,
            }
        }
        matches!(
            freeze,
            FreezeMode::FreezeWithoutReset | FreezeMode::FreezeWithReset
        )
    }

    fn bcr(c: &Counter) -> Bcr {
        Bcr {
            reading: c.frozen,
            sequence: c.sq,
            ..Bcr::default()
        }
    }

    /// One counter's frozen value as an `M_IT` ASDU with `cause`, built through
    /// the layout layer (5-101 clause 7.3.1).
    fn total(c: &Counter, cause: Cause) -> Vec<u8> {
        m_it(c.tagged, cause, CA, c.ioa, Self::bcr(c))
    }

    /// The same values as spontaneous frames, built by the library's `tx`
    /// (5-104 clause 7.4's `M SPONT`).
    fn spontaneous(&self, tx: &Transmission, request: Request) -> Result<Vec<Vec<u8>>, String> {
        let group = request.group_number();
        self.counters
            .iter()
            .filter(|c| group.is_none_or(|g| c.group == g))
            .map(|c| {
                let built = if c.tagged {
                    tx.spontaneous(&LayoutObject {
                        ioa: c.ioa,
                        value: MItTb1 {
                            bcr: Self::bcr(c),
                            time: sample_time(),
                        },
                    })
                } else {
                    tx.spontaneous(&LayoutObject {
                        ioa: c.ioa,
                        value: MItNa1 { bcr: Self::bcr(c) },
                    })
                };
                built.map_err(|e| format!("tx: {e:?}"))
            })
            .collect()
    }
}

impl CounterSource for Model {
    fn ready(&self, _request: Request) -> bool {
        true
    }

    fn totals(&self, request: Request, out: &mut Vec<Vec<u8>>) {
        let group = request.group_number();
        for c in self
            .counters
            .iter()
            .filter(|c| group.is_none_or(|g| c.group == g))
        {
            out.push(Self::total(c, request.cause()));
        }
    }
}

/// One `M_IT` ASDU, `M_IT_TB_1` with [`sample_time`] when `tagged`, built
/// through the layout layer from 5-101 clause 7.3.1's fields.
fn m_it(tagged: bool, cause: Cause, ca: u16, ioa: u32, bcr: Bcr) -> Vec<u8> {
    let header = Header {
        type_id: if tagged {
            TypeId::MItTb1
        } else {
            TypeId::MItNa1
        },
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: ORIGINATOR,
        common_address: ca,
    };
    if tagged {
        let time = sample_time();
        encode_asdu(
            &header,
            &[LayoutObject {
                ioa,
                value: MItTb1 { bcr, time },
            }],
        )
    } else {
        encode_asdu(
            &header,
            &[LayoutObject {
                ioa,
                value: MItNa1 { bcr },
            }],
        )
    }
    .expect("the layout builds an M_IT")
}

/// One received `M_IT` ASDU: its header, address, `BCR` and time tag.
fn read_total(asdu: &[u8]) -> (Header, u32, Bcr, Option<Cp56Time2a>) {
    let header = Header::parse(asdu).expect("an M_IT header");
    match header.type_id {
        TypeId::MItNa1 => {
            let objects = decode_asdu::<MItNa1>(asdu).expect("an M_IT_NA_1");
            (header, objects[0].ioa, objects[0].value.bcr, None)
        }
        TypeId::MItTb1 => {
            let objects = decode_asdu::<MItTb1>(asdu).expect("an M_IT_TB_1");
            (
                header,
                objects[0].ioa,
                objects[0].value.bcr,
                Some(objects[0].value.time),
            )
        }
        other => panic!("an M_IT was expected, got type {}", other.to_u8()),
    }
}

// ------------------------------------------ the controlled station's glue

/// Mode A's local clock (5-101 clause 7.4.8: in this mode the freeze, with or
/// without reset, is triggered by clocks local to the controlled station): every
/// `interval`, the actual values integrate `step`, the station freezes all its
/// counters and reports them spontaneously, `left` times in all.
struct LocalFreeze {
    interval: Duration,
    step: i32,
    left: usize,
    next: Option<Instant>,
}

/// The controlled station's application for Table 20: the library's `ci` in
/// the station's counter mode answers every `C_CI_NA_1`, the library's `tx`
/// builds every spontaneous `M_IT`, and [`Model`] is the counter data. The glue
/// only routes: it hands `ci` the ASDU, applies the `RQT`/`FRZ` the library's
/// reaction names to the model, and sends what the library built.
pub struct CounterApp {
    ci: CounterInterrogation,
    tx: Transmission,
    model: Model,
    local: Option<LocalFreeze>,
    log: Arc<Mutex<Vec<Reaction>>>,
}

impl CounterApp {
    fn new(mode: CounterMode) -> (Self, Arc<Mutex<Vec<Reaction>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let app = Self {
            ci: CounterInterrogation::controlled(mode, CA, ORIGINATOR),
            tx: Transmission::controlled(
                StationFunctions::NONE.with(Function::Spontaneous, true),
                ProjectList::empty(),
                CA,
                ORIGINATOR,
            ),
            model: Model::new(),
            local: None,
            log: Arc::clone(&log),
        };
        (app, log)
    }
}

impl StationApp for CounterApp {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
        if header.type_id != TypeId::CCiNa1 {
            return Ok(station_reply(asdu)?.into_iter().collect());
        }
        let known = station_profile(asdu)?;
        let outcome = self
            .ci
            .on_request(asdu, &known, &self.model)
            .map_err(|e| format!("ci: {e:?}"))?;
        self.log.lock().expect("the log").push(outcome.reaction);
        let mut out = outcome.send;
        if let Reaction::ActivationConfirmed {
            request,
            freeze,
            negative: false,
        } = outcome.reaction
            && self.model.memorise(request, freeze)
            && self.ci.mode().reports_spontaneously()
        {
            // Mode D: the frozen values go out spontaneously.
            out.extend(self.model.spontaneous(&self.tx, request)?);
        }
        if self.ci.awaiting_data() {
            out.extend(
                self.ci
                    .complete(&self.model)
                    .map_err(|e| format!("ci: {e:?}"))?,
            );
        }
        Ok(out)
    }

    fn poll(&mut self, now: Instant) -> Result<Vec<Vec<u8>>, String> {
        let Some(local) = self.local.as_mut() else {
            return Ok(Vec::new());
        };
        if local.left == 0 {
            return Ok(Vec::new());
        }
        let next = *local.next.get_or_insert(now + local.interval);
        if now < next {
            return Ok(Vec::new());
        }
        local.next = Some(next + local.interval);
        local.left -= 1;
        for c in &mut self.model.counters {
            c.actual += local.step;
        }
        self.model
            .memorise(Request::General, FreezeMode::FreezeWithoutReset);
        self.model.spontaneous(&self.tx, Request::General)
    }
}

/// Starts a controlled station running [`CounterApp`] in `mode` and connects
/// the mock controlling station to it.
fn controlled(
    mode: CounterMode,
    local: Option<LocalFreeze>,
) -> (ControlledStation, Link, Arc<Mutex<Vec<Reaction>>>) {
    let (mut app, log) = CounterApp::new(mode);
    app.local = local;
    let station = ControlledStation::start_app(app, Vec::new()).expect("the station binds");
    let link = Link::start(station.addr()).expect("the controlling station starts");
    (station, link, log)
}

/// Closes the link and waits for the station, failing on its own error.
fn end(station: ControlledStation, link: Link) {
    link.finish().expect("the peer closes");
    station.join().expect("the station ends cleanly");
}

/// The cause of a collection's objects, from 5-101 table 14 (clause 7.2.3):
/// `<37>` for the general counter request, `<38..41>` for the group 1 … 4
/// counter requests.
fn collection_cause(request: Request) -> u8 {
    37 + request.group_number().unwrap_or(0)
}

/// Asserts that `asdu` is one `M_IT` of a collection for `request`: one of the
/// two `M_IT` types, cause `<37>` (general) or `<37 + n>` (group `n`), the
/// station's own common address `ca`, a counter of the group, and the frozen
/// value `reading` says that counter holds.
fn assert_collected(
    what: &str,
    asdu: &[u8],
    request: Request,
    ca: u16,
    reading: impl Fn(u32) -> i32,
) -> u32 {
    let (header, ioa, bcr, _) = read_total(asdu);
    let rqt = request.group_number().unwrap_or(5);
    assert!(
        COUNTER_TYPES.contains(&header.type_id),
        "{what}: an M_IT type, got {:?}",
        header.type_id
    );
    assert_eq!(
        header.cause.to_u8(),
        collection_cause(request),
        "{what}: the cause (37-41) that matches RQT {rqt}"
    );
    assert!(!header.negative, "{what}: P/N = 0");
    assert_eq!(header.common_address, ca, "{what}: the station's own CASDU");
    assert!(
        request
            .group_number()
            .is_none_or(|g| counter(ioa).group == g),
        "{what}: {ioa:#x} is not a counter of RQT {rqt}"
    );
    assert_eq!(bcr.reading, reading(ioa), "{what}: the value at {ioa:#x}");
    ioa
}

// ------------------------------------------------------------- mode A

/// 604 Table 20 (1 of 4), PDF page index 78 (printed 77), procedure
/// **`5.4.20.1`**, *"Transmission of integrated totals – sequential procedure:
/// Mode A – Local freeze with spontaneous transmission"*, `Reference`
/// `IEC 60870-5-101:2003, 7.4.8`, `IEC 60870-5-5:1995, 6.9.1`, `Required` `M`:
///
/// the controlled station reports counter values (in the ASDUs its PICS
/// declares) as events, cause 3 (`SPONT`), with a correct time tag where the
/// type has one, at the intervals it is configured for; and this must hold for
/// each `M_IT` ASDU of the PICS that allows cause 3.
///
/// DUT: the **controlled** station. Its local clock ([`LocalFreeze`], the
/// harness's) freezes twice; each time the station's `tx` builds one `M_IT` per
/// counter with cause 3. Asserted from the standard: the cause, `P/N = 0`, the
/// station's common address, both `M_IT` types of 5-104 clause 9's selection on
/// the wire (`M_IT_NA_1` and `M_IT_TB_1`), and the `CP56Time2a` the station
/// stamped read back intact from figure 73's position (5-101 clause 7.3.1).
///
/// The two plausibility rows (the value is the increment or the integrated
/// total frozen locally; the sequence number `SQ` moves on each transmission
/// interval)
/// are the harness's figure 92 model; they are observed below to show the
/// library carries the model's `BCR` unchanged, not as a property of the
/// library.
#[test]
fn clause_5_4_20_1_mode_a_the_controlled_station_reports_its_totals_spontaneously() {
    let step = 7;
    let (station, mut link, log) = controlled(
        CounterMode::LocalFreezeSpontaneous,
        Some(LocalFreeze {
            interval: Duration::from_millis(30),
            step,
            left: 2,
            next: None,
        }),
    );
    let frames = link.recv_n(2 * COUNTERS.len()).expect("two intervals");
    assert_eq!(
        link.quiet(),
        Ok(()),
        "5.4.20.1: two intervals were configured"
    );
    end(station, link);
    assert!(
        log.lock().expect("the log").is_empty(),
        "5.4.20.1: mode A: the controlling station sends no counter interrogation \
         (C_CI) in this mode (5-101 cl.7.4.8), and none was received"
    );

    let mut types = Vec::new();
    for (i, asdu) in frames.iter().enumerate() {
        let interval = i / COUNTERS.len() + 1;
        let (header, ioa, bcr, time) = read_total(asdu);
        let c = counter(ioa);
        assert_eq!(
            header.cause,
            Cause::Spontaneous,
            "5.4.20.1: COT = 3 (SPONT)"
        );
        assert!(!header.negative, "5.4.20.1: P/N = 0");
        assert_eq!(header.common_address, CA, "5.4.20.1: the station's CASDU");
        assert_eq!(
            header.type_id,
            if c.tagged {
                TypeId::MItTb1
            } else {
                TypeId::MItNa1
            },
            "5.4.20.1: the counter's own M_IT type"
        );
        if c.tagged {
            assert_eq!(
                time,
                Some(sample_time()),
                "5.4.20.1: the time tag is the correct one"
            );
        }
        // The harness's figure 92 model, carried unchanged: the frozen
        // integrated total and a sequence number that moves each interval.
        assert_eq!(bcr.reading, c.actual + step * interval as i32);
        assert_eq!(bcr.sequence, interval as u8);
        types.push(header.type_id);
    }
    for t in COUNTER_TYPES {
        assert!(
            types.contains(&t),
            "5.4.20.1: each M_IT ASDU allowing cause 3: {t:?} not seen"
        );
    }
}

/// The same row's ASDU set, from the library's rules rather than the wire:
/// the tests must hold for each `M_IT` ASDU of the PICS that allows cause 3
/// (`Reference` `IEC 60870-5-101:2003, 8.5, 8.6`, `Required` `M`, index 78).
///
/// The `M_IT` ASDUs a 104 PICS can carry are 5-101 clause 7.3.1's three minus
/// the one 5-104 clause 9 (PDF page index 100 of 5-104) strikes: it allows
/// only `<30>` – `<40>` as time-tagged ASDUs in 104. So `M_IT_NA_1` `<15>` and `M_IT_TB_1` `<37>` are
/// spontaneous types and `M_IT_TA_1` `<16>` is not.
#[test]
fn clause_5_4_20_1_every_m_it_asdu_104_permits_is_a_spontaneous_type() {
    assert!(tx::is_spontaneous_type(TypeId::MItNa1), "<15> M_IT_NA_1");
    assert!(tx::is_spontaneous_type(TypeId::MItTb1), "<37> M_IT_TB_1");
    assert!(
        !tx::is_spontaneous_type(TypeId::MItTa1),
        "<16> M_IT_TA_1 carries a CP24Time2a, outside <30>..<40>"
    );
    assert_eq!(COUNTER_TYPES, [TypeId::MItNa1, TypeId::MItTb1]);
}

/// 604 `5.4.20.1` in the reverse direction (§5.1), index 78, `Required` `M`:
/// the same rows with the library as the **controlling** station, which
/// receives the counter values the mock controlled station sends as events
/// (COT 3).
///
/// Asserted: the library's `tx` classifies both `M_IT` types with cause 3 as
/// spontaneous; `ci` does not take them for a collection's objects; the
/// decoded `BCR` and `CP56Time2a` are exactly the octets the peer sent (what a
/// controlling station stores comes from here); and, from 5-101 clause 7.4.8's
/// mode A, where the controlling station sends no counter interrogation
/// (`C_CI`): `ci` refuses to build one and none goes on the wire.
#[test]
fn clause_5_4_20_1_mode_a_the_controlling_station_takes_the_spontaneous_totals() {
    let sent = [
        m_it(
            false,
            Cause::Spontaneous,
            CA,
            0x4001,
            Bcr {
                reading: 1_234,
                sequence: 3,
                ..Bcr::default()
            },
        ),
        m_it(
            true,
            Cause::Spontaneous,
            CA,
            0x4002,
            Bcr {
                reading: -5,
                sequence: 31,
                carry: true,
                ..Bcr::default()
            },
        ),
    ];
    let peer = ScriptedPeer::start(sent.to_vec(), Vec::new()).expect("the peer binds");
    let mut station = started_station(peer.addr()).expect("the station starts");
    let got = station_recv_n(&mut station, sent.len()).expect("both totals");

    let mut ci = CounterInterrogation::controlling(CounterMode::LocalFreezeSpontaneous, CA, 0);
    assert_eq!(
        ci.request(Request::General, FreezeMode::Read),
        Err(CiError::RequestsNotAccepted {
            mode: CounterMode::LocalFreezeSpontaneous
        }),
        "5-101 cl.7.4.8, mode A: no C_CI"
    );
    let tx = Transmission::controlling(CA, 0);
    for (asdu, want) in got.iter().zip(&sent) {
        assert_eq!(asdu, want, "5.4.20.1: the total arrives as it was sent");
        let known = counter_known(asdu);
        let header = Header::parse(asdu).expect("the header");
        assert_eq!(
            tx.on_response(asdu, &known).expect("tx").reaction,
            tx::Reaction::Spontaneous {
                type_id: header.type_id
            },
            "5.4.20.1: an event with cause 3 (SPONT)"
        );
        assert_eq!(
            ci.on_response(asdu, &known).expect("ci").reaction,
            Reaction::Other,
            "5.4.20.1: a spontaneous total is not a collection's object"
        );
    }
    let (_, _, bcr, time) = read_total(&got[1]);
    assert_eq!(
        (bcr.reading, bcr.sequence, bcr.carry, time),
        (-5, 31, true, Some(sample_time())),
        "5.4.20.1: the values the controlling station stores are the ones sent"
    );
    station.close().expect("the station closes");
    let report = peer.join().expect("the peer ends");
    assert!(
        report.requests.is_empty(),
        "5.4.20.1: the controlling station sent no C_CI: {:?}",
        report.requests
    );
}

/// The controlling station's answers for a received counter frame: the
/// standard's types and causes, its own common address, and the counters of
/// [`COUNTERS`] plus the irrelevant address 0 a `C_CI_NA_1` carries (figure
/// 73) as the objects it knows.
fn counter_known(asdu: &[u8]) -> Known {
    let header = Header::parse(asdu).expect("the header");
    let ioa = iec104::asdu::read_ioa(&asdu[Header::LEN..]).expect("the address");
    Known::standard(
        &header,
        header.common_address == CA,
        ioa == 0 || COUNTERS.iter().any(|c| c.ioa == ioa),
    )
}

// ------------------------------------------------------------- mode B

/// 604 Table 20 (2 of 4), PDF page index 79 (printed 78), procedure
/// **`5.4.20.10`**, *"Transmission of integrated totals – sequential procedure:
/// Mode B – Local freeze with Counter Interrogation"*, `Reference`
/// `IEC 60870-5-101:2003, 7.4.8`, every row below `Required` `M`: the
/// controlling station sends a counter interrogation (ASDU 101, cause 6,
/// `ACT`) with `FRZ` = 0 (neither freeze nor reset) and the general `RQT`; the
/// controlled station sends the command back with cause 7 (`ACTCON`), then
/// every counter object the requested `RQT` covers, each with its matching
/// cause (37 to 41), then the command it received once more with cause 10
/// (`ACTTERM`). This must hold for each `M_IT` ASDU of the PICS that allows
/// causes 37 to 41.
///
/// The row gives the general request as `RQT` 1; 5-101 clause 7.2.6.23 makes the general
/// request `RQT = <5>` and `<1>` group 1, so the general request here is `RQT`
/// 5 and group 1 is driven by the groups case below.
///
/// DUT: the **controlled** station. Expected frames: the confirmation and the
/// termination are the request's own ten octets with the cause octet 7 and 10
/// (5-101 figure 94); every counter of the station is returned once, between
/// them, with cause 37, with the frozen value the station holds (the local
/// freeze of mode B is the application's and is not run here). The request is
/// sent twice: a collection can be repeated, which is what the controlling
/// station's configured intervals need.
#[test]
fn clause_5_4_20_10_mode_b_the_general_request_is_confirmed_answered_and_terminated() {
    let (station, mut link, log) = controlled(CounterMode::LocalFreezeByInterrogation, None);
    for round in 1..=2 {
        let what = format!("5.4.20.10 (round {round})");
        link.send(&c_ci(6, CA, qcc(5, 0))).expect("C_CI ACT");
        let frames = link.recv_n(COUNTERS.len() + 2).expect("the collection");
        assert_eq!(
            frames[0],
            c_ci(7, CA, qcc(5, 0)),
            "{what}: C_CI_ACTCON mirrors the command"
        );
        let mut seen = Vec::new();
        let mut types = Vec::new();
        for asdu in &frames[1..=COUNTERS.len()] {
            let ioa =
                assert_collected(&what, asdu, Request::General, CA, |ioa| counter(ioa).frozen);
            seen.push(ioa);
            types.push(Header::parse(asdu).expect("the header").type_id);
        }
        seen.sort_unstable();
        assert_eq!(
            seen,
            COUNTERS.iter().map(|c| c.ioa).collect::<Vec<_>>(),
            "{what}: every counter object of the general request, once each"
        );
        for t in COUNTER_TYPES {
            assert!(
                types.contains(&t),
                "{what}: each M_IT ASDU allowing causes 37-41: {t:?}"
            );
        }
        assert_eq!(
            frames[COUNTERS.len() + 1],
            c_ci(10, CA, qcc(5, 0)),
            "{what}: C_CI_ACTTERM is the same command with COT = 10"
        );
        assert_eq!(
            link.quiet(),
            Ok(()),
            "{what}: nothing after the termination"
        );
    }
    end(station, link);
    assert_eq!(
        *log.lock().expect("the log"),
        vec![
            Reaction::ActivationConfirmed {
                request: Request::General,
                freeze: FreezeMode::Read,
                negative: false,
            };
            2
        ]
    );
}

/// 604 `5.4.20.10`, index 79, the counter-group row, `Required` `PICS, 9.6
/// Transmission of integrated totals`:
///
/// the tests must hold for each counter group the station supports: the
/// controlling station sends the counter interrogation (ASDU 101, cause 6,
/// `ACT`, `FRZ` = 0, neither freeze nor reset) with `RQT` 1 to 4 (groups 1 to
/// 4), and at least two groups are tested unless the station supports only
/// one.
///
/// DUT: the **controlled** station, all four groups. For group `n` the objects
/// carry cause `<37 + n>` (5-101 clause 7.2.3, `<38..41>`: the group 1 … 4
/// counter requests) and are exactly the counters configured in group
/// `n`; the confirmation and termination mirror `RQT = n`.
#[test]
fn clause_5_4_20_10_mode_b_every_counter_group_is_collected_on_its_own() {
    let (station, mut link, _) = controlled(CounterMode::LocalFreezeByInterrogation, None);
    for group in 1..=4u8 {
        let what = format!("5.4.20.10 (RQT {group})");
        let request = Request::Group(group);
        let n = members(request).len();
        assert!(n >= 1, "{what}: the group has counters");
        link.send(&c_ci(6, CA, qcc(group, 0))).expect("C_CI ACT");
        let frames = link.recv_n(n + 2).expect("the collection");
        assert_eq!(frames[0], c_ci(7, CA, qcc(group, 0)), "{what}: ACTCON");
        for asdu in &frames[1..=n] {
            assert_collected(&what, asdu, request, CA, |ioa| counter(ioa).frozen);
        }
        assert_eq!(
            frames[n + 1],
            c_ci(10, CA, qcc(group, 0)),
            "{what}: ACTTERM"
        );
        assert_eq!(
            link.quiet(),
            Ok(()),
            "{what}: nothing after the termination"
        );
    }
    end(station, link);
}

/// 604 `5.4.20.10`, index 79, the broadcast row, `Required` `PIXIT`:
///
/// where the station supports it, the counter interrogation should also be
/// tested addressed to the broadcast CASDU, and the controlled station should
/// answer with its own CASDU (or CASDUs).
///
/// DUT: the **controlled** station. 604 `5.4.10.10` (index 54) permits the
/// broadcast CASDU with type 101. The request goes to `FF FF`; the confirmation
/// and the termination are the command with the station's own CASDU in place of
/// the broadcast one (the library builds both), and the objects carry it too
/// (the application builds those).
#[test]
fn clause_5_4_20_10_mode_b_a_broadcast_request_is_answered_with_the_own_casdu() {
    let (station, mut link, _) = controlled(CounterMode::LocalFreezeByInterrogation, None);
    link.send(&c_ci(6, BROADCAST, qcc(5, 0))).expect("C_CI ACT");
    let frames = link.recv_n(COUNTERS.len() + 2).expect("the collection");
    assert_eq!(
        frames[0],
        c_ci(7, CA, qcc(5, 0)),
        "5.4.20.10: ACTCON, own CASDU"
    );
    for asdu in &frames[1..=COUNTERS.len()] {
        assert_collected("5.4.20.10", asdu, Request::General, CA, |ioa| {
            counter(ioa).frozen
        });
    }
    assert_eq!(
        frames[COUNTERS.len() + 1],
        c_ci(10, CA, qcc(5, 0)),
        "5.4.20.10: ACTTERM, own CASDU"
    );
    end(station, link);
}

/// The `QCC` octet of `request` with `freeze`, from 5-101 clause 7.2.6.23's
/// numbering (`FRZ` `<0>` read, `<1>` freeze without reset, `<2>` freeze with
/// reset, `<3>` reset; `RQT` `<5>` general, `<1..4>` the groups).
fn qcc_of(request: Request, freeze: FreezeMode) -> u8 {
    let frz = match freeze {
        FreezeMode::Read => 0,
        FreezeMode::FreezeWithoutReset => 1,
        FreezeMode::FreezeWithReset => 2,
        FreezeMode::Reset => 3,
    };
    qcc(request.group_number().unwrap_or(5), frz)
}

/// One scripted collection as the mock controlled station answers it (5-101
/// figure 94): the command mirrored with cause 7, one `M_IT` per `(ioa,
/// reading)` with the request's cause `<37..41>`, the command mirrored with
/// cause 10.
fn scripted_collection(request: Request, objects: &[(u32, i32)]) -> Vec<Vec<u8>> {
    let q = qcc_of(request, FreezeMode::Read);
    let cause = Cause::from_u8(collection_cause(request));
    let mut out = vec![c_ci(7, CA, q)];
    for &(ioa, reading) in objects {
        let bcr = Bcr {
            reading,
            sequence: 1,
            ..Bcr::default()
        };
        out.push(m_it(counter(ioa).tagged, cause, CA, ioa, bcr));
    }
    out.push(c_ci(10, CA, q));
    out
}

/// Runs `requests` from the library's `ci` as the **controlling** station
/// against a mock controlled station answering each with the batch the case
/// wrote in `replies`, and returns what the peer read plus, per request, the
/// library's reaction to every answer.
fn controlling_run(
    ci: &mut CounterInterrogation,
    requests: &[(Request, FreezeMode)],
    replies: Vec<Vec<Vec<u8>>>,
) -> (Vec<Vec<u8>>, Vec<Vec<Reaction>>) {
    let counts: Vec<usize> = replies.iter().map(Vec::len).collect();
    let peer = ScriptedPeer::start(Vec::new(), replies).expect("the peer binds");
    let mut station = started_station(peer.addr()).expect("the station starts");
    let mut reactions = Vec::new();
    for (&(request, freeze), &n) in requests.iter().zip(&counts) {
        let asdu = ci.request(request, freeze).expect("ci builds the request");
        station_send(&mut station, &asdu).expect("the request goes out");
        let answers = station_recv_n(&mut station, n).expect("the scripted answers");
        reactions.push(
            answers
                .iter()
                .map(|a| ci.on_response(a, &counter_known(a)).expect("ci").reaction)
                .collect(),
        );
    }
    station.close().expect("the station closes");
    let report = peer.join().expect("the peer ends");
    (report.requests, reactions)
}

/// 604 `5.4.20.10` in the reverse direction (§5.1), index 79, the rows about
/// the **controlling** station, `Required` `M`:
///
/// the controlling station sends the counter interrogation (ASDU 101, cause 6,
/// `ACT`, `FRZ` = 0, neither freeze nor reset, general `RQT`) to the controlled
/// station, and does so at its configured intervals; together with the groups
/// row (`RQT=1...4`).
///
/// DUT: the **controlling** station. What goes on the wire is compared octet
/// for octet with figure 73 and clause 7.2.6.23 (`FRZ = 0`, `RQT` 5 for the
/// general request and 1 to 4 for the groups); the library's reactions to the
/// scripted answers are the confirmation, one counted object per `M_IT` and the
/// termination, and nothing is left running. The general request runs twice
/// (a repeatable collection is what an interval needs). Mode B's own rule,
/// 5-101 clause 7.4.8: the counter interrogation may not ask for a freeze, with
/// or without reset, so its qualifier must carry `FRZ` = 0: `ci` refuses to
/// build one that does not.
#[test]
fn clause_5_4_20_10_mode_b_the_controlling_station_collects_general_and_groups() {
    let mode = CounterMode::LocalFreezeByInterrogation;
    let requests: Vec<(Request, FreezeMode)> = [
        Request::General,
        Request::Group(1),
        Request::Group(2),
        Request::Group(3),
        Request::Group(4),
        Request::General,
    ]
    .into_iter()
    .map(|r| (r, FreezeMode::Read))
    .collect();
    let replies = requests
        .iter()
        .map(|&(r, _)| {
            let objects: Vec<(u32, i32)> = members(r).iter().map(|c| (c.ioa, c.frozen)).collect();
            scripted_collection(r, &objects)
        })
        .collect();
    let mut ci = CounterInterrogation::controlling(mode, CA, ORIGINATOR);
    assert_eq!(
        ci.request(Request::General, FreezeMode::FreezeWithoutReset),
        Err(CiError::FreezeNotAllowed { mode }),
        "5-101 cl.7.4.8, mode B: FRZ = 0 only"
    );
    let (sent, reactions) = controlling_run(&mut ci, &requests, replies);

    assert_eq!(
        sent.len(),
        requests.len(),
        "5.4.20.10: one C_CI per request"
    );
    for ((asdu, &(request, _)), got) in sent.iter().zip(&requests).zip(&reactions) {
        assert_eq!(
            *asdu,
            c_ci(6, CA, qcc_of(request, FreezeMode::Read)),
            "5.4.20.10: C_CI_ACT, COT=6, FRZ=0, RQT of {request:?}"
        );
        let mut want = vec![Reaction::ActivationConfirmed {
            request,
            freeze: FreezeMode::Read,
            negative: false,
        }];
        want.extend(vec![Reaction::Counted { request }; members(request).len()]);
        want.push(Reaction::Terminated { request });
        assert_eq!(*got, want, "5.4.20.10: {request:?}");
    }
    assert!(ci.running().is_empty(), "5.4.20.10: every collection ended");
}

/// 604 `5.4.20.10`, index 79, the broadcast row (`PIXIT`), with the library as
/// the **controlling** station: the command goes out with the broadcast CASDU
/// `FF FF`, the mock controlled station answers with its own CASDU, as the row
/// says it should, and the library
/// takes those answers as the procedure's.
#[test]
fn clause_5_4_20_10_mode_b_the_controlling_station_takes_answers_to_a_broadcast() {
    let objects: Vec<(u32, i32)> = COUNTERS.iter().map(|c| (c.ioa, c.frozen)).collect();
    let mut ci = CounterInterrogation::controlling(
        CounterMode::LocalFreezeByInterrogation,
        BROADCAST,
        ORIGINATOR,
    );
    let (sent, reactions) = controlling_run(
        &mut ci,
        &[(Request::General, FreezeMode::Read)],
        vec![scripted_collection(Request::General, &objects)],
    );
    assert_eq!(sent, vec![c_ci(6, BROADCAST, qcc(5, 0))]);
    let mut want = vec![Reaction::ActivationConfirmed {
        request: Request::General,
        freeze: FreezeMode::Read,
        negative: false,
    }];
    want.extend(vec![
        Reaction::Counted {
            request: Request::General
        };
        COUNTERS.len()
    ]);
    want.push(Reaction::Terminated {
        request: Request::General,
    });
    assert_eq!(reactions, vec![want]);
    assert_eq!(ci.running(), [] as [iec104::ci::Request; 0]);
}

// ------------------------------------------------------------- mode C

/// 604 Table 20 (3 of 4), PDF page index 80 (printed 79), procedure
/// **`5.4.20.20`**, *"Transmission of integrated totals – sequential procedure:
/// Mode C – Remote initiated freeze with Counter Interrogation"*, `Reference`
/// `IEC 60870-5-101:2003, 7.4.8`, every row below `Required` `M`:
///
/// the controlling station sends a counter interrogation (ASDU 101, cause 6,
/// `ACT`) with `FRZ` 1 to 3 (freeze, freeze with reset, reset) and the general
/// `RQT`; the controlled station confirms that same command with cause 7
/// (`ACTCON`) and memorises the counters the `RQT` selects, leaving every other
/// counter value, and any counter still waiting to be sent, untouched. Then
/// comes the collection (`FRZ = 0`), its confirmation, its objects with causes
/// 37 to 41, its `C_CI_ACTTERM`, and a plausibility check that each value is
/// the increment or the integrated total memorised by the preceding memorise
/// command.
///
/// DUT: the **controlled** station, with the group row (`FRZ=1`,
/// `RQT=1...4`, `PICS 9.6`). The memorize command is answered with its
/// confirmation only: 5-101 figure 95 draws `C_CI ACT` then `C_CI ACTCON` and
/// then the collection of the frozen values as in mode B, and clause 7.4.8
/// states that this command by itself transmits no counter values, so no
/// object and no termination follow it.
///
/// The library hands the application the command's own `RQT` and `FRZ`
/// (asserted on its reaction); the application's figure 92 model memorises
/// only that group. Freezing group 1, then 2, 3 and 4 and collecting the
/// general request after each therefore shows the frozen value (the configured
/// actual value) for the frozen groups and the old one for the rest.
#[test]
fn clause_5_4_20_20_mode_c_a_group_freeze_is_confirmed_and_touches_only_its_group() {
    let (station, mut link, log) = controlled(CounterMode::FreezeAndTransmit, None);
    for group in 1..=4u8 {
        let what = format!("5.4.20.20 (FRZ 1, RQT {group})");
        link.send(&c_ci(6, CA, qcc(group, 1)))
            .expect("C_CI ACT FRZ=1");
        assert_eq!(
            link.recv().expect("the confirmation"),
            c_ci(7, CA, qcc(group, 1)),
            "{what}: ACTCON of the same command"
        );
        assert_eq!(
            link.quiet(),
            Ok(()),
            "{what}: a memorize transmits nothing and is not terminated"
        );

        link.send(&c_ci(6, CA, qcc(5, 0))).expect("C_CI ACT FRZ=0");
        let frames = link.recv_n(COUNTERS.len() + 2).expect("the collection");
        assert_eq!(frames[0], c_ci(7, CA, qcc(5, 0)), "{what}: ACTCON");
        for asdu in &frames[1..=COUNTERS.len()] {
            assert_collected(&what, asdu, Request::General, CA, |ioa| {
                let c = counter(ioa);
                if c.group <= group { c.actual } else { c.frozen }
            });
        }
        assert_eq!(
            frames[COUNTERS.len() + 1],
            c_ci(10, CA, qcc(5, 0)),
            "{what}: ACTTERM"
        );
    }
    end(station, link);
    let log = log.lock().expect("the log");
    for group in 1..=4u8 {
        assert_eq!(
            log[2 * (group as usize - 1)],
            Reaction::ActivationConfirmed {
                request: Request::Group(group),
                freeze: FreezeMode::FreezeWithoutReset,
                negative: false,
            },
            "5.4.20.20: the library names RQT {group} and FRZ 1 to the application"
        );
    }
}

/// 604 `5.4.20.20`, index 80, the first row (`FRZ=1..3` with the general
/// request, `M`) and the reset row, `Required` `PICS, 9.6`:
///
/// the tests must hold for each counter reset option the station supports: the
/// controlling station sends the counter interrogation (ASDU 101, cause 6,
/// `ACT`) with `FRZ` 2 or 3 (freeze with reset, or reset alone) and `RQT` 5
/// (general); plus the broadcast row (`PIXIT`), where the controlled station
/// should answer with its own CASDU (or CASDUs).
///
/// DUT: the **controlled** station. Each of `FRZ` 1, 2 and 3 on `RQT` 5, and
/// `FRZ` 1 to the broadcast CASDU, is confirmed with the same command (own
/// CASDU) and nothing else, and the library names each `FRZ` to the
/// application.
#[test]
fn clause_5_4_20_20_mode_c_every_freeze_and_reset_option_is_confirmed() {
    let (station, mut link, log) = controlled(CounterMode::FreezeAndTransmit, None);
    for (ca, frz) in [(CA, 1), (CA, 2), (CA, 3), (BROADCAST, 1)] {
        let what = format!("5.4.20.20 (CASDU {ca:#x}, FRZ {frz}, RQT 5)");
        link.send(&c_ci(6, ca, qcc(5, frz))).expect("C_CI ACT");
        assert_eq!(
            link.recv().expect("the confirmation"),
            c_ci(7, CA, qcc(5, frz)),
            "{what}: ACTCON of the same command, own CASDU"
        );
        assert_eq!(link.quiet(), Ok(()), "{what}: nothing else");
    }
    end(station, link);
    let freezes: Vec<Reaction> = [
        FreezeMode::FreezeWithoutReset,
        FreezeMode::FreezeWithReset,
        FreezeMode::Reset,
        FreezeMode::FreezeWithoutReset,
    ]
    .into_iter()
    .map(|freeze| Reaction::ActivationConfirmed {
        request: Request::General,
        freeze,
        negative: false,
    })
    .collect();
    assert_eq!(*log.lock().expect("the log"), freezes);
}

/// 604 `5.4.20.20` in the reverse direction (§5.1), index 80, the rows about
/// the **controlling** station (`M`): it sends a counter interrogation (ASDU
/// 101, cause 6, `C_CI_ACT`) with `FRZ` 1 to 3, then another with `FRZ` = 0
/// (neither freeze nor reset) and `RQT` 1 to 5, with the group row
/// (`FRZ=1`, `RQT=1...4`) and the reset row (`FRZ=2 or 3`, `RQT=5`).
///
/// DUT: the **controlling** station. Each command is figure 73's frame with
/// clause 7.2.6.23's `QCC`; a memorize answered by its confirmation alone is
/// complete (nothing left running, 5-101 figure 95), and the collection that
/// follows runs as in mode B.
#[test]
fn clause_5_4_20_20_mode_c_the_controlling_station_freezes_then_collects() {
    let requests = [
        (Request::General, FreezeMode::FreezeWithoutReset),
        (Request::Group(1), FreezeMode::FreezeWithoutReset),
        (Request::Group(2), FreezeMode::FreezeWithoutReset),
        (Request::General, FreezeMode::FreezeWithReset),
        (Request::General, FreezeMode::Reset),
        (Request::General, FreezeMode::Read),
        (Request::Group(1), FreezeMode::Read),
    ];
    let replies = requests
        .iter()
        .map(|&(request, freeze)| {
            if freeze == FreezeMode::Read {
                let objects: Vec<(u32, i32)> =
                    members(request).iter().map(|c| (c.ioa, c.actual)).collect();
                scripted_collection(request, &objects)
            } else {
                vec![c_ci(7, CA, qcc_of(request, freeze))]
            }
        })
        .collect();
    let mut ci = CounterInterrogation::controlling(CounterMode::FreezeAndTransmit, CA, ORIGINATOR);
    let (sent, reactions) = controlling_run(&mut ci, &requests, replies);
    assert_eq!(
        sent.len(),
        requests.len(),
        "5.4.20.20: one C_CI per command"
    );
    for ((asdu, &(request, freeze)), got) in sent.iter().zip(&requests).zip(&reactions) {
        let what = format!("5.4.20.20 ({request:?}, {freeze:?})");
        assert_eq!(
            *asdu,
            c_ci(6, CA, qcc_of(request, freeze)),
            "{what}: C_CI_ACT"
        );
        let mut want = vec![Reaction::ActivationConfirmed {
            request,
            freeze,
            negative: false,
        }];
        if freeze == FreezeMode::Read {
            want.extend(vec![Reaction::Counted { request }; members(request).len()]);
            want.push(Reaction::Terminated { request });
        }
        assert_eq!(*got, want, "{what}");
    }
    assert!(ci.running().is_empty(), "5.4.20.20: nothing left running");
}

// ------------------------------------------------------------- mode D

/// 604 Table 20 (4 of 4), PDF page index 81 (printed 80), procedure
/// **`5.4.20.30`**, *"Transmission of integrated totals – sequential procedure:
/// Mode D – Remote initiated freeze with spontaneous transmission"*,
/// `Reference` `IEC 60870-5-101:2003, 7.4.8`, every row below `Required` `M`:
///
/// the controlling station sends a counter interrogation (ASDU 101, cause 6,
/// `ACT`) with `FRZ` 1 to 3 (freeze, freeze with reset, reset) and `RQT` 5
/// (general); the controlled station confirms that same command with cause 7
/// (`ACTCON`) and reports the counter values (in the ASDUs its PICS declares)
/// as events, cause 3 (`SPONT`), with a correct time tag where the type has
/// one. A note on the row says the order of the `ACTCON` and the events does
/// not matter and must not be tested. All of this must hold for each `M_IT`
/// ASDU of the PICS that allows cause 3.
///
/// with the group row (`FRZ=1`, `RQT=1...4`, `PICS 9.6`), the reset row
/// (`FRZ=2 or 3`, `RQT=5`) and the broadcast row (`PIXIT`).
///
/// DUT: the **controlled** station. Each command is confirmed with the same
/// command (own CASDU) and never terminated (the row draws no `C_CI_ACTTERM`),
/// and every counter the `RQT` names follows as a cause-3 `M_IT` in either
/// order, with the value just memorised. `FRZ = 3` is *"counter reset"* (5-101
/// clause 7.2.6.23), which memorises nothing (figure 92), so it has a
/// confirmation and no value to report. The spontaneous report is the library's
/// `ci` mode predicate (`reports_spontaneously`) and its `tx` builder; the
/// frozen values are the application's model, mirrored here to know what to
/// expect.
#[test]
fn clause_5_4_20_30_mode_d_a_freeze_is_confirmed_and_reported_spontaneously() {
    let (station, mut link, log) = controlled(CounterMode::FreezeSpontaneous, None);
    let cases: [(u16, Request, u8); 7] = [
        (CA, Request::General, 1),
        (CA, Request::Group(1), 1),
        (CA, Request::Group(2), 1),
        (CA, Request::Group(3), 1),
        (CA, Request::Group(4), 1),
        (CA, Request::General, 2),
        (BROADCAST, Request::General, 1),
    ];
    let mut model = Model::new();
    for (ca, request, frz) in cases {
        let rqt = request.group_number().unwrap_or(5);
        let what = format!("5.4.20.30 (CASDU {ca:#x}, FRZ {frz}, RQT {rqt})");
        model.memorise(request, FreezeMode::from_bits(frz));
        link.send(&c_ci(6, ca, qcc(rqt, frz))).expect("C_CI ACT");
        let n = members(request).len();
        let frames = link.recv_n(n + 1).expect("the answers");
        assert_eq!(
            link.quiet(),
            Ok(()),
            "{what}: no C_CI_ACTTERM, nothing else"
        );
        let (con, totals): (Vec<_>, Vec<_>) = frames
            .into_iter()
            .partition(|a| Header::parse(a).expect("header").type_id == TypeId::CCiNa1);
        assert_eq!(con, vec![c_ci(7, CA, qcc(rqt, frz))], "{what}: one ACTCON");
        let mut seen = Vec::new();
        for asdu in &totals {
            let (header, ioa, bcr, time) = read_total(asdu);
            let held = model
                .counters
                .iter()
                .find(|c| c.ioa == ioa)
                .expect("a configured counter");
            assert_eq!(header.cause, Cause::Spontaneous, "{what}: COT = 3");
            assert!(!header.negative, "{what}: P/N = 0");
            assert_eq!(header.common_address, CA, "{what}: own CASDU");
            assert!(
                request.group_number().is_none_or(|g| held.group == g),
                "{what}: {ioa:#x} is not in the RQT"
            );
            assert_eq!(
                (bcr.reading, bcr.sequence),
                (held.frozen, held.sq),
                "{what}: the value just memorised"
            );
            if held.tagged {
                assert_eq!(time, Some(sample_time()), "{what}: the time tag");
            }
            seen.push(header.type_id);
        }
        if request.is_general() {
            for t in COUNTER_TYPES {
                assert!(seen.contains(&t), "{what}: every M_IT with COT 3: {t:?}");
            }
        }
    }
    // Reset only: confirmed, nothing memorised, nothing reported.
    link.send(&c_ci(6, CA, qcc(5, 3))).expect("C_CI ACT FRZ=3");
    assert_eq!(
        link.recv().expect("the confirmation"),
        c_ci(7, CA, qcc(5, 3)),
        "5.4.20.30 (FRZ 3): ACTCON"
    );
    assert_eq!(link.quiet(), Ok(()), "5.4.20.30 (FRZ 3): nothing else");
    end(station, link);
    assert_eq!(
        log.lock().expect("the log").last(),
        Some(&Reaction::ActivationConfirmed {
            request: Request::General,
            freeze: FreezeMode::Reset,
            negative: false,
        })
    );
}

/// 604 `5.4.20.30` in the reverse direction (§5.1), index 81, the rows about
/// the **controlling** station (`M`): it sends a counter interrogation (ASDU
/// 101, cause 6, `C_CI_ACT`) with `FRZ` 1 to 3 and `RQT` 5 (general) (and `RQT=1...4` for the group row), and takes the confirmation and the
/// spontaneous totals that follow, in whichever order they come (the row's
/// Note).
///
/// DUT: the **controlling** station. Each command is figure 73's frame; the
/// confirmation completes it (nothing left running, no termination awaited);
/// the cause-3 `M_IT`s are the library's `tx` spontaneous objects and not
/// `ci`'s. The second command's answers come totals first, confirmation last.
/// Mode D has no collection (5-101 clause 7.4.8: in this mode the frozen
/// values go out spontaneously), and `ci` refuses to build one.
#[test]
fn clause_5_4_20_30_mode_d_the_controlling_station_freezes_and_takes_the_reports() {
    let mode = CounterMode::FreezeSpontaneous;
    let requests = [
        (Request::General, FreezeMode::FreezeWithoutReset),
        (Request::Group(2), FreezeMode::FreezeWithoutReset),
        (Request::General, FreezeMode::FreezeWithReset),
        (Request::General, FreezeMode::Reset),
    ];
    let spont = |c: &Counter| {
        let bcr = Bcr {
            reading: c.actual,
            sequence: 1,
            ..Bcr::default()
        };
        m_it(c.tagged, Cause::Spontaneous, CA, c.ioa, bcr)
    };
    let replies: Vec<Vec<Vec<u8>>> = requests
        .iter()
        .enumerate()
        .map(|(i, &(request, freeze))| {
            let con = c_ci(7, CA, qcc_of(request, freeze));
            let totals: Vec<Vec<u8>> = if freeze == FreezeMode::Reset {
                Vec::new()
            } else {
                members(request).iter().map(spont).collect()
            };
            if i == 1 {
                totals.into_iter().chain([con]).collect()
            } else {
                std::iter::once(con).chain(totals).collect()
            }
        })
        .collect();
    let answers = replies.clone();
    let mut ci = CounterInterrogation::controlling(mode, CA, ORIGINATOR);
    assert_eq!(
        ci.request(Request::General, FreezeMode::Read),
        Err(CiError::CollectionNotAllowed { mode }),
        "5-101 cl.7.4.8, mode D: the values are reported, not collected"
    );
    let (sent, reactions) = controlling_run(&mut ci, &requests, replies);
    assert_eq!(
        sent.len(),
        requests.len(),
        "5.4.20.30: one C_CI per command"
    );
    let tx = Transmission::controlling(CA, 0);
    for (i, &(request, freeze)) in requests.iter().enumerate() {
        let what = format!("5.4.20.30 ({request:?}, {freeze:?})");
        assert_eq!(
            sent[i],
            c_ci(6, CA, qcc_of(request, freeze)),
            "{what}: C_CI_ACT"
        );
        assert_eq!(reactions[i].len(), answers[i].len(), "{what}: every answer");
        for (asdu, reaction) in answers[i].iter().zip(&reactions[i]) {
            let header = Header::parse(asdu).expect("header");
            if header.type_id == TypeId::CCiNa1 {
                assert_eq!(
                    *reaction,
                    Reaction::ActivationConfirmed {
                        request,
                        freeze,
                        negative: false
                    },
                    "{what}: ACTCON"
                );
            } else {
                assert_eq!(*reaction, Reaction::Other, "{what}: not ci's");
                assert_eq!(
                    tx.on_response(asdu, &counter_known(asdu))
                        .expect("tx")
                        .reaction,
                    tx::Reaction::Spontaneous {
                        type_id: header.type_id
                    },
                    "{what}: M_IT_SPONT"
                );
            }
        }
    }
    assert!(ci.running().is_empty(), "5.4.20.30: nothing left running");
}
