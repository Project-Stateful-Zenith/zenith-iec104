//! The harness half of 604 Table 17 (general interrogation): the controlled
//! station's application, the mock peers and the controlling station's driver.
//!
//! Every protocol decision below is the crate's: the controlled station answers
//! through `gi::Interrogation::controlled` over a [`DataSource`], the
//! controlling station classifies through `gi::Interrogation::controlling`, and
//! the object areas are read through `asdu::BodyReader`. What is here is glue:
//! a process image (project data, 5-101 clause 8.9's interoperability list), the
//! moment the application releases an interrogation's data, and the sockets.
//!
//! The frames the **mocks** put on the wire are built from the octets the
//! standard fixes (5-101 clause 7.3.4.1, figure 72, PDF page index 105, for
//! `C_IC_NA_1`; clause 7.2.3's header), not through `gi`, so a mistake in the
//! module under test cannot hide in the mock's frames.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{
    BodyReader, Cause, Header, IOA_IRRELEVANT, Known, TypeId, element_len, read_ioa,
};
use iec104::gi::{DataSource, GiError, Interrogation, ReActivation, Reaction, Scope};

use crate::conformance604::interop::Station;
use crate::conformance604::{ORIGINATOR, Peer, StationApp, deadline};

/// The broadcast common address of the two-octet profile, 5-101 clause 7.2.4
/// (PDF page index 43): all ones, `0xFF` or `0xFFFF`.
pub const BROADCAST: u16 = 0xFFFF;

/// 5-101 clause 7.2.6.22 (PDF page index 53): `<20>` station interrogation.
pub const QOI_STATION: u8 = 20;

/// 5-101 clause 7.2.6.22: `<21>` … `<36>` are groups 1 … 16, so group `n` is
/// `20 + n`.
pub const fn qoi_group(n: u8) -> u8 {
    20 + n
}

/// 5-101 clause 7.2.3, table 14 (PDF page index 41): `<20>` interrogated by
/// station interrogation, `<21>` … `<36>` interrogated by group 1 … 16.
pub const fn cause_octet(scope: Scope) -> u8 {
    match scope {
        Scope::Station => 20,
        Scope::Group(n) => 20 + n,
    }
}

/// Table 14's cause codes this table uses (5-101 clause 7.2.3, PDF page index
/// 41): `<3>` spont, `<6>` act, `<7>` actcon, `<8>` deact, `<9>` deactcon,
/// `<10>` actterm.
pub const COT_SPONT: u8 = 3;
pub const COT_ACT: u8 = 6;
pub const COT_ACTCON: u8 = 7;
pub const COT_DEACT: u8 = 8;
pub const COT_DEACTCON: u8 = 9;
pub const COT_ACTTERM: u8 = 10;

/// One `C_IC_NA_1` from figure 72's octets (5-101 clause 7.3.4.1, PDF page
/// index 105): type `<100>`, `SQ = 0`, `N = 1`, the cause and `P/N` given, the
/// harness originator, the common address, `INFORMATION OBJECT ADDRESS = 0`
/// and the `QOI` octet. Ten octets.
pub fn c_ic(cause: u8, negative: bool, ca: u16, qoi: u8) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::from_u8(100),
        sequence: false,
        count: 1,
        cause: Cause::from_u8(cause),
        negative,
        test: false,
        originator: ORIGINATOR,
        common_address: ca,
    };
    let mut out = Vec::with_capacity(10);
    header.encode(&mut out).expect("the header encodes");
    out.extend_from_slice(&[0, 0, 0, qoi]);
    out
}

/// One monitor-direction ASDU of `type_id`, `SQ = 0`, `N = 1`, carrying one
/// object at `ioa` with `element` as its element octets.
pub fn point_asdu(type_id: u8, cause: u8, ca: u16, ioa: u32, element: &[u8]) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::from_u8(type_id),
        sequence: false,
        count: 1,
        cause: Cause::from_u8(cause),
        negative: false,
        test: false,
        originator: ORIGINATOR,
        common_address: ca,
    };
    let mut out = Vec::new();
    header.encode(&mut out).expect("the header encodes");
    out.extend_from_slice(&ioa.to_le_bytes()[..3]);
    out.extend_from_slice(element);
    out
}

/// The fields of a received `C_IC_NA_1` a case asserts, read from the octets
/// of figure 72 (octet 10 is the `QOI`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcFrame {
    pub cause: u8,
    pub negative: bool,
    pub ca: u16,
    pub ioa: u32,
    pub qoi: u8,
}

/// Reads a `C_IC_NA_1`, or `None` for any other type.
pub fn ic_frame(asdu: &[u8]) -> Option<IcFrame> {
    let header = Header::parse(asdu).ok()?;
    if header.type_id.to_u8() != 100 || asdu.len() != Header::LEN + 4 {
        return None;
    }
    Some(IcFrame {
        cause: header.cause.to_u8(),
        negative: header.negative,
        ca: header.common_address,
        ioa: read_ioa(&asdu[Header::LEN..]).ok()?,
        qoi: asdu[Header::LEN + 3],
    })
}

/// Whether `asdu` is the `C_IC ACTTERM` (cause `<10>`) of `ca`.
pub fn is_actterm(asdu: &[u8], ca: u16) -> bool {
    matches!(ic_frame(asdu), Some(f) if f.cause == COT_ACTTERM && f.ca == ca)
}

/// Every object of a monitor ASDU as `(ioa, element octets)`, read through the
/// crate's `BodyReader` with the type's element length (5-101 clause 7.3), so
/// `SQ = 0` and `SQ = 1` are both read as clause 7.2.2.1 defines them.
pub fn objects_of(asdu: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, String> {
    let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
    let len = element_len(header.type_id)
        .ok_or_else(|| format!("no element length for {:?}", header.type_id))?;
    let mut reader = BodyReader::new(header, &asdu[Header::LEN..]);
    let mut out = Vec::new();
    while let Some(object) = reader
        .next_object(len)
        .map_err(|e| format!("the object area: {e:?}"))?
    {
        out.push((object.ioa, object.element.to_vec()));
    }
    reader
        .finish()
        .map_err(|e| format!("the object area: {e:?}"))?;
    Ok(out)
}

// ------------------------------------------------------------ the process image

/// One information object of the controlled station's process image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Point {
    pub ioa: u32,
    pub type_id: u8,
    pub element: Vec<u8>,
    /// The groups (1..=16) the object belongs to. Every object belongs to the
    /// station interrogation (5-101 clause 7.4.5 says a station interrogation
    /// should be answered with every process information object the controlled
    /// station stores).
    pub groups: Vec<u8>,
}

/// The controlled station's process image for one LRU: its common address,
/// whether it is ready, its objects, and ASDUs the application packs itself
/// (the `SQ` rows).
#[derive(Debug, Clone, Default)]
pub struct Image {
    pub ca: u16,
    pub ready: bool,
    pub points: Vec<Point>,
    /// Whole ASDUs an application packed for a scope, sent after the points.
    pub blocks: Vec<(Scope, Vec<u8>)>,
}

impl Image {
    pub const fn new(ca: u16, points: Vec<Point>) -> Self {
        Self {
            ca,
            ready: true,
            points,
            blocks: Vec::new(),
        }
    }

    /// Whether `point` belongs to `scope`.
    pub fn in_scope(point: &Point, scope: Scope) -> bool {
        match scope {
            Scope::Station => true,
            Scope::Group(n) => point.groups.contains(&n),
        }
    }

    /// The ASDUs `scope` returns, one per object, with `scope`'s cause.
    pub fn asdus(&self, scope: Scope) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = self
            .points
            .iter()
            .filter(|point| Self::in_scope(point, scope))
            .map(|point| {
                point_asdu(
                    point.type_id,
                    cause_octet(scope),
                    self.ca,
                    point.ioa,
                    &point.element,
                )
            })
            .collect();
        out.extend(
            self.blocks
                .iter()
                .filter(|(s, _)| *s == scope)
                .map(|(_, asdu)| asdu.clone()),
        );
        out
    }

    /// Sets the element of the object at `ioa`.
    pub fn set(&mut self, ioa: u32, element: &[u8]) {
        let point = self
            .points
            .iter_mut()
            .find(|point| point.ioa == ioa)
            .expect("the image holds the object");
        point.element = element.to_vec();
    }
}

/// The image as the crate's [`DataSource`], shared with the test so a case can
/// change a value (an event) or the readiness while the station runs.
#[derive(Debug, Clone)]
pub struct SharedImage(pub Arc<Mutex<Image>>);

impl SharedImage {
    pub fn new(image: Image) -> Self {
        Self(Arc::new(Mutex::new(image)))
    }

    pub fn lock(&self) -> std::sync::MutexGuard<'_, Image> {
        self.0.lock().expect("the image lock")
    }
}

impl DataSource for SharedImage {
    fn ready(&self, _scope: Scope) -> bool {
        self.lock().ready
    }

    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
        out.extend(self.lock().asdus(scope));
    }
}

// --------------------------------------------------- the controlled station

/// What a case controls while the controlled station runs.
#[derive(Debug, Default)]
pub struct Controls {
    /// While false, a confirmed interrogation's data and termination are held:
    /// the interrogation is *running* (Table 17 page 3 of 5 calls a GI running
    /// from the controlling station's `C_IC_ACT` until it receives the
    /// `C_IC_TERM`). Once true, the application completes every
    /// running interrogation.
    pub release: AtomicBool,
    /// Spontaneous ASDUs the application sends before anything it releases
    /// (an event the process produced, built by `tx::spontaneous`).
    pub events: Mutex<VecDeque<Vec<u8>>>,
}

impl Controls {
    pub fn release(&self) {
        self.release.store(true, Ordering::SeqCst);
    }

    pub fn push_event(&self, asdu: Vec<u8>) {
        self.events.lock().expect("the event lock").push_back(asdu);
    }
}

/// One logical remote unit: its own `gi::Interrogation::controlled` and image,
/// under its own common address (5-101 clause 7.4.5: every LRU is identified by
/// a common address chosen for the system).
pub struct Lru {
    pub gi: Interrogation,
    pub image: SharedImage,
}

/// The controlled station's application for Table 17: `C_IC_NA_1` goes to every
/// LRU it addresses (its own common address, or the broadcast one for all),
/// and each LRU's `Interrogation` decides the answer.
pub struct GiStation {
    lrus: Vec<Lru>,
    controls: Arc<Controls>,
}

impl GiStation {
    /// A station of one LRU per image, each running re-activation option
    /// `policy`. With `release` false the data of a confirmed interrogation is
    /// held until [`Controls::release`].
    pub fn new(
        policy: ReActivation,
        images: &[SharedImage],
        release: bool,
    ) -> (Self, Arc<Controls>) {
        let controls = Arc::new(Controls::default());
        controls.release.store(release, Ordering::SeqCst);
        let lrus = images
            .iter()
            .map(|image| {
                let ca = image.lock().ca;
                Lru {
                    gi: Interrogation::controlled(policy, ca, ORIGINATOR),
                    image: image.clone(),
                }
            })
            .collect();
        (
            Self {
                lrus,
                controls: controls.clone(),
            },
            controls,
        )
    }

    /// Every running interrogation's owed data and termination, as the crate's
    /// `Interrogation::complete` produces them. `GiError::NotRunning` is the
    /// crate saying there is nothing to complete.
    fn flush(&mut self) -> Result<Vec<Vec<u8>>, String> {
        let mut out = Vec::new();
        if !self.controls.release.load(Ordering::SeqCst) {
            return Ok(out);
        }
        for lru in &mut self.lrus {
            match lru.gi.complete(&lru.image) {
                Ok(frames) => out.extend(frames),
                Err(GiError::NotRunning) => {}
                Err(e) => return Err(format!("the GI completion: {e:?}")),
            }
        }
        Ok(out)
    }
}

impl StationApp for GiStation {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
        if header.type_id != TypeId::CIcNa1 {
            return Ok(Vec::new());
        }
        let ioa = read_ioa(&asdu[Header::LEN..]).map_err(|e| format!("the IOA: {e:?}"))?;
        let mut out = Vec::new();
        for lru in &mut self.lrus {
            let own = lru.gi.addressing().0;
            if header.common_address != own && header.common_address != BROADCAST {
                continue;
            }
            // 5-101 clause 7.2.4 (index 43): the broadcast address is permitted
            // for type 100, so it is a known address for every LRU; figure 72's
            // object address is the irrelevant 0.
            let known = Known::standard(&header, true, ioa == IOA_IRRELEVANT);
            let outcome = lru
                .gi
                .on_request(asdu, &known, &lru.image)
                .map_err(|e| format!("the GI request: {e:?}"))?;
            out.extend(outcome.send);
        }
        out.extend(self.flush()?);
        Ok(out)
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        let mut out: Vec<Vec<u8>> = self
            .controls
            .events
            .lock()
            .expect("the event lock")
            .drain(..)
            .collect();
        out.extend(self.flush()?);
        Ok(out)
    }
}

/// The mock controlling station for the controlled-station cases: a [`Peer`]
/// that numbers its I-frames and acknowledges the station's (clause 5.1), so a
/// response longer than the k window still flows.
pub struct GiPeer {
    pub peer: Peer,
    ns: u16,
    vr: u16,
    unacked: u16,
    /// Every ASDU the station sent, in order.
    pub asdus: Vec<Vec<u8>>,
}

impl GiPeer {
    /// Connects and completes the STARTDT exchange (104 clause 5.3).
    pub fn start(addr: SocketAddr) -> Result<Self, String> {
        let mut peer = Peer::connect(addr)?;
        peer.start_data_transfer()?;
        Ok(Self {
            peer,
            ns: 0,
            vr: 0,
            unacked: 0,
            asdus: Vec::new(),
        })
    }

    /// One I-frame carrying `asdu`.
    pub fn send(&mut self, asdu: &[u8]) -> Result<(), String> {
        self.peer
            .send_i(SeqNo::new(self.ns), SeqNo::new(self.vr), asdu)?;
        self.ns += 1;
        Ok(())
    }

    /// The next ASDU the station sends, acknowledged every fourth I-frame
    /// (below the default w of 8, 104 clause 9.6).
    pub fn next(&mut self, limit: Instant) -> Result<Vec<u8>, String> {
        let (_, asdu) = self.peer.expect_i(limit)?;
        self.vr += 1;
        self.unacked += 1;
        if self.unacked >= 4 {
            self.peer.send_s(SeqNo::new(self.vr))?;
            self.unacked = 0;
        }
        self.asdus.push(asdu.clone());
        Ok(asdu)
    }

    /// ASDUs up to and including the first one `done` accepts.
    pub fn until(&mut self, done: impl Fn(&[u8]) -> bool) -> Result<Vec<Vec<u8>>, String> {
        let limit = deadline(5);
        let mut out = Vec::new();
        loop {
            let asdu = self.next(limit)?;
            let last = done(&asdu);
            out.push(asdu);
            if last {
                return Ok(out);
            }
        }
    }

    /// Exactly `n` ASDUs.
    pub fn take(&mut self, n: usize) -> Result<Vec<Vec<u8>>, String> {
        let limit = deadline(5);
        (0..n).map(|_| self.next(limit)).collect()
    }

    /// Whatever the station sends within `millis`; a case that expects silence
    /// asserts it is empty.
    pub fn quiet(&mut self, millis: u64) -> Vec<Vec<u8>> {
        let limit = Instant::now() + Duration::from_millis(millis);
        let mut out = Vec::new();
        while let Ok(asdu) = self.next(limit) {
            out.push(asdu);
        }
        out
    }

    /// Closes the socket, ending the station's thread.
    pub fn close(&self) -> Result<(), String> {
        self.peer.close()
    }
}

// --------------------------------------------------- the controlling station

/// The mock controlled station for the controlling-station cases: this crate's
/// link layer on a socket (`ControlledStation`) with a scripted application
/// that answers the n-th received ASDU with the n-th list of ASDUs, and
/// nothing of its own protocol logic.
pub struct ScriptApp {
    answers: VecDeque<Vec<Vec<u8>>>,
    /// Once every answer is out, end the connection (the link is lost).
    drop_link: bool,
}

impl ScriptApp {
    pub fn new(answers: Vec<Vec<Vec<u8>>>) -> Self {
        Self {
            answers: answers.into(),
            drop_link: false,
        }
    }

    /// The same script, after which the mock drops the connection.
    pub const fn then_drop(mut self) -> Self {
        self.drop_link = true;
        self
    }
}

/// The error text a scripted link loss ends the mock's thread with.
pub const LINK_DROPPED: &str = "the scripted link loss";

impl StationApp for ScriptApp {
    fn on_asdu(&mut self, _asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        Ok(self.answers.pop_front().unwrap_or_default())
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        if self.drop_link && self.answers.is_empty() {
            return Err(LINK_DROPPED.into());
        }
        Ok(Vec::new())
    }
}

/// This crate as the controlling station: the interoperability harness's
/// `Station` (link layer on a socket) plus `gi::Interrogation::controlling`,
/// and the station's copy of the objects it received (its network image).
pub struct Master {
    pub station: Station,
    pub gi: Interrogation,
    /// The common addresses this station knows (its LRUs).
    pub cas: Vec<u16>,
    /// Every object an interrogation delivered, by `(common address, IOA)`:
    /// `(type identification, element octets, cause)`.
    pub image: BTreeMap<(u16, u32), (u8, Vec<u8>, u8)>,
    /// Every received ASDU with the crate's reaction to it, in order.
    pub log: Vec<(Vec<u8>, Reaction)>,
}

impl Master {
    /// Connects to `addr` and completes the STARTDT exchange (104 clause 5.3).
    pub fn connect(addr: SocketAddr, gi: Interrogation, cas: &[u16]) -> Result<Self, String> {
        let mut station = Station::connect(addr)?;
        let actions = station.session_mut().request_start();
        station.send_actions(&actions)?;
        station.expect("STARTDT con", deadline(5), |apci, _| {
            apci == Apci::U(UFunction::StartDtCon)
        })?;
        Ok(Self {
            station,
            gi,
            cas: cas.to_vec(),
            image: BTreeMap::new(),
            log: Vec::new(),
        })
    }

    /// One I-frame carrying `asdu`.
    pub fn send(&mut self, asdu: &[u8]) -> Result<(), String> {
        let action = self
            .station
            .session_mut()
            .send_i_frame(asdu)
            .ok_or("104 cl.5.3: data transfer is not allowed")?;
        self.station.send_actions(&[action])
    }

    /// The next received ASDU, unclassified.
    pub fn next_asdu(&mut self, limit: Instant) -> Result<Vec<u8>, String> {
        loop {
            match self.station.next(limit)? {
                Some((apci, asdu)) if apci.is_i_format() => return Ok(asdu),
                Some(_) => {}
                None => return Err("no I-frame before the deadline".into()),
            }
        }
    }

    /// The crate's classification of one received ASDU, and the objects of an
    /// interrogation response stored in the station's image.
    pub fn classify(&mut self, asdu: &[u8]) -> Result<Reaction, String> {
        let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
        let known = Known::standard(&header, self.cas.contains(&header.common_address), true);
        let outcome = self
            .gi
            .on_response(asdu, &known)
            .map_err(|e| format!("the GI response: {e:?}"))?;
        if let Reaction::Interrogated { .. } = outcome.reaction {
            for (ioa, element) in objects_of(asdu)? {
                self.image.insert(
                    (header.common_address, ioa),
                    (header.type_id.to_u8(), element, header.cause.to_u8()),
                );
            }
        }
        self.log.push((asdu.to_vec(), outcome.reaction));
        Ok(outcome.reaction)
    }

    /// Receives and classifies ASDUs until `done` accepts a reaction.
    pub fn until(&mut self, done: impl Fn(&Reaction) -> bool) -> Result<(), String> {
        let limit = deadline(5);
        loop {
            let asdu = self.next_asdu(limit)?;
            if done(&self.classify(&asdu)?) {
                return Ok(());
            }
        }
    }

    /// Receives and classifies exactly `n` ASDUs.
    pub fn take(&mut self, n: usize) -> Result<Vec<Reaction>, String> {
        let limit = deadline(5);
        let mut out = Vec::new();
        for _ in 0..n {
            let asdu = self.next_asdu(limit)?;
            out.push(self.classify(&asdu)?);
        }
        Ok(out)
    }

    /// The reactions of the log, in order.
    pub fn reactions(&self) -> Vec<Reaction> {
        self.log.iter().map(|(_, r)| *r).collect()
    }

    /// Closes the socket.
    pub fn close(&self) -> Result<(), String> {
        self.station.close()
    }
}

/// The ASDUs a mock controlled station received, read from its report.
pub fn received_asdus(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    frames
        .iter()
        .filter_map(|frame| {
            let (apci, asdu) = crate::conformance604::parse_frame(frame).ok()?;
            apci.is_i_format().then_some(asdu)
        })
        .collect()
}
