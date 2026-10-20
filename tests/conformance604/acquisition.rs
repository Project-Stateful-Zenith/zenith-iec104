//! What the data-acquisition tables share: 604 Tables 14 (cyclic data and the
//! background scan), 15 (read), 16 (events) and 18 (clock synchronisation).
//!
//! Four pieces, none of them protocol code:
//!
//! - [`visit_monitor_layout`] reaches the crate's typed layout for a monitor
//!   type identification octet, so a case can loop over every ASDU the PICS
//!   lists through the library's own generic producers (`tx::cyclic`,
//!   `rd::answer`, ...) instead of writing octets by hand;
//! - [`sample_value`] is one well-formed element of such a type, built from
//!   [`sample_element`] (5-101 clause 7.3's geometry, time tags inside clause
//!   7.2.6.18's ranges) with a nonzero value octet, so a value that arrives
//!   as zero cannot pass for the one the station holds;
//! - [`read_i_frames`] is the mock controlling station's reading loop, which
//!   acknowledges every I-frame (clause 5.1) so the station's k window never
//!   stalls a case that does not mean to test it;
//! - [`Scripted`] is a mock **controlled** peer's application for the cases
//!   whose DUT is the **controlling** station: it plugs into
//!   [`ControlledStation`] (the socket loop and `link::Session` of the harness)
//!   and answers only what the case spells out.

use std::collections::VecDeque;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::conformance604::{
    CA, ControlledStation, ORIGINATOR, Peer, StationApp, StationReport, deadline, interop,
    read_ioa, sample_element,
};
use iec104::apci::{Apci, SeqNo, UFunction};
use iec104::asdu::{
    AsduLayout, Cause, Header, Known, LayoutObject, MBoNa1, MBoTb1, MDpNa1, MDpTb1, MEpTd1, MEpTe1,
    MEpTf1, MItNa1, MItTb1, MMeNa1, MMeNb1, MMeNc1, MMeNd1, MMeTd1, MMeTe1, MMeTf1, MPsNa1, MSpNa1,
    MSpTb1, MStNa1, MStTb1, TypeId,
};
use iec104::tx::{Function, ProjectList, StationFunctions, Transmission};

/// The broadcast common address of the conventional two-octet profile (5-101
/// clause 7.2.4: `FFFF`).
pub const BROADCAST: u16 = 0xFFFF;

/// A generic step over one typed layout; [`visit_monitor_layout`] calls it with
/// the layout of the type the case names.
pub trait LayoutVisitor {
    /// What one visit produces.
    type Out;
    /// Runs the step for layout `A`.
    fn visit<A: AsduLayout + PartialEq + Debug + Copy + Send + 'static>(&mut self) -> Self::Out;
}

/// Every monitor type identification [`visit_monitor_layout`] reaches: the
/// untagged types of 5-101 tables 8 and 10 that 104 clause 9 selects (`<1>` to
/// `<21>`, without the `CP24Time2a` forms 104 does not permit) and the
/// `CP56Time2a` set `<30>` to `<40>` (104 clause 9, PDF page index 100: for
/// time-tagged ASDUs this companion standard allows only `<30>` to `<40>`).
pub const MONITOR_LAYOUTS: [u8; 21] = [
    1, 3, 5, 7, 9, 11, 13, 15, 20, 21, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
];

/// Calls `visitor` with the typed layout of the monitor type `type_id`, or
/// answers `None` for a type this helper does not reach.
pub fn visit_monitor_layout<V: LayoutVisitor>(type_id: u8, visitor: &mut V) -> Option<V::Out> {
    Some(match type_id {
        1 => visitor.visit::<MSpNa1>(),
        3 => visitor.visit::<MDpNa1>(),
        5 => visitor.visit::<MStNa1>(),
        7 => visitor.visit::<MBoNa1>(),
        9 => visitor.visit::<MMeNa1>(),
        11 => visitor.visit::<MMeNb1>(),
        13 => visitor.visit::<MMeNc1>(),
        15 => visitor.visit::<MItNa1>(),
        20 => visitor.visit::<MPsNa1>(),
        21 => visitor.visit::<MMeNd1>(),
        30 => visitor.visit::<MSpTb1>(),
        31 => visitor.visit::<MDpTb1>(),
        32 => visitor.visit::<MStTb1>(),
        33 => visitor.visit::<MBoTb1>(),
        34 => visitor.visit::<MMeTd1>(),
        35 => visitor.visit::<MMeTe1>(),
        36 => visitor.visit::<MMeTf1>(),
        37 => visitor.visit::<MItTb1>(),
        38 => visitor.visit::<MEpTd1>(),
        39 => visitor.visit::<MEpTe1>(),
        40 => visitor.visit::<MEpTf1>(),
        _ => return None,
    })
}

/// One well-formed element of layout `A` whose first octet is `marker`.
///
/// The first octet is the value (or the status bits) of every monitor element
/// of 5-101 clause 7.3.1, and `1` is a legal value in each of them (`SPI` ON,
/// `DCS`/`DPI` OFF, a value or counter of one, `ES` OFF). The rest is
/// [`sample_element`]'s zero fill with every `CP56Time2a` inside clause
/// 7.2.6.18's ranges.
pub fn sample_value<A: AsduLayout>(marker: u8) -> A {
    let type_id = A::TYPE_ID.to_u8();
    let mut element = sample_element(type_id);
    element[0] = marker;
    A::parse(&element).unwrap_or_else(|e| panic!("type {type_id}: the sample element: {e:?}"))
}

/// The controlled station's answers for one received ASDU in these cases:
/// the standard's types and causes (`Known::standard`), its own common address
/// (the broadcast one too for the four types 5-101 clause 7.2.4 permits it on),
/// and every information object address. Which addresses the station holds is
/// the read procedure's own question (`rd::DataSource` answers `None` for one
/// it does not hold), so the profile does not decide it here.
pub fn station_known(asdu: &[u8]) -> Result<Known, String> {
    let header = Header::parse(asdu).map_err(|e| format!("the header: {e:?}"))?;
    let broadcastable = matches!(header.type_id.to_u8(), 100 | 101 | 103 | 105);
    let common_address =
        header.common_address == CA || (broadcastable && header.common_address == BROADCAST);
    Ok(Known::standard(&header, common_address, true))
}

/// Reads `n` I-frames from the controlled station under test, acknowledging
/// each with an S-frame (clause 5.1) so the station's k window stays open.
/// U- and S-frames in between are skipped. Returns the ASDUs, oldest first.
pub fn read_i_frames(peer: &mut Peer, n: usize, limit: Instant) -> Result<Vec<Vec<u8>>, String> {
    let mut asdus = Vec::with_capacity(n);
    while asdus.len() < n {
        let (apci, asdu) = peer
            .expect_i(limit)
            .map_err(|why| format!("I-frame {} of {n}: {why}", asdus.len() + 1))?;
        if let Apci::I { ns, .. } = apci {
            peer.send_s(ns.next())?;
        }
        asdus.push(asdu);
    }
    Ok(asdus)
}

/// The N(R) the mock controlling station's next I-frame carries: every I-frame
/// it has read so far (clause 5.1), so an I-frame after [`read_i_frames`]'s
/// S-frames never takes an acknowledgement back.
pub fn next_nr(peer: &Peer) -> SeqNo {
    let received = peer
        .received
        .iter()
        .filter(|frame| {
            crate::conformance604::apci_of(frame).is_ok_and(iec104::apci::Apci::is_i_format)
        })
        .count();
    SeqNo::new(received as u16)
}

/// Requires that no I-frame arrives before `limit`: a bounded silence.
pub fn expect_no_i_frame(peer: &mut Peer, limit: Instant) -> Result<(), String> {
    match peer.expect_i(limit) {
        Ok((_, asdu)) => Err(format!("an I-frame arrived: {asdu:02x?}")),
        Err(why) if why == "no frame before the deadline" => Ok(()),
        Err(why) => Err(why),
    }
}

/// The ASDUs a scripted mock peer received, shared with the case.
pub type Received = Arc<Mutex<Vec<Vec<u8>>>>;

/// A scripted answer: the ASDUs a mock peer sends back for one it received.
pub type Script = Box<dyn FnMut(&[u8]) -> Vec<Vec<u8>> + Send>;

/// The application of a mock **controlled** peer: it records every ASDU it
/// receives, answers each with what [`Script`] says, and puts `unprompted` on
/// the wire of its own accord once data transfer is started. It invents no
/// protocol behaviour: every ASDU it sends is one the case spells out.
pub struct Scripted {
    /// Everything the peer received, in order.
    pub received: Received,
    /// The peer's answers.
    pub script: Script,
    /// ASDUs sent once, as soon as the connection is started.
    pub unprompted: VecDeque<Vec<u8>>,
}

impl Scripted {
    /// A peer that answers nothing and sends `unprompted` once started.
    pub fn sending(unprompted: Vec<Vec<u8>>) -> (Self, Received) {
        Self::answering(unprompted, Box::new(|_| Vec::new()))
    }

    /// A peer that answers with `script` and sends `unprompted` once started.
    pub fn answering(unprompted: Vec<Vec<u8>>, script: Script) -> (Self, Received) {
        let received: Received = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                received: Arc::clone(&received),
                script,
                unprompted: unprompted.into(),
            },
            received,
        )
    }
}

impl StationApp for Scripted {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.received
            .lock()
            .map_err(|_| "the record is poisoned".to_string())?
            .push(asdu.to_vec());
        Ok((self.script)(asdu))
    }

    fn poll(&mut self, _now: Instant) -> Result<Vec<Vec<u8>>, String> {
        Ok(self.unprompted.drain(..).collect())
    }
}

/// The **controlling** station under test, connected to `peer` and started:
/// the interoperability harness's `interop::Station` (this library's
/// `link::Session` in `Role::Controlling`) sends `STARTDT act` and waits for
/// the `con` (clause 5.3).
pub fn started_controlling(peer: &ControlledStation) -> Result<interop::Station, String> {
    let mut station = interop::Station::connect(peer.addr())?;
    let actions = station.session_mut().request_start();
    station.send_actions(&actions)?;
    station.expect("STARTDT con", deadline(5), |apci, _| {
        apci == Apci::U(UFunction::StartDtCon)
    })?;
    Ok(station)
}

/// The next `n` I-frames the controlling station under test received,
/// oldest first; the station's session acknowledges them itself.
pub fn station_i_frames(
    station: &mut interop::Station,
    n: usize,
    limit: Instant,
) -> Result<Vec<Vec<u8>>, String> {
    let mut asdus = Vec::with_capacity(n);
    while asdus.len() < n {
        if let Some((asdu, _)) = station.stashed.pop_front() {
            asdus.push(asdu);
            continue;
        }
        let (_, asdu) = station.expect("an I-frame", limit, |apci, _| apci.is_i_format())?;
        asdus.push(asdu);
    }
    Ok(asdus)
}

/// The controlling station under test sends one ASDU in an I-frame.
pub fn station_send(station: &mut interop::Station, asdu: &[u8]) -> Result<(), String> {
    let action = station
        .session_mut()
        .send_i_frame(asdu)
        .ok_or("the controlling station cannot send an I-frame now")?;
    station.send_actions(&[action])
}

/// The type identification octet of an ASDU.
pub fn type_of(asdu: &[u8]) -> u8 {
    Header::parse(asdu).map_or_else(
        |e| panic!("the header of {asdu:02x?}: {e:?}"),
        |header| header.type_id.to_u8(),
    )
}

/// The type identification behind an octet, for messages.
pub const fn name(type_id: u8) -> TypeId {
    TypeId::from_u8(type_id)
}

/// One frame from the library's own producer for `function` (`tx::cyclic`,
/// `tx::background` or `tx::spontaneous`, through a controlled
/// `tx::Transmission` that uses all three), carrying one [`sample_value`] of the
/// visited layout at `ioa`, plus that value's element octets.
pub struct Produce {
    /// Which of the three producers builds the frame.
    pub function: Function,
    /// The information object address of the one object.
    pub ioa: u32,
    /// The value octet [`sample_value`] writes.
    pub marker: u8,
}

impl LayoutVisitor for Produce {
    type Out = Result<(Vec<u8>, Vec<u8>), String>;

    fn visit<A: AsduLayout + PartialEq + Debug + Copy + Send + 'static>(&mut self) -> Self::Out {
        let value = sample_value::<A>(self.marker);
        let mut element = Vec::new();
        value.encode(&mut element);
        let station =
            Transmission::controlled(StationFunctions::ALL, ProjectList::empty(), CA, ORIGINATOR);
        let object = LayoutObject {
            ioa: self.ioa,
            value,
        };
        let frame = match self.function {
            Function::Cyclic => station.cyclic(&object),
            Function::Background => station.background(&object),
            Function::Spontaneous => station.spontaneous(&object),
        }
        .map_err(|e| format!("type {}: the producer: {e:?}", A::TYPE_ID.to_u8()))?;
        Ok((frame, element))
    }
}

/// Runs the **controlled** station under test with an application that hands
/// over `frames` (built by the library's producers) once data transfer is
/// started, and `pre_start` in the clause 5.3 queue; the mock controlling
/// station starts data transfer and reads `frames.len() + pre_start.len()`
/// I-frames, acknowledging each. Returns them and the station's report.
pub fn controlled_sends(
    frames: Vec<Vec<u8>>,
    pre_start: Vec<Vec<u8>>,
) -> Result<(Vec<Vec<u8>>, StationReport), String> {
    let n = frames.len() + pre_start.len();
    let (app, _) = Scripted::sending(frames);
    let station = ControlledStation::start_app(app, pre_start)?;
    let mut peer = Peer::connect(station.addr())?;
    peer.start_data_transfer()?;
    let asdus = read_i_frames(&mut peer, n, deadline(5));
    peer.close()?;
    let report = station.join()?;
    Ok((asdus?, report))
}

/// Checks one monitor ASDU of one object: its type identification, cause,
/// `P/N = 0`, `SQ = 0`, `N = 1`, the station's common address, the address
/// and the element octets. `row` names the 604 procedure in every message.
pub fn assert_single_object(
    row: &str,
    asdu: &[u8],
    type_id: u8,
    cause: Cause,
    ioa: u32,
    element: &[u8],
) {
    let header = Header::parse(asdu).unwrap_or_else(|e| panic!("{row}: the header: {e:?}"));
    assert_eq!(
        header.type_id.to_u8(),
        type_id,
        "{row}: the type identification"
    );
    assert_eq!(
        header.cause, cause,
        "{row} (type {type_id}): the cause of transmission"
    );
    assert!(!header.negative, "{row} (type {type_id}): P/N = 0");
    assert!(!header.sequence, "{row} (type {type_id}): SQ = 0");
    assert_eq!(header.count, 1, "{row} (type {type_id}): one object");
    assert_eq!(
        header.common_address, CA,
        "{row} (type {type_id}): the station's CASDU"
    );
    assert_eq!(
        read_ioa(&asdu[Header::LEN..]).expect("an address"),
        ioa,
        "{row} (type {type_id}): the information object address"
    );
    assert_eq!(
        &asdu[Header::LEN + 3..],
        element,
        "{row} (type {type_id}): the value the station holds"
    );
}

/// What the receiving station stores from one ASDU of the visited layout: it
/// decodes the objects with the crate's layout (`asdu::decode_asdu`) and
/// answers `Ok(addresses)` when every value equals <code>[sample_value](marker)</code>,
/// the value the sending side holds.
pub struct Stored<'a> {
    /// The ASDU as it arrived.
    pub asdu: &'a [u8],
    /// The value octet the sending side's objects hold.
    pub marker: u8,
}

impl LayoutVisitor for Stored<'_> {
    type Out = Result<Vec<u32>, String>;

    fn visit<A: AsduLayout + PartialEq + Debug + Copy + Send + 'static>(&mut self) -> Self::Out {
        let objects = iec104::asdu::decode_asdu::<A>(self.asdu)
            .map_err(|e| format!("type {}: decode: {e:?}", A::TYPE_ID.to_u8()))?;
        let held = sample_value::<A>(self.marker);
        for object in &objects {
            if object.value != held {
                return Err(format!(
                    "type {}: stored {:?}, the sender holds {held:?}",
                    A::TYPE_ID.to_u8(),
                    object.value
                ));
            }
        }
        Ok(objects.iter().map(|object| object.ioa).collect())
    }
}
