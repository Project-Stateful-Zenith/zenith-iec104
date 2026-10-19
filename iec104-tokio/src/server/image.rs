//! The server's process image and the monitor ASDUs built from it.
//!
//! Each information object address holds its configuration and its latest
//! sample. The image answers the core's three data sources (interrogation,
//! counter interrogation, read) and builds the event ASDUs, always through the
//! layouts of 5-101 clause 7.3.1.

use std::collections::BTreeMap;

use iec104::asdu::{
    AddressSizes, AsduLayout, Bcr, Bsi, Cause, Cp16Time2a, Cp56Time2a, Diq, Header, LayoutError,
    LayoutObject, MBoNa1, MBoTb1, MDpNa1, MDpTb1, MEpTd1, MEpTe1, MEpTf1, MItNa1, MItTb1, MMeNa1,
    MMeNb1, MMeNc1, MMeTd1, MMeTe1, MMeTf1, MPsNa1, MSpNa1, MSpTb1, MStNa1, MStTb1, Nva, Qdp, Qds,
    Quality, R32, Scd, Sep, Siq, Sva, TypeId, Value, Vti, encode_asdu_with,
};
use iec104::ci::{self, CounterSource};
use iec104::gi::{self, DataSource, Scope};
use iec104::rd;

use super::PointConfig;

/// One value of a point: what the application last wrote.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    pub value: Value,
    pub quality: Quality,
    /// The time tag, for a point whose events carry one.
    pub time: Option<Cp56Time2a>,
}

/// One information object of the image.
#[derive(Debug, Clone)]
pub struct Entry {
    pub config: PointConfig,
    pub sample: Sample,
}

/// The kind of a value, so that a write cannot change a point's types.
pub fn same_kind(a: &Value, b: &Value) -> bool {
    std::mem::discriminant(a) == std::mem::discriminant(b)
}

/// The untagged monitor type that carries `value` (5-101 cl.7.3.1). The
/// normalized value takes `M_ME_NA_1`, the form with a quality descriptor.
/// The protection events have no untagged form in 104: `M_EP_TA_1` to
/// `M_EP_TC_1` carry a `CP24Time2a`, which 104 clause 9 does not permit.
pub const fn untagged(value: &Value) -> Option<TypeId> {
    Some(match value {
        Value::Single(_) => TypeId::MSpNa1,
        Value::Double(_) => TypeId::MDpNa1,
        Value::StepPosition { .. } => TypeId::MStNa1,
        Value::Bitstring(_) => TypeId::MBoNa1,
        Value::Normalized(_) => TypeId::MMeNa1,
        Value::Scaled(_) => TypeId::MMeNb1,
        Value::Float(_) => TypeId::MMeNc1,
        Value::PackedSingle { .. } => TypeId::MPsNa1,
        Value::Counter { .. } => TypeId::MItNa1,
        Value::ProtectionEvent { .. }
        | Value::ProtectionStart { .. }
        | Value::ProtectionCommand { .. } => return None,
    })
}

/// The `CP56Time2a` monitor type that carries `value`: 104 clause 9, *"only
/// the use of the set <30> – <40> for ASDUs with time tag is permitted"*.
/// `M_PS_NA_1` has no tagged form.
pub const fn tagged(value: &Value) -> Option<TypeId> {
    Some(match value {
        Value::Single(_) => TypeId::MSpTb1,
        Value::Double(_) => TypeId::MDpTb1,
        Value::StepPosition { .. } => TypeId::MStTb1,
        Value::Bitstring(_) => TypeId::MBoTb1,
        Value::Normalized(_) => TypeId::MMeTd1,
        Value::Scaled(_) => TypeId::MMeTe1,
        Value::Float(_) => TypeId::MMeTf1,
        Value::Counter { .. } => TypeId::MItTb1,
        Value::ProtectionEvent { .. } => TypeId::MEpTd1,
        Value::ProtectionStart { .. } => TypeId::MEpTe1,
        Value::ProtectionCommand { .. } => TypeId::MEpTf1,
        Value::PackedSingle { .. } => return None,
    })
}

/// Whether the point's ASDUs carry a time tag: as configured, where the value
/// has both forms.
pub const fn is_tagged(config: &PointConfig, value: &Value) -> bool {
    match (untagged(value), tagged(value)) {
        (Some(_), Some(_)) => config.tagged,
        (None, _) => true,
        (_, None) => false,
    }
}

/// The type an event (or a counter's answer) of this point is sent with.
/// Every value has at least one form, so this is never `None`.
const fn event_type(config: &PointConfig, value: &Value) -> Option<TypeId> {
    if is_tagged(config, value) {
        tagged(value)
    } else {
        untagged(value)
    }
}

/// What every ASDU built here shares.
#[derive(Debug, Clone, Copy)]
pub struct Addressing {
    pub common_address: u16,
    pub sizes: AddressSizes,
}

/// The process image.
#[derive(Debug, Clone)]
pub struct Image {
    pub entries: BTreeMap<u32, Entry>,
    pub addressing: Addressing,
    /// Counter values frozen by a counter interrogation command (5-101
    /// cl.7.4.8), per request, with the counters of the request's group.
    pub frozen: Vec<(ci::Request, Vec<(u32, Sample)>)>,
}

impl Image {
    /// The event ASDU for `ioa`'s current sample, with `cause` (3, 11 or 12).
    /// `None` when there is no point at `ioa`.
    pub fn event(&self, ioa: u32, cause: Cause) -> Result<Option<Vec<u8>>, LayoutError> {
        let Some(entry) = self.entries.get(&ioa) else {
            return Ok(None);
        };
        let Some(type_id) = event_type(&entry.config, &entry.sample.value) else {
            return Ok(None);
        };
        let frames = encode(
            type_id,
            &[(ioa, entry.sample)],
            cause,
            0,
            false,
            self.addressing,
        )?;
        Ok(frames.into_iter().next())
    }

    /// The counters of `request` (the general request or one of the four
    /// counter groups), with their frozen value where one was frozen for it.
    fn counters(&self, request: ci::Request) -> Vec<(u32, Sample)> {
        let frozen = self
            .frozen
            .iter()
            .find(|(r, _)| *r == request)
            .or_else(|| self.frozen.iter().find(|(r, _)| *r == ci::Request::General));
        self.entries
            .iter()
            .filter(|(_, entry)| {
                matches!(entry.sample.value, Value::Counter { .. })
                    && in_counter_request(&entry.config, request)
            })
            .map(|(&ioa, entry)| {
                let sample = frozen
                    .and_then(|(_, values)| values.iter().find(|(i, _)| *i == ioa))
                    .map_or(entry.sample, |(_, sample)| *sample);
                (ioa, sample)
            })
            .collect()
    }

    /// Stores the current values of `request`'s counters as its frozen copy.
    pub fn freeze(&mut self, request: ci::Request) {
        let values: Vec<(u32, Sample)> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                matches!(entry.sample.value, Value::Counter { .. })
                    && in_counter_request(&entry.config, request)
            })
            .map(|(&ioa, entry)| (ioa, entry.sample))
            .collect();
        self.frozen.retain(|(r, _)| *r != request);
        self.frozen.push((request, values));
    }

    /// An ASDU of an interrogation's or a counter interrogation's answer
    /// (causes 20 to 41), encoded again with what its objects hold now: the
    /// same type, cause, originator address, test bit and objects, each with
    /// its current sample, or for a counter the value the counter
    /// interrogation returns (the frozen copy where there is one). Any other
    /// ASDU comes back as it is.
    ///
    /// An answer is encoded when the procedure completes, but its ASDUs wait
    /// in the queue until the window takes them, and events overtake them
    /// meanwhile (5-101 Table 16). Encoding each one again when it is handed
    /// over keeps 5-101 cl.7.2.2.2: *"The transmission of successive values
    /// of a particular INFORMATION OBJECT must always be in the chronological
    /// order in which the values were measured."* A point's kind never
    /// changes, so the ASDU keeps its type and length.
    pub fn refresh(&self, asdu: Vec<u8>) -> Vec<u8> {
        let sizes = self.addressing.sizes;
        let Ok(header) = Header::parse_with(&asdu, sizes) else {
            return asdu;
        };
        if header.negative || header.sequence {
            return asdu;
        }
        let counters: Option<BTreeMap<u32, Sample>> = match header.cause {
            Cause::InterrogatedByStation | Cause::InterrogatedByGroup(_) => None,
            cause => match ci::Request::from_cause(cause) {
                Some(request) => Some(self.counters(request).into_iter().collect()),
                None => return asdu,
            },
        };
        let Ok(decoded) = iec104::asdu::decode_with(&asdu, sizes) else {
            return asdu;
        };
        let points: Option<Vec<(u32, Sample)>> = decoded
            .objects
            .points()
            .iter()
            .map(|point| {
                let entry = self.entries.get(&point.ioa)?;
                let (sample, type_id) = match &counters {
                    None => (entry.sample, untagged(&entry.sample.value)?),
                    Some(counters) => {
                        let sample = *counters.get(&point.ioa)?;
                        (sample, event_type(&entry.config, &sample.value)?)
                    }
                };
                (type_id == header.type_id).then_some((point.ioa, sample))
            })
            .collect();
        let Some(points) = points.filter(|p| p.len() == usize::from(header.count)) else {
            return asdu;
        };
        match encode(
            header.type_id,
            &points,
            header.cause,
            header.originator,
            header.test,
            self.addressing,
        ) {
            Ok(mut frames) if frames.len() == 1 => frames.remove(0),
            _ => asdu,
        }
    }

    /// The frozen values of `request` as spontaneous events (counter mode D,
    /// 5-101 cl.7.4.8).
    pub fn frozen_events(&self, request: ci::Request) -> Result<Vec<Vec<u8>>, LayoutError> {
        let mut frames = Vec::new();
        for (ioa, sample) in self.counters(request) {
            let Some(type_id) = self
                .entries
                .get(&ioa)
                .and_then(|entry| event_type(&entry.config, &sample.value))
            else {
                continue;
            };
            frames.extend(encode(
                type_id,
                &[(ioa, sample)],
                Cause::Spontaneous,
                0,
                false,
                self.addressing,
            )?);
        }
        Ok(frames)
    }
}

/// Whether group `n` (counted from 1) is one of `groups`.
fn in_group(groups: u16, n: u8) -> bool {
    group_bit(n).is_some_and(|bit| groups & bit != 0)
}

/// The bit of group `n` (1 to 16) in a group mask, `None` for another `n`.
pub(super) fn group_bit(n: u8) -> Option<u16> {
    n.checked_sub(1)
        .and_then(|shift| 1u16.checked_shl(u32::from(shift)))
}

fn in_counter_request(config: &PointConfig, request: ci::Request) -> bool {
    request
        .group_number()
        .map_or(config.station, |n| in_group(config.groups, n))
}

fn in_scope(config: &PointConfig, scope: Scope) -> bool {
    scope
        .group_number()
        .map_or(config.station, |n| in_group(config.groups, n))
}

/// The image is always ready: a station that is still starting up has no
/// server yet. So an interrogation is never refused as *"not ready"* (5-101
/// cl.7.4.5).
impl DataSource for Image {
    fn ready(&self, _scope: Scope) -> bool {
        true
    }

    /// Every point of the scope in its untagged type (5-101 cl.7.4.5: *"ASDUs
    /// with cause of transmission 20 to 36 are transmitted without time
    /// tags"*), one ASDU per type, in address order. Counters are the counter
    /// interrogation's and protection events have no interrogated form.
    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
        let points: Vec<(u32, Sample, TypeId)> = self
            .entries
            .iter()
            .filter(|(_, entry)| in_scope(&entry.config, scope))
            .filter_map(|(&ioa, entry)| {
                let type_id = untagged(&entry.sample.value)?;
                gi::is_interrogated(type_id).then_some((ioa, entry.sample, type_id))
            })
            .collect();
        out.extend(by_type(&points, scope.cause(), 0, false, self.addressing));
    }
}

impl CounterSource for Image {
    fn ready(&self, _request: ci::Request) -> bool {
        true
    }

    /// The counters of the request, frozen where a freeze stored them, in the
    /// configured `M_IT` type (`<15>` or `<37>`).
    fn totals(&self, request: ci::Request, out: &mut Vec<Vec<u8>>) {
        let points: Vec<(u32, Sample, TypeId)> = self
            .counters(request)
            .into_iter()
            .filter_map(|(ioa, sample)| {
                let type_id = event_type(&self.entries.get(&ioa)?.config, &sample.value)?;
                Some((ioa, sample, type_id))
            })
            .collect();
        out.extend(by_type(&points, request.cause(), 0, false, self.addressing));
    }
}

/// The image as a read's data source: the answer echoes the command's
/// originator address and test bit (5-101 cl.7.2.3), which `rd` checks.
pub struct ReadSource<'a> {
    pub image: &'a Image,
    pub originator: u8,
    pub test: bool,
}

impl rd::DataSource for ReadSource<'_> {
    /// A readable point in its untagged type with cause 5 (5-101 cl.7.4.2:
    /// *"Normally, these requested objects do not include the time tag."*).
    /// Counters and protection events are not on the read's list of types
    /// (`rd::RETURNED_TYPES`), so reading one is answered with cause 47.
    fn object(&self, ioa: u32) -> Option<Vec<u8>> {
        let entry = self.image.entries.get(&ioa)?;
        if !entry.config.readable {
            return None;
        }
        let type_id = untagged(&entry.sample.value)?;
        if !rd::RETURNED_TYPES.contains(&type_id) {
            return None;
        }
        encode(
            type_id,
            &[(ioa, entry.sample)],
            Cause::Request,
            self.originator,
            self.test,
            self.image.addressing,
        )
        .ok()
        .map(|mut frames| frames.remove(0))
    }
}

/// ASDUs for `points`, one run of ASDUs per type in the order the types first
/// appear, each ASDU as full as the APDU allows.
fn by_type(
    points: &[(u32, Sample, TypeId)],
    cause: Cause,
    originator: u8,
    test: bool,
    addressing: Addressing,
) -> Vec<Vec<u8>> {
    let mut types: Vec<TypeId> = Vec::new();
    for (_, _, type_id) in points {
        if !types.contains(type_id) {
            types.push(*type_id);
        }
    }
    let mut out = Vec::new();
    for type_id in types {
        let group: Vec<(u32, Sample)> = points
            .iter()
            .filter(|(_, _, t)| *t == type_id)
            .map(|(ioa, sample, _)| (*ioa, *sample))
            .collect();
        // The types come from the tables above, so the layout accepts them.
        if let Ok(frames) = encode(type_id, &group, cause, originator, test, addressing) {
            out.extend(frames);
        }
    }
    out
}

fn qds(q: Quality) -> Qds {
    Qds {
        overflow: q.overflow.unwrap_or(false),
        blocked: q.blocked,
        substituted: q.substituted,
        not_topical: q.not_topical,
        invalid: q.invalid,
    }
}

const fn qdp(q: Quality, elapsed_invalid: bool) -> Qdp {
    Qdp {
        elapsed_time_invalid: elapsed_invalid,
        blocked: q.blocked,
        substituted: q.substituted,
        not_topical: q.not_topical,
        invalid: q.invalid,
    }
}

/// Encodes `points` of one type as `SQ = 0` ASDUs (each object with its own
/// address), as many objects per ASDU as the 249 octets of an APDU's ASDU
/// hold (104 clause 5; 5-101 cl.7.2.2's `N` up to 127).
pub fn encode(
    type_id: TypeId,
    points: &[(u32, Sample)],
    cause: Cause,
    originator: u8,
    test: bool,
    addressing: Addressing,
) -> Result<Vec<Vec<u8>>, LayoutError> {
    let time = |s: &Sample| s.time.unwrap_or_default();
    macro_rules! build {
        ($layout:ident, |$s:ident| $value:expr) => {
            chunks::<$layout>(
                points,
                |$s: &Sample| -> Option<$layout> { Some($value) },
                cause,
                originator,
                test,
                addressing,
            )
        };
    }
    match type_id {
        TypeId::MSpNa1 => build!(MSpNa1, |s| MSpNa1 { siq: siq(s)? }),
        TypeId::MSpTb1 => build!(MSpTb1, |s| MSpTb1 {
            siq: siq(s)?,
            time: time(s)
        }),
        TypeId::MDpNa1 => build!(MDpNa1, |s| MDpNa1 { diq: diq(s)? }),
        TypeId::MDpTb1 => build!(MDpTb1, |s| MDpTb1 {
            diq: diq(s)?,
            time: time(s)
        }),
        TypeId::MStNa1 => build!(MStNa1, |s| MStNa1 {
            vti: vti(s)?,
            qds: qds(s.quality)
        }),
        TypeId::MStTb1 => build!(MStTb1, |s| MStTb1 {
            vti: vti(s)?,
            qds: qds(s.quality),
            time: time(s)
        }),
        TypeId::MBoNa1 => build!(MBoNa1, |s| MBoNa1 {
            bsi: bsi(s)?,
            qds: qds(s.quality)
        }),
        TypeId::MBoTb1 => build!(MBoTb1, |s| MBoTb1 {
            bsi: bsi(s)?,
            qds: qds(s.quality),
            time: time(s)
        }),
        TypeId::MMeNa1 => build!(MMeNa1, |s| MMeNa1 {
            nva: nva(s)?,
            qds: qds(s.quality)
        }),
        TypeId::MMeTd1 => build!(MMeTd1, |s| MMeTd1 {
            nva: nva(s)?,
            qds: qds(s.quality),
            time: time(s)
        }),
        TypeId::MMeNb1 => build!(MMeNb1, |s| MMeNb1 {
            sva: sva(s)?,
            qds: qds(s.quality)
        }),
        TypeId::MMeTe1 => build!(MMeTe1, |s| MMeTe1 {
            sva: sva(s)?,
            qds: qds(s.quality),
            time: time(s)
        }),
        TypeId::MMeNc1 => build!(MMeNc1, |s| MMeNc1 {
            r32: r32(s)?,
            qds: qds(s.quality)
        }),
        TypeId::MMeTf1 => build!(MMeTf1, |s| MMeTf1 {
            r32: r32(s)?,
            qds: qds(s.quality),
            time: time(s)
        }),
        TypeId::MPsNa1 => build!(MPsNa1, |s| MPsNa1 {
            scd: scd(s)?,
            qds: qds(s.quality)
        }),
        TypeId::MItNa1 => build!(MItNa1, |s| MItNa1 { bcr: bcr(s)? }),
        TypeId::MItTb1 => build!(MItTb1, |s| MItTb1 {
            bcr: bcr(s)?,
            time: time(s)
        }),
        TypeId::MEpTd1 => build!(MEpTd1, |s| ep_td1(s)?),
        TypeId::MEpTe1 => build!(MEpTe1, |s| ep_te1(s)?),
        TypeId::MEpTf1 => build!(MEpTf1, |s| ep_tf1(s)?),
        other => Err(LayoutError::TypeMismatch {
            expected: TypeId::MSpNa1,
            got: other,
        }),
    }
}

/// `element` is `None` for a sample whose value the type `A` does not carry;
/// the types come from the values, so that is refused as a mismatch.
fn chunks<A: AsduLayout>(
    points: &[(u32, Sample)],
    element: impl Fn(&Sample) -> Option<A>,
    cause: Cause,
    originator: u8,
    test: bool,
    addressing: Addressing,
) -> Result<Vec<Vec<u8>>, LayoutError> {
    let sizes = addressing.sizes;
    let per_object = usize::from(sizes.information_object_address_octets()).saturating_add(A::LEN);
    let fit = sizes
        .max_body()
        .checked_div(per_object)
        .unwrap_or_default()
        .clamp(1, 127);
    let mut frames = Vec::new();
    for run in points.chunks(fit) {
        let objects: Vec<LayoutObject<A>> = run
            .iter()
            .map(|(ioa, sample)| {
                element(sample)
                    .map(|value| LayoutObject { ioa: *ioa, value })
                    .ok_or_else(|| LayoutError::TypeMismatch {
                        expected: A::TYPE_ID,
                        got: untagged(&sample.value)
                            .or_else(|| tagged(&sample.value))
                            .unwrap_or(A::TYPE_ID),
                    })
            })
            .collect::<Result<_, _>>()?;
        // At most 127 objects per run (`fit`).
        let count =
            u8::try_from(objects.len()).map_err(|_| LayoutError::ObjectCountNotAllowed {
                type_id: A::TYPE_ID,
                count: u8::MAX,
            })?;
        let header = Header {
            type_id: A::TYPE_ID,
            sequence: false,
            count,
            cause,
            negative: false,
            test,
            originator,
            common_address: addressing.common_address,
        };
        frames.push(encode_asdu_with(&header, &objects, sizes)?);
    }
    Ok(frames)
}

const fn siq(s: &Sample) -> Option<Siq> {
    let Value::Single(spi) = s.value else {
        return None;
    };
    let q = &s.quality;
    Some(Siq {
        spi,
        blocked: q.blocked,
        substituted: q.substituted,
        not_topical: q.not_topical,
        invalid: q.invalid,
    })
}

const fn diq(s: &Sample) -> Option<Diq> {
    let Value::Double(dpi) = s.value else {
        return None;
    };
    let q = &s.quality;
    Some(Diq {
        dpi,
        blocked: q.blocked,
        substituted: q.substituted,
        not_topical: q.not_topical,
        invalid: q.invalid,
    })
}

const fn vti(s: &Sample) -> Option<Vti> {
    let Value::StepPosition { value, transient } = s.value else {
        return None;
    };
    Some(Vti { value, transient })
}

const fn bsi(s: &Sample) -> Option<Bsi> {
    let Value::Bitstring(bits) = s.value else {
        return None;
    };
    Some(Bsi { bits })
}

fn nva(s: &Sample) -> Option<Nva> {
    let Value::Normalized(value) = s.value else {
        return None;
    };
    Some(Nva::from_scaled(value))
}

const fn sva(s: &Sample) -> Option<Sva> {
    let Value::Scaled(value) = s.value else {
        return None;
    };
    Some(Sva { value })
}

const fn r32(s: &Sample) -> Option<R32> {
    let Value::Float(value) = s.value else {
        return None;
    };
    Some(R32 { value })
}

const fn scd(s: &Sample) -> Option<Scd> {
    let Value::PackedSingle { status, change } = s.value else {
        return None;
    };
    Some(Scd { status, change })
}

const fn bcr(s: &Sample) -> Option<Bcr> {
    let Value::Counter {
        reading,
        sequence,
        carry,
        adjusted,
    } = s.value
    else {
        return None;
    };
    Some(Bcr {
        reading,
        sequence,
        carry,
        adjusted,
        invalid: s.quality.invalid,
    })
}

fn ep_td1(s: &Sample) -> Option<MEpTd1> {
    let Value::ProtectionEvent {
        state,
        elapsed_ms,
        elapsed_invalid,
    } = s.value
    else {
        return None;
    };
    let q = &s.quality;
    Some(MEpTd1 {
        sep: Sep {
            event_state: state,
            elapsed_time_invalid: elapsed_invalid,
            blocked: q.blocked,
            substituted: q.substituted,
            not_topical: q.not_topical,
            invalid: q.invalid,
        },
        elapsed: Cp16Time2a {
            milliseconds: elapsed_ms,
        },
        time: s.time.unwrap_or_default(),
    })
}

fn ep_te1(s: &Sample) -> Option<MEpTe1> {
    let Value::ProtectionStart {
        start,
        elapsed_ms,
        elapsed_invalid,
    } = s.value
    else {
        return None;
    };
    Some(MEpTe1 {
        spe: start,
        qdp: qdp(s.quality, elapsed_invalid),
        elapsed: Cp16Time2a {
            milliseconds: elapsed_ms,
        },
        time: s.time.unwrap_or_default(),
    })
}

fn ep_tf1(s: &Sample) -> Option<MEpTf1> {
    let Value::ProtectionCommand {
        command,
        elapsed_ms,
        elapsed_invalid,
    } = s.value
    else {
        return None;
    };
    Some(MEpTf1 {
        oci: command,
        qdp: qdp(s.quality, elapsed_invalid),
        elapsed: Cp16Time2a {
            milliseconds: elapsed_ms,
        },
        time: s.time.unwrap_or_default(),
    })
}
