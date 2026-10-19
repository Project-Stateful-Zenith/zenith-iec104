//! Diagnostics: one-line descriptions of frames and settings, in the
//! standards' own words, for a log or a runbook.
//!
//! This is a display layer only. It turns values a caller already holds into
//! the words the two standards use for them and returns the line as a
//! [`String`]. It opens no sink, reads no clock and keeps no state: the caller
//! timestamps, filters and writes the line wherever it wants. That is the same
//! contract [`crate::link::Session`], [`crate::timers::Timers`] and
//! [`crate::manager::ConnectionManager`] keep, and it is why the crate needs no
//! `log` or `tracing` dependency.
//!
//! # What the standards say about a log
//!
//! 5-101 clause 7.2.3 (PDF page index 42, printed 41):
//!
//! > A controlling station may monitor for and maintain a communications error
//! > log reporting each time that the following ASDUs are received:
//! > - ASDUs in the monitor direction with undefined values in the data unit
//! >   identifier (except the variable structure qualifier);
//! > - ASDUs in the monitor direction with undefined values of information
//! >   object address;
//! > - mirrored ASDUs due to unknown numbers in the control direction
//! >   (type identifications 45 to 51).
//!
//! [`discard`] writes those classes as one line, from the
//! [`crate::asdu::Discard`] that [`crate::asdu::discard_reason`] returns.
//!
//! # Where the words come from
//!
//! Every name in a line comes from an existing accessor, not a second copy:
//!
//! - the ASDU name: [`crate::asdu::TypeId::name`] (5-101 tables 8–13 plus
//!   5-104 clause 6's additions);
//! - the cause mnemonic: [`crate::asdu::Cause::mnemonic`] (5-101 table 14),
//!   with [`crate::asdu::Cause::to_u8`]'s number beside it;
//! - the header fields: [`Header`] (5-101 clauses 7.2.1 to 7.2.4);
//! - the information object address: [`crate::asdu::read_ioa_with`] (5-101
//!   clause 7.2.5);
//! - the address widths: [`AddressSizes`] (5-104 clause 9.5);
//! - the time-outs: [`LinkParams`] (5-104 clause 9).
//!
//! The one table this module adds is [`u_function`], the names of the six
//! U-format functions, spelled as 5-104 clause 5's figures spell them
//! (`STARTDT act`, `TESTFR con`), because [`crate::apci`] carries only their
//! codes.
//!
//! # One function per line, not a `Display` impl per value
//!
//! A log line is a composition of several values (a control field, a header
//! and an address), which a `Display` impl on each type cannot express without
//! each type knowing its neighbours. The entry point is therefore one
//! function, [`apdu`], which formats one complete frame. The smaller
//! formatters [`u_function`], [`control`], [`header`] and
//! [`information_object_address`] are the pieces [`apdu`] is built from;
//! [`discard`], [`timers`] and [`address_sizes`] format values that are not
//! part of a frame. They are all public so a caller that
//! already holds a parsed [`Apci`], [`Header`] or [`LinkParams`] does not have
//! to rebuild octets to format one.

use crate::apci::{self, Apci, UFunction};
use crate::asdu::{AddressSizes, AsduError, Discard, Header};
use crate::params::LinkParams;
use std::fmt;

/// The name of a U-format function as 5-104 clause 5's figures spell it
/// (figure 8, PDF page index 28, printed 27): `STARTDT act`, `STARTDT con`,
/// `STOPDT act`, `STOPDT con`, `TESTFR act` or `TESTFR con`.
///
/// [`UFunction::code`] is the octet; this is the word.
#[must_use]
pub const fn u_function(function: UFunction) -> &'static str {
    match function {
        UFunction::StartDtAct => "STARTDT act",
        UFunction::StartDtCon => "STARTDT con",
        UFunction::StopDtAct => "STOPDT act",
        UFunction::StopDtCon => "STOPDT con",
        UFunction::TestFrAct => "TESTFR act",
        UFunction::TestFrCon => "TESTFR con",
    }
}

/// One line for a parsed control field (the APCI of 5-104 clause 5, figures
/// 6–8).
///
/// `I N(S)=3 N(R)=7`, `S N(R)=7` or `U STARTDT act`: the format letter the
/// clause uses (*"numbered information transfer (I format), numbered
/// supervisory functions (S format) and unnumbered control functions (U
/// format)"*), then the sequence numbers the format carries, or the U
/// function's name.
#[must_use]
pub fn control(field: Apci) -> String {
    match field {
        Apci::I { ns, nr } => format!("I N(S)={} N(R)={}", ns.get(), nr.get()),
        Apci::S { nr } => format!("S N(R)={}", nr.get()),
        Apci::U(function) => format!("U {}", u_function(function)),
    }
}

/// One line for a parsed ASDU [`Header`] under the address profile `sizes`
/// fixes.
///
/// The fields are 5-101 clause 7.2.1/7.2.2's type identification and VSQ
/// (`SQ`, `N`), clause 7.2.3's cause with its table 14 mnemonic, its `P/N` and
/// `T` flags and its originator, and clause 7.2.4's common address.
///
/// Two renderings are decisions rather than transcriptions:
///
/// - A cause that `Cause::mnemonic` has no mnemonic for (a reserved or
///   private cause, or 44 to 47) prints its number alone (`cause=14`). The
///   mnemonics come from `Cause::mnemonic` (`cause=inro1(21)`), so this module
///   does not keep a second copy of table 14.
/// - A profile without the originator octet prints `ORG=-`, not `ORG=0`. 5-104
///   clause 9.5 reads *"Originator address is set to zero if not used"*, so a
///   `0` there would be indistinguishable from clause 7.2.3's real
///   `<0> := default`.
#[must_use]
pub fn header(header: &Header, sizes: AddressSizes) -> String {
    let mnemonic = header.cause.mnemonic();
    let cause = if mnemonic.is_empty() {
        format!("{}", header.cause.to_u8())
    } else {
        format!("{mnemonic}({})", header.cause.to_u8())
    };
    let originator = if sizes.originator_address() {
        header.originator.to_string()
    } else {
        String::from("-")
    };
    format!(
        "{}({}) SQ={} N={} cause={} P/N={} T={} ORG={} CA={}",
        header.type_id.name(),
        header.type_id.to_u8(),
        u8::from(header.sequence),
        header.count,
        cause,
        u8::from(header.negative),
        u8::from(header.test),
        originator,
        header.common_address,
    )
}

/// One line for the information object address at the head of an object area,
/// read at the width `sizes` fixes with [`crate::asdu::read_ioa_with`].
///
/// 5-101 clause 7.2.5: *"The length of the INFORMATION OBJECT ADDRESS (one,
/// two or three octets) is a parameter which is fixed per system."* This reads
/// the address at the start of the object area and nothing more. For an
/// SQ = 1 sequence that is the base address, the only one on the wire (5-101
/// clause 7.2.2.1).
///
/// # Errors
///
/// [`Error::Asdu`] when `objects` is too short to hold an address of the width
/// `sizes` fixes.
pub fn information_object_address(objects: &[u8], sizes: AddressSizes) -> Result<String, Error> {
    Ok(format!(
        "IOA={}",
        crate::asdu::read_ioa_with(objects, sizes)?
    ))
}

/// One line for a discarded ASDU, in the terms of 5-101 clause 7.2.3's error
/// log.
///
/// [`Discard::Unspecified`] prints the field with the undefined value and its
/// cause (`discarded: type identification (cause 44)`), from
/// [`crate::asdu::Unspecified::field`] and [`crate::asdu::Unspecified::cause`].
/// [`Discard::Mirror`] prints `discarded: mirrored ASDU`, the clause's third
/// bullet.
#[must_use]
pub fn discard(discard: Discard) -> String {
    match discard {
        Discard::Unspecified(field) => format!(
            "discarded: {} (cause {})",
            field.field(),
            field.cause().to_u8()
        ),
        Discard::Mirror => String::from("discarded: mirrored ASDU"),
    }
}

/// One line for a connection's parameters: 5-104 clause 9's time-outs, k, w
/// and the port.
///
/// `t0=30 s t1=15 s t2=10 s t3=20 s k=12 w=8 port=2404` for
/// [`LinkParams::default`], the table's default values. Useful as a startup
/// line, so a log reader can see which time-outs a connection was configured
/// with; clause 10.7 asks for them to be settable per connection (*"It should
/// be possible to set the values of the timers t0 to t3 individually for each
/// connection within a redundancy group."*).
///
/// The crate holds each time-out as a `Duration`, so a sub-second part is
/// printed exactly (`t1=1.5 s`) rather than rounded down: `t2=500 ms` printed
/// as `t2=0 s` would show a value [`LinkParams::validate`] refuses. A whole
/// number of seconds prints as `15 s`.
#[must_use]
pub fn timers(params: &LinkParams) -> String {
    format!(
        "t0={} t1={} t2={} t3={} k={} w={} port={}",
        duration(params.t0),
        duration(params.t1),
        duration(params.t2),
        duration(params.t3),
        params.k,
        params.w,
        params.port,
    )
}

/// One line for an address profile: the field widths of 5-104 clause 9.5 and
/// 5-101 clauses 7.2.3 to 7.2.5.
///
/// `CA 2 octets, IOA 3 octets, originator present` is the conventional profile.
/// A frame log is only readable with the profile beside it, because nothing on
/// the wire says which profile the two stations agreed.
#[must_use]
pub fn address_sizes(sizes: AddressSizes) -> String {
    format!(
        "CA {}, IOA {}, originator {}",
        octets(sizes.common_address_octets()),
        octets(sizes.information_object_address_octets()),
        if sizes.originator_address() {
            "present"
        } else {
            "absent"
        },
    )
}

/// One line for a complete APDU, from its own octets.
///
/// The frame is parsed with [`crate::apci::parse`] and formatted as the
/// control field and, for an I-format frame, the ASDU header
/// ([`Header::parse_with`], in the profile `sizes` fixes) and the first
/// information object address, separated by ` | `.
///
/// A frame the codec refuses is an [`Error`] carrying the parse failure, never
/// a panic and never a partly formatted line. Octets *behind* the first frame
/// are refused too ([`Error::TrailingOctets`]): this function formats exactly
/// one frame, so a buffer holding two frames or stray padding must not have the
/// extra octets silently dropped.
///
/// ```
/// use iec104::asdu::AddressSizes;
/// use iec104::diag;
///
/// // A U-format frame: START, length 4, `STARTDT act`, three reserved zeroes.
/// let frame = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
/// assert_eq!(diag::apdu(&frame, AddressSizes::CONVENTIONAL).unwrap(), "U STARTDT act");
/// ```
///
/// # Errors
///
/// [`Error::Apci`] when `bytes` does not start with a whole, legal APDU,
/// [`Error::TrailingOctets`] when octets follow it, and [`Error::Asdu`] when
/// the ASDU of an I-format frame cannot be read.
pub fn apdu(bytes: &[u8], sizes: AddressSizes) -> Result<String, Error> {
    let (parsed, consumed) = apci::parse(bytes)?;
    if consumed != bytes.len() {
        return Err(Error::TrailingOctets {
            frame: consumed,
            have: bytes.len(),
        });
    }
    let mut line = control(parsed.apci);
    if parsed.apci.is_i_format() {
        let decoded = Header::parse_with(parsed.asdu, sizes)?;
        line.push_str(" | ");
        line.push_str(&header(&decoded, sizes));
        if decoded.count > 0 {
            let objects = parsed.asdu.get(sizes.header_len()..).unwrap_or_default();
            line.push_str(" | ");
            line.push_str(&information_object_address(objects, sizes)?);
        }
    }
    Ok(line)
}

/// `1 octet` or `3 octets`.
fn octets(count: u8) -> String {
    format!("{count} octet{}", if count == 1 { "" } else { "s" })
}

/// `15 s` for a whole number of seconds and `1.5 s` for one with a sub-second
/// part: exact, never rounded down to zero.
fn duration(value: std::time::Duration) -> String {
    let seconds = value.as_secs();
    let nanos = value.subsec_nanos();
    if nanos == 0 {
        return format!("{seconds} s");
    }
    let mut fraction = format!("{nanos:09}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{seconds}.{fraction} s")
}

/// Why a frame could not be formatted.
///
/// [`Error::Apci`] and [`Error::Asdu`] carry the codec's own errors unchanged:
/// [`crate::apci::parse`]'s refusal (clause 5's start, length and control
/// field rules), and [`Header::parse_with`]'s or
/// [`crate::asdu::read_ioa_with`]'s (the field widths of 5-101 clauses 7.2.1 to
/// 7.2.5). [`Error::TrailingOctets`] is this module's own: the codec succeeded
/// on a prefix, but the caller handed in more than the one frame [`apdu`]
/// formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The APDU itself was not one clause 5 allows.
    Apci(apci::ParseError),
    /// The ASDU behind an I-format frame was not one clauses 7.2.1–7.2.5 allow.
    Asdu(AsduError),
    /// The buffer held more octets than the first complete frame: `frame` is the
    /// frame's own length in octets (the count [`crate::apci::parse`] consumed)
    /// and `have` is the buffer's.
    TrailingOctets {
        /// Length of the first complete frame, in octets.
        frame: usize,
        /// Length of the buffer handed in, in octets.
        have: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apci(e) => write!(f, "unformattable APDU: {e:?}"),
            Self::Asdu(e) => write!(f, "unformattable ASDU: {e:?}"),
            // `6 octets behind a 6-octet frame`, and `1 octet` (not
            // `1 octets`) for a single stray octet.
            Self::TrailingOctets { frame, have } => {
                let extra = have.saturating_sub(*frame);
                write!(
                    f,
                    "unformattable APDU: {} octet{} behind a {}-octet frame",
                    extra,
                    if extra == 1 { "" } else { "s" },
                    frame
                )
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl From<apci::ParseError> for Error {
    fn from(e: apci::ParseError) -> Self {
        Self::Apci(e)
    }
}

impl From<AsduError> for Error {
    fn from(e: AsduError) -> Self {
        Self::Asdu(e)
    }
}
