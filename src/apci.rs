//! APCI (Application Protocol Control Information): the frame header codec.
//!
//! Wire layout of every APDU on the TCP stream (octet indices absolute):
//!
//! ```text
//! 0        0x68                       start octet
//! 1        length                     number of octets AFTER this field
//!                                     = 4 (control) + ASDU length, max 253
//! 2..5     control field              I-/S-/U-format, see below
//! 6..      ASDU                       only present in I-format frames
//! ```
//!
//! Control field formats. N(S)/N(R) are 15-bit counters carried little-endian
//! and shifted left by one bit: the low bit of the first octet of the pair is a
//! format flag, and the second octet carries the counter's eight high bits.
//!
//! ```text
//! I-format:  bit0(cf0) = 0   N(S) = cf0[7:1] | cf1[7:0] << 7
//!                            N(R) = cf2[7:1] | cf3[7:0] << 7
//! S-format:  cf0 = 0x01, cf1 = 0x00, N(R) as above in cf2/cf3
//! U-format:  cf0 = 0b11 | function bits, cf1..cf3 = 0
//! ```
//!
//! U-format function codes (cf0):
//!
//! ```text
//! 0x07 STARTDT act    0x0B STARTDT con
//! 0x13 STOPDT  act    0x23 STOPDT  con
//! 0x43 TESTFR  act    0x83 TESTFR  con
//! ```
//!
//! Source: IEC 60870-5-104:2006 clause 5 (start and length octets, figures 4–5;
//! control field formats, figures 6–8). The Beckhoff TF6500 documentation
//! "IEC 60870-5-104 telegram structure" (a public vendor document with worked
//! byte examples) shows the same layout.
//!
//! Rules the parser enforces, all from clause 5:
//!
//! - I format is defined by octet 1 bit 1 = 0, and an I-format APDU *always*
//!   contains an ASDU, so its length field is at least 5.
//! - S format is defined by octet 1 bit 1 = 1 and bit 2 = 0; figure 7 shows
//!   octet 1 = 0000 0001 and octet 2 = 0, so both must be exactly that.
//! - U format is defined by octet 1 bit 1 = 1 and bit 2 = 1, with the remaining
//!   six bits selecting one of the six functions in figure 8; octets 2–4 are 0.
//! - "Only one function – TESTFR, STOPDT or STARTDT – may be active at the same
//!   time." An octet with two function bits set is not one of the six codes and
//!   is rejected.

/// Start octet of every APDU.
pub const START: u8 = 0x68;

/// Largest value the length field may carry.
///
/// Clause 5: "the maximum value of the field length of APDU is 253".
pub const MAX_LENGTH: u8 = 253;

/// Largest ASDU that fits in one APDU.
///
/// Clause 5: "The maximum length of the ASDU is limited to 249 because the
/// maximum value of the field length of APDU is 253 … and the length of the
/// control field is 4 octets."
pub const MAX_ASDU: usize = 249;

/// Largest complete APDU: start octet, length octet and 253 (clause 5's
/// `APDUmax = 255`).
pub const MAX_APDU: usize = 255;

/// Smallest length-field value: the 4 control octets of an S- or U-format APCI.
pub const MIN_LENGTH: u8 = 4;

/// Smallest length-field value of an I-format APDU: 4 control octets plus at
/// least one ASDU octet (clause 5: I-format APDUs always contain an ASDU).
pub const MIN_LENGTH_I: u8 = 5;

/// A 15-bit sequence number (N(S) or N(R)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeqNo(u16);

impl SeqNo {
    /// The sequence number `value` modulo 32768 (the counter is 15 bits wide).
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value & 0x7FFF)
    }

    /// The counter value, 0 to 32767.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Next counter value with 15-bit wrap-around.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.wrapping_add(1) & 0x7FFF)
    }
}

/// U-format supervision function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UFunction {
    /// STARTDT act (`0x07`): start data transfer.
    StartDtAct,
    /// STARTDT con (`0x0B`): the confirmation of a STARTDT act.
    StartDtCon,
    /// STOPDT act (`0x13`): stop data transfer.
    StopDtAct,
    /// STOPDT con (`0x23`): the confirmation of a STOPDT act.
    StopDtCon,
    /// TESTFR act (`0x43`): a test frame.
    TestFrAct,
    /// TESTFR con (`0x83`): the confirmation of a TESTFR act.
    TestFrCon,
}

impl UFunction {
    /// Control-field octet 0 for this function.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::StartDtAct => 0x07,
            Self::StartDtCon => 0x0B,
            Self::StopDtAct => 0x13,
            Self::StopDtCon => 0x23,
            Self::TestFrAct => 0x43,
            Self::TestFrCon => 0x83,
        }
    }

    const fn from_code(code: u8) -> Result<Self, ParseError> {
        Ok(match code {
            0x07 => Self::StartDtAct,
            0x0B => Self::StartDtCon,
            0x13 => Self::StopDtAct,
            0x23 => Self::StopDtCon,
            0x43 => Self::TestFrAct,
            0x83 => Self::TestFrCon,
            other => return Err(ParseError::UnknownUFunction(other)),
        })
    }
}

/// Decoded control field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apci {
    /// Numbered information transfer, carries an ASDU.
    I {
        /// N(S): this frame's send sequence number.
        ns: SeqNo,
        /// N(R): the receive sequence number, which acknowledges every I-frame
        /// numbered below it.
        nr: SeqNo,
    },
    /// Numbered supervision of received frames, no ASDU.
    S {
        /// N(R): the receive sequence number, which acknowledges every I-frame
        /// numbered below it.
        nr: SeqNo,
    },
    /// Unnumbered supervision function, no ASDU.
    U(UFunction),
}

impl Apci {
    /// The four control-field octets for this header.
    #[must_use]
    pub const fn control_field(self) -> [u8; 4] {
        match self {
            Self::I { ns, nr } => {
                let [ns0, ns1] = seq_octets(ns);
                let [nr0, nr1] = seq_octets(nr);
                [ns0, ns1, nr0, nr1]
            }
            Self::S { nr } => {
                let [nr0, nr1] = seq_octets(nr);
                [0x01, 0x00, nr0, nr1]
            }
            Self::U(func) => [func.code(), 0x00, 0x00, 0x00],
        }
    }

    /// True for I-format frames (the only ones carrying user data).
    #[must_use]
    pub const fn is_i_format(self) -> bool {
        matches!(self, Self::I { .. })
    }
}

/// The two control-field octets carrying `n`: shifted left by one bit, low
/// octet first (figure 6).
const fn seq_octets(n: SeqNo) -> [u8; 2] {
    (n.get() << 1).to_le_bytes()
}

/// A parsed APDU; `asdu` is empty for S- and U-format frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Apdu<'a> {
    /// The decoded control field.
    pub apci: Apci,
    /// The ASDU the frame carries, empty for S- and U-format frames.
    pub asdu: &'a [u8],
}

impl Apdu<'_> {
    /// Encodes this APDU into `out` (appending, not clearing).
    ///
    /// Rejects the two payload/format combinations the standard does not allow:
    /// an I-format APDU without an ASDU, and an S- or U-format APDU with one
    /// (clause 5: S and U format APDUs consist of the APCI only).
    ///
    /// # Errors
    ///
    /// [`ParseError::FormatPayloadMismatch`] for those two combinations, and
    /// [`ParseError::AsduTooLong`] for an ASDU longer than [`MAX_ASDU`].
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        match self.apci.is_i_format() {
            true if self.asdu.is_empty() => {
                return Err(ParseError::FormatPayloadMismatch(
                    "I-format APDU without an ASDU",
                ));
            }
            false if !self.asdu.is_empty() => {
                return Err(ParseError::FormatPayloadMismatch(
                    "S/U-format APDU with an ASDU",
                ));
            }
            _ => {}
        }
        let too_long = ParseError::AsduTooLong(self.asdu.len());
        if self.asdu.len() > MAX_ASDU {
            return Err(too_long);
        }
        let total = u8::try_from(self.asdu.len())
            .ok()
            .and_then(|len| len.checked_add(MIN_LENGTH))
            .ok_or(too_long)?;
        out.push(START);
        out.push(total);
        out.extend_from_slice(&self.apci.control_field());
        out.extend_from_slice(self.asdu);
        Ok(())
    }
}

/// Why an APDU could not be parsed or encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// First octet was not 0x68.
    BadStart(u8),
    /// Fewer octets available than the length field promises.
    Incomplete {
        /// Octets the frame needs, start and length octets included.
        needed: usize,
        /// Octets that were available.
        have: usize,
    },
    /// Length field < 4 (no room for a control field) or > 253.
    BadLength(u8),
    /// U-format octet 0 was not one of the six defined function codes.
    UnknownUFunction(u8),
    /// An I-format APDU carried no ASDU (length field < 5); clause 5 says an
    /// I-format APDU always contains an ASDU.
    IFormatWithoutAsdu(u8),
    /// S-format octets 1–2 were not the required `0x01 0x00` (figure 7).
    BadSFormatOctet {
        /// The first control-field octet received.
        octet1: u8,
        /// The second control-field octet received.
        octet2: u8,
    },
    /// S- or U-format frame carried reserved octets that must be zero.
    ReservedOctetNotZero,
    /// An S- or U-format APDU was built with a non-empty ASDU, or an I-format
    /// APDU with an empty one. Neither can be encoded.
    FormatPayloadMismatch(&'static str),
    /// ASDU too long for one APDU (clause 5: max 249 octets).
    AsduTooLong(usize),
}

/// Length in octets of the complete APDU starting with `start` and `length`.
///
/// This is the format-independent bound check of clause 5 (`START = 0x68`,
/// length field between 4 and 253). The I-format minimum of 5 octets needs the
/// control field and is applied by [`parse`].
///
/// # Errors
///
/// [`ParseError::BadStart`] if `start` is not `0x68`, and
/// [`ParseError::BadLength`] if `length` lies outside 4 to 253.
pub fn apdu_len(start: u8, length: u8) -> Result<usize, ParseError> {
    if start != START {
        return Err(ParseError::BadStart(start));
    }
    if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
        return Err(ParseError::BadLength(length));
    }
    Ok(usize::from(length) + 2)
}

/// Parses one APDU from the front of `buf`.
///
/// Returns the decoded APDU plus the number of octets consumed. `Err(Incomplete)`
/// means "wait for more bytes": the framing layer should buffer and retry.
///
/// # Errors
///
/// [`ParseError::Incomplete`] while `buf` holds less than one whole APDU, and
/// the other [`ParseError`] variants for a frame that breaks clause 5.
pub fn parse(buf: &[u8]) -> Result<(Apdu<'_>, usize), ParseError> {
    let Some(&start) = buf.first() else {
        return Err(ParseError::Incomplete { needed: 2, have: 0 });
    };
    if start != START {
        return Err(ParseError::BadStart(start));
    }
    let Some(&length) = buf.get(1) else {
        return Err(ParseError::Incomplete {
            needed: 2,
            have: buf.len(),
        });
    };
    let total = apdu_len(start, length)?;
    let Some((&[_, _, cf0, cf1, cf2, cf3], rest)) =
        buf.get(..total).and_then(<[u8]>::split_first_chunk::<6>)
    else {
        return Err(ParseError::Incomplete {
            needed: total,
            have: buf.len(),
        });
    };
    let apci = if cf0 & 0x01 == 0 {
        // I format (clause 5: octet 1 bit 1 = 0). It always carries an ASDU.
        if length < MIN_LENGTH_I {
            return Err(ParseError::IFormatWithoutAsdu(length));
        }
        Apci::I {
            ns: SeqNo((u16::from(cf1) << 7) | (u16::from(cf0) >> 1)),
            nr: SeqNo((u16::from(cf3) << 7) | (u16::from(cf2) >> 1)),
        }
    } else if cf0 & 0x03 == 0x01 {
        // S format (octet 1 bit 1 = 1, bit 2 = 0). Figure 7 pins the whole of
        // octets 1 and 2: 0000 0001 and 0000 0000.
        if cf0 != 0x01 || cf1 != 0x00 {
            return Err(ParseError::BadSFormatOctet {
                octet1: cf0,
                octet2: cf1,
            });
        }
        Apci::S {
            nr: SeqNo((u16::from(cf3) << 7) | (u16::from(cf2) >> 1)),
        }
    } else {
        // U format (octet 1 bits 1 and 2 = 1), exactly one function bit set.
        let func = UFunction::from_code(cf0)?;
        if cf1 != 0 || cf2 != 0 || cf3 != 0 {
            return Err(ParseError::ReservedOctetNotZero);
        }
        Apci::U(func)
    };
    let asdu = if apci.is_i_format() { rest } else { &[][..] };
    Ok((Apdu { apci, asdu }, total))
}
