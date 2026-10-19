//! The value elements `NVA`, `SVA`, `R32-IEEE STD 754`, `BCR` and `FBP` of
//! IEC 60870-5-101:2003 clause 7.2.6.6–7.2.6.9 and 7.2.6.14, plus `TSC`,
//! which is **not** a 5-101 element: clause 8.8 of IEC 60870-5-104:2006
//! defines it for the time-tagged test command `C_TS_TA_1` (type 107). It sits
//! here because it is a value the caller chooses and echoes.
//!
//! All multi-octet fields here are little-endian on the wire (see the
//! `elements` module doc): `NVA`/`SVA` are `F16`/`I16` least significant octet
//! first, `BCR` is an `I32` followed by its status octet, `TSC` is a `UI16`,
//! and `R32` is an IEEE 754 single in the figure-40 order "Fraction, Fraction,
//! E Fraction, S Exponent".

use super::super::AsduError;
use super::octets;

/// Normalized value (`NVA`), clause 7.2.6.6 (two octets).
///
/// `NVA := F16[1..16]<–1..+1 –2^–15>`: a **fixed-point** number in two's
/// complement, so the raw `i16` is the value times 32768 and
/// `raw / 32768.0` is in `[–1, +1 – 2^-15]`. "The resolution of measured values
/// is not defined. If the resolution of the measured value is coarser than the
/// unit of the LSB, then the least significant bits are set to zero."
///
/// This type stores the wire value; [`Nva::to_scaled`] and [`Nva::from_scaled`]
/// are the two directions of the scaling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Nva {
    /// The raw `F16` as it appears on the wire.
    pub value: i16,
}

impl Nva {
    /// Octets on the wire.
    pub const LEN: usize = 2;

    /// The raw wire value.
    #[must_use]
    pub const fn from_raw(value: i16) -> Self {
        Self { value }
    }

    /// The raw wire value.
    #[must_use]
    pub const fn raw(&self) -> i16 {
        self.value
    }

    /// The normalized value, `raw / 32768`.
    ///
    /// `i16::MIN` is exactly `−1.0`; `i16::MAX` is `1.0 − 2^−15`.
    #[must_use]
    pub fn to_scaled(&self) -> f64 {
        f64::from(self.value) / 32768.0
    }

    /// The `NVA` for a normalized value, rounded to the nearest raw step
    /// (`value * 32768`, `f64::round`, half away from zero) and saturating at
    /// the ends of the `F16` range rather than wrapping. A magnitude past
    /// `±1` clamps to `i16::MIN` / `i16::MAX`; it is never truncated modulo
    /// 2^16.
    #[must_use]
    pub fn from_scaled(value: f64) -> Self {
        let scaled = (value * 32768.0).round();
        let raw = if scaled >= f64::from(i16::MAX) {
            i16::MAX
        } else if scaled <= f64::from(i16::MIN) {
            i16::MIN
        } else {
            #[expect(
                clippy::as_conversions,
                clippy::cast_possible_truncation,
                reason = "in range after the clamp above, and std has no checked float to integer conversion"
            )]
            let raw = scaled as i16;
            raw
        };
        Self { value: raw }
    }

    /// Reads two octets, little-endian.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let octets = octets::<{ Self::LEN }>(buf)?;
        Ok(Self::from_raw(i16::from_le_bytes([octets[0], octets[1]])))
    }

    /// Appends two octets, little-endian.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
    }
}

/// Scaled value (`SVA`), clause 7.2.6.7 (two octets).
///
/// `SVA := I16[1..16]<–2^15..+2^15–1>`: a plain signed 16-bit integer in two's
/// complement. "Range and position of decimal point are fixed parameters":
/// they are project data (the clause's own example is "Voltage: 10,3 kV;
/// transmitted value 103, decimal point 10^–1"), so they are **not** a field of
/// this type and the caller applies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sva {
    /// The raw `I16` as it appears on the wire.
    pub value: i16,
}

impl Sva {
    /// Octets on the wire.
    pub const LEN: usize = 2;

    /// The raw wire value.
    #[must_use]
    pub const fn from_raw(value: i16) -> Self {
        Self { value }
    }

    /// The raw wire value.
    #[must_use]
    pub const fn raw(&self) -> i16 {
        self.value
    }

    /// Reads two octets, little-endian.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let octets = octets::<{ Self::LEN }>(buf)?;
        Ok(Self::from_raw(i16::from_le_bytes([octets[0], octets[1]])))
    }

    /// Appends two octets, little-endian.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
    }
}

/// Short floating point number (`R32-IEEE STD 754`), clause 7.2.6.8 (four
/// octets).
///
/// `R32-IEEE STD 754 := R32.23{Fraction,Exponent,Sign}`: an IEEE 754 single in
/// little-endian octet order, i.e. exactly `f32::from_le_bytes` (see
/// [`R32::parse`] for the octet-by-octet reading of figure 40).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct R32 {
    /// The number, as an IEEE 754 single.
    pub value: f32,
}

impl R32 {
    /// Octets on the wire.
    pub const LEN: usize = 4;

    /// The floating point value.
    #[must_use]
    pub const fn from_raw(value: f32) -> Self {
        Self { value }
    }

    /// The floating point value.
    #[must_use]
    pub const fn raw(&self) -> f32 {
        self.value
    }

    /// Reads four octets, little-endian.
    ///
    /// Figure 40 prints the four octets as "Fraction, Fraction, E Fraction,
    /// S Exponent": octet 1 is fraction bits 1–8, octet 2 fraction bits 9–16,
    /// octet 3 fraction bits 17–23 in bits 1–7 with exponent bit 1 in bit 8,
    /// octet 4 exponent bits 2–8 in bits 1–7 with the sign in bit 8. That is
    /// an IEEE 754 single in little-endian octet order.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let octets = octets::<{ Self::LEN }>(buf)?;
        Ok(Self::from_raw(f32::from_le_bytes([
            octets[0], octets[1], octets[2], octets[3],
        ])))
    }

    /// Appends four octets, little-endian (figure 40's "Fraction, Fraction,
    /// E Fraction, S Exponent").
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
    }
}

/// Binary counter reading (`BCR`), clause 7.2.6.9 (five octets).
///
/// ```text
/// BCR := CP40{Counter reading, Sequence notation}
/// Counter reading := I32[1..32]<–2^31..+2^31–1>   octets 1–4, little-endian
/// Sequence notation := CP8{SQ,CY,CA,IV}           octet 5
/// SQ := UI5[33..37]<0..31>  0x1F
/// CY := BS1[38]<0..1>       0x20  carry: counter overflow in the period
/// CA := BS1[39]<0..1>       0x40  counter was adjusted since last reading
/// IV := BS1[40]<0..1>       0x80  counter reading is invalid
/// ```
///
/// "Counter overflow occurs when the value increments from +2^31–1 to zero or
/// from –2^31 to zero"; `CY`/`CA`/`IV` are only modified when the value is
/// determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bcr {
    /// `Counter reading`: the integrated total.
    pub reading: i32,
    /// `SQ`: the sequence number, 0..=31.
    pub sequence: u8,
    /// `CY`: a counter overflow occurred in the integration period.
    pub carry: bool,
    /// `CA`: the counter was adjusted since the last reading.
    pub adjusted: bool,
    /// `IV`: the counter reading is invalid.
    pub invalid: bool,
}

impl Bcr {
    /// Octets on the wire.
    pub const LEN: usize = 5;

    /// Reads five octets.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let octets = octets::<{ Self::LEN }>(buf)?;
        let status = octets[4];
        Ok(Self {
            reading: i32::from_le_bytes([octets[0], octets[1], octets[2], octets[3]]),
            sequence: status & 0x1F,
            carry: status & 0x20 != 0,
            adjusted: status & 0x40 != 0,
            invalid: status & 0x80 != 0,
        })
    }

    /// Appends five octets.
    ///
    /// `sequence` is `SQ := UI5[33..37]<0..31>`, a five-bit field, so a value
    /// above 31 is masked to its low five bits rather than written whole.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.reading.to_le_bytes());
        let status = (self.sequence & 0x1F)
            | if self.carry { 0x20 } else { 0 }
            | if self.adjusted { 0x40 } else { 0 }
            | if self.invalid { 0x80 } else { 0 };
        out.push(status);
    }
}

/// Fixed test bit pattern (`FBP`), clause 7.2.6.14 (two octets).
///
/// `FBP := UI16[1..16]<55AAH>`: the test command `C_TS_NA_1` (clause 7.3.4.5,
/// figure 76) carries exactly this constant, which is how a controlled station
/// recognises it. The figure's two octet rows read `10101010` then `01010101`,
/// i.e. the little-endian encoding of `0x55AA`.
///
/// A `parse` of any other value is [`AsduError::FixedPatternMismatch`]: the
/// element has exactly one legal value, so a different one is not a value to
/// carry forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Fbp;

impl Fbp {
    /// Octets on the wire.
    pub const LEN: usize = 2;

    /// The one legal wire value, `55AAH`.
    pub const VALUE: u16 = 0x55AA;

    /// Reads the two octets, accepting only [`Fbp::VALUE`].
    ///
    /// Any other pattern is [`AsduError::FixedPatternMismatch`]: the element
    /// has exactly one legal value.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let octets = octets::<{ Self::LEN }>(buf)?;
        let got = u16::from_le_bytes([octets[0], octets[1]]);
        if got != Self::VALUE {
            return Err(AsduError::FixedPatternMismatch {
                expected: Self::VALUE,
                got,
            });
        }
        Ok(Self)
    }

    /// Appends the two octets of [`Fbp::VALUE`], least significant octet first
    /// (`AA 55`).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&Self::VALUE.to_le_bytes());
    }
}

/// Test sequence counter (`TSC`), IEC 60870-5-104:2006 clause 8.8 (two octets).
///
/// `TSC := UI16[1..16]<0..65535>`, carried by the **time-tagged** test command
/// `C_TS_TA_1` (type 107), whose clause 8.8 definition line is
/// `C_TS_TA_1 := CP{Data unit identifier,Information object address,TSC,CP56Time2a}`.
/// Figure 30 prints the field as "TSC = Test sequence counter, 16 bit".
///
/// The rule for the value is the caller's: "The requesting station may choose
/// any value of TSC. The TSC in the response shall match the request, and the
/// time in the response shall also exactly match the time in the request".
/// This type carries whatever counter the caller picked and does not check
/// that a response echoes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tsc {
    /// The counter, `0..=65535`.
    pub value: u16,
}

impl Tsc {
    /// Octets on the wire.
    pub const LEN: usize = 2;

    /// The counter value.
    #[must_use]
    pub const fn from_raw(value: u16) -> Self {
        Self { value }
    }

    /// The counter value.
    #[must_use]
    pub const fn raw(&self) -> u16 {
        self.value
    }

    /// Reads two octets, little-endian.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let octets = octets::<{ Self::LEN }>(buf)?;
        Ok(Self::from_raw(u16::from_le_bytes([octets[0], octets[1]])))
    }

    /// Appends two octets, little-endian.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
    }
}
