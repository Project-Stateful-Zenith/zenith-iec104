//! The quality and status elements: `SIQ` (7.2.6.1), `DIQ` (7.2.6.2), `QDS`
//! (7.2.6.3), `QDP` (7.2.6.4), `VTI` (7.2.6.5), `SEP` (7.2.6.10), `SPE`
//! (7.2.6.11), `OCI` (7.2.6.12), `BSI` (7.2.6.13) and `SCD` (7.2.6.40) of
//! IEC 60870-5-101:2003 clause 7.2.6. (The clause's 7.2.6.6–7.2.6.9 and
//! 7.2.6.14 values live in `value.rs`; this file is grouped by what the
//! element is *for*, not by subsection order.)
//!
//! Every element in this file except [`Bsi`] and [`Scd`] is one octet, and all
//! of them number their bits from the least significant bit
//! (`SPI := BS1[1]<0..1>` ⇒ `0x01`, `IV := BS1[8]` ⇒ `0x80`). The figures print
//! those rows MSB-first (`|IV NT SB BL 0 0 0 OV|`); the definition lists in the
//! clause text are the authoritative reading.

use super::super::AsduError;
use super::octets;

/// Quality descriptor (`QDS`), 5-101 clause 7.2.6.3 (one octet).
///
/// ```text
/// QDS := CP8{OV,RES,BL,SB,NT,IV}
/// OV := BS1[1]<0..1>  0x01   overflow / no overflow
/// RES:= BS3[2..4]<0>  reserved, written as zero
/// BL := BS1[5]<0..1>  0x10   blocked / not blocked
/// SB := BS1[6]<0..1>  0x20   substituted / not substituted
/// NT := BS1[7]<0..1>  0x40   not topical / topical
/// IV := BS1[8]<0..1>  0x80   invalid / valid
/// ```
///
/// "Intermediate devices may modify the quality descriptors BL, SB, NT and
/// IV." (clause 7.2.6.3): an application decision, not this codec's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Qds {
    /// `OV`: the value is beyond a predefined range (mainly analog values).
    pub overflow: bool,
    /// `BL`: the value is blocked for transmission.
    pub blocked: bool,
    /// `SB`: the value was provided by an operator or an automatic source.
    pub substituted: bool,
    /// `NT`: the most recent update was not successful.
    pub not_topical: bool,
    /// `IV`: the value was not correctly acquired and cannot be used.
    pub invalid: bool,
}

impl Qds {
    /// Octets on the wire (`CP8`).
    pub const LEN: usize = 1;

    /// Decodes the octet. The `BS3[2..4]` reserved bits are ignored (clause
    /// 7.2.6.3 fixes them to `<0>`).
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            overflow: raw & 0x01 != 0,
            blocked: raw & 0x10 != 0,
            substituted: raw & 0x20 != 0,
            not_topical: raw & 0x40 != 0,
            invalid: raw & 0x80 != 0,
        }
    }

    /// The octet, with the reserved bits written as zero.
    #[must_use]
    pub fn raw(&self) -> u8 {
        u8::from(self.overflow)
            | u8::from(self.blocked) << 4
            | u8::from(self.substituted) << 5
            | u8::from(self.not_topical) << 6
            | u8::from(self.invalid) << 7
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Single-point information with quality descriptor (`SIQ`), clause 7.2.6.1.
///
/// `SIQ := CP8{SPI,RES,BL,SB,NT,IV}`: `SPI := BS1[1]<0..1>` (`<0>` OFF,
/// `<1>` ON), then the same `BL`/`SB`/`NT`/`IV` bits as [`Qds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Siq {
    /// `SPI`: the single-point state, `<0>` OFF and `<1>` ON.
    pub spi: bool,
    /// `BL`: blocked / not blocked.
    pub blocked: bool,
    /// `SB`: substituted / not substituted.
    pub substituted: bool,
    /// `NT`: not topical / topical.
    pub not_topical: bool,
    /// `IV`: invalid / valid.
    pub invalid: bool,
}

impl Siq {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// The quality half as a [`Qds`] (`OV` is not carried by `SIQ`).
    #[must_use]
    pub const fn quality(&self) -> Qds {
        Qds {
            overflow: false,
            blocked: self.blocked,
            substituted: self.substituted,
            not_topical: self.not_topical,
            invalid: self.invalid,
        }
    }

    /// A `SIQ` from a single-point state and a [`Qds`]'s quality bits.
    ///
    /// `OV` has no bit in `SIQ` (clause 7.2.6.1), so it is dropped.
    #[must_use]
    pub const fn with_quality(spi: bool, quality: Qds) -> Self {
        Self {
            spi,
            blocked: quality.blocked,
            substituted: quality.substituted,
            not_topical: quality.not_topical,
            invalid: quality.invalid,
        }
    }

    /// Decodes the octet. The `BS3[2..4]` reserved bits are ignored (clause
    /// 7.2.6.1 fixes them to `<0>`).
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            spi: raw & 0x01 != 0,
            blocked: raw & 0x10 != 0,
            substituted: raw & 0x20 != 0,
            not_topical: raw & 0x40 != 0,
            invalid: raw & 0x80 != 0,
        }
    }

    /// The octet, reserved bits zero.
    #[must_use]
    pub fn raw(&self) -> u8 {
        u8::from(self.spi)
            | u8::from(self.blocked) << 4
            | u8::from(self.substituted) << 5
            | u8::from(self.not_topical) << 6
            | u8::from(self.invalid) << 7
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// The two-bit double-point state `DPI` of [`Diq`].
///
/// (`ES`, `DCS` and `RCS` have their own types: [`EventState`],
/// [`DoubleCommandState`](crate::asdu::DoubleCommandState) and
/// [`RegulatingStepState`](crate::asdu::RegulatingStepState).) Clause 7.2.6.2: `<0> := indeterminate or intermediate state`,
/// `<1> := determined state OFF`, `<2> := determined state ON`,
/// `<3> := indeterminate state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoublePointState {
    /// `<0>`: indeterminate or intermediate state.
    NotDetermined,
    /// `<1>`: determined state OFF.
    Off,
    /// `<2>`: determined state ON.
    On,
    /// `<3>`: indeterminate state.
    Indeterminate,
}

impl DoublePointState {
    /// Decodes the two bits (`UI2[1..2]`, value 0..=3). Bits above the field
    /// are masked off.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::NotDetermined,
            1 => Self::Off,
            2 => Self::On,
            _ => Self::Indeterminate,
        }
    }

    /// The two-bit value, 0..=3.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::NotDetermined => 0,
            Self::Off => 1,
            Self::On => 2,
            Self::Indeterminate => 3,
        }
    }
}

/// Double-point information with quality descriptor (`DIQ`), clause 7.2.6.2.
///
/// `DIQ := CP8{DPI,RES,BL,SB,NT,IV}` with `DPI := UI2[1..2]<0..3>` (see
/// [`DoublePointState`]) and `RES := BS2[3..4]<0>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Diq {
    /// `DPI`: the double-point state.
    pub dpi: DoublePointState,
    /// `BL`: blocked / not blocked.
    pub blocked: bool,
    /// `SB`: substituted / not substituted.
    pub substituted: bool,
    /// `NT`: not topical / topical.
    pub not_topical: bool,
    /// `IV`: invalid / valid.
    pub invalid: bool,
}

impl Diq {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// The quality half as a [`Qds`] (`OV` is not carried by `DIQ`).
    #[must_use]
    pub const fn quality(&self) -> Qds {
        Qds {
            overflow: false,
            blocked: self.blocked,
            substituted: self.substituted,
            not_topical: self.not_topical,
            invalid: self.invalid,
        }
    }

    /// A `DIQ` from a double-point state and a [`Qds`]'s quality bits.
    ///
    /// `OV` has no bit in `DIQ` (clause 7.2.6.2), so it is dropped.
    #[must_use]
    pub const fn with_quality(dpi: DoublePointState, quality: Qds) -> Self {
        Self {
            dpi,
            blocked: quality.blocked,
            substituted: quality.substituted,
            not_topical: quality.not_topical,
            invalid: quality.invalid,
        }
    }

    /// Decodes the octet. The `BS2[3..4]` reserved bits are ignored (clause
    /// 7.2.6.2 fixes them to `<0>`).
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            dpi: DoublePointState::from_bits(raw),
            blocked: raw & 0x10 != 0,
            substituted: raw & 0x20 != 0,
            not_topical: raw & 0x40 != 0,
            invalid: raw & 0x80 != 0,
        }
    }

    /// The octet, reserved bits zero.
    #[must_use]
    pub fn raw(&self) -> u8 {
        self.dpi.to_bits()
            | u8::from(self.blocked) << 4
            | u8::from(self.substituted) << 5
            | u8::from(self.not_topical) << 6
            | u8::from(self.invalid) << 7
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Quality descriptor for events of protection equipment (`QDP`), clause
/// 7.2.6.4 (one octet).
///
/// `QDP := CP8{RES,EI,BL,SB,NT,IV}`: `EI := BS1[4]<0..1>` (`0x08`, "elapsed
/// time valid / elapsed time invalid") replaces the `OV` of [`Qds`]; the
/// `BL`/`SB`/`NT`/`IV` bits are the same ones clause 7.2.6.3 defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Qdp {
    /// `EI`: elapsed time invalid (`<1>`) rather than valid (`<0>`).
    pub elapsed_time_invalid: bool,
    /// `BL`: blocked / not blocked.
    pub blocked: bool,
    /// `SB`: substituted / not substituted.
    pub substituted: bool,
    /// `NT`: not topical / topical.
    pub not_topical: bool,
    /// `IV`: invalid / valid.
    pub invalid: bool,
}

impl Qdp {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// The `BL`/`SB`/`NT`/`IV` half as a [`Qds`] (`EI` is not `OV`).
    #[must_use]
    pub const fn quality(&self) -> Qds {
        Qds {
            overflow: false,
            blocked: self.blocked,
            substituted: self.substituted,
            not_topical: self.not_topical,
            invalid: self.invalid,
        }
    }

    /// Decodes the octet. The `BS3[1..3]` reserved bits are ignored (clause
    /// 7.2.6.4 fixes them to `<0>`).
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            elapsed_time_invalid: raw & 0x08 != 0,
            blocked: raw & 0x10 != 0,
            substituted: raw & 0x20 != 0,
            not_topical: raw & 0x40 != 0,
            invalid: raw & 0x80 != 0,
        }
    }

    /// The octet, reserved bits zero.
    #[must_use]
    pub fn raw(&self) -> u8 {
        u8::from(self.elapsed_time_invalid) << 3
            | u8::from(self.blocked) << 4
            | u8::from(self.substituted) << 5
            | u8::from(self.not_topical) << 6
            | u8::from(self.invalid) << 7
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Value with transient state indication (`VTI`), clause 7.2.6.5 (one octet).
///
/// `VTI := CP8{Value,Transient}`: `Value := I7[1..7]<–64..+63>` is a
/// two's-complement 7-bit integer in bits 1–7, `Transient := BS1[8]<0..1>`
/// (`0x80`) in bit 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vti {
    /// `Value`: step position, `-64..=63`.
    pub value: i8,
    /// `Transient`: the equipment is in a transient state.
    pub transient: bool,
}

impl Vti {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet. `Value` is the two's-complement `I7[1..7]`: the
    /// 7-bit field is sign-extended (bit 7 is the sign), so 64..127 become
    /// −64..−1.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            value: (raw << 1).cast_signed() >> 1,
            transient: raw & 0x80 != 0,
        }
    }

    /// The octet. `Value` is masked to its 7 bits; bit 8 is `Transient`.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.value.cast_unsigned() & 0x7F) | if self.transient { 0x80 } else { 0 }
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// The two-bit event state of `SEP`, `ES`, clause 7.2.6.10.
///
/// `<0> := indeterminate state`, `<1> := OFF`, `<2> := ON`,
/// `<3> := indeterminate state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventState {
    /// `<0>`: indeterminate state.
    NotDetermined,
    /// `<1>`: OFF.
    Off,
    /// `<2>`: ON.
    On,
    /// `<3>`: indeterminate state.
    Indeterminate,
}

impl EventState {
    /// Decodes the two bits. Bits above the field are masked off.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::NotDetermined,
            1 => Self::Off,
            2 => Self::On,
            _ => Self::Indeterminate,
        }
    }

    /// The two-bit value, 0..=3.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::NotDetermined => 0,
            Self::Off => 1,
            Self::On => 2,
            Self::Indeterminate => 3,
        }
    }
}

/// Single event of protection equipment (`SEP`), clause 7.2.6.10 (one octet).
///
/// `SEP := CP8{ES,RES,EI,BL,SB,NT,IV}`: `ES := UI2[1..2]`, `RES := BS1[3]<0>`,
/// then `EI` (`0x08`), `BL`, `SB`, `NT`, `IV` exactly as [`Qdp`] defines them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Sep {
    /// `ES`: the event state.
    pub event_state: EventState,
    /// `EI`: elapsed time invalid.
    pub elapsed_time_invalid: bool,
    /// `BL`: blocked / not blocked.
    pub blocked: bool,
    /// `SB`: substituted / not substituted.
    pub substituted: bool,
    /// `NT`: not topical / topical.
    pub not_topical: bool,
    /// `IV`: event invalid / valid.
    pub invalid: bool,
}

impl Sep {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// The `EI`/`BL`/`SB`/`NT`/`IV` half as a [`Qdp`].
    #[must_use]
    pub const fn quality(&self) -> Qdp {
        Qdp {
            elapsed_time_invalid: self.elapsed_time_invalid,
            blocked: self.blocked,
            substituted: self.substituted,
            not_topical: self.not_topical,
            invalid: self.invalid,
        }
    }

    /// Decodes the octet. The `BS1[3]` reserved bit is ignored (clause
    /// 7.2.6.10 fixes it to `<0>`).
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            event_state: EventState::from_bits(raw),
            elapsed_time_invalid: raw & 0x08 != 0,
            blocked: raw & 0x10 != 0,
            substituted: raw & 0x20 != 0,
            not_topical: raw & 0x40 != 0,
            invalid: raw & 0x80 != 0,
        }
    }

    /// The octet, reserved bits zero.
    #[must_use]
    pub fn raw(&self) -> u8 {
        self.event_state.to_bits()
            | u8::from(self.elapsed_time_invalid) << 3
            | u8::from(self.blocked) << 4
            | u8::from(self.substituted) << 5
            | u8::from(self.not_topical) << 6
            | u8::from(self.invalid) << 7
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Start events of protection equipment (`SPE`), clause 7.2.6.11 (one octet).
///
/// `SPE := BS8{GS,SL1,SL2,SL3,SIE,SRD,RES}`: `GS` `0x01`, `SL1` `0x02`,
/// `SL2` `0x04`, `SL3` `0x08`, `SIE` `0x10`, `SRD` `0x20`,
/// `RES := BS2[7..8]<0>`. The three `SL*` bits are the phases L1/L2/L3 and
/// `SIE` is the earth current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Spe {
    /// `GS`: general start of operation.
    pub general_start: bool,
    /// `SL1`: start of operation phase L1.
    pub start_l1: bool,
    /// `SL2`: start of operation phase L2.
    pub start_l2: bool,
    /// `SL3`: start of operation phase L3.
    pub start_l3: bool,
    /// `SIE`: start of operation, earth current.
    pub start_ie: bool,
    /// `SRD`: start of operation in reverse direction.
    pub start_reverse: bool,
}

impl Spe {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet. The `BS2[7..8]` reserved bits are ignored (clause
    /// 7.2.6.11 fixes them to `<0>`).
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            general_start: raw & 0x01 != 0,
            start_l1: raw & 0x02 != 0,
            start_l2: raw & 0x04 != 0,
            start_l3: raw & 0x08 != 0,
            start_ie: raw & 0x10 != 0,
            start_reverse: raw & 0x20 != 0,
        }
    }

    /// The octet, reserved bits zero.
    #[must_use]
    pub fn raw(&self) -> u8 {
        u8::from(self.general_start)
            | u8::from(self.start_l1) << 1
            | u8::from(self.start_l2) << 2
            | u8::from(self.start_l3) << 3
            | u8::from(self.start_ie) << 4
            | u8::from(self.start_reverse) << 5
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Output circuit information of protection equipment (`OCI`), clause
/// 7.2.6.12 (one octet).
///
/// `OCI := BS8{GC,CL1,CL2,CL3,RES}`: `GC` `0x01`, `CL1` `0x02`, `CL2` `0x04`,
/// `CL3` `0x08`, `RES := BS4[5..8]<0>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Oci {
    /// `GC`: general command to output circuit.
    pub general_command: bool,
    /// `CL1`: command to output circuit phase L1.
    pub command_l1: bool,
    /// `CL2`: command to output circuit phase L2.
    pub command_l2: bool,
    /// `CL3`: command to output circuit phase L3.
    pub command_l3: bool,
}

impl Oci {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet. The `BS4[5..8]` reserved bits are ignored (clause
    /// 7.2.6.12 fixes them to `<0>`).
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            general_command: raw & 0x01 != 0,
            command_l1: raw & 0x02 != 0,
            command_l2: raw & 0x04 != 0,
            command_l3: raw & 0x08 != 0,
        }
    }

    /// The octet, reserved bits zero.
    #[must_use]
    pub fn raw(&self) -> u8 {
        u8::from(self.general_command)
            | u8::from(self.command_l1) << 1
            | u8::from(self.command_l2) << 2
            | u8::from(self.command_l3) << 3
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Binary state information, 32 bit (`BSI`), clause 7.2.6.13 (four octets).
///
/// `BSI := 32BS1[1..32]<0..1>`: a 32-bit bitstring, least significant octet
/// first, with bit `n` (1-based, as the clause numbers it) at `1 << (n - 1)` of
/// the little-endian `u32`, so bit 1 is the low bit of octet 1 and bit 32 the
/// high bit of octet 4 (clause 7.3.1.7, figure 31 prints four "Bitstring"
/// octets in that order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bsi {
    /// The 32 bits, little-endian on the wire.
    pub bits: u32,
}

impl Bsi {
    /// Octets on the wire.
    pub const LEN: usize = 4;

    /// Bit `n`, numbered 1..=32 as the clause numbers it. `n` outside that
    /// range is `false`.
    #[must_use]
    pub fn bit(&self, n: u8) -> bool {
        if !(1..=32).contains(&n) {
            return false;
        }
        self.bits & (1 << n.saturating_sub(1)) != 0
    }

    /// Sets bit `n` (1..=32) to `value`; a `n` outside that range changes
    /// nothing.
    pub fn set_bit(&mut self, n: u8, value: bool) {
        if !(1..=32).contains(&n) {
            return;
        }
        let mask = 1 << n.saturating_sub(1);
        if value {
            self.bits |= mask;
        } else {
            self.bits &= !mask;
        }
    }

    /// Decodes the four octets (little-endian).
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self { bits: raw }
    }

    /// The 32 bits as a little-endian `u32`.
    #[must_use]
    pub const fn raw(&self) -> u32 {
        self.bits
    }

    /// Reads four octets, least significant first.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?;
        let bytes = [raw[0], raw[1], raw[2], raw[3]];
        Ok(Self::from_raw(u32::from_le_bytes(bytes)))
    }

    /// Appends four octets, least significant first.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bits.to_le_bytes());
    }
}

/// Status and status change detection (`SCD`), clause 7.2.6.40 (four octets).
///
/// `SCD := CP32{ST,CD}`: `ST := BS16[1..16]` occupies the first two octets and
/// `CD := BS16[17..32]` the next two, both little-endian, with bit `n` of `ST`
/// at `1 << (n - 1)` (bits 1–16) and `CDn` the status-change bit "in bit
/// position n+16". `CDn<1>` means at least one status change was detected since
/// the last reporting of this information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scd {
    /// `ST`: the 16 status bits, little-endian.
    pub status: u16,
    /// `CD`: the 16 status-change detection bits, little-endian.
    pub change: u16,
}

impl Scd {
    /// Octets on the wire.
    pub const LEN: usize = 4;

    /// Status bit `n`, numbered 1..=16. `n` outside that range is `false`.
    #[must_use]
    pub fn status_bit(&self, n: u8) -> bool {
        if !(1..=16).contains(&n) {
            return false;
        }
        self.status & (1 << n.saturating_sub(1)) != 0
    }

    /// Status-change bit `n`, numbered 1..=16. `n` outside that range is
    /// `false`.
    #[must_use]
    pub fn change_bit(&self, n: u8) -> bool {
        if !(1..=16).contains(&n) {
            return false;
        }
        self.change & (1 << n.saturating_sub(1)) != 0
    }

    /// Reads four octets: `ST` in the first two, `CD` in the next two, both
    /// little-endian.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?;
        Ok(Self {
            status: u16::from_le_bytes([raw[0], raw[1]]),
            change: u16::from_le_bytes([raw[2], raw[3]]),
        })
    }

    /// Appends four octets: `ST` then `CD`, both little-endian.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&self.change.to_le_bytes());
    }
}
