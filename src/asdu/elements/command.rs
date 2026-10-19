//! The command elements `SCO`, `DCO`, `RCO`, `QOC` and `QOS` of
//! IEC 60870-5-101:2003 clause 7.2.6.15–7.2.6.17, 7.2.6.26 and 7.2.6.39.
//!
//! All five are one octet. `SCO`/`DCO`/`RCO` carry a command state in the low
//! bits and a [`Qoc`] in bits 3–8:
//!
//! ```text
//! SCO := CP8{SCS,RES,QOC}   SCS bit 1 0x01, RES bit 2, QOC bits 3..8
//! DCO := CP8{DCS,QOC}       DCS UI2[1..2], QOC bits 3..8
//! RCO := CP8{RCS,QOC}       RCS UI2[1..2], QOC bits 3..8
//! QOC := CP6{QU,S/E}        QU UI5[3..7] 0x7C, S/E BS1[8] 0x80
//! QOS := CP8{QL,S/E}        QL UI7[1..7] 0x7F, S/E BS1[8] 0x80
//! ```

use super::super::AsduError;
use super::octets;

/// The two-bit command state of `DCS`, clause 7.2.6.16.
///
/// `<0> := not permitted`, `<1> := OFF`, `<2> := ON`,
/// `<3> := not permitted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DoubleCommandState {
    /// `<0>`: not permitted.
    NotPermitted,
    /// `<1>`: OFF.
    Off,
    /// `<2>`: ON.
    On,
    /// `<3>`: not permitted.
    NotPermittedAlt,
}

impl DoubleCommandState {
    /// Decodes the two bits. Bits above bit 2 are ignored.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::NotPermitted,
            1 => Self::Off,
            2 => Self::On,
            _ => Self::NotPermittedAlt,
        }
    }

    /// The two-bit value, 0..=3.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::NotPermitted => 0,
            Self::Off => 1,
            Self::On => 2,
            Self::NotPermittedAlt => 3,
        }
    }
}

/// The two-bit command state of `RCS`, clause 7.2.6.17.
///
/// `<0> := not permitted`, `<1> := next step LOWER`,
/// `<2> := next step HIGHER`, `<3> := not permitted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegulatingStepState {
    /// `<0>`: not permitted.
    NotPermitted,
    /// `<1>`: next step LOWER.
    Lower,
    /// `<2>`: next step HIGHER.
    Higher,
    /// `<3>`: not permitted.
    NotPermittedAlt,
}

impl RegulatingStepState {
    /// Decodes the two bits. Bits above bit 2 are ignored.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::NotPermitted,
            1 => Self::Lower,
            2 => Self::Higher,
            _ => Self::NotPermittedAlt,
        }
    }

    /// The two-bit value, 0..=3.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::NotPermitted => 0,
            Self::Lower => 1,
            Self::Higher => 2,
            Self::NotPermittedAlt => 3,
        }
    }
}

/// The `QU` field of the qualifier of command, clause 7.2.6.26, as its named
/// values:
///
/// ```text
/// QU := UI5[3..7]<0..31>
/// <0>      := no additional definition
/// <1>      := short pulse duration (circuit-breaker), duration
///             determined by a system parameter in the outstation
/// <2>      := long pulse duration, duration determined by a system
///             parameter in the outstation
/// <3>      := persistent output
/// <4..8>   := reserved for standard definitions of this companion standard
///             (compatible range)
/// <9..15>  := reserved for the selection of other predefined functions
/// <16..31> := reserved for special use (private range)
/// ```
///
/// Footnote 5 of the clause says `<0>` *"May be used when the attributes (for
/// example pulse duration, etc.) of the addressed control function are fixed
/// (predefined) in the controlled station and not selected by the controlling
/// station."* It is the [`Default`].
///
/// The three reserved ranges keep their number, so every `QU` value
/// round-trips through [`CommandQualifier::from_raw`] and
/// [`CommandQualifier::raw`]. [`Qoc::qu`] stays the raw number;
/// [`Qoc::new`] and [`Qoc::qualifier`] convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CommandQualifier {
    /// `<0>`: no additional definition.
    #[default]
    NoAdditionalDefinition,
    /// `<1>`: short pulse duration, the duration a system parameter in the
    /// outstation determines.
    ShortPulse,
    /// `<2>`: long pulse duration, the duration a system parameter in the
    /// outstation determines.
    LongPulse,
    /// `<3>`: persistent output.
    PersistentOutput,
    /// `<4..8>`: reserved for standard definitions (compatible range).
    Reserved(u8),
    /// `<9..15>`: reserved for the selection of other predefined functions.
    PredefinedFunction(u8),
    /// `<16..31>`: reserved for special use (private range).
    Private(u8),
}

impl CommandQualifier {
    /// The named value of a `QU` number. Only the five bits of `UI5` are
    /// read, so `raw` above 31 is taken modulo 32.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        match raw & 0x1F {
            0 => Self::NoAdditionalDefinition,
            1 => Self::ShortPulse,
            2 => Self::LongPulse,
            3 => Self::PersistentOutput,
            n @ 4..=8 => Self::Reserved(n),
            n @ 9..=15 => Self::PredefinedFunction(n),
            n => Self::Private(n),
        }
    }

    /// The `QU` number, `0..=31`. A reserved variant built with a number
    /// outside its own range is written as that number masked to five bits,
    /// which is what [`Qoc::raw`] would write for it anyway.
    #[must_use]
    pub const fn raw(self) -> u8 {
        match self {
            Self::NoAdditionalDefinition => 0,
            Self::ShortPulse => 1,
            Self::LongPulse => 2,
            Self::PersistentOutput => 3,
            Self::Reserved(n) | Self::PredefinedFunction(n) | Self::Private(n) => n & 0x1F,
        }
    }
}

/// Qualifier of command (`QOC`), clause 7.2.6.26 (six bits, in bits 3–8 of an
/// octet).
///
/// `QOC := CP6{QU, S/E}`: `QU := UI5[3..7]<0..31>` (`0x7C`) is the pulse
/// duration / predefined function, `S/E := BS1[8]<0..1>` (`0x80`) is `<0>`
/// execute and `<1>` select. The clause notes that "S/E of the qualifier of
/// command QOC is irrelevant in ASDUs with causes of transmission DEACT and
/// DEACTCON".
///
/// The two bits below it belong to the command state of the [`Sco`]/[`Dco`]/
/// [`Rco`] octet that carries this qualifier, so this type's own encoding
/// leaves them zero ([`Qoc::LEN`] is one octet because the qualifier is stored
/// in one). [`Qoc::from_raw`] drops bits 1–2, and [`Qoc::raw`] / [`Qoc::encode`]
/// write them as zero: the command-state bits of a received octet are not
/// part of `QOC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Qoc {
    /// `QU`: pulse duration or predefined function, `0..=31`.
    pub qu: u8,
    /// `S/E`: `true` selects, `false` executes.
    pub select: bool,
}

impl Qoc {
    /// Octets this qualifier is stored in.
    pub const LEN: usize = 1;

    /// A qualifier from its named `QU` value and its `S/E` bit (`true`
    /// selects, `false` executes).
    #[must_use]
    pub const fn new(qualifier: CommandQualifier, select: bool) -> Self {
        Self {
            qu: qualifier.raw(),
            select,
        }
    }

    /// The named value of [`Qoc::qu`].
    #[must_use]
    pub const fn qualifier(&self) -> CommandQualifier {
        CommandQualifier::from_raw(self.qu)
    }

    /// Decodes the octet (bits 1–2, the command state, are ignored).
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            qu: (raw & 0x7C) >> 2,
            select: raw & 0x80 != 0,
        }
    }

    /// The octet this qualifier occupies, bits 1–2 written as zero.
    ///
    /// `QU` is masked to `UI5` (`0x1F`) so a value outside `0..=31` cannot
    /// spill into the command-state bits or into `S/E`.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        ((self.qu & 0x1F) << 2) | if self.select { 0x80 } else { 0 }
    }

    /// Reads the octet that carries the qualifier.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self::from_raw(octets::<{ Self::LEN }>(buf)?[0]))
    }

    /// Appends the octet that carries the qualifier (bits 1–2 zero).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Single command (`SCO`), clause 7.2.6.15 (one octet).
///
/// `SCO := CP8{SCS,RES,QOC}`: `SCS := BS1[1]<0..1>` (`<0>` OFF, `<1>` ON),
/// `RES := BS1[2]<0>`, then the [`Qoc`] in bits 3–8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sco {
    /// `SCS`: the single command state, `<0>` OFF and `<1>` ON.
    pub scs: bool,
    /// `QOC`: the qualifier of command.
    pub qoc: Qoc,
}

impl Sco {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet. The reserved bit (`BS1[2]`) is dropped.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            scs: raw & 0x01 != 0,
            qoc: Qoc::from_raw(raw),
        }
    }

    /// The octet, reserved bit zero.
    #[must_use]
    pub fn raw(&self) -> u8 {
        u8::from(self.scs) | self.qoc.raw()
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

/// Double command (`DCO`), clause 7.2.6.16 (one octet).
///
/// `DCO := CP8{DCS,QOC}`: `DCS := UI2[1..2]<0..3>` (see
/// [`DoubleCommandState`]) then the [`Qoc`] in bits 3–8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dco {
    /// `DCS`: the double command state.
    pub dcs: DoubleCommandState,
    /// `QOC`: the qualifier of command.
    pub qoc: Qoc,
}

impl Dco {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            dcs: DoubleCommandState::from_bits(raw),
            qoc: Qoc::from_raw(raw),
        }
    }

    /// The octet.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        self.dcs.to_bits() | self.qoc.raw()
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

/// Regulating step command (`RCO`), clause 7.2.6.17 (one octet).
///
/// `RCO := CP8{RCS,QOC}`: `RCS := UI2[1..2]<0..3>` (see
/// [`RegulatingStepState`]) then the [`Qoc`] in bits 3–8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rco {
    /// `RCS`: the regulating step command state.
    pub rcs: RegulatingStepState,
    /// `QOC`: the qualifier of command.
    pub qoc: Qoc,
}

impl Rco {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            rcs: RegulatingStepState::from_bits(raw),
            qoc: Qoc::from_raw(raw),
        }
    }

    /// The octet.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        self.rcs.to_bits() | self.qoc.raw()
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

/// Qualifier of set-point command (`QOS`), clause 7.2.6.39 (one octet).
///
/// `QOS := CP8{QL, S/E}`: `QL := UI7[1..7]<0..127>` (`0x7F`), "default" for
/// `<0>` and reserved for `<1..63>`/`<64..127>`; `S/E := BS1[8]<0..1>` (`0x80`)
/// is `<0>` execute and `<1>` select.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Qos {
    /// `QL`: the qualifier of set-point command, `0..=127`.
    pub ql: u8,
    /// `S/E`: `true` selects, `false` executes.
    pub select: bool,
}

impl Qos {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            ql: raw & 0x7F,
            select: raw & 0x80 != 0,
        }
    }

    /// The octet. `QL` is masked to `UI7` so it cannot spill into `S/E`.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.ql & 0x7F) | if self.select { 0x80 } else { 0 }
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
