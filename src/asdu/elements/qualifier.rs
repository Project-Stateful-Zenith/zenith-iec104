//! The qualifier elements `COI`, `QOI`, `QCC`, `QPM`, `QPA` and `QRP` of
//! IEC 60870-5-101:2003 clause 7.2.6.21–7.2.6.25 and 7.2.6.27.
//!
//! All six are one octet and all six number their bits from the least
//! significant bit, so `QCC`'s `RQT := UI6[1..6]` is `0x3F` and its
//! `FRZ := UI2[7..8]` is `0xC0`.

use super::super::AsduError;
use super::octets;

/// Cause of initialization (`COI`), clause 7.2.6.21 (one octet).
///
/// `COI := CP8{UI7[1..7],BS1[8]}`: the cause in bits 1–7 (`0` local power
/// switch on, `1` local manual reset, `2` remote reset, `3..31` reserved for
/// this companion standard, `32..127` private) and bit 8 `<0>` "initialization
/// with unchanged local parameters" / `<1>` "initialization after change of
/// local parameters". It is carried by `M_EI_NA_1` (type 70).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coi {
    /// The 7-bit cause, `0..=127`.
    pub cause: u8,
    /// Bit 8: the local parameters changed.
    pub changed_local_parameters: bool,
}

impl Coi {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Local power switch on.
    pub const LOCAL_POWER_ON: u8 = 0;
    /// Local manual reset.
    pub const LOCAL_MANUAL_RESET: u8 = 1;
    /// Remote reset.
    pub const REMOTE_RESET: u8 = 2;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            cause: raw & 0x7F,
            changed_local_parameters: raw & 0x80 != 0,
        }
    }

    /// The octet. The cause is masked to `UI7` so it cannot spill into bit 8.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.cause & 0x7F)
            | if self.changed_local_parameters {
                0x80
            } else {
                0
            }
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

/// Qualifier of interrogation (`QOI`), clause 7.2.6.22 (one octet).
///
/// `QOI := UI8[1..8]<0..255>`: `<20>` is the global station interrogation and
/// `<21>`…`<36>` are groups 1–16. `<0>` is "not used", `<1..19>` and
/// `<37..63>` are reserved, and `<64..255>` is the private range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Qoi {
    /// The octet as the clause numbers its values.
    pub value: u8,
}

impl Qoi {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// `<20>`: station interrogation, global.
    pub const STATION_INTERROGATION: u8 = 20;
    /// `<21>`: interrogation of group 1.
    pub const GROUP_1: u8 = 21;
    /// `<36>`: interrogation of group 16.
    pub const GROUP_16: u8 = 36;

    /// The `QOI` for group `n` (`1..=16`), clamped into the standard's range.
    ///
    /// The value is `20 + n`, so group 1 is `<21>` and group 16 is `<36>`.
    /// An `n` of `0` clamps to 1; an `n` above 16 clamps to 16.
    #[must_use]
    pub fn group(n: u8) -> Self {
        Self {
            value: Self::STATION_INTERROGATION.saturating_add(n.clamp(1, 16)),
        }
    }

    /// The `QOI` for group `n`, or `None` outside `1..=16`. Use it for a group
    /// number that is not known to be in range, where clamping would
    /// interrogate a different group.
    #[must_use]
    pub fn try_group(n: u8) -> Option<Self> {
        (1..=16).contains(&n).then(|| Self::group(n))
    }

    /// The group number, `Some(1..=16)` for `<21>`…`<36>`.
    #[must_use]
    pub fn group_number(&self) -> Option<u8> {
        if (Self::GROUP_1..=Self::GROUP_16).contains(&self.value) {
            Some(self.value.saturating_sub(Self::STATION_INTERROGATION))
        } else {
            None
        }
    }

    /// Whether this is the global station interrogation `<20>`.
    #[must_use]
    pub const fn is_station_wide(&self) -> bool {
        self.value == Self::STATION_INTERROGATION
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self {
            value: octets::<{ Self::LEN }>(buf)?[0],
        })
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.value);
    }
}

/// The freeze mode of `QCC` (`FRZ`), clause 7.2.6.23 (`UI2[7..8]<0..3>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreezeMode {
    /// `<0>`: read (no freeze or reset).
    #[default]
    Read,
    /// `<1>`: counter freeze without reset (integrated total).
    FreezeWithoutReset,
    /// `<2>`: counter freeze with reset (incremental information).
    FreezeWithReset,
    /// `<3>`: counter reset.
    Reset,
}

impl FreezeMode {
    /// Decodes the two bits. Bits above bit 2 are ignored.
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::Read,
            1 => Self::FreezeWithoutReset,
            2 => Self::FreezeWithReset,
            _ => Self::Reset,
        }
    }

    /// The two-bit value, 0..=3.
    #[must_use]
    pub const fn to_bits(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::FreezeWithoutReset => 1,
            Self::FreezeWithReset => 2,
            Self::Reset => 3,
        }
    }
}

/// Qualifier of counter interrogation command (`QCC`), clause 7.2.6.23 (one
/// octet).
///
/// `QCC := CP8{RQT,FRZ}`: `RQT := UI6[1..6]<0..63>` (`0x3F`) is the request
/// (`<1>`…`<4>` counter groups 1–4, `<5>` general request counter, `<0>` "no
/// counter requested (not used)") and `FRZ := UI2[7..8]<0..3>` (`0xC0`) is the
/// [`FreezeMode`]. "The action specified by the FRZ code is applied only to the
/// group specified by the RQT code."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Qcc {
    /// `RQT`: the request, `0..=63`.
    pub rqt: u8,
    /// `FRZ`: the freeze mode.
    pub frz: FreezeMode,
}

impl Qcc {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// `<5>`: general request counter.
    pub const GENERAL_REQUEST: u8 = 5;

    /// The `RQT` for counter group `n` (`1..=4`), clamped into the range.
    ///
    /// `FRZ` is [`FreezeMode::Read`]: naming a group does not freeze it.
    /// An `n` of `0` clamps to 1; an `n` above 4 clamps to 4.
    #[must_use]
    pub fn counter_group(n: u8) -> Self {
        Self {
            rqt: n.clamp(1, 4),
            frz: FreezeMode::Read,
        }
    }

    /// The `RQT` for counter group `n`, or `None` outside `1..=4`.
    #[must_use]
    pub fn try_counter_group(n: u8) -> Option<Self> {
        (1..=4).contains(&n).then(|| Self::counter_group(n))
    }

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            rqt: raw & 0x3F,
            frz: FreezeMode::from_bits(raw >> 6),
        }
    }

    /// The octet. `RQT` is masked to `UI6` so it cannot spill into `FRZ`.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.rqt & 0x3F) | (self.frz.to_bits() << 6)
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

/// Qualifier of parameter of measured values (`QPM`), clause 7.2.6.24 (one
/// octet).
///
/// `QPM := CP8{KPA,LPC,POP}`: `KPA := UI6[1..6]<0..63>` (`0x3F`) is the kind of
/// parameter (`<1>` threshold value, `<2>` smoothing factor, `<3>` low limit
/// for transmission, `<4>` high limit, `<0>` not used, `<5..31>` reserved,
/// `<32..63>` private), `LPC := BS1[7]<0..1>` (`0x40`) is the local parameter
/// change and `POP := BS1[8]<0..1>` (`0x80`) is `<0>` in operation / `<1>` not
/// in operation. "LPC and POP are not used in this standard and set to zero."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Qpm {
    /// `KPA`: the kind of parameter, `0..=63`.
    pub kpa: u8,
    /// `LPC`: a local parameter change.
    pub local_parameter_change: bool,
    /// `POP`: `<1>` = the parameter is not in operation.
    pub parameter_not_in_operation: bool,
}

impl Qpm {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// `<1>`: threshold value.
    pub const THRESHOLD: u8 = 1;
    /// `<2>`: smoothing factor (filter time constant).
    pub const SMOOTHING_FACTOR: u8 = 2;
    /// `<3>`: low limit for transmission of measured values.
    pub const LOW_LIMIT: u8 = 3;
    /// `<4>`: high limit for transmission of measured values.
    pub const HIGH_LIMIT: u8 = 4;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            kpa: raw & 0x3F,
            local_parameter_change: raw & 0x40 != 0,
            parameter_not_in_operation: raw & 0x80 != 0,
        }
    }

    /// The octet. `KPA` is masked to `UI6` so it cannot spill into `LPC`/`POP`.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.kpa & 0x3F)
            | if self.local_parameter_change { 0x40 } else { 0 }
            | if self.parameter_not_in_operation {
                0x80
            } else {
                0
            }
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

/// Qualifier of parameter activation (`QPA`), clause 7.2.6.25 (one octet).
///
/// `QPA := UI8[1..8]<0..255>`: `<0>` not used, `<1>` act/deact of the
/// previously loaded parameters (object address = 0), `<2>` act/deact of the
/// parameter of the addressed object, `<3>` act/deact of persistent cyclic or
/// periodic transmission of the addressed object, `<4..127>` reserved,
/// `<128..255>` private. `<1>` and `<2>` are marked "not used in this companion
/// standard (reserved for extension of parameter loading functions)", and
/// act/deact itself is a cause of transmission. Carried by `P_AC_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Qpa {
    /// The octet as the clause numbers its values.
    pub value: u8,
}

impl Qpa {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// `<1>`: act/deact of the previously loaded parameters (address 0).
    pub const PREVIOUSLY_LOADED: u8 = 1;
    /// `<2>`: act/deact of the parameter of the addressed object.
    pub const ADDRESSED_OBJECT: u8 = 2;
    /// `<3>`: act/deact of persistent cyclic or periodic transmission.
    pub const PERSISTENT_CYCLIC: u8 = 3;

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self {
            value: octets::<{ Self::LEN }>(buf)?[0],
        })
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.value);
    }
}

/// Qualifier of reset process command (`QRP`), clause 7.2.6.27 (one octet).
///
/// `QRP := UI8[1..8]<0..255>`: `<0>` not used, `<1>` general reset of process,
/// `<2>` reset of pending information with time tag of the event buffer,
/// `<3..127>` reserved, `<128..255>` private. Carried by `C_RP_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Qrp {
    /// The octet as the clause numbers its values.
    pub value: u8,
}

impl Qrp {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// `<1>`: general reset of process.
    pub const GENERAL_RESET: u8 = 1;
    /// `<2>`: reset of pending information with time tag.
    pub const RESET_PENDING_INFORMATION: u8 = 2;

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        Ok(Self {
            value: octets::<{ Self::LEN }>(buf)?[0],
        })
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.value);
    }
}
