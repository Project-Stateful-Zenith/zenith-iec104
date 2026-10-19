//! The file-transfer elements `FRQ`, `SRQ`, `SCQ`, `LSQ`, `AFQ`, `NOF`,
//! `NOS`, `LOF`, `LOS`, `CHS` and `SOF` of IEC 60870-5-101:2003 clause
//! 7.2.6.28–7.2.6.38.
//!
//! All eleven number their bits from the least significant bit, and the
//! multi-octet ones are little-endian (`NOF` a `UI16`, `LOF` a `UI24`).

use super::super::AsduError;
use super::octets;

/// File ready qualifier (`FRQ`), clause 7.2.6.28 (one octet).
///
/// `FRQ := CP8{UI7[1..7],BS1[8]}`: the 7-bit value in bits 1–7 (`<0>` default,
/// `<1..63>` reserved for this companion standard, `<64..127>` private) and
/// bit 8 `<0>` positive confirm / `<1>` negative confirm of select, request,
/// deactivate or delete. Carried by `F_FR_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Frq {
    /// The 7-bit value, `0..=127`.
    pub value: u8,
    /// Bit 8: negative confirm.
    pub negative_confirm: bool,
}

impl Frq {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            value: raw & 0x7F,
            negative_confirm: raw & 0x80 != 0,
        }
    }

    /// The octet.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.value & 0x7F) | if self.negative_confirm { 0x80 } else { 0 }
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self::from_raw(raw))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Section ready qualifier (`SRQ`), clause 7.2.6.29 (one octet).
///
/// `SRQ := CP8{UI7[1..7],BS1[8]}`: the 7-bit value in bits 1–7 and bit 8
/// `<0>` "section ready to load" / `<1>` "section not ready to load". Carried
/// by `F_SR_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Srq {
    /// The 7-bit value, `0..=127`.
    pub value: u8,
    /// Bit 8: the section is not ready to load.
    pub not_ready: bool,
}

impl Srq {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            value: raw & 0x7F,
            not_ready: raw & 0x80 != 0,
        }
    }

    /// The octet.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.value & 0x7F) | if self.not_ready { 0x80 } else { 0 }
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self::from_raw(raw))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Select and call qualifier (`SCQ`), clause 7.2.6.30 (one octet).
///
/// `SCQ := CP8{UI4[1..4],UI4[5..8]}`: the action in bits 1–4 (`<1>` select
/// file, `<2>` request file, `<3>` deactivate file, `<4>` delete file,
/// `<5>` select section, `<6>` request section, `<7>` deactivate section,
/// `<0>` default) and the error code in bits 5–8 (`<1>` requested memory space
/// not available, `<2>` checksum failed, `<3>` unexpected communication
/// service, `<4>` unexpected name of file, `<5>` unexpected name of section,
/// `<0>` default). Carried by `F_SC_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Scq {
    /// The action, bits 1–4.
    pub action: u8,
    /// The error code, bits 5–8.
    pub error: u8,
}

impl Scq {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// `<1>`: select file.
    pub const SELECT_FILE: u8 = 1;
    /// `<2>`: request file.
    pub const REQUEST_FILE: u8 = 2;
    /// `<3>`: deactivate file.
    pub const DEACTIVATE_FILE: u8 = 3;
    /// `<4>`: delete file.
    pub const DELETE_FILE: u8 = 4;
    /// `<5>`: select section.
    pub const SELECT_SECTION: u8 = 5;
    /// `<6>`: request section.
    pub const REQUEST_SECTION: u8 = 6;
    /// `<7>`: deactivate section.
    pub const DEACTIVATE_SECTION: u8 = 7;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            action: raw & 0x0F,
            error: raw >> 4,
        }
    }

    /// The octet.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.action & 0x0F) | ((self.error & 0x0F) << 4)
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self::from_raw(raw))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Last section or segment qualifier (`LSQ`), clause 7.2.6.31 (one octet).
///
/// `LSQ := UI8[1..8]<0..255>`: `<1>` file transfer without deactivation,
/// `<2>` file transfer with deactivation, `<3>` section transfer without
/// deactivation, `<4>` section transfer with deactivation, `<0>` not used.
/// Carried by `F_LS_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lsq {
    /// The octet as the clause numbers its values.
    pub value: u8,
}

impl Lsq {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// `<1>`: file transfer without deactivation.
    pub const FILE_WITHOUT_DEACTIVATION: u8 = 1;
    /// `<2>`: file transfer with deactivation.
    pub const FILE_WITH_DEACTIVATION: u8 = 2;
    /// `<3>`: section transfer without deactivation.
    pub const SECTION_WITHOUT_DEACTIVATION: u8 = 3;
    /// `<4>`: section transfer with deactivation.
    pub const SECTION_WITH_DEACTIVATION: u8 = 4;

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let value = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self { value })
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.value);
    }
}

/// Acknowledge file or section qualifier (`AFQ`), clause 7.2.6.32 (one octet).
///
/// `AFQ := CP8{UI4[1..4],UI4[5..8]}`: the acknowledgement in bits 1–4 (`<1>`
/// positive acknowledge of file transfer, `<2>` negative acknowledge of file
/// transfer, `<3>` positive acknowledge of section transfer, `<4>` negative
/// acknowledge of section transfer, `<0>` not used) and the error code in bits
/// 5–8 as in [`Scq`]. Carried by `F_AF_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Afq {
    /// The acknowledgement, bits 1–4.
    pub action: u8,
    /// The error code, bits 5–8.
    pub error: u8,
}

impl Afq {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// `<1>`: positive acknowledge of file transfer.
    pub const FILE_POSITIVE: u8 = 1;
    /// `<2>`: negative acknowledge of file transfer.
    pub const FILE_NEGATIVE: u8 = 2;
    /// `<3>`: positive acknowledge of section transfer.
    pub const SECTION_POSITIVE: u8 = 3;
    /// `<4>`: negative acknowledge of section transfer.
    pub const SECTION_NEGATIVE: u8 = 4;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            action: raw & 0x0F,
            error: raw >> 4,
        }
    }

    /// The octet.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.action & 0x0F) | ((self.error & 0x0F) << 4)
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self::from_raw(raw))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}

/// Name of file (`NOF`), clause 7.2.6.33 (two octets).
///
/// `NOF := UI16[1..16]<0..65535>`, little-endian: `<0>` default, else the name
/// of the file. Carried by every file-transfer ASDU, `F_FR_NA_1` to
/// `F_SC_NB_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Nof {
    /// The file name number.
    pub value: u16,
}

impl Nof {
    /// Octets on the wire.
    pub const LEN: usize = 2;

    /// Reads two octets, little-endian.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let octets = octets::<{ Self::LEN }>(buf)?;
        Ok(Self {
            value: u16::from_le_bytes([octets[0], octets[1]]),
        })
    }

    /// Appends two octets, little-endian.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes());
    }
}

/// Name of section (`NOS`), clause 7.2.6.34 (one octet).
///
/// `NOS := UI8[1..8]<0..255>`: `<0>` default, else the name of the section.
/// Carried by `F_SR_NA_1`, `F_SC_NA_1`, `F_LS_NA_1`, `F_AF_NA_1` and
/// `F_SG_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Nos {
    /// The section name number.
    pub value: u8,
}

impl Nos {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let value = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self { value })
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.value);
    }
}

/// Length of file or section (`LOF`), clause 7.2.6.35 (three octets).
///
/// `LOF := UI24[1..24]<0..16777215>`, little-endian: `<0>` not used, else the
/// number of octets of the complete file or section. The same `UI24` width and
/// order as a three-octet information object address. Carried by
/// `F_FR_NA_1`, `F_SR_NA_1` and `F_DR_TA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Lof {
    /// The length in octets.
    pub value: u32,
}

impl Lof {
    /// Octets on the wire.
    pub const LEN: usize = 3;

    /// Largest representable length, `16777215` (`UI24`).
    pub const MAX: u32 = 0x00FF_FFFF;

    /// Reads three octets, little-endian.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let octets = octets::<{ Self::LEN }>(buf)?;
        Ok(Self {
            value: u32::from_le_bytes([octets[0], octets[1], octets[2], 0]),
        })
    }

    /// Appends three octets, little-endian. A value above [`Lof::MAX`] is
    /// truncated to its low three octets, as the field is what it is; callers
    /// holding such a value should check before encoding.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.value.to_le_bytes()[..Self::LEN]);
    }
}

/// Length of segment (`LOS`), clause 7.2.6.36 (one octet).
///
/// `LOS := UI8[1..8]<0..255>`: the number of octets of the segment, whose
/// maximum "ranges between 234 (maximum length of link field, DATA UNIT
/// IDENTIFIER AND INFORMATION OBJECT ADDRESSes) and 240 (minimum length of link
/// field, DATA UNIT IDENTIFIER AND INFORMATION OBJECT ADDRESSes)". That range
/// is 5-101's; under 5-104 the bound is the 249-octet ASDU less the header, the
/// IOA, `NOF`, `NOS` and `LOS`, which is
/// [`MAX_SEGMENT`](crate::asdu::MAX_SEGMENT) (236) for the conventional
/// profile. Carried by `F_SG_NA_1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Los {
    /// The segment length in octets.
    pub value: u8,
}

impl Los {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// The upper end of clause 7.2.6.36's range for a segment (5-101, minimum
    /// link field). Larger than a 5-104 ASDU can carry: see
    /// [`MAX_SEGMENT`](crate::asdu::MAX_SEGMENT).
    pub const MAX: u8 = 240;

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let value = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self { value })
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.value);
    }
}

/// Checksum (`CHS`), clause 7.2.6.37 (one octet).
///
/// `CHS := UI8[1..8]<0..255>`: "arithmetic sum disregarding overflows (sum
/// modulo 256) over all octets of a section (when used in a last segment PDU)
/// or of a complete file (when used in a last section PDU)". The summation
/// itself is the file-transfer procedure's job, not this codec's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Chs {
    /// The checksum octet.
    pub value: u8,
}

impl Chs {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let value = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self { value })
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.value);
    }
}

/// Status of file (`SOF`), clause 7.2.6.38 (one octet).
///
/// `SOF := CP8{STATUS,LFD,FOR,FA}`: `STATUS := UI5[1..5]<0..32>` (`0x1F`,
/// `<0>` default, `<1..15>` reserved, `<16..32>` private), `LFD := BS1[6]`
/// (`0x20`): `<0>` "additional file of the directory follows" / `<1>` "last
/// file of the directory"; `FOR := BS1[7]` (`0x40`): `<0>` "name defines file"
/// / `<1>` "name defines subdirectory"; `FA := BS1[8]` (`0x80`): `<0>` "file
/// waits for transfer" / `<1>` "transfer of this file is active". Carried by
/// `F_DR_TA_1` (the directory).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Sof {
    /// `STATUS`: the file status, `0..=31`.
    pub status: u8,
    /// `LFD`: this is the last file of the directory.
    pub last_file_of_directory: bool,
    /// `FOR`: the name defines a subdirectory.
    pub name_defines_subdirectory: bool,
    /// `FA`: the transfer of this file is active.
    pub transfer_active: bool,
}

impl Sof {
    /// Octets on the wire.
    pub const LEN: usize = 1;

    /// Decodes the octet.
    #[must_use]
    pub const fn from_raw(raw: u8) -> Self {
        Self {
            status: raw & 0x1F,
            last_file_of_directory: raw & 0x20 != 0,
            name_defines_subdirectory: raw & 0x40 != 0,
            transfer_active: raw & 0x80 != 0,
        }
    }

    /// The octet.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        (self.status & 0x1F)
            | if self.last_file_of_directory { 0x20 } else { 0 }
            | if self.name_defines_subdirectory {
                0x40
            } else {
                0
            }
            | if self.transfer_active { 0x80 } else { 0 }
    }

    /// Reads one octet.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?[0];
        Ok(Self::from_raw(raw))
    }

    /// Appends one octet.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.raw());
    }
}
