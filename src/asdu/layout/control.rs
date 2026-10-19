//! The control-direction, system and parameter ASDU types of IEC
//! 60870-5-101:2003 clauses **7.3.2**–**7.3.5**, plus the eight types IEC
//! 60870-5-104:2006 clause **8** adds.
//!
//! One struct per subsection, each carrying the elements of its definition line
//! as fields in the order that line lists them, and each implementing
//! [`AsduLayout`](super::AsduLayout) under the same contract as the monitor
//! types: `LEN` is the sum of its elements' `LEN` constants, `parse` reads one
//! information object's element octets and `encode` appends them. The data unit
//! identifier is [`super::super::Header`] and the information object address is
//! [`super::super::BodyReader`]'s; only the `CP{…}` arguments are a layout.
//!
//! # The three clause families and the 104 additions
//!
//! 7.3.2 is the process information in the **control** direction (the seven
//! command ASDUs 45–51), 7.3.3 is the single system-information ASDU
//! (`M_EI_NA_1`, type 70), 7.3.4 is the system commands (types 100–106) and
//! 7.3.5 the parameter ASDUs (types 110–113). Clause 8 of 5-104 adds the
//! time-tagged command forms 58–64, which are 5-104's own (5-101 has no such
//! type), and the time-tagged test command 107 in place of 5-101's untagged
//! 104. Both asymmetries come from 5-104's selection tables 1–6 (PDF page
//! indices 48–52); see
//! [`TypeId::is_selected_104`](super::super::TypeId::is_selected_104).
//!
//! # Every one of the 27 is a single information object
//!
//! Each clause page prints *"Single information object (SQ = 0)"* and no
//! "Number i of objects" row, and no definition line carries an `i(...)`/`j(...)`
//! form. So there is no SQ = 1 form for any control, system or parameter ASDU,
//! and `N ≥ 2` is [`LayoutError::ObjectCountNotAllowed`](super::LayoutError::ObjectCountNotAllowed):
//! every row of [`CONTROL_LAYOUTS`](super::CONTROL_LAYOUTS) is
//! [`ObjectCount::Single`](super::ObjectCount::Single). On the read side
//! `N = 0` stays clause 7.2.2's defined "ASDU contains no INFORMATION OBJECT";
//! [`encode_asdu`](super::encode_asdu) does not write one.
//!
//! # Two facts that are easy to get wrong
//!
//! * **`C_RD_NA_1` (type 102) has no element at all.** Its `LEN` is 0 and its
//!   whole payload is the information object address. Clause 7.2.5: "The
//!   read command `C_RD_NA_1` is a general exception since its information
//!   object address serves to address available information objects which
//!   are returned in the monitor direction." This is the object the body
//!   cursor's `next_object(0)` path exists for.
//! * **`C_TS_TA_1` (type 107) carries `TSC`,** the one element of this crate
//!   that 5-101 does not define (`TSC := UI16[1..16]<0..65535>`, 5-104 cl.8.8).
//!
//! # What is the project's choice, not the standard's
//!
//! * **The struct names and field names are this crate's spelling**, as in the
//!   monitor family: the standard has no identifiers for "a parsed `C_SC_NA_1`".
//! * **The layouts of the types 104 does not select are here anyway.**
//!   `C_TS_NA_1` (104) and `C_CD_NA_1` (106) are 5-101 functions that 104
//!   replaces or omits (the tables list 107 in place of 104, and 5-104 clause
//!   9.5's cause table marks the <104> and <106> rows "option not permitted").
//!   Like the unselected `CP24Time2a` monitor types, they are laid out because a
//!   real link may still see them, and refusing to describe them would not stop
//!   one.
//!
//! # Sources
//!
//! IEC 60870-5-101:2003 clauses 7.3.2–7.3.5, PDF page indices 99–113, and IEC
//! 60870-5-104:2006 clause 8, PDF page indices 76–90 (the English pages; the
//! French twin of each figure sits one index earlier). The definition lines are
//! text and extract cleanly; the ASCII field rows around them are printed
//! MSB-first and are *not* used here. Element octet counts are the clause 7.2.6
//! `LEN` constants, except `TSC`, whose citation is 5-104 clause 8.8.

use super::AsduLayout;
use crate::asdu::elements::{
    Bsi, Coi, Cp16Time2a, Cp56Time2a, Dco, Fbp, Nva, Qcc, Qoi, Qos, Qpa, Qpm, Qrp, R32, Rco, Sco,
    Sva, Tsc,
};
use crate::asdu::elements::{split_off, take};
use crate::asdu::{AsduError, TypeId};

/// `C_SC_NA_1`: Single command, 5-101 clause
/// 7.3.2.1 (PDF page index 99).
///
/// ```text
/// C_SC_NA_1 := CP{Data unit identifier,Information object address,SCO}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CScNa1 {
    /// Single command with its qualifier of command (`SCO`, 7.2.6.15).
    pub sco: Sco,
}

impl AsduLayout for CScNa1 {
    const TYPE_ID: TypeId = TypeId::CScNa1;
    const LEN: usize = Sco::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            sco: Sco::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sco.encode(out);
    }
}

/// `C_DC_NA_1`: Double command, 5-101 clause
/// 7.3.2.2 (PDF page index 100).
///
/// ```text
/// C_DC_NA_1 := CP{Data unit identifier,Information object address,DCO}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CDcNa1 {
    /// Double command (`DCO`, 7.2.6.16).
    pub dco: Dco,
}

impl AsduLayout for CDcNa1 {
    const TYPE_ID: TypeId = TypeId::CDcNa1;
    const LEN: usize = Dco::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            dco: Dco::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.dco.encode(out);
    }
}

/// `C_RC_NA_1`: Regulating step command, 5-101 clause
/// 7.3.2.3 (PDF page index 100).
///
/// ```text
/// C_RC_NA_1 := CP{Data unit identifier,Information object address,RCO}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CRcNa1 {
    /// Regulating step command (`RCO`, 7.2.6.17).
    pub rco: Rco,
}

impl AsduLayout for CRcNa1 {
    const TYPE_ID: TypeId = TypeId::CRcNa1;
    const LEN: usize = Rco::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            rco: Rco::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.rco.encode(out);
    }
}

/// `C_SE_NA_1`: Set-point command, normalized value, 5-101 clause
/// 7.3.2.4 (PDF page index 101).
///
/// ```text
/// C_SE_NA_1 := CP{Data unit identifier,Information object address,NVA,QOS}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CSeNa1 {
    /// Normalized set-point value (`NVA`, 7.2.6.6).
    pub nva: Nva,
    /// Qualifier of set-point command, carrying the `S/E` bit (`QOS`, 7.2.6.39).
    pub qos: Qos,
}

impl AsduLayout for CSeNa1 {
    const TYPE_ID: TypeId = TypeId::CSeNa1;
    const LEN: usize = Nva::LEN + Qos::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nva: Nva::parse(split_off(&mut element, Nva::LEN)?)?,
            qos: Qos::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nva.encode(out);
        self.qos.encode(out);
    }
}

/// `C_SE_NB_1`: Set-point command, scaled value, 5-101 clause
/// 7.3.2.5 (PDF page index 102).
///
/// ```text
/// C_SE_NB_1 := CP{Data unit identifier,Information object address,SVA,QOS}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CSeNb1 {
    /// Scaled set-point value (`SVA`, 7.2.6.7).
    pub sva: Sva,
    /// Qualifier of set-point command, carrying the `S/E` bit (`QOS`, 7.2.6.39).
    pub qos: Qos,
}

impl AsduLayout for CSeNb1 {
    const TYPE_ID: TypeId = TypeId::CSeNb1;
    const LEN: usize = Sva::LEN + Qos::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sva: Sva::parse(split_off(&mut element, Sva::LEN)?)?,
            qos: Qos::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sva.encode(out);
        self.qos.encode(out);
    }
}

/// `C_SE_NC_1`: Set-point command, short floating point number, 5-101 clause
/// 7.3.2.6 (PDF page index 102).
///
/// ```text
/// C_SE_NC_1 := CP{Data unit identifier,Information object address,IEEE STD 754,QOS}
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CSeNc1 {
    /// Short floating point number, IEEE STD 754 (`R32`, 7.2.6.8).
    pub r32: R32,
    /// Qualifier of set-point command, carrying the `S/E` bit (`QOS`, 7.2.6.39).
    pub qos: Qos,
}

impl AsduLayout for CSeNc1 {
    const TYPE_ID: TypeId = TypeId::CSeNc1;
    const LEN: usize = R32::LEN + Qos::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            r32: R32::parse(split_off(&mut element, R32::LEN)?)?,
            qos: Qos::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.r32.encode(out);
        self.qos.encode(out);
    }
}

/// `C_BO_NA_1`: Bitstring of 32 bit, 5-101 clause
/// 7.3.2.7 (PDF page index 103).
///
/// ```text
/// C_BO_NA_1 := CP{Data unit identifier,Information object address,BSI}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CBoNa1 {
    /// Binary state information, 32 bit (`BSI`, 7.2.6.13).
    pub bsi: Bsi,
}

impl AsduLayout for CBoNa1 {
    const TYPE_ID: TypeId = TypeId::CBoNa1;
    const LEN: usize = Bsi::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            bsi: Bsi::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.bsi.encode(out);
    }
}

/// `C_SC_TA_1`: Single command with time tag `CP56Time2a`, 5-104 clause
/// 8.1 (PDF page index 76).
///
/// ```text
/// C_SC_TA_1 := CP{Data unit identifier,Information object address,SCO,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CScTa1 {
    /// Single command with its qualifier of command (`SCO`, 7.2.6.15).
    pub sco: Sco,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CScTa1 {
    const TYPE_ID: TypeId = TypeId::CScTa1;
    const LEN: usize = Sco::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sco: Sco::parse(split_off(&mut element, Sco::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sco.encode(out);
        self.time.encode(out);
    }
}

/// `C_DC_TA_1`: Double command with time tag `CP56Time2a`, 5-104 clause
/// 8.2 (PDF page index 78).
///
/// ```text
/// C_DC_TA_1 := CP{Data unit identifier,Information object address,DCO,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CDcTa1 {
    /// Double command (`DCO`, 7.2.6.16).
    pub dco: Dco,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CDcTa1 {
    const TYPE_ID: TypeId = TypeId::CDcTa1;
    const LEN: usize = Dco::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            dco: Dco::parse(split_off(&mut element, Dco::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.dco.encode(out);
        self.time.encode(out);
    }
}

/// `C_RC_TA_1`: Regulating step command with time tag `CP56Time2a`, 5-104 clause
/// 8.3 (PDF page index 80).
///
/// ```text
/// C_RC_TA_1 := CP{Data unit identifier,Information object address,RCO,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CRcTa1 {
    /// Regulating step command (`RCO`, 7.2.6.17).
    pub rco: Rco,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CRcTa1 {
    const TYPE_ID: TypeId = TypeId::CRcTa1;
    const LEN: usize = Rco::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            rco: Rco::parse(split_off(&mut element, Rco::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.rco.encode(out);
        self.time.encode(out);
    }
}

/// `C_SE_TA_1`: Set-point command with time tag `CP56Time2a`, normalized value, 5-104 clause
/// 8.4 (PDF page index 82).
///
/// ```text
/// C_SE_TA_1 := CP{Data unit identifier,Information object address,NVA,QOS,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CSeTa1 {
    /// Normalized set-point value (`NVA`, 7.2.6.6).
    pub nva: Nva,
    /// Qualifier of set-point command, carrying the `S/E` bit (`QOS`, 7.2.6.39).
    pub qos: Qos,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CSeTa1 {
    const TYPE_ID: TypeId = TypeId::CSeTa1;
    const LEN: usize = Nva::LEN + Qos::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nva: Nva::parse(split_off(&mut element, Nva::LEN)?)?,
            qos: Qos::parse(split_off(&mut element, Qos::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nva.encode(out);
        self.qos.encode(out);
        self.time.encode(out);
    }
}

/// `C_SE_TB_1`: Set-point command with time tag `CP56Time2a`, scaled value, 5-104 clause
/// 8.5 (PDF page index 84).
///
/// ```text
/// C_SE_TB_1 := CP{Data unit identifier,Information object address,SVA,QOS,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CSeTb1 {
    /// Scaled set-point value (`SVA`, 7.2.6.7).
    pub sva: Sva,
    /// Qualifier of set-point command, carrying the `S/E` bit (`QOS`, 7.2.6.39).
    pub qos: Qos,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CSeTb1 {
    const TYPE_ID: TypeId = TypeId::CSeTb1;
    const LEN: usize = Sva::LEN + Qos::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sva: Sva::parse(split_off(&mut element, Sva::LEN)?)?,
            qos: Qos::parse(split_off(&mut element, Qos::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sva.encode(out);
        self.qos.encode(out);
        self.time.encode(out);
    }
}

/// `C_SE_TC_1`: Set-point command with time tag `CP56Time2a`, short floating point number, 5-104 clause
/// 8.6 (PDF page index 86).
///
/// ```text
/// C_SE_TC_1 := CP{Data unit identifier,Information object address,IEEE STD 754,QOS,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CSeTc1 {
    /// Short floating point number, IEEE STD 754 (`R32`, 7.2.6.8).
    pub r32: R32,
    /// Qualifier of set-point command, carrying the `S/E` bit (`QOS`, 7.2.6.39).
    pub qos: Qos,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CSeTc1 {
    const TYPE_ID: TypeId = TypeId::CSeTc1;
    const LEN: usize = R32::LEN + Qos::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            r32: R32::parse(split_off(&mut element, R32::LEN)?)?,
            qos: Qos::parse(split_off(&mut element, Qos::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.r32.encode(out);
        self.qos.encode(out);
        self.time.encode(out);
    }
}

/// `C_BO_TA_1`: Bitstring of 32 bit with time tag `CP56Time2a`, 5-104 clause
/// 8.7 (PDF page index 88).
///
/// ```text
/// C_BO_TA_1 := CP{Data unit identifier,Information object address,BSI,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CBoTa1 {
    /// Binary state information, 32 bit (`BSI`, 7.2.6.13).
    pub bsi: Bsi,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CBoTa1 {
    const TYPE_ID: TypeId = TypeId::CBoTa1;
    const LEN: usize = Bsi::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            bsi: Bsi::parse(split_off(&mut element, Bsi::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.bsi.encode(out);
        self.time.encode(out);
    }
}

/// `M_EI_NA_1`: End of initialization, 5-101 clause
/// 7.3.3.1 (PDF page index 104).
///
/// ```text
/// M_EI_NA_1 := CP{Data unit identifier,Information object address,COI}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MEiNa1 {
    /// Cause of initialization (`COI`, 7.2.6.21).
    pub coi: Coi,
}

impl AsduLayout for MEiNa1 {
    const TYPE_ID: TypeId = TypeId::MEiNa1;
    const LEN: usize = Coi::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            coi: Coi::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.coi.encode(out);
    }
}

/// `C_IC_NA_1`: Interrogation command, 5-101 clause
/// 7.3.4.1 (PDF page index 105).
///
/// ```text
/// C_IC_NA_1 := CP{Data unit identifier,Information object address,QOI}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CIcNa1 {
    /// Qualifier of interrogation (`QOI`, 7.2.6.22).
    pub qoi: Qoi,
}

impl AsduLayout for CIcNa1 {
    const TYPE_ID: TypeId = TypeId::CIcNa1;
    const LEN: usize = Qoi::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            qoi: Qoi::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.qoi.encode(out);
    }
}

/// `C_CI_NA_1`: Counter interrogation command, 5-101 clause
/// 7.3.4.2 (PDF page index 106).
///
/// ```text
/// C_CI_NA_1 := CP{Data unit identifier,Information object address,QCC}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CCiNa1 {
    /// Qualifier of counter interrogation (`QCC`, 7.2.6.23).
    pub qcc: Qcc,
}

impl AsduLayout for CCiNa1 {
    const TYPE_ID: TypeId = TypeId::CCiNa1;
    const LEN: usize = Qcc::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            qcc: Qcc::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.qcc.encode(out);
    }
}

/// `C_RD_NA_1`: Read command, 5-101 clause
/// 7.3.4.3 (PDF page index 106).
///
/// ```text
/// C_RD_NA_1 := CP{Data unit identifier,Information object address}
/// ```
///
/// The type's whole payload is its information object address, which clause
/// 7.2.5 describes as the exception: "The read command `C_RD_NA_1` is a general
/// exception since its information object address serves to address available
/// information objects which are returned in the monitor direction."
/// `LEN` is therefore 0 and the element part of the object is empty, which is
/// what `BodyReader::next_object(0)` yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CRdNa1;

impl AsduLayout for CRdNa1 {
    const TYPE_ID: TypeId = TypeId::CRdNa1;
    const LEN: usize = 0;

    fn parse(_element: &[u8]) -> Result<Self, AsduError> {
        Ok(Self)
    }

    fn encode(&self, _out: &mut Vec<u8>) {}
}

/// `C_CS_NA_1`: Clock synchronization command, 5-101 clause
/// 7.3.4.4 (PDF page index 107).
///
/// ```text
/// C_CS_NA_1 := CP{Data unit identifier,Information object address,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CCsNa1 {
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CCsNa1 {
    const TYPE_ID: TypeId = TypeId::CCsNa1;
    const LEN: usize = Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.time.encode(out);
    }
}

/// `C_TS_NA_1`: Test command, 5-101 clause
/// 7.3.4.5 (PDF page index 108).
///
/// ```text
/// C_TS_NA_1 := CP{Data unit identifier,Information object address,FBP}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CTsNa1 {
    /// The fixed test bit pattern `UI16[1..16]<55AAH>` (`FBP`, 7.2.6.14).
    pub fbp: Fbp,
}

impl AsduLayout for CTsNa1 {
    const TYPE_ID: TypeId = TypeId::CTsNa1;
    const LEN: usize = Fbp::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            fbp: Fbp::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.fbp.encode(out);
    }
}

/// `C_RP_NA_1`: Reset process command, 5-101 clause
/// 7.3.4.6 (PDF page index 108).
///
/// ```text
/// C_RP_NA_1 := CP{Data unit identifier,Information object address,QRP}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CRpNa1 {
    /// Qualifier of reset process command (`QRP`, 7.2.6.27).
    pub qrp: Qrp,
}

impl AsduLayout for CRpNa1 {
    const TYPE_ID: TypeId = TypeId::CRpNa1;
    const LEN: usize = Qrp::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            qrp: Qrp::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.qrp.encode(out);
    }
}

/// `C_CD_NA_1`: Delay acquisition command, 5-101 clause
/// 7.3.4.7 (PDF page index 109).
///
/// ```text
/// C_CD_NA_1 := CP{Data unit identifier,Information object address,CP16Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CCdNa1 {
    /// Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).
    pub elapsed: Cp16Time2a,
}

impl AsduLayout for CCdNa1 {
    const TYPE_ID: TypeId = TypeId::CCdNa1;
    const LEN: usize = Cp16Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            elapsed: Cp16Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.elapsed.encode(out);
    }
}

/// `C_TS_TA_1`: Test command with time tag `CP56Time2a`, 5-104 clause
/// 8.8 (PDF page index 90).
///
/// ```text
/// C_TS_TA_1 := CP{Data unit identifier,Information object address,TSC,CP56Time2a}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CTsTa1 {
    /// Test sequence counter, `UI16[1..16]<0..65535>` (`TSC`, 5-104 clause 8.8).
    pub tsc: Tsc,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for CTsTa1 {
    const TYPE_ID: TypeId = TypeId::CTsTa1;
    const LEN: usize = Tsc::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            tsc: Tsc::parse(split_off(&mut element, Tsc::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.tsc.encode(out);
        self.time.encode(out);
    }
}

/// `P_ME_NA_1`: Parameter of measured values, normalized value, 5-101 clause
/// 7.3.5.1 (PDF page index 110).
///
/// ```text
/// P_ME_NA_1 := CP{Data unit identifier,Information object address,NVA,QPM}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PMeNa1 {
    /// Normalized set-point value (`NVA`, 7.2.6.6).
    pub nva: Nva,
    /// Qualifier of parameter of measured values (`QPM`, 7.2.6.24).
    pub qpm: Qpm,
}

impl AsduLayout for PMeNa1 {
    const TYPE_ID: TypeId = TypeId::PMeNa1;
    const LEN: usize = Nva::LEN + Qpm::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nva: Nva::parse(split_off(&mut element, Nva::LEN)?)?,
            qpm: Qpm::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nva.encode(out);
        self.qpm.encode(out);
    }
}

/// `P_ME_NB_1`: Parameter of measured values, scaled value, 5-101 clause
/// 7.3.5.2 (PDF page index 111).
///
/// ```text
/// P_ME_NB_1 := CP{Data unit identifier,Information object address,SVA,QPM}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PMeNb1 {
    /// Scaled set-point value (`SVA`, 7.2.6.7).
    pub sva: Sva,
    /// Qualifier of parameter of measured values (`QPM`, 7.2.6.24).
    pub qpm: Qpm,
}

impl AsduLayout for PMeNb1 {
    const TYPE_ID: TypeId = TypeId::PMeNb1;
    const LEN: usize = Sva::LEN + Qpm::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sva: Sva::parse(split_off(&mut element, Sva::LEN)?)?,
            qpm: Qpm::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sva.encode(out);
        self.qpm.encode(out);
    }
}

/// `P_ME_NC_1`: Parameter of measured values, short floating point number, 5-101 clause
/// 7.3.5.3 (PDF page index 112).
///
/// ```text
/// P_ME_NC_1 := CP{Data unit identifier,Information object address,IEEE STD 754,QPM}
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PMeNc1 {
    /// Short floating point number, IEEE STD 754 (`R32`, 7.2.6.8).
    pub r32: R32,
    /// Qualifier of parameter of measured values (`QPM`, 7.2.6.24).
    pub qpm: Qpm,
}

impl AsduLayout for PMeNc1 {
    const TYPE_ID: TypeId = TypeId::PMeNc1;
    const LEN: usize = R32::LEN + Qpm::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            r32: R32::parse(split_off(&mut element, R32::LEN)?)?,
            qpm: Qpm::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.r32.encode(out);
        self.qpm.encode(out);
    }
}

/// `P_AC_NA_1`: Parameter activation, 5-101 clause
/// 7.3.5.4 (PDF page index 113).
///
/// ```text
/// P_AC_NA_1 := CP{Data unit identifier,Information object address,QPA}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PAcNa1 {
    /// Qualifier of parameter activation (`QPA`, 7.2.6.25).
    pub qpa: Qpa,
}

impl AsduLayout for PAcNa1 {
    const TYPE_ID: TypeId = TypeId::PAcNa1;
    const LEN: usize = Qpa::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            qpa: Qpa::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.qpa.encode(out);
    }
}
