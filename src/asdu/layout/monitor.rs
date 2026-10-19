//! The 32 monitor-direction ASDU types of IEC 60870-5-101:2003 clause 7.3.1.
//!
//! One struct per subsection, in the document's own order (`7.3.1.1` …
//! `7.3.1.32`), each carrying the elements of its definition line as fields in
//! the order that line lists them. Every struct implements
//! [`AsduLayout`](super::AsduLayout): `LEN` is the sum of its elements'
//! clause 7.2.6 `LEN` constants, `parse` reads one information object's element
//! octets and `encode` appends them.
//!
//! The definition line in each doc comment is the clause's own, copied from the
//! PDF page index named beside it, with the `i(...)`/`j(...)` part being the
//! struct's fields in order. The addressing of the objects is
//! [`BodyReader`](super::super::BodyReader)'s, and what an element *is* belongs
//! to clause 7.2.6 and [`super::super::elements`].
//!
//! Clause 7.3.1's two addressing rules are quoted on the types and enforced
//! through the rows of [`MONITOR_LAYOUTS`](super::MONITOR_LAYOUTS): the ten
//! untagged types have a `j(...)` form and may be sent as a sequence, every
//! time-tagged type states that it cannot, and four types (18, 19, 39, 40) are
//! one information object by construction.

use super::AsduLayout;
use crate::asdu::elements::{
    Bcr, Bsi, Cp16Time2a, Cp24Time2a, Cp56Time2a, Diq, Nva, Oci, Qdp, Qds, R32, Scd, Sep, Siq, Spe,
    Sva, Vti,
};
use crate::asdu::elements::{split_off, take};
use crate::asdu::{AsduError, TypeId};

/// `M_SP_NA_1`: Single-point information without time tag, 5-101 clause
/// 7.3.1.1 (PDF page index 60).
///
/// ```text
/// M_SP_NA_1 := CP{Data unit identifier,i(Information object address,SIQ)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MSpNa1 {
    /// Single-point information with quality descriptor (`SIQ`, 7.2.6.1).
    pub siq: Siq,
}

impl AsduLayout for MSpNa1 {
    const TYPE_ID: TypeId = TypeId::MSpNa1;
    const LEN: usize = Siq::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            siq: Siq::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.siq.encode(out);
    }
}

/// `M_SP_TA_1`: Single-point information with time tag, 5-101 clause
/// 7.3.1.2 (PDF page index 62).
///
/// ```text
/// M_SP_TA_1 := CP{Data unit identifier,i(Information object address,SIQ,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each single-point information
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MSpTa1 {
    /// Single-point information with quality descriptor (`SIQ`, 7.2.6.1).
    pub siq: Siq,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MSpTa1 {
    const TYPE_ID: TypeId = TypeId::MSpTa1;
    const LEN: usize = Siq::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            siq: Siq::parse(split_off(&mut element, Siq::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.siq.encode(out);
        self.time.encode(out);
    }
}

/// `M_DP_NA_1`: Double-point information without time tag, 5-101 clause
/// 7.3.1.3 (PDF page index 63).
///
/// ```text
/// M_DP_NA_1 := CP{Data unit identifier,i(Information object address,DIQ)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MDpNa1 {
    /// Double-point information with quality descriptor (`DIQ`, 7.2.6.2).
    pub diq: Diq,
}

impl AsduLayout for MDpNa1 {
    const TYPE_ID: TypeId = TypeId::MDpNa1;
    const LEN: usize = Diq::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            diq: Diq::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.diq.encode(out);
    }
}

/// `M_DP_TA_1`: Double-point information with time tag, 5-101 clause
/// 7.3.1.4 (PDF page index 64).
///
/// ```text
/// M_DP_TA_1 := CP{Data unit identifier,i(Information object address,DIQ,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each double-point information
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MDpTa1 {
    /// Double-point information with quality descriptor (`DIQ`, 7.2.6.2).
    pub diq: Diq,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MDpTa1 {
    const TYPE_ID: TypeId = TypeId::MDpTa1;
    const LEN: usize = Diq::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            diq: Diq::parse(split_off(&mut element, Diq::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.diq.encode(out);
        self.time.encode(out);
    }
}

/// `M_ST_NA_1`: Step position information, 5-101 clause
/// 7.3.1.5 (PDF page index 65).
///
/// ```text
/// M_ST_NA_1 := CP{Data unit identifier,i(Information object address,VTI,QDS)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MStNa1 {
    /// Value with transient state indication (`VTI`, 7.2.6.5).
    pub vti: Vti,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
}

impl AsduLayout for MStNa1 {
    const TYPE_ID: TypeId = TypeId::MStNa1;
    const LEN: usize = Vti::LEN + Qds::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            vti: Vti::parse(split_off(&mut element, Vti::LEN)?)?,
            qds: Qds::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.vti.encode(out);
        self.qds.encode(out);
    }
}

/// `M_ST_TA_1`: Step position information with time tag, 5-101 clause
/// 7.3.1.6 (PDF page index 66).
///
/// ```text
/// M_ST_TA_1 := CP{Data unit identifier,i(Information object address,VTI,QDS,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each step position information
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MStTa1 {
    /// Value with transient state indication (`VTI`, 7.2.6.5).
    pub vti: Vti,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MStTa1 {
    const TYPE_ID: TypeId = TypeId::MStTa1;
    const LEN: usize = Vti::LEN + Qds::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            vti: Vti::parse(split_off(&mut element, Vti::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.vti.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_BO_NA_1`: Bitstring of 32 bit, 5-101 clause
/// 7.3.1.7 (PDF page index 67).
///
/// ```text
/// M_BO_NA_1 := CP{Data unit identifier,i(Information object address,BSI,QDS)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MBoNa1 {
    /// Binary state information, 32 bit (`BSI`, 7.2.6.13).
    pub bsi: Bsi,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
}

impl AsduLayout for MBoNa1 {
    const TYPE_ID: TypeId = TypeId::MBoNa1;
    const LEN: usize = Bsi::LEN + Qds::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            bsi: Bsi::parse(split_off(&mut element, Bsi::LEN)?)?,
            qds: Qds::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.bsi.encode(out);
        self.qds.encode(out);
    }
}

/// `M_BO_TA_1`: Bitstring of 32 bit with time tag, 5-101 clause
/// 7.3.1.8 (PDF page index 69).
///
/// ```text
/// M_BO_TA_1 := CP{Data unit identifier,i(Information object address,BSI,QDS,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each bitstring
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MBoTa1 {
    /// Binary state information, 32 bit (`BSI`, 7.2.6.13).
    pub bsi: Bsi,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MBoTa1 {
    const TYPE_ID: TypeId = TypeId::MBoTa1;
    const LEN: usize = Bsi::LEN + Qds::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            bsi: Bsi::parse(split_off(&mut element, Bsi::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.bsi.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_ME_NA_1`: Measured value, normalized value, 5-101 clause
/// 7.3.1.9 (PDF page index 70).
///
/// ```text
/// M_ME_NA_1 := CP{Data unit identifier,i(Information object address,NVA,QDS)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MMeNa1 {
    /// Normalized value (`NVA`, 7.2.6.6).
    pub nva: Nva,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
}

impl AsduLayout for MMeNa1 {
    const TYPE_ID: TypeId = TypeId::MMeNa1;
    const LEN: usize = Nva::LEN + Qds::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nva: Nva::parse(split_off(&mut element, Nva::LEN)?)?,
            qds: Qds::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nva.encode(out);
        self.qds.encode(out);
    }
}

/// `M_ME_TA_1`: Measured value, normalized value with time tag, 5-101 clause
/// 7.3.1.10 (PDF page index 71).
///
/// ```text
/// M_ME_TA_1 := CP{Data unit identifier,i(Information object address,NVA,QDS,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each measured value
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MMeTa1 {
    /// Normalized value (`NVA`, 7.2.6.6).
    pub nva: Nva,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MMeTa1 {
    const TYPE_ID: TypeId = TypeId::MMeTa1;
    const LEN: usize = Nva::LEN + Qds::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nva: Nva::parse(split_off(&mut element, Nva::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nva.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_ME_NB_1`: Measured value, scaled value, 5-101 clause
/// 7.3.1.11 (PDF page index 72).
///
/// ```text
/// M_ME_NB_1 := CP{Data unit identifier,i(Information object address,SVA,QDS)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MMeNb1 {
    /// Scaled value (`SVA`, 7.2.6.7).
    pub sva: Sva,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
}

impl AsduLayout for MMeNb1 {
    const TYPE_ID: TypeId = TypeId::MMeNb1;
    const LEN: usize = Sva::LEN + Qds::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sva: Sva::parse(split_off(&mut element, Sva::LEN)?)?,
            qds: Qds::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sva.encode(out);
        self.qds.encode(out);
    }
}

/// `M_ME_TB_1`: Measured value, scaled value with time tag, 5-101 clause
/// 7.3.1.12 (PDF page index 74).
///
/// ```text
/// M_ME_TB_1 := CP{Data unit identifier,i(Information object address,SVA,QDS,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each measured value
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MMeTb1 {
    /// Scaled value (`SVA`, 7.2.6.7).
    pub sva: Sva,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MMeTb1 {
    const TYPE_ID: TypeId = TypeId::MMeTb1;
    const LEN: usize = Sva::LEN + Qds::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sva: Sva::parse(split_off(&mut element, Sva::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sva.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_ME_NC_1`: Measured value, short floating point number, 5-101 clause
/// 7.3.1.13 (PDF page index 75).
///
/// ```text
/// M_ME_NC_1 := CP{Data unit identifier,i(Information object address,IEEE STD 754,QDS)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MMeNc1 {
    /// Short floating point number, IEEE STD 754 (`R32`, 7.2.6.8).
    pub r32: R32,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
}

impl AsduLayout for MMeNc1 {
    const TYPE_ID: TypeId = TypeId::MMeNc1;
    const LEN: usize = R32::LEN + Qds::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            r32: R32::parse(split_off(&mut element, R32::LEN)?)?,
            qds: Qds::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.r32.encode(out);
        self.qds.encode(out);
    }
}

/// `M_ME_TC_1`: Measured value, short floating point number with time tag, 5-101 clause
/// 7.3.1.14 (PDF page index 77).
///
/// ```text
/// M_ME_TC_1 := CP{Data unit identifier,i(Information object address,IEEE STD 754,QDS,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each measured value
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.14).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MMeTc1 {
    /// Short floating point number, IEEE STD 754 (`R32`, 7.2.6.8).
    pub r32: R32,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MMeTc1 {
    const TYPE_ID: TypeId = TypeId::MMeTc1;
    const LEN: usize = R32::LEN + Qds::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            r32: R32::parse(split_off(&mut element, R32::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.r32.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_IT_NA_1`: Integrated totals, 5-101 clause
/// 7.3.1.15 (PDF page index 78).
///
/// ```text
/// M_IT_NA_1 := CP{Data unit identifier,i(Information object address,BCR)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MItNa1 {
    /// Binary counter reading (`BCR`, 7.2.6.9).
    pub bcr: Bcr,
}

impl AsduLayout for MItNa1 {
    const TYPE_ID: TypeId = TypeId::MItNa1;
    const LEN: usize = Bcr::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            bcr: Bcr::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.bcr.encode(out);
    }
}

/// `M_IT_TA_1`: Integrated totals with time tag, 5-101 clause
/// 7.3.1.16 (PDF page index 80).
///
/// ```text
/// M_IT_TA_1 := CP{Data unit identifier,i(Information object address,BCR,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each integrated total
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MItTa1 {
    /// Binary counter reading (`BCR`, 7.2.6.9).
    pub bcr: Bcr,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MItTa1 {
    const TYPE_ID: TypeId = TypeId::MItTa1;
    const LEN: usize = Bcr::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            bcr: Bcr::parse(split_off(&mut element, Bcr::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.bcr.encode(out);
        self.time.encode(out);
    }
}

/// `M_EP_TA_1`: Event of protection equipment with time tag, 5-101 clause
/// 7.3.1.17 (PDF page index 81).
///
/// ```text
/// M_EP_TA_1 := CP{Data unit identifier,i(Information object address,SEP,CP16Time2a,CP24Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each event of protection equipment
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MEpTa1 {
    /// Single event of protection equipment (`SEP`, 7.2.6.10).
    pub sep: Sep,
    /// Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).
    pub elapsed: Cp16Time2a,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MEpTa1 {
    const TYPE_ID: TypeId = TypeId::MEpTa1;
    const LEN: usize = Sep::LEN + Cp16Time2a::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sep: Sep::parse(split_off(&mut element, Sep::LEN)?)?,
            elapsed: Cp16Time2a::parse(split_off(&mut element, Cp16Time2a::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sep.encode(out);
        self.elapsed.encode(out);
        self.time.encode(out);
    }
}

/// `M_EP_TB_1`: Packed start events of protection equipment with time tag, 5-101 clause
/// 7.3.1.18 (PDF page index 82).
///
/// ```text
/// M_EP_TB_1 := CP{Data unit identifier,Information object address,SPE,QDP,CP16Time2a,CP24Time2a}
/// ```
///
/// The figure is headed *"Single information object (SQ = 0)"*, prints no
/// "Number i of objects" field and the definition line has no
/// `i(...)`/`j(...)`, so an ASDU of this type carries exactly one information
/// object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MEpTb1 {
    /// Start events of protection equipment (`SPE`, 7.2.6.11).
    pub spe: Spe,
    /// Quality descriptor for events of protection equipment (`QDP`, 7.2.6.4).
    pub qdp: Qdp,
    /// Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).
    pub elapsed: Cp16Time2a,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MEpTb1 {
    const TYPE_ID: TypeId = TypeId::MEpTb1;
    const LEN: usize = Spe::LEN + Qdp::LEN + Cp16Time2a::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            spe: Spe::parse(split_off(&mut element, Spe::LEN)?)?,
            qdp: Qdp::parse(split_off(&mut element, Qdp::LEN)?)?,
            elapsed: Cp16Time2a::parse(split_off(&mut element, Cp16Time2a::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.spe.encode(out);
        self.qdp.encode(out);
        self.elapsed.encode(out);
        self.time.encode(out);
    }
}

/// `M_EP_TC_1`: Packed output circuit information of protection equipment with time tag, 5-101 clause
/// 7.3.1.19 (PDF page index 83).
///
/// ```text
/// M_EP_TC_1 := CP{Data unit identifier,Information object address,OCI,QDP,CP16Time2a,CP24Time2a}
/// ```
///
/// The figure is headed *"Single information object (SQ = 0)"*, prints no
/// "Number i of objects" field and the definition line has no
/// `i(...)`/`j(...)`, so an ASDU of this type carries exactly one information
/// object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MEpTc1 {
    /// Output circuit information of protection equipment (`OCI`, 7.2.6.12).
    pub oci: Oci,
    /// Quality descriptor for events of protection equipment (`QDP`, 7.2.6.4).
    pub qdp: Qdp,
    /// Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).
    pub elapsed: Cp16Time2a,
    /// Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).
    pub time: Cp24Time2a,
}

impl AsduLayout for MEpTc1 {
    const TYPE_ID: TypeId = TypeId::MEpTc1;
    const LEN: usize = Oci::LEN + Qdp::LEN + Cp16Time2a::LEN + Cp24Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            oci: Oci::parse(split_off(&mut element, Oci::LEN)?)?,
            qdp: Qdp::parse(split_off(&mut element, Qdp::LEN)?)?,
            elapsed: Cp16Time2a::parse(split_off(&mut element, Cp16Time2a::LEN)?)?,
            time: Cp24Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.oci.encode(out);
        self.qdp.encode(out);
        self.elapsed.encode(out);
        self.time.encode(out);
    }
}

/// `M_PS_NA_1`: Packed single-point information with status change detection, 5-101 clause
/// 7.3.1.20 (PDF page index 84).
///
/// ```text
/// M_PS_NA_1 := CP{Data unit identifier,i(Information object address,SCD,QDS)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MPsNa1 {
    /// Status and status change detection (`SCD`, 7.2.6.40).
    pub scd: Scd,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
}

impl AsduLayout for MPsNa1 {
    const TYPE_ID: TypeId = TypeId::MPsNa1;
    const LEN: usize = Scd::LEN + Qds::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            scd: Scd::parse(split_off(&mut element, Scd::LEN)?)?,
            qds: Qds::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.scd.encode(out);
        self.qds.encode(out);
    }
}

/// `M_ME_ND_1`: Measured value, normalized value without quality descriptor, 5-101 clause
/// 7.3.1.21 (PDF page index 86).
///
/// ```text
/// M_ME_ND_1 := CP{Data unit identifier,i(Information object address,NVA)}
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MMeNd1 {
    /// Normalized value (`NVA`, 7.2.6.6).
    pub nva: Nva,
}

impl AsduLayout for MMeNd1 {
    const TYPE_ID: TypeId = TypeId::MMeNd1;
    const LEN: usize = Nva::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let element = take(element, Self::LEN)?;
        Ok(Self {
            nva: Nva::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nva.encode(out);
    }
}

/// `M_SP_TB_1`: Single-point information with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.22 (PDF page index 87).
///
/// ```text
/// M_SP_TB_1 := CP{Data unit identifier,i(Information object address,SIQ,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each single-point information
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MSpTb1 {
    /// Single-point information with quality descriptor (`SIQ`, 7.2.6.1).
    pub siq: Siq,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MSpTb1 {
    const TYPE_ID: TypeId = TypeId::MSpTb1;
    const LEN: usize = Siq::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            siq: Siq::parse(split_off(&mut element, Siq::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.siq.encode(out);
        self.time.encode(out);
    }
}

/// `M_DP_TB_1`: Double-point information with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.23 (PDF page index 88).
///
/// ```text
/// M_DP_TB_1 := CP{Data unit identifier,i(Information object address,DIQ,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each double-point information
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MDpTb1 {
    /// Double-point information with quality descriptor (`DIQ`, 7.2.6.2).
    pub diq: Diq,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MDpTb1 {
    const TYPE_ID: TypeId = TypeId::MDpTb1;
    const LEN: usize = Diq::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            diq: Diq::parse(split_off(&mut element, Diq::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.diq.encode(out);
        self.time.encode(out);
    }
}

/// `M_ST_TB_1`: Step position information with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.24 (PDF page index 89).
///
/// ```text
/// M_ST_TB_1 := CP{Data unit identifier,i(Information object address,VTI,QDS,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each step position information
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.24).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MStTb1 {
    /// Value with transient state indication (`VTI`, 7.2.6.5).
    pub vti: Vti,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MStTb1 {
    const TYPE_ID: TypeId = TypeId::MStTb1;
    const LEN: usize = Vti::LEN + Qds::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            vti: Vti::parse(split_off(&mut element, Vti::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.vti.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_BO_TB_1`: Bitstring of 32 bits with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.25 (PDF page index 90).
///
/// ```text
/// M_BO_TB_1 := CP{Data unit identifier,i(Information object address,BSI,QDS,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each bitstring
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.25).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MBoTb1 {
    /// Binary state information, 32 bit (`BSI`, 7.2.6.13).
    pub bsi: Bsi,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MBoTb1 {
    const TYPE_ID: TypeId = TypeId::MBoTb1;
    const LEN: usize = Bsi::LEN + Qds::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            bsi: Bsi::parse(split_off(&mut element, Bsi::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.bsi.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_ME_TD_1`: Measured value, normalized value with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.26 (PDF page index 91).
///
/// ```text
/// M_ME_TD_1 := CP{Data unit identifier,i(Information object address,NVA,QDS,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each measured value
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.26).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MMeTd1 {
    /// Normalized value (`NVA`, 7.2.6.6).
    pub nva: Nva,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MMeTd1 {
    const TYPE_ID: TypeId = TypeId::MMeTd1;
    const LEN: usize = Nva::LEN + Qds::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            nva: Nva::parse(split_off(&mut element, Nva::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.nva.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_ME_TE_1`: Measured value, scaled value with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.27 (PDF page index 92).
///
/// ```text
/// M_ME_TE_1 := CP{Data unit identifier,i(Information object address,SVA,QDS,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each measured value
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MMeTe1 {
    /// Scaled value (`SVA`, 7.2.6.7).
    pub sva: Sva,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MMeTe1 {
    const TYPE_ID: TypeId = TypeId::MMeTe1;
    const LEN: usize = Sva::LEN + Qds::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sva: Sva::parse(split_off(&mut element, Sva::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sva.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_ME_TF_1`: Measured value, short floating point number with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.28 (PDF page index 94).
///
/// ```text
/// M_ME_TF_1 := CP{Data unit identifier,i(Information object address,IEEE STD 754,QDS,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each measured value
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.28).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MMeTf1 {
    /// Short floating point number, IEEE STD 754 (`R32`, 7.2.6.8).
    pub r32: R32,
    /// Quality descriptor (`QDS`, 7.2.6.3).
    pub qds: Qds,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MMeTf1 {
    const TYPE_ID: TypeId = TypeId::MMeTf1;
    const LEN: usize = R32::LEN + Qds::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            r32: R32::parse(split_off(&mut element, R32::LEN)?)?,
            qds: Qds::parse(split_off(&mut element, Qds::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.r32.encode(out);
        self.qds.encode(out);
        self.time.encode(out);
    }
}

/// `M_IT_TB_1`: Integrated totals with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.29 (PDF page index 95).
///
/// ```text
/// M_IT_TB_1 := CP{Data unit identifier,i(Information object address,BCR,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each integrated total
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.29).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MItTb1 {
    /// Binary counter reading (`BCR`, 7.2.6.9).
    pub bcr: Bcr,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MItTb1 {
    const TYPE_ID: TypeId = TypeId::MItTb1;
    const LEN: usize = Bcr::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            bcr: Bcr::parse(split_off(&mut element, Bcr::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.bcr.encode(out);
        self.time.encode(out);
    }
}

/// `M_EP_TD_1`: Event of protection equipment with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.30 (PDF page index 96).
///
/// ```text
/// M_EP_TD_1 := CP{Data unit identifier,i(Information object address,SEP,CP16Time2a,CP56Time2a)}
/// ```
///
/// No sequence form, in the clause's words: *"Since each event of protection equipment
/// has its individual time tag, this type of ASDU does not exist as a sequence of
/// information elements"* (7.3.1.30).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MEpTd1 {
    /// Single event of protection equipment (`SEP`, 7.2.6.10).
    pub sep: Sep,
    /// Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).
    pub elapsed: Cp16Time2a,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MEpTd1 {
    const TYPE_ID: TypeId = TypeId::MEpTd1;
    const LEN: usize = Sep::LEN + Cp16Time2a::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            sep: Sep::parse(split_off(&mut element, Sep::LEN)?)?,
            elapsed: Cp16Time2a::parse(split_off(&mut element, Cp16Time2a::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.sep.encode(out);
        self.elapsed.encode(out);
        self.time.encode(out);
    }
}

/// `M_EP_TE_1`: Packed start events of protection equipment with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.31 (PDF page index 97).
///
/// ```text
/// M_EP_TE_1 := CP{Data unit identifier,Information object address,SPE,QDP,CP16Time2a,CP56Time2a}
/// ```
///
/// The figure is headed *"Single information object (SQ = 0)"*, prints no
/// "Number i of objects" field and the definition line has no
/// `i(...)`/`j(...)`, so an ASDU of this type carries exactly one information
/// object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MEpTe1 {
    /// Start events of protection equipment (`SPE`, 7.2.6.11).
    pub spe: Spe,
    /// Quality descriptor for events of protection equipment (`QDP`, 7.2.6.4).
    pub qdp: Qdp,
    /// Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).
    pub elapsed: Cp16Time2a,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MEpTe1 {
    const TYPE_ID: TypeId = TypeId::MEpTe1;
    const LEN: usize = Spe::LEN + Qdp::LEN + Cp16Time2a::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            spe: Spe::parse(split_off(&mut element, Spe::LEN)?)?,
            qdp: Qdp::parse(split_off(&mut element, Qdp::LEN)?)?,
            elapsed: Cp16Time2a::parse(split_off(&mut element, Cp16Time2a::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.spe.encode(out);
        self.qdp.encode(out);
        self.elapsed.encode(out);
        self.time.encode(out);
    }
}

/// `M_EP_TF_1`: Packed output circuit information of protection equipment with time tag `CP56Time2a`, 5-101 clause
/// 7.3.1.32 (PDF page index 98).
///
/// ```text
/// M_EP_TF_1 := CP{Data unit identifier,Information object address,OCI,QDP,CP16Time2a,CP56Time2a}
/// ```
///
/// The figure is headed *"Single information object (SQ = 0)"*, prints no
/// "Number i of objects" field and the definition line has no
/// `i(...)`/`j(...)`, so an ASDU of this type carries exactly one information
/// object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MEpTf1 {
    /// Output circuit information of protection equipment (`OCI`, 7.2.6.12).
    pub oci: Oci,
    /// Quality descriptor for events of protection equipment (`QDP`, 7.2.6.4).
    pub qdp: Qdp,
    /// Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).
    pub elapsed: Cp16Time2a,
    /// Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).
    pub time: Cp56Time2a,
}

impl AsduLayout for MEpTf1 {
    const TYPE_ID: TypeId = TypeId::MEpTf1;
    const LEN: usize = Oci::LEN + Qdp::LEN + Cp16Time2a::LEN + Cp56Time2a::LEN;

    fn parse(element: &[u8]) -> Result<Self, AsduError> {
        let mut element = take(element, Self::LEN)?;
        Ok(Self {
            oci: Oci::parse(split_off(&mut element, Oci::LEN)?)?,
            qdp: Qdp::parse(split_off(&mut element, Qdp::LEN)?)?,
            elapsed: Cp16Time2a::parse(split_off(&mut element, Cp16Time2a::LEN)?)?,
            time: Cp56Time2a::parse(element)?,
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        self.oci.encode(out);
        self.qdp.encode(out);
        self.elapsed.encode(out);
        self.time.encode(out);
    }
}
