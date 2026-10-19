//! The information elements of IEC 60870-5-101:2003 clause 7.2.6.
//!
//! Clause 7.2.6 defines **40** information elements in 40 contiguous
//! subsections, `7.2.6.1` … `7.2.6.40`. Every one of them has a Rust type in
//! this module, grouped by what the element is for:
//!
//! ```text
//! status.rs     SIQ .1 DIQ .2 QDS .3 QDP .4 VTI .5 SEP .10 SPE .11 OCI .12
//!               BSI .13 SCD .40
//! value.rs      NVA .6 SVA .7 R32 .8 BCR .9 FBP .14 TSC (5-104 cl.8.8)
//! time.rs       CP56Time2a .18 CP24Time2a .19 CP16Time2a .20
//! command.rs    SCO .15 DCO .16 RCO .17 QOC .26 QOS .39
//! qualifier.rs  COI .21 QOI .22 QCC .23 QPM .24 QPA .25 QRP .27
//! file.rs       FRQ .28 SRQ .29 SCQ .30 LSQ .31 AFQ .32 NOF .33 NOS .34
//!               LOF .35 LOS .36 CHS .37 SOF .38
//! ```
//!
//! The number after each name is the subsection, so `QDS .3` reads "clause
//! 7.2.6.3". The files group by what an element is *for*, not by the clause's
//! order: `SCD` (7.2.6.40) sits with the status octets and `FBP` (7.2.6.14)
//! with the values.
//!
//! **One type here is not a clause 7.2.6 element.** `TSC` (the test sequence
//! counter of the time-tagged test command `C_TS_TA_1`, type 107) is defined by
//! clause 8.8 of IEC 60870-5-104:2006 and has no 5-101 counterpart. It
//! implements the same `LEN`/`parse`/`encode` contract as the others, which is
//! the whole interface the layout layer needs.
//!
//! **What this layer is, and what it is not.** An element type knows its own
//! octet length on the wire ([`Qds::LEN`] and the same constant on every type),
//! how to read itself from an element's octets ([`parse`](Qds::parse)) and how
//! to append itself to an encoding ([`encode`](Qds::encode)). It does **not**
//! know which ASDU type carries it or in what order: assembling `(IOA,
//! element …)` into the per-type ASDU layouts of clause 7.3 is the job of
//! [`layout`](super::layout). The seam between the two layers is exactly the
//! octet length, which is the `element_len` argument of
//! [`BodyReader::next_object`](super::BodyReader::next_object).
//!
//! **Bit numbering.** Clause 7.2.6 writes its bit fields as
//! `BL := BS1[5]<0..1>`: a 1-based position counted **from the least
//! significant bit** of the octet, so field `[n]` is `1 << (n - 1)`. The
//! figures print the same octet's bits MSB-first (`|IV NT SB BL 0 0 0 OV|`);
//! the definition lists are authoritative, and each type's doc comment names
//! the mask it uses.
//!
//! **Octet order.** Every multi-octet element is little-endian on the wire
//! (5-104 cl.9.5's transmission mode 1, the same order as the header's common
//! address and the IOA): `UI16`/`I16` are least significant octet first,
//! `UI24`/`I32` continue that, and the IEEE 754 `R32` is a `f32` in
//! little-endian octet order (5-101 cl.7.2.6.8, figure 40: "Fraction,
//! Fraction, E Fraction, S Exponent" reading octets 1–4).
//!
//! **Reserved bits.** Several elements carry bits the standard fixes to zero
//! (`RES := BS3[2..4]<0>`, the `RES1`–`RES4` of `CP56Time2a`, …). This crate
//! does not model them: they are written as zero on encode and dropped on
//! decode, because the standard assigns them no value (`<0> :=` is the fixed
//! value, not a range) and nothing in the standard reads them. A received
//! element whose reserved bits are set is therefore decoded and re-encoded with
//! them cleared.
//!
//! **No panics.** Every `parse` reports a short buffer as
//! [`AsduError::TooShort`] with both octet counts, so a network-supplied
//! element of any prefix length is a typed error, as in
//! [`BodyReader`](super::BodyReader).
//!
//! Sources:
//! IEC 60870-5-101:2003 clause 7.2.6.1–7.2.6.40 (printed pages 44–58) and the
//! per-type figures of clause 7.3.1–7.3.6 (the octet orders), corroborated by
//! the published worked example in Clarke/Reynders/Wright, *Practical Modern
//! SCADA Protocols* (Appendix D). IEC 60870-5-104 clause 9 fixes the address
//! profile this crate uses.

mod command;
mod file;
mod qualifier;
mod status;
mod time;
mod value;

pub use command::{
    CommandQualifier, Dco, DoubleCommandState, Qoc, Qos, Rco, RegulatingStepState, Sco,
};
pub use file::{Afq, Chs, Frq, Lof, Los, Lsq, Nof, Nos, Scq, Sof, Srq};
pub use qualifier::{Coi, FreezeMode, Qcc, Qoi, Qpa, Qpm, Qrp};
pub use status::{Bsi, Diq, DoublePointState, EventState, Oci, Qdp, Qds, Scd, Sep, Siq, Spe, Vti};
pub use time::{Cp16Time2a, Cp24Time2a, Cp56Time2a, TimeField, TimeRangeError};
pub use value::{Bcr, Fbp, Nva, R32, Sva, Tsc};

use super::AsduError;

/// Reads `LEN` octets off the front of `buf`, or reports the shortfall.
///
/// Every element type's `parse` starts here, so the "no panic on network
/// input" rule has one implementation.
pub(crate) fn take(buf: &[u8], len: usize) -> Result<&[u8], AsduError> {
    buf.get(..len).ok_or(AsduError::TooShort {
        need: len,
        have: buf.len(),
    })
}

/// Reads the first `N` octets of `buf` as an array, or reports the shortfall.
///
/// The fixed-length form of [`take`], for an element whose octets are read by
/// position.
pub(crate) fn octets<const N: usize>(buf: &[u8]) -> Result<[u8; N], AsduError> {
    buf.first_chunk().copied().ok_or(AsduError::TooShort {
        need: N,
        have: buf.len(),
    })
}

/// Splits `len` octets off the front of `*buf`, leaving the rest in `*buf`, or
/// reports the shortfall.
pub(crate) fn split_off<'a>(buf: &mut &'a [u8], len: usize) -> Result<&'a [u8], AsduError> {
    let (head, rest) = buf.split_at_checked(len).ok_or(AsduError::TooShort {
        need: len,
        have: buf.len(),
    })?;
    *buf = rest;
    Ok(head)
}
