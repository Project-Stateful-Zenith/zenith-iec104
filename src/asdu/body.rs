//! The ASDU *body*: the information objects behind the `Header`.
//!
//! This module is the cursor that walks the object area of an ASDU. It owns
//! the addressing rules of IEC 60870-5-101:2003 clause 7.2.2.1 (SQ = 0: one
//! information object address per object; SQ = 1: a sequence whose single
//! wire address is the base, with element *i* at base + *i*) and the
//! exact-remaining-octets check that keeps a truncated ASDU a typed error
//! instead of a silent short read.
//!
//! ```text
//! body octets = N * (IOA + element)          for SQ = 0
//!             = IOA + N * element            for SQ = 1
//! ```
//!
//! **Who owns the element geometry.** This layer does not know how long an
//! information element is: that is the per-type layout of 5-101 clause 7.2.6
//! (information elements) and clause 7.3 (ASDU layouts), which the caller
//! supplies as the `element_len` argument of [`BodyReader::next_object`]. What
//! this module guarantees is that the *cursor* never reads short: an object
//! the remaining area cannot hold is [`AsduError::TruncatedElement`], and an
//! area with octets no promised object can claim is
//! [`AsduError::ObjectsNotExhausted`].
//!
//! Sources: IEC 60870-5-101:2003 clause
//! 7.2.2 / figure 12: `number = N := UI7[1..7]<0..127>`, `<0> := ASDU contains
//! no INFORMATION OBJECT`. Clause 7.2.2.1: with SQ = 0 every information
//! element (or combination of elements) has its own information object
//! address, and N, binary coded, counts the information objects; with SQ = 1
//! the address belongs to the first element of the sequence, the following
//! elements are numbered on from it in steps of +1, and the ASDU holds a
//! single information object. Clause 7.2.5 / figure 21: `INFORMATION OBJECT
//! ADDRESS := UI24[1..24]<0..16777215>`, `<0>` meaning the address is
//! irrelevant; controlling stations discard ASDUs whose information object
//! address is undefined, and an ASDU that does not use the address sets it to
//! zero.
//!
//! Address sizes: the IOA width is a parameter fixed for the whole system
//! (5-101 cl.7.2.5, index 43). The interoperability sheet of 5-104 cl.9.5
//! (index 98) marks *"Three octets"* but lists *"One octet"* and *"Two
//! octets"* beside it as a system-specific parameter, so the width is
//! carried by [`AddressSizes`] and the cursor is told which profile it walks
//! ([`BodyReader::with_sizes`]).
//! [`BodyReader::new`] and [`encode_body`] are the conventional profile's
//! wrappers: originator present, 2-octet CA, 3-octet IOA.

use super::{AddressSizes, AsduError, Header};
use crate::apci::MAX_ASDU;

/// Largest three-octet information object address, `UI24[1..24]<0..16777215>`
/// (5-101 cl.7.2.5, figure 21).
pub const MAX_IOA: u32 = 0x00FF_FFFF;

/// The information object address `0`, which clause 7.2.5 defines as
/// "INFORMATION OBJECT ADDRESS is irrelevant".
///
/// An ASDU that has no use for the field sets it to zero. A controlling station discards an ASDU whose IOA is
/// undefined for the type in question (the discard itself is an application
/// decision, not this layer's).
pub const IOA_IRRELEVANT: u32 = 0;

/// Largest object area that fits under the conventional profile's 6-octet
/// header in a 249-octet ASDU (5-104 clause 5: an ASDU is at most 249
/// octets).
///
/// Only [`AddressSizes::CONVENTIONAL`]'s budget: a profile with a narrower
/// header leaves more room, so the writer's budget is
/// [`AddressSizes::max_body`], which this constant equals for the conventional
/// profile.
pub const MAX_BODY: usize = MAX_ASDU - Header::LEN;

/// One information object as it appears in the body: its address and its
/// information-element octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Object<'a> {
    /// Information object address (one to three octets as the profile fixes,
    /// little-endian on the wire). An IOA of
    /// [`IOA_IRRELEVANT`] means "the address is irrelevant" (5-101 cl.7.2.5).
    pub ioa: u32,
    /// The object's information-element octets, exactly as they appear on the
    /// wire. Their layout is per-type (5-101 cl.7.2.6 / cl.7.3).
    pub element: &'a [u8],
}

/// A cursor over the object area of an ASDU.
///
/// Constructed from the parsed [`Header`] plus the octets after it, so the
/// SQ = 1 base-address arithmetic is driven by the header rather than by the
/// caller remembering the addressing mode.
#[derive(Debug, Clone)]
pub struct BodyReader<'a> {
    header: Header,
    object_area: &'a [u8],
    /// The address profile whose IOA width this cursor reads (5-101 cl.7.2.5:
    /// a parameter fixed for the whole system).
    sizes: AddressSizes,
    /// Octets of `object_area` already consumed.
    pos: usize,
    /// Objects already yielded.
    index: u8,
    /// The sequence's base address, read once from the head of the area.
    base_ioa: Option<u32>,
    /// The element length the first object was read with. 5-101 cl.7.2.2.1
    /// defines an ASDU as one or more **equal** INFORMATION OBJECTs (SQ = 0) or a
    /// sequence of **equal** COMBINATIONs (SQ = 1), so a caller that asks for a
    /// different length for a later object is reporting a geometry the standard
    /// does not have.
    element_len: Option<usize>,
}

impl<'a> BodyReader<'a> {
    /// Cursor over `object_area`, following `header`'s addressing mode, with the
    /// conventional address sizes.
    ///
    /// Thin wrapper over [`BodyReader::with_sizes`] with
    /// [`AddressSizes::CONVENTIONAL`].
    #[must_use]
    pub const fn new(header: Header, object_area: &'a [u8]) -> Self {
        Self::with_sizes(header, object_area, AddressSizes::CONVENTIONAL)
    }

    /// Cursor over `object_area`, following `header`'s addressing mode and
    /// reading each object's address in the width `sizes` fixes.
    ///
    /// `sizes` must be the profile the ASDU was parsed with; the cursor reads
    /// exactly [`AddressSizes::information_object_address_octets`] octets per
    /// address and refuses a sequence address past [`AddressSizes::max_ioa`].
    #[must_use]
    pub const fn with_sizes(header: Header, object_area: &'a [u8], sizes: AddressSizes) -> Self {
        BodyReader {
            header,
            object_area,
            sizes,
            pos: 0,
            index: 0,
            base_ioa: None,
            element_len: None,
        }
    }

    /// Parses the conventional 6-octet header of a complete ASDU and cursors its
    /// body.
    ///
    /// Thin wrapper over [`Header::parse`] plus [`BodyReader::new`]; a
    /// non-conventional profile parses with [`Header::parse_with`] and cursors
    /// the area behind [`AddressSizes::header_len`] octets with
    /// [`BodyReader::with_sizes`].
    ///
    /// # Errors
    ///
    /// As [`Header::parse`].
    pub fn from_asdu(asdu: &'a [u8]) -> Result<Self, AsduError> {
        let header = Header::parse(asdu)?;
        // `Header::parse` read the whole header, so the slice is in range.
        Ok(BodyReader::new(
            header,
            asdu.get(Header::LEN..).unwrap_or_default(),
        ))
    }

    /// The header this cursor was built from.
    #[must_use]
    pub const fn header(&self) -> Header {
        self.header
    }

    /// Octets of the object area not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.object_area.len().saturating_sub(self.pos)
    }

    /// Objects the header promises minus the objects already yielded.
    #[must_use]
    pub const fn objects_left(&self) -> u8 {
        self.header.count.saturating_sub(self.index)
    }

    /// Yields the next object, with an element of `element_len` octets.
    ///
    /// Returns `Ok(None)` once the header's object count is exhausted (which is
    /// immediately for `count == 0`; 5-101 cl.7.2.2: "ASDU contains no
    /// INFORMATION OBJECT"). `element_len` is the per-type element size of
    /// 5-101 cl.7.2.6/7.3, which this layer does not know; every object of one
    /// ASDU has the same size (cl.7.2.2.1's *equal* objects), so a call with a
    /// different length than the previous one is
    /// [`AsduError::ElementLengthMismatch`].
    ///
    /// With SQ = 1 the base address is read from the head of the object area on
    /// the first call and the following objects reuse it: clause 7.2.2.1 puts
    /// only one INFORMATION OBJECT on the wire.
    ///
    /// # Errors
    ///
    /// [`AsduError::ElementLengthMismatch`] as above,
    /// [`AsduError::TruncatedElement`] if the object area ends inside the
    /// object, and [`AsduError::IoaOutOfRange`] or
    /// [`AsduError::IoaOutOfRangeForWidth`] for a sequence address past the
    /// profile's range.
    pub fn next_object(&mut self, element_len: usize) -> Result<Option<Object<'a>>, AsduError> {
        let index = self.index;
        if index >= self.header.count {
            return Ok(None);
        }

        // Every object of one ASDU has the same element length (cl.7.2.2.1), so
        // a length that differs from the first object's is a caller-side
        // geometry error, not something to read around.
        match self.element_len {
            Some(expected) if expected != element_len => {
                return Err(AsduError::ElementLengthMismatch {
                    index,
                    expected,
                    got: element_len,
                });
            }
            None => self.element_len = Some(element_len),
            _ => {}
        }

        let ioa = if self.header.sequence {
            let base = if let Some(base) = self.base_ioa {
                base
            } else {
                let base = self.read_ioa(index)?;
                self.base_ioa = Some(base);
                base
            };
            // The sequence's addresses increment; one that runs past the end of
            // the configured width's range cannot be expressed, so it is
            // rejected rather than wrapped.
            // `base` fits the width and `index` an octet, so this cannot wrap.
            let advanced = base.wrapping_add(u32::from(index));
            let max = self.sizes.max_ioa();
            if advanced > max {
                return Err(super::ioa_out_of_range(advanced, max));
            }
            advanced
        } else {
            self.read_ioa(index)?
        };

        let element = self.take(index, element_len)?;
        // `index` is below the header's `u8` count.
        self.index = index.wrapping_add(1);
        Ok(Some(Object { ioa, element }))
    }

    /// Asserts that the object area was consumed exactly: whatever is left
    /// cannot be attributed to any object the header promised.
    ///
    /// # Errors
    ///
    /// [`AsduError::ObjectsNotExhausted`] if any octet is left.
    pub const fn finish(&self) -> Result<(), AsduError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(AsduError::ObjectsNotExhausted {
                count: self.header.count,
                remaining,
            })
        }
    }

    /// Reads the object's address in the profile's own width, little-endian
    /// (5-101 fig.19/20/21; 104 cl.9.5's three IOA options).
    fn read_ioa(&mut self, index: u8) -> Result<u32, AsduError> {
        let width = usize::from(self.sizes.information_object_address_octets());
        let element = self.take(index, width)?;
        super::read_ioa_with(element, self.sizes)
    }

    /// Consumes `len` octets of the object area, or reports the shortfall
    /// against the object it belongs to.
    fn take(&mut self, index: u8, len: usize) -> Result<&'a [u8], AsduError> {
        let rest = self.object_area.get(self.pos..).unwrap_or_default();
        let element = rest.get(..len).ok_or(AsduError::TruncatedElement {
            index,
            need: len,
            have: rest.len(),
        })?;
        self.pos = self.pos.wrapping_add(len);
        Ok(element)
    }
}

/// Encodes an object area from `(IOA, element)` pairs, in `header`'s addressing
/// mode, with the conventional address sizes.
///
/// Thin wrapper over [`encode_body_with`] with [`AddressSizes::CONVENTIONAL`].
///
/// # Errors
///
/// As [`encode_body_with`].
pub fn encode_body(header: &Header, objects: &[Object<'_>]) -> Result<Vec<u8>, AsduError> {
    encode_body_with(header, objects, AddressSizes::CONVENTIONAL)
}

/// Encodes an object area from `(IOA, element)` pairs, in `header`'s addressing
/// mode and the address sizes `sizes` fixes.
///
/// For SQ = 1 the base address is written once and the remaining objects'
/// addresses must be consecutive from it. In both modes the elements must
/// share one length: the wire carries neither the following addresses of a
/// sequence nor an element length, so anything else could not be decoded again
/// (5-101 cl.7.2.2.1 defines one ASDU as *equal* objects or combinations).
/// Each address is written in
/// [`AddressSizes::information_object_address_octets`] octets and checked
/// against [`AddressSizes::max_ioa`]: a one-octet profile's bound is `255`
/// (`UI8[1..8]`, 5-101 cl.7.2.5 figure 19), and an address past it is
/// [`AsduError::IoaOutOfRangeForWidth`] rather than a truncated one. The
/// 249-octet ASDU limit of 5-104 cl.5 is checked against
/// [`AddressSizes::max_body`], because a narrower header leaves more room.
///
/// # Errors
///
/// [`AsduError::ObjectCountMismatch`] if `objects` does not match the header's
/// count, [`AsduError::ElementLengthMismatch`] for unequal elements,
/// [`AsduError::SequenceNotContiguous`] for a gap in an SQ = 1 sequence,
/// [`AsduError::IoaOutOfRange`] or [`AsduError::IoaOutOfRangeForWidth`] for an
/// address the width cannot carry, and [`AsduError::BodyTooLong`] past the
/// profile's budget.
pub fn encode_body_with(
    header: &Header,
    objects: &[Object<'_>],
    sizes: AddressSizes,
) -> Result<Vec<u8>, AsduError> {
    if objects.len() != usize::from(header.count) {
        return Err(AsduError::ObjectCountMismatch {
            header: header.count,
            objects: objects.len(),
        });
    }

    let max_ioa = sizes.max_ioa();
    let max_body = sizes.max_body();
    let base_ioa = objects.first().map_or(0, |first| first.ioa);

    let mut out = Vec::new();
    let mut element_len: Option<usize> = None;
    // The count check above keeps `objects` within the `u8` index range.
    for (index, object) in (0..=u8::MAX).zip(objects) {
        if object.ioa > max_ioa {
            return Err(super::ioa_out_of_range(object.ioa, max_ioa));
        }

        // One ASDU holds one or more *equal* information objects (cl.7.2.2.1),
        // whatever the addressing mode: the element length is not on the wire, so
        // a set of unequal ones could not be decoded again.
        match element_len {
            Some(expected) => {
                if object.element.len() != expected {
                    return Err(AsduError::ElementLengthMismatch {
                        index,
                        expected,
                        got: object.element.len(),
                    });
                }
            }
            None => element_len = Some(object.element.len()),
        }

        if header.sequence {
            if index == 0 {
                // Only the base address is written (cl.7.2.2.1).
                super::write_ioa_with(&mut out, object.ioa, sizes);
            } else {
                // The base passed the range check at index 0, so this cannot
                // wrap.
                let expected = base_ioa.wrapping_add(u32::from(index));
                // The incremented address must still be an address: the reader
                // reports the same situation as the width's out-of-range error,
                // and the two sides must not disagree on which error it is.
                if expected > max_ioa {
                    return Err(super::ioa_out_of_range(expected, max_ioa));
                }
                if object.ioa != expected {
                    return Err(AsduError::SequenceNotContiguous {
                        index,
                        expected,
                        got: object.ioa,
                    });
                }
            }
        } else {
            super::write_ioa_with(&mut out, object.ioa, sizes);
        }

        out.extend_from_slice(object.element);
        if out.len() > max_body {
            return Err(AsduError::BodyTooLong {
                len: out.len(),
                max: max_body,
            });
        }
    }
    Ok(out)
}
