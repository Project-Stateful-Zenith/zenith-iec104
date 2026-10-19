//! 604 Table 11, *"Information object address conformance test procedures"*,
//! PDF page index 54 (printed 53), procedure `5.4.11.1`.
//!
//! The row is quoted verbatim on the test. Its `Reference` column is
//! `IEC 60870-5-101:2003, 7.2.3`: the same clause the type-identification and
//! cause cases of Table 10 come from, whose table pairs the four unknown-field
//! classes with the causes 44, 45, 46 and 47.
//!
//! # The NOTE, and what "each supported ASDU" means here
//!
//! The block's NOTE, on the same page, is *"These tests are performed correctly
//! **for each supported ASDU**."*, so one sample is not the procedure. The three
//! cases below therefore loop over the whole supported set, and each of them
//! first asserts that the set holds more than one type, so a filter that
//! silently matched nothing could not pass in place of the NOTE:
//!
//! - the two **controlled**-station cases drive every type in
//!   [`control_direction_type_ids`]: the types the station supports whose
//!   direction is `Control` or `Both`, 32 of them;
//! - the **controlling**-station case drives every type in
//!   [`monitor_direction_type_ids`]: direction `Monitor` or `Both`, 30 of them.
//!
//! **No type is excluded**, and there is nothing to exclude: the crate lays out
//! the whole family (`layout::element_len` answers `Some` for the file-transfer
//! types 120–124, 126 and 127, and `<125>` is read and written through
//! `layout::file::encode_segment`), so every sample is built **well formed** for
//! its own type by `conformance604::sample_object_area`, from 5-101 clause 7.3's
//! element length, and is as exercisable as `C_SC_NA_1`. A profile whose sample
//! could not be expressed would have to be named in a `const` here with its
//! reason; none is.
//!
//! Every assertion message carries the type identification it is about.
//!
//! # Direction
//!
//! Both halves of the row are driven, as §5.1 makes the direction part of the
//! test. The **controlled**-station half (the row's own words, *"received by the
//! controlled station"*) is driven over a loopback socket, as §5.1's COT44-47
//! exception requires: 47 is one of the four causes only a controlled station
//! may send. The **controlling**-station half (*"Any message received by the
//! controlling station containing an undefined IOA is ignored (or discarded)"*)
//! is driven by the interoperability harness's `interop::Station` against the
//! mock `MonitorPeer`, with the crate's monitor-direction rule
//! `asdu::unknown::discard_reason` as the verdict. Each sample carries the cause
//! clause 7.3 sends its own type with: COT 3 (`spont`) for most, COT 4 (`init`)
//! for `M_EI_NA_1` and COT 13 (`file`) for the file-transfer family *except*
//! `F_DR_TA_1` `<126>`, whose figure (index 120) lists only `<3>` and `<5>`.
//! These are all causes of the monitor direction, so the traffic is the
//! direction the row is about: a controlled station's.

use crate::conformance604::{
    CA, HELD_IOA, SAMPLE_SEGMENT_LEN, apci_of, asdu_with_body, assert_sample_element_is_legal,
    control_cause, control_direction_type_ids, controlling_discard, controlling_exchange,
    element_len, exchange, mirror_of, monitor_cause, monitor_direction_type_ids,
    sample_object_area,
};
use iec104::apci::{Apci, UFunction};
use iec104::asdu::{Cause, Direction, Discard, Header, TypeId, Unspecified, cause_is_defined};

/// The element-octet count of [`sample_object_area`]'s sample for `type_id`,
/// the number the length assertions below check against: 5-101 clause 7.3's
/// fixed `element_len`, except for the one variable-length type `<125>`
/// `F_SG_NA_1`, whose element is figure 88's `NOF` 2 + `NOS` 1 + `LOS` 1 + the
/// [`SAMPLE_SEGMENT_LEN`]-octet segment (index 119). The type is named in the
/// message, so a filter that slipped a type with no layout cannot pass as one
/// the crate lays out.
fn sample_element_octets(type_id: u8) -> usize {
    if type_id == 125 {
        4 + SAMPLE_SEGMENT_LEN
    } else {
        element_len(TypeId::from_u8(type_id)).unwrap_or_else(|| {
            panic!("5.4.11.1 (type {type_id}): clause 7.3 defines no element length for it")
        })
    }
}

/// 604 Table 11, PDF page index 54 (printed 53), procedure **`5.4.11.1`**,
/// `Test` column *"OBJECT ADDRESS"*, `Reference` `IEC 60870-5-101:2003, 7.2.3`,
/// `Required` `PICS, 9.5`, the block's mandatory (`M`) row:
///
/// > If COT=47 is supported, any ASDU with undefined IOA in control direction
/// > is mirrored by the controlled station with P/N = 1: negative confirmation
/// > of activation using COT = 47 (unknown IOA)
///
/// and the row's NOTE, same page: *"These tests are performed correctly for each
/// supported ASDU."*
///
/// DUT: the **controlled** station. The station holds data for exactly one
/// information object address, so an ASDU addressed to any other one is
/// undefined for it: 5-101 clause 7.2.5's address space is a station's own data
/// set, not a range the standard fixes. The NOTE's "each supported ASDU" is the
/// loop below: every type of [`control_direction_type_ids`], each with the cause
/// 5-101 clause 7.3 sends its own type with: `6` (`activation`) for most, `5`
/// (`request`) for `C_RD_NA_1` and `F_DR_TA_1` (index 106's read cause, and
/// index 120's `<5> := requested`), `13` (`file`) for the rest of the
/// file-transfer family. That is every ASDU a controlling station may send.
#[test]
fn clause_5_4_11_1_an_undefined_object_address_is_mirrored_with_cause_47() {
    let types = control_direction_type_ids();
    assert!(
        types.len() > 1,
        "5.4.11.1: the NOTE asks for each supported ASDU, so the filter must find more \
         than one type; it found {} ({types:?})",
        types.len()
    );
    for type_id in types {
        let direction = TypeId::from_u8(type_id).direction();
        assert!(
            matches!(direction, Some(Direction::Control | Direction::Both)),
            "5.4.11.1 (type {type_id}): the sample must be a control-direction ASDU, whose \
             direction is {direction:?}"
        );
        // The station's own data set holds HELD_IOA only, and HELD_IOA + 1 is
        // neither that address nor the *irrelevant* address 0 the station-level
        // types (100, 101, 103, 105) carry, so it is undefined for the station
        // whatever the type (5-101 clause 7.2.5).
        let cause = control_cause(type_id);
        assert!(
            cause_is_defined(Cause::from_u8(cause)),
            "5.4.11.1 (type {type_id}): clause 7.3 sends it with cause {cause}, which \
             table 14 defines"
        );
        let request = asdu_with_body(
            type_id,
            cause,
            CA,
            &sample_object_area(type_id, HELD_IOA + 1),
        );
        assert_eq!(
            request.len(),
            Header::LEN + 3 + sample_element_octets(type_id),
            "5.4.11.1 (type {type_id}): the sample must be 5-101 clause 7.3's geometry for \
             its own type, not the one-octet stand-in"
        );
        // The sample's *values* are as deliberate as its geometry: a permitted
        // command state for 46/47, and a CP56Time2a inside clause 7.2.6.18's
        // ranges for every time-tagged type.
        assert_sample_element_is_legal(type_id, &request[Header::LEN + 3..]);
        let (_, reply, _) =
            mirror_of(&request).unwrap_or_else(|why| panic!("5.4.11.1 (type {type_id}): {why}"));

        let header = Header::parse(&reply).expect("the mirror's header");
        assert_eq!(
            header.type_id.to_u8(),
            type_id,
            "5.4.11.1 (type {type_id}): the type identification is mirrored"
        );
        assert_eq!(
            header.cause.to_u8(),
            47,
            "5.4.11.1 (type {type_id}): \"using COT = 47 (unknown IOA)\""
        );
        assert!(
            header.negative,
            "5.4.11.1 (type {type_id}): \"mirrored … with P/N = 1\""
        );
        assert_eq!(
            header.common_address, CA,
            "5.4.11.1 (type {type_id}): the common address is mirrored"
        );
        assert_eq!(
            &reply[Header::LEN..],
            &request[Header::LEN..],
            "5.4.11.1 (type {type_id}): \"mirrored\" — the object area, address included, is copied"
        );
    }
}

/// The other half of the same row, same loop: an address the station *does* hold
/// is not mirrored at all. Without this, the case above would pass for a station
/// that mirrors everything, including, for every one of the 32 types, a request
/// it knows.
///
/// `5.4.11.1` is one procedure with one `Required` column; the negative of the
/// assertion is the row's own precondition ("an undefined IOA"), so it is
/// asserted here rather than left to the reader.
#[test]
fn clause_5_4_11_1_a_defined_object_address_is_not_mirrored() {
    let types = control_direction_type_ids();
    assert!(
        types.len() > 1,
        "5.4.11.1: the NOTE's \"each supported ASDU\" must find more than one type; it found \
         {} ({types:?})",
        types.len()
    );
    for type_id in types {
        let cause = control_cause(type_id);
        assert!(
            cause_is_defined(Cause::from_u8(cause)),
            "5.4.11.1 (type {type_id}): clause 7.3 sends it with cause {cause}, which \
             table 14 defines"
        );
        let request = asdu_with_body(type_id, cause, CA, &sample_object_area(type_id, HELD_IOA));
        assert_eq!(
            request.len(),
            Header::LEN + 3 + sample_element_octets(type_id),
            "5.4.11.1 (type {type_id}): the sample must be 5-101 clause 7.3's geometry for \
             its own type, not the one-octet stand-in"
        );
        // The sample's values are checked as well as its geometry above.
        assert_sample_element_is_legal(type_id, &request[Header::LEN + 3..]);
        let exchange = exchange(&request, 1).unwrap_or_else(|why| {
            panic!(
                "5.4.11.1 (type {type_id}): the controlled station takes a request it knows: {why}"
            )
        });

        assert!(
            exchange.reply.is_none(),
            "5.4.11.1 (type {type_id}): an ASDU the station knows is not mirrored: {:?}",
            exchange.reply
        );
        assert_eq!(
            exchange
                .report
                .sent
                .iter()
                .map(|frame| apci_of(frame).expect("a sent frame"))
                .collect::<Vec<_>>(),
            vec![Apci::U(UFunction::StartDtCon)],
            "5.4.11.1 (type {type_id}): the STARTDT con and nothing else"
        );
    }
}

/// The **controlling** station's half of the same procedure, same page,
/// `Required` `PICS, 9.5`:
///
/// > Any message received by the controlling station containing an undefined IOA
/// > is ignored (or discarded)
///
/// DUT: the **controlling** station. An ASDU addressed to an information object
/// the station holds no data for arrives in the monitor direction; the station's
/// verdict is [`Discard::Unspecified`] with the object-address class, and no
/// I-frame goes back. The NOTE's "each supported ASDU" applies to this row of
/// the block too, so every type of [`monitor_direction_type_ids`] is driven, each
/// with the cause 5-101 clause 7.3 sends its own type with: COT 3 (`spont`) for
/// most, COT 4 (`init`) for `M_EI_NA_1`, COT 13 (`file`) for the file-transfer
/// family except `F_DR_TA_1` `<126>`, which index 120 gives `<3>` and `<5>` and
/// no `<13>`. These are all monitor-direction causes, which is what a controlled
/// station sends.
#[test]
fn clause_5_4_11_1_an_undefined_object_address_in_the_monitor_direction_is_discarded() {
    let types = monitor_direction_type_ids();
    assert!(
        types.len() > 1,
        "5.4.11.1: the NOTE asks for each supported ASDU, so the filter must find more \
         than one type; it found {} ({types:?})",
        types.len()
    );
    for type_id in types {
        let direction = TypeId::from_u8(type_id).direction();
        assert!(
            matches!(direction, Some(Direction::Monitor | Direction::Both)),
            "5.4.11.1 (type {type_id}): the sample must be monitor-direction traffic, whose \
             direction is {direction:?}"
        );
        let cause = monitor_cause(type_id);
        assert!(
            cause_is_defined(Cause::from_u8(cause)),
            "5.4.11.1 (type {type_id}): clause 7.3 sends it with cause {cause}, which \
             table 14 defines"
        );
        let monitor = asdu_with_body(
            type_id,
            cause,
            CA,
            &sample_object_area(type_id, HELD_IOA + 1),
        );
        assert_eq!(
            monitor.len(),
            Header::LEN + 3 + sample_element_octets(type_id),
            "5.4.11.1 (type {type_id}): the sample must be 5-101 clause 7.3's geometry for \
             its own type, not the one-octet stand-in"
        );
        // The sample's CP56Time2a time tags are inside clause
        // 7.2.6.18's ranges, not the zero fill's day of month 0.
        assert_sample_element_is_legal(type_id, &monitor[Header::LEN + 3..]);
        let exchange = controlling_exchange(&monitor)
            .unwrap_or_else(|why| panic!("5.4.11.1 (type {type_id}): {why}"));
        assert_eq!(
            controlling_discard(&exchange.asdu).expect("the controlling station's answers"),
            Some(Discard::Unspecified(Unspecified::InformationObjectAddress)),
            "5.4.11.1 (type {type_id}): \"Any message received by the controlling station \
             containing an undefined IOA is ignored (or discarded)\""
        );
        assert!(
            !exchange.sent.iter().any(|apci| apci.is_i_format()),
            "5.4.11.1 (type {type_id}): the discarded ASDU is not answered with an I-frame: {:?}",
            exchange.sent
        );
    }
}
