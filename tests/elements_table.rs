//! The octet geometry of the information-element layer.
//!
//! This file pins every element's octet length against the standard. The ASDU
//! body cursor takes an element's length as an argument
//! (`BodyReader::next_object(element_len)`) and does not derive it; the
//! per-type layouts compute it from the elements' `LEN` constants. Those
//! constants are therefore the whole interface between the two layers, and a
//! wrong one puts every ASDU layout that uses it one octet out.
//!
//! The numbers below are read off IEC 60870-5-101:2003 clause 7.2.6's own
//! definition lists and the per-type figures of clause 7.3 that print the
//! element's octet rows. A `CP8`/`BS8`/one `UI8`-style field is one octet, and
//! each figure column is one octet:
//!
//! ```text
//! clause   element       octets  where the count is visible
//! 7.2.6.1  SIQ   1   CP8{SPI,RES,BL,SB,NT,IV}
//! .2  DIQ   1   CP8{DPI,RES,BL,SB,NT,IV}
//! .3  QDS   1   CP8{OV,RES,BL,SB,NT,IV}
//! .4  QDP   1   CP8{RES,EI,BL,SB,NT,IV}
//! .5  VTI   1   CP8{Value,Transient}
//! .6  NVA   2   F16[1..16]                     (figure 34, M_ME_NA_1)
//! .7  SVA   2   I16[1..16]                     (figure 37, M_ME_NB_1)
//! .8  R32   4   R32.23{Fraction,Exponent,Sign} (figure 40, M_ME_NC_1)
//! .9  BCR   5   CP40{…}                        (figure 43, M_IT_NA_1)
//! .10 SEP   1   CP8{ES,RES,EI,BL,SB,NT,IV}
//! .11 SPE   1   BS8{GS,SL1,SL2,SL3,SIE,SRD,RES}
//! .12 OCI   1   BS8{GC,CL1,CL2,CL3,RES}
//! .13 BSI   4   32BS1[1..32]                   (figure 31, M_BO_NA_1)
//! .14 FBP   2   UI16[1..16]<55AAH>             (figure 76, C_TS_NA_1)
//! .15 SCO   1   CP8{SCS,RES,QOC}
//! .16 DCO   1   CP8{DCS,QOC}
//! .17 RCO   1   CP8{RCS,QOC}
//! .18 CP56Time2a  7  CP56{milliseconds…years}  (figure 53, M_SP_TB_1)
//! .19 CP24Time2a  3  CP24{milliseconds,minutes,RES1,invalid}
//! .20 CP16Time2a  2  UI16[1..16]<0..59 999 ms> (M_EP_TA_1, figure 46)
//! .21 COI   1   CP8{UI7[1..7],BS1[8]}          (figure 71, M_EI_NA_1)
//! .22 QOI   1   UI8[1..8]<0..255>              (figure 72, C_IC_NA_1)
//! .23 QCC   1   CP8{RQT,FRZ}                   (figure 73, C_CI_NA_1)
//! .24 QPM   1   CP8{KPA,LPC,POP}               (figure 79, P_ME_NA_1)
//! .25 QPA   1   UI8[1..8]<0..255>              (figure 82, P_AC_NA_1)
//! .26 QOC   1*  CP6{QU,S/E}  (bits 3..8 of the SCO/DCO/RCO octet)
//! .27 QRP   1   UI8[1..8]<0..255>              (figure 77, C_RP_NA_1)
//! .28 FRQ   1   CP8{UI7[1..7],BS1[8]}          (figure 83, F_FR_NA_1)
//! .29 SRQ   1   CP8{UI7[1..7],BS1[8]}          (figure 84, F_SR_NA_1)
//! .30 SCQ   1   CP8{UI4[1..4],UI4[5..8]}       (figure 85, F_SC_NA_1)
//! .31 LSQ   1   UI8[1..8]<0..255>              (figure 86, F_LS_NA_1)
//! .32 AFQ   1   CP8{UI4[1..4],UI4[5..8]}       (figure 87, F_AF_NA_1)
//! .33 NOF   2   UI16[1..16]<0..65535>          (figure 83, F_FR_NA_1)
//! .34 NOS   1   UI8[1..8]<0..255>              (figure 84, F_SR_NA_1)
//! .35 LOF   3   UI24[1..24]<0..16777215>       (figure 83, F_FR_NA_1)
//! .36 LOS   1   UI8[1..8]<0..255>              (figure 88, F_SG_NA_1)
//! .37 CHS   1   UI8[1..8]<0..255>              (figure 89, F_LS_NA_1)
//! .38 SOF   1   CP8{STATUS,LFD,FOR,FA}         (figure 91, F_DR_TA_1)
//! .39 QOS   1   CP8{QL,S/E}                    (figures 67–69, C_SE_*)
//! .40 SCD   4   CP32{ST,CD}                    (figure 49, M_PS_NA_1)
//! ```
//!
//! `QOC` is the one element whose clause layout is a *fragment* (`CP6[3..8]`)
//! rather than an octet of its own; this crate stores it in the one octet the
//! command state shares, so its `LEN` is 1 and its bits 1–2 read as zero.

use iec104::asdu::{
    Afq, AsduError, Bcr, BodyReader, Bsi, Cause, Chs, Coi, Cp16Time2a, Cp24Time2a, Cp56Time2a, Dco,
    Diq, Fbp, Frq, Header, Lof, Los, Lsq, Nof, Nos, Nva, Oci, Qcc, Qdp, Qds, Qoc, Qoi, Qos, Qpa,
    Qpm, Qrp, R32, Rco, Scd, Sco, Scq, Sep, Siq, Sof, Spe, Srq, Sva, Tsc, TypeId, Vti, encode_body,
};

/// The one table every element's `LEN` is checked against: the standard's
/// abbreviation, the constant, and the octet count read off clause 7.2.6 /
/// the clause 7.3 figures.
#[test]
fn every_element_length_matches_the_figure() {
    let cases: &[(&str, usize, usize)] = &[
        ("SIQ", Siq::LEN, 1),
        ("DIQ", Diq::LEN, 1),
        ("QDS", Qds::LEN, 1),
        ("QDP", Qdp::LEN, 1),
        ("VTI", Vti::LEN, 1),
        ("NVA", Nva::LEN, 2),
        ("SVA", Sva::LEN, 2),
        ("R32-IEEE STD 754", R32::LEN, 4),
        ("BCR", Bcr::LEN, 5),
        ("SEP", Sep::LEN, 1),
        ("SPE", Spe::LEN, 1),
        ("OCI", Oci::LEN, 1),
        ("BSI", Bsi::LEN, 4),
        ("FBP", Fbp::LEN, 2),
        ("SCO", Sco::LEN, 1),
        ("DCO", Dco::LEN, 1),
        ("RCO", Rco::LEN, 1),
        ("CP56Time2a", Cp56Time2a::LEN, 7),
        ("CP24Time2a", Cp24Time2a::LEN, 3),
        ("CP16Time2a", Cp16Time2a::LEN, 2),
        ("COI", Coi::LEN, 1),
        ("QOI", Qoi::LEN, 1),
        ("QCC", Qcc::LEN, 1),
        ("QPM", Qpm::LEN, 1),
        ("QPA", Qpa::LEN, 1),
        ("QOC", Qoc::LEN, 1),
        ("QRP", Qrp::LEN, 1),
        ("FRQ", Frq::LEN, 1),
        ("SRQ", Srq::LEN, 1),
        ("SCQ", Scq::LEN, 1),
        ("LSQ", Lsq::LEN, 1),
        ("AFQ", Afq::LEN, 1),
        ("NOF", Nof::LEN, 2),
        ("NOS", Nos::LEN, 1),
        ("LOF", Lof::LEN, 3),
        ("LOS", Los::LEN, 1),
        ("CHS", Chs::LEN, 1),
        ("SOF", Sof::LEN, 1),
        ("QOS", Qos::LEN, 1),
        ("SCD", Scd::LEN, 4),
    ];

    // Clause 7.2.6 has 40 contiguous subsections (7.2.6.1 … 7.2.6.40), so the
    // table must name exactly 40 elements, each once. A table that silently
    // misses one element (39 of 40) is the slip this count exists to catch.
    assert_eq!(cases.len(), 40, "clause 7.2.6 has 40 information elements");
    let mut names: Vec<&str> = cases.iter().map(|(name, _, _)| *name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 40, "every element must appear once");

    for (name, got, want) in cases {
        assert_eq!(
            got, want,
            "{name}: LEN says {got} octets, the clause and its figures say {want}"
        );
    }
}

/// The one element this layer carries that clause 7.2.6 does **not** define:
/// `TSC` of IEC 60870-5-104:2006 clause 8.8, two octets
/// (`TSC := UI16[1..16]<0..65535>`), carried by the time-tagged test command
/// `C_TS_TA_1` (type 107).
///
/// It is asserted separately rather than added to the 40-row table above,
/// because that 40 is clause 7.2.6's own subsection count and does not move
/// when 5-104 adds an element.
#[test]
fn the_element_outside_clause_7_2_6_is_two_octets() {
    assert_eq!(
        Tsc::LEN,
        2,
        "TSC := UI16[1..16]<0..65535> (5-104 clause 8.8, figure 30)"
    );
    // And the constant and the parser agree: one octet is short of the field.
    assert_eq!(
        Tsc::parse(&[0x00]),
        Err(AsduError::TooShort { need: 2, have: 1 })
    );
}

/// The body cursor and the element layer meet exactly at `element_len`, so an
/// object whose whole element is one `BCR` (type 15, `M_IT_NA_1`, clause
/// 7.3.1.15: `i(Information object address, BCR)`) must walk, decode and
/// re-encode byte-for-byte.
#[test]
fn a_bcr_object_area_survives_the_body_cursor() {
    // Two integrated totals: IOA 0x010203 = 66051 and 0x010204, with a
    // five-octet BCR each.
    let asdu: Vec<u8> = {
        let header = Header {
            type_id: TypeId::MItNa1,
            sequence: false,
            count: 2,
            cause: Cause::Spontaneous,
            negative: false,
            test: false,
            originator: 0,
            common_address: 12,
        };
        let mut out = Vec::new();
        header.encode(&mut out);
        // object 1: reading 1, sequence 3, carry set
        out.extend_from_slice(&[0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x23]);
        // object 2: reading -2, sequence 31, invalid
        out.extend_from_slice(&[0x04, 0x02, 0x01, 0xFE, 0xFF, 0xFF, 0xFF, 0x9F]);
        out
    };

    let mut body = BodyReader::from_asdu(&asdu).expect("header");
    let mut objects = Vec::new();
    while let Some(object) = body.next_object(Bcr::LEN).expect("object") {
        objects.push((object.ioa, Bcr::parse(object.element).expect("bcr")));
    }
    body.finish().expect("exact area");

    assert_eq!(objects.len(), 2);
    assert_eq!(objects[0].0, 0x0001_0203);
    assert_eq!(objects[0].1.reading, 1);
    assert_eq!(objects[0].1.sequence, 3);
    assert!(objects[0].1.carry);
    assert_eq!(objects[1].1.reading, -2);
    assert_eq!(objects[1].1.sequence, 31);
    assert!(objects[1].1.invalid);

    // Re-encoding the decoded objects reproduces the object area.
    let header = Header::parse(&asdu).expect("header");
    let elements: Vec<Vec<u8>> = objects
        .iter()
        .map(|(_, bcr)| {
            let mut buf = Vec::new();
            bcr.encode(&mut buf);
            buf
        })
        .collect();
    let reencoded: Vec<iec104::asdu::Object<'_>> = objects
        .iter()
        .zip(&elements)
        .map(|((ioa, _), element)| iec104::asdu::Object {
            ioa: *ioa,
            element: element.as_slice(),
        })
        .collect();
    assert_eq!(
        encode_body(&header, &reencoded).expect("encode"),
        &asdu[Header::LEN..]
    );
}

/// The same seam with the element the standard fixes to one value: a
/// `C_TS_NA_1` test command (type 104, clause 7.3.4.5) is one object of
/// `IOA(3) + FBP(2)`, and the `AA 55` the figure prints must come back.
#[test]
fn a_test_command_body_round_trips() {
    let body = [0x00, 0x00, 0x00, 0xAA, 0x55];
    let header = Header {
        type_id: TypeId::CTsNa1,
        sequence: false,
        count: 1,
        cause: Cause::Activation,
        negative: false,
        test: false,
        originator: 0,
        common_address: 1,
    };
    let mut asdu = Vec::new();
    header.encode(&mut asdu);
    asdu.extend_from_slice(&body);

    let mut cursor = BodyReader::from_asdu(&asdu).expect("header");
    let object = cursor
        .next_object(Fbp::LEN)
        .expect("object")
        .expect("one object");
    assert_eq!(object.ioa, 0);
    Fbp::parse(object.element).expect("fixed test bit pattern");
    cursor.finish().expect("exact area");
}
