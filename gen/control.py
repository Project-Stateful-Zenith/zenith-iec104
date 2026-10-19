#!/usr/bin/env python3
"""Emit src/asdu/layout/control.rs from the clause 7.3.2–7.3.5 inventory.

Table columns: (source document, section, TypeId variant, struct, ASDU name,
title, field list, definition line, PDF page index).

The 19 rows whose source is 5-101 are clause 7.3.2 (`C_SC_NA_1` … `C_BO_NA_1`,
the control direction), 7.3.3 (`M_EI_NA_1`, the one system-information ASDU),
7.3.4 (`C_IC_NA_1` … `C_CD_NA_1`, the system commands) and 7.3.5 (`P_ME_NA_1` …
`P_AC_NA_1`, the parameters). The 8 rows whose source is 5-104 are clause 8 of
IEC 60870-5-104:2006: the time-tagged command forms 58–64 and the time-tagged
test command 107. `C_TS_TA_1` is also the only layout in this crate that carries
an element 5-101 does not define (`TSC`, 5-104 cl.8.8).

Committed so a further clause family can extend the same pattern, and so every
per-type octet count and field order stays re-derivable from the table instead
of only from the generated text.

Usage:

    python3 gen/control.py > src/asdu/layout/control.rs && cargo fmt

`cargo fmt` is part of the step: this script does not sort the imports or strip
the trailing blank line, so the generated file is rustfmt-clean only after it.
The pair is idempotent: regenerating and formatting leaves the committed file
byte-identical, which is the check that the table still describes the module.

`--stub` emits the same types with `unimplemented!()` bodies (correct `LEN`s,
no behaviour), which is what makes a new family's tests RED on assertions
rather than on a compile error.
"""
import re
import sys

SCO = ("sco", "Sco")
DCO = ("dco", "Dco")
RCO = ("rco", "Rco")
NVA = ("nva", "Nva")
SVA = ("sva", "Sva")
R32 = ("r32", "R32")
QOS = ("qos", "Qos")
BSI = ("bsi", "Bsi")
COI = ("coi", "Coi")
QOI = ("qoi", "Qoi")
QCC = ("qcc", "Qcc")
CP56 = ("time", "Cp56Time2a")
FBP = ("fbp", "Fbp")
QRP = ("qrp", "Qrp")
CP16 = ("elapsed", "Cp16Time2a")
QPM = ("qpm", "Qpm")
QPA = ("qpa", "Qpa")
TSC = ("tsc", "Tsc")

FIELD_DOC = {
    "Sco": "Single command with its qualifier of command (`SCO`, 7.2.6.15).",
    "Dco": "Double command (`DCO`, 7.2.6.16).",
    "Rco": "Regulating step command (`RCO`, 7.2.6.17).",
    "Nva": "Normalized set-point value (`NVA`, 7.2.6.6).",
    "Sva": "Scaled set-point value (`SVA`, 7.2.6.7).",
    "R32": "Short floating point number, IEEE STD 754 (`R32`, 7.2.6.8).",
    "Qos": "Qualifier of set-point command, carrying the `S/E` bit (`QOS`, 7.2.6.39).",
    "Bsi": "Binary state information, 32 bit (`BSI`, 7.2.6.13).",
    "Coi": "Cause of initialization (`COI`, 7.2.6.21).",
    "Qoi": "Qualifier of interrogation (`QOI`, 7.2.6.22).",
    "Qcc": "Qualifier of counter interrogation (`QCC`, 7.2.6.23).",
    "Cp56Time2a": "Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).",
    "Cp16Time2a": "Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).",
    "Fbp": "The fixed test bit pattern `UI16[1..16]<55AAH>` (`FBP`, 7.2.6.14).",
    "Qrp": "Qualifier of reset process command (`QRP`, 7.2.6.27).",
    "Qpm": "Qualifier of parameter of measured values (`QPM`, 7.2.6.24).",
    "Qpa": "Qualifier of parameter activation (`QPA`, 7.2.6.25).",
    "Tsc": "Test sequence counter, `UI16[1..16]<0..65535>` (`TSC`, 5-104 clause 8.8).",
}

RD_NOTE = [
    "The type's whole payload is its information object address, which clause",
    "7.2.5 describes as the exception: \"The read command `C_RD_NA_1` is a general",
    "exception since its information object address serves to address available",
    "information objects which are returned in the monitor direction.\"",
    "`LEN` is therefore 0 and the element part of the object is empty, which is",
    "what `BodyReader::next_object(0)` yields.",
]

# (source, section, variant, struct, ASDU, title, fields, definition, page)
TABLE = [
    ("5-101", "7.3.2.1", "CScNa1", "CScNa1", "C_SC_NA_1", "Single command",
     [SCO], "CP{Data unit identifier,Information object address,SCO}", 99),
    ("5-101", "7.3.2.2", "CDcNa1", "CDcNa1", "C_DC_NA_1", "Double command",
     [DCO], "CP{Data unit identifier,Information object address,DCO}", 100),
    ("5-101", "7.3.2.3", "CRcNa1", "CRcNa1", "C_RC_NA_1", "Regulating step command",
     [RCO], "CP{Data unit identifier,Information object address,RCO}", 100),
    ("5-101", "7.3.2.4", "CSeNa1", "CSeNa1", "C_SE_NA_1", "Set-point command, normalized value",
     [NVA, QOS], "CP{Data unit identifier,Information object address,NVA,QOS}", 101),
    ("5-101", "7.3.2.5", "CSeNb1", "CSeNb1", "C_SE_NB_1", "Set-point command, scaled value",
     [SVA, QOS], "CP{Data unit identifier,Information object address,SVA,QOS}", 102),
    ("5-101", "7.3.2.6", "CSeNc1", "CSeNc1", "C_SE_NC_1",
     "Set-point command, short floating point number",
     [R32, QOS], "CP{Data unit identifier,Information object address,IEEE STD 754,QOS}", 102),
    ("5-101", "7.3.2.7", "CBoNa1", "CBoNa1", "C_BO_NA_1", "Bitstring of 32 bit",
     [BSI], "CP{Data unit identifier,Information object address,BSI}", 103),
    ("5-104", "8.1", "CScTa1", "CScTa1", "C_SC_TA_1", "Single command with time tag CP56Time2a",
     [SCO, CP56], "CP{Data unit identifier,Information object address,SCO,CP56Time2a}", 76),
    ("5-104", "8.2", "CDcTa1", "CDcTa1", "C_DC_TA_1", "Double command with time tag CP56Time2a",
     [DCO, CP56], "CP{Data unit identifier,Information object address,DCO,CP56Time2a}", 78),
    ("5-104", "8.3", "CRcTa1", "CRcTa1", "C_RC_TA_1",
     "Regulating step command with time tag CP56Time2a",
     [RCO, CP56], "CP{Data unit identifier,Information object address,RCO,CP56Time2a}", 80),
    ("5-104", "8.4", "CSeTa1", "CSeTa1", "C_SE_TA_1",
     "Set-point command with time tag CP56Time2a, normalized value",
     [NVA, QOS, CP56], "CP{Data unit identifier,Information object address,NVA,QOS,CP56Time2a}", 82),
    ("5-104", "8.5", "CSeTb1", "CSeTb1", "C_SE_TB_1",
     "Set-point command with time tag CP56Time2a, scaled value",
     [SVA, QOS, CP56], "CP{Data unit identifier,Information object address,SVA,QOS,CP56Time2a}", 84),
    ("5-104", "8.6", "CSeTc1", "CSeTc1", "C_SE_TC_1",
     "Set-point command with time tag CP56Time2a, short floating point number",
     [R32, QOS, CP56],
     "CP{Data unit identifier,Information object address,IEEE STD 754,QOS,CP56Time2a}", 86),
    ("5-104", "8.7", "CBoTa1", "CBoTa1", "C_BO_TA_1", "Bitstring of 32 bit with time tag CP56Time2a",
     [BSI, CP56], "CP{Data unit identifier,Information object address,BSI,CP56Time2a}", 88),
    ("5-101", "7.3.3.1", "MEiNa1", "MEiNa1", "M_EI_NA_1",
     "End of initialization", [COI],
     "CP{Data unit identifier,Information object address,COI}", 104),
    ("5-101", "7.3.4.1", "CIcNa1", "CIcNa1", "C_IC_NA_1",
     "Interrogation command", [QOI],
     "CP{Data unit identifier,Information object address,QOI}", 105),
    ("5-101", "7.3.4.2", "CCiNa1", "CCiNa1", "C_CI_NA_1",
     "Counter interrogation command", [QCC],
     "CP{Data unit identifier,Information object address,QCC}", 106),
    ("5-101", "7.3.4.3", "CRdNa1", "CRdNa1", "C_RD_NA_1", "Read command",
     [], "CP{Data unit identifier,Information object address}", 106),
    ("5-101", "7.3.4.4", "CCsNa1", "CCsNa1", "C_CS_NA_1", "Clock synchronization command",
     [CP56], "CP{Data unit identifier,Information object address,CP56Time2a}", 107),
    ("5-101", "7.3.4.5", "CTsNa1", "CTsNa1", "C_TS_NA_1", "Test command",
     [FBP], "CP{Data unit identifier,Information object address,FBP}", 108),
    ("5-101", "7.3.4.6", "CRpNa1", "CRpNa1", "C_RP_NA_1", "Reset process command",
     [QRP], "CP{Data unit identifier,Information object address,QRP}", 108),
    ("5-101", "7.3.4.7", "CCdNa1", "CCdNa1", "C_CD_NA_1", "Delay acquisition command",
     [CP16], "CP{Data unit identifier,Information object address,CP16Time2a}", 109),
    ("5-104", "8.8", "CTsTa1", "CTsTa1", "C_TS_TA_1", "Test command with time tag CP56Time2a",
     [TSC, CP56], "CP{Data unit identifier,Information object address,TSC,CP56Time2a}", 90),
    ("5-101", "7.3.5.1", "PMeNa1", "PMeNa1", "P_ME_NA_1",
     "Parameter of measured values, normalized value", [NVA, QPM],
     "CP{Data unit identifier,Information object address,NVA,QPM}", 110),
    ("5-101", "7.3.5.2", "PMeNb1", "PMeNb1", "P_ME_NB_1",
     "Parameter of measured values, scaled value", [SVA, QPM],
     "CP{Data unit identifier,Information object address,SVA,QPM}", 111),
    ("5-101", "7.3.5.3", "PMeNc1", "PMeNc1", "P_ME_NC_1",
     "Parameter of measured values, short floating point number", [R32, QPM],
     "CP{Data unit identifier,Information object address,IEEE STD 754,QPM}", 112),
    ("5-101", "7.3.5.4", "PAcNa1", "PAcNa1", "P_AC_NA_1",
     "Parameter activation", [QPA],
     "CP{Data unit identifier,Information object address,QPA}", 113),
]

STUB = "--stub" in sys.argv

HEADER = '''//! The control-direction, system and parameter ASDU types of IEC
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
    Bsi, Coi, Cp16Time2a, Cp56Time2a, Dco, Fbp, Nva, Qcc, Qoi, Qos, Qpa, Qpm, Qrp, Rco, Sco, Sva,
    Tsc, R32,
};
use crate::asdu::elements::{split_off, take};
use crate::asdu::{AsduError, TypeId};
'''


def emit(source, section, variant, struct, asdu, title, fields, definition, page):
    # The title names a time tag type, which rustdoc wants as code.
    doc_title = re.sub(r"\b(CP\d+Time2a)\b", r"`\1`", title)
    L = []
    L.append(f"/// `{asdu}`: {doc_title}, {source} clause")
    L.append(f"/// {section} (PDF page index {page}).")
    L.append("///")
    L.append("/// ```text")
    L.append(f"/// {asdu} := {definition}")
    L.append("/// ```")
    if not fields:
        L.append("///")
        L.extend("/// " + line for line in RD_NOTE)
    # R32 is an f32, so the types carrying one cannot derive Eq.
    derives = "Debug, Clone, Copy, PartialEq" + ("" if any(t == "R32" for _, t in fields) else ", Eq")
    L.append(f"#[derive({derives})]")
    if not fields:
        L.append(f"pub struct {struct};")
        L.append("")
        L.append(f"impl AsduLayout for {struct} {{")
        L.append(f"    const TYPE_ID: TypeId = TypeId::{variant};")
        L.append("    const LEN: usize = 0;")
        L.append("")
        if STUB:
            L.append("    fn parse(element: &[u8]) -> Result<Self, AsduError> {")
            L.append("        unimplemented!()")
            L.append("    }")
            L.append("")
            L.append("    fn encode(&self, out: &mut Vec<u8>) {")
            L.append("        unimplemented!()")
            L.append("    }")
        else:
            L.append("    fn parse(_element: &[u8]) -> Result<Self, AsduError> {")
            L.append("        Ok(Self)")
            L.append("    }")
            L.append("")
            L.append("    fn encode(&self, _out: &mut Vec<u8>) {}")
        L.append("}")
        return "\n".join(L)

    L.append(f"pub struct {struct} {{")
    for fname, ftype in fields:
        L.append(f"    /// {FIELD_DOC[ftype]}")
        L.append(f"    pub {fname}: {ftype},")
    L.append("}")
    L.append("")
    L.append(f"impl AsduLayout for {struct} {{")
    L.append(f"    const TYPE_ID: TypeId = TypeId::{variant};")
    L.append("    const LEN: usize = " + " + ".join(f"{t}::LEN" for _, t in fields) + ";")
    L.append("")
    if STUB:
        L.append("    fn parse(element: &[u8]) -> Result<Self, AsduError> {")
        L.append("        unimplemented!()")
        L.append("    }")
        L.append("")
        L.append("    fn encode(&self, out: &mut Vec<u8>) {")
        L.append("        unimplemented!()")
        L.append("    }")
    else:
        # Each field takes its element's own LEN off the front, in order.
        L.append("    fn parse(element: &[u8]) -> Result<Self, AsduError> {")
        mut = "mut " if len(fields) > 1 else ""
        L.append(f"        let {mut}element = take(element, Self::LEN)?;")
        L.append("        Ok(Self {")
        for i, (fname, ftype) in enumerate(fields):
            if i + 1 < len(fields):
                L.append(f"            {fname}: {ftype}::parse(split_off(&mut element, {ftype}::LEN)?)?,")
            else:
                L.append(f"            {fname}: {ftype}::parse(element)?,")
        L.append("        })")
        L.append("    }")
        L.append("")
        L.append("    fn encode(&self, out: &mut Vec<u8>) {")
        for fname, _ in fields:
            L.append(f"        self.{fname}.encode(out);")
        L.append("    }")
    L.append("}")
    return "\n".join(L)


out = [HEADER]
for row in TABLE:
    out.append(emit(*row))
print("\n\n".join(out).rstrip() + "\n")