#!/usr/bin/env python3
"""Emit src/asdu/layout/monitor.rs from the clause 7.3.1 inventory.

Table columns: (subsection, TypeId variant, struct, ASDU name, title,
field list, definition line, PDF page index, note).

Committed so a further clause family can extend the same pattern (gen/control.py
does, for the control direction), and so every per-type octet count and field
order stays re-derivable from the table instead of only from the generated text.

Usage:

    python3 gen/monitor.py > src/asdu/layout/monitor.rs && cargo fmt

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

SIQ = ("siq", "Siq")
DIQ = ("diq", "Diq")
VTI = ("vti", "Vti")
QDS = ("qds", "Qds")
QDP = ("qdp", "Qdp")
BSI = ("bsi", "Bsi")
NVA = ("nva", "Nva")
SVA = ("sva", "Sva")
R32 = ("r32", "R32")
BCR = ("bcr", "Bcr")
SCD = ("scd", "Scd")
SEP = ("sep", "Sep")
SPE = ("spe", "Spe")
OCI = ("oci", "Oci")
ELAPSED = ("elapsed", "Cp16Time2a")
CP24 = ("time", "Cp24Time2a")
CP56 = ("time", "Cp56Time2a")

FIELD_DOC = {
    "Siq": "Single-point information with quality descriptor (`SIQ`, 7.2.6.1).",
    "Diq": "Double-point information with quality descriptor (`DIQ`, 7.2.6.2).",
    "Vti": "Value with transient state indication (`VTI`, 7.2.6.5).",
    "Qds": "Quality descriptor (`QDS`, 7.2.6.3).",
    "Qdp": "Quality descriptor for events of protection equipment (`QDP`, 7.2.6.4).",
    "Bsi": "Binary state information, 32 bit (`BSI`, 7.2.6.13).",
    "Nva": "Normalized value (`NVA`, 7.2.6.6).",
    "Sva": "Scaled value (`SVA`, 7.2.6.7).",
    "R32": "Short floating point number, IEEE STD 754 (`R32`, 7.2.6.8).",
    "Bcr": "Binary counter reading (`BCR`, 7.2.6.9).",
    "Scd": "Status and status change detection (`SCD`, 7.2.6.40).",
    "Sep": "Single event of protection equipment (`SEP`, 7.2.6.10).",
    "Spe": "Start events of protection equipment (`SPE`, 7.2.6.11).",
    "Oci": "Output circuit information of protection equipment (`OCI`, 7.2.6.12).",
    "Cp24Time2a": "Three-octet binary time tag (`CP24Time2a`, 7.2.6.19).",
    "Cp56Time2a": "Seven-octet binary time tag (`CP56Time2a`, 7.2.6.18).",
    "Cp16Time2a": "Two-octet binary elapsed time (`CP16Time2a`, 7.2.6.20).",
}

NO_SEQUENCE = (
    "No sequence form, in the clause's words: *\"Since each "
    "{what}\n/// has its individual time tag, this type of ASDU does not exist as a "
    "sequence of\n/// information elements\"* (7.3.1.{sub})."
)
SINGLE_OBJECT = (
    "The figure is headed *\"Single information object (SQ = 0)\"*, prints no\n"
    "/// \"Number i of objects\" field and the definition line has no\n"
    "/// `i(...)`/`j(...)`, so an ASDU of this type carries exactly one information\n"
    "/// object."
)

TABLE = [
    # subsection, variant, struct, ASDU, title, fields, definition, page, note-kind, note-what
    (1, "MSpNa1", "MSpNa1", "M_SP_NA_1", "Single-point information without time tag",
     [SIQ], "CP{Data unit identifier,i(Information object address,SIQ)}", 60, None, None),
    (2, "MSpTa1", "MSpTa1", "M_SP_TA_1", "Single-point information with time tag",
     [SIQ, CP24], "CP{Data unit identifier,i(Information object address,SIQ,CP24Time2a)}", 62, "seq", "single-point information"),
    (3, "MDpNa1", "MDpNa1", "M_DP_NA_1", "Double-point information without time tag",
     [DIQ], "CP{Data unit identifier,i(Information object address,DIQ)}", 63, None, None),
    (4, "MDpTa1", "MDpTa1", "M_DP_TA_1", "Double-point information with time tag",
     [DIQ, CP24], "CP{Data unit identifier,i(Information object address,DIQ,CP24Time2a)}", 64, "seq", "double-point information"),
    (5, "MStNa1", "MStNa1", "M_ST_NA_1", "Step position information",
     [VTI, QDS], "CP{Data unit identifier,i(Information object address,VTI,QDS)}", 65, None, None),
    (6, "MStTa1", "MStTa1", "M_ST_TA_1", "Step position information with time tag",
     [VTI, QDS, CP24], "CP{Data unit identifier,i(Information object address,VTI,QDS,CP24Time2a)}", 66, "seq", "step position information"),
    (7, "MBoNa1", "MBoNa1", "M_BO_NA_1", "Bitstring of 32 bit",
     [BSI, QDS], "CP{Data unit identifier,i(Information object address,BSI,QDS)}", 67, None, None),
    (8, "MBoTa1", "MBoTa1", "M_BO_TA_1", "Bitstring of 32 bit with time tag",
     [BSI, QDS, CP24], "CP{Data unit identifier,i(Information object address,BSI,QDS,CP24Time2a)}", 69, "seq", "bitstring"),
    (9, "MMeNa1", "MMeNa1", "M_ME_NA_1", "Measured value, normalized value",
     [NVA, QDS], "CP{Data unit identifier,i(Information object address,NVA,QDS)}", 70, None, None),
    (10, "MMeTa1", "MMeTa1", "M_ME_TA_1", "Measured value, normalized value with time tag",
     [NVA, QDS, CP24], "CP{Data unit identifier,i(Information object address,NVA,QDS,CP24Time2a)}", 71, "seq", "measured value"),
    (11, "MMeNb1", "MMeNb1", "M_ME_NB_1", "Measured value, scaled value",
     [SVA, QDS], "CP{Data unit identifier,i(Information object address,SVA,QDS)}", 72, None, None),
    (12, "MMeTb1", "MMeTb1", "M_ME_TB_1", "Measured value, scaled value with time tag",
     [SVA, QDS, CP24], "CP{Data unit identifier,i(Information object address,SVA,QDS,CP24Time2a)}", 74, "seq", "measured value"),
    (13, "MMeNc1", "MMeNc1", "M_ME_NC_1", "Measured value, short floating point number",
     [R32, QDS], "CP{Data unit identifier,i(Information object address,IEEE STD 754,QDS)}", 75, None, None),
    (14, "MMeTc1", "MMeTc1", "M_ME_TC_1", "Measured value, short floating point number with time tag",
     [R32, QDS, CP24], "CP{Data unit identifier,i(Information object address,IEEE STD 754,QDS,CP24Time2a)}", 77, "seq", "measured value"),
    (15, "MItNa1", "MItNa1", "M_IT_NA_1", "Integrated totals",
     [BCR], "CP{Data unit identifier,i(Information object address,BCR)}", 78, None, None),
    (16, "MItTa1", "MItTa1", "M_IT_TA_1", "Integrated totals with time tag",
     [BCR, CP24], "CP{Data unit identifier,i(Information object address,BCR,CP24Time2a)}", 80, "seq", "integrated total"),
    (17, "MEpTa1", "MEpTa1", "M_EP_TA_1", "Event of protection equipment with time tag",
     [SEP, ELAPSED, CP24], "CP{Data unit identifier,i(Information object address,SEP,CP16Time2a,CP24Time2a)}", 81, "seq", "event of protection equipment"),
    (18, "MEpTb1", "MEpTb1", "M_EP_TB_1", "Packed start events of protection equipment with time tag",
     [SPE, QDP, ELAPSED, CP24], "CP{Data unit identifier,Information object address,SPE,QDP,CP16Time2a,CP24Time2a}", 82, "single", None),
    (19, "MEpTc1", "MEpTc1", "M_EP_TC_1", "Packed output circuit information of protection equipment with time tag",
     [OCI, QDP, ELAPSED, CP24], "CP{Data unit identifier,Information object address,OCI,QDP,CP16Time2a,CP24Time2a}", 83, "single", None),
    (20, "MPsNa1", "MPsNa1", "M_PS_NA_1", "Packed single-point information with status change detection",
     [SCD, QDS], "CP{Data unit identifier,i(Information object address,SCD,QDS)}", 84, None, None),
    (21, "MMeNd1", "MMeNd1", "M_ME_ND_1", "Measured value, normalized value without quality descriptor",
     [NVA], "CP{Data unit identifier,i(Information object address,NVA)}", 86, None, None),
    (22, "MSpTb1", "MSpTb1", "M_SP_TB_1", "Single-point information with time tag CP56Time2a",
     [SIQ, CP56], "CP{Data unit identifier,i(Information object address,SIQ,CP56Time2a)}", 87, "seq", "single-point information"),
    (23, "MDpTb1", "MDpTb1", "M_DP_TB_1", "Double-point information with time tag CP56Time2a",
     [DIQ, CP56], "CP{Data unit identifier,i(Information object address,DIQ,CP56Time2a)}", 88, "seq", "double-point information"),
    (24, "MStTb1", "MStTb1", "M_ST_TB_1", "Step position information with time tag CP56Time2a",
     [VTI, QDS, CP56], "CP{Data unit identifier,i(Information object address,VTI,QDS,CP56Time2a)}", 89, "seq", "step position information"),
    (25, "MBoTb1", "MBoTb1", "M_BO_TB_1", "Bitstring of 32 bits with time tag CP56Time2a",
     [BSI, QDS, CP56], "CP{Data unit identifier,i(Information object address,BSI,QDS,CP56Time2a)}", 90, "seq", "bitstring"),
    (26, "MMeTd1", "MMeTd1", "M_ME_TD_1", "Measured value, normalized value with time tag CP56Time2a",
     [NVA, QDS, CP56], "CP{Data unit identifier,i(Information object address,NVA,QDS,CP56Time2a)}", 91, "seq", "measured value"),
    (27, "MMeTe1", "MMeTe1", "M_ME_TE_1", "Measured value, scaled value with time tag CP56Time2a",
     [SVA, QDS, CP56], "CP{Data unit identifier,i(Information object address,SVA,QDS,CP56Time2a)}", 92, "seq", "measured value"),
    (28, "MMeTf1", "MMeTf1", "M_ME_TF_1", "Measured value, short floating point number with time tag CP56Time2a",
     [R32, QDS, CP56], "CP{Data unit identifier,i(Information object address,IEEE STD 754,QDS,CP56Time2a)}", 94, "seq", "measured value"),
    (29, "MItTb1", "MItTb1", "M_IT_TB_1", "Integrated totals with time tag CP56Time2a",
     [BCR, CP56], "CP{Data unit identifier,i(Information object address,BCR,CP56Time2a)}", 95, "seq", "integrated total"),
    (30, "MEpTd1", "MEpTd1", "M_EP_TD_1", "Event of protection equipment with time tag CP56Time2a",
     [SEP, ELAPSED, CP56], "CP{Data unit identifier,i(Information object address,SEP,CP16Time2a,CP56Time2a)}", 96, "seq", "event of protection equipment"),
    (31, "MEpTe1", "MEpTe1", "M_EP_TE_1", "Packed start events of protection equipment with time tag CP56Time2a",
     [SPE, QDP, ELAPSED, CP56], "CP{Data unit identifier,Information object address,SPE,QDP,CP16Time2a,CP56Time2a}", 97, "single", None),
    (32, "MEpTf1", "MEpTf1", "M_EP_TF_1", "Packed output circuit information of protection equipment with time tag CP56Time2a",
     [OCI, QDP, ELAPSED, CP56], "CP{Data unit identifier,Information object address,OCI,QDP,CP16Time2a,CP56Time2a}", 98, "single", None),
]

STUB = "--stub" in sys.argv

HEADER = '''//! The 32 monitor-direction ASDU types of IEC 60870-5-101:2003 clause 7.3.1.
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
    Bcr, Bsi, Cp16Time2a, Cp24Time2a, Cp56Time2a, Diq, Nva, Oci, Qdp, Qds, Scd, Sep, Siq, Spe, Sva,
    Vti, R32,
};
use crate::asdu::elements::{split_off, take};
use crate::asdu::{AsduError, TypeId};
'''


def emit(sub, variant, struct, asdu, title, fields, definition, page, kind, what):
    # The title names a time tag type, which rustdoc wants as code.
    doc_title = re.sub(r"\b(CP\d+Time2a)\b", r"`\1`", title)
    L = []
    L.append(f"/// `{asdu}`: {doc_title}, 5-101 clause")
    L.append(f"/// 7.3.1.{sub} (PDF page index {page}).")
    L.append("///")
    L.append("/// ```text")
    L.append(f"/// {asdu} := {definition}")
    L.append("/// ```")
    if kind == "seq":
        L.append("///")
        L.append("/// " + NO_SEQUENCE.format(what=what, sub=sub))
    if kind == "single":
        L.append("///")
        L.append("/// " + SINGLE_OBJECT)
    # R32 is an f32, so those three types cannot derive Eq.
    derives = "Debug, Clone, Copy, PartialEq" + ("" if any(t == "R32" for _, t in fields) else ", Eq")
    L.append(f"#[derive({derives})]")
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