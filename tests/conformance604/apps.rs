//! The controlled station's application for the procedure cases of Tables 12,
//! 22 and 24, and the hand-built frames those cases compare its answers with.
//!
//! [`ProcedureApp`] is glue, not protocol: every decision it forwards is made in
//! `src/`. `dispatch::route` names the procedure that owns a received ASDU;
//! `gi::Interrogation` answers a general interrogation; `ts::TestProcedure`
//! answers a test command; `dispatch::not_implemented` is clause 7.2.3's
//! cause-44 mirror for a basic application function no module serves. The
//! glue only hands the ASDU to the module the route names and returns what that
//! module says to send.
//!
//! The expected frames ([`gi_activation`], [`test_command`] and the octet
//! offsets beside them) are written out octet by octet from the 101 and 104
//! figures, so an assertion never compares the crate's output with the
//! crate's own builder.

use iec104::asdu::{
    AddressSizes, Cause, Header, Known, LayoutObject, MSpNa1, Siq, TypeId, encode_asdu,
};
use iec104::dispatch::{Route, not_implemented, route};
use iec104::gi::{DataSource, Interrogation, ReActivation, Reaction as GiReaction, Scope};
use iec104::ts::{Selection, TestProcedure};

use crate::conformance604::{CA, HELD_IOA, ORIGINATOR, StationApp};

/// The octet offset of the cause of transmission in an ASDU (5-101 clause 7.2,
/// figure 13: type identification, variable structure qualifier, then the
/// cause octet whose bit 7 is `P/N` and bit 8 is `T`).
pub const COT_OCTET: usize = 2;

/// The `P/N` bit of the cause octet, bit 7 (5-101 clause 7.2.3, index 38:
/// *"P/N := BS1[7] <0..1> <0> := positive confirm <1> := negative confirm"*).
pub const PN_BIT: u8 = 0x40;

/// The first octet of the information object area with the conventional
/// address profile: a 6-octet data unit identifier (104 clause 9: one-octet
/// originator address, two-octet common address).
pub const IOA_OCTET: usize = 6;

/// The controlled station's process image: one single point, ON, at
/// [`HELD_IOA`], returned for a station interrogation.
pub struct OnePoint;

impl DataSource for OnePoint {
    fn ready(&self, _scope: Scope) -> bool {
        true
    }

    fn interrogated(&self, scope: Scope, out: &mut Vec<Vec<u8>>) {
        if scope == Scope::Station {
            out.push(single_point(Cause::InterrogatedByStation));
        }
    }
}

/// One `M_SP_NA_1` (5-101 clause 7.3.1.1) at [`HELD_IOA`], ON, with `cause`:
/// the process image's one object, as an interrogation response or as a
/// spontaneous event.
pub fn single_point(cause: Cause) -> Vec<u8> {
    let header = Header {
        type_id: TypeId::MSpNa1,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator: ORIGINATOR,
        common_address: CA,
    };
    encode_asdu(
        &header,
        &[LayoutObject {
            ioa: HELD_IOA,
            value: MSpNa1 {
                siq: Siq {
                    spi: true,
                    ..Default::default()
                },
            },
        }],
    )
    .expect("the layout builds one single point")
}

/// The controlled station's application: the procedure `dispatch::route`
/// names for each received ASDU answers it.
pub struct ProcedureApp {
    gi: Interrogation,
    ts: TestProcedure,
}

impl ProcedureApp {
    /// A station that serves general interrogation (option 1 of Table 17's
    /// re-activation, a PIXIT the cases here never reach) and the test
    /// procedure with `test` as its 104 clause 9.6 selection.
    pub const fn new(test: Selection) -> Self {
        Self {
            gi: Interrogation::controlled(ReActivation::Continue, CA, ORIGINATOR),
            ts: TestProcedure::controlled(test, CA, ORIGINATOR),
        }
    }

    /// The ASDUs to send in answer to one received ASDU. Also called directly
    /// by the cases that drive a connection-level component rather than the
    /// single session of [`crate::conformance604::ControlledStation`].
    pub fn answer(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        let header = Header::parse(asdu).map_err(|e| format!("the ASDU header: {e:?}"))?;
        match route(&header) {
            Route::Interrogation => {
                let outcome = self
                    .gi
                    .on_request(asdu, &Known::EVERYTHING, &OnePoint)
                    .map_err(|e| format!("gi: {e:?}"))?;
                let mut send = outcome.send;
                if matches!(
                    outcome.reaction,
                    GiReaction::ActivationConfirmed {
                        negative: false,
                        ..
                    }
                ) {
                    send.extend(
                        self.gi
                            .complete(&OnePoint)
                            .map_err(|e| format!("gi: {e:?}"))?,
                    );
                }
                Ok(send)
            }
            Route::Test => Ok(self
                .ts
                .on_request(asdu, &Known::EVERYTHING)
                .map_err(|e| format!("ts: {e:?}"))?
                .send),
            Route::NotImplemented => {
                Ok(
                    not_implemented(&header, asdu, CA, AddressSizes::CONVENTIONAL)
                        .into_iter()
                        .collect(),
                )
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Drops the running interrogation: what `gi::Interrogation::reset` is for
    /// (the caller's connection loss).
    pub fn connection_lost(&mut self) {
        self.gi.reset();
    }
}

impl StationApp for ProcedureApp {
    fn on_asdu(&mut self, asdu: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.answer(asdu)
    }
}

/// `C_IC_NA_1` with cause `cause`, written out from 5-101 clause 7.3.4.1
/// (figure 72): type `100`, `SQ = 0` and `N = 1` (`01`), the cause
/// octet, originator [`ORIGINATOR`], common address [`CA`] low octet first
/// (clause 7.2.4), the irrelevant information object address `00 00 00`
/// (clause 7.2.5) and `QOI` 20, station interrogation (clause 7.2.6.22).
pub fn gi_frame(cause: u8) -> Vec<u8> {
    let [ca_lo, ca_hi] = CA.to_le_bytes();
    vec![100, 0x01, cause, ORIGINATOR, ca_lo, ca_hi, 0, 0, 0, 20]
}

/// The station interrogation's activation, [`gi_frame`] with cause `<6>`.
pub fn gi_activation() -> Vec<u8> {
    gi_frame(6)
}

/// `C_TS_TA_1` with cause `cause`, written out from 5-104 clause 8.8 (figure
/// 30, index 90): type `107`, `SQ = 0` and `N = 1`, the cause octet, originator
/// [`ORIGINATOR`], common address [`CA`], information object address
/// `00 00 00`, then `TSC := UI16[1..16]` low octet first and the seven
/// `CP56Time2a` octets `time`.
pub fn test_command(cause: u8, tsc: u16, time: [u8; 7]) -> Vec<u8> {
    let [ca_lo, ca_hi] = CA.to_le_bytes();
    let [tsc_lo, tsc_hi] = tsc.to_le_bytes();
    let mut asdu = vec![
        107, 0x01, cause, ORIGINATOR, ca_lo, ca_hi, 0, 0, 0, tsc_lo, tsc_hi,
    ];
    asdu.extend_from_slice(&time);
    asdu
}

/// A `CP56Time2a` (5-101 clause 7.2.6.18, index 52) written out octet by
/// octet: 2026-09-25 (a Friday), 12:34:56.789, standard time, valid. The
/// milliseconds field `56 789` is `0xDDD5`, low octet first; then minutes
/// `34`, hours `12`, day of month `25` with day of week `5` in bits 6..8
/// (`5 << 5 | 25` = `0xB9`), months `9`, years `26`.
pub const TIME: [u8; 7] = [0xD5, 0xDD, 34, 12, 0xB9, 9, 26];

/// The same instant one millisecond later (`0xDDD6`): a time that differs from
/// [`TIME`] in one octet only.
pub const TIME_PLUS_1MS: [u8; 7] = [0xD6, 0xDD, 34, 12, 0xB9, 9, 26];
