//! Cyclic transmission, the background scan and the acquisition of events:
//! the controlled station's three producers of monitor-direction ASDUs, plus
//! the double transmission of 104 clause 9.6.
//!
//! # The service rows
//!
//! 5-104 clause **7.3** (PDF page index 64, printed page 63) is headed *"Cyclic
//! data transmission (6.3 of IEC 60870-5-5)"* and its table is one primitive
//! pair: `A_CYCLIC_DATA.req` / `send` / `M CYCLIC` and `A_CYCLIC_DATA.ind` /
//! `receive` / `M CYCLIC`. Clause **7.4** on the same page is headed
//! *"Acquisition of events (6.4 of IEC 60870-5-5)"* and its table is
//! `A_EVENT.req` / `send` / `M SPONT` and `A_EVENT.ind` / `receive` /
//! `M SPONT`. `M` is any monitor-direction ASDU of 5-101 clause 7.3.1 and the
//! label's second word is its cause of transmission: `M CYCLIC` is cause `<1>`,
//! `M SPONT` cause `<3>`. 104 clause 7 has no service table for the background
//! scan.
//!
//! # The background scan (5-101 clause 7.4.13)
//!
//! 5-101 clause **7.4.13** (PDF page index 149, printed page 148):
//!
//! > The background scan is used to update process information from the
//! > controlled station to the controlling station as an additional safeguard
//! > to the station interrogation and spontaneous transmission procedures.
//! > ASDUs with the same type identification numbers as defined for the station
//! > interrogation procedure may be transmitted with cause of transmission
//! > `<2>` background scan on a low-priority continuous basis. The background
//! > scan is initiated by the controlled station and therefore independent from
//! > station interrogation commands. The transmission cycle is configured by
//! > fixed parameters in the controlled station. Measured values reported by
//! > periodic or cyclic transmission (COT = 1) are not usually reported as
//! > background scan (COT = 2), spontaneous (COT = 3) or station interrogation
//! > (COT = 20 to 36).
//!
//! The same page's **Table 21** names nine types, each with cause `<2>`:
//! [`BACKGROUND_TYPES`]. 104 carries the function only as a checkbox in its
//! interoperability list (clause **9.6**, PDF page index 114), so a 104 station
//! selects it and takes its type set from 101's Table 21.
//!
//! # The type set of each cause, and the send order
//!
//! 5-101 clauses **7.4.3** and **7.4.4** (PDF page index 122) select *"The
//! complete function"* of IEC 60870-5-5 6.3 and 6.4 and name no types. The
//! types come from **5-101 Table 16**, *"Respond priorities of the controlled
//! station"* (PDF page index 121, printed page 120):
//!
//! | Table 16 row | Cause |
//! | --- | --- |
//! | `9, 11, 13, 21` / `120 to 127`: *"Cyclic data transmission (in monitor direction with COT = 1), file transfer"* | `<1>` `per/cyc` |
//! | `1 to 44` / `103` / `106`: *"Event reporting / Clock synchronization / Acquisition of transmission delay"*, *"Event reporting: In monitor direction with COT = 3"* | `<3>` `spont` |
//!
//! The cyclic cause carries the four measured-value types ([`CYCLIC_TYPES`]);
//! `120 to 127` are the file-transfer types of [`crate::ft`] and are not built
//! here. The spontaneous cause carries the event row intersected with the
//! monitor types 104 clause 9 selects (PDF page index 100): see
//! [`is_spontaneous_type`].
//!
//! The table's order is also a send order: *"If a controlled station has data
//! for more than one of the following ASDU types ready for transmission at the
//! same time, they must be sent in the following order regardless of which data
//! was generated first."* Nothing in this module is scheduled, so that order is
//! the caller's to apply; [`respond_priority`] names the row of an ASDU.
//! `iec104-tokio`'s `server::Server` is such a caller: it queues what it sends
//! by that row.
//!
//! # No link classes
//!
//! 5-101 clause **7.4.2** (index 122) assigns cyclic ASDUs to link data class 2
//! and spontaneous ones to class 1. 104 clause **7.2** (index 64) removes the
//! classes: *"Request of user data class 1 and 2 are link functions of
//! IEC 60870-5-2 and therefore not available in this standard."* The *"low
//! priority continuous basis"* of the background scan is therefore a property
//! of the cause, not something this crate schedules. Clause 7.2's advice
//! against cyclic requests is about the read procedure ([`crate::rd`]), not
//! about clause 7.3's cyclic data transmission.
//!
//! # The double transmission
//!
//! 104 clause **9.6** (PDF page index 108, printed page 107), *"Double
//! transmission of information objects with cause of transmission
//! spontaneous"*:
//!
//! > The following type identifications may be transmitted in succession caused
//! > by a single status change of an information object. The particular
//! > information object addresses for which double transmission is enabled are
//! > defined in a project-specific list.
//!
//! It then lists seven type families, which are [`DoublePair`];
//! [`DoublePair::types`] is each bullet's own list. The addresses the project
//! enables are [`ProjectList`].
//!
//! The pairs are the standard's but the tag half is restricted: 104 clause
//! **9** (PDF page index 100, printed page 99) says *"In this companion
//! standard only the use of the set `<30>` – `<40>` for ASDUs with time tag is
//! permitted."* So the tagged half of a 104 double transmission is a
//! `CP56Time2a` type (`M_SP_TB_1` `<30>` and its siblings), never `M_SP_TA_1`
//! `<2>` or another `CP24Time2a` form. [`is_permitted_tag`] is that sentence,
//! and [`doubled`] refuses a pair whose tagged half is outside it
//! ([`TxError::TagNotPermitted`]). [`crate::ci`] excludes `M_IT_TA_1` `<16>`
//! from its responses by the same sentence.
//!
//! # The two roles
//!
//! The controlled station *produces* these ASDUs: it owns the process image,
//! and the background scan is *"initiated by the controlled station"*. The
//! controlling station *receives* them and only classifies which of the three
//! causes arrived. A cyclic, background or spontaneous ASDU answers nothing:
//! no confirmation is built and no originator echoed (5-101 clause 7.2.3's echo
//! rule is for a monitor-direction frame that answers a control-direction
//! one). The reception side runs 5-101 clause 7.2.3's discard rule first, as
//! the other procedure modules do, and keeps no state.
//!
//! # What is the caller's
//!
//! * **The scan cycles and the send order.** *"The transmission cycle is
//!   configured by fixed parameters in the controlled station."* Nothing here
//!   reads a clock, holds a timer or schedules anything. [`StationFunctions`]
//!   selects the functions the station uses (104 clause 9.6's checkboxes), and
//!   the [`Transmission`] producers refuse a function it does not use. The
//!   free builders such as [`cyclic`] do not consult it.
//! * **The process image.** The caller owns each typed monitor value (a layout
//!   struct of 5-101 clause 7.3.1, as [`crate::asdu::encode_asdu`] takes it)
//!   and its information object address.
//! * **The project-specific double-transmission list** and, for a received
//!   ASDU, the station's [`Known`] profile.
//!
//! # Example
//!
//! ```
//! use iec104::asdu::{
//!     Cause, Cp56Time2a, Header, Known, LayoutObject, MMeNa1, MSpNa1, Nva, Qds, Siq, TypeId,
//! };
//! use iec104::tx::{
//!     background, cyclic, doubled, spontaneous, DoublePair, ProjectList, Reaction,
//!     StationFunctions, Transmission,
//! };
//!
//! // A cyclic measured value: `M_ME_NA_1` is one of Table 16's cyclic types.
//! let value = MMeNa1 {
//!     nva: Nva { value: 0x2000 },
//!     qds: Qds::default(),
//! };
//! let frame = cyclic(&LayoutObject { ioa: 0x4001, value }, 12, 0).unwrap();
//! let header = Header::parse(&frame).unwrap();
//! assert_eq!(header.cause, Cause::Periodic);
//! assert_eq!(header.type_id, TypeId::MMeNa1);
//!
//! // The background scan is Table 21's nine types; `M_SP_NA_1` is one.
//! let sp = LayoutObject {
//!     ioa: 0x4001,
//!     value: MSpNa1 {
//!         siq: Siq::default(),
//!     },
//! };
//! let scan = background(&sp, 12, 0).unwrap();
//! assert_eq!(Header::parse(&scan).unwrap().cause, Cause::BackgroundScan);
//!
//! // A double transmission: the untagged ASDU first, its `<30>`–`<40>` twin
//! // second, the same value in both. This free builder does not check the
//! // project list; `Transmission::double` does.
//! let pair = doubled(&sp, Cp56Time2a::default(), 12, 0).unwrap();
//! assert_eq!(Header::parse(&pair[0]).unwrap().type_id, TypeId::MSpNa1);
//! assert_eq!(Header::parse(&pair[1]).unwrap().type_id, TypeId::MSpTb1);
//! assert_eq!(DoublePair::SinglePoint.untagged(), TypeId::MSpNa1);
//!
//! // The station-selection gates the producers, and the reception role
//! // classifies what arrives.
//! let station = Transmission::controlled(
//!     StationFunctions { cyclic: true, ..StationFunctions::NONE },
//!     ProjectList::new([0x4001]),
//!     12,
//!     0,
//! );
//! assert!(station.cyclic(&LayoutObject { ioa: 0x4001, value }).is_ok());
//! assert!(station.background(&sp).is_err());
//!
//! let listening = Transmission::controlling(12, 0);
//! assert_eq!(
//!     listening
//!         .on_response(&frame, &Known::EVERYTHING)
//!         .unwrap()
//!         .reaction,
//!     Reaction::Cyclic { type_id: TypeId::MMeNa1 }
//! );
//! assert_eq!(
//!     listening
//!         .on_response(
//!             &spontaneous(&sp, 12, 0).unwrap(),
//!             &Known::EVERYTHING,
//!         )
//!         .unwrap()
//!         .reaction,
//!     Reaction::Spontaneous { type_id: TypeId::MSpNa1 }
//! );
//! ```

use crate::apci::MAX_ASDU;
use crate::asdu::{
    AddressSizes, AsduError, AsduLayout, BodyReader, Cause, Cp56Time2a, Discard, Header, Known,
    LayoutError, LayoutObject, MBoNa1, MBoTb1, MDpNa1, MDpTb1, MMeNa1, MMeNb1, MMeNc1, MMeTd1,
    MMeTe1, MMeTf1, MSpNa1, MSpTb1, MStNa1, MStTb1, TypeId, discard_reason, element_len,
    encode_asdu_with,
};

/// `<1> periodic, cyclic`: the cause of every frame [`cyclic`] and
/// [`Transmission::cyclic`] build (5-104 clause 7.3's `M CYCLIC` row, PDF page
/// index 64; 5-101 Table 16's cyclic row, index 121).
pub const CAUSE_PERIODIC: Cause = Cause::Periodic;

/// `<2> background scan`: the cause of every frame [`background`] and
/// [`Transmission::background`] build (5-101 clause 7.4.13, PDF page index 149,
/// and its Table 21).
pub const CAUSE_BACKGROUND: Cause = Cause::BackgroundScan;

/// `<3> spontaneous`.
///
/// The cause of every frame [`spontaneous`], [`Transmission::spontaneous`] and
/// both halves of [`doubled`] build (5-104 clause 7.4's `M SPONT` row, PDF page
/// index 64; 5-101 Table 16's event row, index 121).
pub const CAUSE_SPONTANEOUS: Cause = Cause::Spontaneous;

/// The four type identifications Table 16's cyclic row lists, `9, 11, 13, 21`.
///
/// They are `M_ME_NA_1`, `M_ME_NB_1`, `M_ME_NC_1` and `M_ME_ND_1` (5-101
/// Table 16, PDF page index 121, printed page 120: *"911, 13, 21 / 120 to 127 |
/// Cyclic data transmission (in monitor direction with COT = 1), file
/// transfer"*).
///
/// The row's other half, `120 to 127`, is the file-transfer set of 5-101
/// clause 7.3.6 and 104's `F_SC_NB_1`, which [`crate::ft`] builds with its own
/// causes; the cyclic builders here refuse it.
pub const CYCLIC_TYPES: [TypeId; 4] = [
    TypeId::MMeNa1,
    TypeId::MMeNb1,
    TypeId::MMeNc1,
    TypeId::MMeNd1,
];

/// The nine type identifications of 5-101 **Table 21**.
///
/// Table 21 is *"Type identifications for background scan"* (clause 7.4.13, PDF
/// page index 149, printed page 148). In the table's own order: `M_SP_NA_1`,
/// `M_DP_NA_1`, `M_ST_NA_1`, `M_BO_NA_1`, `M_ME_NA_1`, `M_ME_NB_1`,
/// `M_ME_NC_1`, `M_PS_NA_1`, `M_ME_ND_1`, each with cause `<2>`. The clause
/// says the same in prose (*"ASDUs with the same type identification numbers as
/// defined for the station interrogation procedure may be transmitted with
/// cause of transmission `<2>` background scan"*), which is why
/// [`crate::gi::INTERROGATED_TYPES`] holds the same nine names.
pub const BACKGROUND_TYPES: [TypeId; 9] = [
    TypeId::MSpNa1,
    TypeId::MDpNa1,
    TypeId::MStNa1,
    TypeId::MBoNa1,
    TypeId::MMeNa1,
    TypeId::MMeNb1,
    TypeId::MMeNc1,
    TypeId::MPsNa1,
    TypeId::MMeNd1,
];

/// The low end of Table 16's event row, *"1 to 44"* (5-101 Table 16, PDF page
/// index 121).
///
/// 5-101 clause 7.3.1's process types run 1 to 40; 41 to 44 are
/// reserved numbers the range covers and table 8 does not name. A 104 station
/// narrows the range with clause 9's selection: see [`is_spontaneous_type`].
pub const SPONTANEOUS_MIN: u8 = 1;

/// The high end of Table 16's event row (*"1 to 44"*); see [`SPONTANEOUS_MIN`].
pub const SPONTANEOUS_MAX: u8 = 44;

/// The eleven `CP24Time2a` monitor forms 104 clause 9 strikes out of the
/// monitor-direction type list (PDF page index 100, printed page 99).
///
/// They are `<2>`
/// `M_SP_TA_1`, `<4>` `M_DP_TA_1`, `<6>` `M_ST_TA_1`, `<8>` `M_BO_TA_1`, `<10>`
/// `M_ME_TA_1`, `<12>` `M_ME_TB_1`, `<14>` `M_ME_TC_1`, `<16>` `M_IT_TA_1`,
/// `<17>` `M_EP_TA_1`, `<18>` `M_EP_TB_1` and `<19>` `M_EP_TC_1`.
///
/// They are inside 5-101 Table 16's event row `1 to 44`, so a 101 station may
/// report them spontaneously but a 104 station may not.
///
/// The list is over the **wire octet**, like the range it narrows, so the
/// unnamed `TypeId::Other(2)` answers as `TypeId::MSpTa1` does.
pub const SPONTANEOUS_EXCLUDED_OCTETS: [u8; 11] = [2, 4, 6, 8, 10, 12, 14, 16, 17, 18, 19];

// Table 16's event row also names `<103>` `C_CS_NA_1` and `<106>` `C_CD_NA_1`
// outside `1 to 44`. Neither is a spontaneous type in 104: clause 9 (PDF page
// index 100, printed page 99) strikes `<106>` from the type list, and draws the
// `<103>`/cause `3` box black ([`crate::interop::SHEET`]), in line with clause
// 7.6, whose service table names only `C_CS ACT` and `C_CS ACTCON`. The
// spontaneous clock time of TS 60870-5-604 is [`crate::cs`]'s own path.

/// Whether `type_id` is one the spontaneous cause carries in 104.
///
/// That is Table 16's event row `1 to 44` (5-101 Table 16, PDF page index 121),
/// **intersected with what 104 clause 9 permits** (index 100). The `CP24Time2a`
/// forms of [`SPONTANEOUS_EXCLUDED_OCTETS`] answer `false`, and so do the row's
/// two control types, `<103>` and `<106>`: clause 9 permits neither with
/// cause 3.
///
/// The test is over the type's **wire octet**, so an unnamed [`TypeId::Other`]
/// of a named octet answers exactly as the named variant does, and a reserved
/// number inside `1..=44` (41 to 44) answers `true` as the table words it. The
/// caller's [`Known`] decides whether an arrival of such a number is something
/// to process.
#[must_use]
pub fn is_spontaneous_type(type_id: TypeId) -> bool {
    let octet = type_id.to_u8();
    if SPONTANEOUS_EXCLUDED_OCTETS.contains(&octet) {
        return false;
    }
    (SPONTANEOUS_MIN..=SPONTANEOUS_MAX).contains(&octet)
}

/// One of the three functions 104 clause 9.6's checkboxes select and this
/// module's producers serve (PDF page index 114).
///
/// Each function corresponds to exactly one cause of transmission
/// ([`Function::cause`], [`Function::of_cause`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Function {
    /// Cyclic data transmission: cause `<1>`, Table 16's cyclic row.
    Cyclic,
    /// The background scan: cause `<2>`, 5-101 clause 7.4.13 and its Table 21.
    Background,
    /// Spontaneous transmission: cause `<3>`, Table 16's event row.
    Spontaneous,
}

impl Function {
    /// The three functions, in cause order.
    pub const ALL: [Self; 3] = [Self::Cyclic, Self::Background, Self::Spontaneous];

    /// The cause of transmission this function's ASDUs carry.
    #[must_use]
    pub const fn cause(self) -> Cause {
        match self {
            Self::Cyclic => CAUSE_PERIODIC,
            Self::Background => CAUSE_BACKGROUND,
            Self::Spontaneous => CAUSE_SPONTANEOUS,
        }
    }

    /// The function whose cause of transmission is `cause`, or `None` for a
    /// cause other than `<1>`, `<2>` and `<3>`.
    #[must_use]
    pub const fn of_cause(cause: Cause) -> Option<Self> {
        match cause {
            Cause::Periodic => Some(Self::Cyclic),
            Cause::BackgroundScan => Some(Self::Background),
            Cause::Spontaneous => Some(Self::Spontaneous),
            _ => None,
        }
    }

    /// The standard's mnemonic for the function's cause (`per/cyc`, `back`,
    /// `spont`).
    #[must_use]
    pub fn mnemonic(self) -> &'static str {
        self.cause().mnemonic()
    }

    /// Whether this function's table carries `type_id`: Table 16's cyclic row
    /// ([`CYCLIC_TYPES`]), Table 21 ([`BACKGROUND_TYPES`]) or Table 16's event
    /// row ([`is_spontaneous_type`]).
    #[must_use]
    pub fn carries(self, type_id: TypeId) -> bool {
        match self {
            Self::Cyclic => CYCLIC_TYPES.contains(&type_id),
            Self::Background => BACKGROUND_TYPES.contains(&type_id),
            Self::Spontaneous => is_spontaneous_type(type_id),
        }
    }
}

/// [`Function::of_cause`] as a `Result`, for a caller that holds a cause and
/// expects one of the three: a different cause is [`TxError::NotOurCause`].
///
/// # Errors
///
/// [`TxError::NotOurCause`] when `cause` names none of the three functions.
pub fn function_of(cause: Cause) -> Result<Function, TxError> {
    Function::of_cause(cause).ok_or(TxError::NotOurCause { cause })
}

/// Which of the three functions a station uses.
///
/// These are 104 clause 9.6's three checkboxes (PDF page index 114), each
/// *"(station-specific parameter, mark `X` if function is only used in the
/// standard direction, `R` if only used in the reverse direction, and `B` if
/// used in both directions)"*.
///
/// The value carries one direction's answer: a station holds an instance per
/// direction, as the procedure roles of [`crate::gi`] to [`crate::pm`] do.
/// Every producer refuses a function this value does not select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StationFunctions {
    /// Cause `<1>`: cyclic data transmission.
    pub cyclic: bool,
    /// Cause `<2>`: the background scan.
    pub background: bool,
    /// Cause `<3>`: spontaneous transmission.
    pub spontaneous: bool,
}

impl StationFunctions {
    /// No function selected: the station produces none of the three.
    pub const NONE: Self = Self {
        cyclic: false,
        background: false,
        spontaneous: false,
    };

    /// All three selected: the 101 selection, whose clauses 7.4.3 and 7.4.4
    /// each say *"The complete function … is used."*
    pub const ALL: Self = Self {
        cyclic: true,
        background: true,
        spontaneous: true,
    };

    /// Whether `function` is selected.
    #[must_use]
    pub const fn uses(self, function: Function) -> bool {
        match function {
            Function::Cyclic => self.cyclic,
            Function::Background => self.background,
            Function::Spontaneous => self.spontaneous,
        }
    }

    /// The same selection with `function` set to `used`.
    #[must_use]
    pub const fn with(self, function: Function, used: bool) -> Self {
        match function {
            Function::Cyclic => Self {
                cyclic: used,
                ..self
            },
            Function::Background => Self {
                background: used,
                ..self
            },
            Function::Spontaneous => Self {
                spontaneous: used,
                ..self
            },
        }
    }

    /// How many of the three functions are selected.
    #[must_use]
    pub fn count(self) -> usize {
        Function::ALL
            .into_iter()
            .filter(|function| self.uses(*function))
            .count()
    }
}

impl Default for StationFunctions {
    /// [`StationFunctions::NONE`]: a station that has not said which functions
    /// it uses uses none.
    fn default() -> Self {
        Self::NONE
    }
}

/// One of the seven information-object families in 104 clause 9.6's
/// double-transmission list (PDF page index 108, printed page 107).
///
/// Each family is a bullet of type names in the clause and a pair in the
/// procedure: a type without time and its corresponding type with time.
/// [`DoublePair::types`] is the bullet; [`DoublePair::untagged`] and
/// [`DoublePair::tagged`] are the pair, and the tagged member is always inside
/// 104 clause 9's permitted set `<30>` to `<40>` ([`is_permitted_tag`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DoublePair {
    /// *"Single-point information `M_SP_NA_1`, `M_SP_TA_1`, `M_SP_TB_1` and
    /// `M_PS_NA_1`"*. The bullet names an extra untagged member, `M_PS_NA_1`
    /// (type 20), which has no time-tagged type in `<30>` to `<40>` and so is
    /// not paired.
    SinglePoint,
    /// *"Double-point information `M_DP_NA_1`, `M_DP_TA_1` and `M_DP_TB_1`"*.
    DoublePoint,
    /// *"Step position information `M_ST_NA_1`, `M_ST_TA_1` and `M_ST_TB_1`"*.
    StepPosition,
    /// *"Bitstring of 32 bit `M_BO_NA_1`, `M_BO_TA_1` and `M_BO_TB_1` (if defined
    /// for a specific project)"*. The project decision is expressed through
    /// [`ProjectList`].
    Bitstring,
    /// *"Measured value, normalized value `M_ME_NA_1`, `M_ME_TA_1`, `M_ME_ND_1`
    /// and `M_ME_TD_1`"*. The extra untagged member `M_ME_ND_1` (type 21) has
    /// no [`Doubles`] implementation: its tagged twin `M_ME_TD_1` carries a
    /// `QDS` the untagged frame does not, so a station that tags it supplies
    /// the quality itself.
    MeasuredNormalized,
    /// *"Measured value, scaled value `M_ME_NB_1`, `M_ME_TB_1` and `M_ME_TE_1`"*.
    MeasuredScaled,
    /// *"Measured value, short floating point number `M_ME_NC_1`, `M_ME_TC_1` and
    /// `M_ME_TF_1`"*.
    MeasuredFloat,
}

impl DoublePair {
    /// The seven families, in the clause's own order.
    pub const ALL: [Self; 7] = [
        Self::SinglePoint,
        Self::DoublePoint,
        Self::StepPosition,
        Self::Bitstring,
        Self::MeasuredNormalized,
        Self::MeasuredScaled,
        Self::MeasuredFloat,
    ];

    /// The clause's own bullet for this family: every type name the bullet
    /// prints, including the `CP24Time2a` members 104 clause 9 (page index 100)
    /// removes from a 104 station's pairs.
    #[must_use]
    pub const fn types(self) -> &'static [TypeId] {
        match self {
            Self::SinglePoint => &[
                TypeId::MSpNa1,
                TypeId::MSpTa1,
                TypeId::MSpTb1,
                TypeId::MPsNa1,
            ],
            Self::DoublePoint => &[TypeId::MDpNa1, TypeId::MDpTa1, TypeId::MDpTb1],
            Self::StepPosition => &[TypeId::MStNa1, TypeId::MStTa1, TypeId::MStTb1],
            Self::Bitstring => &[TypeId::MBoNa1, TypeId::MBoTa1, TypeId::MBoTb1],
            Self::MeasuredNormalized => &[
                TypeId::MMeNa1,
                TypeId::MMeTa1,
                TypeId::MMeNd1,
                TypeId::MMeTd1,
            ],
            Self::MeasuredScaled => &[TypeId::MMeNb1, TypeId::MMeTb1, TypeId::MMeTe1],
            Self::MeasuredFloat => &[TypeId::MMeNc1, TypeId::MMeTc1, TypeId::MMeTf1],
        }
    }

    /// The pair's member **without** a time tag: the frame that goes out
    /// first.
    #[must_use]
    pub const fn untagged(self) -> TypeId {
        match self {
            Self::SinglePoint => TypeId::MSpNa1,
            Self::DoublePoint => TypeId::MDpNa1,
            Self::StepPosition => TypeId::MStNa1,
            Self::Bitstring => TypeId::MBoNa1,
            Self::MeasuredNormalized => TypeId::MMeNa1,
            Self::MeasuredScaled => TypeId::MMeNb1,
            Self::MeasuredFloat => TypeId::MMeNc1,
        }
    }

    /// The pair's member **with** a `CP56Time2a` tag: the frame that goes out
    /// second, and one of 104 clause 9's permitted set `<30>` to `<40>` (page
    /// index 100).
    #[must_use]
    pub const fn tagged(self) -> TypeId {
        match self {
            Self::SinglePoint => TypeId::MSpTb1,
            Self::DoublePoint => TypeId::MDpTb1,
            Self::StepPosition => TypeId::MStTb1,
            Self::Bitstring => TypeId::MBoTb1,
            Self::MeasuredNormalized => TypeId::MMeTd1,
            Self::MeasuredScaled => TypeId::MMeTe1,
            Self::MeasuredFloat => TypeId::MMeTf1,
        }
    }

    /// The family `type_id` belongs to, or `None` for a type outside the
    /// clause's seven bullets. A tagged member answers its own family, so
    /// `M_SP_TB_1` is [`DoublePair::SinglePoint`] as `M_SP_NA_1` is.
    #[must_use]
    pub fn of_type(type_id: TypeId) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|pair| pair.types().contains(&type_id))
    }

    /// The clause's name for the family, for a log line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SinglePoint => "single-point information",
            Self::DoublePoint => "double-point information",
            Self::StepPosition => "step position information",
            Self::Bitstring => "bitstring of 32 bit",
            Self::MeasuredNormalized => "measured value, normalized value",
            Self::MeasuredScaled => "measured value, scaled value",
            Self::MeasuredFloat => "measured value, short floating point number",
        }
    }
}

/// Whether a tagged type identification is inside 104 clause 9's permitted set
/// `<30>` to `<40>`.
///
/// 104 clause 9 (PDF page index 100, printed page 99): *"In this companion
/// standard only the use of the set `<30>` – `<40>` for ASDUs with time tag is
/// permitted."*
///
/// The test is over the type's **wire octet**. It answers `true` for every
/// `CP56Time2a` monitor form of 5-101 clause 7.3.1 (`<30>` `M_SP_TB_1` to
/// `<40>` `M_EP_TF_1`, including the integrated totals and protection-event
/// types) and `false` for the `CP24Time2a` forms `<2>` to `<19>`, which a 104
/// station may not send.
#[must_use]
pub fn is_permitted_tag(type_id: TypeId) -> bool {
    (TypeId::MSpTb1.to_u8()..=40).contains(&type_id.to_u8())
}

/// One pair's value carried twice: the untagged monitor value of 5-101 clause
/// 7.3.1 and the same value as its time-tagged twin.
///
/// The tagged frame is built **from** the untagged one, with the caller
/// supplying only the time tag, so [`doubled`] guarantees both frames carry
/// the same value (clause 9.6's *"single status change"*). Its implementations
/// are the seven pairs' untagged members: `M_SP_NA_1`, `M_DP_NA_1`,
/// `M_ST_NA_1`, `M_BO_NA_1`, `M_ME_NA_1`, `M_ME_NB_1`, `M_ME_NC_1`.
pub trait Doubles: crate::asdu::AsduLayout {
    /// The pair's tagged member.
    type Tagged: crate::asdu::AsduLayout;
    /// The family this type is the untagged member of.
    const PAIR: DoublePair;
    /// The same value with `time` as its `CP56Time2a` tag.
    fn doubled(&self, time: Cp56Time2a) -> Self::Tagged;
}

impl Doubles for MSpNa1 {
    type Tagged = MSpTb1;
    const PAIR: DoublePair = DoublePair::SinglePoint;

    fn doubled(&self, time: Cp56Time2a) -> MSpTb1 {
        MSpTb1 {
            siq: self.siq,
            time,
        }
    }
}

impl Doubles for MDpNa1 {
    type Tagged = MDpTb1;
    const PAIR: DoublePair = DoublePair::DoublePoint;

    fn doubled(&self, time: Cp56Time2a) -> MDpTb1 {
        MDpTb1 {
            diq: self.diq,
            time,
        }
    }
}

impl Doubles for MStNa1 {
    type Tagged = MStTb1;
    const PAIR: DoublePair = DoublePair::StepPosition;

    fn doubled(&self, time: Cp56Time2a) -> MStTb1 {
        MStTb1 {
            vti: self.vti,
            qds: self.qds,
            time,
        }
    }
}

impl Doubles for MBoNa1 {
    type Tagged = MBoTb1;
    const PAIR: DoublePair = DoublePair::Bitstring;

    fn doubled(&self, time: Cp56Time2a) -> MBoTb1 {
        MBoTb1 {
            bsi: self.bsi,
            qds: self.qds,
            time,
        }
    }
}

impl Doubles for MMeNa1 {
    type Tagged = MMeTd1;
    const PAIR: DoublePair = DoublePair::MeasuredNormalized;

    fn doubled(&self, time: Cp56Time2a) -> MMeTd1 {
        MMeTd1 {
            nva: self.nva,
            qds: self.qds,
            time,
        }
    }
}

impl Doubles for MMeNb1 {
    type Tagged = MMeTe1;
    const PAIR: DoublePair = DoublePair::MeasuredScaled;

    fn doubled(&self, time: Cp56Time2a) -> MMeTe1 {
        MMeTe1 {
            sva: self.sva,
            qds: self.qds,
            time,
        }
    }
}

impl Doubles for MMeNc1 {
    type Tagged = MMeTf1;
    const PAIR: DoublePair = DoublePair::MeasuredFloat;

    fn doubled(&self, time: Cp56Time2a) -> MMeTf1 {
        MMeTf1 {
            r32: self.r32,
            qds: self.qds,
            time,
        }
    }
}

/// The information object addresses a project enables double transmission
/// for.
///
/// 104 clause 9.6: *"The particular information object addresses for
/// which double transmission is enabled are defined in a project-specific
/// list."* (PDF page index 108).
///
/// The default is the empty list: a station doubles nothing unless the caller
/// hands in its project's list, as with [`crate::gi`]'s group membership.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProjectList {
    addresses: Vec<u32>,
}

impl ProjectList {
    /// A list of the given information object addresses.
    pub fn new(addresses: impl IntoIterator<Item = u32>) -> Self {
        Self {
            addresses: addresses.into_iter().collect(),
        }
    }

    /// The empty list: no object is doubled.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            addresses: Vec::new(),
        }
    }

    /// The listed addresses, in the order they were given.
    #[must_use]
    pub fn addresses(&self) -> &[u32] {
        &self.addresses
    }

    /// Whether `ioa` is enabled for double transmission.
    #[must_use]
    pub fn contains(&self, ioa: u32) -> bool {
        self.addresses.contains(&ioa)
    }

    /// How many addresses the list holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Whether the list is empty, so the station uses no double transmission.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

/// Which side of the procedure a [`Transmission`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The controlled station: it owns the process image and produces the
    /// ASDUs (5-101 clause 7.4.13: the background scan *"is initiated by the
    /// controlled station"*).
    Controlled,
    /// The side that receives them: classification only, no state and no
    /// answers.
    Controlling,
}

/// What one received frame means to the controlling station.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reaction {
    /// A cyclic ASDU arrived (cause `<1>`) carrying one of Table 16's cyclic
    /// types.
    Cyclic {
        /// The type identification it carried.
        type_id: TypeId,
    },
    /// A background-scan ASDU arrived (cause `<2>`) carrying one of Table 21's
    /// nine types.
    BackgroundScanned {
        /// The type identification it carried.
        type_id: TypeId,
    },
    /// A spontaneous ASDU arrived (cause `<3>`) carrying a type
    /// [`is_spontaneous_type`] accepts. A spontaneous `<103>` is not one of
    /// them; [`crate::cs`] handles the clock announcement.
    Spontaneous {
        /// The type identification it carried.
        type_id: TypeId,
    },
    /// 5-101 clause 7.2.3 says this ASDU is discarded and may be logged.
    Discard(Discard),
    /// Not this module's: the cause is not one of the three, or the type is
    /// not one that cause's table carries (a `M_IT_NA_1` with cause `<2>`, a
    /// `<30>`-tagged type with cause `<1>`).
    Other,
}

/// What a received ASDU means, and what to send because of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The classification of the received ASDU.
    pub reaction: Reaction,
    /// The ASDUs to send, in order. **Always empty here**: none of the three
    /// causes answers anything, so no confirmation, termination or echo is
    /// built.
    pub send: Vec<Vec<u8>>,
}

/// What can go wrong in this layer, over and above the codec's own errors.
///
/// Every variant names a rule of the standard that the call would have broken.
/// The standard defines no refusal frame for these three causes (they are the
/// controlled station's own initiative), so a received frame that does not fit
/// is [`Reaction::Other`], not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    /// The entry point does not belong to this instance's role: the producers
    /// are the controlled station's, `on_response` the controlling station's.
    WrongRole,
    /// The cause is not one of the three this module handles (5-104 clauses 7.3
    /// and 7.4, 5-101 clause 7.4.13).
    NotOurCause {
        /// The cause offered.
        cause: Cause,
    },
    /// The station's [`StationFunctions`] does not select this function (104
    /// clause 9.6's checkbox is not marked).
    FunctionNotUsed {
        /// The cause of the function the station does not use.
        cause: Cause,
    },
    /// The type is not one the cause's table carries: Table 16's cyclic row for
    /// cause `<1>` (the four measured-value types), Table 21 for cause `<2>`
    /// (the nine), Table 16's event row for cause `<3>` as
    /// [`is_spontaneous_type`] narrows it.
    CauseTypeNotAllowed {
        /// The type offered.
        type_id: TypeId,
        /// The cause whose table does not carry it.
        cause: Cause,
    },
    /// The untagged type is not one of 104 clause 9.6's seven
    /// double-transmission families (its bullet list, page index 108).
    NotADoublePair {
        /// The type offered.
        type_id: TypeId,
    },
    /// The pair's tagged half is outside 104 clause 9's permitted set
    /// `<30>` to `<40>` (page index 100), such as a `CP24Time2a` twin like
    /// `M_SP_TA_1` `<2>`.
    TagNotPermitted {
        /// The tagged type the pair would have used.
        type_id: TypeId,
    },
    /// The information object address is not on the station's project list for
    /// double transmission (clause 9.6's *"project-specific list"*).
    DoubleNotEnabled {
        /// The address the object carries.
        ioa: u32,
    },
    /// The ASDU itself could not be parsed; the layout/header layer's error,
    /// unchanged.
    Layout(LayoutError),
}

impl From<LayoutError> for TxError {
    fn from(err: LayoutError) -> Self {
        Self::Layout(err)
    }
}

impl From<AsduError> for TxError {
    /// The codec error reaches this layer through the layout layer's own
    /// wrapper, exactly as [`crate::asdu::decode_asdu`] surfaces it.
    fn from(err: AsduError) -> Self {
        Self::Layout(LayoutError::Asdu(err))
    }
}

/// Builds one monitor ASDU of a type's own elements: `N = 1`, `SQ = 0` and
/// `P/N = 0`, with `cause` and the addressing as given.
fn frame<A: crate::asdu::AsduLayout>(
    cause: Cause,
    object: &LayoutObject<A>,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, LayoutError> {
    let header = Header {
        type_id: A::TYPE_ID,
        sequence: false,
        count: 1,
        cause,
        negative: false,
        test: false,
        originator,
        common_address,
    };
    encode_asdu_with(&header, std::slice::from_ref(object), sizes)
}

/// Packs `objects` of one type and cause into as few `SQ = 0` ASDUs as fit,
/// each filled up to, and not beyond, the 249-octet ASDU in order. `P/N = 0`;
/// no ASDU for an empty slice.
///
/// 5-101 clause 7.2.2.1, `SQ = 0`: *"The ASDU may consist of one or more than
/// one equal INFORMATION OBJECTs. The number N is binary coded and defines the
/// number of the INFORMATION OBJECTs."* N is `UI7[1..7]<0..127>`, so an ASDU
/// carries at most 127 objects however short they are. The octet budget is
/// 5-104 clause 5's 249 less the profile's header
/// ([`AddressSizes::max_body`]). TS 60870-5-604 5.4.14.1 and 5.4.16.1 (PDF
/// page indices 61 and 63) require the controlled station to send data of
/// *"the same Type, COT and priority but with gaps in their addresses as a Set
/// of Information elements (SQ:=0) in one single ASDU, filled up to but not
/// exceeding the maximum configured ASDU or APDU length"*.
fn frames<A: crate::asdu::AsduLayout>(
    cause: Cause,
    objects: &[LayoutObject<A>],
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<Vec<u8>>, LayoutError> {
    const MAX_OBJECTS: usize = 127;
    let object_len = usize::from(sizes.information_object_address_octets()).saturating_add(A::LEN);
    let per_asdu = sizes
        .max_body()
        .checked_div(object_len)
        .unwrap_or(0)
        .clamp(1, MAX_OBJECTS);
    objects
        .chunks(per_asdu)
        .map(|chunk| {
            let header = Header {
                type_id: A::TYPE_ID,
                sequence: false,
                // A chunk holds at most MAX_OBJECTS, so the fallback is never taken.
                count: u8::try_from(chunk.len()).unwrap_or(u8::MAX),
                cause,
                negative: false,
                test: false,
                originator,
                common_address,
            };
            encode_asdu_with(&header, chunk, sizes)
        })
        .collect()
}

/// Appends the information objects of `next` to `asdu` when one ASDU may
/// carry both, and says whether it did; `asdu` is left as it was otherwise.
///
/// TS 60870-5-604 5.4.16.1 (PDF page index 63): *"The Controlled station
/// transmits events of the same Type, COT and priority but with gaps in their
/// addresses as a Set of Information elements (SQ:=0) in one single ASDU,
/// filled until the maximum configured ASDU or ADPU length as in the PICS"*.
/// So both must be `SQ = 0` ASDUs (5-101 cl.7.2.2.1) of the same type, cause,
/// P/N and test bits, originator and common address (the priority of 5-101
/// Table 16 follows from type and cause), with no more than 127 objects
/// together (N is `UI7`) and no more than the 249 octets of 5-104 clause 5.
/// Both must decode in `sizes`, so the result does too.
///
/// One rule is this crate's own: an address already in `asdu` is not
/// appended again. The standard allows it, but a controlling station that
/// takes an ASDU as a set of values would keep only one of the two, so a
/// repeated address starts a new ASDU and every value is seen.
pub fn append_objects(asdu: &mut Vec<u8>, next: &[u8], sizes: AddressSizes) -> bool {
    const MAX_OBJECTS: usize = 127;
    let (Ok(head), Ok(tail)) = (
        Header::parse_with(asdu, sizes),
        Header::parse_with(next, sizes),
    ) else {
        return false;
    };
    let same = (
        head.type_id,
        head.cause,
        head.negative,
        head.test,
        head.originator,
        head.common_address,
    ) == (
        tail.type_id,
        tail.cause,
        tail.negative,
        tail.test,
        tail.originator,
        tail.common_address,
    );
    if !same || head.sequence || tail.sequence {
        return false;
    }
    let Some(count) = head
        .count
        .checked_add(tail.count)
        .filter(|&count| usize::from(count) <= MAX_OBJECTS)
    else {
        return false;
    };
    let Some((_, objects)) = next.split_at_checked(sizes.header_len()) else {
        return false;
    };
    if asdu.len().saturating_add(objects.len()) > MAX_ASDU {
        return false;
    }
    let (Ok(have), Ok(add)) = (
        crate::asdu::decode_with(asdu, sizes),
        crate::asdu::decode_with(next, sizes),
    ) else {
        return false;
    };
    let have = have.objects.points();
    if add
        .objects
        .points()
        .iter()
        .any(|p| have.iter().any(|q| q.ioa == p.ioa))
    {
        return false;
    }
    asdu.extend_from_slice(objects);
    // The variable structure qualifier is the second octet: SQ (0) and N.
    if let Some(qualifier) = asdu.get_mut(1) {
        *qualifier = count;
    }
    true
}

/// Refuses a type outside the cause's own table.
fn require(function: Function, type_id: TypeId) -> Result<(), TxError> {
    if function.carries(type_id) {
        Ok(())
    } else {
        Err(TxError::CauseTypeNotAllowed {
            type_id,
            cause: function.cause(),
        })
    }
}

/// Builds one cyclic ASDU (cause `<1>`): 5-104 clause 7.3's `M CYCLIC`
/// (PDF page index 64), built from the typed monitor value the caller holds.
///
/// The type must be one of [`CYCLIC_TYPES`], the four of 5-101 Table 16's
/// cyclic row (page index 121); the file-transfer numbers the same row names
/// belong to [`crate::ft`] and are refused here. The information object
/// address, the common address and the originator are the caller's.
///
/// This free builder does not consult [`StationFunctions`];
/// [`Transmission::cyclic`] does.
///
/// # Errors
///
/// [`TxError::CauseTypeNotAllowed`] when the type is not [`CYCLIC_TYPES`], and
/// [`TxError::Layout`] when the frame cannot be encoded.
pub fn cyclic<A: crate::asdu::AsduLayout>(
    object: &LayoutObject<A>,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, TxError> {
    cyclic_with(
        object,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`cyclic`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`cyclic`].
pub fn cyclic_with<A: crate::asdu::AsduLayout>(
    object: &LayoutObject<A>,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, TxError> {
    require(Function::Cyclic, A::TYPE_ID)?;
    Ok(frame(
        CAUSE_PERIODIC,
        object,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds one background-scan ASDU (cause `<2>`): 5-101 clause 7.4.13 and
/// **Table 21** (PDF page index 149), built from the typed monitor value the
/// caller holds.
///
/// The type must be one of [`BACKGROUND_TYPES`], Table 21's nine, which are
/// the same nine names 5-101 clause 7.4.5 lists for a station-interrogation
/// response ([`crate::gi::INTERROGATED_TYPES`]). All nine are untagged.
///
/// # Errors
///
/// [`TxError::CauseTypeNotAllowed`] when the type is not [`BACKGROUND_TYPES`],
/// and [`TxError::Layout`] when the frame cannot be encoded.
pub fn background<A: crate::asdu::AsduLayout>(
    object: &LayoutObject<A>,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, TxError> {
    background_with(
        object,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`background`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`background`].
pub fn background_with<A: crate::asdu::AsduLayout>(
    object: &LayoutObject<A>,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, TxError> {
    require(Function::Background, A::TYPE_ID)?;
    Ok(frame(
        CAUSE_BACKGROUND,
        object,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds one spontaneous ASDU (cause `<3>`): 5-104 clause 7.4's `M SPONT`
/// (PDF page index 64), built from the typed monitor value the caller holds.
///
/// The type must be one Table 16's event row carries (page index 121) as 104
/// clause 9 (index 100) narrows it: a 5-101 process type in `1..=44` that
/// clause 9 does not strike out. See [`is_spontaneous_type`]; the spontaneous
/// clock time is [`crate::cs::announcement`], not this.
///
/// # Errors
///
/// [`TxError::CauseTypeNotAllowed`] when the type is not one
/// [`is_spontaneous_type`] accepts, and [`TxError::Layout`] when the frame
/// cannot be encoded.
pub fn spontaneous<A: crate::asdu::AsduLayout>(
    object: &LayoutObject<A>,
    common_address: u16,
    originator: u8,
) -> Result<Vec<u8>, TxError> {
    spontaneous_with(
        object,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`spontaneous`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`spontaneous`].
pub fn spontaneous_with<A: crate::asdu::AsduLayout>(
    object: &LayoutObject<A>,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<u8>, TxError> {
    require(Function::Spontaneous, A::TYPE_ID)?;
    Ok(frame(
        CAUSE_SPONTANEOUS,
        object,
        common_address,
        originator,
        sizes,
    )?)
}

/// [`cyclic`] for a set of objects of one type: as few `SQ = 0` ASDUs as fit,
/// each filled up to the 249-octet ASDU, the objects in the order given. No
/// ASDU for an empty set.
///
/// This is the cyclic half of TS 60870-5-604 5.4.14.1's *"Set of Information
/// elements (SQ:=0) in one single ASDU, filled up to but not exceeding the
/// maximum configured ASDU or APDU length"*, under 5-101 clause 7.2.2.1's
/// `SQ = 0` (*"The ASDU may consist of one or more than one equal INFORMATION
/// OBJECTs"*); an ASDU carries at most 127 objects, N's own range.
///
/// # Errors
///
/// As [`cyclic`], for the type of the set.
pub fn cyclic_set<A: crate::asdu::AsduLayout>(
    objects: &[LayoutObject<A>],
    common_address: u16,
    originator: u8,
) -> Result<Vec<Vec<u8>>, TxError> {
    cyclic_set_with(
        objects,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`cyclic_set`] in the address sizes `sizes` fixes; a narrower header leaves
/// room for more objects.
///
/// # Errors
///
/// As [`cyclic_set`].
pub fn cyclic_set_with<A: crate::asdu::AsduLayout>(
    objects: &[LayoutObject<A>],
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<Vec<u8>>, TxError> {
    require(Function::Cyclic, A::TYPE_ID)?;
    Ok(frames(
        CAUSE_PERIODIC,
        objects,
        common_address,
        originator,
        sizes,
    )?)
}

/// [`background`] for a set of objects of one type: as few `SQ = 0` ASDUs as fit,
/// each filled up to the 249-octet ASDU, the objects in the order given. No
/// ASDU for an empty set.
///
/// This is the background-scan half of TS 60870-5-604 5.4.14.1's *"Set of
/// Information elements (SQ:=0) in one single ASDU, filled up to but not
/// exceeding the maximum configured ASDU or APDU length"*, under 5-101 clause
/// 7.2.2.1's `SQ = 0` (*"The ASDU may consist of one or more than one equal
/// INFORMATION OBJECTs"*); an ASDU carries at most 127 objects, N's own range.
///
/// # Errors
///
/// As [`background`], for the type of the set.
pub fn background_set<A: crate::asdu::AsduLayout>(
    objects: &[LayoutObject<A>],
    common_address: u16,
    originator: u8,
) -> Result<Vec<Vec<u8>>, TxError> {
    background_set_with(
        objects,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`background_set`] in the address sizes `sizes` fixes; a narrower header
/// leaves room for more objects.
///
/// # Errors
///
/// As [`background_set`].
pub fn background_set_with<A: crate::asdu::AsduLayout>(
    objects: &[LayoutObject<A>],
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<Vec<u8>>, TxError> {
    require(Function::Background, A::TYPE_ID)?;
    Ok(frames(
        CAUSE_BACKGROUND,
        objects,
        common_address,
        originator,
        sizes,
    )?)
}

/// [`spontaneous`] for a set of objects of one type: as few `SQ = 0` ASDUs as
/// fit, each filled up to the 249-octet ASDU, the objects in the order given.
/// No ASDU for an empty set.
///
/// This is the spontaneous half of TS 60870-5-604 5.4.16.1's *"Set of
/// Information elements (SQ:=0) in one single ASDU, filled up to but not
/// exceeding the maximum configured ASDU or APDU length"*, under 5-101 clause
/// 7.2.2.1's `SQ = 0` (*"The ASDU may consist of one or more than one equal
/// INFORMATION OBJECTs"*); an ASDU carries at most 127 objects, N's own range.
///
/// # Errors
///
/// As [`spontaneous`], for the type of the set.
pub fn spontaneous_set<A: crate::asdu::AsduLayout>(
    objects: &[LayoutObject<A>],
    common_address: u16,
    originator: u8,
) -> Result<Vec<Vec<u8>>, TxError> {
    spontaneous_set_with(
        objects,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`spontaneous_set`] in the address sizes `sizes` fixes; a narrower header
/// leaves room for more objects.
///
/// # Errors
///
/// As [`spontaneous_set`].
pub fn spontaneous_set_with<A: crate::asdu::AsduLayout>(
    objects: &[LayoutObject<A>],
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<Vec<u8>>, TxError> {
    require(Function::Spontaneous, A::TYPE_ID)?;
    Ok(frames(
        CAUSE_SPONTANEOUS,
        objects,
        common_address,
        originator,
        sizes,
    )?)
}

/// Builds both halves of a double transmission (104 clause 9.6, PDF page
/// index 108).
///
/// The untagged ASDU comes **first** and its time-tagged twin **second**, with
/// the same value and the same information object address in both.
///
/// The twin is built from the untagged value by [`Doubles::doubled`]; the
/// caller supplies only the `CP56Time2a` tag. Both carry cause `<3>`, because
/// the clause's heading is *"…information objects with cause of transmission
/// spontaneous"*.
///
/// The tagged half must be inside 104 clause 9's permitted set `<30>` to
/// `<40>` ([`is_permitted_tag`]); a `CP24Time2a` twin is
/// [`TxError::TagNotPermitted`]. This free builder does not consult the
/// [`ProjectList`]; [`Transmission::double`] does.
///
/// # Errors
///
/// [`TxError::NotADoublePair`] when `A` is not one of clause 9.6's families,
/// [`TxError::TagNotPermitted`] as above, and [`TxError::Layout`] when either
/// half cannot be encoded.
pub fn doubled<A: Doubles>(
    object: &LayoutObject<A>,
    time: Cp56Time2a,
    common_address: u16,
    originator: u8,
) -> Result<Vec<Vec<u8>>, TxError> {
    doubled_with(
        object,
        time,
        common_address,
        originator,
        AddressSizes::CONVENTIONAL,
    )
}

/// [`doubled`] in the address sizes `sizes` fixes.
///
/// # Errors
///
/// As [`doubled`].
pub fn doubled_with<A: Doubles>(
    object: &LayoutObject<A>,
    time: Cp56Time2a,
    common_address: u16,
    originator: u8,
    sizes: AddressSizes,
) -> Result<Vec<Vec<u8>>, TxError> {
    if DoublePair::of_type(A::TYPE_ID) != Some(A::PAIR) {
        return Err(TxError::NotADoublePair {
            type_id: A::TYPE_ID,
        });
    }
    if !is_permitted_tag(A::Tagged::TYPE_ID) {
        return Err(TxError::TagNotPermitted {
            type_id: A::Tagged::TYPE_ID,
        });
    }
    let untagged = frame(CAUSE_SPONTANEOUS, object, common_address, originator, sizes)?;
    let twin = LayoutObject {
        ioa: object.ioa,
        value: object.value.doubled(time),
    };
    let tagged = frame(CAUSE_SPONTANEOUS, &twin, common_address, originator, sizes)?;
    Ok(vec![untagged, tagged])
}

/// One role's side of the three functions of 104 clauses 7.3, 7.4 and 101
/// clause 7.4.13: the controlled station's producers, or the controlling
/// station's classification.
///
/// The role is the *procedure's* role, not the transport's: the TCP client is
/// the controlling station (5-104 clause 7), but the same station may hold the
/// other role's instance for the reverse direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transmission {
    role: Role,
    functions: StationFunctions,
    doubles: ProjectList,
    ca: u16,
    org: u8,
    sizes: AddressSizes,
}

impl Transmission {
    /// A controlled station's instance: the functions it uses (104 clause 9.6),
    /// the addresses its project doubles (clause 9.6's list) and the addressing
    /// its frames carry.
    #[must_use]
    pub const fn controlled(
        functions: StationFunctions,
        doubles: ProjectList,
        common_address: u16,
        originator: u8,
    ) -> Self {
        Self {
            role: Role::Controlled,
            functions,
            doubles,
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
        }
    }

    /// A controlling station's instance. It selects no function: it only
    /// classifies what arrives. The addressing is kept for symmetry with
    /// [`Transmission::controlled`].
    #[must_use]
    pub const fn controlling(common_address: u16, originator: u8) -> Self {
        Self {
            role: Role::Controlling,
            functions: StationFunctions::NONE,
            doubles: ProjectList::empty(),
            ca: common_address,
            org: originator,
            sizes: AddressSizes::CONVENTIONAL,
        }
    }

    /// The same instance with the system's address sizes (104 cl.9.5), for
    /// every frame it reads and builds. [`AddressSizes::CONVENTIONAL`] by
    /// default.
    #[must_use]
    pub const fn with_address_sizes(mut self, sizes: AddressSizes) -> Self {
        self.sizes = sizes;
        self
    }

    /// The address sizes this instance reads and builds frames with.
    #[must_use]
    pub const fn address_sizes(&self) -> AddressSizes {
        self.sizes
    }

    /// Which side of the procedure this instance is.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The functions the station uses, or `None` for a controlling station,
    /// which selects none.
    #[must_use]
    pub const fn functions(&self) -> Option<StationFunctions> {
        match self.role {
            Role::Controlled => Some(self.functions),
            Role::Controlling => None,
        }
    }

    /// The project's double-transmission addresses.
    #[must_use]
    pub const fn doubles(&self) -> &ProjectList {
        &self.doubles
    }

    /// The common address and originator the built frames carry.
    #[must_use]
    pub const fn addressing(&self) -> (u16, u8) {
        (self.ca, self.org)
    }

    /// The controlled station's cyclic frame for one object (see [`cyclic`]).
    ///
    /// Refused with [`TxError::FunctionNotUsed`] when the station's
    /// [`StationFunctions`] does not select the cyclic function, and with
    /// [`TxError::CauseTypeNotAllowed`] for a type outside Table 16's cyclic
    /// row.
    ///
    /// # Errors
    ///
    /// [`TxError::WrongRole`] on a controlling station,
    /// [`TxError::FunctionNotUsed`] when the station does not select the
    /// function, and the errors of [`cyclic`].
    pub fn cyclic<A: crate::asdu::AsduLayout>(
        &self,
        object: &LayoutObject<A>,
    ) -> Result<Vec<u8>, TxError> {
        self.require_selected(Function::Cyclic)?;
        cyclic_with(object, self.ca, self.org, self.sizes)
    }

    /// The controlled station's background-scan frame for one object (see
    /// [`background`]). Refused by the station's selection and by Table 21.
    ///
    /// # Errors
    ///
    /// [`TxError::WrongRole`] on a controlling station,
    /// [`TxError::FunctionNotUsed`] when the station does not select the
    /// function, and the errors of [`background`].
    pub fn background<A: crate::asdu::AsduLayout>(
        &self,
        object: &LayoutObject<A>,
    ) -> Result<Vec<u8>, TxError> {
        self.require_selected(Function::Background)?;
        background_with(object, self.ca, self.org, self.sizes)
    }

    /// The controlled station's spontaneous frame for one object (see
    /// [`spontaneous`]). Refused by the station's selection and by Table 16's
    /// event row.
    ///
    /// # Errors
    ///
    /// [`TxError::WrongRole`] on a controlling station,
    /// [`TxError::FunctionNotUsed`] when the station does not select the
    /// function, and the errors of [`spontaneous`].
    pub fn spontaneous<A: crate::asdu::AsduLayout>(
        &self,
        object: &LayoutObject<A>,
    ) -> Result<Vec<u8>, TxError> {
        self.require_selected(Function::Spontaneous)?;
        spontaneous_with(object, self.ca, self.org, self.sizes)
    }

    /// The controlled station's cyclic frames for a set of objects of one
    /// type, packed into as few `SQ = 0` ASDUs as fit (see [`cyclic_set`]).
    /// Refused as [`Transmission::cyclic`] is.
    ///
    /// # Errors
    ///
    /// As [`Transmission::cyclic`], with the errors of [`cyclic_set`].
    pub fn cyclic_set<A: crate::asdu::AsduLayout>(
        &self,
        objects: &[LayoutObject<A>],
    ) -> Result<Vec<Vec<u8>>, TxError> {
        self.require_selected(Function::Cyclic)?;
        cyclic_set_with(objects, self.ca, self.org, self.sizes)
    }

    /// The controlled station's background-scan frames for a set of objects of
    /// one type, packed into as few `SQ = 0` ASDUs as fit (see
    /// [`background_set`]). Refused as [`Transmission::background`] is.
    ///
    /// # Errors
    ///
    /// As [`Transmission::background`], with the errors of [`background_set`].
    pub fn background_set<A: crate::asdu::AsduLayout>(
        &self,
        objects: &[LayoutObject<A>],
    ) -> Result<Vec<Vec<u8>>, TxError> {
        self.require_selected(Function::Background)?;
        background_set_with(objects, self.ca, self.org, self.sizes)
    }

    /// The controlled station's spontaneous frames for a set of objects of one
    /// type, packed into as few `SQ = 0` ASDUs as fit (see [`spontaneous_set`]).
    /// Refused as [`Transmission::spontaneous`] is.
    ///
    /// # Errors
    ///
    /// As [`Transmission::spontaneous`], with the errors of [`spontaneous_set`].
    pub fn spontaneous_set<A: crate::asdu::AsduLayout>(
        &self,
        objects: &[LayoutObject<A>],
    ) -> Result<Vec<Vec<u8>>, TxError> {
        self.require_selected(Function::Spontaneous)?;
        spontaneous_set_with(objects, self.ca, self.org, self.sizes)
    }

    /// Both halves of a double transmission for one object (see [`doubled`]).
    ///
    /// The spontaneous function's selection gates it, because the pair's cause
    /// is `<3>`, and an address the project list does not hold is
    /// [`TxError::DoubleNotEnabled`].
    ///
    /// # Errors
    ///
    /// [`TxError::WrongRole`] on a controlling station,
    /// [`TxError::FunctionNotUsed`] when the spontaneous function is not
    /// selected, [`TxError::DoubleNotEnabled`] as above, and the errors of
    /// [`doubled`].
    pub fn double<A: Doubles>(
        &self,
        object: &LayoutObject<A>,
        time: Cp56Time2a,
    ) -> Result<Vec<Vec<u8>>, TxError> {
        self.require_selected(Function::Spontaneous)?;
        if !self.doubles.contains(object.ioa) {
            return Err(TxError::DoubleNotEnabled { ioa: object.ioa });
        }
        doubled_with(object, time, self.ca, self.org, self.sizes)
    }

    /// The controlling station's decision for one received ASDU.
    ///
    /// 5-101 clause 7.2.3's discard rule runs first. The frame's cause then
    /// names the function, and that **function's own table** (the same sets
    /// the producers enforce) decides whether the type belongs to it; any other
    /// cause, or a type the cause's table does not carry, is
    /// [`Reaction::Other`]. The returned [`Outcome::send`] is always empty.
    ///
    /// The object area is checked against the type's element length before
    /// the frame is classified, so a truncated ASDU is a typed error. A type
    /// with no fixed element length (no layout, or `F_SG_NA_1`'s variable
    /// segment) is checked only as far as its header.
    ///
    /// # Errors
    ///
    /// [`TxError::WrongRole`] on a controlled station, and [`TxError::Layout`]
    /// when the header cannot be parsed or the object area does not fit the
    /// type's element length.
    pub fn on_response(&self, asdu: &[u8], known: &Known) -> Result<Outcome, TxError> {
        if self.role != Role::Controlling {
            return Err(TxError::WrongRole);
        }
        let header = Header::parse_with(asdu, self.sizes)?;
        if let Some(reason) = discard_reason(&header, known) {
            return Ok(Outcome {
                reaction: Reaction::Discard(reason),
                send: Vec::new(),
            });
        }
        framed(asdu, &header, self.sizes)?;
        let reaction = match Function::of_cause(header.cause) {
            Some(Function::Cyclic) if Function::Cyclic.carries(header.type_id) => {
                Reaction::Cyclic {
                    type_id: header.type_id,
                }
            }
            Some(Function::Background) if Function::Background.carries(header.type_id) => {
                Reaction::BackgroundScanned {
                    type_id: header.type_id,
                }
            }
            Some(Function::Spontaneous) if Function::Spontaneous.carries(header.type_id) => {
                Reaction::Spontaneous {
                    type_id: header.type_id,
                }
            }
            _ => Reaction::Other,
        };
        Ok(Outcome {
            reaction,
            send: Vec::new(),
        })
    }

    /// The two shared guards of the producers: the role, and the station's
    /// selection.
    fn require_selected(&self, function: Function) -> Result<(), TxError> {
        if self.role != Role::Controlled {
            return Err(TxError::WrongRole);
        }
        if !self.functions.uses(function) {
            return Err(TxError::FunctionNotUsed {
                cause: function.cause(),
            });
        }
        Ok(())
    }
}

/// Walks a received ASDU's object area against its type's own element length,
/// so every short prefix is a typed error rather than a classification. A type
/// with no fixed element length ([`element_len`] is `None`) cannot be walked,
/// so its header is all this checks.
fn framed(asdu: &[u8], header: &Header, sizes: AddressSizes) -> Result<(), AsduError> {
    let Some(len) = element_len(header.type_id) else {
        return Ok(());
    };
    let body = asdu.get(sizes.header_len()..).unwrap_or(&[]);
    let mut cursor = BodyReader::with_sizes(*header, body, sizes);
    while cursor.next_object(len)?.is_some() {}
    cursor.finish()
}

/// A row of 5-101 **Table 16**, *"Respond priorities of the controlled
/// station"* (clause 7.4, PDF page index 121, printed page 120), highest
/// first, so the derived order is the send order.
///
/// Clause 7.4: *"If a controlled station has data for more than one of the
/// following ASDU types ready for transmission at the same time, they must be
/// sent in the following order regardless of which data was generated first."*
/// and *"ASDU type identifications within the same row may be sent in any
/// order."*
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Priority {
    /// `70` *"End of initialization"*.
    EndOfInitialisation,
    /// `45 to 69` *"Command transmission"*, *"Mirrored ASDUs"*.
    Command,
    /// `1 to 44`, `103`, `106`: *"Event reporting / Clock synchronization /
    /// Acquisition of transmission delay"*.
    Event,
    /// `102, 104, 105, 110 to 113`: *"Read command, test procedure, reset
    /// process, parameter loading"*.
    Request,
    /// `100, 101`: *"Station interrogation, transmission of integrated
    /// totals"*.
    Interrogation,
    /// `9, 11, 13, 21` / `120 to 127`: *"Cyclic data transmission (in monitor
    /// direction with COT = 1), file transfer"*.
    Cyclic,
}

/// The row of 5-101 Table 16 (see [`Priority`]) a monitor-direction ASDU with
/// `header` belongs to.
///
/// The table's first column is headed *"Request ASDU"*: a row is a procedure,
/// and the ASDUs that answer it belong to it. So the data of an interrogation
/// (causes `<20>` to `<41>`) is in the interrogation row whatever its type, a
/// read's object (cause `<5>`) in the read row, and the event row holds types
/// `1 to 44` only *"In monitor direction with COT = 3"*. The type decides
/// first, where the table names it:
///
/// - `<70>`: [`Priority::EndOfInitialisation`];
/// - `<45>` to `<69>`, any cause (the mirrors): [`Priority::Command`];
/// - `<103>`, `<106>`: [`Priority::Event`];
/// - `<102>`, `<104>`, `<105>`, `<107>`, `<110>` to `<113>`:
///   [`Priority::Request`]. `<107>` `C_TS_TA_1` is the test command 104 uses
///   in place of 101's `<104>` (104 Table 4), so it takes that row;
/// - `<100>`, `<101>`: [`Priority::Interrogation`];
/// - `<120>` to `<127>`, file transfer whatever its cause:
///   [`Priority::Cyclic`].
///
/// Then the cause, for the monitor types `1 to 44` that answer a procedure:
///
/// - `<20>` to `<41>`: [`Priority::Interrogation`];
/// - `<5>`: [`Priority::Request`];
/// - `<3>`, and the return information `<11>`, `<12>` (5-101 clause 7.4.7),
///   which the table does not name and this crate puts with the events:
///   [`Priority::Event`];
/// - `<1>`, and the background scan `<2>`, which the table does not name and
///   5-101 clause 7.4.13 sends *"on a low-priority continuous basis"*:
///   [`Priority::Cyclic`].
///
/// Anything else (a cause 44 mirror of a type the table does not name, say)
/// is [`Priority::Request`]: an answer to a request, below the events. That
/// row is this crate's choice.
#[must_use]
pub fn respond_priority(header: &Header) -> Priority {
    match header.type_id.to_u8() {
        70 => Priority::EndOfInitialisation,
        45..=69 => Priority::Command,
        103 | 106 => Priority::Event,
        102 | 104 | 105 | 107 | 110..=113 => Priority::Request,
        100 | 101 => Priority::Interrogation,
        120..=127 => Priority::Cyclic,
        _ => match header.cause.to_u8() {
            20..=41 => Priority::Interrogation,
            3 | 11 | 12 => Priority::Event,
            1 | 2 => Priority::Cyclic,
            _ => Priority::Request,
        },
    }
}
