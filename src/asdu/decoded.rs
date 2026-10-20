//! One entry point that decodes any ASDU the crate has a layout for.
//!
//! [`decode_asdu`] reads one type and needs the caller to name it, so a
//! receiver that takes whatever the peer sends has to read the header first
//! and pick the layout from its type identification (5-101 cl.7.2.1). This
//! module is that step, done once: [`decode`] reads the header, picks the
//! layout of clause 7.3 (or 5-104 clause 8) the type identification names, and
//! returns the objects as an [`Objects`] variant, one per type.
//!
//! ```
//! use iec104::asdu::{self, Objects};
//!
//! // M_ME_NC_1, one object, spontaneous (cause <3>), CA 12, IOA 0x3010,
//! // 1.5 (0x3FC00000) with a good quality descriptor.
//! let frame = [
//!     0x0D, 0x01, 0x03, 0x00, 0x0C, 0x00,
//!     0x10, 0x30, 0x00, 0x00, 0x00, 0xC0, 0x3F, 0x00,
//! ];
//! let asdu = asdu::decode(&frame).unwrap();
//! assert_eq!(asdu.header.common_address, 12);
//! match asdu.objects {
//!     Objects::MMeNc1(objects) => {
//!         assert_eq!(objects[0].ioa, 0x3010);
//!         assert_eq!(objects[0].value.r32.value, 1.5);
//!     }
//!     other => panic!("not a short float: {:?}", other.type_id()),
//! }
//! ```
//!
//! A type identification with no layout (a reserved or private one, 5-101
//! cl.7.2.1) is [`LayoutError::NoLayout`]; the header is still readable with
//! [`Header::parse_with`] for a caller that wants to report it. Every other
//! error is the one [`decode_asdu_with`] or [`decode_segment_with`] returns
//! for that type, so the addressing rules of clause 7.3 hold here exactly as
//! they do there.

use super::elements::{
    Bcr, Cp16Time2a, Cp24Time2a, Cp56Time2a, Diq, DoublePointState, EventState, Oci, Qdp, Qds, Scd,
    Sep, Siq, Spe, Vti,
};
use super::layout::{
    CBoNa1, CBoTa1, CCdNa1, CCiNa1, CCsNa1, CDcNa1, CDcTa1, CIcNa1, CRcNa1, CRcTa1, CRdNa1, CRpNa1,
    CScNa1, CScTa1, CSeNa1, CSeNb1, CSeNc1, CSeTa1, CSeTb1, CSeTc1, CTsNa1, CTsTa1, FAfNa1, FDrTa1,
    FFrNa1, FLsNa1, FScNa1, FScNb1, FSrNa1, LayoutError, LayoutObject, MBoNa1, MBoTa1, MBoTb1,
    MDpNa1, MDpTa1, MDpTb1, MEiNa1, MEpTa1, MEpTb1, MEpTc1, MEpTd1, MEpTe1, MEpTf1, MItNa1, MItTa1,
    MItTb1, MMeNa1, MMeNb1, MMeNc1, MMeNd1, MMeTa1, MMeTb1, MMeTc1, MMeTd1, MMeTe1, MMeTf1, MPsNa1,
    MSpNa1, MSpTa1, MSpTb1, MStNa1, MStTa1, MStTb1, PAcNa1, PMeNa1, PMeNb1, PMeNc1, Segment,
    decode_asdu_with, decode_segment_with, encode_asdu_with, encode_segment_with,
};
use super::{AddressSizes, Header, TypeId};

macro_rules! objects {
    ($($(#[$doc:meta])* $name:ident,)*) => {
        /// The information objects of one ASDU, typed by its type
        /// identification.
        ///
        /// One variant per layout of 5-101 clause 7.3 and 5-104 clause 8, named
        /// as the layout struct is. Each holds the objects in the order the ASDU
        /// carries them. `F_SG_NA_1` `<125>` carries one segment of variable
        /// length and is read through [`decode_segment_with`].
        ///
        /// No `Eq`: several layouts carry an `R32` (an IEEE 754 `f32`).
        #[derive(Debug, Clone, PartialEq)]
        pub enum Objects {
            $($(#[$doc])* $name(Vec<LayoutObject<$name>>),)*
            /// `F_SG_NA_1` `<125>`: see [`Segment`].
            FSgNa1(LayoutObject<Segment>),
        }

        impl Objects {
            /// The type identification the objects were decoded with.
            pub const fn type_id(&self) -> TypeId {
                match self {
                    $(Objects::$name(_) => TypeId::$name,)*
                    Objects::FSgNa1(_) => TypeId::FSgNa1,
                }
            }

            /// The number of information objects. A segment is one object.
            pub const fn len(&self) -> usize {
                match self {
                    $(Objects::$name(objects) => objects.len(),)*
                    Objects::FSgNa1(_) => 1,
                }
            }

            /// Whether the ASDU carried no information object (5-101 cl.7.2.2's
            /// number of objects `<0>`).
            pub const fn is_empty(&self) -> bool {
                self.len() == 0
            }

            /// The validity flags of every information object, in order: the
            /// value's `IV` and the time tag's `IV`. See [`Validity`].
            pub fn validity(&self) -> Vec<Validity> {
                match self {
                    $(Objects::$name(objects) => objects
                        .iter()
                        .map(|object| Validity {
                            ioa: object.ioa,
                            invalid: object.value.invalid(),
                            time_invalid: object.value.time_invalid(),
                        })
                        .collect(),)*
                    Objects::FSgNa1(object) => vec![Validity {
                        ioa: object.ioa,
                        invalid: None,
                        time_invalid: None,
                    }],
                }
            }

            /// Every monitored value of the ASDU as a [`Point`], in order:
            /// its address, its value, its quality descriptor and its time
            /// tag, the same shape whatever the type identification.
            ///
            /// Only the 32 process information types of the monitor
            /// direction (5-101 table 8, `<1>` to `<21>` and `<30>` to
            /// `<40>`; clauses 7.3.1.1 to 7.3.1.32) carry a value. Every other type (commands and
            /// their mirrors, system information such as `M_EI_NA_1`,
            /// parameters and file transfer) returns an empty `Vec`: its
            /// objects are requests or procedure steps, not values of the
            /// process. Read those from the [`Objects`] variant itself.
            ///
            /// ```
            /// use iec104::asdu::{self, Point, Quality, Value};
            ///
            /// // M_ME_NC_1 <13>, one object, spontaneous (cause <3>), CA 12,
            /// // IOA 0x3010: R32 1.5 (0x3FC00000), then a QDS with IV set.
            /// let frame = [
            ///     0x0D, 0x01, 0x03, 0x00, 0x0C, 0x00,
            ///     0x10, 0x30, 0x00, 0x00, 0x00, 0xC0, 0x3F, 0x80,
            /// ];
            /// let points = asdu::decode(&frame).unwrap().objects.points();
            /// assert_eq!(
            ///     points,
            ///     [Point {
            ///         ioa: 0x3010,
            ///         value: Value::Float(1.5),
            ///         quality: Some(Quality {
            ///             invalid: true,
            ///             overflow: Some(false),
            ///             ..Quality::default()
            ///         }),
            ///         time: None,
            ///     }]
            /// );
            /// ```
            pub fn points(&self) -> Vec<Point> {
                match self {
                    $(Objects::$name(objects) => objects
                        .iter()
                        .filter_map(|object| {
                            let (value, quality, time) = object.value.point()?;
                            Some(Point {
                                ioa: object.ioa,
                                value,
                                quality,
                                time,
                            })
                        })
                        .collect(),)*
                    Objects::FSgNa1(_) => Vec::new(),
                }
            }
        }

        fn decode_objects(
            asdu: &[u8],
            header: &Header,
            sizes: AddressSizes,
        ) -> Result<Objects, LayoutError> {
            match header.type_id {
                $(TypeId::$name => Ok(Objects::$name(decode_asdu_with::<$name>(asdu, sizes)?)),)*
                TypeId::FSgNa1 => Ok(Objects::FSgNa1(decode_segment_with(asdu, sizes)?)),
                type_id => Err(LayoutError::NoLayout { type_id }),
            }
        }

        fn encode_objects(
            header: &Header,
            objects: &Objects,
            sizes: AddressSizes,
        ) -> Result<Vec<u8>, LayoutError> {
            match objects {
                $(Objects::$name(objects) => encode_asdu_with(header, objects, sizes),)*
                Objects::FSgNa1(object) => {
                    encode_segment_with(header, object.ioa, &object.value, sizes)
                }
            }
        }
    };
}

objects! {
    /// `M_SP_NA_1` `<1>`: see [`MSpNa1`].
    MSpNa1,
    /// `M_SP_TA_1` `<2>`: see [`MSpTa1`].
    MSpTa1,
    /// `M_DP_NA_1` `<3>`: see [`MDpNa1`].
    MDpNa1,
    /// `M_DP_TA_1` `<4>`: see [`MDpTa1`].
    MDpTa1,
    /// `M_ST_NA_1` `<5>`: see [`MStNa1`].
    MStNa1,
    /// `M_ST_TA_1` `<6>`: see [`MStTa1`].
    MStTa1,
    /// `M_BO_NA_1` `<7>`: see [`MBoNa1`].
    MBoNa1,
    /// `M_BO_TA_1` `<8>`: see [`MBoTa1`].
    MBoTa1,
    /// `M_ME_NA_1` `<9>`: see [`MMeNa1`].
    MMeNa1,
    /// `M_ME_TA_1` `<10>`: see [`MMeTa1`].
    MMeTa1,
    /// `M_ME_NB_1` `<11>`: see [`MMeNb1`].
    MMeNb1,
    /// `M_ME_TB_1` `<12>`: see [`MMeTb1`].
    MMeTb1,
    /// `M_ME_NC_1` `<13>`: see [`MMeNc1`].
    MMeNc1,
    /// `M_ME_TC_1` `<14>`: see [`MMeTc1`].
    MMeTc1,
    /// `M_IT_NA_1` `<15>`: see [`MItNa1`].
    MItNa1,
    /// `M_IT_TA_1` `<16>`: see [`MItTa1`].
    MItTa1,
    /// `M_EP_TA_1` `<17>`: see [`MEpTa1`].
    MEpTa1,
    /// `M_EP_TB_1` `<18>`: see [`MEpTb1`].
    MEpTb1,
    /// `M_EP_TC_1` `<19>`: see [`MEpTc1`].
    MEpTc1,
    /// `M_PS_NA_1` `<20>`: see [`MPsNa1`].
    MPsNa1,
    /// `M_ME_ND_1` `<21>`: see [`MMeNd1`].
    MMeNd1,
    /// `M_SP_TB_1` `<30>`: see [`MSpTb1`].
    MSpTb1,
    /// `M_DP_TB_1` `<31>`: see [`MDpTb1`].
    MDpTb1,
    /// `M_ST_TB_1` `<32>`: see [`MStTb1`].
    MStTb1,
    /// `M_BO_TB_1` `<33>`: see [`MBoTb1`].
    MBoTb1,
    /// `M_ME_TD_1` `<34>`: see [`MMeTd1`].
    MMeTd1,
    /// `M_ME_TE_1` `<35>`: see [`MMeTe1`].
    MMeTe1,
    /// `M_ME_TF_1` `<36>`: see [`MMeTf1`].
    MMeTf1,
    /// `M_IT_TB_1` `<37>`: see [`MItTb1`].
    MItTb1,
    /// `M_EP_TD_1` `<38>`: see [`MEpTd1`].
    MEpTd1,
    /// `M_EP_TE_1` `<39>`: see [`MEpTe1`].
    MEpTe1,
    /// `M_EP_TF_1` `<40>`: see [`MEpTf1`].
    MEpTf1,
    /// `C_SC_NA_1` `<45>`: see [`CScNa1`].
    CScNa1,
    /// `C_DC_NA_1` `<46>`: see [`CDcNa1`].
    CDcNa1,
    /// `C_RC_NA_1` `<47>`: see [`CRcNa1`].
    CRcNa1,
    /// `C_SE_NA_1` `<48>`: see [`CSeNa1`].
    CSeNa1,
    /// `C_SE_NB_1` `<49>`: see [`CSeNb1`].
    CSeNb1,
    /// `C_SE_NC_1` `<50>`: see [`CSeNc1`].
    CSeNc1,
    /// `C_BO_NA_1` `<51>`: see [`CBoNa1`].
    CBoNa1,
    /// `C_SC_TA_1` `<58>`: see [`CScTa1`].
    CScTa1,
    /// `C_DC_TA_1` `<59>`: see [`CDcTa1`].
    CDcTa1,
    /// `C_RC_TA_1` `<60>`: see [`CRcTa1`].
    CRcTa1,
    /// `C_SE_TA_1` `<61>`: see [`CSeTa1`].
    CSeTa1,
    /// `C_SE_TB_1` `<62>`: see [`CSeTb1`].
    CSeTb1,
    /// `C_SE_TC_1` `<63>`: see [`CSeTc1`].
    CSeTc1,
    /// `C_BO_TA_1` `<64>`: see [`CBoTa1`].
    CBoTa1,
    /// `M_EI_NA_1` `<70>`: see [`MEiNa1`].
    MEiNa1,
    /// `C_IC_NA_1` `<100>`: see [`CIcNa1`].
    CIcNa1,
    /// `C_CI_NA_1` `<101>`: see [`CCiNa1`].
    CCiNa1,
    /// `C_RD_NA_1` `<102>`: see [`CRdNa1`].
    CRdNa1,
    /// `C_CS_NA_1` `<103>`: see [`CCsNa1`].
    CCsNa1,
    /// `C_TS_NA_1` `<104>`: see [`CTsNa1`].
    CTsNa1,
    /// `C_RP_NA_1` `<105>`: see [`CRpNa1`].
    CRpNa1,
    /// `C_CD_NA_1` `<106>`: see [`CCdNa1`].
    CCdNa1,
    /// `C_TS_TA_1` `<107>`: see [`CTsTa1`].
    CTsTa1,
    /// `P_ME_NA_1` `<110>`: see [`PMeNa1`].
    PMeNa1,
    /// `P_ME_NB_1` `<111>`: see [`PMeNb1`].
    PMeNb1,
    /// `P_ME_NC_1` `<112>`: see [`PMeNc1`].
    PMeNc1,
    /// `P_AC_NA_1` `<113>`: see [`PAcNa1`].
    PAcNa1,
    /// `F_FR_NA_1` `<120>`: see [`FFrNa1`].
    FFrNa1,
    /// `F_SR_NA_1` `<121>`: see [`FSrNa1`].
    FSrNa1,
    /// `F_SC_NA_1` `<122>`: see [`FScNa1`].
    FScNa1,
    /// `F_LS_NA_1` `<123>`: see [`FLsNa1`].
    FLsNa1,
    /// `F_AF_NA_1` `<124>`: see [`FAfNa1`].
    FAfNa1,
    /// `F_DR_TA_1` `<126>`: see [`FDrTa1`].
    FDrTa1,
    /// `F_SC_NB_1` `<127>`: see [`FScNb1`].
    FScNb1,
}

/// The two validity flags of one information object.
///
/// - `invalid` is the `IV` bit of the object's quality descriptor (`SIQ`,
///   `DIQ`, `QDS`, `QDP`, `SEP` or `BCR`; 5-101 cl.7.2.6.1 to 7.2.6.4,
///   7.2.6.9, 7.2.6.10): it tells the receiver the value may be wrong and is
///   not to be used (cl.7.2.6.3). `None` for a type that has no quality descriptor
///   (`M_ME_ND_1`, commands, system, parameter and file types).
/// - `time_invalid` is the `IV` bit of the object's time tag (`CP24Time2a` or
///   `CP56Time2a`, cl.7.2.6.18 and 7.2.6.19). 104 cl.7.6: the controlled
///   station marks time tags inaccurate (invalid) when its clock
///   synchronisation is overdue and after a restart. `None` for a type without
///   a time tag, and for `F_SC_NB_1`, which carries two.
///
/// The two are independent: a value can be valid with an invalid time, and
/// the other way round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// The object's information object address.
    pub ioa: u32,
    /// The value's `IV`.
    pub invalid: Option<bool>,
    /// The time tag's `IV`.
    pub time_invalid: Option<bool>,
}

/// Where each layout keeps the two `IV` bits.
trait Flags {
    fn invalid(&self) -> Option<bool>;
    fn time_invalid(&self) -> Option<bool>;
}

macro_rules! flags {
    ($($name:ident: $quality:tt, $time:tt;)*) => {
        $(impl Flags for $name {
            fn invalid(&self) -> Option<bool> {
                flags!(@field self $quality)
            }
            fn time_invalid(&self) -> Option<bool> {
                flags!(@field self $time)
            }
        })*
    };
    (@field $self:ident -) => {
        None
    };
    (@field $self:ident $field:ident) => {
        Some($self.$field.invalid)
    };
}

// Generated from the layouts' fields: the quality descriptor, then the time
// tag, `-` where the type has none.
flags! {
    MSpNa1: siq, -;
    MSpTa1: siq, time;
    MDpNa1: diq, -;
    MDpTa1: diq, time;
    MStNa1: qds, -;
    MStTa1: qds, time;
    MBoNa1: qds, -;
    MBoTa1: qds, time;
    MMeNa1: qds, -;
    MMeTa1: qds, time;
    MMeNb1: qds, -;
    MMeTb1: qds, time;
    MMeNc1: qds, -;
    MMeTc1: qds, time;
    MItNa1: bcr, -;
    MItTa1: bcr, time;
    MEpTa1: sep, time;
    MEpTb1: qdp, time;
    MEpTc1: qdp, time;
    MPsNa1: qds, -;
    MMeNd1: -, -;
    MSpTb1: siq, time;
    MDpTb1: diq, time;
    MStTb1: qds, time;
    MBoTb1: qds, time;
    MMeTd1: qds, time;
    MMeTe1: qds, time;
    MMeTf1: qds, time;
    MItTb1: bcr, time;
    MEpTd1: sep, time;
    MEpTe1: qdp, time;
    MEpTf1: qdp, time;
    CScNa1: -, -;
    CDcNa1: -, -;
    CRcNa1: -, -;
    CSeNa1: -, -;
    CSeNb1: -, -;
    CSeNc1: -, -;
    CBoNa1: -, -;
    CScTa1: -, time;
    CDcTa1: -, time;
    CRcTa1: -, time;
    CSeTa1: -, time;
    CSeTb1: -, time;
    CSeTc1: -, time;
    CBoTa1: -, time;
    MEiNa1: -, -;
    CIcNa1: -, -;
    CRdNa1: -, -;
    CCiNa1: -, -;
    CCsNa1: -, time;
    CTsNa1: -, -;
    CRpNa1: -, -;
    CCdNa1: -, -;
    CTsTa1: -, time;
    PMeNa1: -, -;
    PMeNb1: -, -;
    PMeNc1: -, -;
    PAcNa1: -, -;
    FFrNa1: -, -;
    FSrNa1: -, -;
    FScNa1: -, -;
    FLsNa1: -, -;
    FAfNa1: -, -;
    FDrTa1: -, time;
    FScNb1: -, -;
}

/// One monitored value in a uniform shape, whatever the type identification
/// that carried it. See [`Objects::points`].
///
/// No `Eq`: [`Value`] carries floating-point values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    /// The object's information object address.
    pub ioa: u32,
    /// The value, typed by the information element that carried it.
    pub value: Value,
    /// The quality bits. `None` for the one monitor type without a quality
    /// descriptor, `M_ME_ND_1` (5-101 cl.7.3.1.21, *"without quality
    /// descriptor"*).
    pub quality: Option<Quality>,
    /// The time tag. `None` for a type without one (`M_ME_ND_1` and the
    /// `..._NA_1` types).
    pub time: Option<TimeTag>,
}

/// The value of a [`Point`], one variant per kind of process information of
/// 5-101 clause 7.3.1.
///
/// Each variant names the information element it comes from (5-101
/// cl.7.2.6) and the types that carry it. The quality bits of the element are
/// in [`Point::quality`], not here, except for bits that describe the value
/// itself: the step position's transient bit, a counter's sequence number,
/// `CY` and `CA`, and a protection event's `EI`, which qualifies its elapsed
/// time and sits next to it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    /// `SPI` of `SIQ` (7.2.6.1): `false` OFF, `true` ON. `M_SP_NA_1`,
    /// `M_SP_TA_1`, `M_SP_TB_1`.
    Single(bool),
    /// `DPI` of `DIQ` (7.2.6.2). `M_DP_NA_1`, `M_DP_TA_1`, `M_DP_TB_1`.
    Double(DoublePointState),
    /// `VTI` (7.2.6.5). `M_ST_NA_1`, `M_ST_TA_1`, `M_ST_TB_1`.
    StepPosition {
        /// `Value`: the step position, `-64..=63`.
        value: i8,
        /// `Transient`: the equipment is in a transient state.
        transient: bool,
    },
    /// `BSI` (7.2.6.13): the 32 bits, bit 1 of the clause in the low bit (see
    /// [`Bsi`](crate::asdu::Bsi)). `M_BO_NA_1`, `M_BO_TA_1`, `M_BO_TB_1`.
    Bitstring(u32),
    /// `NVA` (7.2.6.6) as a number in `[-1, 1 - 2^-15]`, through
    /// [`Nva::to_scaled`](crate::asdu::Nva::to_scaled). `M_ME_NA_1`,
    /// `M_ME_TA_1`, `M_ME_ND_1`, `M_ME_TD_1`.
    Normalized(f64),
    /// `SVA` (7.2.6.7). `M_ME_NB_1`, `M_ME_TB_1`, `M_ME_TE_1`.
    Scaled(i16),
    /// `R32-IEEE STD 754` (7.2.6.8). `M_ME_NC_1`, `M_ME_TC_1`, `M_ME_TF_1`.
    Float(f32),
    /// `BCR` (7.2.6.9) without its `IV`, which is in the quality.
    /// `M_IT_NA_1`, `M_IT_TA_1`, `M_IT_TB_1`.
    Counter {
        /// `Counter reading`.
        reading: i32,
        /// `SQ`: the sequence number, `0..=31`.
        sequence: u8,
        /// `CY`: a counter overflow occurred in the integration period.
        carry: bool,
        /// `CA`: the counter was adjusted since the last reading.
        adjusted: bool,
    },
    /// `SEP` (7.2.6.10) with its elapsed time (`CP16Time2a`, 7.2.6.20).
    /// `M_EP_TA_1`, `M_EP_TD_1`.
    ProtectionEvent {
        /// `ES`: the event state.
        state: EventState,
        /// The elapsed time in milliseconds.
        elapsed_ms: u16,
        /// `EI` of the `SEP`: the elapsed time is invalid.
        elapsed_invalid: bool,
    },
    /// `SPE` (7.2.6.11) with the relay duration time (`CP16Time2a`,
    /// 7.2.6.20). `M_EP_TB_1`, `M_EP_TE_1`.
    ProtectionStart {
        /// The start events.
        start: Spe,
        /// The relay duration time in milliseconds.
        elapsed_ms: u16,
        /// `EI` of the `QDP` (7.2.6.4): the elapsed time is invalid.
        elapsed_invalid: bool,
    },
    /// `OCI` (7.2.6.12) with the relay operating time (`CP16Time2a`,
    /// 7.2.6.20). `M_EP_TC_1`, `M_EP_TF_1`.
    ProtectionCommand {
        /// The commands to the output circuits.
        command: Oci,
        /// The relay operating time in milliseconds.
        elapsed_ms: u16,
        /// `EI` of the `QDP` (7.2.6.4): the elapsed time is invalid.
        elapsed_invalid: bool,
    },
    /// `SCD` (7.2.6.40): sixteen single points and their change bits, bit 1
    /// of the clause in the low bit (see [`Scd`](crate::asdu::Scd)).
    /// `M_PS_NA_1`.
    PackedSingle {
        /// `ST`: the sixteen states.
        status: u16,
        /// `CD`: a change was detected since the last report.
        change: u16,
    },
}

/// The quality bits of a [`Point`]'s value.
///
/// The bits of `QDS` (5-101 cl.7.2.6.3), which `SIQ`, `DIQ`, `QDP` and `SEP`
/// (cl.7.2.6.1, 7.2.6.2, 7.2.6.4, 7.2.6.10) repeat in the same positions.
/// `overflow` is `Some` only for a `QDS`: the others have no `OV` bit.
///
/// A counter reading's `BCR` (cl.7.2.6.9) has only `IV`. Its quality has
/// `invalid` from that bit, `false` for the three bits the element does not
/// have, and no `overflow` (its `CY`, the counter's own overflow, is in
/// [`Value::Counter`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one field per flag bit the standard defines"
)]
pub struct Quality {
    /// `IV`: the value was not correctly acquired and cannot be used.
    pub invalid: bool,
    /// `NT`: the most recent update was not successful.
    pub not_topical: bool,
    /// `SB`: the value was provided by an operator or an automatic source.
    pub substituted: bool,
    /// `BL`: the value is blocked for transmission.
    pub blocked: bool,
    /// `OV`: the value is beyond a predefined range. `None` where the
    /// element has no `OV` bit.
    pub overflow: Option<bool>,
}

/// The time tag of a [`Point`]: three octets (`CP24Time2a`, 5-101
/// cl.7.2.6.19) or seven (`CP56Time2a`, cl.7.2.6.18). Its own `IV` and `GEN`
/// bits are the `invalid` and `substituted` fields of either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeTag {
    /// `CP24Time2a`: milliseconds and minutes.
    Cp24(Cp24Time2a),
    /// `CP56Time2a`: the full date and time.
    Cp56(Cp56Time2a),
}

impl From<Cp24Time2a> for TimeTag {
    fn from(time: Cp24Time2a) -> Self {
        Self::Cp24(time)
    }
}

impl From<Cp56Time2a> for TimeTag {
    fn from(time: Cp56Time2a) -> Self {
        Self::Cp56(time)
    }
}

/// An element that carries quality bits.
trait Descriptor {
    fn quality(&self) -> Quality;
}

macro_rules! descriptor {
    ($($element:ident: $overflow:ident;)*) => {
        $(impl Descriptor for $element {
            fn quality(&self) -> Quality {
                Quality {
                    invalid: self.invalid,
                    not_topical: self.not_topical,
                    substituted: self.substituted,
                    blocked: self.blocked,
                    overflow: descriptor!(@overflow self $overflow),
                }
            }
        })*
    };
    (@overflow $self:ident overflow) => {
        Some($self.overflow)
    };
    (@overflow $self:ident none) => {
        None
    };
}

// `OV` exists only in `QDS` (5-101 cl.7.2.6.3); `SIQ`, `DIQ`, `QDP` and `SEP`
// have a reserved bit or `EI` in its place (cl.7.2.6.1, 7.2.6.2, 7.2.6.4,
// 7.2.6.10).
descriptor! {
    Qds: overflow;
    Siq: none;
    Diq: none;
    Qdp: none;
    Sep: none;
}

/// `BCR` (5-101 cl.7.2.6.9) has `IV` and none of the other four bits.
impl Descriptor for Bcr {
    fn quality(&self) -> Quality {
        Quality {
            invalid: self.invalid,
            ..Quality::default()
        }
    }
}

/// What one information object contributes to a [`Point`].
type Parts = (Value, Option<Quality>, Option<TimeTag>);

/// Where each layout keeps its value, its quality bits and its time tag.
trait Points {
    /// `None` for a type that carries no process value.
    fn point(&self) -> Option<Parts>;
}

macro_rules! points {
    ($($name:ident: $value:tt, $quality:tt, $time:tt;)*) => {
        $(impl Points for $name {
            fn point(&self) -> Option<Parts> {
                let value = points!(@value self $value)?;
                Some((value, points!(@quality self $quality), points!(@time self $time)))
            }
        })*
    };
    (@value $self:ident -) => {
        None
    };
    (@value $self:ident { |$o:ident| $value:expr }) => {{
        let $o = $self;
        Some($value)
    }};
    (@quality $self:ident -) => {
        None
    };
    (@quality $self:ident $field:ident) => {
        Some(Descriptor::quality(&$self.$field))
    };
    (@time $self:ident -) => {
        None
    };
    (@time $self:ident $field:ident) => {
        Some(TimeTag::from($self.$field))
    };
}

// One row per layout, from the layouts' fields (5-101 cl.7.3.1): the value,
// the element holding the quality bits, the time tag, `-` where the type has
// none. A type whose value is `-` carries no process value and yields no
// point: the control, system, parameter and file types.
points! {
    MSpNa1: { |o| Value::Single(o.siq.spi) }, siq, -;
    MSpTa1: { |o| Value::Single(o.siq.spi) }, siq, time;
    MDpNa1: { |o| Value::Double(o.diq.dpi) }, diq, -;
    MDpTa1: { |o| Value::Double(o.diq.dpi) }, diq, time;
    MStNa1: { |o| step(o.vti) }, qds, -;
    MStTa1: { |o| step(o.vti) }, qds, time;
    MBoNa1: { |o| Value::Bitstring(o.bsi.bits) }, qds, -;
    MBoTa1: { |o| Value::Bitstring(o.bsi.bits) }, qds, time;
    MMeNa1: { |o| Value::Normalized(o.nva.to_scaled()) }, qds, -;
    MMeTa1: { |o| Value::Normalized(o.nva.to_scaled()) }, qds, time;
    MMeNb1: { |o| Value::Scaled(o.sva.value) }, qds, -;
    MMeTb1: { |o| Value::Scaled(o.sva.value) }, qds, time;
    MMeNc1: { |o| Value::Float(o.r32.value) }, qds, -;
    MMeTc1: { |o| Value::Float(o.r32.value) }, qds, time;
    MItNa1: { |o| counter(o.bcr) }, bcr, -;
    MItTa1: { |o| counter(o.bcr) }, bcr, time;
    MEpTa1: { |o| event(o.sep, o.elapsed) }, sep, time;
    MEpTb1: { |o| start(o.spe, o.qdp, o.elapsed) }, qdp, time;
    MEpTc1: { |o| command(o.oci, o.qdp, o.elapsed) }, qdp, time;
    MPsNa1: { |o| packed(o.scd) }, qds, -;
    MMeNd1: { |o| Value::Normalized(o.nva.to_scaled()) }, -, -;
    MSpTb1: { |o| Value::Single(o.siq.spi) }, siq, time;
    MDpTb1: { |o| Value::Double(o.diq.dpi) }, diq, time;
    MStTb1: { |o| step(o.vti) }, qds, time;
    MBoTb1: { |o| Value::Bitstring(o.bsi.bits) }, qds, time;
    MMeTd1: { |o| Value::Normalized(o.nva.to_scaled()) }, qds, time;
    MMeTe1: { |o| Value::Scaled(o.sva.value) }, qds, time;
    MMeTf1: { |o| Value::Float(o.r32.value) }, qds, time;
    MItTb1: { |o| counter(o.bcr) }, bcr, time;
    MEpTd1: { |o| event(o.sep, o.elapsed) }, sep, time;
    MEpTe1: { |o| start(o.spe, o.qdp, o.elapsed) }, qdp, time;
    MEpTf1: { |o| command(o.oci, o.qdp, o.elapsed) }, qdp, time;
    CScNa1: -, -, -;
    CDcNa1: -, -, -;
    CRcNa1: -, -, -;
    CSeNa1: -, -, -;
    CSeNb1: -, -, -;
    CSeNc1: -, -, -;
    CBoNa1: -, -, -;
    CScTa1: -, -, -;
    CDcTa1: -, -, -;
    CRcTa1: -, -, -;
    CSeTa1: -, -, -;
    CSeTb1: -, -, -;
    CSeTc1: -, -, -;
    CBoTa1: -, -, -;
    MEiNa1: -, -, -;
    CIcNa1: -, -, -;
    CRdNa1: -, -, -;
    CCiNa1: -, -, -;
    CCsNa1: -, -, -;
    CTsNa1: -, -, -;
    CRpNa1: -, -, -;
    CCdNa1: -, -, -;
    CTsTa1: -, -, -;
    PMeNa1: -, -, -;
    PMeNb1: -, -, -;
    PMeNc1: -, -, -;
    PAcNa1: -, -, -;
    FFrNa1: -, -, -;
    FSrNa1: -, -, -;
    FScNa1: -, -, -;
    FLsNa1: -, -, -;
    FAfNa1: -, -, -;
    FDrTa1: -, -, -;
    FScNb1: -, -, -;
}

const fn step(vti: Vti) -> Value {
    Value::StepPosition {
        value: vti.value,
        transient: vti.transient,
    }
}

const fn counter(bcr: Bcr) -> Value {
    Value::Counter {
        reading: bcr.reading,
        sequence: bcr.sequence,
        carry: bcr.carry,
        adjusted: bcr.adjusted,
    }
}

const fn event(sep: Sep, elapsed: Cp16Time2a) -> Value {
    Value::ProtectionEvent {
        state: sep.event_state,
        elapsed_ms: elapsed.milliseconds,
        elapsed_invalid: sep.elapsed_time_invalid,
    }
}

const fn start(spe: Spe, qdp: Qdp, elapsed: Cp16Time2a) -> Value {
    Value::ProtectionStart {
        start: spe,
        elapsed_ms: elapsed.milliseconds,
        elapsed_invalid: qdp.elapsed_time_invalid,
    }
}

const fn command(oci: Oci, qdp: Qdp, elapsed: Cp16Time2a) -> Value {
    Value::ProtectionCommand {
        command: oci,
        elapsed_ms: elapsed.milliseconds,
        elapsed_invalid: qdp.elapsed_time_invalid,
    }
}

const fn packed(scd: Scd) -> Value {
    Value::PackedSingle {
        status: scd.status,
        change: scd.change,
    }
}

/// A decoded ASDU: its data unit identifier and its typed information objects.
#[derive(Debug, Clone, PartialEq)]
pub struct Asdu {
    /// The data unit identifier (5-101 cl.7.2): type identification, variable
    /// structure qualifier, cause, originator and common address.
    pub header: Header,
    /// The information objects, typed by `header.type_id`.
    pub objects: Objects,
}

impl Asdu {
    /// Writes the ASDU back out with the conventional address sizes.
    ///
    /// `header` and `objects` must agree: the type identification, the number
    /// of objects and the sequence bit are checked as [`encode_asdu_with`]
    /// checks them.
    ///
    /// # Errors
    ///
    /// As [`Asdu::encode_with`].
    pub fn encode(&self) -> Result<Vec<u8>, LayoutError> {
        self.encode_with(AddressSizes::CONVENTIONAL)
    }

    /// Writes the ASDU back out with the address sizes `sizes` fixes.
    ///
    /// # Errors
    ///
    /// [`LayoutError::TypeMismatch`] if the header's type identification is
    /// not the objects', otherwise as [`encode_asdu_with`].
    pub fn encode_with(&self, sizes: AddressSizes) -> Result<Vec<u8>, LayoutError> {
        if self.header.type_id != self.objects.type_id() {
            return Err(LayoutError::TypeMismatch {
                expected: self.objects.type_id(),
                got: self.header.type_id,
            });
        }
        encode_objects(&self.header, &self.objects, sizes)
    }
}

/// Decodes a complete ASDU of any laid-out type with the conventional address
/// sizes (a cause octet with the originator, a two-octet common address and a
/// three-octet information object address).
///
/// # Errors
///
/// As [`decode_with`].
pub fn decode(asdu: &[u8]) -> Result<Asdu, LayoutError> {
    decode_with(asdu, AddressSizes::CONVENTIONAL)
}

/// Decodes a complete ASDU of any laid-out type with the address sizes `sizes`
/// fixes (5-101 cl.7.2.3 to 7.2.5; 104 cl.9.5).
///
/// # Errors
///
/// [`LayoutError::NoLayout`] for a type with no layout, otherwise as
/// [`decode_asdu_with`] (or [`decode_segment_with`] for `F_SG_NA_1`).
pub fn decode_with(asdu: &[u8], sizes: AddressSizes) -> Result<Asdu, LayoutError> {
    let header = Header::parse_with(asdu, sizes)?;
    let objects = decode_objects(asdu, &header, sizes)?;
    Ok(Asdu { header, objects })
}
