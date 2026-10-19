//! The time elements `CP56Time2a`, `CP24Time2a` and `CP16Time2a` of
//! IEC 60870-5-101:2003 clause 7.2.6.18–7.2.6.20.
//!
//! `CP56Time2a` is the seven-octet time tag of clause 7.2.6.18 ("This binary
//! time is defined in 6.8 of IEC 60870-5-4"), `CP24Time2a` is its three-octet
//! prefix (7.2.6.19: "The octets 4 up to 7 are discarded"), and `CP16Time2a` is
//! a two-octet **elapsed** time in milliseconds, not a time tag (7.2.6.20).
//!
//! ```text
//! octet 1..2  milliseconds   UI16, little-endian, 0..59999
//! octet 3     minutes        UI6[1..6] 0x3F, RES1 (GEN) bit 7 0x40,
//!                            invalid (IV) bit 8 0x80
//! octet 4     hours          UI5[1..5] 0x1F, RES2 bits 6..7, summer time (SU)
//!                            bit 8 0x80
//! octet 5     day of month   UI5[1..5] 0x1F, day of week bits 6..8 0xE0
//! octet 6     months         UI4[1..4] 0x0F, RES3 bits 5..8
//! octet 7     years          UI7[1..7] 0x7F (0..99), RES4 bit 8 0x80
//! ```
//!
//! `RES1 := GEN`: `<0>` genuine time (the tag was added when the object was
//! acquired) and `<1>` substituted time. Day of week is `<0>` not used and
//! `<1..7>` Monday…Sunday. The `SU` bit "may optionally be used … to indicate
//! the presently valid time (standard or summer-time)".
//!
//! The bit positions above follow the field order of clause 7.2.6.18's own
//! definition list (the 5-4 §6.8 figure it references is not reproduced in the
//! 5-101 or 5-104 PDF) and the field sizes of its `UI5`/`UI6`/`UI7` ranges. The
//! octet order is confirmed by a published worked example, Clarke/Reynders/Wright,
//! *Practical Modern SCADA Protocols*, Appendix D: `55 69 10 0D 13 01 01` is
//! "26.965 seconds", 16 minutes, 13 hours, day 19, January, year 2001, and the
//! `57 6E …` of the second example carries the same reading.
//!
//! `RES2` (bits 6–7 of the hours octet), `RES3` (bits 5–8 of the months octet)
//! and `RES4` (bit 8 of the years octet) are fixed to zero by the standard and
//! are not modelled: encode writes them as zero, decode ignores them.
//!
//! The clause's ranges are the caller's to respect. A decode never fails on a
//! range and an encode never clamps, so a value outside `0..59999` / `0..59` /
//! `0..23` / `1..31` / `1..12` / `0..99` / `0` or `1..7` still round-trips as
//! long as it fits its field's bits. Bits beyond the field width are masked off
//! on encode (e.g. an `hours` of 32 is written as 0).
//!
//! [`Cp56Time2a::from_unix`] and [`Cp56Time2a::to_unix`] convert between the
//! tag and a time since the Unix epoch (1970-01-01 00:00:00 UTC), with
//! `SystemTime` forms beside them. They are calendar arithmetic only: nothing
//! here reads a clock. The tag's fields are read as UTC, which clause 7.2.6.18
//! recommends: *"For systems that span time-zone boundaries, the adoption of
//! UTC for all time tags is recommended."*

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::super::AsduError;
use super::octets;

/// Seven-octet binary time (`CP56Time2a`), clause 7.2.6.18.
///
/// `CP56Time2a := CP56{milliseconds,minutes,RES1,invalid,hours,RES2,summer
/// time,day of month,day of week,months,RES3,years,RES4}`. See the module doc
/// for the octet-by-octet layout and the bit of each field.
///
/// The clause's own ranges (`milliseconds` `0..59999`, `minutes` `0..59`,
/// `hours` `0..23`, day of month `1..31`, months `1..12`, years `0..99`,
/// day of week `0` or `1..7`) are the caller's to respect: a decode never
/// fails on a range, and an encode writes any value that fits the field's
/// bits unchanged (bits beyond the field width are masked off).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cp56Time2a {
    /// Milliseconds of the minute, `0..=59999` per the clause.
    pub milliseconds: u16,
    /// Minutes, `0..=59`.
    pub minutes: u8,
    /// `RES1`/`GEN`: `true` = substituted time, `false` = genuine time.
    pub substituted: bool,
    /// `IV`: the time is invalid.
    pub invalid: bool,
    /// Hours, `0..=23`.
    pub hours: u8,
    /// `SU`: the time is summer time (`true`) rather than standard time.
    pub summer_time: bool,
    /// Day of the month, `1..=31`.
    pub day_of_month: u8,
    /// Day of the week: `0` = not used, `1..=7` = Monday…Sunday.
    pub day_of_week: u8,
    /// Months, `1..=12`.
    pub months: u8,
    /// Years of the century, `0..=99`. The century is not on the wire;
    /// [`Cp56Time2a::millis_since_2000`] reads it as 2000 to 2099.
    pub years: u8,
}

impl Cp56Time2a {
    /// Octets on the wire.
    pub const LEN: usize = 7;

    /// Milliseconds since 2000-01-01 00:00:00.000 of the same clock, for
    /// comparing two time tags. `years` is read as 2000 to 2099 and the `SU`,
    /// `IV` and `GEN` flags are ignored, so both tags must come from clocks
    /// that agree on the time zone. `None` for a month outside `1..=12`.
    #[must_use]
    pub fn millis_since_2000(&self) -> Option<i64> {
        if !(1..=12).contains(&self.months) {
            return None;
        }
        // Days from civil (proleptic Gregorian), March-based year. Every
        // input is a u8 or u16, so no step below overflows an i64.
        let m = i64::from(self.months);
        let y = i64::from(self.years).checked_add(if m <= 2 { 1999 } else { 2000 })?;
        let era = y.div_euclid(400);
        let yoe = y.rem_euclid(400);
        let mp = m.checked_add(9)? % 12;
        let doy = (mp.checked_mul(153)?.checked_add(2)? / 5)
            .checked_add(i64::from(self.day_of_month))?
            .checked_sub(1)?;
        let doe = yoe
            .checked_mul(365)?
            .checked_add(yoe / 4)?
            .checked_sub(yoe / 100)?
            .checked_add(doy)?;
        // Shift the epoch to 2000-01-01.
        let days = era
            .checked_mul(146_097)?
            .checked_add(doe)?
            .checked_sub(730_425)?;
        days.checked_mul(24)?
            .checked_add(i64::from(self.hours))?
            .checked_mul(60)?
            .checked_add(i64::from(self.minutes))?
            .checked_mul(60_000)?
            .checked_add(i64::from(self.milliseconds))
    }

    /// [`Cp56Time2a::millis_since_2000`] read as standard time: one hour less
    /// when `SU` is set, so a summer-time tag and a standard-time clock compare
    /// in one time. `None` as for `millis_since_2000`.
    ///
    /// Clause 7.2.6.18: *"The summer-time bit SU may optionally be used as an
    /// additional information to indicate the presently valid time (standard or
    /// summer-time)."* The one hour is TS 60870-5-604 5.4.25.4's (PDF page
    /// index 88): *"A command sent with SU-bit =1 (in summer time) and time
    /// 15:00:000 is executed by the DUT when its time is 14:00:000 not in summer
    /// time."*
    #[must_use]
    pub fn standard_millis_since_2000(&self) -> Option<i64> {
        const HOUR: i64 = 3_600_000;
        self.millis_since_2000().and_then(|millis| {
            if self.summer_time {
                millis.checked_sub(HOUR)
            } else {
                Some(millis)
            }
        })
    }

    /// The tag for `since_epoch` after 1970-01-01 00:00:00 UTC, read as UTC.
    ///
    /// Every field is filled within its clause 7.2.6.18 range. Day of week is
    /// filled as the clause numbers it, Monday `<1>` to Sunday `<7>` (the
    /// clause's `<0>` "not used" is never written). `SU`, `IV` and `GEN` are
    /// clear: whether the time is summer time is the caller's to set. Anything
    /// below a millisecond is cut off, not rounded, so the tag never names a
    /// later millisecond than the instant.
    ///
    /// The `years` field is `UI7` `0..99`, read as 2000 to 2099 (as
    /// [`Cp56Time2a::millis_since_2000`] does). An instant before
    /// 2000-01-01 00:00:00.000 or from 2100-01-01 00:00:00.000 on is an error,
    /// never a wrapped year.
    ///
    /// # Errors
    ///
    /// [`TimeRangeError::BeforeYear2000`] or [`TimeRangeError::AfterYear2099`]
    /// for an instant outside the years 2000 to 2099.
    pub fn from_unix(since_epoch: Duration) -> Result<Self, TimeRangeError> {
        // Past i64 is past 2099 as well.
        let millis = i64::try_from(since_epoch.as_millis()).unwrap_or(i64::MAX);
        if millis < UNIX_MILLIS_2000 {
            return Err(TimeRangeError::BeforeYear2000);
        }
        if millis >= UNIX_MILLIS_2100 {
            return Err(TimeRangeError::AfterYear2099);
        }
        // In range, so nothing below overflows and every field fits its type.
        let since_2000 = millis.wrapping_sub(UNIX_MILLIS_2000);
        let mut days = since_2000 / MILLIS_PER_DAY;
        let of_day = since_2000 % MILLIS_PER_DAY;
        // 2000-01-01 was a Saturday, day 6 of the clause's Monday-based week.
        let day_of_week = low_u8(days.wrapping_add(5) % 7).wrapping_add(1);
        let mut year = 2000;
        while days >= days_in_year(year) {
            days = days.wrapping_sub(days_in_year(year));
            year = year.wrapping_add(1);
        }
        let mut month = 1;
        while days >= days_in_month(year, month) {
            days = days.wrapping_sub(days_in_month(year, month));
            month = month.wrapping_add(1);
        }
        Ok(Self {
            milliseconds: low_u16(of_day % 60_000),
            minutes: low_u8(of_day / 60_000 % 60),
            substituted: false,
            invalid: false,
            hours: low_u8(of_day / 3_600_000),
            summer_time: false,
            day_of_month: low_u8(days).wrapping_add(1),
            day_of_week,
            months: low_u8(month),
            years: low_u8(year.wrapping_sub(2000)),
        })
    }

    /// [`Cp56Time2a::from_unix`] for a `SystemTime`, typically the caller's
    /// `SystemTime::now()`. A time before the Unix epoch is
    /// [`TimeRangeError::BeforeYear2000`].
    ///
    /// # Errors
    ///
    /// As [`Cp56Time2a::from_unix`].
    pub fn from_system_time(time: SystemTime) -> Result<Self, TimeRangeError> {
        let since_epoch = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TimeRangeError::BeforeYear2000)?;
        Self::from_unix(since_epoch)
    }

    /// The time since 1970-01-01 00:00:00 UTC this tag names, its fields read
    /// as UTC and `years` as 2000 to 2099.
    ///
    /// `SU`, `IV`, `GEN` and day of week are not read: the date fields alone
    /// name the instant, and a summer-time tag is the caller's to shift (see
    /// [`Cp56Time2a::standard_millis_since_2000`]). A field outside its clause
    /// 7.2.6.18 range (`milliseconds` `0..59999`, `minutes` `0..59`, `hours`
    /// `0..23`, `months` `1..12`, `years` `0..99`, day of month `1` to the
    /// month's last day) is [`TimeRangeError::Field`], never carried into the
    /// next field.
    ///
    /// # Errors
    ///
    /// [`TimeRangeError::Field`] for the first field outside its range.
    pub fn to_unix(&self) -> Result<Duration, TimeRangeError> {
        let check = |field, value: u16, range: std::ops::RangeInclusive<u16>| {
            if range.contains(&value) {
                Ok(())
            } else {
                Err(TimeRangeError::Field { field, value })
            }
        };
        check(TimeField::Milliseconds, self.milliseconds, 0..=59_999)?;
        check(TimeField::Minutes, self.minutes.into(), 0..=59)?;
        check(TimeField::Hours, self.hours.into(), 0..=23)?;
        check(TimeField::Months, self.months.into(), 1..=12)?;
        check(TimeField::Years, self.years.into(), 0..=99)?;
        let last_day = days_in_month(i64::from(self.years).wrapping_add(2000), self.months.into());
        check(
            TimeField::DayOfMonth,
            self.day_of_month.into(),
            1..=low_u16(last_day),
        )?;
        // `None` only for a month outside 1..=12, which was checked above.
        let since_2000 = self
            .millis_since_2000()
            .ok_or_else(|| TimeRangeError::Field {
                field: TimeField::Months,
                value: self.months.into(),
            })?;
        // The checked fields make both terms non-negative and their sum small.
        Ok(Duration::from_millis(
            UNIX_MILLIS_2000.wrapping_add(since_2000).cast_unsigned(),
        ))
    }

    /// [`Cp56Time2a::to_unix`] as a `SystemTime`.
    ///
    /// # Errors
    ///
    /// As [`Cp56Time2a::to_unix`], and [`TimeRangeError::AfterYear2099`] if the
    /// platform's `SystemTime` cannot hold the instant.
    pub fn to_system_time(&self) -> Result<SystemTime, TimeRangeError> {
        UNIX_EPOCH
            .checked_add(self.to_unix()?)
            .ok_or(TimeRangeError::AfterYear2099)
    }

    /// The three-octet prefix (milliseconds, minutes, `GEN`, `IV`) as the
    /// `CP24Time2a` of clause 7.2.6.19.
    #[must_use]
    pub const fn to_cp24(&self) -> Cp24Time2a {
        Cp24Time2a {
            milliseconds: self.milliseconds,
            minutes: self.minutes,
            substituted: self.substituted,
            invalid: self.invalid,
        }
    }

    /// Reads seven octets.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?;
        let (milliseconds, minutes, substituted, invalid) = parse_prefix(&raw)?;
        Ok(Self {
            milliseconds,
            minutes,
            substituted,
            invalid,
            hours: raw[3] & 0x1F,
            summer_time: raw[3] & 0x80 != 0,
            day_of_month: raw[4] & 0x1F,
            day_of_week: raw[4] >> 5,
            months: raw[5] & 0x0F,
            years: raw[6] & 0x7F,
        })
    }

    /// Appends seven octets, reserved bits written as zero.
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_prefix(
            self.milliseconds,
            self.minutes,
            self.substituted,
            self.invalid,
            out,
        );
        let mut hours = self.hours & 0x1F;
        if self.summer_time {
            hours |= 0x80;
        }
        out.push(hours);
        out.push((self.day_of_month & 0x1F) | (self.day_of_week << 5));
        out.push(self.months & 0x0F);
        out.push(self.years & 0x7F);
    }
}

/// Milliseconds from the Unix epoch to 2000-01-01 00:00:00.000 UTC, the first
/// instant a `CP56Time2a` names.
const UNIX_MILLIS_2000: i64 = 946_684_800_000;
/// Milliseconds from the Unix epoch to 2100-01-01 00:00:00.000 UTC, the first
/// instant after the last one a `CP56Time2a` names.
const UNIX_MILLIS_2100: i64 = 4_102_444_800_000;
const MILLIS_PER_DAY: i64 = 86_400_000;

/// The low octet of `x`, which the caller has bounded to `0..=255`.
const fn low_u8(x: i64) -> u8 {
    let [lo, ..] = x.to_le_bytes();
    lo
}

/// The low two octets of `x`, which the caller has bounded to `0..=65535`.
const fn low_u16(x: i64) -> u16 {
    let [lo, hi, ..] = x.to_le_bytes();
    u16::from_le_bytes([lo, hi])
}

/// The Gregorian leap year rule.
const fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const fn days_in_year(year: i64) -> i64 {
    if is_leap(year) { 366 } else { 365 }
}

/// Days of `month` (`1..=12`) in `year`.
const fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Why a [`Cp56Time2a`] and a time since the Unix epoch could not be
/// converted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRangeError {
    /// The instant is before 2000-01-01 00:00:00.000 UTC, the earliest a
    /// `years` field of `0..99` read as 2000 to 2099 can name.
    BeforeYear2000,
    /// The instant is 2100-01-01 00:00:00.000 UTC or later.
    AfterYear2099,
    /// A field of the tag lies outside its clause 7.2.6.18 range.
    Field {
        /// Which field.
        field: TimeField,
        /// Its value.
        value: u16,
    },
}

/// A date or time field of [`Cp56Time2a`], for [`TimeRangeError::Field`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeField {
    /// `milliseconds`, `0..59999`.
    Milliseconds,
    /// `minutes`, `0..59`.
    Minutes,
    /// `hours`, `0..23`.
    Hours,
    /// `day_of_month`, `1` to the month's last day.
    DayOfMonth,
    /// `months`, `1..12`.
    Months,
    /// `years`, `0..99`.
    Years,
}

impl fmt::Display for TimeRangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeforeYear2000 => f.write_str("time before the year 2000"),
            Self::AfterYear2099 => f.write_str("time after the year 2099"),
            Self::Field { field, value } => {
                write!(f, "{field:?} {value} outside its range")
            }
        }
    }
}

impl std::error::Error for TimeRangeError {}

/// Three-octet binary time (`CP24Time2a`), clause 7.2.6.19.
///
/// `CP24Time2a := CP24{milliseconds,minutes,RES1,invalid}`: the first three
/// octets of the [`Cp56Time2a`] layout, which is why clause 7.2.6.19 says "the
/// octets 4 up to 7 are discarded". Encoded through the same prefix helper as
/// the seven-octet form so the two cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cp24Time2a {
    /// Milliseconds of the minute, `0..=59999`.
    pub milliseconds: u16,
    /// Minutes, `0..=59`.
    pub minutes: u8,
    /// `RES1`/`GEN`: `true` = substituted time, `false` = genuine time.
    pub substituted: bool,
    /// `IV`: the time is invalid.
    pub invalid: bool,
}

impl Cp24Time2a {
    /// Octets on the wire.
    pub const LEN: usize = 3;

    /// Reads three octets.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let (milliseconds, minutes, substituted, invalid) = parse_prefix(buf)?;
        Ok(Self {
            milliseconds,
            minutes,
            substituted,
            invalid,
        })
    }

    /// Appends three octets.
    pub fn encode(&self, out: &mut Vec<u8>) {
        encode_prefix(
            self.milliseconds,
            self.minutes,
            self.substituted,
            self.invalid,
            out,
        );
    }
}

/// Two-octet binary time (`CP16Time2a`), clause 7.2.6.20.
///
/// `CP16Time2a := UI16[1..16]<0..59 999 ms>`: an **elapsed** time in
/// milliseconds ("used for an elapsed time such as 'Relay operating time' or
/// 'Relay duration time'"), little-endian on the wire. The clause's
/// `0..59 999` range is the caller's to respect: this codec carries any `u16`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Cp16Time2a {
    /// Elapsed milliseconds, `0..=59999` per the clause.
    pub milliseconds: u16,
}

impl Cp16Time2a {
    /// Octets on the wire.
    pub const LEN: usize = 2;

    /// Reads two octets, little-endian.
    ///
    /// # Errors
    ///
    /// [`AsduError::TooShort`] if `buf` is shorter than [`Self::LEN`].
    pub fn parse(buf: &[u8]) -> Result<Self, AsduError> {
        let raw = octets::<{ Self::LEN }>(buf)?;
        Ok(Self {
            milliseconds: u16::from_le_bytes([raw[0], raw[1]]),
        })
    }

    /// Appends two octets, little-endian.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.milliseconds.to_le_bytes());
    }
}

/// Shared three-octet prefix of [`Cp56Time2a`] and [`Cp24Time2a`] (7.2.6.18/19).
///
/// Both time tags start with the same three octets, and clause 7.2.6.19
/// defines `CP24Time2a` as that prefix ("the octets 4 up to 7 are discarded").
/// One helper keeps the two encoders from drifting.
pub fn encode_prefix(
    milliseconds: u16,
    minutes: u8,
    substituted: bool,
    invalid: bool,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&milliseconds.to_le_bytes());
    let mut octet = minutes & 0x3F;
    if substituted {
        octet |= 0x40;
    }
    if invalid {
        octet |= 0x80;
    }
    out.push(octet);
}

/// Reads the shared three-octet prefix. See [`encode_prefix`].
pub fn parse_prefix(buf: &[u8]) -> Result<(u16, u8, bool, bool), AsduError> {
    let raw = octets::<3>(buf)?;
    Ok((
        u16::from_le_bytes([raw[0], raw[1]]),
        raw[2] & 0x3F,
        raw[2] & 0x40 != 0,
        raw[2] & 0x80 != 0,
    ))
}
