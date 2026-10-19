//! Time elements: IEC 60870-5-101:2003 clause 7.2.6.18–7.2.6.20.
//!
//! `CP56Time2a` (7.2.6.18) is the seven-octet time tag, `CP24Time2a` (7.2.6.19)
//! is its three-octet prefix ("the octets 4 up to 7 are discarded"), and
//! `CP16Time2a` (7.2.6.20) is a two-octet elapsed time, not a time tag.
//! The last part converts `CP56Time2a` to and from a time since the Unix epoch.

// Test code may panic, index and compute freely, as clippy.toml allows inside #[test] functions.
#![allow(clippy::panic, clippy::indexing_slicing)]

use std::time::{Duration, UNIX_EPOCH};

use iec104::asdu::{AsduError, Cp16Time2a, Cp24Time2a, Cp56Time2a, TimeField, TimeRangeError};

/// Clarke/Reynders/Wright, *Practical Modern SCADA Protocols*, Appendix D:
/// `55 69 10 0D 13 01 01` is 26.965 s, 16 min, 13 h, day 19, January, year 2001,
/// day of week unused, every flag clear.
const WORKED: [u8; 7] = [0x55, 0x69, 0x10, 0x0D, 0x13, 0x01, 0x01];

const fn worked_cp56() -> Cp56Time2a {
    Cp56Time2a {
        milliseconds: 26_965,
        minutes: 16,
        substituted: false,
        invalid: false,
        hours: 13,
        summer_time: false,
        day_of_month: 19,
        day_of_week: 0,
        months: 1,
        years: 1,
    }
}

fn assert_too_short<T, F>(len: usize, parse: F)
where
    T: std::fmt::Debug,
    F: Fn(&[u8]) -> Result<T, AsduError>,
{
    let full = vec![0xA5; len];
    for have in 0..len {
        match parse(&full[..have]) {
            Err(AsduError::TooShort { need, have: got }) => {
                assert_eq!(need, len, "need at prefix {have}");
                assert_eq!(got, have, "have at prefix {have}");
            }
            other => panic!("prefix {have} of {len}: expected TooShort, got {other:?}"),
        }
    }
}

/// Clause 7.2.6.18: `CP56Time2a` is seven octets on the wire.
#[test]
fn cp56_len_is_seven() {
    assert_eq!(Cp56Time2a::LEN, 7);
}

/// Clause 7.2.6.18 plus the Appendix D worked example: the seven octets
/// `55 69 10 0D 13 01 01` are milliseconds 26965, minutes 16, hours 13,
/// day of month 19, months 1, years 1, day of week 0, every flag false.
#[test]
fn cp56_worked_example_parses_and_encodes() {
    let parsed = Cp56Time2a::parse(&WORKED).expect("worked example");
    assert_eq!(parsed, worked_cp56());
    let mut out = Vec::new();
    parsed.encode(&mut out);
    assert_eq!(out, WORKED);
}

/// Clause 7.2.6.18: every named field occupies the bit range the definition
/// list assigns, and a fully populated value round-trips.
#[test]
fn cp56_named_fields_and_round_trip() {
    let value = Cp56Time2a {
        milliseconds: 59_999,
        minutes: 0x3F,
        substituted: true,
        invalid: true,
        hours: 0x1F,
        summer_time: true,
        day_of_month: 0x1F,
        day_of_week: 7,
        months: 0x0F,
        years: 0x7F,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out.len(), Cp56Time2a::LEN);
    assert_eq!(&out[0..2], &59_999u16.to_le_bytes());
    assert_eq!(out[2], 0x3F | 0x40 | 0x80, "minutes | GEN | IV");
    assert_eq!(out[3], 0x1F | 0x80, "hours | SU; RES2 bits 6-7 stay zero");
    assert_eq!(out[4], 0x1F | 0xE0, "day of month | Sunday");
    assert_eq!(out[5], 0x0F, "months; RES3 bits 5-8 stay zero");
    assert_eq!(out[6], 0x7F, "years; RES4 bit 8 stays zero");
    assert_eq!(Cp56Time2a::parse(&out).expect("round trip"), value);
}

/// Clause 7.2.6.18: `summer_time` is bit 8 of octet 4 (`0x80`).
#[test]
fn cp56_summer_time_sets_octet4_bit8() {
    let mut value = worked_cp56();
    value.summer_time = true;
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out[3], 0x0D | 0x80);
    assert!(Cp56Time2a::parse(&out).expect("su").summer_time);
}

/// Clause 7.2.6.18: `substituted` (GEN/RES1) is bit 7 of octet 3 (`0x40`)
/// and `invalid` (IV) is bit 8 of the same octet (`0x80`).
#[test]
fn cp56_substituted_and_invalid_set_octet3_flags() {
    let mut value = worked_cp56();
    value.substituted = true;
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out[2] & 0x40, 0x40);
    assert_eq!(out[2] & 0x80, 0);
    value.invalid = true;
    out.clear();
    value.encode(&mut out);
    assert_eq!(out[2], 0x10 | 0x40 | 0x80);
}

/// Clause 7.2.6.18: day of week 7 (Sunday) occupies bits 6-8 of octet 5, so
/// day of month 31 with Sunday encodes octet 5 as `0x1F | 0xE0`.
#[test]
fn cp56_sunday_sets_octet5_day_of_week() {
    let mut value = worked_cp56();
    value.day_of_month = 31;
    value.day_of_week = 7;
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out[4], 0x1F | 0xE0);
    assert_eq!(Cp56Time2a::parse(&out).expect("sunday").day_of_week, 7);
}

/// Clause 7.2.6.18: reserved bits (`RES2` of the hours octet, `RES3` of the
/// months octet, `RES4` of the years octet) are written as zero and ignored
/// on decode, so a re-encode clears them.
#[test]
fn cp56_reserved_bits_are_written_zero_and_ignored() {
    let mut wire = WORKED;
    wire[3] |= 0x60;
    wire[5] |= 0xF0;
    wire[6] |= 0x80;
    let parsed = Cp56Time2a::parse(&wire).expect("reserved set");
    assert_eq!(parsed, worked_cp56());
    let mut out = Vec::new();
    parsed.encode(&mut out);
    assert_eq!(out, WORKED);
}

/// Clause 7.2.6.18: a short buffer is `TooShort { need: 7, have }`, never a
/// panic and never `Ok`, for every prefix of a valid encoding.
#[test]
fn cp56_truncation_sweep() {
    assert_too_short(Cp56Time2a::LEN, Cp56Time2a::parse);
}

/// Clause 7.2.6.19: `CP24Time2a` is three octets on the wire.
#[test]
fn cp24_len_is_three() {
    assert_eq!(Cp24Time2a::LEN, 3);
}

/// Clause 7.2.6.19: the three-octet prefix of the worked example is the
/// `CP24Time2a`, and `Cp56Time2a::to_cp24` returns that same prefix.
#[test]
fn cp24_is_the_cp56_prefix() {
    let from_prefix = Cp24Time2a::parse(&WORKED[..3]).expect("prefix");
    let from_cp56 = Cp56Time2a::parse(&WORKED).expect("cp56").to_cp24();
    assert_eq!(from_prefix, from_cp56);
    assert_eq!(
        from_prefix,
        Cp24Time2a {
            milliseconds: 26_965,
            minutes: 16,
            substituted: false,
            invalid: false,
        }
    );
    let mut out = Vec::new();
    from_prefix.encode(&mut out);
    assert_eq!(out, &WORKED[..3]);
}

/// Clause 7.2.6.19: a fully populated prefix round-trips, and its flags sit
/// in the same bits as the seven-octet form.
#[test]
fn cp24_named_fields_and_round_trip() {
    let value = Cp24Time2a {
        milliseconds: 59_999,
        minutes: 0x3F,
        substituted: true,
        invalid: true,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out.len(), Cp24Time2a::LEN);
    assert_eq!(&out[0..2], &59_999u16.to_le_bytes());
    assert_eq!(out[2], 0x3F | 0x40 | 0x80);
    assert_eq!(Cp24Time2a::parse(&out).expect("round trip"), value);
    assert_eq!(
        Cp56Time2a {
            milliseconds: value.milliseconds,
            minutes: value.minutes,
            substituted: value.substituted,
            invalid: value.invalid,
            ..Cp56Time2a::default()
        }
        .to_cp24(),
        value
    );
}

/// Clause 7.2.6.19: a short buffer is `TooShort { need: 3, have }` for every
/// prefix of a valid encoding.
#[test]
fn cp24_truncation_sweep() {
    assert_too_short(Cp24Time2a::LEN, Cp24Time2a::parse);
}

/// Clause 7.2.6.20: `CP16Time2a` is two octets on the wire.
#[test]
fn cp16_len_is_two() {
    assert_eq!(Cp16Time2a::LEN, 2);
}

/// Clause 7.2.6.20: `UI16[1..16]<0..59 999 ms>`, little-endian. 59999 is
/// `0xEA5F`, so the wire octets are `5F EA` (not `9F EA`, which is 60063 and
/// outside the range).
#[test]
fn cp16_59999_is_little_endian_5f_ea() {
    let value = Cp16Time2a {
        milliseconds: 59_999,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, [0x5F, 0xEA]);
    assert_eq!(Cp16Time2a::parse(&out).expect("59999").milliseconds, 59_999);
}

/// Clause 7.2.6.20: a fully populated elapsed time round-trips, including a
/// value the field can hold past the clause's stated range (the codec does
/// not clamp).
#[test]
fn cp16_round_trip_does_not_clamp() {
    let value = Cp16Time2a {
        milliseconds: 0xFFFF,
    };
    let mut out = Vec::new();
    value.encode(&mut out);
    assert_eq!(out, [0xFF, 0xFF]);
    assert_eq!(
        Cp16Time2a::parse(&[0x00, 0x00]).expect("zero").milliseconds,
        0
    );
    assert_eq!(Cp16Time2a::parse(&out).expect("round trip"), value);
}

/// Clause 7.2.6.20: a short buffer is `TooShort { need: 2, have }` for every
/// prefix of a valid encoding.
#[test]
fn cp16_truncation_sweep() {
    assert_too_short(Cp16Time2a::LEN, Cp16Time2a::parse);
}

// Conversion to and from the Unix epoch.
//
// Every Unix time below was computed outside this crate with GNU coreutils
// `date`, reading the date as UTC, e.g. `date -u -d '2001-01-19 13:16:26 UTC'
// +%s` prints `979910186`. The day of week comes from the same tool's `%u`
// (ISO 8601: 1 = Monday .. 7 = Sunday), the numbering clause 7.2.6.18 uses
// (`<1>` Monday .. `<7>` Sunday).

/// A tag with every flag clear, as `from_unix` fills it.
const fn utc(
    years: u8,
    months: u8,
    day_of_month: u8,
    day_of_week: u8,
    hours: u8,
    minutes: u8,
    milliseconds: u16,
) -> Cp56Time2a {
    Cp56Time2a {
        milliseconds,
        minutes,
        substituted: false,
        invalid: false,
        hours,
        summer_time: false,
        day_of_month,
        day_of_week,
        months,
        years,
    }
}

/// Asserts both directions: `unix_millis` gives `tag`, and `tag` gives
/// `unix_millis` back.
fn assert_both_ways(unix_millis: u64, tag: Cp56Time2a) {
    let since_epoch = Duration::from_millis(unix_millis);
    assert_eq!(Cp56Time2a::from_unix(since_epoch), Ok(tag), "{unix_millis}");
    assert_eq!(tag.to_unix(), Ok(since_epoch), "{tag:?}");
}

/// The Appendix D worked example (Clarke/Reynders/Wright): `55 69 10 0D 13
/// 01 01` is 2001-01-19 13:16:26.965. `date -u -d '2001-01-19 13:16:26 UTC'
/// +%s` is 979910186, so the instant is 979910186965 ms; `%u` is 5, a Friday.
/// The example leaves day of week unused (`0`), which `to_unix` does not read.
#[test]
fn unix_worked_example() {
    let mut expected = worked_cp56();
    expected.day_of_week = 5;
    assert_both_ways(979_910_186_965, expected);
    assert_eq!(
        worked_cp56().to_unix(),
        Ok(Duration::from_millis(979_910_186_965))
    );
    let mut out = Vec::new();
    Cp56Time2a::from_unix(Duration::from_millis(979_910_186_965))
        .unwrap()
        .encode(&mut out);
    // Octet 5: day of month 19 (0x13) with Friday (5) in bits 6..8.
    assert_eq!(out, [0x55, 0x69, 0x10, 0x0D, 0x13 | (5 << 5), 0x01, 0x01]);
}

/// The first instant the `UI7` years field read as 2000 to 2099 names:
/// `date -u -d '2000-01-01 00:00:00 UTC' +%s` is 946684800, `%u` 6
/// (Saturday).
#[test]
fn unix_first_instant_of_2000() {
    assert_both_ways(946_684_800_000, utc(0, 1, 1, 6, 0, 0, 0));
}

/// The last instant: `date -u -d '2099-12-31 23:59:59 UTC' +%s` is
/// 4102444799, `%u` 4 (Thursday), plus 999 ms.
#[test]
fn unix_last_instant_of_2099() {
    assert_both_ways(4_102_444_799_999, utc(99, 12, 31, 4, 23, 59, 59_999));
}

/// 2000 is a leap year (divisible by 400). `date -u -d '2000-02-29 12:00:00
/// UTC' +%s` is 951825600 (`%u` 2, Tuesday); `date -u -d '2000-03-01
/// 00:00:00 UTC' +%s` is 951868800 (`%u` 3, Wednesday); `date -u -d
/// '2000-12-31 23:59:59 UTC' +%s` is 978307199 (`%u` 7, Sunday), the 366th
/// day.
#[test]
fn unix_leap_year_2000() {
    assert_both_ways(951_825_600_000, utc(0, 2, 29, 2, 12, 0, 0));
    assert_both_ways(951_868_800_000, utc(0, 3, 1, 3, 0, 0, 0));
    assert_both_ways(978_307_199_000, utc(0, 12, 31, 7, 23, 59, 59_000));
}

/// 2024 is a leap year: `date -u -d '2024-02-29 08:30:15 UTC' +%s` is
/// 1709195415 (`%u` 4, Thursday); `date -u -d '2024-12-31 00:00:00 UTC' +%s`
/// is 1735603200 (`%u` 2, Tuesday).
#[test]
fn unix_leap_year_2024() {
    assert_both_ways(1_709_195_415_250, utc(24, 2, 29, 4, 8, 30, 15_250));
    assert_both_ways(1_735_603_200_000, utc(24, 12, 31, 2, 0, 0, 0));
}

/// 2023 is not a leap year, so February ends on the 28th: `date -u -d
/// '2023-02-28 23:59:59 UTC' +%s` is 1677628799 (`%u` 2, Tuesday) and one
/// second later is 2023-03-01 (`%u` 3, Wednesday).
#[test]
fn unix_month_end_2023() {
    assert_both_ways(1_677_628_799_999, utc(23, 2, 28, 2, 23, 59, 59_999));
    assert_both_ways(1_677_628_800_000, utc(23, 3, 1, 3, 0, 0, 0));
}

/// Below a millisecond is cut off, never rounded up into the next one.
#[test]
fn unix_truncates_below_a_millisecond() {
    let since_epoch = Duration::from_millis(979_910_186_965) + Duration::from_nanos(999_999);
    let tag = Cp56Time2a::from_unix(since_epoch).unwrap();
    assert_eq!(tag.milliseconds, 26_965);
}

/// Out of range is an error, not a wrapped year. `date -u -d '1999-12-31
/// 23:59:59 UTC' +%s` is 946684799 (plus 999 ms, one millisecond before
/// 2000); `date -u -d '2100-01-01 00:00:00 UTC' +%s` is 4102444800.
#[test]
fn unix_out_of_range_is_an_error() {
    assert_eq!(
        Cp56Time2a::from_unix(Duration::from_millis(946_684_799_999)),
        Err(TimeRangeError::BeforeYear2000)
    );
    assert_eq!(
        Cp56Time2a::from_unix(Duration::ZERO),
        Err(TimeRangeError::BeforeYear2000)
    );
    assert_eq!(
        Cp56Time2a::from_unix(Duration::from_secs(4_102_444_800)),
        Err(TimeRangeError::AfterYear2099)
    );
    assert_eq!(
        Cp56Time2a::from_unix(Duration::MAX),
        Err(TimeRangeError::AfterYear2099)
    );
    assert_eq!(
        Cp56Time2a::from_system_time(UNIX_EPOCH - Duration::from_secs(1)),
        Err(TimeRangeError::BeforeYear2000)
    );
}

/// The `SystemTime` forms are the `Duration` forms from `UNIX_EPOCH`.
#[test]
fn unix_system_time_forms() {
    let at = UNIX_EPOCH + Duration::from_millis(979_910_186_965);
    let tag = Cp56Time2a::from_system_time(at).unwrap();
    assert_eq!(tag.to_cp24(), worked_cp56().to_cp24());
    assert_eq!(tag.day_of_week, 5, "2001-01-19 is a Friday");
    assert_eq!(tag.to_system_time(), Ok(at));
}

/// `to_unix` reads the date fields as UTC and ignores `SU`, `IV`, `GEN` and
/// day of week, which do not name the instant.
#[test]
fn unix_to_ignores_flags_and_day_of_week() {
    let mut tag = worked_cp56();
    tag.summer_time = true;
    tag.invalid = true;
    tag.substituted = true;
    tag.day_of_week = 1;
    assert_eq!(tag.to_unix(), Ok(Duration::from_millis(979_910_186_965)));
}

/// `to_unix` rejects a field outside its clause 7.2.6.18 range instead of
/// carrying it into the next field. February 2023 has 28 days, February 2024
/// has 29, April has 30.
#[test]
fn unix_to_rejects_fields_out_of_range() {
    let field = |field, value| Err(TimeRangeError::Field { field, value });
    let with = |edit: fn(&mut Cp56Time2a)| {
        let mut tag = worked_cp56();
        edit(&mut tag);
        tag.to_unix()
    };
    assert_eq!(
        with(|t| t.milliseconds = 60_000),
        field(TimeField::Milliseconds, 60_000)
    );
    assert_eq!(with(|t| t.minutes = 60), field(TimeField::Minutes, 60));
    assert_eq!(with(|t| t.hours = 24), field(TimeField::Hours, 24));
    assert_eq!(with(|t| t.months = 0), field(TimeField::Months, 0));
    assert_eq!(with(|t| t.months = 13), field(TimeField::Months, 13));
    assert_eq!(with(|t| t.years = 100), field(TimeField::Years, 100));
    assert_eq!(
        with(|t| t.day_of_month = 0),
        field(TimeField::DayOfMonth, 0)
    );
    assert_eq!(
        with(|t| {
            t.years = 23;
            t.months = 2;
            t.day_of_month = 29;
        }),
        field(TimeField::DayOfMonth, 29)
    );
    assert!(
        with(|t| {
            t.years = 24;
            t.months = 2;
            t.day_of_month = 29;
        })
        .is_ok()
    );
    assert_eq!(
        with(|t| {
            t.months = 4;
            t.day_of_month = 31;
        }),
        field(TimeField::DayOfMonth, 31)
    );
}

/// Every day of the range round-trips, and the days of week run 1..7 without
/// a gap. The range is 36525 days: (4102444800 - 946684800) / 86400 from the
/// two `date` bounds above, which is 100 * 365 plus the 25 leap days of 2000
/// to 2096.
#[test]
fn unix_every_day_round_trips() {
    const DAY: u64 = 86_400_000;
    let first = 946_684_800_000;
    let mut day_of_week = 6; // 2000-01-01, a Saturday
    for day in 0..36_525 {
        // Noon plus a few milliseconds, to exercise every field.
        let at = Duration::from_millis(first + day * DAY + 12 * 3_600_000 + 1_234);
        let tag = Cp56Time2a::from_unix(at).unwrap();
        assert_eq!(tag.day_of_week, day_of_week, "{tag:?}");
        assert_eq!(tag.to_unix(), Ok(at), "{tag:?}");
        day_of_week = day_of_week % 7 + 1;
    }
    assert_eq!(
        Cp56Time2a::from_unix(Duration::from_millis(first + 36_525 * DAY)),
        Err(TimeRangeError::AfterYear2099)
    );
}
