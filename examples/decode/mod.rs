//! Typed printing of monitor-direction ASDUs, shared by the `spontaneous` and
//! `interrogation` examples.

use iec104::asdu::{self, AddressSizes, Header, Point, Quality, TimeTag, Value};

/// Prints one line per information object of `asdu`: its cause, the common
/// address, the object address, the value, the quality bits that are set and
/// the time tag. Returns how many objects were printed.
///
/// Every monitor type with a process value (`<1>` to `<21>` and `<30>` to
/// `<40>`) is printed through `Objects::points`, the same shape for all of
/// them. Any other type is named but not printed.
pub fn print_objects(asdu: &[u8], sizes: AddressSizes) -> usize {
    let header = match Header::parse_with(asdu, sizes) {
        Ok(header) => header,
        Err(e) => {
            println!("   not understood: {e:?}");
            return 0;
        }
    };
    let cause = header.cause.mnemonic();
    let name = header.type_id.name();
    let decoded = match asdu::decode_with(asdu, sizes) {
        Ok(decoded) => decoded,
        Err(e) => {
            println!("   {cause} {name}: {e:?}");
            return 0;
        }
    };
    let points = decoded.objects.points();
    if points.is_empty() && !decoded.objects.is_empty() {
        println!("   {cause} {name}: not a process value, not printed here");
    }
    for point in &points {
        println!(
            "   {cause} {name} CA {} IOA {}: {}{}{}",
            header.common_address,
            point.ioa,
            value(&point.value),
            quality(point),
            time(point.time),
        );
    }
    points.len()
}

fn value(value: &Value) -> String {
    match *value {
        Value::Single(on) => if on { "ON" } else { "OFF" }.to_string(),
        Value::Double(state) => format!("{state:?}"),
        Value::StepPosition { value, transient } => {
            format!(
                "step {value}{}",
                if transient { " (transient)" } else { "" }
            )
        }
        Value::Bitstring(bits) => format!("{bits:#010x}"),
        Value::Normalized(v) => format!("{v:.5}"),
        Value::Scaled(v) => v.to_string(),
        Value::Float(v) => v.to_string(),
        Value::Counter {
            reading,
            sequence,
            carry,
            adjusted,
        } => format!(
            "{reading} (SQ {sequence}{}{})",
            if carry { " CY" } else { "" },
            if adjusted { " CA" } else { "" }
        ),
        Value::ProtectionEvent {
            state,
            elapsed_ms,
            elapsed_invalid,
        } => format!("{state:?}, {elapsed_ms} ms{}", ei(elapsed_invalid)),
        Value::ProtectionStart {
            start,
            elapsed_ms,
            elapsed_invalid,
        } => format!("{start:?}, {elapsed_ms} ms{}", ei(elapsed_invalid)),
        Value::ProtectionCommand {
            command,
            elapsed_ms,
            elapsed_invalid,
        } => format!("{command:?}, {elapsed_ms} ms{}", ei(elapsed_invalid)),
        Value::PackedSingle { status, change } => {
            format!("status {status:#06x} change {change:#06x}")
        }
    }
}

const fn ei(invalid: bool) -> &'static str {
    if invalid { " EI" } else { "" }
}

/// The quality bits that are set, or nothing for a good value.
fn quality(point: &Point) -> String {
    let Some(Quality {
        invalid,
        not_topical,
        substituted,
        blocked,
        overflow,
    }) = point.quality
    else {
        return String::new();
    };
    let bits = [
        (invalid, "IV"),
        (not_topical, "NT"),
        (substituted, "SB"),
        (blocked, "BL"),
        (overflow == Some(true), "OV"),
    ];
    let set: Vec<&str> = bits
        .iter()
        .filter(|(set, _)| *set)
        .map(|(_, name)| *name)
        .collect();
    if set.is_empty() {
        String::new()
    } else {
        format!(" [{}]", set.join(" "))
    }
}

fn time(time: Option<TimeTag>) -> String {
    let flags = |invalid: bool, substituted: bool| {
        format!(
            "{}{}",
            if invalid { " IV" } else { "" },
            if substituted { " GEN" } else { "" }
        )
    };
    match time {
        None => String::new(),
        Some(TimeTag::Cp24(t)) => format!(
            " at minute {}, {} ms{}",
            t.minutes,
            t.milliseconds,
            flags(t.invalid, t.substituted)
        ),
        Some(TimeTag::Cp56(t)) => format!(
            " at 20{:02}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}{}",
            t.years,
            t.months,
            t.day_of_month,
            t.hours,
            t.minutes,
            t.milliseconds / 1000,
            t.milliseconds % 1000,
            flags(t.invalid, t.substituted)
        ),
    }
}
