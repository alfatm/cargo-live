//! Minimal timestamped logging to stderr.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::log::emit(format_args!($($arg)*))
    };
}

pub fn emit(args: fmt::Arguments<'_>) {
    eprintln!("{} {args}", now_rfc3339());
}

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_utc(secs)
}

fn format_utc(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn formats_utc_timestamps() {
        assert_eq!(super::format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(super::format_utc(1_795_000_000), "2026-11-18T11:06:40Z");
    }
}
