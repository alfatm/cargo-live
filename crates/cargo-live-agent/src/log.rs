//! Minimal timestamped logging to stderr.

use std::fmt;

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
    format_utc(cargo_live_proto::cred::now_unix())
}

fn format_utc(secs: i64) -> String {
    cargo_live_proto::cred::format_rfc3339(secs)
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
