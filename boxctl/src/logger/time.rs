use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    format_unix_time(seconds as i64)
}

#[cfg(target_family = "unix")]
fn format_unix_time(seconds: i64) -> String {
    use std::mem::MaybeUninit;
    use std::os::raw::{c_char, c_int, c_long};

    #[repr(C)]
    struct Tm {
        tm_sec: c_int,
        tm_min: c_int,
        tm_hour: c_int,
        tm_mday: c_int,
        tm_mon: c_int,
        tm_year: c_int,
        tm_wday: c_int,
        tm_yday: c_int,
        tm_isdst: c_int,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        tm_gmtoff: c_long,
        #[cfg(any(target_os = "android", target_os = "linux"))]
        tm_zone: *const c_char,
    }

    extern "C" {
        fn localtime_r(timep: *const i64, result: *mut Tm) -> *mut Tm;
    }

    let mut tm = MaybeUninit::<Tm>::uninit();
    let ok = unsafe { !localtime_r(&seconds, tm.as_mut_ptr()).is_null() };
    if ok {
        let tm = unsafe { tm.assume_init() };
        return format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        );
    }

    format_unix_time_utc(seconds)
}

#[cfg(not(target_family = "unix"))]
fn format_unix_time(seconds: i64) -> String {
    format_unix_time_utc(seconds)
}

fn format_unix_time_utc(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let secs = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = secs / 3_600;
    let minute = (secs % 3_600) / 60;
    let second = secs % 60;

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year, month, day)
}
