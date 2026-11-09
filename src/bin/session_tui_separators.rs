//! Display-only separators of the transcript: local-date headers and the
//! "Unread Messages" line. Nothing here is stored or changes a message.
//!
//! Local dates use the UTC offset in force at each message's own instant
//! (not today's offset), so messages around a daylight-saving change land on
//! the right day.

use std::cell::RefCell;
use std::collections::HashMap;

use time::{Date, OffsetDateTime, UtcOffset};

/// Identifies a message across chats and reloads: in groups two members can
/// send at the same millisecond, so the author is part of the key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MessageKey {
    pub timestamp_ms: u64,
    pub outgoing: bool,
    pub author: String,
}

/// UTC offset (seconds) in force at `unix_seconds` in the user's time zone.
#[cfg(unix)]
fn system_offset_at(unix_seconds: i64) -> i32 {
    let time: libc::time_t = unix_seconds as libc::time_t;
    // SAFETY: `localtime_r` writes only into `tm`; the program never changes
    // TZ, so there is no concurrent environment write.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let result = unsafe { libc::localtime_r(&time, &mut tm) };
    if result.is_null() {
        return fallback_offset();
    }
    tm.tm_gmtoff as i32
}

#[cfg(not(unix))]
fn system_offset_at(unix_seconds: i64) -> i32 {
    // Windows has no multi-thread restriction on looking up the local offset.
    OffsetDateTime::from_unix_timestamp(unix_seconds)
        .ok()
        .and_then(|at| UtcOffset::local_offset_at(at).ok())
        .map_or_else(fallback_offset, UtcOffset::whole_seconds)
}

/// Offset at startup, where the system can't tell.
fn fallback_offset() -> i32 {
    super::LOCAL_OFFSET
        .get()
        .map_or(0, |offset| offset.whole_seconds())
}

thread_local! {
    /// Offsets by 15-minute bucket: every real zone transition falls on a
    /// quarter hour, and the transcript asks for the same instants each frame.
    static OFFSET_CACHE: RefCell<HashMap<i64, i32>> = RefCell::new(HashMap::new());
}

#[cfg(unix)]
unsafe extern "C" {
    fn tzset();
}

/// Prepare the C library's zone data. Call once, before other threads start.
pub fn init_local_time() {
    // SAFETY: called from `main` while the process is single-threaded.
    #[cfg(unix)]
    unsafe {
        tzset()
    };
}

/// The local offset at `timestamp_ms`.
pub fn local_offset(timestamp_ms: u64) -> UtcOffset {
    let seconds = (timestamp_ms / 1000) as i64;
    let bucket = seconds.div_euclid(900);
    let offset = OFFSET_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.len() > 200_000 {
            cache.clear();
        }
        *cache
            .entry(bucket)
            .or_insert_with(|| system_offset_at(bucket * 900))
    });
    UtcOffset::from_whole_seconds(offset).unwrap_or(UtcOffset::UTC)
}

/// Local calendar date of `timestamp_ms`, with `offset_at` giving the zone's
/// offset at a given instant (tests pass fixed rules).
pub fn local_date_with(timestamp_ms: u64, offset_at: impl Fn(u64) -> UtcOffset) -> Option<Date> {
    let at = OffsetDateTime::from_unix_timestamp((timestamp_ms / 1000) as i64).ok()?;
    Some(at.to_offset(offset_at(timestamp_ms)).date())
}

pub fn local_date(timestamp_ms: u64) -> Option<Date> {
    local_date_with(timestamp_ms, local_offset)
}

pub fn today() -> Option<Date> {
    local_date(now_ms())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// "Today", "Yesterday" or the full date with its weekday.
pub fn date_label(date: Date, today: Date) -> String {
    if date == today {
        return "Today".into();
    }
    if today.previous_day() == Some(date) {
        return "Yesterday".into();
    }
    let weekday = match date.weekday() {
        time::Weekday::Monday => "Mon",
        time::Weekday::Tuesday => "Tue",
        time::Weekday::Wednesday => "Wed",
        time::Weekday::Thursday => "Thu",
        time::Weekday::Friday => "Fri",
        time::Weekday::Saturday => "Sat",
        time::Weekday::Sunday => "Sun",
    };
    format!(
        "{}-{:02}-{:02} {weekday}",
        date.year(),
        date.month() as u8,
        date.day()
    )
}

/// What to draw above a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Separator {
    Date(String),
    Unread,
}

/// Separators above each message of a chat, in order. `dates[i]` is the
/// local date of message `i`; `unread_at` is the index of the first unread
/// message fixed for this visit. Derived from the whole list every time, so
/// loading more history can never repeat a header.
pub fn separators(
    dates: &[Option<Date>],
    unread_at: Option<usize>,
    today: Date,
) -> Vec<Vec<Separator>> {
    let mut out = Vec::with_capacity(dates.len());
    let mut previous: Option<Date> = None;
    for (index, date) in dates.iter().enumerate() {
        let mut above = Vec::new();
        if let Some(date) = *date
            && previous != Some(date)
        {
            above.push(Separator::Date(date_label(date, today)));
            previous = Some(date);
        }
        if unread_at == Some(index) {
            above.push(Separator::Unread);
        }
        out.push(above);
    }
    out
}

/// The unread boundary of one visit to a chat. It is fixed when the chat
/// is opened and only filled in later if unread messages arrive while it
/// had none, so reading (or scrolling) never moves or removes the line.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnreadMarker {
    pub conversation: String,
    pub first_unread: Option<MessageKey>,
}

impl UnreadMarker {
    /// Update for the open chat. `first_unread` is the key of the oldest
    /// unread incoming message now, if any.
    pub fn update(marker: &mut Option<Self>, conversation: &str, first_unread: Option<MessageKey>) {
        match marker {
            Some(current) if current.conversation == conversation => {
                if current.first_unread.is_none() {
                    current.first_unread = first_unread;
                }
            }
            _ => {
                *marker = Some(Self {
                    conversation: conversation.to_owned(),
                    first_unread,
                });
            }
        }
    }
}

/// Bottom-of-chat target for End / Ctrl+End: the newest message.
pub fn last_index(len: usize) -> Option<usize> {
    len.checked_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn d(y: i32, m: u8, day: u8) -> Date {
        Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), day).unwrap()
    }

    fn ms(date: Date, hour: u8, minute: u8, offset_hours: i8) -> u64 {
        let local = date.with_hms(hour, minute, 0).unwrap();
        let offset = UtcOffset::from_hms(offset_hours, 0, 0).unwrap();
        (local.assume_offset(offset).unix_timestamp() * 1000) as u64
    }

    fn fixed(hours: i8) -> impl Fn(u64) -> UtcOffset {
        move |_| UtcOffset::from_hms(hours, 0, 0).unwrap()
    }

    /// Central European rules for 2026: +1, +2 from 29 March 01:00 UTC to
    /// 25 October 01:00 UTC.
    fn cet(at_ms: u64) -> UtcOffset {
        let start = ms(d(2026, 3, 29), 1, 0, 0);
        let end = ms(d(2026, 10, 25), 1, 0, 0);
        let hours = if (start..end).contains(&at_ms) { 2 } else { 1 };
        UtcOffset::from_hms(hours, 0, 0).unwrap()
    }

    #[test]
    fn local_dates_follow_the_offset_at_each_instant() {
        // 23:30 local on 28 March (CET, +1) is still 28 March, while the
        // same wall clock in summer (+2) after the switch is the 29th's eve.
        let before = ms(d(2026, 3, 28), 23, 30, 1);
        assert_eq!(local_date_with(before, cet), Some(d(2026, 3, 28)));
        // 00:30 local right after the autumn change (+1 again).
        let after_autumn = ms(d(2026, 10, 26), 0, 30, 1);
        assert_eq!(local_date_with(after_autumn, cet), Some(d(2026, 10, 26)));
        // 23:30 local in summer is that day, not the next (UTC would say so
        // for a fixed winter offset reading).
        let summer_late = ms(d(2026, 7, 1), 23, 30, 2);
        assert_eq!(local_date_with(summer_late, cet), Some(d(2026, 7, 1)));
        assert_eq!(local_date_with(summer_late, fixed(1)), Some(d(2026, 7, 1)));
        assert_eq!(local_date_with(summer_late, fixed(3)), Some(d(2026, 7, 2)));
    }

    #[test]
    fn labels_today_yesterday_and_full_dates() {
        let today = d(2026, 1, 1);
        assert_eq!(date_label(today, today), "Today");
        assert_eq!(date_label(d(2025, 12, 31), today), "Yesterday");
        assert_eq!(date_label(d(2025, 12, 30), today), "2025-12-30 Tue");
        assert_eq!(date_label(d(2026, 3, 1), today), "2026-03-01 Sun");
    }

    #[test]
    fn date_headers_on_day_month_and_year_changes_only() {
        let today = d(2027, 1, 5);
        let dates = [
            Some(d(2026, 1, 31)),
            Some(d(2026, 1, 31)),
            Some(d(2026, 2, 1)),
            Some(d(2026, 12, 31)),
            Some(d(2027, 1, 1)),
            Some(d(2027, 1, 1)),
        ];
        let out = separators(&dates, None, today);
        let headers: Vec<usize> = out
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.is_empty())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(headers, [0, 2, 3, 4]);
        assert_eq!(out[4], [Separator::Date("2027-01-01 Fri".into())]);
    }

    #[test]
    fn rebuilding_after_more_history_never_repeats_headers() {
        let today = d(2026, 6, 10);
        let older = [Some(d(2026, 6, 8)), Some(d(2026, 6, 9))];
        let mut all = older.to_vec();
        all.extend([Some(d(2026, 6, 9)), Some(d(2026, 6, 10))]);
        let out = separators(&all, None, today);
        let count = out.iter().map(Vec::len).sum::<usize>();
        assert_eq!(count, 3);
        assert_eq!(out[3], [Separator::Date("Today".into())]);
    }

    #[test]
    fn unread_line_after_date_header_and_only_when_unread() {
        let today = d(2026, 6, 10);
        let dates = [Some(today), Some(today), Some(today)];
        assert!(separators(&dates, None, today).iter().all(|s| s.len() <= 1));
        let out = separators(&dates, Some(1), today);
        assert_eq!(out[1], [Separator::Unread]);
        let out = separators(&dates, Some(0), today);
        assert_eq!(out[0], [Separator::Date("Today".into()), Separator::Unread]);
    }

    fn key(ts: u64) -> MessageKey {
        MessageKey {
            timestamp_ms: ts,
            outgoing: false,
            author: "05aa".into(),
        }
    }

    #[test]
    fn unread_marker_is_fixed_per_visit() {
        let mut marker = None;
        UnreadMarker::update(&mut marker, "a", Some(key(5)));
        // Reading clears the unread state; the boundary stays.
        UnreadMarker::update(&mut marker, "a", None);
        assert_eq!(marker.as_ref().unwrap().first_unread, Some(key(5)));
        // A later unread message does not move it either.
        UnreadMarker::update(&mut marker, "a", Some(key(9)));
        assert_eq!(marker.as_ref().unwrap().first_unread, Some(key(5)));
        // Leaving and coming back recomputes.
        UnreadMarker::update(&mut marker, "b", None);
        UnreadMarker::update(&mut marker, "a", None);
        assert_eq!(marker.as_ref().unwrap().first_unread, None);
        // Opened with nothing unread, then a message arrives: shown once.
        UnreadMarker::update(&mut marker, "a", Some(key(12)));
        assert_eq!(marker.as_ref().unwrap().first_unread, Some(key(12)));
    }

    #[test]
    fn bottom_target() {
        assert_eq!(last_index(0), None);
        assert_eq!(last_index(4), Some(3));
    }
}
