//! Lightweight request metrics for the network diagnostics page.
//!
//! What is measured: one *onion round trip* — from handing the prepared
//! onion request to the transport (an HTTPS request to the path's guard
//! node) until the destination's reply has come back through all three hops
//! and been decrypted. It therefore includes the three relays, the
//! destination's own processing and, if set, the HTTPS proxy. It is not the
//! latency of any single node, which this client never measures on its own.
//!
//! Requests that fail before anything is sent (no path could be built) are
//! counted as failures without a duration. Retries are separate samples.
//! Recording is a short `std::sync::Mutex` section and never awaits.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

/// Window the summary covers.
pub const METRICS_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Samples kept at most (older ones are dropped first).
const MAX_SAMPLES: usize = 4096;
/// Recent error summaries kept.
const MAX_ERRORS: usize = 8;

#[derive(Clone, Copy, Debug)]
struct Sample {
    at: Instant,
    /// `None`: failed before a request was sent.
    round_trip: Option<Duration>,
    ok: bool,
}

/// Summary of the samples inside [`METRICS_WINDOW`].
#[derive(Clone, Debug, Default, PartialEq)]
pub struct MetricsSummary {
    pub requests: usize,
    pub failures: usize,
    /// `None` without samples.
    pub success_rate: Option<f64>,
    /// Round trips of successful requests.
    pub last_round_trip: Option<Duration>,
    pub average_round_trip: Option<Duration>,
    pub max_round_trip: Option<Duration>,
}

#[derive(Debug, Default)]
pub struct NetworkMetrics {
    samples: VecDeque<Sample>,
    last_success: Option<SystemTime>,
    errors: VecDeque<(SystemTime, String)>,
}

impl NetworkMetrics {
    pub fn record(&mut self, round_trip: Option<Duration>, error: Option<&str>) {
        self.record_at(Instant::now(), SystemTime::now(), round_trip, error);
    }

    /// Record one request finishing at `now` (`error: None` = success).
    pub fn record_at(
        &mut self,
        now: Instant,
        wall: SystemTime,
        round_trip: Option<Duration>,
        error: Option<&str>,
    ) {
        let ok = error.is_none();
        self.samples.push_back(Sample {
            at: now,
            round_trip,
            ok,
        });
        while self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
        self.prune(now);
        match error {
            None => self.last_success = Some(wall),
            Some(error) => {
                self.errors.push_back((wall, redact(error)));
                while self.errors.len() > MAX_ERRORS {
                    self.errors.pop_front();
                }
            }
        }
    }

    fn prune(&mut self, now: Instant) {
        while self
            .samples
            .front()
            .is_some_and(|s| now.saturating_duration_since(s.at) > METRICS_WINDOW)
        {
            self.samples.pop_front();
        }
    }

    pub fn summary(&self) -> MetricsSummary {
        self.summary_at(Instant::now())
    }

    pub fn summary_at(&self, now: Instant) -> MetricsSummary {
        let recent: Vec<&Sample> = self
            .samples
            .iter()
            .filter(|s| now.saturating_duration_since(s.at) <= METRICS_WINDOW)
            .collect();
        let failures = recent.iter().filter(|s| !s.ok).count();
        let trips: Vec<Duration> = recent
            .iter()
            .filter(|s| s.ok)
            .filter_map(|s| s.round_trip)
            .collect();
        MetricsSummary {
            requests: recent.len(),
            failures,
            success_rate: (!recent.is_empty())
                .then(|| (recent.len() - failures) as f64 / recent.len() as f64),
            last_round_trip: trips.last().copied(),
            average_round_trip: (!trips.is_empty())
                .then(|| trips.iter().sum::<Duration>() / trips.len() as u32),
            max_round_trip: trips.iter().max().copied(),
        }
    }

    pub fn last_success(&self) -> Option<SystemTime> {
        self.last_success
    }

    /// Recent errors, oldest first, already redacted.
    pub fn recent_errors(&self) -> Vec<(SystemTime, String)> {
        self.errors.iter().cloned().collect()
    }
}

/// Shorten an error for display: long hex strings (keys, IDs, hashes) keep
/// only their first 4 characters, IPv4 addresses their first two octets,
/// and `user:pass@` in URLs is removed. At most 160 characters.
pub fn redact(error: &str) -> String {
    let chars: Vec<char> = error.chars().collect();
    let mut out = String::with_capacity(error.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        // Credentials in a URL: drop "user:pass@" after "://".
        if c == ':' && chars.get(i + 1) == Some(&'/') && chars.get(i + 2) == Some(&'/') {
            out.push_str("://");
            i += 3;
            let rest: String = chars[i..].iter().collect();
            let end = rest
                .find(|c: char| c == '/' || c.is_whitespace())
                .unwrap_or(rest.len());
            if let Some(at) = rest[..end].rfind('@') {
                out.push_str("***@");
                i += rest[..=at].chars().count();
            }
            continue;
        }
        if c.is_ascii_hexdigit() {
            let run = chars[i..]
                .iter()
                .take_while(|c| c.is_ascii_hexdigit())
                .count();
            if run >= 16 {
                out.extend(&chars[i..i + 4]);
                out.push('…');
                i += run;
                continue;
            }
        }
        if c.is_ascii_digit() {
            let token: String = chars[i..]
                .iter()
                .take_while(|c| c.is_ascii_digit() || **c == '.')
                .collect();
            let octets: Vec<&str> = token.trim_end_matches('.').split('.').collect();
            if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
                out.push_str(&format!("{}.{}.x.x", octets[0], octets[1]));
                i += octets.iter().map(|o| o.len()).sum::<usize>() + 3;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    if out.chars().count() > 160 {
        out = out.chars().take(159).collect();
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_covers_the_last_five_minutes_only() {
        let mut metrics = NetworkMetrics::default();
        let start = Instant::now();
        let wall = SystemTime::UNIX_EPOCH;
        metrics.record_at(start, wall, Some(Duration::from_millis(900)), None);
        let later = start + Duration::from_secs(200);
        metrics.record_at(later, wall, Some(Duration::from_millis(300)), None);
        metrics.record_at(later, wall, Some(Duration::from_millis(500)), None);
        metrics.record_at(later, wall, None, Some("no path"));
        let s = metrics.summary_at(later);
        assert_eq!((s.requests, s.failures), (4, 1));
        assert_eq!(s.success_rate, Some(0.75));
        assert_eq!(
            s.average_round_trip,
            Some(Duration::from_millis(566) + Duration::from_nanos(666_666))
        );
        assert_eq!(s.last_round_trip, Some(Duration::from_millis(500)));
        assert_eq!(s.max_round_trip, Some(Duration::from_millis(900)));
        // The first sample leaves the window.
        let s = metrics.summary_at(start + Duration::from_secs(301));
        assert_eq!((s.requests, s.failures), (3, 1));
        assert_eq!(s.max_round_trip, Some(Duration::from_millis(500)));
        // Nothing recent: no rate, no averages (shown as N/A).
        let s = metrics.summary_at(start + Duration::from_secs(1000));
        assert_eq!(s, MetricsSummary::default());
    }

    #[test]
    fn failed_round_trips_do_not_count_as_latency() {
        let mut metrics = NetworkMetrics::default();
        let now = Instant::now();
        metrics.record_at(
            now,
            SystemTime::UNIX_EPOCH,
            Some(Duration::from_secs(9)),
            Some("timeout"),
        );
        let s = metrics.summary_at(now);
        assert_eq!(s.failures, 1);
        assert_eq!(s.success_rate, Some(0.0));
        assert_eq!(s.average_round_trip, None);
        assert_eq!(metrics.last_success(), None);
    }

    #[test]
    fn keeps_bounded_samples_and_errors() {
        let mut metrics = NetworkMetrics::default();
        let now = Instant::now();
        for i in 0..MAX_SAMPLES + 50 {
            metrics.record_at(now, SystemTime::UNIX_EPOCH, None, Some(&format!("e{i}")));
        }
        assert_eq!(metrics.summary_at(now).requests, MAX_SAMPLES);
        let errors = metrics.recent_errors();
        assert_eq!(errors.len(), MAX_ERRORS);
        assert_eq!(errors.last().unwrap().1, format!("e{}", MAX_SAMPLES + 49));
    }

    #[test]
    fn redacts_keys_addresses_and_credentials() {
        let key = "a".repeat(64);
        assert_eq!(
            redact(&format!("node {key} at 144.76.164.202:22100 failed")),
            "node aaaa… at 144.76.x.x:22100 failed"
        );
        assert_eq!(
            redact("proxy http://bob:secret@proxy.local:8080/ refused"),
            "proxy http://***@proxy.local:8080/ refused"
        );
        assert_eq!(
            redact("status 421 after 3 attempts"),
            "status 421 after 3 attempts"
        );
        assert_eq!(redact("05abc"), "05abc");
        assert_eq!(redact(&"x".repeat(500)).chars().count(), 160);
    }
}
