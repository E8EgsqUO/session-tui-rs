//! Pure parsing and scheduling helpers. No I/O, secrets, or database access.

use serde_json::Value;

pub(super) fn parse_duration(text: &str) -> Option<u32> {
    let (number, unit) = text.split_at(text.find(|c: char| !c.is_ascii_digit())?);
    let number: u32 = number.parse().ok()?;
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    number.checked_mul(scale).filter(|seconds| *seconds > 0)
}

pub(super) fn format_duration(seconds: u32) -> String {
    for (unit, size) in [("w", 604_800), ("d", 86_400), ("h", 3600), ("m", 60)] {
        if seconds >= size && seconds % size == 0 {
            return format!("{}{unit}", seconds / size);
        }
    }
    format!("{seconds}s")
}

/// Split command arguments on whitespace, honouring double quotes.
pub(super) fn split_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut has_token = false;
    for c in input.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                has_token = true;
            }
            c if c.is_whitespace() && !quoted => {
                if has_token {
                    args.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(current);
    }
    args
}

/// Wait before automatic attempt `attempts + 1`: 5 s, 15 s, 45 s … up to
/// 15 minutes, so a flaky connection is retried quickly and a dead one
/// isn't hammered.
pub(super) fn outbox_backoff_ms(attempts: u32) -> u64 {
    (5_000u64.saturating_mul(3u64.saturating_pow(attempts.saturating_sub(1)))).min(15 * 60 * 1000)
}

/// A message's expiry in a `get_expiries` reply: `{"expiries": {hash: ms}}`,
/// possibly per swarm node under `"swarm"`. Missing means already expired.
#[cfg(test)]
pub(super) fn parse_expiry(body: &Value, hash: &str) -> Option<u64> {
    let direct = body
        .get("expiries")
        .and_then(|e| e.get(hash))
        .and_then(Value::as_u64);
    direct.or_else(|| {
        body.get("swarm")?
            .as_object()?
            .values()
            .filter_map(|node| node.get("expiries")?.get(hash)?.as_u64())
            .min()
    })
}

/// Only a valid expiry map can establish that a hash is absent/expired.
/// An invalid 200 reply must be retried, not interpreted as a deletion.
pub(super) fn validated_expiry_reply(body: &Value, hash: &str) -> Result<Option<u64>, String> {
    fn expiry_map(value: &Value, hash: &str) -> Result<Option<u64>, String> {
        let map = value
            .as_object()
            .ok_or("get_expiries: invalid expiries map")?;
        if map.values().any(|value| value.as_u64().is_none()) {
            return Err("get_expiries: invalid expiry timestamp".into());
        }
        Ok(map.get(hash).and_then(Value::as_u64))
    }
    if let Some(value) = body.get("expiries") {
        return expiry_map(value, hash);
    }
    let nodes = body
        .get("swarm")
        .and_then(Value::as_object)
        .ok_or("get_expiries: missing expiries map")?;
    let mut valid = false;
    let mut earliest: Option<u64> = None;
    for node in nodes.values() {
        if let Some(map) = node.get("expiries") {
            if let Ok(expiry) = expiry_map(map, hash) {
                valid = true;
                if let Some(expiry) = expiry {
                    earliest = Some(earliest.map_or(expiry, |prior| prior.min(expiry)));
                }
            }
        }
    }
    if valid {
        Ok(earliest)
    } else {
        Err("get_expiries: no valid node expiry map".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durations_reject_overflow_empty_and_non_ascii_numbers() {
        for text in ["", "0s", "12", "-1s", "１２h", "4294967295w", "1ms"] {
            assert_eq!(parse_duration(text), None, "{text}");
        }
        assert_eq!(parse_duration("4294967295s"), Some(u32::MAX));
        assert_eq!(parse_duration("2w"), Some(1_209_600));
        for n in [1, 60, 3600, 86_400, u32::MAX] {
            assert_eq!(parse_duration(&format_duration(n)), Some(n));
        }
    }
    #[test]
    fn arguments_preserve_unicode_and_windows_paths() {
        assert_eq!(
            split_args(r#""图片 a.png" "C:\my files\b.png" -- caption"#),
            ["图片 a.png", r"C:\my files\b.png", "--", "caption"]
        );
    }
    #[test]
    fn retry_budget_is_bounded_even_at_integer_limits() {
        assert_eq!(outbox_backoff_ms(1), 5_000);
        assert_eq!(outbox_backoff_ms(2), 15_000);
        assert_eq!(outbox_backoff_ms(u32::MAX), 900_000);
        for n in 0..100 {
            assert!(outbox_backoff_ms(n) <= 900_000);
        }
    }
}

#[cfg(test)]
mod expiry_validation_tests {
    use super::*;
    #[test]
    fn malformed_success_replies_cannot_expire_a_message() {
        for reply in [
            serde_json::json!({}),
            serde_json::json!({"expiries":null}),
            serde_json::json!({"expiries":{"h":"42"}}),
            serde_json::json!({"swarm":{}}),
            serde_json::json!({"swarm":{"node":{"error":"unavailable"}}}),
        ] {
            assert!(validated_expiry_reply(&reply, "h").is_err(), "{reply}");
        }
        assert_eq!(
            validated_expiry_reply(&serde_json::json!({"expiries":{}}), "h"),
            Ok(None)
        );
        let direct = serde_json::json!({"expiries":{"h":42}});
        assert_eq!(
            validated_expiry_reply(&direct, "h"),
            Ok(parse_expiry(&direct, "h"))
        );
        let wrapped = serde_json::json!({"swarm":{"a":{"expiries":{"h":45}},"b":{"expiries":{"h":40}},"failed":{"error":"unavailable"}}});
        assert_eq!(
            validated_expiry_reply(&wrapped, "h"),
            Ok(parse_expiry(&wrapped, "h"))
        );
    }
}
