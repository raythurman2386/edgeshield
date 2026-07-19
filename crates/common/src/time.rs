//! Timestamp utilities for consistent time handling.
//!
//! All timestamps in EdgeShield use `chrono::DateTime<Utc>` for consistency.
//! This module provides a `Timestamp` newtype that serializes to ISO 8601
//! format in JSON responses.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A UTC timestamp that serializes as an ISO 8601 string.
///
/// We use a newtype rather than raw `DateTime<Utc>` to:
/// 1. Control serialization format (ISO 8601 with millisecond precision)
/// 2. Make the type self-documenting in API responses
/// 3. Allow future changes without touching every usage site
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Timestamp(
    #[serde(
        serialize_with = "serialize_iso8601",
        deserialize_with = "deserialize_iso8601"
    )]
    DateTime<Utc>,
);

impl Timestamp {
    /// Create a new timestamp from the current time.
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// Create a timestamp from a `DateTime<Utc>`.
    pub const fn from_datetime(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    /// Get the inner `DateTime<Utc>`.
    pub fn inner(&self) -> &DateTime<Utc> {
        &self.0
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.format("%Y-%m-%dT%H:%M:%S%.3fZ"))
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }
}

/// Serialize a `DateTime<Utc>` as ISO 8601 with millisecond precision.
///
/// Uses `collect_str` to write directly into the serializer's buffer
/// when possible, avoiding the intermediate `String` allocation that
/// `format(...).to_string()` would create on every serialization.
fn serialize_iso8601<S>(dt: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_str(&dt.format("%Y-%m-%dT%H:%M:%S%.3fZ"))
}

/// Deserialize a `DateTime<Utc>` and truncate to millisecond precision.
///
/// Without this, serde would accept any RFC 3339 input (including
/// nanosecond precision) via `DateTime<Utc>`'s default `Deserialize`
/// impl, while our serializer truncates to milliseconds. That asymmetry
/// causes silent precision loss on round-trips. We truncate explicitly
/// on input so serialize(deserialize(x)) == x for any valid x.
///
/// `from_timestamp_millis` returns `None` only for dates outside the
/// representable range (year ±262143). Any value that successfully
/// deserialized as a `DateTime<Utc>` is by definition in range after
/// truncation, so the `expect` cannot fire on well-formed input.
fn deserialize_iso8601<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let dt: DateTime<Utc> = Deserialize::deserialize(deserializer)?;
    let ms = dt.timestamp_millis();
    Ok(
        DateTime::from_timestamp_millis(ms)
            .expect("timestamp_millis out of range after truncation"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_now() {
        let ts = Timestamp::now();
        let formatted = ts.to_string();
        // ISO 8601 format check
        assert!(formatted.contains('T'));
        assert!(formatted.ends_with('Z'));
    }

    #[test]
    fn test_timestamp_serde() {
        let ts = Timestamp::now();
        let json = serde_json::to_string(&ts).unwrap();
        // Should be a quoted ISO 8601 string
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
        assert!(json.contains('T'));

        let deserialized: Timestamp = serde_json::from_str(&json).unwrap();
        // Serialization truncates to milliseconds, so compare formatted strings
        assert_eq!(ts.to_string(), deserialized.to_string());
    }
}
