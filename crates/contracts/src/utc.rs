//! UTC instants (`time::OffsetDateTime`) as DB values and as text.
//!
//! Until task #1016 the workspace used chrono (RUSTSEC-2026-0543: unmaintained). The text shapes here are the ones
//! chrono produced, kept byte for byte so API responses, logs and stored strings do not change:
//!
//! | here | chrono | example |
//! |---|---|---|
//! | [`UtcInstant::to_rfc3339`] | `to_rfc3339()` | `2026-11-18T22:30:00.123+00:00` |
//! | [`UtcInstant::to_rfc3339_seconds_z`] | `to_rfc3339_opts(SecondsFormat::Secs, true)` | `2026-11-18T22:30:00Z` |
//! | [`UtcInstant::to_rfc3339_micros_z`] | `to_rfc3339_opts(SecondsFormat::Micros, true)` | `2026-11-18T22:30:00.123000Z` |
//! | [`serde_rfc3339`] | `Serialize` of `DateTime<Utc>` | `2026-11-18T22:30:00.123Z` |
//!
//! The fraction follows chrono's `AutoSi`: none when zero, otherwise 3, 6 or 9 digits (the fewest that are exact).
//!
//! DB columns are `DATETIME(6)` holding UTC. Values are bound as [`UtcInstant::naive_utc`] and read back with
//! [`from_naive_utc`], the same shape as chrono's `naive_utc()` / `Utc.from_utc_datetime()`.

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};

/// Conversions of a UTC instant that the workspace uses everywhere.
pub trait UtcInstant {
    /// The instant as a UTC wall-clock value (for `DATETIME` columns).
    fn naive_utc(&self) -> PrimitiveDateTime;
    /// RFC 3339 with the offset written as `+00:00` and an `AutoSi` fraction.
    fn to_rfc3339(&self) -> String;
    /// RFC 3339 with whole seconds and `Z`.
    fn to_rfc3339_seconds_z(&self) -> String;
    /// RFC 3339 with exactly six fraction digits and `Z`.
    fn to_rfc3339_micros_z(&self) -> String;
}

impl UtcInstant for OffsetDateTime {
    fn naive_utc(&self) -> PrimitiveDateTime {
        let utc = self.to_offset(UtcOffset::UTC);
        PrimitiveDateTime::new(utc.date(), utc.time())
    }

    fn to_rfc3339(&self) -> String {
        format!("{}{}+00:00", whole_seconds(*self), auto_si_fraction(*self))
    }

    fn to_rfc3339_seconds_z(&self) -> String {
        format!("{}Z", whole_seconds(*self))
    }

    fn to_rfc3339_micros_z(&self) -> String {
        let micros = self.to_offset(UtcOffset::UTC).microsecond();
        format!("{}.{micros:06}Z", whole_seconds(*self))
    }
}

/// A `DATETIME` value read from the DB (UTC wall clock) as an instant.
pub fn from_naive_utc(naive: PrimitiveDateTime) -> OffsetDateTime {
    naive.assume_utc()
}

/// Parses RFC 3339 text (any offset) and returns the instant in UTC.
pub fn parse_rfc3339(text: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(text, &Rfc3339).map(|t| t.to_offset(UtcOffset::UTC))
}

/// The instant `seconds` after the Unix epoch, or `None` when out of range.
pub fn from_unix_seconds(seconds: i64) -> Option<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(seconds).ok()
}

fn whole_seconds(t: OffsetDateTime) -> String {
    let t = t.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

fn auto_si_fraction(t: OffsetDateTime) -> String {
    let nanos = t.nanosecond();
    if nanos == 0 {
        String::new()
    } else if nanos.is_multiple_of(1_000_000) {
        format!(".{:03}", nanos / 1_000_000)
    } else if nanos.is_multiple_of(1_000) {
        format!(".{:06}", nanos / 1_000)
    } else {
        format!(".{nanos:09}")
    }
}

/// `#[serde(with = "assay_contracts::utc::serde_rfc3339")]` for an `OffsetDateTime` field: RFC 3339 with `Z` and an
/// `AutoSi` fraction on the way out (chrono's form), any RFC 3339 offset on the way in.
pub mod serde_rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use time::OffsetDateTime;

    pub fn serialize<S: Serializer>(t: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!(
            "{}{}Z",
            super::whole_seconds(*t),
            super::auto_si_fraction(*t)
        ))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OffsetDateTime, D::Error> {
        let text = String::deserialize(deserializer)?;
        super::parse_rfc3339(&text).map_err(serde::de::Error::custom)
    }

    /// The same for `Option<OffsetDateTime>` (`null` when absent).
    pub mod option {
        use serde::{Deserialize, Deserializer, Serializer};
        use time::OffsetDateTime;

        pub fn serialize<S: Serializer>(
            t: &Option<OffsetDateTime>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match t {
                Some(t) => super::serialize(t, serializer),
                None => serializer.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<OffsetDateTime>, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|text| super::super::parse_rfc3339(&text).map_err(serde::de::Error::custom))
                .transpose()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn rfc3339_matches_chrono_auto_si() {
        assert_eq!(
            datetime!(2026-07-27 01:02:03 UTC).to_rfc3339(),
            "2026-07-27T01:02:03+00:00"
        );
        assert_eq!(
            datetime!(2026-07-27 01:02:03.5 UTC).to_rfc3339(),
            "2026-07-27T01:02:03.500+00:00"
        );
        assert_eq!(
            datetime!(2026-07-27 01:02:03.000_123 UTC).to_rfc3339(),
            "2026-07-27T01:02:03.000123+00:00"
        );
        assert_eq!(
            datetime!(2026-07-27 01:02:03.000_000_007 UTC).to_rfc3339(),
            "2026-07-27T01:02:03.000000007+00:00"
        );
    }

    #[test]
    fn other_offsets_are_written_in_utc() {
        assert_eq!(
            datetime!(2026-07-27 10:02:03 +9).to_rfc3339(),
            "2026-07-27T01:02:03+00:00"
        );
        assert_eq!(
            datetime!(2026-07-27 10:02:03 +9).naive_utc(),
            datetime!(2026-07-27 01:02:03)
        );
    }

    #[test]
    fn seconds_and_micros_forms() {
        let t = datetime!(2026-11-18 22:30:00.123_456_789 UTC);
        assert_eq!(t.to_rfc3339_seconds_z(), "2026-11-18T22:30:00Z");
        assert_eq!(t.to_rfc3339_micros_z(), "2026-11-18T22:30:00.123456Z");
    }

    #[test]
    fn naive_round_trip() {
        let t = datetime!(2026-11-18 22:30:00.123_456 UTC);
        assert_eq!(from_naive_utc(t.naive_utc()), t);
    }

    #[test]
    fn parse_accepts_any_offset() {
        assert_eq!(
            parse_rfc3339("2026-07-27T10:02:03+09:00").unwrap(),
            datetime!(2026-07-27 01:02:03 UTC)
        );
        assert!(parse_rfc3339("not a date").is_err());
    }

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Holder {
        #[serde(with = "serde_rfc3339")]
        at: OffsetDateTime,
        #[serde(with = "serde_rfc3339::option")]
        maybe: Option<OffsetDateTime>,
    }

    #[test]
    fn serde_uses_z_and_auto_si() {
        let h = Holder {
            at: datetime!(2026-07-27 01:02:03.25 UTC),
            maybe: None,
        };
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, r#"{"at":"2026-07-27T01:02:03.250Z","maybe":null}"#);
        assert_eq!(serde_json::from_str::<Holder>(&json).unwrap(), h);
    }
}
