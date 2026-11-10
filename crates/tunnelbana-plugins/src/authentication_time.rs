use chrono::{DateTime, Utc};
use tunnelbana_core::error::{Error, Result};

pub(crate) fn parse(timestamp: Option<&str>) -> Result<Option<DateTime<Utc>>> {
    timestamp
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|time| time.with_timezone(&Utc))
                .map_err(|_| Error::Authn("invalid authentication timestamp".into()))
        })
        .transpose()
}

pub(crate) fn unix_seconds(timestamp: Option<&str>) -> Result<Option<u64>> {
    parse(timestamp)?
        .map(|time| {
            u64::try_from(time.timestamp())
                .map_err(|_| Error::Authn("authentication timestamp precedes Unix epoch".into()))
        })
        .transpose()
}

pub(crate) fn from_oidc(value: Option<&serde_json::Value>) -> Result<Option<String>> {
    value
        .map(|value| {
            let invalid = || Error::Authn("invalid upstream auth_time".into());
            let seconds = value
                .as_f64()
                .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
                .ok_or_else(invalid)?;
            let time = DateTime::from_timestamp(seconds.floor() as i64, 0).ok_or_else(invalid)?;
            let latest = tunnelbana_core::util::now_secs()
                .saturating_add(jose_rs::jwt::Validation::default().leeway);
            if time.timestamp() as u64 > latest {
                return Err(Error::Authn("upstream auth_time is in the future".into()));
            }
            Ok(time.to_rfc3339())
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn preserves_original_times_and_keeps_missing_times_unknown() {
        let original = 1_577_934_245;
        let timestamp = from_oidc(Some(&json!(original))).unwrap().unwrap();
        assert_eq!(unix_seconds(Some(&timestamp)).unwrap(), Some(original));
        assert_eq!(
            unix_seconds(Some("2020-01-02T04:04:05+01:00")).unwrap(),
            Some(original)
        );
        let fractional = from_oidc(Some(&json!(1_577_934_245.75))).unwrap().unwrap();
        assert_eq!(unix_seconds(Some(&fractional)).unwrap(), Some(original));
        assert_eq!(from_oidc(None).unwrap(), None);
        assert_eq!(unix_seconds(None).unwrap(), None);
        assert_eq!(parse(None).unwrap(), None);
    }

    #[test]
    fn rejects_invalid_authentication_times() {
        for value in [
            json!(null),
            json!(true),
            json!("1577934245"),
            json!(-1),
            json!(1e30),
            json!(tunnelbana_core::util::now_secs() + 3600),
        ] {
            assert!(from_oidc(Some(&value)).is_err(), "{value}");
        }
        for timestamp in ["not a timestamp", "1969-12-31T23:59:59Z"] {
            assert!(unix_seconds(Some(timestamp)).is_err());
        }
    }
}
