//! `hasher` — salted-hash the subject id and/or selected attributes.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha512};
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

#[derive(Debug, Deserialize)]
struct RawEntry {
    #[serde(default)]
    salt: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    subject_id: Option<bool>,
    #[serde(default)]
    attributes: Option<Vec<String>>,
}

#[derive(Clone)]
struct HasherEntry {
    salt: String,
    alg: HashAlg,
    subject_id: bool,
    attributes: Vec<String>,
}

#[derive(Clone, Copy)]
enum HashAlg {
    Sha256,
    Sha512,
}

impl HashAlg {
    fn parse(s: &str, name: &str) -> Result<Self> {
        match s {
            "sha256" => Ok(HashAlg::Sha256),
            "sha512" => Ok(HashAlg::Sha512),
            other => Err(Error::Config(format!(
                "hasher {name}: unsupported alg: {other}"
            ))),
        }
    }
}

/// SATOSA's `util.hash_data`: `hex(hash(value || salt))`.
fn hash_data(alg: HashAlg, salt: &str, value: &str) -> String {
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(value.as_bytes());
            h.update(salt.as_bytes());
            format!("{:x}", h.finalize())
        }
        HashAlg::Sha512 => {
            let mut h = Sha512::new();
            h.update(value.as_bytes());
            h.update(salt.as_bytes());
            format!("{:x}", h.finalize())
        }
    }
}

/// Hashes the subject id and/or selected attributes with a per-requester salt
/// and algorithm (SATOSA: `Hasher`). The config is a map keyed by requester;
/// the `""` entry provides required defaults (`salt`; `alg` defaults to
/// `sha512`, `subject_id` to `true`, `attributes` to `[]`) that requester
/// entries override field-by-field.
pub struct Hasher {
    name: String,
    entries: BTreeMap<String, HasherEntry>,
}

impl Hasher {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let raw: BTreeMap<String, RawEntry> = bx.parse_config()?;
        let defaults = raw.get("").ok_or_else(|| {
            Error::Config(format!("hasher {}: missing default (\"\") section", bx.name))
        })?;
        let default_salt = defaults
            .salt
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::Config(format!("hasher {}: default section needs a salt", bx.name))
            })?;
        let default_alg = HashAlg::parse(defaults.alg.as_deref().unwrap_or("sha512"), &bx.name)?;
        let default_subject_id = defaults.subject_id.unwrap_or(true);
        let default_attributes = defaults.attributes.clone().unwrap_or_default();

        let mut entries = BTreeMap::new();
        for (requester, entry) in &raw {
            let alg = match &entry.alg {
                Some(a) => HashAlg::parse(a, &bx.name)?,
                None => default_alg,
            };
            entries.insert(
                requester.clone(),
                HasherEntry {
                    salt: entry.salt.clone().unwrap_or_else(|| default_salt.clone()),
                    alg,
                    subject_id: entry.subject_id.unwrap_or(default_subject_id),
                    attributes: entry
                        .attributes
                        .clone()
                        .unwrap_or_else(|| default_attributes.clone()),
                },
            );
        }
        Ok(Box::new(Hasher {
            name: bx.name.clone(),
            entries,
        }))
    }
}

#[async_trait]
impl MicroService for Hasher {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        _ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        let requester = data.requester.as_deref().unwrap_or("");
        let entry = self
            .entries
            .get(requester)
            .or_else(|| self.entries.get(""))
            .expect("default entry enforced at build time");

        if entry.subject_id {
            if let Some(subject) = &data.subject_id {
                data.subject_id = Some(hash_data(entry.alg, &entry.salt, subject));
            }
        }
        for attribute in &entry.attributes {
            if let Some(values) = data.attributes.get_mut(attribute) {
                for value in values.iter_mut() {
                    *value = hash_data(entry.alg, &entry.salt, value);
                }
            }
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    fn sha512_hex(input: &str) -> String {
        let mut h = Sha512::new();
        h.update(input.as_bytes());
        format!("{:x}", h.finalize())
    }

    fn sha256_hex(input: &str) -> String {
        let mut h = Sha256::new();
        h.update(input.as_bytes());
        format!("{:x}", h.finalize())
    }

    #[tokio::test]
    async fn hashes_subject_id_and_listed_attributes_with_defaults() {
        let hasher = Hasher::build(&bx(
            "hasher",
            serde_json::json!({
                "": { "salt": "abcdef", "attributes": ["edupersontargetedid"] }
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.subject_id = Some("anna".into());
        data.set_attr("edupersontargetedid", "tid");
        data.set_attr("mail", "anna@example.org");
        let data = hasher.process_response(&mut ctx(), data).await.unwrap();
        // Default alg is sha512; hash(value || salt).
        assert_eq!(data.subject_id.as_deref(), Some(sha512_hex("annaabcdef").as_str()));
        assert_eq!(
            data.attr_first("edupersontargetedid"),
            Some(sha512_hex("tidabcdef").as_str())
        );
        // Unlisted attributes untouched.
        assert_eq!(data.attr_first("mail"), Some("anna@example.org"));
    }

    #[tokio::test]
    async fn per_requester_entry_overrides_alg_and_subject_id() {
        let hasher = Hasher::build(&bx(
            "hasher",
            serde_json::json!({
                "": { "salt": "abcdef", "alg": "sha512" },
                "https://sp.example": { "alg": "sha256", "subject_id": true },
                "https://other.example": { "subject_id": false }
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.subject_id = Some("anna".into());
        let data = hasher.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.subject_id.as_deref(), Some(sha256_hex("annaabcdef").as_str()));

        let mut data = response_from("https://other.example");
        data.subject_id = Some("anna".into());
        let data = hasher.process_response(&mut ctx(), data).await.unwrap();
        assert_eq!(data.subject_id.as_deref(), Some("anna"));
    }

    #[test]
    fn requires_default_section_with_salt() {
        assert!(Hasher::build(&bx("hasher", serde_json::json!({}))).is_err());
        assert!(Hasher::build(&bx("hasher", serde_json::json!({ "": {} }))).is_err());
        assert!(Hasher::build(&bx(
            "hasher",
            serde_json::json!({ "": { "salt": "x", "alg": "md5" } })
        ))
        .is_err());
    }
}
