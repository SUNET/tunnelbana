//! `custom_logging` — per-flow JSON audit records (SATOSA:
//! `CustomLoggingService`).

use std::io::Write;
use std::path::PathBuf;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

#[derive(Debug, Deserialize)]
struct CustomLoggingConfig {
    /// File receiving one JSON object per completed flow.
    log_target: String,
    /// Internal attribute names whose values are included in the record.
    #[serde(default)]
    attrs: Vec<String>,
}

/// Appends a JSON line per authentication response: timestamp, requester
/// (SP/RP), issuer (IdP/OP), frontend/backend names and the configured subset
/// of attributes. Logging failures are reported but never fail the flow.
pub struct CustomLogging {
    name: String,
    log_target: PathBuf,
    attrs: Vec<String>,
}

impl CustomLogging {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: CustomLoggingConfig = bx.parse_config()?;
        let log_target = PathBuf::from(&cfg.log_target);
        // Surface an unwritable target at startup, not mid-flow.
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_target)
            .map_err(|e| {
                Error::Config(format!(
                    "custom_logging {}: cannot open log_target {}: {e}",
                    bx.name, cfg.log_target
                ))
            })?;
        Ok(Box::new(CustomLogging {
            name: bx.name.clone(),
            log_target,
            attrs: cfg.attrs,
        }))
    }
}

#[async_trait]
impl MicroService for CustomLogging {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_response(
        &self,
        ctx: &mut Context,
        data: InternalData,
    ) -> Result<InternalData> {
        let timestamp = data
            .auth_info
            .timestamp
            .clone()
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let attrs: serde_json::Map<String, serde_json::Value> = self
            .attrs
            .iter()
            .filter_map(|a| {
                data.attributes
                    .get(a)
                    .map(|v| (a.clone(), serde_json::json!(v)))
            })
            .collect();
        let record = serde_json::json!({
            "timestamp": timestamp,
            "sp": data.requester,
            "idp": data.auth_info.issuer,
            "frontend": ctx.target_frontend,
            "backend": ctx.target_backend,
            "attr": attrs,
        });

        let written = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_target)
            .and_then(|mut f| writeln!(f, "{record}"));
        if let Err(e) = written {
            tracing::error!(
                microservice = %self.name,
                target = %self.log_target.display(),
                error = %e,
                "failed to write audit record"
            );
        }
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    fn temp_log(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "tunnelbana-custom-logging-{tag}-{}.jsonl",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn writes_one_json_record_per_response() {
        let path = temp_log("ok");
        let _ = std::fs::remove_file(&path);
        let svc = CustomLogging::build(&bx(
            "audit",
            serde_json::json!({
                "log_target": path.to_str().unwrap(),
                "attrs": ["mail", "absent"]
            }),
        ))
        .unwrap();

        let mut data = response_from("https://sp.example");
        data.auth_info.issuer = Some("https://idp.example".into());
        data.auth_info.timestamp = Some("2026-06-10T12:00:00Z".into());
        data.set_attr("mail", "anna@example.org");
        data.set_attr("secret", "do-not-log");
        let mut c = ctx();
        c.target_frontend = Some("OidcOP".into());
        c.target_backend = Some("Saml2".into());
        svc.process_response(&mut c, data).await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let record: serde_json::Value = serde_json::from_str(contents.lines().last().unwrap()).unwrap();
        assert_eq!(record["sp"], "https://sp.example");
        assert_eq!(record["idp"], "https://idp.example");
        assert_eq!(record["timestamp"], "2026-06-10T12:00:00Z");
        assert_eq!(record["frontend"], "OidcOP");
        assert_eq!(record["attr"]["mail"][0], "anna@example.org");
        // Only configured attributes are recorded.
        assert!(record["attr"].get("secret").is_none());
        assert!(record["attr"].get("absent").is_none());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_unwritable_target_at_build_time() {
        assert!(CustomLogging::build(&bx(
            "audit",
            serde_json::json!({ "log_target": "/nonexistent-dir/audit.jsonl" })
        ))
        .is_err());
    }
}
