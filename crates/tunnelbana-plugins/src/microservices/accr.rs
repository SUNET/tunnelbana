//! `accr` — Authentication Context Class Ref (Level of Assurance) negotiation.
//!
//! Ports eduID's `accr` SATOSA micro-service (both the request and response
//! halves). On the **request** path it reads the SP's requested
//! AuthnContextClassRef list (published by the SAML frontend as the
//! [`KEY_REQUESTED_ACCR`] decoration), drops unsupported values, enforces a
//! per-virtual-IdP minimum, applies an optional rewrite for the upstream IdP,
//! and forwards the result to the backend via the
//! [`KEY_TARGET_AUTHN_CONTEXT_CLASS_REF`] decoration. On the **response** path
//! it reverses the rewrite and validates the IdP-returned ACCR against what was
//! requested, falling back to the highest-priority requested value.
//!
//! Divergence from SATOSA recorded for parity: when the per-virtual-IdP minimum
//! is enforced, the forwarded list is the raw supported range (the
//! `internal_accr_rewrite_map` is *not* applied to it) — this matches eduID's
//! implementation exactly.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tunnelbana_core::context::{
    Context, KEY_REQUESTED_ACCR, KEY_REQUESTED_ACCR_COMPARISON, KEY_TARGET_ACCR_COMPARISON,
    KEY_TARGET_AUTHN_CONTEXT_CLASS_REF, KEY_TARGET_FRONTEND, STATE_KEY_BASE,
};
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

#[derive(Debug, Default, Deserialize)]
struct AccrConfig {
    /// ACCRs this proxy can satisfy, highest priority first.
    #[serde(default)]
    supported_accr_sorted_by_prio: Vec<String>,
    /// Per-virtual-IdP (frontend) minimum acceptable ACCR.
    #[serde(default)]
    lowest_accepted_accr_for_virtual_idp: BTreeMap<String, String>,
    /// Rewrite SP-requested ACCR → upstream-understood ACCR on the request path.
    #[serde(default)]
    internal_accr_rewrite_map: BTreeMap<String, String>,
    /// Comparison to forward when the SP did not specify one
    /// (`exact`/`minimum`/`maximum`/`better`).
    #[serde(default)]
    default_comparison: Option<String>,
}

/// Negotiates AuthnContextClassRef between the SP request and the upstream IdP
/// (SATOSA/eduID: `accr`).
pub struct Accr {
    name: String,
    supported: Vec<String>,
    lowest: BTreeMap<String, String>,
    rewrite: BTreeMap<String, String>,
    /// Inverse of `rewrite`, applied on the response path.
    reverse_rewrite: BTreeMap<String, String>,
    default_comparison: Option<String>,
}

impl Accr {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: AccrConfig = bx.parse_config()?;
        if cfg.supported_accr_sorted_by_prio.is_empty() {
            return Err(Error::Config(format!(
                "accr {}: supported_accr_sorted_by_prio must not be empty",
                bx.name
            )));
        }
        for (idp, minimum) in &cfg.lowest_accepted_accr_for_virtual_idp {
            if !cfg.supported_accr_sorted_by_prio.contains(minimum) {
                return Err(Error::Config(format!(
                    "accr {}: {idp} minimum accr {minimum} is not in supported_accr_sorted_by_prio",
                    bx.name
                )));
            }
        }
        // The reverse map (used on the response leg) inverts the rewrite map.
        // Reject a non-injective map at build time: if two origins shared one
        // rewritten value, the inverse could not reverse it unambiguously and
        // one mapping would be silently lost.
        let mut reverse_rewrite: BTreeMap<String, String> = BTreeMap::new();
        for (origin, rewritten) in &cfg.internal_accr_rewrite_map {
            if reverse_rewrite
                .insert(rewritten.clone(), origin.clone())
                .is_some()
            {
                return Err(Error::Config(format!(
                    "accr {}: internal_accr_rewrite_map is not one-to-one; \
                     multiple origins map to {rewritten}",
                    bx.name
                )));
            }
        }
        Ok(Box::new(Accr {
            name: bx.name.clone(),
            supported: cfg.supported_accr_sorted_by_prio,
            lowest: cfg.lowest_accepted_accr_for_virtual_idp,
            rewrite: cfg.internal_accr_rewrite_map,
            reverse_rewrite,
            default_comparison: cfg.default_comparison,
        }))
    }
}

fn decoration_list(ctx: &Context, key: &str) -> Vec<String> {
    ctx.decoration(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn json_strings(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

#[async_trait]
impl MicroService for Accr {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_request(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData> {
        let requested = decoration_list(ctx, KEY_REQUESTED_ACCR);
        let comparison = ctx
            .decoration(KEY_REQUESTED_ACCR_COMPARISON)
            .and_then(|v| v.as_str())
            .map(String::from);

        // Filter the SP request down to what we support (preserving SP order).
        let mut supported_to_forward: Vec<String> = Vec::new();
        if !requested.is_empty() {
            for accr in &requested {
                if self.supported.contains(accr) {
                    supported_to_forward.push(accr.clone());
                } else {
                    tracing::info!(
                        microservice = %self.name,
                        accr = %accr,
                        "removing unsupported AuthnContextClassRef from request"
                    );
                }
            }
            if supported_to_forward.is_empty() {
                return Err(Error::Authn(format!(
                    "accr {}: none of the requested AuthnContextClassRef values are supported",
                    self.name
                )));
            }
        }

        // The filtered (pre-rewrite) request is what the response path validates against.
        let requested_filtered = supported_to_forward.clone();

        // Apply the rewrite map to the forwarded copy.
        let mut accr_to_forward = supported_to_forward;
        for value in accr_to_forward.iter_mut() {
            if let Some(rewritten) = self.rewrite.get(value) {
                *value = rewritten.clone();
            }
        }

        // Per-virtual-IdP minimum: replace the forwarded list with the supported
        // range from the strongest down to the configured minimum. (Faithful to
        // eduID: the rewrite map is intentionally not applied to this range.)
        let vidp = ctx
            .target_frontend
            .clone()
            .or_else(|| ctx.state.get_str(STATE_KEY_BASE, KEY_TARGET_FRONTEND));
        if let Some(vidp) = vidp.as_deref() {
            if let Some(minimum) = self.lowest.get(vidp) {
                if let Some(idx) = self.supported.iter().position(|s| s == minimum) {
                    accr_to_forward = self.supported[..=idx].to_vec();
                }
            }
        }

        // Forward to the backend (first writer wins, mirroring KEY_TARGET_ENTITYID).
        if ctx.decoration(KEY_TARGET_AUTHN_CONTEXT_CLASS_REF).is_none()
            && !accr_to_forward.is_empty()
        {
            ctx.decorate(
                KEY_TARGET_AUTHN_CONTEXT_CLASS_REF,
                json_strings(&accr_to_forward),
            );
            if let Some(cmp) = comparison.or_else(|| self.default_comparison.clone()) {
                ctx.decorate(KEY_TARGET_ACCR_COMPARISON, Value::String(cmp));
            }
        }

        // Save the filtered request for the response leg.
        ctx.state.set_value(
            &self.name,
            "requested_accr",
            json_strings(&requested_filtered),
        );
        Ok(data)
    }

    async fn process_response(
        &self,
        ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<InternalData> {
        let requested: Vec<String> = ctx
            .state
            .get_value(&self.name, "requested_accr")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Reverse the request-path rewrite so the SP sees its own vocabulary.
        // eduID only saves the rewrite map to state when the SP had a non-empty
        // supported request, so the reverse rewrite is gated the same way here
        // (`requested` is non-empty for exactly those flows) to stay byte-for-byte
        // compatible with accr.py.
        let mut received = data.auth_info.auth_class_ref.clone();
        if !requested.is_empty() {
            if let Some(r) = received.as_deref() {
                if let Some(origin) = self.reverse_rewrite.get(r) {
                    received = Some(origin.clone());
                }
            }
        }

        if requested.is_empty() {
            // Nothing was requested (or only a minimum was enforced): pass the
            // received value through unchanged. (eduID leaves auth_class_ref as
            // the raw received; `received` equals it here since the reverse
            // rewrite above is gated off.)
            data.auth_info.auth_class_ref = received;
        } else if received
            .as_deref()
            .is_some_and(|r| requested.iter().any(|x| x == r))
        {
            data.auth_info.auth_class_ref = received;
        } else {
            // Received is unrequested/missing: fall back to the highest-priority
            // requested value.
            let fallback = self
                .supported
                .iter()
                .find(|s| requested.contains(s))
                .cloned();
            data.auth_info.auth_class_ref = fallback.or(received);
        }

        ctx.state.clear_namespace(&self.name);
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx, response_from};
    use super::*;

    const MFA: &str = "https://refeds.org/profile/mfa";
    const SFA: &str = "https://refeds.org/profile/sfa";
    const PWD: &str = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";

    fn build_accr(cfg: serde_json::Value) -> Box<dyn MicroService> {
        Accr::build(&bx("accr", cfg)).unwrap()
    }

    fn default_cfg() -> serde_json::Value {
        serde_json::json!({
            "supported_accr_sorted_by_prio": [MFA, SFA, PWD]
        })
    }

    #[tokio::test]
    async fn filters_unsupported_and_forwards_supported() {
        let accr = build_accr(default_cfg());
        let mut c = ctx();
        c.decorate(
            KEY_REQUESTED_ACCR,
            json_strings(&[SFA.into(), "urn:bogus".into()]),
        );

        let _ = accr
            .process_request(&mut c, InternalData::request("sp"))
            .await
            .unwrap();
        assert_eq!(
            decoration_list(&c, KEY_TARGET_AUTHN_CONTEXT_CLASS_REF),
            vec![SFA.to_string()]
        );
    }

    #[tokio::test]
    async fn all_unsupported_is_authn_error() {
        let accr = build_accr(default_cfg());
        let mut c = ctx();
        c.decorate(KEY_REQUESTED_ACCR, json_strings(&["urn:bogus".into()]));
        assert!(accr
            .process_request(&mut c, InternalData::request("sp"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn enforces_per_vidp_minimum_range() {
        let accr = build_accr(serde_json::json!({
            "supported_accr_sorted_by_prio": [MFA, SFA, PWD],
            "lowest_accepted_accr_for_virtual_idp": { "SunetIDP": SFA }
        }));
        let mut c = ctx();
        c.target_frontend = Some("SunetIDP".into());
        // SP only asked for the weakest; minimum lifts the forwarded range to MFA..=SFA.
        c.decorate(KEY_REQUESTED_ACCR, json_strings(&[PWD.into()]));

        let _ = accr
            .process_request(&mut c, InternalData::request("sp"))
            .await
            .unwrap();
        assert_eq!(
            decoration_list(&c, KEY_TARGET_AUTHN_CONTEXT_CLASS_REF),
            vec![MFA.to_string(), SFA.to_string()]
        );
    }

    #[tokio::test]
    async fn minimum_response_leg_downgrades_to_sp_request_eduid_parity() {
        // eduID parity (accr.py:73,76,87-101): the per-vIdP minimum reshapes only
        // the forwarded request; the saved `requested_accr` stays the SP's
        // filtered request. So even though the IdP returns a value inside the
        // enforced range (MFA), the response leg validates against [PWD] and
        // downgrades to it. This is intentional and documented (ADR 0030, F2);
        // the test locks it in so the behavior is not "fixed" by accident.
        let accr = build_accr(serde_json::json!({
            "supported_accr_sorted_by_prio": [MFA, SFA, PWD],
            "lowest_accepted_accr_for_virtual_idp": { "SunetIDP": SFA }
        }));
        let mut c = ctx();
        c.target_frontend = Some("SunetIDP".into());
        c.decorate(KEY_REQUESTED_ACCR, json_strings(&[PWD.into()]));
        let _ = accr
            .process_request(&mut c, InternalData::request("sp"))
            .await
            .unwrap();

        // IdP honored the enforced minimum and returned MFA (stronger than PWD).
        let mut data = response_from("sp");
        data.auth_info.auth_class_ref = Some(MFA.into());
        let data = accr.process_response(&mut c, data).await.unwrap();
        // Downgraded back to the SP's original request, per eduID.
        assert_eq!(data.auth_info.auth_class_ref.as_deref(), Some(PWD));
    }

    #[tokio::test]
    async fn applies_rewrite_and_forwards_comparison() {
        let accr = build_accr(serde_json::json!({
            "supported_accr_sorted_by_prio": [MFA, SFA],
            "internal_accr_rewrite_map": { MFA: "urn:upstream:mfa" }
        }));
        let mut c = ctx();
        c.decorate(KEY_REQUESTED_ACCR, json_strings(&[MFA.into()]));
        c.decorate(
            KEY_REQUESTED_ACCR_COMPARISON,
            Value::String("minimum".into()),
        );

        let _ = accr
            .process_request(&mut c, InternalData::request("sp"))
            .await
            .unwrap();
        assert_eq!(
            decoration_list(&c, KEY_TARGET_AUTHN_CONTEXT_CLASS_REF),
            vec!["urn:upstream:mfa".to_string()]
        );
        assert_eq!(
            c.decoration(KEY_TARGET_ACCR_COMPARISON)
                .and_then(|v| v.as_str()),
            Some("minimum")
        );
    }

    #[tokio::test]
    async fn response_reverses_rewrite_and_keeps_requested() {
        let accr = build_accr(serde_json::json!({
            "supported_accr_sorted_by_prio": [MFA, SFA],
            "internal_accr_rewrite_map": { MFA: "urn:upstream:mfa" }
        }));
        let mut c = ctx();
        c.decorate(KEY_REQUESTED_ACCR, json_strings(&[MFA.into()]));
        let _ = accr
            .process_request(&mut c, InternalData::request("sp"))
            .await
            .unwrap();

        // IdP returns the upstream (rewritten) value.
        let mut data = response_from("sp");
        data.auth_info.auth_class_ref = Some("urn:upstream:mfa".into());
        let data = accr.process_response(&mut c, data).await.unwrap();
        assert_eq!(data.auth_info.auth_class_ref.as_deref(), Some(MFA));
    }

    #[tokio::test]
    async fn response_falls_back_to_highest_requested_when_unmatched() {
        let accr = build_accr(default_cfg());
        let mut c = ctx();
        c.decorate(KEY_REQUESTED_ACCR, json_strings(&[MFA.into(), SFA.into()]));
        let _ = accr
            .process_request(&mut c, InternalData::request("sp"))
            .await
            .unwrap();

        let mut data = response_from("sp");
        // IdP returned something not requested.
        data.auth_info.auth_class_ref = Some(PWD.into());
        let data = accr.process_response(&mut c, data).await.unwrap();
        assert_eq!(data.auth_info.auth_class_ref.as_deref(), Some(MFA));
    }

    #[tokio::test]
    async fn response_without_request_passes_raw_received_unrewritten() {
        // eduID parity: when the SP requested no ACCR, accr.py never saved the
        // rewrite map to state, so the response is the raw received value with
        // no reverse rewrite applied.
        let accr = build_accr(serde_json::json!({
            "supported_accr_sorted_by_prio": [MFA, SFA],
            "internal_accr_rewrite_map": { MFA: "urn:upstream:mfa" }
        }));
        let mut c = ctx();
        // No KEY_REQUESTED_ACCR decoration -> nothing forwarded, nothing saved.
        let _ = accr
            .process_request(&mut c, InternalData::request("sp"))
            .await
            .unwrap();

        let mut data = response_from("sp");
        // A value that *would* reverse-rewrite to MFA if the rewrite were applied.
        data.auth_info.auth_class_ref = Some("urn:upstream:mfa".into());
        let data = accr.process_response(&mut c, data).await.unwrap();
        // Unchanged raw value, matching accr.py.
        assert_eq!(
            data.auth_info.auth_class_ref.as_deref(),
            Some("urn:upstream:mfa")
        );
    }

    #[test]
    fn rejects_minimum_not_in_supported() {
        assert!(Accr::build(&bx(
            "accr",
            serde_json::json!({
                "supported_accr_sorted_by_prio": [MFA],
                "lowest_accepted_accr_for_virtual_idp": { "X": SFA }
            })
        ))
        .is_err());
    }

    #[test]
    fn rejects_non_injective_rewrite_map() {
        // Two origins mapping to the same rewritten value cannot be reversed
        // unambiguously on the response leg -> fail fast at build.
        assert!(Accr::build(&bx(
            "accr",
            serde_json::json!({
                "supported_accr_sorted_by_prio": [MFA, SFA],
                "internal_accr_rewrite_map": {
                    MFA: "urn:upstream:loa",
                    SFA: "urn:upstream:loa"
                }
            })
        ))
        .is_err());
    }

    #[test]
    fn rejects_empty_supported() {
        assert!(Accr::build(&bx("accr", serde_json::json!({}))).is_err());
    }
}
