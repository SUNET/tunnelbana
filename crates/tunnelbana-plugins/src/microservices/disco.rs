//! `disco_to_target_issuer` - suspend a flow for external IdP discovery and
//! resume it with the chosen issuer (SATOSA: `DiscoToTargetIssuer`).

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::{Context, KEY_TARGET_ENTITYID};
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService, MicroServiceAction, Route};

use super::level;

/// Key within this service's state namespace holding the suspended flow.
const KEY_SNAPSHOT: &str = "snapshot";
/// Prefix for this service's state namespace. The namespace is
/// `{prefix}{instance name}` rather than the bare instance name: config only
/// deduplicates names *within* the microservice list, and the router
/// deliberately supports reusing a name across plugin kinds - so a disco
/// instance named like a frontend (e.g. `OIDC`) would otherwise share that
/// frontend's namespace, and the whole-namespace `clear_namespace` on resume
/// would wipe the frontend's own flow state (its `authz_request`) along with
/// the snapshot.
const NAMESPACE_PREFIX: &str = "disco_to_target_issuer:";
/// Discovery services return the chosen IdP in this query parameter
/// (SAML IdP Discovery Protocol).
const PARAM_ENTITY_ID: &str = "entityID";
/// Reject absurdly long entity ids before they reach routing or logs. SAML
/// metadata caps entityID at 1024 characters.
const MAX_ENTITY_ID_LEN: usize = 1024;
/// Upper bound on the serialized snapshot JSON. The sealed state cookie is
/// hard-capped at 4096 bytes; a snapshot beyond this would be dropped at
/// seal time *after* the browser was already redirected to the discovery
/// service, leaving an unrecoverable flow. Failing here surfaces the problem
/// as a normal protocol error before the redirect happens. Half the cookie
/// budget leaves room for base64 expansion, JWE overhead and the other state
/// namespaces.
const MAX_SNAPSHOT_BYTES: usize = 2048;

/// A well-formed entity id: non-empty, at most [`MAX_ENTITY_ID_LEN`]
/// *characters* (the SAML cap counts characters, not UTF-8 bytes, so a
/// non-ASCII id must not be rejected early), and free of ASCII control
/// characters. Shared by config validation and the discovery-return filter
/// so both enforce the same rule.
fn is_valid_entity_id(v: &str) -> bool {
    !v.is_empty()
        && v.chars().count() <= MAX_ENTITY_ID_LEN
        && !v.chars().any(|c| c.is_ascii_control())
}

#[derive(Debug, Deserialize)]
struct DiscoToTargetIssuerConfig {
    /// Literal request paths (no leading slash) the external discovery service
    /// redirects back to, e.g. `["Saml2/disco"]`. Registered before backend
    /// routes, so a path may deliberately shadow a backend's own disco return
    /// endpoint. SATOSA takes regexes here; exact paths are a deliberate
    /// divergence - the discovery service is configured with a fixed return
    /// URL, and exact routes cannot fail to compile.
    disco_endpoints: Vec<String>,
    /// Allowlist of issuer entity ids the discovery return may select,
    /// keyed by requester (the usual exact → `""` → `"default"` levels). The
    /// resumed flow's requester picks its issuer set; a returned `entityID`
    /// outside that set - or a requester with no applicable set - is
    /// rejected before the pipeline resumes. The scoping is per
    /// `(issuer, requester)` pair on purpose: the target-entity decoration
    /// stays set through `custom_routing`'s requester/default fallback, so a
    /// merely global list would let any requester reach any listed issuer
    /// via the fallback backend's metadata resolution even when no issuer
    /// rule authorizes the pair. Exactly one of `allowed_issuers` and
    /// `allow_any_issuer` must be configured: unmatched issuers fail closed
    /// unless the operator explicitly opts out.
    #[serde(default)]
    allowed_issuers: Option<BTreeMap<String, Vec<String>>>,
    /// Explicitly accept any well-formed returned entityID (SATOSA's
    /// behavior). Only sound when every backend a discovery return can reach
    /// verifies the selected entity against signed federation metadata
    /// (MDQ/trust chain), which is then the effective allowlist - e.g. an
    /// eduGAIN-scale proxy where enumerating issuers is impossible.
    #[serde(default)]
    allow_any_issuer: bool,
}

/// Snapshots the in-flight request into the encrypted state cookie on the
/// request path, and owns the discovery-return endpoint: when the discovery
/// service sends the browser back with `?entityID=<issuer>`, the suspended
/// flow is restored, the target-entity decoration is set, and the request
/// pipeline resumes so issuer-based routing (`custom_routing`) can pick the
/// matching backend.
pub struct DiscoToTargetIssuer {
    name: String,
    disco_endpoints: Vec<String>,
    allowed_issuers: Option<BTreeMap<String, Vec<String>>>,
}

impl DiscoToTargetIssuer {
    /// This instance's state namespace: see [`NAMESPACE_PREFIX`].
    fn state_namespace(&self) -> String {
        format!("{NAMESPACE_PREFIX}{}", self.name)
    }

    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: DiscoToTargetIssuerConfig = bx.parse_config()?;
        if cfg.disco_endpoints.is_empty() {
            return Err(Error::Config(format!(
                "disco_to_target_issuer {}: disco_endpoints must not be empty",
                bx.name
            )));
        }
        let mut disco_endpoints = Vec::with_capacity(cfg.disco_endpoints.len());
        for path in cfg.disco_endpoints {
            let path = path.trim_start_matches('/').to_string();
            if path.is_empty() || path.contains(char::is_whitespace) || path.contains('?') {
                return Err(Error::Config(format!(
                    "disco_to_target_issuer {}: disco_endpoints entries must be \
                     non-empty literal paths without whitespace or query strings",
                    bx.name
                )));
            }
            disco_endpoints.push(path);
        }
        // Fail closed by default: the operator either enumerates the issuers
        // a discovery return may select, or explicitly accepts any (leaving
        // backend metadata verification as the only gate).
        match (&cfg.allowed_issuers, cfg.allow_any_issuer) {
            (Some(_), true) | (None, false) => {
                return Err(Error::Config(format!(
                    "disco_to_target_issuer {}: configure exactly one of \
                     allowed_issuers (enumerated issuers) or \
                     allow_any_issuer = true (rely on backend metadata \
                     verification)",
                    bx.name
                )));
            }
            (Some(map), false) => {
                if map.is_empty() {
                    return Err(Error::Config(format!(
                        "disco_to_target_issuer {}: allowed_issuers must not \
                         be empty",
                        bx.name
                    )));
                }
                for (requester, issuers) in map {
                    if issuers.is_empty() {
                        return Err(Error::Config(format!(
                            "disco_to_target_issuer {}: allowed_issuers for \
                             requester {requester:?} must not be empty",
                            bx.name
                        )));
                    }
                    if issuers.iter().any(|i| !is_valid_entity_id(i)) {
                        return Err(Error::Config(format!(
                            "disco_to_target_issuer {}: allowed_issuers \
                             entries for requester {requester:?} must be \
                             non-empty, at most {MAX_ENTITY_ID_LEN} \
                             characters, and contain no ASCII control \
                             characters",
                            bx.name
                        )));
                    }
                }
            }
            (None, true) => {}
        }
        Ok(Box::new(DiscoToTargetIssuer {
            name: bx.name.clone(),
            disco_endpoints,
            allowed_issuers: cfg.allowed_issuers,
        }))
    }
}

#[async_trait]
impl MicroService for DiscoToTargetIssuer {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_request(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData> {
        // Suspend-side bookkeeping: the outbound hop to the discovery service
        // itself is owned by the default backend (`disco_srv`) or the
        // deployment; this service only has to remember enough to resume.
        let snapshot = serde_json::json!({
            "target_frontend": ctx.target_frontend,
            "internal_data": data,
        });
        // Reject a snapshot the state cookie cannot carry *now*, while a
        // protocol error can still reach the requester. Discovering this at
        // seal time would strand the user: the disco redirect would go out
        // without the cookie and the return could never resume.
        let size = snapshot.to_string().len();
        if size > MAX_SNAPSHOT_BYTES {
            return Err(Error::Authn(format!(
                "discovery snapshot of {size} bytes exceeds the \
                 {MAX_SNAPSHOT_BYTES}-byte state-cookie budget"
            )));
        }
        ctx.state
            .set_value(&self.state_namespace(), KEY_SNAPSHOT, snapshot);
        Ok(data)
    }

    fn register_endpoints(&self) -> Vec<Route> {
        self.disco_endpoints
            .iter()
            .map(|p| Route::exact(p, p))
            .collect()
    }

    async fn handle_endpoint(
        &self,
        ctx: &mut Context,
        _route_id: &str,
    ) -> Result<MicroServiceAction> {
        let issuer = ctx
            .request
            .query
            .get(PARAM_ENTITY_ID)
            .filter(|v| is_valid_entity_id(v))
            .cloned()
            // The snapshot is left in place so the user can be sent through
            // discovery again after a malformed return.
            .ok_or_else(|| Error::Authn("no valid entityID in the discovery response".into()))?;

        let snapshot = ctx
            .state
            .get_value(&self.state_namespace(), KEY_SNAPSHOT)
            .cloned()
            .ok_or_else(|| Error::Authn("no discovery flow in progress".into()))?;

        let target_frontend = snapshot
            .get("target_frontend")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let request: InternalData = match snapshot
            .get("internal_data")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| Error::State(format!("invalid discovery snapshot: {e}")))
            .and_then(|d| d.ok_or_else(|| Error::State("invalid discovery snapshot".into())))
        {
            Ok(request) => request,
            Err(e) => {
                // A corrupt snapshot can never resume; drop it so the user
                // restarts cleanly instead of replaying the same error.
                ctx.state.clear_namespace(&self.state_namespace());
                return Err(e);
            }
        };

        if let Some(allowed) = &self.allowed_issuers {
            // The allowlist authorizes `(issuer, requester)` pairs: the
            // resumed flow's requester selects its issuer set. A global
            // check would let a requester without an issuer rule keep the
            // target-issuer decoration through `custom_routing`'s
            // requester/default fallback and authenticate at any globally
            // listed issuer via the fallback backend's metadata resolution.
            // Checked before consuming the snapshot, so the user can go back
            // to the discovery page and pick a permitted issuer.
            let issuers = request.requester.as_deref().and_then(|r| level(allowed, r));
            if !issuers.is_some_and(|list| list.iter().any(|a| a == &issuer)) {
                return Err(Error::Authn(
                    "discovery response issuer is not in allowed_issuers for this requester".into(),
                ));
            }
        }

        // Consume-once: the resealed cookie on this response no longer
        // carries the snapshot, so a replayed discovery return fails at the
        // lookup above.
        ctx.state.clear_namespace(&self.state_namespace());

        ctx.target_frontend = target_frontend;
        ctx.decorate(KEY_TARGET_ENTITYID, serde_json::Value::String(issuer));
        Ok(MicroServiceAction::ResumeRequest { request })
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{bx, ctx};
    use super::*;

    fn service() -> Box<dyn MicroService> {
        DiscoToTargetIssuer::build(&bx(
            "disco",
            serde_json::json!({
                "disco_endpoints": ["Saml2/disco"],
                "allow_any_issuer": true,
            }),
        ))
        .unwrap()
    }

    #[test]
    fn build_validates_endpoints() {
        for config in [
            serde_json::json!({ "disco_endpoints": [], "allow_any_issuer": true }),
            serde_json::json!({ "disco_endpoints": [""], "allow_any_issuer": true }),
            serde_json::json!({ "disco_endpoints": ["/"], "allow_any_issuer": true }),
            serde_json::json!({ "disco_endpoints": ["a b"], "allow_any_issuer": true }),
            serde_json::json!({ "disco_endpoints": ["disco?x=1"], "allow_any_issuer": true }),
            serde_json::json!({ "allow_any_issuer": true }),
        ] {
            assert!(
                DiscoToTargetIssuer::build(&bx("disco", config.clone())).is_err(),
                "accepted {config}"
            );
        }
    }

    #[test]
    fn registers_exact_routes_with_stripped_slash() {
        let svc = DiscoToTargetIssuer::build(&bx(
            "disco",
            serde_json::json!({
                "disco_endpoints": ["/Saml2/disco"],
                "allow_any_issuer": true,
            }),
        ))
        .unwrap();
        let routes = svc.register_endpoints();
        assert_eq!(routes.len(), 1);
        assert!(routes[0].matches("Saml2/disco"));
        assert!(!routes[0].matches("Saml2/disco/x"));
    }

    #[tokio::test]
    async fn process_request_snapshots_and_passes_through() {
        let svc = service();
        let mut c = ctx();
        c.target_frontend = Some("OIDC".into());
        let mut data = InternalData::request("sp-a");
        data.is_passive = true;

        let out = svc.process_request(&mut c, data).await.unwrap();
        assert_eq!(out.requester.as_deref(), Some("sp-a"));
        assert!(out.is_passive);

        let snapshot = c
            .state
            .get_value(&format!("{NAMESPACE_PREFIX}disco"), KEY_SNAPSHOT)
            .unwrap();
        assert_eq!(
            snapshot.get("target_frontend").and_then(|v| v.as_str()),
            Some("OIDC")
        );
        let restored: InternalData =
            serde_json::from_value(snapshot.get("internal_data").unwrap().clone()).unwrap();
        assert_eq!(restored.requester.as_deref(), Some("sp-a"));
        assert!(restored.is_passive);
    }

    #[tokio::test]
    async fn disco_return_restores_flow_and_consumes_snapshot() {
        let svc = service();
        let mut c = ctx();
        c.target_frontend = Some("OIDC".into());
        let _ = svc
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();

        // Fresh context, as on the actual return navigation.
        let mut ret = ctx();
        ret.state = c.state;
        ret.request
            .query
            .insert("entityID".into(), "https://idp.example".into());

        let action = svc.handle_endpoint(&mut ret, "Saml2/disco").await.unwrap();
        let request = match action {
            MicroServiceAction::ResumeRequest { request } => request,
            MicroServiceAction::Respond(_) => panic!("expected a resume"),
            MicroServiceAction::ResumeResponse { .. } => panic!("expected a request resume"),
        };
        assert_eq!(request.requester.as_deref(), Some("sp-a"));
        assert_eq!(ret.target_frontend.as_deref(), Some("OIDC"));
        assert_eq!(
            ret.decoration(KEY_TARGET_ENTITYID).and_then(|v| v.as_str()),
            Some("https://idp.example")
        );
        // Consume-once: the snapshot is gone.
        assert!(ret
            .state
            .get_value(&format!("{NAMESPACE_PREFIX}disco"), KEY_SNAPSHOT)
            .is_none());

        // A replay with the post-resume state fails.
        let mut replay = ctx();
        replay.state = ret.state;
        replay
            .request
            .query
            .insert("entityID".into(), "https://idp.example".into());
        assert!(svc
            .handle_endpoint(&mut replay, "Saml2/disco")
            .await
            .is_err());
    }

    /// The state namespace is `disco_to_target_issuer:{name}`, never the bare
    /// instance name: config only dedupes names within the microservice list
    /// and the router supports cross-kind name reuse, so a disco instance
    /// named like a frontend would otherwise share that frontend's namespace
    /// and the consume-once `clear_namespace` on resume would wipe the
    /// frontend's own flow state (e.g. the OIDC frontend's `authz_request`).
    #[tokio::test]
    async fn namespace_does_not_collide_with_same_named_module() {
        let svc = service(); // instance name: "disco"
        let mut c = ctx();
        // A same-named module of another kind stored its own flow state under
        // the bare instance name before disco ran.
        c.state.set_str("disco", "authz_request", "frontend-data");

        let _ = svc
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();

        let mut ret = ctx();
        ret.state = c.state;
        ret.request
            .query
            .insert("entityID".into(), "https://idp.example".into());
        svc.handle_endpoint(&mut ret, "Saml2/disco").await.unwrap();

        // The snapshot was consumed, the sibling module's state survived.
        assert!(ret
            .state
            .get_value(&format!("{NAMESPACE_PREFIX}disco"), KEY_SNAPSHOT)
            .is_none());
        assert_eq!(
            ret.state.get_str("disco", "authz_request").as_deref(),
            Some("frontend-data")
        );
    }

    #[tokio::test]
    async fn missing_or_invalid_entity_id_is_rejected_and_snapshot_kept() {
        let svc = service();
        let mut c = ctx();
        let _ = svc
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();

        for value in [
            None,
            Some(String::new()),
            Some("a".repeat(MAX_ENTITY_ID_LEN + 1)),
            Some("å".repeat(MAX_ENTITY_ID_LEN + 1)),
            Some("https://idp.example/\r\nX: y".into()),
        ] {
            let mut ret = ctx();
            ret.state = c.state.clone();
            if let Some(v) = value {
                ret.request.query.insert("entityID".into(), v);
            }
            assert!(svc.handle_endpoint(&mut ret, "Saml2/disco").await.is_err());
            // The user can still be sent through discovery again.
            assert!(ret
                .state
                .get_value(&format!("{NAMESPACE_PREFIX}disco"), KEY_SNAPSHOT)
                .is_some());
        }
    }

    #[test]
    fn build_requires_exactly_one_issuer_policy() {
        // Neither knob: fail closed at config time.
        assert!(DiscoToTargetIssuer::build(&bx(
            "disco",
            serde_json::json!({ "disco_endpoints": ["Saml2/disco"] }),
        ))
        .is_err());
        // Both knobs: ambiguous, rejected.
        assert!(DiscoToTargetIssuer::build(&bx(
            "disco",
            serde_json::json!({
                "disco_endpoints": ["Saml2/disco"],
                "allowed_issuers": { "sp-a": ["https://idp.example"] },
                "allow_any_issuer": true,
            }),
        ))
        .is_err());
    }

    #[test]
    fn build_validates_allowed_issuers() {
        for issuers in [
            serde_json::json!({}),
            serde_json::json!({ "sp-a": [] }),
            serde_json::json!({ "sp-a": [""] }),
            serde_json::json!({ "sp-a": ["https://idp.example/\u{7}"] }),
            serde_json::json!({ "sp-a": ["a".repeat(MAX_ENTITY_ID_LEN + 1)] }),
            serde_json::json!({ "sp-a": ["å".repeat(MAX_ENTITY_ID_LEN + 1)] }),
        ] {
            assert!(
                DiscoToTargetIssuer::build(&bx(
                    "disco",
                    serde_json::json!({
                        "disco_endpoints": ["Saml2/disco"],
                        "allowed_issuers": issuers,
                    }),
                ))
                .is_err(),
                "accepted allowed_issuers {issuers}"
            );
        }
    }

    /// Basic allowlist behavior for a requester *with* a rule set: an issuer
    /// outside it is rejected before the resume - leaving the snapshot in
    /// place so the user can pick again, and the decoration unset - while a
    /// listed issuer resumes and decorates `KEY_TARGET_ENTITYID`.
    #[tokio::test]
    async fn allowed_issuers_gates_the_disco_return() {
        let svc = DiscoToTargetIssuer::build(&bx(
            "disco",
            serde_json::json!({
                "disco_endpoints": ["Saml2/disco"],
                "allowed_issuers": {
                    "sp-a": ["https://spid-idp.example", "https://cie-idp.example"],
                },
            }),
        ))
        .unwrap();
        let mut c = ctx();
        let _ = svc
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();

        // An unlisted issuer is rejected and the snapshot survives, so the
        // user can be sent through discovery again.
        let mut ret = ctx();
        ret.state = c.state.clone();
        ret.request
            .query
            .insert("entityID".into(), "https://rogue-idp.example".into());
        let err = match svc.handle_endpoint(&mut ret, "Saml2/disco").await {
            Ok(_) => panic!("accepted an unlisted issuer"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("allowed_issuers"));
        assert!(ret
            .state
            .get_value(&format!("{NAMESPACE_PREFIX}disco"), KEY_SNAPSHOT)
            .is_some());
        assert!(ret.decoration(KEY_TARGET_ENTITYID).is_none());

        // A listed issuer resumes as usual.
        let mut ok = ctx();
        ok.state = c.state;
        ok.request
            .query
            .insert("entityID".into(), "https://cie-idp.example".into());
        assert!(svc.handle_endpoint(&mut ok, "Saml2/disco").await.is_ok());
        assert_eq!(
            ok.decoration(KEY_TARGET_ENTITYID).and_then(|v| v.as_str()),
            Some("https://cie-idp.example")
        );
    }

    /// The allowlist authorizes `(issuer, requester)` pairs, not issuers
    /// globally: each requester may only resume with an issuer from its own
    /// rule set, and a requester with no rule set at all is rejected for
    /// every issuer. Without this scoping, the target-issuer decoration
    /// would survive `custom_routing`'s requester/default fallback and let
    /// any requester authenticate at any listed issuer via the fallback
    /// backend's metadata resolution (see the field docs on
    /// `allowed_issuers`).
    #[tokio::test]
    async fn allowed_issuers_is_requester_scoped() {
        // sp-a and sp-b each get one issuer; sp-c is deliberately absent.
        let svc = DiscoToTargetIssuer::build(&bx(
            "disco",
            serde_json::json!({
                "disco_endpoints": ["Saml2/disco"],
                "allowed_issuers": {
                    "sp-a": ["https://spid-idp.example"],
                    "sp-b": ["https://cie-idp.example"],
                },
            }),
        ))
        .unwrap();

        for (requester, issuer, accepted) in [
            ("sp-a", "https://spid-idp.example", true),
            ("sp-b", "https://spid-idp.example", false),
            ("sp-b", "https://cie-idp.example", true),
            // No rule set for this requester: every issuer is rejected.
            ("sp-c", "https://spid-idp.example", false),
        ] {
            let mut c = ctx();
            let _ = svc
                .process_request(&mut c, InternalData::request(requester))
                .await
                .unwrap();
            let mut ret = ctx();
            ret.state = c.state;
            ret.request.query.insert("entityID".into(), issuer.into());
            let result = svc.handle_endpoint(&mut ret, "Saml2/disco").await;
            assert_eq!(
                result.is_ok(),
                accepted,
                "requester {requester} picking {issuer}"
            );
            if !accepted {
                assert!(ret
                    .state
                    .get_value(&format!("{NAMESPACE_PREFIX}disco"), KEY_SNAPSHOT)
                    .is_some());
                assert!(ret.decoration(KEY_TARGET_ENTITYID).is_none());
            }
        }
    }

    /// The requester lookup follows the shared `level()` convention (SATOSA's
    /// `get_dict_defaults`): exact requester key, else `""`, else
    /// `"default"`. An unlisted requester therefore inherits the `""` rule
    /// set, while a requester with an exact entry gets *only* that entry -
    /// rule sets are selected, never merged with the default.
    #[tokio::test]
    async fn allowed_issuers_empty_key_is_the_default_rule_set() {
        let svc = DiscoToTargetIssuer::build(&bx(
            "disco",
            serde_json::json!({
                "disco_endpoints": ["Saml2/disco"],
                "allowed_issuers": {
                    "": ["https://cie-idp.example"],
                    "sp-a": ["https://spid-idp.example"],
                },
            }),
        ))
        .unwrap();

        for (requester, issuer, accepted) in [
            // Unlisted requesters get the "" rule set.
            ("sp-other", "https://cie-idp.example", true),
            ("sp-other", "https://spid-idp.example", false),
            // The exact rule set is selected, not merged with the default.
            ("sp-a", "https://spid-idp.example", true),
            ("sp-a", "https://cie-idp.example", false),
        ] {
            let mut c = ctx();
            let _ = svc
                .process_request(&mut c, InternalData::request(requester))
                .await
                .unwrap();
            let mut ret = ctx();
            ret.state = c.state;
            ret.request.query.insert("entityID".into(), issuer.into());
            let result = svc.handle_endpoint(&mut ret, "Saml2/disco").await;
            assert_eq!(
                result.is_ok(),
                accepted,
                "requester {requester} picking {issuer}"
            );
        }
    }

    #[tokio::test]
    async fn oversized_snapshot_is_rejected_before_the_disco_hop() {
        let svc = service();
        let mut c = ctx();
        let mut data = InternalData::request("sp-a");
        data.attributes
            .insert("big".into(), vec!["x".repeat(MAX_SNAPSHOT_BYTES)]);

        let err = match svc.process_request(&mut c, data).await {
            Ok(_) => panic!("accepted an oversized snapshot"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("state-cookie budget"));
        // Nothing was written: no half-started discovery flow.
        assert!(c
            .state
            .get_value(&format!("{NAMESPACE_PREFIX}disco"), KEY_SNAPSHOT)
            .is_none());

        // A normal-sized request still snapshots fine.
        let mut c = ctx();
        assert!(svc
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .is_ok());
        assert!(c
            .state
            .get_value(&format!("{NAMESPACE_PREFIX}disco"), KEY_SNAPSHOT)
            .is_some());
    }

    /// The SAML entityID cap is 1024 *characters*; `is_valid_entity_id` must
    /// not measure UTF-8 bytes (`String::len`), which would reject valid
    /// non-ASCII issuers early. Exercises the full path: a 1024-character
    /// two-byte-per-character issuer (2048 bytes) is accepted both by config
    /// validation and by the discovery-return filter, and ends up in the
    /// target-entity decoration. The over-limit counterparts live in
    /// `build_validates_allowed_issuers` and
    /// `missing_or_invalid_entity_id_is_rejected_and_snapshot_kept`.
    #[tokio::test]
    async fn entity_id_limit_counts_characters_not_bytes() {
        let issuer = "å".repeat(MAX_ENTITY_ID_LEN);
        let svc = DiscoToTargetIssuer::build(&bx(
            "disco",
            serde_json::json!({
                "disco_endpoints": ["Saml2/disco"],
                "allowed_issuers": { "sp-a": [issuer.clone()] },
            }),
        ))
        .unwrap();

        let mut c = ctx();
        let _ = svc
            .process_request(&mut c, InternalData::request("sp-a"))
            .await
            .unwrap();
        let mut ret = ctx();
        ret.state = c.state;
        ret.request.query.insert("entityID".into(), issuer.clone());
        assert!(svc.handle_endpoint(&mut ret, "Saml2/disco").await.is_ok());
        assert_eq!(
            ret.decoration(KEY_TARGET_ENTITYID).and_then(|v| v.as_str()),
            Some(issuer.as_str())
        );
    }

    #[tokio::test]
    async fn disco_return_without_open_flow_fails_cleanly() {
        let svc = service();
        let mut c = ctx();
        c.request
            .query
            .insert("entityID".into(), "https://idp.example".into());
        let err = match svc.handle_endpoint(&mut c, "Saml2/disco").await {
            Ok(_) => panic!("accepted a discovery return with no open flow"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("no discovery flow in progress"));
    }
}
