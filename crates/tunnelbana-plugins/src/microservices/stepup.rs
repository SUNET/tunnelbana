//! `stepup` - eduID MFA step-up through a native SAML micro-SP.
//!
//! SCIM enrichment remains an optional Python response service and publishes
//! only the linked-account JSON decoration. This service owns the protocol
//! boundary: it snapshots the validated response in encrypted state, sends a
//! subject-bound signed AuthnRequest to the linked provider, validates the ACS
//! response with the ordinary SAML backend machinery, and resumes the later
//! response services.

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::{
    Context, KEY_MFA_STEPUP_ACCOUNTS, KEY_PROVIDER_ASSURANCE_CERTIFICATIONS, KEY_REQUESTED_ACCR,
    KEY_REQUESTER_ENTITY_CATEGORIES, KEY_TARGET_ACCR_COMPARISON,
    KEY_TARGET_AUTHN_CONTEXT_CLASS_REF, KEY_TARGET_ENTITYID,
};
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{
    Backend, BackendAction, BuildContext, MicroService, MicroServiceAction,
    MicroServiceResponseAction, Route,
};

use crate::saml2_backend::Saml2Backend;

const REFEDS_MFA: &str = "https://refeds.org/profile/mfa";
const KEY_REQUEST: &str = "request";
const KEY_SNAPSHOT: &str = "snapshot";
const MAX_SNAPSHOT_BYTES: usize = 32 * 1024;
const NAMESPACE_PREFIX: &str = "stepup:";

fn default_identifier_attribute() -> String {
    "eduPersonPrincipalName".to_string()
}

fn default_assurance_attribute() -> String {
    "eduPersonAssurance".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct LoaSettings {
    requested: Vec<String>,
    #[serde(default)]
    extra_accepted: Vec<String>,
    #[serde(default)]
    returned: Option<String>,
}

impl LoaSettings {
    fn accepts(&self, loa: Option<&str>) -> bool {
        loa.is_some_and(|loa| {
            self.requested.iter().any(|value| value == loa)
                || self.extra_accepted.iter().any(|value| value == loa)
        })
    }
}

#[derive(Debug, Deserialize)]
struct MfaConfig {
    #[serde(default)]
    by_entity_id: BTreeMap<String, LoaSettings>,
    #[serde(default)]
    by_entity_category: BTreeMap<String, LoaSettings>,
    // Recognize and normalize an already-satisfied initial IdP response by a
    // trusted metadata assurance certification. The second exchange itself is
    // selected by requester entity ID/category and the SCIM linked account.
    #[serde(default)]
    by_assurance_certification: BTreeMap<String, LoaSettings>,
}

#[derive(Debug, Deserialize)]
struct StepUpConfig {
    mfa: MfaConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct MfaStepupAccount {
    entity_id: String,
    identifier: String,
    #[serde(default = "default_identifier_attribute")]
    attribute: String,
    #[serde(default = "default_assurance_attribute")]
    assurance: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RequestPolicy {
    requester_loas: Vec<String>,
    loa_settings: LoaSettings,
    #[serde(default)]
    is_passive: bool,
}

#[derive(Debug, Deserialize, Serialize)]
struct StepupSnapshot {
    response: InternalData,
    account: MfaStepupAccount,
    policy: RequestPolicy,
    target_frontend: Option<String>,
    decorations: BTreeMap<String, Value>,
}

/// Response-path MFA step-up service.
pub struct StepUp {
    name: String,
    mfa: MfaConfig,
    saml: Saml2Backend,
    mapper: std::sync::Arc<AttributeMapper>,
}

impl StepUp {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: StepUpConfig = bx.parse_config()?;
        validate_mfa(&bx.name, &cfg.mfa)?;
        let saml = Saml2Backend::build_stepup(bx)?;
        Ok(Box::new(Self {
            name: bx.name.clone(),
            mfa: cfg.mfa,
            saml,
            mapper: bx.attribute_mapper.clone(),
        }))
    }

    fn state_namespace(&self) -> String {
        format!("{NAMESPACE_PREFIX}{}", self.name)
    }

    fn request_policy(&self, ctx: &Context, requester: Option<&str>) -> RequestPolicy {
        let requester_loas = decoration_strings(ctx, KEY_REQUESTED_ACCR);
        let configured = requester
            .and_then(|entity_id| self.mfa.by_entity_id.get(entity_id))
            .or_else(|| {
                decoration_strings(ctx, KEY_REQUESTER_ENTITY_CATEGORIES)
                    .iter()
                    .find_map(|category| self.mfa.by_entity_category.get(category))
            })
            .cloned();
        let loa_settings = configured.unwrap_or_else(|| LoaSettings {
            requested: requester_loas.clone(),
            extra_accepted: Vec::new(),
            returned: requester_loas.first().cloned(),
        });
        RequestPolicy {
            requester_loas,
            loa_settings,
            is_passive: false,
        }
    }

    fn provider_already_satisfied(
        &self,
        ctx: &Context,
        data: &InternalData,
    ) -> Option<&LoaSettings> {
        let issuer = data.auth_info.issuer.as_deref()?;
        let settings = self.mfa.by_entity_id.get(issuer).or_else(|| {
            decoration_strings(ctx, KEY_PROVIDER_ASSURANCE_CERTIFICATIONS)
                .iter()
                .find_map(|certification| self.mfa.by_assurance_certification.get(certification))
        })?;
        settings
            .accepts(data.auth_info.auth_class_ref.as_deref())
            .then_some(settings)
    }

    fn snapshot(&self, ctx: &Context) -> Result<StepupSnapshot> {
        let value = ctx
            .state
            .get_value(&self.state_namespace(), KEY_SNAPSHOT)
            .cloned()
            .ok_or_else(|| Error::Authn("no step-up flow in progress".into()))?;
        serde_json::from_value(value)
            .map_err(|e| Error::State(format!("invalid step-up snapshot: {e}")))
    }

    fn finish_stepup(
        &self,
        ctx: &mut Context,
        mut snapshot: StepupSnapshot,
        stepup_response: InternalData,
    ) -> Result<InternalData> {
        let issuer_ok = stepup_response.auth_info.issuer.as_deref()
            == Some(snapshot.account.entity_id.as_str());
        let loa = stepup_response.auth_info.auth_class_ref.as_deref();
        // pysaml2 was configured with Comparison="exact" and the original
        // service additionally checked membership in `requested` itself.
        let loa_ok = loa.is_some_and(|loa| {
            snapshot
                .policy
                .loa_settings
                .requested
                .iter()
                .any(|requested| requested == loa)
        });

        let identifier_internal =
            internal_name_for_external(self.mapper.as_ref(), &snapshot.account.attribute)?;
        let identifier_ok = stepup_response
            .attributes
            .get(&identifier_internal)
            .is_some_and(|values| values.contains(&snapshot.account.identifier));

        if !(issuer_ok && loa_ok && identifier_ok) {
            tracing::warn!(
                microservice = %self.name,
                issuer_ok,
                loa_ok,
                identifier_ok,
                "step-up response did not satisfy the linked-account requirements"
            );
            return Err(Error::Authn(
                "step-up authentication did not satisfy the linked-account requirements".into(),
            ));
        }

        let assurance_internal =
            internal_name_for_external(self.mapper.as_ref(), &snapshot.account.assurance)?;
        if let Some(assurances) = stepup_response.attributes.get(&assurance_internal) {
            let target = snapshot
                .response
                .attributes
                .entry(assurance_internal)
                .or_default();
            for assurance in assurances {
                if !target.contains(assurance) {
                    target.push(assurance.clone());
                }
            }
        }

        snapshot.response.auth_info.auth_class_ref = snapshot
            .policy
            .loa_settings
            .returned
            .clone()
            .or_else(|| snapshot.policy.requester_loas.first().cloned())
            .or_else(|| loa.map(str::to_string));

        // The callback's SAML backend publishes decorations for the step-up
        // IdP. Later response services belong to the original authentication
        // and must see the exact decoration snapshot from that flow instead.
        ctx.target_frontend = snapshot.target_frontend;
        ctx.decorations = snapshot.decorations;
        Ok(snapshot.response)
    }
}

#[async_trait]
impl MicroService for StepUp {
    fn name(&self) -> &str {
        &self.name
    }

    async fn process_request(&self, ctx: &mut Context, data: InternalData) -> Result<InternalData> {
        let mut policy = self.request_policy(ctx, data.requester.as_deref());
        policy.is_passive = data.is_passive;
        ctx.state.set_value(
            &self.state_namespace(),
            KEY_REQUEST,
            serde_json::to_value(policy)
                .map_err(|e| Error::State(format!("serializing step-up policy: {e}")))?,
        );
        Ok(data)
    }

    async fn process_response_action(
        &self,
        ctx: &mut Context,
        mut data: InternalData,
    ) -> Result<MicroServiceResponseAction> {
        let policy: RequestPolicy = ctx
            .state
            .get_value(&self.state_namespace(), KEY_REQUEST)
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| Error::State(format!("invalid saved step-up policy: {e}")))?
            .unwrap_or_else(|| self.request_policy(ctx, data.requester.as_deref()));

        if !policy.requester_loas.iter().any(|loa| loa == REFEDS_MFA) {
            ctx.state.clear_namespace(&self.state_namespace());
            return Ok(MicroServiceResponseAction::Continue(data));
        }

        if let Some(settings) = self.provider_already_satisfied(ctx, &data) {
            if let Some(returned) = &settings.returned {
                data.auth_info.auth_class_ref = Some(returned.clone());
            }
            ctx.state.clear_namespace(&self.state_namespace());
            return Ok(MicroServiceResponseAction::Continue(data));
        }
        if data.auth_info.auth_class_ref.as_deref() == Some(REFEDS_MFA) {
            ctx.state.clear_namespace(&self.state_namespace());
            return Ok(MicroServiceResponseAction::Continue(data));
        }

        if policy.is_passive {
            ctx.mark_interaction_required();
            return Err(Error::Authn(
                "passive authentication cannot initiate an MFA step-up interaction".into(),
            ));
        }

        let accounts_value = ctx
            .decoration(KEY_MFA_STEPUP_ACCOUNTS)
            .cloned()
            .unwrap_or_else(|| Value::Array(Vec::new()));
        let accounts: Vec<MfaStepupAccount> = serde_json::from_value(accounts_value)
            .map_err(|_| Error::Authn("invalid MFA linked-account data".into()))?;
        let account = accounts.into_iter().next().ok_or_else(|| {
            Error::Authn("MFA is required but the user has no linked account".into())
        })?;
        if account.entity_id.is_empty()
            || account.identifier.is_empty()
            || account.attribute.is_empty()
            || account.assurance.is_empty()
        {
            return Err(Error::Authn("MFA linked-account data is incomplete".into()));
        }
        self.saml.validate_stepup_target(&account.entity_id)?;
        if policy.requester_loas.is_empty() || policy.loa_settings.requested.is_empty() {
            ctx.state.clear_namespace(&self.state_namespace());
            return Ok(MicroServiceResponseAction::Continue(data));
        }

        // Fail before redirecting if either linked-account attribute cannot be
        // represented by the configured internal attribute map.
        internal_name_for_external(self.mapper.as_ref(), &account.attribute)?;
        internal_name_for_external(self.mapper.as_ref(), &account.assurance)?;

        let snapshot = StepupSnapshot {
            response: data,
            account: account.clone(),
            policy: policy.clone(),
            target_frontend: ctx.target_frontend.clone(),
            decorations: ctx.decorations.clone(),
        };
        let snapshot_value = serde_json::to_value(&snapshot)
            .map_err(|e| Error::State(format!("serializing step-up snapshot: {e}")))?;
        let snapshot_size = snapshot_value.to_string().len();
        if snapshot_size > MAX_SNAPSHOT_BYTES {
            return Err(Error::Authn(format!(
                "step-up snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte state budget"
            )));
        }
        ctx.state
            .set_value(&self.state_namespace(), KEY_SNAPSHOT, snapshot_value);

        ctx.decorate(KEY_TARGET_ENTITYID, Value::String(account.entity_id));
        ctx.decorate(
            KEY_TARGET_AUTHN_CONTEXT_CLASS_REF,
            json_strings(&policy.loa_settings.requested),
        );
        ctx.decorate(KEY_TARGET_ACCR_COMPARISON, Value::String("exact".into()));

        let request = InternalData {
            subject_id: Some(account.identifier),
            requester: snapshot.response.requester.clone(),
            ..Default::default()
        };
        let redirect = self.saml.start_auth(ctx, request).await?;
        tracing::info!(microservice = %self.name, "starting MFA step-up authentication");
        Ok(MicroServiceResponseAction::Respond(redirect))
    }

    fn register_endpoints(&self) -> Vec<Route> {
        self.saml
            .register_endpoints()
            .into_iter()
            .filter(|route| route.id == "acs" || route.id == "metadata")
            .collect()
    }

    async fn handle_endpoint(
        &self,
        ctx: &mut Context,
        route_id: &str,
    ) -> Result<MicroServiceAction> {
        if route_id == "metadata" {
            return match self.saml.handle_endpoint(ctx, route_id).await? {
                BackendAction::Respond(response) => Ok(MicroServiceAction::Respond(response)),
                BackendAction::AuthResponse(_) => Err(Error::Internal(
                    "step-up metadata endpoint returned authentication data".into(),
                )),
            };
        }
        if route_id != "acs" {
            return Err(Error::NoBoundEndpoint(route_id.to_string()));
        }

        // Clone before the delegated backend consumes its namespace on a
        // successful, replay-checked ACS response.
        let snapshot = self.snapshot(ctx)?;
        match self.saml.handle_endpoint(ctx, route_id).await? {
            BackendAction::AuthResponse(response) => {
                // A verified SAML response consumes the higher-level snapshot
                // even when the linked subject/LoA checks below reject it.
                ctx.state.clear_namespace(&self.state_namespace());
                let response = self.finish_stepup(ctx, snapshot, response)?;
                tracing::info!(microservice = %self.name, "MFA step-up authentication succeeded");
                Ok(MicroServiceAction::ResumeResponse { response })
            }
            BackendAction::Respond(_) => Err(Error::Internal(
                "step-up ACS did not return authentication data".into(),
            )),
        }
    }
}

fn validate_mfa(name: &str, mfa: &MfaConfig) -> Result<()> {
    for settings in mfa
        .by_entity_id
        .values()
        .chain(mfa.by_entity_category.values())
        .chain(mfa.by_assurance_certification.values())
    {
        if settings.requested.is_empty()
            || settings.requested.iter().any(String::is_empty)
            || settings.extra_accepted.iter().any(String::is_empty)
            || settings.returned.as_ref().is_some_and(String::is_empty)
        {
            return Err(Error::Config(format!(
                "stepup {name}: LoA settings must contain non-empty requested values"
            )));
        }
    }
    Ok(())
}

fn decoration_strings(ctx: &Context, key: &str) -> Vec<String> {
    ctx.decoration(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn json_strings(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn internal_name_for_external(mapper: &AttributeMapper, external: &str) -> Result<String> {
    let matches: Vec<String> = mapper
        .attributes()
        .filter_map(|(internal, profiles)| {
            let mapping = profiles.get("saml")?;
            (mapping.names.iter().any(|name| name == external)
                || mapping.oid.as_deref() == Some(external)
                || mapping.friendly_name.as_deref() == Some(external))
            .then(|| internal.clone())
        })
        .collect();
    match matches.as_slice() {
        [internal] => Ok(internal.clone()),
        [] => Err(Error::Config(format!(
            "step-up SAML attribute {external:?} has no internal mapping"
        ))),
        _ => Err(Error::Config(format!(
            "step-up SAML attribute {external:?} has multiple internal mappings"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::io::Read;
    use std::sync::Arc;
    use tunnelbana_core::attributes::AttributeMapper;
    use tunnelbana_core::internal::AuthenticationInformation;

    const REQUESTER: &str = "https://service.example/sp";
    const STEPUP_IDP: &str = "https://accounts.example/idp";

    fn service() -> StepUp {
        let testdata = format!("{}/testdata", env!("CARGO_MANIFEST_DIR"));
        let mut bx = super::super::testutil::bx(
            "stepup",
            serde_json::json!({
                "mfa": {
                    "by_entity_id": {
                        (REQUESTER): {
                            "requested": [REFEDS_MFA],
                            "returned": REFEDS_MFA
                        }
                    }
                },
                "sp_entity_id": "https://proxy.example/stepup/metadata",
                "sp_key_path": format!("{testdata}/sp-key.pem"),
                "sp_cert_path": format!("{testdata}/sp-cert.pem"),
                "idp_entity_id": STEPUP_IDP,
                "idp_sso_url": "https://accounts.example/sso",
                "idp_cert_path": format!("{testdata}/idp-cert.pem"),
                "sign_authn_requests": true,
                "security": "permissive"
            }),
        );
        bx.attribute_mapper = Arc::new(
            AttributeMapper::from_toml(
                r#"
                [attributes.eppn]
                saml = ["eduPersonPrincipalName"]
                [attributes.assurance]
                saml = ["eduPersonAssurance"]
                "#,
            )
            .unwrap(),
        );
        let cfg: StepUpConfig = bx.parse_config().unwrap();
        StepUp {
            name: bx.name.clone(),
            mfa: cfg.mfa,
            saml: Saml2Backend::build_stepup(&bx).unwrap(),
            mapper: bx.attribute_mapper.clone(),
        }
    }

    fn initial_response() -> InternalData {
        InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: Some(
                    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport".into(),
                ),
                issuer: Some("https://initial.example/idp".into()),
                ..Default::default()
            },
            requester: Some(REQUESTER.into()),
            subject_id: Some("original-subject".into()),
            ..Default::default()
        }
    }

    fn redirect_xml(response: &tunnelbana_core::http::Response) -> String {
        let location = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value)
            .unwrap();
        let encoded = url::form_urlencoded::parse(location.split_once('?').unwrap().1.as_bytes())
            .find(|(name, _)| name == "SAMLRequest")
            .map(|(_, value)| value.into_owned())
            .unwrap();
        let compressed = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let mut xml = String::new();
        flate2::read::DeflateDecoder::new(&compressed[..])
            .read_to_string(&mut xml)
            .unwrap();
        xml
    }

    fn signed_stepup_response(request_id: &str) -> String {
        use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
        use gamlastan::core::assertion::name_id::NameId;
        use gamlastan::crypto::keys::loader;
        use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};
        use gamlastan::profiles::sso::idp;
        use gamlastan::profiles::sso::web_browser::{ResponseOptions, ResponseTimes};
        use gamlastan::xml::serialize::SamlSerialize;

        let sp_entity_id = "https://proxy.example/stepup/metadata";
        let options = ResponseOptions {
            idp_entity_id: STEPUP_IDP.into(),
            in_response_to: Some(request_id.into()),
            sp_entity_id: sp_entity_id.into(),
            acs_url: "https://x/stepup/acs".into(),
            assertion_lifetime_seconds: 300,
            session_index: None,
            session_not_on_or_after: None,
            authn_context_class_ref: Some(REFEDS_MFA.into()),
            client_address: None,
            attributes: vec![
                Attribute {
                    name: "eduPersonPrincipalName".into(),
                    name_format: None,
                    friendly_name: None,
                    values: vec![AttributeValue::String("alice@example.org".into())],
                },
                Attribute {
                    name: "eduPersonAssurance".into(),
                    name_format: None,
                    friendly_name: None,
                    values: vec![AttributeValue::String(
                        "https://refeds.org/assurance/IAP/high".into(),
                    )],
                },
            ],
        };
        let name_id = NameId {
            value: "account-subject".into(),
            format: Some(gamlastan::core::constants::NAMEID_PERSISTENT.into()),
            name_qualifier: Some(STEPUP_IDP.into()),
            sp_name_qualifier: Some(sp_entity_id.into()),
            sp_provided_id: None,
        };
        let response =
            idp::create_response(&options, &name_id, ResponseTimes::at(chrono::Utc::now()));
        let assertion_id = response.assertions[0].id.clone();
        let xml = response.to_xml_string().unwrap();

        let testdata = format!("{}/testdata", env!("CARGO_MANIFEST_DIR"));
        let cert_pem = std::fs::read(format!("{testdata}/idp-cert.pem")).unwrap();
        let cert_b64 = crate::saml_common::extract_cert_b64(&cert_pem);
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(&cert_b64)
            .unwrap();
        let key_pem = std::fs::read(format!("{testdata}/idp-key.pem")).unwrap();
        let mut key = loader::load_pem_auto(&key_pem, None).unwrap();
        key.usage = KeyUsage::Sign;
        key.x509_chain = vec![cert_der];
        let mut manager = KeysManager::new();
        manager.add_key(key);
        let signer = SamlSigner::new(manager);
        let signature = format!(
            r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
        );
        let assertion_start = xml.find("<saml:Assertion").unwrap();
        let opening_end = assertion_start + xml[assertion_start..].find('>').unwrap();
        let templated = format!(
            "{}{}{}",
            &xml[..=opening_end],
            signature,
            &xml[opening_end + 1..]
        );
        let signed = signer.sign_enveloped(&templated).unwrap();
        base64::engine::general_purpose::STANDARD.encode(signed.as_bytes())
    }

    #[test]
    fn external_attribute_mapping_must_be_unique() {
        let mapper = AttributeMapper::from_toml(
            r#"
            [attributes.eppn]
            saml = ["eduPersonPrincipalName"]
            [attributes.assurance]
            saml = ["eduPersonAssurance"]
            "#,
        )
        .unwrap();
        assert_eq!(
            internal_name_for_external(&mapper, "eduPersonPrincipalName").unwrap(),
            "eppn"
        );
        assert!(internal_name_for_external(&mapper, "missing").is_err());
    }

    #[test]
    fn loa_settings_accept_requested_and_aliases() {
        let settings = LoaSettings {
            requested: vec!["loa3".into()],
            extra_accepted: vec!["loa3-alias".into()],
            returned: Some(REFEDS_MFA.into()),
        };
        assert!(settings.accepts(Some("loa3")));
        assert!(settings.accepts(Some("loa3-alias")));
        assert!(!settings.accepts(Some("loa2")));
    }

    #[test]
    fn requester_category_and_provider_certification_select_policy() {
        let mut service = service();
        let category_settings = LoaSettings {
            requested: vec!["urn:category:loa".into()],
            extra_accepted: vec![],
            returned: Some(REFEDS_MFA.into()),
        };
        service.mfa.by_entity_category.insert(
            "https://category.example/mfa".into(),
            category_settings.clone(),
        );
        let provider_settings = LoaSettings {
            requested: vec!["urn:provider:loa3".into()],
            extra_accepted: vec!["urn:provider:loa3-alias".into()],
            returned: Some(REFEDS_MFA.into()),
        };
        service.mfa.by_assurance_certification.insert(
            "https://certification.example/eid".into(),
            provider_settings,
        );

        let mut ctx = super::super::testutil::ctx();
        ctx.decorate(
            KEY_REQUESTED_ACCR,
            Value::Array(vec![Value::String(REFEDS_MFA.into())]),
        );
        ctx.decorate(
            KEY_REQUESTER_ENTITY_CATEGORIES,
            serde_json::json!(["https://category.example/mfa"]),
        );
        let policy = service.request_policy(&ctx, Some("https://unlisted.example/sp"));
        assert_eq!(policy.loa_settings, category_settings);

        ctx.decorate(
            KEY_PROVIDER_ASSURANCE_CERTIFICATIONS,
            serde_json::json!(["https://certification.example/eid"]),
        );
        let mut response = initial_response();
        response.auth_info.auth_class_ref = Some("urn:provider:loa3-alias".into());
        assert!(service
            .provider_already_satisfied(&ctx, &response)
            .is_some());
    }

    #[tokio::test]
    async fn starts_subject_bound_exact_mfa_request() {
        let service = service();
        let mut ctx = super::super::testutil::ctx();
        ctx.target_frontend = Some("SamlFrontend".into());
        ctx.decorate(
            KEY_REQUESTED_ACCR,
            Value::Array(vec![Value::String(REFEDS_MFA.into())]),
        );
        service
            .process_request(&mut ctx, InternalData::request(REQUESTER))
            .await
            .unwrap();
        ctx.decorate(
            KEY_MFA_STEPUP_ACCOUNTS,
            serde_json::json!([{
                "entity_id": STEPUP_IDP,
                "identifier": "alice@example.org"
            }]),
        );

        let response = match service
            .process_response_action(&mut ctx, initial_response())
            .await
            .unwrap()
        {
            MicroServiceResponseAction::Respond(response) => response,
            MicroServiceResponseAction::Continue(_) => panic!("expected step-up redirect"),
        };
        let xml = redirect_xml(&response);
        assert!(xml.contains("alice@example.org"), "got {xml}");
        assert!(xml.contains(REFEDS_MFA), "got {xml}");
        assert!(xml.contains("Comparison=\"exact\""), "got {xml}");
        let location = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value)
            .unwrap();
        assert!(location.contains("SigAlg=") && location.contains("Signature="));
        assert!(ctx.state.get("stepup:stepup").is_some());
        assert!(ctx.state.get("stepup_saml:stepup").is_some());
    }

    #[tokio::test]
    async fn validated_acs_resumes_original_response() {
        let service = service();
        let mut ctx = super::super::testutil::ctx();
        ctx.target_frontend = Some("SamlFrontend".into());
        ctx.decorate(
            KEY_REQUESTED_ACCR,
            Value::Array(vec![Value::String(REFEDS_MFA.into())]),
        );
        service
            .process_request(&mut ctx, InternalData::request(REQUESTER))
            .await
            .unwrap();
        ctx.decorate(
            KEY_MFA_STEPUP_ACCOUNTS,
            serde_json::json!([{
                "entity_id": STEPUP_IDP,
                "identifier": "alice@example.org"
            }]),
        );
        let redirect = match service
            .process_response_action(&mut ctx, initial_response())
            .await
            .unwrap()
        {
            MicroServiceResponseAction::Respond(response) => response,
            MicroServiceResponseAction::Continue(_) => panic!("expected step-up redirect"),
        };
        let request_xml = redirect_xml(&redirect);
        let id_start = request_xml.find("ID=\"").unwrap() + 4;
        let id_end = id_start + request_xml[id_start..].find('"').unwrap();
        let saml_response = signed_stepup_response(&request_xml[id_start..id_end]);
        ctx.request = tunnelbana_core::http::HttpRequestData {
            path: "stepup/acs".into(),
            uri: "https://x/stepup/acs".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLResponse".into(), saml_response)]),
            ..Default::default()
        };

        let resumed = match service.handle_endpoint(&mut ctx, "acs").await.unwrap() {
            MicroServiceAction::ResumeResponse { response } => response,
            _ => panic!("expected response resume"),
        };
        assert_eq!(resumed.subject_id.as_deref(), Some("original-subject"));
        assert_eq!(
            resumed.auth_info.auth_class_ref.as_deref(),
            Some(REFEDS_MFA)
        );
        assert_eq!(
            resumed.attributes.get("assurance").unwrap(),
            &["https://refeds.org/assurance/IAP/high"]
        );
        assert!(ctx.state.get("stepup:stepup").is_none());
        assert!(ctx.state.get("stepup_saml:stepup").is_none());
    }

    #[tokio::test]
    async fn required_mfa_without_linked_account_fails_closed() {
        let service = service();
        let mut ctx = super::super::testutil::ctx();
        ctx.decorate(
            KEY_REQUESTED_ACCR,
            Value::Array(vec![Value::String(REFEDS_MFA.into())]),
        );
        service
            .process_request(&mut ctx, InternalData::request(REQUESTER))
            .await
            .unwrap();
        let error = service
            .process_response_action(&mut ctx, initial_response())
            .await
            .err()
            .expect("missing account must fail");
        assert!(matches!(error, Error::Authn(_)));
    }

    #[tokio::test]
    async fn non_mfa_request_passes_without_scim_account() {
        let service = service();
        let mut ctx = super::super::testutil::ctx();
        service
            .process_request(&mut ctx, InternalData::request(REQUESTER))
            .await
            .unwrap();
        assert!(matches!(
            service
                .process_response_action(&mut ctx, initial_response())
                .await
                .unwrap(),
            MicroServiceResponseAction::Continue(_)
        ));
    }

    #[tokio::test]
    async fn passive_request_never_starts_interactive_stepup() {
        let service = service();
        let mut ctx = super::super::testutil::ctx();
        ctx.decorate(
            KEY_REQUESTED_ACCR,
            Value::Array(vec![Value::String(REFEDS_MFA.into())]),
        );
        let mut request = InternalData::request(REQUESTER);
        request.is_passive = true;
        service.process_request(&mut ctx, request).await.unwrap();
        let error = service
            .process_response_action(&mut ctx, initial_response())
            .await
            .err()
            .expect("passive step-up must fail");
        assert!(matches!(error, Error::Authn(_)));
        assert!(ctx.interaction_required());
    }

    #[test]
    fn verified_stepup_merges_assurance_and_restores_original_flow() {
        let service = service();
        let mut ctx = super::super::testutil::ctx();
        ctx.decorate("callback-decoration", Value::String("replace-me".into()));
        let mut response = initial_response();
        response
            .attributes
            .insert("assurance".into(), vec!["initial-assurance".into()]);
        let snapshot = StepupSnapshot {
            response,
            account: MfaStepupAccount {
                entity_id: STEPUP_IDP.into(),
                identifier: "alice@example.org".into(),
                attribute: default_identifier_attribute(),
                assurance: default_assurance_attribute(),
            },
            policy: RequestPolicy {
                requester_loas: vec![REFEDS_MFA.into()],
                loa_settings: LoaSettings {
                    requested: vec!["urn:stepup:loa3".into()],
                    extra_accepted: vec![],
                    returned: Some(REFEDS_MFA.into()),
                },
                is_passive: false,
            },
            target_frontend: Some("SamlFrontend".into()),
            decorations: BTreeMap::from([(
                "original-decoration".into(),
                Value::String("kept".into()),
            )]),
        };
        let stepup_response = InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: Some("urn:stepup:loa3".into()),
                issuer: Some(STEPUP_IDP.into()),
                ..Default::default()
            },
            attributes: BTreeMap::from([
                ("eppn".into(), vec!["alice@example.org".into()]),
                ("assurance".into(), vec!["stepup-assurance".into()]),
            ]),
            ..Default::default()
        };

        let result = service
            .finish_stepup(&mut ctx, snapshot, stepup_response)
            .unwrap();
        assert_eq!(result.auth_info.auth_class_ref.as_deref(), Some(REFEDS_MFA));
        assert_eq!(
            result.attributes.get("assurance").unwrap(),
            &vec![
                "initial-assurance".to_string(),
                "stepup-assurance".to_string()
            ]
        );
        assert_eq!(ctx.target_frontend.as_deref(), Some("SamlFrontend"));
        assert_eq!(
            ctx.decoration("original-decoration")
                .and_then(Value::as_str),
            Some("kept")
        );
        assert!(ctx.decoration("callback-decoration").is_none());
    }
}
