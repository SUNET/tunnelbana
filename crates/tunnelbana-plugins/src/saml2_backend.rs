//! SAML2 backend — the proxy acts as a SAML Service Provider (SP) to an upstream
//! SAML Identity Provider. Wraps the `gamlastan` core: create AuthnRequest, send
//! via HTTP-Redirect, then at the ACS verify the signature, validate the Response
//! (32-check `AssertionValidator` via `process_response`) and map attributes.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use serde::Deserialize;

use gamlastan::core::assertion::attribute::AttributeValue;
use gamlastan::core::constants;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner, SamlVerifier};
use gamlastan::profiles::sso::sp as sp_profile;
use gamlastan::profiles::sso::web_browser::{self, AuthnRequestOptions};
use gamlastan::security::config::SecurityConfig;
use gamlastan::security::validation::{AssertionValidator, ValidationParams};
use gamlastan::xml::serialize::SamlSerialize;

use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::Response;
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext, Route};
use tunnelbana_core::util::now_rfc3339;

/// XML-DSig RSA-SHA256 signature algorithm URI (for signed redirect requests).
const SIGALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

#[derive(Debug, Deserialize)]
struct Saml2BackendConfig {
    /// SP entity id; defaults to `<base_url>/<name>`.
    #[serde(default)]
    sp_entity_id: Option<String>,
    /// SP private key (PEM) — used for the keys manager and request signing.
    sp_key_path: String,
    /// SP certificate (PEM) — published in SP metadata.
    #[serde(default)]
    sp_cert_path: Option<String>,
    /// Upstream IdP entity id (expected issuer).
    idp_entity_id: String,
    /// Upstream IdP SSO endpoint (where AuthnRequests are sent).
    idp_sso_url: String,
    /// Upstream IdP signing certificate (PEM) — verifies the Response.
    idp_cert_path: String,
    #[serde(default)]
    sign_authn_requests: bool,
    #[serde(default)]
    name_id_format: Option<String>,
    /// Use "strict" or "permissive" security validation (default permissive).
    #[serde(default)]
    security: Option<String>,
}

pub struct Saml2Backend {
    name: String,
    sp_entity_id: String,
    acs_url: String,
    idp_entity_id: String,
    idp_sso_url: String,
    signer: SamlSigner,
    verifier: SamlVerifier,
    sign_requests: bool,
    name_id_format: Option<String>,
    sp_cert_b64: Option<String>,
    strict: bool,
    mapper: Arc<AttributeMapper>,
}

impl Saml2Backend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Backend>> {
        let cfg: Saml2BackendConfig = bx.parse_config()?;
        let module_base = bx.module_base();
        let sp_entity_id = cfg.sp_entity_id.clone().unwrap_or_else(|| module_base.clone());
        let acs_url = format!("{module_base}/acs");

        let sp_key = std::fs::read(&cfg.sp_key_path)
            .map_err(|e| Error::Config(format!("reading sp_key_path: {e}")))?;
        let idp_cert = std::fs::read(&cfg.idp_cert_path)
            .map_err(|e| Error::Config(format!("reading idp_cert_path: {e}")))?;

        // Signer keys manager: the SP private key (for signing AuthnRequests).
        let mut sp_signing_key = loader::load_pem_auto(&sp_key, None)
            .map_err(|e| Error::Crypto(format!("loading sp key: {e}")))?;
        sp_signing_key.usage = KeyUsage::Sign;
        let mut signer_km = KeysManager::new();
        signer_km.add_key(sp_signing_key);
        let signer = SamlSigner::new(signer_km);

        // Verifier keys manager: the IdP certificate as a verification key
        // (public key extracted from the X.509) plus the same cert as a trusted
        // anchor for chain validation.
        let idp_cert_der = base64::engine::general_purpose::STANDARD
            .decode(extract_cert_b64(&idp_cert))
            .map_err(|e| Error::Crypto(format!("decoding idp cert: {e}")))?;
        let idp_key = loader::load_x509_cert_der(&idp_cert_der)
            .map_err(|e| Error::Crypto(format!("parsing idp cert: {e}")))?;
        let mut verifier_km = KeysManager::new();
        verifier_km.add_key(idp_key);
        verifier_km.add_trusted_cert(idp_cert_der);
        let verifier = SamlVerifier::new(verifier_km);

        let sp_cert_b64 = match &cfg.sp_cert_path {
            Some(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| Error::Config(format!("reading sp_cert_path: {e}")))?;
                Some(extract_cert_b64(&pem))
            }
            None => None,
        };

        Ok(Box::new(Saml2Backend {
            name: bx.name.clone(),
            sp_entity_id,
            acs_url,
            idp_entity_id: cfg.idp_entity_id,
            idp_sso_url: cfg.idp_sso_url,
            signer,
            verifier,
            sign_requests: cfg.sign_authn_requests,
            name_id_format: cfg.name_id_format,
            sp_cert_b64,
            strict: cfg.security.as_deref() == Some("strict"),
            mapper: bx.attribute_mapper.clone(),
        }))
    }

    fn security_config(&self) -> SecurityConfig {
        if self.strict {
            SecurityConfig::strict()
        } else {
            SecurityConfig::permissive()
        }
    }

    fn build_metadata(&self) -> Result<String> {
        use gamlastan::metadata::types::endpoint::{Endpoint, IndexedEndpoint};
        use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
        use gamlastan::metadata::types::key_descriptor::KeyDescriptor;
        use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};
        use gamlastan::metadata::types::sp::SpSsoDescriptor;

        let mut base =
            RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]);
        if let Some(cert_b64) = &self.sp_cert_b64 {
            let key_info = gamlastan::crypto::build_x509_key_info(&[cert_b64.as_str()]);
            base.key_descriptors = vec![KeyDescriptor::signing(key_info)];
        }

        let sp_sso = SpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base,
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: vec![
                    constants::NAMEID_PERSISTENT.to_string(),
                    constants::NAMEID_EMAIL.to_string(),
                ],
            },
            authn_requests_signed: Some(self.sign_requests),
            want_assertions_signed: Some(true),
            assertion_consumer_services: vec![IndexedEndpoint::new_default(
                Endpoint::new(constants::BINDING_HTTP_POST, &self.acs_url),
                0,
            )],
            attribute_consuming_services: vec![],
        };

        let entity = EntityDescriptor {
            entity_id: self.sp_entity_id.clone(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![],
                sp_sso: vec![sp_sso],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: None,
            contact_persons: vec![],
            additional_metadata_locations: vec![],
        };

        entity
            .to_xml_string()
            .map_err(|e| Error::Internal(format!("serializing SP metadata: {e}")))
    }

    fn handle_acs(&self, ctx: &mut Context) -> Result<BackendAction> {
        // SAMLResponse arrives via HTTP-POST (form) or HTTP-Redirect (query).
        let saml_response = ctx
            .request
            .form
            .get("SAMLResponse")
            .or_else(|| ctx.request.query.get("SAMLResponse"))
            .ok_or_else(|| Error::BadRequest("missing SAMLResponse".into()))?;

        let xml_bytes = base64::engine::general_purpose::STANDARD
            .decode(saml_response.trim())
            .map_err(|e| Error::BadRequest(format!("base64 SAMLResponse: {e}")))?;
        let xml = String::from_utf8(xml_bytes)
            .map_err(|e| Error::BadRequest(format!("SAMLResponse not UTF-8: {e}")))?;

        // 1) Verify the enveloped signature against the IdP certificate.
        let verify_result = self
            .verifier
            .verify_enveloped(&xml)
            .map_err(|e| Error::Authn(format!("signature verification failed: {e}")))?;
        if let gamlastan::crypto::VerifyResult::Invalid { reason } = &verify_result {
            return Err(Error::Authn(format!(
                "SAML Response signature is not valid: {reason}"
            )));
        }

        // 2) Parse the Response.
        let doc = gamlastan::xml::uppsala::parse(&xml)
            .map_err(|e| Error::BadRequest(format!("invalid SAML XML: {e}")))?;
        let response = gamlastan::xml::deserialize::parse_saml::<
            gamlastan::core::protocol::response::ResponseRef<'_>,
        >(&doc)
        .map_err(|e| Error::BadRequest(format!("parsing Response: {e}")))?
        .to_owned();

        // 3) Status check. A non-success status (e.g. the user cancelled or the
        //    login failed at the IdP) is surfaced as an authn error so the
        //    frontend can return `access_denied` to the RP rather than looping.
        if !response.base.status.is_success() {
            let msg = response
                .base
                .status
                .status_message
                .clone()
                .unwrap_or_else(|| response.base.status.status_code.value.clone());
            return Err(Error::Authn(format!(
                "IdP returned a non-success SAML status: {msg}"
            )));
        }
        if response.assertions.is_empty() {
            return Err(Error::Authn("SAML Response carries no assertions".into()));
        }

        // 4) Run the 32-check validation. The enveloped signature was already
        //    cryptographically verified in step 1; when the signature is on the
        //    Response element itself, tell the validator so it accepts a validly
        //    signed Response. Some IdPs (e.g. crewjam/saml-based) sign the
        //    Response, others sign only the assertion — both are valid SAML and
        //    `verify_enveloped` handles either, so we accept "assertion or
        //    response signed" (cf. SATOSA `want_assertions_or_response_signed`).
        let expected_id = ctx.state.get_str(&self.name, "authn_id");
        let response_signature_verified = if response.base.has_signature {
            Some(true)
        } else {
            None
        };
        let params = ValidationParams {
            received_url: &self.acs_url,
            expected_idp_entity_id: &self.idp_entity_id,
            sp_entity_id: &self.sp_entity_id,
            acs_url: &self.acs_url,
            expected_request_id: expected_id.as_deref(),
            client_address: None,
            relay_state: None,
            response_signature_xml: None,
            response_signature_verified,
            current_proxy_depth: 0,
            now: Utc::now(),
        };
        let cfg = self.security_config();
        let validation = AssertionValidator::new(&cfg).validate_response(&response, &params);
        if !validation.is_valid() {
            let errors = validation
                .failures()
                .iter()
                .map(|c| {
                    format!(
                        "{}: {}",
                        c.check_name,
                        c.detail.as_deref().unwrap_or("failed")
                    )
                })
                .collect::<Vec<_>>()
                .join("; ");
            return Err(Error::Authn(format!("SAML validation failed: {errors}")));
        }

        // 5) Extract identity from the first assertion carrying an AuthnStatement.
        let assertion = response
            .assertions
            .iter()
            .find(|a| !a.authn_statements.is_empty())
            .ok_or_else(|| Error::Authn("no assertion with an AuthnStatement".into()))?;
        let name_id = match assertion.subject.as_ref().and_then(|s| s.name_id.as_ref()) {
            Some(gamlastan::core::assertion::name_id::NameIdOrEncryptedId::NameId(nid)) => {
                nid.value.clone()
            }
            _ => return Err(Error::Authn("missing or unsupported NameID".into())),
        };
        let authn_class_ref = assertion
            .authn_statements
            .first()
            .and_then(|s| s.authn_context.authn_context_class_ref.clone());
        let idp_entity_id = assertion.issuer.value.clone();
        let saml_attributes: Vec<_> = response
            .assertions
            .iter()
            .flat_map(|a| web_browser::extract_attributes(&a.attribute_statements))
            .collect();

        // 6) Map SAML attributes -> internal. Key by both the attribute Name and
        //    its FriendlyName so the attribute map can match either.
        let mut external: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for attr in &saml_attributes {
            let values: Vec<String> = attr
                .values
                .iter()
                .filter_map(|v| match v {
                    AttributeValue::String(s) => Some(s.clone()),
                    AttributeValue::Integer(i) => Some(i.to_string()),
                    AttributeValue::Boolean(b) => Some(b.to_string()),
                    AttributeValue::DateTime(s) => Some(s.clone()),
                    _ => None,
                })
                .collect();
            if values.is_empty() {
                continue;
            }
            external.insert(attr.name.clone(), values.clone());
            if let Some(friendly) = &attr.friendly_name {
                external.insert(friendly.clone(), values);
            }
        }
        let internal_attrs = self.mapper.to_internal("saml", &external);

        ctx.state.clear_namespace(&self.name);

        let response = InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: authn_class_ref,
                timestamp: Some(now_rfc3339()),
                issuer: Some(idp_entity_id),
            },
            requester: None,
            requester_name: Vec::new(),
            subject_id: Some(name_id),
            subject_type: SubjectType::Persistent,
            attributes: internal_attrs,
        };
        Ok(BackendAction::AuthResponse(response))
    }
}

#[async_trait]
impl Backend for Saml2Backend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self) -> Vec<Route> {
        vec![
            Route::new(&regex::escape(&format!("{}/acs", self.name)), "acs"),
            Route::new(&regex::escape(&format!("{}/metadata", self.name)), "metadata"),
        ]
    }

    async fn start_auth(&self, ctx: &mut Context, _request: InternalData) -> Result<Response> {
        let options = AuthnRequestOptions {
            sp_entity_id: self.sp_entity_id.clone(),
            acs_url: Some(self.acs_url.clone()),
            destination: Some(self.idp_sso_url.clone()),
            protocol_binding: Some(constants::BINDING_HTTP_POST.to_string()),
            name_id_format: self.name_id_format.clone(),
            allow_create: true,
            ..Default::default()
        };
        let req = sp_profile::create_authn_request(&options)
            .map_err(|e| Error::Internal(format!("creating AuthnRequest: {e}")))?;
        ctx.state.set_str(&self.name, "authn_id", &req.base.id);

        let xml = req
            .to_xml_string()
            .map_err(|e| Error::Internal(format!("serializing AuthnRequest: {e}")))?;

        let signer = if self.sign_requests {
            Some((&self.signer, SIGALG_RSA_SHA256))
        } else {
            None
        };
        let params = gamlastan::bindings::redirect::RedirectEncodeParams {
            saml_xml: xml.as_bytes(),
            is_request: true,
            destination: &self.idp_sso_url,
            relay_state: None,
            signer,
        };
        let url = gamlastan::bindings::redirect::redirect_encode(&params)
            .map_err(|e| Error::Internal(format!("redirect encode: {e}")))?;
        Ok(Response::redirect(url))
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<BackendAction> {
        match route_id {
            "acs" => self.handle_acs(ctx),
            "metadata" => Ok(BackendAction::Respond(
                Response::new(200)
                    .with_header("content-type", "application/samlmetadata+xml; charset=utf-8")
                    .with_body(self.build_metadata()?.into_bytes()),
            )),
            other => Err(Error::NoBoundEndpoint(other.to_string())),
        }
    }
}

/// Extract the base64 body of the first CERTIFICATE block from PEM.
fn extract_cert_b64(pem: &[u8]) -> String {
    let pem_str = String::from_utf8_lossy(pem);
    let mut in_cert = false;
    let mut b64 = String::new();
    for line in pem_str.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            continue;
        }
        if line.contains("END CERTIFICATE") {
            break;
        }
        if in_cert {
            b64.push_str(line.trim());
        }
    }
    b64
}
