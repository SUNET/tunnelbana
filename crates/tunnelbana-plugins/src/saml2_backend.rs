//! SAML2 backend — the proxy acts as a SAML Service Provider (SP) to an upstream
//! SAML Identity Provider. Wraps the `gamlastan` core: create AuthnRequest, send
//! via HTTP-Redirect, then at the ACS verify the signature, validate the Response
//! (32-check `AssertionValidator` via `process_response`) and map attributes.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use serde::Deserialize;

use gamlastan::core::assertion::attribute::AttributeValue;
use gamlastan::core::constants;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner, SamlVerifier};
use gamlastan::metadata::EntityDescriptor;
use gamlastan::profiles::sso::sp as sp_profile;
use gamlastan::profiles::sso::web_browser::{self, AuthnRequestOptions};
use gamlastan::security::config::SecurityConfig;
use gamlastan::security::validation::{AssertionValidator, ValidationParams};
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan_mdq::{MdqClient, MdqTransform, RequiredRole};

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
    /// Upstream IdP entity id; the target entity (and expected issuer). In MDQ
    /// mode this selects which entity's metadata to resolve.
    idp_entity_id: String,
    /// Upstream IdP SSO endpoint (where AuthnRequests are sent). Required in
    /// static mode; in MDQ mode it is resolved from metadata, so leave it unset.
    #[serde(default)]
    idp_sso_url: Option<String>,
    /// Upstream IdP signing certificate (PEM) — verifies the Response. Required
    /// in static mode; in MDQ mode the signing cert comes from metadata.
    #[serde(default)]
    idp_cert_path: Option<String>,
    /// When present, resolve the IdP's SSO endpoint and signing cert on demand
    /// from an MDQ server instead of the static `idp_sso_url` / `idp_cert_path`.
    #[serde(default)]
    mdq: Option<MdqConfig>,
    #[serde(default)]
    sign_authn_requests: bool,
    #[serde(default)]
    name_id_format: Option<String>,
    /// Use "strict" or "permissive" security validation (default permissive).
    #[serde(default)]
    security: Option<String>,
}

/// `[backend.config.mdq]` — SAML Metadata Query Protocol source for IdP metadata.
#[derive(Debug, Deserialize)]
struct MdqConfig {
    /// MDQ server base URL (a trailing slash is added if missing).
    url: String,
    /// PEM cert that signs the MDQ entity statements. Required unless
    /// `allow_unverified` is set.
    #[serde(default)]
    signing_cert_path: Option<String>,
    /// entityID → request-path transform: `"url_encoded"` (default) or `"sha1"`.
    #[serde(default)]
    transform: Option<String>,
    /// Role the fetched metadata must carry: `"idp"` (default), `"sp"`, `"any"`.
    #[serde(default)]
    require_role: Option<String>,
    /// Cache TTL (seconds) when the document omits `validUntil`/`cacheDuration`.
    #[serde(default)]
    fallback_ttl_secs: Option<u64>,
    /// Accept metadata that cannot be signature-verified (no cert). Insecure;
    /// testing only.
    #[serde(default)]
    allow_unverified: bool,
}

/// Where the upstream IdP's SSO endpoint and signing cert come from.
enum IdpMetadata {
    /// Pinned at build time from `idp_sso_url` + `idp_cert_path`.
    Static {
        sso_url: String,
        verifier: SamlVerifier,
    },
    /// Resolved per request from an MDQ server, keyed by `idp_entity_id`.
    Mdq(MdqClient),
}

pub struct Saml2Backend {
    name: String,
    sp_entity_id: String,
    acs_url: String,
    idp_entity_id: String,
    idp_metadata: IdpMetadata,
    signer: SamlSigner,
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
        let sp_entity_id = cfg
            .sp_entity_id
            .clone()
            .unwrap_or_else(|| module_base.clone());
        let acs_url = format!("{module_base}/acs");

        let sp_key = std::fs::read(&cfg.sp_key_path)
            .map_err(|e| Error::Config(format!("reading sp_key_path: {e}")))?;

        // Signer keys manager: the SP private key (for signing AuthnRequests).
        let mut sp_signing_key = loader::load_pem_auto(&sp_key, None)
            .map_err(|e| Error::Crypto(format!("loading sp key: {e}")))?;
        sp_signing_key.usage = KeyUsage::Sign;
        let mut signer_km = KeysManager::new();
        signer_km.add_key(sp_signing_key);
        let signer = SamlSigner::new(signer_km);

        // IdP metadata source: MDQ (dynamic, per-entity) when an [mdq] section
        // is present, else the static idp_sso_url + idp_cert_path pair.
        let idp_metadata = match &cfg.mdq {
            Some(mdq_cfg) => IdpMetadata::Mdq(build_mdq_client(mdq_cfg)?),
            None => {
                let sso_url = cfg.idp_sso_url.clone().ok_or_else(|| {
                    Error::Config("saml2 backend requires idp_sso_url (or an [mdq] section)".into())
                })?;
                let cert_path = cfg.idp_cert_path.as_ref().ok_or_else(|| {
                    Error::Config(
                        "saml2 backend requires idp_cert_path (or an [mdq] section)".into(),
                    )
                })?;
                let idp_cert = std::fs::read(cert_path)
                    .map_err(|e| Error::Config(format!("reading idp_cert_path: {e}")))?;
                let idp_cert_der = base64::engine::general_purpose::STANDARD
                    .decode(extract_cert_b64(&idp_cert))
                    .map_err(|e| Error::Crypto(format!("decoding idp cert: {e}")))?;
                let verifier = verifier_from_cert_ders(&[idp_cert_der])?;
                IdpMetadata::Static { sso_url, verifier }
            }
        };

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
            idp_metadata,
            signer,
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

    fn is_dynamic_idp_selection(&self) -> bool {
        matches!(&self.idp_metadata, IdpMetadata::Mdq(_))
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

    /// The target IdP for this flow: an `entityID` supplied on the request (e.g.
    /// a discovery-service return), else the configured default `idp_entity_id`.
    fn select_target_idp(&self, ctx: &Context) -> String {
        ctx.request
            .param("entityID")
            .map(str::to_string)
            .unwrap_or_else(|| self.idp_entity_id.clone())
    }

    /// Dispatch the ACS: resolve the verifier (static cert, or the IdP's signing
    /// cert fetched from MDQ for the IdP this flow was sent to), then process the
    /// Response against it.
    async fn handle_acs(&self, ctx: &mut Context) -> Result<BackendAction> {
        match &self.idp_metadata {
            IdpMetadata::Static { verifier, .. } => {
                self.process_acs(ctx, verifier, &self.idp_entity_id)
            }
            IdpMetadata::Mdq(client) => {
                // Verify against the cert for the IdP we actually sent the request
                // to (persisted at start_auth) — not the still-unverified issuer
                // claimed by the Response. Falls back to the configured default.
                let selected = ctx
                    .state
                    .get_str(&self.name, "idp_entity_id")
                    .unwrap_or_else(|| self.idp_entity_id.clone());
                let entity = client
                    .get(&selected)
                    .await
                    .map_err(|e| Error::Authn(format!("MDQ lookup for {selected} failed: {e}")))?;
                let verifier = idp_verifier_from_metadata(&entity)?;
                self.process_acs(ctx, &verifier, &selected)
            }
        }
    }

    fn process_acs(
        &self,
        ctx: &mut Context,
        verifier: &SamlVerifier,
        expected_idp_entity_id: &str,
    ) -> Result<BackendAction> {
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
        let verify_result = verifier
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
            expected_idp_entity_id,
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
        let (name_id, name_id_format) =
            match assertion.subject.as_ref().and_then(|s| s.name_id.as_ref()) {
                Some(gamlastan::core::assertion::name_id::NameIdOrEncryptedId::NameId(nid)) => {
                    (nid.value.clone(), nid.format.clone())
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
        let subject_type = subject_type_from_name_id_format(name_id_format.as_deref());
        let subject_id = select_subject_id(
            self.mapper.as_ref(),
            &internal_attrs,
            &name_id,
            subject_type,
            &idp_entity_id,
            self.is_dynamic_idp_selection(),
        );

        ctx.state.clear_namespace(&self.name);

        let response = InternalData {
            auth_info: AuthenticationInformation {
                auth_class_ref: authn_class_ref,
                timestamp: Some(now_rfc3339()),
                issuer: Some(idp_entity_id),
            },
            requester: None,
            requester_name: Vec::new(),
            subject_id: Some(subject_id),
            subject_type,
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
            Route::new(
                &regex::escape(&format!("{}/metadata", self.name)),
                "metadata",
            ),
        ]
    }

    async fn start_auth(&self, ctx: &mut Context, _request: InternalData) -> Result<Response> {
        // SSO endpoint: static URL, or resolved from MDQ for the target IdP.
        // In MDQ mode the target IdP can be chosen per request — e.g. an
        // `entityID` handed back by a discovery service (SeamlessAccess/thiss.io)
        // — falling back to the configured default. We persist the choice so the
        // ACS verifies the Response against the same IdP's metadata.
        let sso_url = match &self.idp_metadata {
            IdpMetadata::Static { sso_url, .. } => sso_url.clone(),
            IdpMetadata::Mdq(client) => {
                let target = self.select_target_idp(ctx);
                let entity = client
                    .get(&target)
                    .await
                    .map_err(|e| Error::Authn(format!("MDQ lookup for {target} failed: {e}")))?;
                let url = idp_sso_redirect_url(&entity)?;
                ctx.state.set_str(&self.name, "idp_entity_id", &target);
                url
            }
        };

        let options = AuthnRequestOptions {
            sp_entity_id: self.sp_entity_id.clone(),
            acs_url: Some(self.acs_url.clone()),
            destination: Some(sso_url.clone()),
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
            destination: &sso_url,
            relay_state: None,
            signer,
        };
        let url = gamlastan::bindings::redirect::redirect_encode(&params)
            .map_err(|e| Error::Internal(format!("redirect encode: {e}")))?;
        Ok(Response::redirect(url))
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<BackendAction> {
        match route_id {
            "acs" => self.handle_acs(ctx).await,
            "metadata" => Ok(BackendAction::Respond(
                Response::new(200)
                    .with_header(
                        "content-type",
                        "application/samlmetadata+xml; charset=utf-8",
                    )
                    .with_body(self.build_metadata()?.into_bytes()),
            )),
            other => Err(Error::NoBoundEndpoint(other.to_string())),
        }
    }
}

fn subject_type_from_name_id_format(name_id_format: Option<&str>) -> SubjectType {
    match name_id_format {
        Some(constants::NAMEID_TRANSIENT) => SubjectType::Transient,
        _ => SubjectType::Persistent,
    }
}

fn select_subject_id(
    mapper: &AttributeMapper,
    internal_attrs: &BTreeMap<String, Vec<String>>,
    raw_name_id: &str,
    subject_type: SubjectType,
    issuer: &str,
    dynamic_idp_selection: bool,
) -> String {
    if dynamic_idp_selection {
        if let Some(subject_id) = mapper.compose_subject_id(internal_attrs) {
            return subject_id;
        }
        if subject_type == SubjectType::Persistent {
            return scope_subject_id(issuer, raw_name_id);
        }
    }
    raw_name_id.to_string()
}

// In federation mode, a raw persistent NameID is only stable within the IdP
// that issued it, so scope it by issuer before treating it as the downstream
// subject identifier.
fn scope_subject_id(issuer: &str, subject_id: &str) -> String {
    format!("{}:{issuer}:{subject_id}", issuer.len())
}

/// Build an MDQ client from the `[mdq]` config block.
fn build_mdq_client(cfg: &MdqConfig) -> Result<MdqClient> {
    let transform = match cfg.transform.as_deref() {
        None | Some("url_encoded") => MdqTransform::UrlEncoded,
        Some("sha1") => MdqTransform::Sha1,
        Some(other) => return Err(Error::Config(format!("unknown mdq.transform: {other}"))),
    };
    let role = match cfg.require_role.as_deref() {
        None | Some("idp") => RequiredRole::Idp,
        Some("sp") => RequiredRole::Sp,
        Some("any") => RequiredRole::Any,
        Some(other) => return Err(Error::Config(format!("unknown mdq.require_role: {other}"))),
    };

    let mut client = MdqClient::new(cfg.url.clone())
        .with_transform(transform)
        .require_role(role);
    if let Some(ttl) = cfg.fallback_ttl_secs {
        client = client.with_fallback_ttl(Duration::from_secs(ttl));
    }

    // A signing cert makes every fetched document signature-checked; without one
    // the operator must explicitly opt into the insecure unverified mode.
    if let Some(path) = &cfg.signing_cert_path {
        let pem = std::fs::read(path)
            .map_err(|e| Error::Config(format!("reading mdq.signing_cert_path: {e}")))?;
        client = client
            .add_signing_cert_pem(&pem)
            .map_err(|e| Error::Crypto(format!("loading mdq signing cert: {e}")))?;
    } else if cfg.allow_unverified {
        client = client.allow_unverified();
    } else {
        return Err(Error::Config(
            "mdq requires signing_cert_path (or allow_unverified=true for testing)".into(),
        ));
    }
    Ok(client)
}

/// Build an SP-side verifier from a set of DER-encoded IdP signing certs: each
/// cert is both a verification key and a trusted chain anchor (mirrors the
/// static `idp_cert_path` path). Errors if no certs are supplied.
fn verifier_from_cert_ders(ders: &[Vec<u8>]) -> Result<SamlVerifier> {
    if ders.is_empty() {
        return Err(Error::Authn(
            "IdP metadata carries no signing certificate".into(),
        ));
    }
    let mut km = KeysManager::new();
    for der in ders {
        let key = loader::load_x509_cert_der(der)
            .map_err(|e| Error::Crypto(format!("parsing IdP signing cert: {e}")))?;
        km.add_key(key);
        km.add_trusted_cert(der.clone());
    }
    Ok(SamlVerifier::new(km))
}

/// The IdP's HTTP-Redirect `SingleSignOnService` location from its metadata.
fn idp_sso_redirect_url(entity: &EntityDescriptor) -> Result<String> {
    let idp = entity.idp_sso_descriptors().first().ok_or_else(|| {
        Error::Authn(format!(
            "metadata for {} has no IDPSSODescriptor",
            entity.entity_id
        ))
    })?;
    idp.single_sign_on_service(constants::BINDING_HTTP_REDIRECT)
        .map(|e| e.location.clone())
        .ok_or_else(|| {
            Error::Authn(format!(
                "IdP {} advertises no HTTP-Redirect SingleSignOnService",
                entity.entity_id
            ))
        })
}

/// Build a verifier from the IdP's signing certs published in its metadata.
fn idp_verifier_from_metadata(entity: &EntityDescriptor) -> Result<SamlVerifier> {
    let idp = entity.idp_sso_descriptors().first().ok_or_else(|| {
        Error::Authn(format!(
            "metadata for {} has no IDPSSODescriptor",
            entity.entity_id
        ))
    })?;
    verifier_from_cert_ders(&idp.signing_certificates_der())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_mapper() -> AttributeMapper {
        AttributeMapper::from_toml("").expect("empty mapper")
    }

    #[test]
    fn subject_type_tracks_name_id_format() {
        assert_eq!(
            subject_type_from_name_id_format(Some(constants::NAMEID_TRANSIENT)),
            SubjectType::Transient
        );
        assert_eq!(
            subject_type_from_name_id_format(Some(constants::NAMEID_PERSISTENT)),
            SubjectType::Persistent
        );
        assert_eq!(
            subject_type_from_name_id_format(Some(constants::NAMEID_EMAIL)),
            SubjectType::Persistent
        );
        assert_eq!(
            subject_type_from_name_id_format(None),
            SubjectType::Persistent
        );
    }

    #[test]
    fn dynamic_idp_subject_prefers_composed_identifier() {
        let mapper = AttributeMapper::from_toml(
            r#"
            user_id_from_attrs = ["mail"]

            [attributes.mail]
            saml = ["mail"]
        "#,
        )
        .expect("mapper with mail subject");
        let mut attrs = BTreeMap::new();
        attrs.insert("mail".to_string(), vec!["anna@example.com".to_string()]);

        let subject_id = select_subject_id(
            &mapper,
            &attrs,
            "opaque-name-id",
            SubjectType::Persistent,
            "https://idp.example.com",
            true,
        );

        assert_eq!(subject_id, "anna@example.com");
    }

    #[test]
    fn dynamic_idp_scopes_persistent_nameid_fallback() {
        let subject_id = select_subject_id(
            &empty_mapper(),
            &BTreeMap::new(),
            "opaque-name-id",
            SubjectType::Persistent,
            "https://idp.example.com",
            true,
        );

        assert_eq!(
            subject_id,
            scope_subject_id("https://idp.example.com", "opaque-name-id")
        );
    }

    #[test]
    fn static_idp_keeps_raw_nameid() {
        let subject_id = select_subject_id(
            &empty_mapper(),
            &BTreeMap::new(),
            "opaque-name-id",
            SubjectType::Persistent,
            "https://idp.example.com",
            false,
        );

        assert_eq!(subject_id, "opaque-name-id");
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
