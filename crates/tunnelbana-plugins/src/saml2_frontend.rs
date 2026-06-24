//! SAML2 frontend — the proxy acts as a SAML Identity Provider (IdP) to
//! downstream Service Providers. Wraps the `gamlastan` core: parse the inbound
//! AuthnRequest, validate the requester and its ACS against registered SP
//! metadata, and (after the backend authenticates the user) build, sign and
//! POST back a SAML Response.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use chrono::{TimeDelta, Utc};
use serde::Deserialize;

use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
use gamlastan::core::assertion::name_id::NameId;
use gamlastan::core::constants;
use gamlastan::core::identifiers::SamlId;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};
use gamlastan::metadata::types::entity_descriptor::{
    EntitiesDescriptorRef, EntityDescriptor, EntityDescriptorRef,
};
use gamlastan::metadata::types::sp::SpSsoDescriptor;
use gamlastan::profiles::sso::idp as idp_profile;
use gamlastan::profiles::sso::web_browser::ResponseOptions;
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan_mdq::{MdqClient, MdqError};

use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, Frontend, FrontendAction, Route};

use crate::saml_common::{build_mdq_client, extract_cert_b64, verifier_from_cert_ders, MdqConfig};

#[derive(Debug, Deserialize)]
struct Saml2FrontendConfig {
    #[serde(default)]
    idp_entity_id: Option<String>,
    idp_key_path: String,
    idp_cert_path: String,
    #[serde(default = "default_assertion_lifetime")]
    assertion_lifetime_seconds: u64,
    #[serde(default = "default_true")]
    sign_assertions: bool,
    /// Sign the Response envelope too. Off by default: signing the assertion
    /// alone is the common interoperable pattern, and an SP that verifies the
    /// (single) assertion signature is satisfied by it.
    #[serde(default)]
    sign_responses: bool,
    /// Single NameID format (alias for a one-element `name_id_formats`).
    #[serde(default)]
    name_id_format: Option<String>,
    /// Supported NameID formats, in preference order. The first is the
    /// default when the SP states no NameIDPolicy; a requested format outside
    /// this list is answered with an InvalidNameIDPolicy SAML error.
    #[serde(default)]
    name_id_formats: Option<Vec<String>>,
    #[serde(default)]
    authn_context_class_ref: Option<String>,
    /// `"basic"` (default) emits attributes under their plain SAML names;
    /// `"uri"` emits OID-named attributes (`Name="urn:oid:…"`,
    /// `NameFormat=…:attrname-format:uri`, plus `FriendlyName`) as SWAMID SPs
    /// expect. OIDs/friendly names come from the attribute map profile.
    #[serde(default)]
    attribute_name_format: Option<String>,
    /// Registered SP metadata: local files and/or an MDQ source. Required —
    /// without it the frontend would deliver assertions to whatever ACS URL an
    /// unauthenticated AuthnRequest names (see `allow_unknown_sps`).
    #[serde(default)]
    metadata: Option<SpMetadataConfig>,
    /// Require every AuthnRequest to carry a valid signature, even when the
    /// SP's metadata does not state `AuthnRequestsSigned="true"`.
    #[serde(default)]
    want_authn_requests_signed: bool,
    /// Dev-only escape hatch: accept AuthnRequests from unregistered SPs and
    /// trust the ACS URL in the request. Insecure; testing only.
    #[serde(default)]
    allow_unknown_sps: bool,
    /// `[frontend.config.organization]` — published in IdP metadata.
    #[serde(default)]
    organization: Option<crate::saml_metadata::OrganizationConfig>,
    /// `[[frontend.config.contact_person]]` — published in IdP metadata.
    #[serde(default)]
    contact_person: Vec<crate::saml_metadata::ContactPersonConfig>,
    /// Per-SP attribute release policy keyed by SP entity id, with a
    /// `"default"` entry for everyone else (cf. pysaml2's
    /// `policy.default.attribute_restrictions`). An SP-specific entry
    /// replaces the default (no merge). Attribute names are *internal* names.
    #[serde(default)]
    policy: BTreeMap<String, SpPolicy>,
    /// Pin every flow from this frontend to a named backend. Overrides
    /// `custom_routing` and the default backend.
    #[serde(default)]
    backend: Option<String>,
}

/// `[frontend.config.policy."<sp-entity-id-or-default>"]`.
#[derive(Debug, Clone, Deserialize)]
struct SpPolicy {
    /// Internal attribute names this SP may receive; absent = release all.
    #[serde(default)]
    attribute_restrictions: Option<Vec<String>>,
}

/// `[frontend.config.metadata]` — where registered SP metadata comes from.
#[derive(Debug, Deserialize)]
struct SpMetadataConfig {
    /// Metadata files, each an `EntityDescriptor` or `EntitiesDescriptor`.
    #[serde(default)]
    local: Vec<String>,
    /// Optional MDQ source for per-request SP lookup. The role requirement is
    /// forced to `"sp"`.
    #[serde(default)]
    mdq: Option<MdqConfig>,
}

fn default_assertion_lifetime() -> u64 {
    300
}
fn default_true() -> bool {
    true
}

/// A registered SP: its parsed descriptor plus the certs pulled out of it.
#[derive(Clone)]
struct SpEntry {
    sp_sso: SpSsoDescriptor,
    signing_certs_der: Vec<Vec<u8>>,
    /// Kept for the future IdP-side assertion-encryption feature (F6).
    #[allow(dead_code)]
    encryption_certs_der: Vec<Vec<u8>>,
}

/// Where registered SPs are looked up.
#[allow(clippy::large_enum_variant)] // two-variant config enum, built once
enum SpStore {
    /// Legacy open mode (`allow_unknown_sps = true`): any issuer is accepted
    /// and the ACS URL is taken from the request. Insecure; testing only.
    AllowAll,
    /// entityID → SP entry from local metadata files, with an optional MDQ
    /// fallback for entities not present locally.
    Store {
        local: BTreeMap<String, SpEntry>,
        mdq: Option<MdqClient>,
    },
}

impl SpStore {
    /// Resolve a registered SP. `Ok(None)` means "unknown SP" (reject);
    /// only `AllowAll` short-circuits that policy, handled by the caller.
    async fn resolve(&self, entity_id: &str) -> Result<Option<SpEntry>> {
        match self {
            SpStore::AllowAll => Ok(None),
            SpStore::Store { local, mdq } => {
                if let Some(entry) = local.get(entity_id) {
                    return Ok(Some(entry.clone()));
                }
                let Some(client) = mdq else {
                    return Ok(None);
                };
                match client.get(entity_id).await {
                    Ok(entity) => Ok(sp_entry_from_entity(&entity)),
                    Err(MdqError::EntityNotFound(_)) => Ok(None),
                    Err(e) => Err(Error::Authn(format!(
                        "MDQ lookup for {entity_id} failed: {e}"
                    ))),
                }
            }
        }
    }
}

/// Build an [`SpEntry`] from an entity's first SPSSODescriptor, if it has one.
fn sp_entry_from_entity(entity: &EntityDescriptor) -> Option<SpEntry> {
    let sp_sso = entity.sp_sso_descriptors().first()?;
    Some(SpEntry {
        sp_sso: sp_sso.clone(),
        signing_certs_der: sp_sso.signing_certificates_der(),
        encryption_certs_der: sp_sso.encryption_certificates_der(),
    })
}

/// Load and index SP metadata files (`EntityDescriptor` or
/// `EntitiesDescriptor` roots).
fn load_local_metadata(paths: &[String]) -> Result<BTreeMap<String, SpEntry>> {
    let mut store = BTreeMap::new();
    for path in paths {
        let xml = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("reading metadata file {path}: {e}")))?;
        let doc = gamlastan::xml::uppsala::parse(&xml)
            .map_err(|e| Error::Config(format!("metadata file {path}: invalid XML: {e}")))?;

        // Root dispatch: a federation aggregate (EntitiesDescriptor) or a
        // single EntityDescriptor.
        let entities: Vec<EntityDescriptor> = if let Ok(parsed) =
            gamlastan::xml::deserialize::parse_saml::<EntitiesDescriptorRef<'_>>(&doc)
        {
            parsed
                .to_owned()
                .entity_descriptors()
                .into_iter()
                .cloned()
                .collect()
        } else {
            let entity = gamlastan::xml::deserialize::parse_saml::<EntityDescriptorRef<'_>>(&doc)
                .map_err(|e| {
                Error::Config(format!(
                    "metadata file {path}: neither EntitiesDescriptor nor \
                             EntityDescriptor: {e}"
                ))
            })?;
            vec![entity.to_owned()]
        };

        for entity in entities {
            match sp_entry_from_entity(&entity) {
                Some(entry) => {
                    store.insert(entity.entity_id.clone(), entry);
                }
                None => tracing::warn!(
                    "metadata file {path}: entity {} has no SPSSODescriptor; skipped",
                    entity.entity_id
                ),
            }
        }
    }
    Ok(store)
}

/// `gamlastan::bindings::traits::HttpRequest` adapter exposing the **raw**
/// (still percent-encoded) query values from `HttpRequestData.uri`.
/// `HttpRequestData.query` is already decoded, which would corrupt the
/// redirect-binding signature input.
struct RawQueryRequest<'a> {
    request: &'a HttpRequestData,
    raw_query: Option<&'a str>,
}

impl<'a> RawQueryRequest<'a> {
    fn new(request: &'a HttpRequestData) -> Self {
        let raw_query = request.uri.split_once('?').map(|(_, q)| q);
        Self { request, raw_query }
    }
}

impl gamlastan::bindings::traits::HttpRequest for RawQueryRequest<'_> {
    fn method(&self) -> &str {
        &self.request.method
    }
    fn url(&self) -> &str {
        &self.request.uri
    }
    fn query_param(&self, name: &str) -> Option<&str> {
        let qs = self.raw_query?;
        qs.split('&')
            .find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
    }
    fn form_param(&self, name: &str) -> Option<&str> {
        self.request.form.get(name).map(|s| s.as_str())
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.request
            .headers
            .get(&name.to_lowercase())
            .map(|s| s.as_str())
    }
    fn body(&self) -> &[u8] {
        &self.request.body
    }
    fn remote_addr(&self) -> Option<&str> {
        None
    }
}

pub struct Saml2Frontend {
    name: String,
    idp_entity_id: String,
    sso_url: String,
    signer: SamlSigner,
    cert_b64: String,
    assertion_lifetime_seconds: u64,
    sign_assertions: bool,
    sign_responses: bool,
    name_id_formats: Vec<String>,
    attribute_name_format_uri: bool,
    default_acr: Option<String>,
    sp_store: SpStore,
    want_authn_requests_signed: bool,
    organization: Option<gamlastan::metadata::types::organization::Organization>,
    contact_persons: Vec<gamlastan::metadata::types::contact::ContactPerson>,
    policy: BTreeMap<String, SpPolicy>,
    mapper: Arc<AttributeMapper>,
    /// Backend name every flow is pinned to, if configured.
    backend: Option<String>,
}

impl Saml2Frontend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Frontend>> {
        let cfg: Saml2FrontendConfig = bx.parse_config()?;
        let module_base = bx.module_base();
        let idp_entity_id = cfg
            .idp_entity_id
            .clone()
            .unwrap_or_else(|| module_base.clone());
        let sso_url = format!("{module_base}/sso");

        let key_pem = std::fs::read(&cfg.idp_key_path)
            .map_err(|e| Error::Config(format!("reading idp_key_path: {e}")))?;
        let cert_pem = std::fs::read(&cfg.idp_cert_path)
            .map_err(|e| Error::Config(format!("reading idp_cert_path: {e}")))?;
        let cert_b64 = extract_cert_b64(&cert_pem);
        let cert_der = base64::engine::general_purpose::STANDARD
            .decode(&cert_b64)
            .map_err(|e| Error::Config(format!("decoding idp cert: {e}")))?;

        let mut signing_key = gamlastan::crypto::keys::loader::load_pem_auto(&key_pem, None)
            .map_err(|e| Error::Crypto(format!("loading idp key: {e}")))?;
        signing_key.usage = KeyUsage::Sign;
        signing_key.x509_chain = vec![cert_der];

        let mut km = KeysManager::new();
        km.add_key(signing_key);
        let signer = SamlSigner::new(km);

        let name_id_formats = match (&cfg.name_id_format, &cfg.name_id_formats) {
            (Some(_), Some(_)) => {
                return Err(Error::Config(
                    "set either name_id_format or name_id_formats, not both".into(),
                ))
            }
            (Some(single), None) => vec![single.clone()],
            (None, Some(list)) if !list.is_empty() => list.clone(),
            (None, Some(_)) => {
                return Err(Error::Config("name_id_formats must not be empty".into()))
            }
            (None, None) => vec![constants::NAMEID_PERSISTENT.to_string()],
        };

        let attribute_name_format_uri = match cfg.attribute_name_format.as_deref() {
            None | Some("basic") => false,
            Some("uri") => true,
            Some(other) => {
                return Err(Error::Config(format!(
                    "unknown attribute_name_format: {other} (expected \"basic\" or \"uri\")"
                )))
            }
        };

        let sp_store = match (&cfg.metadata, cfg.allow_unknown_sps) {
            (Some(md), _) => {
                let local = load_local_metadata(&md.local)?;
                let mdq = match &md.mdq {
                    Some(mdq_cfg) => {
                        // SP lookups must resolve SP metadata; reject configs
                        // that ask for another role.
                        if !matches!(mdq_cfg.require_role.as_deref(), None | Some("sp")) {
                            return Err(Error::Config(
                                "saml2 frontend [metadata.mdq] require_role must be \"sp\"".into(),
                            ));
                        }
                        let mdq_cfg_sp = MdqConfig {
                            url: mdq_cfg.url.clone(),
                            signing_cert_path: mdq_cfg.signing_cert_path.clone(),
                            transform: mdq_cfg.transform.clone(),
                            require_role: Some("sp".to_string()),
                            fallback_ttl_secs: mdq_cfg.fallback_ttl_secs,
                            allow_unverified: mdq_cfg.allow_unverified,
                        };
                        Some(build_mdq_client(&mdq_cfg_sp)?)
                    }
                    None => None,
                };
                if local.is_empty() && mdq.is_none() {
                    return Err(Error::Config(
                        "saml2 frontend [metadata] must list local files and/or an \
                         [metadata.mdq] source"
                            .into(),
                    ));
                }
                SpStore::Store { local, mdq }
            }
            (None, true) => {
                tracing::warn!(
                    "saml2 frontend {}: allow_unknown_sps=true — accepting AuthnRequests \
                     from unregistered SPs and trusting the ACS URL in the request. \
                     Do not run this in production.",
                    bx.name
                );
                SpStore::AllowAll
            }
            (None, false) => {
                return Err(Error::Config(
                    "saml2 frontend requires [frontend.config.metadata] (registered SP \
                     metadata); set allow_unknown_sps=true to explicitly run open \
                     (insecure, testing only)"
                        .into(),
                ));
            }
        };

        Ok(Box::new(Saml2Frontend {
            name: bx.name.clone(),
            idp_entity_id,
            sso_url,
            signer,
            cert_b64,
            assertion_lifetime_seconds: cfg.assertion_lifetime_seconds,
            sign_assertions: cfg.sign_assertions,
            sign_responses: cfg.sign_responses,
            name_id_formats,
            attribute_name_format_uri,
            default_acr: cfg.authn_context_class_ref,
            sp_store,
            want_authn_requests_signed: cfg.want_authn_requests_signed,
            organization: cfg.organization.as_ref().map(|o| o.to_organization()),
            contact_persons: crate::saml_metadata::contact_persons(&cfg.contact_person)?,
            policy: cfg.policy,
            mapper: bx.attribute_mapper.clone(),
            backend: cfg.backend,
        }))
    }

    async fn handle_sso(&self, ctx: &mut Context) -> Result<FrontendAction> {
        // AuthnRequest via HTTP-Redirect (GET, deflated, optionally
        // query-signed) or HTTP-POST (form, optionally enveloped-signed).
        let (xml, relay_state, redirect_decoded) = if ctx.request.query.contains_key("SAMLRequest")
        {
            let raw = RawQueryRequest::new(&ctx.request);
            let decoded = gamlastan::bindings::redirect::redirect_decode(&raw)
                .map_err(|e| Error::BadRequest(format!("redirect decode: {e}")))?;
            let xml = String::from_utf8(decoded.saml_xml.clone())
                .map_err(|e| Error::BadRequest(format!("SAMLRequest not UTF-8: {e}")))?;
            let relay = decoded.relay_state.clone();
            (xml, relay, Some(decoded))
        } else if let Some(v) = ctx.request.form.get("SAMLRequest") {
            let xml = decode_authn_request(v, false)?;
            (xml, ctx.request.form.get("RelayState").cloned(), None)
        } else {
            return Err(Error::BadRequest("missing SAMLRequest".into()));
        };

        let doc = gamlastan::xml::uppsala::parse(&xml)
            .map_err(|e| Error::BadRequest(format!("invalid AuthnRequest XML: {e}")))?;
        let authn_request = gamlastan::xml::deserialize::parse_saml::<
            gamlastan::core::protocol::request::AuthnRequestRef<'_>,
        >(&doc)
        .map_err(|e| Error::BadRequest(format!("parsing AuthnRequest: {e}")))?
        .to_owned();

        let sp_entity_id = authn_request
            .base
            .issuer
            .as_ref()
            .map(|i| i.value.clone())
            .ok_or_else(|| Error::BadRequest("AuthnRequest carries no Issuer".into()))?;

        // Resolve the requester against registered SP metadata. Unknown SP ⇒
        // 403 — without metadata we must not trust the request's ACS URL.
        let entry = match &self.sp_store {
            SpStore::AllowAll => None,
            store => match store.resolve(&sp_entity_id).await? {
                Some(entry) => Some(entry),
                None => {
                    tracing::warn!("saml2 frontend {}: unknown SP {sp_entity_id}", self.name);
                    return Ok(FrontendAction::Respond(Response::text(
                        403,
                        format!("unknown SP: {sp_entity_id}"),
                    )));
                }
            },
        };

        // Signature policy: required when the SP's metadata says
        // AuthnRequestsSigned="true" or the frontend is configured to insist.
        if let Some(entry) = &entry {
            let must_sign =
                entry.sp_sso.authn_requests_signed == Some(true) || self.want_authn_requests_signed;
            if must_sign {
                if let Err(reason) =
                    verify_authn_request_signature(entry, &redirect_decoded, &authn_request, &xml)
                {
                    tracing::warn!(
                        "saml2 frontend {}: rejecting AuthnRequest from {sp_entity_id}: {reason}",
                        self.name
                    );
                    return Ok(FrontendAction::Respond(Response::text(403, reason)));
                }
            }
        }

        // With SP metadata present this validates/resolves the ACS endpoint
        // against the registered AssertionConsumerServices.
        let processed =
            idp_profile::process_authn_request(&authn_request, entry.as_ref().map(|e| &e.sp_sso))
                .map_err(|e| Error::BadRequest(format!("AuthnRequest validation: {e}")))?;

        // Honor the NameIDPolicy: no (or unspecified) requested format gets
        // the first configured one; a format outside the configured list is
        // answered with an InvalidNameIDPolicy SAML error at the (validated)
        // ACS rather than an HTTP error, per Profiles 4.1.4.2.
        let name_id_format = match processed.requested_name_id_format.as_deref() {
            None | Some(constants::NAMEID_UNSPECIFIED) => self.name_id_formats[0].clone(),
            Some(format) if self.name_id_formats.iter().any(|f| f == format) => format.to_string(),
            Some(format) => {
                tracing::warn!(
                    "saml2 frontend {}: SP {} requested unsupported NameID format {format}",
                    self.name,
                    processed.sp_entity_id
                );
                return self.saml_error_response(
                    &processed,
                    relay_state.as_deref(),
                    gamlastan::core::protocol::status::Status::with_sub_status(
                        constants::STATUS_REQUESTER,
                        constants::STATUS_INVALID_NAMEID_POLICY,
                        Some(format!("unsupported NameID format: {format}")),
                    ),
                );
            }
        };

        // Stash what we need to build the Response on the way back.
        ctx.state
            .set_str(&self.name, "request_id", &processed.request_id);
        ctx.state
            .set_str(&self.name, "sp_entity_id", &processed.sp_entity_id);
        ctx.state.set_str(&self.name, "acs_url", &processed.acs_url);
        ctx.state
            .set_str(&self.name, "name_id_format", &name_id_format);
        // Also publish under the shared base namespace so a response-path
        // micro-service (e.g. `nameid`) can read the resolved format without
        // knowing this frontend's configured name.
        ctx.state.set_str(
            tunnelbana_core::context::STATE_KEY_BASE,
            tunnelbana_core::context::KEY_NAME_ID_FORMAT,
            &name_id_format,
        );
        if let Some(rs) = &relay_state {
            ctx.state.set_str(&self.name, "relay_state", rs);
        }

        // Surface the SP's RequestedAuthnContext for a request-path
        // micro-service (e.g. `accr`). A decoration, not state: this is a
        // single-leg frontend→backend handoff, mirroring `KEY_TARGET_ENTITYID`.
        if !processed.requested_authn_context_class_refs.is_empty() {
            ctx.decorate(
                tunnelbana_core::context::KEY_REQUESTED_ACCR,
                serde_json::Value::Array(
                    processed
                        .requested_authn_context_class_refs
                        .iter()
                        .cloned()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
            if let Some(cmp) = processed.authn_context_comparison {
                ctx.decorate(
                    tunnelbana_core::context::KEY_REQUESTED_ACCR_COMPARISON,
                    serde_json::Value::String(cmp.as_str().to_string()),
                );
            }
        }

        Ok(FrontendAction::StartAuth {
            request: InternalData::request(processed.sp_entity_id),
            target_backend: self.backend.clone(),
        })
    }

    /// POST an assertion-less SAML error Response to the request's
    /// (metadata-validated) ACS.
    fn saml_error_response(
        &self,
        processed: &idp_profile::ProcessedAuthnRequest,
        relay_state: Option<&str>,
        status: gamlastan::core::protocol::status::Status,
    ) -> Result<FrontendAction> {
        let response = idp_profile::create_error_response(
            &self.idp_entity_id,
            Some(&processed.request_id),
            &processed.acs_url,
            status,
            Utc::now(),
        );
        let xml = response
            .to_xml_string()
            .map_err(|e| Error::Internal(format!("serializing error Response: {e}")))?;
        let relay = relay_state.map(gamlastan::bindings::relay_state::RelayState::echo);
        let html = gamlastan::bindings::post::post_encode(
            xml.as_bytes(),
            false,
            &processed.acs_url,
            relay.as_ref(),
        );
        Ok(FrontendAction::Respond(
            Response::html(html).with_header("cache-control", "no-cache, no-store"),
        ))
    }
}

/// Check a required AuthnRequest signature for either binding. Returns the
/// rejection reason on failure.
fn verify_authn_request_signature(
    entry: &SpEntry,
    redirect_decoded: &Option<gamlastan::bindings::redirect::RedirectDecoded>,
    authn_request: &gamlastan::core::protocol::request::AuthnRequest,
    xml: &str,
) -> std::result::Result<(), String> {
    let verifier = verifier_from_cert_ders(&entry.signing_certs_der)
        .map_err(|e| format!("SP metadata carries no usable signing certificate: {e}"))?;
    match redirect_decoded {
        // HTTP-Redirect: the signature covers the raw query string.
        Some(decoded) => {
            if decoded.signature.is_none() {
                return Err("AuthnRequest must be signed (redirect binding)".into());
            }
            match gamlastan::bindings::redirect::redirect_verify_signature(decoded, &verifier) {
                Ok(true) => Ok(()),
                Ok(false) => Err("AuthnRequest redirect signature is not valid".into()),
                Err(e) => Err(format!("AuthnRequest redirect signature verification: {e}")),
            }
        }
        // HTTP-POST: enveloped XML signature on the AuthnRequest element.
        None => {
            if !authn_request.base.has_signature {
                return Err("AuthnRequest must be signed (POST binding)".into());
            }
            match verifier.verify_enveloped(xml) {
                Ok(gamlastan::crypto::VerifyResult::Valid { .. }) => Ok(()),
                Ok(gamlastan::crypto::VerifyResult::Invalid { reason }) => {
                    Err(format!("AuthnRequest signature is not valid: {reason}"))
                }
                Err(e) => Err(format!("AuthnRequest signature verification: {e}")),
            }
        }
    }
}

#[async_trait]
impl Frontend for Saml2Frontend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self, _backend_names: &[String]) -> Vec<Route> {
        let mut routes = vec![
            Route::exact(format!("{}/sso", self.name), "sso"),
            Route::exact(format!("{}/metadata", self.name), "metadata"),
        ];
        // SATOSA's `entityid_endpoint`: when the entity id is itself a URL
        // under this module, serve the metadata document there too (the
        // common `<base>/<name>/proxy.xml` convention).
        let module_base = self.sso_url.trim_end_matches("/sso");
        if let Some(rest) = self.idp_entity_id.strip_prefix(&format!("{module_base}/")) {
            if !rest.is_empty() && rest != "sso" && rest != "metadata" {
                routes.push(Route::exact(format!("{}/{rest}", self.name), "metadata"));
            }
        }
        routes
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<FrontendAction> {
        match route_id {
            "sso" => self.handle_sso(ctx).await,
            "metadata" => Ok(FrontendAction::Respond(
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

    async fn handle_authn_response(
        &self,
        ctx: &mut Context,
        mut response: InternalData,
    ) -> Result<Response> {
        let request_id = ctx
            .state
            .get_str(&self.name, "request_id")
            .ok_or_else(|| Error::State("no in-flight AuthnRequest".into()))?;
        let sp_entity_id = ctx
            .state
            .get_str(&self.name, "sp_entity_id")
            .ok_or_else(|| Error::State("no sp_entity_id in state".into()))?;
        let acs_url = ctx
            .state
            .get_str(&self.name, "acs_url")
            .ok_or_else(|| Error::State("no acs_url in state".into()))?;
        let relay_state = ctx.state.get_str(&self.name, "relay_state");

        // Per-SP attribute release policy (internal names): the SP-specific
        // entry wins over "default"; no entry (or no restrictions) releases
        // all. The global `filter_attributes` micro-service still applies on
        // top — this is the SAML-frontend-local, per-requester layer.
        let sp_policy = self
            .policy
            .get(&sp_entity_id)
            .or_else(|| self.policy.get("default"));
        if let Some(allowed) = sp_policy.and_then(|p| p.attribute_restrictions.as_ref()) {
            response
                .attributes
                .retain(|name, _| allowed.iter().any(|a| a == name));
        }

        // Map internal attributes to SAML attributes. In `uri` mode emit the
        // OID name + FriendlyName from the attribute map; in `basic` mode the
        // first plain SAML name (legacy behavior).
        let attributes: Vec<Attribute> = response
            .attributes
            .iter()
            .filter_map(|(internal_name, values)| {
                let mapping = self.mapper.profile_attribute("saml", internal_name)?;
                let basic_name = mapping.names.first()?;
                let (name, name_format, friendly_name) = if self.attribute_name_format_uri {
                    match &mapping.oid {
                        Some(oid) => (
                            oid.clone(),
                            constants::ATTRNAME_FORMAT_URI,
                            mapping
                                .friendly_name
                                .clone()
                                .or_else(|| Some(basic_name.clone())),
                        ),
                        None => {
                            tracing::warn!(
                                "saml2 frontend {}: attribute {internal_name} has no OID in \
                                 the attribute map; emitting basic name {basic_name}",
                                self.name
                            );
                            (basic_name.clone(), constants::ATTRNAME_FORMAT_BASIC, None)
                        }
                    }
                } else {
                    (basic_name.clone(), constants::ATTRNAME_FORMAT_BASIC, None)
                };
                Some(Attribute {
                    name,
                    name_format: Some(name_format.to_string()),
                    friendly_name,
                    values: values.iter().cloned().map(AttributeValue::String).collect(),
                })
            })
            .collect();

        // The format chosen while honoring the request's NameIDPolicy; the
        // fallback covers flows started before this state key existed.
        let name_id_format = ctx
            .state
            .get_str(&self.name, "name_id_format")
            .unwrap_or_else(|| self.name_id_formats[0].clone());

        // A transient NameID must be a fresh opaque value per response —
        // never the stable subject id.
        let name_id_value = if name_id_format == constants::NAMEID_TRANSIENT {
            SamlId::generate().to_string()
        } else {
            response
                .subject_id
                .clone()
                .or_else(|| self.mapper.compose_subject_id(&response.attributes))
                .ok_or_else(|| Error::Authn("no subject identifier for SAML assertion".into()))?
        };

        let name_id = NameId {
            value: name_id_value,
            format: Some(name_id_format),
            name_qualifier: None,
            sp_name_qualifier: Some(sp_entity_id.clone()),
            sp_provided_id: None,
        };

        let now = Utc::now();
        let options = ResponseOptions {
            idp_entity_id: self.idp_entity_id.clone(),
            in_response_to: Some(request_id),
            sp_entity_id,
            acs_url: acs_url.clone(),
            assertion_lifetime_seconds: self.assertion_lifetime_seconds,
            session_index: Some(SamlId::generate().to_string()),
            session_not_on_or_after: Some(now + TimeDelta::try_hours(8).unwrap()),
            authn_context_class_ref: response
                .auth_info
                .auth_class_ref
                .clone()
                .or_else(|| self.default_acr.clone())
                .or_else(|| Some(constants::AUTHN_CONTEXT_PASSWORD.to_string())),
            client_address: None,
            attributes,
        };

        let saml_response = idp_profile::create_response(&options, &name_id, now);
        let xml = saml_response
            .to_xml_string()
            .map_err(|e| Error::Internal(format!("serializing Response: {e}")))?;
        let assertion_id = saml_response.assertions.first().map(|a| a.id.clone());

        let signed =
            self.sign_response_xml(&xml, &saml_response.base.id, assertion_id.as_deref())?;

        let relay = relay_state
            .as_deref()
            .map(gamlastan::bindings::relay_state::RelayState::echo);
        let html = gamlastan::bindings::post::post_encode(
            signed.as_bytes(),
            false,
            &acs_url,
            relay.as_ref(),
        );

        ctx.state.clear_namespace(&self.name);
        Ok(Response::html(html).with_header("cache-control", "no-cache, no-store"))
    }

    async fn handle_backend_error(&self, _ctx: &mut Context, error: &Error) -> Result<Response> {
        Ok(Response::text(
            500,
            format!("authentication failed: {error}"),
        ))
    }
}

impl Saml2Frontend {
    /// Sign the Response XML (assertion first, then response) by inserting a
    /// ds:Signature template and calling the enveloped signer.
    fn sign_response_xml(
        &self,
        response_xml: &str,
        response_id: &str,
        assertion_id: Option<&str>,
    ) -> Result<String> {
        let mut xml = response_xml.to_string();
        if self.sign_assertions {
            if let Some(aid) = assertion_id {
                let sig = signature_template(aid, &self.cert_b64);
                xml = insert_signature_after_element(&xml, "saml:Assertion", &sig)?;
                xml = self
                    .signer
                    .sign_enveloped(&xml)
                    .map_err(|e| Error::Crypto(format!("assertion signing: {e}")))?;
            }
        }
        if self.sign_responses {
            let sig = signature_template(response_id, &self.cert_b64);
            xml = insert_signature_after_element(&xml, "samlp:Response", &sig)?;
            xml = self
                .signer
                .sign_enveloped(&xml)
                .map_err(|e| Error::Crypto(format!("response signing: {e}")))?;
        }
        Ok(xml)
    }

    fn build_metadata(&self) -> Result<String> {
        use gamlastan::metadata::types::endpoint::Endpoint;
        use gamlastan::metadata::types::entity_descriptor::{EntityDescriptor, EntityRoles};
        use gamlastan::metadata::types::idp::IdpSsoDescriptor;
        use gamlastan::metadata::types::key_descriptor::KeyDescriptor;
        use gamlastan::metadata::types::role_descriptor::{RoleDescriptorBase, SsoDescriptorBase};

        let key_info = gamlastan::crypto::build_x509_key_info(&[self.cert_b64.as_str()]);
        let mut base =
            RoleDescriptorBase::new(vec!["urn:oasis:names:tc:SAML:2.0:protocol".to_string()]);
        base.key_descriptors = vec![KeyDescriptor::signing(key_info)];

        let idp_sso = IdpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base,
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats: self.name_id_formats.clone(),
            },
            want_authn_requests_signed: Some(self.want_authn_requests_signed),
            single_sign_on_services: vec![
                Endpoint::new(constants::BINDING_HTTP_REDIRECT, &self.sso_url),
                Endpoint::new(constants::BINDING_HTTP_POST, &self.sso_url),
            ],
            name_id_mapping_services: vec![],
            assertion_id_request_services: vec![],
            attribute_profiles: vec![],
            attributes: vec![],
        };

        let entity = EntityDescriptor {
            entity_id: self.idp_entity_id.clone(),
            id: None,
            valid_until: None,
            cache_duration: None,
            has_signature: false,
            extensions: None,
            roles: EntityRoles::Roles {
                idp_sso: vec![idp_sso],
                sp_sso: vec![],
                authn_authority: vec![],
                attr_authority: vec![],
                pdp: vec![],
            },
            organization: self.organization.clone(),
            contact_persons: self.contact_persons.clone(),
            additional_metadata_locations: vec![],
        };
        entity
            .to_xml_string()
            .map_err(|e| Error::Internal(format!("serializing IdP metadata: {e}")))
    }
}

/// Decode an inbound AuthnRequest: base64 then (for HTTP-Redirect) DEFLATE.
fn decode_authn_request(encoded: &str, deflated: bool) -> Result<String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| Error::BadRequest(format!("base64 SAMLRequest: {e}")))?;
    if deflated {
        let mut decoder = flate2::read::DeflateDecoder::new(&bytes[..]);
        let mut xml = String::new();
        decoder
            .read_to_string(&mut xml)
            .map_err(|e| Error::BadRequest(format!("inflate SAMLRequest: {e}")))?;
        Ok(xml)
    } else {
        String::from_utf8(bytes).map_err(|e| Error::BadRequest(format!("SAMLRequest UTF-8: {e}")))
    }
}

/// ds:Signature template with empty digest/signature placeholders for enveloped
/// signing (filled by `signer.sign_enveloped`).
fn signature_template(reference_id: &str, cert_b64: &str) -> String {
    format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##,
        id = reference_id,
        cert = cert_b64,
    )
}

/// Insert a signature template right after the opening tag of `element_name`.
fn insert_signature_after_element(xml: &str, element_name: &str, sig: &str) -> Result<String> {
    let with_space = format!("<{element_name} ");
    let with_close = format!("<{element_name}>");
    let tag_start = xml
        .find(&with_space)
        .or_else(|| xml.find(&with_close))
        .ok_or_else(|| Error::Internal(format!("cannot find <{element_name}> in XML")))?;
    let rel = xml[tag_start..]
        .find('>')
        .ok_or_else(|| Error::Internal(format!("malformed <{element_name}> tag")))?;
    let pos = tag_start + rel;
    Ok(format!("{}{}{}", &xml[..=pos], sig, &xml[pos + 1..]))
}
