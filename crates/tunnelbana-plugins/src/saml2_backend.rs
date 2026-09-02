//! SAML2 backend — the proxy acts as a SAML Service Provider (SP) to an upstream
//! SAML Identity Provider. Wraps the `gamlastan` core: create AuthnRequest, send
//! via HTTP-Redirect, then at the ACS verify the signature, validate the Response
//! (32-check `AssertionValidator` via `process_response`) and map attributes.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex as StdMutex, Weak};

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use serde::Deserialize;

use gamlastan::core::assertion::attribute::AttributeValue;
use gamlastan::core::assertion::name_id::{NameId, NameIdOrEncryptedId};
use gamlastan::core::assertion::subject::Subject;
use gamlastan::core::constants;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{
    KeyUsage, KeysManager, SamlDecryptor, SamlSigner, SamlVerifier, VerifyResult,
};
use gamlastan::metadata::EntityDescriptor;
use gamlastan::profiles::sso::sp as sp_profile;
use gamlastan::profiles::sso::web_browser::{self, AuthnRequestOptions};
use gamlastan::security::config::SecurityConfig;
use gamlastan::security::replay::InMemoryReplayCache;
use gamlastan::security::validation::{AssertionValidator, ValidationParams};
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan_mdq::{MdqClient, MdqError, MetadataFetcher, ReqwestFetcher};

use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::{
    Context, KEY_PROVIDER_ASSURANCE_CERTIFICATIONS, KEY_PROVIDER_SCOPES,
};
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext, Route};
use tunnelbana_core::util::now_rfc3339;

use crate::saml_common::{
    build_mdq_client_with_fetcher, extract_cert_b64, verifier_from_cert_ders, MdqConfig,
};

/// XML-DSig RSA-SHA256 signature algorithm URI (for signed redirect requests).
const SIGALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
const MDQ_CACHE_CAPACITY: usize = 1024;

tokio::task_local! {
    static CAPTURED_MDQ_METADATA: RefCell<Option<Bytes>>;
}

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
    /// mode this is the default when no per-request `entityID` arrives and may
    /// be omitted when a discovery service (`disco_srv`) is configured.
    #[serde(default)]
    idp_entity_id: Option<String>,
    /// SAML identity-provider discovery service URL (e.g. SeamlessAccess).
    /// MDQ mode only: when no target IdP is known for a flow the user is sent
    /// here, and the service returns them to `<module_base>/disco?entityID=…`.
    #[serde(default)]
    disco_srv: Option<String>,
    /// Upstream IdP SSO endpoint (where AuthnRequests are sent). Required in
    /// static mode; in MDQ mode it is resolved from metadata, so leave it unset.
    #[serde(default)]
    idp_sso_url: Option<String>,
    /// Upstream IdP signing certificate (PEM) — verifies the Response. Required
    /// in static mode; in MDQ mode the signing cert comes from metadata.
    #[serde(default)]
    idp_cert_path: Option<String>,
    /// Trusted scope values for a statically configured IdP. Dynamic/MDQ
    /// backends obtain these from the selected IdP's signed metadata.
    #[serde(default)]
    idp_scopes: Vec<String>,
    /// Trusted assurance-certification values for a statically configured
    /// IdP. MDQ mode reads these from accepted metadata.
    #[serde(default)]
    idp_assurance_certifications: Vec<String>,
    /// When present, resolve the IdP's SSO endpoint and signing cert on demand
    /// from an MDQ server instead of the static `idp_sso_url` / `idp_cert_path`.
    #[serde(default)]
    mdq: Option<MdqConfig>,
    #[serde(default)]
    sign_authn_requests: bool,
    #[serde(default)]
    name_id_format: Option<String>,
    /// Validation preset: "production", "strict", or "permissive". Ordinary
    /// backends retain the historical permissive default; step-up defaults to
    /// production and rejects permissive.
    #[serde(default)]
    security: Option<String>,
    /// Accepted clock skew (seconds) between this SP and the IdP; overrides
    /// the `security` preset's tolerance (SATOSA: `accepted_time_diff`).
    #[serde(default)]
    accepted_time_diff_secs: Option<u64>,
    /// `[backend.config.organization]` — published in SP metadata.
    #[serde(default)]
    organization: Option<crate::saml_metadata::OrganizationConfig>,
    /// `[[backend.config.contact_person]]` — published in SP metadata.
    #[serde(default)]
    contact_person: Vec<crate::saml_metadata::ContactPersonConfig>,
    /// Keep inbound SAML attributes the attribute map does not know about,
    /// under a lowercased FriendlyName-or-Name key (SATOSA:
    /// `allow_unknown_attributes`). Default false: unmapped attributes are
    /// dropped.
    #[serde(default)]
    passthrough_unmapped_attributes: bool,
    /// MDQ/dynamic mode only: scope every IdP-asserted subject identifier —
    /// composed from attributes or a raw NameID — by the issuing IdP
    /// (`{issuer_len}:{issuer}:{id}`, ADR 0048), so one federation IdP cannot
    /// assert another IdP's subject. Default false = SATOSA behavior:
    /// composed identifiers are used unscoped and persistent NameIDs are
    /// issuer-scoped (ADR 0005). Enabling this changes every downstream
    /// `subject_id` value; migrate stored account links first.
    #[serde(default)]
    scope_subject_id_by_issuer: bool,
    /// Accept IdP-initiated (unsolicited) Responses carrying no
    /// `InResponseTo`, within an existing proxy flow. Default false: the ACS
    /// then requires the AuthnRequest id persisted at `start_auth`. Note that
    /// a cookie-less unsolicited Response can never complete — the proxy
    /// needs the flow state to know the originating frontend — so this flag
    /// only relaxes the `InResponseTo` requirement.
    #[serde(default)]
    allow_unsolicited: bool,
    /// `[[backend.config.encryption_keypairs]]` — private keys for decrypting
    /// `EncryptedAssertion`/`EncryptedID` (usually the signing pair). List
    /// several to rotate: all are tried for decryption; every entry with a
    /// `cert_path` is published in SP metadata with `use="encryption"` (omit
    /// `cert_path` for retired decrypt-only keys).
    #[serde(default)]
    encryption_keypairs: Vec<EncryptionKeypairConfig>,
}

/// One `[[backend.config.encryption_keypairs]]` entry.
#[derive(Debug, Deserialize)]
struct EncryptionKeypairConfig {
    key_path: String,
    #[serde(default)]
    cert_path: Option<String>,
}

/// Where the upstream IdP's SSO endpoint and signing cert come from.
enum IdpMetadata {
    /// Pinned at build time from `idp_sso_url` + `idp_cert_path`.
    Static {
        sso_url: String,
        verifier: SamlVerifier,
        assurance_certifications: Vec<String>,
    },
    /// Resolved per request from an MDQ server, keyed by `idp_entity_id`.
    Mdq(ScopeAwareMdqClient),
}

#[derive(Clone)]
struct CapturingMetadataFetcher<F = ReqwestFetcher> {
    inner: F,
}

impl<F> MetadataFetcher for CapturingMetadataFetcher<F>
where
    F: MetadataFetcher + Sync,
{
    async fn fetch(&self, url: &str) -> std::result::Result<Bytes, MdqError> {
        let bytes = self.inner.fetch(url).await?;
        CAPTURED_MDQ_METADATA
            .try_with(|capture| capture.replace(Some(bytes.clone())))
            .map_err(|_| MdqError::Transport("MDQ capture context is unavailable".into()))?;
        Ok(bytes)
    }
}

#[derive(Default)]
struct TrustedScopeCache {
    entries: BTreeMap<String, Vec<String>>,
}

impl TrustedScopeCache {
    fn requires_reset(&self, entity_id: &str, capacity: usize) -> bool {
        !self.entries.contains_key(entity_id) && self.entries.len() >= capacity
    }

    fn insert(&mut self, entity_id: String, scopes: Vec<String>) {
        self.entries.insert(entity_id, scopes);
    }

    fn clear(&mut self) {
        self.entries.clear();
    }

    fn get(&self, entity_id: &str) -> Vec<String> {
        self.entries.get(entity_id).cloned().unwrap_or_default()
    }
}

/// MDQ client paired with the exact source document accepted by it.
///
/// `EntityDescriptor` intentionally keeps extension XML as a detached source
/// slice, which loses namespace declarations inherited from ancestors. The
/// capture lets scope parsing use the original namespace-aware document after
/// (and only after) the normal MDQ client has accepted that same fetch. Capture
/// is task-local so unrelated network lookups remain concurrent. Weakly held
/// per-entity locks make each entity/scopes cache update atomic without
/// accumulating a second persistent entity map. The scope cache may retain an
/// entry after MDQ purges it, but scopes are never removed independently while
/// MDQ still retains the corresponding entity.
struct ScopeAwareMdqClient<F = ReqwestFetcher> {
    client: MdqClient<CapturingMetadataFetcher<F>>,
    trusted_scopes: StdMutex<TrustedScopeCache>,
    cache_capacity: usize,
    lookup_locks: StdMutex<BTreeMap<String, Weak<tokio::sync::Mutex<()>>>>,
}

impl ScopeAwareMdqClient<ReqwestFetcher> {
    fn build(config: &MdqConfig) -> Result<Self> {
        let inner = ReqwestFetcher::try_default()
            .map_err(|e| Error::Config(format!("building MDQ HTTP client: {e}")))?;
        let fetcher = CapturingMetadataFetcher { inner };
        let client = build_mdq_client_with_fetcher(config, fetcher)?;
        Ok(Self::new(client, MDQ_CACHE_CAPACITY))
    }
}

impl<F> ScopeAwareMdqClient<F>
where
    F: MetadataFetcher + Sync,
{
    fn new(client: MdqClient<CapturingMetadataFetcher<F>>, cache_capacity: usize) -> Self {
        assert!(cache_capacity > 0, "MDQ cache capacity must be non-zero");
        Self {
            client: client.with_cache_capacity(cache_capacity),
            trusted_scopes: StdMutex::new(TrustedScopeCache::default()),
            cache_capacity,
            lookup_locks: StdMutex::new(BTreeMap::new()),
        }
    }

    async fn get(
        &self,
        entity_id: &str,
    ) -> std::result::Result<(EntityDescriptor, Vec<String>, Vec<String>), MdqError> {
        let lookup_lock = self.lookup_lock(entity_id);
        let _lookup = lookup_lock.lock().await;
        // Keep a request-local copy because a concurrent lookup for another
        // entity may reset both shared caches after this lookup hits MDQ's
        // cache but before it returns here.
        let cached_scopes = {
            let mut trusted_scopes = lock_unpoisoned(&self.trusted_scopes);
            if trusted_scopes.requires_reset(entity_id, self.cache_capacity) {
                self.client.clear_cache();
                trusted_scopes.clear();
            }
            trusted_scopes.get(entity_id)
        };
        let (entity, captured_bytes) = CAPTURED_MDQ_METADATA
            .scope(RefCell::new(None), async {
                let entity = self.client.get(entity_id).await?;
                let captured = CAPTURED_MDQ_METADATA.with(|capture| capture.borrow_mut().take());
                Ok::<_, MdqError>((entity, captured))
            })
            .await?;

        let Some(captured_bytes) = captured_bytes else {
            let assurances = trusted_assurance_certifications(&entity);
            return Ok((entity, cached_scopes, assurances));
        };

        // Promote only bytes fetched and accepted by this lookup. The MDQ
        // cache can purge expired entries without exposing their IDs. Never
        // evict a scope entry alone: at the shared bound, clear both caches so
        // every entity retained by MDQ continues to have matching scopes.
        let scopes = std::str::from_utf8(&captured_bytes)
            .map(|xml| trusted_scopes_from_metadata_xml(xml, entity_id))
            .unwrap_or_default();
        let mut trusted_scopes = lock_unpoisoned(&self.trusted_scopes);
        if trusted_scopes.requires_reset(entity_id, self.cache_capacity) {
            self.client.clear_cache();
            trusted_scopes.clear();
        }
        trusted_scopes.insert(entity_id.to_string(), scopes.clone());
        let assurances = trusted_assurance_certifications(&entity);
        Ok((entity, scopes, assurances))
    }

    fn lookup_lock(&self, entity_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = lock_unpoisoned(&self.lookup_locks);
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(entity_id).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(entity_id.to_string(), Arc::downgrade(&lock));
        lock
    }
}

fn lock_unpoisoned<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// `gamlastan::bindings::traits::HttpRequest` adapter exposing the raw
/// percent-encoded query values from `HttpRequestData.uri`, which Redirect
/// binding signature verification must preserve byte-for-byte.
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

struct DecodedAcsResponse {
    xml: String,
    binding_signature_verified: bool,
}

pub struct Saml2Backend {
    name: String,
    state_namespace: String,
    sp_entity_id: String,
    acs_url: String,
    idp_entity_id: Option<String>,
    disco_srv: Option<String>,
    /// `<module_base>/disco` — the discovery-service return endpoint.
    disco_return_url: String,
    idp_metadata: IdpMetadata,
    signer: SamlSigner,
    sign_requests: bool,
    name_id_format: Option<String>,
    sp_cert_b64: Option<String>,
    security: SecurityPreset,
    accepted_time_diff_secs: Option<u64>,
    passthrough_unmapped_attributes: bool,
    scope_subject_id_by_issuer: bool,
    allow_unsolicited: bool,
    /// Operator-configured equivalent of Shibboleth `<Scope>` metadata for a
    /// statically pinned IdP.
    static_idp_scopes: Vec<String>,
    /// Assertion IDs accepted by this backend, retained until their SAML
    /// validity deadline. gamlastan 0.8 fails closed when validation has no
    /// replay cache, so every backend owns one for its full process lifetime.
    /// This protects one tunnelbana process; a future clustered deployment
    /// must replace it with a shared [`gamlastan::security::ReplayCache`].
    replay_cache: InMemoryReplayCache,
    organization: Option<gamlastan::metadata::types::organization::Organization>,
    contact_persons: Vec<gamlastan::metadata::types::contact::ContactPerson>,
    /// One decryptor per configured encryption key (bergshamra only uses the
    /// first RSA key of a manager, so rotation = try each in turn).
    decryptors: Vec<SamlDecryptor>,
    /// Certs published with `use="encryption"` in SP metadata.
    encryption_certs_b64: Vec<String>,
    mapper: Arc<AttributeMapper>,
    /// Include `InternalData.subject_id` as an unspecified NameID in the
    /// outbound AuthnRequest. Enabled only for the step-up micro-SP.
    request_subject: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecurityPreset {
    /// gamlastan's test-only compatibility policy.
    Permissive,
    /// Secure, interoperable SP defaults: signed assertions plus destination,
    /// recipient, time, audience, correlation, replay, and E91 checks.
    Production,
    /// High-security policy requiring signed responses, directly signed and
    /// encrypted assertions, and client-address validation as applicable.
    Strict,
}

impl Saml2Backend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Backend>> {
        Self::build_concrete(bx, false, bx.name.clone())
            .map(|backend| Box::new(backend) as Box<dyn Backend>)
    }

    pub(crate) fn build_stepup(bx: &BuildContext) -> Result<Self> {
        let backend = Self::build_concrete(bx, true, format!("stepup_saml:{}", bx.name))?;
        if backend.security == SecurityPreset::Permissive {
            return Err(Error::Config(format!(
                "stepup {}: security=permissive is test-only and is not allowed; use production or strict",
                bx.name
            )));
        }
        if !backend.sign_requests {
            return Err(Error::Config(format!(
                "stepup {}: sign_authn_requests must be true",
                bx.name
            )));
        }
        if backend.allow_unsolicited {
            return Err(Error::Config(format!(
                "stepup {}: allow_unsolicited must be false",
                bx.name
            )));
        }
        if backend.disco_srv.is_some() {
            return Err(Error::Config(format!(
                "stepup {}: disco_srv is not supported; the linked account selects the provider",
                bx.name
            )));
        }
        Ok(backend)
    }

    pub(crate) fn validate_stepup_target(&self, entity_id: &str) -> Result<()> {
        if entity_id.is_empty()
            || entity_id.chars().count() > 1024
            || entity_id.chars().any(char::is_control)
        {
            return Err(Error::Authn("step-up provider entity id is invalid".into()));
        }
        if matches!(self.idp_metadata, IdpMetadata::Static { .. })
            && self.idp_entity_id.as_deref() != Some(entity_id)
        {
            return Err(Error::Authn(
                "linked step-up provider does not match the statically configured IdP".into(),
            ));
        }
        Ok(())
    }

    fn build_concrete(
        bx: &BuildContext,
        request_subject: bool,
        state_namespace: String,
    ) -> Result<Self> {
        let cfg: Saml2BackendConfig = bx.parse_config()?;
        let module_base = bx.module_base();
        let sp_entity_id = cfg
            .sp_entity_id
            .clone()
            .unwrap_or_else(|| module_base.clone());
        let acs_url = format!("{module_base}/acs");

        if cfg
            .idp_scopes
            .iter()
            .any(|scope| scope.is_empty() || scope.chars().any(char::is_control))
        {
            return Err(Error::Config(format!(
                "saml2 backend {}: idp_scopes entries must be non-empty and contain no control characters",
                bx.name
            )));
        }
        if cfg
            .idp_assurance_certifications
            .iter()
            .any(|value| value.is_empty() || value.chars().any(char::is_control))
        {
            return Err(Error::Config(format!(
                "saml2 backend {}: idp_assurance_certifications entries must be non-empty and contain no control characters",
                bx.name
            )));
        }

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
            Some(mdq_cfg) => {
                if request_subject && mdq_cfg.allow_unverified {
                    return Err(Error::Config(format!(
                        "stepup {}: mdq.allow_unverified is not allowed; step-up metadata must be signature-verified",
                        bx.name
                    )));
                }
                if !cfg.idp_scopes.is_empty() || !cfg.idp_assurance_certifications.is_empty() {
                    return Err(Error::Config(
                        "saml2 backend idp_scopes and idp_assurance_certifications are only valid in static mode; MDQ mode reads them from trusted metadata".into(),
                    ));
                }
                if !request_subject && cfg.idp_entity_id.is_none() && cfg.disco_srv.is_none() {
                    return Err(Error::Config(
                        "saml2 backend in MDQ mode requires idp_entity_id and/or disco_srv".into(),
                    ));
                }
                IdpMetadata::Mdq(ScopeAwareMdqClient::build(mdq_cfg)?)
            }
            None => {
                if cfg.disco_srv.is_some() {
                    // Static mode pins one IdP cert/SSO URL; a discovery
                    // service would select arbitrary IdPs we cannot verify.
                    return Err(Error::Config(
                        "saml2 backend disco_srv requires an [mdq] section".into(),
                    ));
                }
                if cfg.idp_entity_id.is_none() {
                    return Err(Error::Config(
                        "saml2 backend requires idp_entity_id in static mode".into(),
                    ));
                }
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
                IdpMetadata::Static {
                    sso_url,
                    verifier,
                    assurance_certifications: cfg.idp_assurance_certifications,
                }
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

        // One SamlDecryptor per encryption key (try-each rotation).
        let mut decryptors = Vec::new();
        let mut encryption_certs_b64 = Vec::new();
        for keypair in &cfg.encryption_keypairs {
            let key_pem = std::fs::read(&keypair.key_path)
                .map_err(|e| Error::Config(format!("reading encryption_keypairs.key_path: {e}")))?;
            let mut key = loader::load_pem_auto(&key_pem, None)
                .map_err(|e| Error::Crypto(format!("loading encryption key: {e}")))?;
            key.usage = KeyUsage::Decrypt;
            let mut km = KeysManager::new();
            km.add_key(key);
            decryptors.push(SamlDecryptor::new(km));

            if let Some(cert_path) = &keypair.cert_path {
                let pem = std::fs::read(cert_path).map_err(|e| {
                    Error::Config(format!("reading encryption_keypairs.cert_path: {e}"))
                })?;
                encryption_certs_b64.push(extract_cert_b64(&pem));
            }
        }

        // Fail closed on a typo'd security preset instead of silently
        // selecting the permissive one.
        let security = match cfg.security.as_deref() {
            None if request_subject => SecurityPreset::Production,
            None => SecurityPreset::Permissive,
            Some(v) if v.eq_ignore_ascii_case("production") => SecurityPreset::Production,
            Some(v) if v.eq_ignore_ascii_case("strict") => SecurityPreset::Strict,
            Some(v) if v.eq_ignore_ascii_case("permissive") => SecurityPreset::Permissive,
            Some(other) => {
                return Err(Error::Config(format!(
                    "saml2 backend {}: unknown security value {other:?} \
                     (expected \"production\", \"strict\", or \"permissive\")",
                    bx.name
                )))
            }
        };

        Ok(Saml2Backend {
            name: bx.name.clone(),
            state_namespace,
            sp_entity_id,
            acs_url,
            idp_entity_id: cfg.idp_entity_id,
            disco_srv: cfg.disco_srv,
            disco_return_url: format!("{module_base}/disco"),
            idp_metadata,
            signer,
            sign_requests: cfg.sign_authn_requests,
            name_id_format: cfg.name_id_format,
            sp_cert_b64,
            security,
            accepted_time_diff_secs: cfg.accepted_time_diff_secs,
            passthrough_unmapped_attributes: cfg.passthrough_unmapped_attributes,
            scope_subject_id_by_issuer: cfg.scope_subject_id_by_issuer,
            allow_unsolicited: cfg.allow_unsolicited,
            static_idp_scopes: cfg.idp_scopes,
            replay_cache: InMemoryReplayCache::new(),
            organization: cfg.organization.as_ref().map(|o| o.to_organization()),
            contact_persons: crate::saml_metadata::contact_persons(&cfg.contact_person)?,
            decryptors,
            encryption_certs_b64,
            mapper: bx.attribute_mapper.clone(),
            request_subject,
        })
    }

    /// Try each configured decryptor in turn (key rotation): bergshamra only
    /// uses the first RSA key of a manager, so rotation means try-each.
    ///
    /// The decryptor replaces the `xenc:EncryptedData` in-place, so the
    /// `EncryptedAssertion`/`EncryptedID` wrapper element is still the root of
    /// the output; peel it off so the result is the decrypted element itself.
    fn decrypt_with_any(&self, encrypted_xml: &str) -> Result<String> {
        let mut last_error = None;
        for decryptor in &self.decryptors {
            match decryptor.decrypt(encrypted_xml) {
                Ok(plaintext) => return Ok(unwrap_decrypted_wrapper(&plaintext)),
                Err(e) => last_error = Some(e),
            }
        }
        Err(Error::Authn(format!(
            "decrypting SAML element failed with every configured key: {}",
            last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no encryption_keypairs configured".into())
        )))
    }

    pub(crate) fn security_config(&self) -> SecurityConfig {
        let mut cfg = match self.security {
            SecurityPreset::Permissive => SecurityConfig::permissive(),
            SecurityPreset::Production => SecurityConfig::default(),
            SecurityPreset::Strict => SecurityConfig::strict(),
        };
        if let Some(skew) = self.accepted_time_diff_secs {
            cfg.clock_skew_seconds = skew;
        }
        cfg
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
        for cert_b64 in &self.encryption_certs_b64 {
            let key_info = gamlastan::crypto::build_x509_key_info(&[cert_b64.as_str()]);
            base.key_descriptors
                .push(KeyDescriptor::encryption(key_info));
        }
        // Discovery deployments publish where the discovery service may send
        // the user back (idp-discovery-protocol <idpdisc:DiscoveryResponse>).
        if self.disco_srv.is_some() {
            use gamlastan::profiles::swedenconnect::metadata as sc_metadata;
            base.extensions = Some(sc_metadata::extensions(&[
                sc_metadata::discovery_response_xml(0, &self.disco_return_url),
            ]));
        }

        // Advertise the configured NameID format when set; otherwise the
        // formats the backend generally accepts.
        let name_id_formats = match &self.name_id_format {
            Some(format) => vec![format.clone()],
            None => vec![
                constants::NAMEID_PERSISTENT.to_string(),
                constants::NAMEID_EMAIL.to_string(),
            ],
        };

        let sp_sso = SpSsoDescriptor {
            sso_base: SsoDescriptorBase {
                base,
                artifact_resolution_services: vec![],
                single_logout_services: vec![],
                manage_name_id_services: vec![],
                name_id_formats,
            },
            authn_requests_signed: Some(self.sign_requests),
            want_assertions_signed: Some(true),
            // The ACS handler accepts both bindings on the same URL.
            assertion_consumer_services: vec![
                IndexedEndpoint::new_default(
                    Endpoint::new(constants::BINDING_HTTP_POST, &self.acs_url),
                    0,
                ),
                IndexedEndpoint::new(
                    Endpoint::new(constants::BINDING_HTTP_REDIRECT, &self.acs_url),
                    1,
                ),
            ],
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
            organization: self.organization.clone(),
            contact_persons: self.contact_persons.clone(),
            additional_metadata_locations: vec![],
        };

        entity
            .to_xml_string()
            .map_err(|e| Error::Internal(format!("serializing SP metadata: {e}")))
    }

    /// Redirect the user to the configured discovery service, which sends them
    /// back to `<module_base>/disco?entityID=<chosen IdP>`.
    fn disco_redirect(&self, disco_srv: &str) -> Response {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("entityID", &self.sp_entity_id);
        query.append_pair("return", &self.disco_return_url);
        let separator = if disco_srv.contains('?') { '&' } else { '?' };
        Response::redirect(format!("{disco_srv}{separator}{}", query.finish()))
    }

    /// Dispatch the ACS: resolve the verifier (static cert, or the IdP's signing
    /// cert fetched from MDQ for the IdP this flow was sent to), then process the
    /// Response against it.
    async fn handle_acs(&self, ctx: &mut Context) -> Result<BackendAction> {
        match &self.idp_metadata {
            IdpMetadata::Static {
                verifier,
                assurance_certifications,
                ..
            } => {
                let expected = self
                    .idp_entity_id
                    .as_deref()
                    .ok_or_else(|| Error::Internal("static mode without idp_entity_id".into()))?;
                self.process_acs(
                    ctx,
                    verifier,
                    expected,
                    &self.static_idp_scopes,
                    assurance_certifications,
                )
            }
            IdpMetadata::Mdq(client) => {
                // Verify against the cert for the IdP we actually sent the request
                // to (persisted at start_auth) — not the still-unverified issuer
                // claimed by the Response. Falls back to the configured default.
                let selected = ctx
                    .state
                    .get_str(&self.state_namespace, "idp_entity_id")
                    .or_else(|| self.idp_entity_id.clone())
                    .ok_or_else(|| Error::Authn("no IdP selected for this flow".into()))?;
                let (entity, scopes, assurance_certifications) = client
                    .get(&selected)
                    .await
                    .map_err(|e| Error::Authn(format!("MDQ lookup for {selected} failed: {e}")))?;
                let verifier = idp_verifier_from_metadata(&entity)?;
                self.process_acs(
                    ctx,
                    &verifier,
                    &selected,
                    &scopes,
                    &assurance_certifications,
                )
            }
        }
    }

    fn process_acs(
        &self,
        ctx: &mut Context,
        verifier: &SamlVerifier,
        expected_idp_entity_id: &str,
        provider_scopes: &[String],
        provider_assurance_certifications: &[String],
    ) -> Result<BackendAction> {
        // SAMLResponse arrives via HTTP-POST (base64 form field) or
        // HTTP-Redirect (deflated query param, optionally query-signed).
        let DecodedAcsResponse {
            xml,
            binding_signature_verified,
        } = decode_acs_response(&ctx.request, verifier)?;

        // 1) Parse the Response. Parsing precedes signature verification
        //    because EncryptedAssertions must be located (and, for the
        //    assertion-signature case, decrypted) before their signatures can
        //    be checked; nothing parsed is trusted until step 3 passes.
        let doc = gamlastan::xml::uppsala::parse(&xml)
            .map_err(|e| Error::BadRequest(format!("invalid SAML XML: {e}")))?;
        let mut response = gamlastan::xml::deserialize::parse_saml::<
            gamlastan::core::protocol::response::ResponseRef<'_>,
        >(&doc)
        .map_err(|e| Error::BadRequest(format!("parsing Response: {e}")))?
        .to_owned();
        let cleartext_assertions_xml =
            cleartext_assertion_sources(&doc, response.assertions.len())?;

        // 2) Signature acceptance rule, spanning the encryption boundary.
        //
        //    The Response envelope is protected when either the Response XML
        //    signature verifies or the HTTP-Redirect binding signature verifies.
        //    That is enough for response-envelope integrity, but gamlastan 0.7's
        //    direct assertion-signature policy also requires every consumed
        //    Assertion that carries `<ds:Signature>` markup to have its own
        //    verified reference ID. `verify_all_enveloped` is therefore used for
        //    all cleartext XML signatures; `verify_enveloped` only reports the
        //    first signature and would miss a following Assertion signature.
        let mut verified_signed_ids = Vec::new();
        if response.base.has_signature || response.assertions.iter().any(|a| a.has_signature) {
            extend_verified_xml_signature_ids(
                &mut verified_signed_ids,
                verifier,
                &xml,
                &response.base.id,
            )?;
        }
        if binding_signature_verified {
            // The detached Redirect signature covers the SAMLResponse query
            // parameter bytes, so treat it as proof for the Response object.
            // It is not proof of a direct Assertion XML signature.
            add_verified_signed_id(&mut verified_signed_ids, &response.base.id);
        }

        // Only an XML signature whose reference targets the Response ID
        // satisfies gamlastan's response-signature validation check. A detached
        // Redirect signature is tracked separately through `envelope_verified`.
        let response_xml_signature_verified =
            response.base.has_signature && verified_signed_ids.contains(&response.base.id);
        let envelope_verified = binding_signature_verified || response_xml_signature_verified;

        if !envelope_verified {
            // Cleartext assertions must each be signed and verified against the
            // exact subtree they travelled in. A whole-document verifier call
            // only proves one signature, which is insufficient when attributes
            // may later be merged across assertions.
            if response.assertions.iter().any(|a| !a.has_signature) {
                return Err(Error::Authn(
                    "SAML Response is unsigned and not every assertion is signed".into(),
                ));
            }
            for (index, assertion_xml) in cleartext_assertions_xml.iter().enumerate() {
                if let VerifyResult::Invalid { reason } = verifier
                    .verify_enveloped(&standalone_assertion_document(assertion_xml))
                    .map_err(|e| Error::Authn(format!("signature verification failed: {e}")))?
                {
                    return Err(Error::Authn(format!(
                        "assertion {} signature is not valid: {reason}",
                        index + 1
                    )));
                }
            }
        }

        // Decrypt EncryptedAssertions and splice them into the assertion list.
        // A decrypted assertion with signature markup is verified on its
        // plaintext and contributes its own reference ID. When neither an XML
        // Response signature nor a Redirect-binding signature verified, every
        // decrypted assertion must carry such a verified signature.
        let encrypted = std::mem::take(&mut response.encrypted_assertions);
        if !encrypted.is_empty() && self.decryptors.is_empty() {
            return Err(Error::Authn(
                "SAML Response carries EncryptedAssertion but no encryption_keypairs are \
                 configured"
                    .into(),
            ));
        }
        for ea in &encrypted {
            let enc_xml = std::str::from_utf8(&ea.raw)
                .map_err(|e| Error::BadRequest(format!("non-UTF8 EncryptedAssertion: {e}")))?;
            let plaintext = self.decrypt_with_any(enc_xml)?;
            let assertion_doc = gamlastan::xml::uppsala::parse(&plaintext)
                .map_err(|e| Error::Authn(format!("decrypted assertion is not XML: {e}")))?;
            let assertion = gamlastan::xml::deserialize::parse_saml::<
                gamlastan::core::assertion::types::AssertionRef<'_>,
            >(&assertion_doc)
            .map_err(|e| Error::Authn(format!("parsing decrypted assertion: {e}")))?
            .to_owned();

            if assertion.has_signature {
                extend_verified_xml_signature_ids(
                    &mut verified_signed_ids,
                    verifier,
                    &plaintext,
                    &assertion.id,
                )?;
            } else if !envelope_verified {
                return Err(Error::Authn(
                    "SAML Response is unsigned and a decrypted assertion is unsigned".into(),
                ));
            }
            response.assertions.push(assertion);
        }

        // 3) Status check. Ordinary failures are surfaced as authentication
        //    errors so the frontend returns `access_denied`. `NoPassive` on a
        //    stored passive flow is marked separately and becomes
        //    `login_required` instead.
        if !response.base.status.is_success() {
            let status_code = &response.base.status.status_code;
            let is_no_passive = status_code.value == constants::STATUS_NO_PASSIVE
                || status_code
                    .sub_status
                    .as_deref()
                    .is_some_and(|sub| sub.value == constants::STATUS_NO_PASSIVE);
            let is_passive = ctx
                .state
                .get_value(&self.state_namespace, "is_passive")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if is_passive && is_no_passive {
                ctx.mark_interaction_required();
            }
            let msg = response
                .base
                .status
                .status_message
                .clone()
                .unwrap_or_else(|| {
                    status_code
                        .sub_status
                        .as_deref()
                        .unwrap_or(status_code)
                        .value
                        .clone()
                });
            return Err(Error::Authn(format!(
                "IdP returned a non-success SAML status: {msg}"
            )));
        }
        if response.assertions.is_empty() {
            return Err(Error::Authn("SAML Response carries no assertions".into()));
        }

        // 4) Run the 32-check validation. The signatures were already
        //    cryptographically verified in step 2; when the signature is on
        //    the Response element itself, tell the validator so it accepts a
        //    validly signed Response (cf. SATOSA
        //    `want_assertions_or_response_signed`).
        //
        //    A stored AuthnRequest id is *required* unless this is a truly
        //    unsolicited Response (no InResponseTo) and `allow_unsolicited`
        //    is on — a missing id must never silently skip the InResponseTo
        //    check (fail closed).
        let expected_id = match ctx.state.get_str(&self.state_namespace, "authn_id") {
            Some(id) => Some(id),
            None if self.allow_unsolicited && response.base.in_response_to.is_none() => None,
            None if self.allow_unsolicited => {
                return Err(Error::Authn(
                    "SAML Response carries InResponseTo but no AuthnRequest is in flight".into(),
                ));
            }
            None => {
                return Err(Error::Authn(
                    "no in-flight AuthnRequest for this ACS (unsolicited responses are \
                     disabled)"
                        .into(),
                ));
            }
        };
        let response_signature_verified = if response.base.has_signature {
            Some(response_xml_signature_verified)
        } else {
            None
        };
        // Tell the validator (check 6) exactly which IDs we cryptographically
        // verified above, so it accepts only signatures we actually proved.
        let verified_signed_id_refs: Vec<&str> =
            verified_signed_ids.iter().map(String::as_str).collect();
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
            verified_signed_ids: &verified_signed_id_refs,
            current_proxy_depth: 0,
            now: Utc::now(),
        };
        let cfg = self.security_config();
        // Replay insertion is part of the same validation pass as audience,
        // time, recipient, request-correlation, and signature-provenance
        // checks. Keeping the cache on `self` (rather than constructing one
        // per request) makes a previously accepted assertion ID fail check 20
        // for the rest of its validity window.
        let validation = AssertionValidator::new(&cfg)
            .with_replay_cache(&self.replay_cache)
            .validate_response(&response, &params);
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
                Some(NameIdOrEncryptedId::NameId(nid)) => (nid.value.clone(), nid.format.clone()),
                Some(NameIdOrEncryptedId::EncryptedId(eid)) => {
                    let enc_xml = std::str::from_utf8(&eid.raw)
                        .map_err(|e| Error::BadRequest(format!("non-UTF8 EncryptedID: {e}")))?;
                    let plaintext = self.decrypt_with_any(enc_xml)?;
                    let nid_doc = gamlastan::xml::uppsala::parse(&plaintext)
                        .map_err(|e| Error::Authn(format!("decrypted NameID is not XML: {e}")))?;
                    let nid = gamlastan::xml::deserialize::parse_saml::<
                        gamlastan::core::assertion::name_id::NameIdRef<'_>,
                    >(&nid_doc)
                    .map_err(|e| Error::Authn(format!("parsing decrypted NameID: {e}")))?
                    .to_owned();
                    (nid.value, nid.format)
                }
                None => return Err(Error::Authn("missing or unsupported NameID".into())),
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
            let values = attribute_string_values(&attr.values);
            if values.is_empty() {
                continue;
            }
            external.insert(attr.name.clone(), values.clone());
            if let Some(friendly) = &attr.friendly_name {
                external.insert(friendly.clone(), values);
            }
        }
        let mut internal_attrs = self.mapper.to_internal("saml", &external);

        // Optionally keep attributes the map does not know about, under a
        // normalized (lowercased) name — FriendlyName preferred. Iterates the
        // structured attributes (not the Name+FriendlyName-flattened map) so
        // each attribute is considered exactly once. Attributes whose
        // normalized key collides with a mapped internal attribute (of any
        // profile) are dropped, never merged. Leak-safety: frontends emit via
        // `from_internal`, which drops internal names absent from the
        // attribute map, so passthrough attributes cannot leave the proxy
        // without a frontend-side opt-in.
        if self.passthrough_unmapped_attributes {
            // Case-insensitive throughout: an IdP spelling a mapped name as
            // "MAIL"/"Mail" must not bypass the known-attribute check.
            let known: BTreeSet<String> = self
                .mapper
                .external_names("saml")
                .iter()
                .map(|s| s.to_lowercase())
                .collect();
            // Internal names across every profile (not just "saml"): an
            // unmapped attribute must never impersonate an internal attribute
            // the map defines for another profile either.
            let internal_names: BTreeSet<String> = self
                .mapper
                .attributes()
                .map(|(name, _)| name.to_lowercase())
                .collect();
            for attr in &saml_attributes {
                let known_attr = known.contains(&attr.name.to_lowercase())
                    || attr
                        .friendly_name
                        .as_deref()
                        .is_some_and(|f| known.contains(&f.to_lowercase()));
                if known_attr {
                    continue;
                }
                let values = attribute_string_values(&attr.values);
                if values.is_empty() {
                    continue;
                }
                let key = attr
                    .friendly_name
                    .as_deref()
                    .unwrap_or(&attr.name)
                    .to_lowercase();
                // Never merge into or fabricate a mapped internal attribute:
                // that would let an IdP inject values the proxy treats as
                // authoritative (e.g. the subject-id source attributes).
                if internal_attrs.contains_key(&key) || internal_names.contains(&key) {
                    continue;
                }
                let entry = internal_attrs.entry(key).or_default();
                for v in values {
                    if !entry.contains(&v) {
                        entry.push(v);
                    }
                }
            }
        }
        let subject_type = subject_type_from_name_id_format(name_id_format.as_deref());
        let subject_id = select_subject_id(
            self.mapper.as_ref(),
            &internal_attrs,
            &name_id,
            &idp_entity_id,
            self.is_dynamic_idp_selection(),
            subject_type,
            self.scope_subject_id_by_issuer,
        );

        // Only publish scopes after the SAML response has passed signature,
        // issuer, audience, correlation, time and replay validation. Python
        // receives a detached JSON copy through the existing decorations
        // boundary; it never receives the metadata object itself.
        ctx.decorate(
            KEY_PROVIDER_SCOPES,
            serde_json::Value::Array(
                provider_scopes
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        ctx.decorate(
            KEY_PROVIDER_ASSURANCE_CERTIFICATIONS,
            serde_json::Value::Array(
                provider_assurance_certifications
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );

        ctx.state.clear_namespace(&self.state_namespace);

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
            force_authn: false,
            is_passive: false,
        };
        Ok(BackendAction::AuthResponse(response))
    }
}

const SHIBBOLETH_METADATA_NS: &str = "urn:mace:shibboleth:metadata:1.0";
const SAML_METADATA_NS: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

fn trusted_assurance_certifications(entity: &EntityDescriptor) -> Vec<String> {
    let mut values = Vec::new();
    let entity_extensions = entity.extensions.as_ref().into_iter();
    let role_extensions = entity
        .idp_sso_descriptors()
        .iter()
        .filter_map(|role| role.sso_base.base.extensions.as_ref());
    for extensions in entity_extensions.chain(role_extensions) {
        let parsed = gamlastan::metadata::types::MdExtensions::from_extensions(extensions);
        for value in parsed.entity_attribute_values(
            gamlastan::profiles::swedenconnect::constants::ASSURANCE_CERTIFICATION_ATTR,
        ) {
            if !values.contains(&value) {
                values.push(value);
            }
        }
    }
    values
}

/// Extract direct Shibboleth `<Scope>` children of an IdP role's
/// `<md:Extensions>` from the original accepted metadata document.
fn trusted_scopes_from_metadata_xml(xml: &str, entity_id: &str) -> Vec<String> {
    let mut scopes = BTreeSet::new();
    let Ok(doc) = gamlastan::xml::parse_secure_metadata(xml) else {
        return Vec::new();
    };
    let Some(root) = doc.document_element() else {
        return Vec::new();
    };
    let Some(entity) = find_metadata_entity(&doc, root, entity_id) else {
        return Vec::new();
    };

    for role in doc.children_iter(entity) {
        let Some(role_element) = doc.element(role) else {
            continue;
        };
        if !role_element
            .name
            .matches(Some(SAML_METADATA_NS), "IDPSSODescriptor")
        {
            continue;
        }
        for extensions in doc.children_iter(role) {
            let Some(extensions_element) = doc.element(extensions) else {
                continue;
            };
            if !extensions_element
                .name
                .matches(Some(SAML_METADATA_NS), "Extensions")
            {
                continue;
            }
            for scope in doc.children_iter(extensions) {
                let Some(scope_element) = doc.element(scope) else {
                    continue;
                };
                if scope_element
                    .name
                    .matches(Some(SHIBBOLETH_METADATA_NS), "Scope")
                    && !doc
                        .children_iter(scope)
                        .any(|child| doc.element(child).is_some())
                {
                    let value = doc.text_content_deep(scope);
                    let value = value.trim();
                    if !value.is_empty() && !value.chars().any(char::is_control) {
                        scopes.insert(value.to_string());
                    }
                }
            }
        }
    }
    scopes.into_iter().collect()
}

fn find_metadata_entity<'a>(
    doc: &'a gamlastan::xml::uppsala::Document<'a>,
    node: gamlastan::xml::uppsala::NodeId,
    entity_id: &str,
) -> Option<gamlastan::xml::uppsala::NodeId> {
    let element = doc.element(node)?;
    if element
        .name
        .matches(Some(SAML_METADATA_NS), "EntityDescriptor")
    {
        return (doc.get_attribute(node, "entityID") == Some(entity_id)).then_some(node);
    }
    if !element
        .name
        .matches(Some(SAML_METADATA_NS), "EntitiesDescriptor")
    {
        return None;
    }
    doc.children_iter(node)
        .filter(|child| doc.element(*child).is_some())
        .find_map(|child| find_metadata_entity(doc, child, entity_id))
}

#[async_trait]
impl Backend for Saml2Backend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self) -> Vec<Route> {
        vec![
            Route::exact(format!("{}/acs", self.name), "acs"),
            Route::exact(format!("{}/disco", self.name), "disco"),
            Route::exact(format!("{}/metadata", self.name), "metadata"),
        ]
    }

    async fn start_auth(&self, ctx: &mut Context, request: InternalData) -> Result<Response> {
        // Persist the requester's authentication constraints so they survive
        // a discovery-service round-trip and reach `build_authn_redirect`.
        ctx.state.set_value(
            &self.state_namespace,
            "force_authn",
            serde_json::Value::Bool(request.force_authn),
        );
        ctx.state.set_value(
            &self.state_namespace,
            "is_passive",
            serde_json::Value::Bool(request.is_passive),
        );
        if self.request_subject {
            let subject = request
                .subject_id
                .as_deref()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    Error::Authn("step-up request has no linked-account identifier".into())
                })?;
            ctx.state
                .set_str(&self.state_namespace, "requested_subject", subject);
        }
        // Pick the target IdP. In MDQ mode the target can be chosen per
        // request — an `entityID` handed back by a discovery service
        // (SeamlessAccess/thiss.io) or a target-entity decoration left by a
        // hinting micro-service — falling back to the configured default;
        // with neither, the user is sent to the discovery service first.
        match &self.idp_metadata {
            IdpMetadata::Static { .. } => self.build_authn_redirect(ctx, None).await,
            IdpMetadata::Mdq(_) => {
                let decorated_target = || {
                    ctx.decoration(tunnelbana_core::context::KEY_TARGET_ENTITYID)
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                };
                // A step-up target comes solely from the SCIM-derived,
                // operator-mapped linked account. Never let an `entityID`
                // query parameter on the initial IdP's ACS request override
                // it. Ordinary backends retain discovery-parameter priority.
                let target = if self.request_subject {
                    decorated_target()
                } else {
                    ctx.request
                        .param("entityID")
                        .map(str::to_string)
                        .or_else(decorated_target)
                };
                match target.or_else(|| self.idp_entity_id.clone()) {
                    Some(target) => self.build_authn_redirect(ctx, Some(&target)).await,
                    None => {
                        if request.is_passive {
                            // Discovery needs user interaction; fail rather
                            // than silently drop IsPassive.
                            ctx.mark_interaction_required();
                            return Err(Error::Authn(
                                "IsPassive requested but IdP discovery requires user interaction"
                                    .into(),
                            ));
                        }
                        let disco = self.disco_srv.as_deref().ok_or_else(|| {
                            Error::Authn(
                                "no IdP selected and no discovery service configured".into(),
                            )
                        })?;
                        Ok(self.disco_redirect(disco))
                    }
                }
            }
        }
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<BackendAction> {
        match route_id {
            "acs" => self.handle_acs(ctx).await,
            // Discovery-service return: the chosen IdP arrives as ?entityID=.
            // Safe to act on directly because MDQ only resolves
            // signature-verified IdP-role entities.
            "disco" => {
                let target = ctx
                    .request
                    .query
                    .get("entityID")
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .ok_or_else(|| {
                        Error::BadRequest("discovery response carries no entityID".into())
                    })?;
                let redirect = self.build_authn_redirect(ctx, Some(&target)).await?;
                Ok(BackendAction::Respond(redirect))
            }
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

impl Saml2Backend {
    /// Create, (optionally) sign and redirect-encode an AuthnRequest to the
    /// target IdP's SSO endpoint. `target_idp` is required in MDQ mode and
    /// ignored in static mode. The chosen IdP is persisted so the ACS verifies
    /// the Response against the same IdP's metadata.
    async fn build_authn_redirect(
        &self,
        ctx: &mut Context,
        target_idp: Option<&str>,
    ) -> Result<Response> {
        let sso_url = match &self.idp_metadata {
            IdpMetadata::Static { sso_url, .. } => sso_url.clone(),
            IdpMetadata::Mdq(client) => {
                let target = target_idp
                    .ok_or_else(|| Error::Internal("MDQ mode without a target IdP".into()))?;
                let (entity, _, _) = client
                    .get(target)
                    .await
                    .map_err(|e| Error::Authn(format!("MDQ lookup for {target} failed: {e}")))?;
                let url = idp_sso_redirect_url(&entity)?;
                ctx.state
                    .set_str(&self.state_namespace, "idp_entity_id", target);
                url
            }
        };

        // A request-path micro-service (e.g. `accr`) may have selected the
        // AuthnContextClassRef to forward; absent that, no RequestedAuthnContext
        // is emitted (preserving prior behavior).
        let (authn_context_class_refs, authn_context_comparison) = read_target_accr(ctx);

        // The downstream requester's ForceAuthn/IsPassive constraints,
        // persisted by `start_auth` (false when absent), are forwarded
        // upstream so they are never silently dropped.
        let state_flag = |key: &str| {
            ctx.state
                .get_value(&self.state_namespace, key)
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        };

        let options = AuthnRequestOptions {
            sp_entity_id: self.sp_entity_id.clone(),
            acs_url: Some(self.acs_url.clone()),
            destination: Some(sso_url.clone()),
            protocol_binding: Some(constants::BINDING_HTTP_POST.to_string()),
            name_id_format: self.name_id_format.clone(),
            allow_create: true,
            force_authn: state_flag("force_authn").then_some(true),
            is_passive: state_flag("is_passive").then_some(true),
            authn_context_class_refs,
            authn_context_comparison,
            ..Default::default()
        };
        let mut req = sp_profile::create_authn_request(&options)
            .map_err(|e| Error::Internal(format!("creating AuthnRequest: {e}")))?;
        if self.request_subject {
            let subject = ctx
                .state
                .get_str(&self.state_namespace, "requested_subject")
                .ok_or_else(|| Error::State("step-up request subject is missing".into()))?;
            req.subject = Some(Subject {
                name_id: Some(NameIdOrEncryptedId::NameId(NameId {
                    value: subject,
                    format: Some(constants::NAMEID_UNSPECIFIED.to_string()),
                    name_qualifier: None,
                    sp_name_qualifier: None,
                    sp_provided_id: None,
                })),
                subject_confirmations: Vec::new(),
            });
        }
        ctx.state
            .set_str(&self.state_namespace, "authn_id", &req.base.id);

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
}

/// Read the AuthnContextClassRef list + comparison a request-path micro-service
/// (e.g. `accr`) asked to forward into the outgoing AuthnRequest. Returns empty
/// when nothing was selected, in which case no RequestedAuthnContext is emitted.
fn read_target_accr(
    ctx: &Context,
) -> (
    Vec<String>,
    Option<gamlastan::core::protocol::request::AuthnContextComparison>,
) {
    let refs = ctx
        .decoration(tunnelbana_core::context::KEY_TARGET_AUTHN_CONTEXT_CLASS_REF)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let comparison = ctx
        .decoration(tunnelbana_core::context::KEY_TARGET_ACCR_COMPARISON)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok());
    (refs, comparison)
}

fn subject_type_from_name_id_format(name_id_format: Option<&str>) -> SubjectType {
    match name_id_format {
        Some(constants::NAMEID_TRANSIENT) => SubjectType::Transient,
        _ => SubjectType::Persistent,
    }
}

fn decode_acs_response(
    request: &HttpRequestData,
    verifier: &SamlVerifier,
) -> Result<DecodedAcsResponse> {
    if request.query.contains_key("SAMLResponse") {
        let raw = RawQueryRequest::new(request);
        let decoded = gamlastan::bindings::redirect::redirect_decode(&raw)
            .map_err(|e| Error::BadRequest(format!("redirect decode: {e}")))?;

        let binding_signature_verified = if decoded.signature.is_some() || decoded.sig_alg.is_some()
        {
            match gamlastan::bindings::redirect::redirect_verify_signature(&decoded, verifier)
                .map_err(|e| {
                    Error::Authn(format!(
                        "SAML Response redirect signature verification: {e}"
                    ))
                })? {
                true => true,
                false => {
                    return Err(Error::Authn(
                        "SAML Response redirect signature is not valid".into(),
                    ))
                }
            }
        } else {
            false
        };

        let xml = String::from_utf8(decoded.saml_xml)
            .map_err(|e| Error::BadRequest(format!("SAMLResponse not UTF-8: {e}")))?;
        Ok(DecodedAcsResponse {
            xml,
            binding_signature_verified,
        })
    } else if let Some(saml_response) = request.form.get("SAMLResponse") {
        let xml_bytes = base64::engine::general_purpose::STANDARD
            .decode(saml_response.trim())
            .map_err(|e| Error::BadRequest(format!("base64 SAMLResponse: {e}")))?;
        let xml = String::from_utf8(xml_bytes)
            .map_err(|e| Error::BadRequest(format!("SAMLResponse not UTF-8: {e}")))?;
        Ok(DecodedAcsResponse {
            xml,
            binding_signature_verified: false,
        })
    } else {
        Err(Error::BadRequest("missing SAMLResponse".into()))
    }
}

/// Add a verified SAML object ID once.
///
/// The validator receives an unordered set-like list of IDs whose signatures
/// were already verified. Keep first-seen order for predictable diagnostics,
/// while avoiding duplicates when a Response has both XML and Redirect-binding
/// proof for the same target.
fn add_verified_signed_id(ids: &mut Vec<String>, id: &str) {
    if !ids.iter().any(|existing| existing == id) {
        ids.push(id.to_string());
    }
}

/// Verify every enveloped XML signature in `xml` and append referenced IDs.
///
/// `verify_enveloped` reports only the first signature in document order. ACS
/// validation needs all reference targets so gamlastan can distinguish "the
/// Response was signed" from "this exact Assertion was signed". The
/// `empty_uri_target_id` parameter handles the XML-DSig empty-reference case,
/// where the root element of the supplied document is the signed object.
fn extend_verified_xml_signature_ids(
    ids: &mut Vec<String>,
    verifier: &SamlVerifier,
    xml: &str,
    empty_uri_target_id: &str,
) -> Result<()> {
    let verify_results = verifier
        .verify_all_enveloped(xml)
        .map_err(|e| Error::Authn(format!("signature verification failed: {e}")))?;

    for verify_result in verify_results {
        let references = match verify_result {
            VerifyResult::Valid { references, .. } => references,
            VerifyResult::Invalid { reason } => {
                return Err(Error::Authn(format!(
                    "SAML XML signature is not valid: {reason}"
                )));
            }
        };

        for reference in references {
            // Same-document references are normally "#ID". An empty URI signs
            // the root of `xml`, supplied by the caller as `empty_uri_target_id`.
            let id = if reference.uri.is_empty() {
                Some(empty_uri_target_id)
            } else {
                reference.uri.strip_prefix('#')
            };
            if let Some(id) = id {
                add_verified_signed_id(ids, id);
            }
        }
    }

    Ok(())
}

fn cleartext_assertion_sources<'xml>(
    doc: &gamlastan::xml::uppsala::Document<'xml>,
    expected_assertion_count: usize,
) -> Result<Vec<&'xml str>> {
    let root = doc
        .document_element()
        .ok_or_else(|| Error::BadRequest("missing SAML Response element".into()))?;

    let mut assertions = Vec::new();
    for child in doc.children_iter(root) {
        let Some(element) = doc.element(child) else {
            continue;
        };
        if element.name.matches(Some(SAML_ASSERTION_NS), "Assertion") {
            let source = doc.node_source(child).ok_or_else(|| {
                Error::BadRequest("unable to recover original Assertion XML".into())
            })?;
            assertions.push(source);
        }
    }

    if assertions.len() != expected_assertion_count {
        return Err(Error::BadRequest(format!(
            "expected {expected_assertion_count} cleartext Assertion elements, found {}",
            assertions.len()
        )));
    }

    Ok(assertions)
}

fn standalone_assertion_document(assertion_xml: &str) -> String {
    format!(
        r#"<tb:Standalone xmlns:tb="urn:tunnelbana:standalone" xmlns:saml="{SAML_ASSERTION_NS}" xmlns:ds="{XMLDSIG_NS}">{assertion_xml}</tb:Standalone>"#
    )
}

fn select_subject_id(
    mapper: &AttributeMapper,
    internal_attrs: &BTreeMap<String, Vec<String>>,
    raw_name_id: &str,
    issuer: &str,
    dynamic_idp_selection: bool,
    subject_type: SubjectType,
    scope_by_issuer: bool,
) -> String {
    if dynamic_idp_selection {
        if scope_by_issuer {
            // Opt-in hardening (ADR 0048): every IdP-asserted identifier —
            // composed from attributes or a raw persistent/transient NameID —
            // is only stable within the IdP that issued it, so scope it by
            // issuer before treating it as the downstream subject identifier.
            if let Some(subject_id) = mapper.compose_subject_id(internal_attrs) {
                return scope_subject_id(issuer, &subject_id);
            }
            return scope_subject_id(issuer, raw_name_id);
        }
        // SATOSA-compatible default: composed identifiers are used unscoped;
        // only raw persistent NameIDs are issuer-scoped (ADR 0005).
        if let Some(subject_id) = mapper.compose_subject_id(internal_attrs) {
            return subject_id;
        }
        if subject_type == SubjectType::Persistent {
            return scope_subject_id(issuer, raw_name_id);
        }
    }
    raw_name_id.to_string()
}

// In federation mode, an IdP-asserted identifier (composed or raw NameID) is
// only stable within the IdP that issued it, so scope it by issuer before
// treating it as the downstream subject identifier.
fn scope_subject_id(issuer: &str, subject_id: &str) -> String {
    format!("{}:{issuer}:{subject_id}", issuer.len())
}

/// Flatten SAML attribute values into strings (drops XML/complex values).
fn attribute_string_values(values: &[AttributeValue]) -> Vec<String> {
    values
        .iter()
        .filter_map(|v| match v {
            AttributeValue::String(s) => Some(s.clone()),
            AttributeValue::Integer(i) => Some(i.to_string()),
            AttributeValue::Boolean(b) => Some(b.to_string()),
            AttributeValue::DateTime(s) => Some(s.clone()),
            AttributeValue::NameId(n) => Some(n.value.clone()),
            _ => None,
        })
        .collect()
}

/// If `xml`'s root element is an `EncryptedAssertion`/`EncryptedID` wrapper
/// (any prefix), return its inner content — the decrypted element — verbatim
/// (byte-identical, so enveloped signatures inside it stay verifiable).
/// Otherwise return the input unchanged.
fn unwrap_decrypted_wrapper(xml: &str) -> String {
    let trimmed = xml.trim();
    let is_wrapper = trimmed.strip_prefix('<').is_some_and(|rest| {
        let tag_end = rest.find(['>', ' ']).unwrap_or(rest.len());
        let name = &rest[..tag_end];
        let local = name.rsplit(':').next().unwrap_or(name);
        local == "EncryptedAssertion" || local == "EncryptedID"
    });
    if !is_wrapper {
        return xml.to_string();
    }
    let (Some(open_end), Some(close_start)) = (trimmed.find('>'), trimmed.rfind("</")) else {
        return xml.to_string();
    };
    if open_end + 1 >= close_start {
        return xml.to_string();
    }
    trimmed[open_end + 1..close_start].to_string()
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use gamlastan_mdq::RequiredRole;

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
    fn attribute_string_values_preserves_nameid_text() {
        let values = attribute_string_values(&[AttributeValue::NameId(NameId {
            value: "idp!sp!legacy".to_string(),
            format: Some(constants::NAMEID_PERSISTENT.to_string()),
            name_qualifier: Some("idp".to_string()),
            sp_name_qualifier: Some("sp".to_string()),
            sp_provided_id: None,
        })]);

        assert_eq!(values, vec!["idp!sp!legacy".to_string()]);
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

        // Default (SATOSA-compatible): composed identifier is used unscoped.
        let subject_id = select_subject_id(
            &mapper,
            &attrs,
            "opaque-name-id",
            "https://idp.example.com",
            true,
            SubjectType::Persistent,
            false,
        );
        assert_eq!(subject_id, "anna@example.com");

        // Opt-in scoping: a composed identifier is IdP-asserted too, so it
        // is issuer-scoped to stop one federation IdP asserting another
        // IdP's subject.
        let subject_id = select_subject_id(
            &mapper,
            &attrs,
            "opaque-name-id",
            "https://idp.example.com",
            true,
            SubjectType::Persistent,
            true,
        );
        assert_eq!(
            subject_id,
            scope_subject_id("https://idp.example.com", "anna@example.com")
        );
    }

    #[test]
    fn dynamic_idp_nameid_fallback_scoping() {
        // Persistent NameIDs are issuer-scoped in both modes (ADR 0005).
        for scope in [false, true] {
            let subject_id = select_subject_id(
                &empty_mapper(),
                &BTreeMap::new(),
                "opaque-name-id",
                "https://idp.example.com",
                true,
                SubjectType::Persistent,
                scope,
            );
            assert_eq!(
                subject_id,
                scope_subject_id("https://idp.example.com", "opaque-name-id")
            );
        }

        // Transient NameIDs: raw by default (SATOSA), scoped when opted in.
        let subject_id = select_subject_id(
            &empty_mapper(),
            &BTreeMap::new(),
            "opaque-name-id",
            "https://idp.example.com",
            true,
            SubjectType::Transient,
            false,
        );
        assert_eq!(subject_id, "opaque-name-id");

        let subject_id = select_subject_id(
            &empty_mapper(),
            &BTreeMap::new(),
            "opaque-name-id",
            "https://idp.example.com",
            true,
            SubjectType::Transient,
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
            "https://idp.example.com",
            false,
            SubjectType::Persistent,
            true,
        );

        assert_eq!(subject_id, "opaque-name-id");
    }

    #[test]
    fn extracts_direct_scopes_with_inherited_arbitrary_namespace_alias() {
        let xml = r#"
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            xmlns:scopealias="urn:mace:shibboleth:metadata:1.0"
            xmlns:other="urn:not-shibboleth"
            entityID="https://idp.example.org">
          <md:Extensions>
            <scopealias:Scope>entity-level.example</scopealias:Scope>
          </md:Extensions>
          <md:IDPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:Extensions>
              <scopealias:Scope regexp="false">example.org</scopealias:Scope>
              <scopealias:Scope> sub.example.org </scopealias:Scope>
              <scopealias:Scope>example.org</scopealias:Scope>
              <other:Scope>wrong-namespace.example</other:Scope>
              <other:Wrapper>
                <scopealias:Scope>nested.example</scopealias:Scope>
              </other:Wrapper>
            </md:Extensions>
            <md:SingleSignOnService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                Location="https://idp.example.org/sso"/>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>
        "#;
        assert_eq!(
            trusted_scopes_from_metadata_xml(xml, "https://idp.example.org"),
            ["example.org", "sub.example.org"]
        );
    }

    #[test]
    fn extracts_trusted_assurance_certifications_from_entity_metadata() {
        let xml = r#"
        <md:EntityDescriptor
            xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
            xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute"
            xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
            entityID="https://idp.example.org">
          <md:Extensions>
            <mdattr:EntityAttributes>
              <saml:Attribute Name="urn:oasis:names:tc:SAML:attribute:assurance-certification">
                <saml:AttributeValue>https://cert.example/eid</saml:AttributeValue>
              </saml:Attribute>
            </mdattr:EntityAttributes>
          </md:Extensions>
          <md:IDPSSODescriptor
              protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <md:SingleSignOnService
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                Location="https://idp.example.org/sso"/>
          </md:IDPSSODescriptor>
        </md:EntityDescriptor>
        "#;
        let doc = gamlastan::xml::uppsala::parse(xml).unwrap();
        let entity = gamlastan::xml::deserialize::parse_saml::<
            gamlastan::metadata::types::entity_descriptor::EntityDescriptorRef<'_>,
        >(&doc)
        .unwrap()
        .to_owned();
        assert_eq!(
            trusted_assurance_certifications(&entity),
            ["https://cert.example/eid"]
        );
    }

    #[test]
    fn malformed_or_dtd_scope_extensions_fail_soft() {
        for xml in [
            "<md:EntityDescriptor>",
            r#"<!DOCTYPE x [<!ENTITY e "scope.example">]><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.org">&e;</md:EntityDescriptor>"#,
        ] {
            assert!(trusted_scopes_from_metadata_xml(xml, "https://idp.example.org").is_empty());
        }
    }

    #[test]
    fn trusted_scope_cache_requests_a_coupled_reset_at_capacity() {
        let mut cache = TrustedScopeCache::default();
        cache.insert("first".into(), vec!["first.scope.example.org".into()]);
        cache.insert("second".into(), vec!["second.scope.example.org".into()]);

        assert!(!cache.requires_reset("first", 2));
        assert!(cache.requires_reset("third", 2));
        cache.clear();
        cache.insert("third".into(), vec!["third.scope.example.org".into()]);
        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.get("third"), ["third.scope.example.org"]);
    }

    #[derive(Clone)]
    struct ConcurrentMetadataFetcher {
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
        fetch_count: Arc<AtomicUsize>,
        delay: Duration,
    }

    impl MetadataFetcher for ConcurrentMetadataFetcher {
        async fn fetch(&self, url: &str) -> std::result::Result<Bytes, MdqError> {
            self.fetch_count.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            tokio::time::sleep(self.delay).await;
            self.active.fetch_sub(1, Ordering::SeqCst);

            let entity_id = url.rsplit('/').next().expect("MDQ entity path");
            let scope = format!("{entity_id}.scope.example.org");
            Ok(Bytes::from(format!(
                r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:scope="urn:mace:shibboleth:metadata:1.0" entityID="{entity_id}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:Extensions><scope:Scope>{scope}</scope:Scope></md:Extensions><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
            )))
        }
    }

    #[tokio::test]
    async fn scope_aware_mdq_lookups_are_concurrent_and_request_scoped() {
        let first_entity_id = "first".to_string();
        let second_entity_id = "second".to_string();
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fetcher = CapturingMetadataFetcher {
            inner: ConcurrentMetadataFetcher {
                active: Arc::clone(&active),
                max_active: Arc::clone(&max_active),
                fetch_count,
                delay: Duration::from_millis(25),
            },
        };
        let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
            .require_role(RequiredRole::Idp)
            .allow_unverified();
        let client = ScopeAwareMdqClient::new(client, MDQ_CACHE_CAPACITY);

        let (first, second) =
            tokio::join!(client.get(&first_entity_id), client.get(&second_entity_id));
        assert_eq!(first.unwrap().1, ["first.scope.example.org"]);
        assert_eq!(second.unwrap().1, ["second.scope.example.org"]);
        assert_eq!(max_active.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn scope_cache_reset_clears_mdq_cache_and_refetches_with_scopes() {
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fetcher = CapturingMetadataFetcher {
            inner: ConcurrentMetadataFetcher {
                active: Arc::new(AtomicUsize::new(0)),
                max_active: Arc::new(AtomicUsize::new(0)),
                fetch_count: Arc::clone(&fetch_count),
                delay: Duration::ZERO,
            },
        };
        let client = MdqClient::with_fetcher("https://mdq.example.org/", fetcher)
            .require_role(RequiredRole::Idp)
            .allow_unverified();
        let client = ScopeAwareMdqClient::new(client, 2);

        assert_eq!(
            client.get("first").await.unwrap().1,
            ["first.scope.example.org"]
        );
        assert_eq!(
            client.get("second").await.unwrap().1,
            ["second.scope.example.org"]
        );
        assert_eq!(client.client.cache_len(), 2);

        assert_eq!(
            client.get("third").await.unwrap().1,
            ["third.scope.example.org"]
        );
        assert_eq!(client.client.cache_len(), 1);
        assert_eq!(lock_unpoisoned(&client.trusted_scopes).entries.len(), 1);

        assert_eq!(
            client.get("first").await.unwrap().1,
            ["first.scope.example.org"]
        );
        assert_eq!(fetch_count.load(Ordering::SeqCst), 4);
    }
}
