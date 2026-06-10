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
use gamlastan::core::assertion::name_id::NameIdOrEncryptedId;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlDecryptor, SamlSigner, SamlVerifier};
use gamlastan::metadata::EntityDescriptor;
use gamlastan::profiles::sso::sp as sp_profile;
use gamlastan::profiles::sso::web_browser::{self, AuthnRequestOptions};
use gamlastan::security::config::SecurityConfig;
use gamlastan::security::validation::{AssertionValidator, ValidationParams};
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan_mdq::MdqClient;

use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext, Route};
use tunnelbana_core::util::now_rfc3339;

use crate::saml_common::{build_mdq_client, extract_cert_b64, verifier_from_cert_ders, MdqConfig};

/// XML-DSig RSA-SHA256 signature algorithm URI (for signed redirect requests).
const SIGALG_RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SAML_ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

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
    },
    /// Resolved per request from an MDQ server, keyed by `idp_entity_id`.
    Mdq(MdqClient),
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
    strict: bool,
    accepted_time_diff_secs: Option<u64>,
    passthrough_unmapped_attributes: bool,
    allow_unsolicited: bool,
    organization: Option<gamlastan::metadata::types::organization::Organization>,
    contact_persons: Vec<gamlastan::metadata::types::contact::ContactPerson>,
    /// One decryptor per configured encryption key (bergshamra only uses the
    /// first RSA key of a manager, so rotation = try each in turn).
    decryptors: Vec<SamlDecryptor>,
    /// Certs published with `use="encryption"` in SP metadata.
    encryption_certs_b64: Vec<String>,
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
            Some(mdq_cfg) => {
                if cfg.idp_entity_id.is_none() && cfg.disco_srv.is_none() {
                    return Err(Error::Config(
                        "saml2 backend in MDQ mode requires idp_entity_id and/or disco_srv"
                            .into(),
                    ));
                }
                IdpMetadata::Mdq(build_mdq_client(mdq_cfg)?)
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

        // One SamlDecryptor per encryption key (try-each rotation).
        let mut decryptors = Vec::new();
        let mut encryption_certs_b64 = Vec::new();
        for keypair in &cfg.encryption_keypairs {
            let key_pem = std::fs::read(&keypair.key_path).map_err(|e| {
                Error::Config(format!("reading encryption_keypairs.key_path: {e}"))
            })?;
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

        Ok(Box::new(Saml2Backend {
            name: bx.name.clone(),
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
            strict: cfg.security.as_deref() == Some("strict"),
            accepted_time_diff_secs: cfg.accepted_time_diff_secs,
            passthrough_unmapped_attributes: cfg.passthrough_unmapped_attributes,
            allow_unsolicited: cfg.allow_unsolicited,
            organization: cfg.organization.as_ref().map(|o| o.to_organization()),
            contact_persons: crate::saml_metadata::contact_persons(&cfg.contact_person)?,
            decryptors,
            encryption_certs_b64,
            mapper: bx.attribute_mapper.clone(),
        }))
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

    fn security_config(&self) -> SecurityConfig {
        let mut cfg = if self.strict {
            SecurityConfig::strict()
        } else {
            SecurityConfig::permissive()
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
            base.key_descriptors.push(KeyDescriptor::encryption(key_info));
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
            IdpMetadata::Static { verifier, .. } => {
                let expected = self.idp_entity_id.as_deref().ok_or_else(|| {
                    Error::Internal("static mode without idp_entity_id".into())
                })?;
                self.process_acs(ctx, verifier, expected)
            }
            IdpMetadata::Mdq(client) => {
                // Verify against the cert for the IdP we actually sent the request
                // to (persisted at start_auth) — not the still-unverified issuer
                // claimed by the Response. Falls back to the configured default.
                let selected = ctx
                    .state
                    .get_str(&self.name, "idp_entity_id")
                    .or_else(|| self.idp_entity_id.clone())
                    .ok_or_else(|| {
                        Error::Authn("no IdP selected for this flow".into())
                    })?;
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
        let cleartext_assertions_xml = cleartext_assertion_sources(&doc, response.assertions.len())?;

        // 2) Signature acceptance rule, spanning the encryption boundary
        //    (supersedes plain want_assertions_or_response_signed): either the
        //    Response envelope is protected and verifies — by an XML signature
        //    on the Response element or by a valid Redirect-binding detached
        //    signature over the whole message, both of which cover any
        //    EncryptedAssertion ciphertext too — or *every* assertion
        //    (cleartext and decrypted alike) carries its own signature that
        //    verifies on the XML it travelled in: the original subtree for
        //    cleartext assertions, the decrypted plaintext for encrypted ones.
        let envelope_verified = if response.base.has_signature {
            match verifier
                .verify_enveloped(&xml)
                .map_err(|e| Error::Authn(format!("signature verification failed: {e}")))?
            {
                gamlastan::crypto::VerifyResult::Invalid { reason } => {
                    return Err(Error::Authn(format!(
                        "SAML Response signature is not valid: {reason}"
                    )));
                }
                _ => true,
            }
        } else {
            binding_signature_verified
        };

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
                if let gamlastan::crypto::VerifyResult::Invalid { reason } = verifier
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

        // Decrypt EncryptedAssertions and splice them into the assertion
        // list. When neither an XML Response signature nor a Redirect-binding
        // signature verified, each decrypted assertion must carry a signature
        // that verifies on its decrypted plaintext.
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

            if !envelope_verified {
                if !assertion.has_signature {
                    return Err(Error::Authn(
                        "SAML Response is unsigned and a decrypted assertion is unsigned"
                            .into(),
                    ));
                }
                if let gamlastan::crypto::VerifyResult::Invalid { reason } = verifier
                    .verify_enveloped(&plaintext)
                    .map_err(|e| Error::Authn(format!("signature verification failed: {e}")))?
                {
                    return Err(Error::Authn(format!(
                        "decrypted assertion signature is not valid: {reason}"
                    )));
                }
            }
            response.assertions.push(assertion);
        }

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
        let expected_id = match ctx.state.get_str(&self.name, "authn_id") {
            Some(id) => Some(id),
            None if self.allow_unsolicited && response.base.in_response_to.is_none() => None,
            None if self.allow_unsolicited => {
                return Err(Error::Authn(
                    "SAML Response carries InResponseTo but no AuthnRequest is in flight"
                        .into(),
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
                Some(NameIdOrEncryptedId::NameId(nid)) => {
                    (nid.value.clone(), nid.format.clone())
                }
                Some(NameIdOrEncryptedId::EncryptedId(eid)) => {
                    let enc_xml = std::str::from_utf8(&eid.raw).map_err(|e| {
                        Error::BadRequest(format!("non-UTF8 EncryptedID: {e}"))
                    })?;
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
        // each attribute is considered exactly once. Mapped internal values
        // are never clobbered; collisions merge with order-preserving dedupe.
        // Leak-safety: frontends emit via `from_internal`, which drops
        // internal names absent from the attribute map, so passthrough
        // attributes cannot leave the proxy without a frontend-side opt-in.
        if self.passthrough_unmapped_attributes {
            let known = self.mapper.external_names("saml");
            for attr in &saml_attributes {
                let known_attr = known.contains(attr.name.as_str())
                    || attr
                        .friendly_name
                        .as_deref()
                        .is_some_and(|f| known.contains(f));
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
            Route::new(&regex::escape(&format!("{}/disco", self.name)), "disco"),
            Route::new(
                &regex::escape(&format!("{}/metadata", self.name)),
                "metadata",
            ),
        ]
    }

    async fn start_auth(&self, ctx: &mut Context, _request: InternalData) -> Result<Response> {
        // Pick the target IdP. In MDQ mode the target can be chosen per
        // request — an `entityID` handed back by a discovery service
        // (SeamlessAccess/thiss.io) — falling back to the configured default;
        // with neither, the user is sent to the discovery service first.
        match &self.idp_metadata {
            IdpMetadata::Static { .. } => self.build_authn_redirect(ctx, None).await,
            IdpMetadata::Mdq(_) => {
                let target = ctx.request.param("entityID").map(str::to_string);
                match target.or_else(|| self.idp_entity_id.clone()) {
                    Some(target) => self.build_authn_redirect(ctx, Some(&target)).await,
                    None => {
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
                let entity = client
                    .get(target)
                    .await
                    .map_err(|e| Error::Authn(format!("MDQ lookup for {target} failed: {e}")))?;
                let url = idp_sso_redirect_url(&entity)?;
                ctx.state.set_str(&self.name, "idp_entity_id", target);
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
}

fn subject_type_from_name_id_format(name_id_format: Option<&str>) -> SubjectType {
    match name_id_format {
        Some(constants::NAMEID_TRANSIENT) => SubjectType::Transient,
        _ => SubjectType::Persistent,
    }
}

fn decode_acs_response(request: &HttpRequestData, verifier: &SamlVerifier) -> Result<DecodedAcsResponse> {
    if request.query.contains_key("SAMLResponse") {
        let raw = RawQueryRequest::new(request);
        let decoded = gamlastan::bindings::redirect::redirect_decode(&raw)
            .map_err(|e| Error::BadRequest(format!("redirect decode: {e}")))?;

        let binding_signature_verified = if decoded.signature.is_some() || decoded.sig_alg.is_some() {
            match gamlastan::bindings::redirect::redirect_verify_signature(&decoded, verifier)
                .map_err(|e| {
                    Error::Authn(format!(
                        "SAML Response redirect signature verification: {e}"
                    ))
                })?
            {
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

/// Flatten SAML attribute values into strings (drops XML/complex values).
fn attribute_string_values(values: &[AttributeValue]) -> Vec<String> {
    values
        .iter()
        .filter_map(|v| match v {
            AttributeValue::String(s) => Some(s.clone()),
            AttributeValue::Integer(i) => Some(i.to_string()),
            AttributeValue::Boolean(b) => Some(b.to_string()),
            AttributeValue::DateTime(s) => Some(s.clone()),
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
