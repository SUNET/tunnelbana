//! SAML2 frontend — the proxy acts as a SAML Identity Provider (IdP) to
//! downstream Service Providers. Wraps the `gamlastan` core: parse the inbound
//! AuthnRequest, and (after the backend authenticates the user) build, sign and
//! POST back a SAML Response.

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
use gamlastan::profiles::sso::idp as idp_profile;
use gamlastan::profiles::sso::web_browser::ResponseOptions;
use gamlastan::xml::serialize::SamlSerialize;

use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::Response;
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, Frontend, FrontendAction, Route};

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
    #[serde(default)]
    name_id_format: Option<String>,
    #[serde(default)]
    authn_context_class_ref: Option<String>,
}

fn default_assertion_lifetime() -> u64 {
    300
}
fn default_true() -> bool {
    true
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
    name_id_format: String,
    default_acr: Option<String>,
    mapper: Arc<AttributeMapper>,
}

impl Saml2Frontend {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn Frontend>> {
        let cfg: Saml2FrontendConfig = bx.parse_config()?;
        let module_base = bx.module_base();
        let idp_entity_id = cfg.idp_entity_id.clone().unwrap_or_else(|| module_base.clone());
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

        Ok(Box::new(Saml2Frontend {
            name: bx.name.clone(),
            idp_entity_id,
            sso_url,
            signer,
            cert_b64,
            assertion_lifetime_seconds: cfg.assertion_lifetime_seconds,
            sign_assertions: cfg.sign_assertions,
            sign_responses: cfg.sign_responses,
            name_id_format: cfg
                .name_id_format
                .unwrap_or_else(|| constants::NAMEID_PERSISTENT.to_string()),
            default_acr: cfg.authn_context_class_ref,
            mapper: bx.attribute_mapper.clone(),
        }))
    }

    fn handle_sso(&self, ctx: &mut Context) -> Result<FrontendAction> {
        // AuthnRequest via HTTP-Redirect (GET, deflated) or HTTP-POST (form).
        let (encoded, deflated) = if let Some(v) = ctx.request.query.get("SAMLRequest") {
            (v.clone(), true)
        } else if let Some(v) = ctx.request.form.get("SAMLRequest") {
            (v.clone(), false)
        } else {
            return Err(Error::BadRequest("missing SAMLRequest".into()));
        };
        let relay_state = ctx
            .request
            .param("RelayState")
            .map(|s| s.to_string());

        let xml = decode_authn_request(&encoded, deflated)?;
        let doc = gamlastan::xml::uppsala::parse(&xml)
            .map_err(|e| Error::BadRequest(format!("invalid AuthnRequest XML: {e}")))?;
        let authn_request = gamlastan::xml::deserialize::parse_saml::<
            gamlastan::core::protocol::request::AuthnRequestRef<'_>,
        >(&doc)
        .map_err(|e| Error::BadRequest(format!("parsing AuthnRequest: {e}")))?
        .to_owned();

        let processed = idp_profile::process_authn_request(&authn_request, None)
            .map_err(|e| Error::BadRequest(format!("AuthnRequest validation: {e}")))?;

        // Stash what we need to build the Response on the way back.
        ctx.state.set_str(&self.name, "request_id", &processed.request_id);
        ctx.state.set_str(&self.name, "sp_entity_id", &processed.sp_entity_id);
        ctx.state.set_str(&self.name, "acs_url", &processed.acs_url);
        if let Some(rs) = &relay_state {
            ctx.state.set_str(&self.name, "relay_state", rs);
        }

        Ok(FrontendAction::StartAuth {
            request: InternalData::request(processed.sp_entity_id),
            target_backend: None,
        })
    }
}

#[async_trait]
impl Frontend for Saml2Frontend {
    fn name(&self) -> &str {
        &self.name
    }

    fn register_endpoints(&self, _backend_names: &[String]) -> Vec<Route> {
        vec![
            Route::new(&regex::escape(&format!("{}/sso", self.name)), "sso"),
            Route::new(&regex::escape(&format!("{}/metadata", self.name)), "metadata"),
        ]
    }

    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<FrontendAction> {
        match route_id {
            "sso" => self.handle_sso(ctx),
            "metadata" => Ok(FrontendAction::Respond(
                Response::new(200)
                    .with_header("content-type", "application/samlmetadata+xml; charset=utf-8")
                    .with_body(self.build_metadata()?.into_bytes()),
            )),
            other => Err(Error::NoBoundEndpoint(other.to_string())),
        }
    }

    async fn handle_authn_response(
        &self,
        ctx: &mut Context,
        response: InternalData,
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

        // Map internal attributes to SAML attributes.
        let external = self.mapper.from_internal("saml", &response.attributes);
        let attributes: Vec<Attribute> = external
            .into_iter()
            .map(|(name, values)| Attribute {
                name,
                name_format: Some(constants::ATTRNAME_FORMAT_BASIC.to_string()),
                friendly_name: None,
                values: values.into_iter().map(AttributeValue::String).collect(),
            })
            .collect();

        let subject = response
            .subject_id
            .clone()
            .or_else(|| self.mapper.compose_subject_id(&response.attributes))
            .ok_or_else(|| Error::Authn("no subject identifier for SAML assertion".into()))?;

        let name_id = NameId {
            value: subject,
            format: Some(self.name_id_format.clone()),
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

        let signed = self.sign_response_xml(
            &xml,
            &saml_response.base.id,
            assertion_id.as_deref(),
        )?;

        let relay = relay_state.as_deref().map(gamlastan::bindings::relay_state::RelayState::echo);
        let html = gamlastan::bindings::post::post_encode(
            signed.as_bytes(),
            false,
            &acs_url,
            relay.as_ref(),
        );

        ctx.state.clear_namespace(&self.name);
        Ok(Response::html(html)
            .with_header("cache-control", "no-cache, no-store"))
    }

    async fn handle_backend_error(&self, _ctx: &mut Context, error: &Error) -> Result<Response> {
        Ok(Response::text(500, format!("authentication failed: {error}")))
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
                name_id_formats: vec![
                    constants::NAMEID_PERSISTENT.to_string(),
                    constants::NAMEID_TRANSIENT.to_string(),
                    constants::NAMEID_EMAIL.to_string(),
                ],
            },
            want_authn_requests_signed: Some(false),
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
            organization: None,
            contact_persons: vec![],
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
