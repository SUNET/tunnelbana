//! SAML round-trip: our SAML2 **frontend** (IdP) signs a Response that our SAML2
//! **backend** (SP) verifies, validates (gamlastan's 32-check `process_response`)
//! and maps to internal attributes. Uses real RSA cert/key fixtures so the XML
//! signature is genuinely produced and verified.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{
    Backend, BackendAction, BuildContext, Frontend, FrontendAction, NullHttpClient,
};
use tunnelbana_core::state::State;

const BASE: &str = "https://proxy.example.com";
const IDP_ENTITY: &str = "https://proxy.example.com/IdP";
const SP_ENTITY: &str = "https://proxy.example.com/SP";
const ACS_URL: &str = "https://proxy.example.com/SP/acs";

fn testdata(file: &str) -> String {
    format!("{}/testdata/{}", env!("CARGO_MANIFEST_DIR"), file)
}

fn mapper() -> Arc<AttributeMapper> {
    Arc::new(
        AttributeMapper::from_toml(
            r#"
            [attributes.mail]
            saml = ["mail", "emailAddress"]
            [attributes.givenname]
            saml = ["givenName"]
        "#,
        )
        .unwrap(),
    )
}

fn build_ctx(name: &str, config: serde_json::Value) -> BuildContext {
    BuildContext {
        name: name.to_string(),
        base_url: BASE.to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: Arc::new(NullHttpClient),
        secret: "saml-test-secret".to_string(),
        previous_secrets: Vec::new(),
    }
}

fn frontend() -> Box<dyn Frontend> {
    frontend_with(serde_json::Map::new())
}

/// Build the IdP frontend with the standard test config plus `extra` overrides.
fn frontend_with(extra: serde_json::Map<String, serde_json::Value>) -> Box<dyn Frontend> {
    let mut config = serde_json::json!({
        "idp_key_path": testdata("idp-key.pem"),
        "idp_cert_path": testdata("idp-cert.pem"),
        "sign_assertions": true,
        "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "metadata": { "local": [testdata("sp-metadata.xml")] }
    });
    config.as_object_mut().unwrap().extend(extra);
    tunnelbana_plugins::saml2_frontend::Saml2Frontend::build(&build_ctx("IdP", config)).unwrap()
}

fn backend() -> Box<dyn Backend> {
    let config = serde_json::json!({
        "sp_key_path": testdata("sp-key.pem"),
        "idp_entity_id": IDP_ENTITY,
        "idp_sso_url": "https://proxy.example.com/IdP/sso",
        "idp_cert_path": testdata("idp-cert.pem"),
        "security": "permissive"
    });
    tunnelbana_plugins::saml2_backend::Saml2Backend::build(&build_ctx("SP", config)).unwrap()
}

/// Build an AuthnRequest XML as a downstream SP would, base64 for HTTP-POST.
fn downstream_authn_request() -> (String, String) {
    use gamlastan::profiles::sso::sp;
    use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
    use gamlastan::xml::serialize::SamlSerialize;

    let opts = AuthnRequestOptions {
        sp_entity_id: SP_ENTITY.to_string(),
        acs_url: Some(ACS_URL.to_string()),
        destination: Some("https://proxy.example.com/IdP/sso".to_string()),
        protocol_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
        allow_create: true,
        ..Default::default()
    };
    let req = sp::create_authn_request(&opts).unwrap();
    let id = req.base.id.clone();
    let xml = req.to_xml_string().unwrap();
    let b64 = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
    (id, b64)
}

/// Pull the SAMLResponse value out of the auto-submit POST form HTML.
fn extract_saml_response(html: &str) -> String {
    let marker = r#"name="SAMLResponse" value=""#;
    let start = html.find(marker).expect("SAMLResponse field") + marker.len();
    let end = html[start..].find('"').expect("closing quote") + start;
    html[start..end].to_string()
}

fn redirect_response_url(xml: &str, sign_query: bool) -> String {
    use gamlastan::bindings::redirect::{redirect_encode, RedirectEncodeParams};
    use gamlastan::crypto::keys::loader;
    use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};

    let key_pem = std::fs::read(testdata("idp-key.pem")).unwrap();
    let mut key = loader::load_pem_auto(&key_pem, None).unwrap();
    key.usage = KeyUsage::Sign;
    let mut km = KeysManager::new();
    km.add_key(key);
    let signer = SamlSigner::new(km);
    let query_signer = if sign_query {
        Some((&signer, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"))
    } else {
        None
    };

    redirect_encode(&RedirectEncodeParams {
        saml_xml: xml.as_bytes(),
        is_request: false,
        destination: ACS_URL,
        relay_state: None,
        signer: query_signer,
    })
    .unwrap()
}

async fn redirect_acs_result(
    sp: &dyn Backend,
    url: &str,
    req_id: Option<&str>,
) -> tunnelbana_core::error::Result<BackendAction> {
    let query: BTreeMap<String, String> =
        form_urlencoded::parse(url.split_once('?').map(|(_, q)| q).unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    let mut sp_ctx = Context::new(
        HttpRequestData {
            path: "SP/acs".into(),
            method: "GET".into(),
            uri: url.to_string(),
            query,
            ..Default::default()
        },
        State::new(),
    );
    if let Some(id) = req_id {
        sp_ctx.state.set_str("SP", "authn_id", id);
    }
    sp.handle_endpoint(&mut sp_ctx, "acs").await
}

#[tokio::test]
async fn saml_idp_signs_and_sp_verifies() {
    let idp = frontend();
    let sp = backend();

    // 1) Downstream SP sends an AuthnRequest (HTTP-POST) to our IdP frontend.
    let (req_id, authn_b64) = downstream_authn_request();
    let mut idp_ctx = Context::new(
        HttpRequestData {
            path: "IdP/sso".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLRequest".to_string(), authn_b64)]),
            ..Default::default()
        },
        State::new(),
    );
    let action = idp.handle_endpoint(&mut idp_ctx, "sso").await.unwrap();
    assert!(matches!(action, FrontendAction::StartAuth { .. }));

    // 2) Backend "authenticated" the user — IdP frontend renders a signed Response.
    let mut authenticated = InternalData {
        subject_id: Some("anna-persistent-id".to_string()),
        auth_info: AuthenticationInformation {
            auth_class_ref: Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".into()),
            timestamp: None,
            issuer: Some("urn:upstream".into()),
        },
        ..Default::default()
    };
    authenticated
        .attributes
        .insert("mail".into(), vec!["anna@example.com".into()]);
    authenticated
        .attributes
        .insert("givenname".into(), vec!["Anna".into()]);

    let resp: Response = idp
        .handle_authn_response(&mut idp_ctx, authenticated)
        .await
        .unwrap();
    let html = String::from_utf8(resp.body).unwrap();
    assert!(html.contains("SAMLResponse"));
    let saml_response_b64 = extract_saml_response(&html);

    // 3) The SP backend receives that Response at its ACS, verifies + validates.
    let mut sp_ctx = Context::new(
        HttpRequestData {
            path: "SP/acs".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLResponse".to_string(), saml_response_b64)]),
            ..Default::default()
        },
        State::new(),
    );
    // The SP would have stored its AuthnRequest id; mirror the IdP's InResponseTo.
    sp_ctx.state.set_str("SP", "authn_id", &req_id);

    let action = sp.handle_endpoint(&mut sp_ctx, "acs").await.unwrap();
    let internal = match action {
        BackendAction::AuthResponse(d) => d,
        _ => panic!("expected AuthResponse"),
    };

    assert_eq!(internal.subject_id.as_deref(), Some("anna-persistent-id"));
    assert_eq!(internal.subject_type, SubjectType::Persistent);
    assert_eq!(internal.attr_first("mail"), Some("anna@example.com"));
    assert_eq!(internal.attr_first("givenname"), Some("Anna"));
    assert_eq!(internal.auth_info.issuer.as_deref(), Some(IDP_ENTITY));
}

#[tokio::test]
async fn saml_backend_rejects_tampered_response() {
    let idp = frontend();
    let sp = backend();

    let (req_id, authn_b64) = downstream_authn_request();
    let mut idp_ctx = Context::new(
        HttpRequestData {
            path: "IdP/sso".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLRequest".to_string(), authn_b64)]),
            ..Default::default()
        },
        State::new(),
    );
    idp.handle_endpoint(&mut idp_ctx, "sso").await.unwrap();

    let mut authenticated = InternalData {
        subject_id: Some("anna".into()),
        ..Default::default()
    };
    authenticated
        .attributes
        .insert("mail".into(), vec!["anna@example.com".into()]);
    let resp = idp
        .handle_authn_response(&mut idp_ctx, authenticated)
        .await
        .unwrap();
    let html = String::from_utf8(resp.body).unwrap();
    let b64 = extract_saml_response(&html);

    // Tamper: decode, flip an attribute value, re-encode (breaks the signature).
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap(),
    )
    .unwrap();
    let tampered_xml = xml.replace("anna@example.com", "attacker@evil.example");
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(tampered_xml.as_bytes());

    let mut sp_ctx = Context::new(
        HttpRequestData {
            path: "SP/acs".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLResponse".to_string(), tampered_b64)]),
            ..Default::default()
        },
        State::new(),
    );
    sp_ctx.state.set_str("SP", "authn_id", &req_id);

    let result = sp.handle_endpoint(&mut sp_ctx, "acs").await;
    assert!(result.is_err(), "tampered Response must be rejected");
}

#[tokio::test]
async fn saml_backend_accepts_signed_redirect_response() {
    let sp = backend();
    let req_id = "_redir_resp1";
    let b64 = signed_response_with(
        Some(req_id),
        0,
        vec![gamlastan::core::assertion::attribute::Attribute {
            name: "mail".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![
                gamlastan::core::assertion::attribute::AttributeValue::String(
                    "anna@example.com".to_string(),
                ),
            ],
        }],
    );
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap(),
    )
    .unwrap();
    let url = redirect_response_url(&xml, true);

    let action = redirect_acs_result(sp.as_ref(), &url, Some(req_id))
        .await
        .unwrap();
    let internal = match action {
        BackendAction::AuthResponse(d) => d,
        _ => panic!("expected AuthResponse"),
    };

    assert_eq!(internal.subject_id.as_deref(), Some("anna-persistent-id"));
    assert_eq!(internal.attr_first("mail"), Some("anna@example.com"));
}

#[tokio::test]
async fn saml_backend_rejects_tampered_redirect_response_signature() {
    let sp = backend();
    let req_id = "_redir_resp2";
    let b64 = signed_response_with(Some(req_id), 0, vec![]);
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap(),
    )
    .unwrap();
    let url = redirect_response_url(&xml, true);

    let sig_start = url.find("&Signature=").unwrap() + "&Signature=".len();
    let mut tampered = url[..sig_start].to_string();
    let sig = &url[sig_start..];
    let flipped: String = sig
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i < 8 {
                if c == 'A' {
                    'B'
                } else {
                    'A'
                }
            } else {
                c
            }
        })
        .collect();
    tampered.push_str(&flipped);

    assert!(
        redirect_acs_result(sp.as_ref(), &tampered, Some(req_id))
            .await
            .is_err(),
        "tampered redirect signature must be rejected"
    );
}

// ---------------------------------------------------------------------------
// F1: SP metadata store + AuthnRequest validation
// ---------------------------------------------------------------------------

/// An AuthnRequest from an issuer/ACS pair of the caller's choosing, base64
/// for HTTP-POST.
fn authn_request_from(issuer: &str, acs_url: &str) -> String {
    use gamlastan::profiles::sso::sp;
    use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
    use gamlastan::xml::serialize::SamlSerialize;

    let opts = AuthnRequestOptions {
        sp_entity_id: issuer.to_string(),
        acs_url: Some(acs_url.to_string()),
        destination: Some("https://proxy.example.com/IdP/sso".to_string()),
        protocol_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
        allow_create: true,
        ..Default::default()
    };
    let req = sp::create_authn_request(&opts).unwrap();
    let xml = req.to_xml_string().unwrap();
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

fn post_sso_ctx(authn_b64: String) -> Context {
    Context::new(
        HttpRequestData {
            path: "IdP/sso".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLRequest".to_string(), authn_b64)]),
            ..Default::default()
        },
        State::new(),
    )
}

#[tokio::test]
async fn saml_frontend_rejects_unknown_sp() {
    let idp = frontend();
    let authn_b64 = authn_request_from("https://evil.example.com", "https://evil.example.com/acs");
    let mut ctx = post_sso_ctx(authn_b64);

    let action = idp.handle_endpoint(&mut ctx, "sso").await.unwrap();
    match action {
        FrontendAction::Respond(resp) => assert_eq!(resp.status, 403),
        _ => panic!("unknown SP must get a 403, not start authentication"),
    }
}

#[tokio::test]
async fn saml_frontend_rejects_acs_not_in_metadata() {
    let idp = frontend();
    // Known SP issuer, but the ACS points somewhere not registered for it.
    let authn_b64 = authn_request_from(SP_ENTITY, "https://attacker.example.com/acs");
    let mut ctx = post_sso_ctx(authn_b64);

    let result = idp.handle_endpoint(&mut ctx, "sso").await;
    assert!(result.is_err(), "ACS not in SP metadata must be rejected");
}

#[tokio::test]
async fn saml_frontend_rejects_unsigned_request_when_signing_required() {
    let idp = frontend_with(
        serde_json::json!({ "want_authn_requests_signed": true })
            .as_object()
            .unwrap()
            .clone(),
    );
    let (_, authn_b64) = downstream_authn_request();
    let mut ctx = post_sso_ctx(authn_b64);

    let action = idp.handle_endpoint(&mut ctx, "sso").await.unwrap();
    match action {
        FrontendAction::Respond(resp) => assert_eq!(resp.status, 403),
        _ => panic!("unsigned AuthnRequest must be rejected when signing is required"),
    }
}

/// Build a signed HTTP-Redirect AuthnRequest URL using the SP's test key.
fn signed_redirect_url() -> String {
    use gamlastan::crypto::keys::loader;
    use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};
    use gamlastan::profiles::sso::sp;
    use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
    use gamlastan::xml::serialize::SamlSerialize;

    let key_pem = std::fs::read(testdata("sp-key.pem")).unwrap();
    let mut key = loader::load_pem_auto(&key_pem, None).unwrap();
    key.usage = KeyUsage::Sign;
    let mut km = KeysManager::new();
    km.add_key(key);
    let signer = SamlSigner::new(km);

    let opts = AuthnRequestOptions {
        sp_entity_id: SP_ENTITY.to_string(),
        acs_url: Some(ACS_URL.to_string()),
        destination: Some("https://proxy.example.com/IdP/sso".to_string()),
        protocol_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
        allow_create: true,
        ..Default::default()
    };
    let req = sp::create_authn_request(&opts).unwrap();
    let xml = req.to_xml_string().unwrap();

    gamlastan::bindings::redirect::redirect_encode(
        &gamlastan::bindings::redirect::RedirectEncodeParams {
            saml_xml: xml.as_bytes(),
            is_request: true,
            destination: "https://proxy.example.com/IdP/sso",
            relay_state: None,
            signer: Some((&signer, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")),
        },
    )
    .unwrap()
}

fn redirect_sso_ctx(url: &str) -> Context {
    let query: BTreeMap<String, String> =
        form_urlencoded::parse(url.split_once('?').map(|(_, q)| q).unwrap_or("").as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    Context::new(
        HttpRequestData {
            path: "IdP/sso".into(),
            method: "GET".into(),
            uri: url.to_string(),
            query,
            ..Default::default()
        },
        State::new(),
    )
}

#[tokio::test]
async fn saml_frontend_accepts_signed_redirect_request() {
    let idp = frontend_with(
        serde_json::json!({ "want_authn_requests_signed": true })
            .as_object()
            .unwrap()
            .clone(),
    );
    let url = signed_redirect_url();
    let mut ctx = redirect_sso_ctx(&url);

    let action = idp.handle_endpoint(&mut ctx, "sso").await.unwrap();
    assert!(
        matches!(action, FrontendAction::StartAuth { .. }),
        "validly signed redirect AuthnRequest must start authentication"
    );
}

#[tokio::test]
async fn saml_frontend_rejects_tampered_redirect_signature() {
    let idp = frontend_with(
        serde_json::json!({ "want_authn_requests_signed": true })
            .as_object()
            .unwrap()
            .clone(),
    );
    let url = signed_redirect_url();
    // Corrupt the signature value while keeping it valid base64/URL encoding.
    let sig_start = url.find("&Signature=").unwrap() + "&Signature=".len();
    let mut tampered = url[..sig_start].to_string();
    let sig = &url[sig_start..];
    let flipped: String = sig
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i < 8 {
                if c == 'A' {
                    'B'
                } else {
                    'A'
                }
            } else {
                c
            }
        })
        .collect();
    tampered.push_str(&flipped);
    let mut ctx = redirect_sso_ctx(&tampered);

    match idp.handle_endpoint(&mut ctx, "sso").await {
        Ok(FrontendAction::Respond(resp)) => assert_eq!(resp.status, 403),
        Ok(_) => panic!("tampered redirect signature must be rejected"),
        Err(_) => {} // also acceptable: decode-level rejection
    }
}

// ---------------------------------------------------------------------------
// B3: organization / contact_person metadata publishing
// ---------------------------------------------------------------------------

fn org_contact_json() -> serde_json::Map<String, serde_json::Value> {
    serde_json::json!({
        "organization": {
            "name": "SUNET",
            "display_name": "Sunet",
            "url": "https://sunet.se"
        },
        "contact_person": [
            { "contact_type": "technical", "email_address": "noc@sunet.se", "given_name": "Ops" }
        ]
    })
    .as_object()
    .unwrap()
    .clone()
}

fn parse_entity(xml: &str) -> gamlastan::metadata::types::entity_descriptor::EntityDescriptor {
    let doc = gamlastan::xml::uppsala::parse(xml).unwrap();
    gamlastan::xml::deserialize::parse_saml::<
        gamlastan::metadata::types::entity_descriptor::EntityDescriptorRef<'_>,
    >(&doc)
    .unwrap()
    .to_owned()
}

#[tokio::test]
async fn saml_frontend_metadata_carries_organization_and_contact() {
    let idp = frontend_with(org_contact_json());
    let mut ctx = Context::new(HttpRequestData::default(), State::new());
    let action = idp.handle_endpoint(&mut ctx, "metadata").await.unwrap();
    let xml = match action {
        FrontendAction::Respond(resp) => String::from_utf8(resp.body).unwrap(),
        _ => panic!("expected metadata response"),
    };

    let entity = parse_entity(&xml);
    let org = entity.organization.expect("Organization in IdP metadata");
    assert_eq!(org.organization_names[0].value, "SUNET");
    assert_eq!(entity.contact_persons.len(), 1);
    assert_eq!(
        entity.contact_persons[0].email_addresses,
        vec!["noc@sunet.se".to_string()]
    );
}

#[tokio::test]
async fn saml_backend_metadata_carries_organization_contact_and_accurate_endpoints() {
    let mut config = serde_json::json!({
        "sp_key_path": testdata("sp-key.pem"),
        "sp_cert_path": testdata("sp-cert.pem"),
        "idp_entity_id": IDP_ENTITY,
        "idp_sso_url": "https://proxy.example.com/IdP/sso",
        "idp_cert_path": testdata("idp-cert.pem"),
        "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    });
    config.as_object_mut().unwrap().extend(org_contact_json());
    let sp =
        tunnelbana_plugins::saml2_backend::Saml2Backend::build(&build_ctx("SP", config)).unwrap();

    let mut ctx = Context::new(HttpRequestData::default(), State::new());
    let action = sp.handle_endpoint(&mut ctx, "metadata").await.unwrap();
    let xml = match action {
        BackendAction::Respond(resp) => String::from_utf8(resp.body).unwrap(),
        _ => panic!("expected metadata response"),
    };

    let entity = parse_entity(&xml);
    let org = entity
        .organization
        .as_ref()
        .expect("Organization in SP metadata");
    assert_eq!(org.organization_urls[0].value, "https://sunet.se");
    assert_eq!(entity.contact_persons.len(), 1);

    let sp_sso = &entity.sp_sso_descriptors()[0];
    // Configured NameID format is advertised (not the hardcoded list).
    assert_eq!(
        sp_sso.sso_base.name_id_formats,
        vec!["urn:oasis:names:tc:SAML:2.0:nameid-format:transient".to_string()]
    );
    // Both ACS bindings on the same URL.
    let bindings: Vec<&str> = sp_sso
        .assertion_consumer_services
        .iter()
        .map(|e| e.endpoint.binding.as_str())
        .collect();
    assert!(bindings.contains(&"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
    assert!(bindings.contains(&"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"));
    assert!(sp_sso
        .assertion_consumer_services
        .iter()
        .all(|e| e.endpoint.location == ACS_URL));
}

// ---------------------------------------------------------------------------
// F4: NameIDPolicy honoring + transient NameIDs
// ---------------------------------------------------------------------------

/// AuthnRequest for the registered test SP carrying a NameIDPolicy format.
fn authn_request_with_name_id_policy(format: &str) -> String {
    use gamlastan::profiles::sso::sp;
    use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
    use gamlastan::xml::serialize::SamlSerialize;

    let opts = AuthnRequestOptions {
        sp_entity_id: SP_ENTITY.to_string(),
        acs_url: Some(ACS_URL.to_string()),
        destination: Some("https://proxy.example.com/IdP/sso".to_string()),
        protocol_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
        name_id_format: Some(format.to_string()),
        allow_create: true,
        ..Default::default()
    };
    let req = sp::create_authn_request(&opts).unwrap();
    let xml = req.to_xml_string().unwrap();
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

#[tokio::test]
async fn saml_frontend_unsupported_name_id_policy_yields_saml_error() {
    // Frontend supports only persistent; the SP asks for transient.
    let idp = frontend();
    let authn_b64 = authn_request_with_name_id_policy(TRANSIENT);
    let mut ctx = post_sso_ctx(authn_b64);

    let action = idp.handle_endpoint(&mut ctx, "sso").await.unwrap();
    let html = match action {
        FrontendAction::Respond(resp) => {
            assert_eq!(resp.status, 200, "SAML errors travel in a POST form");
            String::from_utf8(resp.body).unwrap()
        }
        _ => panic!("unsupported NameIDPolicy must produce a SAML error Response"),
    };
    // The error Response is auto-POSTed to the metadata-validated ACS.
    assert!(html.contains(ACS_URL));
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(extract_saml_response(&html))
            .unwrap(),
    )
    .unwrap();
    assert!(xml.contains("InvalidNameIDPolicy"));
    assert!(xml.contains("InResponseTo"));
    assert!(
        !xml.contains("<saml:Assertion"),
        "error carries no assertion"
    );
}

/// Run a full frontend flow with a transient NameIDPolicy and return the
/// NameID value from the produced Response.
async fn transient_flow_name_id(idp: &dyn Frontend) -> String {
    let authn_b64 = authn_request_with_name_id_policy(TRANSIENT);
    let mut ctx = post_sso_ctx(authn_b64);
    let action = idp.handle_endpoint(&mut ctx, "sso").await.unwrap();
    assert!(matches!(action, FrontendAction::StartAuth { .. }));

    let authenticated = InternalData {
        subject_id: Some("anna-persistent-id".to_string()),
        ..Default::default()
    };
    let resp = idp
        .handle_authn_response(&mut ctx, authenticated)
        .await
        .unwrap();
    let html = String::from_utf8(resp.body).unwrap();
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(extract_saml_response(&html))
            .unwrap(),
    )
    .unwrap();

    // Pull the NameID text out of the assertion.
    let start = xml.find("NameID").expect("NameID element");
    let open_end = xml[start..].find('>').unwrap() + start + 1;
    let close = xml[open_end..].find('<').unwrap() + open_end;
    xml[open_end..close].to_string()
}

#[tokio::test]
async fn saml_frontend_transient_name_id_is_fresh_per_response() {
    let idp = frontend_with(
        serde_json::json!({ "name_id_formats": [TRANSIENT], "name_id_format": null })
            .as_object()
            .unwrap()
            .clone(),
    );
    let first = transient_flow_name_id(idp.as_ref()).await;
    let second = transient_flow_name_id(idp.as_ref()).await;

    assert_ne!(first, "anna-persistent-id", "transient ≠ subject id");
    assert_ne!(second, "anna-persistent-id");
    assert_ne!(first, second, "transient NameIDs must differ per response");
}

#[tokio::test]
async fn saml_frontend_metadata_advertises_configured_name_id_formats() {
    let idp = frontend_with(
        serde_json::json!({
            "name_id_formats": [TRANSIENT, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"],
            "name_id_format": null
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let mut ctx = Context::new(HttpRequestData::default(), State::new());
    let action = idp.handle_endpoint(&mut ctx, "metadata").await.unwrap();
    let xml = match action {
        FrontendAction::Respond(resp) => String::from_utf8(resp.body).unwrap(),
        _ => panic!("expected metadata response"),
    };
    let entity = parse_entity(&xml);
    let idp_sso = &entity.idp_sso_descriptors()[0];
    assert_eq!(
        idp_sso.sso_base.name_id_formats,
        vec![
            TRANSIENT.to_string(),
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()
        ]
    );
}

#[test]
fn saml_frontend_rejects_both_name_id_config_forms() {
    let config = serde_json::json!({
        "idp_key_path": testdata("idp-key.pem"),
        "idp_cert_path": testdata("idp-cert.pem"),
        "metadata": { "local": [testdata("sp-metadata.xml")] },
        "name_id_format": TRANSIENT,
        "name_id_formats": [TRANSIENT]
    });
    assert!(
        tunnelbana_plugins::saml2_frontend::Saml2Frontend::build(&build_ctx("IdP", config))
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// F3: attribute name format (uri/OID)
// ---------------------------------------------------------------------------

const MAIL_OID: &str = "urn:oid:0.9.2342.19200300.100.1.3";

fn oid_mapper() -> Arc<AttributeMapper> {
    Arc::new(
        AttributeMapper::from_toml(&format!(
            r#"
            [attributes.mail]
            saml = {{ names = ["mail"], oid = "{MAIL_OID}", friendly_name = "mail" }}
            [attributes.givenname]
            saml = ["givenName"]
        "#
        ))
        .unwrap(),
    )
}

#[tokio::test]
async fn saml_frontend_uri_mode_emits_oid_attributes_and_backend_maps_back() {
    // Frontend in uri mode with an OID-carrying attribute map.
    let config = serde_json::json!({
        "idp_key_path": testdata("idp-key.pem"),
        "idp_cert_path": testdata("idp-cert.pem"),
        "sign_assertions": true,
        "attribute_name_format": "uri",
        "metadata": { "local": [testdata("sp-metadata.xml")] }
    });
    let bx = BuildContext {
        name: "IdP".to_string(),
        base_url: BASE.to_string(),
        config,
        attribute_mapper: oid_mapper(),
        http_client: Arc::new(NullHttpClient),
        secret: "saml-test-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    let idp = tunnelbana_plugins::saml2_frontend::Saml2Frontend::build(&bx).unwrap();

    let (req_id, authn_b64) = downstream_authn_request();
    let mut idp_ctx = post_sso_ctx(authn_b64);
    idp.handle_endpoint(&mut idp_ctx, "sso").await.unwrap();

    let mut authenticated = InternalData {
        subject_id: Some("anna".to_string()),
        ..Default::default()
    };
    authenticated
        .attributes
        .insert("mail".into(), vec!["anna@example.com".into()]);
    authenticated
        .attributes
        .insert("givenname".into(), vec!["Anna".into()]);
    let resp = idp
        .handle_authn_response(&mut idp_ctx, authenticated)
        .await
        .unwrap();
    let html = String::from_utf8(resp.body).unwrap();
    let b64 = extract_saml_response(&html);
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap(),
    )
    .unwrap();

    // OID name + uri format + FriendlyName for the mapped attribute…
    assert!(xml.contains(&format!(r#"Name="{MAIL_OID}""#)));
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:attrname-format:uri"));
    assert!(xml.contains(r#"FriendlyName="mail""#));
    // …and a warned basic fallback for the OID-less one.
    assert!(xml.contains(r#"Name="givenName""#));

    // The SP backend (sharing the attribute map) maps the OID back to `mail`.
    let backend_config = serde_json::json!({
        "sp_key_path": testdata("sp-key.pem"),
        "idp_entity_id": IDP_ENTITY,
        "idp_sso_url": "https://proxy.example.com/IdP/sso",
        "idp_cert_path": testdata("idp-cert.pem"),
        "security": "permissive"
    });
    let sp_bx = BuildContext {
        name: "SP".to_string(),
        base_url: BASE.to_string(),
        config: backend_config,
        attribute_mapper: oid_mapper(),
        http_client: Arc::new(NullHttpClient),
        secret: "saml-test-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    let sp = tunnelbana_plugins::saml2_backend::Saml2Backend::build(&sp_bx).unwrap();
    let mut sp_ctx = Context::new(
        HttpRequestData {
            path: "SP/acs".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLResponse".to_string(), b64)]),
            ..Default::default()
        },
        State::new(),
    );
    sp_ctx.state.set_str("SP", "authn_id", &req_id);
    let action = sp.handle_endpoint(&mut sp_ctx, "acs").await.unwrap();
    let internal = match action {
        BackendAction::AuthResponse(d) => d,
        _ => panic!("expected AuthResponse"),
    };
    assert_eq!(internal.attr_first("mail"), Some("anna@example.com"));
    assert_eq!(internal.attr_first("givenname"), Some("Anna"));
}

// ---------------------------------------------------------------------------
// F2: per-SP attribute release policy
// ---------------------------------------------------------------------------

/// Run a frontend flow with two attributes and return the Response XML.
async fn policy_flow_xml(idp: &dyn Frontend) -> String {
    let (_, authn_b64) = downstream_authn_request();
    let mut ctx = post_sso_ctx(authn_b64);
    idp.handle_endpoint(&mut ctx, "sso").await.unwrap();

    let mut authenticated = InternalData {
        subject_id: Some("anna".to_string()),
        ..Default::default()
    };
    authenticated
        .attributes
        .insert("mail".into(), vec!["anna@example.com".into()]);
    authenticated
        .attributes
        .insert("givenname".into(), vec!["Anna".into()]);
    let resp = idp
        .handle_authn_response(&mut ctx, authenticated)
        .await
        .unwrap();
    let html = String::from_utf8(resp.body).unwrap();
    String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(extract_saml_response(&html))
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn saml_frontend_default_policy_filters_attributes() {
    let idp = frontend_with(
        serde_json::json!({
            "policy": { "default": { "attribute_restrictions": ["mail"] } }
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let xml = policy_flow_xml(idp.as_ref()).await;
    assert!(xml.contains("anna@example.com"), "mail is released");
    assert!(!xml.contains("givenName"), "givenname is withheld");
}

#[tokio::test]
async fn saml_frontend_sp_policy_overrides_default() {
    // Default releases everything; the SP-specific entry restricts to
    // givenname only (override replaces, no merge).
    let idp = frontend_with(
        serde_json::json!({
            "policy": {
                "default": { "attribute_restrictions": ["mail", "givenname"] },
                SP_ENTITY: { "attribute_restrictions": ["givenname"] }
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    );
    let xml = policy_flow_xml(idp.as_ref()).await;
    assert!(xml.contains("Anna"), "givenname is released");
    assert!(!xml.contains("anna@example.com"), "mail is withheld");
}

#[tokio::test]
async fn saml_frontend_no_policy_releases_all() {
    let idp = frontend();
    let xml = policy_flow_xml(idp.as_ref()).await;
    assert!(xml.contains("anna@example.com"));
    assert!(xml.contains("Anna"));
}

// ---------------------------------------------------------------------------
// B4: accepted_time_diff_secs (clock skew)
// ---------------------------------------------------------------------------

/// Build and sign a SAML Response whose timestamps lie `skew_minutes` in the
/// past, mirroring the frontend's assertion-signing flow. `req_id = None`
/// produces an unsolicited Response (no InResponseTo).
fn skewed_signed_response(req_id: Option<&str>, skew_minutes: i64) -> String {
    signed_response_with(req_id, skew_minutes, vec![])
}

fn build_response(
    req_id: Option<&str>,
    skew_minutes: i64,
    attributes: Vec<gamlastan::core::assertion::attribute::Attribute>,
) -> gamlastan::core::protocol::response::Response {
    use gamlastan::core::assertion::name_id::NameId;
    use gamlastan::profiles::sso::idp as idp_profile;
    use gamlastan::profiles::sso::web_browser::ResponseOptions;

    let now = chrono::Utc::now() - chrono::TimeDelta::try_minutes(skew_minutes).unwrap();
    let options = ResponseOptions {
        idp_entity_id: IDP_ENTITY.to_string(),
        in_response_to: req_id.map(str::to_string),
        sp_entity_id: SP_ENTITY.to_string(),
        acs_url: ACS_URL.to_string(),
        assertion_lifetime_seconds: 300,
        session_index: None,
        session_not_on_or_after: None,
        authn_context_class_ref: Some(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
        ),
        client_address: None,
        attributes,
    };
    let name_id = NameId {
        value: "anna-persistent-id".to_string(),
        format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()),
        name_qualifier: None,
        sp_name_qualifier: Some(SP_ENTITY.to_string()),
        sp_provided_id: None,
    };
    idp_profile::create_response(&options, &name_id, now)
}

fn idp_signer_and_cert() -> (gamlastan::crypto::SamlSigner, String) {
    use gamlastan::crypto::keys::loader;
    use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};

    let key_pem = std::fs::read(testdata("idp-key.pem")).unwrap();
    let cert_pem = std::fs::read(testdata("idp-cert.pem")).unwrap();
    let cert_b64: String = String::from_utf8_lossy(&cert_pem)
        .lines()
        .filter(|l| !l.contains("CERTIFICATE"))
        .map(|l| l.trim())
        .collect();
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(&cert_b64)
        .unwrap();
    let mut key = loader::load_pem_auto(&key_pem, None).unwrap();
    key.usage = KeyUsage::Sign;
    key.x509_chain = vec![cert_der];
    let mut km = KeysManager::new();
    km.add_key(key);
    (SamlSigner::new(km), cert_b64)
}

fn sign_assertion_in_document(
    document_xml: &str,
    assertion_id: &str,
    cert_b64: &str,
    signer: &gamlastan::crypto::SamlSigner,
) -> String {
    let sig = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
    );
    let open_tag_end = document_xml.find("<saml:Assertion").unwrap();
    let rel = document_xml[open_tag_end..].find('>').unwrap();
    let pos = open_tag_end + rel;
    let with_template = format!(
        "{}{}{}",
        &document_xml[..=pos],
        sig,
        &document_xml[pos + 1..]
    );
    signer.sign_enveloped(&with_template).unwrap()
}

fn standalone_assertion_document(assertion_xml: &str) -> String {
    format!(
        r#"<tb:Standalone xmlns:tb="urn:tunnelbana:test" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">{assertion_xml}</tb:Standalone>"#
    )
}

fn sign_assertion_fragment(
    assertion_xml: &str,
    assertion_id: &str,
    cert_b64: &str,
    signer: &gamlastan::crypto::SamlSigner,
) -> String {
    let wrapped = standalone_assertion_document(assertion_xml);
    let signed = sign_assertion_in_document(&wrapped, assertion_id, cert_b64, signer);
    response_assertion_sources(&signed)
        .into_iter()
        .next()
        .expect("signed assertion fragment")
}

fn response_assertion_sources(xml: &str) -> Vec<String> {
    let doc = gamlastan::xml::uppsala::parse(xml).unwrap();
    let root = doc.document_element().unwrap();
    doc.children_iter(root)
        .filter_map(|child| {
            let element = doc.element(child)?;
            if element
                .name
                .matches(Some("urn:oasis:names:tc:SAML:2.0:assertion"), "Assertion")
            {
                Some(doc.node_source(child).unwrap().to_string())
            } else {
                None
            }
        })
        .collect()
}

fn signed_response_with(
    req_id: Option<&str>,
    skew_minutes: i64,
    attributes: Vec<gamlastan::core::assertion::attribute::Attribute>,
) -> String {
    use gamlastan::xml::serialize::SamlSerialize;

    let response = build_response(req_id, skew_minutes, attributes);
    let xml = response.to_xml_string().unwrap();
    let (signer, cert_b64) = idp_signer_and_cert();
    let signed = sign_assertion_in_document(&xml, &response.assertions[0].id, &cert_b64, &signer);
    base64::engine::general_purpose::STANDARD.encode(signed.as_bytes())
}

fn multi_assertion_response_with_tampered_second(req_id: &str) -> String {
    use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
    use gamlastan::xml::serialize::SamlSerialize;

    let mut response = build_response(
        Some(req_id),
        0,
        vec![Attribute {
            name: "mail".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![AttributeValue::String("anna@example.com".to_string())],
        }],
    );
    let mut second = response.assertions[0].clone();
    second.id = "_multi_assertion_2".to_string();
    second.attribute_statements[0].attributes[0].values =
        vec![AttributeValue::String("guest@example.com".to_string())];
    response.assertions.push(second);

    let xml = response.to_xml_string().unwrap();
    let assertion_sources = response_assertion_sources(&xml);
    assert_eq!(assertion_sources.len(), response.assertions.len());

    let (signer, cert_b64) = idp_signer_and_cert();
    let signed_assertions: Vec<String> = response
        .assertions
        .iter()
        .zip(assertion_sources.iter())
        .map(|(assertion, source)| {
            sign_assertion_fragment(source, &assertion.id, &cert_b64, &signer)
        })
        .collect();

    let mut signed_xml = xml;
    for (unsigned, signed) in assertion_sources.iter().zip(signed_assertions.iter()) {
        signed_xml = signed_xml.replacen(unsigned, signed, 1);
    }

    let tampered_xml = signed_xml.replacen("guest@example.com", "mallory@evil.example", 1);
    base64::engine::general_purpose::STANDARD.encode(tampered_xml.as_bytes())
}

fn backend_with(extra: serde_json::Map<String, serde_json::Value>) -> Box<dyn Backend> {
    let mut config = serde_json::json!({
        "sp_key_path": testdata("sp-key.pem"),
        "idp_entity_id": IDP_ENTITY,
        "idp_sso_url": "https://proxy.example.com/IdP/sso",
        "idp_cert_path": testdata("idp-cert.pem"),
        "security": "permissive"
    });
    config.as_object_mut().unwrap().extend(extra);
    tunnelbana_plugins::saml2_backend::Saml2Backend::build(&build_ctx("SP", config)).unwrap()
}

async fn acs_result(
    sp: &dyn Backend,
    saml_response_b64: String,
    req_id: Option<&str>,
) -> tunnelbana_core::error::Result<BackendAction> {
    let mut sp_ctx = Context::new(
        HttpRequestData {
            path: "SP/acs".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLResponse".to_string(), saml_response_b64)]),
            ..Default::default()
        },
        State::new(),
    );
    if let Some(id) = req_id {
        sp_ctx.state.set_str("SP", "authn_id", id);
    }
    sp.handle_endpoint(&mut sp_ctx, "acs").await
}

#[tokio::test]
async fn saml_backend_clock_skew_override_accepts_skewed_response() {
    let req_id = "_skewtest123";
    // 30 minutes in the past: outside permissive's 600s default tolerance.
    let b64 = skewed_signed_response(Some(req_id), 30);

    let default_sp = backend_with(serde_json::Map::new());
    assert!(
        acs_result(default_sp.as_ref(), b64.clone(), Some(req_id))
            .await
            .is_err(),
        "30-minute-old response must fail the default 600s skew"
    );

    let tolerant_sp = backend_with(
        serde_json::json!({ "accepted_time_diff_secs": 3600 })
            .as_object()
            .unwrap()
            .clone(),
    );
    assert!(
        acs_result(tolerant_sp.as_ref(), b64, Some(req_id))
            .await
            .is_ok(),
        "accepted_time_diff_secs=3600 must accept a 30-minute-old response"
    );
}

#[tokio::test]
async fn saml_backend_rejects_tampered_second_signed_assertion() {
    let sp = backend_with(serde_json::Map::new());
    let req_id = "_multi_assertion_req";
    let b64 = multi_assertion_response_with_tampered_second(req_id);
    assert!(
        acs_result(sp.as_ref(), b64, Some(req_id)).await.is_err(),
        "tampering any signed assertion in an unsigned multi-assertion response must be rejected"
    );
}

// ---------------------------------------------------------------------------
// B6: unknown-attribute passthrough
// ---------------------------------------------------------------------------

fn passthrough_test_attributes() -> Vec<gamlastan::core::assertion::attribute::Attribute> {
    use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
    vec![
        // Known: maps to internal "mail" via the test mapper.
        Attribute {
            name: "mail".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![AttributeValue::String("anna@example.com".to_string())],
        },
        // Unknown, with FriendlyName: keyed by lowercased FriendlyName.
        Attribute {
            name: "urn:oid:1.3.6.1.4.1.25178.1.2.9".to_string(),
            name_format: None,
            friendly_name: Some("schacHomeOrganization".to_string()),
            values: vec![AttributeValue::String("example.org".to_string())],
        },
        // Unknown, no FriendlyName: keyed by lowercased Name.
        Attribute {
            name: "customAttr".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![AttributeValue::String("custom-value".to_string())],
        },
    ]
}

async fn passthrough_internal(sp: &dyn Backend) -> tunnelbana_core::internal::InternalData {
    let req_id = "_pass1";
    let b64 = signed_response_with(Some(req_id), 0, passthrough_test_attributes());
    match acs_result(sp, b64, Some(req_id)).await.unwrap() {
        BackendAction::AuthResponse(d) => d,
        _ => panic!("expected AuthResponse"),
    }
}

#[tokio::test]
async fn saml_backend_drops_unmapped_attributes_by_default() {
    let sp = backend_with(serde_json::Map::new());
    let internal = passthrough_internal(sp.as_ref()).await;
    assert_eq!(internal.attr_first("mail"), Some("anna@example.com"));
    assert!(!internal.attributes.contains_key("schachomeorganization"));
    assert!(!internal.attributes.contains_key("customattr"));
}

#[tokio::test]
async fn saml_backend_passthrough_keeps_unmapped_attributes() {
    let sp = backend_with(
        serde_json::json!({ "passthrough_unmapped_attributes": true })
            .as_object()
            .unwrap()
            .clone(),
    );
    let internal = passthrough_internal(sp.as_ref()).await;
    // Mapped attribute still arrives under its internal name.
    assert_eq!(internal.attr_first("mail"), Some("anna@example.com"));
    // Unknown attribute keyed by lowercased FriendlyName, exactly once.
    assert_eq!(
        internal.attributes.get("schachomeorganization"),
        Some(&vec!["example.org".to_string()])
    );
    assert!(
        !internal
            .attributes
            .keys()
            .any(|k| k.contains("1.3.6.1.4.1.25178")),
        "OID-named duplicate must not appear alongside the FriendlyName key"
    );
    // Unknown attribute without FriendlyName keyed by lowercased Name.
    assert_eq!(
        internal.attributes.get("customattr"),
        Some(&vec!["custom-value".to_string()])
    );

    // Leak-safety: from_internal drops passthrough keys for any profile.
    let saml_out = mapper().from_internal("saml", &internal.attributes);
    assert!(!saml_out.contains_key("schachomeorganization"));
    assert!(!saml_out.contains_key("customattr"));
    assert!(saml_out.contains_key("mail"));
}

// ---------------------------------------------------------------------------
// B5: allow_unsolicited + fail-closed InResponseTo handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn saml_backend_rejects_response_without_stored_request_by_default() {
    // Fail closed: no stored authn_id means rejection — previously the
    // InResponseTo check was silently skipped.
    let sp = backend_with(serde_json::Map::new());
    let b64 = skewed_signed_response(Some("_whatever"), 0);
    assert!(acs_result(sp.as_ref(), b64, None).await.is_err());

    // Even a truly unsolicited response (no InResponseTo) is rejected.
    let b64 = skewed_signed_response(None, 0);
    assert!(acs_result(sp.as_ref(), b64, None).await.is_err());
}

#[tokio::test]
async fn saml_backend_accepts_unsolicited_with_flag() {
    let sp = backend_with(
        serde_json::json!({ "allow_unsolicited": true })
            .as_object()
            .unwrap()
            .clone(),
    );
    let b64 = skewed_signed_response(None, 0);
    assert!(
        acs_result(sp.as_ref(), b64, None).await.is_ok(),
        "unsolicited response accepted when allow_unsolicited=true"
    );
}

#[tokio::test]
async fn saml_backend_rejects_dangling_in_response_to_even_with_flag() {
    let sp = backend_with(
        serde_json::json!({ "allow_unsolicited": true })
            .as_object()
            .unwrap()
            .clone(),
    );
    // InResponseTo present but nothing in flight: must be rejected.
    let b64 = skewed_signed_response(Some("_dangling"), 0);
    assert!(acs_result(sp.as_ref(), b64, None).await.is_err());
}

// ---------------------------------------------------------------------------
// F5: entityid metadata endpoint
// ---------------------------------------------------------------------------

#[tokio::test]
async fn saml_frontend_serves_metadata_at_entity_id_url() {
    let idp = frontend_with(
        serde_json::json!({ "idp_entity_id": "https://proxy.example.com/IdP/proxy.xml" })
            .as_object()
            .unwrap()
            .clone(),
    );
    let routes = idp.register_endpoints(&[]);
    let entity_route = routes
        .iter()
        .find(|r| r.pattern.is_match("IdP/proxy.xml"))
        .expect("route for the entity-id path");
    assert_eq!(entity_route.id, "metadata");

    // Same document as <name>/metadata.
    let mut ctx = Context::new(HttpRequestData::default(), State::new());
    let action = idp.handle_endpoint(&mut ctx, "metadata").await.unwrap();
    let xml = match action {
        FrontendAction::Respond(resp) => String::from_utf8(resp.body).unwrap(),
        _ => panic!("expected metadata"),
    };
    assert!(xml.contains("https://proxy.example.com/IdP/proxy.xml"));
}

#[test]
fn saml_frontend_external_entity_id_registers_no_extra_route() {
    let idp = frontend_with(
        serde_json::json!({ "idp_entity_id": "https://idp.example.org/external" })
            .as_object()
            .unwrap()
            .clone(),
    );
    assert_eq!(idp.register_endpoints(&[]).len(), 2);
}

#[test]
fn saml_frontend_requires_metadata_or_explicit_open_mode() {
    let base = serde_json::json!({
        "idp_key_path": testdata("idp-key.pem"),
        "idp_cert_path": testdata("idp-cert.pem"),
    });

    // No [metadata] and no allow_unknown_sps ⇒ refuse to build.
    let result =
        tunnelbana_plugins::saml2_frontend::Saml2Frontend::build(&build_ctx("IdP", base.clone()));
    assert!(
        result.is_err(),
        "frontend without SP metadata must not build"
    );

    // Explicit open mode builds (legacy/dev behavior).
    let mut open = base.clone();
    open.as_object_mut()
        .unwrap()
        .insert("allow_unknown_sps".into(), serde_json::json!(true));
    assert!(
        tunnelbana_plugins::saml2_frontend::Saml2Frontend::build(&build_ctx("IdP", open)).is_ok()
    );

    // An empty [metadata] block is a config error, not silently open.
    let mut empty_md = base;
    empty_md
        .as_object_mut()
        .unwrap()
        .insert("metadata".into(), serde_json::json!({}));
    assert!(
        tunnelbana_plugins::saml2_frontend::Saml2Frontend::build(&build_ctx("IdP", empty_md))
            .is_err()
    );
}
