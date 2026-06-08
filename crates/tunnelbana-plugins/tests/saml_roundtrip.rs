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
    let config = serde_json::json!({
        "idp_key_path": testdata("idp-key.pem"),
        "idp_cert_path": testdata("idp-cert.pem"),
        "sign_assertions": true,
        "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    });
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
    let mut authenticated = InternalData::default();
    authenticated.subject_id = Some("anna-persistent-id".to_string());
    authenticated.auth_info = AuthenticationInformation {
        auth_class_ref: Some("urn:oasis:names:tc:SAML:2.0:ac:classes:Password".into()),
        timestamp: None,
        issuer: Some("urn:upstream".into()),
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

    let mut authenticated = InternalData::default();
    authenticated.subject_id = Some("anna".into());
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
        base64::engine::general_purpose::STANDARD.decode(&b64).unwrap(),
    )
    .unwrap();
    let tampered_xml = xml.replace("anna@example.com", "attacker@evil.example");
    let tampered_b64 =
        base64::engine::general_purpose::STANDARD.encode(tampered_xml.as_bytes());

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
