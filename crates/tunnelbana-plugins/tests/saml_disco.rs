//! B1: discovery-service flow through the real `Proxy`. An OIDC frontend
//! starts authentication; the SAML2 backend (MDQ mode, no default IdP) sends
//! the user to the discovery service; the discovery return picks the IdP via
//! MDQ (served by an in-test HTTP server) and redirects to its SSO endpoint;
//! the signed SAML Response then completes the flow back to the RP — proving
//! the encrypted state cookie survives the disco hop.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use base64::Engine;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::plugin::{Backend, BuildContext, Frontend, NullHttpClient};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;
use tunnelbana_oidc::pkce;

const BASE: &str = "https://proxy.example.com";
const IDP_ENTITY: &str = "https://idp.example.org";
const IDP_SSO_URL: &str = "https://idp.example.org/sso";
const SP_ENTITY: &str = "https://proxy.example.com/SP";
const ACS_URL: &str = "https://proxy.example.com/SP/acs";
const DISCO_SRV: &str = "https://service.seamlessaccess.org/ds";

fn testdata(file: &str) -> String {
    format!("{}/testdata/{}", env!("CARGO_MANIFEST_DIR"), file)
}

fn cert_b64(path: &str) -> String {
    String::from_utf8_lossy(&std::fs::read(path).unwrap())
        .lines()
        .filter(|l| !l.contains("CERTIFICATE"))
        .map(|l| l.trim().to_string())
        .collect()
}

/// IdP metadata document served by the in-test MDQ server.
fn idp_metadata_xml() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_SSO_URL}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
        cert = cert_b64(&testdata("idp-cert.pem")),
    )
}

/// Minimal HTTP server answering every GET with the given body. Returns the
/// base URL.
async fn serve_metadata(body: String) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 8192];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/samlmetadata+xml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    format!("http://{addr}/")
}

fn mapper() -> Arc<AttributeMapper> {
    Arc::new(
        AttributeMapper::from_toml(
            r#"
            [attributes.mail]
            openid = ["email"]
            saml = ["mail"]
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
        secret: "disco-test-secret".to_string(),
        previous_secrets: Vec::new(),
    }
}

fn saml_backend(mdq_url: &str) -> Box<dyn Backend> {
    let config = serde_json::json!({
        "sp_key_path": testdata("sp-key.pem"),
        "disco_srv": DISCO_SRV,
        "mdq": { "url": mdq_url, "allow_unverified": true }
    });
    tunnelbana_plugins::saml2_backend::Saml2Backend::build(&build_ctx("SP", config)).unwrap()
}

fn oidc_frontend() -> Box<dyn Frontend> {
    let mut jwk = jose_rs::jwk::generate_ec("P-256").unwrap();
    jwk.alg = Some("ES256".into());
    let signing_jwk: serde_json::Value = serde_json::from_str(&jwk.to_json().unwrap()).unwrap();
    let config = serde_json::json!({
        "signing_jwk": signing_jwk,
        "signing_algorithm": "ES256",
        "signing_key_id": "k1",
        "clients": [{
            "client_id": "rp-1",
            "redirect_uris": ["https://rp.example.com/cb"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        }]
    });
    tunnelbana_plugins::oidc_frontend::OidcFrontend::build(&build_ctx("OIDC", config)).unwrap()
}

fn req(path: &str, method: &str, cookie: Option<&str>) -> HttpRequestData {
    let mut r = HttpRequestData {
        path: path.trim_start_matches('/').to_string(),
        method: method.to_string(),
        ..Default::default()
    };
    if let Some((p, q)) = path.split_once('?') {
        r.path = p.trim_start_matches('/').to_string();
        r.query = form_parse(q);
    }
    if let Some(c) = cookie {
        if let Some((k, v)) = c.split_once('=') {
            r.cookies.insert(k.to_string(), v.to_string());
        }
    }
    r
}

fn form_parse(s: &str) -> BTreeMap<String, String> {
    form_urlencoded::parse(s.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn location(resp: &Response) -> String {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
        .expect("location header")
}

fn set_cookie(resp: &Response) -> Option<String> {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.split(';').next().unwrap().to_string())
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let (_, q) = url.split_once('?')?;
    form_parse(q).get(key).cloned()
}

/// Pull the AuthnRequest ID out of a redirect-binding URL.
fn authn_request_id(redirect_url: &str) -> String {
    let saml_request = query_param(redirect_url, "SAMLRequest").expect("SAMLRequest param");
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(saml_request)
        .unwrap();
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(&compressed[..])
        .read_to_string(&mut xml)
        .unwrap();
    let start = xml.find("ID=\"").unwrap() + 4;
    let end = xml[start..].find('"').unwrap() + start;
    xml[start..end].to_string()
}

/// Sign a SAML Response for the given request id with the test IdP key
/// (assertion signature, like the SAML2 frontend produces).
fn signed_idp_response(req_id: &str) -> String {
    use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
    use gamlastan::core::assertion::name_id::NameId;
    use gamlastan::crypto::keys::loader;
    use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};
    use gamlastan::profiles::sso::idp as idp_profile;
    use gamlastan::profiles::sso::web_browser::ResponseOptions;
    use gamlastan::xml::serialize::SamlSerialize;

    let now = chrono::Utc::now();
    let options = ResponseOptions {
        idp_entity_id: IDP_ENTITY.to_string(),
        in_response_to: Some(req_id.to_string()),
        sp_entity_id: SP_ENTITY.to_string(),
        acs_url: ACS_URL.to_string(),
        assertion_lifetime_seconds: 300,
        session_index: None,
        session_not_on_or_after: None,
        authn_context_class_ref: Some(
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
        ),
        client_address: None,
        attributes: vec![Attribute {
            name: "mail".to_string(),
            name_format: None,
            friendly_name: None,
            values: vec![AttributeValue::String("anna@example.com".to_string())],
        }],
    };
    let name_id = NameId {
        value: "anna-persistent-id".to_string(),
        format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()),
        name_qualifier: None,
        sp_name_qualifier: Some(SP_ENTITY.to_string()),
        sp_provided_id: None,
    };
    let response = idp_profile::create_response(&options, &name_id, now);
    let xml = response.to_xml_string().unwrap();
    let assertion_id = response.assertions[0].id.clone();

    let cert_b64 = cert_b64(&testdata("idp-cert.pem"));
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(&cert_b64)
        .unwrap();
    let key_pem = std::fs::read(testdata("idp-key.pem")).unwrap();
    let mut key = loader::load_pem_auto(&key_pem, None).unwrap();
    key.usage = KeyUsage::Sign;
    key.x509_chain = vec![cert_der];
    let mut km = KeysManager::new();
    km.add_key(key);
    let signer = SamlSigner::new(km);

    let sig = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{assertion_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
    );
    let tag_start = xml.find("<saml:Assertion").unwrap();
    let rel = xml[tag_start..].find('>').unwrap();
    let pos = tag_start + rel;
    let with_template = format!("{}{}{}", &xml[..=pos], sig, &xml[pos + 1..]);
    let signed = signer.sign_enveloped(&with_template).unwrap();
    base64::engine::general_purpose::STANDARD.encode(signed.as_bytes())
}

#[tokio::test]
async fn discovery_flow_through_proxy() {
    let mdq_url = serve_metadata(idp_metadata_xml()).await;
    let frontend = oidc_frontend();
    let backend = saml_backend(&mdq_url);
    let sealer = StateSealer::new("disco-test-secret", "TB_STATE").with_secure(false);
    let proxy = Proxy::new(vec![frontend], vec![backend], vec![], sealer);

    let verifier = "verifier-abcdefghijklmnop-abcdefghijklmnop";
    let challenge = pkce::s256_challenge(verifier);

    // 1) RP starts an OIDC flow; with no IdP selected the SAML backend sends
    //    the user to the discovery service, with flow state in the cookie.
    let authz_url = format!(
        "OIDC/authorization?client_id=rp-1&response_type=code&redirect_uri={}&scope=openid&state=st-1&nonce=no-1&code_challenge={}&code_challenge_method=S256",
        urlenc("https://rp.example.com/cb"),
        challenge
    );
    let r1 = proxy.run(req(&authz_url, "GET", None)).await;
    assert_eq!(r1.status, 302, "{}", String::from_utf8_lossy(&r1.body));
    let disco_url = location(&r1);
    assert!(
        disco_url.starts_with(DISCO_SRV),
        "redirects to disco: {disco_url}"
    );
    assert_eq!(
        query_param(&disco_url, "entityID").as_deref(),
        Some(SP_ENTITY)
    );
    assert_eq!(
        query_param(&disco_url, "return").as_deref(),
        Some("https://proxy.example.com/SP/disco")
    );
    let cookie1 = set_cookie(&r1).expect("state cookie on disco redirect");

    // 2) Discovery service sends the user back with the chosen IdP. The
    //    backend resolves it via MDQ and redirects to the IdP's SSO endpoint.
    let disco_return = format!("SP/disco?entityID={}", urlenc(IDP_ENTITY));
    let r2 = proxy.run(req(&disco_return, "GET", Some(&cookie1))).await;
    assert_eq!(r2.status, 302, "{}", String::from_utf8_lossy(&r2.body));
    let sso_redirect = location(&r2);
    assert!(
        sso_redirect.starts_with(IDP_SSO_URL),
        "redirects to the chosen IdP: {sso_redirect}"
    );
    let req_id = authn_request_id(&sso_redirect);
    let cookie2 = set_cookie(&r2).expect("state cookie after disco hop");

    // 3) The IdP posts back a signed Response; the ACS verifies it against
    //    the same IdP's MDQ metadata and the flow completes to the RP.
    let mut acs_req = req("SP/acs", "POST", Some(&cookie2));
    acs_req.form = BTreeMap::from([("SAMLResponse".to_string(), signed_idp_response(&req_id))]);
    let r3 = proxy.run(acs_req).await;
    assert_eq!(r3.status, 302, "{}", String::from_utf8_lossy(&r3.body));
    let rp_redirect = location(&r3);
    assert!(rp_redirect.starts_with("https://rp.example.com/cb?"));
    assert_eq!(query_param(&rp_redirect, "state").as_deref(), Some("st-1"));
    assert!(query_param(&rp_redirect, "code").is_some());
}

#[tokio::test]
async fn disco_endpoint_requires_entity_id() {
    let mdq_url = serve_metadata(idp_metadata_xml()).await;
    let backend = saml_backend(&mdq_url);
    let mut ctx = tunnelbana_core::context::Context::new(
        req("SP/disco", "GET", None),
        tunnelbana_core::state::State::new(),
    );
    let result = backend.handle_endpoint(&mut ctx, "disco").await;
    assert!(result.is_err(), "disco return without entityID is an error");
}

#[tokio::test]
async fn sp_metadata_advertises_discovery_response() {
    let mdq_url = serve_metadata(idp_metadata_xml()).await;
    let backend = saml_backend(&mdq_url);
    let mut ctx = tunnelbana_core::context::Context::new(
        req("SP/metadata", "GET", None),
        tunnelbana_core::state::State::new(),
    );
    let action = backend.handle_endpoint(&mut ctx, "metadata").await.unwrap();
    let xml = match action {
        tunnelbana_core::plugin::BackendAction::Respond(resp) => {
            String::from_utf8(resp.body).unwrap()
        }
        _ => panic!("expected metadata response"),
    };
    assert!(xml.contains("DiscoveryResponse"));
    assert!(xml.contains("https://proxy.example.com/SP/disco"));
    // Still valid metadata for gamlastan's own parser.
    let doc = gamlastan::xml::uppsala::parse(&xml).unwrap();
    gamlastan::xml::deserialize::parse_saml::<
        gamlastan::metadata::types::entity_descriptor::EntityDescriptorRef<'_>,
    >(&doc)
    .unwrap();
}

#[test]
fn build_validation_matrix() {
    use tunnelbana_plugins::saml2_backend::Saml2Backend;

    let base = |extra: serde_json::Value| {
        let mut cfg = serde_json::json!({ "sp_key_path": testdata("sp-key.pem") });
        cfg.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        cfg
    };

    // Static mode with disco_srv is rejected.
    assert!(Saml2Backend::build(&build_ctx(
        "SP",
        base(serde_json::json!({
            "idp_entity_id": IDP_ENTITY,
            "idp_sso_url": IDP_SSO_URL,
            "idp_cert_path": testdata("idp-cert.pem"),
            "disco_srv": DISCO_SRV
        }))
    ))
    .is_err());

    // Static mode without idp_entity_id is rejected.
    assert!(Saml2Backend::build(&build_ctx(
        "SP",
        base(serde_json::json!({
            "idp_sso_url": IDP_SSO_URL,
            "idp_cert_path": testdata("idp-cert.pem")
        }))
    ))
    .is_err());

    // MDQ mode needs idp_entity_id or disco_srv.
    assert!(Saml2Backend::build(&build_ctx(
        "SP",
        base(serde_json::json!({
            "mdq": { "url": "http://127.0.0.1:1/", "allow_unverified": true }
        }))
    ))
    .is_err());

    // MDQ + disco_srv builds.
    assert!(Saml2Backend::build(&build_ctx(
        "SP",
        base(serde_json::json!({
            "disco_srv": DISCO_SRV,
            "mdq": { "url": "http://127.0.0.1:1/", "allow_unverified": true }
        }))
    ))
    .is_ok());

    // MDQ + default idp_entity_id (no disco) still builds.
    assert!(Saml2Backend::build(&build_ctx(
        "SP",
        base(serde_json::json!({
            "idp_entity_id": IDP_ENTITY,
            "mdq": { "url": "http://127.0.0.1:1/", "allow_unverified": true }
        }))
    ))
    .is_ok());
}

fn urlenc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}
