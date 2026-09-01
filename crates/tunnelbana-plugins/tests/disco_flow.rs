//! `disco_to_target_issuer` end-to-end: an OIDC frontend starts a flow, the
//! default SAML2 backend redirects to the discovery service, and the disco
//! return - intercepted by the micro-service, which shadows the backend's own
//! disco route - resumes the request pipeline so `custom_routing` issuer rules
//! re-pick the backend (the iam-proxy-italia SPID-vs-CIE shape). Negative
//! coverage: replayed returns, forged returns with no open flow, and issuers
//! outside the routing allowlist.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;

use base64::Engine;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::http::{HttpRequestData, Response};
use tunnelbana_core::plugin::{Backend, BuildContext, Frontend, MicroService, NullHttpClient};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;
use tunnelbana_oidc::pkce;

const BASE: &str = "https://proxy.example.com";
const SPID_IDP: &str = "https://spid-idp.example.org";
const SPID_SSO_URL: &str = "https://spid-idp.example.org/sso";
const CIE_IDP: &str = "https://cie-idp.example.org";
const CIE_SSO_URL: &str = "https://cie-idp.example.org/sso";
const DISCO_SRV: &str = "https://proxy.example.com/static/disco.html";

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

fn idp_metadata_xml(entity_id: &str, sso_url: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{entity_id}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{cert}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"#,
        cert = cert_b64(&testdata("idp-cert.pem")),
    )
}

/// Minimal HTTP server answering every GET with the given body.
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
        secret: "disco-flow-test-secret".to_string(),
        previous_secrets: Vec::new(),
    }
}

/// Default backend: MDQ + disco_srv, so the first pass redirects to the
/// discovery service. Its MDQ URL is a closed port - an issuer that survives
/// routing without an issuer rule fails its metadata fetch instead of
/// silently authenticating anywhere.
fn default_backend() -> Box<dyn Backend> {
    let config = serde_json::json!({
        "sp_key_path": testdata("sp-key.pem"),
        "disco_srv": DISCO_SRV,
        "mdq": { "url": "http://127.0.0.1:1/", "allow_unverified": true }
    });
    tunnelbana_plugins::saml2_backend::Saml2Backend::build(&build_ctx("Saml2", config)).unwrap()
}

/// A protocol backend (SPID/CIE shape): MDQ mode with a default IdP; the
/// target-entity decoration set by the disco return selects the IdP.
fn idp_backend(name: &str, idp_entity: &str, mdq_url: &str) -> Box<dyn Backend> {
    let config = serde_json::json!({
        "sp_key_path": testdata("sp-key.pem"),
        "idp_entity_id": idp_entity,
        "mdq": { "url": mdq_url, "allow_unverified": true }
    });
    tunnelbana_plugins::saml2_backend::Saml2Backend::build(&build_ctx(name, config)).unwrap()
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
        }, {
            "client_id": "rp-2",
            "redirect_uris": ["https://rp.example.com/cb"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        }]
    });
    tunnelbana_plugins::oidc_frontend::OidcFrontend::build(&build_ctx("OIDC", config)).unwrap()
}

fn microservices() -> Vec<Box<dyn MicroService>> {
    let disco = tunnelbana_plugins::microservices::DiscoToTargetIssuer::build(&build_ctx(
        "disco",
        serde_json::json!({
            "disco_endpoints": ["Saml2/disco"],
            // Requester-scoped: rp-1 may pick these issuers; a requester with
            // no rule set fails closed at the disco return.
            "allowed_issuers": { "rp-1": [SPID_IDP, CIE_IDP] },
        }),
    ))
    .unwrap();
    let routing = tunnelbana_plugins::microservices::CustomRouting::build(&build_ctx(
        "router",
        serde_json::json!({
            "issuer_rule": [
                { "issuer": SPID_IDP, "requesters": ["rp-1"], "backend": "SPID" },
                { "issuer": CIE_IDP, "requesters": ["rp-1"], "backend": "CIE" }
            ]
        }),
    ))
    .unwrap();
    vec![disco, routing]
}

async fn proxy() -> Proxy {
    let spid_mdq = serve_metadata(idp_metadata_xml(SPID_IDP, SPID_SSO_URL)).await;
    let cie_mdq = serve_metadata(idp_metadata_xml(CIE_IDP, CIE_SSO_URL)).await;
    let sealer = StateSealer::new("disco-flow-test-secret", "TB_STATE").with_secure(false);
    Proxy::new(
        vec![oidc_frontend()],
        vec![
            default_backend(),
            idp_backend("SPID", SPID_IDP, &spid_mdq),
            idp_backend("CIE", CIE_IDP, &cie_mdq),
        ],
        microservices(),
        sealer,
    )
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

fn maybe_location(resp: &Response) -> Option<String> {
    resp.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("location"))
        .map(|(_, v)| v.clone())
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

fn urlenc(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
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

/// Sign a SAML Response for the given request id with the test IdP key.
fn signed_idp_response(req_id: &str, idp_entity: &str, sp_entity: &str, acs_url: &str) -> String {
    use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
    use gamlastan::core::assertion::name_id::NameId;
    use gamlastan::crypto::keys::loader;
    use gamlastan::crypto::{KeyUsage, KeysManager, SamlSigner};
    use gamlastan::profiles::sso::idp as idp_profile;
    use gamlastan::profiles::sso::web_browser::ResponseOptions;
    use gamlastan::xml::serialize::SamlSerialize;

    let now = chrono::Utc::now();
    let options = ResponseOptions {
        idp_entity_id: idp_entity.to_string(),
        in_response_to: Some(req_id.to_string()),
        sp_entity_id: sp_entity.to_string(),
        acs_url: acs_url.to_string(),
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
        sp_name_qualifier: Some(sp_entity.to_string()),
        sp_provided_id: None,
    };
    let response = idp_profile::create_response(
        &options,
        &name_id,
        gamlastan::profiles::sso::web_browser::ResponseTimes::at(now),
    );
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

/// OIDC authorization URL for the default test client `rp-1`.
fn authz_url() -> String {
    authz_url_for("rp-1")
}

/// OIDC authorization URL (code + PKCE) for the given registered client.
/// Both test clients share the redirect URI; only the requester identity
/// differs, which is what the requester-scoped allowlist tests need.
fn authz_url_for(client_id: &str) -> String {
    let verifier = "verifier-abcdefghijklmnop-abcdefghijklmnop";
    let challenge = pkce::s256_challenge(verifier);
    format!(
        "OIDC/authorization?client_id={client_id}&response_type=code&redirect_uri={}&scope=openid&state=st-1&nonce=no-1&code_challenge={}&code_challenge_method=S256",
        urlenc("https://rp.example.com/cb"),
        challenge
    )
}

#[tokio::test]
async fn disco_return_reroutes_backend_and_flow_completes() {
    let proxy = proxy().await;

    // 1) RP starts an OIDC flow; the default SAML2 backend sends the user to
    //    the discovery service; the snapshot rides the state cookie.
    let r1 = proxy.run(req(&authz_url(), "GET", None)).await;
    assert_eq!(r1.status, 302, "{}", String::from_utf8_lossy(&r1.body));
    let disco_url = location(&r1);
    assert!(disco_url.starts_with(DISCO_SRV), "to disco: {disco_url}");
    // The backend's return URL is the path the micro-service shadows.
    assert_eq!(
        query_param(&disco_url, "return").as_deref(),
        Some("https://proxy.example.com/Saml2/disco")
    );
    let cookie1 = set_cookie(&r1).expect("state cookie on disco redirect");

    // 2) The discovery return is intercepted by disco_to_target_issuer, the
    //    pipeline resumes, and the issuer rule re-routes to the SPID backend.
    let disco_return = format!("Saml2/disco?entityID={}", urlenc(SPID_IDP));
    let r2 = proxy.run(req(&disco_return, "GET", Some(&cookie1))).await;
    assert_eq!(r2.status, 302, "{}", String::from_utf8_lossy(&r2.body));
    let sso_redirect = location(&r2);
    assert!(
        sso_redirect.starts_with(SPID_SSO_URL),
        "re-routed to the SPID backend's IdP: {sso_redirect}"
    );
    let req_id = authn_request_id(&sso_redirect);
    let cookie2 = set_cookie(&r2).expect("state cookie after resume");

    // 3) The SPID IdP posts back a signed Response to the SPID backend's ACS;
    //    the flow completes to the RP - the requester and originating frontend
    //    survived the suspend/resume round trip.
    let mut acs_req = req("SPID/acs", "POST", Some(&cookie2));
    acs_req.form = BTreeMap::from([(
        "SAMLResponse".to_string(),
        signed_idp_response(
            &req_id,
            SPID_IDP,
            "https://proxy.example.com/SPID",
            "https://proxy.example.com/SPID/acs",
        ),
    )]);
    let r3 = proxy.run(acs_req).await;
    assert_eq!(r3.status, 302, "{}", String::from_utf8_lossy(&r3.body));
    let rp_redirect = location(&r3);
    assert!(rp_redirect.starts_with("https://rp.example.com/cb?"));
    assert_eq!(query_param(&rp_redirect, "state").as_deref(), Some("st-1"));
    assert!(query_param(&rp_redirect, "code").is_some());
}

#[tokio::test]
async fn cie_issuer_routes_to_cie_backend() {
    let proxy = proxy().await;

    let r1 = proxy.run(req(&authz_url(), "GET", None)).await;
    let cookie1 = set_cookie(&r1).unwrap();

    let disco_return = format!("Saml2/disco?entityID={}", urlenc(CIE_IDP));
    let r2 = proxy.run(req(&disco_return, "GET", Some(&cookie1))).await;
    assert_eq!(r2.status, 302, "{}", String::from_utf8_lossy(&r2.body));
    assert!(location(&r2).starts_with(CIE_SSO_URL));
}

#[tokio::test]
async fn replayed_disco_return_is_rejected() {
    let proxy = proxy().await;

    let r1 = proxy.run(req(&authz_url(), "GET", None)).await;
    let cookie1 = set_cookie(&r1).unwrap();

    let disco_return = format!("Saml2/disco?entityID={}", urlenc(SPID_IDP));
    let r2 = proxy.run(req(&disco_return, "GET", Some(&cookie1))).await;
    assert_eq!(r2.status, 302);
    let cookie2 = set_cookie(&r2).unwrap();

    // The snapshot was consumed: the same return with the post-resume cookie
    // must not start another authentication.
    let r3 = proxy.run(req(&disco_return, "GET", Some(&cookie2))).await;
    if let Some(loc) = maybe_location(&r3) {
        assert!(
            !loc.starts_with(SPID_SSO_URL) && !loc.starts_with(CIE_SSO_URL),
            "replay reached an IdP: {loc}"
        );
    }
}

#[tokio::test]
async fn forged_disco_return_without_flow_fails_cleanly() {
    let proxy = proxy().await;

    let disco_return = format!("Saml2/disco?entityID={}", urlenc(SPID_IDP));
    let r = proxy.run(req(&disco_return, "GET", None)).await;
    assert_ne!(r.status, 302);
    assert_eq!(String::from_utf8(r.body).unwrap(), "request failed");
}

#[tokio::test]
async fn unlisted_issuer_fails_closed_at_the_disco_return() {
    let proxy = proxy().await;

    let r1 = proxy.run(req(&authz_url(), "GET", None)).await;
    let cookie1 = set_cookie(&r1).unwrap();

    // The issuer is not in allowed_issuers: the return is rejected before
    // the pipeline resumes, so the decoration never reaches fallback routing
    // or any backend's metadata resolution.
    let disco_return = format!(
        "Saml2/disco?entityID={}",
        urlenc("https://unlisted-idp.example.org")
    );
    let r2 = proxy.run(req(&disco_return, "GET", Some(&cookie1))).await;
    if let Some(loc) = maybe_location(&r2) {
        assert!(
            !loc.starts_with(SPID_SSO_URL) && !loc.starts_with(CIE_SSO_URL),
            "unlisted issuer reached a configured IdP: {loc}"
        );
    }
    // The snapshot survives the rejection, so a subsequent valid pick works.
    let cookie2 = set_cookie(&r2).unwrap_or(cookie1);
    let retry = format!("Saml2/disco?entityID={}", urlenc(SPID_IDP));
    let r3 = proxy.run(req(&retry, "GET", Some(&cookie2))).await;
    assert_eq!(r3.status, 302, "{}", String::from_utf8_lossy(&r3.body));
    assert!(location(&r3).starts_with(SPID_SSO_URL));
}

/// End-to-end proof that the `allowed_issuers` allowlist is enforced per
/// `(issuer, requester)` pair, not globally. `rp-2` is a registered client
/// with no `allowed_issuers` rule set; an issuer that `rp-1` may pick must
/// not resume `rp-2`'s flow. Without the requester scoping, the
/// target-issuer decoration would survive into `custom_routing`'s
/// requester/default fallback and the default backend's MDQ metadata
/// resolution would authenticate `rp-2` at that issuer anyway.
#[tokio::test]
async fn issuer_allowed_for_another_requester_fails_closed() {
    let proxy = proxy().await;

    // Start a flow as rp-2, reaching the discovery redirect as usual.
    let r1 = proxy.run(req(&authz_url_for("rp-2"), "GET", None)).await;
    assert_eq!(r1.status, 302, "{}", String::from_utf8_lossy(&r1.body));
    let cookie1 = set_cookie(&r1).expect("state cookie on disco redirect");

    let disco_return = format!("Saml2/disco?entityID={}", urlenc(SPID_IDP));
    let r2 = proxy.run(req(&disco_return, "GET", Some(&cookie1))).await;
    if let Some(loc) = maybe_location(&r2) {
        assert!(
            !loc.starts_with(SPID_SSO_URL) && !loc.starts_with(CIE_SSO_URL),
            "another requester's issuer reached a configured IdP: {loc}"
        );
    }
}
