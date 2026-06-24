//! `accr` plumbing: a real SAML AuthnRequest carrying a `RequestedAuthnContext`
//! flows through our SAML2 **frontend** (which publishes the requested ACCR as a
//! decoration) and then the `accr` micro-service (which filters, rewrites and
//! re-publishes it for the backend). Proves the request-path plumbing end to end.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::{
    Context, KEY_REQUESTED_ACCR, KEY_TARGET_ACCR_COMPARISON, KEY_TARGET_AUTHN_CONTEXT_CLASS_REF,
};
use tunnelbana_core::http::HttpRequestData;
use tunnelbana_core::plugin::{
    BuildContext, Frontend, FrontendAction, MicroService, NullHttpClient, Registry,
};
use tunnelbana_core::state::State;

const BASE: &str = "https://proxy.example.com";
const SP_ENTITY: &str = "https://proxy.example.com/SP";
const ACS_URL: &str = "https://proxy.example.com/SP/acs";
const MFA: &str = "https://refeds.org/profile/mfa";
const SFA: &str = "https://refeds.org/profile/sfa";
const UPSTREAM_MFA: &str = "http://id.elegnamnden.se/loa/1.0/loa2";

fn testdata(file: &str) -> String {
    format!("{}/testdata/{}", env!("CARGO_MANIFEST_DIR"), file)
}

fn build_ctx(name: &str, config: serde_json::Value) -> BuildContext {
    BuildContext {
        name: name.to_string(),
        base_url: BASE.to_string(),
        config,
        attribute_mapper: Arc::new(AttributeMapper::default()),
        http_client: Arc::new(NullHttpClient),
        secret: "accr-test-secret".to_string(),
        previous_secrets: Vec::new(),
    }
}

fn frontend() -> Box<dyn Frontend> {
    let config = serde_json::json!({
        "idp_key_path": testdata("idp-key.pem"),
        "idp_cert_path": testdata("idp-cert.pem"),
        "sign_assertions": true,
        "name_id_format": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        "metadata": { "local": [testdata("sp-metadata.xml")] }
    });
    tunnelbana_plugins::saml2_frontend::Saml2Frontend::build(&build_ctx("IdP", config)).unwrap()
}

/// Build an AuthnRequest carrying a RequestedAuthnContext, base64 for HTTP-POST.
fn authn_request_with_accr(refs: &[&str], comparison: &str) -> String {
    use gamlastan::core::protocol::request::AuthnContextComparison;
    use gamlastan::profiles::sso::sp;
    use gamlastan::profiles::sso::web_browser::AuthnRequestOptions;
    use gamlastan::xml::serialize::SamlSerialize;

    let opts = AuthnRequestOptions {
        sp_entity_id: SP_ENTITY.to_string(),
        acs_url: Some(ACS_URL.to_string()),
        destination: Some("https://proxy.example.com/IdP/sso".to_string()),
        protocol_binding: Some("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".to_string()),
        allow_create: true,
        authn_context_class_refs: refs.iter().map(|s| s.to_string()).collect(),
        authn_context_comparison: comparison.parse::<AuthnContextComparison>().ok(),
        ..Default::default()
    };
    let req = sp::create_authn_request(&opts).unwrap();
    let xml = req.to_xml_string().unwrap();
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

fn accr_microservice() -> Box<dyn MicroService> {
    let mut registry = Registry::new();
    tunnelbana_plugins::register_all(&mut registry);
    registry
        .build_microservice(
            "accr",
            &build_ctx(
                "accr",
                serde_json::json!({
                    "supported_accr_sorted_by_prio": [MFA, SFA],
                    "internal_accr_rewrite_map": { MFA: UPSTREAM_MFA }
                }),
            ),
        )
        .unwrap()
}

fn decoration_list(ctx: &Context, key: &str) -> Vec<String> {
    ctx.decoration(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn requested_accr_flows_frontend_to_backend_signal() {
    let idp = frontend();
    let authn_b64 = authn_request_with_accr(&[MFA], "minimum");

    let mut ctx = Context::new(
        HttpRequestData {
            method: "POST".into(),
            path: "IdP/sso".into(),
            form: BTreeMap::from([("SAMLRequest".to_string(), authn_b64)]),
            ..Default::default()
        },
        State::new(),
    );

    let action = idp.handle_endpoint(&mut ctx, "sso").await.unwrap();
    let request = match action {
        FrontendAction::StartAuth { request, .. } => request,
        _ => panic!("expected StartAuth"),
    };

    // The frontend published the SP's requested ACCR.
    assert_eq!(
        decoration_list(&ctx, KEY_REQUESTED_ACCR),
        vec![MFA.to_string()]
    );

    // The accr micro-service rewrites it for the upstream IdP and forwards it.
    let accr = accr_microservice();
    let _ = accr.process_request(&mut ctx, request).await.unwrap();

    assert_eq!(
        decoration_list(&ctx, KEY_TARGET_AUTHN_CONTEXT_CLASS_REF),
        vec![UPSTREAM_MFA.to_string()]
    );
    assert_eq!(
        ctx.decoration(KEY_TARGET_ACCR_COMPARISON)
            .and_then(|v| v.as_str()),
        Some("minimum")
    );
}
