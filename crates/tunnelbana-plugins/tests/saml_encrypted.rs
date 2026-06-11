//! B2: encrypted assertions at the SAML2 backend's ACS. Responses are
//! encrypted in-test with gamlastan's `SamlEncryptor` (AES-256-GCM data,
//! RSA-OAEP key transport to the SP's cert) and presented to the backend,
//! exercising decryption, the cross-encryption-boundary signature rule, key
//! rotation, EncryptedID and the metadata encryption KeyDescriptor.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::context::Context;
use tunnelbana_core::http::HttpRequestData;
use tunnelbana_core::plugin::{Backend, BackendAction, BuildContext, NullHttpClient};
use tunnelbana_core::state::State;

use gamlastan::core::assertion::attribute::{Attribute, AttributeValue};
use gamlastan::core::assertion::name_id::{EncryptedId, NameId, NameIdOrEncryptedId};
use gamlastan::core::assertion::types::EncryptedAssertion;
use gamlastan::core::protocol::response::Response as SamlResponse;
use gamlastan::crypto::keys::loader;
use gamlastan::crypto::{KeyUsage, KeysManager, SamlEncryptor, SamlSigner};
use gamlastan::profiles::sso::idp as idp_profile;
use gamlastan::profiles::sso::web_browser::ResponseOptions;
use gamlastan::xml::serialize::SamlSerialize;

const BASE: &str = "https://proxy.example.com";
const IDP_ENTITY: &str = "https://idp.example.org";
const SP_ENTITY: &str = "https://proxy.example.com/SP";
const ACS_URL: &str = "https://proxy.example.com/SP/acs";
const REQ_ID: &str = "_encreq1";
const NS_SAML: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

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

fn mapper() -> Arc<AttributeMapper> {
    Arc::new(
        AttributeMapper::from_toml(
            r#"
            [attributes.mail]
            saml = ["mail"]
        "#,
        )
        .unwrap(),
    )
}

/// SAML2 backend with the standard static-IdP test config plus `extra`.
fn backend_with(extra: serde_json::Value) -> Box<dyn Backend> {
    let mut config = serde_json::json!({
        "sp_key_path": testdata("sp-key.pem"),
        "sp_cert_path": testdata("sp-cert.pem"),
        "idp_entity_id": IDP_ENTITY,
        "idp_sso_url": "https://idp.example.org/sso",
        "idp_cert_path": testdata("idp-cert.pem"),
        "security": "permissive"
    });
    config
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let bx = BuildContext {
        name: "SP".to_string(),
        base_url: BASE.to_string(),
        config,
        attribute_mapper: mapper(),
        http_client: Arc::new(NullHttpClient),
        secret: "enc-test-secret".to_string(),
        previous_secrets: Vec::new(),
    };
    tunnelbana_plugins::saml2_backend::Saml2Backend::build(&bx).unwrap()
}

fn sp_keypairs() -> serde_json::Value {
    serde_json::json!({
        "encryption_keypairs": [
            { "key_path": testdata("sp-key.pem"), "cert_path": testdata("sp-cert.pem") }
        ]
    })
}

/// Signer over the IdP test key (with cert chain for KeyInfo).
fn idp_signer() -> (SamlSigner, String) {
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
    (SamlSigner::new(km), cert_b64)
}

/// Encryptor towards the SP's certificate (the recipient).
fn sp_encryptor() -> SamlEncryptor {
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(cert_b64(&testdata("sp-cert.pem")))
        .unwrap();
    let mut key = loader::load_x509_cert_der(&cert_der).unwrap();
    key.usage = KeyUsage::Encrypt;
    let mut km = KeysManager::new();
    km.add_key(key);
    SamlEncryptor::new(km)
}

/// xmlsec-style template: AES-256-GCM data encryption, RSA-OAEP key transport.
fn encryption_template() -> &'static str {
    r#"<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue/></xenc:CipherData></xenc:EncryptedData>"#
}

/// Encrypt an XML element and wrap it in the given SAML wrapper element.
fn encrypt_wrapped(plaintext: &str, wrapper: &str) -> Vec<u8> {
    let encrypted = sp_encryptor()
        .encrypt(encryption_template(), plaintext.as_bytes())
        .unwrap();
    format!(r#"<saml:{wrapper} xmlns:saml="{NS_SAML}">{encrypted}</saml:{wrapper}>"#).into_bytes()
}

/// Insert a ds:Signature template right after the opening tag of `element`.
fn insert_signature(xml: &str, element: &str, reference_id: &str, cert_b64: &str) -> String {
    let sig = format!(
        r##"<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#{reference_id}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue/></ds:Reference></ds:SignedInfo><ds:SignatureValue/><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>"##
    );
    let tag_start = xml.find(&format!("<{element}")).unwrap();
    let rel = xml[tag_start..].find('>').unwrap();
    let pos = tag_start + rel;
    format!("{}{}{}", &xml[..=pos], sig, &xml[pos + 1..])
}

/// A fresh success Response for the test SP.
fn make_response(name_id: Option<NameIdOrEncryptedId>) -> SamlResponse {
    let options = ResponseOptions {
        idp_entity_id: IDP_ENTITY.to_string(),
        in_response_to: Some(REQ_ID.to_string()),
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
    let plain_name_id = NameId {
        value: "anna-persistent-id".to_string(),
        format: Some("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".to_string()),
        name_qualifier: None,
        sp_name_qualifier: Some(SP_ENTITY.to_string()),
        sp_provided_id: None,
    };
    let mut response = idp_profile::create_response(&options, &plain_name_id, chrono::Utc::now());
    if let Some(replacement) = name_id {
        response.assertions[0].subject.as_mut().unwrap().name_id = Some(replacement);
    }
    response
}

/// Encrypt the response's assertions (optionally signing each assertion
/// first), then optionally sign the Response envelope. Returns base64.
fn encrypted_response_b64(sign_assertion: bool, sign_envelope: bool) -> String {
    encrypted_response_b64_with(make_response(None), sign_assertion, sign_envelope)
}

fn encrypted_response_b64_with(
    mut response: SamlResponse,
    sign_assertion: bool,
    sign_envelope: bool,
) -> String {
    let (signer, idp_cert) = idp_signer();

    let assertions = std::mem::take(&mut response.assertions);
    for assertion in &assertions {
        let mut plaintext = assertion.to_xml_string().unwrap();
        if sign_assertion {
            plaintext = insert_signature(&plaintext, "saml:Assertion", &assertion.id, &idp_cert);
            plaintext = signer.sign_enveloped(&plaintext).unwrap();
        }
        response.encrypted_assertions.push(EncryptedAssertion {
            raw: encrypt_wrapped(&plaintext, "EncryptedAssertion"),
        });
    }

    let mut xml = response.to_xml_string().unwrap();
    if sign_envelope {
        xml = insert_signature(&xml, "samlp:Response", &response.base.id, &idp_cert);
        xml = signer.sign_enveloped(&xml).unwrap();
    }
    base64::engine::general_purpose::STANDARD.encode(xml.as_bytes())
}

async fn run_acs(
    backend: &dyn Backend,
    b64: String,
) -> tunnelbana_core::error::Result<BackendAction> {
    let mut ctx = Context::new(
        HttpRequestData {
            path: "SP/acs".into(),
            method: "POST".into(),
            form: BTreeMap::from([("SAMLResponse".to_string(), b64)]),
            ..Default::default()
        },
        State::new(),
    );
    ctx.state.set_str("SP", "authn_id", REQ_ID);
    backend.handle_endpoint(&mut ctx, "acs").await
}

fn assert_anna(action: BackendAction) {
    match action {
        BackendAction::AuthResponse(data) => {
            assert_eq!(data.subject_id.as_deref(), Some("anna-persistent-id"));
            assert_eq!(data.attr_first("mail"), Some("anna@example.com"));
        }
        _ => panic!("expected AuthResponse"),
    }
}

#[tokio::test]
async fn encrypted_assertion_in_signed_response_is_accepted() {
    let backend = backend_with(sp_keypairs());
    let action = run_acs(backend.as_ref(), encrypted_response_b64(false, true))
        .await
        .unwrap();
    assert_anna(action);
}

#[tokio::test]
async fn encrypted_signed_assertion_in_unsigned_response_is_accepted() {
    let backend = backend_with(sp_keypairs());
    let action = run_acs(backend.as_ref(), encrypted_response_b64(true, false))
        .await
        .unwrap();
    assert_anna(action);
}

#[tokio::test]
async fn encrypted_but_nothing_signed_is_rejected() {
    let backend = backend_with(sp_keypairs());
    let result = run_acs(backend.as_ref(), encrypted_response_b64(false, false)).await;
    assert!(
        result.is_err(),
        "neither envelope nor assertion signed must be rejected"
    );
}

#[tokio::test]
async fn encrypted_without_configured_keypairs_is_rejected() {
    let backend = backend_with(serde_json::json!({}));
    let result = run_acs(backend.as_ref(), encrypted_response_b64(false, true)).await;
    let err = result.err().expect("must fail without encryption keys");
    assert!(
        err.to_string().contains("encryption_keypairs"),
        "error names the missing config: {err}"
    );
}

#[tokio::test]
async fn second_keypair_decrypts_after_rotation() {
    // First decryptor is a different (wrong) key; the second matches the
    // cert the response was encrypted to.
    let backend = backend_with(serde_json::json!({
        "encryption_keypairs": [
            { "key_path": testdata("idp-key.pem") },
            { "key_path": testdata("sp-key.pem"), "cert_path": testdata("sp-cert.pem") }
        ]
    }));
    let action = run_acs(backend.as_ref(), encrypted_response_b64(false, true))
        .await
        .unwrap();
    assert_anna(action);
}

#[tokio::test]
async fn tampered_ciphertext_is_rejected() {
    let backend = backend_with(sp_keypairs());
    let b64 = encrypted_response_b64(true, false);
    let xml = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .unwrap(),
    )
    .unwrap();
    // Flip characters in the *data* CipherValue (the last one in document
    // order), keeping valid base64 so the failure is cryptographic.
    let last_cv = xml.rfind("<xenc:CipherValue>").unwrap() + "<xenc:CipherValue>".len();
    let mut tampered = xml.clone();
    let target = &xml[last_cv..last_cv + 8];
    let flipped: String = target
        .chars()
        .map(|c| if c == 'A' { 'B' } else { 'A' })
        .collect();
    tampered.replace_range(last_cv..last_cv + 8, &flipped);
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(tampered.as_bytes());

    let result = run_acs(backend.as_ref(), tampered_b64).await;
    assert!(result.is_err(), "tampered ciphertext must be rejected");
}

#[tokio::test]
async fn encrypted_name_id_is_decrypted() {
    let backend = backend_with(sp_keypairs());

    // Encrypt the NameID element and put it in the assertion as EncryptedID.
    let name_id_xml = format!(
        r#"<saml:NameID xmlns:saml="{NS_SAML}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPNameQualifier="{SP_ENTITY}">anna-persistent-id</saml:NameID>"#
    );
    let encrypted_id = NameIdOrEncryptedId::EncryptedId(EncryptedId {
        raw: encrypt_wrapped(&name_id_xml, "EncryptedID"),
    });
    let response = make_response(Some(encrypted_id));
    let b64 = encrypted_response_b64_with(response, false, true);

    let action = run_acs(backend.as_ref(), b64).await.unwrap();
    assert_anna(action);
}

#[tokio::test]
async fn metadata_publishes_encryption_key_descriptor() {
    let backend = backend_with(sp_keypairs());
    let mut ctx = Context::new(HttpRequestData::default(), State::new());
    let action = backend.handle_endpoint(&mut ctx, "metadata").await.unwrap();
    let xml = match action {
        BackendAction::Respond(resp) => String::from_utf8(resp.body).unwrap(),
        _ => panic!("expected metadata response"),
    };
    assert!(xml.contains(r#"use="encryption""#));

    let doc = gamlastan::xml::uppsala::parse(&xml).unwrap();
    let entity = gamlastan::xml::deserialize::parse_saml::<
        gamlastan::metadata::types::entity_descriptor::EntityDescriptorRef<'_>,
    >(&doc)
    .unwrap()
    .to_owned();
    let sp_sso = &entity.sp_sso_descriptors()[0];
    assert!(
        !sp_sso.encryption_certificates_der().is_empty(),
        "encryption cert resolvable via the new gamlastan helper"
    );
}
