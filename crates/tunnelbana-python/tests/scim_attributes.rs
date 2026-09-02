use serde_json::json;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::http::HttpRequestData;
use tunnelbana_core::internal::{AuthenticationInformation, InternalData};
use tunnelbana_core::plugin::{BuildContext, MicroService, NullHttpClient};
use tunnelbana_core::{Context, State};
use tunnelbana_python::PythonRuntime;

fn runtime() -> Arc<PythonRuntime> {
    static RUNTIME: OnceLock<Arc<PythonRuntime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            let modules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../python");
            PythonRuntime::initialize(modules, None::<&std::path::Path>, 4, Duration::from_secs(2))
                .unwrap()
        })
        .clone()
}

fn mapper() -> AttributeMapper {
    AttributeMapper::from_toml(
        r#"
        [attributes.edupersonprincipalname]
        saml = { names = ["eduPersonPrincipalName"], oid = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", friendly_name = "eduPersonPrincipalName" }

        [attributes.mail]
        saml = { names = ["mail"], oid = "urn:oid:0.9.2342.19200300.100.1.3", friendly_name = "mail" }

        [attributes.displayname]
        saml = ["displayName"]
        "#,
    )
    .unwrap()
}

fn build(settings: serde_json::Value) -> tunnelbana_core::Result<Box<dyn MicroService>> {
    let bx = BuildContext {
        name: "scim".into(),
        base_url: "https://proxy.example".into(),
        config: json!({
            "module": "testsupport.scim_fakes",
            "class": "FakeScimAttributes",
            "pass_internal_attributes": true,
            "settings": settings,
        }),
        attribute_mapper: Arc::new(mapper()),
        http_client: Arc::new(NullHttpClient),
        secret: "not-exposed-to-python".into(),
        previous_secrets: vec![],
    };
    runtime().build_microservice(&bx, &[])
}

fn context(frontend: &str) -> Context {
    let mut ctx = Context::new(HttpRequestData::default(), State::new());
    ctx.target_frontend = Some(frontend.into());
    ctx
}

fn response(external_id: &str, issuer: &str) -> InternalData {
    InternalData {
        auth_info: AuthenticationInformation {
            issuer: Some(issuer.into()),
            ..Default::default()
        },
        attributes: [("edupersonprincipalname".into(), vec![external_id.into()])].into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn enriches_profile_groups_and_stepup_accounts() {
    let service = build(json!({
        "mongo_uri": "mongodb://unused.test",
        "neo4j_uri": "bolt://unused.test",
        "virt_idp_to_data_owner": {"SamlFrontend": "example.org"},
        "mfa_stepup_issuer_to_entity_id": {
            "eduid.se": "https://login.idp.eduid.se/idp.xml"
        },
        "fake_users": {
            "example.org": {
                "user@example.org": {
                    "scim_id": "scim-user",
                    "profiles": {
                        "z-profile": {"displayName": ["Wrong profile"]},
                        "a-profile": {
                            "mail": ["user@example.org"],
                            "displayName": "Example User"
                        }
                    },
                    "linked_accounts": [
                        {
                            "issuer": "eduid.se",
                            "value": "linked@eduid.se",
                            "parameters": {"mfa_stepup": true}
                        },
                        {
                            "issuer": "eduid.se",
                            "value": "not-enabled@eduid.se",
                            "parameters": {"mfa_stepup": false}
                        }
                    ]
                }
            }
        },
        "fake_groups": {
            "example.org": {
                "scope": "example.org",
                "member": ["group-1"],
                "manager": ["group-2"]
            }
        }
    }))
    .unwrap();
    let mut ctx = context("SamlFrontend");
    let output = service
        .process_response(
            &mut ctx,
            response("user@example.org", "https://idp.example.org"),
        )
        .await
        .unwrap();

    assert_eq!(output.attributes["mail"], ["user@example.org"]);
    assert_eq!(output.attributes["displayname"], ["Example User"]);
    assert_eq!(
        output.attributes["edupersonentitlement"],
        [
            "example.org:group:group-1#eduid-iam",
            "example.org:group:group-2:role=manager#eduid-iam"
        ]
    );
    assert_eq!(
        ctx.decorations["mfa_stepup_accounts"],
        json!([{
            "entity_id": "https://login.idp.eduid.se/idp.xml",
            "identifier": "linked@eduid.se",
            "attribute": "eduPersonPrincipalName",
            "assurance": "eduPersonAssurance"
        }])
    );
}

#[tokio::test]
async fn resolves_data_owner_from_trusted_provider_scopes() {
    let service = build(json!({
        "mongo_uri": "mongodb://unused.test",
        "scope_to_data_owner": {"scope.example": "owner.example"},
        "fake_users": {
            "owner.example": {
                "user@example.org": {
                    "profiles": {"default": {"mail": ["scoped@example.org"]}}
                }
            }
        }
    }))
    .unwrap();
    let mut ctx = context("SamlFrontend");
    ctx.decorations.insert(
        "provider_scopes".into(),
        json!(["unmatched.example", "scope.example"]),
    );
    let output = service
        .process_response(
            &mut ctx,
            response("user@example.org", "https://idp.example.org"),
        )
        .await
        .unwrap();
    assert_eq!(output.attributes["mail"], ["scoped@example.org"]);
}

#[tokio::test]
async fn missing_user_obeys_per_frontend_allow_policy() {
    let service = build(json!({
        "mongo_uri": "mongodb://unused.test",
        "fallback_data_owner": "example.org",
        "allow_users_not_in_database": {
            "default": false,
            "AllowedFrontend": true
        }
    }))
    .unwrap();

    let mut allowed = context("AllowedFrontend");
    let input = response("missing@example.org", "https://idp.example.org");
    let expected = serde_json::to_value(&input).unwrap();
    let output = service.process_response(&mut allowed, input).await.unwrap();
    assert_eq!(serde_json::to_value(output).unwrap(), expected);
    assert_eq!(allowed.decorations["mfa_stepup_accounts"], json!([]));

    let mut denied = context("DeniedFrontend");
    let error = service
        .process_response(
            &mut denied,
            response("missing@example.org", "https://idp.example.org"),
        )
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "internal error: python microservice returned invalid output"
    );
}

#[tokio::test]
async fn missing_data_owner_obeys_the_same_fail_closed_policy() {
    let service = build(json!({
        "mongo_uri": "mongodb://unused.test",
        "allow_users_not_in_database": {
            "default": false,
            "AllowedFrontend": true
        }
    }))
    .unwrap();

    let mut allowed = context("AllowedFrontend");
    service
        .process_response(
            &mut allowed,
            response("user@example.org", "https://unmapped-idp.example.org"),
        )
        .await
        .unwrap();
    assert_eq!(allowed.decorations["mfa_stepup_accounts"], json!([]));

    let mut denied = context("DeniedFrontend");
    assert!(service
        .process_response(
            &mut denied,
            response("user@example.org", "https://unmapped-idp.example.org"),
        )
        .await
        .is_err());
}

#[tokio::test]
async fn no_scim_owner_is_an_explicit_pass_through() {
    let service = build(json!({
        "mongo_uri": "mongodb://unused.test",
        "virt_idp_to_data_owner": {"EntraFrontend": "no-scim"}
    }))
    .unwrap();
    let mut ctx = context("EntraFrontend");
    let input = response("user@example.org", "https://entra.example.org");
    let expected = serde_json::to_value(&input).unwrap();
    let output = service.process_response(&mut ctx, input).await.unwrap();
    assert_eq!(serde_json::to_value(output).unwrap(), expected);
    assert_eq!(ctx.decorations["mfa_stepup_accounts"], json!([]));
}

#[test]
fn requires_attribute_map_opt_in_and_an_eppn_mapping() {
    let bx = BuildContext {
        name: "scim-invalid".into(),
        base_url: "https://proxy.example".into(),
        config: json!({
            "module": "tunnelbana_scimapi.scim_attributes",
            "class": "ScimAttributes",
            "settings": {"mongo_uri": "mongodb://unused.test"}
        }),
        attribute_mapper: Arc::new(mapper()),
        http_client: Arc::new(NullHttpClient),
        secret: "not-exposed-to-python".into(),
        previous_secrets: vec![],
    };
    assert!(runtime().build_microservice(&bx, &[]).is_err());

    let bx = BuildContext {
        name: "scim-invalid-map".into(),
        config: json!({
            "module": "tunnelbana_scimapi.scim_attributes",
            "class": "ScimAttributes",
            "pass_internal_attributes": true,
            "settings": {"mongo_uri": "mongodb://unused.test"}
        }),
        attribute_mapper: Arc::new(AttributeMapper::default()),
        ..bx
    };
    assert!(runtime().build_microservice(&bx, &[]).is_err());
}

#[test]
fn configured_adapter_fails_startup_when_eduid_dependency_cannot_load() {
    let bx = BuildContext {
        name: "scim-missing-dependency".into(),
        base_url: "https://proxy.example".into(),
        config: json!({
            "module": "testsupport.scim_fakes",
            "class": "MissingDependencyScimAttributes",
            "pass_internal_attributes": true,
            "settings": {"mongo_uri": "mongodb://unused.test"}
        }),
        attribute_mapper: Arc::new(mapper()),
        http_client: Arc::new(NullHttpClient),
        secret: "not-exposed-to-python".into(),
        previous_secrets: vec![],
    };

    assert!(runtime().build_microservice(&bx, &[]).is_err());
}

#[test]
fn unknown_configuration_keys_are_reported_in_sorted_order() {
    use pyo3::types::{PyAnyMethods, PyDict, PyDictMethods, PyStringMethods};

    let _runtime = runtime();
    pyo3::Python::attach(|py| {
        let module = py.import("tunnelbana_scimapi.scim_attributes").unwrap();
        let class = module.getattr("ScimAttributes").unwrap();
        let settings = PyDict::new(py);
        settings.set_item("z_typo", true).unwrap();
        settings.set_item("a_typo", true).unwrap();
        let error = class
            .call1(("scim", "https://proxy.example", settings, PyDict::new(py)))
            .unwrap_err();
        let message = error.value(py).str().unwrap();
        assert_eq!(
            message.to_str().unwrap(),
            "unknown ScimAttributes configuration keys: a_typo, z_typo"
        );
    });
}
