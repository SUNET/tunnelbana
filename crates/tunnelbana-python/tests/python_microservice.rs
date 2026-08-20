use serde_json::json;
use std::sync::{Arc, Once};
use std::time::Duration;
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::http::HttpRequestData;
use tunnelbana_core::internal::{AuthenticationInformation, InternalData, SubjectType};
use tunnelbana_core::plugin::{BuildContext, MicroService, NullHttpClient};
use tunnelbana_core::{Context, State};
use tunnelbana_python::PythonRuntime;

fn fixture_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn runtime(max: usize, timeout: Duration) -> Arc<PythonRuntime> {
    static TEST_ENV: Once = Once::new();
    // Must be set before the interpreter starts: the isolated configuration
    // is expected to ignore it (see pythonpath_environment_is_ignored).
    // Bytecode caches are disabled by the runtime itself, not an env var.
    TEST_ENV.call_once(|| {
        std::env::set_var(
            "PYTHONPATH",
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pythonpath"),
        )
    });
    PythonRuntime::initialize(fixture_path(), max, timeout).unwrap()
}

fn build(
    runtime: &Arc<PythonRuntime>,
    name: &str,
    module: &str,
    class: &str,
    settings: serde_json::Value,
) -> tunnelbana_core::Result<Box<dyn MicroService>> {
    let bx = BuildContext {
        name: name.into(),
        base_url: "https://proxy.example".into(),
        config: json!({"module": module, "class": class, "settings": settings}),
        attribute_mapper: Arc::new(AttributeMapper::default()),
        http_client: Arc::new(NullHttpClient),
        secret: "not-exposed-to-python".into(),
        previous_secrets: vec![],
    };
    runtime.build_microservice(&bx)
}

fn context() -> Context {
    let request = HttpRequestData {
        path: "frontend/start".into(),
        method: "POST".into(),
        uri: "https://proxy.example/frontend/start?secret=hidden".into(),
        query: [("prompt".into(), "login".into())].into(),
        form: [("client_id".into(), "requester".into())].into(),
        body: b"secret body".to_vec(),
        headers: [("authorization".into(), "Bearer secret".into())].into(),
        cookies: [("session".into(), "secret".into())].into(),
    };
    let mut ctx = Context::new(request, State::new());
    ctx.set_requester("requester");
    ctx.target_frontend = Some("frontend".into());
    ctx
}

fn complete_data() -> InternalData {
    InternalData {
        auth_info: AuthenticationInformation {
            auth_class_ref: Some("urn:example:acr".into()),
            timestamp: Some("2026-08-19T10:00:00Z".into()),
            issuer: Some("https://issuer.example".into()),
        },
        requester: Some("requester".into()),
        requester_name: vec!["Requester".into(), "Begärare".into()],
        subject_id: Some("subject".into()),
        subject_type: SubjectType::Pairwise,
        attributes: [("mail".into(), vec!["user@example.org".into()])].into(),
        force_authn: true,
        is_passive: false,
    }
}

#[tokio::test]
async fn valid_request_transformation_and_settings() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(
        &runtime,
        "request",
        "services",
        "RequestTransform",
        json!({"allowed": ["student", "staff"]}),
    )
    .unwrap();
    let output = service
        .process_request(&mut context(), InternalData::default())
        .await
        .unwrap();
    assert_eq!(output.attributes["affiliation"], ["student", "staff"]);
}

#[tokio::test]
async fn valid_response_transformation() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(
        &runtime,
        "response",
        "services",
        "ResponseTransform",
        json!({"subject": "python-subject"}),
    )
    .unwrap();
    let output = service
        .process_response(&mut context(), InternalData::default())
        .await
        .unwrap();
    assert_eq!(output.subject_id.as_deref(), Some("python-subject"));
}

#[tokio::test]
async fn missing_direction_is_identity() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(&runtime, "one-way", "services", "RequestOnly", json!({})).unwrap();
    let mut ctx = context();
    let input = complete_data();
    let expected = serde_json::to_value(&input).unwrap();
    let output = service.process_response(&mut ctx, input).await.unwrap();
    assert_eq!(serde_json::to_value(output).unwrap(), expected);
}

#[tokio::test]
async fn complete_internal_data_round_trips() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(&runtime, "roundtrip", "services", "RoundTrip", json!({})).unwrap();
    let input = complete_data();
    let expected = serde_json::to_value(&input).unwrap();
    let output = service
        .process_request(&mut context(), input)
        .await
        .unwrap();
    assert_eq!(serde_json::to_value(output).unwrap(), expected);
}

#[tokio::test]
async fn permitted_context_changes_are_committed() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(
        &runtime,
        "context",
        "services",
        "ContextMutation",
        json!({}),
    )
    .unwrap();
    let mut ctx = context();
    service
        .process_request(&mut ctx, InternalData::default())
        .await
        .unwrap();
    assert_eq!(ctx.target_backend.as_deref(), Some("python-selected"));
    assert_eq!(ctx.decorations["python"], json!({"accepted": true}));
}

#[tokio::test]
async fn read_only_context_mutation_is_rejected_atomically() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(
        &runtime,
        "readonly",
        "services",
        "ReadOnlyMutation",
        json!({}),
    )
    .unwrap();
    let mut ctx = context();
    ctx.target_backend = Some("original".into());
    ctx.decorations.insert("original".into(), json!(true));
    let error = service
        .process_request(&mut ctx, InternalData::default())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "internal error: python microservice returned invalid output"
    );
    assert_eq!(ctx.request.method, "POST");
    assert_eq!(ctx.target_backend.as_deref(), Some("original"));
    assert_eq!(ctx.decorations, [("original".into(), json!(true))].into());
}

#[tokio::test]
async fn malformed_internal_data_is_rejected_atomically() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(
        &runtime,
        "malformed",
        "services",
        "MalformedData",
        json!({}),
    )
    .unwrap();
    let mut ctx = context();
    ctx.target_backend = Some("original".into());
    let error = service
        .process_request(&mut ctx, InternalData::default())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "internal error: python microservice returned invalid output"
    );
    assert_eq!(ctx.target_backend.as_deref(), Some("original"));
}

#[tokio::test]
async fn reserved_decorations_are_first_writer_wins() {
    let runtime = runtime(4, Duration::from_secs(2));
    let writer = build(
        &runtime,
        "reserved-writer",
        "services",
        "TargetEntityWriter",
        json!({}),
    )
    .unwrap();

    // Publishing the target entity id when absent is allowed.
    let mut ctx = context();
    writer
        .process_request(&mut ctx, InternalData::default())
        .await
        .unwrap();
    assert_eq!(
        ctx.decorations["target_entity_id"],
        json!("https://python-chosen-idp.example")
    );

    // Changing a value another component already set is rejected atomically.
    let mut ctx = context();
    ctx.decorations.insert(
        "target_entity_id".into(),
        json!("https://discovery-chosen.example"),
    );
    let error = writer
        .process_request(&mut ctx, InternalData::default())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "internal error: python microservice returned invalid output"
    );
    assert_eq!(
        ctx.decorations["target_entity_id"],
        json!("https://discovery-chosen.example")
    );

    // Removing it is a change too.
    let remover = build(
        &runtime,
        "reserved-remover",
        "services",
        "TargetEntityRemover",
        json!({}),
    )
    .unwrap();
    let mut ctx = context();
    ctx.decorations.insert(
        "target_entity_id".into(),
        json!("https://discovery-chosen.example"),
    );
    assert!(remover
        .process_request(&mut ctx, InternalData::default())
        .await
        .is_err());
    assert_eq!(
        ctx.decorations["target_entity_id"],
        json!("https://discovery-chosen.example")
    );
}

#[test]
fn pythonpath_environment_is_ignored() {
    let runtime = runtime(4, Duration::from_secs(2));
    // env_probe.py sits in the directory PYTHONPATH points at (set before the
    // interpreter started) and would build successfully if the interpreter
    // honored the environment. The isolated configuration must reject it.
    assert!(build(&runtime, "env-probe", "env_probe", "EnvProbe", json!({})).is_err());
}

#[test]
fn initialize_rejects_a_second_module_path() {
    let _runtime = runtime(4, Duration::from_secs(2));
    let other = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/pythonpath");
    let error = PythonRuntime::initialize(other, 4, Duration::from_secs(2))
        .err()
        .expect("a second module path must be rejected");
    assert!(error.to_string().contains("different module path"));
}

#[tokio::test]
async fn exceptions_have_sanitized_outward_errors() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(&runtime, "raises", "services", "Raises", json!({})).unwrap();
    let error = service
        .process_request(&mut context(), InternalData::default())
        .await
        .unwrap_err();
    let message = error.to_string();
    assert_eq!(
        message,
        "internal error: python microservice returned invalid output"
    );
    assert!(!message.contains("secret-input"));
}

#[tokio::test]
async fn coroutine_methods_and_awaitable_results_are_rejected() {
    let runtime = runtime(4, Duration::from_secs(2));
    assert!(build(
        &runtime,
        "coroutine",
        "services",
        "CoroutineMethod",
        json!({})
    )
    .is_err());

    let service = build(
        &runtime,
        "awaitable",
        "services",
        "AwaitableReturn",
        json!({}),
    )
    .unwrap();
    let error = service
        .process_request(&mut context(), InternalData::default())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "internal error: python microservice returned invalid output"
    );
}

#[test]
fn imports_classes_methods_constructors_and_config_are_validated() {
    let runtime = runtime(4, Duration::from_secs(2));
    for (module, class) in [
        ("missing_module", "Anything"),
        ("services", "MissingClass"),
        ("services", "NoMethods"),
        ("services", "NonCallableMethod"),
        ("services", "ConstructorFailure"),
    ] {
        assert!(
            build(&runtime, "invalid", module, class, json!({})).is_err(),
            "accepted {module}.{class}"
        );
    }
    let bx = BuildContext {
        name: "unknown-field".into(),
        base_url: "https://proxy.example".into(),
        config: json!({
            "module": "services",
            "class": "RoundTrip",
            "unexpected": true
        }),
        attribute_mapper: Arc::new(AttributeMapper::default()),
        http_client: Arc::new(NullHttpClient),
        secret: "secret".into(),
        previous_secrets: vec![],
    };
    assert!(runtime.build_microservice(&bx).is_err());
}

#[tokio::test]
async fn configured_class_instance_is_reused() {
    let runtime = runtime(4, Duration::from_secs(2));
    let service = build(&runtime, "reuse", "services", "ReusedInstance", json!({})).unwrap();
    let first = service
        .process_request(&mut context(), InternalData::default())
        .await
        .unwrap();
    let second = service
        .process_request(&mut context(), InternalData::default())
        .await
        .unwrap();
    assert_eq!(first.subject_id.as_deref(), Some("1"));
    assert_eq!(second.subject_id.as_deref(), Some("2"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_semaphore_limits_concurrency() {
    let runtime = runtime(1, Duration::from_secs(3));
    let one = build(
        &runtime,
        "concurrency-one",
        "services",
        "ConcurrencyProbe",
        json!({"wait_seconds": 0.15}),
    )
    .unwrap();
    let two = build(
        &runtime,
        "concurrency-two",
        "services",
        "ConcurrencyProbe",
        json!({"wait_seconds": 0.15}),
    )
    .unwrap();
    let first = tokio::spawn(async move {
        one.process_request(&mut context(), InternalData::default())
            .await
    });
    let second = tokio::spawn(async move {
        two.process_request(&mut context(), InternalData::default())
            .await
    });
    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    assert_eq!(first.subject_id.as_deref(), Some("1"));
    assert_eq!(second.subject_id.as_deref(), Some("1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timed_out_call_retains_permit_until_python_exits() {
    let runtime = runtime(1, Duration::from_millis(50));
    let service = build(
        &runtime,
        "slow",
        "services",
        "SlowCall",
        json!({"delay": 0.3}),
    )
    .unwrap();
    let error = service
        .process_request(&mut context(), InternalData::default())
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "internal error: python microservice call timed out"
    );
    assert_eq!(runtime.available_permits(), 0);

    // The same total deadline also applies while waiting for the permit still
    // owned by the detached first call.
    let waiting_error = service
        .process_request(&mut context(), InternalData::default())
        .await
        .unwrap_err();
    assert_eq!(
        waiting_error.to_string(),
        "internal error: python microservice call timed out"
    );
    assert_eq!(runtime.available_permits(), 0);

    tokio::time::timeout(Duration::from_secs(2), async {
        while runtime.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(runtime.available_permits(), 1);
}
