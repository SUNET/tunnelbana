//! The tunnelbana identity proxy server (actix-web).

mod reqwest_client;

use std::collections::BTreeMap;
use std::sync::Arc;

use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use tunnelbana_core::attributes::AttributeMapper;
use tunnelbana_core::config::ProxyConfig;
use tunnelbana_core::http::{HttpClient, HttpRequestData, Response};
use tunnelbana_core::plugin::{BuildContext, Registry};
use tunnelbana_core::proxy::Proxy;
use tunnelbana_core::state::StateSealer;

use reqwest_client::ReqwestClient;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config/proxy.toml".to_string());

    let cfg = ProxyConfig::load(&config_path).unwrap_or_else(|e| {
        eprintln!("failed to load config {config_path}: {e}");
        std::process::exit(1);
    });

    init_tracing(&cfg.logging);

    let bind = std::env::var("TUNNELBANA_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    tracing::info!(base_url = %cfg.base_url, %bind, "starting tunnelbana");

    let proxy = build_proxy(cfg).unwrap_or_else(|e| {
        eprintln!("failed to assemble proxy: {e}");
        std::process::exit(1);
    });
    let proxy = web::Data::new(Arc::new(proxy));

    HttpServer::new(move || {
        App::new()
            .app_data(proxy.clone())
            .default_service(web::to(handle))
    })
    .bind(&bind)?
    .run()
    .await
}

fn init_tracing(logging: &tunnelbana_core::config::LoggingConfig) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(&logging.level).unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    if logging.format == "json" {
        builder.json().init();
    } else {
        builder.init();
    }
}

/// Instantiate all configured plugins and assemble the proxy.
fn build_proxy(cfg: ProxyConfig) -> anyhow::Result<Proxy> {
    let mut registry = Registry::new();
    tunnelbana_plugins::register_all(&mut registry);

    // Attribute mapper.
    let mapper = match &cfg.attributes {
        Some(path) => {
            let toml_str = std::fs::read_to_string(resolve(&cfg, path))?;
            AttributeMapper::from_toml(&toml_str)?
        }
        None => AttributeMapper::default(),
    };
    let mapper = Arc::new(mapper);

    let http: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new());

    let make_ctx = |name: &str, config: serde_json::Value| BuildContext {
        name: name.to_string(),
        base_url: cfg.base_url.clone(),
        config,
        attribute_mapper: mapper.clone(),
        http_client: http.clone(),
        secret: cfg.state_encryption_key.clone(),
        previous_secrets: cfg.previous_state_encryption_keys.clone(),
    };

    let mut frontends = Vec::new();
    for p in &cfg.frontends {
        let bx = make_ctx(&p.name, p.config_json());
        frontends.push(registry.build_frontend(&p.kind, &bx)?);
        tracing::info!(name = %p.name, kind = %p.kind, "loaded frontend");
    }
    let mut backends = Vec::new();
    for p in &cfg.backends {
        let bx = make_ctx(&p.name, p.config_json());
        backends.push(registry.build_backend(&p.kind, &bx)?);
        tracing::info!(name = %p.name, kind = %p.kind, "loaded backend");
    }
    let mut microservices = Vec::new();
    for p in &cfg.microservices {
        let bx = make_ctx(&p.name, p.config_json());
        microservices.push(registry.build_microservice(&p.kind, &bx)?);
        tracing::info!(name = %p.name, kind = %p.kind, "loaded microservice");
    }

    let ttl = if cfg.state_cookie_max_age == 0 {
        None
    } else {
        Some(cfg.state_cookie_max_age)
    };
    let sealer = StateSealer::new(&cfg.state_encryption_key, cfg.cookie_name.clone())
        .with_secure(cfg.cookie_secure)
        .with_same_site(cfg.cookie_same_site.clone())
        .with_ttl_seconds(ttl)
        .with_previous_secrets(&cfg.previous_state_encryption_keys);

    Ok(Proxy::new(frontends, backends, microservices, sealer))
}

fn resolve(cfg: &ProxyConfig, path: &str) -> String {
    // Attribute path is relative to the (already-loaded) config; if absolute use
    // as-is, else relative to cache_dir or cwd. Kept simple: return as given.
    let _ = cfg;
    path.to_string()
}

/// actix entry point: adapt the actix request into our framework type, run the
/// proxy flow, and adapt the framework response back.
async fn handle(req: HttpRequest, body: web::Bytes, proxy: web::Data<Arc<Proxy>>) -> HttpResponse {
    let request = build_request_data(&req, &body);
    let response = proxy.run(request).await;
    to_actix(response)
}

fn build_request_data(req: &HttpRequest, body: &web::Bytes) -> HttpRequestData {
    let path = req.path().trim_start_matches('/').to_string();
    let method = req.method().as_str().to_uppercase();

    let query: BTreeMap<String, String> = form_urlencoded_parse(req.query_string());

    let mut headers = BTreeMap::new();
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            headers.insert(name.as_str().to_lowercase(), v.to_string());
        }
    }

    // Form body (application/x-www-form-urlencoded).
    let is_form = headers
        .get("content-type")
        .map(|c| c.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);
    let form = if is_form {
        form_urlencoded_parse(std::str::from_utf8(body).unwrap_or(""))
    } else {
        BTreeMap::new()
    };

    let cookies = parse_cookies(headers.get("cookie").map(|s| s.as_str()).unwrap_or(""));

    let uri = format!(
        "{}://{}{}",
        req.connection_info().scheme(),
        req.connection_info().host(),
        req.uri()
    );

    HttpRequestData {
        path,
        method,
        uri,
        query,
        form,
        body: body.to_vec(),
        headers,
        cookies,
    }
}

fn form_urlencoded_parse(s: &str) -> BTreeMap<String, String> {
    form_urlencoded::parse(s.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

fn parse_cookies(header: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for part in header.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

fn to_actix(resp: Response) -> HttpResponse {
    let status = actix_web::http::StatusCode::from_u16(resp.status)
        .unwrap_or(actix_web::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut builder = HttpResponse::build(status);
    for (k, v) in &resp.headers {
        builder.append_header((k.clone(), v.clone()));
    }
    builder.body(resp.body)
}
