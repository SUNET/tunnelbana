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

    // Resolve the index page once at boot. A configured but unreadable file is a
    // fatal config error (fail-fast), never a silent fall-back to the default.
    let index_page = load_index_page(&cfg, &config_path).unwrap_or_else(|e| {
        eprintln!("failed to load index_html: {e}");
        std::process::exit(1);
    });
    let index_page = web::Data::new(index_page);

    let proxy = build_proxy(cfg).unwrap_or_else(|e| {
        eprintln!("failed to assemble proxy: {e}");
        std::process::exit(1);
    });
    let proxy = web::Data::new(Arc::new(proxy));

    HttpServer::new(move || {
        App::new()
            .app_data(proxy.clone())
            .app_data(index_page.clone())
            .route("/", web::get().to(index))
            .route("/assets/tunnelbana.png", web::get().to(logo))
            .route("/health", web::get().to(health))
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

/// Liveness/readiness probe. Returns `{"status": "ok"}` and bypasses the proxy
/// flow entirely so orchestrators can health-check without touching identity
/// state.
async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

/// The tunnelbana logo, embedded at compile time from `./assets`.
const LOGO_PNG: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../assets/tunnelbana.png"
));

/// Built-in landing page served at `/` when no `index_html` is configured:
/// logo, one-line tagline, project link.
const DEFAULT_INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Tunnelbana</title>
<style>
  html, body { height: 100%; margin: 0; }
  body {
    background: #ffffff;
    color: #001b39;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 1rem;
    text-align: center;
  }
    img { width: min(500px, 90vw); height: auto; }
  p { font-size: 1.1rem; margin: 0; }
  a { color: #0b63dd; text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
</head>
<body>
  <img src="/assets/tunnelbana.png" alt="Tunnelbana logo">
  <p>Tunnelbana, the fast identity proxy from Sunet.</p>
  <p><a href="https://github.com/SUNET/tunnelbana">https://github.com/SUNET/tunnelbana</a></p>
</body>
</html>
"#;

/// The index page to serve at `/`, resolved once at boot into ready-to-send
/// bytes (cheaply `clone`able per request).
type IndexPage = web::Bytes;

/// Resolve the configured `index_html` (or the built-in default) into the bytes
/// to serve at `/`. A configured path is read relative to the config file (or
/// taken as-is when absolute); an unreadable path is a fatal error.
fn load_index_page(cfg: &ProxyConfig, config_path: &str) -> std::io::Result<IndexPage> {
    match &cfg.index_html {
        Some(rel) => {
            let path = resolve_sibling(config_path, rel);
            let html = std::fs::read_to_string(&path).map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("reading index_html {}: {e}", path.display()),
                )
            })?;
            tracing::info!(path = %path.display(), "serving custom index page at /");
            Ok(web::Bytes::from(html))
        }
        None => Ok(web::Bytes::from_static(DEFAULT_INDEX_HTML.as_bytes())),
    }
}

/// Resolve `rel` against the directory of `config_path` unless it is absolute.
fn resolve_sibling(config_path: &str, rel: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(rel);
    if p.is_absolute() {
        return p.to_path_buf();
    }
    std::path::Path::new(config_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join(p)
}

/// Landing page served at `/` (built-in default, or the admin's `index_html`).
async fn index(page: web::Data<IndexPage>) -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(page.get_ref().clone())
}

/// Serve the embedded logo image.
async fn logo() -> HttpResponse {
    HttpResponse::Ok().content_type("image/png").body(LOGO_PNG)
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test};

    #[actix_web::test]
    async fn health_returns_status_ok() {
        let app = test::init_service(App::new().route("/health", web::get().to(health))).await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body, serde_json::json!({ "status": "ok" }));
    }

    #[actix_web::test]
    async fn index_serves_builtin_landing_page() {
        let page = web::Bytes::from_static(DEFAULT_INDEX_HTML.as_bytes());
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(page))
                .route("/", web::get().to(index)),
        )
        .await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );

        let body = test::read_body(resp).await;
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("Tunnelbana, the fast identity proxy from Sunet."));
        assert!(html.contains("https://github.com/SUNET/tunnelbana"));
        assert!(html.contains("/assets/tunnelbana.png"));
    }

    #[actix_web::test]
    async fn index_serves_custom_page() {
        let page = web::Bytes::from_static(b"<h1>custom</h1>");
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(page))
                .route("/", web::get().to(index)),
        )
        .await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body = test::read_body(resp).await;
        assert_eq!(&body[..], b"<h1>custom</h1>");
    }

    #[actix_web::test]
    async fn load_index_page_defaults_to_builtin_when_unset() {
        let cfg = ProxyConfig::from_str(
            "base_url = \"https://x\"\n\
             state_encryption_key = \"a-32-byte-or-longer-test-secret!!\"\n",
        )
        .unwrap();
        let page = load_index_page(&cfg, "config/proxy.toml").unwrap();
        assert_eq!(page, web::Bytes::from_static(DEFAULT_INDEX_HTML.as_bytes()));
    }

    /// A uniquely-named, freshly-created temp directory. `tag` keeps parallel
    /// tests in the same binary apart; the process id keeps repeated runs apart.
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("tb-index-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // clear any leftover from a crashed run
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[actix_web::test]
    async fn load_index_page_reads_custom_file_relative_to_config() {
        let dir = unique_temp_dir("custom");
        std::fs::write(dir.join("landing.html"), b"<h1>hello</h1>").unwrap();
        let cfg = ProxyConfig::from_str(
            "base_url = \"https://x\"\n\
             state_encryption_key = \"a-32-byte-or-longer-test-secret!!\"\n\
             index_html = \"landing.html\"\n",
        )
        .unwrap();
        let config_path = dir.join("proxy.toml");
        let page = load_index_page(&cfg, config_path.to_str().unwrap()).unwrap();
        assert_eq!(&page[..], b"<h1>hello</h1>");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[actix_web::test]
    async fn load_index_page_errors_on_missing_file() {
        // Use an isolated temp dir so the result never depends on the repo's
        // `config/` contents or the current working directory.
        let dir = unique_temp_dir("missing");
        let cfg = ProxyConfig::from_str(
            "base_url = \"https://x\"\n\
             state_encryption_key = \"a-32-byte-or-longer-test-secret!!\"\n\
             index_html = \"does-not-exist.html\"\n",
        )
        .unwrap();
        let config_path = dir.join("proxy.toml");
        assert!(load_index_page(&cfg, config_path.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[actix_web::test]
    async fn logo_serves_png() {
        let app =
            test::init_service(App::new().route("/assets/tunnelbana.png", web::get().to(logo)))
                .await;
        let req = test::TestRequest::get()
            .uri("/assets/tunnelbana.png")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("content-type").unwrap(), "image/png");

        let body = test::read_body(resp).await;
        // PNG magic number.
        assert_eq!(
            &body[..8],
            &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]
        );
    }
}
