//! URL scheme validation for upstream endpoints.
//!
//! Endpoint and issuer URLs — whether configured statically or resolved
//! through a trust anchor — are redirected to (authorization) or fetched with
//! credentials attached (token, userinfo, JWKS). They must be HTTPS; plain
//! HTTP is accepted only for loopback hosts so local development and tests
//! keep working.

use tunnelbana_core::error::{Error, Result};

/// Require `url` to use the `https` scheme, allowing `http` only when the
/// host is loopback (`localhost`, `127.0.0.0/8`, `::1`). `what` names the
/// setting/endpoint for the error message.
pub fn require_https(url: &str, what: &str) -> Result<()> {
    let parsed = url::Url::parse(url)
        .map_err(|e| Error::Config(format!("{what}: invalid URL '{url}': {e}")))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(parsed.host()) => Ok(()),
        scheme => Err(Error::Config(format!(
            "{what}: '{url}' uses scheme '{scheme}'; https is required \
             (http is allowed only for loopback hosts)"
        ))),
    }
}

fn is_loopback(host: Option<url::Host<&str>>) -> bool {
    match host {
        Some(url::Host::Domain("localhost")) => true,
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_accepted() {
        assert!(require_https("https://op.example.com/token", "token_endpoint").is_ok());
    }

    #[test]
    fn plain_http_is_rejected() {
        let err = require_https("http://op.example.com/token", "token_endpoint").unwrap_err();
        assert!(err.to_string().contains("https is required"), "got: {err}");
    }

    #[test]
    fn loopback_http_is_allowed_for_local_dev() {
        for url in [
            "http://localhost:8080/token",
            "http://127.0.0.1/token",
            "http://[::1]/token",
        ] {
            assert!(require_https(url, "token_endpoint").is_ok(), "url: {url}");
        }
    }

    #[test]
    fn non_loopback_lookalikes_are_rejected() {
        // `localhost.evil.com` is not loopback; neither is a non-IP host that
        // merely contains a loopback address as text.
        assert!(require_https("http://localhost.evil.com/token", "t").is_err());
        assert!(require_https("http://127.0.0.1.evil.com/token", "t").is_err());
    }

    #[test]
    fn other_schemes_are_rejected() {
        assert!(require_https("ftp://op.example.com/jwks", "jwks_uri").is_err());
        assert!(require_https("not a url", "issuer").is_err());
    }
}
