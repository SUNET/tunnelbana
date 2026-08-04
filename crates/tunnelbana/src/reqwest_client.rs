//! A `reqwest`-backed implementation of the core `HttpClient` trait.

use async_trait::async_trait;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpClient, HttpFetchResponse};

pub struct ReqwestClient {
    inner: reqwest::Client,
    max_response_bytes: usize,
}

impl ReqwestClient {
    pub fn new() -> Self {
        Self::with_limits(10, 15, 30, 8 * 1024 * 1024)
    }

    pub fn with_limits(
        connect_timeout_seconds: u64,
        read_timeout_seconds: u64,
        request_timeout_seconds: u64,
        max_response_bytes: usize,
    ) -> Self {
        let inner = reqwest::Client::builder()
            .user_agent(concat!("tunnelbana/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(std::time::Duration::from_secs(connect_timeout_seconds))
            .read_timeout(std::time::Duration::from_secs(read_timeout_seconds))
            .timeout(std::time::Duration::from_secs(request_timeout_seconds))
            .build()
            .expect("failed to build reqwest client");
        Self {
            inner,
            max_response_bytes,
        }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn get(&self, url: &str) -> Result<HttpFetchResponse> {
        let resp = self
            .inner
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("GET {url}: {e}")))?;
        into_fetch(resp, self.max_response_bytes)
            .await
            .map_err(|error| request_error("GET", url, error))
    }

    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        headers: &[(String, String)],
    ) -> Result<HttpFetchResponse> {
        let mut req = self.inner.post(url).form(form);
        for (k, v) in headers {
            req = req.header(k.as_str(), v.as_str());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Internal(format!("POST {url}: {e}")))?;
        into_fetch(resp, self.max_response_bytes)
            .await
            .map_err(|error| request_error("POST", url, error))
    }
}

/// Retain the originating operation when body streaming or size enforcement
/// fails after the request itself was sent successfully.
fn request_error(method: &str, url: &str, error: Error) -> Error {
    Error::Internal(format!("{method} {url}: {error}"))
}

async fn into_fetch(
    mut resp: reqwest::Response,
    max_response_bytes: usize,
) -> Result<HttpFetchResponse> {
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    if resp
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(Error::Internal(format!(
            "outbound response exceeds {max_response_bytes} byte limit"
        )));
    }

    // Content-Length is optional and cannot be trusted on its own. Stream the
    // body and check before every extension so a chunked peer cannot force an
    // unbounded allocation.
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| Error::Internal(format!("reading body: {e}")))?
    {
        append_bounded(&mut body, &chunk, max_response_bytes)?;
    }
    Ok(HttpFetchResponse {
        status,
        body,
        content_type,
    })
}

fn append_bounded(body: &mut Vec<u8>, chunk: &[u8], max_response_bytes: usize) -> Result<()> {
    body.len()
        .checked_add(chunk.len())
        .filter(|length| *length <= max_response_bytes)
        .ok_or_else(|| {
            Error::Internal(format!(
                "outbound response exceeds {max_response_bytes} byte limit"
            ))
        })?;
    body.extend_from_slice(chunk);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_body_limit_is_enforced_before_extension() {
        let mut body = b"1234".to_vec();
        append_bounded(&mut body, b"56", 6).unwrap();
        assert_eq!(body, b"123456");

        let error = append_bounded(&mut body, b"7", 6).unwrap_err();
        assert!(error.to_string().contains("6 byte limit"));
        assert_eq!(body, b"123456", "oversized chunk must not be appended");
    }

    #[test]
    fn body_processing_errors_retain_request_context() {
        for (method, url) in [
            ("GET", "https://issuer.example/jwks"),
            ("POST", "https://issuer.example/token"),
        ] {
            let error = request_error(
                method,
                url,
                Error::Internal("outbound response exceeds limit".into()),
            );
            let message = error.to_string();
            assert!(message.contains(&format!("{method} {url}")));
            assert!(message.contains("outbound response exceeds limit"));
        }
    }
}
