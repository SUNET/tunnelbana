//! A `reqwest`-backed implementation of the core `HttpClient` trait.

use async_trait::async_trait;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::http::{HttpClient, HttpFetchResponse};

pub struct ReqwestClient {
    inner: reqwest::Client,
}

impl ReqwestClient {
    pub fn new() -> Self {
        let inner = reqwest::Client::builder()
            .user_agent("tunnelbana/0.1")
            .build()
            .expect("failed to build reqwest client");
        Self { inner }
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
        into_fetch(resp).await
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
        into_fetch(resp).await
    }
}

async fn into_fetch(resp: reqwest::Response) -> Result<HttpFetchResponse> {
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let body = resp
        .bytes()
        .await
        .map_err(|e| Error::Internal(format!("reading body: {e}")))?
        .to_vec();
    Ok(HttpFetchResponse {
        status,
        body,
        content_type,
    })
}
