//! Sweden Connect release rules and the one-use upstream transaction.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tunnelbana_core::cache::TtlCache;
use tunnelbana_core::context::{Context, VerifiedOidc};
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::state::State;
use tunnelbana_oidc::client::Client;
use tunnelbana_oidc::oauth_error::OAuthError;
use tunnelbana_oidc::provider::AuthorizedClaims;
use tunnelbana_oidc::request::AuthorizationRequest;
use tunnelbana_oidc::rp::RequestObjectParameters;

pub const INFO: &str = "https://id.oidc.se/scope/naturalPersonInfo";
pub const NUMBER: &str = "https://id.oidc.se/scope/naturalPersonNumber";
pub const APPROVAL: &str = "https://id.oidc.se/scope/signApproval";
pub const SIGN_REQUEST: &str = "https://id.oidc.se/param/signRequest";
pub const PIN: &str = "https://id.oidc.se/claim/personalIdentityNumber";
pub const COORD: &str = "https://id.oidc.se/claim/coordinationNumber";
pub const NAMES: [&str; 5] = [
    "given_name",
    "family_name",
    "middle_name",
    "name",
    "birthdate",
];

#[derive(Debug, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    SwedenConnect,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub state: State,
    pub params: RequestObjectParameters,
}

pub enum Transactions {
    Memory(TtlCache<Transaction>),
    Redis(redis::aio::ConnectionManager, String),
}

impl Transactions {
    pub fn new(redis_url: Option<&str>, entity: &str) -> Result<Self> {
        match redis_url {
            None => Ok(Self::Memory(TtlCache::new(600))),
            Some(url) => {
                let conn = redis::Client::open(url)
                    .and_then(|client| client.get_connection_manager_lazy(Default::default()))
                    .map_err(|_| Error::Config("invalid transaction Redis configuration".into()))?;
                Ok(Self::Redis(
                    conn,
                    format!("tunnelbana:{entity}:transaction:"),
                ))
            }
        }
    }
    pub async fn insert(&self, handle: &str, value: Transaction) -> Result<()> {
        let stored = match self {
            Self::Memory(cache) => cache.put_if_absent(handle, value, 600),
            Self::Redis(conn, prefix) => redis::cmd("SET")
                .arg(format!("{prefix}{handle}"))
                .arg(serde_json::to_vec(&value)?)
                .arg("EX")
                .arg(600)
                .arg("NX")
                .query_async::<Option<String>>(&mut conn.clone())
                .await
                .map_err(|_| Error::State("transaction store unavailable".into()))?
                .is_some(),
        };
        if stored {
            Ok(())
        } else {
            Err(Error::State("transaction could not be stored".into()))
        }
    }
    pub async fn take(&self, handle: &str) -> Result<Transaction> {
        let value = match self {
            Self::Memory(cache) => cache.take(handle),
            Self::Redis(conn, prefix) => redis::cmd("GETDEL")
                .arg(format!("{prefix}{handle}"))
                .query_async::<Option<Vec<u8>>>(&mut conn.clone())
                .await
                .map_err(|_| Error::State("transaction store unavailable".into()))?
                .map(|v| serde_json::from_slice(&v))
                .transpose()?,
        };
        value.ok_or_else(|| Error::Authn("transaction already completed or expired".into()))
    }
}

/// Enforce the approval extension before reaching an upstream consent screen.
pub fn validate_approval(req: &AuthorizationRequest, authorized: bool) -> Result<Option<Value>> {
    let approval = req.scopes().contains(&APPROVAL);
    let raw = req.extra.get(SIGN_REQUEST);
    if req.scopes().contains(&"https://id.oidc.se/scope/sign") || approval != raw.is_some() {
        return Err(Error::BadRequest("inconsistent signature request".into()));
    }
    let Some(raw) = raw else { return Ok(None) };
    if !authorized || !req.has_prompt("login") || !req.has_prompt("consent") {
        return Err(Error::Authn("signature approval is not authorized".into()));
    }
    // The upstream OP cannot prove a proxy-issued subject or audience to the
    // signer. Reject such constraints before sending the sign message.
    for destination in ["id_token", "userinfo"] {
        if req
            .claims
            .as_ref()
            .and_then(|c| c[destination].as_object())
            .is_some_and(|entries| {
                entries.iter().any(|(name, spec)| {
                    matches!(name.as_str(), "sub" | "iss" | "aud" | "nonce" | "azp")
                        && spec.get("essential") == Some(&Value::Bool(true))
                })
            })
        {
            return Err(Error::BadRequest(
                "signer constraint belongs to the downstream issuer".into(),
            ));
        }
    }
    let request: Value = serde_json::from_str(raw)?;
    let message = request
        .get("sign_message")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::BadRequest("missing sign message".into()))?;
    if request.get("tbs_data").is_some()
        || !message.iter().any(|(k, v)| {
            (k == "message" || k.starts_with("message#"))
                && v.as_str().is_some_and(|v| !v.is_empty())
        })
    {
        return Err(Error::BadRequest("invalid approval message".into()));
    }
    Ok(Some(request))
}

pub fn parameters(ctx: &Context, allowed_scope: &str) -> Result<(String, RequestObjectParameters)> {
    let req = ctx
        .target_frontend
        .as_deref()
        .and_then(|f| ctx.state.get_value(f, "authz_request"))
        .map(|v| serde_json::from_value::<AuthorizationRequest>(v.clone()))
        .transpose()?;
    let mut params = RequestObjectParameters::default();
    let scope = if let Some(req) = req {
        let authorized_approval = ctx.state.get_value(
            ctx.target_frontend.as_deref().unwrap_or_default(),
            "approved_signature_client",
        ) == Some(&Value::Bool(true));
        params.sign_request = validate_approval(&req, authorized_approval)?;
        params.prompt = req.prompt;
        params.acr_values = req.acr_values;
        params.ui_locales = req.extra.get("ui_locales").cloned();
        params.max_age = req
            .extra
            .get("max_age")
            .map(|v| v.parse::<u64>())
            .transpose()
            .map_err(|_| Error::BadRequest("invalid max_age".into()))?;
        if let Some(claims) = &req.claims {
            validate_claims(claims)?;
        }
        params.claims = req.claims;
        req.scope
            .split_whitespace()
            .filter(|s| allowed_scope.split_whitespace().any(|a| a == *s))
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        if let Some(values) = ctx.decoration(tunnelbana_core::context::KEY_REQUESTED_ACCR) {
            if ctx
                .decoration(tunnelbana_core::context::KEY_REQUESTED_ACCR_COMPARISON)
                .and_then(Value::as_str)
                .is_some_and(|c| c != "exact")
            {
                return Err(Error::UnmetAuthenticationRequirements);
            }
            params.claims = Some(json!({"id_token":{"acr":{"essential":true,"values":values}}}));
        }
        allowed_scope
            .split_whitespace()
            .filter(|s| *s != APPROVAL)
            .collect::<Vec<_>>()
            .join(" ")
    };
    if params.sign_request.is_some() && !scope.split_whitespace().any(|s| s == APPROVAL) {
        return Err(Error::Authn(
            "upstream approval scope is not configured".into(),
        ));
    }
    Ok((scope, params))
}

fn validate_claims(claims: &Value) -> Result<()> {
    let invalid = || Error::BadRequest("malformed requested claims".into());
    for (destination, entries) in claims.as_object().ok_or_else(invalid)? {
        if !matches!(destination.as_str(), "id_token" | "userinfo") {
            return Err(invalid());
        }
        for spec in entries.as_object().ok_or_else(invalid)?.values() {
            if spec.is_null() {
                continue;
            }
            let obj = spec.as_object().ok_or_else(invalid)?;
            if obj
                .keys()
                .any(|k| !matches!(k.as_str(), "essential" | "value" | "values"))
                || obj.get("essential").is_some_and(|v| !v.is_boolean())
                || (obj.contains_key("value") && obj.contains_key("values"))
                || obj
                    .get("values")
                    .is_some_and(|v| v.as_array().is_none_or(Vec::is_empty))
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

fn matches_constraint(value: Option<&Value>, spec: &Value) -> bool {
    value.is_some_and(|value| {
        spec.get("value").is_none_or(|wanted| value == wanted)
            && spec
                .get("values")
                .is_none_or(|wanted| wanted.as_array().is_some_and(|list| list.contains(value)))
    })
}

/// Verify signer and assurance constraints against the corresponding verified JWT.
pub fn check_result(params: &RequestObjectParameters, id: &Value, ui: &Value) -> Result<()> {
    if id
        .get("acr")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || id.get("auth_time").and_then(Value::as_u64).is_none()
    {
        return Err(Error::UnmetAuthenticationRequirements);
    }
    for (dest, values) in [("id_token", id), ("userinfo", ui)] {
        if let Some(requested) = params
            .claims
            .as_ref()
            .and_then(|v| v.get(dest))
            .and_then(Value::as_object)
        {
            for (name, spec) in requested {
                if spec.get("essential") == Some(&Value::Bool(true))
                    && (name == "acr" || params.sign_request.is_some())
                    && !matches_constraint(values.get(name), spec)
                {
                    return Err(Error::UnmetAuthenticationRequirements);
                }
            }
        }
    }
    for source in [id, ui] {
        for key in [PIN, COORD] {
            if source.get(key).is_some_and(|v| {
                !v.as_str()
                    .is_some_and(|n| n.len() == 12 && n.bytes().all(|c| c.is_ascii_digit()))
            }) {
                return Err(Error::Authn("invalid Swedish identity number".into()));
            }
        }
    }
    if [PIN, COORD]
        .iter()
        .all(|k| id.get(k).is_some() || ui.get(k).is_some())
        || [PIN, COORD]
            .iter()
            .any(|k| id.get(k).zip(ui.get(k)).is_some_and(|(a, b)| a != b))
    {
        return Err(Error::Authn("conflicting Swedish identity numbers".into()));
    }
    Ok(())
}

pub fn release(
    req: &AuthorizationRequest,
    verified: &VerifiedOidc,
    allow: &[String],
) -> AuthorizedClaims {
    let mut claims = AuthorizedClaims::default();
    for (dest, source, output) in [
        ("id_token", &verified.id_token, &mut claims.id_token),
        ("userinfo", &verified.userinfo, &mut claims.userinfo),
    ] {
        for name in allow {
            let by_scope = ((name == PIN || name == COORD) && req.scopes().contains(&NUMBER))
                || (dest == "userinfo"
                    && ((NAMES.contains(&name.as_str()) && req.scopes().contains(&INFO))
                        || tunnelbana_oidc::provider::standard_claim_scope(name)
                            .is_some_and(|scope| req.scopes().contains(&scope))));
            let explicit = req
                .claims
                .as_ref()
                .and_then(|v| v.get(dest))
                .and_then(|v| v.get(name));
            if let Some(value) = source.get(name) {
                if by_scope || explicit.is_some_and(|s| matches_constraint(Some(value), s)) {
                    output.insert(name.clone(), value.clone());
                }
            }
        }
    }
    claims
}

/// Derive an opaque subject bound to this OP and (for pairwise) the registered sector.
pub fn subject(
    secret: &str,
    issuer: &str,
    client: &Client,
    upstream: &str,
    sub: &str,
) -> std::result::Result<String, OAuthError> {
    let host = |s: &str| {
        url::Url::parse(s)
            .ok()
            .filter(|u| u.scheme() == "https")
            .and_then(|u| u.host_str().map(str::to_owned))
    };
    let sector = if client.subject_type == "pairwise" {
        Some(
            if let Some(uri) = &client.response_policy.sector_identifier_uri {
                host(uri).ok_or_else(|| OAuthError::invalid_request("invalid registered sector"))?
            } else {
                let all = client
                    .redirect_uris
                    .iter()
                    .map(|u| host(u))
                    .collect::<Option<std::collections::BTreeSet<_>>>()
                    .unwrap_or_default();
                if all.len() != 1 {
                    return Err(OAuthError::invalid_request(
                        "pairwise client needs a registered sector",
                    ));
                }
                all.into_iter().next().unwrap()
            },
        )
    } else {
        None
    };
    let input = serde_json::to_vec(&("sweden-connect-sub-v1", issuer, sector, upstream, sub))
        .expect("string tuple");
    Ok(URL_SAFE_NO_PAD.encode(tunnelbana_core::mac::hmac_sha256(secret.as_bytes(), &input)))
}

/// Entries come exclusively from the pinned resolver's signed response. Its
/// endorsement cannot extend the lifetime of the embedded mark itself.
pub fn has_mark(marks: &[Value], expected: &str, subject: &str, now: u64) -> bool {
    marks
        .iter()
        .filter(|v| v["trust_mark_type"] == expected)
        .filter_map(|v| {
            tunnelbana_oidc::jwt::peek_claims_unverified(v["trust_mark"].as_str()?).ok()
        })
        .any(|mark| {
            mark.sub.as_deref() == Some(subject)
                && mark.extra.get("trust_mark_type").and_then(Value::as_str) == Some(expected)
                && mark.iat.is_some_and(|iat| iat.as_secs() <= now)
                && mark.exp.is_none_or(|exp| exp.as_secs() > now)
        })
}

pub fn check_keys(
    a: &tunnelbana_core::keys::SigningKey,
    b: &tunnelbana_core::keys::SigningKey,
) -> Result<()> {
    if [a, b].iter().any(|key| key.kid().is_none_or(str::is_empty))
        || jose_rs::jwk::thumbprint::thumbprint_sha256(&a.public_jwk())?
            == jose_rs::jwk::thumbprint::thumbprint_sha256(&b.public_jwk())?
    {
        return Err(Error::Config(
            "Sweden Connect requires separate identified federation and protocol keys".into(),
        ));
    }
    Ok(())
}

/// Limit operator presentation metadata to fields that cannot replace endpoints,
/// supported algorithms or the issuer.
pub fn presentation(
    fields: serde_json::Map<String, Value>,
) -> Result<serde_json::Map<String, Value>> {
    for k in fields.keys() {
        if !matches!(
            k.split('#').next(),
            Some(
                "contacts"
                    | "logo_uri"
                    | "client_uri"
                    | "client_name"
                    | "display_name"
                    | "organization_name"
                    | "policy_uri"
                    | "tos_uri"
                    | "op_policy_uri"
                    | "op_tos_uri"
            )
        ) {
            return Err(Error::Config(format!(
                "unsupported presentation metadata {k}"
            )));
        }
    }
    Ok(fields)
}

/// Protocol key material published during rollover. Retired decryption keys
/// are loaded for incoming traffic only while peers refresh cached metadata.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotationConfig {
    #[serde(default)]
    signing_public_jwks: Vec<jose_rs::jwk::Jwk>,
    #[serde(default)]
    decryption_jwk_paths: Vec<String>,
    #[serde(default)]
    retired_decryption_jwk_paths: Vec<String>,
}

pub struct ProtocolKeys {
    pub published: jose_rs::jwk::JwkSet,
    decrypt: Vec<jose_rs::jwk::Jwk>,
}

impl ProtocolKeys {
    pub fn load(
        config: RotationConfig,
        signing: &tunnelbana_core::keys::SigningKey,
        federation: &tunnelbana_core::keys::SigningKey,
    ) -> Result<Self> {
        use jose_rs::jwk::{thumbprint::thumbprint_sha256, Jwk};
        let mut published = signing.to_public_jwks();
        if config.signing_public_jwks.is_empty()
            && config.decryption_jwk_paths.is_empty()
            && config.retired_decryption_jwk_paths.is_empty()
        {
            return Ok(Self {
                published,
                decrypt: vec![],
            });
        }
        let mut decrypt = Vec::new();
        let mut kids =
            std::collections::HashSet::from([signing.kid().unwrap_or_default().to_owned()]);
        let mut materials = std::collections::HashSet::from([
            thumbprint_sha256(&signing.public_jwk())?,
            thumbprint_sha256(&federation.public_jwk())?,
        ]);
        let mut distinct = |key: &Jwk| -> Result<()> {
            if !matches!(key.kty.as_str(), "RSA" | "EC")
                || key
                    .kid
                    .as_ref()
                    .is_none_or(|kid| kid.is_empty() || !kids.insert(kid.clone()))
                || !materials.insert(thumbprint_sha256(key)?)
            {
                return Err(Error::Config(
                    "rotation keys require unique identifiers and separate asymmetric material"
                        .into(),
                ));
            }
            Ok(())
        };
        for key in config.signing_public_jwks {
            distinct(&key)?;
            if key.d.is_some() || key.use_.as_deref() != Some("sig") {
                return Err(Error::Config(
                    "prepublished signing keys must be public signature keys".into(),
                ));
            }
            published.keys.push(key.to_public_jwk());
        }
        for (paths, publish) in [
            (config.decryption_jwk_paths, true),
            (config.retired_decryption_jwk_paths, false),
        ] {
            for path in paths {
                let key = Jwk::from_json(
                    &std::fs::read_to_string(path)
                        .map_err(|_| Error::Config("reading decryption key failed".into()))?,
                )?;
                distinct(&key)?;
                if key.d.is_none()
                    || key.use_.as_deref() != Some("enc")
                    || !matches!(
                        key.alg.as_deref(),
                        Some("RSA-OAEP" | "RSA-OAEP-256" | "ECDH-ES")
                    )
                {
                    return Err(Error::Config(
                        "decryption key needs private material and a profile encryption algorithm"
                            .into(),
                    ));
                }
                if publish {
                    published.keys.push(key.to_public_jwk());
                }
                decrypt.push(key);
            }
        }
        Ok(Self { published, decrypt })
    }
    pub fn supports(&self, alg: &str) -> bool {
        self.published
            .keys
            .iter()
            .any(|key| key.use_.as_deref() == Some("enc") && key.alg.as_deref() == Some(alg))
    }

    pub fn open(&self, token: &str) -> Result<String> {
        let header = jose_rs::jwe::compact::decode_header(token)?;
        let key = self
            .decrypt
            .iter()
            .find(|k| k.kid == header.kid)
            .ok_or_else(|| Error::Authn("unknown decryption key".into()))?;
        if key.alg.as_deref() != Some(header.alg.as_str())
            || !matches!(
                header.enc.as_deref(),
                Some("A128GCM" | "A256GCM" | "A128CBC-HS256" | "A256CBC-HS512")
            )
        {
            return Err(Error::Authn("unsupported response encryption".into()));
        }
        String::from_utf8(jose_rs::jwe::decrypt_with_jwk(key, token)?)
            .map_err(|_| Error::Authn("invalid nested JWT".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(scope: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            scope: scope.into(),
            ..Default::default()
        }
    }

    #[test]
    fn scopes_select_destinations_without_changing_values() {
        let id = json!({PIN:"012345678901","custom":{"nested":[1,true]}});
        let ui = json!({PIN:"012345678901","given_name":"Eva","custom":[1,true]});
        let result = VerifiedOidc {
            id_token: id,
            userinfo: ui,
            subject: "s".into(),
            approval: false,
        };
        let allow = [PIN, "given_name", "custom"].map(String::from);
        let none = release(&request("openid"), &result, &allow);
        assert!(none.userinfo.is_empty() && none.id_token.is_empty());
        let mut req = request(&format!("openid {INFO} {NUMBER}"));
        req.claims = Some(json!({"userinfo":{"custom":null}}));
        let values = release(&req, &result, &allow);
        assert_eq!(values.userinfo["given_name"], "Eva");
        assert!(!values.id_token.contains_key("given_name"));
        assert_eq!(values.id_token[PIN], "012345678901");
        assert_eq!(values.userinfo[PIN], values.id_token[PIN]);
        assert_eq!(values.userinfo["custom"], json!([1, true]));
        assert!(!values.id_token.contains_key("custom"));
        assert!(!release(&req, &result, &[]).userinfo.contains_key(PIN));
    }

    #[test]
    fn requires_verified_assurance_and_the_requested_signer() {
        let expected = "012345678901";
        let id = json!({"acr":"loa3","auth_time":123,PIN:expected});
        let mut p = RequestObjectParameters {
            claims: Some(
                json!({"id_token":{"acr":{"essential":true,"values":["loa3","loa4"]},PIN:{"essential":true,"value":expected}}}),
            ),
            sign_request: Some(json!({})),
            ..Default::default()
        };
        assert!(check_result(&p, &id, &json!({})).is_ok());
        assert!(check_result(
            &p,
            &json!({"acr":"loa3","auth_time":123,PIN:"999999999999"}),
            &json!({})
        )
        .is_err());
        p.sign_request = None;
        for invalid in [
            json!({"auth_time":123}),
            json!({"acr":"loa3"}),
            json!({"acr":"loa2","auth_time":123}),
            json!({"acr":"loa3","auth_time":123,PIN:123456789012u64}),
            json!({"acr":"loa3","auth_time":123,PIN:expected,COORD:expected}),
        ] {
            assert!(check_result(&p, &invalid, &json!({})).is_err());
        }
    }

    #[tokio::test]
    async fn one_callback_wins_concurrent_transaction_consumption() {
        let store = Transactions::new(None, "fixture").unwrap();
        store
            .insert(
                "handle",
                Transaction {
                    state: State::new(),
                    params: Default::default(),
                },
            )
            .await
            .unwrap();
        let (a, b) = tokio::join!(store.take("handle"), store.take("handle"));
        assert_ne!(a.is_ok(), b.is_ok());
    }

    #[test]
    fn pairwise_subject_is_scoped_to_registration_sector() {
        let mut c:Client=serde_json::from_value(json!({"client_id":"a","redirect_uris":["https://sector.test/cb"],"subject_type":"pairwise"})).unwrap();
        let derive = |c: &Client| subject("secret", "op", c, "upstream", "subject").unwrap();
        let first = derive(&c);
        c.client_id = "b".into();
        assert_eq!(first, derive(&c));
        c.response_policy.sector_identifier_uri = Some("https://other.test/registration".into());
        assert_ne!(first, derive(&c));
        c.subject_type = "public".into();
        assert_ne!(derive(&c), "subject");
        assert_ne!(first, derive(&c));
    }
}
