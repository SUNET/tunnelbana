# Built-in plugin reference

Every built-in plugin and its config `type`:

| `type` | Kind | Role |
| --- | --- | --- |
| `oidc` | frontend | OpenID Provider (OP) |
| `oidc_federation` | frontend | OpenID Federation 1.0 OP |
| `saml2` | frontend | SAML2 Identity Provider (IdP) |
| `oidc` | backend | OpenID Connect Relying Party (RP) |
| `saml2` | backend | SAML2 Service Provider (SP) |
| `static_attributes` | micro-service | inject fixed attributes (response path) |
| `filter_attributes` | micro-service | allow-list attributes (response path) |
| `custom_routing` | micro-service | pick a backend by requester (request path) |

All `signing_*` keys follow the [key-loading rules](configuration.md#keys-pem-or-jwk).

## `oidc` frontend — OpenID Provider

```toml
[[frontend]]
type = "oidc"
name = "OIDC"
  [frontend.config]
  signing_key_path  = "keys/op.key"   # id_token signing key
  signing_algorithm = "ES256"
  signing_key_id    = "op-key-1"
  code_ttl          = 600             # seconds (default 600)
  access_token_ttl  = 3600            # seconds (default 3600)
  id_token_ttl      = 3600            # seconds (default 3600)

  [frontend.config.dpop]
  enabled             = true           # default false
  proof_max_age_secs  = 300            # default 300
  require_nonce       = false          # default false
  nonce_lifetime_secs = 300            # default 300

  # Statically registered clients (repeat the table per client).
  [[frontend.config.clients]]
  client_id                  = "demo-rp"
  client_secret              = "demo-rp-secret"
  redirect_uris              = ["https://rp.example.com/callback"]
  response_types             = ["code"]
  token_endpoint_auth_method = "client_secret_basic"

  # Optional: extra fields merged into the discovery document.
  [frontend.config.extra_metadata]
  # e.g. service_documentation = "https://…"
```

Serves `…/OIDC/.well-known/openid-configuration`, `…/OIDC/jwks`,
`…/OIDC/authorization`, `…/OIDC/token`, `…/OIDC/userinfo`. Supports the code
flow with PKCE, the `client_credentials` grant for confidential clients, and
the `client_secret_basic`, `client_secret_post`, `none` and `private_key_jwt`
token-endpoint auth methods. When `frontend.config.dpop.enabled = true`, the
frontend advertises `dpop_signing_alg_values_supported = ["ES256"]`, accepts
DPoP proofs on the token and userinfo endpoints, and issues sender-constrained
access tokens (`token_type = "DPoP"`).

## `oidc_federation` frontend — Federation OP

A federation-aware OP: it serves a signed entity configuration, auto-registers
unknown RPs by resolving them through a trust anchor, unpacks request objects
(RFC 9101) and accepts `private_key_jwt` (RFC 7523).

```toml
[[frontend]]
type = "oidc_federation"
name = "OIDFed"
  [frontend.config]
  # Federation entity identifier. Defaults to <base_url>/<name>; set it to a
  # stable id (e.g. the bare host) independent of where endpoints are mounted.
  entity_id         = "https://op.example.com"
  # OIDC id_token signing key.
  signing_key_path  = "keys/oidc_signing.key"
  signing_algorithm = "RS256"
  signing_key_id    = "oidc-key-1"

  [frontend.config.federation]
  # Federation signing key — signs the entity configuration.
  signing_key_path              = "keys/federation_ec.key"
  signing_algorithm             = "ES256"
  signing_key_id                = "federation-key-1"
  authority_hints               = ["https://ta.example.com"]
  organization_name             = "Example OP"
  organization_uri              = "https://example.com"
  entity_configuration_lifetime = 86400   # seconds (default 86400)
  rp_cache_ttl                  = 3600    # auto-registered RP cache TTL (default 3600)
  trust_marks                   = []      # optional array of trust-mark JWTs

  # One table per trust anchor; `keys` are the anchor's pinned JWKS.
  [[frontend.config.federation.trust_anchor]]
  entity_id = "https://ta.example.com"
  keys = [
    { kty = "EC", crv = "P-256", x = "…", y = "…", kid = "ta-1", use = "sig", alg = "ES256" },
  ]
```

The entity configuration is served at `…/OIDFed/.well-known/openid-federation`
(see the [reverse-proxy note](configuration.md#mount-points) for exposing it on
the bare host). The OIDC endpoints mirror the plain `oidc` frontend, under
`…/OIDFed/`.

## `saml2` frontend — Identity Provider

```toml
[[frontend]]
type = "saml2"
name = "Saml2IDP"
  [frontend.config]
  idp_entity_id            = "https://idp.example.com/Saml2IDP"  # default <base_url>/<name>
  idp_key_path             = "keys/saml_idp.key"   # signing key (PEM)
  idp_cert_path            = "keys/saml_idp.crt"   # cert (PEM), published in metadata
  assertion_lifetime_seconds = 300                 # default 300
  sign_assertions          = true                  # default true
  sign_responses           = false                 # default false (see note)
  name_id_format           = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  authn_context_class_ref  = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
```

> **Signing.** By default tunnelbana signs the **assertion** only, which is the
> common interoperable pattern: an SP that verifies the single assertion
> signature is satisfied. Set `sign_responses = true` to also sign the Response
> envelope. (Conversely, the [SAML SP backend](#saml2-backend--service-provider)
> accepts either a signed assertion **or** a signed Response.)

## `oidc` backend — Relying Party

```toml
[[backend]]
type = "oidc"
name = "Upstream"
  [backend.config]
  # Either discover from the issuer…
  issuer                     = "https://accounts.upstream.example"
  # …or pin endpoints explicitly:
  # authorization_endpoint   = "https://…/authorize"
  # token_endpoint           = "https://…/token"
  # userinfo_endpoint        = "https://…/userinfo"
  # jwks_uri                 = "https://…/jwks"

  client_id                  = "tunnelbana-rp"
  client_secret              = "upstream-rp-secret"      # for client_secret_* methods
  token_endpoint_auth_method = "client_secret_basic"
  scope                      = "openid profile email"

  # For private_key_jwt, supply a signing key instead of a secret:
  # signing_key_path  = "keys/rp.key"
  # signing_algorithm = "ES256"
  # signing_key_id    = "rp-key-1"
```

Always uses PKCE (S256). The callback is served at `…/Upstream/`.

## `saml2` backend — Service Provider

Static single-IdP mode:

```toml
[[backend]]
type = "saml2"
name = "Saml2"
  [backend.config]
  sp_entity_id        = "https://sp.example.com/Saml2"   # default <base_url>/<name>
  sp_key_path         = "keys/sp.key"      # SP private key (PEM)
  sp_cert_path        = "keys/sp.crt"      # published in SP metadata
  idp_entity_id       = "https://idp.example.com/metadata"   # expected issuer
  idp_sso_url         = "https://idp.example.com/sso"        # where AuthnRequests go
  idp_cert_path       = "keys/idp.crt"     # IdP signing cert — verifies the Response
  sign_authn_requests = true               # default false
  name_id_format      = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  security            = "permissive"       # "permissive" (default) or "strict"
```

  Dynamic federation mode via MDQ:

  ```toml
  [[backend]]
  type = "saml2"
  name = "Saml2"
    [backend.config]
    sp_entity_id        = "https://sp.example.com/Saml2"   # default <base_url>/<name>
    sp_key_path         = "keys/sp.key"
    sp_cert_path        = "keys/sp.crt"
    idp_entity_id       = "https://idp.example.org/idp"    # default/fallback when no entityID arrives
    sign_authn_requests = false
    name_id_format      = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    security            = "permissive"

     [backend.config.mdq]
     url               = "https://mdq.example.org/"
     signing_cert_path = "keys/mdq-signer.crt"
     transform         = "sha1"           # "url_encoded" (default) or "sha1"
     require_role      = "idp"            # "idp" (default), "sp", or "any"
     fallback_ttl_secs = 3600
     # allow_unverified = true             # testing only; disables metadata signature verification
  ```

  The ACS is served at `…/Saml2/acs` (HTTP-POST) and SP metadata at
  `…/Saml2/metadata` in both modes.

  In **static mode**, AuthnRequests always go to `idp_sso_url`, and the backend
  verifies the response against `idp_cert_path`.

  In **MDQ mode**, the backend resolves the upstream IdP per request:

  1. Read `entityID` from the inbound auth request's query or form parameters.
  2. If `entityID` is missing, fall back to the configured `idp_entity_id`.
  3. Fetch that entity's metadata from the MDQ server and send the AuthnRequest
    to its HTTP-Redirect SSO endpoint.
  4. Persist the selected `entityID` in the encrypted state cookie.
  5. On the ACS, fetch metadata for that same persisted entity again, build the
    verifier from its signing certificates, and validate the Response against
    that IdP.

  This is the discovery boundary: tunnelbana consumes an incoming `entityID`
  handed back by a discovery service such as SeamlessAccess, but it does not yet
  implement the full SP-initiated Discovery Service Protocol itself.

  ### MDQ options

  | Key | Required | Default | Meaning |
  | --- | --- | --- | --- |
  | `mdq.url` | ✅ | — | MDQ server base URL. |
  | `mdq.signing_cert_path` | | — | PEM certificate used to verify signed MDQ entity statements. Required unless `allow_unverified = true`. |
  | `mdq.transform` | | `url_encoded` | EntityID-to-path transform: `url_encoded` or `sha1`. |
  | `mdq.require_role` | | `idp` | Require the fetched metadata to contain an `IDPSSODescriptor`, `SPSSODescriptor`, or either. |
  | `mdq.fallback_ttl_secs` | | metadata-driven | Cache TTL used when the metadata omits `validUntil` and `cacheDuration`. |
  | `mdq.allow_unverified` | | `false` | Accept unsigned/unverified metadata. For testing only. |

  ### Subject identifier selection

  A non-success SAML status (for example a cancelled login) is surfaced as an
  authentication error to the frontend. The Response is accepted when **either**
  the assertion or the Response envelope is signed and verifies.

  In MDQ mode, downstream subject selection follows the SATOSA-style
  primary-identifier pattern:

  1. If [configuration](configuration.md#the-attribute-map) sets
    `user_id_from_attrs` and those internal attributes are present, their
    composed value becomes `subject_id`.
  2. Otherwise tunnelbana falls back to the raw upstream SAML `NameID`.
  3. If that fallback is a persistent `NameID`, tunnelbana scopes it by the IdP
    issuer before exposing it downstream, so the same persistent `NameID` value
    from two different IdPs does not collapse onto one RP account.

  In multi-IdP deployments, prefer a federation-stable internal attribute such as
  `edupersontargetedid` or another deployment-specific stable identifier instead
  of relying on the raw `NameID` fallback.

## Micro-services

```toml
# Inject fixed attributes onto every response (does not overwrite existing ones).
[[microservice]]
type = "static_attributes"
name = "static"
  [microservice.config.attributes]
  affiliation = ["member", "staff"]

# Keep only allow-listed internal attributes on the response path.
[[microservice]]
type = "filter_attributes"
name = "filter"
  [microservice.config]
  allowed = ["mail", "givenname", "surname", "edupersonprincipalname"]

# Pick the backend on the request path by the requester (RP/SP id).
[[microservice]]
type = "custom_routing"
name = "routing"
  [[microservice.config.rule]]
  requester = "https://sp-a.example.com"
  backend   = "Saml2"
  [[microservice.config.rule]]
  requester = "https://sp-b.example.com"
  backend   = "Upstream"
```
