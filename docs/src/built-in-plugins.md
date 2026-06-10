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
  # Supported NameID formats in preference order; the first is the default
  # when the SP states no NameIDPolicy. A requested format outside the list
  # is answered with an InvalidNameIDPolicy SAML error at the SP's ACS.
  # "transient" mints a fresh random opaque value per response.
  name_id_formats          = ["urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"]
  # name_id_format = "…"   # single-value alias; do not set both forms
  authn_context_class_ref  = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
  # "basic" (default) emits plain attribute names; "uri" emits OID names +
  # FriendlyName from the attribute map (SWAMID-style).
  attribute_name_format    = "basic"
  # Require signed AuthnRequests even when the SP's metadata does not say
  # AuthnRequestsSigned="true". Also advertised in IdP metadata.
  want_authn_requests_signed = false

  # REQUIRED: registered SP metadata (see the security note below).
  [frontend.config.metadata]
  local = ["metadata/sp1.xml", "metadata/federation-sps.xml"]
  # Optional MDQ source for SPs not found in the local files; the role
  # requirement is forced to "sp". Same keys as the backend's [mdq] table.
  # [frontend.config.metadata.mdq]
  # url               = "https://mdq.swamid.se/"
  # signing_cert_path = "keys/mdq-signer.crt"

  # Optional per-SP attribute release policy (internal attribute names).
  # The SP-specific entry replaces "default" (no merge); no matching entry
  # (or no attribute_restrictions) releases everything.
  # [frontend.config.policy.default]
  # attribute_restrictions = ["mail", "edupersonprincipalname"]
  # [frontend.config.policy."https://sp.example.org"]
  # attribute_restrictions = ["mail"]

  # Optional: published in IdP metadata (needed for e.g. SWAMID registration).
  # [frontend.config.organization]
  # name = "SUNET"
  # display_name = "Sunet"
  # url = "https://sunet.se"
  # lang = "en"                       # default "en"
  # [[frontend.config.contact_person]]
  # contact_type  = "technical"       # technical|support|administrative|billing|other
  # email_address = "noc@sunet.se"
  # given_name    = "Ops"
```

> **Security: registered SPs are mandatory.** Every AuthnRequest's issuer is
> resolved against the `[frontend.config.metadata]` store (local files are
> `EntityDescriptor` or `EntitiesDescriptor` documents; MDQ fills the gaps).
> Unknown SPs get a **403**, and the ACS URL is validated against the SP's
> registered `AssertionConsumerService`s — assertions are never delivered to a
> URL taken from the request. Without this an attacker who knows the SSO URL
> could exfiltrate signed assertions to an arbitrary ACS. The frontend
> therefore **refuses to start** without a metadata source; the dev-only
> escape hatch is `allow_unknown_sps = true` (logged loudly, never use it in
> production). When a signature is required (SP metadata or
> `want_authn_requests_signed`), redirect-binding signatures are verified over
> the raw query string and POST-binding requests via their enveloped XML
> signature, against the SP's metadata-registered signing certs. See ADR 0006.

> **Signing.** By default tunnelbana signs the **assertion** only, which is the
> common interoperable pattern: an SP that verifies the single assertion
> signature is satisfied. Set `sign_responses = true` to also sign the Response
> envelope. (Conversely, the [SAML SP backend](#saml2-backend--service-provider)
> accepts either a signed assertion **or** a signed Response.)

The IdP serves `…/Saml2IDP/sso` (Redirect + POST) and `…/Saml2IDP/metadata`.
When `idp_entity_id` is itself a URL under the module base (the common
`…/Saml2IDP/proxy.xml` convention), the metadata document is additionally
served at that path (SATOSA's `entityid_endpoint`).

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
  # Clock-skew tolerance towards the IdP in seconds, overriding the preset
  # (SATOSA: accepted_time_diff). Permissive defaults to 600, strict to 180.
  # accepted_time_diff_secs = 300
  # Keep inbound attributes the attribute map does not know, under a
  # lowercased FriendlyName-or-Name key (SATOSA: allow_unknown_attributes).
  # Frontends still drop them unless the map learns the name.
  # passthrough_unmapped_attributes = true
  # Accept IdP-initiated Responses (no InResponseTo) within an existing
  # proxy flow. Default false: the ACS requires the in-flight AuthnRequest id.
  # allow_unsolicited = true

  # Decrypt <EncryptedAssertion> / <EncryptedID> (usually the signing pair).
  # List several entries to rotate keys: all are tried for decryption, and
  # every entry with a cert_path is published with use="encryption" in SP
  # metadata (omit cert_path for retired decrypt-only keys).
  # [[backend.config.encryption_keypairs]]
  # key_path  = "keys/sp.key"
  # cert_path = "keys/sp.crt"

  # Optional: published in SP metadata (same shape as the frontend's).
  # [backend.config.organization]
  # name = "SUNET"
  # display_name = "Sunet"
  # url = "https://sunet.se"
  # [[backend.config.contact_person]]
  # contact_type  = "technical"
  # email_address = "noc@sunet.se"
```

  Dynamic federation mode via MDQ, with IdP discovery:

  ```toml
  [[backend]]
  type = "saml2"
  name = "Saml2"
    [backend.config]
    sp_entity_id        = "https://sp.example.com/Saml2"   # default <base_url>/<name>
    sp_key_path         = "keys/sp.key"
    sp_cert_path        = "keys/sp.crt"
    # Default/fallback IdP when no entityID arrives. Optional when disco_srv
    # is set; MDQ mode needs at least one of the two.
    idp_entity_id       = "https://idp.example.org/idp"
    # Identity-provider discovery service (SeamlessAccess / thiss.io). When a
    # flow has no target IdP, the user is redirected here and returns with
    # their choice at …/Saml2/disco. MDQ mode only.
    disco_srv           = "https://service.seamlessaccess.org/ds"
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

  The ACS is served at `…/Saml2/acs` (HTTP-POST and HTTP-Redirect, both
  advertised in metadata), the discovery return at `…/Saml2/disco` (when
  `disco_srv` is set, also published as an `<idpdisc:DiscoveryResponse>`
  metadata extension), and SP metadata at `…/Saml2/metadata`.

  In **static mode**, AuthnRequests always go to `idp_sso_url`, and the backend
  verifies the response against `idp_cert_path`. `disco_srv` is rejected in
  static mode — a pinned cert cannot verify arbitrary discovery choices.

  In **MDQ mode**, the backend resolves the upstream IdP per request:

  1. Read `entityID` from the inbound auth request's query or form parameters.
  2. If `entityID` is missing, fall back to the configured `idp_entity_id`;
     with neither, redirect the user to `disco_srv`
     (`?entityID=<sp>&return=…/Saml2/disco`) and pick up their choice from the
     `entityID` parameter on the return.
  3. Fetch that entity's metadata from the MDQ server and send the AuthnRequest
    to its HTTP-Redirect SSO endpoint.
  4. Persist the selected `entityID` in the encrypted state cookie (the
     discovery round-trip needs no other state).
  5. On the ACS, fetch metadata for that same persisted entity again, build the
    verifier from its signing certificates, and validate the Response against
    that IdP.

  > The discovery hop is a top-level cross-site navigation: the state cookie
  > must survive it (`cookie_same_site = "None"`, or `"Lax"` for GET returns).
  > See ADR 0007.

  ### Encrypted assertions

  With `[[backend.config.encryption_keypairs]]` configured, the ACS decrypts
  `<EncryptedAssertion>` elements (RSA-OAEP / RSA-1.5 key transport,
  AES-CBC/GCM data encryption) and `<EncryptedID>` subjects. Each keypair gets
  its own decryptor and all are tried in turn, so rotation is: add the new
  pair, keep the old key (without `cert_path`) until drained, then drop it.

  The signature acceptance rule spans the encryption boundary: a Response is
  accepted when **either** its envelope signature verifies on the received
  document (the signature covers the ciphertext), **or** every assertion —
  cleartext and decrypted alike — carries a signature that verifies on the XML
  it travelled in (the decrypted plaintext for encrypted assertions). A
  Response carrying encrypted assertions with no `encryption_keypairs`
  configured is rejected. See ADR 0009.

  ### MDQ options

  | Key | Required | Default | Meaning |
  | --- | --- | --- | --- |
  | `mdq.url` | ✅ | — | MDQ server base URL. |
  | `mdq.signing_cert_path` | | — | PEM certificate used to verify signed MDQ entity statements. Required unless `allow_unverified = true`. |
  | `mdq.transform` | | `url_encoded` | EntityID-to-path transform: `url_encoded` or `sha1`. |
  | `mdq.require_role` | | `idp` | Require the fetched metadata to contain an `IDPSSODescriptor`, `SPSSODescriptor`, or either. |
  | `mdq.fallback_ttl_secs` | | metadata-driven | Cache TTL used when the metadata omits `validUntil` and `cacheDuration`. |
  | `mdq.allow_unverified` | | `false` | Accept unsigned/unverified metadata. For testing only. |

  ### The MDQ signer certificate

  `mdq.signing_cert_path` points at the **federation's metadata-signing
  certificate** — a PEM-encoded X.509 certificate, published by the federation
  operator (e.g. SWAMID, eduGAIN, or your pyFF instance). At startup the
  backend reads the file and hands it to the `gamlastan-mdq` client, after
  which **every** EntityDescriptor fetched from the MDQ server is
  signature-verified against it before being trusted or cached.

  The setting is effectively required: with neither `signing_cert_path` nor
  `allow_unverified = true`, the backend refuses to start with

  ```text
  mdq requires signing_cert_path (or allow_unverified=true for testing)
  ```

  A relative path is resolved against the proxy's working directory, the same
  convention as `sp_key_path` and `sp_cert_path`.

  > **Key rollover:** the config currently accepts a single certificate, even
  > though the underlying `gamlastan-mdq` client can hold several trusted
  > signer certs at once. During a federation signing-key rollover, switch the
  > file contents at the announced cutover rather than expecting both keys to
  > be accepted simultaneously.

  ### Subject identifier selection

  A non-success SAML status (for example a cancelled login) is surfaced as an
  authentication error to the frontend. The ACS also **fails closed** on
  request correlation: without the AuthnRequest id persisted at flow start the
  Response is rejected, unless it is truly unsolicited (no `InResponseTo`) and
  `allow_unsolicited = true` (see ADR 0010).

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

# Rewrite attribute values on the response path (SATOSA: AttributeProcessor).
# Processors run in order; regex_sub replaces every match in every value.
# Replacement accepts $1/${1} and Python-style \1 (SATOSA configs port as-is).
[[microservice]]
type = "attribute_processor"
name = "rewrite"
  [[microservice.config.process]]
  attribute = "mail"                     # internal attribute name
    [[microservice.config.process.processors]]
    name = "regex_sub"
    match_pattern = '@legacy\.example\.org$'
    replace_pattern = '@example.org'

# Reject the authentication unless response attributes satisfy regex rules
# (SATOSA: AttributeAuthorization). Rules nest requester -> provider ->
# attribute; "default" (or "") is the wildcard at the first two levels, and a
# specific entry replaces — never merges with — the default. Allow: some value
# must match some regex (absent attribute rejects only with the force flag).
# Deny: any match rejects.
[[microservice]]
type = "attribute_authorization"
name = "authz"
  [microservice.config]
  force_attributes_presence_on_allow = true
  [microservice.config.attribute_allow.default.default]
  mail = ["."]                           # must be present and non-empty
```

See the [micro-services chapter](micro-services.md) for the
`attribute_processor` and `attribute_authorization` semantics in detail
(ADRs 0011/0012).
