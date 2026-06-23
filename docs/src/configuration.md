# Configuration

tunnelbana is configured by a single TOML file, conventionally `proxy.toml`,
passed as the binary's only argument:

```bash
TUNNELBANA_BIND=0.0.0.0:8080 tunnelbana config/proxy.toml
```

`TUNNELBANA_BIND` (env) sets the listen address; it defaults to
`127.0.0.1:8080`. Everything else lives in the config file.

## Top-level keys

```toml
base_url             = "https://proxy.example.com"  # required, no trailing slash
state_encryption_key = "a-long-random-secret"       # required, >= 32 bytes
cookie_name          = "TUNNELBANA_STATE"           # default
cookie_secure        = true                          # default; set false for local http
cookie_same_site     = "None"                        # default; None|Lax|Strict
state_cookie_max_age = 1800                           # default, seconds (0 disables)
attributes           = "config/attributes.toml"      # path, relative to this file
cache_dir            = "/var/lib/tunnelbana/cache"    # optional, disk cache snapshots
```

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `base_url` | ✅ | — | Public base URL. Each module is mounted under `<base_url>/<name>`. |
| `state_encryption_key` | ✅ | — | Secret used to derive the state-cookie AEAD key and the OIDC token-codec key. Must be ≥ 32 bytes; see [Security](security-state-cookie.md). |
| `previous_state_encryption_keys` | | `[]` | Old secrets kept for **decryption only**, to allow zero-downtime [key rotation](security-state-cookie.md#algorithm-pinning-and-key-rotation). |
| `cookie_name` | | `TUNNELBANA_STATE` | Name of the encrypted state cookie. Carries a `__Host-` prefix when `cookie_secure` is on. |
| `cookie_secure` | | `true` | Sets the cookie `Secure` flag. Set `false` only for local plain-HTTP testing. |
| `cookie_same_site` | | `None` | The cookie `SameSite` attribute (`None`, `Lax`, or `Strict`). `None` is needed for cross-site SSO POST-back. |
| `state_cookie_max_age` | | `1800` | Max lifetime of sealed state, in seconds; emitted as `Max-Age` and enforced on unseal. `0` disables the freshness check. |
| `attributes` | | — | Path to the [attribute map](#the-attribute-map). Without it, no attribute translation happens. |
| `cache_dir` | | — | Directory for cache persistence snapshots (e.g. federation metadata). |

> **Security:** `state_encryption_key`, the cookie attributes, and the TTL all
> harden the [stateless state cookie](security-state-cookie.md) that carries
> per-flow secrets (PKCE verifier, OIDC `state`/`nonce`). Read that page before
> tuning these in production.

### Logging

```toml
[logging]
level  = "info,tunnelbana=debug"   # a tracing EnvFilter directive
format = "json"                     # "pretty" (default) or "json"
```

## Modules: frontends, backends, micro-services

Each module is an array-of-tables entry. The `type` selects a registered
plugin; the `name` is a unique instance name that becomes its URL prefix and its
state namespace.

```toml
[[frontend]]
type = "oidc_federation"
name = "OIDFed"
  [frontend.config]
  # … plugin-specific keys …

[[backend]]
type = "saml2"
name = "Saml2"
  [backend.config]
  # … plugin-specific keys …

[[microservice]]
type = "filter_attributes"
name = "filter"
  [microservice.config]
  allowed = ["mail", "givenname", "surname", "edupersonprincipalname"]
```

You may list multiple frontends, backends and micro-services. Micro-services run
in the order listed. The per-plugin `config` keys are documented in the
[built-in plugin reference](built-in-plugins.md).

### Backend selection

With more than one `[[backend]]`, every authentication flow is steered to exactly
one of them. The choice is resolved with this precedence (first match wins):

1. **Frontend pin** — a frontend with `backend = "<name>"` in its `config` always
   routes its flows to that backend.
2. **Micro-service routing** — a request-path service such as
   [`custom_routing`](micro-services.md#custom_routing) (often fed by
   [`idp_hinting`](micro-services.md#idp_hinting)) sets the target backend per
   request.
3. **Default backend** — the **first** `[[backend]]` in the file, used when
   nothing above selected one.

The frontend pin is the most direct way to say *"this entry point always talks to
that upstream."* For example, a SAML IdP frontend that should always authenticate
against an OIDC upstream, alongside an OIDC OP frontend pinned to a SAML SP
backend:

```toml
# Two backends. "FederationSP" is listed first, so it is the default.
[[backend]]
type = "oidc_federation"
name = "FederationSP"
  [backend.config]
  # … RP/federation keys …

[[backend]]
type = "saml2"
name = "SamlSP"
  [backend.config]
  # … SP keys …

# A SAML IdP frontend, pinned to the federation backend regardless of routing.
[[frontend]]
type = "saml2"
name = "SamlIdP"
  [frontend.config]
  backend = "FederationSP"
  # … IdP keys …

# An OIDC OP frontend, pinned to the SAML SP backend.
[[frontend]]
type = "oidc"
name = "OidcOP"
  [frontend.config]
  backend = "SamlSP"
  # … OP keys …
```

`backend` is optional and accepted by all three frontends (`oidc`,
`oidc_federation`, `saml2`). It must name a configured `[[backend]]`; an unknown
name fails the flow at runtime with an unknown-module error (the same surface as
a `custom_routing` rule pointing at a missing backend). Because the pin sits
above micro-service routing, a pinned frontend ignores `custom_routing` /
`idp_hinting` for backend selection. The request-path services still execute, so
other effects (for example, a target-entity decoration consumed by the selected
backend) still apply. Leave `backend` unset when you want those services to
choose the backend (ADR 0027).

### Mount points

A module named `Saml2` is mounted at `<base_url>/Saml2`, and its endpoints hang
off that prefix — e.g. the SAML backend serves `…/Saml2/acs` and
`…/Saml2/metadata`; the federation OP serves `…/OIDFed/authorization`,
`…/OIDFed/token`, `…/OIDFed/jwks` and `…/OIDFed/.well-known/openid-federation`.

> **Reverse-proxy note.** Some identifiers must live at a fixed well-known path
> on the bare host. For example an OpenID-Federation entity whose `entity_id` is
> the bare host serves its entity configuration under `/<name>/.well-known/…`,
> so the fronting reverse proxy should rewrite
> `/.well-known/openid-federation` → `/<name>/.well-known/openid-federation`.

### Splitting config out with `include`

Any module's `config` table can be pulled into its own file with `include`
(path relative to the main config file). The included file *replaces* the inline
`config`:

```toml
[[frontend]]
type = "oidc_federation"
name = "OIDFed"
include = "plugins/oidfed.toml"
```

`include` replaces the **whole** plugin `config` (TOML, path relative to this
file). To externalize **only** the OIDC client roster while keeping keys and
other settings inline, use the `oidc`/`oidc_federation` frontends'
[`clients_file`](built-in-plugins.md#client-roster-from-a-file) key instead - a
JSON array of clients, merged with any inline `clients`, with its path read
relative to the working directory (like the key paths beside it).

## SAML MDQ and discovery

The `saml2` backend has two upstream-metadata modes:

1. **Static single-IdP mode.** Pin one IdP with `idp_entity_id`,
  `idp_sso_url`, and `idp_cert_path`.
2. **MDQ federation mode.** Keep `idp_entity_id` as the default/fallback IdP,
  and add `[backend.config.mdq]` so the backend resolves the selected IdP's
  metadata on demand from an MDQ server.

In MDQ mode, the chosen IdP can arrive on the auth request as an `entityID`
parameter (a discovery-service return, a frontend-specific handoff, or a
reverse-proxy rewrite) — or the backend runs the discovery itself when
`disco_srv` is configured. The flow:

1. Read `entityID` from the inbound query or form parameters. If it is absent,
  fall back to the configured `idp_entity_id`. With neither, redirect the user
  to `disco_srv` (`?entityID=<sp_entity_id>&return=…/<name>/disco`, the
  SP-initiated Identity Provider Discovery Service Protocol); the discovery
  service sends them back to `…/<name>/disco` with the chosen `entityID`.
2. Resolve that entity from the MDQ server, require the configured role, and
  send the AuthnRequest to the entity's HTTP-Redirect `SingleSignOnService`.
3. Persist the chosen `entityID` in the encrypted state cookie (the discovery
  round-trip needs no other state; the in-flight frontend request already
  rides the cookie).
4. On the ACS, re-resolve metadata for that same persisted `entityID`, build a
  verifier from its signing certificates, and validate the SAML Response
  against that IdP rather than trusting the unverified `Issuer` alone.

This gives tunnelbana the same practical split SATOSA uses: discovery chooses
the target IdP before the backend sends the AuthnRequest, and the ACS verifies
the response against the IdP that was actually selected for the flow. With
`disco_srv` set, SP metadata also publishes the
`<idpdisc:DiscoveryResponse>` extension so the federation knows the return
endpoint. `disco_srv` requires MDQ mode; the state cookie must survive the
top-level cross-site discovery hop (`cookie_same_site = "None"`, or `"Lax"`
for GET returns). See ADR 0007.

The trust anchor for all of this is `mdq.signing_cert_path`: the federation's
metadata-signing certificate (PEM). Every entity statement fetched from the
MDQ server is signature-verified against it, so the MDQ server itself never
has to be trusted. Without it the backend refuses to start unless
`allow_unverified = true` is set explicitly (testing only). See
[MDQ options](built-in-plugins.md#mdq-options) for the full key reference.

The `saml2` **frontend** has its own metadata requirement in the other
direction: downstream SPs must be registered via
`[frontend.config.metadata]` (local files and/or MDQ with the role forced to
`"sp"`) before their AuthnRequests are accepted — see the
[plugin reference](built-in-plugins.md#saml2-frontend--identity-provider).

## `${ENV}` interpolation

Anywhere in the config (and in included files), `${VAR}` is replaced by the
environment variable `VAR` before parsing. Unknown variables become the empty
string. Use this to keep secrets out of the file:

```toml
state_encryption_key = "${TUNNELBANA_STATE_KEY}"
```

## The attribute map

The `attributes` file mirrors SATOSA's `internal_attributes.yaml`: it maps an
**internal** attribute name to the **external** names used by each protocol
profile (`openid`, `saml`). Frontends and backends only ever deal in internal
names; the map translates at the edges.

```toml
# config/attributes.toml
user_id_from_attrs = ["edupersonprincipalname"]

[attributes.mail]
openid = ["email"]
saml   = { names = ["mail", "email", "emailAddress"], oid = "urn:oid:0.9.2342.19200300.100.1.3", friendly_name = "mail" }

[attributes.givenname]
openid = ["given_name"]
saml   = ["givenName"]              # plain-list form, still valid

[attributes.edupersonprincipalname]
openid = ["sub"]
saml   = { names = ["eduPersonPrincipalName"], oid = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", friendly_name = "eduPersonPrincipalName" }
```

- Each `[attributes.<internal>]` table lists the external names per profile. On
  the way **in** from a protocol, any matching external name is collected under
  `<internal>`; on the way **out**, the internal value is emitted under the
  first external name for the target profile.
- A profile entry is either a **plain list** of names (the legacy form) or a
  **detailed table** with `names`, an `oid` urn and a `friendly_name`. The OID
  and FriendlyName are also matched on the way in, and they feed the SAML
  frontend's `attribute_name_format = "uri"` mode (OID-named attributes, as
  SWAMID SPs expect).
- `user_id_from_attrs` lists the internal attributes used to compose the
  subject identifier when a backend does not supply one directly.

For the SAML backend in MDQ mode, `user_id_from_attrs` is also the preferred
way to select a federation-stable primary identifier. If the configured
attributes compose a subject, tunnelbana uses that value downstream; otherwise
it falls back to the raw SAML `NameID`. When that fallback is a persistent
`NameID` from MDQ mode, tunnelbana scopes it by the upstream IdP issuer before
handing it to downstream frontends, so two IdPs that mint the same persistent
identifier do not collide.

In practice, prefer a federation-stable internal attribute such as
`edupersontargetedid`, `epuid`, or another deployment-specific stable user
identifier over the raw `NameID` when you run against multiple IdPs.

## Keys: PEM or JWK

Anywhere a plugin needs a signing key it accepts **one** of three forms (they
share the same `signing_*` field names):

```toml
# 1. a PEM/DER file on disk
signing_key_path  = "keys/op.key"

# 2. an inline JWK
signing_jwk       = { kty = "EC", crv = "P-256", d = "…", x = "…", y = "…" }

# 3. a JWK in its own file
signing_jwk_path  = "keys/op.jwk"

# common modifiers
signing_algorithm = "ES256"     # inferred from the key if omitted (RSA→RS256, P-256→ES256)
signing_key_id    = "op-key-1"  # the JWK `kid`
```

PEM loading auto-detects RSA, EC P-256/P-384 and Ed25519 private keys (SEC1 or
PKCS#8). Everything is normalised to a `jose_rs::Jwk` internally.

## Validation

On startup tunnelbana fails fast if `base_url` or `state_encryption_key` is
empty, if a module's `type` is not a registered plugin, or if a plugin rejects
its own config (e.g. a missing key file).
