# Configuration

tunnelbana is configured by a single TOML file, conventionally `proxy.toml`,
passed as the binary's only argument:

```bash
TUNNELBANA_BIND=0.0.0.0:8080 tunnelbana config/proxy.toml
```

`TUNNELBANA_BIND` (env) sets the listen address; it defaults to
`127.0.0.1:8080`. Everything else lives in the config file.

The container image also accepts `TUNNELBANA_HEALTHCHECK_URL` for its curl probe;
this does not configure the server listener.

## Top-level keys

```toml
base_url             = "https://proxy.example.com"  # required, no trailing slash
state_encryption_key = "${TUNNELBANA_STATE_KEY}"     # required, >= 32 bytes
cookie_name          = "TUNNELBANA_STATE"           # default
cookie_secure        = true                          # default; set false for local http
cookie_same_site     = "None"                        # default; None|Lax|Strict
state_cookie_max_age = 1800                           # default, seconds (0 disables)
http_connect_timeout_seconds = 10                    # outbound HTTP defaults
http_read_timeout_seconds    = 15
http_request_timeout_seconds = 30
http_max_response_bytes      = 8388608               # 8 MiB
attributes           = "config/attributes.toml"      # path, relative to this file
cache_dir            = "/var/lib/tunnelbana/cache"    # optional, disk cache snapshots
index_html           = "index.html"                  # optional, custom landing page at /
```

| Key | Required | Default | Meaning |
| --- | --- | --- | --- |
| `base_url` | ✅ | - | Public base URL. Each module is mounted under `<base_url>/<name>`. |
| `state_encryption_key` | ✅ | - | Secret used to derive the state-cookie AEAD key and the OIDC token-codec key. Must be ≥ 32 bytes; see [Security](security-state-cookie.md). |
| `previous_state_encryption_keys` | | `[]` | Old secrets kept for **decryption only**, to allow zero-downtime [key rotation](security-state-cookie.md#algorithm-pinning-and-key-rotation). Every old key has the same 32-byte minimum as the primary key. |
| `cookie_name` | | `TUNNELBANA_STATE` | Name of the encrypted state cookie. Carries a `__Host-` prefix when `cookie_secure` is on. |
| `cookie_secure` | | `true` | Sets the cookie `Secure` flag. Set `false` only for local plain-HTTP testing. |
| `cookie_same_site` | | `None` | The cookie `SameSite` attribute (`None`, `Lax`, or `Strict`). `None` is needed for cross-site SSO POST-back. |
| `state_cookie_max_age` | | `1800` | Max lifetime of sealed state, in seconds; emitted as `Max-Age` and enforced on unseal. `0` disables the freshness check. |
| `http_connect_timeout_seconds` | | `10` | Connection-establishment deadline for outbound metadata, discovery, JWKS, token and UserInfo requests. |
| `http_read_timeout_seconds` | | `15` | Maximum idle time between chunks of an outbound response body. |
| `http_request_timeout_seconds` | | `30` | Total deadline for one outbound request, including its response body. |
| `http_max_response_bytes` | | `8388608` | Maximum outbound response body buffered by the shared client. Both `Content-Length` and streamed bytes are checked. |
| `attributes` | | - | Path to the [attribute map](#the-attribute-map). Without it, no attribute translation happens. |
| `cache_dir` | | - | Directory for cache persistence snapshots (e.g. federation metadata). |
| `index_html` | | - | Path to a custom HTML file served verbatim at `/`. Without it, a [built-in landing page](#the-index-page) is served. |

### Inbound TLS and certificate renewal

Without a `[tls]` table the listener serves plain HTTP. This is also the mode
to use behind Caddy or another TLS-terminating reverse proxy. To terminate TLS
in tunnelbana, add:

```toml
[tls]
cert_path = "../keys/fullchain.pem"
key_path = "../keys/privkey.pem"
```

Place this top-level table after scalar settings such as `base_url` and
`state_encryption_key`, and outside any plugin's configuration. For a main file
at `config/proxy.toml`, these paths refer to `keys/fullchain.pem` and
`keys/privkey.pem` in the repository root. These are the HTTPS identity files;
the OIDC/SAML signing keys configured under plugins are separate.

Both paths are required and must be non-empty; unknown keys in this table are
rejected. Relative paths are resolved against the main config file's directory,
and absolute paths and environment interpolation are supported. The certificate
file contains PEM certificates in leaf-first order followed by intermediates.
The key file contains exactly one unencrypted PKCS#1, PKCS#8, or SEC1 private
key supported by rustls's ring provider. Certificate parsing and the leaf/key
match are checked before listening; invalid material fails startup rather than
falling back to HTTP. Clients still validate the hostname, validity dates and
trust chain: the loader does not establish that the certificate is trusted.

TLS uses the same `TUNNELBANA_BIND` address and port as HTTP, with TLS 1.2/1.3
and HTTP/1.1 or HTTP/2. There is one selected transport, no additional HTTP
listener or automatic redirect. Set `base_url` to the externally visible URL;
it does not select the listener transport. Cookie settings remain explicit:
keep `cookie_secure = true` for HTTPS, including HTTPS terminated at a reverse
proxy. Local plain-HTTP testing requires appropriate cookie settings separately.

On Unix, run the built binary directly so the saved PID identifies tunnelbana:

```bash
# Run from the repository root after configuring proxy.toml and its TLS files.
cargo build --locked -p tunnelbana
TUNNELBANA_BIND=127.0.0.1:8443 ./target/debug/tunnelbana config/proxy.toml &
tunnelbana_pid=$!

# After the renewal tool has installed BOTH files at the configured paths:
kill -HUP "$tunnelbana_pid"
```

Set `base_url` to the public HTTPS URL, including the port when it is not 443.
Send HUP to the server process, not a `cargo run` wrapper. Sending the signal
does not wait for loading to finish; look for `TLS certificate reloaded` in the
server log and verify the served certificate on a fresh connection. For a
container use `docker kill --signal=HUP <container>`; for Compose use
`docker compose kill --signal=HUP <service>`. Substitute the actual name without
angle brackets. The image's exec-form entrypoint delivers HUP to tunnelbana.

Each delivered SIGHUP reads both files again. Successful loading atomically
replaces the complete certificate/key identity across all workers. New full TLS
handshakes receive the new certificate; existing connections and ordinary TLS
session resumption are unaffected. A failed reload logs an error and retains
the last successfully loaded identity. Fix the files and send another HUP to
retry. Rapid signals can be coalesced by the OS, so a renewal hook should signal
once after publishing the pair. Log messages report successful reloads and
failures without certificate or key contents.

Symlinks are followed afresh on reload. Publishing a new directory containing
the pair and atomically replacing a `live` symlink works. With separate file
replacement, install both files before signaling. Mount certificate directories
and any symlink targets in containers, rather than individual files whose
bind mounts may keep pointing at an old inode. Give the running user read
access on renewal too; the packaged image runs as UID/GID 10001. Keep private
keys out of images and restrict their filesystem permissions.

HUP does **not** reload `proxy.toml`, TLS paths, protocol signing keys, plugins,
cookie secrets or the landing page. Those changes require a restart. In HTTP
mode HUP is logged and ignored. SIGTERM retains Actix's graceful shutdown
behavior. Non-Unix systems support HTTPS but require a restart for renewal.
This feature does not provision certificates, configure mTLS or select multiple
identities through SNI.

#### Runnable local HTTPS and HUP example

The following Unix walkthrough uses Bash, OpenSSL 3, curl with
`--retry-all-errors` support, and the project's Rust/CPython build prerequisites.
Run all blocks in the **same shell from the repository root**. Port 8443 must be
free. The bundled `config/tls-example.toml` serves `/` and `/health` without
frontends or backends, so this checks transport and renewal without an upstream
identity provider. It uses environment interpolation for the certificate paths;
`TUNNELBANA_TLS_CERT` and `TUNNELBANA_TLS_KEY` are example variables, not built-in
server options.

Create isolated test files and a short-lived self-signed localhost certificate:

```bash
cargo build --locked -p tunnelbana
tls_demo_dir="$(mktemp -d)"
export TUNNELBANA_STATE_KEY="$(openssl rand -base64 48)"
export TUNNELBANA_TLS_CERT="$tls_demo_dir/fullchain.pem"
export TUNNELBANA_TLS_KEY="$tls_demo_dir/privkey.pem"

(umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -noenc -days 2 -set_serial 1 -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$TUNNELBANA_TLS_KEY" -out "$TUNNELBANA_TLS_CERT")

TUNNELBANA_BIND=127.0.0.1:8443 \
  ./target/debug/tunnelbana config/tls-example.toml \
  > "$tls_demo_dir/server.log" 2>&1 &
tls_demo_pid=$!

curl --noproxy '*' --resolve localhost:8443:127.0.0.1 \
  --retry 10 --retry-connrefused --retry-delay 1 --retry-max-time 15 --max-time 3 \
  --fail --show-error --cacert "$TUNNELBANA_TLS_CERT" \
  https://localhost:8443/health
```

Expect `{"status":"ok"}`. Curl trusts only the explicitly supplied test
certificate for this example and verifies the localhost hostname; no `--insecure`
option is needed. For production use your supplied certificate chain and key
in your real proxy configuration.

Generate a replacement with a new key and serial, install both files, then HUP:

```bash
(umask 077; openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -noenc -days 2 -set_serial 2 -subj /CN=localhost \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$tls_demo_dir/next-key.pem" -out "$tls_demo_dir/next-cert.pem")

mv "$tls_demo_dir/next-key.pem" "$TUNNELBANA_TLS_KEY"
mv "$tls_demo_dir/next-cert.pem" "$TUNNELBANA_TLS_CERT"
kill -HUP "$tls_demo_pid"

# A fresh curl process verifies the server against the replacement certificate.
# Brief retries allow the asynchronous HUP reload to finish.
curl --noproxy '*' --resolve localhost:8443:127.0.0.1 \
  --retry 10 --retry-all-errors --retry-delay 1 --retry-max-time 15 --max-time 3 \
  --fail --show-error --cacert "$TUNNELBANA_TLS_CERT" \
  https://localhost:8443/health

grep 'TLS certificate reloaded' "$tls_demo_dir/server.log"
kill -0 "$tls_demo_pid"
```

Expect another `{"status":"ok"}`, a `TLS certificate reloaded` log entry,
and a successful `kill -0` confirming that the same process is still running.
The new self-signed certificate has a different key, so the fresh curl request
also checks that the replacement is actually being served. Before reload
finishes, curl may report a certificate verification failure and then retry.

Stop the demo when finished:

```bash
kill -TERM "$tls_demo_pid"
wait "$tls_demo_pid"
```

The generated files and logs remain in `$tls_demo_dir` for inspection. For plain
HTTP, omit the entire `[tls]` table in your configuration and use an `http://`
health URL; HUP is then a logged no-op.

#### Container health checks with direct TLS

The image defaults to `TUNNELBANA_HEALTHCHECK_URL=http://127.0.0.1:8080/health`.
When enabling TLS, use an HTTPS URL whose hostname matches the certificate and
resolves to the local listener. Supply a trusted CA bundle for private PKI
(for example through curl's `CURL_CA_BUNDLE` environment variable). Certificate
verification remains enabled. Alternatively, override the Compose health check
to explicitly resolve the certificate hostname to loopback:

```yaml
healthcheck:
  test: ["CMD", "curl", "-fsS", "--resolve", "proxy.example.com:8080:127.0.0.1", "https://proxy.example.com:8080/health"]
  interval: 30s
  timeout: 3s
  retries: 3
```

Use the configured listening port in both the URL and `--resolve`. Deployments
that terminate TLS in Caddy continue to use the default HTTP health check.

### The index page

The proxy serves a landing page at `/` (and, for the built-in page, its logo at
`/assets/tunnelbana.png`). By default this is a small static page with the
tunnelbana logo, tagline, and a link to the project.

Point `index_html` at your own HTML file to replace it. A relative path is
resolved against the **config file's directory** (the same rule as a plugin
`include`), so a file sitting next to `proxy.toml` is named directly:

```toml
index_html = "index.html"   # next to proxy.toml; or an absolute path
```

The file is read **once at boot** and served verbatim with
`Content-Type: text/html; charset=utf-8`; it is never re-read per request, so
edits require a restart. A configured-but-unreadable path is a fatal startup
error (fail-fast) rather than a silent fall-back to the default. A custom page
is responsible for its own assets — the built-in `/assets/tunnelbana.png` route
remains available, but nothing else is served for you. See
[ADR 0031](https://github.com/SUNET/tunnelbana/blob/main/docs/adr/0031-custom-index-page.md).

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

1. **Frontend pin** - a frontend with `backend = "<name>"` in its `config` always
   routes its flows to that backend.
2. **Micro-service routing** - a request-path service such as
   [`custom_routing`](micro-services.md#routing-the-flow-custom_routing-and-idp_hinting)
   (often fed by
   [`idp_hinting`](micro-services.md#routing-the-flow-custom_routing-and-idp_hinting))
   sets the target backend per
   request.
3. **Default backend** - the **first** `[[backend]]` in the file, used when
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
off that prefix - e.g. the SAML backend serves `…/Saml2/acs` and
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
reverse-proxy rewrite) - or the backend runs the discovery itself when
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
`"sp"`) before their AuthnRequests are accepted - see the
[plugin reference](built-in-plugins.md#saml2-frontend---identity-provider).

## `${ENV}` interpolation

Anywhere in the config (and in included files), `${VAR}` is replaced by the
environment variable `VAR` before parsing. Interpolation applies to the raw
file text, **including comments** — an unset variable fails configuration
loading with an error naming the variable (matching SATOSA's `!ENV`), so
avoid writing a literal `${...}` pattern in comments. Use this to keep
secrets out of the file:

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

[attributes.authenticating_authority]
openid = ["authenticating_authority"] # trusted upstream issuer claim

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

`authenticating_authority` is a reserved release-control mapping for both the
`oidc` and `oidc_federation` frontends, not an ordinary attribute. Its OpenID
name is populated only from the validated upstream issuer, advertised in
discovery, and may be renamed by changing the first mapped name. Provider-owned
ID-token claim names such as `sub`, `iss`, `nonce`, and `acr` are rejected at
startup. Omit the mapping to suppress the claim. See
[Trusted upstream authentication authority](attributes.md#trusted-upstream-authentication-authority)
for the trust and collision rules.

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
