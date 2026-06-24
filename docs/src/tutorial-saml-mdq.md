# Tutorial: SAML and OIDC frontends over a SWAMID SP backend

This chapter walks through a real tunnelbana deployment that fronts the
[SWAMID](https://wiki.sunet.se/display/SWAMID) federation. Two frontends share
one upstream:

- a generic **SAML2 IdP** (`Saml2IDP`) for downstream SAML service providers, and
- an **OpenID Connect OP** (`OIDC`) for downstream OIDC relying parties,

both authenticating through a single **SAML2 SP** backend (`Saml2SP`) that talks
to SWAMID via **MDQ** (per-entity metadata, signature-verified) and
**SeamlessAccess** discovery.

Everything below is modelled on a working
`deploy/tunnelbana/config/proxy.toml` and `config/attributes.toml`. The SWAMID
service URLs (the MDQ endpoint and SeamlessAccess) are real and kept as-is; the
proxy/RP hostnames such as `proxy.example.com` and `vaultwarden.example.com` are
placeholders - replace them with your own deployment's names.

## What we are building

```text
  SAML SP                tunnelbana (this)                SWAMID IdPs
     │     AuthnRequest    ┌──────────────────┐   AuthnRequest    │
     │ ──────────────────► │ saml2 frontend   │ ────────────────► │
     │                     │ (IdP "Saml2IDP") │  via SeamlessAccess
     │ ◄────────────────── │      +           │  disco + MDQ      │
     │   signed assertion  │ oidc  frontend   │ ◄──────────────── │
     │                     │ (OP   "OIDC")    │   signed assertion
  OIDC RP                  │      +           │                   │
     │  authorization req  │ saml2 backend    │                   │
     │ ──────────────────► │ (SP  "Saml2SP")  │                   │
     │ ◄────────────────── └──────────────────┘                   │
     │   id_token + claims                                         │
```

A downstream SAML SP or OIDC RP starts a flow against the matching frontend.
tunnelbana, acting as a SWAMID SP, sends the user to SeamlessAccess to pick a
home organisation, resolves that IdP's metadata from MDQ, sends an
AuthnRequest, and verifies the returned assertion against that IdP's
signature. The attributes are mapped to internal names, shaped by a small
micro-service pipeline, and re-emitted to whichever frontend started the flow.

The two frontends stay mutually oblivious; they only exchange internal attribute
data through the backend. See [architecture](architecture.md) for the module
model and [configuration](configuration.md) for the full config-key reference.

## Prerequisites

- A **registered SWAMID SP**. You register the SP metadata published at
  `/Saml2SP/metadata` (see [SWAMID registration](#swamid-registration) below)
  and assert the REFEDS **Personalized Access** entity category so IdPs release
  `subject-id`.
- A **TLS-terminating reverse proxy** in front of tunnelbana (the deploy uses
  Caddy with automatic Let's Encrypt, proxying to the binary on `:8080`).
  tunnelbana itself speaks plain HTTP behind it.
- A public **`base_url`** with a DNS name and certificate. The whole config is
  anchored to it; every module mounts under `<base_url>/<name>`.

This tutorial uses `https://proxy.example.com` throughout.

## Top-level config

```toml
base_url = "https://proxy.example.com"
state_encryption_key = "${TUNNELBANA_STATE_KEY}"
cookie_name = "TUNNELBANA_STATE"
cookie_secure = true
# The SeamlessAccess discovery hop and the IdP's SAML POST back are top-level
# cross-site navigations - the state cookie must survive them.
cookie_same_site = "None"
attributes = "config/attributes.toml"

[logging]
level = "info,tunnelbana=debug"
format = "json"
```

The interesting choice here is `cookie_same_site = "None"`. tunnelbana is
stateless: each in-flight flow's secrets (the SP request id, the chosen IdP
`entityID`, the OIDC `state`/`nonce`) live only in an encrypted cookie. Two
steps in this deployment are **top-level cross-site navigations** that must carry
that cookie back:

1. the redirect to SeamlessAccess and the return to `/Saml2SP/disco`, and
2. the IdP's signed-assertion `POST` to `/Saml2SP/acs`.

A `Lax` or `Strict` cookie would be dropped on the cross-site `POST`-back and
the flow would fail to correlate. `None` (with `Secure`, which `cookie_secure =
true` guarantees) is required. The `state_encryption_key` is interpolated from
the environment so the secret never lands in a committed file; see
[`${ENV}` interpolation](configuration.md#env-interpolation) and the
[state-cookie security](security-state-cookie.md) chapter.

## Generating the keys

All keys live in `keys/` and are generated on the server - never commit them.
Run these once:

```bash
mkdir -p ~/tunnelbana-demo/keys && cd ~/tunnelbana-demo/keys

# SAML SP (backend) signing + encryption pair - published in SP metadata.
# RSA-4096: SWAMID Tech 6.2.1 marks key strength under 4096-bit RSA as
# NOT RECOMMENDED.
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout backend.key -out backend.crt \
  -subj "/CN=proxy.example.com"

# SAML IdP (frontend) signing pair - published in IdP metadata:
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 \
  -keyout frontend.key -out frontend.crt \
  -subj "/CN=proxy.example.com"

# OIDC OP id_token signing key (frontend "OIDC") - published at /OIDC/jwks:
openssl ecparam -name prime256v1 -genkey -noout -out op.key

# SWAMID metadata signer cert - verifies MDQ responses (both directions):
curl -sSfO https://mds.swamid.se/md/md-signer2.crt
# Verify the fingerprint against https://wiki.sunet.se/display/SWAMID (the
# SWAMID metadata page publishes the md-signer2 fingerprint).
```

Each key's role:

| File | Role |
| --- | --- |
| `backend.key` / `backend.crt` | The SP's SAML signing **and** decryption key. RSA-4096 to satisfy SWAMID Tech 6.2.1. The cert is published in SP metadata for signing and (with `use="encryption"`) for assertion decryption. |
| `frontend.key` / `frontend.crt` | The IdP's assertion-signing key, published in IdP metadata so downstream SPs can verify the assertions tunnelbana mints. RSA-4096 as well. |
| `op.key` | The OIDC OP's `id_token` signing key. EC `prime256v1` (P-256, `ES256`), published as a JWK at `/OIDC/jwks`. |
| `md-signer2.crt` | The SWAMID metadata signer certificate. The **trust anchor** for every entity statement fetched from MDQ, in both the frontend (SP role) and backend (IdP role) directions. |

The state-cookie key and the OIDC client secret are environment variables, kept
in an `.env` file next to the deployment:

```bash
{
  echo "TUNNELBANA_STATE_KEY=$(openssl rand -base64 48)"
  echo "VAULTWARDEN_CLIENT_SECRET=$(openssl rand -base64 48)"
} > ~/tunnelbana-demo/.env
chmod 600 ~/tunnelbana-demo/.env
```

## Frontend: the SAML2 IdP

This frontend faces downstream SAML SPs. SSO lives at `<base_url>/Saml2IDP/sso`
and the IdP metadata at `<base_url>/Saml2IDP/metadata`.

```toml
# SSO endpoint:  <base_url>/Saml2IDP/sso
# IdP metadata:  <base_url>/Saml2IDP/metadata
[[frontend]]
type = "saml2"
name = "Saml2IDP"
  [frontend.config]
  idp_key_path = "keys/frontend.key"
  idp_cert_path = "keys/frontend.crt"
  sign_assertions = true
  # transient first (default) to match what the upstream leg releases.
  name_id_formats = [
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
  ]
  # OID-named attributes (Name="urn:oid:…" + FriendlyName) as SWAMID SPs expect.
  attribute_name_format = "uri"

  # Registered SP metadata is required (assertions are never sent to an ACS
  # taken from the request). SPs resolve on demand from SWAMID MDQ; add
  # local = ["metadata/my-sp.xml"] entries for SPs outside the federation.
  [frontend.config.metadata]
  [frontend.config.metadata.mdq]
  url = "https://mds.swamid.se/entities/"
  signing_cert_path = "keys/md-signer2.crt"

  [frontend.config.organization]
  name = "Tunnelbana demo (Test)"
  display_name = "Tunnelbana demo (test)"
  url = "https://example.com"

  [[frontend.config.contact_person]]
  contact_type = "technical"
  email_address = "kushal@sunet.se"
  given_name = "Technical"

  [[frontend.config.contact_person]]
  contact_type = "support"
  email_address = "kushal@sunet.se"
  given_name = "Support"
```

Three things matter here:

- **`attribute_name_format = "uri"`** emits attributes with `Name="urn:oid:…"`
  plus a `FriendlyName`, the form SWAMID SPs expect. The OIDs come from the
  detailed `saml` entries in the attribute map (below).
- **`name_id_formats`** lists `transient` first so the IdP's NameID matches what
  the upstream SP leg typically releases; `persistent` is offered as a fallback.
- **The SP metadata source is mandatory.** A downstream SP's AuthnRequest is
  only accepted if that SP is already registered, because tunnelbana never sends
  an assertion to an ACS URL taken from the request itself - it sends it to the
  ACS in the SP's verified metadata. Here SPs are resolved on demand from SWAMID
  MDQ with the role forced to `sp`, signature-verified against `md-signer2.crt`.
  For SPs outside the federation, drop a metadata file in `metadata/` and add a
  `local = ["metadata/my-sp.xml"]` entry under `[frontend.config.metadata]`. See
  the [`saml2` frontend reference](built-in-plugins.md#saml2-frontend---identity-provider).

## Frontend: the OIDC OP

A second frontend, alongside the SAML IdP, lets downstream OIDC relying parties
authenticate through the same SWAMID SP backend. Its endpoints hang off `/OIDC`:

```text
discovery: <base_url>/OIDC/.well-known/openid-configuration
jwks:      <base_url>/OIDC/jwks
authorize: <base_url>/OIDC/authorization
token:     <base_url>/OIDC/token
userinfo:  <base_url>/OIDC/userinfo
```

```toml
[[frontend]]
type = "oidc"
name = "OIDC"
  [frontend.config]
  # id_token signing key (PEM). Generated above:
  #   openssl ecparam -name prime256v1 -genkey -noout -out keys/op.key
  signing_key_path = "keys/op.key"
  signing_algorithm = "ES256"
  signing_key_id = "op-key-1"
  # Refresh-token lifetime (sliding window; rotated on each use). Default 30 days.
  # refresh_token_ttl = 2592000

  # Vaultwarden / OIDCWarden RP. Confidential client: PKCE plus client secret.
  # The secret is NOT stored here - it is injected from VAULTWARDEN_CLIENT_SECRET.
  # refresh_token is enabled so Vaultwarden can extend sessions (offline_access).
  [[frontend.config.clients]]
  client_id = "vaultwarden"
  client_secret = "${VAULTWARDEN_CLIENT_SECRET}"
  redirect_uris = ["https://vaultwarden.example.com/identity/connect/oidc-signin"]
  response_types = ["code"]
  grant_types = ["authorization_code", "refresh_token"]
  token_endpoint_auth_method = "client_secret_basic"
```

The OP signs `id_token`s with the EC `op.key` under `kid = op-key-1`, published
at `/OIDC/jwks`. The single registered client is a **confidential** RP
(Vaultwarden / OIDCWarden): it presents both a client secret (via HTTP Basic,
`client_secret_basic`) and a PKCE verifier. The `client_secret` is interpolated
from `${VAULTWARDEN_CLIENT_SECRET}` so it never lands in the committed file.
`refresh_token` is added to `grant_types` so the RP can request
`offline_access` and silently extend sessions; OIDC tokens are stateless (the
refresh token is a JWE, validated without a server lookup). See the
[`oidc` frontend reference](built-in-plugins.md#oidc-frontend---openid-provider)
for every client knob, and
[client roster from a file](built-in-plugins.md#client-roster-from-a-file) if you
prefer to externalise the client list.

## Backend: the SAML2 SP

The single backend is a SWAMID SP. Its endpoints:

```text
ACS:          <base_url>/Saml2SP/acs
disco return: <base_url>/Saml2SP/disco
SP metadata:  <base_url>/Saml2SP/metadata
```

```toml
[[backend]]
type = "saml2"
name = "Saml2SP"
  [backend.config]
  sp_entity_id = "https://proxy.example.com/"  # (entityid)
  sp_key_path = "keys/backend.key"                          # (key_file)
  sp_cert_path = "keys/backend.crt"                         # (cert_file)
  # No default IdP: users without a target are sent to SeamlessAccess and come
  # back to /Saml2SP/disco with their choice. (disco_srv)
  disco_srv = "https://service.seamlessaccess.org/ds/"
  name_id_format = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  accepted_time_diff_secs = 180          # (accepted_time_diff)
  passthrough_unmapped_attributes = true # (allow_unknown_attributes)
  # Relaxes the InResponseTo requirement within an in-flight flow only - a
  # cookie-less IdP-initiated Response cannot complete in a stateless proxy.
  allow_unsolicited = true               # (allow_unsolicited)

  # IdP metadata resolved per entityID from SWAMID MDQ, signature-verified
  # against the federation signer cert. (metadata.mdq)
  [backend.config.mdq]
  url = "https://mds.swamid.se/entities/"
  signing_cert_path = "keys/md-signer2.crt"

  # Decrypts <EncryptedAssertion>/<EncryptedID>; the cert is published in SP
  # metadata with use="encryption". (encryption_keypairs)
  [[backend.config.encryption_keypairs]]
  key_path = "keys/backend.key"
  cert_path = "keys/backend.crt"

  [backend.config.organization]
  name = "Tunnelbana demo (Test)"
  display_name = "Tunnelbana demo (test)"
  url = "https://example.com"

  [[backend.config.contact_person]]
  contact_type = "technical"
  email_address = "kushal@sunet.se"
  given_name = "Technical"

  [[backend.config.contact_person]]
  contact_type = "support"
  email_address = "kushal@sunet.se"
  given_name = "Support"
```

The SATOSA `SAMLBackend` field names are noted in the inline comments for anyone
migrating an existing config.

**The MDQ resolution flow.** There is no pinned IdP. When a flow has no target,
the backend redirects the user to `disco_srv` (SeamlessAccess) with
`?entityID=<sp_entity_id>&return=…/Saml2SP/disco`. SeamlessAccess sends them
back to `/Saml2SP/disco` carrying the chosen IdP's `entityID`. The backend then:

1. resolves **that one** `entityID` from `https://mds.swamid.se/entities/`,
   verifying the entity statement's signature against `md-signer2.crt`;
2. sends the AuthnRequest to the IdP's HTTP-Redirect `SingleSignOnService`;
3. persists the chosen `entityID` in the encrypted state cookie; and
4. on the ACS, re-resolves metadata for that **same** persisted `entityID`,
   builds a verifier from its signing certificates, and validates the returned
   Response against that IdP rather than trusting the unverified `Issuer`.

So the MDQ signer cert is the only trust anchor needed - the MDQ server itself
is never trusted. See [SAML MDQ and discovery](configuration.md#saml-mdq-and-discovery)
and ADR 0007.

The other key choices:

- **`encryption_keypairs`** lets the SP decrypt `<EncryptedAssertion>` and
  `<EncryptedID>`. The same `backend.crt` is published in SP metadata with
  `use="encryption"` (ADR 0009).
- **`passthrough_unmapped_attributes = true`** carries SAML attributes that have
  no entry in the attribute map through unchanged, instead of dropping them.
- **`allow_unsolicited = true`** relaxes the `InResponseTo` check **within an
  in-flight flow only**. It does not enable true IdP-initiated SSO: a cookie-less
  IdP-initiated Response cannot complete in a stateless proxy (ADR 0010).
- **`accepted_time_diff_secs = 180`** is the clock-skew tolerance for assertion
  validity windows.

Note that tunnelbana is slightly stricter than SATOSA's
`want_assertions_or_response_signed`: the **assertion** must always be signed. A
Response signature is verified when present but never substitutes for the
assertion signature. See the
[`saml2` backend reference](built-in-plugins.md#saml2-backend---service-provider).

## The attribute map

`config/attributes.toml` maps internal attribute names to per-protocol external
names. Frontends and backends only ever deal in internal names; the map
translates at both edges. Full file:

```toml
# Attribute map: internal name -> per-protocol external names.

# The REFEDS Personalized Access entity category (asserted in the SWAMID
# registration) releases SAML subject-id rather than eduPersonPrincipalName.
# When subjectid is absent the backend falls back to a scoped NameID.
user_id_from_attrs = ["subjectid"]

[attributes.subjectid]
saml = { names = ["subject-id"], oid = "urn:oasis:names:tc:SAML:attribute:subject-id", friendly_name = "subject-id" }

[attributes.mail]
openid = ["email"]
saml = { names = ["mail", "email", "emailAddress"], oid = "urn:oid:0.9.2342.19200300.100.1.3", friendly_name = "mail" }

# Synthesized by the static_attributes micro-service (see below), not released
# by the IdP. openid-only, so the SAML frontend never emits it.
[attributes.email_verified]
openid = ["email_verified"]

[attributes.givenname]
openid = ["given_name"]
saml = { names = ["givenName"], oid = "urn:oid:2.5.4.42", friendly_name = "givenName" }

[attributes.surname]
openid = ["family_name"]
saml = { names = ["sn", "surname"], oid = "urn:oid:2.5.4.4", friendly_name = "sn" }

[attributes.name]
openid = ["name"]
saml = { names = ["displayName", "cn"], oid = "urn:oid:2.16.840.1.113730.3.1.241", friendly_name = "displayName" }

[attributes.edupersonprincipalname]
openid = ["sub"]
saml = { names = ["eduPersonPrincipalName"], oid = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", friendly_name = "eduPersonPrincipalName" }
```

The load-bearing line is `user_id_from_attrs = ["subjectid"]`. Under the REFEDS
**Personalized Access** entity category - asserted in the SWAMID registration -
IdPs release the SAML `subject-id` attribute, **not** `eduPersonPrincipalName`.
So the subject identifier is composed from `subjectid`; when it is absent the
backend falls back to a scoped `NameID`. The detailed `saml` entries carry the
OID and FriendlyName that feed the IdP frontend's `attribute_name_format = "uri"`
mode and are matched inbound by the backend.

`email_verified` is `openid`-only and is **not** released by the IdP - it is
synthesized by a micro-service (next section). The OP coerces its string value
to a JSON boolean, as RPs like Vaultwarden require. The detail of how
`email_verified` is injected and coerced belongs to the
[attribute handling chapter](attributes.md); this tutorial only wires it.

## Micro-services

Three response-path micro-services run **in the order listed** (pipeline order is
config order, the same on both request and response paths). They reshape the
internal attribute set before it reaches the frontend:

```toml
# 1. Assert email_verified=true for every flow. SWAMID IdPs release
# institutionally managed mail under REFEDS Personalized Access, so the address
# is treated as verified. OIDC RPs such as Vaultwarden block signup on a
# missing/false email_verified claim.
[[microservice]]
type = "static_attributes"
name = "StaticAttributes"
  [microservice.config.attributes]
  email_verified = ["true"]

# 2. Rewrite the scoped subject-id into a local identifier,
# "user@scope.tld" -> "user_scope". Mirrors SATOSA's RegexSubProcessor.
[[microservice]]
type = "attribute_processor"
name = "AttributeProcessor"
  [[microservice.config.process]]
  attribute = "subjectid"
    [[microservice.config.process.processors]]
    name = "regex_sub"
    match_pattern = '@([^.]+)\.(.+)'
    replace_pattern = '_$1'

# 3. Every response must carry a non-empty subjectid or authentication is
# rejected. Runs after AttributeProcessor, so the rewritten value is checked.
[[microservice]]
type = "attribute_authorization"
name = "AttributeAuthorization"
  [microservice.config]
  force_attributes_presence_on_allow = true
  [microservice.config.attribute_allow.default.platform]
  subjectid = ["."]
  [microservice.config.attribute_allow.default.default]
  subjectid = ["."]
```

The order is deliberate:

1. **`static_attributes`** injects `email_verified = "true"` (it never overwrites
   an existing value). SWAMID IdPs release institutionally managed mail under
   Personalized Access, so the address is treated as verified; OIDC RPs such as
   Vaultwarden block signup on a missing or false `email_verified` claim.
2. **`attribute_processor`** runs a `regex_sub` over `subjectid`, rewriting the
   scoped `user@scope.tld` into a local `user_scope` (here `@([^.]+)\.(.+)` ->
   `_$1`). This mirrors the production SATOSA `RegexSubProcessor`.
3. **`attribute_authorization`** runs **last**, after the rewrite, and rejects
   the whole authentication unless `subjectid` is present and non-empty (the `.`
   regex matches any character). Rules nest `requester -> provider -> attribute`;
   `default` (or `""`) is the wildcard, and a specific entry replaces - never
   merges with - the default. `force_attributes_presence_on_allow = true` makes
   a missing attribute a rejection rather than a silent pass.

For the full menu of micro-services and their nesting semantics see the
[micro-services chapter](micro-services.md) and the
[built-in plugin reference](built-in-plugins.md#micro-services).

## Endpoints

| URL | What |
| --- | --- |
| `/Saml2IDP/sso` | IdP single-sign-on endpoint (Redirect + POST) |
| `/Saml2IDP/metadata` | IdP metadata for downstream SPs |
| `/Saml2SP/metadata` | SP metadata - **register this with SWAMID** |
| `/Saml2SP/acs` | assertion consumer service |
| `/Saml2SP/disco` | SeamlessAccess discovery return endpoint |
| `/OIDC/.well-known/openid-configuration` | OIDC OP discovery document |
| `/OIDC/jwks` | OIDC OP signing keys (JWKS) |
| `/OIDC/authorization` | OIDC authorization endpoint |
| `/OIDC/token` | OIDC token endpoint |
| `/OIDC/userinfo` | OIDC userinfo endpoint |

The SP entity id is `https://proxy.example.com/`; the IdP entity id
defaults to `https://proxy.example.com/Saml2IDP`.

## SWAMID registration

Register the **SP metadata** served at `/Saml2SP/metadata` with SWAMID so
upstream IdPs trust the proxy. That metadata carries the signing and encryption
certificate, the organisation and both contact persons, and announces the
SeamlessAccess `<idpdisc:DiscoveryResponse>` endpoint (because `disco_srv` is
set). Assert the REFEDS Personalized Access entity category so IdPs release
`subject-id`.

Downstream SPs that talk to the `Saml2IDP` frontend do not need manual
registration in tunnelbana - they are resolved on demand from SWAMID MDQ,
signature-verified with `md-signer2.crt`. SPs **outside** the federation go into
`metadata/*.xml` with a matching `local = [...]` entry under
`[frontend.config.metadata]`.

## Verify it works

Once the binary is running behind its TLS proxy, smoke-test both metadata
endpoints:

```bash
curl -s https://proxy.example.com/Saml2SP/metadata | head
curl -s https://proxy.example.com/Saml2IDP/metadata | head
```

Both should return `<EntityDescriptor>` XML. The SP metadata is what you submit
to SWAMID; the IdP metadata is what downstream SPs consume. You can also fetch
the OIDC discovery document to confirm the OP frontend is live:

```bash
curl -s https://proxy.example.com/OIDC/.well-known/openid-configuration
```

A full end-to-end test then drives a real flow: point a registered SP (or the
Vaultwarden RP) at the matching frontend, pick a home organisation in
SeamlessAccess, authenticate at the upstream IdP, and confirm the assertion or
`id_token` comes back with the expected `subjectid` / `sub` and a verified email.