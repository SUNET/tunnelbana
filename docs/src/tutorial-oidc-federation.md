# Tutorial: SAML IdP over an OpenID Federation RP backend with discovery

This is an end-to-end walk-through of a real deployment: tunnelbana fronting a
downstream SAML Service Provider as a **SAML2 Identity Provider**, while
upstream it authenticates against an **OpenID Provider chosen at runtime** by an
external OpenID Federation discovery service. It is modelled on a working lab
proxy; the hostnames below (`proxy.example.com`, `sp.example.org`,
`ta.example.com`, `discovery.example.com`, `op.example.org`) are placeholders -
substitute your own federation's entity ids and service URLs.

Two protocols meet inside one process and stay mutually oblivious: the SAML IdP
frontend (`Saml2IDP`) only ever speaks SAML to the SP, and the OpenID Federation
RP backend (`OIDFedRP`, type `oidc_federation`) only ever speaks OIDC +
federation upstream. They exchange nothing but the proxy's internal attribute
set. For the authoritative per-knob reference of each plugin, see
[Built-in plugin reference](built-in-plugins.md); this chapter shows how the
pieces fit together.

## What we build

```text
                          proxy.example.com (this proxy)
                       ┌──────────────────────────────────────┐
  SAML SP             │  SAML2 IdP frontend   OIDFed RP backend │   discovery       chosen OP
sp.example.org...        │      Saml2IDP   ───►      OIDFedRP    ──┼──►  upptackt  ───►  op.example.org...
  (django-allauth)    │   (faces the SP)     (faces an OP)      │  (picks an OP)   (federation OP)
                       └──────────────────────────────────────┘
        │                       ▲                  │                    │              ▲
        │  1. AuthnRequest      │                  │ 2. start_auth      │              │
        └───────────────────────┘                  └────────────────────┘              │
                                                          302 to upptackt with         │
                                                          entity_id + one-time         │
                                                          target_link_uri              │
                                                                                       │
        user picks an OP at upptackt ──► return to /OIDFedRP/initiate?iss=<op> ─────────┘
```

The SP sends an AuthnRequest to `Saml2IDP`. tunnelbana has no upstream OP pinned,
so it hands the per-flow OP choice to the **upptackt** discovery service
(<https://github.com/SUNET/upptackt>). The user picks their home organization
there; upptackt returns the chosen OP's entity id to `OIDFedRP`, the RP runs the
OIDC code flow against it, and the resulting claims are mapped back into a signed
SAML assertion for the SP.

## Background: OpenID Federation automatic registration

The `oidc_federation` backend is an OpenID Federation 1.1 Relying Party doing
**automatic registration** (OpenID Federation 1.1 section 12.1, ADR 0024). There
is no pre-registered client and no `.well-known/openid-configuration` discovery:

- The RP publishes its own **signed entity configuration** at
  `<entity_id>/.well-known/openid-federation`, carrying its `authority_hints`,
  `redirect_uris`, `client_registration_types = ["automatic"]`,
  `token_endpoint_auth_method = "private_key_jwt"`, and its client-auth public
  `jwks`.
- The upstream OP resolves that RP through the federation (the shared trust
  anchor) and accepts it on the fly.
- The RP authenticates with **`private_key_jwt`** using its **entity id as the
  `client_id`** - no client secret is ever shared.

The full RP flow, the published entity-configuration shape, and the trust-anchor
resolution are documented in
[the `oidc_federation` backend reference](built-in-plugins.md#oidc_federation-backend---federation-relying-party).
This chapter does not contradict it - it instantiates it for one deployment.

## Prerequisites

Automatic registration only works if everyone trusts the same federation:

- **The RP must be a registered leaf** under a trust anchor. Its
  `authority_hints` (here `https://ta.example.com`) must name an authority
  that issues a subordinate statement for this RP, and the RP's federation public
  key must already be on file with that authority. In this lab the RP reuses the
  SATOSA federation key whose public half the realta (inmor) trust anchor holds.
- **The discovery service (upptackt) must be able to resolve this RP** through
  the federation. It reads the RP's entity configuration - in particular the
  `initiate_login_uri` the backend publishes in discovery mode - to verify the RP
  before it will return a chosen OP to it.
- **The chosen OP must itself resolve** through one of the RP's configured trust
  anchors, or the flow is rejected at `/initiate`.

## Top-level config

```toml
base_url             = "https://proxy.example.com"
state_encryption_key = "${TUNNELBANA_STATE_KEY}"
cookie_name          = "TUNNELBANA_STATE"
cookie_secure        = true
attributes           = "config/attributes.toml"

[logging]
level  = "info,tunnelbana=debug"
format = "json"
```

The discovery round-trip is a **top-level cross-site navigation**: the browser
leaves the proxy for upptackt and comes back. The encrypted state cookie must
survive that hop, which is why `cookie_same_site` is left at its default `None`
(see [Configuration](configuration.md#top-level-keys)). The cookie carries the
per-flow secrets (PKCE verifier, OIDC `state`/`nonce`, and the one-time
discovery verifier); read [Security: the state cookie](security-state-cookie.md)
before tuning these in production.

## The SAML2 IdP frontend

```toml
[[frontend]]
type = "saml2"
name = "Saml2IDP"
  [frontend.config]
  # Stable entity id the SP pins. Because it lives under the module base, the
  # metadata document is also served at this exact URL (the
  # …/Saml2IDP/proxy.xml convention - SATOSA's entityid_endpoint).
  idp_entity_id = "https://proxy.example.com/Saml2IDP/proxy.xml"
  # Reused keys: the SP pins this certificate in its settings.
  idp_key_path  = "keys/saml_frontend.key"
  idp_cert_path = "keys/saml_frontend.crt"
  # Advertised NameID formats, in preference order. The first entry is the
  # default when the SP states no NameIDPolicy (and answers the SAML 1.1
  # "unspecified" request this SP sends).
  name_id_formats = [
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
  ]
  # The SP's attribute_mapping reads OID-named attributes, so emit OID names +
  # FriendlyName (SWAMID-style) rather than plain names.
  attribute_name_format = "uri"

  # REQUIRED: registered SP metadata. The frontend refuses to start without a
  # metadata source and 403s unknown SPs, validating the ACS against the SP's
  # registered AssertionConsumerService. Fetched at deploy time from
  # https://sp.example.org/accounts/saml/sunet/metadata/.
  [frontend.config.metadata]
  local = ["config/metadata/samlsp.xml"]

  [frontend.config.organization]
  name         = "tunnelbana SP proxy"
  display_name = "tunnelbana SP proxy"
  url          = "https://proxy.example.com"
```

The `proxy.xml` convention matters: when `idp_entity_id` is itself a URL under
the module base, the metadata is additionally served at that path, so the SP can
both **pin** the entity id and **fetch** the metadata from the same URL. The IdP
also serves `…/Saml2IDP/sso` (Redirect + POST) and `…/Saml2IDP/metadata`. The
mandatory `[frontend.config.metadata]` store is what makes the IdP safe: only
registered SPs are answered, and assertions are only delivered to a registered
ACS (see the security note in the
[`saml2` frontend reference](built-in-plugins.md#saml2-frontend---identity-provider)).

## The OpenID Federation RP backend

```toml
[[backend]]
type = "oidc_federation"
name = "OIDFedRP"
  [backend.config]
  # This RP's federation entity id, and the client_id it sends upstream. The
  # entity configuration must be reachable at
  # <entity_id>/.well-known/openid-federation (see the reverse-proxy section).
  entity_id = "https://proxy.example.com"
  scope     = "openid email profile"

  # OP discovery via upptackt (ADR 0025). Mutually exclusive with op_entity_id:
  # set exactly one. start_auth redirects the browser here; the service verifies
  # this RP through the federation and returns the chosen OP to
  # /OIDFedRP/initiate as a Third-Party Initiated Login.
  [backend.config.discovery]
  enable  = true
  service = "https://discovery.example.com"

  [backend.config.federation]
  # Federation signing key: signs the RP entity configuration AND (by default)
  # signs the private_key_jwt client assertion. Its public half is on file at
  # the trust anchor.
  signing_key_path  = "keys/rp_federation_ec.key"
  signing_algorithm = "ES256"
  signing_key_id    = "rp-fed-key-1"
  authority_hints   = ["https://ta.example.com"]
  organization_name = "tunnelbana SP proxy"
  entity_configuration_lifetime = 3600   # seconds
  op_cache_ttl                  = 600    # resolved OP metadata cache, seconds

  # Trust anchor: the realta (inmor) TA. The keys are PINNED from the TA's live
  # JWKS at deploy time - tunnelbana never auto-fetches anchor keys, it trusts
  # exactly these. (The long RSA modulus is abbreviated here with n = "...".)
  [[backend.config.federation.trust_anchor]]
  entity_id = "https://ta.example.com"
  keys = [
    { kty = "RSA", alg = "RS256", use = "sig", kid = "NbZ2P_LHOpbtEoWQ3ukPR_pnii3Yi8hE7j4ghZaGLOI", e = "AQAB", n = "..." },  # pinned from the TA's JWKS
    { kty = "RSA", alg = "RS256", use = "sig", kid = "jx4OZapVWSZAbLJGt7hFfI-khthAXwgFac7P9HQ3A60", e = "AQAB", n = "..." },  # pinned from the TA's JWKS
  ]
```

> The trust-anchor `keys` are the **root of trust** for the whole upstream flow:
> every resolved OP metadata and every subordinate statement is ultimately
> verified back to these pinned keys. The full deployment config carries the real
> RSA `n` values (the live JWKS of `https://ta.example.com`); rotate them
> here when the TA rolls its signing keys.

`op_entity_id` and `discovery.enable` are mutually exclusive and validated at
startup; with discovery on, the `op_entity_id` line is omitted and the
`/OIDFedRP/initiate` route is registered. At least one `trust_anchor` is required
to boot.

## How a discovery-driven flow works

Step by step, mirroring the
[OP discovery reference](built-in-plugins.md#op-discovery) (ADR 0025):

1. **`start_auth`** has no fixed OP, so instead of resolving one it 302s the
   browser to
   `https://discovery.example.com?entity_id=https://proxy.example.com&target_link_uri=…`.
   The `target_link_uri` is a **one-time return-path verifier**:
   `…/OIDFedRP/initiate?tb_discovery_verifier=<random token>`, and the same token
   is stored in the encrypted state cookie. (If a request-path micro-service such
   as `idp_hinting` pinned a target, it rides along as `hint`; an invalid hint is
   dropped, not fatal.)
2. **upptackt verifies the RP** through the federation - it resolves this RP's
   entity configuration, where the backend publishes
   `initiate_login_uri = …/OIDFedRP/initiate` in discovery mode - then lets the
   user search for and pick their home OP. It sends the user back to
   `…/OIDFedRP/initiate?iss=<chosen-op>&target_link_uri=<echoed verbatim>`, an
   OpenID Connect Core section 4 Third-Party Initiated Login.
3. **`initiate`** accepts the return only when a discovery flow is actually in
   flight (the verifier is in the state cookie from step 1) **and** the echoed
   `target_link_uri` exactly matches the verifier URL it emitted - binding this
   return to that specific outgoing redirect (anti-CSRF / anti-replay; the
   verifier is cleared after use). It validates `iss` as an https entity id, the
   chosen **OP must resolve through the configured trust anchors**, and the OP is
   sealed in the state cookie so the callback resolves the very same OP.
4. The RP then runs the normal automatic-registration code flow: redirect to the
   resolved `authorization_endpoint` with `client_id = <entity_id>`, PKCE (S256),
   and a signed request object; the **callback** (`…/OIDFedRP/callback`) exchanges
   the code with a `private_key_jwt` assertion and verifies the id_token against
   the OP keys from the resolved metadata.

> Security note: `target_link_uri` is **never** used as a redirect target - it is
> only ever compared against the stored verifier. The proxy's continuation always
> rides the encrypted state cookie, never a caller-supplied URL. Do not weaken
> this to a plain "discovery in flight" boolean. See
> [Security: the state cookie](security-state-cookie.md) and the
> [OP discovery reference](built-in-plugins.md#op-discovery).

## Reverse-proxy rewrites

The federation entity id is the **bare host** `https://proxy.example.com`,
but tunnelbana mounts the RP's routes under `/OIDFedRP/`. The fronting reverse
proxy (Caddy here, terminating TLS) must therefore rewrite the bare well-known
path to the module route so the published entity id resolves:

```text
proxy.example.com {
    rewrite /.well-known/openid-federation /OIDFedRP/.well-known/openid-federation
    rewrite /OIDFedRP/Saml2IDP/sso/redirect /Saml2IDP/sso
    rewrite /OIDFedRP/Saml2IDP/sso/post     /Saml2IDP/sso
    reverse_proxy localhost:9003
}
```

- The **federation well-known** rewrite is required: an OpenID Federation entity
  whose `entity_id` is the bare host must serve its entity configuration at
  `<bare-host>/.well-known/openid-federation`, while tunnelbana serves it at
  `…/OIDFedRP/.well-known/openid-federation`. This is the standard reverse-proxy
  note from [Configuration](configuration.md#mount-points).
- The two **legacy SSO rewrites** exist only because this SP pins SATOSA's old
  URL scheme `<backend>/<frontend>/sso/<binding>`. tunnelbana serves a single
  `/Saml2IDP/sso` for both bindings, so the legacy paths are rewritten onto it.
  A greenfield SP would point straight at `/Saml2IDP/sso` and need neither.

## Attribute map

The two protocols only exchange the proxy's internal attribute set, so the
attribute map translates **OIDC claims coming in** (from the federation OP) into
**OID-named SAML attributes going out** (the SP's django-allauth
`attribute_mapping` reads `urn:oid:*` names, which is also why the frontend sets
`attribute_name_format = "uri"`).

```toml
user_id_from_attrs = ["edupersonprincipalname"]

[attributes.mail]
openid = ["email"]
saml   = { names = ["mail", "email", "emailAddress"], oid = "urn:oid:0.9.2342.19200300.100.1.3", friendly_name = "mail" }

[attributes.edupersonprincipalname]
openid = ["sub"]
saml   = { names = ["eduPersonPrincipalName"], oid = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", friendly_name = "eduPersonPrincipalName" }

# …givenname, surname, name, displayname, uid follow the same shape.
```

`user_id_from_attrs = ["edupersonprincipalname"]` selects which internal
attribute composes the SAML subject id - here the OP's `sub` claim, mapped to
`edupersonprincipalname`. For the full map syntax, the `openid`/`saml` profiles,
and value transforms, see
[the attribute map](configuration.md#the-attribute-map).

## Verify it works

Once the binary is running behind the reverse proxy, two unauthenticated GETs
confirm both faces are live:

```bash
# RP entity configuration (a signed JWT - confirms the bare-host rewrite works):
curl -s https://proxy.example.com/.well-known/openid-federation | cut -c1-40

# SAML IdP metadata served at the pinned proxy.xml entity id:
curl -s https://proxy.example.com/Saml2IDP/proxy.xml | head -5
```

The first should return the opening of a compact JWS (the RP entity
configuration); decode it and check `authority_hints`, `metadata.federation_entity`,
and the `client_registration_types = ["automatic"]` /
`token_endpoint_auth_method = "private_key_jwt"` openid_relying_party metadata.
The second should return the IdP `EntityDescriptor`. Then drive a real browser
login from `https://sp.example.org`: you should be bounced to upptackt,
pick an OP, and land back authenticated.
