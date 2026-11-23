# Upgrading from 0.5.1

The changes below are on main for the unreleased 0.6.0 version. They do not
require enabling Python sessions or replacing the standard binary with a
custom application. Review identifier mappings before replacing your deployed
configuration.

## Default attributes and account identifiers

The bundled `config/attributes.toml` now uses:

```toml
user_id_from_attrs = ["subject-id"]

[attributes.subject-id]
openid = ["sub"]
saml = { names = ["subject-id"], oid = "urn:oasis:names:tc:SAML:attribute:subject-id", friendly_name = "subject-id" }

[attributes.edupersonprincipalname]
saml = { names = ["eduPersonPrincipalName"], oid = "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", friendly_name = "eduPersonPrincipalName" }
```

Previously the bundled map composed identifiers from `edupersonprincipalname`
and mapped that attribute to OpenID `sub`. The new map also contains a larger
SWAMID-oriented vocabulary, including `pairwise-id`, assurance certification,
eduPerson, norEdu, SCHAC and directory attributes. It no longer includes a
default `eduPersonTargetedID` mapping. Explicit legacy mappings and the
[`legacy_eptid` service](legacy-identifiers.md) remain available.

Custom attribute files are not automatically rewritten. If you copy the new
bundled map into a deployment, first compare identifiers and released attributes
for representative accounts and relying parties. The MDQ SAML backend prefers
attribute composition; the OIDC frontends prefer an explicit response
`subject_id` and compose only as a fallback. Consequently this map change can
change identifiers, but does not replace every backend-provided subject.
Preserve the old mapping until affected applications can migrate stored account
links, and review attribute-release restrictions when enabling new mappings.
See [Attributes and transforms](attributes.md).

## Saved browser logins are opt-in

The standard binary still authenticates upstream unless a configured
micro-service implements the new `try_authenticate` hook and the selected
backend accepts its result. There is no bundled saved-login implementation,
automatic domain-wide cookie, or new session-store TOML setting.

A Python plugin can read `context["cookies"]`, append raw `Set-Cookie` values
to `context["set_cookies"]`, and return a complete verified upstream identity
from `try_authenticate`. Store the identity before response transformations:
the current response policy and identifier transformations run again on reuse.
The current requester replaces the saved requester's identity.

The plugin must authenticate its session token, enforce expiry and logout,
protect stored identity data, and choose cookie scope and attributes. Native
SAML acceptance checks the selected issuer and reloads trusted metadata; it
declines linked-account step-up and nonempty target authentication context
requirements.
OIDC and federation backends do not opt into reuse. Forced authentication
skips the hooks entirely. See the [saved-login contract](python-microservices.md#reusing-a-saved-login).

## Authentication time and freshness

The proxy now keeps the original SAML `AuthnInstant` or signed OIDC `auth_time`
instead of substituting callback time. Known times are used for downstream
SAML `AuthnInstant` and OIDC `auth_time`; issuance time (`IssueInstant` / `iat`)
still describes the newly issued document. SAML responses also include the
upstream issuer in `AuthenticatingAuthority` when one is available.

Missing upstream OIDC `auth_time` remains unknown internally. Downstream
serializers retain their current-time fallback for missing timestamps, so a
custom session plugin must not treat a missing time as evidence of a fresh
login. Preserve known timestamps in saved identities.

Both OIDC frontends require `max_age` to be a non-negative integer. Any supplied
value conservatively forces a new authentication rather than accepting a
cached login based on its age. `prompt=none` together with `max_age` returns
`login_required`; `prompt=login` also bypasses saved-login hooks. This may cause
more upstream authentication than an application that expects age-based cache
reuse. Upstream backends can reject constraints they cannot honor.

## Replica deployment and replay protection

Keep these kinds of state separate:

| State | Standard binary | New embedding option |
| --- | --- | --- |
| In-flight login state | Authenticated encrypted browser cookie | Unchanged |
| Saved browser login | No default implementation | Trusted micro-service owns it |
| OIDC token-use records | Process-local in-memory store | Ordinary OIDC frontend can receive a shared atomic `TokenUseStore` |

Running the standard binary on multiple replicas does not gain shared replay
protection from this upgrade. Rust embedders can use
`OidcFrontend::build_with_token_use_store` for single-use authorization codes,
rotated refresh tokens and private-key client assertions across replicas.
There is no built-in database adapter selection in TOML. Federation OP replay
storage, DPoP proof caches and SAML assertion caches are separate; injecting
this store does not make them shared. Sticky sessions do not prevent a replay
sent to another replica. See [injecting a token-use store](writing-a-plugin.md#injecting-an-oidc-token-use-store).

## Building and packaging

Use Rust 1.89 or newer. The embedded interpreter still targets system CPython
3.13; existing Python plugin configuration remains valid. PyO3 is pinned to
0.30.1. Pythonize 0.29 is included under `vendor/pythonize` with its PyO3
requirements updated; its conversion implementation is unchanged. Include
that directory in source packages and Docker build contexts. The provided
Dockerfile already copies it. Arbitrary-precision JSON conversion preserves
numbers across the Python boundary, while the existing field/type validation
continues to apply.

Tera stays on 1.20.1 to retain deployed template syntax. The dependency update
removes the older affected RSA and crypto-bigint versions; Actix still requires
the h2 0.3 line affected by RUSTSEC-2026-0258. For exact versions and verification,
see the [dependency notes in the repository](https://github.com/SUNET/tunnelbana/blob/main/docs/ecosystem.md).

## Custom Rust integrations

Existing `Backend` and `MicroService` implementations inherit default refusal
of saved-login reuse, so adding the new hooks does not require enabling them.
If you construct `Context` with a struct literal, add the new `set_cookies`
queue; `Context::new` initializes it for you.

Custom `HttpClient` adapters must populate the updated `HttpFetchResponse`
`headers` field as well as status, content type and bounded body bytes. The
header list uses lowercase names and preserves repeated headers. The provided
Reqwest adapter now preserves response headers. Keep the existing
redirect refusal, response-size and timeout controls in custom adapters.
For test-only synthetic responses where no headers are available,
`headers: Vec::new()` represents an empty header list.

The [plugin guide](writing-a-plugin.md) includes the new hooks, token-use-store
constructor and asynchronous subject-resolver API with authentication time.
