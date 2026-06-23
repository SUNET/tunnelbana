# Changelog

## Unreleased

- All three frontends (`oidc`, `oidc_federation`, `saml2`) accept an optional
  **`backend = "<name>"`** config key that pins every flow from that frontend to
  a named backend, for deployments running more than one `[[backend]]`. The pin
  reuses the existing selection precedence - **frontend pin → `custom_routing` /
  `idp_hinting` → default backend (the first one listed)** - so a pinned frontend
  deterministically overrides backend selections from routing micro-services;
  leave it unset to let those services choose. An unknown name fails the flow at runtime
  (`UnknownModule`), the same surface as a stray `custom_routing` rule. See
  ADR 0027 and [Backend selection](docs/src/configuration.md).

- The `oidc` and `oidc_federation` frontends now support the **`refresh_token`
  grant** (grindvakt 0.4.0, RFC 6749 §6). A client registered with
  `refresh_token` in its `grant_types` receives a refresh token from the
  authorization-code exchange, and the token endpoint accepts
  `grant_type=refresh_token` to mint a fresh access token and id_token (scope
  may be narrowed, never widened). Refresh tokens are stateless and **rotated**
  on each use; a new `refresh_token_ttl` knob (default 30 days) sets the
  sliding lifetime. `refresh_token` is advertised in `grant_types_supported`.
  As before, statelessness means tokens cannot be revoked before expiry.
  Hardening that came with the grindvakt bump: every sealed token (code,
  access, refresh) now carries a verified type tag, so one kind can no longer
  be replayed as another.

- Bumped `gamlastan`/`gamlastan-mdq` to 0.5.0. The SAML assertion validator's
  signature check (check 6) no longer trusts the mere presence of a
  `<ds:Signature>` element: `ValidationParams` now carries a required
  `verified_signed_ids` listing the IDs whose XML-DSig references were
  actually cryptographically verified, and a signed assertion is accepted only
  when its ID (or its enclosing Response ID) is in that list. The `saml2`
  backend feeds in the IDs it already proved in `process_acs`: the Response ID
  when the envelope verified (Response-level XML signature or Redirect-binding
  detached signature over the whole message, both of which cover every
  contained assertion), otherwise each individually verified assertion ID
  (cleartext and decrypted alike).

- The `oidc_federation` backend now sends an RFC 9101 **signed request
  object** (grindvakt 0.3.1 `rp::signed_request_object`, signed with the
  `private_key_jwt` client key) on every authorization request, closing the
  ADR 0024 follow-up: OPs doing OpenID Federation automatic registration
  (e.g. the Shibboleth OIDC OP plugin) authenticate the RP at the
  authorization endpoint with it and resolve the RP's trust chain on the
  fly. Plain query parameters are kept alongside for OPs that ignore the
  `request` parameter; the proxy's own federation frontend verifies it
  against the auto-registered client keys as before.

- The `oidc_federation` backend's discovery mode now delegates OP selection to
  an external OpenID Federation discovery service (`discovery.service`, e.g.
  an upptackt deployment): `start_auth` redirects to the service and the new
  `<name>/initiate` endpoint accepts the OpenID Connect Core §4 third-party
  initiated login return, gated on an in-flight-flow marker in the state
  cookie and the trust-anchor resolution of `iss`. In discovery mode the RP
  entity configuration now publishes `initiate_login_uri`. The in-proxy
  OP-selection page (collection endpoint + HTML chooser) is retired but kept
  commented out in `federation_backend.rs` for reference; its
  `collection_endpoint`/`page_title`/`cache_ttl` config keys are replaced by
  `service`. (ADR 0025)

- Fixed response-path ordering in the proxy so response micro-services receive
  the restored requester and originating frontend context before policy runs.
  This makes requester-scoped `attribute_authorization` rules work in the real
  auth flow.
- Fixed `attribute_processor` `regex_sub` validation to reject missing or empty
  `match_pattern` and `replace_pattern` values at startup, matching the SATOSA
  contract instead of silently rewriting with an empty replacement.