# Changelog

## Unreleased

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