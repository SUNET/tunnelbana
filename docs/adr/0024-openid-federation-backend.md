# ADR 0024 - OpenID Federation backend (federation-aware RP)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` - `federation_backend.rs`
  (`FederationBackend`, backend config type `oidc_federation`).
- **Related:** the `oidc_federation` frontend (`federation_frontend.rs`),
  `grindvakt::federation` (entity statements, trust-anchor resolve, metadata
  policy).

## Context

tunnelbana could already *be* a federation OP (the `oidc_federation`
frontend serves an entity configuration and auto-registers downstream RPs
through trust chains), but it could not *join* a federation as an RP. The
plain `oidc` backend needs `.well-known` discovery or pinned endpoints plus a
pre-registered `client_id` and secret/key, none of which exist in an OpenID
Federation deployment: there, the RP's identity is its entity id, its keys
are published in its own signed entity configuration, the OP's metadata is
obtained through the trust chain, and client registration is *automatic*
(OpenID Federation 1.0 section 12.1).

This was the recorded "planned tunnelbana differentiator" in
`satosa_parity.md` section 3.4. The protocol building blocks were already in
`grindvakt::federation`: `build_entity_configuration`,
`resolve_via_trust_anchors` (delegating to a trust anchor's
`federation_resolve_endpoint` and verifying the `resolve-response+jwt`), and
entity-statement verification.

## Decision

A new backend type `oidc_federation` that mirrors the `oidc` backend's flow
mechanics but replaces every registration-era assumption with its federation
counterpart:

- **Identity.** `entity_id` (default `<base_url>/<name>`) is both the
  federation entity id and the OAuth2 `client_id` sent upstream. The backend
  serves its signed **RP entity configuration** at
  `<name>/.well-known/openid-federation`, with `openid_relying_party`
  metadata carrying `redirect_uris`, `client_registration_types:
  ["automatic"]`, `token_endpoint_auth_method: "private_key_jwt"`, the
  client-auth public `jwks`, `response_types`/`grant_types`, and `scope`,
  plus a `federation_entity` section with organization info. The publishing
  shape matches what the federation frontend's `auto_register` consumes, so
  two tunnelbana instances can attach to each other through a federation.
- **OP resolution.** The upstream OP is resolved with
  `resolve_via_trust_anchors` instead of `.well-known` discovery, and the
  result is cached per OP for `op_cache_ttl` seconds (default 3600). At least
  one `trust_anchor` (entity id + pinned JWKS) is required at build time.
- **OP selection: fixed or discovery.** The OP is chosen one of two ways,
  mutually exclusive and validated at build time:
  - **Fixed:** `op_entity_id` names a single OP used for every flow.
  - **Discovery:** `discovery.enable` + `discovery.collection_endpoint`.
    `start_auth` fetches the federation's OP list from a trust anchor's
    collection endpoint (`grindvakt::federation::fetch_collection`, filtered
    to `openid_provider`, TTL-cached for `discovery.cache_ttl`) and renders a
    self-contained OP-selection page. The user's POST to `<name>/disco`
    carries the chosen `entity_id`; the backend **validates it against the
    fetched list** (so the selection cannot make the proxy resolve arbitrary
    entity ids), then proceeds exactly as the fixed path. The chosen OP is
    persisted in the state cookie so the callback resolves the same OP. This
    mirrors SATOSA's `openid_federation_backend` discovery mode and the SAML
    backend's `disco` flow (ADR 0007); like both, the frontend's in-flight
    request rides the encrypted state cookie, so the selection round-trip
    needs no extra server state.
- **Key separation.** The federation key signs the entity configuration; an
  optional dedicated signing key handles `private_key_jwt` client
  authentication and defaults to the federation key when absent. Only the
  client-auth public keys are published in the `openid_relying_party`
  metadata; the entity configuration's top-level `jwks` carries the
  federation keys, as the spec separates them.
- **id_token verification keys.** The inline `jwks` from the resolved OP
  metadata is preferred because it arrived signed by the trust anchor;
  `jwks_uri` is only fetched when no inline keys exist. This avoids trusting
  a plain HTTPS fetch where a trust-chain-verified document is available.
- **Flow mechanics** are shared with the `oidc` backend: PKCE (S256) always,
  `state`/`nonce`/verifier in the encrypted state cookie under the backend's
  namespace, state checked before any token exchange, nonce checked during
  id_token verification, userinfo merged when the OP advertises an endpoint.
  `subject_type` is reported as `pairwise`, the common federation default.

Not built in this step, recorded for later: signed request objects on the
authorization request, explicit trust-chain building by walking
`authority_hints` (the resolve endpoint covers SUNET-style deployments), and
metadata-policy application on the RP side.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Forged OP metadata (rogue authorization or token endpoint) | OP metadata only comes from a `resolve-response+jwt` verified against the pinned trust-anchor JWKS, with a `sub` match on the OP entity id | The trust anchor is fully trusted; pin only anchors operated by the federation |
| id_token forgery | Verification keys come from the trust-chain-delivered inline `jwks` when present; issuer, audience (the RP entity id) and nonce are all enforced | The `jwks_uri` fallback trusts transport security only; OPs in federations normally publish inline keys |
| Code interception / CSRF on the callback | PKCE S256 plus the state value sealed in the encrypted cookie; state mismatch aborts before any network call | - |
| Client impersonation towards the OP | `private_key_jwt` assertions signed with a key whose public half is published in the signed entity configuration; no shared secret exists | Key compromise equals client compromise, as with any private-key client |
| Stale OP metadata after federation key/endpoint rotation | `op_cache_ttl` bounds reuse; a resolve failure surfaces as an authentication error rather than silent fallback | Within the TTL window a rotated endpoint is still used; lower the TTL where rotation is frequent |
| Discovery selection used to make the proxy resolve an arbitrary entity id | The POSTed `entity_id` must appear in the trust-anchor collection list before any resolution is attempted | A malicious entity *listed* by the trust anchor is still selectable; that trust is the federation's, the same as for the OP list itself |
| Reflected/stored injection via the OP-selection page | All entity ids, display names and logo URLs are HTML-escaped; the page is self-contained (no inline event handlers) | A hostile `logo_uri` from the collection loads as an image only |

## Consequences

**Positive**

- tunnelbana can now sit in the middle of two federations: downstream RPs
  attach via the federation frontend and the proxy itself attaches upstream
  via this backend, with no manual client registration on either side.
- Closes `satosa_parity.md` section 3.4; SATOSA itself has no equivalent, so
  this is a tunnelbana-only capability in the comparison table.

**Negative / accepted trade-offs**

- The resolve-endpoint approach delegates chain building to the trust
  anchor. Federations whose anchors do not offer
  `federation_resolve_endpoint` need the explicit chain walker before this
  backend works there.
- Discovery depends on the trust anchor exposing a collection/listing
  endpoint (an inmor/SUNET extension, not core OpenID Federation). Without
  one, use a fixed `op_entity_id`.

## References

- `crates/tunnelbana-plugins/src/federation_backend.rs` - implementation
  (fixed OP, discovery, OP-selection page)
- `crates/tunnelbana-plugins/tests/federation_rp.rs` - entity configuration,
  full resolved-OP code flow, state/nonce rejection, build validation,
  discovery selection + unlisted-OP rejection + config mutual-exclusion
- `../grindvakt/src/federation.rs` - `resolve_via_trust_anchors`,
  `fetch_collection` / `parse_collection` (OP listing),
  `build_entity_configuration`, `verify_typed`
- OpenID Federation 1.0 sections 10 (resolve endpoint) and 12.1 (automatic
  registration)
