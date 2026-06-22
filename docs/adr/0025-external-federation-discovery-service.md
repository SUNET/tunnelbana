# ADR 0025 - External discovery service for the OpenID Federation backend

- **Status:** Accepted
- **Date:** 2026-06-11
- **Component:** `tunnelbana-plugins` - `federation_backend.rs`
  (`FederationBackend`, backend config type `oidc_federation`, discovery
  mode).
- **Related:** ADR 0024 (OpenID Federation backend; this ADR replaces its
  in-proxy discovery mode), `grindvakt::discovery` (home-organization
  discovery helpers), the upptackt discovery service
  (`../upptackt`, deployed at `https://upptackt.labb.sunet.se`).

## Context

ADR 0024 gave the `oidc_federation` backend a discovery mode that rendered an
OP-selection page **inside the proxy**: `start_auth` fetched a trust anchor's
collection endpoint and served a self-contained HTML chooser, and the user's
choice was POSTed back to `<name>/disco`.

Meanwhile the home-organization discovery problem grew its own standalone
service: **upptackt**, built on `grindvakt::discovery`, with RP verification,
search-as-you-type over the federation's OP collection, a remembered-choice
cookie, and its own ADR trail. Running a second, feature-poorer chooser inside
every proxy duplicates that work, bakes UI into an identity component, and
gives federation operators no single place to brand or improve the selection
experience. The SUNET lab now operates an upptackt instance, so the proxy can
delegate.

The wire protocol is already specified: the RP redirects the browser to the
discovery service with its `entity_id` (plus an optional OP `hint`); the
service verifies the RP through the federation, lets the user pick an OP, and
returns the user to the RP's published `initiate_login_uri` as an OpenID
Connect Core 1.0 §4 **Third-Party Initiated Login** carrying the chosen OP in
`iss`. Both ends of that exchange exist in `grindvakt::discovery`
(`discovery_request_url`, `parse_third_party_initiated_login`) since 0.2.0.

## Decision

Discovery mode now delegates to an **external discovery service**; the
in-proxy chooser is **commented out, not deleted** (marked "In-proxy
discovery" in `federation_backend.rs`) so deployments that need a built-in
chooser can restore it.

- **Config.** `[backend.config.discovery]` keeps `enable` and gains the
  required `service` key - the discovery service's endpoint URL. The old
  `collection_endpoint` / `page_title` / `cache_ttl` keys are retired with
  the in-proxy code. `op_entity_id` and `discovery.enable` stay mutually
  exclusive; `service` is validated at build time (fail fast on an
  unparseable URL or a non-https RP entity id).
- **Outgoing call.** `start_auth` mints a random one-time verifier, stores
  it in the backend's state-cookie namespace (`disco_verifier`, doubling as
  the flow-in-flight marker) and 302s to
  `<service>?entity_id=<rp_entity_id>&target_link_uri=<initiate>?tb_discovery_verifier=<verifier>`.
  The spec'd verbatim round-trip of `target_link_uri` is repurposed as a
  return-path verifier; the in-flight frontend request itself still rides
  the encrypted state cookie (ADR 0007), so nothing else needs returning.
  If a request-path micro-service pinned an upstream via the
  `KEY_TARGET_ENTITYID` decoration (ADR 0013, e.g. `idp_hinting`), it is
  forwarded as `hint`; an invalid hint is dropped with a warning rather
  than failing the flow.
- **Return call.** A new `<name>/initiate` route (registered only in
  discovery mode) receives the third-party initiated login. It requires the
  stored `disco_verifier` - an unsolicited initiate has no frontend request
  to answer and is rejected with an authentication error - and the echoed
  `target_link_uri` must exactly match the verifier URL from the outgoing
  call, binding the return to that specific discovery redirect
  (anti-CSRF/anti-replay; the verifier is cleared after use). It then
  parses and validates `iss` (https entity id, no query/fragment) and
  proceeds exactly as the fixed-OP path: resolve `iss` through the
  configured trust anchors, mint PKCE/state/nonce into the state cookie,
  redirect to the OP. The `target_link_uri` is only ever compared against
  the expected value; it is never used as a redirect target.
- **Metadata.** In discovery mode the RP entity configuration's
  `openid_relying_party` metadata additionally publishes
  `initiate_login_uri = <module_base>/initiate`, which is where a verifying
  discovery service learns the return endpoint (it must be https; upptackt
  refuses anything else).

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Discovery return steers the proxy to an arbitrary issuer | `iss` is only used after `resolve_via_trust_anchors` succeeds against the pinned anchor JWKS - exactly the gate the fixed-OP path uses | An OP the trust anchor vouches for is usable, as before; that trust is the federation's |
| Unsolicited third-party initiated login (login CSRF into the proxy) | `<name>/initiate` requires the one-time `disco_verifier` set by `start_auth` in the encrypted, MACed state cookie, and the echoed `target_link_uri` must match the verifier URL from the outgoing redirect (cleared after use) | A return forged *during* a flow would also need the unguessable verifier; remaining exposure is the discovery service itself choosing the (federation-trusted) OP |
| Open-redirect via `target_link_uri` | The parameter is validated by exact comparison against the verifier URL the proxy itself emitted and is never used as a redirect target; the proxy's continuation lives in the state cookie | - |
| Malicious `iss` syntax (scheme smuggling, query injection) | `parse_third_party_initiated_login` requires a valid https URL without query or fragment before any network activity | - |
| Rogue discovery service (operator-config trust) | `discovery.service` is operator configuration, like a trust anchor; the service only ever learns the RP entity id and hint, and its returned OP still must resolve through the pinned anchors | A hostile *configured* service can pick which (federation-trusted) OP users log in at; choose the service like you choose anchors |
| Hint parameter leaks routing decisions to the service | Only the `KEY_TARGET_ENTITYID` decoration (operator-authored micro-service output) is forwarded, never arbitrary request data | - |

## Consequences

**Positive**

- One discovery UI per federation (search, branding, remembered choice,
  RP verification) instead of one embedded chooser per proxy; the proxy
  sheds HTML rendering and the OP-list cache.
- The proxy now interoperates with any discovery service speaking the
  upptackt/grindvakt flow, and conversely upptackt serves any RP - the lab
  exercises both sides end to end.
- The state-cookie design carries over unchanged: the selection round-trip
  still needs no server-side session.

**Negative / accepted trade-offs**

- Login acquires a third-party dependency: if the discovery service is down,
  discovery-mode flows fail at the redirect (fixed-OP deployments are
  unaffected). The in-proxy chooser remains available in comments for
  operators who cannot accept that.
- This diverges from SATOSA's `openid_federation_backend`, which renders its
  own selection page; recorded here as deliberate.
- The commented-out code is dead weight until someone revives it; it is kept
  because the user-facing chooser is genuinely useful for self-contained
  deployments and small to re-enable.

## References

- `crates/tunnelbana-plugins/src/federation_backend.rs` - implementation
  (`handle_initiate`, discovery redirect, commented in-proxy chooser)
- `crates/tunnelbana-plugins/tests/federation_rp.rs` - service redirect +
  initiate full flow, unsolicited/missing/untrusted `iss` rejection, hint
  forwarding and bad-hint drop, `initiate_login_uri` publication, config
  validation
- `../grindvakt/src/discovery.rs` - `discovery_request_url`,
  `parse_third_party_initiated_login`, `validate_entity_id`
- `../upptackt` - the discovery service (its `docs/adr` covers RP
  verification and open-redirect prevention on the service side)
- OpenID Connect Core 1.0 §4 (Third-Party Initiated Login)
