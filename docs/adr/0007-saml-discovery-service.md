# ADR 0007 — Identity-provider discovery service flow in the SAML2 backend

- **Status:** Accepted
- **Date:** 2026-06-09
- **Component:** `tunnelbana-plugins` — `saml2_backend.rs` (`disco_srv`,
  `disco_redirect`, `build_authn_redirect`, the `disco` route,
  `build_metadata` extensions).
- **Related:** [ADR 0005 — MDQ dynamic IdP](0005-saml-mdq-dynamic-idp.md)
  (this completes the follow-up it left open);
  [ADR 0001 — encrypted state cookie](0001-state-cookie-encryption.md)
  (carries the flow across the hop).

## Context

ADR 0005 made the target IdP selectable per request (`?entityID=`), but the
entityID still had to *arrive on* the request. In a SeamlessAccess-style
federation deployment the user picks their IdP at a central **discovery
service**: the SP redirects there with its own entityID and a `return` URL,
and the service sends the user back with the chosen IdP as a query parameter
(OASIS Identity Provider Discovery Service Protocol and Profile).

## Decision

- **Config.** `disco_srv: Option<String>` on the backend, MDQ mode only —
  rejected at build time without an `[mdq]` section, because static mode pins
  one IdP cert and cannot verify arbitrary discovery choices.
  `idp_entity_id` becomes optional: MDQ mode requires `idp_entity_id` and/or
  `disco_srv`; static mode still requires `idp_entity_id`.
- **Flow.** `start_auth` precedence in MDQ mode: request `entityID` parameter
  → configured `idp_entity_id` default → redirect to
  `{disco_srv}?entityID={sp_entity_id}&return={module_base}/disco`.
  The new `<name>/disco` route requires a non-empty `entityID` query parameter
  and runs the same `build_authn_redirect` path as a direct selection.
- **No new state.** The proxy seals the originating frontend and in-flight
  request into the encrypted state cookie *before* `start_auth`, so the
  discovery round-trip rides the existing cookie; the disco return only adds
  the chosen `idp_entity_id` and the AuthnRequest id. Verified end-to-end by
  `tests/saml_disco.rs` (real `Proxy`, cookie replay through the hop, ACS
  completion).
- **Metadata.** With `disco_srv` set, SP metadata publishes
  `<idpdisc:DiscoveryResponse Binding="…:idp-discovery-protocol" index="0"
  Location="{module_base}/disco"/>` in the SPSSODescriptor's `<Extensions>`
  (via gamlastan's `swedenconnect::metadata::{extensions,
  discovery_response_xml}` helpers, which are protocol-generic).

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Malicious `entityID` injected at the disco return | The entityID is only ever resolved **through** the signature-verified MDQ source (`require_role = idp`); unknown entities fail | Bounded by federation MDQ contents (same as ADR 0005) |
| Disco return forged without a prior flow | The state cookie must already carry the frontend flow; a cookie-less return cannot complete | — |
| Open-redirect via `return` parameter abuse | `return` is fixed to `{module_base}/disco`, never derived from request input | Discovery services should also whitelist return URLs against the published `DiscoveryResponse` |
| Cookie loss on the cross-site hop | Discovery is a top-level navigation; the state cookie must be sent on the return | Cookie `SameSite` must permit top-level cross-site navigation (`Lax` works for GET returns; see `config/proxy.toml` note) |

## Consequences

**Positive**

- The SeamlessAccess flow works end-to-end with no server-side session store
  and no new state: frontend → disco → IdP → ACS → frontend.
- A default IdP and discovery can coexist (default wins when configured;
  operators choose one).

**Negative / accepted trade-offs**

- `returnIDParam` is not emitted (the protocol default `entityID` is used);
  add the knob if a discovery service ever needs a custom name.
- Static mode deliberately cannot use discovery.

## References

- `crates/tunnelbana-plugins/src/saml2_backend.rs` — `disco_redirect`,
  `build_authn_redirect`, route `disco`
- `crates/tunnelbana-plugins/tests/saml_disco.rs` — full proxy-level flow with
  an in-test MDQ server
- OASIS sstc-saml-idp-discovery (Identity Provider Discovery Service Protocol)
