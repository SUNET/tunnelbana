# ADR 0030 - eduID SATOSA micro-services (`pairwiseid`, `static_attributes_for_virtual_idp`, `nameid`, `accr`)

- **Status:** Accepted
- **Date:** 2026-06-24
- **Component:** `tunnelbana-plugins` -
  `microservices/{pairwiseid,static_virtual_idp,nameid,accr}.rs`; the `accr`
  request/response plumbing also touches `saml2_frontend.rs`,
  `saml2_backend.rs` and `tunnelbana-core/src/context.rs`.
- **Related:** ADR 0013 (decoration framework), ADR 0021 (`hasher`).

## Context

eduID's production SATOSA deployment ships four `scimapi` micro-services that
shape the SAML virtual-IdP behavior tunnelbana lacked: a privacy-preserving
pairwise identifier, virtual-IdP-scoped static attributes, NameID value
selection, and AuthnContextClassRef (Level of Assurance) negotiation. Porting
them brings tunnelbana to parity with eduID's SAML proxy semantics.

Two of the four (`pairwiseid`, `static_attributes_for_virtual_idp`) are pure
response-path attribute shaping and map cleanly onto the existing micro-service
framework. The other two needed care:

- `nameid` overlaps with what tunnelbana's SAML frontend already does (NameID
  format negotiation + transient value generation), so only the value-selection
  half (persistent-from-`pairwise-id`, emailAddress-from-`mail`) is ported.
- `accr` is the only **request + response** service. SATOSA reads the SP's
  requested AuthnContextClassRef from a context decoration and forwards the
  chosen value to the backend via context state; tunnelbana's SAML frontend
  previously discarded the requested ACCR and the SAML backend never emitted a
  `RequestedAuthnContext`. New plumbing was required.

## Decision

Port all four, matching eduID's config shape and internal attribute names
(`subject-id`, `pairwise-id`) 1:1.

- **`pairwiseid`** (response): `pairwise-id = hex(HMAC-SHA256(pairwise_salt,
  "{requester}-{subject-id}")) + "@" + scope`, where `scope` is the part of
  `subject-id` after the last `@`. Uses `grindvakt::mac::hmac_sha256`. A
  missing `subject-id` or empty salt fails the flow / boot respectively.
- **`static_attributes_for_virtual_idp`** (response): two-level
  `(requester, virtual_idp)` lookup using the shared `level()` helper
  (exact→`""`→`"default"`); a *replace* map overwrites and an *append* map
  unions+dedups+sorts. `virtual_idp` is `ctx.target_frontend`. Registered as a
  **new** type, leaving the simpler `static_attributes` untouched.
- **`nameid`** (response): reads the resolved NameID format the SAML frontend
  now publishes under the shared base state key `KEY_NAME_ID_FORMAT`; sets
  `subject_id` from `pairwise-id` (persistent, hash part before `@`) or `mail`
  (emailAddress), and marks the subject type transient for transient/unspecified
  (the frontend mints the opaque value). Absent format (e.g. OIDC) = pass through.
- **`accr`** (request + response): the SAML frontend publishes the SP's
  requested ACCR list + comparison as the `KEY_REQUESTED_ACCR` /
  `KEY_REQUESTED_ACCR_COMPARISON` decorations; the service filters them to the
  supported set, enforces a per-`virtual_idp` minimum range, applies an optional
  rewrite for the upstream IdP, and forwards the result as the
  `KEY_TARGET_AUTHN_CONTEXT_CLASS_REF` / `KEY_TARGET_ACCR_COMPARISON`
  decorations (**first writer wins**, mirroring `KEY_TARGET_ENTITYID`). The SAML
  backend reads those into `AuthnRequestOptions` (gamlastan already builds the
  `RequestedAuthnContext`). On the response path it reverses the rewrite and, if
  the IdP returned an unrequested value, falls back to the highest-priority
  requested value. Deliberate divergence kept for parity: when the minimum is
  enforced, the rewrite map is *not* applied to the forced range (matches eduID).

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Cross-SP user correlation via a shared identifier | `pairwiseid` HMACs the requester into the value, so each SP gets a distinct, non-reversible id | Salt compromise lets an attacker recompute ids for a known `(sp, subject-id)`; treat `pairwise_salt` as a secret |
| LoA downgrade (IdP asserts weaker than required) | `accr` enforces a per-`virtual_idp` minimum range on the request path and validates the returned ACCR on the response path, falling back to the highest requested value | tunnelbana does not (yet) *reject* a too-weak response, matching eduID's lenient fallback; operators wanting hard rejection must add an `attribute_authorization`-style gate |
| Third-party-initiated ACCR injection | The requested ACCR is taken only from the validated AuthnRequest the SAML frontend parsed; the forward decoration is first-writer-wins | An earlier request-path service may pin the forwarded ACCR; order config intentionally |
| Static-attribute spoofing of assurance/affiliation | `static_attributes_for_virtual_idp` values come only from operator config, keyed by validated requester + frontend | Operator config errors release wrong values; covered by config review |

## Consequences

**Positive**

- eduID `scimapi` configs port across with the same keys and internal attribute
  names; SAML virtual-IdP deployments reach parity.
- The new ACCR decoration contract is reusable by any future request-path
  service that needs to influence the outgoing `RequestedAuthnContext`.

**Negative / accepted trade-offs**

- `accr` is lenient on a too-weak IdP response (fallback, not rejection), an
  intentional eduID-faithful choice; hard enforcement is a separate decision.
- The minimum-enforced ACCR range bypasses the rewrite map (eduID parity), a
  latent surprise documented in code and here.
- `nameid` depends on the SAML frontend publishing the resolved format; on an
  OIDC frontend the service is a no-op by design.

## References

- `crates/tunnelbana-plugins/src/microservices/{pairwiseid,static_virtual_idp,nameid,accr}.rs`
  - implementations + unit tests.
- `crates/tunnelbana-plugins/tests/accr_flow.rs` - frontend→`accr` request-path
  integration test.
- `crates/tunnelbana-core/src/context.rs` - `KEY_NAME_ID_FORMAT`,
  `KEY_REQUESTED_ACCR`, `KEY_REQUESTED_ACCR_COMPARISON`,
  `KEY_TARGET_AUTHN_CONTEXT_CLASS_REF`, `KEY_TARGET_ACCR_COMPARISON`.
- `https://github.com/SUNET/eduid-backend/src/eduid/satosa/scimapi/{pairwiseid,static_attributes,nameid,accr}.py`
  - ported behavior.
