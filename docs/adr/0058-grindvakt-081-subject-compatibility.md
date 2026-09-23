# ADR 0058 - Grindvakt 0.8.1 and OIDC subject compatibility

- **Status:** Accepted
- **Date:** 2026-09-23
- **Component:** `tunnelbana-oidc`, `tunnelbana-plugins` OIDC and federation frontends
- **Related:** [ADR 0026](0026-oidc-refresh-token-grant.md),
  [ADR 0032](0032-legacy-identifier-compatibility.md),
  [ADR 0035](0035-pairwiseid-injective-hmac-framing.md),
  [ADR 0038](0038-per-frontend-token-sealing-keys.md)

## Context

Tunnelbana delegates OIDC protocol processing to Grindvakt and subject selection
to its configured backend and response micro-service pipeline. Existing RPs use
`iss` and `sub` as account keys. Changing hashing, salt, framing, attribute
precedence, or frontend identity during an upgrade can create new accounts.

Grindvakt 0.8.0 accepts only public-subject registrations. That conflicts with
existing Tunnelbana pairwise registrations and with the federation frontend's
historical `pairwise` default. Grindvakt 0.8.1 restores caller-managed pairwise
support through an explicit provider opt-in and issuance-time resolver APIs.
Methods accepting a precomputed subject remain public-only.

Registrations can change while authentication is in progress, especially when
federation metadata is refreshed. The response pipeline may already have chosen
a subject under the original policy. Merely returning that string from a
resolver without checking the original registration would still permit a public
identifier to be reinterpreted after a change to pairwise.

## Decision

Use the published `grindvakt` 0.8.1 crate from crates.io. Keep the
`tunnelbana-oidc` compatibility re-exports. Both `oidc` and `oidc_federation`
frontends call `with_caller_managed_pairwise_subjects()` and issue responses
through `authorization_redirect_with_claims_and_subject_resolver()`.

Tunnelbana takes responsibility for the caller-managed contract through its
trusted, operator-configured pipeline. No new frontend setting is required for
existing deployments. Discovery advertises `public` and `pairwise`; unsupported
subject types remain rejected. Static registrations retain their `public`
default, while automatic federation registration retains its historical
`pairwise` default when metadata omits `subject_type`.

At initial authorization, save a SHA-256 registration fingerprint inside the
existing authenticated state cookie. Include every serialized client field;
separate flattened JWK extensions before canonicalizing JSON object order.
This avoids extension-name collisions, nondeterministic map order, and storing
client secrets or complete key sets in the cookie. The fingerprint is a
consistency check, not an authentication credential.

At issuance, Grindvakt passes the currently validated client to the resolver.
Tunnelbana compares it with the login fingerprint before selecting the subject.
A mismatch returns `unauthorized_client` with the request's original state and
response mode. Grindvakt then checks for further registration changes or removal
before minting. This is snapshot consistency, not a transaction excluding all
later writes; external sector policy remains operator-owned.

## Subject selection and operator responsibilities

The resolver retains the existing order, for both public and pairwise clients:

1. Use `InternalData.subject_id` supplied by the backend/response pipeline.
2. Otherwise use the existing `user_id_from_attrs` composition.
3. If neither provides an identifier, reject authorization.

Do not automatically prefer `pairwise-id`, hash the subject again, change salts,
change `pairwiseid` framing, or normalize the selected value. `pairwiseid` creates
an attribute; that attribute alone does not make it the OIDC subject. An
upstream `SubjectType::Pairwise` label also does not prove isolation for a new
downstream RP.

Operators using pairwise registrations must already arrange for the selected
final value to be stable for the same user and sector, distinct across sectors,
and non-reversible by RPs. Keep the established derivation, sector mappings and
stored identifiers. For example, an existing response service that sets
`subject_id` must continue doing so; an existing attribute-composition deployment
must retain the same `user_id_from_attrs` inputs. The upgrade does not infer
sector configuration or implement `sector_identifier_uri` validation.

The provider opt-in acknowledges this trusted pipeline contract. It cannot
prove privacy from an arbitrary final string. A deployment currently forwarding
a global upstream subject as pairwise needs an explicit identity migration;
this release does not silently rewrite its users' account keys.

## Rollout and compatibility

Existing correctly configured public and pairwise deployments retain their
configuration and identifiers. Retain frontend names, issuer URLs, signing keys,
master secrets and previous-secret lists. Token lifetimes, scoped sealing-key
derivation, token representations, and configured response services remain the
same. Codes and refresh tokens keep their original subject at exchange; the
upgrade does not derive it again. Process-local replay-store behavior is unchanged.

New logins always carry a registration fingerprint. A public login cookie made
by older code, without that field, may still complete. An older in-flight
pairwise login must restart once: its registration cannot be bound safely after
the fact. Do not fabricate a missing fingerprint from the current registration.
Drain ongoing logins before rollout when even this one-time interruption is
unacceptable. Already-issued refresh tokens do not require a login fingerprint.

The protocol hardening in Grindvakt 0.8 remains active: ordered query/form pairs,
validated response modes, scope filtering, explicit RP signing-algorithm policy,
and upstream issuer checks. This decision preserves subject compatibility; it
does not restore acceptance of malformed protocol requests or unsafe algorithms.

## Validation

`oidc_subject_compatibility.rs` exercises both OP frontends with public and
pairwise clients, explicit subjects and attribute composition, code/implicit/
hybrid responses, verified ID tokens, UserInfo, and refresh exchange after a
frontend restart. It also checks registration changes across login and the
pre-upgrade-cookie boundary. The existing federation test covers an omitted
subject type during automatic registration. Existing full-proxy tests cover
requester restoration, silent login, DPoP, typed claims and refresh behavior.

## Alternatives

- Keep Grindvakt 0.8.0's public-only policy: breaks existing pairwise registrations.
- Introduce a new built-in derivation: changes existing account identifiers.
- Wrap an old subject in a resolver without a login binding: retains the
  registration-change race.
- Require a new opt-in setting for every deployed frontend: unnecessary for a
  proxy whose established trusted pipeline already owns subject selection.
