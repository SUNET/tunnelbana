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
A missing binding or mismatch returns `unauthorized_client`. Before redirecting
any issuance or backend error, revalidate the stored authorization request
against the current registration. Preserve the original state and response mode
only while that validation succeeds; otherwise return the error locally without
a `Location` header. A revoked redirect or removed client must never receive an
error redirect based solely on old login state. Grindvakt also checks for further
registration changes or removal before minting. This is snapshot consistency, not a transaction excluding all
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

New logins always carry a registration fingerprint. Every older in-flight OIDC
login without that field must restart once, including currently public clients:
the current registration cannot prove which subject policy applied before login.
Do not fabricate a missing fingerprint from the current registration. Already-
issued refresh tokens do not require a login fingerprint.

This upgrade requires a coordinated cutover, not a rolling deployment with
mixed old/new workers sharing login cookies. Older code can decrypt the unchanged
cookie envelope and ignore the added fingerprint. Therefore, a registration
binding is enforced only when every worker that can consume its flow state
implements these checks. Sticky routing alone is insufficient, including during
failover or worker replacement.

Deployment procedure:

1. Stop admitting new authorization flows. Allow existing flows to drain on the
   old workers if a one-time login restart is unacceptable.
2. Remove and stop all old workers that can receive login callbacks before
   routing any new login traffic to the upgraded deployment. New workers may be
   prepared in isolation, but must not issue login cookies while old workers can
   still consume them.
3. Route authorization and callback traffic only to upgraded workers, including
   failover capacity, then resume new logins. Unbound old flows restart safely.

Rollback must also be coordinated. Stop new authorizations and stop issuing bound
login state. Draining flows may reduce disruption, but completion only deletes
the browser cookie; saved copies remain valid. Before older workers receive
callbacks, every issued bound cookie must have expired under the rollback
workers' configured finite `state_cookie_max_age`, allowing for clock skew, or
that login state must be explicitly invalidated. With `state_cookie_max_age=0`,
expiry is disabled, so draining or waiting is insufficient and explicit
invalidation is required. Prefer expiry to rotating shared token secrets, which
also invalidates existing codes and refresh tokens. No runtime mixed-version
detection is provided by this change.

The protocol hardening in Grindvakt 0.8 remains active: ordered query/form pairs,
validated response modes, scope filtering, explicit RP signing-algorithm policy,
and upstream issuer checks. This decision preserves subject compatibility; it
does not restore acceptance of malformed protocol requests or unsafe algorithms.

Enable jose-rs 0.7.0's `post-quantum` feature for the workspace so configured
ML-DSA and composite ML-DSA algorithms work for OIDC and federation. Upstream
ID-token policy rejects HMAC and algorithms whose `to_crypto()` mapping fails,
rather than restricting verification to a fixed list of classical algorithms.
Default verification remains `RS256`. PQC signing uses AKP JWKs and an explicit
algorithm; code flow avoids the undefined PQC `c_hash`/`at_hash` mappings rejected
by Grindvakt. See the [PQC configuration guide](../src/configuration.md#pqc-signing-keys-for-oidc).

## Validation

`oidc_subject_compatibility.rs` exercises both OP frontends with public and
pairwise clients, explicit subjects and attribute composition, code/implicit/
hybrid responses, verified ID tokens, UserInfo, and refresh exchange after a
frontend restart. It also checks registration changes across login and the
mandatory rejection of legacy cookies across original/current public and
pairwise policies. It verifies local errors after redirect revocation or client
removal, and preserves error redirects for unchanged valid registrations. The
existing federation test covers an omitted subject type during automatic
registration. Existing full-proxy tests cover
requester restoration, silent login, DPoP, typed claims and refresh behavior.
PQC integration tests exercise all nine jose-rs algorithms through both OP
frontends and both RP backends, including public JWKS, federation signatures and
client assertions. They retain default-policy and unsupported-flow rejection.

## Alternatives

- Keep Grindvakt 0.8.0's public-only policy: breaks existing pairwise registrations.
- Introduce a new built-in derivation: changes existing account identifiers.
- Wrap an old subject in a resolver without a login binding: retains the
  registration-change race.
- Require a new opt-in setting for every deployed frontend: unnecessary for a
  proxy whose established trusted pipeline already owns subject selection.
