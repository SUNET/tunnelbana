# ADR 0012 — `attribute_authorization` micro-service (regex allow/deny)

- **Status:** Accepted
- **Date:** 2026-06-10
- **Component:** `tunnelbana-plugins` — `microservices.rs`
  (`AttributeAuthorization`, config type `attribute_authorization`).
- **Related:** [ADR 0011 — `attribute_processor`](0011-attribute-processor-microservice.md).

## Context

The production SATOSA instances enforce a presence-and-shape gate on response
attributes via `AttributeAuthorization`:

```yaml
force_attributes_presence_on_allow: true
attribute_allow:
  default:
    platform:
      subject-id: ["."]
    default:
      subject-id: ["."]
```

— every authentication response must carry a non-empty `subject-id`, for any
requester and any provider; otherwise authentication is rejected. tunnelbana's
only filtering micro-service (`filter_attributes`) drops attributes but cannot
**reject a response**, so this policy could not be expressed.

SATOSA's semantics (from `attribute_authorization.py`):

- `attribute_allow` / `attribute_deny` are nested
  `requester → provider (issuer) → attribute → [regexes]`;
- at the requester and provider levels, lookup is exact key, else `""`, else
  `"default"` (`get_dict_defaults`) — `""` and `"default"` are synonymous, and
  rule sets are **selected, not merged**;
- allow: the attribute passes when *any* value matches *any* regex
  (unanchored `re.search`); a present-but-non-matching attribute rejects;
  an absent attribute rejects only with `force_attributes_presence_on_allow`;
- deny is the mirror image: any match rejects.

## Decision

Port `AttributeAuthorization` faithfully as a response-path micro-service:

- identical nested config shape (`attribute_allow` / `attribute_deny`,
  both `force_attributes_presence_*` flags, `""`/`"default"` wildcards with
  the same exact→`""`→`"default"` precedence);
- all regexes compiled at **build time**; a bad pattern fails plugin
  construction;
- matching uses `Regex::is_match` (unanchored, like `re.search`), ORed across
  values and patterns;
- the requester is `InternalData.requester` and the provider is
  `InternalData.auth_info.issuer` — the same pair SATOSA uses;
- a violation returns `Error::Authn`, which the proxy renders through the
  frontend's protocol-appropriate error path (SAML error response / OIDC
  `access_denied`), mirroring SATOSA's `SATOSAAuthenticationError`.

Attribute names in the rules are **internal** names (post-mapping), so the
production `subject-id` rule becomes `subjectid` per the attribute map.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Response without the required identifier reaching a downstream SP/RP | `force_attributes_presence_on_allow` rejects responses missing a rule's attribute | Only attributes named in a matching rule set are checked; an empty rule set checks nothing |
| Mis-scoped rule silently inherited by other requesters | Rule sets are selected, never merged — a requester-specific block fully replaces `default` (SATOSA parity) | An operator expecting merge semantics may under-constrain; documented in the config comment |
| Regex DoS via attacker-controlled values | The `regex` crate guarantees linear-time matching regardless of input | — |
| Ordering bypass | Run after `attribute_processor` in the configured chain so rules see transformed values | Chain order is operator responsibility |

## Consequences

**Positive**

- Production SATOSA `AttributeAuthorization` configs port 1:1 (modulo internal
  attribute names).
- The proxy can now *reject* — not merely filter — responses that fail
  attribute policy, closing the gap where an attribute-less authentication
  would previously flow through.

**Negative / accepted trade-offs**

- Selected-not-merged rule sets are subtle but kept for SATOSA parity.
- No per-rule custom error message/URL (SATOSA has none either); all
  violations surface as a generic permission-denied authentication error.

## References

- `crates/tunnelbana-plugins/src/microservices.rs` — `AttributeAuthorization`,
  `level` (the `get_dict_defaults` port)
- `crates/tunnelbana-plugins/src/microservices.rs` tests —
  `attribute_authorization_allows_when_present_denies_when_absent` (the
  production config), `attribute_authorization_requester_specific_overrides_default`,
  `attribute_authorization_deny_rule`
- `../SATOSA/src/satosa/micro_services/attribute_authorization.py`,
  `../SATOSA/src/satosa/util.py` (`get_dict_defaults`) — ported behavior
