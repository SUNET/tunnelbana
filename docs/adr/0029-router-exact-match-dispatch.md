# ADR 0029 - O(1) router dispatch (exact-match map + regex fallback)

- **Status:** Accepted
- **Date:** 2026-06-24
- **Component:** `tunnelbana-core` - `router.rs` (`Router`), `plugin.rs`
  (`Route`, `Matcher`); all plugin `register_endpoints` in `tunnelbana-plugins`.
- **Related:** [ADR 0028 - external client roster file](0028-clients-file.md).

## Context

`Router::resolve` matched an inbound path by a **linear scan**: it iterated
every registered endpoint and ran `pattern.is_match(path)` on a compiled regex
until the first hit. Each frontend mounts five routes
(`.well-known/openid-configuration`, `jwks`, `authorization`, `token`,
`userinfo`), so with `N` frontends a request did up to `5N` regex matches, and a
path that matched nothing - the scan's worst case, since it only short-circuits
on a hit - walked the entire list.

This is fine at a handful of frontends but does not hold at federation scale. A
single proxy can front a large number of entry points (an eduGAIN-sized
deployment is 10-15k entities); at `N = 15k` a worst-case request performs
~75k `is_match` calls, and routing latency grows linearly with `N`. A local
scale rig (`toomanyfronts/`) made the slope visible already at `N = 1000`
(`oidc1` ≈ 9 ms vs `oidc1000` ≈ 11.5 ms per request).

The enabling observation: **every route any plugin registers is a literal
`{module}/{suffix}` path**, built as `Route::new(&regex::escape(...), id)`. None
use wildcards, character classes, alternation, or catch-alls. A literal path
needs string equality, not a regex - so the common case can be a hash probe.

## Decision

Split the router into an exact-match map plus a small regex fallback, and teach
`Route` to carry whether it is literal.

- `Route` holds a `pub(crate) matcher: Matcher` where
  `Matcher = Exact(String) | Regex(regex::Regex)`. A new
  `Route::exact(path, id)` stores the literal path and compiles **no** regex;
  `Route::new(pattern, id)` is unchanged (still anchored `^...$`) and produces
  `Matcher::Regex`, so registering a true-regex route remains possible. The
  formerly public `pattern` field is replaced by a `Route::matches(&self, path)`
  accessor.
- `Router` holds `exact: HashMap<String, EndpointData>` and
  `regexes: Vec<RegexEndpoint>`. `add` routes each `Route` to the map or the
  vec by its matcher. `resolve` probes the map first (O(1)); only on a miss does
  it scan the regex vec (empty in every shipped configuration today).
- **First-registrant-wins** on the exact map (`entry(path).or_insert(data)`)
  preserves the previous first-match precedence. Because `Proxy::new` adds
  frontends before micro-services before backends, a frontend and a backend that
  share a name (so both register e.g. `Saml2/metadata`) still resolve to the
  frontend, exactly as the linear scan did.
- All plugin `register_endpoints` migrate from
  `Route::new(&regex::escape(x), id)` to `Route::exact(x, id)`.

The standard library `HashMap` (SipHash with a per-map random seed) is kept
deliberately - see Security boundaries. `RegexSet` (a single combined DFA) was
considered as a lower-touch alternative but rejected: its build time and memory
scale with `N`, it returns *all* matches (needing a precedence pass), and a hash
probe is both smaller and faster for literal paths.

## Security boundaries

| Threat | Control | Residual risk |
|--------|---------|---------------|
| Attacker floods bogus/unmatched paths to burn CPU | A miss is now O(1) (one hash probe + the empty regex vec), where the old linear scan made misses its `5N`-match worst case | Hashing the path is O(path length); bounded by the HTTP server's request-line size limit, identical to a valid request |
| Hash-flooding (crafted keys colliding into one bucket) | `std::collections::HashMap` uses SipHash keyed by a per-map random `RandomState`; an unkeyed fast hasher (FxHash/ahash) is intentionally **not** adopted | None beyond the standard SipHash guarantees |
| A literal path silently changing match semantics | `Matcher::Exact` is whole-string equality - inherently fully anchored, equivalent to the old `^...$`; module names with regex-special characters now match literally (strictly safer than the escaped regex) | - |
| Operator-registered regex route causing ReDoS on a miss | Only an explicit `Route::new` pattern lands in the regex fallback; none ship today, and this is the pre-existing surface of `Route::new`, unchanged here | Operator-controlled, not attacker-controlled |

## Consequences

**Positive**

- `resolve` is O(1) in `N` for the literal case (the only case in production),
  so routing latency is flat as frontend count climbs to federation scale.
  Verified on the `toomanyfronts` rig at `N = 10000`: `oidc1`, `oidc10000`, and
  a missing path resolve within ~0.1 ms of each other (vs a 2.4 ms first/last
  spread at `N = 1000` before).
- Literal routes compile no regex, removing ~`5N` `Regex::new` calls at boot and
  the per-`Regex` memory. Measured RSS *dropped* from ~95 MB at `N = 1000` to
  ~71 MB at `N = 10000`.
- First-match precedence (including the frontend-beats-backend shared-name case)
  is preserved; the public `Route::new` regex path still works.

**Negative / accepted trade-offs**

- One deliberate semantic refinement: an exact match always wins over a regex
  route, even one registered earlier. This diverges from a pure global
  insertion-order scan but cannot be triggered by current code (no plugin
  registers a regex route); it is documented on `Router::resolve`.
- `Route`'s `pattern` field is no longer public; the one in-tree reader (a SAML
  round-trip test) moved to `Route::matches`. External code that reached into
  `pattern` would need the accessor.

## References

- `crates/tunnelbana-core/src/router.rs` - `Router { exact, regexes }`, `add`
  (`or_insert`), `resolve`; unit tests (exact hit/miss, empty router,
  same-path frontend precedence, regex fallback, exact-beats-regex, large-N).
- `crates/tunnelbana-core/src/plugin.rs` - `Matcher`, `Route::exact`,
  `Route::new`, `Route::matches`.
- `crates/tunnelbana-plugins/src/{oidc,federation,saml2}_{frontend,backend}.rs`
  - `register_endpoints` migrated to `Route::exact`.
- `toomanyfronts/` - the scale rig used to verify flat latency at `N = 10000`.
