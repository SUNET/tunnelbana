# Micro-services

A **micro-service** is the third plugin kind (alongside frontends and backends).
Where a frontend speaks a protocol *down* to RPs/SPs and a backend speaks one
*up* to IdPs/OPs, a micro-service sits **in the middle of the flow** and
transforms the `InternalData` as it passes between them - without either side
knowing it is there. It is tunnelbana's analogue of a SATOSA *micro-service*.

Typical jobs: inject or filter attributes, choose the backend by requester,
enforce consent, look up entitlements, rewrite the subject id.

## The trait

```rust
#[async_trait]
pub trait MicroService: Send + Sync {
    fn name(&self) -> &str;

    /// Transform the request-path data (frontend → backend). Default: identity.
    async fn process_request(&self, ctx: &mut Context, data: InternalData)
        -> Result<InternalData> { Ok(data) }

    /// Transform the response-path data (backend → frontend). Default: identity.
    async fn process_response(&self, ctx: &mut Context, data: InternalData)
        -> Result<InternalData> { Ok(data) }

    /// Optional own endpoints (e.g. a consent callback page).
    fn register_endpoints(&self) -> Vec<Route> { Vec::new() }

    /// Inbound hit on one of those endpoints.
    async fn handle_endpoint(&self, ctx: &mut Context, route_id: &str) -> Result<Response>;
}
```

Both transform methods have a **default identity implementation**, so a
micro-service only overrides the side(s) it cares about: a request-path service
implements `process_request`, a response-path service implements
`process_response`. The supporting types (`BuildContext`, `Route`, `Context`)
are exactly the ones described in [Writing a plugin](writing-a-plugin.md); read
that chapter first for `parse_config`, state namespacing, and the conventions.

## Where they run in the pipeline

The [`Proxy`](architecture.md) holds its micro-services as an **ordered list**
(the order they appear in the config) and invokes them at two precise points -
see `tunnelbana-core/src/proxy.rs`:

```
   inbound request
        │
   ┌────▼─────────┐
   │  frontend    │  handle_endpoint → StartAuth { request, target_backend? }
   └────┬─────────┘
        │  request InternalData
   ┌────▼──────────────────────────────┐
   │  micro-services, in listed order   │  process_request(ctx, data)   ← REQUEST PATH
   └────┬──────────────────────────────┘
        │  backend selected: explicit pin > micro-service pin > default
   ┌────▼─────────┐
   │  backend     │  start_auth → … upstream IdP/OP … → handle_endpoint → AuthResponse(data)
   └────┬─────────┘
        │  response InternalData
   ┌────▼──────────────────────────────┐
   │  micro-services, in listed order   │  process_response(ctx, data)  ← RESPONSE PATH
   └────┬──────────────────────────────┘
        │
   ┌────▼─────────┐
   │  frontend    │  handle_authn_response → protocol response to the RP/SP
   └──────────────┘
```

Key facts that follow from this:

- **They only run on the auth flow.** `process_request` fires when a frontend
  returns `StartAuth`; `process_response` fires when a backend returns
  `AuthResponse`. Endpoints that merely `Respond` (discovery, JWKS, token,
  SP metadata) never touch the micro-service chain.
- **Order is the config order**, and it is the *same* order on both paths
  (request path forward, response path forward) - there is no automatic
  reversal. List them accordingly.
- **A request-path service can steer routing** by setting
  `ctx.target_backend`. Backend selection precedence is: a backend the frontend
  pinned in `StartAuth` → a backend a micro-service pinned in `ctx.target_backend`
  → the default (the first configured backend). `custom_routing` uses exactly
  this hook.
- **The data is the contract.** A micro-service receives and returns
  `InternalData` - `attributes`, `requester`, `subject_id`, `auth_info`. Mutate
  that; don't reach into protocol-specific structures.
- **Own endpoints are dispatched directly.** If a micro-service registers
  routes, an inbound hit goes straight to its `handle_endpoint` (the request/
  response transform chain is not involved). This is how a consent service would
  serve and handle its own approval page.

## Decorations: passing signals between services

Besides `InternalData` (persisted across the flow) and `ctx.state` (the
encrypted cookie), services share **per-request decorations** -
`ctx.decorate(key, value)` / `ctx.decoration(key)` - that live only for the
current HTTP request. Two well-known keys exist (ADR 0013), exported from
`tunnelbana_core::context`:

- **`KEY_TARGET_ENTITYID`** - "the user wants to authenticate at this
  upstream entity". Written by `idp_hinting` (or a future discovery-style
  service); read by `custom_routing`'s issuer rules and by the SAML2
  backend's MDQ mode when picking the target IdP. First writer wins.
- **`KEY_ERROR_REDIRECT`** - an absolute URL. If any later step fails, the
  proxy answers with a **302 to this URL** instead of rendering a protocol
  error. Set it together with returning `Err(..)` to implement a
  "redirect-on-failure" service - `primary_identifier`'s `on_error` does
  exactly this. Only ever set it from operator config, never from request
  data (open-redirect hazard).

## The built-ins

The bundled micro-services (`tunnelbana-plugins/src/microservices/`) are small
and worth reading as templates. Full config examples are in the
[built-in plugin reference](built-in-plugins.md#micro-services).

| `type` | Path | What it does |
| --- | --- | --- |
| `static_attributes` | response | Adds fixed attributes (does not overwrite existing ones). |
| `filter_attributes` | response | Keeps only allow-listed internal attributes, globally or per requester. See [below](#filter_attributes-attribute-allow-lists). |
| `filter_attribute_values` | response | Drops attribute *values* failing a regex, per provider/requester. See [below](#filter_attribute_values-value-level-filtering). |
| `rename_attributes` | response | Renames internal attributes (merging values on collision). |
| `attribute_processor` | response | Rewrites attribute values through per-attribute processor chains (regex, hash, scope, gender). See [below](#attribute_processor-value-transforms). |
| `attribute_generation` | response | Synthesizes attributes from Tera templates over the existing set. See [below](#attribute_generation-synthesized-attributes). |
| `attribute_authorization` | response | Rejects the authentication unless response attributes satisfy regex allow/deny rules. See [below](#attribute_authorization-regex-allowdeny-rules). |
| `hasher` | response | Salted-hashes the subject id and/or selected attributes per requester. See [below](#hasher-pseudonymizing-subject-ids-and-attributes). |
| `primary_identifier` | response | Builds a primary identifier from an ordered candidate list. See [below](#primary_identifier-ordered-identifier-candidates). |
| `custom_logging` | response | Appends a JSON audit record per completed authentication. See [below](#custom_logging-audit-records). |
| `pairwiseid` | response | Derives a per-SP `pairwise-id` from `subject-id`. See [below](#pairwiseid-per-sp-pairwise-identifiers). |
| `static_attributes_for_virtual_idp` | response | Injects/appends static attributes per `(requester, virtual_idp)`. See [below](#static_attributes_for_virtual_idp-per-sp-virtual-idp-attributes). |
| `nameid` | response | Sets the SAML subject id from `pairwise-id`/`mail` per the requested NameID format. See [below](#nameid-saml-subject-value-from-attributes). |
| `accr` | request + response | Negotiates the AuthnContextClassRef (LoA). See [below](#accr-authncontextclassref-loa-negotiation). |
| `custom_routing` | request | Pins `ctx.target_backend` from the target issuer or the `requester`, with an optional default. See [below](#routing-the-flow-custom_routing-and-idp_hinting). |
| `idp_hinting` | request | Lifts an IdP-hint query parameter into `KEY_TARGET_ENTITYID`. See [below](#routing-the-flow-custom_routing-and-idp_hinting). |

For instance, `filter_attributes` is the whole pattern in a few lines:

```rust
#[async_trait]
impl MicroService for FilterAttributes {
    fn name(&self) -> &str { &self.name }

    async fn process_response(&self, _ctx: &mut Context, mut data: InternalData)
        -> Result<InternalData>
    {
        data.attributes.retain(|k, _| self.allowed.contains(k));
        Ok(data)
    }
}
```

## Scoping a service to specific SPs and IdPs

A tunnelbana micro-service is not wired to one SP or IdP the way a frontend or
backend is: **every** service in the chain runs on **every** auth flow. What
makes a service behave differently for one downstream relying party or one
upstream identity provider is its **config nesting** - exactly the model SATOSA
uses, where a micro-service carries per-entity rule maps rather than being
instantiated per entity. Two flow facts drive the lookup:

- **requester** - the downstream SP/RP that started the flow
  (`InternalData.requester`, the SAML SP entityID or the OIDC `client_id`).
- **provider** - the upstream IdP/OP that authenticated the user
  (`InternalData.auth_info.issuer`).

Services that take per-entity config key their rule maps on one or both of
these. There are two wildcard conventions and two ways the entries combine, and
they are not the same across services (this matches SATOSA's own
inconsistencies, kept deliberately for drop-in parity):

- **Wildcard tokens.** Most services treat `""` **and** `"default"` as
  synonymous catch-alls (the shared `level()` lookup is *exact key, else `""`,
  else `"default"`*). `filter_attribute_values` and `hasher` recognise only
  `""`. `primary_identifier` overrides match the entity id exactly, with no
  wildcard.
- **Combination model.** Most services are **selected, not merged**: the most
  specific matching block *replaces* the wildcard block, so a per-SP entry must
  restate any rule it still wants. The exception is `filter_attribute_values`,
  whose layers **stack** (default-provider then specific-provider, and within
  each default-requester then specific-requester all apply cumulatively).

This table is the quick reference for which services can be scoped and how:

| Service | Scopes on | Wildcards | Combination | Config key |
| --- | --- | --- | --- | --- |
| `filter_attributes` | requester | `""` / `default` | selected (replaces global `allowed`) | `policy."<requester>"` |
| `attribute_authorization` | requester -> provider | `""` / `default` | selected | `attribute_allow."<requester>"."<provider>"` |
| `attribute_generation` | requester -> provider | `""` / `default` | selected | `synthetic_attributes."<requester>"."<provider>"` |
| `filter_attribute_values` | provider -> requester | `""` only | **stacked** | `attribute_filters."<provider>"."<requester>"` |
| `hasher` | requester | `""` only | per-field override of the `""` defaults | `"<requester>"` |
| `primary_identifier` | requester or provider | none (exact) | IdP override first, **SP override wins** | `override."<entity id>"` |
| `custom_routing` | requester and/or target issuer | (rule list) | first matching rule, else `default_backend` | `rule` / `issuer_rule` |
| `static_attributes`, `rename_attributes`, `attribute_processor`, `custom_logging`, `idp_hinting` | - | - | apply uniformly to every flow | - |

Note the **order of the two keys flips** between families: the authorization and
generation services nest *requester then provider*, while
`filter_attribute_values` nests *provider then requester*. Read each service's
own section below before writing a nested block.

A worked example - release a narrow attribute set to one strict SP, the default
set to everyone else, and additionally require a staff affiliation when the
assertion comes from one specific upstream IdP:

```toml
# filter_attributes: per-SP release (selected - the SP entry replaces the global)
[[microservice]]
type = "filter_attributes"
name = "release"
  [microservice.config]
  allowed = ["mail", "givenname", "surname", "edupersonprincipalname"]
  [microservice.config.policy."https://strict-sp.example.org"]
  allowed = ["mail"]                       # this SP gets only mail

# attribute_authorization: per-(SP, IdP) gate (requester -> provider)
[[microservice]]
type = "attribute_authorization"
name = "authz"
  [microservice.config]
  force_attributes_presence_on_allow = true
  # Any SP, any IdP: mail must be present.
  [microservice.config.attribute_allow.default.default]
  mail = ["."]
  # This SP, only when the named IdP asserted: also require a staff affiliation.
  # Because blocks are SELECTED not merged, the mail rule is restated here.
  [microservice.config.attribute_allow."https://strict-sp.example.org"."https://idp.example.org"]
  mail = ["."]
  affiliation = ["^staff$"]
```

Services that don't take per-entity config (`static_attributes`,
`attribute_processor`, ...) still apply to one SP/IdP combination if you want -
gate them by listing a scoped service such as `filter_attributes` or
`attribute_authorization` alongside, or split the upstream into its own backend
and [pin the frontend](configuration.md#backend-selection) to it. There is no
global "run this service only for SP X" wrapper; per-entity behavior is always
expressed inside the service's own rule map, as above.

## `attribute_processor`: value transforms

The SATOSA-parity attribute transformer (ADRs 0011 and 0020, SATOSA:
`AttributeProcessor` + `processors/*`). It runs on the **response path** and
rewrites the values of named internal attributes through a chain of
processors, in place.

Config is a `process` list; each entry names one internal attribute and its
processor chain. Six processor kinds exist - `regex_sub`, `hash`, `scope`,
`scope_extractor`, `scope_remover` and `gender`. Starting with `regex_sub`:

```toml
[[microservice]]
type = "attribute_processor"
name = "rewrite"
  [[microservice.config.process]]
  attribute = "mail"                          # internal attribute name
    [[microservice.config.process.processors]]
    name = "regex_sub"
    match_pattern = '@legacy\.example\.org$'  # regex, applied unanchored
    replace_pattern = '@example.org'          # every match replaced
```

This example rewrites a retired mail domain on the fly:
`anna@legacy.example.org` → `anna@example.org`.

How it behaves, precisely:

- **Internal names.** `attribute` is the *internal* attribute name from your
  attribute map - `mail`, not the wire name
  `urn:oid:0.9.2342.19200300.100.1.3`. The backend has already mapped inbound
  protocol attributes by the time this runs.
- **All values, all matches.** Every value of the attribute is rewritten, and
  replacement applies to every match within a value (like Python's `re.sub`).
- **Group references.** Use the regex crate's `$1`/`${1}` syntax. Python-style
  `\1` (as found in SATOSA configs) is accepted and converted automatically,
  so a SATOSA `regex_sub_replace_pattern: _\1` ports verbatim as
  `replace_pattern = '_\1'`. Prefer TOML *literal* strings (single quotes) so
  backslashes need no escaping.
- **Chaining.** A rule may list several processors; they run in order, each
  seeing the previous one's output. Several `[[microservice.config.process]]`
  rules can target different attributes.
- **Fail-fast config.** Patterns compile at startup; a bad regex or an unknown
  processor `name` aborts boot rather than surfacing mid-flow.
- **Ordering.** Place it **before** services that *match on* the transformed
  value (such as `attribute_authorization` below), and note that the subject
  id composed via `user_id_from_attrs` is taken **before** micro-services run
  - the transform affects the released attribute, not NameID minting (same as
  SATOSA).

### The other processors

```toml
[[microservice]]
type = "attribute_processor"
name = "shape"
  # Scoping: build schacHomeOrganization out of the eppn's scope, then strip
  # the scope from a copy-style attribute, then scope an unscoped uid.
  [[microservice.config.process]]
  attribute = "edupersonprincipalname"
    [[microservice.config.process.processors]]
    name = "scope_extractor"
    mapped_attribute = "schachomeorganization"   # receives "example.org"

  [[microservice.config.process]]
  attribute = "edupersonscopedaffiliation"
    [[microservice.config.process.processors]]
    name = "scope_remover"                       # "staff@x.org" -> "staff"

  [[microservice.config.process]]
  attribute = "uid"
    [[microservice.config.process.processors]]
    name = "scope"
    scope = "example.org"                        # "anna" -> "anna@example.org"

  # Pseudonymize one attribute in place (for subject_id, use `hasher`).
  [[microservice.config.process]]
  attribute = "edupersontargetedid"
    [[microservice.config.process.processors]]
    name = "hash"
    salt = "${TUNNELBANA_HASH_SALT}"             # strongly recommended
    hash_algo = "sha256"                         # "sha256" (default) | "sha512"

  # Text gender -> ISO 5218 / schacGender code.
  [[microservice.config.process]]
  attribute = "gender"
    [[microservice.config.process.processors]]
    name = "gender"          # male->1, female->2, "not specified"->9, else 0
```

Behavior notes:

- **`hash`** hashes *every* value as `hex(hash(value || salt))` (SATOSA's
  upstream `HashProcessor` reads the salt from the wrong config key and only
  hashes the first value - neither bug is reproduced, so hashes can differ
  from a buggy SATOSA deployment; see ADR 0020). Only `sha256`/`sha512` are
  accepted; `md5`/`sha1` are startup errors.
- **`scope_extractor`** takes the domain of the **first** scoped value and
  *overwrites* `mapped_attribute` with it; if no value contains `@` it does
  nothing.
- A processor whose target attribute is absent **skips silently** (SATOSA
  logs a warning and continues); bad *config* - unknown processor name,
  missing required field, bad regex - still **aborts startup**.
- Chains compose: `scope_remover` after `scope_extractor` on the same
  attribute implements "split eppn into local part + home org".

## `attribute_authorization`: regex allow/deny rules

The SATOSA-parity authorization gate (ADR 0012, SATOSA:
`AttributeAuthorization`). It runs on the **response path** and *rejects the
authentication* - not merely filters - when response attributes don't satisfy
the configured rules. The originating frontend renders the rejection as a
protocol error (SAML error response / OIDC `access_denied`).

Rules nest **requester → provider → attribute → list of regexes**, where
*requester* is the downstream SP/RP and *provider* is the upstream IdP/OP
issuer. At the requester and provider levels the lookup is: exact key, else
`""`, else `"default"` (`""` and `"default"` are synonymous wildcards):

```toml
[[microservice]]
type = "attribute_authorization"
name = "authz"
  [microservice.config]
  force_attributes_presence_on_allow = true

  # Any requester, any provider: mail must be present and non-empty.
  [microservice.config.attribute_allow.default.default]
  mail = ["."]

  # One locked-down SP additionally requires a staff affiliation.
  [microservice.config.attribute_allow."https://locked.example".default]
  mail = ["."]
  affiliation = ["^staff$"]

  # Deny example (SATOSA's doc case): reject eppn values without an '@'.
  # [microservice.config.attribute_deny.default.default]
  # edupersonprincipalname = ["^[^@]+$"]
```

Semantics (identical to SATOSA's, ported from
`satosa/micro_services/attribute_authorization.py`):

- **Allow rules.** For each attribute in the selected allow set: if the
  attribute is present, at least one of its values must match at least one
  regex (unanchored search, like `re.search`) - otherwise the flow is
  rejected. If the attribute is **absent**, it is rejected only when
  `force_attributes_presence_on_allow = true`; the
  `mail = ["."]` + force-presence pair above is the idiom for "must be
  present and non-empty".
- **Deny rules.** The mirror image: if any value of a listed attribute matches
  any regex, the flow is rejected. `force_attributes_presence_on_deny = true`
  rejects when the attribute is absent.
- **Selected, not merged.** A requester-specific block *replaces* the
  `default` block entirely - rules are never inherited or combined. In the
  example above, `https://locked.example` must therefore repeat the
  `mail` rule alongside its `affiliation` rule.
- **Internal names**, as everywhere: `mail`, `edupersonprincipalname` -
  not the wire names (`urn:oid:…`, `eduPersonPrincipalName`).
- **Fail-fast config.** All regexes compile at startup.
- **Ordering.** List it **after** `attribute_processor` so the rules see the
  transformed values, and make sure nothing earlier in the chain (e.g. a
  `filter_attributes`) strips an attribute you gate on.

## `filter_attributes`: attribute allow-lists

The whole-attribute filter, now with per-requester policy (ADR 0014, SATOSA:
`AttributePolicy`). Response path.

```toml
[[microservice]]
type = "filter_attributes"
name = "release"
  [microservice.config]
  # Applies when no policy entry below matches the requester.
  allowed = ["mail", "givenname", "surname", "edupersonprincipalname"]

  # This SP gets a narrower release. The entry REPLACES the global list.
  [microservice.config.policy."https://minimal.example.org"]
  allowed = ["mail"]

  # ""/"default" is the wildcard policy entry (checked after the exact match).
  # Every policy entry must set allowed; use allowed = [] to release nothing.
  # [microservice.config.policy.default]
  # allowed = ["mail", "edupersonprincipalname"]
```

The three states of `allowed` matter:

- **Key absent** (no global `allowed`, no matching policy): attributes pass
  through untouched.
- **`allowed = []`** (explicitly empty): drops *everything* - occasionally
  useful as a policy entry for an SP that should get no attributes at all.
- **Non-empty list**: keeps exactly those internal names.

This filters; it never rejects. To *fail* the flow when something required is
missing, pair with `attribute_authorization` and its force-presence flag.

## `filter_attribute_values`: value-level filtering

Where `filter_attributes` drops whole attributes, this drops individual
**values** that fail a regex (ADR 0017, SATOSA: `FilterAttributeValues`).
The canonical use is scope policing for multi-valued federation attributes:

```toml
[[microservice]]
type = "filter_attribute_values"
name = "scope-guard"
  # Defaults: any provider (""), any requester ("").
  [microservice.config.attribute_filters."".""]
  edupersonprincipalname = '@example\.org$'      # keep only our scope

  # For one upstream IdP, additionally constrain affiliations.
  [microservice.config.attribute_filters."https://idp.example.org".""]
  edupersonaffiliation = '^(staff|member)$'
```

Semantics worth knowing (they differ from `attribute_authorization`!):

- Nesting is **provider (issuer) → requester → attribute → regex**, and `""`
  defaults apply **in addition to** specific entries - default-provider
  filters run first, then provider-specific, each layer applying
  default-requester then requester-specific filters. Layers *stack*; they are
  not selected-one-of.
- Only `""` is the wildcard here (not `"default"`), matching SATOSA.
- An attribute key of `""` applies that filter to **every** attribute -
  e.g. `"" = '^[^<>]*$'` as a crude value-hygiene pass.
- Both SATOSA notations work: a bare regex string or `{ regexp = '…' }`.
  The metadata-driven `shibmdscope_match_*` types are **rejected at startup**
  - rewrite them as explicit regexes.
- Matching is an unanchored search: anchor (`^…$`) when you mean whole-value.
- A filter can empty a value list; the attribute then remains with zero
  values. Follow with `attribute_authorization` force-presence if an empty
  result should fail the flow.

## `attribute_generation`: synthesized attributes

Builds *new* attributes from templates over the existing set (ADR 0019,
SATOSA: `AddSyntheticAttributes`). Response path. tunnelbana renders
**[Tera](https://keats.github.io/tera/)** templates - SATOSA's recipe
structure ports 1:1, but Mustache template bodies need translating.

```toml
[[microservice]]
type = "attribute_generation"
name = "synthesize"
  # requester -> provider -> attribute -> template; ""/"default" wildcards;
  # entries are selected, not merged.
  [microservice.config.synthetic_attributes.default.default]
  # The classic: home organization from the eppn's scope.
  schachomeorganization = "{{ edupersonprincipalname.scope }}"
  # Static multi-value: ";" and newlines split into separate values.
  edupersonaffiliation = "member;affiliate"
  # Loops work (this is where Tera beats Mustache):
  displaylabels = "{% for v in edupersonaffiliation.values %}{{ v }}@home;{% endfor %}"
```

Inside a template every existing attribute is an object:

| accessor | meaning |
| --- | --- |
| `{{ attr.value }}` | all values joined with `;` (single value → itself) |
| `{{ attr.first }}` | the first value, or `""` |
| `{{ attr.scope }}` | the part after `@` of the first scoped value |
| `{% for v in attr.values %}` | iterate the value list |

Rendered output is split on `;`/newlines, trimmed, empties dropped - so a
loop emitting `a;b;` yields the values `a`, `b`. Synthesized attributes
**override** existing ones of the same name. Templates are compiled at
startup; syntax errors abort boot. Run it **before** `filter_attributes` /
`attribute_authorization` if those should see (and police) the synthesized
values.

## `hasher`: pseudonymizing subject ids and attributes

Salted hashing of the **subject id** (which no attribute-level service can
touch) and selected attributes, per requester (ADR 0021, SATOSA: `Hasher`).
Response path.

```toml
[[microservice]]
type = "hasher"
name = "pseudonymize"
  # The "" entry is REQUIRED and provides defaults:
  # alg = "sha512", subject_id = true, attributes = [].
  [microservice.config.""]
  salt       = "${TUNNELBANA_HASHER_SALT}"
  attributes = ["edupersontargetedid"]

  # Per-requester overrides patch individual fields over the defaults:
  [microservice.config."https://no-hash.example.org"]
  subject_id = false        # this SP receives the real subject id
  attributes = []

  [microservice.config."https://other-salt.example.org"]
  salt = "${OTHER_SP_SALT}" # unlinkable pseudonyms for this SP
```

- Output is `hex(hash(value || salt))` - byte-identical to SATOSA's
  `util.hash_data`, so migrating a SATOSA deployment with the same salt/alg
  **preserves released pseudonyms**.
- Unlike a policy lookup, requester matching is exact-or-`""` (no
  `"default"` synonym - SATOSA parity), and override entries inherit
  field-by-field from `""`.
- Use **different salts per SP** when pseudonyms must not be correlatable
  across SPs; the same salt everywhere yields the same pseudonym everywhere.
- `sha256`/`sha512` only; a missing default section or missing salt fails at
  startup. Remember plain salted hashing of low-entropy inputs (emails) is
  enumerable by an adversary who knows the salt - treat the salt as a secret
  (`${ENV}` interpolation, not a literal in a committed config).
- For hashing a single attribute mid-chain without touching `subject_id`,
  the `hash` *processor* in `attribute_processor` is the lighter tool.

## `primary_identifier`: ordered identifier candidates

Constructs one canonical identifier from whatever the upstream IdP managed to
assert, trying candidates in order (ADR 0022, SATOSA: `PrimaryIdentifier`).
Response path.

```toml
[[microservice]]
type = "primary_identifier"
name = "primary-id"
  [microservice.config]
  primary_identifier     = "uid"   # attribute that receives the result
  replace_subject_id     = true    # also overwrite InternalData.subject_id
  clear_input_attributes = false
  on_error = "https://errors.example.org/no-identifier"

  # Tried in order; the first candidate with ALL parts present wins, and its
  # first values are concatenated in listed order.
  [[microservice.config.ordered_identifier_candidates]]
  attribute_names = ["edupersonuniqueid"]

  [[microservice.config.ordered_identifier_candidates]]
  attribute_names = ["edupersonprincipalname"]

  # "name_id" is the SAML subject / NameID; it only contributes when the
  # response's subject type matches name_id_format (URN or short name).
  # add_scope appends a final component - "issuer_entityid" namespaces the
  # identifier by the asserting IdP, preventing cross-IdP collisions.
  [[microservice.config.ordered_identifier_candidates]]
  attribute_names = ["name_id"]
  name_id_format  = "persistent"
  add_scope       = "issuer_entityid"

  # Per-entity overrides (SP entity id or IdP entity id; SP wins):
  [microservice.config.override."https://special.example.org"]
  primary_identifier = "employeeid"
  [microservice.config.override."https://opt-out.example.org"]
  ignore = true
```

When **no** candidate succeeds: with `on_error`, the browser is 302'd to
`on_error?sp=…&idp=…` (via the `KEY_ERROR_REDIRECT` decoration) and the flow
ends; without it, the response passes through unchanged - pair with an
`attribute_authorization` force-presence rule on `uid` if that should be a
hard failure instead. Run this **early** in the response chain, before
filters and authorization that act on the constructed identifier.

## Routing the flow: `custom_routing` and `idp_hinting`

The two **request-path** services. `idp_hinting` (ADR 0016) reads an
operator-listed query parameter off the inbound authentication request and
stores it in the `KEY_TARGET_ENTITYID` decoration; `custom_routing`
(ADR 0015) picks the backend from that decoration and/or the requester:

```toml
# Order matters: the hint must be lifted before routing reads it.
[[microservice]]
type = "idp_hinting"
name = "hint"
  [microservice.config]
  allowed_params = ["idphint", "idp_hinting", "idp_hint"]

[[microservice]]
type = "custom_routing"
name = "routing"
  # Issuer rules match the decoration and take precedence…
  [[microservice.config.issuer_rule]]
  issuer  = "https://special-idp.example.org"
  backend = "LegacySaml"
  # …then requester rules…
  [[microservice.config.rule]]
  requester = "https://sp-a.example.com"
  backend   = "Saml2"
  # …then the default.
  [microservice.config]
  default_backend = "Upstream"
```

With that in place, an RP can send
`…/OIDC/authorization?…&idphint=https%3A%2F%2Fidp.example.org` and the SAML2
backend (MDQ mode) will request authentication from that IdP directly,
skipping discovery. The hint never overwrites an existing decoration (a
discovery choice wins), and the SAML2 backend still resolves whatever is
selected through MDQ - signature-verified metadata, IdP role required - so a
hint can only choose among legitimate federation IdPs.

These services still run when a frontend has pinned a backend, but their backend
selection loses to the frontend pin. A frontend with `backend = "<name>"` in its
config (see [Backend selection](configuration.md#backend-selection), ADR 0027)
overrides the backend selected by `custom_routing` / `idp_hinting` and the
default backend. Other request-path effects, such as a target-entity decoration
that the pinned backend itself consumes, still apply. Leave the frontend
unpinned when you want request-time backend routing.

## `custom_logging`: audit records

One JSON line per completed authentication, for SIEM/compliance pipelines
(ADR 0023, SATOSA: `CustomLoggingService`). Response path; list it **last**
so it records the attributes as actually released.

```toml
[[microservice]]
type = "custom_logging"
name = "audit"
  [microservice.config]
  log_target = "/var/log/tunnelbana/audit.jsonl"
  attrs      = ["edupersonprincipalname", "mail"]   # only these are recorded
```

A record looks like:

```json
{"timestamp":"2026-06-10T12:00:00Z","sp":"https://sp.example.org",
 "idp":"https://idp.example.org","frontend":"OIDC","backend":"Saml2",
 "attr":{"edupersonprincipalname":["anna@example.org"],"mail":["anna@example.org"]}}
```

An unwritable `log_target` fails at **startup**; a write failure at runtime
is logged via `tracing` and never fails the user's flow (availability over
audit completeness - monitor the error log). Rotation is external
(`logrotate` with copy-truncate works; the file is re-opened per write).
Record only what your data-protection review allows: `attrs` is empty by
default and nothing else carries attribute values.

## `pairwiseid`: per-SP pairwise identifiers

Turns the released `subject-id` into a stable-but-unlinkable identifier scoped to
the requesting SP (ADR 0030, eduID `scimapi`). Response path; run it **before**
`nameid`, which consumes the result for persistent NameIDs.

```toml
[[microservice]]
type = "pairwiseid"
name = "pairwise"
  [microservice.config]
  pairwise_salt = "${TUNNELBANA_PAIRWISE_SALT}"   # required, non-empty secret
```

The value is
`hex(HMAC-SHA256(pairwise_salt, "{requester}-{subject-id}")) + "@" + scope`,
where `scope` is the part of `subject-id` after the last `@`. Different SPs get
different values for the same user; the same SP always gets the same value. Treat
`pairwise_salt` as a secret - a leak lets an attacker recompute ids for a known
`(sp, subject-id)`. A missing `subject-id` fails the flow; an empty salt fails at
startup.

## `static_attributes_for_virtual_idp`: per-(SP, virtual-IdP) attributes

The virtual-IdP-aware cousin of `static_attributes` (ADR 0030, eduID `scimapi`).
It resolves a recipe by a two-level `(requester, virtual_idp)` lookup - where
`virtual_idp` is the originating frontend (`ctx.target_frontend`) - each level
using the usual exact → `""` → `"default"` fallback. Response path.

```toml
[[microservice]]
type = "static_attributes_for_virtual_idp"
name = "vidp-attrs"
  # REPLACE: overwrite the attribute with these values.
  [microservice.config.static_attributes_for_virtual_idp.default.SunetIDP]
  schachomeorganization = ["sunet.se"]

  # APPEND: union with the released values (dedup + sort).
  [microservice.config.static_appended_attributes_for_virtual_idp.default.SunetIDP]
  edupersonassurance = [
    "https://refeds.org/assurance/ATP/ePA-1m",
    "https://refeds.org/assurance/IAP/local-enterprise",
  ]
```

A requester (SP) key wins over `default`; a `virtual_idp` key wins over its
`default`. With no matching recipe the response passes through unchanged.

## `nameid`: SAML subject value from attributes

Picks the SAML subject *value* per the NameID format the SAML frontend already
negotiated (ADR 0030, eduID `scimapi`). Response path; list it **after**
`pairwiseid`. No config.

```toml
[[microservice]]
type = "nameid"
name = "nameid"
```

The resolved format (published by the SAML frontend) drives the choice:

| NameID format | Subject value |
| --- | --- |
| `persistent` | the hash part of `pairwise-id` (before `@`) |
| `emailAddress` | the `mail` attribute |
| `transient` / `unspecified` | left to the frontend (a fresh opaque value) |

A missing `pairwise-id` (persistent) or `mail` (emailAddress) fails the flow. On
an OIDC frontend, where no NameID format is in play, the service is a no-op.

## `accr`: AuthnContextClassRef (LoA) negotiation

The only **request + response** built-in (ADR 0030, eduID `scimapi`). It
negotiates the AuthnContextClassRef / Level of Assurance between the SP request
and the upstream IdP.

```toml
[[microservice]]
type = "accr"
name = "accr"
  [microservice.config]
  supported_accr_sorted_by_prio = [        # highest priority first; required
    "https://refeds.org/profile/mfa",
    "https://refeds.org/profile/sfa",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
  ]
  # default_comparison = "exact"           # forwarded when the SP omits one

  [microservice.config.lowest_accepted_accr_for_virtual_idp]
  SunetIDP = "https://refeds.org/profile/mfa"   # must be in the supported list

  [microservice.config.internal_accr_rewrite_map]
  "http://id.swedenconnect.se/loa/1.0/uncertified-loa2" = "http://id.elegnamnden.se/loa/1.0/loa2"
```

On the **request** path it reads the SP's requested ACCRs (the SAML frontend
publishes them as the `requested_accr` decoration), drops unsupported values,
enforces a per-`virtual_idp` minimum range, applies `internal_accr_rewrite_map`
for the upstream IdP, and forwards the result into the outgoing
`RequestedAuthnContext` (first writer wins). On the **response** path it reverses
the rewrite and, if the IdP returned an unrequested value, falls back to the
highest-priority requested ACCR. It is *lenient*: a too-weak response is
downgraded-to-best-requested rather than rejected (eduID-faithful). When the
minimum is enforced, the rewrite map is intentionally not applied to the forced
range.

## Writing your own

Suppose we want a **response-path** service that rejects the flow unless the
authenticated user's email is in an allow-listed domain. Email only exists once
the backend has returned its attributes, so this is `process_response` work. Add
a module under `tunnelbana-plugins/src/microservices/` (and re-export it from
`microservices/mod.rs`), or keep it in your own crate:

```rust
use async_trait::async_trait;
use serde::Deserialize;
use tunnelbana_core::context::Context;
use tunnelbana_core::error::{Error, Result};
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{BuildContext, MicroService};

#[derive(Debug, Deserialize)]
struct AllowEmailsConfig {
    /// Email domains permitted to complete the flow, e.g. `["example.com"]`.
    #[serde(default)]
    allowed_domains: Vec<String>,
}

/// Aborts the flow unless the user's `mail` attribute is in an allowed domain.
pub struct AllowEmails {
    name: String,
    allowed_domains: Vec<String>,
}

impl AllowEmails {
    pub fn build(bx: &BuildContext) -> Result<Box<dyn MicroService>> {
        let cfg: AllowEmailsConfig = bx.parse_config()?;
        Ok(Box::new(AllowEmails { name: bx.name.clone(), allowed_domains: cfg.allowed_domains }))
    }
}

#[async_trait]
impl MicroService for AllowEmails {
    fn name(&self) -> &str { &self.name }

    async fn process_response(&self, _ctx: &mut Context, data: InternalData)
        -> Result<InternalData>
    {
        // `mail` is the *internal* attribute name (see the attribute map); the
        // backend has already mapped the protocol-specific claim onto it.
        let domain = data
            .attr_first("mail")
            .and_then(|email| email.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()));

        match domain {
            Some(d) if self.allowed_domains.iter().any(|a| a.eq_ignore_ascii_case(&d)) => Ok(data),
            // Returning an error here aborts the flow; the originating frontend
            // renders it as a protocol error (e.g. an OAuth access_denied).
            _ => Err(Error::Authn("email domain not allowed".into())),
        }
    }
}
```

Notes that come straight from the pipeline rules above:

- Implement **only** `process_response` here - `process_request`,
  `register_endpoints` and `handle_endpoint` keep their defaults. Because it runs
  on the response path, the backend's attributes (including `mail`) are already
  populated.
- Returning `Err(..)` from a transform aborts the flow; `render_error` hands it
  to the originating frontend's `handle_backend_error`, so the RP/SP sees a
  protocol-appropriate error rather than a raw 500.
- Need outbound HTTP (entitlement lookup, etc.)? Use `bx.http_client` - never a
  global client - so the service stays testable. Keep this crate **actix-free**.
- Need to remember something across the request/response halves of one flow?
  Stash it in `ctx.state` under your instance `name` (see the state-namespacing
  convention in [Writing a plugin](writing-a-plugin.md)).

## Wiring it in

Two steps: register the constructor under a `type` string, then reference that
type from config.

### 1. Register the constructor

The built-ins are registered in `register_all`
(`tunnelbana-plugins/src/lib.rs`). Add your line:

```rust
pub fn register_all(registry: &mut Registry) {
    // … existing frontends/backends …
    registry.register_microservice("static_attributes", microservices::StaticAttributes::build);
    registry.register_microservice("filter_attributes", microservices::FilterAttributes::build);
    registry.register_microservice("custom_routing",    microservices::CustomRouting::build);
    registry.register_microservice("allow_emails",      microservices::AllowEmails::build); // ← new
}
```

The registry is just a `type`-string → constructor lookup (a `HashMap`), so the
**order of these lines is irrelevant** - registering `allow_emails` before or
after `filter_attributes` makes no difference. Execution order is decided purely
by the order of the `[[microservice]]` blocks in the config (step 2); that's
where "before `filter_attributes`" matters.

If you'd rather not touch the bundled crate, register it in your **own binary**
after pulling in the built-ins:

```rust
let mut registry = Registry::new();
tunnelbana_plugins::register_all(&mut registry);          // the built-ins
registry.register_microservice("allow_emails", my_crate::AllowEmails::build);
```

### 2. Reference it from config

```toml
[[microservice]]
type = "allow_emails"       # the string you registered
name = "gate"               # unique instance label (see below)
  [microservice.config]
  allowed_domains = ["example.com", "example.org"]
```

`name` identifies *this instance* (as opposed to `type`, which picks the code).
The proxy uses it to (a) mount any endpoints the service registers under
`<base_url>/<name>/…` and route hits to it, (b) namespace whatever it stashes in
`ctx.state`, and (c) label it in the startup log - and it's what lets you run two
instances of the same `type` with different configs. This `allow_emails` service
registers no endpoints and uses no state, so here `name` is purely a label: pick
anything unique.

Remember the **order** of `[[microservice]]` blocks is the execution order on
both paths. Put a request-path router (`custom_routing`) before services that act
on the chosen backend; put response shapers (`static_attributes`,
`filter_attributes`) in the order you want them applied - typically inject first,
then filter. A response-path gate like this one reads an attribute (`mail`), so
list it **before** any `filter_attributes` that might strip that attribute,
otherwise the gate sees nothing to check.

## Rebuild and run

Micro-services live in the `tunnelbana-plugins` crate and are compiled into the
`tunnelbana` binary, so wiring one in is a recompile (not a config-only change).
Per the project's package rule, prefix anything that fetches from a registry
with `sfw`.

```bash
# compile (and pull any new deps through Socket Firewall)
sfw cargo build --workspace

# keep the suite green and clippy clean
cargo test --workspace
cargo clippy --workspace        # zero warnings

# run with your config
cargo run -p tunnelbana -- config/proxy.toml
```

On startup tunnelbana logs `loaded microservice name=… kind=…` for each one, and
**fails fast** if a `type` is not registered or a service rejects its own config
(e.g. a bad value in `[microservice.config]`). A successful boot with your new
line in the log means it's in the pipeline.
