# eduID SCIM response attributes

Tunnelbana includes a Python adapter for eduID's SATOSA `ScimAttributes`
micro-service. It enriches a validated upstream authentication response from
the eduID SCIM database before the originating frontend renders it.

This page covers SCIM attribute enrichment. The adapter publishes linked
MFA-account information consumed by the optional native
[step-up service](stepup.md).

## Runtime and files

The adapter is bundled at `python/tunnelbana_scimapi` (and at `/app/python` in
the official container). Point the embedded runtime's import root at the
repository/deployment `python` directory. Paths are relative to `proxy.toml`:

```toml
[python]
module_path = "../python"
venv = "../python-venv"
max_concurrent_calls = 16
call_timeout_seconds = 30
```

The virtual environment must contain the eduID package that provides
`eduid.userdb.scimapi`, including its PyMongo and Neo4j dependencies. The eduID
package imports its group database and Neo4j driver at module load even when
`neo4j_uri` is omitted and group lookup is disabled. Tunnelbana never installs
packages at startup. Configuring `ScimAttributes` imports the eduID user and
group database classes during plugin construction, so a missing or incompatible
dependency fails Tunnelbana startup. When the micro-service is not configured,
the eduID package and its dependencies are not imported or required.

Configure MongoDB and Neo4j connection, server-selection and socket timeouts
below `python.call_timeout_seconds`. A timed-out Python call cannot be killed;
it retains one concurrency permit until the database driver returns.

## Micro-service configuration

```toml
[[microservice]]
type = "python"
name = "ScimAttributes"

[microservice.config]
module = "tunnelbana_scimapi.scim_attributes"
class = "ScimAttributes"
pass_internal_attributes = true

[microservice.config.settings]
mongo_uri = "${EDUID_SCIM_MONGO_URI}"
neo4j_uri = "${EDUID_SCIM_NEO4J_URI}" # optional; omit to disable groups

[microservice.config.settings.neo4j_config]
encrypted = true

[microservice.config.settings.allow_users_not_in_database]
default = false
EntraFrontend = true

[microservice.config.settings.virt_idp_to_data_owner]
SchoolFrontend = "school.example"
EntraFrontend = "no-scim"

[microservice.config.settings.idp_to_data_owner]
"https://idp.example/idp.xml" = "example.org"

[microservice.config.settings.scope_to_data_owner]
"example.org" = "example.org"

# Maps database issuer values to entity IDs accepted by the optional step-up
# service. ScimAttributes alone still performs no redirect.
[microservice.config.settings.mfa_stepup_issuer_to_entity_id]
"eduid.se" = "https://login.idp.eduid.se/idp.xml"

# Used after the explicit virtual-IdP and IdP mappings, but before scopes.
# fallback_data_owner = "eduid.se"
```

`pass_internal_attributes = true` is required. At startup the service locates
the one internal attribute whose SAML mapping recognizes
`eduPersonPrincipalName`. Startup fails if none or more than one exists.

## Processing behavior

The service runs only on the response path and selects a data owner in this
order:

1. `virt_idp_to_data_owner[context.target_frontend]`.
2. `idp_to_data_owner[data.auth_info.issuer]`.
3. `fallback_data_owner`, when configured.
4. The first lexicographically sorted trusted `provider_scopes` value present
   in `scope_to_data_owner`.

No resolved owner is treated like an unresolved user: it fails closed unless
`allow_users_not_in_database` permits that frontend. The special owner
`no-scim` is an unconditional pass-through. Every successful non-enrichment
path publishes `mfa_stepup_accounts` as an empty decoration.

For an active owner, the adapter can perform the lookup only when the mapped
internal `eduPersonPrincipalName` has exactly one value. Any other count is
treated like an unresolved user. The adapter looks up the single value as the
SCIM `external_id`. When the identity is unresolved or no user is found,
`allow_users_not_in_database` is checked first by frontend name and then by
`default`; the default is `false`.

When a user is found:

- The lexicographically first profile name is selected, matching the eduID
  service's current behavior.
- Profile attributes are interpreted as SAML names/OIDs/friendly names and
  converted through Tunnelbana's attribute map. Mapped SCIM values replace the
  corresponding upstream internal values.
- When Neo4j is enabled, membership adds
  `<owner>:group:<id>#eduid-iam`; ownership adds
  `<owner>:group:<id>:role=manager#eduid-iam`.
- Eligible linked accounts are copied to the non-persistent
  `mfa_stepup_accounts` decoration as plain JSON. Frontends never release this
  decoration as an attribute.

Invalid SCIM profile value types, database errors, and unresolved users not
allowed by policy fail the authentication through Tunnelbana's normal
sanitized Python-error path.

## Trusted provider scopes

For an MDQ SAML backend, Tunnelbana extracts Shibboleth `<Scope>` values from
the selected IdP role's metadata. Under the default MDQ policy the metadata is
signature-verified; do not use the unsafe `mdq.allow_unverified` test setting
in production. The values become available to response micro-services only
after the SAML response passes signature, issuer, audience, time,
request-correlation and replay validation.

A statically configured backend has no IdP metadata document to inspect. When
scope-based owner selection is needed, configure the equivalent values:

```toml
[backend.config]
idp_scopes = ["example.org"]
```

Prefer explicit `virt_idp_to_data_owner` or `idp_to_data_owner` mappings when
possible. They are simpler to audit than metadata-derived tenant selection.

## Migration from SATOSA

The following SATOSA settings retain their names and semantics:

- `mongo_uri`, `neo4j_uri`, `neo4j_config`
- `allow_users_not_in_database`
- `fallback_data_owner`
- `idp_to_data_owner`, `scope_to_data_owner`, `virt_idp_to_data_owner`
- `mfa_stepup_issuer_to_entity_id`

Do not copy `only_configure_and_expose_scim`. SATOSA used it to place a live
`ScimAttributes` object in `InternalData` for the step-up plugin. Tunnelbana's
strict JSON boundary replaces that coupling with the
`mfa_stepup_accounts` decoration.
