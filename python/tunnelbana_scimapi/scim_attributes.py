"""Tunnelbana adapter for eduID's SATOSA ``ScimAttributes`` service.

The adapter deliberately contains no SATOSA objects.  It receives Tunnelbana's
strict copied context/data dictionaries, uses eduID's existing database model,
and returns JSON-compatible attributes plus an MFA-linked-account decoration
for a later native step-up service.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from typing import Any


logger = logging.getLogger(__name__)

MFA_STEPUP_ACCOUNTS = "mfa_stepup_accounts"
PROVIDER_SCOPES = "provider_scopes"
EPPN_EXTERNAL_NAME = "eduPersonPrincipalName"

_CONFIG_KEYS = frozenset(
    {
        "mongo_uri",
        "neo4j_uri",
        "neo4j_config",
        "allow_users_not_in_database",
        "fallback_data_owner",
        "idp_to_data_owner",
        "mfa_stepup_issuer_to_entity_id",
        "scope_to_data_owner",
        "virt_idp_to_data_owner",
    }
)


def _string(value: object, key: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value:
        raise TypeError(f"{key} must be a non-empty string")
    return value


def _string_map(value: object, key: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError(f"{key} must be a mapping")
    result: dict[str, str] = {}
    for source, target in value.items():
        if not isinstance(source, str) or not isinstance(target, str) or not target:
            raise TypeError(f"{key} must map strings to non-empty strings")
        result[source] = target
    return result


def _bool_map(value: object, key: str, default: bool) -> dict[str, bool]:
    if value is None:
        return {"default": default}
    if not isinstance(value, Mapping):
        raise TypeError(f"{key} must be a mapping")
    result: dict[str, bool] = {}
    for source, target in value.items():
        if not isinstance(source, str) or not isinstance(target, bool):
            raise TypeError(f"{key} must map strings to booleans")
        result[source] = target
    return result


def _attribute_values(value: object, external_name: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
        return list(value)
    raise TypeError(f"SCIM profile attribute {external_name!r} must contain string values")


class ScimAttributes:
    """Add an eduID SCIM profile and group entitlements to a response."""

    def __init__(
        self,
        name: str,
        base_url: str,
        config: dict[str, Any],
        internal_attributes: dict[str, dict[str, dict[str, Any]]],
    ) -> None:
        del name, base_url
        if not isinstance(config, dict):
            raise TypeError("config must be a dictionary")
        unknown = sorted(set(config) - _CONFIG_KEYS)
        if unknown:
            raise TypeError(
                f"unknown ScimAttributes configuration keys: {', '.join(unknown)}"
            )

        self.mongo_uri = _string(config.get("mongo_uri"), "mongo_uri")
        self.neo4j_uri = _string(config.get("neo4j_uri"), "neo4j_uri", optional=True)
        neo4j_config = config.get("neo4j_config", {})
        if not isinstance(neo4j_config, dict):
            raise TypeError("neo4j_config must be a dictionary")
        self.neo4j_config = dict(neo4j_config)
        self.allow_users_not_in_database = _bool_map(
            config.get("allow_users_not_in_database"),
            "allow_users_not_in_database",
            False,
        )
        self.fallback_data_owner = _string(
            config.get("fallback_data_owner"), "fallback_data_owner", optional=True
        )
        self.idp_to_data_owner = _string_map(config.get("idp_to_data_owner"), "idp_to_data_owner")
        self.mfa_stepup_issuer_to_entity_id = _string_map(
            config.get("mfa_stepup_issuer_to_entity_id"),
            "mfa_stepup_issuer_to_entity_id",
        )
        self.scope_to_data_owner = _string_map(
            config.get("scope_to_data_owner"), "scope_to_data_owner"
        )
        self.virt_idp_to_data_owner = _string_map(
            config.get("virt_idp_to_data_owner"), "virt_idp_to_data_owner"
        )

        self._saml_attributes = self._parse_internal_attributes(internal_attributes)
        eppn_matches = [
            internal
            for internal, external_names in self._saml_attributes.items()
            if EPPN_EXTERNAL_NAME in external_names
        ]
        if len(eppn_matches) != 1:
            raise TypeError(
                "the attribute map must map eduPersonPrincipalName to exactly one internal attribute"
            )
        self.external_id_attribute = eppn_matches[0]
        # Resolve the optional integration dependency during construction. The
        # module remains harmless when it is installed but not configured;
        # once configured, a missing or incompatible eduID package must fail
        # proxy startup rather than the first live database lookup.
        self._userdb_class, self._groupdb_class = self._load_database_classes()
        self._userdbs: dict[str, Any] = {}
        self._groupdbs: dict[str, Any] = {}
        self._cache_lock = threading.Lock()

    @staticmethod
    def _parse_internal_attributes(
        value: object,
    ) -> dict[str, tuple[str, ...]]:
        if not isinstance(value, Mapping):
            raise TypeError("internal_attributes must be a mapping")
        result: dict[str, tuple[str, ...]] = {}
        for internal_name, profiles in value.items():
            if not isinstance(internal_name, str) or not isinstance(profiles, Mapping):
                raise TypeError("invalid internal attribute map")
            saml = profiles.get("saml")
            if saml is None:
                continue
            if not isinstance(saml, Mapping):
                raise TypeError("normalized SAML attribute mapping must be a mapping")
            names = saml.get("names", [])
            oid = saml.get("oid")
            friendly_name = saml.get("friendly_name")
            if not isinstance(names, list) or not all(isinstance(item, str) for item in names):
                raise TypeError("normalized SAML names must be a string list")
            candidates = list(names)
            for extra in (oid, friendly_name):
                if extra is not None:
                    if not isinstance(extra, str):
                        raise TypeError("normalized SAML OID and friendly name must be strings")
                    candidates.append(extra)
            # Preserve priority while avoiding repeated aliases.
            result[internal_name] = tuple(dict.fromkeys(candidates))
        return result

    @staticmethod
    def _load_database_classes() -> tuple[type[Any], type[Any]]:
        from eduid.userdb.scimapi import ScimApiGroupDB
        from eduid.userdb.scimapi.userdb import ScimApiUserDB

        return ScimApiUserDB, ScimApiGroupDB

    def _new_userdb(self, data_owner: str) -> Any:
        owner = data_owner.replace(".", "_")
        collection = "profiles" if data_owner == "eduid.se" else f"{owner}__users"
        return self._userdb_class(
            db_uri=self.mongo_uri,
            collection=collection,
            setup_indexes=False,
        )

    def _new_groupdb(self, data_owner: str) -> Any:
        owner = data_owner.replace(".", "_")
        return self._groupdb_class(
            neo4j_uri=self.neo4j_uri,
            neo4j_config=self.neo4j_config,
            scope=data_owner,
            mongo_uri=self.mongo_uri,
            mongo_dbname="eduid_scimapi",
            mongo_collection=f"{owner}__groups",
            setup_indexes=False,
        )

    def _userdb(self, data_owner: str) -> Any:
        with self._cache_lock:
            database = self._userdbs.get(data_owner)
            if database is None:
                database = self._new_userdb(data_owner)
                self._userdbs[data_owner] = database
            return database

    def _groupdb(self, data_owner: str) -> Any | None:
        if self.neo4j_uri is None:
            return None
        with self._cache_lock:
            database = self._groupdbs.get(data_owner)
            if database is None:
                database = self._new_groupdb(data_owner)
                self._groupdbs[data_owner] = database
            return database

    def _data_owner(self, context: dict[str, Any], data: dict[str, Any]) -> str | None:
        frontend = context.get("target_frontend")
        if isinstance(frontend, str):
            owner = self.virt_idp_to_data_owner.get(frontend)
            if owner:
                return owner

        issuer = data.get("auth_info", {}).get("issuer")
        if isinstance(issuer, str):
            owner = self.idp_to_data_owner.get(issuer)
            if owner:
                return owner

        # Preserve the SATOSA service's precedence: an explicit fallback wins
        # over scope-derived selection.
        if self.fallback_data_owner is not None:
            return self.fallback_data_owner

        scopes = context.get("decorations", {}).get(PROVIDER_SCOPES, [])
        if isinstance(scopes, list):
            for scope in sorted(item for item in scopes if isinstance(item, str)):
                owner = self.scope_to_data_owner.get(scope)
                if owner:
                    return owner
        return None

    def _mapped_profile(self, external: Mapping[str, Any]) -> dict[str, list[str]]:
        mapped: dict[str, list[str]] = {}
        for internal_name, candidates in self._saml_attributes.items():
            values: list[str] = []
            for external_name in candidates:
                if external_name not in external:
                    continue
                for item in _attribute_values(external[external_name], external_name):
                    if item not in values:
                        values.append(item)
            if values:
                mapped[internal_name] = values
        return mapped

    def _apply_user(self, context: dict[str, Any], data: dict[str, Any], user: Any) -> None:
        profiles = getattr(user, "profiles", {})
        if not isinstance(profiles, Mapping):
            raise TypeError("SCIM user profiles must be a mapping")
        if profiles:
            profile_name = min(profiles)
            profile = profiles[profile_name]
            external = getattr(profile, "attributes", None)
            if not isinstance(external, Mapping):
                raise TypeError("SCIM profile attributes must be a mapping")
            data["attributes"].update(self._mapped_profile(external))

        accounts: list[dict[str, str]] = []
        for account in getattr(user, "linked_accounts", []):
            issuer = getattr(account, "issuer", None)
            identifier = getattr(account, "value", None)
            parameters = getattr(account, "parameters", None)
            if not isinstance(parameters, Mapping) or parameters.get("mfa_stepup") is not True:
                continue
            entity_id = self.mfa_stepup_issuer_to_entity_id.get(issuer)
            if entity_id and isinstance(identifier, str) and identifier:
                accounts.append(
                    {
                        "entity_id": entity_id,
                        "identifier": identifier,
                        "attribute": "eduPersonPrincipalName",
                        "assurance": "eduPersonAssurance",
                    }
                )
        context["decorations"][MFA_STEPUP_ACCOUNTS] = accounts

    def _apply_groups(self, data: dict[str, Any], data_owner: str, user: Any) -> None:
        database = self._groupdb(data_owner)
        if database is None:
            return
        user_id = getattr(user, "scim_id", None)
        if user_id is None:
            raise TypeError("SCIM user has no scim_id")
        scope = database.graphdb.scope
        entitlements = data["attributes"].setdefault("edupersonentitlement", [])
        groups = database.get_groups_for_user_identifer(user_id)
        managed = database.get_groups_owned_by_user_identifier(user_id)
        for group in groups:
            value = f"{scope}:group:{group.graph.identifier}#eduid-iam"
            if value not in entitlements:
                entitlements.append(value)
        for group in managed:
            value = f"{scope}:group:{group.graph.identifier}:role=manager#eduid-iam"
            if value not in entitlements:
                entitlements.append(value)

    def _allow_unresolved_user(self, context: dict[str, Any]) -> bool:
        return self.allow_users_not_in_database.get(
            context.get("target_frontend"),
            self.allow_users_not_in_database.get("default", False),
        )

    def process_response(
        self, context: dict[str, Any], data: dict[str, Any]
    ) -> dict[str, Any]:
        # Always publish a deterministic empty value, including pass-through
        # paths. A later step-up service never has to distinguish absent from
        # stale account data.
        context["decorations"][MFA_STEPUP_ACCOUNTS] = []
        data_owner = self._data_owner(context, data)
        if data_owner == "no-scim":
            return data
        if data_owner is None:
            if not self._allow_unresolved_user(context):
                raise PermissionError("no SCIM data owner could be resolved")
            logger.info("SCIM data owner was unresolved; allowing by policy")
            return data

        external_ids = data["attributes"].get(self.external_id_attribute, [])
        user = None
        if len(external_ids) == 1:
            user = self._userdb(data_owner).get_user_by_external_id(external_ids[0])

        if user is None:
            if not self._allow_unresolved_user(context):
                raise PermissionError("user is not present in the SCIM database")
            logger.info("SCIM lookup did not resolve a user; allowing by policy")
            return data

        self._apply_user(context, data, user)
        self._apply_groups(data, data_owner, user)
        logger.info("applied SCIM response enrichment")
        return data
