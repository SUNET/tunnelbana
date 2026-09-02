"""In-memory eduID-like objects used by the Rust/Python boundary tests."""

from __future__ import annotations

from types import SimpleNamespace

from tunnelbana_scimapi.scim_attributes import ScimAttributes


class _UserDb:
    def __init__(self, users):
        self.users = users

    def get_user_by_external_id(self, external_id):
        raw = self.users.get(external_id)
        if raw is None:
            return None
        profiles = {
            name: SimpleNamespace(attributes=attributes)
            for name, attributes in raw.get("profiles", {}).items()
        }
        accounts = [SimpleNamespace(**account) for account in raw.get("linked_accounts", [])]
        return SimpleNamespace(
            scim_id=raw.get("scim_id", "user-id"),
            profiles=profiles,
            linked_accounts=accounts,
        )


class _GroupDb:
    def __init__(self, scope, member, manager):
        self.graphdb = SimpleNamespace(scope=scope)
        self.member = [SimpleNamespace(graph=SimpleNamespace(identifier=x)) for x in member]
        self.manager = [SimpleNamespace(graph=SimpleNamespace(identifier=x)) for x in manager]

    def get_groups_for_user_identifer(self, user_id):
        del user_id
        return self.member

    def get_groups_owned_by_user_identifier(self, user_id):
        del user_id
        return self.manager


class FakeScimAttributes(ScimAttributes):
    def __init__(self, name, base_url, config, internal_attributes):
        config = dict(config)
        self._fake_users = config.pop("fake_users", {})
        self._fake_groups = config.pop("fake_groups", {})
        super().__init__(name, base_url, config, internal_attributes)

    @staticmethod
    def _load_database_classes():
        # Database construction is replaced below, so boundary tests do not
        # require the optional eduID distribution.
        return None, None

    def _new_userdb(self, data_owner):
        return _UserDb(self._fake_users.get(data_owner, {}))

    def _new_groupdb(self, data_owner):
        groups = self._fake_groups.get(data_owner, {})
        return _GroupDb(
            groups.get("scope", data_owner),
            groups.get("member", []),
            groups.get("manager", []),
        )


class MissingDependencyScimAttributes(ScimAttributes):
    @staticmethod
    def _load_database_classes():
        raise ModuleNotFoundError("simulated missing eduid.userdb.scimapi")
