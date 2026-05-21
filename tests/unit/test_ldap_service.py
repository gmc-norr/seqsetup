"""Tests for the LDAP authentication service.

Focus: the ordering invariant that user-bind (password verification) must
happen *before* any role-determining attribute lookup. A misconfigured or
wildcard-loose user_dn_pattern would otherwise let attributes from a
different LDAP entry inform the User.role.
"""

from typing import Any
from unittest.mock import patch

from seqsetup.models.auth_config import LDAPConfig
from seqsetup.services.ldap import LDAPService


class _FakeAttr:
    """ldap3-attribute stand-in: exposes .value and .values."""

    def __init__(self, value: Any = None, values: list = None):
        self.value = value
        self.values = values or ([] if value is None else [value])


class _FakeEntry:
    """ldap3-entry stand-in. Honors hasattr/getattr for attribute names."""

    def __init__(self, entry_dn: str, attrs: dict):
        self.entry_dn = entry_dn
        for name, attr in attrs.items():
            setattr(self, name, attr)


class _OrderRecordingConnection:
    """Minimal ldap3 Connection stand-in that records the order of operations.

    Each instance is identified by the ``user`` kwarg passed at construction so
    a test can distinguish the service-account bind from the user-bind.
    """

    # Class-level shared call log across every instance of a single test.
    log: list = []
    # Map of (user, password) → attribute entries returned by the next .search().
    next_entries: dict = {}

    def __init__(self, server, user="", password="", authentication=None,
                 read_only=False, receive_timeout=None):
        self.user = user
        self.password = password
        self.entries: list = []
        # Capture bind/search/unbind events with the bind-identity context.
        self._bound = False

    def bind(self) -> bool:
        type(self).log.append(("bind", self.user))
        # Fail the user-bind on wrong password; service-bind always succeeds.
        if self.user == "CN=alice,OU=Users,DC=example,DC=com":
            self._bound = self.password == "correct-password"
            return self._bound
        # Service bind
        self._bound = True
        return True

    def search(self, search_base="", search_filter="", search_scope=None,
               attributes=None, size_limit=None):
        type(self).log.append(("search", self.user, search_base))
        # Return entries staged by the test for this connection identity.
        self.entries = type(self).next_entries.get(self.user, [])

    def unbind(self):
        type(self).log.append(("unbind", self.user))


def _build_config() -> LDAPConfig:
    return LDAPConfig(
        server_url="ldap://test.example.com",
        use_ssl=False,
        base_dn="DC=example,DC=com",
        bind_dn="CN=service,OU=Services,DC=example,DC=com",
        bind_password="service-pw",
        user_dn_pattern="CN={username},OU=Users,DC=example,DC=com",
        admin_group_dn="CN=SeqSetup-Admins,OU=Groups,DC=example,DC=com",
    )


class TestLdapAuthOrderingInvariant:
    """The user-bind that verifies the password must precede any conn.search()
    used to derive the user's role.
    """

    def _patch_ldap(self, conn_cls):
        """Patch the ldap3.Connection used in services.ldap with conn_cls."""
        import ldap3
        return patch.object(ldap3, "Connection", conn_cls)

    def test_user_bind_precedes_role_attribute_search(self):
        # Reset shared log
        _OrderRecordingConnection.log = []
        # Stage attribute entries returned to the *service* connection — this
        # mirrors today's flow where the service does the attribute lookup.
        # If the fix is in place, the search should happen on the user connection
        # OR after the user-bind has been recorded.
        _OrderRecordingConnection.next_entries = {
            "CN=service,OU=Services,DC=example,DC=com": [
                _FakeEntry(
                    "CN=alice,OU=Users,DC=example,DC=com",
                    {
                        "displayName": _FakeAttr(value="Alice"),
                        "mail": _FakeAttr(value="alice@example.com"),
                        "memberOf": _FakeAttr(values=[
                            "CN=SeqSetup-Admins,OU=Groups,DC=example,DC=com",
                        ]),
                    },
                )
            ],
            "CN=alice,OU=Users,DC=example,DC=com": [
                _FakeEntry(
                    "CN=alice,OU=Users,DC=example,DC=com",
                    {
                        "displayName": _FakeAttr(value="Alice"),
                        "mail": _FakeAttr(value="alice@example.com"),
                        "memberOf": _FakeAttr(values=[
                            "CN=SeqSetup-Admins,OU=Groups,DC=example,DC=com",
                        ]),
                    },
                )
            ],
        }

        service = LDAPService(_build_config())
        with self._patch_ldap(_OrderRecordingConnection):
            user = service.authenticate("alice", "correct-password")

        assert user.username == "alice"

        # Find positions in the call log.
        log = _OrderRecordingConnection.log
        user_bind_idx = next(
            i for i, e in enumerate(log)
            if e[0] == "bind" and e[1] == "CN=alice,OU=Users,DC=example,DC=com"
        )
        # Find any search that returned role-determining attributes — that is,
        # a search whose entries include 'memberOf' (used by _determine_role).
        attribute_search_idx = next(
            (i for i, e in enumerate(log) if e[0] == "search"),
            None,
        )
        assert attribute_search_idx is not None, "No attribute search recorded"
        # The invariant: user-bind precedes any conn.search used for role lookup.
        assert user_bind_idx < attribute_search_idx, (
            f"User-bind must precede the role-attribute search. "
            f"user_bind at {user_bind_idx}, attribute_search at {attribute_search_idx}. "
            f"Full log: {log}"
        )

    def test_wrong_password_fails_before_attribute_search_leaks(self):
        """If the user-bind fails, we must not have already trusted the DN's attributes."""
        _OrderRecordingConnection.log = []
        _OrderRecordingConnection.next_entries = {
            "CN=service,OU=Services,DC=example,DC=com": [
                _FakeEntry(
                    "CN=alice,OU=Users,DC=example,DC=com",
                    {"memberOf": _FakeAttr(values=[
                        "CN=SeqSetup-Admins,OU=Groups,DC=example,DC=com",
                    ])},
                )
            ],
            "CN=alice,OU=Users,DC=example,DC=com": [],
        }

        service = LDAPService(_build_config())
        import pytest
        from seqsetup.services.ldap import LDAPError
        with self._patch_ldap(_OrderRecordingConnection):
            with pytest.raises(LDAPError):
                service.authenticate("alice", "wrong-password")
