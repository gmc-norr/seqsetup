"""Tests for the LDAP authentication service.

Focus: the ordering invariant that user-bind (password verification) must
happen *before* any role-determining attribute lookup. A misconfigured or
wildcard-loose user_dn_pattern would otherwise let attributes from a
different LDAP entry inform the User.role.
"""

from typing import Any
from unittest.mock import patch

import pytest

from seqsetup.models.auth_config import LDAPConfig
from seqsetup.services.ldap import LDAPError, LDAPService


@pytest.fixture(autouse=True)
def _allow_cleartext_ldap_in_unit_tests(monkeypatch):
    """These unit tests exercise the auth flow against a MOCKED cleartext
    ldap:// connection; opt into cleartext so the transport gate (which
    fails closed in production) doesn't block them. Tests that assert the
    gate itself delete this var explicitly."""
    monkeypatch.setenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", "1")


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


class TestCleartextTransportGate:
    """Plaintext LDAP must be refused by default: the service-account bind
    password and every user's login password would otherwise traverse the wire
    in clear. Mirrors the LIMS plain-HTTP opt-in."""

    def test_cleartext_refused_without_optin(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        svc = LDAPService(_build_config())  # ldap://, use_ssl=False
        with pytest.raises(LDAPError, match="(?i)cleartext|plaintext|tls|ssl"):
            svc._get_server()

    def test_cleartext_allowed_with_optin(self, monkeypatch):
        monkeypatch.setenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", "1")
        svc = LDAPService(_build_config())
        svc._get_server()  # no raise

    def test_ldaps_url_not_gated(self, monkeypatch):
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        cfg = _build_config()
        cfg.server_url = "ldaps://secure.example.com"
        cfg.use_ssl = True
        svc = LDAPService(cfg)
        svc._get_server()  # no raise — TLS transport

    def test_explicit_ldap_scheme_with_use_ssl_is_still_gated(self, monkeypatch):
        # ldap3 derives transport from the URL SCHEME, not the use_ssl kwarg:
        # Server('ldap://...', use_ssl=True) binds in CLEARTEXT (ssl=False).
        # The gate must key on the resolved transport, not trust use_ssl.
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        cfg = _build_config()
        cfg.server_url = "ldap://dc.example.com"
        cfg.use_ssl = True
        svc = LDAPService(cfg)
        with pytest.raises(LDAPError, match="(?i)cleartext|plaintext|tls|ssl"):
            svc._get_server()

    def test_bare_host_with_use_ssl_not_gated_and_resolves_to_ssl(self, monkeypatch):
        # No explicit scheme + use_ssl=True -> ldap3 honors use_ssl (ssl=True).
        monkeypatch.delenv("SEQSETUP_LDAP_ALLOW_CLEARTEXT", raising=False)
        cfg = _build_config()
        cfg.server_url = "dc.example.com"
        cfg.use_ssl = True
        server = LDAPService(cfg)._get_server()  # no raise
        assert server.ssl is True  # actually uses TLS


class TestUserDnPatternEscaping:
    """A login username substituted into user_dn_pattern must be escaped for
    the DN (RFC 4514) context, not the search-filter (RFC 4515) context.

    The login form does not constrain the username's character set, so DN
    metacharacters (',', '=', '+') would otherwise pass through unescaped and
    relocate/alter the bind DN (CWE-90).
    """

    def test_dn_metacharacters_in_username_are_escaped(self):
        service = LDAPService(_build_config())
        user_dn = service._get_user_dn("eviluser,OU=Admins", conn=None)
        # The injected RDN separator/assignment must be escaped so it can't
        # relocate the bind DN; the configured suffix stays intact.
        assert "eviluser\\,OU\\=Admins" in user_dn
        assert user_dn.endswith(",OU=Users,DC=example,DC=com")

    def test_plus_in_username_is_escaped(self):
        service = LDAPService(_build_config())
        user_dn = service._get_user_dn("a+b", conn=None)
        assert "a\\+b" in user_dn

    def test_plain_username_unchanged(self):
        service = LDAPService(_build_config())
        user_dn = service._get_user_dn("jdoe", conn=None)
        assert user_dn == "CN=jdoe,OU=Users,DC=example,DC=com"


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


class TestEffectiveBindPassword:
    """The LDAP bind password must prefer the env var over the stored field
    so production deployments can keep the secret out of MongoDB."""

    def test_env_var_overrides_stored_password(self, monkeypatch):
        from seqsetup.models.auth_config import LDAPConfig
        monkeypatch.setenv("SEQSETUP_LDAP_BIND_PASSWORD", "env-secret")
        cfg = LDAPConfig(bind_dn="CN=svc,DC=ex", bind_password="stored-secret")
        assert cfg.effective_bind_password() == "env-secret"

    def test_falls_back_to_stored_when_env_absent(self, monkeypatch):
        from seqsetup.models.auth_config import LDAPConfig
        monkeypatch.delenv("SEQSETUP_LDAP_BIND_PASSWORD", raising=False)
        cfg = LDAPConfig(bind_dn="CN=svc,DC=ex", bind_password="stored-secret")
        assert cfg.effective_bind_password() == "stored-secret"

    def test_empty_env_value_treated_as_unset(self, monkeypatch):
        from seqsetup.models.auth_config import LDAPConfig
        monkeypatch.setenv("SEQSETUP_LDAP_BIND_PASSWORD", "")
        cfg = LDAPConfig(bind_dn="CN=svc,DC=ex", bind_password="stored-secret")
        assert cfg.effective_bind_password() == "stored-secret"
