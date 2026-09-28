"""Sign-in checks (spec 2026-09-28 group 2b): database accounts only, one
name limit, and the directory first, then the local fallback."""

import inspect
from pathlib import Path
from unittest.mock import patch

import mongomock
import pytest

from seqsetup.models.auth_config import AuthConfig, AuthMethod, LDAPConfig
from seqsetup.models.local_user import LocalUser
from seqsetup.repositories.local_user_repo import LocalUserRepository
from seqsetup.services.auth import AuthenticationError, AuthService
from seqsetup.services.ldap import SignInRefused

SRC = Path(__file__).resolve().parents[2] / "src" / "seqsetup"
PW = "Strong-Passw0rd!"
LDAP_SERVICE = "seqsetup.services.ldap.LDAPService"


def _repo(*names):
    repo = LocalUserRepository(mongomock.MongoClient()["t"])
    for name in names:
        user = LocalUser(username=name, display_name=name.title())
        user.set_password(PW)
        repo.save(user)
    return repo


def _ready_directory(fallback):
    return AuthConfig(
        auth_method=AuthMethod.ACTIVE_DIRECTORY, allow_local_fallback=fallback,
        ldap_config=LDAPConfig(server_url="ldaps://dc.example.org", base_dn="dc=example,dc=org",
                               user_dn_pattern="{username}@lab.example.org",
                               user_group_dn="cn=u,dc=example,dc=org",
                               admin_group_dn="cn=a,dc=example,dc=org"))


def _service(repo, config=None):
    return AuthService(get_auth_config=(lambda: config) if config else None,
                       get_local_user_repo=lambda: repo)


class TestLocalAccounts:
    """Local accounts live only in the database (N-20, F25)."""

    def test_database_account_signs_in(self):
        user = _service(_repo("alice")).authenticate("alice", PW)
        assert (user.username, user.source) == ("alice", "local")

    def test_wrong_password_has_no_second_place_to_try(self):
        with pytest.raises(AuthenticationError) as refused:
            _service(_repo("alice")).authenticate("alice", "Other-Passw0rd!")
        assert refused.value.reason == "local_refused"

    def test_unknown_name_runs_one_dummy_check(self, monkeypatch):
        service = _service(_repo("alice"))
        calls = []
        monkeypatch.setattr(service, "_verify_password", lambda pw, h: calls.append(h) or False)
        with pytest.raises(AuthenticationError):
            service.authenticate("ghost-user", PW)
        assert len(calls) == 1

    def test_known_name_runs_no_dummy_check(self, monkeypatch):
        service = _service(_repo("alice"))
        calls = []
        monkeypatch.setattr(service, "_verify_password", lambda pw, h: calls.append(h) or False)
        with pytest.raises(AuthenticationError):
            service.authenticate("alice", "Other-Passw0rd!")
        assert calls == []

    def test_no_code_reads_the_users_file(self):
        assert "config_path" not in inspect.signature(AuthService).parameters
        assert not hasattr(AuthService, "_load_users")
        mentions = sorted(path.relative_to(SRC).as_posix() for path in SRC.rglob("*.py")
                          if "users.yaml" in path.read_text())
        assert mentions == ["startup.py"]      # only its start-up warning


class TestNameLimit:
    """One limit, 64 characters; a longer name is refused, never cut (review P3)."""

    def test_65_characters_is_refused_before_any_lookup(self):
        repo = _repo("a" * 64)
        looked_up = []
        real = repo.get_by_username
        repo.get_by_username = lambda name: looked_up.append(name) or real(name)
        with pytest.raises(AuthenticationError) as refused:
            _service(repo).authenticate("a" * 65, PW)
        assert refused.value.reason == "bad_name" and looked_up == []

    def test_64_characters_signs_in(self):
        assert _service(_repo("a" * 64)).authenticate("a" * 64, PW).username == "a" * 64


class TestDirectoryThenLocal:
    """The directory first; the local accounts only when fallback is on."""

    def test_refusal_without_fallback_is_final(self):
        with patch(LDAP_SERVICE) as svc:
            svc.return_value.authenticate.side_effect = SignInRefused("directory_refused")
            with pytest.raises(AuthenticationError) as refused:
                _service(_repo("alice"), _ready_directory(False)).authenticate("alice", PW)
        assert (refused.value.reason, refused.value.local_tried) == ("directory_refused", False)

    def test_refusal_with_fallback_tries_local(self):
        with patch(LDAP_SERVICE) as svc:
            svc.return_value.authenticate.side_effect = SignInRefused("not_in_group")
            user = _service(_repo("alice"), _ready_directory(True)).authenticate("alice", PW)
        assert user.source == "local"

    def test_both_refusing_keeps_the_directory_reason(self):
        with patch(LDAP_SERVICE) as svc:
            svc.return_value.authenticate.side_effect = SignInRefused("not_in_group")
            with pytest.raises(AuthenticationError) as refused:
                _service(_repo("alice"), _ready_directory(True)).authenticate(
                    "alice", "Other-Passw0rd!")
        assert (refused.value.reason, refused.value.local_tried) == ("not_in_group", True)

    def test_unreachable_directory_falls_back_to_local(self):
        # Plan decision 1: a server error is a refusal like any other.
        with patch(LDAP_SERVICE) as svc:
            svc.return_value.authenticate.side_effect = SignInRefused(
                "server_error", "Connection refused")
            user = _service(_repo("alice"), _ready_directory(True)).authenticate("alice", PW)
        assert user.source == "local"

    def test_unexpected_directory_error_is_a_server_error(self):
        with patch(LDAP_SERVICE) as svc:
            svc.return_value.authenticate.side_effect = RuntimeError("boom")
            with pytest.raises(AuthenticationError) as refused:
                _service(_repo("alice"), _ready_directory(False)).authenticate("alice", PW)
        assert refused.value.reason == "server_error"
