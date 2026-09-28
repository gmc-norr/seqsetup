"""Tests for the authentication route helpers (separate from AuthService)."""

from datetime import datetime

import mongomock

from seqsetup.models.user import User, UserRole
from seqsetup.repositories.web_session_repo import WebSessionRepository
from seqsetup.routes.auth import _login_user
from seqsetup.services import web_sessions
from seqsetup.services.web_sessions import SessionPolicy

NOW = datetime(2026, 9, 27, 8, 0, 0)
POLICY = SessionPolicy(1800, 28800)


def _repo():
    return WebSessionRepository(mongomock.MongoClient()["t"])


def _user(name, role=UserRole.STANDARD):
    return User(username=name, display_name=name, role=role, source="ldap")


class TestLoginUserSessionFixationDefence:
    """The login helper must regenerate the session contents before applying
    the authenticated user, so an attacker-planted session cannot ride a
    legitimate login on a shared workstation.
    """

    def test_login_clears_prior_session_data(self):
        sess: dict = {"attacker_planted_key": "malicious_value"}
        _login_user(sess, _user("alice"), _repo(), NOW, POLICY)
        assert "attacker_planted_key" not in sess

    def test_login_records_the_user_server_side(self):
        sess: dict = {}
        repo = _repo()
        _login_user(sess, _user("alice", UserRole.ADMIN), repo, NOW, POLICY)
        user = web_sessions.resolve(repo, None, sess["sid"], NOW, POLICY)
        assert (user.username, user.role) == ("alice", UserRole.ADMIN)

    def test_each_login_gets_a_new_ticket(self):
        repo = _repo()
        a, b = {}, {}
        _login_user(a, _user("alice"), repo, NOW, POLICY)
        _login_user(b, _user("alice"), repo, NOW, POLICY)
        assert a["sid"] != b["sid"]
