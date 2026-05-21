"""Tests for the authentication route helpers (separate from AuthService)."""

from dataclasses import dataclass

from seqsetup.routes.auth import _login_user


@dataclass
class _FakeUser:
    """Minimal stand-in matching the to_dict() contract used by the login route."""

    username: str
    role: str = "standard"

    def to_dict(self) -> dict:
        return {"username": self.username, "role": self.role}


class TestLoginUserSessionFixationDefence:
    """The login helper must regenerate the session contents before applying
    the authenticated user, so an attacker-planted session ID cannot ride a
    legitimate login on a shared workstation.
    """

    def test_login_clears_prior_session_data(self):
        sess: dict = {"attacker_planted_key": "malicious_value"}
        user = _FakeUser(username="alice")

        _login_user(sess, user)

        # Any prior session data must be gone — only the authenticated user remains.
        assert "attacker_planted_key" not in sess

    def test_login_sets_authenticated_user(self):
        sess: dict = {}
        user = _FakeUser(username="alice", role="admin")

        _login_user(sess, user)

        assert sess.get("user") == {"username": "alice", "role": "admin"}

    def test_login_replaces_stale_user(self):
        """A previously-logged-in user dict in the session must be replaced, not merged."""
        sess: dict = {"user": {"username": "stale", "role": "standard"}}
        new_user = _FakeUser(username="fresh", role="admin")

        _login_user(sess, new_user)

        assert sess.get("user") == {"username": "fresh", "role": "admin"}
