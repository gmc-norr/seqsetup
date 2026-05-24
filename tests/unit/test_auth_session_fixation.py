"""Unit test for _login_user's session-fixation defense.

The defense: _login_user() calls sess.clear() before setting
sess["user"] = user.to_dict(). Without the clear, an attacker who
plants a known session ID on a shared workstation would retain that
session — including any keys they placed in it — after a legitimate
user logs in.
"""

from seqsetup.routes.auth import _login_user


class _FakeUser:
    def __init__(self, username, role="admin"):
        self.username = username
        self.role = role

    def to_dict(self):
        return {"username": self.username, "role": self.role}


def test_login_user_clears_pre_planted_session_keys():
    """_login_user wipes any pre-existing session keys."""
    sess = {
        "attacker_planted_key": "evil_value",
        "csrf_token": "stale_token",
        "user": {"username": "old_session_user"},
    }
    _login_user(sess, _FakeUser("alice"))
    # Everything the attacker planted is gone.
    assert "attacker_planted_key" not in sess
    assert "csrf_token" not in sess
    # The new user is set.
    assert sess["user"] == {"username": "alice", "role": "admin"}


def test_login_user_starts_from_empty_session_correctly():
    """_login_user works correctly when there's nothing to clear."""
    sess = {}
    _login_user(sess, _FakeUser("bob"))
    assert sess == {"user": {"username": "bob", "role": "admin"}}
