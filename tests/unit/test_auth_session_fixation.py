"""Unit test for _login_user's session-fixation defense.

The defense: _login_user() calls sess.clear() before recording the new
login. Without the clear, an attacker who plants a known session on a
shared workstation would keep any keys they placed in it after a
legitimate user logs in.
"""

from datetime import datetime

import mongomock

from seqsetup.models.user import User, UserRole
from seqsetup.repositories.web_session_repo import WebSessionRepository
from seqsetup.routes.auth import _login_user
from seqsetup.services.web_sessions import SessionPolicy

NOW = datetime(2026, 9, 27, 8, 0, 0)
POLICY = SessionPolicy(1800, 28800)


def _user(name):
    return User(username=name, display_name=name, role=UserRole.ADMIN, source="yaml")


def _sessions():
    return WebSessionRepository(mongomock.MongoClient()["t"])


def test_login_user_clears_pre_planted_session_keys():
    """_login_user wipes any pre-existing session keys, including a planted ticket."""
    sess = {"attacker_planted_key": "evil_value", "csrf_token": "stale_token",
            "sid": "planted-ticket"}
    _login_user(sess, _user("alice"), _sessions(), NOW, POLICY)
    assert set(sess) == {"sid"} and sess["sid"] != "planted-ticket"


def test_login_user_starts_from_empty_session_correctly():
    """_login_user works correctly when there's nothing to clear."""
    sess = {}
    _login_user(sess, _user("bob"), _sessions(), NOW, POLICY)
    assert set(sess) == {"sid"}
