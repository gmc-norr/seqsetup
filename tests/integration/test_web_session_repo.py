"""The login list is a thin store: create, read, touch, delete."""

from datetime import datetime, timedelta

import mongomock
import pytest

from seqsetup.models.user import UserRole
from seqsetup.models.web_session import WebSession
from seqsetup.repositories.web_session_repo import WebSessionRepository

T0 = datetime(2026, 9, 27, 8, 0, 0)


@pytest.fixture
def repo():
    return WebSessionRepository(mongomock.MongoClient()["t"])


def _id(i):
    return f"{i:064x}"


def _ws(i, username="alice", created=T0, seen=T0):
    return WebSession(id=_id(i), username=username, display_name=username,
                      role=UserRole.STANDARD, source="local", session_stamp="",
                      created_at=created, last_seen_at=seen)


class TestWebSessionRepository:
    """Each method does one thing."""

    def test_create_and_get(self, repo):
        repo.create(_ws(1))
        assert repo.get(_id(1)).username == "alice"
        assert repo.get("nope") is None

    def test_touch_moves_forward_only(self, repo):
        repo.create(_ws(1))
        repo.touch(_id(1), T0 + timedelta(minutes=5))
        repo.touch(_id(1), T0 + timedelta(minutes=1))
        assert repo.get(_id(1)).last_seen_at == T0 + timedelta(minutes=5)

    def test_delete_one(self, repo):
        repo.create(_ws(1))
        repo.create(_ws(2))
        repo.delete(_id(1))
        assert repo.get(_id(1)) is None and repo.get(_id(2)) is not None

    def test_delete_for_user_leaves_others(self, repo):
        repo.create(_ws(1))
        repo.create(_ws(2))
        repo.create(_ws(3, username="bob"))
        assert repo.delete_for_user("alice") == 2
        assert repo.get(_id(3)) is not None

    def test_delete_expired_both_rules(self, repo):
        repo.create(_ws(1, seen=T0 - timedelta(hours=1)))       # unused too long
        repo.create(_ws(2, created=T0 - timedelta(hours=9)))     # too old
        repo.create(_ws(3))                                      # live
        n = repo.delete_expired(seen_before=T0 - timedelta(minutes=30),
                                created_before=T0 - timedelta(hours=8))
        assert n == 2 and repo.get(_id(3)) is not None

    def test_indexes(self, repo):
        keys = {tuple(ix["key"]) for ix in repo.collection.index_information().values()}
        assert {(("username", 1),), (("last_seen_at", 1),), (("created_at", 1),)} <= keys


def test_registered_on_app_context(fresh_app):
    _app, ctx, _db = fresh_app
    assert isinstance(ctx.web_session_repo, WebSessionRepository)
