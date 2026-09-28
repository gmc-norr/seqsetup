"""The login rules: idle limit, hard cap, database-user stamp, hashing."""

import logging
from datetime import datetime, timedelta

import mongomock
import pytest

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import User, UserRole
from seqsetup.repositories.local_user_repo import LocalUserRepository
from seqsetup.repositories.web_session_repo import WebSessionRepository
from seqsetup.services import web_sessions as ws
from seqsetup.services.web_sessions import SessionPolicy

T0 = datetime(2026, 9, 27, 8, 0, 0)
POLICY = SessionPolicy(idle_seconds=1800, max_age_seconds=28800)


@pytest.fixture
def repos():
    db = mongomock.MongoClient()["t"]
    return WebSessionRepository(db), LocalUserRepository(db)


def _directory_user(name="bob"):
    return User(username=name, display_name=name, role=UserRole.STANDARD, source="ldap")


def _db_user(users, name="alice", role=UserRole.ADMIN):
    u = LocalUser(username=name, display_name=name, role=role)
    users.save(u)
    return u


class TestPolicy:
    """Defaults, overrides, visible clamps, refused junk."""

    def test_defaults(self):
        assert SessionPolicy.from_env({}) == SessionPolicy(1800, 28800)

    def test_overrides(self):
        p = SessionPolicy.from_env({"SEQSETUP_SESSION_IDLE_SECONDS": "600",
                                    "SEQSETUP_SESSION_MAX_AGE_SECONDS": "3600"})
        assert p == SessionPolicy(600, 3600)

    @pytest.mark.parametrize("env,expected", [
        ({"SEQSETUP_SESSION_IDLE_SECONDS": "5"}, SessionPolicy(60, 28800)),
        ({"SEQSETUP_SESSION_IDLE_SECONDS": "99999"}, SessionPolicy(28800, 28800)),
        ({"SEQSETUP_SESSION_MAX_AGE_SECONDS": "10"}, SessionPolicy(300, 300)),
        ({"SEQSETUP_SESSION_MAX_AGE_SECONDS": "999999"}, SessionPolicy(1800, 86400)),
    ])
    def test_clamps_with_a_warning(self, env, expected, caplog):
        caplog.set_level(logging.WARNING, logger="seqsetup.services.web_sessions")
        assert SessionPolicy.from_env(env) == expected
        assert any("SEQSETUP_SESSION_" in r.getMessage() for r in caplog.records)

    def test_in_range_values_do_not_warn(self, caplog):
        caplog.set_level(logging.WARNING, logger="seqsetup.services.web_sessions")
        SessionPolicy.from_env({})
        assert not caplog.records

    def test_non_integer_is_refused(self):
        with pytest.raises(ValueError):
            SessionPolicy.from_env({"SEQSETUP_SESSION_IDLE_SECONDS": "30m"})


class TestResolve:
    """A ticket is accepted only while every rule holds."""

    def test_db_stores_the_hash_not_the_ticket(self, repos):
        sessions, _ = repos
        ticket = ws.start(sessions, _directory_user(), T0, POLICY)
        doc = sessions.collection.find_one()
        assert doc["_id"] == ws.ticket_id(ticket) != ticket
        assert ticket not in str(doc)

    def test_unknown_ticket(self, repos):
        assert ws.resolve(*repos, "nope", T0, POLICY) is None

    @pytest.mark.parametrize("after,ok", [(1799, True), (1800, True), (1801, False)])
    def test_idle_limit(self, repos, after, ok):
        t = ws.start(repos[0], _directory_user(), T0, POLICY)
        assert (ws.resolve(*repos, t, T0 + timedelta(seconds=after), POLICY) is not None) == ok

    def test_idle_refusal_removes_the_row(self, repos):
        t = ws.start(repos[0], _directory_user(), T0, POLICY)
        ws.resolve(*repos, t, T0 + timedelta(minutes=31), POLICY)
        assert repos[0].get(ws.ticket_id(t)) is None

    def test_activity_every_29_minutes_lasts_until_the_cap(self, repos):
        t = ws.start(repos[0], _directory_user(), T0, POLICY)
        now = T0
        while now + timedelta(minutes=29) <= T0 + timedelta(hours=8):
            now += timedelta(minutes=29)
            assert ws.resolve(*repos, t, now, POLICY) is not None, now
        assert ws.resolve(*repos, t, T0 + timedelta(hours=8, minutes=1), POLICY) is None

    def test_short_idle_with_requests_every_59_seconds(self, repos):
        p = SessionPolicy(idle_seconds=60, max_age_seconds=28800)
        t = ws.start(repos[0], _directory_user(), T0, p)
        for i in range(1, 11):
            assert ws.resolve(*repos, t, T0 + timedelta(seconds=59 * i), p) is not None, i

    @pytest.mark.parametrize("age,ok", [(timedelta(hours=7, minutes=59), True),
                                        (timedelta(hours=8, minutes=1), False)])
    def test_hard_cap(self, repos, age, ok):
        t = ws.start(repos[0], _directory_user(), T0, POLICY)
        repos[0].touch(ws.ticket_id(t), T0 + age)          # in use until now
        assert (ws.resolve(*repos, t, T0 + age, POLICY) is not None) == ok

    def test_directory_user_needs_no_user_record(self, repos):
        sessions, _ = repos
        t = ws.start(sessions, _directory_user(), T0, POLICY)
        user = ws.resolve(sessions, None, t, T0, POLICY)
        assert (user.username, user.source) == ("bob", "ldap")

    def test_file_account_login_is_refused(self, repos):
        # Sign-in with file accounts was removed (spec 2026-09-28 group 2b).
        sessions, _ = repos
        t = ws.start(sessions, User(username="bob", display_name="bob",
                                    role=UserRole.ADMIN, source="yaml"), T0, POLICY)
        assert ws.resolve(sessions, None, t, T0, POLICY) is None

    def test_db_user_stamp_mismatch_is_refused(self, repos):
        sessions, users = repos
        u = _db_user(users)
        t = ws.start(sessions, u.to_user(), T0, POLICY)
        u.role = UserRole.STANDARD
        users.save(u)
        assert ws.resolve(sessions, users, t, T0, POLICY) is None
        assert sessions.get(ws.ticket_id(t)) is None

    def test_deleted_db_user_is_refused(self, repos):
        sessions, users = repos
        u = _db_user(users)
        t = ws.start(sessions, u.to_user(), T0, POLICY)
        users.delete("alice")
        assert ws.resolve(sessions, users, t, T0, POLICY) is None

    def test_db_user_details_come_from_the_current_record(self, repos):
        sessions, users = repos
        u = _db_user(users)
        t = ws.start(sessions, u.to_user(), T0, POLICY)
        u.display_name = "Alice Renamed"
        users.save(u)
        assert ws.resolve(sessions, users, t, T0, POLICY).display_name == "Alice Renamed"

    def test_unknown_source_is_refused(self, repos):
        user = User(username="x", display_name="x", role=UserRole.ADMIN, source="")
        t = ws.start(repos[0], user, T0, POLICY)
        assert ws.resolve(*repos, t, T0, POLICY) is None

    def test_start_clears_expired_rows(self, repos):
        old = ws.start(repos[0], _directory_user("old"), T0, POLICY)
        ws.start(repos[0], _directory_user("new"), T0 + timedelta(hours=1), POLICY)
        assert repos[0].get(ws.ticket_id(old)) is None


class TestEnd:
    """Logout ends one login; revocation ends all of a user's."""

    def test_end_one(self, repos):
        a = ws.start(repos[0], _directory_user(), T0, POLICY)
        b = ws.start(repos[0], _directory_user(), T0, POLICY)
        ws.end(repos[0], a)
        assert ws.resolve(*repos, a, T0, POLICY) is None
        assert ws.resolve(*repos, b, T0, POLICY) is not None

    def test_end_all_for(self, repos):
        ws.start(repos[0], _directory_user("bob"), T0, POLICY)
        ws.start(repos[0], _directory_user("bob"), T0, POLICY)
        keep = ws.start(repos[0], _directory_user("eve"), T0, POLICY)
        assert ws.end_all_for(repos[0], "bob") == 2
        assert ws.resolve(*repos, keep, T0, POLICY) is not None
