"""AuditEventRepository: insert-only, newest first, filters, keyset pages."""

import re
from datetime import datetime, timedelta, timezone

import mongomock
import pytest

from seqsetup.models.audit_event import AuditEvent
from seqsetup.repositories.audit_event_repo import AuditEventRepository

T0 = datetime(2026, 9, 26, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def repo():
    return AuditEventRepository(mongomock.MongoClient()["t"])


def _add(repo, minutes, event="x.y", actor="alice", target="run-1"):
    e = AuditEvent(timestamp=T0 + timedelta(minutes=minutes), event=event,
                   actor=actor, target=target)
    repo.append(e)
    return e


class TestAuditEventRepositorySearch:
    """Newest first, with each filter on its own."""

    def test_newest_first(self, repo):
        for m in (1, 3, 2):
            _add(repo, m, target=f"t{m}")
        assert [e.target for e in repo.search(limit=10)] == ["t3", "t2", "t1"]

    def test_limit(self, repo):
        for m in range(5):
            _add(repo, m)
        assert len(repo.search(limit=2)) == 2

    def test_event_prefix_matches_the_start_only(self, repo):
        _add(repo, 1, event="login.success")
        _add(repo, 2, event="login.failure")
        _add(repo, 3, event="logout")
        _add(repo, 4, event="api.login.x")
        assert sorted(e.event for e in repo.search(limit=10, event_prefix="login")) == [
            "login.failure", "login.success"]

    def test_event_prefix_is_literal_text_not_a_pattern(self, repo):
        _add(repo, 1, event="aXb")
        _add(repo, 2, event="a.b")
        assert [e.event for e in repo.search(limit=10, event_prefix="a.")] == ["a.b"]

    def test_actor_matches_exactly(self, repo):
        _add(repo, 1, actor="alice")
        _add(repo, 2, actor="alice2")
        assert [e.actor for e in repo.search(limit=10, actor="alice")] == ["alice"]

    def test_target_matches_exactly_even_when_long(self, repo):
        long_target = "https://lims.example.com/" + "p" * 275  # 300 chars
        assert len(long_target) == 300
        _add(repo, 1, target=long_target)
        _add(repo, 2, target=long_target + "x")
        found = repo.search(limit=10, target=long_target)
        assert [e.target for e in found] == [long_target]

    def test_from_is_inclusive_and_to_is_exclusive(self, repo):
        for m in (0, 10, 20):
            _add(repo, m, target=f"t{m}")
        from_ts = (T0 + timedelta(minutes=10)).replace(tzinfo=None).isoformat()
        to_ts = (T0 + timedelta(minutes=20)).replace(tzinfo=None).isoformat()
        assert [e.target for e in repo.search(limit=10, from_ts=from_ts, to_ts=to_ts)] == ["t10"]


class TestAuditEventRepositoryPaging:
    """Keyset pages cover every event once, even with equal timestamps."""

    def test_pages_through_ties_without_gaps_or_repeats(self, repo):
        same = [AuditEvent(timestamp=T0, event="x", target=f"t{i}") for i in range(5)]
        for e in same:
            repo.append(e)
        seen, cursor = [], (None, None)
        while True:
            page = repo.search(limit=2, before_ts=cursor[0], before_id=cursor[1])
            if not page:
                break
            seen += [e.id for e in page]
            cursor = page[-1].cursor()
        assert sorted(seen) == sorted(e.id for e in same)
        assert len(seen) == 5

    def test_paging_keeps_the_filters(self, repo):
        for m in range(4):
            _add(repo, m, actor="alice" if m % 2 else "bob", target=f"t{m}")
        first = repo.search(limit=1, actor="alice")
        rest = repo.search(limit=10, actor="alice",
                           before_ts=first[0].cursor()[0], before_id=first[0].cursor()[1])
        assert [e.target for e in first + rest] == ["t3", "t1"]


class TestAuditEventRepositoryIsInsertOnly:
    """No method can change or remove an event."""

    def test_no_update_or_delete_methods(self):
        names = [n for n in dir(AuditEventRepository)
                 if re.match(r"(delete|update|replace|remove|drop|clear|upsert|save)", n)]
        assert names == []


class TestAuditEventRepositoryRegistration:
    """The app builds the repository and hands it out through AppContext."""

    def test_app_context_carries_the_repo(self, fresh_app):
        _app, ctx, _db = fresh_app
        assert isinstance(ctx.audit_event_repo, AuditEventRepository)
