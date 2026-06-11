"""Integration tests for run change history (repo, capture, route)."""

from datetime import datetime

import pytest

from seqsetup.models.run_history import RunHistoryEntry


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _entry(run_id, ts, kind="updated", **kw):
    return RunHistoryEntry(run_id=run_id, timestamp=ts, actor="alice", kind=kind, **kw)


class TestRunHistoryRepository:
    def test_append_and_list_newest_first(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        repo.append(_entry("r1", datetime(2026, 6, 11, 10, 0, 0)))
        repo.append(_entry("r1", datetime(2026, 6, 11, 11, 0, 0)))
        repo.append(_entry("r2", datetime(2026, 6, 11, 10, 30, 0)))
        got = repo.list_by_run("r1", limit=10)
        assert [e.timestamp.hour for e in got] == [11, 10]   # newest first
        assert all(e.run_id == "r1" for e in got)

    def test_append_duplicate_id_raises(self, fresh_app):
        _app, ctx, _db = fresh_app
        from pymongo.errors import DuplicateKeyError
        repo = ctx.run_history_repo
        e = _entry("r1", datetime(2026, 6, 11, 10, 0, 0))
        repo.append(e)
        with pytest.raises(DuplicateKeyError):
            repo.append(e)   # same _id -> DuplicateKeyError

    def test_repo_has_no_update_path(self, fresh_app):
        _app, ctx, _db = fresh_app
        # The append-only guarantee: no `save` upsert method is exposed.
        assert not hasattr(ctx.run_history_repo, "save")

    def test_list_is_bounded_and_pageable(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        for h in range(5):
            repo.append(_entry("r1", datetime(2026, 6, 11, 10, h, 0)))
        page1 = repo.list_by_run("r1", limit=2)
        assert len(page1) == 2 and page1[0].timestamp.minute == 4
        cur_ts, cur_id = page1[-1].cursor()
        page2 = repo.list_by_run("r1", limit=2, before_ts=cur_ts, before_id=cur_id)
        assert len(page2) == 2 and page2[0].timestamp.minute < page1[-1].timestamp.minute

    def test_pagination_handles_same_timestamp_tiebreak(self, fresh_app):
        # All three entries share a timestamp -> the cursor's _id tiebreak
        # branch is what must page correctly (no dup, no skip).
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        ts = datetime(2026, 6, 11, 10, 0, 0)
        for _ in range(3):
            repo.append(_entry("r1", ts))
        page1 = repo.list_by_run("r1", limit=2)
        assert len(page1) == 2
        cur_ts, cur_id = page1[-1].cursor()
        page2 = repo.list_by_run("r1", limit=2, before_ts=cur_ts, before_id=cur_id)
        assert len(page2) == 1
        assert page2[0].id not in {e.id for e in page1}

    def test_delete_by_run(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        repo.append(_entry("r1", datetime(2026, 6, 11, 10, 0, 0)))
        repo.append(_entry("r1", datetime(2026, 6, 11, 11, 0, 0)))
        repo.append(_entry("r2", datetime(2026, 6, 11, 10, 0, 0)))
        assert repo.delete_by_run("r1") == 2
        assert repo.list_by_run("r1", limit=10) == []
        assert len(repo.list_by_run("r2", limit=10)) == 1
