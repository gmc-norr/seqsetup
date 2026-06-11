"""Integration tests for run change history (repo, capture, route)."""

from datetime import datetime

import pytest

from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sequencing_run import RunStatus


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


def _create_run(client) -> str:
    r = client.post("/runs/new", follow_redirects=False, headers=_origin())
    assert r.status_code == 303, r.text[:300]
    return r.headers["location"].split("run_id=", 1)[1].split("&", 1)[0]


class TestEditCapture:
    def test_edit_records_field_change(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": "Renamed", "run_description": ""},
                              headers=_origin())
        entries = ctx.run_history_repo.list_by_run(run_id, limit=10)
        updated = [e for e in entries if e.kind == "updated"]
        assert updated, "an updated entry should be recorded"
        fields = {c["field"]: c for c in updated[0].field_changes}
        assert fields["run_name"]["after"] == "Renamed"
        assert updated[0].actor   # actor recorded
        run = ctx.run_repo.get_by_id(run_id)
        assert updated[0].timestamp == run.updated_at

    def test_noop_save_records_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        before = len([e for e in ctx.run_history_repo.list_by_run(run_id, limit=50)
                      if e.kind == "updated"])
        run = ctx.run_repo.get_by_id(run_id)
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": run.run_name,
                                    "run_description": run.run_description},
                              headers=_origin())
        after = len([e for e in ctx.run_history_repo.list_by_run(run_id, limit=50)
                     if e.kind == "updated"])
        assert after == before

    def test_sample_add_records_added_entry(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/samples",
                              data={"sample_id": "S1"}, headers=_origin())
        entries = ctx.run_history_repo.list_by_run(run_id, limit=50)
        sample_adds = [e for e in entries
                       for sc in e.sample_changes if sc["kind"] == "added"]
        assert sample_adds

    def test_no_phantom_entry_on_conflict(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        from seqsetup.repositories.base import ConflictError
        before = len(ctx.run_history_repo.list_by_run(run_id, limit=50))
        monkeypatch.setattr(ctx.run_repo, "save",
                            lambda run: (_ for _ in ()).throw(ConflictError("x")))
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": "Z", "run_description": ""},
                              headers=_origin())
        after = len(ctx.run_history_repo.list_by_run(run_id, limit=50))
        assert after == before

    def test_history_write_failure_does_not_break_edit(
        self, logged_in_client, fresh_app, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        monkeypatch.setattr(ctx.run_history_repo, "append",
                            lambda entry: (_ for _ in ()).throw(RuntimeError("boom")))
        r = logged_in_client.post(f"/runs/{run_id}/name",
                                  data={"run_name": "Persisted", "run_description": ""},
                                  headers=_origin())
        assert r.status_code == 200
        assert ctx.run_repo.get_by_id(run_id).run_name == "Persisted"


class TestCreationEntries:
    def test_blank_creation_records_created_entry(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        entries = ctx.run_history_repo.list_by_run(run_id, limit=10)
        created = [e for e in entries if e.kind == "created"]
        assert len(created) == 1
        assert created[0].provenance == {"source": "blank", "ref": None}

    def test_clone_records_created_with_source(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        src_id = _create_run(logged_in_client)
        r = logged_in_client.post(f"/runs/{src_id}/duplicate",
                                  data={"include_samples": "false"},
                                  headers=_origin(), follow_redirects=False)
        new_id = r.headers["location"].rsplit("/", 1)[1]
        created = [e for e in ctx.run_history_repo.list_by_run(new_id, limit=10)
                   if e.kind == "created"]
        assert created[0].provenance == {"source": "clone", "ref": src_id}

    def test_from_template_records_created_with_template_ref(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/save-as-template",
                              data={"name": "T", "description": "",
                                    "scaffold_sample_ids": "[]"},
                              headers=_origin(), follow_redirects=False)
        tid = ctx.run_template_repo.list_all()[0].id
        r = logged_in_client.post(f"/runs/new/from-template/{tid}",
                                  headers=_origin(), follow_redirects=False)
        new_id = r.headers["location"].rsplit("/", 1)[1]
        created = [e for e in ctx.run_history_repo.list_by_run(new_id, limit=10)
                   if e.kind == "created"]
        assert created[0].provenance == {"source": "template", "ref": tid}


class TestCascadeDelete:
    def test_deleting_archived_run_removes_its_history(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": "X", "run_description": ""},
                              headers=_origin())
        assert ctx.run_history_repo.list_by_run(run_id, limit=10)   # has history
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.ARCHIVED
        ctx.run_repo.save(run)
        r = logged_in_client.delete(f"/runs/{run_id}", headers=_origin())
        assert r.status_code == 200
        assert ctx.run_history_repo.list_by_run(run_id, limit=10) == []


class TestHistoryRouteAndPanel:
    def test_edit_page_shows_history_panel(self, logged_in_client, fresh_app):
        run_id = _create_run(logged_in_client)
        r = logged_in_client.get(f"/runs/{run_id}")
        assert r.status_code == 200
        assert f"/runs/{run_id}/history" in r.text

    def test_history_route_renders_entries(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        logged_in_client.post(f"/runs/{run_id}/name",
                              data={"run_name": "Visible", "run_description": ""},
                              headers=_origin())
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "Visible" in r.text          # the new value appears
        assert "Created" in r.text          # the blank-creation entry

    def test_history_route_404_for_missing_run(self, logged_in_client):
        r = logged_in_client.get("/runs/nope/history")
        assert r.status_code == 404

    def test_history_route_works_for_archived_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.ARCHIVED
        ctx.run_repo.save(run)
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200

    def test_baseline_marker_for_run_without_created_entry(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        ctx.run_history_repo.delete_by_run(run_id)   # drop the auto 'created'
        ctx.run_history_repo.append(RunHistoryEntry(
            run_id=run_id, timestamp=datetime(2026, 6, 11, 9, 0, 0),
            actor="alice", kind="updated",
            field_changes=[{"field": "run_name", "before": "A", "after": "B"}]))
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "history began" in r.text.lower()
