"""Integration tests for run change history (repo, capture, route)."""

from datetime import datetime

import pytest

from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sequencing_run import RunStatus

from .conftest import disable_repos


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _entry(run_id, ts, kind="updated", **kw):
    return RunHistoryEntry(run_id=run_id, timestamp=ts, actor="alice", kind=kind, **kw)


class TestRunHistoryRepository:
    """Each test uses its OWN run id(s) rather than a shared "r1"/"r2". The
    run_history collection is not reliably reset between tests of this class
    when it runs in isolation, so colliding on shared ids made these tests
    accumulate and fail count assertions outside the full-suite ordering.
    Namespacing each test's data by a unique run id keeps them independent of
    that fixture behaviour (queries/deletes are run_id-scoped)."""

    def test_append_and_list_newest_first(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        run, other = "ral-run", "ral-other"
        repo.append(_entry(run, datetime(2026, 6, 11, 10, 0, 0)))
        repo.append(_entry(run, datetime(2026, 6, 11, 11, 0, 0)))
        repo.append(_entry(other, datetime(2026, 6, 11, 10, 30, 0)))
        got = repo.list_by_run(run, limit=10)
        assert [e.timestamp.hour for e in got] == [11, 10]   # newest first
        assert all(e.run_id == run for e in got)             # other run excluded

    def test_append_duplicate_id_raises(self, fresh_app):
        _app, ctx, _db = fresh_app
        from pymongo.errors import DuplicateKeyError
        repo = ctx.run_history_repo
        e = _entry("rdup-run", datetime(2026, 6, 11, 10, 0, 0))
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
        run = "rlb-run"
        for h in range(5):
            repo.append(_entry(run, datetime(2026, 6, 11, 10, h, 0)))
        page1 = repo.list_by_run(run, limit=2)
        assert len(page1) == 2 and page1[0].timestamp.minute == 4
        cur_ts, cur_id = page1[-1].cursor()
        page2 = repo.list_by_run(run, limit=2, before_ts=cur_ts, before_id=cur_id)
        assert len(page2) == 2 and page2[0].timestamp.minute < page1[-1].timestamp.minute

    def test_pagination_handles_same_timestamp_tiebreak(self, fresh_app):
        # All three entries share a timestamp -> the cursor's _id tiebreak
        # branch is what must page correctly (no dup, no skip).
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        run = "rtb-run"
        ts = datetime(2026, 6, 11, 10, 0, 0)
        for _ in range(3):
            repo.append(_entry(run, ts))
        page1 = repo.list_by_run(run, limit=2)
        assert len(page1) == 2
        cur_ts, cur_id = page1[-1].cursor()
        page2 = repo.list_by_run(run, limit=2, before_ts=cur_ts, before_id=cur_id)
        assert len(page2) == 1
        assert page2[0].id not in {e.id for e in page1}

    def test_pagination_across_legacy_isoformat_rows_no_duplicate(self, fresh_app):
        # Rows persisted before timestamp normalization stored a bare
        # isoformat() string (whole-second values lack the ".000000" fraction).
        # The keyset cursor must page across such rows without re-including the
        # boundary entry — otherwise an audit page silently duplicates/loops.
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        rid = "legacy-fmt-run"   # unique id: insulate from other repo tests' "r1"
        for _id, sec in [("LEGACY_A", 7), ("LEGACY_B", 8)]:
            repo.collection.insert_one({
                "_id": _id, "id": _id, "run_id": rid,
                "timestamp": datetime(2026, 6, 11, 10, 0, sec).isoformat(),
                "actor": "a", "kind": "updated", "provenance": None,
                "field_changes": [], "sample_changes": []})
        page1 = repo.list_by_run(rid, limit=1)
        assert [e.id for e in page1] == ["LEGACY_B"]
        cur_ts, cur_id = page1[-1].cursor()
        page2 = repo.list_by_run(rid, limit=5, before_ts=cur_ts, before_id=cur_id)
        assert [e.id for e in page2] == ["LEGACY_A"]   # no LEGACY_B duplicate

    def test_delete_by_run(self, fresh_app):
        _app, ctx, _db = fresh_app
        repo = ctx.run_history_repo
        run, other = "rdel-run", "rdel-other"
        repo.append(_entry(run, datetime(2026, 6, 11, 10, 0, 0)))
        repo.append(_entry(run, datetime(2026, 6, 11, 11, 0, 0)))
        repo.append(_entry(other, datetime(2026, 6, 11, 10, 0, 0)))
        assert repo.delete_by_run(run) == 2
        assert repo.list_by_run(run, limit=10) == []
        assert len(repo.list_by_run(other, limit=10)) == 1


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

    def test_history_route_requires_authentication(self, client, fresh_app):
        # The new route must sit behind the global auth middleware like every
        # other run route; an unauthenticated GET redirects to /login.
        _app, ctx, _db = fresh_app
        run = ctx.run_repo.create_run("alice")
        r = client.get(f"/runs/{run.id}/history", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/login"

    def test_history_route_degrades_when_repo_unavailable(
        self, logged_in_client, fresh_app
    ):
        # The read path must not 500 if history isn't configured — mirror the
        # None-guard the recording helpers apply (AppContext.run_history_repo
        # is declared Optional). disable_repos nulls BOTH ctx and startup._repos
        # so the route's per-request get_app_context() sees None.
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        disable_repos(ctx, "run_history")
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "No change history recorded yet" in r.text

    def test_partial_cursor_is_rejected(self, logged_in_client, fresh_app):
        # A keyset cursor is both-or-neither; a half cursor is malformed input
        # and must be rejected (not silently re-served as page 1).
        run_id = _create_run(logged_in_client)
        only_ts = logged_in_client.get(
            f"/runs/{run_id}/history",
            params={"before_ts": "2026-06-11T00:00:00.000000"})
        only_id = logged_in_client.get(
            f"/runs/{run_id}/history", params={"before_id": "abc"})
        assert only_ts.status_code == 400
        assert only_id.status_code == 400

    def test_history_panel_escapes_user_controlled_values(
        self, logged_in_client, fresh_app
    ):
        # actor and before/after values are user-controlled (sample ids, names,
        # descriptions). They must be HTML-escaped, never rendered as live markup.
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        ctx.run_history_repo.append(RunHistoryEntry(
            run_id=run_id, timestamp=datetime(2026, 6, 11, 9, 0, 0),
            actor="<script>alert(1)</script>", kind="updated",
            field_changes=[{"field": "run_name", "before": "A",
                            "after": "<img src=x onerror=alert(2)>"}]))
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
        assert "<img src=x onerror=" not in r.text
        assert "&lt;script&gt;" in r.text   # escaped form present

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

    def test_route_pagination_exposes_and_serves_older_page(
        self, logged_in_client, fresh_app
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        for i in range(60):   # > _HISTORY_PAGE (50)
            ctx.run_history_repo.append(RunHistoryEntry(
                run_id=run_id, timestamp=datetime(2026, 6, 11, 0, 0, i),
                actor="alice", kind="updated",
                field_changes=[{"field": "run_name", "before": str(i),
                                "after": str(i + 1)}]))
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "before_ts=" in r.text and "before_id=" in r.text  # Load-older link
        # Following the cursor returns the older page (200, fewer/older entries).
        older = logged_in_client.get(
            f"/runs/{run_id}/history",
            params={"before_ts": "2026-06-11T00:00:10", "before_id": "zzz"})
        assert older.status_code == 200

    def test_summary_sample_change_renders_readably(
        self, logged_in_client, fresh_app
    ):
        # A summarized (oversized-import) entry must render a readable count
        # line, not "Sample None changed:" with no fields.
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        ctx.run_history_repo.append(RunHistoryEntry(
            run_id=run_id, timestamp=datetime(2026, 6, 11, 9, 0, 0),
            actor="alice", kind="updated",
            sample_changes=[{"sample_id": None, "kind": "summary", "fields": [],
                             "summary": {"added": 5000, "removed": 0,
                                         "modified": 0, "total": 5000}}]))
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "5000 sample changes" in r.text
        assert "5000 added" in r.text
        assert "Sample None" not in r.text   # not the generic per-sample line

    def test_summary_without_summary_key_degrades_gracefully(
        self, logged_in_client, fresh_app
    ):
        # A malformed summary change (no "summary" mapping) must not 500 the
        # whole panel — degrade rather than raise UndefinedError.
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        ctx.run_history_repo.append(RunHistoryEntry(
            run_id=run_id, timestamp=datetime(2026, 6, 11, 9, 0, 0),
            actor="alice", kind="updated",
            sample_changes=[{"sample_id": None, "kind": "summary", "fields": []}]))
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200

    def test_index_change_renders_readably_not_raw_dict(
        self, logged_in_client, fresh_app
    ):
        # A structured index value must render via the histval filter
        # ("D701 ATTACTCG"), not as a raw Python dict repr.
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        ctx.run_history_repo.append(RunHistoryEntry(
            run_id=run_id, timestamp=datetime(2026, 6, 11, 9, 0, 0),
            actor="alice", kind="updated",
            sample_changes=[{"sample_id": "S1", "kind": "modified", "fields": [
                {"name": "index1",
                 "before": {"name": "D701", "sequence": "ATTACTCG"},
                 "after": {"name": "D702", "sequence": "TCCGGAGA"}}]}]))
        r = logged_in_client.get(f"/runs/{run_id}/history")
        assert r.status_code == 200
        assert "D701 ATTACTCG" in r.text and "D702 TCCGGAGA" in r.text
        assert "'sequence'" not in r.text   # no raw dict repr


class TestReadyPromotionDiff:
    def test_ready_promotion_records_only_status_not_export_blobs(self, fresh_app):
        # Promoting to READY also populates the (large, volatile) generated_*
        # export blobs in the same save. The history entry must record ONLY
        # status: draft -> ready, never the export blobs.
        from seqsetup.services.run_history import record_run_updated
        _app, ctx, _db = fresh_app
        run = ctx.run_repo.create_run("alice")
        before = run.to_dict()
        run.status = RunStatus.READY
        run.generated_samplesheet_v2 = "SHEET-V2"
        run.generated_json = "JSON"
        run.generated_validation_pdf = b"PDFBYTES"
        run.touch(updated_by="alice")
        ctx.run_repo.save(run)
        record_run_updated(ctx, run, before, "alice")
        entry = ctx.run_history_repo.list_by_run(run.id, limit=10)[0]
        assert entry.kind == "updated"
        names = {c["field"] for c in entry.field_changes}
        assert "status" in names
        assert not any(n.startswith("generated_") for n in names)


class TestOversizedEntrySummarized:
    """A bulk import that would produce a history entry exceeding the BSON cap
    must be summarized, not silently dropped by the best-effort append guard."""

    def test_large_diff_is_summarized_not_dropped(self, fresh_app, monkeypatch):
        from seqsetup.services import run_history as rh
        _app, ctx, _db = fresh_app
        # Force the size ceiling low so a modest diff trips the summary path
        # (instead of materializing thousands of samples in the test).
        monkeypatch.setattr(rh, "_MAX_ENTRY_BSON_BYTES", 200)
        run = ctx.run_repo.create_run("alice")
        before = run.to_dict()
        from seqsetup.models.sample import Sample
        for i in range(5):
            run.add_sample(Sample(sample_id=f"S{i}"))
        run.touch(updated_by="alice")
        ctx.run_repo.save(run)
        rh.record_run_updated(ctx, run, before, "alice")

        entry = ctx.run_history_repo.list_by_run(run.id, limit=10)[0]
        assert entry.kind == "updated"
        assert len(entry.sample_changes) == 1
        sc = entry.sample_changes[0]
        assert sc["kind"] == "summary"
        assert sc["summary"]["added"] == 5
        assert sc["summary"]["total"] == 5

    def test_field_dominated_oversize_also_collapses_field_changes(
        self, fresh_app, monkeypatch
    ):
        # If, after summarizing samples, the entry is STILL too large (a
        # pathological run-level field diff), field_changes must also collapse
        # so we never append a doc the best-effort guard would silently drop.
        from seqsetup.services import run_history as rh
        _app, ctx, _db = fresh_app
        monkeypatch.setattr(rh, "_MAX_ENTRY_BSON_BYTES", 50)
        run = ctx.run_repo.create_run("alice")
        before = run.to_dict()
        from seqsetup.models.sample import Sample
        run.run_name = "Renamed"
        run.add_sample(Sample(sample_id="S1"))
        run.touch(updated_by="alice")
        ctx.run_repo.save(run)
        rh.record_run_updated(ctx, run, before, "alice")

        entry = ctx.run_history_repo.list_by_run(run.id, limit=10)[0]
        assert entry.sample_changes[0]["kind"] == "summary"
        # field_changes collapsed to a single summary marker, not the raw diff
        assert len(entry.field_changes) == 1
        assert entry.field_changes[0]["field"] == "(summary)"

    def test_small_diff_keeps_full_detail(self, fresh_app):
        from seqsetup.services import run_history as rh
        _app, ctx, _db = fresh_app
        run = ctx.run_repo.create_run("alice")
        before = run.to_dict()
        from seqsetup.models.sample import Sample
        run.add_sample(Sample(sample_id="S1"))
        run.touch(updated_by="alice")
        ctx.run_repo.save(run)
        rh.record_run_updated(ctx, run, before, "alice")

        entry = ctx.run_history_repo.list_by_run(run.id, limit=10)[0]
        assert [sc["kind"] for sc in entry.sample_changes] == ["added"]
        assert entry.sample_changes[0]["sample_id"] == "S1"


class TestHistoryFailureNonFatal:
    def test_blank_creation_survives_history_failure(
        self, logged_in_client, fresh_app, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        monkeypatch.setattr(ctx.run_history_repo, "append",
                            lambda entry: (_ for _ in ()).throw(RuntimeError("boom")))
        before = len(ctx.run_repo.list_all())
        r = logged_in_client.post("/runs/new", follow_redirects=False, headers=_origin())
        assert r.status_code == 303
        assert len(ctx.run_repo.list_all()) == before + 1   # run still created

    def test_cascade_delete_survives_history_failure(
        self, logged_in_client, fresh_app, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        run = ctx.run_repo.get_by_id(run_id)
        run.status = RunStatus.ARCHIVED
        ctx.run_repo.save(run)
        monkeypatch.setattr(ctx.run_history_repo, "delete_by_run",
                            lambda rid: (_ for _ in ()).throw(RuntimeError("boom")))
        r = logged_in_client.delete(f"/runs/{run_id}", headers=_origin())
        assert r.status_code == 200
        assert ctx.run_repo.get_by_id(run_id) is None   # run still deleted
