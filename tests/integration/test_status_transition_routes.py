"""The run status rules hold through every route that changes a run's status.

Two routes change it: ``POST /runs/{id}/status/{status}`` (``update_status``)
and the dashboard's ``POST /runs/{id}/archive`` (``archive_run``); both load
the run with ``get_archivable_run``, which checks no status, and leave the
rules to ``check_status_transition``. A Draft cannot be archived by either;
an Archived run cannot go back to Ready or Draft, nor be archived again; a
refused request leaves the stored run exactly as it was, its exports
included. Ready -> Archived is the control: allowed, and the stored exports
are kept for the API ("Risk 5" gap).

Already tested elsewhere, and not repeated here as such:
Archived -> Draft through /status/draft answers 400 and keeps the status
(test_smoke_validation.py ``TestStatusTransition``; this file adds that the
whole stored run, its exports included, is unchanged); Ready -> Archived
through /status/archived keeps the v2 sheet and the JSON
(test_smoke_wizard.py) and the sheet targets (test_sheet_targets.py);
the dashboard archives a Ready run (test_dashboard_unreadable_run.py, status
only).
"""

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import hold_edit_lock, stored_export, seed_profiles

ORIGIN = {"Origin": "http://testserver"}

# The files a Ready run carries, each in its own record; the run keeps the
# manifest (docs/design/2026-10-16-export-files-own-records-design.md).
STORED_FILES = {
    "samplesheet_v2": "[Header]\nRunName,Stored\nSTORED-V2\n",
    "samplesheet_v1": "[Header]\nSTORED-V1\n",
    "json": '{"stored": "json"}',
    "validation_json": '{"stored": "validation"}',
    "validation_pdf": b"%PDF-1.4 stored report",
}

STORED_EXPORTS = {
    "test_versions_used": [{"test": "WGS", "asked": "1", "version": "1.0.0", "file": "Wgs.yaml"}],
    "sheet_targets": {
        "samplesheet_v2": {
            "instrument": "NovaSeq 6000", "software": "BCL Convert", "software_version": "4.3.6",
            "i5_workflow": "v1.0 reagents", "index2_column": "forward",
            "needs_runinfo_reverse_mark": False,
        },
        "samplesheet_v1": {
            "instrument": "NovaSeq 6000", "software": "bcl2fastq", "software_version": None,
            "i5_workflow": "v1.0 reagents", "index2_column": "forward",
            "needs_runinfo_reverse_mark": False,
        },
    },
}


def _pair(i7: str, i5: str, name: str) -> IndexPair:
    return IndexPair(
        id=name, name=name,
        index1=Index(name=f"{name}-i7", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"{name}-i5", sequence=i5, index_type=IndexType.I5),
    )


def _seed(ctx, run_id: str, status: RunStatus) -> str:
    """A run that passes the checks with no profiles, so a move the rules
    let through would go all the way. A Ready or Archived run carries
    stored exports; the logged-in admin holds the edit lock, so the lock is
    never what stops a request here."""
    seed_profiles(ctx)
    run = SequencingRun(
        id=run_id, run_name="Status rules",
        instrument_platform=InstrumentPlatform.NOVASEQ_6000, flowcell_type="S4",
        i5_workflow="v1.0 reagents", run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(test_id="WGS", test_version="1", sample_id="S1", index_pair=_pair("ATTACTCG", "TATAGCCT", "p1"), lanes=[1]))
    run.add_sample(Sample(test_id="WGS", test_version="1", sample_id="S2", index_pair=_pair("TCCGGAGA", "ATAGAGGC", "p2"), lanes=[1]))
    if status != RunStatus.DRAFT:
        run.status = RunStatus.READY
        for key, value in STORED_EXPORTS.items():
            setattr(run, key, value)
        run.exports = _write_files(ctx, run_id)
        run.status = status
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run_id)
    return run_id


def _write_files(ctx, run_id: str) -> dict:
    """Write STORED_FILES as Mark Ready does and return the manifest."""
    import hashlib
    import uuid
    manifest = {}
    for kind, content in STORED_FILES.items():
        raw = content.encode("utf-8") if isinstance(content, str) else content
        file_id = uuid.uuid4().hex
        ctx.run_export_repo.insert({
            "_id": file_id, "run_id": run_id, "kind": kind, "content": content,
            "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            "created_at": "2026-10-16T00:00:00", "created_by": "seed",
        })
        manifest[kind] = {"id": file_id, "sha256": hashlib.sha256(raw).hexdigest(),
                          "size": len(raw)}
    return manifest


def _raw(ctx, run_id: str) -> dict:
    return ctx.run_repo.collection.find_one({"_id": run_id})


def _status_events(ctx, run_id: str) -> list:
    return [
        e for prefix in ("run.status.changed", "run.archived")
        for e in ctx.audit_event_repo.search(limit=100, event_prefix=prefix)
        if e.target == run_id
    ]


def _assert_exports_kept(ctx, run: SequencingRun) -> None:
    for key, value in STORED_EXPORTS.items():
        assert getattr(run, key) == value, f"{key} was not kept"
    assert set(run.exports) == set(STORED_FILES), "the manifest was not kept"
    for kind, content in STORED_FILES.items():
        assert stored_export(ctx, run, kind) == content, f"{kind} was not kept"


class TestADraftCannotBeArchived:
    """Draft -> Archived skips Ready, its checks and its exports: refused by
    both routes that archive, and the run is not touched."""

    @pytest.mark.parametrize("path", ["/runs/{id}/status/archived", "/runs/{id}/archive"],
                             ids=["status-route", "dashboard-archive"])
    def test_archiving_a_draft_is_refused_and_changes_nothing(
            self, logged_in_client, fresh_app, path):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "draft-to-archived", RunStatus.DRAFT)
        before = _raw(ctx, run_id)

        resp = logged_in_client.post(path.format(id=run_id), headers=ORIGIN)

        assert resp.status_code == 400
        assert resp.text == "Invalid status transition: draft → archived"
        assert _raw(ctx, run_id) == before
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        assert _status_events(ctx, run_id) == []


class TestAnArchivedRunStaysArchived:
    """Archived is terminal: no route moves it, and its stored exports, which
    the API serves, stay exactly as they were."""

    @pytest.mark.parametrize("target", ["ready", "draft"])
    def test_moving_an_archived_run_is_refused_and_keeps_its_exports(
            self, logged_in_client, fresh_app, target):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, f"archived-to-{target}", RunStatus.ARCHIVED)
        before = _raw(ctx, run_id)

        resp = logged_in_client.post(f"/runs/{run_id}/status/{target}", headers=ORIGIN)

        assert resp.status_code == 400
        assert resp.text == f"Invalid status transition: archived → {target}"
        assert _raw(ctx, run_id) == before
        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status == RunStatus.ARCHIVED
        _assert_exports_kept(ctx, stored)
        assert _status_events(ctx, run_id) == []

    @pytest.mark.parametrize("path,code,text", [
        ("/runs/{id}/status/archived", 400, "Invalid status transition: archived → archived"),
        ("/runs/{id}/archive", 403, "Run is already archived"),
    ], ids=["status-route", "dashboard-archive"])
    def test_archiving_an_archived_run_again_is_refused(
            self, logged_in_client, fresh_app, path, code, text):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "archived-again", RunStatus.ARCHIVED)
        before = _raw(ctx, run_id)

        resp = logged_in_client.post(path.format(id=run_id), headers=ORIGIN)

        assert resp.status_code == code
        assert resp.text == text
        assert _raw(ctx, run_id) == before
        assert _status_events(ctx, run_id) == []


class TestTheSameStatusIsNotAMove:
    """Asking for the status a run already has is refused, so a Ready run's
    stored exports are never made again over themselves."""

    @pytest.mark.parametrize("status", [RunStatus.DRAFT, RunStatus.READY], ids=lambda s: s.value)
    def test_the_same_status_is_refused_and_changes_nothing(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, f"same-{status.value}", status)
        before = _raw(ctx, run_id)

        resp = logged_in_client.post(f"/runs/{run_id}/status/{status.value}", headers=ORIGIN)

        assert resp.status_code == 400
        assert resp.text == f"Invalid status transition: {status.value} → {status.value}"
        assert _raw(ctx, run_id) == before
        assert _status_events(ctx, run_id) == []


class TestAnUnknownStatusIsRefused:
    """A status that is not one of the three is refused before any rule."""

    @pytest.mark.parametrize("status,code,text", [
        ("bogus", 400, "Invalid status: bogus"),
        ("READY", 400, "Invalid status: READY"),
        ("deleted", 400, "Invalid status: deleted"),
        ("", 404, None),  # no route matches /status/
    ], ids=["bogus", "upper-case", "deleted", "empty"])
    def test_an_unknown_status_is_refused_and_changes_nothing(
            self, logged_in_client, fresh_app, status, code, text):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "unknown-status", RunStatus.READY)
        before = _raw(ctx, run_id)

        resp = logged_in_client.post(f"/runs/{run_id}/status/{status}", headers=ORIGIN)

        assert resp.status_code == code
        if text is not None:
            assert resp.text == text
        assert _raw(ctx, run_id) == before
        assert _status_events(ctx, run_id) == []


class TestAReadyRunCanBeArchived:
    """The control: Ready -> Archived goes through on both routes, and every
    stored export is kept for the API."""

    @pytest.mark.parametrize("path", ["/runs/{id}/status/archived", "/runs/{id}/archive"],
                             ids=["status-route", "dashboard-archive"])
    def test_archiving_a_ready_run_keeps_its_exports(self, logged_in_client, fresh_app, path):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "ready-to-archived", RunStatus.READY)
        before = ctx.run_repo.get_by_id(run_id)

        resp = logged_in_client.post(path.format(id=run_id), headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status == RunStatus.ARCHIVED
        assert stored.was_ready is True
        _assert_exports_kept(ctx, stored)
        assert stored.samplesheet_v1_withheld == before.samplesheet_v1_withheld
        assert [s.to_dict() for s in stored.samples] == [s.to_dict() for s in before.samples]
        assert len(_status_events(ctx, run_id)) == 1
