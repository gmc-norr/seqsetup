"""Ready is the last step: a run never goes Ready naming a file that cannot
be served.

Each insert is made to fail in turn, and so is the read-back, and each time
the run must be exactly the Draft that was loaded, with its edit lock still
held (docs/design/2026-10-16-export-files-own-records-design.md, "What proves
it" 2).
"""

import pytest

from seqsetup.models.sequencing_run import EXPORT_KINDS, RunStatus
from seqsetup.services import run_exports

from .conftest import mark_ready, nothing_stored
from .test_export_files_own_records import ORIGIN, records, seed_run


def _fail_on(monkeypatch, ctx, kind, how="insert"):
    """Make the ``kind`` file's insert raise, or its read-back come back
    wrong."""
    repo = ctx.run_export_repo
    real_insert, real_get = repo.insert, repo.get

    def insert(doc):
        if doc["kind"] == kind and how == "insert":
            raise RuntimeError("the server went away")
        real_insert(doc)

    def get(file_id):
        record = real_get(file_id)
        if how == "readback" and record and record["kind"] == kind:
            content = record["content"]
            record["content"] = (b"\x00" * len(content) if isinstance(content, bytes)
                                 else "\x00" * len(content))
        return record

    monkeypatch.setattr(repo, "insert", insert)
    monkeypatch.setattr(repo, "get", get)


def _lock_holder(ctx, run_id):
    doc = ctx.edit_lock_repo.collection.find_one({"_id": run_id})
    return (doc or {}).get("username")


def _denials(ctx, run_id):
    return [e.details.get("reason") for e in
            ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")
            if e.target == run_id]


class TestAFailedWriteLeavesTheDraftExactlyAsItWas:

    @pytest.mark.parametrize("kind", EXPORT_KINDS)
    def test_an_insert_that_fails_keeps_the_run_a_draft(
            self, logged_in_client, fresh_app, monkeypatch, kind):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, f"insert-fails-{kind}")
        before = ctx.run_repo.collection.find_one({"_id": run_id})
        _fail_on(monkeypatch, ctx, kind)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 500, resp.text[:300]
        assert "could not be stored" in resp.text, resp.text[:300]
        assert ctx.run_repo.collection.find_one({"_id": run_id}) == before
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        assert nothing_stored(ctx, run_id)
        assert _lock_holder(ctx, run_id) == "admin-test", "the edit lock was released"
        assert "export_files_not_written" in _denials(ctx, run_id)

    @pytest.mark.parametrize("kind", EXPORT_KINDS)
    def test_a_read_back_that_differs_keeps_the_run_a_draft(
            self, logged_in_client, fresh_app, monkeypatch, kind):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, f"readback-fails-{kind}")
        before = ctx.run_repo.collection.find_one({"_id": run_id})
        _fail_on(monkeypatch, ctx, kind, how="readback")

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 500, resp.text[:300]
        assert "not stored as they were written" in resp.text, resp.text[:300]
        assert ctx.run_repo.collection.find_one({"_id": run_id}) == before
        assert nothing_stored(ctx, run_id)
        assert _lock_holder(ctx, run_id) == "admin-test"
        assert "export_file_not_stored" in _denials(ctx, run_id)

    def test_the_files_written_before_the_failure_are_left_in_place(
            self, logged_in_client, fresh_app, monkeypatch):
        """The collection is insert-only: records of a Mark Ready that failed
        are referenced by nothing and are not removed — removing one would
        mean a delete path that could also reach a file a run still names."""
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "left-in-place")
        _fail_on(monkeypatch, ctx, "validation_pdf")

        mark_ready(logged_in_client, run_id, ORIGIN)

        written = {r["kind"] for r in records(ctx, run_id)}
        assert written == {"samplesheet_v2", "samplesheet_v1", "json", "validation_json"}
        assert nothing_stored(ctx, run_id), "the run must name none of them"

    def test_a_failure_can_be_followed_by_a_mark_ready_that_works(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "retry")
        _fail_on(monkeypatch, ctx, "json")
        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 500
        monkeypatch.undo()

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.status == RunStatus.READY
        assert set(stored.exports) == set(EXPORT_KINDS)

    def test_the_run_is_not_saved_when_the_run_document_itself_is_refused(
            self, logged_in_client, fresh_app, monkeypatch):
        """The files are already written when the run document is measured:
        the run stays a Draft naming none of them."""
        from seqsetup.routes import runs as runs_module
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "document-refused")
        monkeypatch.setattr(runs_module, "_ready_document_size", lambda run: 20 * 1024 * 1024)

        mark_ready(logged_in_client, run_id, ORIGIN)

        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        assert nothing_stored(ctx, run_id)
        assert len(records(ctx, run_id)) == len(EXPORT_KINDS), (
            "the files were written before the document was measured")


class TestEveryRequiredFileMustBeThereBeforeTheRunGoesReady:
    """Ready is the last step: a reader must never see a Ready run whose
    files are not all stored (the spec's second "must not change").

    ``write_exports`` skips a kind whose content is None, so an exporter that
    returned nothing -- or an empty string -- would have given a Ready run
    that names four files and answers 500 for the fifth for ever, with no
    refusal at Mark Ready (review 1, P3-2).
    """

    @pytest.mark.parametrize("empty", [None, "", b""], ids=["none", "empty-text", "empty-bytes"])
    def test_a_report_that_came_out_empty_refuses_mark_ready(
            self, logged_in_client, fresh_app, monkeypatch, empty):
        from seqsetup.services.validation_report import ValidationReportPDF
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, f"empty-pdf-{type(empty).__name__}")
        monkeypatch.setattr(ValidationReportPDF, "export",
                            staticmethod(lambda _run, _result: empty))

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 500, resp.text[:300]
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        assert nothing_stored(ctx, run_id)
        assert "export_file_missing" in _denials(ctx, run_id)

    def test_an_empty_sheet_refuses_too(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "empty-v2")
        monkeypatch.setattr(SampleSheetV2Exporter, "export",
                            staticmethod(lambda *a, **k: ""))

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 500, resp.text[:300]
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        assert records(ctx, run_id) == [], "a file was written for a run that was refused"

    def test_a_v1_sheet_is_not_required_of_an_instrument_that_writes_none(
            self, logged_in_client, fresh_app):
        """The control: the four are required, the v1 sheet is not."""
        from .test_export_files_own_records import V2_ONLY
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "no-v1-still-ready", V2_ONLY)

        assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY


class TestTheWriteIsMeasuredBeforeAnyInsert:

    def test_no_file_is_written_when_a_later_one_is_too_big(self, fresh_app):
        """Not through the route: ``write_exports`` on its own, so the order
        is pinned where it is decided."""
        _app, ctx, _db = fresh_app
        run = ctx.run_repo.create_run("someone")
        too_big = b"x" * (run_exports.MAX_EXPORT_FILE - run_exports.EXPORT_FILE_MARGIN + 1)

        with pytest.raises(run_exports.ExportFileTooBig) as raised:
            run_exports.write_exports(
                ctx, run,
                {"samplesheet_v2": "[Header]\n", "json": "{}",
                 "validation_json": "{}", "validation_pdf": too_big},
                actor="someone")

        assert raised.value.kind == "validation_pdf"
        assert records(ctx, run.id) == []


class TestFilesLeftByARefusedMarkReadyAreNamed:
    """A Mark Ready refused after the files were written leaves them
    referenced by nothing, and the collection is never pruned. What was
    written must therefore be findable: the write itself is logged with the
    run id, and the refusal's own audit row names the files (the spec's
    "logged with the run id"; review 1, P2-1)."""

    def test_the_write_is_logged_with_the_run_id_and_the_file_ids(
            self, logged_in_client, fresh_app, caplog):
        import logging
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "logged-write")

        with caplog.at_level(logging.INFO, logger="seqsetup.services.run_exports"):
            assert mark_ready(logged_in_client, run_id, ORIGIN).status_code == 200

        written = ctx.run_repo.get_by_id(run_id).exports
        (line,) = [r.getMessage() for r in caplog.records
                   if "stored" in r.getMessage() and "export files" in r.getMessage()]
        assert run_id in line
        for kind, entry in written.items():
            assert f"{kind}={entry['id']}" in line, kind

    def test_a_refusal_after_the_write_names_the_files_it_left(
            self, logged_in_client, fresh_app, monkeypatch):
        """A config sync that finishes inside the Mark Ready: the transition
        is refused after five files were written."""
        from seqsetup.routes import runs as runs_module
        from seqsetup.services import validation as validation_module
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "sync-after-write")
        real = runs_module.write_exports

        def write_then_change_the_settings(*args, **kwargs):
            manifest = real(*args, **kwargs)
            validation_module.clear_validation_cache()   # moves the inputs version
            return manifest

        monkeypatch.setattr(runs_module, "write_exports", write_then_change_the_settings)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 409, resp.text[:300]
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        left = records(ctx, run_id)
        assert len(left) == len(EXPORT_KINDS), "nothing was written, so nothing to name"
        (row,) = [e.details for e in
                  ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")
                  if e.target == run_id
                  and e.details.get("reason") == "settings_changed_during_export"]
        assert sorted(row["export_files"]) == sorted(r["_id"] for r in left)
