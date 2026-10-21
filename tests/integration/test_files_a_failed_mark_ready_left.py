"""A Mark Ready refused after some export files were written names them.

CLAUDE.md, Run state integrity: "Every file written is logged with the run id
and the file ids -- whether the write finished or failed part way -- and every
refusal after it **that writes an audit row** names those ids in it
(``_files_left``)". A refusal on a read-back that differed named them in no
log line, and no refusal of the write itself named them in its audit row, so
the records left in an insert-only collection could be found only by reading
the collection (review LIFECYCLE-1). No data is lost either way; what was
missing is the trail to it.
"""

import logging

from .conftest import mark_ready
from .test_export_files_own_records import ORIGIN, records, seed_run
from .test_export_write_failures import _fail_on


def _denial(ctx, run_id, reason):
    for event in ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied"):
        if event.target == run_id and event.details.get("reason") == reason:
            return event
    return None


class TestAReadBackThatDiffers:

    def test_the_log_names_every_file_written(self, logged_in_client, fresh_app,
                                              monkeypatch, caplog):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "left-readback-log")
        _fail_on(monkeypatch, ctx, "json", how="readback")

        with caplog.at_level(logging.INFO):
            answer = mark_ready(logged_in_client, run_id, ORIGIN)

        assert answer.status_code == 500, answer.text[:300]
        left = [r["_id"] for r in records(ctx, run_id)]
        assert len(left) == 3, left   # v2, v1, and the json that read back wrong
        assert [file_id for file_id in left if file_id not in caplog.text] == []

    def test_the_audit_row_names_every_file_written(self, logged_in_client, fresh_app,
                                                    monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "left-readback-audit")
        _fail_on(monkeypatch, ctx, "json", how="readback")

        mark_ready(logged_in_client, run_id, ORIGIN)

        event = _denial(ctx, run_id, "export_file_not_stored")
        assert event is not None
        assert sorted(event.details.get("export_files", [])) == sorted(
            r["_id"] for r in records(ctx, run_id)), event.details


class TestAnInsertThatFailsPartWay:

    def test_the_audit_row_names_every_file_written(self, logged_in_client, fresh_app,
                                                    monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "left-insert-audit")
        _fail_on(monkeypatch, ctx, "validation_pdf")

        mark_ready(logged_in_client, run_id, ORIGIN)

        event = _denial(ctx, run_id, "export_files_not_written")
        assert event is not None, [
            e.details for e in ctx.audit_event_repo.search(limit=20,
                                                           event_prefix="run.status.denied")]
        left = sorted(r["_id"] for r in records(ctx, run_id))
        assert len(left) == 4, left   # everything but the pdf
        assert sorted(event.details.get("export_files", [])) == left, event.details

    def test_the_log_names_them_too(self, logged_in_client, fresh_app, monkeypatch, caplog):
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "left-insert-log")
        _fail_on(monkeypatch, ctx, "validation_pdf")

        with caplog.at_level(logging.INFO):
            mark_ready(logged_in_client, run_id, ORIGIN)

        left = [r["_id"] for r in records(ctx, run_id)]
        assert [file_id for file_id in left if file_id not in caplog.text] == []


class TestARefusalBeforeAnythingIsWritten:

    def test_names_no_file(self, logged_in_client, fresh_app, monkeypatch):
        """A file measured too large to store refuses the whole Mark Ready
        before a single insert, so there is nothing to name."""
        _app, ctx, _db = fresh_app
        run_id = seed_run(ctx, "left-nothing-written")
        monkeypatch.setattr("seqsetup.services.run_exports.MAX_EXPORT_FILE", 1024)

        mark_ready(logged_in_client, run_id, ORIGIN)

        event = _denial(ctx, run_id, "export_file_too_large")
        assert event is not None
        assert "export_files" not in event.details, event.details
        assert records(ctx, run_id) == []
