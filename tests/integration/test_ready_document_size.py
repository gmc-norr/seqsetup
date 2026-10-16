"""Mark Ready refuses, with a message and an audit row, when what it must
store would not fit MongoDB's 16 MiB document limit (outside review of
f490536, finding F6).

Every export used to live inside the run document, the validation report's
PDF as base64. Measured by the verifier on real mongo:7: 96 different
samples per lane on an 8-lane flowcell was 18.9 MB, 112.8% of the limit,
and the save failed with DocumentTooLarge after the full export time. The
person saw a bare 500 "Internal Server Error" in the error banner, the run
stayed Draft with the lock still held, no run.status.denied row was
written, a retry failed the same way, and nothing said what to change.

The files now live in their own records, one document each
(docs/design/2026-10-16-export-files-own-records-design.md), so the size of
a whole run is no longer a limit. What is measured here is one of them: the
oversized report below is refused as a file, before anything is written,
reason ``export_file_too_large``. The run document's own limit is still
measured and still pinned at the bottom of this file; the per-file refusal
is covered end to end in test_export_file_size.py, under a collection
wrapper that refuses an oversize document as a real server does.
"""

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services.validation_report import ValidationReportPDF

from .conftest import disable_repos, mark_ready, nothing_stored
from .test_group_a3 import ORIGIN
from .test_scheduled_sync_instrument_cache import _seed_run


def _oversized_pdf(_run, _result):
    """A report big enough that the run document cannot be stored. Random-
    looking bytes, so nothing compresses it away."""
    import hashlib
    block = hashlib.sha256(b"seed").digest() * 4096          # 128 KiB
    return block * 160                                        # ~20 MiB


def _audit_reasons(ctx, run_id):
    return [e.details.get("reason") for e in
            ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")
            if e.target == run_id]


class TestMarkReadyRefusesWhatWillNotFit:

    def test_the_run_stays_a_draft(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.DRAFT
        assert resp.status_code != 500, resp.text[:300]

    def test_the_refusal_names_the_size_and_the_limit(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-message")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message", dict(resp.headers)
        assert "16 MB" in resp.text, resp.text[:600]
        assert "MB" in resp.text and "Draft" in resp.text, resp.text[:600]

    def test_the_refusal_says_it_is_a_seqsetup_limit_and_gives_no_lab_advice(
            self, logged_in_client, fresh_app, monkeypatch):
        """Splitting a run costs another sequencing run, and how samples go on
        lanes is the lab's design: the message must not bend either to this
        limit (the user's decision, 2026-10-16)."""
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-advice")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        message = resp.text.split("<ul>", 1)[-1].split("</ul>", 1)[0]
        assert "limit of SeqSetup, not a problem with the run" in message, message
        assert "administrator" in message, message
        for advice in ("lane", "more than one run", "split"):
            assert advice not in message.lower(), message

    def test_the_attempt_is_audited(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-audit")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        mark_ready(logged_in_client, run_id, ORIGIN)

        assert "export_file_too_large" in _audit_reasons(ctx, run_id)

    def test_nothing_of_the_exports_is_left_on_the_run(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-clean")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        mark_ready(logged_in_client, run_id, ORIGIN)

        stored = ctx.run_repo.get_by_id(run_id)
        assert nothing_stored(ctx, stored)
        assert stored.status == RunStatus.DRAFT

    def test_control_a_run_whose_exports_fit_still_goes_ready(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "fits")

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY


class TestTheRefusalIsNotAValidationRefusal:
    """A fresh review found the size refusal reusing the validation
    refusal's panel, whose footer says samples with errors are marked in
    the table and points at the validation page -- for a size refusal no
    sample is marked and the same run reports zero errors."""

    def test_it_does_not_send_the_person_to_a_page_with_no_errors(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-footer")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert "Samples with errors are marked in the table" not in resp.text, resp.text
        assert "Open the validation page" not in resp.text, resp.text

    def test_it_does_not_count_the_size_as_an_error_to_fix(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-count")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert "Cannot mark ready: 1 error to fix first" not in resp.text, resp.text


class TestTheLimitItselfIsPinned:
    """A fresh review pointed out that a negative margin -- which would let
    the route accept a document MongoDB refuses, the exact 500-after-two-
    minutes this fix exists to stop -- left every test green. Both limits
    are pinned: the run document's, and one export file's."""

    def test_the_threshold_is_at_or_below_what_mongodb_accepts(self):
        from seqsetup.routes.runs import _MAX_RUN_DOCUMENT, _RUN_DOCUMENT_MARGIN
        assert _RUN_DOCUMENT_MARGIN > 0, "no margin for what touch() writes after the check"
        assert _MAX_RUN_DOCUMENT <= 16 * 1024 * 1024, "above MongoDB's own document limit"
        assert _MAX_RUN_DOCUMENT - _RUN_DOCUMENT_MARGIN < 16 * 1024 * 1024

    def test_one_file_is_measured_against_the_same_limit(self):
        from seqsetup.services.run_exports import EXPORT_FILE_MARGIN, MAX_EXPORT_FILE
        assert EXPORT_FILE_MARGIN > 0, "no margin for the record's other fields"
        assert MAX_EXPORT_FILE <= 16 * 1024 * 1024, "above MongoDB's own document limit"
        assert MAX_EXPORT_FILE - EXPORT_FILE_MARGIN < 16 * 1024 * 1024
