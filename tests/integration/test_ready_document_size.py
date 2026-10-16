"""Mark Ready refuses, with a message and an audit row, when the Ready
record would not fit MongoDB's 16 MiB document limit (outside review of
f490536, finding F6 -- the interim refusal, not the separate storage).

Every export lives inside the run document, the validation report's PDF as
base64. Measured by the verifier on real mongo:7: 96 different samples per
lane on an 8-lane flowcell is 18.9 MB, 112.8% of the limit, and the save
fails with DocumentTooLarge after the full export time. The person saw a
bare 500 "Internal Server Error" in the error banner, the run stayed Draft
with the lock still held, no run.status.denied row was written, a retry
failed the same way, and nothing said what to change.

The size is now measured before the save, so the refusal names it and says
what to do, and the attempt is audited like every other refused transition.
"""

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services.validation_report import ValidationReportPDF

from .conftest import disable_repos, mark_ready
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


class TestMarkReadyRefusesADocumentThatWillNotFit:

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

    def test_the_refusal_says_what_to_change(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-advice")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert "lane" in resp.text.lower(), resp.text[:600]
        assert "more than one run" in resp.text, resp.text[:600]

    def test_the_attempt_is_audited(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-audit")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        mark_ready(logged_in_client, run_id, ORIGIN)

        assert "ready_document_too_large" in _audit_reasons(ctx, run_id)

    def test_nothing_of_the_exports_is_left_on_the_run(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "too-big-clean")
        monkeypatch.setattr(ValidationReportPDF, "export", _oversized_pdf)

        mark_ready(logged_in_client, run_id, ORIGIN)

        stored = ctx.run_repo.get_by_id(run_id)
        assert stored.generated_samplesheet_v2 is None
        assert stored.generated_validation_pdf is None
        assert stored.status == RunStatus.DRAFT

    def test_control_a_run_whose_exports_fit_still_goes_ready(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed_run(ctx, "fits")

        resp = mark_ready(logged_in_client, run_id, ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY
