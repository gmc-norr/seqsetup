"""The paste box the preview refills takes what the file it read held (batch 4,
item 4f(iii)).

A file previews up to 10 MB. "Edit paste" on the preview puts that text back
into the paste box, and pressing Preview again sent it as a form field, which
Starlette bounds at 1 MB: a file over 1 MB could be previewed once and never
edited. That form asks for the file branch's 10 MB now. The paste box on the
page itself keeps the 1 MB every other form field has.
"""

from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

MB = 1024 * 1024
ORIGIN = {"Origin": "http://testserver"}


def _run(ctx, run_id="edit-paste-run"):
    run = SequencingRun(
        id=run_id, run_name="Paste run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
    )
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return run_id


def _text(pad_bytes: int) -> str:
    """One readable row, then blank lines, which the parser skips."""
    return "sample_id\nS0001\n" + "\n" * pad_bytes


def _preview_file(client, run_id, text):
    return client.post(
        f"/runs/{run_id}/samples/preview",
        files={"sample_file": ("worklist.csv", text.encode(), "text/csv"),
               "lanes": (None, "1")},
        headers=ORIGIN,
    )


def _preview_box(client, run_id, text, *, edited=False):
    query = "?edited=1" if edited else ""
    return client.post(
        f"/runs/{run_id}/samples/preview{query}",
        files={"paste_data": (None, text), "lanes": (None, "1")},
        headers=ORIGIN,
    )


class TestAFileOverOneMegabyteCanBeEdited:
    """Preview a 2 MB file, then preview the text it put in the box."""

    def test_the_file_previews(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        response = _preview_file(logged_in_client, run_id, _text(2 * MB))
        assert response.status_code == 200, response.text[:300]
        assert "1 sample read" in response.text

    def test_the_refilled_box_previews_the_same_text(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        response = _preview_box(logged_in_client, run_id, _text(2 * MB), edited=True)
        assert response.status_code == 200, response.text[:300]
        assert "1 sample read" in response.text

    def test_the_preview_refills_the_form_with_the_larger_limit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        response = _preview_file(logged_in_client, run_id, _text(0))
        assert response.status_code == 200, response.text[:300]
        assert f"/runs/{run_id}/samples/preview?edited=1" in response.text


class TestThePlainPasteBoxKeepsOneMegabyte:
    """The form on the page itself, which no preview has filled."""

    def test_a_box_over_1_mb_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        response = _preview_box(logged_in_client, run_id, _text(2 * MB))
        assert response.status_code != 200, response.text[:300]
        assert ctx.run_repo.get_by_id(run_id).samples == []

    def test_the_page_asks_for_the_plain_limit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        response = logged_in_client.get(f"/runs/{run_id}")
        assert response.status_code == 200
        assert f"/runs/{run_id}/samples/preview" in response.text
        assert "samples/preview?edited=1" not in response.text


class TestTheRefilledBoxStopsAtTenMegabytes:
    """The file branch's own limit, not more."""

    def test_a_box_over_10_mb_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        response = _preview_box(logged_in_client, run_id, _text(10 * MB), edited=True)
        assert response.status_code != 200, response.text[:300]
        assert ctx.run_repo.get_by_id(run_id).samples == []
