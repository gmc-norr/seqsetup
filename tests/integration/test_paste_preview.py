"""Adding samples by paste: preview first, then add exactly what was shown.

The bulk route is the authority: it re-reads the text and refuses an ID
repeated within the paste, applies the picked lanes and the default test
(blank test cells only), and names IDs it skips because they are already
in the run.
"""

import html
import re

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

ORIGIN = {"Origin": "http://testserver"}


def _run(ctx, run_id="paste-run", *, samples=(), status=RunStatus.DRAFT, flowcell="10B"):
    run = SequencingRun(
        id=run_id, run_name="Paste run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type=flowcell,
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    for s in samples:
        run.add_sample(s)
    ctx.run_repo.save(run)
    return run_id


def _wgs(ctx):
    # Imported here: a module-level TestProfile would be collected by pytest.
    from seqsetup.models.test_profile import TestProfile
    ctx.test_profile_repo.save(TestProfile(test_type="WGS", test_name="Whole Genome"))


def _post(client, run_id, action, text, *, lanes=("1",), default_test="", default_version=None):
    data = {"paste_data": text, "lanes": list(lanes), "default_test_id": default_test}
    if default_version is not None:
        data["default_test_version"] = default_version
    return client.post(f"/runs/{run_id}/samples/{action}", data=data, headers=ORIGIN)


def _samples(ctx, run_id):
    return {s.sample_id: s for s in ctx.run_repo.get_by_id(run_id).samples}


class TestBulkAdd:
    """POST /samples/bulk applies lanes and the default test and refuses repeats."""

    def test_applies_lanes_and_default_test(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        # A picked test needs its version (spec 2026-10-07 group A4, §2, decision 6).
        r = _post(logged_in_client, run_id, "bulk", "S1\nS2,RNA\n", lanes=("2", "3"), default_test="WGS",
                  default_version="1")
        assert r.status_code == 200
        assert "Added 2 samples to lanes 2, 3." in r.text
        samples = _samples(ctx, run_id)
        assert (samples["S1"].lanes, samples["S1"].test_id) == ([2, 3], "WGS")
        assert (samples["S2"].lanes, samples["S2"].test_id) == ([2, 3], "RNA")

    def test_repeated_id_in_paste_adds_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "bulk", "S1,WGS\nS2,WGS\nS1,WGS\n")
        assert r.status_code == 200
        assert "more than once in the paste: S1" in r.text
        assert _samples(ctx, run_id) == {}

    def test_ids_already_in_run_are_skipped_and_named(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, samples=[Sample(id="old", sample_id="OLD-1", lanes=[1])])
        r = _post(logged_in_client, run_id, "bulk", "OLD-1,WGS\nNEW-1,WGS\n")
        assert "Skipped 1 already in the run: OLD-1." in r.text
        assert list(_samples(ctx, run_id)) == ["OLD-1", "NEW-1"]

    def test_no_lane_is_rejected(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = logged_in_client.post(f"/runs/{run_id}/samples/bulk", data={"paste_data": "S1,WGS"}, headers=ORIGIN)
        assert r.status_code == 400
        assert "at least one lane" in r.text
        assert _samples(ctx, run_id) == {}

    def test_lane_outside_flowcell_is_rejected(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "bulk", "S1,WGS", lanes=("9",))
        assert r.status_code == 400
        assert "between 1 and 8" in r.text

    def test_unknown_default_test_is_rejected(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "bulk", "S1", default_test="NOPE")
        assert r.status_code == 400
        assert "NOPE" in html.unescape(r.text)
        assert _samples(ctx, run_id) == {}

    def test_locked_run_is_forbidden(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, status=RunStatus.READY)
        assert _post(logged_in_client, run_id, "bulk", "S1,WGS").status_code == 403


def _add_form_text(page_html):
    m = re.search(r'<textarea name="paste_data" hidden>\n(.*?)</textarea>', page_html, re.S)
    return html.unescape(m.group(1)) if m else None


class TestPreviewRoute:
    """POST /samples/preview shows what would be added and saves nothing."""

    def test_preview_shows_rows_and_saves_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview",
                  "sample_id,test_id,test_version,comment\nS1,WGS,1,hi\nS2,WGX,1,\n")
        assert r.status_code == 200
        assert "Check what we read" in r.text
        assert 'data-state="ok"' in r.text and 'data-state="look"' in r.text
        assert "Not used:" in r.text and "<code>comment</code>" in r.text
        assert "Add 2 samples" in r.text
        assert _samples(ctx, run_id) == {}

    def test_add_form_carries_the_exact_text(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        text = "\nS1,WGS\nS2,WGS"  # a leading blank line must survive the round trip
        r = _post(logged_in_client, run_id, "preview", text, lanes=("2",))
        assert _add_form_text(r.text) == text
        assert f'hx-post="/runs/{run_id}/samples/bulk"' in r.text
        assert '<input type="hidden" name="lanes" value="2">' in r.text

    def test_repeated_id_disables_add(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "S1,WGS\nS1,WGS\n")
        assert "Fix the red rows first." in r.text
        assert "/samples/bulk" not in r.text

    def test_unreadable_paste_shows_the_reason(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "sample_id,test_id\n,WGS\n")
        assert r.status_code == 200
        assert "sample_id is required" in r.text
        assert "/samples/bulk" not in r.text

    def test_guessed_columns_are_announced(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "S1\tATTACTCG\tTATAGCCT\n")
        assert "No header row, so we guessed the columns." in r.text

    def test_form_is_refilled_for_back_to_edit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "preview", "S1", lanes=("2",), default_test="WGS")
        assert 'name="lanes" value="2" checked' in r.text
        assert 'name="lanes" value="1">' in r.text
        assert '<option value="WGS" selected>' in r.text

    def test_no_lane_is_400(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        assert _post(logged_in_client, run_id, "preview", "S1", lanes=()).status_code == 400

    def test_locked_run_is_forbidden(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, status=RunStatus.READY)
        assert _post(logged_in_client, run_id, "preview", "S1").status_code == 403


class TestRunPagePasteForm:
    """The run page's Add-samples box previews first and offers the pickers."""

    def test_form_posts_to_preview_with_lane_1_ticked(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert f'hx-post="/runs/{run_id}/samples/preview"' in page
        assert 'name="lanes" value="1" checked' in page
        assert 'name="lanes" value="8">' in page

    def test_single_lane_flowcell_sends_lane_1(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, flowcell="")
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert '<input type="hidden" name="lanes" value="1">' in page
        assert 'type="checkbox" name="lanes"' not in page
