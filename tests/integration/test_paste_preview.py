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


def _post(client, run_id, action, text, *, lanes=("1",), default_test=""):
    return client.post(
        f"/runs/{run_id}/samples/{action}",
        data={"paste_data": text, "lanes": list(lanes), "default_test_id": default_test},
        headers=ORIGIN,
    )


def _samples(ctx, run_id):
    return {s.sample_id: s for s in ctx.run_repo.get_by_id(run_id).samples}


class TestBulkAdd:
    """POST /samples/bulk applies lanes and the default test and refuses repeats."""

    def test_applies_lanes_and_default_test(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _wgs(ctx)
        run_id = _run(ctx)
        r = _post(logged_in_client, run_id, "bulk", "S1\nS2,RNA\n", lanes=("2", "3"), default_test="WGS")
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
