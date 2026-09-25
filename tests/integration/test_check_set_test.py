"""Check offers to set the test for every sample that has none.

"N samples have no test_id" was the most common error, and fixing it
meant ticking each row first. The Check box now has a picker and a
button that set the test for exactly those samples (listed when the box
was drawn), through the same save route as the bulk panel.
"""

import json
import re

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

ORIGIN = {"Origin": "http://testserver"}


def _run(ctx, run_id="fix-test-run", *, status=RunStatus.DRAFT):
    run = SequencingRun(
        id=run_id, run_name="Fix test run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    run.add_sample(Sample(id="s1", sample_id="S1", lanes=[1]))
    run.add_sample(Sample(id="s2", sample_id="S2", lanes=[1], test_id="WGS"))
    run.add_sample(Sample(id="s3", sample_id="S3", lanes=[1]))
    ctx.run_repo.save(run)
    return run_id


def _profiles(ctx, *test_types):
    # Imported here: a module-level TestProfile would be collected by pytest.
    from seqsetup.models.test_profile import TestProfile
    for t in test_types:
        ctx.test_profile_repo.save(TestProfile(test_type=t))


def _fix_ids(panel_html):
    m = re.search(r'<form class="validate-fix".*?name="sample_ids" value=\'([^\']*)\'', panel_html, re.S)
    return json.loads(m.group(1)) if m else None


class TestSetTestFromCheck:
    """The picker lists only samples without a test, on a draft, when tests exist."""

    def test_offers_to_set_the_missing_tests(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _profiles(ctx, "WGS")
        run_id = _run(ctx)
        panel = logged_in_client.get(f"/runs/{run_id}/validate-panel").text
        assert "Set test for the 2 samples without one" in panel
        assert sorted(_fix_ids(panel)) == ["s1", "s3"]
        assert f'hx-post="/runs/{run_id}/samples/set-test-id"' in panel
        page = logged_in_client.get(f"/runs/{run_id}").text
        assert sorted(_fix_ids(page)) == ["s1", "s3"]

    def test_setting_changes_only_those_samples(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _profiles(ctx, "WGS", "RNA")
        run_id = _run(ctx)
        ids = _fix_ids(logged_in_client.get(f"/runs/{run_id}/validate-panel").text)
        r = logged_in_client.post(
            f"/runs/{run_id}/samples/set-test-id",
            data={"sample_ids": json.dumps(ids), "test_id": "RNA"},
            headers=ORIGIN,
        )
        assert r.status_code == 200
        tests = {s.sample_id: s.test_id for s in ctx.run_repo.get_by_id(run_id).samples}
        assert tests == {"S1": "RNA", "S2": "WGS", "S3": "RNA"}
        assert _fix_ids(logged_in_client.get(f"/runs/{run_id}/validate-panel").text) is None

    def test_not_offered_without_test_profiles(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        # Clear explicitly: integration tests can see an earlier test's data
        # (startup.py binds init_db at first import).
        ctx.test_profile_repo.delete_all()
        run_id = _run(ctx)
        assert _fix_ids(logged_in_client.get(f"/runs/{run_id}/validate-panel").text) is None

    def test_not_offered_on_a_locked_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _profiles(ctx, "WGS")
        run_id = _run(ctx, status=RunStatus.READY)
        assert _fix_ids(logged_in_client.get(f"/runs/{run_id}/validate-panel").text) is None
