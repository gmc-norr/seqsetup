"""``POST /runs/{run_id}/bclconvert`` is gone.

It set a run's two barcode-mismatch counts and ``no_lane_splitting`` --
three values that go straight into the Sample Sheet's
[BCLConvert_Settings] section, so into how the run is demultiplexed. No
page, script or static file ever posted to it: every mismatch box on the
sample table posts to ``/runs/{id}/samples/{sample_id}/settings``
instead. A reachable, authenticated route that changes a clinical value
and that nothing uses is surface with no purpose, so it is removed.

The three run-wide fields keep their defaults (1, 1 and false) and are
still written to the sheet; per-sample settings are unchanged.
"""

from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from seqsetup.models.sample import Sample
from .page_shows import shown_setting
from .conftest import hold_edit_lock


ORIGIN = {"Origin": "http://testserver"}
RUN_ID = "gone-route-run"


def _run(ctx):
    run = SequencingRun(
        id=RUN_ID,
        run_name="Gone route run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        reagent_cycles=300,
        run_cycles=RunCycles(151, 151, 10, 10),
        barcode_mismatches_index1=0,
        barcode_mismatches_index2=0,
        no_lane_splitting=True,
    )
    run.add_sample(Sample(id="s1", sample_id="PAT-1", lanes=[1], test_id="WGS",
                          test_version="1"))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return run


class TestTheRouteIsNotThere:
    def test_no_route_of_the_app_has_that_path(self):
        from seqsetup.routes import runs as runs_module

        assert [r.path for r in runs_module.router.routes if "bclconvert" in r.path] == []

    def test_there_is_no_handler_left(self):
        from seqsetup.routes import runs as runs_module

        assert not hasattr(runs_module, "update_bclconvert")

    def test_a_post_to_it_is_not_answered(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/bclconvert",
            data={"barcode_mismatches_index1": "2", "barcode_mismatches_index2": "2",
                  "no_lane_splitting": "0"},
            headers=ORIGIN)

        assert response.status_code == 404

    def test_such_a_post_changes_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        before = _run(ctx).to_dict()

        logged_in_client.post(
            f"/runs/{RUN_ID}/bclconvert",
            data={"barcode_mismatches_index1": "2", "barcode_mismatches_index2": "2",
                  "no_lane_splitting": "0"},
            headers=ORIGIN)

        assert ctx.run_repo.get_by_id(RUN_ID).to_dict() == before


class TestTheFieldsItSetAreUnchanged:
    def test_a_new_run_still_has_their_defaults(self):
        run = SequencingRun(id="defaults", run_name="Defaults")
        assert (run.barcode_mismatches_index1, run.barcode_mismatches_index2,
                run.no_lane_splitting) == (1, 1, False)

    def test_a_stored_run_keeps_what_it_was_given(self, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)
        stored = ctx.run_repo.get_by_id(RUN_ID)
        assert (stored.barcode_mismatches_index1, stored.barcode_mismatches_index2,
                stored.no_lane_splitting) == (0, 0, True)

    def test_the_per_sample_mismatch_route_still_stores_one(self, logged_in_client, fresh_app):
        """The route the sample table's mismatch boxes really post to."""
        _app, ctx, _db = fresh_app
        _run(ctx)

        response = logged_in_client.post(
            f"/runs/{RUN_ID}/samples/s1/settings",
            data={"barcode_mismatches_index1": "2",
                  "target_setting": shown_setting(logged_in_client, RUN_ID, "s1",
                                                  "barcode_mismatches_index1")},
            headers=ORIGIN)

        assert response.status_code == 200
        assert ctx.run_repo.get_by_id(RUN_ID).get_sample("s1").barcode_mismatches_index1 == 2
