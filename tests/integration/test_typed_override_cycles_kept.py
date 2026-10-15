"""A cycle change never replaces an Override Cycles typed by hand (found
2026-10-15; the user's choice "Refuse the change").

Changing a cycle count, saving the setup page with other counts, or picking
a reagent kit with other default counts recalculated every sample's Override
Cycles from its indexes: a value typed by hand -- a UMI, a skipped cycle --
was replaced with no word, and Mark Ready could not see it, because the new
value fits the run. Now each of those saves is refused while any sample's
stored value is not the calculated one, naming the samples, and nothing is
saved. A save that leaves the counts as they are changes no sample.
"""

import json

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.services.cycle_calculator import CycleCalculator
from .conftest import hold_edit_lock, run_version

ORIGIN = {"Origin": "http://testserver", "HX-Request": "true"}
RUN_ID = "oc-kept"
SAME = {"read1_cycles": "151", "read2_cycles": "151", "index1_cycles": "10", "index2_cycles": "10"}
TYPED = "U8Y143;I10;I10;N2Y149"


def _pair(n: int) -> IndexPair:
    i7 = ["ACGTACGTAC", "TGCATGCATG", "CATGCATGCA", "GTACGTACGT", "AACCGGTTAA", "TTGGCCAATT",
          "AGAGAGAGAG"][n]
    i5 = ["TTGGCCAATT", "AACCGGTTAA", "GTACGTACGT", "CATGCATGCA", "TGCATGCATG", "ACGTACGTAC",
          "CTCTCTCTCT"][n]
    return IndexPair(id=f"k_p{n}", name=f"P{n}",
                     index1=Index(f"P{n}", i7, IndexType.I7),
                     index2=Index(f"P{n}", i5, IndexType.I5))


def _make_run(ctx, samples: int = 1, read1_pattern=None) -> None:
    run = SequencingRun(id=RUN_ID, run_name="oc-kept", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", reagent_cycles=300,
                        run_cycles=RunCycles(151, 151, 10, 10), status=RunStatus.DRAFT)
    for n in range(samples):
        sample = Sample(id=f"s{n}", sample_id=f"S{n}", lanes=[1])
        sample.assign_index(_pair(n))
        sample.read1_override_pattern = read1_pattern
        run.add_sample(sample)
    CycleCalculator.update_all_sample_override_cycles(run)
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, RUN_ID)


def _type(client, sample_ids, value):
    resp = client.post(f"/runs/{RUN_ID}/samples/set-override-cycles", headers=ORIGIN,
                       data={"sample_ids": json.dumps(sample_ids), "override_cycles": value})
    assert resp.status_code == 200, resp.text


def _stored(ctx):
    return ctx.run_repo.get_by_id(RUN_ID)


def _post_cycles(client, ctx, **counts):
    return client.post(f"/runs/{RUN_ID}/cycles", headers=ORIGIN,
                       data={**SAME, **counts, "run_version": run_version(ctx, RUN_ID)})


class TestACycleChangeKeepsTypedOverrideCycles:
    """A save that would recalculate the Override Cycles is refused while a
    sample has one typed by hand, and nothing is saved."""

    def test_a_cycle_change_is_refused_while_a_value_is_typed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx)
        _type(logged_in_client, ["s0"], TYPED)

        resp = _post_cycles(logged_in_client, ctx, read2_cycles="101")

        assert resp.status_code == 400
        assert "Nothing was saved" in resp.text and "S0" in resp.text
        run = _stored(ctx)
        assert run.samples[0].override_cycles == TYPED
        assert run.run_cycles == RunCycles(151, 151, 10, 10)

    def test_continue_to_run_is_refused_and_saves_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx)
        _type(logged_in_client, ["s0"], TYPED)

        resp = logged_in_client.post(f"/runs/{RUN_ID}/setup", headers=ORIGIN, data={
            **SAME, "read2_cycles": "101", "run_name": "renamed", "run_description": "",
            "run_version": run_version(ctx, RUN_ID)})

        assert resp.status_code == 400
        assert "S0" in resp.text
        run = _stored(ctx)
        assert run.samples[0].override_cycles == TYPED
        assert run.run_cycles == RunCycles(151, 151, 10, 10)
        assert run.run_name == "oc-kept"

    def test_a_reagent_kit_with_other_cycles_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx)
        _type(logged_in_client, ["s0"], TYPED)

        resp = logged_in_client.post(f"/runs/{RUN_ID}/reagent-kit", headers=ORIGIN, data={
            "reagent_cycles": "200", "run_version": run_version(ctx, RUN_ID)})

        assert resp.status_code == 400
        assert "S0" in resp.text
        run = _stored(ctx)
        assert run.samples[0].override_cycles == TYPED
        assert run.reagent_cycles == 300
        assert run.run_cycles == RunCycles(151, 151, 10, 10)

    def test_picking_the_same_reagent_kit_again_keeps_the_typed_value(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx)
        _type(logged_in_client, ["s0"], TYPED)

        resp = logged_in_client.post(f"/runs/{RUN_ID}/reagent-kit", headers=ORIGIN, data={
            "reagent_cycles": "300", "run_version": run_version(ctx, RUN_ID)})

        assert resp.status_code == 200, resp.text
        assert _stored(ctx).samples[0].override_cycles == TYPED

    def test_saving_the_same_counts_keeps_the_typed_value(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx)
        _type(logged_in_client, ["s0"], TYPED)

        resp = _post_cycles(logged_in_client, ctx)

        assert resp.status_code == 200, resp.text
        assert _stored(ctx).samples[0].override_cycles == TYPED

    def test_the_message_names_five_samples_and_counts_the_rest(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx, samples=7)
        _type(logged_in_client, [f"s{n}" for n in range(7)], TYPED)

        resp = _post_cycles(logged_in_client, ctx, read2_cycles="101")

        assert resp.status_code == 400
        assert "7 sample(s)" in resp.text
        assert "S0, S1, S2, S3, S4, and 2 more" in resp.text
        assert "S5" not in resp.text


class TestACycleChangeStillRecalculates:
    """With no value typed by hand, a cycle change goes through and
    recalculates every sample, as before."""

    def test_a_kit_read_pattern_is_not_a_typed_value(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx, read1_pattern="U8Y*")
        assert _stored(ctx).samples[0].override_cycles == "U8Y143;I10;I10;Y151"

        resp = _post_cycles(logged_in_client, ctx, read2_cycles="101")

        assert resp.status_code == 200, resp.text
        run = _stored(ctx)
        assert run.run_cycles == RunCycles(151, 101, 10, 10)
        assert run.samples[0].override_cycles == "U8Y143;I10;I10;Y101"

    def test_a_reagent_kit_pick_recalculates(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx)

        resp = logged_in_client.post(f"/runs/{RUN_ID}/reagent-kit", headers=ORIGIN, data={
            "reagent_cycles": "200", "run_version": run_version(ctx, RUN_ID)})

        assert resp.status_code == 200, resp.text
        run = _stored(ctx)
        assert run.reagent_cycles == 200
        assert run.samples[0].override_cycles == "Y101;I10;I10;Y101"

    def test_a_value_set_back_to_auto_lets_the_change_through(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_run(ctx)
        _type(logged_in_client, ["s0"], TYPED)
        _type(logged_in_client, ["s0"], "")

        resp = _post_cycles(logged_in_client, ctx, read2_cycles="101")

        assert resp.status_code == 200, resp.text
        assert _stored(ctx).samples[0].override_cycles == "Y151;I10;I10;Y101"
