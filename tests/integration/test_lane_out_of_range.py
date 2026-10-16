"""A sample on a lane the run's flow cell does not have ("Risk 2" gap).

``ValidationService._validate_lane_assignments`` (category
``lane_out_of_range``) ran in no test: only hand-built ConfigurationError
objects in the report tests used the category. A sample on lane 3 of a
2-lane flow cell has a [BCLConvert_Data] row for a lane the instrument never
reads, so its reads go nowhere. These tests drive the check, Mark Ready's
refusal, the flow cell change that leaves a sample's lane behind (it keeps
lanes), and the set-lanes route, which refuses such a lane before it is
saved.
"""

import html
import json

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)
from seqsetup.services.validation import ValidationService

from .conftest import hold_edit_lock, mark_ready, nothing_stored, run_version, stored_export
from .test_index_safety_net import TEST_ID, TEST_VERSION, _seed_profiles

ORIGIN = {"Origin": "http://testserver"}
TWO_LANES, EIGHT_LANES = "1.5B", "10B"  # NovaSeq X flow cells (config/instruments.yaml)


def _out_of_range(sample_id: str, lane: int, lanes: int) -> str:
    return (f"Sample '{sample_id}' is assigned to lane {lane}, "
            f"but the selected flowcell only has lanes 1-{lanes}.")


def _draft(ctx, run_id: str, flowcell: str, s1_lanes, s2_lanes=(1,)) -> SequencingRun:
    """Two samples with far-apart dual indexes on the safety net's test, so
    the run passes every check but the one about its lanes."""
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type=flowcell, run_cycles=RunCycles(151, 151, 10, 10))
    for sid, lanes, i7, i5 in (("S1", s1_lanes, "ACGTACGTAC", "TTGGCCAATT"),
                               ("S2", s2_lanes, "TGCATGCAAC", "AACCGGTTCA")):
        run.add_sample(Sample(
            id=f"id-{sid}", sample_id=sid, lanes=list(lanes), test_id=TEST_ID,
            test_version=TEST_VERSION,
            index_pair=IndexPair(id=f"p{sid}", name=f"p{sid}",
                                 index1=Index(name=f"{sid}7", sequence=i7, index_type=IndexType.I7),
                                 index2=Index(name=f"{sid}5", sequence=i5, index_type=IndexType.I5))))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run_id)
    return ctx.run_repo.get_by_id(run_id)


def _lane_errors(ctx, run_id: str) -> list:
    run = ctx.run_repo.get_by_id(run_id)
    result = ValidationService.validate_run(
        run, test_profile_repo=ctx.test_profile_repo, app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config)
    return [e for e in result.configuration_errors if e.category == "lane_out_of_range"]


def _assert_refused(resp, ctx, run_id: str, message: str):
    assert resp.headers.get("HX-Retarget") == "#ready-message", resp.text[:400]
    assert message in html.unescape(resp.text)
    run = ctx.run_repo.get_by_id(run_id)
    assert run.status == RunStatus.DRAFT
    assert nothing_stored(ctx, run)


@pytest.fixture(autouse=True)
def _profiles(fresh_app):
    _app, ctx, _db = fresh_app
    _seed_profiles(ctx)


class TestTheCheckNamesALaneOutsideTheFlowcell:
    """validate_run gives a lane_out_of_range ERROR naming the sample and the
    lane; lanes inside the flow cell give none."""

    def test_lane_three_on_a_two_lane_flowcell(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "lane-3-of-2", TWO_LANES, s1_lanes=[3])

        (error,) = _lane_errors(ctx, "lane-3-of-2")

        assert error.severity.value == "error"
        assert error.sample_names == ["S1"]
        assert error.lane == 3
        assert error.message == _out_of_range("S1", 3, 2)

    def test_only_the_lane_outside_is_named(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "lanes-2-3-of-2", TWO_LANES, s1_lanes=[2, 3], s2_lanes=[1, 4])

        errors = _lane_errors(ctx, "lanes-2-3-of-2")

        assert [(e.sample_names, e.lane) for e in errors] == [(["S1"], 3), (["S2"], 4)]

    def test_lanes_inside_the_flowcell_give_none(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "lanes-1-2-of-2", TWO_LANES, s1_lanes=[1, 2], s2_lanes=[2])

        assert _lane_errors(ctx, "lanes-1-2-of-2") == []

    def test_the_last_lane_of_an_eight_lane_flowcell_is_inside(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "lane-8-of-8", EIGHT_LANES, s1_lanes=[8])

        assert _lane_errors(ctx, "lane-8-of-8") == []

    def test_the_validation_page_shows_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "lane-3-page", TWO_LANES, s1_lanes=[3])

        page = html.unescape(logged_in_client.get("/runs/lane-3-page/validation").text)

        assert "Lane out of range: " in page
        assert _out_of_range("S1", 3, 2) in page


class TestMarkReadyRefusesALaneOutsideTheFlowcell:
    """The run stays a Draft and no export is stored."""

    def test_it_refuses_and_stores_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "ready-lane-3", TWO_LANES, s1_lanes=[3])

        resp = mark_ready(logged_in_client, "ready-lane-3", ORIGIN)

        _assert_refused(resp, ctx, "ready-lane-3", _out_of_range("S1", 3, 2))

    def test_the_same_run_inside_the_flowcell_is_marked_ready(self, logged_in_client, fresh_app):
        # The control: only the lane differs, so the refusal above is the lane's.
        _app, ctx, _db = fresh_app
        _draft(ctx, "ready-lane-2", TWO_LANES, s1_lanes=[2])

        resp = mark_ready(logged_in_client, "ready-lane-2", ORIGIN)

        run = ctx.run_repo.get_by_id("ready-lane-2")
        assert run.status == RunStatus.READY, html.unescape(resp.text)[:600]
        assert stored_export(ctx, run, "samplesheet_v2")


class TestASmallerFlowcellLeavesALaneBehind:
    """The flow cell route keeps every sample's lanes: a sample on lane 8 of
    an 8-lane flow cell is on a lane the new 2-lane one does not have. The
    check then names it and Mark Ready refuses."""

    def _shrink(self, client, ctx, run_id: str):
        resp = client.post(f"/runs/{run_id}/flowcell",
                           data={"flowcell_type": TWO_LANES, "run_version": run_version(ctx, run_id)},
                           headers=ORIGIN)
        assert resp.status_code == 200, resp.text[:300]

    def test_the_lane_is_kept_and_the_check_names_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "shrink", EIGHT_LANES, s1_lanes=[8])
        assert _lane_errors(ctx, "shrink") == []

        self._shrink(logged_in_client, ctx, "shrink")

        run = ctx.run_repo.get_by_id("shrink")
        assert run.flowcell_type == TWO_LANES
        assert run.get_sample("id-S1").lanes == [8]
        assert [e.message for e in _lane_errors(ctx, "shrink")] == [_out_of_range("S1", 8, 2)]
        page = html.unescape(logged_in_client.get("/runs/shrink/validation").text)
        assert _out_of_range("S1", 8, 2) in page

    def test_mark_ready_refuses_after_the_change(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "shrink-ready", EIGHT_LANES, s1_lanes=[8])

        self._shrink(logged_in_client, ctx, "shrink-ready")
        resp = mark_ready(logged_in_client, "shrink-ready", ORIGIN)

        _assert_refused(resp, ctx, "shrink-ready", _out_of_range("S1", 8, 2))

    def test_samples_inside_the_smaller_flowcell_are_marked_ready(self, logged_in_client,
                                                                   fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "shrink-ok", EIGHT_LANES, s1_lanes=[2])

        self._shrink(logged_in_client, ctx, "shrink-ok")
        resp = mark_ready(logged_in_client, "shrink-ok", ORIGIN)

        run = ctx.run_repo.get_by_id("shrink-ok")
        assert run.status == RunStatus.READY, html.unescape(resp.text)[:600]


class TestSetLanesRefusesALaneOutsideTheFlowcell:
    """POST /runs/{run_id}/samples/set-lanes refuses any lane the flow cell
    does not have, before anything is saved (today's behaviour, pinned)."""

    def _set(self, client, run_id: str, lanes, shown=((1,),)):
        # target_lanes: what the page showed for the ticked row, as the
        # panel sends it (design note 2026-10-17).
        return client.post(f"/runs/{run_id}/samples/set-lanes", data={
            "sample_ids": json.dumps(["id-S1"]), "lanes": json.dumps(lanes),
            "target_lanes": json.dumps([list(row) for row in shown])}, headers=ORIGIN)

    @pytest.mark.parametrize("lanes", [[3], [1, 3], ["3"], [0], [-1]])
    def test_it_is_refused_and_nothing_is_saved(self, logged_in_client, fresh_app, lanes):
        _app, ctx, _db = fresh_app
        _draft(ctx, "set-lanes-out", TWO_LANES, s1_lanes=[1])

        resp = self._set(logged_in_client, "set-lanes-out", lanes)

        assert resp.status_code == 400
        assert resp.text == "Invalid lane selection. Use lane numbers between 1 and 2."
        assert ctx.run_repo.get_by_id("set-lanes-out").get_sample("id-S1").lanes == [1]

    @pytest.mark.parametrize("flowcell,lanes", [(TWO_LANES, [1, 2]), (TWO_LANES, ["2"]),
                                                (EIGHT_LANES, [8])])
    def test_lanes_inside_the_flowcell_are_saved(self, logged_in_client, fresh_app,
                                                 flowcell, lanes):
        _app, ctx, _db = fresh_app
        _draft(ctx, "set-lanes-in", flowcell, s1_lanes=[1])

        resp = self._set(logged_in_client, "set-lanes-in", lanes)

        assert resp.status_code == 200, resp.text[:300]
        assert ctx.run_repo.get_by_id("set-lanes-in").get_sample("id-S1").lanes == [
            int(lane) for lane in lanes]
