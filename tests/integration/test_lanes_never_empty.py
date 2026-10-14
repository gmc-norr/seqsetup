"""The lane panel never saves a sample with no lane (index mix-up audit #5,
2026-10-14; the user's choice "Tick every box").

Apply with no lane ticked sent an empty lane list, and Clear sent the same
with no question. With a Lane column in the profile (the shipped one) that
is a Check error, "Pick their lanes"; without one it put the samples in
every lane. Either way it happened without a word. Now an empty lane list
is refused, and the panel's All lanes ticks every lane box, as the paste's
does, so every lane is listed.
"""

import json
import re

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}
RUN_ID = "never-empty-run"
TICK_A_LANE = "Tick at least one lane. Nothing was saved."


def _run(ctx):
    run = SequencingRun(
        id=RUN_ID, run_name="Never empty", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
    run.add_sample(Sample(id="s1", sample_id="P1", lanes=[2]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, RUN_ID)


def _set(client, lanes):
    return client.post(f"/runs/{RUN_ID}/samples/set-lanes", data={
        "sample_ids": json.dumps(["s1"]), "lanes": json.dumps(lanes),
    }, headers=ORIGIN)


def _lanes(ctx):
    return ctx.run_repo.get_by_id(RUN_ID).get_sample("s1").lanes


class TestAnEmptyLaneListIsRefused:
    """set-lanes saves only a list with at least one lane."""

    @pytest.mark.parametrize("lanes", [[], [""], [" "]])
    def test_nothing_is_saved(self, logged_in_client, fresh_app, lanes):
        _app, ctx, _db = fresh_app
        _run(ctx)

        r = _set(logged_in_client, lanes)

        assert r.status_code == 400
        assert r.text == TICK_A_LANE
        assert _lanes(ctx) == [2]

    def test_ticked_lanes_are_set_as_before(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        r = _set(logged_in_client, [3, 4])

        assert r.status_code == 200, r.text[:300]
        assert _lanes(ctx) == [3, 4]

    def test_every_lane_is_listed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        r = _set(logged_in_client, list(range(1, 9)))

        assert r.status_code == 200, r.text[:300]
        assert _lanes(ctx) == [1, 2, 3, 4, 5, 6, 7, 8]


class TestThePanel:
    """The lane panel has All lanes in place of Clear (what it does is in
    tests/browser/test_lanes_never_empty.py)."""

    def test_it_has_all_lanes_and_no_clear(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        page = logged_in_client.get(f"/runs/{RUN_ID}").text

        assert re.search(r'data-action="bulk-all-lanes"[^>]*>All lanes</button>', page)
        assert 'data-action="bulk-clear-lanes"' not in page
