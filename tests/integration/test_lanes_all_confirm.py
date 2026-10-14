"""Putting samples in every lane takes its own button and a yes (index
mix-up audit #5, 2026-10-14; the user's choice "Refuse + confirm").

The lane panel's Apply with no lane ticked sent an empty lane list, which
means every lane, and Clear sent the same with no question: a sample meant
for lane 2 went to all lanes without a word. Now an empty lane list is
refused unless the "All lanes" button sent it (all_lanes=yes), and that
button asks first.
"""

import json
import re

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}
RUN_ID = "all-lanes-run"
TICK_A_LANE = "Tick at least one lane. Nothing was saved."


def _run(ctx):
    run = SequencingRun(
        id=RUN_ID, run_name="All lanes", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
    run.add_sample(Sample(id="s1", sample_id="P1", lanes=[2]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, RUN_ID)


def _set(client, lanes, **form):
    return client.post(f"/runs/{RUN_ID}/samples/set-lanes", data={
        "sample_ids": json.dumps(["s1"]), "lanes": json.dumps(lanes), **form,
    }, headers=ORIGIN)


def _lanes(ctx):
    return ctx.run_repo.get_by_id(RUN_ID).get_sample("s1").lanes


class TestAnEmptyLaneListNeedsTheAllLanesButton:

    @pytest.mark.parametrize("lanes", [[], [""], [" "]])
    @pytest.mark.parametrize("form", [{}, {"all_lanes": ""}, {"all_lanes": "no"}])
    def test_without_it_nothing_is_saved(self, logged_in_client, fresh_app, lanes, form):
        _app, ctx, _db = fresh_app
        _run(ctx)

        r = _set(logged_in_client, lanes, **form)

        assert r.status_code == 400
        assert r.text == TICK_A_LANE
        assert _lanes(ctx) == [2]

    def test_with_it_the_sample_goes_to_every_lane(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        r = _set(logged_in_client, [], all_lanes="yes")

        assert r.status_code == 200, r.text[:300]
        assert _lanes(ctx) == []

    def test_ticked_lanes_are_set_as_before(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        r = _set(logged_in_client, [3, 4], all_lanes="")

        assert r.status_code == 200, r.text[:300]
        assert _lanes(ctx) == [3, 4]


class TestThePanel:

    def test_it_has_an_all_lanes_button_and_no_lane_clear(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        page = logged_in_client.get(f"/runs/{RUN_ID}").text

        assert re.search(r'data-action="bulk-all-lanes"[^>]*>All lanes</button>', page)
        assert 'data-action="bulk-clear-lanes"' not in page
        form = re.search(r'<form id="bulk-lanes-form".*?</form>', page, re.S).group(0)
        assert '<input type="hidden" name="all_lanes" id="bulk-all-lanes">' in form
