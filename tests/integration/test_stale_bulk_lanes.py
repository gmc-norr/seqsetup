"""A bulk lane Apply from a page loaded before another tab changed those
rows' lanes is refused, and nothing is saved (design note
docs/design/2026-10-17-stale-page-checks-design.md, step 1).

The edit lock is per user, so two tabs of one person both pass it, and the
run is reloaded on every request, so the repository's version check only
catches a write landing inside one request. The lane panel sent only the
ticked sample ids and the lanes to write, so an Apply from the stale tab
overwrote the other tab's lanes with no word -- and a lane decides which
lane a patient's reads land in, which no sample-sheet check can see.

The panel now sends the lanes each ticked row showed (``target_lanes``, from
``data-lanes`` on the row), as the index routes send ``target_indexes``
(F8). A row whose stored lanes are not the ones the page showed refuses the
whole Apply, 409, with nothing written; a request without the field is
refused 400; a ticked sample the run no longer has is refused 409.
"""

import json

import pytest

from .conftest import hold_edit_lock
from .test_group_a1 import ORIGIN, RUN, _run, _stored

ORIGIN = ORIGIN

STALE = "This page is out of date. Nothing was saved. Reload the page and try again."
GONE = ("The sample list changed since this page was loaded. "
        "Reload the page and try again.")


@pytest.fixture
def two_rows(fresh_app):
    """A draft whose PAT1 and PAT2 are both on lane 1."""
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    return ctx


def _set_lanes_behind_the_page(ctx, sid, lanes):
    """Another tab's Apply, as it would leave the run while this page sat
    open."""
    run = _stored(ctx)
    run.get_sample(sid).lanes = lanes
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _apply(client, sids, lanes, shown=((1,), (1,))):
    """The lane panel's Apply, as applyBulkLanesForm sends it. ``shown`` is
    what the page showed in each ticked row: a list of lane lists, a raw
    string, or None (not sent at all)."""
    data = {"sample_ids": json.dumps(sids), "lanes": json.dumps(lanes)}
    if shown is not None:
        data["target_lanes"] = (shown if isinstance(shown, str)
                                else json.dumps([list(row) for row in shown]))
    return client.post(f"/runs/{RUN}/samples/set-lanes", data=data, headers=ORIGIN)


def _lanes(ctx):
    return [(s.sample_id, s.lanes) for s in _stored(ctx).samples]


def _everything(ctx):
    """The whole stored run. A refusal writes nothing at all -- not the
    lanes, and not run.touch()'s updated_at either."""
    return _stored(ctx).to_dict()


class TestAnApplyOnChangedLanesIsRefused:
    def test_a_row_another_tab_moved_refuses_the_whole_apply(self, logged_in_client, two_rows):
        ctx = two_rows
        _set_lanes_behind_the_page(ctx, "s2", [3])
        before = _everything(ctx)

        resp = _apply(logged_in_client, ["s1", "s2"], [2])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was saved. Reload the page and try again. The lanes on these "
            "samples changed since this page was loaded: PAT2.")
        assert _everything(ctx) == before, "a refused Apply must save nothing, not even PAT1"

    def test_the_order_of_the_stored_lanes_counts(self, logged_in_client, two_rows):
        ctx = two_rows
        _set_lanes_behind_the_page(ctx, "s1", [2, 1])
        before = _lanes(ctx)

        resp = _apply(logged_in_client, ["s1"], [4], shown=[[1, 2]])

        assert resp.status_code == 409, resp.text[:300]
        assert _lanes(ctx) == before

    def test_a_control_apply_on_the_lanes_the_page_showed(self, logged_in_client, two_rows):
        ctx = two_rows

        resp = _apply(logged_in_client, ["s1", "s2"], [2, 3])

        assert resp.status_code == 200, resp.text[:300]
        assert _lanes(ctx) == [("PAT1", [2, 3]), ("PAT2", [2, 3])]

    def test_a_second_apply_uses_the_lanes_the_answer_rendered(self, logged_in_client, two_rows):
        """The answer re-renders the rows, so the page's own change is not
        stale a moment later."""
        ctx = two_rows
        first = _apply(logged_in_client, ["s1", "s2"], [2, 3])
        assert 'data-lanes="2,3"' in first.text, first.text[:300]

        resp = _apply(logged_in_client, ["s1", "s2"], [4], shown=[[2, 3], [2, 3]])

        assert resp.status_code == 200, resp.text[:300]
        assert _lanes(ctx) == [("PAT1", [4]), ("PAT2", [4])]

    def test_each_rows_shown_lanes_are_matched_to_that_row(self, logged_in_client, two_rows):
        """The entries are read in the order the ids are sent, not as a set:
        reading PAT1's lanes against PAT2's row would refuse a page that is
        right, and pass one that is not."""
        ctx = two_rows
        _set_lanes_behind_the_page(ctx, "s2", [2])

        fresh = _apply(logged_in_client, ["s1", "s2"], [5], shown=[[1], [2]])
        assert fresh.status_code == 200, fresh.text[:300]
        assert _lanes(ctx) == [("PAT1", [5]), ("PAT2", [5])]

        _set_lanes_behind_the_page(ctx, "s1", [1])
        _set_lanes_behind_the_page(ctx, "s2", [2])
        swapped = _apply(logged_in_client, ["s1", "s2"], [6], shown=[[2], [1]])
        assert swapped.status_code == 409, swapped.text[:300]
        assert _lanes(ctx) == [("PAT1", [1]), ("PAT2", [2])]

    @pytest.mark.parametrize("shown", [None, "", "not json", "[]", "[[1]]", '"1"',
                                       "[[1],[2],[3]]", "[1,1]", '[["1"],["1"]]',
                                       "[[true],[1]]", "null"])
    def test_an_apply_that_sends_no_readable_shown_lanes_is_refused(
            self, logged_in_client, two_rows, shown):
        ctx = two_rows
        before = _everything(ctx)

        resp = _apply(logged_in_client, ["s1", "s2"], [2], shown=shown)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == STALE
        assert _everything(ctx) == before

    def test_a_ticked_sample_the_run_no_longer_has_is_refused(self, logged_in_client, two_rows):
        ctx = two_rows
        run = _stored(ctx)
        run.remove_sample("s2")
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)
        before = _everything(ctx)

        resp = _apply(logged_in_client, ["s1", "s2"], [2])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == GONE
        assert _everything(ctx) == before

    def test_a_redrawn_single_row_carries_its_lanes_too(self, logged_in_client, two_rows):
        """A row redrawn on its own (an index drop or clear, a settings box)
        comes from the same template: without data-lanes on it, every later
        Apply would be refused until the page was reloaded."""
        ctx = two_rows

        row = logged_in_client.post(
            f"/runs/{RUN}/samples/s1/settings", data={"override_cycles": ""},
            headers=ORIGIN)

        assert row.status_code == 200, row.text[:300]
        assert 'data-lanes="1"' in row.text
        assert _lanes(ctx)[0] == ("PAT1", [1])

    def test_the_lanes_the_page_shows_are_the_stored_ones(self, logged_in_client, two_rows):
        """The row carries what the server would compare, so a page that
        reads it back is never refused for a lane nobody changed."""
        ctx = two_rows
        _set_lanes_behind_the_page(ctx, "s1", [3, 1])

        page = logged_in_client.get(f"/runs/{RUN}")

        assert 'data-lanes="3,1"' in page.text
        assert 'data-lanes="1"' in page.text
