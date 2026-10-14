"""A LIMS worklist import puts its samples on the lanes picked for it, never
silently on lane 1 (index mix-up audit, 2026-10-14; the user's choice "Same
rules as paste").

The import put every sample on lane 1, whatever the run's flowcell, and the
preview did not show a lane. Now the worksheet picker has the paste's lane
boxes (lane 1 ticked to start), the preview shows the lanes, and the import
uses the lanes its preview showed: they are part of the plan it compares.
"""

import html
import re

from .test_lims_preview_binding import CHANGED, ORIGIN, RUN, _ids, _lims, _plan, _run

PICK_A_LANE = "Pick at least one lane for the new samples."


def _preview(client, lanes=("1",), worklist_id="W1"):
    return client.get(f"/runs/{RUN}/samples/preview-worklist",
                      params={"worklist_id": worklist_id, "lanes": list(lanes)})


def _shown_lanes(page):
    return re.findall(r'<input type="hidden" name="lanes" value="(\d+)">', page)


def _import(client, page, lanes=None):
    return client.post(f"/runs/{RUN}/samples/fetch-worklist", data={
        "worklist_id": "W1", "plan": _plan(page) or "",
        "lanes": _shown_lanes(page) if lanes is None else list(lanes),
    }, headers=ORIGIN)


def _lanes(ctx):
    return {s.sample_id: s.lanes for s in ctx.run_repo.get_by_id(RUN).samples}


class TestThePickerOffersTheLanes:

    def test_the_flowcells_lanes_with_lane_1_ticked(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        page = logged_in_client.get(f"/runs/{RUN}/samples/worklists").text

        boxes = re.findall(r'<input type="checkbox" name="lanes" value="(\d+)"( checked)?>', page)
        assert [lane for lane, _ in boxes] == [str(n) for n in range(1, 9)]
        assert [lane for lane, checked in boxes if checked] == ["1"]
        assert 'hx-include="#worklist-select, #worklist-lanes"' in page


class TestTheImportUsesThePreviewsLanes:

    def test_the_lanes_picked_are_shown_and_stored(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        page = _preview(logged_in_client, lanes=("2", "3")).text
        assert "to lanes 2, 3" in page
        assert _shown_lanes(page) == ["2", "3"]
        r = _import(logged_in_client, page)

        assert r.status_code == 200, r.text[:300]
        assert _lanes(ctx) == {"P1": [2, 3], "P2": [2, 3]}

    def test_a_preview_without_a_lane_is_refused(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        page = _preview(logged_in_client, lanes=()).text

        assert PICK_A_LANE in page
        assert _plan(page) is None

    def test_a_lane_outside_the_flowcell_is_refused(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        page = _preview(logged_in_client, lanes=("9",)).text

        assert "Use lane numbers between 1 and 8." in page
        assert _plan(page) is None

    def test_an_import_with_other_lanes_than_its_preview_is_refused(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        page = _preview(logged_in_client, lanes=("2",)).text
        r = _import(logged_in_client, page, lanes=("3",))

        assert r.status_code == 409
        assert CHANGED in r.text
        assert _ids(ctx) == []

    def test_an_import_without_lanes_is_refused(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        _lims(ctx, monkeypatch)

        page = _preview(logged_in_client).text
        r = _import(logged_in_client, page, lanes=())

        assert r.status_code == 400
        assert PICK_A_LANE in r.text
        assert _ids(ctx) == []


class TestALimsLaneFieldIsRefused:

    def test_the_preview_names_it(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _run(ctx)
        rows = _lims(ctx, monkeypatch)
        rows[0]["lane"] = 2

        page = html.unescape(_preview(logged_in_client).text)

        assert 'LIMS row(s) 1: the field(s) "lane" look like an index or a lane' in page
        assert _plan(page) is None
