"""A row's own Override Cycles or mismatch box, saved from a page that is
out of date, is refused (design note
docs/design/2026-10-17-stale-page-checks-design.md, step 4).

These boxes are F3's code (a row save keeps typing): each saves on its
own, its answer replaces nothing (hx-swap="none"), and the saves of one
row go one after another (hx-sync). The box sent only its new value, so a
save from a tab loaded before another tab's change overwrote it with no
word -- and an Override Cycles that fits the run is something no check can
see.

The box now sends what the page showed for it: its defaultValue, which
app.js sets to the stored value on every answer, read when the request is
issued rather than when it is queued, so a save waiting its turn says what
the one before it stored.
"""

import pytest

from .conftest import hold_edit_lock
from .test_group_a1 import ORIGIN, RUN, _run, _stored

ORIGIN = ORIGIN

STALE = "This page is out of date. Nothing was saved. Reload the page and try again."


@pytest.fixture
def two_rows(fresh_app):
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    return ctx


def _behind_the_page(ctx, sid, **fields):
    run = _stored(ctx)
    for name, value in fields.items():
        setattr(run.get_sample(sid), name, value)
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _everything(ctx):
    return _stored(ctx).to_dict()


def _save(client, field, value, shown="", sid="s1"):
    """One box saving, as the row sends it: its own field and what the page
    showed for it. ``shown=None`` sends no shown value at all."""
    data = {field: value}
    if shown is not None:
        data["target_setting"] = shown
    return client.post(f"/runs/{RUN}/samples/{sid}/settings", data=data, headers=ORIGIN)


def _row(ctx, sid="s1"):
    sample = _stored(ctx).get_sample(sid)
    return (sample.override_cycles, sample.barcode_mismatches_index1,
            sample.barcode_mismatches_index2)


class TestTheMismatchBoxes:
    def test_a_box_another_tab_changed_is_not_overwritten(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", barcode_mismatches_index1=2)
        before = _everything(ctx)

        resp = _save(logged_in_client, "barcode_mismatches_index1", "0", shown="1")

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was saved. Reload the page and try again. The barcode mismatches "
            "on these samples changed since this page was loaded: PAT1.")
        assert _everything(ctx) == before

    def test_a_control_save_of_what_the_box_showed(self, logged_in_client, two_rows):
        ctx = two_rows

        resp = _save(logged_in_client, "barcode_mismatches_index1", "0", shown="1")

        assert resp.status_code == 200, resp.text[:300]
        assert _row(ctx) == (None, 0, 1)

    def test_the_other_column_changing_is_not_this_box_business(
            self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", barcode_mismatches_index2=2)

        resp = _save(logged_in_client, "barcode_mismatches_index1", "0", shown="1")

        assert resp.status_code == 200, resp.text[:300]
        assert _row(ctx) == (None, 0, 2)

    def test_a_cleared_box_is_compared_as_empty(self, logged_in_client, two_rows):
        """The box shows "" for the default, so that is what it sends."""
        ctx = two_rows
        _behind_the_page(ctx, "s1", barcode_mismatches_index1=None)

        right = _save(logged_in_client, "barcode_mismatches_index1", "2", shown="")
        assert right.status_code == 200, right.text[:300]
        assert _row(ctx) == (None, 2, 1)

        stale = _save(logged_in_client, "barcode_mismatches_index1", "0", shown="")
        assert stale.status_code == 409, stale.text[:300]
        assert _row(ctx) == (None, 2, 1)


class TestTheOverrideCyclesBox:
    def test_a_box_another_tab_changed_is_not_overwritten(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", override_cycles="U8Y143;I10;I10;Y151")
        before = _everything(ctx)

        resp = _save(logged_in_client, "override_cycles", "Y151;I10;I10;Y151", shown="")

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was saved. Reload the page and try again. The Override Cycles "
            "on these samples changed since this page was loaded: PAT1.")
        assert _everything(ctx) == before

    def test_a_control_save_of_what_the_box_showed(self, logged_in_client, two_rows):
        ctx = two_rows

        resp = _save(logged_in_client, "override_cycles", "Y151;I10;I10;Y151", shown="")

        assert resp.status_code == 200, resp.text[:300]
        assert _row(ctx)[0] == "Y151;I10;I10;Y151"

    def test_a_second_save_uses_what_the_first_stored(self, logged_in_client, two_rows):
        """The queue sends one save after another; the second says what the
        first stored, which is what the answer put in the box."""
        ctx = two_rows
        first = _save(logged_in_client, "override_cycles", "Y151;I10;I10;Y151", shown="")
        assert first.status_code == 200, first.text[:300]
        assert 'value="Y151;I10;I10;Y151"' in first.text, first.text[:300]

        second = _save(logged_in_client, "override_cycles", "Y150N1;I10;I10;Y151",
                       shown="Y151;I10;I10;Y151")

        assert second.status_code == 200, second.text[:300]
        assert _row(ctx)[0] == "Y150N1;I10;I10;Y151"


class TestWhatIsRefusedAndWhatIsNot:
    @pytest.mark.parametrize("field,value", [("override_cycles", "Y151;I10;I10;Y151"),
                                             ("barcode_mismatches_index1", "0"),
                                             ("barcode_mismatches_index2", "0")])
    def test_a_save_with_no_shown_value_is_refused(self, logged_in_client, two_rows,
                                                   field, value):
        ctx = two_rows
        before = _everything(ctx)

        resp = _save(logged_in_client, field, value, shown=None)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == STALE
        assert _everything(ctx) == before

    def test_a_request_that_writes_nothing_needs_no_shown_value(
            self, logged_in_client, two_rows):
        """No box sends one, and nothing is compared because nothing is
        written: today's behaviour, pinned."""
        ctx = two_rows

        resp = logged_in_client.post(f"/runs/{RUN}/samples/s1/settings", data={},
                                     headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _row(ctx) == (None, 1, 1)

    def test_a_sample_the_run_no_longer_has_is_still_refused(self, logged_in_client, two_rows):
        ctx = two_rows
        run = _stored(ctx)
        run.remove_sample("s1")
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)

        resp = _save(logged_in_client, "barcode_mismatches_index1", "0", shown="1")

        assert resp.status_code == 404, resp.text[:300]
        assert resp.text == "Sample not found"

    def test_a_bad_value_is_still_refused_for_what_it_is(self, logged_in_client, two_rows):
        """The box's own refusals come first: a page that is out of date and
        a value out of range are two different things to put right."""
        ctx = two_rows
        before = _everything(ctx)

        resp = _save(logged_in_client, "barcode_mismatches_index1", "5", shown="1")

        assert resp.status_code == 400, resp.text[:300]
        assert "0, 1 or 2" in resp.text
        assert _everything(ctx) == before
