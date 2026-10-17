"""Deleting a sample from a page that is out of date is refused (design
note docs/design/2026-10-17-stale-page-checks-design.md, step 3).

A delete is the one action that cannot be put right by doing it again: the
sample, its index and its lanes are gone. The row's x button and the
panel's Delete Selected sent only the ids, so a delete from a tab loaded
before another tab's change removed a row that had since been given an
index -- and a sample the run no longer had was "deleted" with a word
about neither, the run touched as if something had happened.

Both now send the index each targeted row showed (``target_indexes``, the
field the assign and clear routes already take, F8) and are refused 409
when one has moved, or when the run no longer has one of the samples.
"""

import json
from urllib.parse import quote

import pytest

from seqsetup.models.index import Index, IndexType

from .conftest import hold_edit_lock
from .test_group_a1 import ORIGIN, PLAIN_PAIRS, RUN, _pair_kit, _run, _stored

ORIGIN = ORIGIN

STALE = "This page is out of date. Nothing was deleted. Reload the page and try again."
CHANGED = ("Nothing was deleted. Reload the page and try again. The index on these "
           "samples changed since this page was loaded: {}.")
GONE = ("The sample list changed since this page was loaded. Nothing was deleted. "
        "Reload the page and try again.")


@pytest.fixture
def two_rows(fresh_app):
    """A draft whose PAT1 and PAT2 have no index, and a kit to drop."""
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    return ctx, _pair_kit(ctx, "PlainKit", PLAIN_PAIRS)


def _indexed_behind_the_page(ctx, sid, i7="GGGGCCCCAA"):
    run = _stored(ctx)
    run.get_sample(sid).assign_index1(Index(name="other", sequence=i7, index_type=IndexType.I7))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _drop_sample(ctx, sid):
    run = _stored(ctx)
    run.remove_sample(sid)
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _everything(ctx):
    return _stored(ctx).to_dict()


def _ids(ctx):
    return [s.sample_id for s in _stored(ctx).samples]


def _delete_row(client, sid="s1", shown=(["", ""],)):
    """The row's x button: a DELETE, so htmx 2 puts its hx-vals in the query
    string (methodsThatUseUrlParams includes delete)."""
    url = f"/runs/{RUN}/samples/{sid}"
    if shown is not None:
        raw = shown if isinstance(shown, str) else json.dumps([list(row) for row in shown])
        url += f"?target_indexes={quote(raw)}"      # as htmx encodes it
    return client.delete(url, headers=ORIGIN)


def _delete_ticked(client, sids, shown=(["", ""], ["", ""])):
    data = {"sample_ids": json.dumps(sids)}
    if shown is not None:
        data["target_indexes"] = (shown if isinstance(shown, str)
                                  else json.dumps([list(row) for row in shown]))
    return client.post(f"/runs/{RUN}/samples/bulk-delete", data=data, headers=ORIGIN)


class TestTheRowsDeleteButton:
    def test_a_row_another_tab_indexed_is_not_deleted(self, logged_in_client, two_rows):
        ctx, _kit = two_rows
        _indexed_behind_the_page(ctx, "s1")
        before = _everything(ctx)

        resp = _delete_row(logged_in_client, "s1")

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == CHANGED.format("PAT1")
        assert _everything(ctx) == before

    def test_a_control_delete_of_the_row_the_page_showed(self, logged_in_client, two_rows):
        ctx, _kit = two_rows

        resp = _delete_row(logged_in_client, "s1")

        assert resp.status_code == 200, resp.text[:300]
        assert _ids(ctx) == ["PAT2"]

    def test_a_delete_with_no_shown_index_is_refused(self, logged_in_client, two_rows):
        ctx, _kit = two_rows
        before = _everything(ctx)

        resp = _delete_row(logged_in_client, "s1", shown=None)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == STALE
        assert _everything(ctx) == before

    @pytest.mark.parametrize("shown", ["", "not json", "[]", '[["A"]]', "[[1,2]]",
                                       '[["",""],["",""]]', "null"])
    def test_a_delete_with_an_unreadable_shown_index_is_refused(
            self, logged_in_client, two_rows, shown):
        ctx, _kit = two_rows
        before = _everything(ctx)

        resp = _delete_row(logged_in_client, "s1", shown=shown)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == STALE
        assert _everything(ctx) == before

    def test_a_sample_the_run_no_longer_has_is_refused(self, logged_in_client, two_rows):
        """It used to answer 200 and touch the run, as if a sample had been
        deleted."""
        ctx, _kit = two_rows
        _drop_sample(ctx, "s1")
        before = _everything(ctx)

        resp = _delete_row(logged_in_client, "s1")

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == GONE
        assert _everything(ctx) == before, "nothing was deleted, so nothing was touched"

    def test_the_row_the_page_draws_carries_the_index_its_button_sends(
            self, logged_in_client, two_rows):
        ctx, _kit = two_rows
        _indexed_behind_the_page(ctx, "s1", "ACGTACGTAC")

        page = logged_in_client.get(f"/runs/{RUN}")

        assert 'data-i7="ACGTACGTAC"' in page.text

    def test_the_button_sends_the_index_and_replaces_the_section(
            self, logged_in_client, two_rows):
        """What the browser test drives, pinned in the fast suite too: the
        button sends the row's index, and asks for the section the route
        answers with -- targeting the table nested a second section inside
        the first."""
        ctx, _kit = two_rows
        _indexed_behind_the_page(ctx, "s1", "ACGTACGTAC")

        page = logged_in_client.get(f"/runs/{RUN}").text
        button = page[page.index('hx-delete="/runs/a1-run/samples/s1'):]
        button = button[:button.index("</button>")]

        assert 'hx-target="#sample-section"' in button, button
        assert "target_indexes" in button and "ACGTACGTAC" in button, button


class TestDeleteSelected:
    def test_a_ticked_row_another_tab_indexed_refuses_the_whole_delete(
            self, logged_in_client, two_rows):
        ctx, _kit = two_rows
        _indexed_behind_the_page(ctx, "s2")
        before = _everything(ctx)

        resp = _delete_ticked(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == CHANGED.format("PAT2")
        assert _everything(ctx) == before, "a refused delete must remove nothing, not even PAT1"

    def test_a_control_delete_of_the_rows_the_page_showed(self, logged_in_client, two_rows):
        ctx, _kit = two_rows

        resp = _delete_ticked(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 200, resp.text[:300]
        assert _ids(ctx) == []

    @pytest.mark.parametrize("shown", [None, "", "not json", "[]", '[["",""]]', "null"])
    def test_a_delete_without_readable_shown_indexes_is_refused(
            self, logged_in_client, two_rows, shown):
        ctx, _kit = two_rows
        before = _everything(ctx)

        resp = _delete_ticked(logged_in_client, ["s1", "s2"], shown=shown)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == STALE
        assert _everything(ctx) == before

    def test_a_ticked_sample_the_run_no_longer_has_is_refused(self, logged_in_client, two_rows):
        """It used to delete the rest and count only those, with no word
        about the one that was already gone."""
        ctx, _kit = two_rows
        _drop_sample(ctx, "s2")
        before = _everything(ctx)

        resp = _delete_ticked(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == GONE
        assert _everything(ctx) == before

    def test_each_rows_shown_index_is_matched_to_that_row(self, logged_in_client, two_rows):
        """The entries are read in the order the ids are sent, not as a set:
        reading PAT1's index against PAT2's row would refuse a page that is
        right, and let through one that is not."""
        ctx, kit = two_rows
        _indexed_behind_the_page(ctx, "s1", "AAAACCCCGG")
        _indexed_behind_the_page(ctx, "s2", "TTTTGGGGAA")
        shown = [["TTTTGGGGAA", ""], ["AAAACCCCGG", ""]]   # the two rows' own, swapped

        swapped = _delete_ticked(logged_in_client, ["s1", "s2"], shown=shown)
        assert swapped.status_code == 409, swapped.text[:300]
        assert _ids(ctx) == ["PAT1", "PAT2"]

        right = _delete_ticked(logged_in_client, ["s1", "s2"],
                               shown=[["AAAACCCCGG", ""], ["TTTTGGGGAA", ""]])
        assert right.status_code == 200, right.text[:300]
        assert _ids(ctx) == []

    def test_an_index_another_tab_cleared_also_refuses_the_delete(
            self, logged_in_client, two_rows):
        """The other direction: the page showed an index, and it is gone."""
        ctx, kit = two_rows
        _indexed_behind_the_page(ctx, "s1", "AAAACCCCGG")
        before = _everything(ctx)

        resp = _delete_ticked(logged_in_client, ["s1"],
                              shown=[["AAAACCCCGG", ""]])
        assert resp.status_code == 200, resp.text[:300]   # control: what it shows

        _run_again = _run(ctx, ["PAT1", "PAT2"])
        _indexed_behind_the_page(ctx, "s1", "AAAACCCCGG")
        run = _stored(ctx)
        run.get_sample("s1").clear_index1()
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)
        before = _everything(ctx)

        resp = _delete_ticked(logged_in_client, ["s1"], shown=[["AAAACCCCGG", ""]])

        assert resp.status_code == 409, resp.text[:300]
        assert _everything(ctx) == before

    def test_a_second_delete_uses_what_the_first_answer_rendered(
            self, logged_in_client, two_rows):
        """The answer re-renders the table, so the rows it shows carry the
        indexes the next delete must send."""
        ctx, kit = two_rows
        _indexed_behind_the_page(ctx, "s2", "AAAACCCCGG")

        first = _delete_ticked(logged_in_client, ["s1"], shown=[["", ""]])
        assert first.status_code == 200, first.text[:300]
        assert 'data-i7="AAAACCCCGG"' in first.text, first.text[:300]

        second = _delete_ticked(logged_in_client, ["s2"], shown=[["AAAACCCCGG", ""]])
        assert second.status_code == 200, second.text[:300]
        assert _ids(ctx) == []

    def test_the_same_sample_ticked_twice_is_still_deleted(self, logged_in_client, two_rows):
        ctx, _kit = two_rows

        resp = _delete_ticked(logged_in_client, ["s1", "s1"], shown=[["", ""], ["", ""]])

        assert resp.status_code == 200, resp.text[:300]
        assert _ids(ctx) == ["PAT2"]
