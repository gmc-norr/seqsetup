"""A single-row index assign or clear is refused when that row's index
changed since the page was loaded (outside review of f490536, finding F8;
index mix-up audit item B4).

A multi-index drop already names the index each target row showed and is
refused when one has moved (``target_indexes``, assign-indexes-bulk). The
three single-row routes -- assign-index, clear-index and
assign-index-to-selected -- asked nothing, so a drop or a clear from a page
loaded before another tab's change replaced or removed that change without a
word, and the lab would see this page's index where the other tab had just
put another. The index safety net cannot catch it: both requests are
well-formed and each is applied exactly as asked.

The three routes now take the same ``target_indexes`` field, refuse 400 when
it is missing or unreadable (as the kit fingerprint is refused), and refuse
409 naming the samples whose index has moved, with nothing written.
"""

import json

import pytest

from seqsetup.models.index import Index, IndexType

from .conftest import hold_edit_lock
from .test_group_a1 import ORIGIN, PLAIN_PAIRS, RUN, _pair_kit, _run, _stored

ORIGIN = ORIGIN
EMPTY = [["", ""]]


@pytest.fixture
def two_empty_rows(fresh_app):
    """A draft whose PAT1 and PAT2 have no index, and a kit to drop."""
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    return ctx, _pair_kit(ctx, "PlainKit", PLAIN_PAIRS)


def _assign_behind_the_page(ctx, sid, i7, i5=""):
    """Another tab gives one sample an index, as a request that landed
    while this page sat open would leave it."""
    run = _stored(ctx)
    sample = run.get_sample(sid)
    sample.assign_index1(Index(name="other", sequence=i7, index_type=IndexType.I7))
    if i5:
        sample.assign_index2(Index(name="other", sequence=i5, index_type=IndexType.I5))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _indexes(ctx):
    return [(s.sample_id, s.index1_sequence, s.index2_sequence) for s in _stored(ctx).samples]


def _drop_one(client, kit, sid="s1", shown=EMPTY, pair=0):
    """A one-pair drop on one row, as handleIndexDrop sends it. ``shown`` is
    what the page showed in that row: a list of [i7, i5], a raw string, or
    None (not sent at all)."""
    data = {"index_pair_id": f"{kit.name}_P{pair}", "kit_id": kit.kit_id,
            "kit_fingerprint": kit.fingerprint(), "context": "", "existing_ids": ""}
    if shown is not None:
        data["target_indexes"] = shown if isinstance(shown, str) else json.dumps(shown)
    return client.post(f"/runs/{RUN}/samples/{sid}/assign-index", data=data, headers=ORIGIN)


def _clear_one(client, sid="s1", shown=EMPTY, index_type=""):
    data = {}
    if shown is not None:
        data["target_indexes"] = shown if isinstance(shown, str) else json.dumps(shown)
    url = f"/runs/{RUN}/samples/{sid}/clear-index"
    if index_type:
        url += f"?index_type={index_type}"
    return client.post(url, data=data, headers=ORIGIN)


def _drop_on_ticked(client, kit, sids, shown, pair=0):
    data = {"sample_ids": json.dumps(sids), "index_pair_id": f"{kit.name}_P{pair}",
            "index_id": "", "index_type": "", "kit_id": kit.kit_id,
            "kit_fingerprint": kit.fingerprint(), "context": "", "existing_ids": ""}
    if shown is not None:
        data["target_indexes"] = shown if isinstance(shown, str) else json.dumps(shown)
    return client.post(f"/runs/{RUN}/samples/assign-index-to-selected", data=data,
                       headers=ORIGIN)


class TestADropOnAChangedRowIsRefused:
    def test_a_drop_on_a_row_whose_index_another_tab_set(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _assign_behind_the_page(ctx, "s1", "GGGGCCCCAA")
        before = _indexes(ctx)

        resp = _drop_one(logged_in_client, kit, "s1", EMPTY)

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was assigned. Reload the page and drag again. The index on these "
            "samples changed since this page was loaded: PAT1.")
        assert _indexes(ctx) == before

    def test_a_drop_on_a_row_whose_index_another_tab_replaced(
            self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _drop_one(logged_in_client, kit, "s1", EMPTY, pair=0)      # this page's own drop
        shown = [[PLAIN_PAIRS[0][0], PLAIN_PAIRS[0][1]]]
        _assign_behind_the_page(ctx, "s1", "GGGGCCCCAA", "TTTTAAAACC")
        before = _indexes(ctx)

        resp = _drop_one(logged_in_client, kit, "s1", shown, pair=1)

        assert resp.status_code == 409, resp.text[:300]
        assert _indexes(ctx) == before

    def test_a_control_drop_on_the_row_the_page_showed(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows

        resp = _drop_one(logged_in_client, kit, "s1", EMPTY)

        assert resp.status_code == 200, resp.text[:300]
        assert _indexes(ctx)[0] == ("PAT1", PLAIN_PAIRS[0][0], PLAIN_PAIRS[0][1])

    @pytest.mark.parametrize("shown", [None, "", "not json", "[]", '[["A"]]',
                                       '[["A","B"],["C","D"]]', '"ACGT"', "[[1,2]]"])
    def test_a_drop_that_sends_no_readable_shown_index_is_refused(
            self, logged_in_client, two_empty_rows, shown):
        ctx, kit = two_empty_rows
        before = _indexes(ctx)

        resp = _drop_one(logged_in_client, kit, "s1", shown)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == "This page is out of date. Reload the page and drag again."
        assert _indexes(ctx) == before


class TestAClearOnAChangedRowIsRefused:
    def test_a_clear_of_an_index_another_tab_replaced(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _drop_one(logged_in_client, kit, "s1", EMPTY)
        shown = [[PLAIN_PAIRS[0][0], PLAIN_PAIRS[0][1]]]
        _assign_behind_the_page(ctx, "s1", "GGGGCCCCAA", "TTTTAAAACC")
        before = _indexes(ctx)

        resp = _clear_one(logged_in_client, "s1", shown)

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was cleared. Reload the page and try again. The index on these "
            "samples changed since this page was loaded: PAT1.")
        assert _indexes(ctx) == before

    def test_a_control_clear_of_the_index_the_page_showed(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _drop_one(logged_in_client, kit, "s1", EMPTY)
        shown = [[PLAIN_PAIRS[0][0], PLAIN_PAIRS[0][1]]]

        resp = _clear_one(logged_in_client, "s1", shown)

        assert resp.status_code == 200, resp.text[:300]
        assert _indexes(ctx)[0] == ("PAT1", None, None)

    def test_a_clear_that_sends_no_shown_index_is_refused(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _drop_one(logged_in_client, kit, "s1", EMPTY)
        before = _indexes(ctx)

        resp = _clear_one(logged_in_client, "s1", None)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == "This page is out of date. Reload the page and try again."
        assert _indexes(ctx) == before


class TestTickedRowsAreRefusedTheSameWay:
    def test_one_changed_row_refuses_the_whole_drop(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _assign_behind_the_page(ctx, "s2", "GGGGCCCCAA")
        before = _indexes(ctx)

        resp = _drop_on_ticked(logged_in_client, kit, ["s1", "s2"], [["", ""], ["", ""]])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was assigned. Reload the page and drag again. The index on these "
            "samples changed since this page was loaded: PAT2.")
        assert _indexes(ctx) == before, "a refused drop must assign nothing, not even to PAT1"

    def test_a_control_drop_on_the_rows_the_page_showed(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows

        resp = _drop_on_ticked(logged_in_client, kit, ["s1", "s2"], [["", ""], ["", ""]])

        assert resp.status_code == 200, resp.text[:300]
        assert [(s[1], s[2]) for s in _indexes(ctx)] == [
            (PLAIN_PAIRS[0][0], PLAIN_PAIRS[0][1])] * 2

    def test_a_sample_the_run_no_longer_has_refuses_the_drop(
            self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        run = _stored(ctx)
        run.remove_sample("s2")
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)
        before = _indexes(ctx)

        resp = _drop_on_ticked(logged_in_client, kit, ["s1", "s2"], [["", ""], ["", ""]])

        assert resp.status_code == 409, resp.text[:300]
        assert "changed since this page was loaded" in resp.text
        assert _indexes(ctx) == before

    def test_a_drop_whose_shown_list_is_the_wrong_length_is_refused(
            self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        before = _indexes(ctx)

        resp = _drop_on_ticked(logged_in_client, kit, ["s1", "s2"], [["", ""]])

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == "This page is out of date. Reload the page and drag again."
        assert _indexes(ctx) == before
