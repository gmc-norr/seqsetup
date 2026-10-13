"""A multi-index drop is refused when a target row's index changed in
another tab.

The drop already names the rows the page showed, so a row added or removed
elsewhere is refused. The index on those rows was not checked: a second tab
that assigned, replaced or cleared one left the first tab able to overwrite
it with no warning, and the lab would see the drop's indexes where it had
just put others. The drop now sends the i7 and i5 each target row showed and
the server refuses, with 409 and the sample IDs, when any of them has moved.
"""

import json

import pytest

from seqsetup.models.index import Index, IndexType

from .test_group_a1 import ORIGIN, PLAIN_PAIRS, RUN, _pair_kit, _run, _stored

ORIGIN = ORIGIN


def _drop(client, kit, count, shown, start="s1", targets=None):
    """A multi-index drop of the kit's first ``count`` pairs on ``start``.
    ``shown`` is what the page showed in each target row, as the page sends
    it: a list of [i7, i5], a raw string, or None (not sent at all)."""
    data = {
        "start_sample_id": start,
        "indexes_json": json.dumps([
            {"id": f"{kit.name}_P{k}", "type": "pair", "kit_id": kit.kit_id}
            for k in range(count)
        ]),
        "target_sample_ids": json.dumps(
            targets if targets is not None else [f"s{k}" for k in range(1, count + 1)]),
    }
    if shown is not None:
        data["target_indexes"] = shown if isinstance(shown, str) else json.dumps(shown)
    return client.post(f"/runs/{RUN}/samples/assign-indexes-bulk", data=data, headers=ORIGIN)


def _assign_behind_the_page(ctx, sid, i7, i5=""):
    """Another tab gives one sample an index."""
    run = _stored(ctx)
    sample = run.get_sample(sid)
    sample.assign_index1(Index(name="other", sequence=i7, index_type=IndexType.I7))
    if i5:
        sample.assign_index2(Index(name="other", sequence=i5, index_type=IndexType.I5))
    ctx.run_repo.save(run)


def _indexes(ctx):
    return [(s.sample_id, s.index1_sequence, s.index2_sequence) for s in _stored(ctx).samples]


@pytest.fixture
def two_empty_rows(fresh_app):
    """A draft whose PAT1 and PAT2 have no index, and a kit to drop."""
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    return ctx, _pair_kit(ctx, "PlainKit", PLAIN_PAIRS)


EMPTY_TWO = [["", ""], ["", ""]]


class TestADropOntoAChangedIndexIsRefused:
    def test_an_index_assigned_in_another_tab(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _assign_behind_the_page(ctx, "s2", "GGGGCCCCAA")
        before = _indexes(ctx)

        resp = _drop(logged_in_client, kit, 2, EMPTY_TWO)

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "The index on PAT2 changed since this page was loaded. Nothing was assigned. "
            "Reload the page and drag again.")
        assert _indexes(ctx) == before

    def test_every_changed_sample_is_named(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _assign_behind_the_page(ctx, "s1", "GGGGCCCCAA")
        _assign_behind_the_page(ctx, "s2", "AAAAGGGGTT")
        before = _indexes(ctx)

        resp = _drop(logged_in_client, kit, 2, EMPTY_TWO)

        assert resp.status_code == 409
        assert resp.text.startswith("The index on PAT1, PAT2 changed since this page was loaded.")
        assert _indexes(ctx) == before

    def test_an_i5_changed_on_its_own(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        run = _stored(ctx)
        run.get_sample("s2").assign_index2(
            Index(name="other", sequence="TTTTAAAACC", index_type=IndexType.I5))
        ctx.run_repo.save(run)
        before = _indexes(ctx)

        resp = _drop(logged_in_client, kit, 2, EMPTY_TWO)

        assert resp.status_code == 409
        assert resp.text.startswith("The index on PAT2 changed since this page was loaded.")
        assert _indexes(ctx) == before

    def test_an_index_cleared_in_another_tab(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _assign_behind_the_page(ctx, "s2", "GGGGCCCCAA", "TTTTAAAACC")
        # The page was loaded with that index on PAT2; another tab cleared it.
        shown = [["", ""], ["GGGGCCCCAA", "TTTTAAAACC"]]
        run = _stored(ctx)
        run.get_sample("s2").clear_index()
        ctx.run_repo.save(run)
        before = _indexes(ctx)

        resp = _drop(logged_in_client, kit, 2, shown)

        assert resp.status_code == 409
        assert resp.text.startswith("The index on PAT2 changed since this page was loaded.")
        assert _indexes(ctx) == before


class TestADropThatMatchesTheStoredIndexesGoesAhead:
    def test_rows_with_no_index(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows

        resp = _drop(logged_in_client, kit, 2, EMPTY_TWO)

        assert resp.status_code == 200, resp.text[:300]
        assert _indexes(ctx) == [("PAT1", PLAIN_PAIRS[0][0], PLAIN_PAIRS[0][1]),
                                 ("PAT2", PLAIN_PAIRS[1][0], PLAIN_PAIRS[1][1])]

    def test_a_row_the_page_showed_with_its_index(self, logged_in_client, two_empty_rows):
        ctx, kit = two_empty_rows
        _assign_behind_the_page(ctx, "s2", "GGGGCCCCAA", "TTTTAAAACC")

        resp = _drop(logged_in_client, kit, 2,
                     [["", ""], ["GGGGCCCCAA", "TTTTAAAACC"]])

        assert resp.status_code == 200, resp.text[:300]
        assert _indexes(ctx) == [("PAT1", PLAIN_PAIRS[0][0], PLAIN_PAIRS[0][1]),
                                 ("PAT2", PLAIN_PAIRS[1][0], PLAIN_PAIRS[1][1])]


class TestWhatTheDropSendsMustBeReadable:
    @pytest.mark.parametrize("shown", [
        pytest.param("not json", id="not-json"),
        pytest.param('{"s1": ["", ""]}', id="an-object"),
        pytest.param('[["", ""], "x"]', id="a-row-that-is-not-a-list"),
        pytest.param('[["", ""], ["", "", ""]]', id="a-row-of-three"),
        pytest.param('[["", ""], [1, 2]]', id="a-row-of-numbers"),
        pytest.param('[["", ""]]', id="one-row-for-two-targets"),
    ])
    def test_it_is_refused_and_nothing_is_assigned(
            self, logged_in_client, two_empty_rows, shown):
        ctx, kit = two_empty_rows
        before = _indexes(ctx)

        resp = _drop(logged_in_client, kit, 2, shown)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == "This page is out of date. Reload the page and drag again."
        assert _indexes(ctx) == before

    def test_a_drop_that_sends_no_shown_indexes_is_refused(
            self, logged_in_client, two_empty_rows):
        """The field is required. Every page that can drop sends it -- app.js
        is served at /js/app.js?v=<content hash>, so no browser holds a
        pre-change script against post-change HTML -- and a request without
        it would overwrite an index another tab set (batch 4 review fix A)."""
        ctx, kit = two_empty_rows
        _assign_behind_the_page(ctx, "s2", "GGGGCCCCAA")
        before = _indexes(ctx)

        resp = _drop(logged_in_client, kit, 2, None)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == "This page is out of date. Reload the page and drag again."
        assert _indexes(ctx) == before
