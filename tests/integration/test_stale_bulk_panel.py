"""The rest of the bulk panel -- mismatches, Override Cycles, test ID --
refuses an Apply from a page that is out of date (design note
docs/design/2026-10-17-stale-page-checks-design.md, step 2).

Each of the three sends what the page showed for the field it changes, one
entry per ticked row in the order the ids are sent, and the route compares
every one with the stored value before it writes anything: a row another
tab has changed refuses the whole Apply (409), a request without the field
is refused (400), and a ticked sample the run no longer has is refused
(409) instead of being skipped without a word.

The Check panel's two fix boxes keep their own check (``only_if``): they
say what their samples lacked when the page was loaded, and send no
``target_tests``.
"""

import json

import pytest

from .conftest import hold_edit_lock
from .test_group_a1 import ORIGIN, RUN, _run, _stored

ORIGIN = ORIGIN

STALE = "This page is out of date. Nothing was saved. Reload the page and try again."
GONE = ("The sample list changed since this page was loaded. "
        "Reload the page and try again.")
BAD = [None, "", "not json", "[]", '"x"', "null", "[[]]"]


@pytest.fixture
def two_rows(fresh_app):
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    return ctx


def _behind_the_page(ctx, sid, **fields):
    """Another tab's change, as it would leave the run while this page sat
    open."""
    run = _stored(ctx)
    sample = run.get_sample(sid)
    for name, value in fields.items():
        setattr(sample, name, value)
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _everything(ctx):
    """The whole stored run: a refusal writes nothing at all."""
    return _stored(ctx).to_dict()


def _drop_sample(ctx, sid):
    run = _stored(ctx)
    run.remove_sample(sid)
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)


def _shown(data, field, shown):
    """Put ``shown`` in the form as the page would: a value to encode, a raw
    string (the unreadable cases), or None -- the field is not sent at all."""
    if shown is not None:
        data[field] = shown if isinstance(shown, str) else json.dumps(shown)
    return data


def _rows(shown):
    """A list of rows as JSON, or a raw string left as it is."""
    if shown is None or isinstance(shown, str):
        return shown
    return [list(row) if isinstance(row, (list, tuple)) else row for row in shown]


# A new Sample's barcode mismatches default to 1 in both columns
# (models/sample.py), so that is what a fresh page shows in the boxes.
DEFAULT_MM = ["1", "1"]


def _mismatches(client, sids, i7="1", i5="2", shown=(DEFAULT_MM, DEFAULT_MM), mode="apply"):
    data = _shown({"sample_ids": json.dumps(sids), "mismatch_index1": i7,
                   "mismatch_index2": i5, "mode": mode},
                  "target_mismatches", _rows(shown))
    return client.post(f"/runs/{RUN}/samples/set-mismatches", data=data, headers=ORIGIN)


def _override(client, sids, value="Y151;I10;I10;Y151", shown=("", "")):
    data = _shown({"sample_ids": json.dumps(sids), "override_cycles": value},
                  "target_override_cycles", _rows(shown))
    return client.post(f"/runs/{RUN}/samples/set-override-cycles", data=data, headers=ORIGIN)


def _test_id(client, sids, test="WGS", version="1", shown=(["", ""], ["", ""]), only_if=None):
    data = {"sample_ids": json.dumps(sids), "test_id": test, "test_version": version}
    if only_if is not None:
        data["only_if"] = only_if
    _shown(data, "target_tests", _rows(shown))
    return client.post(f"/runs/{RUN}/samples/set-test-id", data=data, headers=ORIGIN)


def _mm(ctx):
    return [(s.sample_id, s.barcode_mismatches_index1, s.barcode_mismatches_index2)
            for s in _stored(ctx).samples]


def _oc(ctx):
    return [(s.sample_id, s.override_cycles) for s in _stored(ctx).samples]


def _tests(ctx):
    return [(s.sample_id, s.test_id, s.test_version) for s in _stored(ctx).samples]


class TestMismatches:
    def test_a_row_another_tab_changed_refuses_the_whole_apply(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s2", barcode_mismatches_index1=0)
        before = _everything(ctx)

        resp = _mismatches(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was saved. Reload the page and try again. The barcode mismatches "
            "on these samples changed since this page was loaded: PAT2.")
        assert _everything(ctx) == before

    def test_apply_compares_only_the_column_it_writes(self, logged_in_client, two_rows):
        """A blank box leaves that column alone, so a change there is not
        this Apply's business: refusing it would stop work nobody is
        overwriting."""
        ctx = two_rows
        _behind_the_page(ctx, "s1", barcode_mismatches_index2=2)

        resp = _mismatches(logged_in_client, ["s1"], i7="1", i5="",
                           shown=[DEFAULT_MM])

        assert resp.status_code == 200, resp.text[:300]
        assert _mm(ctx)[0] == ("PAT1", 1, 2)

    def test_apply_refuses_a_change_in_the_column_it_writes(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", barcode_mismatches_index1=2)
        before = _everything(ctx)

        resp = _mismatches(logged_in_client, ["s1"], i7="1", i5="", shown=[DEFAULT_MM])

        assert resp.status_code == 409, resp.text[:300]
        assert _everything(ctx) == before

    def test_clear_compares_both_columns(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", barcode_mismatches_index2=2)
        before = _everything(ctx)

        resp = _mismatches(logged_in_client, ["s1"], i7="", i5="", mode="clear",
                           shown=[DEFAULT_MM])

        assert resp.status_code == 409, resp.text[:300]
        assert _everything(ctx) == before

    def test_a_control_apply_on_what_the_page_showed(self, logged_in_client, two_rows):
        ctx = two_rows

        resp = _mismatches(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 200, resp.text[:300]
        assert _mm(ctx) == [("PAT1", 1, 2), ("PAT2", 1, 2)]

    def test_a_second_apply_uses_what_the_answer_rendered(self, logged_in_client, two_rows):
        ctx = two_rows
        first = _mismatches(logged_in_client, ["s1", "s2"])
        assert 'value="2"' in first.text, first.text[:300]

        resp = _mismatches(logged_in_client, ["s1", "s2"], i7="0", i5="0",
                           shown=[["1", "2"], ["1", "2"]])

        assert resp.status_code == 200, resp.text[:300]
        assert _mm(ctx) == [("PAT1", 0, 0), ("PAT2", 0, 0)]

    @pytest.mark.parametrize("shown", BAD + ['[["1"]]', '[[1,2],[1,2]]',
                                             '[["","",""],["",""]]'])
    def test_an_apply_without_readable_shown_values_is_refused(
            self, logged_in_client, two_rows, shown):
        ctx = two_rows
        before = _everything(ctx)

        resp = _mismatches(logged_in_client, ["s1", "s2"], shown=shown)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == STALE
        assert _everything(ctx) == before

    def test_a_ticked_sample_the_run_no_longer_has_is_refused(self, logged_in_client, two_rows):
        ctx = two_rows
        _drop_sample(ctx, "s2")
        before = _everything(ctx)

        resp = _mismatches(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == GONE
        assert _everything(ctx) == before


class TestOverrideCycles:
    def test_a_row_another_tab_changed_refuses_the_whole_apply(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s2", override_cycles="U8Y143;I10;I10;Y151")
        before = _everything(ctx)

        resp = _override(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was saved. Reload the page and try again. The Override Cycles "
            "on these samples changed since this page was loaded: PAT2.")
        assert _everything(ctx) == before

    def test_a_control_apply_on_what_the_page_showed(self, logged_in_client, two_rows):
        ctx = two_rows

        resp = _override(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 200, resp.text[:300]
        assert _oc(ctx) == [("PAT1", "Y151;I10;I10;Y151"), ("PAT2", "Y151;I10;I10;Y151")]

    def test_a_second_apply_uses_what_the_answer_rendered(self, logged_in_client, two_rows):
        ctx = two_rows
        _override(logged_in_client, ["s1", "s2"])

        resp = _override(logged_in_client, ["s1", "s2"], value="Y150N1;I10;I10;Y151",
                         shown=("Y151;I10;I10;Y151", "Y151;I10;I10;Y151"))

        assert resp.status_code == 200, resp.text[:300]
        assert _oc(ctx) == [("PAT1", "Y150N1;I10;I10;Y151"), ("PAT2", "Y150N1;I10;I10;Y151")]

    def test_auto_is_refused_on_a_row_another_tab_changed(self, logged_in_client, two_rows):
        """Auto sends an empty value, which rewrites every ticked sample's
        OverrideCycles: exactly the overwrite this step is about."""
        ctx = two_rows
        _behind_the_page(ctx, "s1", override_cycles="U8Y143;I10;I10;Y151")
        before = _everything(ctx)

        resp = _override(logged_in_client, ["s1"], value="", shown=("",))

        assert resp.status_code == 409, resp.text[:300]
        assert _everything(ctx) == before

    @pytest.mark.parametrize("shown", BAD + ['["a"]', '[1,1]', '[null,null]'])
    def test_an_apply_without_readable_shown_values_is_refused(
            self, logged_in_client, two_rows, shown):
        ctx = two_rows
        before = _everything(ctx)

        resp = _override(logged_in_client, ["s1", "s2"], shown=shown)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == STALE
        assert _everything(ctx) == before

    def test_a_ticked_sample_the_run_no_longer_has_is_refused(self, logged_in_client, two_rows):
        ctx = two_rows
        _drop_sample(ctx, "s2")
        before = _everything(ctx)

        resp = _override(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == GONE
        assert _everything(ctx) == before


class TestTestId:
    def test_a_row_another_tab_changed_refuses_the_whole_apply(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s2", test_id="EXOME", test_version="3")
        before = _everything(ctx)

        resp = _test_id(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == (
            "Nothing was saved. Reload the page and try again. The test on these "
            "samples changed since this page was loaded: PAT2.")
        assert _everything(ctx) == before

    def test_the_version_alone_changing_refuses_the_apply(self, logged_in_client, two_rows):
        ctx = two_rows
        _test_id(logged_in_client, ["s1"], test="WGS", version="1", shown=[["", ""]])
        _behind_the_page(ctx, "s1", test_version="2")
        before = _everything(ctx)

        resp = _test_id(logged_in_client, ["s1"], test="EXOME", version="4",
                        shown=[["WGS", "1"]])

        assert resp.status_code == 409, resp.text[:300]
        assert _everything(ctx) == before

    def test_a_control_apply_on_what_the_page_showed(self, logged_in_client, two_rows):
        ctx = two_rows

        resp = _test_id(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 200, resp.text[:300]
        assert _tests(ctx) == [("PAT1", "WGS", "1"), ("PAT2", "WGS", "1")]

    def test_a_second_apply_uses_what_the_answer_rendered(self, logged_in_client, two_rows):
        ctx = two_rows
        _test_id(logged_in_client, ["s1", "s2"])

        resp = _test_id(logged_in_client, ["s1", "s2"], test="EXOME", version="2",
                        shown=[["WGS", "1"], ["WGS", "1"]])

        assert resp.status_code == 200, resp.text[:300]
        assert _tests(ctx) == [("PAT1", "EXOME", "2"), ("PAT2", "EXOME", "2")]

    def test_clear_is_refused_on_a_row_another_tab_changed(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", test_id="EXOME", test_version="3")
        before = _everything(ctx)

        resp = _test_id(logged_in_client, ["s1"], test="", version="", shown=[["", ""]])

        assert resp.status_code == 409, resp.text[:300]
        assert _everything(ctx) == before

    @pytest.mark.parametrize("shown", BAD + ['[["WGS"]]', '[[1,1],[1,1]]'])
    def test_an_apply_without_readable_shown_values_is_refused(
            self, logged_in_client, two_rows, shown):
        ctx = two_rows
        before = _everything(ctx)

        resp = _test_id(logged_in_client, ["s1", "s2"], shown=shown)

        assert resp.status_code == 400, resp.text[:300]
        assert resp.text == STALE
        assert _everything(ctx) == before

    def test_a_ticked_sample_the_run_no_longer_has_is_refused(self, logged_in_client, two_rows):
        ctx = two_rows
        _drop_sample(ctx, "s2")
        before = _everything(ctx)

        resp = _test_id(logged_in_client, ["s1", "s2"])

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == GONE
        assert _everything(ctx) == before


class TestEachRowsShownValueIsMatchedToThatRow:
    """The entries are read in the order the ids are sent, not as a set:
    reading PAT1's value against PAT2's row would refuse a page that is
    right, and let through one that is not. Step 1 pins this for the lanes;
    the panel's other three need it as much (first review of step 3, I-1)."""

    def test_mismatches(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", barcode_mismatches_index1=0)
        _behind_the_page(ctx, "s2", barcode_mismatches_index1=2)

        swapped = _mismatches(logged_in_client, ["s1", "s2"], i7="1", i5="",
                              shown=[["2", "1"], ["0", "1"]])
        assert swapped.status_code == 409, swapped.text[:300]

        right = _mismatches(logged_in_client, ["s1", "s2"], i7="1", i5="",
                            shown=[["0", "1"], ["2", "1"]])
        assert right.status_code == 200, right.text[:300]
        assert [row[1] for row in _mm(ctx)] == [1, 1]

    def test_override_cycles(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", override_cycles="Y151;I10;I10;Y151")
        _behind_the_page(ctx, "s2", override_cycles="Y150N1;I10;I10;Y151")

        swapped = _override(logged_in_client, ["s1", "s2"],
                            shown=("Y150N1;I10;I10;Y151", "Y151;I10;I10;Y151"))
        assert swapped.status_code == 409, swapped.text[:300]

        right = _override(logged_in_client, ["s1", "s2"],
                          shown=("Y151;I10;I10;Y151", "Y150N1;I10;I10;Y151"))
        assert right.status_code == 200, right.text[:300]

    def test_tests(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", test_id="WGS", test_version="1")
        _behind_the_page(ctx, "s2", test_id="EXOME", test_version="2")

        swapped = _test_id(logged_in_client, ["s1", "s2"], test="RNA", version="3",
                           shown=[["EXOME", "2"], ["WGS", "1"]])
        assert swapped.status_code == 409, swapped.text[:300]

        right = _test_id(logged_in_client, ["s1", "s2"], test="RNA", version="3",
                         shown=[["WGS", "1"], ["EXOME", "2"]])
        assert right.status_code == 200, right.text[:300]
        assert _tests(ctx) == [("PAT1", "RNA", "3"), ("PAT2", "RNA", "3")]


class TestAStoredCarriageReturnStillMatches:
    """A browser turns CR and CRLF into LF when it reads an attribute back,
    so a stored test with a carriage return in it would never match what the
    page sends and its row could never be given another test (first review
    of step 2, Minor 4). No path stores one today; the LIMS import only
    strips the ends."""

    def test_a_test_with_a_carriage_return_is_not_called_changed(
            self, logged_in_client, two_rows):
        ctx = two_rows
        # The version cannot hold one: the model refuses it. The test can.
        _behind_the_page(ctx, "s1", test_id="A\r\nB", test_version="1")

        resp = _test_id(logged_in_client, ["s1"], test="WGS", version="1",
                        shown=[["A\nB", "1"]])

        assert resp.status_code == 200, resp.text[:300]
        assert _tests(ctx)[0] == ("PAT1", "WGS", "1")

    def test_a_test_that_really_changed_is_still_refused(self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s1", test_id="A\rC", test_version="1")
        before = _everything(ctx)

        resp = _test_id(logged_in_client, ["s1"], test="WGS", version="1",
                        shown=[["A\nB", "1"]])

        assert resp.status_code == 409, resp.text[:300]
        assert _everything(ctx) == before


class TestTheCheckPanelsFixBoxesKeepTheirOwnCheck:
    """They say what their samples lacked when the page was loaded
    (``only_if``), send no ``target_tests``, and must keep working."""

    def test_a_fix_box_without_target_tests_still_works(self, logged_in_client, two_rows):
        ctx = two_rows

        resp = _test_id(logged_in_client, ["s1", "s2"], only_if="no_test", shown=None)

        assert resp.status_code == 200, resp.text[:300]
        assert _tests(ctx) == [("PAT1", "WGS", "1"), ("PAT2", "WGS", "1")]

    def test_a_fix_box_is_still_refused_on_a_sample_that_has_a_test(
            self, logged_in_client, two_rows):
        ctx = two_rows
        _behind_the_page(ctx, "s2", test_id="EXOME", test_version="3")
        before = _everything(ctx)

        resp = _test_id(logged_in_client, ["s1", "s2"], only_if="no_test", shown=None)

        assert resp.status_code == 409, resp.text[:300]
        assert "changed since this page was loaded" in resp.text
        assert _everything(ctx) == before

    def test_a_fix_box_is_refused_for_a_sample_the_run_no_longer_has(
            self, logged_in_client, two_rows):
        ctx = two_rows
        _drop_sample(ctx, "s2")
        before = _everything(ctx)

        resp = _test_id(logged_in_client, ["s1", "s2"], only_if="no_test", shown=None)

        assert resp.status_code == 409, resp.text[:300]
        assert resp.text == GONE
        assert _everything(ctx) == before
