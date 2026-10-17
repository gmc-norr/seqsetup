"""Edit indexes on the run page, and the change history folded away.

Once every sample in a draft had an index, the run page offered no way to
change one: the index list showed only while some sample had none, and the
clear buttons were drawn only in the wizard. An "Edit indexes" button now
opens both. They stay closed until it is clicked, so an index is not
changed by accident. The change history folds away like "Add Samples".
"""

import json
import re
from datetime import datetime

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunStatus
from .conftest import hold_edit_lock


def _shown(ctx, run_id, sid) -> dict:
    """What the row shows, as its clear button sends it (hx-vals): the
    clear-index route compares it with the stored index and refuses a row
    another tab has changed (F8)."""
    sample = ctx.run_repo.get_by_id(run_id).get_sample(sid)
    return {"target_indexes": json.dumps(
        [[sample.index1_sequence or "", sample.index2_sequence or ""]])}


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _indexed(sample_id):
    sample = Sample(sample_id=sample_id, lanes=[1])
    sample.assign_index1(Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7))
    sample.assign_index2(Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5))
    return sample


def _paired(sample_id):
    sample = Sample(sample_id=sample_id, lanes=[1])
    sample.assign_index(IndexPair(
        id="UDI0001", name="UDI0001",
        index1=Index(name="UDI0001", sequence="GAACTGAG", index_type=IndexType.I7),
        index2=Index(name="UDI0001", sequence="CGCTCCAC", index_type=IndexType.I5),
    ))
    return sample


def _make_run(ctx, samples, status=RunStatus.DRAFT):
    run = ctx.run_repo.create_run("tester")
    hold_edit_lock(ctx, run.id)
    run = ctx.run_repo.get_by_id(run.id)
    run.run_name = "Fold run"
    for sample in samples:
        run.add_sample(sample)
    run.status = status
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return run


def _tag(html, marker):
    """The start tags that contain ``marker``."""
    return re.findall(r"<[a-z]+\b[^<>]*" + re.escape(marker) + r"[^<>]*>", html)


def _page(client, run):
    resp = client.get(f"/runs/{run.id}")
    assert resp.status_code == 200
    return resp.text


class TestEditIndexesButton:
    """A draft with samples has the button; nothing else does."""

    def test_draft_with_samples_has_the_button(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_indexed("S1")]))
        assert re.search(r'<button[^<>]*x-show="!editingIndexes"[^<>]*>\s*Edit indexes\s*</button>', page)
        assert re.search(r'<button[^<>]*x-show="editingIndexes"[^<>]*>\s*Done editing indexes\s*</button>', page)

    def test_edit_mode_starts_closed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_indexed("S1")]))
        [fieldset] = _tag(page, 'id="samples"')
        assert 'x-data="{ editingIndexes: false }"' in fieldset
        done = re.search(r'<button[^<>]*x-show="editingIndexes"[^<>]*>\s*Done editing indexes', page)
        assert "x-cloak" in done.group(0)

    def test_draft_without_samples_has_no_button(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, []))
        assert "Edit indexes" not in page

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_locked_run_has_no_button(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_indexed("S1")], status))
        assert "Edit indexes" not in page
        assert "wizard-index-panel" not in page


class TestTheIndexList:
    """The list is on the page in a draft, shown while editing or while a
    sample has no index (as before)."""

    def test_all_indexed_draft_hides_the_list_until_editing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_indexed("S1"), _indexed("S2")]))
        [panel] = _tag(page, 'class="wizard-index-panel"')
        assert 'x-show="editingIndexes"' in panel
        assert "x-cloak" in panel

    def test_all_indexed_draft_keeps_the_table_full_width_until_editing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_indexed("S1")]))
        assert 'class="run-page-with-index-panel"' not in page
        assert _tag(page, ":class=\"{ 'run-page-with-index-panel': editingIndexes }\"")

    def test_a_sample_without_index_shows_the_list_as_before(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_indexed("S1"), Sample(sample_id="S2", lanes=[1])]))
        [panel] = _tag(page, 'class="wizard-index-panel"')
        assert "x-show" not in panel
        assert "x-cloak" not in panel
        assert 'class="run-page-with-index-panel"' in page


class TestClearButtons:
    """Each index on the run page has a clear button, shown while editing."""

    def test_page_rows_have_clear_buttons_shown_while_editing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _make_run(ctx, [_indexed("S1")])
        page = _page(logged_in_client, run)
        sid = run.samples[0].id
        for index_type in ("i7", "i5"):
            [button] = _tag(page, f'title="Clear {index_type} index"')
            assert 'x-show="editingIndexes"' in button
            assert "x-cloak" in button
            assert f'hx-post="/runs/{run.id}/samples/{sid}/clear-index?index_type={index_type}"' in button

    def test_a_cleared_row_keeps_the_other_clear_button(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _make_run(ctx, [_indexed("S1")])
        sid = run.samples[0].id
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{sid}/clear-index?index_type=i7",
            data=_shown(ctx, run.id, sid), headers=_origin())
        assert resp.status_code == 200
        assert 'data-drop-zone-type="i7"' in resp.text
        assert _tag(resp.text, 'title="Clear i7 index"') == []
        [button] = _tag(resp.text, 'title="Clear i5 index"')
        assert 'x-show="editingIndexes"' in button
        sample = ctx.run_repo.get_by_id(run.id).get_sample(sid)
        assert sample.index1_sequence is None
        assert sample.index2_sequence == "TATAGCCT"

    def test_a_pair_has_one_clear_button_for_the_pair(self, logged_in_client, fresh_app):
        """The i7 and i5 of a pair are one assignment; clearing half of it
        did nothing (Sample.clear_index1 leaves index_pair alone)."""
        _app, ctx, _db = fresh_app
        run = _make_run(ctx, [_paired("S1")])
        page = _page(logged_in_client, run)
        sid = run.samples[0].id
        [button] = _tag(page, 'title="Clear index pair"')
        assert 'x-show="editingIndexes"' in button
        assert f'hx-post="/runs/{run.id}/samples/{sid}/clear-index"' in button
        assert _tag(page, 'title="Clear i7 index"') == []
        assert _tag(page, 'title="Clear i5 index"') == []

    def test_a_pair_without_an_i5_has_the_pair_button(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        sample = Sample(sample_id="S1", lanes=[1])
        sample.assign_index(IndexPair(
            id="SI01", name="SI01",
            index1=Index(name="SI01", sequence="GAACTGAG", index_type=IndexType.I7)))
        run = _make_run(ctx, [sample])
        page = _page(logged_in_client, run)
        assert len(_tag(page, 'title="Clear index pair"')) == 1
        assert _tag(page, 'title="Clear i7 index"') == []
        assert _tag(page, 'title="Clear i5 index"') == []

    def test_clear_buttons_name_their_sample(self, logged_in_client, fresh_app):
        """Screen readers read the button's name, not its title; "x" alone
        does not say which sample or index it clears."""
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_paired("PAIR-1"), _indexed("SOLO-1")]))
        [pair] = _tag(page, 'title="Clear index pair"')
        [i7] = _tag(page, 'title="Clear i7 index"')
        [i5] = _tag(page, 'title="Clear i5 index"')
        assert 'aria-label="Clear index pair of PAIR-1"' in pair
        assert 'aria-label="Clear i7 index of SOLO-1"' in i7
        assert 'aria-label="Clear i5 index of SOLO-1"' in i5

    def test_clearing_the_pair_empties_both(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _make_run(ctx, [_paired("S1")])
        sid = run.samples[0].id
        resp = logged_in_client.post(f"/runs/{run.id}/samples/{sid}/clear-index",
                                     data=_shown(ctx, run.id, sid), headers=_origin())
        assert resp.status_code == 200
        assert 'data-drop-zone-type="i7"' in resp.text
        assert 'data-drop-zone-type="i5"' in resp.text
        sample = ctx.run_repo.get_by_id(run.id).get_sample(sid)
        assert sample.index_pair is None
        assert (sample.index1_sequence, sample.index2_sequence) == (None, None)

    @pytest.mark.parametrize("index_type", ["i7", "i5"])
    def test_clearing_half_a_pair_is_refused(self, logged_in_client, fresh_app, index_type):
        _app, ctx, _db = fresh_app
        run = _make_run(ctx, [_paired("S1")])
        sid = run.samples[0].id
        before = ctx.run_repo.get_by_id(run.id).updated_at
        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{sid}/clear-index?index_type={index_type}",
            data=_shown(ctx, run.id, sid), headers=_origin())
        assert resp.status_code == 400
        assert "pair" in resp.text
        stored = ctx.run_repo.get_by_id(run.id)
        assert stored.get_sample(sid).index_pair is not None
        assert stored.updated_at == before

    def test_an_assigned_index_is_a_drop_target_while_editing(self, logged_in_client, fresh_app):
        """While editing, a drop on an index replaces it (app.js asks first)."""
        _app, ctx, _db = fresh_app
        run = _make_run(ctx, [_paired("PAIR-1")])
        page = _page(logged_in_client, run)
        sid = run.samples[0].id
        cells = _tag(page, "class=\"index-assigned\"")
        assert len(cells) == 2
        for cell, slot in zip(cells, ("i7", "i5")):
            assert ":class=\"{ 'replace-zone': editingIndexes }\"" in cell
            assert f'data-sample-id="{sid}"' in cell
            assert f'data-run-id="{run.id}"' in cell
            assert f'data-drop-zone-type="{slot}"' in cell
            assert 'data-sample-name="PAIR-1"' in cell
            assert 'data-index-name="UDI0001"' in cell
            assert 'data-has-pair="1"' in cell

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_a_locked_index_is_never_a_drop_target(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_paired("PAIR-1")], status))
        assert "replace-zone" not in page
        assert "data-has-pair" not in page

    def test_wizard_rows_keep_their_clear_buttons_always_shown(self, fresh_app):
        from seqsetup.templating import templates

        html = templates.env.get_template("wizard/_sample_row.html").render(
            sample=_indexed("S1"), run_id="r1", run_cycles=None,
            run_updated_at=datetime(2026, 10, 17, 12, 0, 0), show_drop_zones=True,
            num_lanes=1, show_bulk_actions=False, context="add_step2",
            editable=True, show_checkboxes=None,
        )
        buttons = _tag(html, 'class="btn-tiny btn-clear"')
        assert len(buttons) == 2
        assert all("x-show" not in b and "x-cloak" not in b for b in buttons)
        assert "replace-zone" not in html


class TestChangeHistoryFolds:
    """The history is closed at first and loads when opened."""

    def test_history_is_a_closed_fold(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _make_run(ctx, [_indexed("S1")])
        page = _page(logged_in_client, run)
        [fold] = _tag(page, f'hx-get="/runs/{run.id}/history"')
        assert fold.startswith("<details")
        assert not re.search(r"\sopen\b", fold)
        assert 'hx-trigger="toggle once"' in fold
        assert "More: Save as template · Change history" in page
        assert "Change history" in page

    def test_history_waits_for_the_fold_to_open(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = _page(logged_in_client, _make_run(ctx, [_indexed("S1")]))
        assert 'hx-trigger="revealed"' not in page
