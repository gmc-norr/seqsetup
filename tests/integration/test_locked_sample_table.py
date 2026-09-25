"""A locked (Ready/Archived) run shows what will go on the sheet, read-only.

The locked table used to hide the index, lane and override columns, so the
person checking a Ready run before loading the sequencer could not see
which index each sample had. It must show them, with no way to edit.
"""

import pytest

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunStatus


def _make_run(ctx, status):
    run = ctx.run_repo.create_run("tester")
    run = ctx.run_repo.get_by_id(run.id)
    run.run_name = "Locked run"
    sample = Sample(sample_id="S1", lanes=[1, 2], barcode_mismatches_index1=0)
    sample.assign_index1(Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7))
    sample.assign_index2(Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5))
    run.add_sample(sample)
    run.status = status
    ctx.run_repo.save(run)
    return run.id


@pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
class TestLockedSampleTable:
    """Indexes, lanes and settings are visible; nothing is editable."""

    def _page(self, client, ctx, status):
        run_id = _make_run(ctx, status)
        resp = client.get(f"/runs/{run_id}")
        assert resp.status_code == 200
        return resp.text

    def test_locked_table_shows_indexes(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        page = self._page(logged_in_client, ctx, status)
        assert "ATTACTCG" in page
        assert "TATAGCCT" in page
        assert "D701" in page

    def test_locked_table_shows_lanes_and_mismatches(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        page = self._page(logged_in_client, ctx, status)
        assert '<span class="lanes-display">1,2</span>' in page
        assert '<span class="mismatch-display">0</span>' in page

    def test_locked_table_has_no_edit_controls(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        page = self._page(logged_in_client, ctx, status)
        assert 'class="sample-checkbox"' not in page
        assert 'id="bulk-action-panel"' not in page
        assert 'name="override_cycles"' not in page
        assert "drop-zone" not in page
        assert 'title="Delete sample"' not in page
        assert "clear-index" not in page
