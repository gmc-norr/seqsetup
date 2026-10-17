"""The sample table always has its i5 column.

The table once hid the column when every index kit stored was single-index
-- a choice made from the kits, not the samples. A sample can hold an i5
without any such kit (a paste or LIMS worklist with an Index2 column, a copy
of an older run), and that i5 goes into the Sample Sheet: the page hid an
index the sheet writes. A row redrawn after a change always had its i5 cell,
so under the shortened header its cells moved one column to the right.

The user chose (2026-10-17) to always show the column.
"""

import json
import re

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}


def _only_single_index_kits(ctx):
    ctx.index_kit_repo.save(IndexKit(
        name="Single kit", version="1", index_mode=IndexMode.SINGLE,
        i7_indexes=[Index(name="A", sequence="ACGTACGT", index_type=IndexType.I7)],
    ))


def _run(ctx, status=RunStatus.DRAFT):
    run = SequencingRun(id="r", run_name="r", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10), status=status)
    run.add_sample(Sample(
        id="dual", sample_id="PAT-1", lanes=[1],
        index1=Index(name="X1", sequence="AAAACCCCGG", index_type=IndexType.I7),
        index2=Index(name="Y1", sequence="TTTTGGGGCC", index_type=IndexType.I5),
    ))
    run.add_sample(Sample(id="none", sample_id="PAT-2", lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, "r")
    return run


def _table(page):
    return page[page.index('id="sample-table"'):]


def _header_cells(page):
    table = _table(page)
    return len(re.findall(r"<th[\s>]", table[table.index("<thead"):table.index("</thead>")]))


def _row(text, sample_id):
    row = text[text.index(f'id="sample-row-{sample_id}"'):]
    return row[:row.index("</tr>")]


def _row_cells(text, sample_id):
    return len(re.findall(r"<td[\s>]", _row(text, sample_id)))


class TestTheColumnIsShownWhenEveryKitIsSingleIndex:

    def test_a_stored_i5_is_shown(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _only_single_index_kits(ctx)
        _run(ctx)

        page = logged_in_client.get("/runs/r").text

        assert "<th>Index (i5)</th>" in _table(page)
        assert '<span class="assigned-index i5">TTTTGGGG...</span>' in _row(page, "dual")

    def test_a_ready_run_shows_its_stored_i5(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _only_single_index_kits(ctx)
        _run(ctx, status=RunStatus.READY)

        page = logged_in_client.get("/runs/r").text

        assert "<th>Index (i5)</th>" in _table(page)
        assert '<span class="assigned-index i5">TTTTGGGG...</span>' in _row(page, "dual")

    @pytest.mark.parametrize("status", [RunStatus.DRAFT, RunStatus.READY])
    def test_every_row_has_as_many_cells_as_the_header(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        _only_single_index_kits(ctx)
        _run(ctx, status=status)

        page = logged_in_client.get("/runs/r").text

        header = _header_cells(page)
        assert _row_cells(page, "dual") == header
        assert _row_cells(page, "none") == header

    def test_a_row_redrawn_after_a_change_still_fits_the_header(self, logged_in_client, fresh_app):
        """Clearing the i7 redraws the row in place (hx-swap outerHTML); the
        row keeps its i5, and its cells stay under their headings."""
        _app, ctx, _db = fresh_app
        _only_single_index_kits(ctx)
        _run(ctx)
        header = _header_cells(logged_in_client.get("/runs/r").text)

        redrawn = logged_in_client.post(
            "/runs/r/samples/dual/clear-index?index_type=i7",
            data={"target_indexes": json.dumps([["AAAACCCCGG", "TTTTGGGGCC"]])}, headers=ORIGIN)

        assert redrawn.status_code == 200
        assert _row_cells(redrawn.text, "dual") == header
        assert '<span class="assigned-index i5">TTTTGGGG...</span>' in _row(redrawn.text, "dual")
