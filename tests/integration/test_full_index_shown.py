"""The sample table shows every base of an assigned index.

The i7 and i5 cells once showed ``sequence[:8]`` with a trailing "..." and
no tooltip, so two 10-base indexes that differ only after base 8 read as
the same index on the run page -- the one page a person uses to check that
each sample carries the index it should.

The user chose (2026-10-18) to show the whole sequence in both cells.
"""

import pytest

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import hold_edit_lock

# Two 10-base indexes that differ only in the last two bases.
I7_A = "AAAACCCCGG"
I7_B = "AAAACCCCTT"
I5_A = "TTTTGGGGCC"
I5_B = "TTTTGGGGAA"


def _run(ctx, status=RunStatus.DRAFT):
    run = SequencingRun(id="r", run_name="r", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10), status=status)
    run.add_sample(Sample(
        id="s1", sample_id="PAT-1", lanes=[1],
        index1=Index(name="X1", sequence=I7_A, index_type=IndexType.I7),
        index2=Index(name="Y1", sequence=I5_A, index_type=IndexType.I5),
    ))
    run.add_sample(Sample(
        id="s2", sample_id="PAT-2", lanes=[1],
        index1=Index(name="X2", sequence=I7_B, index_type=IndexType.I7),
        index2=Index(name="Y2", sequence=I5_B, index_type=IndexType.I5),
    ))
    ctx.run_repo.save(run)
    if status == RunStatus.DRAFT:
        hold_edit_lock(ctx, "r")
    return run


def _row(text, sample_id):
    row = text[text.index(f'id="sample-row-{sample_id}"'):]
    return row[:row.index("</tr>")]


class TestTheRunPageShowsTheWholeSequence:

    def test_a_ten_base_i7_is_shown_whole(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        page = logged_in_client.get("/runs/r").text

        assert f'<span class="assigned-index i7">{I7_A}</span>' in _row(page, "s1")
        assert f'<span class="assigned-index i7">{I7_B}</span>' in _row(page, "s2")

    def test_a_ten_base_i5_is_shown_whole(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        page = logged_in_client.get("/runs/r").text

        assert f'<span class="assigned-index i5">{I5_A}</span>' in _row(page, "s1")
        assert f'<span class="assigned-index i5">{I5_B}</span>' in _row(page, "s2")

    def test_no_cell_ends_in_an_ellipsis(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        page = logged_in_client.get("/runs/r").text

        for sid in ("s1", "s2"):
            assert "..." not in _row(page, sid), sid

    def test_two_rows_whose_indexes_differ_after_base_eight_read_apart(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        page = logged_in_client.get("/runs/r").text

        seq_cells = lambda sid: [
            _row(page, sid)[m:].split(">", 1)[1].split("<", 1)[0]
            for m in _offsets(_row(page, sid), 'class="assigned-index ')
        ]
        assert seq_cells("s1") != seq_cells("s2")

    def test_a_ready_run_shows_the_whole_sequence(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, status=RunStatus.READY)

        page = logged_in_client.get("/runs/r").text

        assert f'<span class="assigned-index i7">{I7_A}</span>' in _row(page, "s1")
        assert f'<span class="assigned-index i5">{I5_A}</span>' in _row(page, "s1")


class TestARedrawnRowShowsTheWholeSequence:

    def test_a_row_redrawn_after_a_setting_save_shows_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx)

        redrawn = logged_in_client.post(
            "/runs/r/samples/s1/clear-index?index_type=i5",
            data={"target_indexes": f'[["{I7_A}", "{I5_A}"]]'},
            headers={"Origin": "http://testserver", "HX-Request": "true"},
        )

        assert redrawn.status_code == 200, redrawn.text
        assert f'<span class="assigned-index i7">{I7_A}</span>' in redrawn.text


def _offsets(text, needle):
    out, i = [], text.find(needle)
    while i >= 0:
        out.append(i)
        i = text.find(needle, i + 1)
    return out
