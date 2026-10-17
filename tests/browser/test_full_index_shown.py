"""The sample table's index cells show every base, and clip none of it.

The cells once showed ``sequence[:8]`` plus "...", with no tooltip: two
10-base indexes that differ only after base 8 read as the same index on
the run page. Showing the whole sequence only helps if the browser then
puts all of it on the screen, so this checks the rendered cell, not the
HTML (later list #1, 2026-10-18).
"""

from datetime import datetime
from itertools import count

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform, RunCycles, RunStatus, SequencingRun,
)

from .conftest import BROWSER_ADMIN, hold_edit_lock

I7_A, I7_B = "AAAACCCCGG", "AAAACCCCTT"
I5_A, I5_B = "TTTTGGGGCC", "TTTTGGGGAA"

_counter = count(1)


@pytest.fixture
def long_index_run_id(app_ctx):
    """A short-lived DRAFT run whose two samples carry 10-base indexes that
    differ only in their last two bases."""
    run_id = f"long-index-run-{next(_counter):04d}"
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=run_id, run_name=f"Long index run {run_id}",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 10, 10), status=RunStatus.DRAFT,
        created_by=BROWSER_ADMIN["username"], updated_by=BROWSER_ADMIN["username"],
        created_at=t, updated_at=t,
    )
    for n, (i7, i5) in enumerate(((I7_A, I5_A), (I7_B, I5_B)), start=1):
        run.add_sample(Sample(
            id=f"{run_id}-s{n}", sample_id=f"LONG-{n:02d}", lanes=[1],
            index1=Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5),
        ))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run_id
    app_ctx.run_repo.collection.delete_one({"_id": run_id})


def _cell(page, run_id, n, which):
    return page.locator(f"#sample-row-{run_id}-s{n} .assigned-index.{which}")


# The sequence span can be clipped by itself or by any box between it and
# #sample-section, which is the one box allowed to hide content: it scrolls,
# so what is outside it is one scroll away rather than gone. A max-width plus
# overflow:hidden on the <td> cut the sequence while leaving the span's own
# scrollWidth equal to its clientWidth, so checking the span alone missed it.
_CLIPPERS = """el => {
    const bad = [];
    for (let n = el; n && n.id !== 'sample-section'; n = n.parentElement) {
        if (n.scrollWidth > n.clientWidth + 1 || n.scrollHeight > n.clientHeight + 1) {
            bad.push(n.tagName.toLowerCase() + '.' + (n.className || '(none)'));
        }
    }
    return bad;
}"""


def _clippers(cell):
    """The boxes from the sequence span up to #sample-section that hide part
    of their content. Empty means every base is on the screen."""
    return cell.evaluate(_CLIPPERS)


@pytest.mark.browser
def test_every_base_is_on_the_screen(logged_in_page, base_url, long_index_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{long_index_run_id}")
    page.wait_for_selector(f"#sample-row-{long_index_run_id}-s1 .assigned-index.i7")

    for n, (i7, i5) in enumerate(((I7_A, I5_A), (I7_B, I5_B)), start=1):
        for which, seq in (("i7", i7), ("i5", i5)):
            cell = _cell(page, long_index_run_id, n, which)
            expect(cell).to_have_text(seq)
            clipped = _clippers(cell)
            assert not clipped, f"sample {n} {which} sequence is clipped by {clipped}"


@pytest.mark.browser
def test_two_indexes_that_differ_after_base_eight_read_apart(
        logged_in_page, base_url, long_index_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{long_index_run_id}")
    page.wait_for_selector(f"#sample-row-{long_index_run_id}-s1 .assigned-index.i7")

    seen = [_cell(page, long_index_run_id, n, w).inner_text().strip()
            for n in (1, 2) for w in ("i7", "i5")]
    assert len(set(seen)) == 4, seen
