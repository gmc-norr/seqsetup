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


# "Every base on the screen" has to survive more than a shorter string: the
# span can be hidden, blanked or cut by CSS without the HTML changing at all.
#
# A box hides part of its content when it overflows its own client box AND
# does not scroll in that direction -- a scroll container (overflow auto or
# scroll) puts the rest one scroll away rather than taking it away. That is
# why the walk goes all the way to <body> and asks each box what it does,
# instead of stopping at #sample-section: measured, #sample-section does not
# scroll on the run page (#main.main-content is the scroller), so stopping
# there would have skipped a clip put on #sample-section itself.
_CLIPPERS = """el => {
    const bad = [];
    for (let n = el; n && n !== document.body; n = n.parentElement) {
        const st = getComputedStyle(n);
        const scrolls = o => o === 'auto' || o === 'scroll';
        if (n.scrollWidth > n.clientWidth + 1 && !scrolls(st.overflowX)) {
            bad.push(n.tagName.toLowerCase() + '.' + (n.className || '(none)') + ' (width)');
        }
        if (n.scrollHeight > n.clientHeight + 1 && !scrolls(st.overflowY)) {
            bad.push(n.tagName.toLowerCase() + '.' + (n.className || '(none)') + ' (height)');
        }
    }
    return bad;
}"""

# The span may also be there, unclipped, and still unreadable: zero opacity,
# a zero font size, ink the colour of the paper, a clip-path over it, or the
# text pushed out of its box by an indent. to_be_visible() catches
# display:none, visibility:hidden and a zero-size box; these catch the rest.
_UNREADABLE = """el => {
    const bad = [];
    const st = getComputedStyle(el);
    if (parseFloat(st.opacity) < 0.99) bad.push('opacity ' + st.opacity);
    if (parseFloat(st.fontSize) < 8) bad.push('font-size ' + st.fontSize);
    if (st.clipPath && st.clipPath !== 'none') bad.push('clip-path ' + st.clipPath);
    if (st.textIndent && parseFloat(st.textIndent) !== 0) bad.push('text-indent ' + st.textIndent);
    let bg = 'rgba(0, 0, 0, 0)';
    for (let n = el; n && bg === 'rgba(0, 0, 0, 0)'; n = n.parentElement) {
        bg = getComputedStyle(n).backgroundColor;
    }
    if (st.color === bg) bad.push('colour equals background ' + bg);
    // The text's own box must fit inside the span's: a wider range means
    // the span shows a part of the sequence, whatever its scrollWidth says.
    const r = document.createRange();
    r.selectNodeContents(el);
    const t = r.getBoundingClientRect(), b = el.getBoundingClientRect();
    if (t.width > b.width + 1 || t.left < b.left - 1 || t.right > b.right + 1) {
        bad.push('text box ' + Math.round(t.width) + 'px in a ' + Math.round(b.width) + 'px span');
    }
    return bad;
}"""


def _unreadable(cell):
    """Every reason the sequence in ``cell`` cannot be read. Empty is good."""
    return cell.evaluate(_CLIPPERS) + cell.evaluate(_UNREADABLE)


@pytest.mark.browser
def test_every_base_is_on_the_screen(logged_in_page, base_url, long_index_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{long_index_run_id}")
    page.wait_for_selector(f"#sample-row-{long_index_run_id}-s1 .assigned-index.i7")

    for n, (i7, i5) in enumerate(((I7_A, I5_A), (I7_B, I5_B)), start=1):
        for which, seq in (("i7", i7), ("i5", i5)):
            cell = _cell(page, long_index_run_id, n, which)
            expect(cell).to_be_visible()
            expect(cell).to_have_text(seq)
            hidden = _unreadable(cell)
            assert not hidden, f"sample {n} {which} sequence cannot be read: {hidden}"


@pytest.mark.browser
def test_two_indexes_that_differ_after_base_eight_read_apart(
        logged_in_page, base_url, long_index_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{long_index_run_id}")
    page.wait_for_selector(f"#sample-row-{long_index_run_id}-s1 .assigned-index.i7")

    seen = [_cell(page, long_index_run_id, n, w).inner_text().strip()
            for n in (1, 2) for w in ("i7", "i5")]
    assert len(set(seen)) == 4, seen
