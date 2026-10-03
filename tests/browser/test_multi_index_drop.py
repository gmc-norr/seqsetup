"""Dragging several indexes fills samples in order, and never silently
replaces or drops anything.

Several indexes dropped on a sample go to it and the samples below it, in
table order. That used to replace indexes those samples already had
without a word, and quietly skip indexes that ran past the last sample.
The feature was also hidden (shift-click); the panel now says how.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

# Drag the first `n` chips (as one multi-select) onto the i7 drop zone of `rowSel`.
_MULTI_DROP = """([n, rowSel]) => {
    const chips = Array.from(document.querySelectorAll('.draggable-index-compact')).slice(0, n);
    const payload = {multi: true, indexes: chips.map(c => ({
        id: c.dataset.indexPairId || c.dataset.indexId, type: c.dataset.indexType || 'pair'}))};
    const zone = document.querySelector(rowSel + ' .drop-zone');
    const dt = new DataTransfer();
    dt.setData('text/plain', JSON.stringify(payload));
    zone.dispatchEvent(new DragEvent('dragover', {dataTransfer: dt, bubbles: true, cancelable: true}));
    zone.dispatchEvent(new DragEvent('drop', {dataTransfer: dt, bubbles: true, cancelable: true}));
}"""


@pytest.fixture
def empty_rows_run_id(app_ctx):
    """A draft whose three samples have no index yet; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="multi-drop-run", run_name="Multi drop run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2, 3):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"EMPTY-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.delete(run.id)


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")


def _watch(page):
    dialogs, posts = [], []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.on("request", lambda r: posts.append(r.url) if "assign-indexes-bulk" in r.url else None)
    return dialogs, posts


@pytest.mark.browser
def test_panel_explains_filling_in_order(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    _open(page, base_url, mutable_run_id)
    expect(page.locator(".index-panel-hint")).to_contain_text("shift-click")


@pytest.mark.browser
def test_indexes_past_the_last_sample_ask_first(logged_in_page, base_url, mutable_run_id):
    """MUT-04 is the last row: of two indexes dropped on it, one has no
    sample to go to."""
    page = logged_in_page
    _open(page, base_url, mutable_run_id)
    dialogs, posts = _watch(page)

    page.evaluate(_MULTI_DROP, [2, f"#sample-row-{mutable_run_id}-s4"])
    page.wait_for_timeout(500)
    assert len(dialogs) == 1
    assert "1 index" in dialogs[0] and "not be used" in dialogs[0]
    assert posts == []


@pytest.mark.browser
def test_filling_over_an_indexed_sample_asks(logged_in_page, base_url, empty_rows_run_id, app_ctx):
    page = logged_in_page
    # Give the middle sample an index, so a 3-index drop on the first row
    # would replace it.
    run = app_ctx.run_repo.get_by_id(empty_rows_run_id)
    kit = app_ctx.index_kit_repo.list_all()[0]
    run.samples[1].assign_index(kit.index_pairs[0])
    app_ctx.run_repo.save(run)

    _open(page, base_url, empty_rows_run_id)
    dialogs, posts = _watch(page)
    page.evaluate(_MULTI_DROP, [3, f"#sample-row-{empty_rows_run_id}-s1"])
    page.wait_for_timeout(500)

    assert len(dialogs) == 1
    assert "EMPTY-02" in dialogs[0] and "replace" in dialogs[0]
    assert posts == []
    stored = app_ctx.run_repo.get_by_id(empty_rows_run_id).samples[1]
    assert stored.index1_sequence == kit.index_pairs[0].index1.sequence


@pytest.mark.browser
def test_filling_empty_rows_does_not_ask(logged_in_page, base_url, empty_rows_run_id):
    page = logged_in_page
    _open(page, base_url, empty_rows_run_id)
    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))

    with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as resp:
        page.evaluate(_MULTI_DROP, [2, f"#sample-row-{empty_rows_run_id}-s1"])
    assert resp.value.status == 200
    assert dialogs == []


@pytest.mark.browser
def test_a_drop_on_a_middle_row_fills_from_that_row(logged_in_page, base_url, empty_rows_run_id, app_ctx):
    """The page sends the rows it shows from the drop row on (spec
    2026-10-03 group A1, §1). The other drops here start on the first
    row, so they cannot tell "from the drop row" from "from the top"."""
    page = logged_in_page
    _open(page, base_url, empty_rows_run_id)

    with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as resp:
        page.evaluate(_MULTI_DROP, [2, f"#sample-row-{empty_rows_run_id}-s2"])

    assert resp.value.status == 200
    samples = app_ctx.run_repo.get_by_id(empty_rows_run_id).samples
    assert [s.has_index for s in samples] == [False, True, True]


@pytest.mark.browser
def test_a_drop_after_the_run_changed_is_refused_and_says_why(logged_in_page, base_url, empty_rows_run_id, app_ctx):
    """Another tab removed EMPTY-02 after this page loaded. Two indexes
    dropped on EMPTY-01 would now fill EMPTY-01 and EMPTY-03, not the rows
    shown: nothing is assigned and the page says why (spec 2026-10-03
    group A1, §1)."""
    page = logged_in_page
    _open(page, base_url, empty_rows_run_id)
    run = app_ctx.run_repo.get_by_id(empty_rows_run_id)
    run.remove_sample(f"{empty_rows_run_id}-s2")
    app_ctx.run_repo.save(run)

    with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as resp:
        page.evaluate(_MULTI_DROP, [2, f"#sample-row-{empty_rows_run_id}-s1"])

    assert resp.value.status == 409
    expect(page.locator("#error-banner")).to_contain_text(
        "The sample list changed since this page was loaded. Reload the page and drag again."
    )
    expect(page.locator(f"#sample-row-{empty_rows_run_id}-s2")).to_be_visible()
    samples = app_ctx.run_repo.get_by_id(empty_rows_run_id).samples
    assert [s.has_index for s in samples] == [False, False]


@pytest.mark.browser
def test_indexes_past_the_last_sample_go_ahead_once_confirmed(logged_in_page, base_url, mutable_run_id, app_ctx):
    """MUT-04 is the last row. Two indexes dropped on it, and the lab
    accepts that one will not be used: the page sends the one row it has,
    and the server fills it (plan review F-2)."""
    page = logged_in_page
    _open(page, base_url, mutable_run_id)
    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))

    with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as resp:
        page.evaluate(_MULTI_DROP, [2, f"#sample-row-{mutable_run_id}-s4"])

    assert resp.value.status == 200
    assert len(dialogs) == 1 and "not be used" in dialogs[0]
    assert app_ctx.run_repo.get_by_id(mutable_run_id).get_sample(f"{mutable_run_id}-s4").has_index
