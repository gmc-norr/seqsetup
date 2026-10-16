"""A drop or a clear from a page loaded before another tab changed that
row's index is refused and says why (outside review of f490536, finding F8;
index mix-up audit B4).

The multi-index drop already asked; the three single-row routes did not, so
a drop from the stale page replaced the other tab's index, and the row's
clear button removed it, without a word. The index safety net cannot catch
it: both requests are well-formed and each is applied exactly as asked.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

KIT = "Stale-Row-Test"
SEQS = [("ACGTACGT", "AACCGGTT"), ("TGCATGCA", "TTGGCCAA")]
OTHER_TAB = "GGGGGGGG"
CHANGED = "The index on these samples changed since this page was loaded"


@pytest.fixture
def kit(app_ctx):
    from seqsetup.services.validation import clear_validation_cache
    app_ctx.index_kit_repo.save(IndexKit(
        name=KIT, version="1.0", index_mode=IndexMode.UNIQUE_DUAL, index_pairs=[
            IndexPair(id=f"{KIT}_SR{k}", name=f"SR{k}",
                      index1=Index(f"SR{k}", i7, IndexType.I7),
                      index2=Index(f"SR{k}", i5, IndexType.I5))
            for k, (i7, i5) in enumerate(SEQS)
        ]))
    clear_validation_cache()
    yield
    app_ctx.index_kit_repo.delete(KIT, "1.0")
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="stale-row-run", run_name="Stale row run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"SR-0{n}", lanes=[n]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", f"{KIT}:1.0")
    expect(page.locator("#index-list-container")).to_contain_text("SR0")


def _the_other_tab_assigns(app_ctx, run_id, n, i7=OTHER_TAB):
    """A request from another tab that landed while this page sat open."""
    run = app_ctx.run_repo.get_by_id(run_id)
    run.samples[n - 1].assign_index1(Index("other", i7, IndexType.I7))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run_id)


def _chip(page, k):
    return page.locator(f'#index-list-container [data-index-pair-id="{KIT}_SR{k}"]')


def _zone(page, run_id, n):
    return page.locator(f"#sample-row-{run_id}-s{n} .drop-zone").first


def _i7s(app_ctx, run_id):
    return [s.index1_sequence for s in app_ctx.run_repo.get_by_id(run_id).samples]


def _sent_what_the_row_showed(resp, shown):
    """Refused for the index the page showed, not for sending nothing."""
    assert "target_indexes" in resp.value.request.post_data, resp.value.request.post_data
    assert shown in resp.value.request.post_data, resp.value.request.post_data


@pytest.mark.browser
def test_a_dragged_chip_onto_a_row_another_tab_indexed(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    _the_other_tab_assigns(app_ctx, run_id, 1)

    with page.expect_response(lambda r: r.url.endswith("/assign-index")) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 409
    _sent_what_the_row_showed(resp, "%5B%5B%22%22%2C%22%22%5D%5D")   # [["",""]]
    expect(page.locator("#error-banner")).to_contain_text(CHANGED)
    expect(page.locator("#error-banner")).to_contain_text("SR-01")
    assert _i7s(app_ctx, run_id) == [OTHER_TAB, None]


@pytest.mark.browser
def test_a_keyboard_assign_onto_a_row_another_tab_indexed(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    _the_other_tab_assigns(app_ctx, run_id, 1)

    _chip(page, 0).click()
    with page.expect_response(lambda r: r.url.endswith("/assign-index")) as resp:
        _zone(page, run_id, 1).press("Enter")

    assert resp.value.status == 409
    expect(page.locator("#error-banner")).to_contain_text(CHANGED)
    assert _i7s(app_ctx, run_id) == [OTHER_TAB, None]


@pytest.mark.browser
def test_the_rows_clear_button_on_an_index_another_tab_replaced(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)
    with page.expect_response(lambda r: r.url.endswith("/assign-index")):
        _chip(page, 0).drag_to(_zone(page, run_id, 1))
    assert _i7s(app_ctx, run_id) == [SEQS[0][0], None]
    _the_other_tab_assigns(app_ctx, run_id, 1)

    page.get_by_role("button", name="Edit indexes").click()
    with page.expect_response(lambda r: "/clear-index" in r.url) as resp:
        page.get_by_role("button", name="Clear index pair of SR-01").click()

    assert resp.value.status == 409
    _sent_what_the_row_showed(resp, SEQS[0][0])
    expect(page.locator("#error-banner")).to_contain_text("Nothing was cleared")
    assert _i7s(app_ctx, run_id) == [OTHER_TAB, None]


@pytest.mark.browser
def test_control_a_drop_on_the_row_the_page_shows_is_saved(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id)

    with page.expect_response(lambda r: r.url.endswith("/assign-index")) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 200
    assert _i7s(app_ctx, run_id) == [SEQS[0][0], None]


@pytest.mark.browser
def test_control_after_a_reload_the_drop_is_saved(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    page.on("dialog", lambda d: d.accept())   # dropping on an index asks first
    _the_other_tab_assigns(app_ctx, run_id, 1)
    _open(page, base_url, run_id)

    page.get_by_role("button", name="Edit indexes").click()
    with page.expect_response(lambda r: r.url.endswith("/assign-index")) as resp:
        _chip(page, 1).drag_to(page.locator(
            f"#sample-row-{run_id}-s1 .index-assigned").first)

    assert resp.value.status == 200, resp.value.text()
    _sent_what_the_row_showed(resp, OTHER_TAB)   # the page now shows the other tab's
    assert _i7s(app_ctx, run_id) == [SEQS[1][0], None]


@pytest.mark.browser
def test_a_drop_on_the_ticked_rows_when_one_of_them_changed(
        logged_in_page, base_url, app_ctx, kit, run_id):
    """Ticking a row sends the drop to every ticked row at once
    (assign-index-to-selected). One row another tab has changed refuses the
    whole drop, so the row the person dropped on gets nothing either."""
    page = logged_in_page
    page.on("dialog", lambda d: d.accept())   # one index on several rows asks first
    _open(page, base_url, run_id)
    _the_other_tab_assigns(app_ctx, run_id, 2)

    page.locator(f'#sample-row-{run_id}-s2 .sample-checkbox').check()
    with page.expect_response(lambda r: r.url.endswith("/assign-index-to-selected")) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 409
    _sent_what_the_row_showed(resp, "target_indexes")
    expect(page.locator("#error-banner")).to_contain_text(CHANGED)
    expect(page.locator("#error-banner")).to_contain_text("SR-02")
    assert _i7s(app_ctx, run_id) == [None, OTHER_TAB], "the dropped-on row got one too"


@pytest.mark.browser
def test_control_a_drop_on_the_ticked_rows_the_page_shows_is_saved(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    page.on("dialog", lambda d: d.accept())
    _open(page, base_url, run_id)

    page.locator(f'#sample-row-{run_id}-s2 .sample-checkbox').check()
    with page.expect_response(lambda r: r.url.endswith("/assign-index-to-selected")) as resp:
        _chip(page, 0).drag_to(_zone(page, run_id, 1))

    assert resp.value.status == 200, resp.value.text()[:300]
    assert _i7s(app_ctx, run_id) == [SEQS[0][0], SEQS[0][0]]


@pytest.fixture
def singles_run_id(app_ctx):
    """A draft whose one sample holds an i7 and an i5 as single indexes, not
    a pair, so the row draws a clear button for each half."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="stale-singles-run", run_name="Stale singles run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    sample = Sample(id="stale-singles-run-s1", sample_id="SG-01", lanes=[1])
    sample.assign_index1(Index("solo-i7", SEQS[0][0], IndexType.I7))
    sample.assign_index2(Index("solo-i5", SEQS[0][1], IndexType.I5))
    run.add_sample(sample)
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


@pytest.mark.browser
def test_the_half_clear_button_on_an_index_another_tab_replaced(
        logged_in_page, base_url, app_ctx, kit, singles_run_id):
    """Clear i7 is the one button that carries both a query string
    (?index_type=i7) and hx-vals: htmx puts hx-vals in the body for a POST,
    so the route sees both. A stale half-clear must be refused too."""
    page = logged_in_page
    page.goto(f"{base_url}/runs/{singles_run_id}")
    page.wait_for_load_state("networkidle")
    _the_other_tab_assigns(app_ctx, singles_run_id, 1)

    page.get_by_role("button", name="Edit indexes").click()
    with page.expect_response(lambda r: "/clear-index" in r.url) as resp:
        page.get_by_role("button", name="Clear i7 index of SG-01").click()

    assert resp.value.status == 409, resp.value.text()[:300]
    _sent_what_the_row_showed(resp, SEQS[0][0])
    expect(page.locator("#error-banner")).to_contain_text("Nothing was cleared")
    assert _i7s(app_ctx, singles_run_id) == [OTHER_TAB]


@pytest.mark.browser
def test_control_the_half_clear_button_on_the_index_the_page_shows(
        logged_in_page, base_url, app_ctx, kit, singles_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{singles_run_id}")
    page.wait_for_load_state("networkidle")

    page.get_by_role("button", name="Edit indexes").click()
    with page.expect_response(lambda r: "/clear-index" in r.url) as resp:
        page.get_by_role("button", name="Clear i7 index of SG-01").click()

    assert resp.value.status == 200, resp.value.text()[:300]
    stored = app_ctx.run_repo.get_by_id(singles_run_id).samples[0]
    assert (stored.index1_sequence, stored.index2_sequence) == (None, SEQS[0][1])
