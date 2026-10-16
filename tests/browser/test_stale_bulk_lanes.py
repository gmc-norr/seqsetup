"""Two tabs: a lane Apply from the page loaded first is refused and says
why (design note docs/design/2026-10-17-stale-page-checks-design.md, step 1).

The edit lock is per user, so both tabs pass it. The lane panel used to send
only the ticked ids and the lanes to write, so the stale tab's Apply
overwrote the other tab's lanes without a word.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

RUN_ID = "stale-lanes-run"
CHANGED = "The lanes on these samples changed since this page was loaded"


@pytest.fixture
def run_id(app_ctx):
    """A draft with two samples, both on lane 1."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Stale lanes run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{RUN_ID}-s{n}", sample_id=f"SL-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _open_and_tick_both(page, base_url):
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()


def _the_other_tab_sets_lanes(app_ctx, n, lanes):
    """A request from another tab that landed while this page sat open."""
    run = app_ctx.run_repo.get_by_id(RUN_ID)
    run.samples[n - 1].lanes = lanes
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)


def _apply(page, lanes):
    for lane in lanes:
        page.locator(f'.bulk-lane-checkbox[value="{lane}"]').check()
    with page.expect_response(lambda r: r.url.endswith("/samples/set-lanes")) as answer:
        page.locator('[data-action="bulk-apply-lanes"]').click()
    return answer.value


def _lanes(app_ctx):
    return [s.lanes for s in app_ctx.run_repo.get_by_id(RUN_ID).samples]


@pytest.mark.browser
def test_an_apply_on_a_row_another_tab_moved_is_refused(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open_and_tick_both(page, base_url)
    _the_other_tab_sets_lanes(app_ctx, 2, [4])

    answer = _apply(page, [2])

    assert answer.status == 409
    # Refused for the lanes the page showed, not for sending nothing.
    assert "target_lanes" in answer.request.post_data, answer.request.post_data
    expect(page.locator("#error-banner")).to_contain_text(CHANGED)
    expect(page.locator("#error-banner")).to_contain_text("SL-02")
    assert _lanes(app_ctx) == [[1], [4]]


@pytest.mark.browser
def test_the_page_sends_the_lanes_each_ticked_row_shows(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open_and_tick_both(page, base_url)

    answer = _apply(page, [3])

    assert answer.status == 200
    sent = answer.request.post_data
    assert "target_lanes=%5B%5B1%5D%2C%5B1%5D%5D" in sent, sent   # [[1],[1]]
    assert _lanes(app_ctx) == [[3], [3]]


@pytest.mark.browser
def test_two_applies_in_a_row_are_both_saved(logged_in_page, base_url, app_ctx, run_id):
    """The answer re-renders the rows, so the page's own change does not
    make the next Apply stale."""
    page = logged_in_page
    _open_and_tick_both(page, base_url)

    assert _apply(page, [2]).status == 200
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()
    page.locator('.bulk-lane-checkbox[value="2"]').uncheck()
    answer = _apply(page, [5])

    assert answer.status == 200, answer.text()
    assert _lanes(app_ctx) == [[5], [5]]
