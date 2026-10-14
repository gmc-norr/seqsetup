"""The lane panel: Apply with no lane ticked is refused, and All lanes ticks
every lane box, as the paste's does (index mix-up audit #5, 2026-10-14; the
user's choice "Tick every box"). Apply with no lane, and the old Clear,
saved samples with no lane without a word."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

RUN_ID = "never-empty-browser-run"


@pytest.fixture
def run_id(app_ctx):
    """A draft with two samples on lane 2; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Never empty run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{RUN_ID}-s{n}", sample_id=f"NE-0{n}", lanes=[2]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _open_and_tick_both(page, base_url):
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()


def _lanes(app_ctx):
    return [s.lanes for s in app_ctx.run_repo.get_by_id(RUN_ID).samples]


def _apply(page):
    with page.expect_response(lambda r: r.url.endswith("/samples/set-lanes")) as answer:
        page.locator('[data-action="bulk-apply-lanes"]').click()
    return answer.value


@pytest.mark.browser
def test_apply_with_no_lane_ticked_is_refused(logged_in_page, base_url, run_id, app_ctx):
    page = logged_in_page
    _open_and_tick_both(page, base_url)

    assert _apply(page).status == 400

    expect(page.locator("#error-banner")).to_contain_text("Tick at least one lane. Nothing was saved.")
    assert _lanes(app_ctx) == [[2], [2]]


@pytest.mark.browser
def test_all_lanes_ticks_every_box_and_saves_nothing(logged_in_page, base_url, run_id, app_ctx):
    page = logged_in_page
    _open_and_tick_both(page, base_url)
    dialogs, posts = [], []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
    page.on("request", lambda r: posts.append(r.url) if r.url.endswith("/set-lanes") else None)
    page.locator('.bulk-lane-checkbox[value="3"]').check()  # stays ticked: not a toggle

    page.locator('[data-action="bulk-all-lanes"]').click()
    page.wait_for_timeout(300)

    boxes = page.locator(".bulk-lane-checkbox")
    assert boxes.count() == 8
    for k in range(8):
        expect(boxes.nth(k)).to_be_checked()
    assert dialogs == [] and posts == []
    assert _lanes(app_ctx) == [[2], [2]]


@pytest.mark.browser
def test_all_lanes_then_apply_lists_every_lane(logged_in_page, base_url, run_id, app_ctx):
    page = logged_in_page
    _open_and_tick_both(page, base_url)

    page.locator('[data-action="bulk-all-lanes"]').click()

    assert _apply(page).status == 200
    assert _lanes(app_ctx) == [[1, 2, 3, 4, 5, 6, 7, 8]] * 2
