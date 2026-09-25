"""Bulk lane panel applies bulk actions without nesting the sample section.

The panel's hidden forms (see wizard/_bulk_lane_panel.html) all carried
hx-target="#sample-table" hx-swap="outerHTML". Four of the five routes
(set-lanes, set-mismatches, set-override-cycles, set-test-id) actually
return the *whole* #sample-section fragment via _render_sample_section
— which itself contains a nested #sample-table. Targeting #sample-table
meant the response (a full #sample-section) replaced the old
#sample-table, nesting a duplicate #sample-section inside the section
it belongs to. The fifth route, bulk-delete, returns just the
#sample-table fragment, so its #sample-table target was already correct
and is left alone.

These tests drive the panel the way a user would (tick samples, set a
value, click Apply) and check the resulting DOM shape plus the
persisted change, for each of the four fixed actions.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


@pytest.fixture
def bulk_lane_panel_run_id(app_ctx):
    """A draft with two samples on lane 1; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="bulk-lane-panel-run", run_name="Bulk lane panel run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"BULK-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.delete(run.id)


def _open_and_select_both(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.locator(f"#sample-row-{run_id}-s1 .sample-checkbox").check()
    page.locator(f"#sample-row-{run_id}-s2 .sample-checkbox").check()


def _assert_single_sample_section(page):
    assert page.locator("#sample-section").count() == 1
    assert page.locator("#sample-table #sample-section").count() == 0
    assert page.locator("#sample-table").count() == 1


@pytest.mark.browser
def test_bulk_lane_change_leaves_one_sample_section(logged_in_page, base_url, bulk_lane_panel_run_id, app_ctx):
    page = logged_in_page
    _open_and_select_both(page, base_url, bulk_lane_panel_run_id)

    # Tick lane 2 in the bulk panel and click Apply, as a user would.
    page.locator('.bulk-lane-checkbox[value="2"]').check()
    with page.expect_response(lambda r: r.url.endswith("/samples/set-lanes")) as resp_info:
        page.locator('[data-action="bulk-apply-lanes"]').click()
    assert resp_info.value.status == 200

    # Let the swap settle before inspecting the DOM.
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(300)

    _assert_single_sample_section(page)

    run = app_ctx.run_repo.get_by_id(bulk_lane_panel_run_id)
    for sample in run.samples:
        assert sample.lanes == [2]


@pytest.mark.browser
def test_bulk_mismatch_change_leaves_one_sample_section(logged_in_page, base_url, bulk_lane_panel_run_id, app_ctx):
    page = logged_in_page
    _open_and_select_both(page, base_url, bulk_lane_panel_run_id)

    page.locator("#bulk-mismatch-i7-input").fill("2")
    page.locator("#bulk-mismatch-i5-input").fill("1")
    with page.expect_response(lambda r: r.url.endswith("/samples/set-mismatches")) as resp_info:
        page.locator('[data-action="bulk-apply-mismatches"]').click()
    assert resp_info.value.status == 200

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(300)

    _assert_single_sample_section(page)

    run = app_ctx.run_repo.get_by_id(bulk_lane_panel_run_id)
    for sample in run.samples:
        assert sample.barcode_mismatches_index1 == 2
        assert sample.barcode_mismatches_index2 == 1


@pytest.mark.browser
def test_bulk_override_cycles_change_leaves_one_sample_section(logged_in_page, base_url, bulk_lane_panel_run_id, app_ctx):
    page = logged_in_page
    _open_and_select_both(page, base_url, bulk_lane_panel_run_id)

    page.locator("#bulk-override-cycles-input").fill("Y151;I8;I8;Y151")
    with page.expect_response(lambda r: r.url.endswith("/samples/set-override-cycles")) as resp_info:
        page.locator('[data-action="bulk-apply-override"]').click()
    assert resp_info.value.status == 200

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(300)

    _assert_single_sample_section(page)

    run = app_ctx.run_repo.get_by_id(bulk_lane_panel_run_id)
    for sample in run.samples:
        assert sample.override_cycles == "Y151;I8;I8;Y151"


@pytest.mark.browser
def test_bulk_test_id_change_leaves_one_sample_section(logged_in_page, base_url, bulk_lane_panel_run_id, app_ctx):
    page = logged_in_page
    _open_and_select_both(page, base_url, bulk_lane_panel_run_id)

    page.select_option("#bulk-test-id-input", value="WGS")
    with page.expect_response(lambda r: r.url.endswith("/samples/set-test-id")) as resp_info:
        page.locator('[data-action="bulk-apply-testid"]').click()
    assert resp_info.value.status == 200

    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(300)

    _assert_single_sample_section(page)

    run = app_ctx.run_repo.get_by_id(bulk_lane_panel_run_id)
    for sample in run.samples:
        assert sample.test_id == "WGS"
