"""The run setup page saves what the user sees.

Cycles typed on the New Run page used to be dropped (the form aimed at an
element that is not on that page), "Continue to Run" was a plain link
that could beat the last save, Enter in the name box reloaded the page
without its run, and Cancel left an empty draft behind.
"""

import pytest
from playwright.sync_api import expect


def _new_run(page, base_url):
    """Start a run from the sidebar; return its id."""
    page.click("button.sidebar-btn")
    page.wait_for_url("**/runs/new/step/1?new=1&run_id=*")
    page.wait_for_load_state("networkidle")
    return page.url.split("run_id=", 1)[1]


@pytest.fixture
def created_runs(app_ctx):
    """Runs a test creates through the UI, deleted afterwards so they never
    show up in later screenshot tests."""
    ids = []
    yield ids
    for run_id in ids:
        app_ctx.run_repo.delete(run_id)


@pytest.mark.browser
def test_new_run_keeps_typed_name_and_cycles(logged_in_page, base_url, app_ctx, created_runs):
    page = logged_in_page
    run_id = _new_run(page, base_url)
    created_runs.append(run_id)

    page.fill("#read1_cycles", "101")
    page.fill("#read2_cycles", "0")
    page.select_option("#index1_cycles", "8")
    # Typed, then Continue clicked straight away: its change-save and the
    # Continue save must both land, in order.
    page.fill("#run_name", "Setup test run")
    page.click("text=Continue to Run")
    page.wait_for_url(f"{base_url}/runs/{run_id}")

    run = app_ctx.run_repo.get_by_id(run_id)
    assert run.run_name == "Setup test run"
    rc = run.run_cycles
    assert (rc.read1_cycles, rc.read2_cycles, rc.index1_cycles) == (101, 0, 8)
    expect(page.locator("#run-config-panel")).to_contain_text("Read 1: 101")


@pytest.mark.browser
def test_cycle_change_saves_and_updates_total(logged_in_page, base_url, app_ctx, created_runs):
    page = logged_in_page
    run_id = _new_run(page, base_url)
    created_runs.append(run_id)

    before = app_ctx.run_repo.get_by_id(run_id).run_cycles
    with page.expect_response(lambda r: r.url.endswith("/cycles") and r.status == 200):
        page.select_option("#index2_cycles", "8")
    expected = before.read1_cycles + before.read2_cycles + before.index1_cycles + 8
    expect(page.locator(".cycle-total")).to_contain_text(f"Total: {expected} /")
    assert app_ctx.run_repo.get_by_id(run_id).run_cycles.index2_cycles == 8


@pytest.mark.browser
def test_bad_cycle_value_is_shown_and_blocks_continue(logged_in_page, base_url, created_runs):
    page = logged_in_page
    run_id = _new_run(page, base_url)
    created_runs.append(run_id)

    with page.expect_response(lambda r: r.url.endswith("/cycles") and r.status == 400):
        page.fill("#read1_cycles", "")
        page.dispatch_event("#read1_cycles", "change")
    expect(page.locator("#error-banner")).to_contain_text("Read 1 cycles must be a whole number")

    with page.expect_response(lambda r: r.url.endswith("/setup") and r.status == 400):
        page.click("text=Continue to Run")
    assert "/runs/new/step/1" in page.url


@pytest.mark.browser
def test_enter_in_name_stays_on_page(logged_in_page, base_url, app_ctx, created_runs):
    page = logged_in_page
    run_id = _new_run(page, base_url)
    created_runs.append(run_id)

    with page.expect_response(lambda r: r.url.endswith("/name") and r.status == 200):
        page.fill("#run_name", "Enter test")
        page.press("#run_name", "Enter")
    page.wait_for_load_state("networkidle")
    assert f"run_id={run_id}" in page.url
    assert app_ctx.run_repo.get_by_id(run_id).run_name == "Enter test"


@pytest.mark.browser
def test_cancel_deletes_the_new_run(logged_in_page, base_url, app_ctx, created_runs):
    page = logged_in_page
    run_id = _new_run(page, base_url)
    created_runs.append(run_id)

    page.on("dialog", lambda d: d.accept())
    page.click("text=Cancel")
    page.wait_for_url(f"{base_url}/")
    assert app_ctx.run_repo.get_by_id(run_id) is None


@pytest.mark.browser
def test_edit_setup_from_run_page(logged_in_page, base_url, app_ctx, mutable_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.click("text=Edit setup")
    page.wait_for_load_state("networkidle")
    expect(page.locator("h2")).to_have_text("Run Setup")
    expect(page.locator("text=Cancel")).to_have_count(0)

    page.fill("#run_description", "Edited later")
    page.click("text=Back to Run")
    page.wait_for_url(f"{base_url}/runs/{mutable_run_id}")
    assert app_ctx.run_repo.get_by_id(mutable_run_id).run_description == "Edited later"
