"""Paste, preview, then add: nothing is saved until Add, and Add saves
exactly what the preview showed."""

import pytest
from playwright.sync_api import expect


def _open_paste(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.click("summary.paste-section-summary")


def _preview(page):
    with page.expect_response(lambda r: r.url.endswith("/samples/preview") and r.status == 200):
        page.click(".paste-form button[type=submit]")


@pytest.mark.browser
def test_preview_then_add(logged_in_page, base_url, app_ctx, mutable_run_id):
    page = logged_in_page
    _open_paste(page, base_url, mutable_run_id)
    page.fill("#paste_data", "sample_id,test_id\nNEW-01,\nNEW-02,WGS\n")
    page.select_option("#default_test_id", "WGS")
    page.check("input[name=lanes][value='3']")
    _preview(page)

    expect(page.locator(".paste-table tbody tr")).to_have_count(2)
    expect(page.locator(".paste-preview")).to_contain_text("(picked)")
    assert len(app_ctx.run_repo.get_by_id(mutable_run_id).samples) == 4  # nothing saved yet

    page.click("text=Add 2 samples")
    expect(page.locator("#error-banner")).to_contain_text("Added 2 samples to lanes 1, 3.")
    added = {s.sample_id: s for s in app_ctx.run_repo.get_by_id(mutable_run_id).samples}
    assert (added["NEW-01"].test_id, added["NEW-01"].lanes) == ("WGS", [1, 3])


@pytest.mark.browser
def test_back_to_edit_keeps_the_text(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    _open_paste(page, base_url, mutable_run_id)
    page.fill("#paste_data", "KEEP-01,WGS")
    _preview(page)
    page.click("text=Back to edit")
    expect(page.locator("#paste_data")).to_have_value("KEEP-01,WGS")


@pytest.mark.browser
def test_repeated_id_disables_add(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    _open_paste(page, base_url, mutable_run_id)
    page.fill("#paste_data", "DUP-01,WGS\nDUP-01,WGS")
    _preview(page)
    expect(page.locator(".paste-actions button.btn-primary")).to_be_disabled()
    expect(page.locator(".paste-actions")).to_contain_text("Fix the red rows first.")
