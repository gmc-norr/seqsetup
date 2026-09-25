"""Typing in the dashboard search finds runs by sample ID; clearing it
brings the tabs back."""

import pytest
from playwright.sync_api import expect


@pytest.mark.browser
def test_search_by_sample_id_then_clear(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    page.goto(base_url + "/")
    page.wait_for_load_state("networkidle")

    with page.expect_response(lambda r: "/dashboard/search" in r.url):
        page.fill("#dashboard-search", "MUT-02")
    row = page.locator(f"#run-item-{mutable_run_id}")
    expect(row).to_be_visible()
    expect(row).to_contain_text("Sample: MUT-02")
    expect(page.locator("#dashboard")).to_contain_text("1 run matches")

    with page.expect_response(lambda r: "/dashboard/search" in r.url):
        page.fill("#dashboard-search", "")
    expect(page.locator("#dashboard button", has_text="Ready")).to_be_visible()
