"""Check's "Set test" picker fixes every sample without a test in one go,
and the table, Check box and step bar all update without a reload."""

import pytest
from playwright.sync_api import expect


@pytest.mark.browser
def test_set_test_for_samples_without_one(logged_in_page, base_url, app_ctx, mutable_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")

    fix = page.locator("form.validate-fix")
    expect(fix).to_contain_text("Set test for the 4 samples without one")
    fix.locator("select").select_option("WGS")
    with page.expect_response(lambda r: r.url.endswith("/samples/set-test-id") and r.status == 200):
        fix.locator("button").click()

    expect(page.locator("form.validate-fix")).to_have_count(0)  # Check refreshed
    expect(page.locator("#sample-section")).to_have_count(1)    # swapped, not nested
    tests = {s.sample_id: s.test_id for s in app_ctx.run_repo.get_by_id(mutable_run_id).samples}
    assert set(tests.values()) == {"WGS"}
