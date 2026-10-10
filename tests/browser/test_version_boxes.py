"""The version boxes in the browser (spec 2026-10-07 group A4, §2, §4)."""

import pytest
from playwright.sync_api import expect

from .test_paste_preview import _open_paste, _preview


@pytest.mark.browser
def test_the_paste_box_gives_rows_without_one_a_version(logged_in_page, base_url, app_ctx,
                                                        mutable_run_id):
    page = logged_in_page
    _open_paste(page, base_url, mutable_run_id)
    page.fill("#paste_data", "sample_id,test_id,test_version\nVER-01,WGS,\nVER-02,WGS,2\n")
    page.fill("#default_test_version", "1")
    _preview(page)
    expect(page.locator(".paste-table tbody tr").first).to_contain_text("(picked)")
    page.click("text=Add 2 samples")
    expect(page.locator("#error-banner")).to_contain_text("Added 2 samples")
    added = {s.sample_id: (s.test_id, s.test_version)
             for s in app_ctx.run_repo.get_by_id(mutable_run_id).samples}
    assert (added["VER-01"], added["VER-02"]) == (("WGS", "1"), ("WGS", "2"))


def _set_samples(app_ctx, run_id, test, version):
    run = app_ctx.run_repo.get_by_id(run_id)
    for sample in run.samples:
        sample.test_id, sample.test_version = test, version
    app_ctx.run_repo.save(run)


def _tests(app_ctx, run_id):
    return {s.sample_id: (s.test_id, s.test_version)
            for s in app_ctx.run_repo.get_by_id(run_id).samples}


@pytest.mark.browser
def test_clear_takes_the_test_and_the_version(logged_in_page, base_url, app_ctx, mutable_run_id):
    _set_samples(app_ctx, mutable_run_id, "WGS", "1")
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")
    page.locator(f"#sample-row-{mutable_run_id}-s1 .sample-checkbox").check()
    page.locator(f"#sample-row-{mutable_run_id}-s2 .sample-checkbox").check()
    with page.expect_response(lambda r: r.url.endswith("/samples/set-test-id") and r.status == 200):
        page.locator('[data-action="bulk-clear-testid"]').click()
    assert _tests(app_ctx, mutable_run_id) == {
        "MUT-01": ("", ""), "MUT-02": ("", ""), "MUT-03": ("WGS", "1"), "MUT-04": ("WGS", "1")}


@pytest.mark.browser
def test_the_version_box_for_one_test(logged_in_page, base_url, app_ctx, mutable_run_id):
    _set_samples(app_ctx, mutable_run_id, "WGS", "")
    page = logged_in_page
    page.goto(f"{base_url}/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")
    fix = page.locator("form.validate-fix", has_text="WGS: set the version for the 4 samples")
    fix.locator("input[name=test_version]").fill("1")
    with page.expect_response(lambda r: r.url.endswith("/samples/set-test-id") and r.status == 200):
        fix.locator("button").click()
    expect(page.locator("form.validate-fix")).to_have_count(0)
    assert set(_tests(app_ctx, mutable_run_id).values()) == {("WGS", "1")}
