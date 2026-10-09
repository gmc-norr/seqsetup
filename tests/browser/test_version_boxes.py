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
