"""The setup page's version field is kept current, and a stale one is refused.

"Continue to Run" / "Back to Run" posts the whole setup form, so a tab left
open used to write its old name and cycles over another window's — and every
sample's OverrideCycles with the cycles. The page now sends the version of
the run it showed; each save answers with the version it wrote, out of band,
and a version that is no longer the stored one is refused.
"""

import pytest
from playwright.sync_api import expect
from .conftest import hold_edit_lock


@pytest.mark.browser
def test_a_save_refreshes_the_version_and_a_stale_one_is_refused(
        logged_in_page, base_url, app_ctx):
    page = logged_in_page
    page.click("button.sidebar-btn")
    page.wait_for_url("**/runs/new/step/1?new=1&run_id=*")
    run_id = page.url.split("run_id=", 1)[1]
    try:
        page.wait_for_load_state("networkidle")
        opened_with = page.input_value("#run-version")
        assert opened_with

        # A save on the page answers with the version it wrote. Tab moves the
        # focus off the box, so clicking Continue below saves nothing first.
        with page.expect_response(lambda r: r.url.endswith("/name") and r.status == 200):
            page.fill("#run_name", "Version test run")
            page.press("#run_name", "Tab")
        page.wait_for_function(
            "v => document.getElementById('run-version').value !== v", arg=opened_with)

        # Another window changes the run: this page's version is now stale.
        run = app_ctx.run_repo.get_by_id(run_id)
        run.run_name = "Other window"
        run.touch(updated_by="other-window")
        app_ctx.run_repo.save(run)
        hold_edit_lock(app_ctx, run.id)

        with page.expect_response(lambda r: r.url.endswith("/setup") and r.status == 409):
            page.click("text=Continue to Run")
        expect(page.locator("#error-banner")).to_contain_text(
            "This run was changed in another window.")
        assert "/runs/new/step/1" in page.url
        assert app_ctx.run_repo.get_by_id(run_id).run_name == "Other window"
    finally:
        app_ctx.run_repo.collection.delete_one({"_id": run_id})
