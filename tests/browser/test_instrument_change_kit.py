"""Changing the instrument on the setup page keeps a reagent kit the new
flowcell offers — the reagent-kit select must refresh even though the
instrument select's HTMX request targets the flowcell select, not it."""

import pytest
from playwright.sync_api import expect

GAIIX = "GAIIx"


@pytest.mark.browser
def test_instrument_change_refreshes_reagent_kit_select(logged_in_page, base_url, app_ctx):
    page = logged_in_page
    page.click("button.sidebar-btn")
    page.wait_for_url("**/runs/new/step/1?new=1&run_id=*")
    run_id = page.url.split("run_id=", 1)[1]
    try:
        page.wait_for_load_state("networkidle")

        with page.expect_response(lambda r: r.url.endswith("/instrument") and r.status == 200):
            page.select_option("#instrument_platform", GAIIX)

        kit_select = page.locator("#reagent-kit-select")
        expect(kit_select).to_have_count(1)
        options = kit_select.locator("option")
        expect(options).to_have_count(5)
        expect(options).to_have_text(
            ["36 cycles", "50 cycles", "76 cycles", "100 cycles", "150 cycles"])

        run = app_ctx.run_repo.get_by_id(run_id)
        assert run.reagent_cycles == 36
        assert kit_select.input_value() == "36"
    finally:
        app_ctx.run_repo.delete(run_id)
