"""The setup page shows the kit's cycle limit, warns when the total is over
it, and keeps the limit current when the instrument changes."""

import pytest
from playwright.sync_api import expect

NOVASEQ_X = "NovaSeq X Series"
NEXTSEQ = "NextSeq 1000/2000"


@pytest.fixture
def kit_limits(monkeypatch):
    """Limits for the 300-cycle kit in the fallback YAML (the browser app
    runs in this process and syncs no instruments)."""
    from seqsetup.data import instruments as instruments_module
    from seqsetup.services.validation import clear_validation_cache
    for name, limit in ((NOVASEQ_X, 338), (NEXTSEQ, 340)):
        config = dict(instruments_module._instruments[name])
        config["reagent_kit_max_cycles"] = {300: limit}
        monkeypatch.setitem(instruments_module._instruments, name, config)
    clear_validation_cache()
    yield
    clear_validation_cache()


@pytest.mark.browser
def test_limit_warning_and_instrument_change(logged_in_page, base_url, app_ctx, kit_limits):
    page = logged_in_page
    page.click("button.sidebar-btn")
    page.wait_for_url("**/runs/new/step/1?new=1&run_id=*")
    run_id = page.url.split("run_id=", 1)[1]
    try:
        page.wait_for_load_state("networkidle")
        total = page.locator("#cycle-total")
        expect(total).to_contain_text("Total: 322 / 338 max (300-cycle kit)")
        expect(total).not_to_contain_text("Too many cycles")

        with page.expect_response(lambda r: r.url.endswith("/cycles") and r.status == 200):
            page.fill("#read1_cycles", "301")
            page.dispatch_event("#read1_cycles", "change")
        expect(total).to_contain_text("Total: 472 / 338 max (300-cycle kit)")
        expect(total).to_contain_text("Too many cycles for this kit.")

        with page.expect_response(lambda r: r.url.endswith("/instrument") and r.status == 200):
            page.select_option("#instrument_platform", NEXTSEQ)
        expect(total).to_contain_text("Total: 472 / 340 max (300-cycle kit)")
        expect(page.locator("#cycle-total")).to_have_count(1)
    finally:
        app_ctx.run_repo.delete(run_id)
