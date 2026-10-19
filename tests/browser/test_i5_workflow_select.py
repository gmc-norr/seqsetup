"""The setup page's i5 workflow select (spec 2026-10-04 group A2, §3): shown
for an instrument with more than one workflow, saved on change, and gone
when the instrument changes to one with a single workflow."""

import pytest
from playwright.sync_api import expect

I100 = "MiSeq i100 Series"
MINISEQ = "MiniSeq"
NOVASEQ_X = "NovaSeq X Series"


def _new_run(page) -> str:
    page.click("button.sidebar-btn")
    page.wait_for_url("**/runs/new/step/1?new=1&run_id=*")
    page.wait_for_load_state("networkidle")
    return page.url.split("run_id=", 1)[1]


def _pick_instrument(page, name: str) -> None:
    """Pick an instrument and wait until htmx has settled the swap: a select
    sent out of band is wired up only then."""
    page.evaluate("""() => {
        window.__a2Settled = false;
        document.body.addEventListener('htmx:afterSettle',
            () => { window.__a2Settled = true; }, {once: true});
    }""")
    with page.expect_response(lambda r: r.url.endswith("/instrument") and r.status == 200):
        page.select_option("#instrument_platform", name)
    page.wait_for_function("() => window.__a2Settled")


@pytest.mark.browser
def test_the_select_shows_for_miniseq_and_not_for_novaseq_x_or_the_i100(logged_in_page, app_ctx):
    page = logged_in_page
    run_id = _new_run(page)
    try:
        container = page.locator("#i5-workflow-config")
        expect(container).to_be_hidden()
        expect(page.locator("#i5_workflow")).to_have_count(0)

        _pick_instrument(page, MINISEQ)
        expect(container).to_be_visible()
        expect(page.locator("#i5_workflow option")).to_have_text(
            ["Standard kits (standard)", "Rapid kits"])
        expect(page.locator("#i5_workflow")).to_have_value("Standard kits")

        _pick_instrument(page, NOVASEQ_X)
        expect(page.locator("#i5_workflow")).to_have_count(0)
        expect(container).to_be_hidden()
        assert app_ctx.run_repo.get_by_id(run_id).i5_workflow == "Standard"

        # The shipped i100 lists Read-first only
        # (docs/design/2026-10-19-i100-read-first-design.md).
        _pick_instrument(page, I100)
        expect(page.locator("#i5_workflow")).to_have_count(0)
        expect(container).to_be_hidden()
        assert app_ctx.run_repo.get_by_id(run_id).i5_workflow == "Read-first"
    finally:
        app_ctx.run_repo.collection.delete_one({"_id": run_id})


@pytest.mark.browser
def test_a_change_is_saved(logged_in_page, app_ctx):
    page = logged_in_page
    run_id = _new_run(page)
    try:
        _pick_instrument(page, MINISEQ)
        with page.expect_response(lambda r: r.url.endswith("/i5-workflow") and r.status == 200):
            page.select_option("#i5_workflow", "Rapid kits")
        expect(page.locator("#i5_workflow")).to_have_value("Rapid kits")
        assert app_ctx.run_repo.get_by_id(run_id).i5_workflow == "Rapid kits"

        page.reload()
        expect(page.locator("#i5_workflow")).to_have_value("Rapid kits")
    finally:
        app_ctx.run_repo.collection.delete_one({"_id": run_id})
