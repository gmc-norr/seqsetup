"""A user who sets up a run control by control is never refused.

Every setup save sends the version of the run the page showed and is refused
when it is stale (the night run's Q2, 2026-10-13). Each save answers with the
version it wrote, so the next control sends that one. This walks the page as
a user does -- instrument, i5 workflow, flow cell, kit, cycles, name -- then
Continue, and no save may be refused on the way.
"""

import pytest
from playwright.sync_api import expect

NOVASEQ_6000 = "NovaSeq 6000"


@pytest.mark.browser
def test_each_setup_control_in_turn_then_continue(logged_in_page, base_url, app_ctx):
    page = logged_in_page
    page.click("button.sidebar-btn")
    page.wait_for_url("**/runs/new/step/1?new=1&run_id=*")
    run_id = page.url.split("run_id=", 1)[1]
    refused = []
    page.on("response", lambda r: refused.append(f"{r.status} {r.url}")
            if f"/runs/{run_id}/" in r.url and r.status >= 400 else None)
    try:
        page.wait_for_load_state("networkidle")

        def saved(path, act):
            """Act, check the save was answered 200, and wait until htmx has
            settled the swap: a select sent out of band is wired up only then
            (as in test_i5_workflow_select.py). A person is never faster."""
            page.evaluate("""() => {
                window.__settled = false;
                document.body.addEventListener('htmx:afterSettle',
                    () => { window.__settled = true; }, {once: true});
            }""")
            with page.expect_response(lambda r: r.url.endswith(path)) as answer:
                act()
            assert answer.value.status == 200, f"{path}: {answer.value.status} {answer.value.text()[:300]}"
            page.wait_for_function(
                "() => window.__settled && !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling')")

        saved("/instrument", lambda: page.select_option("#instrument_platform", NOVASEQ_6000))
        saved("/i5-workflow", lambda: page.select_option("#i5_workflow", "v1.0 reagents"))
        saved("/flowcell", lambda: page.select_option("#flowcell-select", "S4"))
        saved("/reagent-kit", lambda: page.select_option("#reagent-kit-select", "300"))
        for box, value in (("#read1_cycles", "101"), ("#read2_cycles", "101")):
            saved("/cycles", lambda: (page.fill(box, value), page.press(box, "Tab")))
        saved("/cycles", lambda: page.select_option("#index1_cycles", "8"))
        saved("/cycles", lambda: page.select_option("#index2_cycles", "8"))
        saved("/name", lambda: (page.fill("#run_name", "Setup chain run"), page.press("#run_name", "Tab")))

        page.click("text=Continue to Run")
        page.wait_for_url(f"{base_url}/runs/{run_id}")

        assert refused == []
        run = app_ctx.run_repo.get_by_id(run_id)
        rc = run.run_cycles
        assert (run.run_name, run.instrument_platform.value, run.i5_workflow, run.flowcell_type,
                run.reagent_cycles) == ("Setup chain run", NOVASEQ_6000, "v1.0 reagents", "S4", 300)
        assert (rc.read1_cycles, rc.read2_cycles, rc.index1_cycles, rc.index2_cycles) == (101, 101, 8, 8)
        expect(page.locator("#run-config-panel")).to_contain_text("Read 1: 101")
    finally:
        app_ctx.run_repo.collection.delete_one({"_id": run_id})
