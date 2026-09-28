"""An admin deletes an Archived run from the dashboard and finds it, with
its change history, on Admin → Deleted runs (spec 2026-09-28 group 2a, F16)."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.services import database

RUN_ID = "group-2a-archived"


@pytest.fixture
def archived_run_id(app_ctx):
    t = datetime(2026, 1, 12, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Group 2a archived",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.ARCHIVED,
        created_by="maker", created_at=t, updated_at=t,
    )
    run.add_sample(Sample(id=f"{RUN_ID}-s1", sample_id="G2A-SAMPLE-1", lanes=[1]))
    app_ctx.run_repo.save(run)
    app_ctx.run_history_repo.append(RunHistoryEntry(
        run_id=RUN_ID, timestamp=t, actor="maker", kind="updated",
        field_changes=[{"field": "run_name", "before": "Old name", "after": "Group 2a archived"}]))
    yield RUN_ID
    # Other browser tests share this database. Clean up here; the app itself
    # has no way to remove a copy or history, on purpose.
    db = database.get_db()
    db["runs"].delete_many({"_id": RUN_ID})
    db["deleted_runs"].delete_many({"run_id": RUN_ID})
    db["run_history"].delete_many({"run_id": RUN_ID})


@pytest.mark.browser
def test_admin_deletes_an_archived_run_and_finds_it(logged_in_page, base_url, archived_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")
    page.click("button[hx-get='/dashboard/tab/archived']")
    row = page.locator(f"#run-item-{archived_run_id}")
    row.wait_for()
    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), d.accept()))
    row.get_by_role("button", name="Delete").click()
    expect(page.locator(f"#run-item-{archived_run_id}")).to_have_count(0)
    assert "A copy and its change history are kept on Admin → Deleted runs." in dialogs[0]

    # The sidebar's Admin section is folded shut outside /admin pages, so go
    # by address; the integration tests check the sidebar link.
    page.goto(f"{base_url}/admin/deleted-runs")
    link = page.get_by_role("link", name="Group 2a archived")
    expect(link).to_be_visible()
    expect(page.locator("#deleted-runs-page tbody tr").filter(has=link)).to_contain_text("Deleted")
    link.click()
    expect(page.locator("#deleted-run-page")).to_contain_text("G2A-SAMPLE-1")
    panel = page.locator("#deleted-run-page .run-history-panel")
    panel.scroll_into_view_if_needed()
    expect(panel).to_contain_text("Old name")
