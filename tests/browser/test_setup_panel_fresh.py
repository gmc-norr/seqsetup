"""Mark Ready and Return to Draft refresh the setup panel on the real page.

The integration tests check that the panel is in the answer and marked out of
band; this checks that htmx actually swaps it, so **Edit setup** really goes
away on Mark Ready and really comes back on Return to Draft, with no reload
(2026-10-18 batch, step 6).
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)

from .conftest import hold_edit_lock


@pytest.fixture
def setup_panel_run_id(app_ctx):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="setup-panel-run", run_name="Setup panel run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n, (i7, i5) in enumerate((("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC"),
                                  ("CGCTCATT", "CCTATCCT"), ("GAGATTCC", "GGCTCTGA")),
                                 start=1):
        run.add_sample(Sample(
            id=f"{run.id}-s{n}", sample_id=f"SETUP-{n}", lanes=list(range(1, 9)),
            test_id="WGS", test_version="1",
            index1=Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5),
        ))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


def _answer_any_questions(page):
    """Mark Ready may ask about colour balance or empty lanes; accept each."""
    for _ in range(4):
        confirm = page.locator("#ready-message .ready-confirm").get_by_role(
            "button", name="Mark Ready anyway")
        if confirm.count() == 0:
            return
        confirm.first.click()
        page.wait_for_timeout(500)


@pytest.mark.browser
def test_edit_setup_goes_and_comes_back_with_the_status(logged_in_page, base_url,
                                                        setup_panel_run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{setup_panel_run_id}")
    page.wait_for_load_state("networkidle")
    panel = page.locator("#run-config-panel")
    expect(panel.get_by_text("Edit setup")).to_be_visible()

    page.get_by_role("button", name="Mark Ready").click()
    _answer_any_questions(page)
    page.wait_for_selector("#run-status-bar .status-ready")

    # One panel, and no Edit setup in it -- without a reload.
    expect(page.locator("#run-config-panel")).to_have_count(1)
    expect(page.locator("#run-config-panel").get_by_text("Edit setup")).to_have_count(0)
    expect(page.locator("#run-config-panel")).to_contain_text("NovaSeq X Series")

    page.get_by_role("button", name="Return to Draft").click()
    page.wait_for_selector("#run-status-bar .status-draft")

    expect(page.locator("#run-config-panel")).to_have_count(1)
    expect(page.locator("#run-config-panel").get_by_text("Edit setup")).to_be_visible()
