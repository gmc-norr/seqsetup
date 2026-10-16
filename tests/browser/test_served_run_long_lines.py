"""API Exports, on a narrow screen: wide content scrolls inside its box,
not the whole page.

A Sample Sheet or JSON line can be far wider than a phone, or than a
laptop's window, and so can the list's columns; the page itself must not
scroll sideways.
"""

from datetime import datetime

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from ..export_seed import seed_stored_exports
from .conftest import hold_edit_lock

LONG_LINE = "Sample_ID," + ",".join(f"Column{n}" for n in range(120))


@pytest.fixture
def run_id(app_ctx):
    """A Ready run whose stored sheet has one very long line; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="served-wide-run", run_name="Served wide run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.READY,
        created_at=t, updated_at=t,
        exports=seed_stored_exports(
            app_ctx, "served-wide-run",
            samplesheet_v2=f"[Header]\nFileFormatVersion,2\n\n[BCLConvert_Data]\n{LONG_LINE}\n",
            json="{}", validation_json='{"errors": []}', validation_pdf=b"%PDF-1.4\n"),
        sheet_targets={"samplesheet_v1": None, "samplesheet_v2": {
            "instrument": "NovaSeq X Series", "software": "BCL Convert", "software_version": "4.3.6",
            "i5_workflow": "W" * 64, "index2_column": "forward", "needs_runinfo_reverse_mark": True}},
    )
    run.add_sample(Sample(id=f"{run.id}-s1", sample_id="S1", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


@pytest.mark.browser
def test_the_list_fits_a_phone(logged_in_page, base_url, run_id):
    """The list's columns are wider than a phone: the table scrolls in its
    box, not the page."""
    page = logged_in_page
    page.set_viewport_size({"width": 390, "height": 800})
    page.goto(f"{base_url}/served-runs")
    page.wait_for_load_state("networkidle")
    assert page.locator(f"#served-run-{run_id}").is_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


@pytest.mark.browser
@pytest.mark.parametrize("width", [390, 1280])
def test_a_long_line_scrolls_in_its_box(logged_in_page, base_url, run_id, width):
    page = logged_in_page
    page.set_viewport_size({"width": width, "height": 800})
    page.goto(f"{base_url}/served-runs/{run_id}")
    page.wait_for_load_state("networkidle")

    box = page.locator("#served-samplesheet-v2 .served-content")
    assert LONG_LINE in box.inner_text()
    # The target box, with the longest i5 workflow name, wraps instead: none
    # of it runs past the box, where it would be cut off.
    target = page.locator("#served-samplesheet-v2 .served-target")
    assert target.is_visible()
    assert target.evaluate("e => e.scrollWidth <= e.clientWidth")
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert box.evaluate("e => e.scrollWidth > e.clientWidth")
    assert box.evaluate("e => getComputedStyle(e).overflowX") in ("auto", "scroll")
