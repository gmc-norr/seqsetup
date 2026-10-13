"""A stored file's long line scrolls inside its box, not the whole page.

A Sample Sheet or JSON line can be far wider than a phone, or than a
laptop's window; the page itself must not scroll sideways.
"""

from datetime import datetime

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

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
        generated_samplesheet_v2=f"[Header]\nFileFormatVersion,2\n\n[BCLConvert_Data]\n{LONG_LINE}\n",
    )
    run.add_sample(Sample(id=f"{run.id}-s1", sample_id="S1", lanes=[1]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


@pytest.mark.browser
@pytest.mark.parametrize("width", [390, 1280])
def test_a_long_line_scrolls_in_its_box(logged_in_page, base_url, run_id, width):
    page = logged_in_page
    page.set_viewport_size({"width": width, "height": 800})
    page.goto(f"{base_url}/served-runs/{run_id}")
    page.wait_for_load_state("networkidle")

    box = page.locator("#served-samplesheet-v2 .served-content")
    assert LONG_LINE in box.inner_text()
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    assert box.evaluate("e => e.scrollWidth > e.clientWidth")
    assert box.evaluate("e => getComputedStyle(e).overflowX") in ("auto", "scroll")
