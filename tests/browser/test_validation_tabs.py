"""The validation page's tabs open when clicked.

The Heatmaps, Color Balance and Dark Cycles tabs are Alpine ``x-show``
toggles on one page, so only a click shows them. The screenshot capture
file that used to click them was removed (night run batch 4, item 4b), and
nothing else in the browser suite clicked a validation tab.
"""

from datetime import datetime

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from .conftest import hold_edit_lock

TABS = [
    ("Heatmaps", ".heatmaps-tab-content"),
    ("Color Balance", ".colorbalance-tab-content"),
    ("Dark Cycles", ".darkcycles-tab-content"),
]


@pytest.fixture
def run_id(app_ctx):
    """A NovaSeq X (two-colour) draft with two indexed samples in lane 1, so
    all three tabs have something to show; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(id="validation-tabs-run", run_name="Validation tabs run",
                        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
                        run_cycles=RunCycles(151, 151, 8, 8), created_at=t, updated_at=t)
    for n, (i7, i5) in enumerate([("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")], start=1):
        pair = IndexPair(id=f"p{n}", name=f"p{n}",
                         index1=Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7),
                         index2=Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5))
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"S{n}", lanes=[1], index_pair=pair))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


@pytest.mark.browser
def test_each_tab_shows_its_content_when_clicked(logged_in_page, base_url, run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}/validation")
    page.wait_for_load_state("networkidle")
    tabs = page.locator("#validation-tabs")

    for label, content in TABS:
        assert not page.locator(content).is_visible(), f"{label} shows before it is clicked"

    for label, content in TABS:
        tabs.get_by_role("button", name=label).click()
        page.locator(content).wait_for(state="visible")
        for _other, other_content in TABS:
            if other_content != content:
                assert not page.locator(other_content).is_visible(), f"{_other} still shows"
