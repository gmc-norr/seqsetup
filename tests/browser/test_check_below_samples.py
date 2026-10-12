"""Check refreshing does not move the sample rows.

Check refreshes itself 300 ms after each change, and its error list grows
or shrinks. Placed above the table, it pushed every row down or up by
about one row each time, so a quick drag could land on the wrong sample.
Below the table, nothing above the rows changes height.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

I7 = ["ATTACTCG", "TCCGGAGA"]
I5 = ["TATAGCCT", "ATAGAGGC"]


@pytest.fixture
def run_id(app_ctx):
    """A draft with two indexed samples; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="check-below-run", run_name="Check below run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        sample = Sample(id=f"{run.id}-s{n}", sample_id=f"CB-0{n}", lanes=[1])
        sample.assign_index(IndexPair(
            id=f"cb-{n}", name=f"CB{n}",
            index1=Index(name=f"CB{n}", sequence=I7[n - 1], index_type=IndexType.I7),
            index2=Index(name=f"CB{n}", sequence=I5[n - 1], index_type=IndexType.I5),
        ))
        run.add_sample(sample)
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


TOP = "id => Math.round(document.getElementById(id).getBoundingClientRect().top)"
HEIGHT = "id => Math.round(document.getElementById(id).getBoundingClientRect().height)"


@pytest.mark.browser
def test_rows_stay_put_when_check_refreshes(logged_in_page, base_url, run_id):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.get_by_role("button", name="Edit indexes").click()
    row = f"sample-row-{run_id}-s1"
    page.evaluate("id => window.scrollBy(0, document.getElementById(id).getBoundingClientRect().top - 300)", row)

    check = page.locator("#validate-panel")
    assert check.evaluate("e => e.closest('#samples') !== null")
    assert check.evaluate("e => e.closest('#sample-section') === null")
    top, check_height = page.evaluate(TOP, row), page.evaluate(HEIGHT, "validate-panel")

    # Clearing the pair adds an error to Check, 300 ms later.
    with page.expect_response(lambda r: r.url.endswith(f"/runs/{run_id}/validate-panel")):
        with page.expect_response(lambda r: "/clear-index" in r.url):
            page.locator(f'#{row} button[title="Clear index pair"]').click()
    page.wait_for_function(
        "() => !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added')")
    expect(page.locator(f"#{row} .drop-zone").first).to_be_visible()

    assert page.evaluate(HEIGHT, "validate-panel") != check_height
    assert abs(page.evaluate(TOP, row) - top) <= 1
