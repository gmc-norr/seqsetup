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
from .conftest import hold_edit_lock

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
    hold_edit_lock(app_ctx, run.id)
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


def _spread(count, skip=0):
    """``count`` 8-base sequences, each at least 4 bases from the others and
    none starting with GG, so they raise no index error."""
    picked = []
    for n in range(4 ** 8):
        seq = "".join("ACGT"[(n >> (2 * k)) & 3] for k in range(8))
        if not seq.startswith("GG") and all(sum(a != b for a, b in zip(seq, p)) >= 4 for p in picked):
            picked.append(seq)
            if len(picked) == skip + count:
                break
    return picked[skip:]


@pytest.fixture
def long_run_id(app_ctx):
    """A draft with 14 indexed samples, the last in lane 9 (an error on a
    10B flow cell, which has 8 lanes); deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="check-shrink-run", run_name="Check shrink run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    i7s, i5s = _spread(14), _spread(14, skip=14)
    for n in range(1, 15):
        sample = Sample(id=f"{run.id}-s{n}", sample_id=f"CS-{n:02d}", lanes=[9 if n == 14 else 1])
        sample.assign_index(IndexPair(
            id=f"cs-{n}", name=f"CS{n}",
            index1=Index(name=f"CS{n}", sequence=i7s[n - 1], index_type=IndexType.I7),
            index2=Index(name=f"CS{n}", sequence=i5s[n - 1], index_type=IndexType.I5),
        ))
        run.add_sample(sample)
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


@pytest.mark.browser
def test_rows_stay_put_when_check_shrinks_at_the_bottom(logged_in_page, base_url, app_ctx, long_run_id):
    """Scrolled to the very end, a Check that got shorter made the page
    shorter, and the browser pulled every row down. Check keeps its
    tallest height while the page is open."""
    page = logged_in_page
    page.set_viewport_size({"width": 1280, "height": 1000})
    page.goto(f"{base_url}/runs/{long_run_id}")
    page.wait_for_load_state("networkidle")
    page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight)")
    assert page.evaluate("() => scrollY + innerHeight >= document.documentElement.scrollHeight - 1")
    row = f"sample-row-{long_run_id}-s14"
    top = page.evaluate(TOP, row)
    assert 0 < top < 1000
    expect(page.locator("#validate-panel")).to_contain_text("lane 9")

    # Fix the lane-9 error behind the page's back, then let Check refresh
    # exactly as it does after any change made on the page.
    run = app_ctx.run_repo.get_by_id(long_run_id)
    run.get_sample(f"{long_run_id}-s14").lanes = [1]
    run.touch(updated_by="tester")
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    with page.expect_response(lambda r: r.url.endswith(f"/runs/{long_run_id}/validate-panel")):
        page.evaluate("() => document.body.dispatchEvent(new CustomEvent('htmx:afterRequest',"
                      " {detail: {successful: true, requestConfig: {verb: 'post'}}}))")
    page.wait_for_function(
        "() => !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added')")

    expect(page.locator("#validate-panel")).not_to_contain_text("lane 9")
    assert abs(page.evaluate(TOP, row) - top) <= 1
