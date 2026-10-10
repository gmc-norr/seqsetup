"""Mark Ready is quiet until Check passes, and says why.

It used to be the brightest button on the page even when the run had
errors and Mark Ready could only refuse. It is still clickable (the
refusal lists every error); it just is not the loudest thing on the page
until Check is green.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

_BUTTON = "#run-status-bar button[type=submit]"


def _background(page):
    return page.evaluate(f"() => getComputedStyle(document.querySelector('{_BUTTON}')).backgroundColor")


@pytest.fixture
def clean_run_id(app_ctx):
    """A draft with one indexed sample and a known test: Check passes."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="clean-ready-candidate", run_name="Clean candidate",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    run.add_sample(Sample(
        id="clean-s1", sample_id="CLEAN-01", test_id="WGS", test_version="1", lanes=[1],
        index_pair=IndexPair(
            id="clean-p1", name="UDP0001",
            index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
    ))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.delete(run.id)


@pytest.mark.browser
def test_mark_ready_is_quiet_until_check_passes(logged_in_page, base_url, mutable_run_id, clean_run_id):
    page = logged_in_page

    page.goto(f"{base_url}/runs/{mutable_run_id}")  # has errors
    page.wait_for_load_state("networkidle")
    expect(page.locator(".run-step[data-step=check]")).not_to_have_attribute("data-state", "done")
    quiet = _background(page)
    expect(page.locator(".mark-ready-hint")).to_be_visible()
    expect(page.locator(_BUTTON)).to_be_enabled()

    page.goto(f"{base_url}/runs/{clean_run_id}")
    page.wait_for_load_state("networkidle")
    expect(page.locator(".run-step[data-step=check]")).to_have_attribute("data-state", "done")
    loud = _background(page)
    expect(page.locator(".mark-ready-hint")).to_be_hidden()

    assert quiet != loud, (quiet, loud)
