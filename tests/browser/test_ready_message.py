"""Mark Ready's messages live in #ready-message; save failures stay in
#error-banner (spec 2026-09-27 run checks 1b, Astra's review points 1 and 3)."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


# See CLEAN_PAIR in tests/integration/test_run_checks_1b.py: i5 GGGGGGGG is
# read as CCCCCCCC on NovaSeq X, so this pair has no error of any kind.
CLEAN = ("CCCCCCCC", "GGGGGGGG")


def _seed(app_ctx, run_id, i7, i5, test_id="WGS", indexed=True):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
                        created_at=t, updated_at=t)
    pair = IndexPair(id=f"{run_id}-p", name="p",
                     index1=Index(name="i7", sequence=i7, index_type=IndexType.I7),
                     index2=Index(name="i5", sequence=i5, index_type=IndexType.I5)) if indexed else None
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="RM-01", test_id=test_id, index_pair=pair,
                          lanes=[1]))
    app_ctx.run_repo.save(run)
    return run_id


@pytest.fixture
def cleanup(app_ctx):
    ids = []
    yield ids
    for run_id in ids:
        app_ctx.run_repo.delete(run_id)


@pytest.mark.browser
def test_save_failure_survives_mark_ready(logged_in_page, base_url, app_ctx, cleanup):
    """A refused edit leaves the old value stored; Mark Ready can succeed
    on it, and the failure message must still be on screen afterwards."""
    run_id = _seed(app_ctx, "ready-msg-survive", *CLEAN)
    cleanup.append(run_id)
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    box = page.locator('td.override-cell input[name="override_cycles"]').first
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == 400):
        box.fill("Y*Q;I8;I8;Y*")
        box.dispatch_event("change")
    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")

    page.get_by_role("button", name="Mark Ready").click()
    expect(page.locator("#run-status-bar .status-ready")).to_be_visible()

    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")


@pytest.mark.browser
def test_refusal_does_not_replace_a_save_failure(logged_in_page, base_url, app_ctx, cleanup):
    run_id = _seed(app_ctx, "ready-msg-refused", *CLEAN, test_id="")
    cleanup.append(run_id)
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    box = page.locator('td.override-cell input[name="override_cycles"]').first
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == 400):
        box.fill("Y*Q;I8;I8;Y*")
        box.dispatch_event("change")

    page.get_by_role("button", name="Mark Ready").click()

    expect(page.locator("#ready-message .ready-refused")).to_contain_text("Cannot mark ready")
    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")


@pytest.mark.browser
def test_question_survives_a_retry_after_a_failure(logged_in_page, base_url, app_ctx, cleanup):
    """Astra's point 1: after Mark Ready failed (here a 500), the retry's
    question must stay on screen and its button must work."""
    run_id = _seed(app_ctx, "ready-msg-retry", "ATTACTCG", "TATAGCCT")
    cleanup.append(run_id)
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.route(f"**/runs/{run_id}/status/ready",
               lambda route: route.fulfill(status=500, body="Failed to generate exports",
                                           content_type="text/plain"),
               times=1)
    page.get_by_role("button", name="Mark Ready").click()
    expect(page.locator("#error-banner")).to_contain_text("Failed to generate exports")

    with page.expect_response(lambda r: r.url.endswith("/status/ready") and r.status == 200):
        page.get_by_role("button", name="Mark Ready").click()
    page.wait_for_load_state("networkidle")

    question = page.locator("#ready-message .ready-confirm")
    expect(question).to_be_visible()
    question.get_by_role("button", name="Mark Ready anyway").click()
    expect(page.locator("#run-status-bar .status-ready")).to_be_visible()
    expect(page.locator("#ready-message")).to_be_empty()
