"""Mark Ready's messages live in #ready-message; save failures stay in
#error-banner (spec 2026-09-27 run checks 1b, Astra's review points 1 and 3)."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock


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
    # Every lane of the 10B, so Mark Ready has no lane without samples to ask about.
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="RM-01", test_id=test_id, index_pair=pair,
                          test_version="1" if test_id else "", lanes=list(range(1, 9))))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    return run_id


@pytest.fixture
def cleanup(app_ctx):
    ids = []
    yield ids
    for run_id in ids:
        app_ctx.run_repo.collection.delete_one({"_id": run_id})


# Mark Ready pre-generates the five export files before it flips the status,
# the validation report's charts included. Playwright's default five seconds
# is therefore a bet on how busy the machine is, and under load these two
# tests lost it. The waits below are on the response, which is the real
# signal, with a limit matched to the work (2026-10-18 batch, step 9).
#
# 30 s, not the two minutes CLAUDE.md gives: that figure is for a LARGE run,
# and these runs hold one sample -- measured at about 6 s under load. Six
# times the measurement is room enough for a busy machine, and a real
# regression still fails in 30 s rather than hanging for two minutes.
MARK_READY_MS = 30_000


def _mark_ready(page):
    """Click Mark Ready and wait for the answer, not for a redraw."""
    with page.expect_response(lambda r: r.url.endswith("/status/ready"),
                              timeout=MARK_READY_MS):
        page.get_by_role("button", name="Mark Ready").click()


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
    # One change, as a person makes: box.fill() fires a change of its own, so
    # with dispatch_event the same refused value was saved twice, the second
    # queued behind the first (hx-sync "closest tr"), and still waiting when
    # Mark Ready was clicked -- which now gives Mark Ready up, because a
    # change was not stored (static/js/app.js, fresh review of b425b0b P1-1).
    # What this test is about is the message slots.
    box.click()
    page.keyboard.press("Control+A")
    page.keyboard.type("Y*Q;I8;I8;Y*")
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == 400):
        page.keyboard.press("Tab")
    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")

    _mark_ready(page)
    expect(page.locator("#run-status-bar .status-ready")).to_be_visible(
        timeout=MARK_READY_MS)

    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")


@pytest.mark.browser
def test_refusal_does_not_replace_a_save_failure(logged_in_page, base_url, app_ctx, cleanup):
    run_id = _seed(app_ctx, "ready-msg-refused", *CLEAN, test_id="")
    cleanup.append(run_id)
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    box = page.locator('td.override-cell input[name="override_cycles"]').first
    # One change, as a person makes: box.fill() fires a change of its own, so
    # with dispatch_event the same refused value was saved twice, the second
    # queued behind the first (hx-sync "closest tr"), and still waiting when
    # Mark Ready was clicked -- which now gives Mark Ready up, because a
    # change was not stored (static/js/app.js, fresh review of b425b0b P1-1).
    # What this test is about is the message slots.
    box.click()
    page.keyboard.press("Control+A")
    page.keyboard.type("Y*Q;I8;I8;Y*")
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == 400):
        page.keyboard.press("Tab")
    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")

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

    with page.expect_response(lambda r: r.url.endswith("/status/ready") and r.status == 200,
                              timeout=MARK_READY_MS):
        page.get_by_role("button", name="Mark Ready").click()
    page.wait_for_load_state("networkidle")

    question = page.locator("#ready-message .ready-confirm")
    expect(question).to_be_visible()
    with page.expect_response(lambda r: r.url.endswith("/status/ready"),
                              timeout=MARK_READY_MS):
        question.get_by_role("button", name="Mark Ready anyway").click()
    expect(page.locator("#run-status-bar .status-ready")).to_be_visible(
        timeout=MARK_READY_MS)
    expect(page.locator("#ready-message")).to_be_empty()
