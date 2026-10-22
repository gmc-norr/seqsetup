"""Back, and a reload, show the run page as it is stored.

A browser puts back what was typed in a form, and a page restored from the
back/forward cache comes back whole -- with a value a save was refused for
still in its box, and a row's tick on whichever row is now in that place. A
box showing an Override Cycles the run does not have is a value a person
reads as saved, and a tick on the wrong row aims the bulk panel at the wrong
sample (review EDITING-3). The row inputs and the tick boxes carry
``autocomplete="off"``, and ``app.js`` reloads a page restored from the cache.
"""

from datetime import datetime

import pytest

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import SCREENSHOT_KIT_NAME, hold_edit_lock

BOX_RUN = "back-shows-box"
TICK_RUN = "back-shows-ticks"
BOX = f"#override-cycles-{BOX_RUN}-s1"
REFUSED = "Y150;I8;I8;Y151"  # does not fit 151/8/8/151: the route refuses it


def _run(run_id: str) -> SequencingRun:
    t = datetime(2026, 1, 10, 9, 0, 0)
    return SequencingRun(
        id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t)


@pytest.fixture
def box_run(app_ctx):
    run = _run(BOX_RUN)
    run.add_sample(Sample(id=f"{BOX_RUN}-s1", sample_id="RB-01", lanes=[1], index_pair=IndexPair(
        id="sck-p1", name="UDP0001",
        index1=Index(name="i7-01", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="i5-01", sequence="TATAGCCT", index_type=IndexType.I5)),
        index_kit_name=SCREENSHOT_KIT_NAME))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, BOX_RUN)
    yield BOX_RUN
    app_ctx.run_repo.collection.delete_one({"_id": BOX_RUN})


@pytest.fixture
def tick_run(app_ctx):
    run = _run(TICK_RUN)
    for n in (1, 2, 3):
        run.add_sample(Sample(id=f"{TICK_RUN}-s{n}", sample_id=f"RT-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, TICK_RUN)
    yield TICK_RUN
    app_ctx.run_repo.collection.delete_one({"_id": TICK_RUN})


def _stored_override(app_ctx) -> str:
    return app_ctx.run_repo.get_by_id(BOX_RUN).samples[0].override_cycles or ""


def _type_a_refused_override(page, base_url):
    page.goto(f"{base_url}/runs/{BOX_RUN}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: r.url.endswith("/settings")):
        page.fill(BOX, REFUSED)
        page.locator(BOX).press("Tab")
    page.wait_for_timeout(300)


def _ticked(page):
    return page.evaluate(
        "[...document.querySelectorAll('.sample-checkbox')].filter(c => c.checked)"
        ".map(c => c.dataset.sampleId)")


@pytest.mark.browser
class TestARowBoxShowsTheStoredValue:

    def test_after_a_refused_save_and_a_reload(self, logged_in_page, base_url, app_ctx, box_run):
        page = logged_in_page
        _type_a_refused_override(page, base_url)

        page.reload()
        page.wait_for_load_state("networkidle")

        assert _stored_override(app_ctx) == ""
        assert page.locator(BOX).input_value() == ""

    def test_after_back(self, logged_in_page, base_url, app_ctx, box_run):
        page = logged_in_page
        _type_a_refused_override(page, base_url)
        page.goto(f"{base_url}/runs/{BOX_RUN}/validation")
        page.wait_for_load_state("networkidle")

        page.go_back()
        page.wait_for_load_state("networkidle")

        assert _stored_override(app_ctx) == ""
        assert page.locator(BOX).input_value() == ""


@pytest.mark.browser
class TestAPageGivenBackFromTheCache:
    """A headless browser may never use its back/forward cache, so the Back
    tests above do not reach the ``pageshow`` listener. These two drive it
    directly: the run page asks to be fetched again, and a page that does not
    ask is left alone (a page rendered as the answer to a POST would ask the
    browser to send that POST again)."""

    def test_the_run_page_is_fetched_again(self, logged_in_page, base_url, box_run):
        page = logged_in_page
        page.goto(f"{base_url}/runs/{BOX_RUN}")
        page.wait_for_load_state("networkidle")
        page.evaluate("window.__sameDocument = true")

        with page.expect_navigation():
            page.evaluate(
                "window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))")

        page.wait_for_load_state("networkidle")
        assert page.evaluate("window.__sameDocument || null") is None

    def test_a_page_that_does_not_ask_is_left_alone(self, logged_in_page, base_url, box_run):
        page = logged_in_page
        page.goto(f"{base_url}/runs/{BOX_RUN}/validation")
        page.wait_for_load_state("networkidle")
        page.evaluate("window.__sameDocument = true")

        page.evaluate(
            "window.dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}))")
        page.wait_for_timeout(500)

        assert page.evaluate("window.__sameDocument || null") is True


@pytest.mark.browser
class TestNoTickComesBackOnAnotherRow:

    def test_after_back_with_the_list_changed(self, logged_in_page, base_url, app_ctx, tick_run):
        page = logged_in_page
        page.goto(f"{base_url}/runs/{TICK_RUN}")
        page.wait_for_load_state("networkidle")
        page.locator(f"#sample-row-{TICK_RUN}-s2 .sample-checkbox").check()
        assert _ticked(page) == [f"{TICK_RUN}-s2"]
        page.goto(f"{base_url}/runs/{TICK_RUN}/validation")
        page.wait_for_load_state("networkidle")
        # Meanwhile, in another tab of the same person, the first sample goes.
        run = app_ctx.run_repo.get_by_id(TICK_RUN)
        run.remove_sample(f"{TICK_RUN}-s1")
        app_ctx.run_repo.save(run)

        page.go_back()
        page.wait_for_load_state("networkidle")

        ticked = _ticked(page)
        assert ticked == [], f"a tick came back after Back: {ticked}"
        assert page.locator("#selected-sample-count").inner_text() == "0"
        assert not page.evaluate(
            "document.getElementById('bulk-action-panel').classList.contains('has-selection')")
