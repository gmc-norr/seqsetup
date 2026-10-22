"""A drop lands on the row it was aimed at while a message above the table
comes or goes.

The message slots (#form-errors, #error-banner, #row-setting-notes) sit
above the samples and take no room when empty. A slow answer that cleared
the banner during the next drag moved the table up by more than a row, and
the chip landed on the next sample (project review of 7d970c7, 2026-10-21,
EDITING-4): every index still unique, so no check could see it. While an
index is dragged the slots keep the height they had when the drag began.

A row that gets its index is about 5 px shorter than one showing drop boxes,
less than the 9 px between two rows' boxes, so it cannot move a drop onto
the next sample by itself; the tests check that nothing above the table
moves, and where the drop lands.
"""

import re
from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import SCREENSHOT_KIT_NAME, hold_edit_lock

RUN_ID = "drop-while-message"


@pytest.fixture
def run_id(app_ctx):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Drop while a message changes",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in range(1, 7):
        run.add_sample(Sample(id=f"{RUN_ID}-s{n}", sample_id=f"DM-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _open(page, base_url):
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", f"{SCREENSHOT_KIT_NAME}:1.0")
    page.wait_for_function(
        "() => !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added')")


def _zone(page, n):
    return page.locator(f"#sample-row-{RUN_ID}-s{n} .drop-zone.i7-drop")


def _chip(page, pid):
    return page.locator(f'#index-list-container [data-index-pair-id="{pid}"]')


def _row_y(page, n):
    return page.locator(f"#sample-row-{RUN_ID}-s{n}").bounding_box()["y"]


def _behind_the_page(app_ctx, n):
    """Give sample n an index the page does not show, so a drop on it is
    refused (409: the row changed since the page was loaded)."""
    run = app_ctx.run_repo.get_by_id(RUN_ID)
    run.get_sample(f"{RUN_ID}-s{n}").assign_index1(
        Index(name="x", sequence="GGGGCCCC", index_type=IndexType.I7))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)


def _wait_until_held(page, held):
    for _ in range(50):
        if held:
            return
        page.wait_for_timeout(100)


def _start_drag_onto(page, pid, n):
    """Pointer down on the chip and moved into sample n's drop zone, near its
    top; returns that point."""
    chip = _chip(page, pid).bounding_box()
    page.mouse.move(chip["x"] + chip["width"] / 2, chip["y"] + chip["height"] / 2)
    page.mouse.down()
    zone = _zone(page, n).bounding_box()
    point = (zone["x"] + zone["width"] / 2, zone["y"] + 4)
    page.mouse.move(*point, steps=10)
    return point


def _drop_at(page, point):
    """A resting hand makes the browser fire dragover again; Playwright fires
    it only on a move, so the pointer moves one pixel before it lets go."""
    x, y = point
    page.mouse.move(x, y + 1)
    page.mouse.up()


@pytest.mark.browser
def test_an_answer_that_clears_the_banner_mid_drag_does_not_move_the_drop(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open(page, base_url)
    _behind_the_page(app_ctx, 1)
    with page.expect_response(lambda r: "/assign-index" in r.url) as refused:
        _chip(page, "sck-p1").drag_to(_zone(page, 1))
    assert refused.value.status == 409
    expect(page.locator("#error-banner")).not_to_be_empty()

    held = []
    page.route("**/samples/*/assign-index", lambda route: held.append(route))
    _chip(page, "sck-p2").drag_to(_zone(page, 2))       # succeeds; its answer is held
    _wait_until_held(page, held)
    assert len(held) == 1

    point = _start_drag_onto(page, "sck-p3", 3)
    above = _row_y(page, 1)  # nothing above the table moves
    with page.expect_response(lambda r: "/assign-index" in r.url and "-s2/" in r.url):
        held[0].continue_()                             # clears the banner, mid-drag
    page.unroute("**/samples/*/assign-index")
    page.wait_for_timeout(300)
    assert _row_y(page, 1) == above
    with page.expect_response(lambda r: "/assign-index" in r.url and "-s3/" in r.url):
        _drop_at(page, point)

    stored = {s.sample_id: s.index1_sequence for s in app_ctx.run_repo.get_by_id(RUN_ID).samples}
    assert (stored["DM-03"], stored["DM-04"]) == ("CGCTCATT", None), stored


@pytest.mark.browser
def test_a_message_that_comes_mid_drag_does_not_move_the_drop_either(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open(page, base_url)
    _behind_the_page(app_ctx, 1)
    held = []
    page.route("**/samples/*/assign-index", lambda route: held.append(route))
    _chip(page, "sck-p1").drag_to(_zone(page, 1))       # will be refused; held
    _wait_until_held(page, held)
    assert len(held) == 1
    expect(page.locator("#error-banner")).to_be_empty()

    point = _start_drag_onto(page, "sck-p3", 3)
    above = _row_y(page, 1)  # nothing above the table moves
    with page.expect_response(lambda r: "/assign-index" in r.url and "-s1/" in r.url):
        held[0].continue_()                             # the refusal fills the banner, mid-drag
    page.unroute("**/samples/*/assign-index")
    page.wait_for_timeout(300)
    assert _row_y(page, 1) == above
    with page.expect_response(lambda r: "/assign-index" in r.url and "-s3/" in r.url):
        _drop_at(page, point)

    stored = {s.sample_id: s.index1_sequence for s in app_ctx.run_repo.get_by_id(RUN_ID).samples}
    assert (stored["DM-03"], stored["DM-04"]) == ("CGCTCATT", None), stored
    # Once the drag is over the slots take their own height again.
    expect(page.locator("#message-slots")).to_have_attribute("style", "")


@pytest.mark.browser
def test_a_drag_let_go_off_the_samples_lets_the_slots_and_the_page_go(
        logged_in_page, base_url, app_ctx, run_id):
    """A drag that ends anywhere but on a sample has no drop to let the held
    heights go; its dragend must, or a later message stays out of sight."""
    page = logged_in_page
    _open(page, base_url)
    # Playwright's own drag first: before one, a drag made with the mouse
    # alone starts no drag at all in this browser.
    with page.expect_response(lambda r: "/assign-index" in r.url):
        _chip(page, "sck-p2").drag_to(_zone(page, 2))
    point = _start_drag_onto(page, "sck-p3", 3)
    expect(page.locator("#message-slots")).to_have_attribute("style", re.compile("min-height"))
    expect(page.locator("html")).to_have_attribute("style", re.compile("min-height"))
    page.mouse.move(point[0], 5, steps=10)                       # the top of the window
    page.mouse.up()

    expect(page.locator("#message-slots")).to_have_attribute("style", "")
    expect(page.locator("html")).to_have_attribute("style", "")
    stored = {s.sample_id: s.index1_sequence for s in app_ctx.run_repo.get_by_id(RUN_ID).samples}
    assert [k for k, v in stored.items() if v] == ["DM-02"], stored
