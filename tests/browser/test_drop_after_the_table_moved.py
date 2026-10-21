"""A drop on a row that moved while the index was being dragged is refused.

Holding the message slots (test_drop_while_a_message_changes.py) keeps one
cause of a moving table away, but any answer that lands mid-drag and redraws
the samples can move them under the pointer: the bulk panel folds when an
Apply answer unticks the rows, a multi-index drop's answer fills ten rows
that are each about 5 px shorter, and the index panel above the table gains
its hint paragraph on the first section redraw. The index then went to a
sample one to three rows away from the one aimed at, every index still
unique, so no check could see it (review of fix/review-p1, 2026-10-21). The
page now notes where each row is when a drag starts and refuses a drop on a
row that is no longer there; the person drops again.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

RUN_ID = "drop-after-move"
KIT = "Drop-After-Move-Kit"
MOVED = "The samples moved while you were dragging, so no index was given. Drop it again."


def _sequence(prefix, k):
    bases = ""
    for _ in range(6):
        bases += "ACGT"[k % 4]
        k //= 4
    return prefix + bases


I7 = [_sequence("AC", k) for k in range(20)]
I5 = [_sequence("GT", k) for k in range(20)]


@pytest.fixture
def kit(app_ctx):
    from seqsetup.services.validation import clear_validation_cache
    kit = IndexKit(
        name=KIT, version="1.0", index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[
            IndexPair(id=f"{KIT}_P{k:02d}", name=f"P{k:02d}",
                      index1=Index(name=f"P{k:02d}", sequence=I7[k], index_type=IndexType.I7),
                      index2=Index(name=f"P{k:02d}", sequence=I5[k], index_type=IndexType.I5))
            for k in range(20)
        ],
    )
    app_ctx.index_kit_repo.save(kit)
    clear_validation_cache()
    yield kit
    app_ctx.index_kit_repo.delete(kit.name, kit.version)
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx, kit):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Drop after the table moved",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in range(1, 25):
        run.add_sample(Sample(id=f"{RUN_ID}-s{n}", sample_id=f"MV-{n:02d}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _open(page, base_url, width):
    page.set_viewport_size({"width": width, "height": 1800})
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", f"{KIT}:1.0")
    page.wait_for_function(
        "() => !document.querySelector('.htmx-request, .htmx-swapping, .htmx-settling, .htmx-added')")


def _zone(page, n):
    return page.locator(f"#sample-row-{RUN_ID}-s{n} .drop-zone.i7-drop")


def _chip(page, k):
    return page.locator(f'#index-list-container [data-index-pair-id="{KIT}_P{k:02d}"]')


def _row_y(page, n):
    return page.locator(f"#sample-row-{RUN_ID}-s{n}").bounding_box()["y"]


def _held(page, pattern):
    """Hold every answer to `pattern` until the test lets it go."""
    held = []
    page.route(pattern, lambda route: held.append(route))
    return held


def _wait_until_held(page, held):
    for _ in range(50):
        if held:
            return
        page.wait_for_timeout(100)


def _start_drag_onto(page, k, n, edge):
    """Pointer down on chip k and moved into sample n's i7 drop box, near
    its top or its bottom edge; returns that point."""
    chip = _chip(page, k).bounding_box()
    page.mouse.move(chip["x"] + chip["width"] / 2, chip["y"] + chip["height"] / 2)
    page.mouse.down()
    zone = _zone(page, n).bounding_box()
    y = zone["y"] + 4 if edge == "top" else zone["y"] + zone["height"] - 4
    point = (zone["x"] + zone["width"] / 2, y)
    page.mouse.move(*point, steps=10)
    return point


def _let_go_after(page, held, pattern, url_part, point, n):
    """Let the held answer land mid-drag, see the aimed row move, then drop
    where the pointer is."""
    before = _row_y(page, n)
    with page.expect_response(lambda r: url_part in r.url):
        held[0].continue_()
    page.unroute(pattern)
    page.wait_for_timeout(500)
    assert _row_y(page, n) != before, "the table did not move: the test proves nothing"
    assigns = []
    page.on("request", lambda r: assigns.append(r.url) if "/assign-index" in r.url else None)
    x, y = point
    page.mouse.move(x, y + 1)
    page.mouse.up()
    page.wait_for_timeout(1000)
    return assigns


def _given(app_ctx, sequence):
    return [s.sample_id for s in app_ctx.run_repo.get_by_id(RUN_ID).samples
            if s.index1_sequence == sequence]


@pytest.mark.browser
@pytest.mark.parametrize("width", [1600, 1280])
def test_the_bulk_panel_folding_mid_drag_refuses_the_drop(
        logged_in_page, base_url, app_ctx, run_id, width):
    page = logged_in_page
    _open(page, base_url, width)
    for n in (1, 2, 3):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()
    page.locator("#bulk-mismatch-i7-input").fill("0")
    page.locator("#bulk-mismatch-i5-input").fill("0")
    pattern = "**/samples/set-mismatches"
    held = _held(page, pattern)
    page.locator('[data-action="bulk-apply-mismatches"]').click()
    _wait_until_held(page, held)
    assert len(held) == 1

    point = _start_drag_onto(page, 0, 8, "top")
    assigns = _let_go_after(page, held, pattern, "set-mismatches", point, 8)

    assert assigns == []
    assert _given(app_ctx, I7[0]) == []
    expect(page.locator("#error-banner")).to_have_text(MOVED)


@pytest.mark.browser
def test_a_multi_drop_answer_mid_drag_refuses_the_drop(logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open(page, base_url, 1600)
    _chip(page, 0).click()
    _chip(page, 9).click(modifiers=["Shift"])
    pattern = "**/samples/assign-indexes-bulk"
    held = _held(page, pattern)
    _chip(page, 0).drag_to(_zone(page, 1))
    _wait_until_held(page, held)
    assert len(held) == 1

    point = _start_drag_onto(page, 10, 11, "top")
    assigns = _let_go_after(page, held, pattern, "assign-indexes-bulk", point, 11)

    assert assigns == []
    assert _given(app_ctx, I7[10]) == []
    assert _given(app_ctx, I7[9]) == ["MV-10"]           # the held drop itself landed
    expect(page.locator("#error-banner")).to_have_text(MOVED)
    # The redraw took the dragged chip away, so no dragend came: the drop
    # itself let the message slots go, and the refusal shows.
    expect(page.locator("#message-slots")).to_have_attribute("style", "")


@pytest.mark.browser
def test_the_index_panel_growing_above_the_table_refuses_the_drop(
        logged_in_page, base_url, app_ctx, run_id):
    """At 1280 px the index panel sits above the table, and the first
    section redraw draws it with its hint paragraph: the table moves down."""
    page = logged_in_page
    _open(page, base_url, 1280)
    _chip(page, 0).click()
    _chip(page, 1).click(modifiers=["Shift"])
    pattern = "**/samples/assign-indexes-bulk"
    held = _held(page, pattern)
    _chip(page, 0).drag_to(_zone(page, 5))
    _wait_until_held(page, held)
    assert len(held) == 1

    point = _start_drag_onto(page, 2, 2, "bottom")
    assigns = _let_go_after(page, held, pattern, "assign-indexes-bulk", point, 2)

    assert assigns == []
    assert _given(app_ctx, I7[2]) == []
    expect(page.locator("#error-banner")).to_have_text(MOVED)
    expect(page.locator("#message-slots")).to_have_attribute("style", "")


@pytest.mark.browser
def test_a_drop_on_a_table_that_did_not_move_still_lands(logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open(page, base_url, 1280)
    with page.expect_response(lambda r: "/assign-index" in r.url) as answer:
        _chip(page, 3).drag_to(_zone(page, 4))
    assert answer.value.status == 200
    assert _given(app_ctx, I7[3]) == ["MV-04"]
    expect(page.locator("#error-banner")).to_be_empty()


@pytest.mark.browser
def test_a_redraw_that_moves_nothing_does_not_refuse_the_drop(logged_in_page, base_url, app_ctx, run_id):
    """An answer that redraws the section mid-drag but leaves every row where
    it was (the panel beside the table, one row filled below the aimed one)
    is no reason to refuse."""
    page = logged_in_page
    _open(page, base_url, 1600)
    pattern = "**/samples/*/assign-index"
    held = _held(page, pattern)
    _chip(page, 0).drag_to(_zone(page, 20))
    _wait_until_held(page, held)
    assert len(held) == 1

    point = _start_drag_onto(page, 1, 3, "top")
    before = _row_y(page, 3)
    with page.expect_response(lambda r: "/assign-index" in r.url and "-s20/" in r.url):
        held[0].continue_()
    page.unroute(pattern)
    page.wait_for_timeout(500)
    assert _row_y(page, 3) == before
    with page.expect_response(lambda r: "/assign-index" in r.url and "-s3/" in r.url) as answer:
        x, y = point
        page.mouse.move(x, y + 1)
        page.mouse.up()
    assert answer.value.status == 200
    assert _given(app_ctx, I7[1]) == ["MV-03"]


_SCRIPT_DROP = """([chipSel, zoneSel, pad]) => {
    const chip = document.querySelector(chipSel);
    const dt = new DataTransfer();
    chip.dispatchEvent(new DragEvent('dragstart', {dataTransfer: dt, bubbles: true}));
    if (pad) {
        const block = document.createElement('div');
        block.style.height = `${pad}px`;
        document.getElementById('sample-table').before(block);
    }
    const zone = document.querySelector(zoneSel);
    zone.dispatchEvent(new DragEvent('dragover', {dataTransfer: dt, bubbles: true, cancelable: true}));
    zone.dispatchEvent(new DragEvent('drop', {dataTransfer: dt, bubbles: true, cancelable: true}));
}"""


@pytest.mark.browser
def test_a_drop_made_in_script_after_its_row_moved_is_refused(logged_in_page, base_url, app_ctx, run_id):
    """A drop made in script carries no pointer position, so the spot check
    cannot run: its row must not have moved at all. 20 px is less than a
    row, which the spot check would let through."""
    page = logged_in_page
    _open(page, base_url, 1280)
    assigns = []
    page.on("request", lambda r: assigns.append(r.url) if "/assign-index" in r.url else None)
    page.evaluate(_SCRIPT_DROP, [f'#index-list-container [data-index-pair-id="{KIT}_P04"]',
                                 f"#sample-row-{RUN_ID}-s5 .drop-zone.i7-drop", 20])
    expect(page.locator("#error-banner")).to_have_text(MOVED)
    page.wait_for_timeout(500)
    assert assigns == []
    assert _given(app_ctx, I7[4]) == []


@pytest.mark.browser
def test_a_drop_made_in_script_on_a_row_that_stayed_lands(logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open(page, base_url, 1280)
    with page.expect_response(lambda r: "/assign-index" in r.url) as answer:
        page.evaluate(_SCRIPT_DROP, [f'#index-list-container [data-index-pair-id="{KIT}_P04"]',
                                     f"#sample-row-{RUN_ID}-s5 .drop-zone.i7-drop", 0])
    assert answer.value.status == 200
    assert _given(app_ctx, I7[4]) == ["MV-05"]
