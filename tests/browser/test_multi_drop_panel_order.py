"""Several chips dragged at once go to the rows in the order the panel shows
them, however they were clicked (index mix-up audit, 2026-10-14; the user's
choice "Panel order").

Clicking the last chip first and shift-clicking the first one used to send
the chips in click order, so the first row got the last chip's index. The
kit here is stored out of name order (PO2, PO0, PO1), so the panel's order
is neither the click order nor the names' order (review of 2471610, P3-1).
"""

import json
from datetime import datetime
from urllib.parse import parse_qs

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

KIT = "Panel-Order-Kit"
SHOWN = ["PO2", "PO0", "PO1"]  # the panel's order: the kit's stored order
I7 = ["AACCGGTT", "CCGGTTAA", "GGTTAACC"]  # of SHOWN[0], SHOWN[1], SHOWN[2]
I5 = ["TGTGCACA", "GTGTACAC", "CACAGTGT"]


@pytest.fixture
def kit(app_ctx):
    """A three-pair kit stored as PO2, PO0, PO1; deleted afterwards."""
    from seqsetup.services.validation import clear_validation_cache

    kit = IndexKit(name=KIT, version="1.0", index_mode=IndexMode.UNIQUE_DUAL, index_pairs=[
        IndexPair(id=f"{KIT}_{name}", name=name,
                  index1=Index(name=name, sequence=I7[k], index_type=IndexType.I7),
                  index2=Index(name=name, sequence=I5[k], index_type=IndexType.I5))
        for k, name in enumerate(SHOWN)])
    app_ctx.index_kit_repo.save(kit)
    clear_validation_cache()
    yield kit
    app_ctx.index_kit_repo.delete(kit.name, kit.version)
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx):
    """A draft with three un-indexed samples; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="panel-order-run", run_name="Panel order run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2, 3):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"PO-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


def _open_on_kit(page, base_url, run_id, kit_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", kit_id)
    expect(page.locator("#index-list-container")).to_contain_text("PO0")


def _chip(page, k):
    """The chip the panel shows k-th."""
    return page.locator(f'#index-list-container [data-index-pair-id="{KIT}_{SHOWN[k]}"]')


def _zone(page, run_id, n):
    return page.locator(f"#sample-row-{run_id}-s{n} .drop-zone").first


def _drag_and_read(page, run_id, chip):
    """Drag `chip` onto the first row; return the ids the page sent, in order."""
    with page.expect_request(lambda r: "assign-indexes-bulk" in r.url) as req:
        with page.expect_response(lambda r: "assign-indexes-bulk" in r.url) as resp:
            _chip(page, chip).drag_to(_zone(page, run_id, 1))
    assert resp.value.status == 200
    sent = json.loads(parse_qs(req.value.post_data)["indexes_json"][0])
    return [entry["id"] for entry in sent]


def _stored_i7s(app_ctx, run_id):
    return [s.index1_sequence for s in app_ctx.run_repo.get_by_id(run_id).samples]


@pytest.mark.browser
def test_a_shift_click_made_backwards_fills_in_panel_order(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open_on_kit(page, base_url, run_id, kit.kit_id)

    _chip(page, 2).click()
    _chip(page, 0).click(modifiers=["Shift"])
    sent = _drag_and_read(page, run_id, 0)

    assert sent == [f"{KIT}_{name}" for name in SHOWN]
    assert _stored_i7s(app_ctx, run_id) == I7


@pytest.mark.browser
def test_chips_ctrl_clicked_out_of_order_fill_in_panel_order(
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open_on_kit(page, base_url, run_id, kit.kit_id)

    _chip(page, 1).click()
    _chip(page, 0).click(modifiers=["Control"])
    sent = _drag_and_read(page, run_id, 1)

    assert sent == [f"{KIT}_{SHOWN[0]}", f"{KIT}_{SHOWN[1]}"]
    assert _stored_i7s(app_ctx, run_id) == [I7[0], I7[1], None]


@pytest.mark.browser
def test_enter_with_several_selected_assigns_the_panels_first(
        logged_in_page, base_url, app_ctx, kit, run_id):
    """The keyboard assigns one index: the panel's first selected one, not
    the first one clicked (review of 2471610, P3-2)."""
    page = logged_in_page
    _open_on_kit(page, base_url, run_id, kit.kit_id)

    _chip(page, 2).click()
    _chip(page, 0).click(modifiers=["Shift"])
    zone = _zone(page, run_id, 1)
    zone.focus()
    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        zone.press("Enter")

    assert resp.value.status == 200
    assert _stored_i7s(app_ctx, run_id) == [I7[0], None, None]
