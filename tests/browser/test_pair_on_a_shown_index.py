"""A pair dropped on the empty cell of a sample that already shows an index.

A unique-dual pair fills both cells, so a pair dropped on the empty i5 cell
of a sample that has only an i7 replaced that i7, with no question and with
"Edit indexes" off (project review of 7d970c7, 2026-10-21, EDITING-1). The
guide says a drop on a sample that has an index does nothing unless you are
editing indexes, and that while editing SeqSetup first asks. A single i5
dropped there still fills the i5: that is how a combinatorial kit is used.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock
from .test_edit_indexes import COMBI, I5, I7, KIT, _drag, _pick_kit, _wait_for_dialog, _watch
from .test_edit_indexes import combi_kit, kit  # noqa: F401 (fixtures)

OWN_I7 = "GGTTAACC"  # CI7 of the combinatorial kit


@pytest.fixture
def run_id(app_ctx, combi_kit):  # noqa: F811
    """EI-01 has the combinatorial kit's i7 and no i5; EI-02 has no index."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="pair-on-shown", run_name="Pair on a shown index",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    first = Sample(id=f"{run.id}-s1", sample_id="EI-01", lanes=[1])
    first.assign_index1(combi_kit.i7_indexes[0])
    first.index_kit_name = COMBI
    run.add_sample(first)
    run.add_sample(Sample(id=f"{run.id}-s2", sample_id="EI-02", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


def _open(page, base_url, run_id, kit):  # noqa: F811
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    _pick_kit(page, kit)


def _i5_zone(page, run_id):
    return page.locator(f"#sample-row-{run_id}-s1 .drop-zone.i5-drop")


def _stored(app_ctx, run_id, n):
    sample = app_ctx.run_repo.get_by_id(run_id).get_sample(f"{run_id}-s{n}")
    return sample.index1_sequence, sample.index2_sequence


def _pair(page, n=2):
    return page.locator(f'#index-list-container [data-index-pair-id="{KIT}_EI{n}"]')


REFUSED = ("EI-01 already has an index, and an index pair fills both its i7 and i5. "
           "Select Edit indexes to replace it.")
ASKED = ("EI-01 already has an index (CI7). Replace it with the index pair you dropped? "
         "A pair fills both its i7 and i5.")


@pytest.mark.browser
def test_a_dropped_pair_is_refused_while_not_editing(logged_in_page, base_url, app_ctx, kit,  # noqa: F811
                                                     run_id):
    page = logged_in_page
    _open(page, base_url, run_id, kit)
    seen = _watch(page)

    _drag(page, _pair(page), _i5_zone(page, run_id))
    expect(page.locator("#error-banner")).to_have_text(REFUSED)

    assert seen["dialogs"] == [] and seen["assigns"] == []
    assert _stored(app_ctx, run_id, 1) == (OWN_I7, None)


@pytest.mark.browser
def test_a_pair_assigned_by_keyboard_is_refused_while_not_editing(  # noqa: F811
        logged_in_page, base_url, app_ctx, kit, run_id):
    page = logged_in_page
    _open(page, base_url, run_id, kit)
    seen = _watch(page)

    _pair(page).click()
    _i5_zone(page, run_id).focus()
    _i5_zone(page, run_id).press("Enter")
    expect(page.locator("#error-banner")).to_have_text(REFUSED)

    assert seen["dialogs"] == [] and seen["assigns"] == []
    assert _stored(app_ctx, run_id, 1) == (OWN_I7, None)


@pytest.mark.browser
def test_while_editing_it_asks_and_replaces_on_yes(logged_in_page, base_url, app_ctx, kit,  # noqa: F811
                                                   run_id):
    page = logged_in_page
    _open(page, base_url, run_id, kit)
    page.get_by_role("button", name="Edit indexes").click()
    seen = _watch(page)

    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        _drag(page, _pair(page), _i5_zone(page, run_id))

    assert resp.value.status == 200
    assert seen["dialogs"] == [ASKED]
    assert _stored(app_ctx, run_id, 1) == (I7[2], I5[2])


@pytest.mark.browser
def test_while_editing_saying_no_keeps_the_index(logged_in_page, base_url, app_ctx, kit,  # noqa: F811
                                                 run_id):
    page = logged_in_page
    _open(page, base_url, run_id, kit)
    page.get_by_role("button", name="Edit indexes").click()
    seen = _watch(page)
    seen["answer"] = False

    _drag(page, _pair(page), _i5_zone(page, run_id))
    _wait_for_dialog(page, seen)
    page.wait_for_timeout(500)

    assert seen["dialogs"] == [ASKED] and seen["assigns"] == []
    assert _stored(app_ctx, run_id, 1) == (OWN_I7, None)


@pytest.mark.browser
def test_a_single_i5_still_fills_the_empty_i5_cell(logged_in_page, base_url, app_ctx,
                                                   combi_kit, run_id):  # noqa: F811
    page = logged_in_page
    _open(page, base_url, run_id, combi_kit)
    seen = _watch(page)

    chip = page.locator(f'#index-list-container [data-index-id="{COMBI}_i5_CI5"]')
    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        _drag(page, chip, _i5_zone(page, run_id))

    assert resp.value.status == 200
    assert seen["dialogs"] == []
    assert _stored(app_ctx, run_id, 1) == (OWN_I7, "CCAATTGG")


@pytest.mark.browser
def test_a_pair_on_a_sample_with_no_index_is_not_asked_about(logged_in_page, base_url, app_ctx,
                                                             kit, run_id):  # noqa: F811
    page = logged_in_page
    _open(page, base_url, run_id, kit)
    seen = _watch(page)

    zone = page.locator(f"#sample-row-{run_id}-s2 .drop-zone.i7-drop")
    with page.expect_response(lambda r: "/assign-index" in r.url) as resp:
        _drag(page, _pair(page), zone)

    assert resp.value.status == 200
    assert seen["dialogs"] == []
    assert _stored(app_ctx, run_id, 2) == (I7[2], I5[2])
