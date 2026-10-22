"""One index dropped while rows are ticked goes to every ticked row, and a
ticked row that already shows an index had it replaced with "Edit indexes"
off. The only question asked ("Give this same index to all N samples ...")
never said so, and with the samples in different lanes no check sees it
(review of fix/review-p1, 2026-10-21). Like a drop on one row, it is now
refused while not editing, naming those samples, and asked about by name
while editing.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock
from .test_edit_indexes import COMBI, I5, I7, KIT, _drag, _pick_kit, _wait_for_dialog, _watch
from .test_edit_indexes import combi_kit, kit  # noqa: F401 (fixtures)

RUN = "ticked-with-index"
OWN_I7 = "GGTTAACC"  # CI7 of the combinatorial kit

REFUSED = ("TK-01 and TK-03 already have an index. Select Edit indexes to replace them, "
           "or untick them.")
ASKED = ("Give this same index to all 3 samples (the ticked ones and the one you dropped on)? "
         "It replaces the index TK-01 and TK-03 already have.\n\n"
         "Samples in the same lane must not share an index.")


@pytest.fixture
def run_id(app_ctx, kit, combi_kit):  # noqa: F811
    """TK-01 has a pair, TK-02 nothing, TK-03 an i7 only; three lanes."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN, run_name="Ticked rows with an index",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    first = Sample(id=f"{RUN}-s1", sample_id="TK-01", lanes=[1])
    first.assign_index(kit.index_pairs[0])
    first.index_kit_name = KIT
    run.add_sample(first)
    run.add_sample(Sample(id=f"{RUN}-s2", sample_id="TK-02", lanes=[2]))
    third = Sample(id=f"{RUN}-s3", sample_id="TK-03", lanes=[3])
    third.assign_index1(combi_kit.i7_indexes[0])
    third.index_kit_name = COMBI
    run.add_sample(third)
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN)
    yield RUN
    app_ctx.run_repo.collection.delete_one({"_id": RUN})


def _open_and_tick(page, base_url, kit, editing):  # noqa: F811
    page.goto(f"{base_url}/runs/{RUN}")
    page.wait_for_load_state("networkidle")
    _pick_kit(page, kit)
    if editing:
        page.get_by_role("button", name="Edit indexes").click()
    for n in (1, 3):
        page.locator(f"#sample-row-{RUN}-s{n} .sample-checkbox").check()


def _drop_pair_on_tk02(page):
    chip = page.locator(f'#index-list-container [data-index-pair-id="{KIT}_EI2"]')
    _drag(page, chip, page.locator(f"#sample-row-{RUN}-s2 .drop-zone.i7-drop"))


def _stored(app_ctx):
    run = app_ctx.run_repo.get_by_id(RUN)
    return {s.sample_id: (s.index1_sequence, s.index2_sequence) for s in run.samples}


BEFORE = {"TK-01": (I7[0], I5[0]), "TK-02": (None, None), "TK-03": (OWN_I7, None)}


@pytest.mark.browser
def test_is_refused_while_not_editing_and_names_them(logged_in_page, base_url, app_ctx, kit,  # noqa: F811
                                                     run_id):
    page = logged_in_page
    _open_and_tick(page, base_url, kit, editing=False)
    seen = _watch(page)

    _drop_pair_on_tk02(page)
    expect(page.locator("#error-banner")).to_have_text(REFUSED)

    page.wait_for_timeout(500)
    assert seen["dialogs"] == [] and seen["assigns"] == []
    assert _stored(app_ctx) == BEFORE


@pytest.mark.browser
def test_while_editing_it_names_them_and_replaces_on_yes(logged_in_page, base_url, app_ctx, kit,  # noqa: F811
                                                         run_id):
    page = logged_in_page
    _open_and_tick(page, base_url, kit, editing=True)
    seen = _watch(page)

    with page.expect_response(lambda r: "/assign-index-to-selected" in r.url) as answer:
        _drop_pair_on_tk02(page)

    assert answer.value.status == 200
    assert seen["dialogs"] == [ASKED]
    assert _stored(app_ctx) == {name: (I7[2], I5[2]) for name in BEFORE}


@pytest.mark.browser
def test_while_editing_no_keeps_every_index(logged_in_page, base_url, app_ctx, kit,  # noqa: F811
                                            run_id):
    page = logged_in_page
    _open_and_tick(page, base_url, kit, editing=True)
    seen = _watch(page)
    seen["answer"] = False

    _drop_pair_on_tk02(page)
    _wait_for_dialog(page, seen)
    page.wait_for_timeout(500)

    assert seen["dialogs"] == [ASKED] and seen["assigns"] == []
    assert _stored(app_ctx) == BEFORE


def _open_with_tk03_ticked(page, base_url, combi_kit):  # noqa: F811
    page.goto(f"{base_url}/runs/{RUN}")
    page.wait_for_load_state("networkidle")
    _pick_kit(page, combi_kit)
    page.locator(f"#sample-row-{RUN}-s3 .sample-checkbox").check()


def _single(page, kind):
    return page.locator(f'#index-list-container [data-index-id="{COMBI}_{kind}_C{kind.upper()}"]')


@pytest.mark.browser
def test_an_i7_is_refused_when_a_ticked_row_shows_an_i7(logged_in_page, base_url, app_ctx,
                                                        combi_kit, run_id):  # noqa: F811
    page = logged_in_page
    _open_with_tk03_ticked(page, base_url, combi_kit)
    seen = _watch(page)

    _drag(page, _single(page, "i7"), page.locator(f"#sample-row-{RUN}-s2 .drop-zone.i7-drop"))
    expect(page.locator("#error-banner")).to_have_text(
        "TK-03 already has an index. Select Edit indexes to replace it, or untick it.")

    page.wait_for_timeout(500)
    assert seen["dialogs"] == [] and seen["assigns"] == []
    assert _stored(app_ctx) == BEFORE


@pytest.mark.browser
def test_an_i5_fills_ticked_rows_that_have_an_i7_and_no_i5(logged_in_page, base_url, app_ctx,
                                                           combi_kit, run_id):  # noqa: F811
    """How a combinatorial kit is used: the i5 replaces nothing, so it is
    asked about as before and given."""
    page = logged_in_page
    _open_with_tk03_ticked(page, base_url, combi_kit)
    seen = _watch(page)

    with page.expect_response(lambda r: "/assign-index-to-selected" in r.url) as answer:
        _drag(page, _single(page, "i5"), page.locator(f"#sample-row-{RUN}-s2 .drop-zone.i5-drop"))

    assert answer.value.status == 200
    assert seen["dialogs"] == [
        "Give this same index to all 2 samples (the ticked ones and the one you dropped on)?\n\n"
        "Samples in the same lane must not share an index."]
    assert _stored(app_ctx) == {**BEFORE, "TK-02": (None, "CCAATTGG"), "TK-03": (OWN_I7, "CCAATTGG")}
