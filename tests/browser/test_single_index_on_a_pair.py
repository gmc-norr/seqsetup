"""A single i7 or i5 put on a sample whose index came as a pair.

A unique-dual kit may give a pair with an i7 and no i5. Such a sample shows
an empty i5 cell, but a single i5 dropped there makes the server drop the
whole pair (`Sample.assign_index2`), so the sample lost its i7 with no
question, also through ticked rows and a drop of several (second review of
fix/review-p1, 2026-10-22). That is a replace like any other: refused while
"Edit indexes" is off, asked about by name while it is on.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock
from .test_edit_indexes import _drag, _pick_kit, _wait_for_dialog, _watch

RUN = "single-on-pair"
PAIRS = "Single-On-Pair-Pairs"
SINGLES = "Single-On-Pair-Singles"
PAIR_I7 = "ACACACAC"
I5S = ["CCAATTGG", "GGCCTTAA"]


def _save(app_ctx, kit):
    from seqsetup.services.validation import clear_validation_cache
    app_ctx.index_kit_repo.save(kit)
    clear_validation_cache()


@pytest.fixture
def kits(app_ctx):
    """A unique-dual kit whose one pair has no i5, and a combinatorial kit
    with one i7 and two i5s."""
    from seqsetup.services.validation import clear_validation_cache
    pairs = IndexKit(name=PAIRS, version="1.0", index_mode=IndexMode.UNIQUE_DUAL,
                     index_pairs=[IndexPair(id=f"{PAIRS}_S1", name="S1",
                                            index1=Index(name="S1", sequence=PAIR_I7,
                                                         index_type=IndexType.I7))])
    singles = IndexKit(name=SINGLES, version="1.0", index_mode=IndexMode.COMBINATORIAL,
                       i7_indexes=[Index(name="X7", sequence="TTTTGGGG", index_type=IndexType.I7)],
                       i5_indexes=[Index(name=f"X5{n}", sequence=s, index_type=IndexType.I5)
                                   for n, s in enumerate(I5S)])
    _save(app_ctx, pairs)
    _save(app_ctx, singles)
    yield pairs, singles
    for kit in (pairs, singles):
        app_ctx.index_kit_repo.delete(kit.name, kit.version)
    clear_validation_cache()


@pytest.fixture
def run_id(app_ctx, kits):
    """PA-01 has the i7-only pair; PA-02 and PA-03 have nothing; three lanes."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN, run_name="Single index on a pair",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    first = Sample(id=f"{RUN}-s1", sample_id="PA-01", lanes=[1])
    first.assign_index(kits[0].index_pairs[0])
    first.index_kit_name = PAIRS
    run.add_sample(first)
    run.add_sample(Sample(id=f"{RUN}-s2", sample_id="PA-02", lanes=[2]))
    run.add_sample(Sample(id=f"{RUN}-s3", sample_id="PA-03", lanes=[3]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN)
    yield RUN
    app_ctx.run_repo.collection.delete_one({"_id": RUN})


BEFORE = {"PA-01": (PAIR_I7, None), "PA-02": (None, None), "PA-03": (None, None)}


def _open(page, base_url, kits, editing=False):
    page.goto(f"{base_url}/runs/{RUN}")
    page.wait_for_load_state("networkidle")
    _pick_kit(page, kits[1])
    if editing:
        page.get_by_role("button", name="Edit indexes").click()


def _i5(page, n=0):
    return page.locator(f'#index-list-container [data-index-id="{SINGLES}_i5_X5{n}"]')


def _i5_zone(page, n):
    return page.locator(f"#sample-row-{RUN}-s{n} .drop-zone.i5-drop")


def _stored(app_ctx):
    run = app_ctx.run_repo.get_by_id(RUN)
    return {s.sample_id: (s.index1_sequence, s.index2_sequence) for s in run.samples}


@pytest.mark.browser
def test_an_i5_on_the_pairs_empty_cell_is_refused_while_not_editing(
        logged_in_page, base_url, app_ctx, kits, run_id):
    page = logged_in_page
    _open(page, base_url, kits)
    seen = _watch(page)

    _drag(page, _i5(page), _i5_zone(page, 1))
    expect(page.locator("#error-banner")).to_have_text(
        "PA-01 has an index pair, and a single i5 replaces the whole pair. "
        "Select Edit indexes to replace it.")

    page.wait_for_timeout(500)
    assert seen["dialogs"] == [] and seen["assigns"] == []
    assert _stored(app_ctx) == BEFORE


@pytest.mark.browser
def test_an_i5_on_the_pairs_empty_cell_is_asked_about_while_editing(
        logged_in_page, base_url, app_ctx, kits, run_id):
    page = logged_in_page
    _open(page, base_url, kits, editing=True)
    seen = _watch(page)

    with page.expect_response(lambda r: "/assign-index" in r.url) as answer:
        _drag(page, _i5(page), _i5_zone(page, 1))

    assert answer.value.status == 200
    assert seen["dialogs"] == ["PA-01 has an index pair (S1). Replace it with the i5 you dropped? "
                               "The sample keeps only the i5."]
    assert _stored(app_ctx) == {**BEFORE, "PA-01": (None, I5S[0])}


@pytest.mark.browser
def test_an_i5_on_ticked_rows_with_the_pair_is_refused_while_not_editing(
        logged_in_page, base_url, app_ctx, kits, run_id):
    page = logged_in_page
    _open(page, base_url, kits)
    page.locator(f"#sample-row-{RUN}-s1 .sample-checkbox").check()
    seen = _watch(page)

    _drag(page, _i5(page), _i5_zone(page, 2))
    expect(page.locator("#error-banner")).to_have_text(
        "PA-01 already has an index. Select Edit indexes to replace it, or untick it.")

    page.wait_for_timeout(500)
    assert seen["dialogs"] == [] and seen["assigns"] == []
    assert _stored(app_ctx) == BEFORE


@pytest.mark.browser
def test_two_i5s_dropped_from_the_pair_name_it_in_their_question(
        logged_in_page, base_url, app_ctx, kits, run_id):
    page = logged_in_page
    _open(page, base_url, kits, editing=True)
    _i5(page, 0).click()
    _i5(page, 1).click(modifiers=["Shift"])
    seen = _watch(page)
    seen["answer"] = False

    _drag(page, _i5(page, 0), _i5_zone(page, 1))
    _wait_for_dialog(page, seen)
    page.wait_for_timeout(500)

    assert seen["dialogs"] == ["This will replace the index on 1 sample(s) that already have one: "
                               "PA-01.\n\nContinue?"]
    assert seen["assigns"] == []
    assert _stored(app_ctx) == BEFORE
