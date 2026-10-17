"""Two tabs: a row's own Override Cycles or mismatch box, saved from the
page loaded first, is refused and says why (design note
docs/design/2026-10-17-stale-page-checks-design.md, step 4).

The queue case -- a correction typed while the first save is on its way,
whose save must name what that first save stored -- is pinned inside F3's
own tests (tests/browser/test_row_save_keeps_typing.py, the post bodies of
TestACorrectionTypedWhileTheBoxSaves).
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

RUN_ID = "stale-box-run"


@pytest.fixture
def run_id(app_ctx):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Stale box run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{RUN_ID}-s{n}", sample_id=f"SB-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _open(page, base_url):
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")


def _the_other_tab(app_ctx, n, **fields):
    run = app_ctx.run_repo.get_by_id(RUN_ID)
    for name, value in fields.items():
        setattr(run.samples[n - 1], name, value)
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)


def _save(page, box_id, value):
    box = page.locator(f"#{box_id}")
    box.fill(value)
    with page.expect_response(lambda r: r.url.endswith("/settings")) as answer:
        box.press("Tab")
    return answer.value


def _row(app_ctx, n=1):
    sample = app_ctx.run_repo.get_by_id(RUN_ID).samples[n - 1]
    return (sample.override_cycles, sample.barcode_mismatches_index1,
            sample.barcode_mismatches_index2)


@pytest.mark.browser
def test_a_mismatch_box_another_tab_changed_is_refused(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open(page, base_url)
    _the_other_tab(app_ctx, 1, barcode_mismatches_index1=2)

    answer = _save(page, f"mismatch-i7-{RUN_ID}-s1", "0")

    assert answer.status == 409
    assert "target_setting=1" in answer.request.post_data, answer.request.post_data
    expect(page.locator("#error-banner")).to_contain_text(
        "The barcode mismatches on these samples changed since this page was loaded")
    expect(page.locator("#error-banner")).to_contain_text("SB-01")
    assert _row(app_ctx) == (None, 2, 1)


@pytest.mark.browser
def test_an_override_cycles_box_another_tab_changed_is_refused(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open(page, base_url)
    _the_other_tab(app_ctx, 1, override_cycles="U8Y143;I8;I8;Y151")

    answer = _save(page, f"override-cycles-{RUN_ID}-s1", "Y151;I8;I8;Y151")

    assert answer.status == 409
    expect(page.locator("#error-banner")).to_contain_text(
        "The Override Cycles on these samples changed since this page was loaded")
    assert _row(app_ctx) == ("U8Y143;I8;I8;Y151", 1, 1)


@pytest.mark.browser
def test_a_fresh_box_still_saves_and_the_next_save_is_not_stale(
        logged_in_page, base_url, app_ctx, run_id):
    """Two saves of the same box, one after the other: the second says what
    the first stored, which the answer put in the box."""
    page = logged_in_page
    _open(page, base_url)

    first = _save(page, f"mismatch-i7-{RUN_ID}-s1", "0")
    assert first.status == 200, first.text()
    assert "target_setting=1" in first.request.post_data, first.request.post_data

    second = _save(page, f"mismatch-i7-{RUN_ID}-s1", "2")
    assert second.status == 200, second.text()
    assert "target_setting=0" in second.request.post_data, second.request.post_data
    assert _row(app_ctx) == (None, 2, 1)


@pytest.mark.browser
def test_a_box_of_another_row_is_not_this_box_business(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open(page, base_url)
    _the_other_tab(app_ctx, 2, barcode_mismatches_index1=2)

    answer = _save(page, f"mismatch-i7-{RUN_ID}-s1", "0")

    assert answer.status == 200, answer.text()
    assert _row(app_ctx, 1) == (None, 0, 1)
    assert _row(app_ctx, 2) == (None, 2, 1)
