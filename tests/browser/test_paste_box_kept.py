"""A bulk action does not wipe what is typed in the paste box.

The bulk panel's four Apply forms (lanes, mismatches, override cycles, test)
swapped ``#sample-section`` outerHTML, and ``#sample-section`` holds the
paste box: its ``<details>`` fold, its textarea, its lane tick boxes and its
test picker. So anything typed or picked there -- a worklist a person had
just pasted and not yet added -- was thrown away the moment they set lanes on
a few ticked rows.

The forms now target the ``#sample-table`` *inside* the returned section and
pull it out with ``hx-select``, so the paste box is left alone. Targeting
``#sample-table`` without ``hx-select`` is the bug
``test_bulk_lane_panel_swap.py`` exists for -- the whole section was swapped
in where the table was, nesting a second one inside the first -- so these
tests check both: the paste box survives, and there is still exactly one
``#sample-section`` and one ``#sample-table``.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)

from .conftest import hold_edit_lock

TYPED = "PASTED-01\tWGS\nPASTED-02\tWGS\n"


@pytest.fixture
def paste_box_run_id(app_ctx):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="paste-box-run", run_name="Paste box run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"KEEP-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, run.id)
    yield run.id
    app_ctx.run_repo.collection.delete_one({"_id": run.id})


def _open_with_typed_paste(page, base_url, run_id):
    """Open the run, open the paste fold, type a worklist, pick lane 2 for it,
    and tick both sample rows."""
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.locator(".paste-section-summary").click()
    page.locator("#paste_data").fill(TYPED)
    page.locator('.paste-lane input[value="2"]').check()
    page.locator(f"#sample-row-{run_id}-s1 .sample-checkbox").check()
    page.locator(f"#sample-row-{run_id}-s2 .sample-checkbox").check()


def _assert_paste_box_survived(page):
    expect(page.locator("#paste_data")).to_have_value(TYPED)
    expect(page.locator('.paste-lane input[value="2"]')).to_be_checked()
    assert page.locator(".paste-section[open]").count() == 1


def _assert_one_section(page):
    assert page.locator("#sample-section").count() == 1
    assert page.locator("#sample-table #sample-section").count() == 0
    assert page.locator("#sample-table").count() == 1


def _apply(page, action, url_end):
    with page.expect_response(lambda r: r.url.endswith(url_end)) as got:
        page.locator(f'[data-action="{action}"]').click()
    assert got.value.status == 200, got.value.status
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(300)


@pytest.mark.browser
def test_applying_lanes_keeps_the_paste_box(logged_in_page, base_url, paste_box_run_id,
                                            app_ctx):
    page = logged_in_page
    _open_with_typed_paste(page, base_url, paste_box_run_id)

    page.locator('.bulk-lane-checkbox[value="2"]').check()
    _apply(page, "bulk-apply-lanes", "/samples/set-lanes")

    _assert_paste_box_survived(page)
    _assert_one_section(page)
    run = app_ctx.run_repo.get_by_id(paste_box_run_id)
    assert [s.lanes for s in run.samples] == [[2], [2]]


@pytest.mark.browser
def test_applying_mismatches_keeps_the_paste_box(logged_in_page, base_url,
                                                 paste_box_run_id, app_ctx):
    page = logged_in_page
    _open_with_typed_paste(page, base_url, paste_box_run_id)

    page.locator("#bulk-mismatch-i7-input").fill("2")
    _apply(page, "bulk-apply-mismatches", "/samples/set-mismatches")

    _assert_paste_box_survived(page)
    _assert_one_section(page)
    run = app_ctx.run_repo.get_by_id(paste_box_run_id)
    assert [s.barcode_mismatches_index1 for s in run.samples] == [2, 2]


@pytest.mark.browser
def test_applying_override_cycles_keeps_the_paste_box(logged_in_page, base_url,
                                                      paste_box_run_id, app_ctx):
    page = logged_in_page
    _open_with_typed_paste(page, base_url, paste_box_run_id)

    page.locator("#bulk-override-cycles-input").fill("Y151;I8;I8;Y151")
    _apply(page, "bulk-apply-override", "/samples/set-override-cycles")

    _assert_paste_box_survived(page)
    _assert_one_section(page)
    run = app_ctx.run_repo.get_by_id(paste_box_run_id)
    assert [s.override_cycles for s in run.samples] == ["Y151;I8;I8;Y151"] * 2


@pytest.mark.browser
def test_applying_a_test_keeps_the_paste_box(logged_in_page, base_url, paste_box_run_id,
                                             app_ctx):
    page = logged_in_page
    _open_with_typed_paste(page, base_url, paste_box_run_id)

    page.select_option("#bulk-test-id-input", value="WGS")
    page.locator("#bulk-test-version-input").fill("1")
    _apply(page, "bulk-apply-testid", "/samples/set-test-id")

    _assert_paste_box_survived(page)
    _assert_one_section(page)
    run = app_ctx.run_repo.get_by_id(paste_box_run_id)
    assert [s.test_id for s in run.samples] == ["WGS", "WGS"]


@pytest.mark.browser
def test_the_table_still_shows_what_was_applied(logged_in_page, base_url,
                                                paste_box_run_id):
    """The narrower swap must still redraw the table: the lanes a person just
    applied have to be on the screen without a reload."""
    page = logged_in_page
    _open_with_typed_paste(page, base_url, paste_box_run_id)

    page.locator('.bulk-lane-checkbox[value="3"]').check()
    _apply(page, "bulk-apply-lanes", "/samples/set-lanes")

    for n in (1, 2):
        expect(page.locator(
            f"#sample-row-{paste_box_run_id}-s{n} .lanes-display")).to_have_text("3")


@pytest.mark.browser
def test_adding_the_pasted_samples_still_clears_the_box(logged_in_page, base_url,
                                                        paste_box_run_id, app_ctx):
    """The paste's own Add swaps the whole section on purpose, so the box must
    come back empty -- the narrower bulk swap must not change that."""
    page = logged_in_page
    _open_with_typed_paste(page, base_url, paste_box_run_id)

    with page.expect_response(lambda r: "/samples/preview" in r.url):
        page.locator('form.paste-form button[type="submit"]').click()
    page.wait_for_selector(".paste-preview")
    with page.expect_response(lambda r: r.url.endswith("/samples/bulk")) as got:
        page.locator('.paste-actions button[type="submit"]').first.click()
    assert got.value.status == 200, got.value.status
    page.wait_for_load_state("networkidle")

    assert page.locator("#paste_data").input_value() == ""
    _assert_one_section(page)
    run = app_ctx.run_repo.get_by_id(paste_box_run_id)
    assert sorted(s.sample_id for s in run.samples) == [
        "KEEP-01", "KEEP-02", "PASTED-01", "PASTED-02"]
