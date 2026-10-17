"""Two tabs: the bulk panel's mismatches, Override Cycles and test Apply
are refused when the page is out of date (design note
docs/design/2026-10-17-stale-page-checks-design.md, step 2).

The page sends what each ticked row showed for the field it changes: the
two mismatch boxes and the Override Cycles box carry it in their
defaultValue, which app.js sets to the stored value on every answer (F3),
and the test comes from the row (data-test-id / data-test-version).
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from .conftest import hold_edit_lock

RUN_ID = "stale-panel-run"


@pytest.fixture
def run_id(app_ctx):
    """A draft with two samples, both on lane 1, mismatches at the default."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id=RUN_ID, run_name="Stale panel run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{RUN_ID}-s{n}", sample_id=f"SP-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)
    yield RUN_ID
    app_ctx.run_repo.collection.delete_one({"_id": RUN_ID})


def _open_and_tick_both(page, base_url):
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()


def _the_other_tab(app_ctx, n, **fields):
    run = app_ctx.run_repo.get_by_id(RUN_ID)
    for name, value in fields.items():
        setattr(run.samples[n - 1], name, value)
    app_ctx.run_repo.save(run)
    hold_edit_lock(app_ctx, RUN_ID)


def _click(page, action, route):
    with page.expect_response(lambda r: r.url.endswith(route)) as answer:
        page.locator(f'[data-action="{action}"]').click()
    return answer.value


def _stored(app_ctx):
    return [(s.barcode_mismatches_index1, s.barcode_mismatches_index2,
             s.override_cycles, s.test_id, s.test_version)
            for s in app_ctx.run_repo.get_by_id(RUN_ID).samples]


@pytest.mark.browser
def test_a_mismatch_apply_on_a_row_another_tab_changed_is_refused(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open_and_tick_both(page, base_url)
    _the_other_tab(app_ctx, 2, barcode_mismatches_index1=0)
    before = _stored(app_ctx)

    page.fill("#bulk-mismatch-i7-input", "2")
    answer = _click(page, "bulk-apply-mismatches", "/samples/set-mismatches")

    assert answer.status == 409
    assert "target_mismatches" in answer.request.post_data, answer.request.post_data
    expect(page.locator("#error-banner")).to_contain_text(
        "The barcode mismatches on these samples changed since this page was loaded")
    expect(page.locator("#error-banner")).to_contain_text("SP-02")
    assert _stored(app_ctx) == before


@pytest.mark.browser
def test_an_override_cycles_apply_on_a_row_another_tab_changed_is_refused(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open_and_tick_both(page, base_url)
    _the_other_tab(app_ctx, 1, override_cycles="U8Y143;I8;I8;Y151")
    before = _stored(app_ctx)

    answer = _click(page, "bulk-clear-override", "/samples/set-override-cycles")

    assert answer.status == 409
    expect(page.locator("#error-banner")).to_contain_text(
        "The Override Cycles on these samples changed since this page was loaded")
    expect(page.locator("#error-banner")).to_contain_text("SP-01")
    assert _stored(app_ctx) == before


@pytest.mark.browser
def test_a_test_apply_on_a_row_another_tab_changed_is_refused(
        logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open_and_tick_both(page, base_url)
    _the_other_tab(app_ctx, 2, test_id="EXOME", test_version="3")
    before = _stored(app_ctx)

    answer = _click(page, "bulk-clear-testid", "/samples/set-test-id")

    assert answer.status == 409
    assert "target_tests" in answer.request.post_data, answer.request.post_data
    expect(page.locator("#error-banner")).to_contain_text(
        "The test on these samples changed since this page was loaded")
    expect(page.locator("#error-banner")).to_contain_text("SP-02")
    assert _stored(app_ctx) == before


@pytest.mark.browser
def test_a_fresh_apply_still_works_for_all_three(logged_in_page, base_url, app_ctx, run_id):
    page = logged_in_page
    _open_and_tick_both(page, base_url)

    page.fill("#bulk-mismatch-i7-input", "2")
    assert _click(page, "bulk-apply-mismatches", "/samples/set-mismatches").status == 200
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()
    page.fill("#bulk-override-cycles-input", "Y150N1;I8;I8;Y151")
    assert _click(page, "bulk-apply-override", "/samples/set-override-cycles").status == 200
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()
    assert _click(page, "bulk-clear-testid", "/samples/set-test-id").status == 200

    assert _stored(app_ctx) == [(2, 1, "Y150N1;I8;I8;Y151", "", "")] * 2


@pytest.mark.browser
def test_a_row_box_saved_first_does_not_make_the_panel_stale(
        logged_in_page, base_url, app_ctx, run_id):
    """A row's own MM box saves without redrawing the row (hx-swap="none",
    F3), so an attribute on the row would go stale: the panel reads the
    box's defaultValue, which app.js sets to the stored value."""
    page = logged_in_page
    page.goto(f"{base_url}/runs/{RUN_ID}")
    page.wait_for_load_state("networkidle")

    box = page.locator(f"#mismatch-i7-{RUN_ID}-s1")
    box.fill("0")
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == 200):
        box.press("Tab")
    page.wait_for_function("() => !document.querySelector('.htmx-request')")
    for n in (1, 2):
        page.locator(f"#sample-row-{RUN_ID}-s{n} .sample-checkbox").check()
    page.fill("#bulk-mismatch-i5-input", "2")
    answer = _click(page, "bulk-apply-mismatches", "/samples/set-mismatches")

    assert answer.status == 200, answer.text()
    assert [row[:2] for row in _stored(app_ctx)] == [(0, 2), (1, 2)]
