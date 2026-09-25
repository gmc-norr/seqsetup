"""Fill empty samples in order: preview, change of "Start at", Assign, and
Cancel.

Nothing is saved until Assign; the preview only ever reads the run and the
kit. Assign saves exactly the plan the preview showed, in table order.
"""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import SCREENSHOT_KIT_NAME


@pytest.fixture
def fill_run_id(app_ctx):
    """A draft whose three samples have no index yet; deleted afterwards."""
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(
        id="index-fill-run", run_name="Index fill run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
        created_at=t, updated_at=t,
    )
    for n in (1, 2, 3):
        run.add_sample(Sample(id=f"{run.id}-s{n}", sample_id=f"FILL-0{n}", lanes=[1]))
    app_ctx.run_repo.save(run)
    yield run.id
    app_ctx.run_repo.delete(run.id)


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")


def _select_kit(page):
    with page.expect_response(lambda r: "/indexes/kit-content" in r.url and r.status == 200):
        page.select_option("#index-kit-dropdown", f"{SCREENSHOT_KIT_NAME}:1.0")


def _open_preview(page):
    with page.expect_response(lambda r: r.url.endswith("/index-fill/preview") and r.status == 200):
        page.click(".index-fill-start button")


@pytest.mark.browser
def test_preview_lists_next_unused_indexes(logged_in_page, base_url, app_ctx, fill_run_id):
    page = logged_in_page
    _open(page, base_url, fill_run_id)
    _select_kit(page)
    _open_preview(page)

    preview = page.locator("#index-fill-preview")
    for name in ("UDP0001", "UDP0002", "UDP0003"):
        expect(preview).to_contain_text(name)
    expect(page.locator(".index-fill-table tbody tr")).to_have_count(3)

    stored = app_ctx.run_repo.get_by_id(fill_run_id)
    assert all(not s.has_index for s in stored.samples)


@pytest.mark.browser
def test_changing_start_reprevews_from_that_index(logged_in_page, base_url, fill_run_id):
    page = logged_in_page
    _open(page, base_url, fill_run_id)
    _select_kit(page)
    _open_preview(page)

    udp2_id = page.locator(
        "#index-fill-start option", has_text="UDP0002"
    ).get_attribute("value")

    with page.expect_response(lambda r: r.url.endswith("/index-fill/preview") and r.status == 200):
        page.select_option("#index-fill-start", udp2_id)

    first_row = page.locator(".index-fill-table tbody tr").first
    expect(first_row).to_contain_text("UDP0002")


@pytest.mark.browser
def test_assign_saves_the_previewed_plan_and_removes_preview(
    logged_in_page, base_url, app_ctx, fill_run_id
):
    page = logged_in_page
    _open(page, base_url, fill_run_id)
    _select_kit(page)
    _open_preview(page)

    udp2_id = page.locator(
        "#index-fill-start option", has_text="UDP0002"
    ).get_attribute("value")
    with page.expect_response(lambda r: r.url.endswith("/index-fill/preview") and r.status == 200):
        page.select_option("#index-fill-start", udp2_id)

    with page.expect_response(lambda r: r.url.endswith("/index-fill") and r.status == 200):
        page.click(".index-fill-actions button[type=submit]")

    expect(page.locator("#index-fill-preview")).to_have_count(0)

    stored = app_ctx.run_repo.get_by_id(fill_run_id)
    # kit order from UDP0002: i7 TCCGGAGA/i5 ATAGAGGC, CGCTCATT/CCTATCCT, GAGATTCC/GGCTCTGA
    expected = [
        ("TCCGGAGA", "ATAGAGGC"),
        ("CGCTCATT", "CCTATCCT"),
        ("GAGATTCC", "GGCTCTGA"),
    ]
    assert [(s.index1_sequence, s.index2_sequence) for s in stored.samples] == expected


@pytest.mark.browser
def test_cancel_clears_the_area_and_saves_nothing(logged_in_page, base_url, app_ctx, fill_run_id):
    page = logged_in_page
    _open(page, base_url, fill_run_id)
    _select_kit(page)
    _open_preview(page)
    expect(page.locator("#index-fill-preview")).to_be_visible()

    page.click("[data-action='cancel-index-fill']")

    expect(page.locator("#index-fill-area")).to_be_empty()
    stored = app_ctx.run_repo.get_by_id(fill_run_id)
    assert all(not s.has_index for s in stored.samples)


@pytest.mark.browser
def test_preview_fits_at_375px_without_page_scroll(logged_in_page, base_url, fill_run_id):
    page = logged_in_page
    page.set_viewport_size({"width": 375, "height": 800})
    _open(page, base_url, fill_run_id)
    _select_kit(page)
    _open_preview(page)

    expect(page.locator("#index-fill-preview")).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth <= document.documentElement.clientWidth")
