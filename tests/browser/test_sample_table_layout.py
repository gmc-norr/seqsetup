"""The sample table never hides columns, and the bulk tools stay out of the
way until they can be used.

With the index panel open, the table was squeezed beside it and its right
columns (overrides, mismatches, delete) and the bulk panel's buttons were
cut off behind a sideways scroll, even at 1440 px. The bulk panel was
always open, including a red "Delete Selected" with nothing ticked.
"""

import pytest
from playwright.sync_api import expect

_OVERFLOW = """sel => { const e = document.querySelector(sel);
                       return e ? e.scrollWidth - e.clientWidth : null; }"""


def _open(page, base_url, run_id, width):
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")


@pytest.mark.browser
@pytest.mark.parametrize("width", [1280, 1440])
def test_table_not_cut_off_with_index_panel(logged_in_page, base_url, seeded_ids, width):
    page = logged_in_page
    _open(page, base_url, seeded_ids["draft_run_id"], width)
    expect(page.locator(".wizard-index-panel")).to_be_visible()
    page.locator(".sample-checkbox").first.check()
    for sel in (".run-page-sample-panel", "#bulk-action-panel", "#sample-section"):
        assert page.evaluate(_OVERFLOW, sel) <= 1, f"{sel} overflows at {width}px"


@pytest.mark.browser
def test_panel_beside_table_on_wide_screen(logged_in_page, base_url, seeded_ids):
    page = logged_in_page
    _open(page, base_url, seeded_ids["draft_run_id"], 1600)
    panel = page.locator(".wizard-index-panel").bounding_box()
    table = page.locator(".run-page-sample-panel").bounding_box()
    assert panel["x"] + panel["width"] <= table["x"]
    assert page.evaluate(_OVERFLOW, ".run-page-sample-panel") <= 1


@pytest.mark.browser
def test_bulk_tools_fold_until_a_sample_is_ticked(logged_in_page, base_url, seeded_ids):
    page = logged_in_page
    _open(page, base_url, seeded_ids["draft_run_id"], 1440)
    grid = page.locator("#bulk-action-panel .bulk-action-grid")
    delete = page.locator("#bulk-delete-btn")
    hint = page.locator("#bulk-action-panel .bulk-hint")

    expect(grid).to_be_hidden()
    expect(delete).to_be_hidden()
    expect(hint).to_be_visible()

    box = page.locator(".sample-checkbox").first
    box.check()
    expect(grid).to_be_visible()
    expect(delete).to_be_visible()
    expect(hint).to_be_hidden()

    box.uncheck()
    expect(grid).to_be_hidden()
    expect(delete).to_be_hidden()
