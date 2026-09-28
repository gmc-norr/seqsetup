"""Samples named by a blocking error are marked in the table, and a refused
Mark Ready reads as a list.

The two colliding samples used to look exactly like the rest, and the
refusal was one long red paragraph ending in "(+1 more)".
"""

import re

import pytest
from playwright.sync_api import expect


def _row(page, sample_id):
    return page.locator("#sample-table .sample-row", has=page.locator(f"td[title='{sample_id}']"))


@pytest.mark.browser
def test_colliding_rows_are_marked(logged_in_page, base_url, seeded_ids):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{seeded_ids['collision_run_id']}")
    page.wait_for_load_state("networkidle")

    for sample_id in ("COLL-01", "COLL-02"):
        row = _row(page, sample_id)
        expect(row).to_have_class(re.compile(r"\bhas-error\b"))
        badge = row.locator(".row-error-badge")
        expect(badge).to_be_visible()
        assert "collision" in badge.get_attribute("title")

    third = _row(page, "COLL-03").locator(".row-error-badge")
    if third.count():
        assert "collision" not in third.get_attribute("title")


@pytest.mark.browser
def test_refusal_is_a_list(logged_in_page, base_url, seeded_ids):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{seeded_ids['collision_run_id']}")
    page.wait_for_load_state("networkidle")

    page.click("text=Mark Ready")
    banner = page.locator("#ready-message")
    expect(banner.locator("li").first).to_be_visible()
    expect(banner).to_contain_text("Cannot mark ready")
    expect(banner).not_to_contain_text("more)")
    expect(banner.locator("a", has_text="validation page")).to_have_attribute(
        "href", f"/runs/{seeded_ids['collision_run_id']}/validation")
