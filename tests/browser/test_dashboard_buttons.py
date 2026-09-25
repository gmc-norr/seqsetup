"""Dashboard row buttons share one size, and Archive is not the loudest.

A global `button` rule made Duplicate/Archive larger than the Edit link
beside them, and Archive (a routine step) was the one orange button.
"""

import pytest

_BOXES = """row => Array.from(row.querySelectorAll('a, button')).map(el => ({
    text: el.textContent.trim(),
    h: Math.round(el.getBoundingClientRect().height),
    bg: getComputedStyle(el).backgroundColor,
}))"""


def _row_controls(page, base_url, tab, run_id):
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")
    page.click(f"button[hx-get='/dashboard/tab/{tab}']")
    row = page.locator(f"#run-item-{run_id}")
    row.wait_for()
    return {c["text"]: c for c in row.evaluate(_BOXES) if c["text"]}


@pytest.mark.browser
def test_ready_row_buttons_match(logged_in_page, base_url, seeded_ids):
    controls = _row_controls(logged_in_page, base_url, "ready", seeded_ids["ready_run_id"])
    buttons = {k: v for k, v in controls.items() if k in ("Open", "Duplicate", "Archive")}
    assert set(buttons) == {"Open", "Duplicate", "Archive"}
    heights = {v["h"] for v in buttons.values()}
    assert max(heights) - min(heights) <= 1, buttons
    assert buttons["Archive"]["bg"] == buttons["Duplicate"]["bg"]


@pytest.mark.browser
def test_draft_row_says_edit(logged_in_page, base_url, seeded_ids):
    controls = _row_controls(logged_in_page, base_url, "draft", seeded_ids["draft_run_id"])
    assert "Edit" in controls and "Open" not in controls
