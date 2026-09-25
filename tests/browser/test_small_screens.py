"""The app shell works on a phone and still looks the same on a desktop.

On narrow screens the 180px sidebar stayed a column beside the page, so
the page was squeezed into what was left and the header text overlapped.
Now the sidebar becomes a bar above the page, and side-by-side boxes
stack. Also: the Settings/Admin arrows sat on a line of their own.
"""

import pytest


def _box(page, sel):
    return page.locator(sel).first.bounding_box()


def _no_sideways_page_scroll(page):
    return page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


@pytest.mark.browser
def test_phone_sidebar_sits_above_page(logged_in_page, base_url):
    page = logged_in_page
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")

    sidebar, main = _box(page, ".sidebar"), _box(page, "#main")
    assert sidebar["y"] + sidebar["height"] <= main["y"] + 1
    assert main["width"] >= 390 * 0.85
    assert _no_sideways_page_scroll(page)
    for link in ("Dashboard", "Run Templates"):
        assert page.locator(".sidebar", has_text=link).is_visible()
    # Run names are readable: the list scrolls sideways instead of
    # squeezing the Name column to nothing.
    for name in page.locator("#dashboard [id^='run-item-'] > a").all():
        assert name.bounding_box()["width"] > 60


@pytest.mark.browser
def test_phone_run_page_boxes_stack(logged_in_page, base_url, seeded_ids):
    page = logged_in_page
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{base_url}/runs/{seeded_ids['draft_run_id']}")
    page.wait_for_load_state("networkidle")

    validate, export = _box(page, "#validate-panel"), _box(page, "#export-panel")
    assert export["y"] >= validate["y"] + validate["height"] - 1
    assert _no_sideways_page_scroll(page)


@pytest.mark.browser
def test_desktop_sidebar_is_still_a_column(logged_in_page, base_url):
    page = logged_in_page
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{base_url}/")
    page.wait_for_load_state("networkidle")

    sidebar, main = _box(page, ".sidebar"), _box(page, "#main")
    assert sidebar["x"] + sidebar["width"] <= main["x"] + 1
    # Arrow and label share one line: as tall as a one-line nav item.
    one_line = _box(page, ".sidebar > a.nav-item")["height"]
    for summary in page.locator(".settings-section > summary").all():
        assert summary.bounding_box()["height"] <= one_line + 2
