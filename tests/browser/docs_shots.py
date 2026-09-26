"""Capture one documentation screenshot: outline the control the text talks
about, clip a padded region around it, save an optimised PNG.

Used by tests/browser/test_docs_screenshots.py; tested by
tests/browser/test_docs_harness.py.
"""

from pathlib import Path

from PIL import Image
from playwright.sync_api import Locator, Page, expect

OUTLINE = "3px solid #e11d48"

_PAGE_BOX_JS = """el => {
    const r = el.getBoundingClientRect();
    return {x: r.left + window.scrollX, y: r.top + window.scrollY,
            width: r.width, height: r.height};
}"""


def shoot(page: Page, path: Path, target: Locator, region: Locator | None = None,
          pad: int = 16) -> Path:
    """Outline ``target``, save a PNG of ``region`` (default ``target``) plus
    ``pad`` px on each side, then remove the outline.

    Fails with AssertionError when ``target`` or ``region`` is not visible,
    so a moved or removed control breaks the docs run instead of leaving a
    stale picture behind.
    """
    expect(target).to_be_visible()
    area = region or target
    expect(area).to_be_visible()
    target.scroll_into_view_if_needed()
    previous = target.evaluate(
        "(el, outline) => { const old = [el.style.outline, el.style.outlineOffset];"
        " el.style.outline = outline; el.style.outlineOffset = '2px'; return old; }",
        OUTLINE,
    )
    try:
        box = area.evaluate(_PAGE_BOX_JS)
        page_w = page.evaluate("document.documentElement.scrollWidth")
        page_h = page.evaluate("document.documentElement.scrollHeight")
        x = max(0, box["x"] - pad)
        y = max(0, box["y"] - pad)
        clip = {
            "x": x,
            "y": y,
            "width": min(page_w, box["x"] + box["width"] + pad) - x,
            "height": min(page_h, box["y"] + box["height"] + pad) - y,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        page.screenshot(path=str(path), clip=clip, full_page=True)
    finally:
        target.evaluate(
            "(el, old) => { el.style.outline = old[0]; el.style.outlineOffset = old[1]; }",
            previous,
        )
    Image.open(path).save(path, optimize=True)
    return path
