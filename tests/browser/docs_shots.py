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
        # A control just clicked or typed in may still be fading to its new
        # colour; finish every fade first, or the picture differs per run.
        page.screenshot(path=str(path), clip=clip, full_page=True, animations="disabled")
    finally:
        target.evaluate(
            "(el, old) => { el.style.outline = old[0]; el.style.outlineOffset = old[1]; }",
            previous,
        )
    Image.open(path).save(path, optimize=True)
    return path


_REPLACE_TEXT_JS = """(root, [pattern, values]) => {
    const re = new RegExp(pattern, "g");
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const nodes = [];
    for (let n = walker.nextNode(); n; n = walker.nextNode()) nodes.push(n);
    const found = nodes.reduce((k, n) => k + (n.nodeValue.match(re) || []).length, 0);
    if (found !== values.length) return found;
    let i = 0;
    for (const n of nodes) n.nodeValue = n.nodeValue.replace(re, () => values[i++]);
    return found;
}"""


def replace_text(region: Locator, pattern: str, values: list[str]) -> None:
    """Replace, in page order, each text in ``region`` that matches the
    regular expression ``pattern`` with the next of ``values``. Times of day
    and random values (IDs, tokens) differ on every run; fixed example values
    keep a picture the same.

    Fails with AssertionError, changing nothing, when ``pattern`` does not
    match exactly ``len(values)`` times, so a page that changes breaks the
    docs run instead of leaving a moving value in a picture.
    """
    found = region.evaluate(_REPLACE_TEXT_JS, [pattern, values])
    assert found == len(values), f"{pattern!r} matched {found} times, not {len(values)}"
