"""Accessibility gate — axe-core no-new-violations check.

axe.min.js is vendored at src/seqsetup/static/js/vendor/axe.min.js and injected
via ``page.evaluate()`` which runs through CDP and is NOT subject to page CSP.
The app's CSP is ``script-src 'self' 'unsafe-eval'`` so a CDN <script> would be
blocked, but CDP-side evaluation is exempt.

First run records the baseline (``a11y_baseline.json``) and skips.
Subsequent runs enforce: any *new* serious/critical violation that was not in
the baseline causes a test failure.
"""

import json
import pytest
from pathlib import Path

AXE = (Path(__file__).parents[2] / "src/seqsetup/static/js/vendor/axe.min.js").read_text()
BASELINE = Path(__file__).parent / "a11y_baseline.json"   # committed; never allowed to grow


def _serious_ids(page):
    page.wait_for_load_state("networkidle")
    page.evaluate(AXE)  # defines window.axe; CDP eval bypasses CSP
    res = page.evaluate("async () => await axe.run(document, {resultTypes:['violations']})")
    return sorted({v["id"] for v in res["violations"] if v["impact"] in ("serious", "critical")})


def _check(page, key):
    ids = _serious_ids(page)
    data = json.loads(BASELINE.read_text()) if BASELINE.exists() else {}
    if key not in data:
        data[key] = ids
        BASELINE.write_text(json.dumps(data, indent=2, sort_keys=True))
        pytest.skip(f"recorded a11y baseline for {key}: {ids}")
    new = set(ids) - set(data[key])
    assert not new, f"NEW serious/critical a11y violations on {key}: {sorted(new)}"


@pytest.mark.browser
def test_axe_dashboard(logged_in_page):
    _check(logged_in_page, "dashboard")


@pytest.mark.browser
def test_index_keyboard_assign(logged_in_page, base_url, mutable_run_id):
    page = logged_in_page
    page.goto(base_url + f"/runs/{mutable_run_id}")
    page.wait_for_load_state("networkidle")
    before = page.locator(".sample-row.has-index").count()
    chip = page.locator(".draggable-index-compact").first
    chip.focus()
    assert chip.evaluate("el => el.tabIndex") == 0
    page.keyboard.press("Enter")                                  # select
    assert page.locator(".draggable-index-compact.index-selected").count() >= 1
    zone = page.locator(".drop-zone").first
    zone.focus()
    assert zone.evaluate("el => el.tabIndex") == 0
    page.keyboard.press("Enter")                                  # assign selected → this sample
    page.wait_for_function(f"document.querySelectorAll('.sample-row.has-index').length === {before + 1}")
    assert page.locator(".sample-row.has-index").count() == before + 1
