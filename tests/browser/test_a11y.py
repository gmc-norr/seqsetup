"""Accessibility gate — WCAG 2.1 AA certification.

axe.min.js is vendored at src/seqsetup/static/js/vendor/axe.min.js and injected
via ``page.evaluate()`` which runs through CDP and is NOT subject to page CSP.
The app's CSP is ``script-src 'self' 'unsafe-eval'`` so a CDN <script> would be
blocked, but CDP-side evaluation is exempt.

Phase 4.2 gate (Task 4.2):
  - Zero serious/critical axe violations on dashboard, run-editor, and validation.
  - Contrast matrix: all §4.4 foreground/background pairs meet their WCAG target.
  - Focus rings: button, input, and index chip each get a non-empty box-shadow
    on :focus-visible.
"""

import math
import pytest
from pathlib import Path

AXE = (Path(__file__).parents[2] / "src/seqsetup/static/js/vendor/axe.min.js").read_text()


# ---------------------------------------------------------------------------
# Helper: run axe and return serious/critical violations as a list of dicts
# ---------------------------------------------------------------------------

def _serious_violations(page):
    page.wait_for_load_state("networkidle")
    page.evaluate(AXE)  # defines window.axe; CDP eval bypasses CSP
    res = page.evaluate("async () => await axe.run(document, {resultTypes:['violations']})")
    return [v for v in res["violations"] if v["impact"] in ("serious", "critical")]


def _assert_zero(page, label):
    viols = _serious_violations(page)
    assert not viols, (
        f"{len(viols)} serious/critical a11y violation(s) on {label}:\n"
        + "\n".join(
            f"  [{v['impact'].upper()}] {v['id']}: {v['description']}\n"
            + "".join(
                f"    {n['target']} — {n['failureSummary'][:160]}\n"
                for n in v["nodes"][:3]
            )
            for v in viols
        )
    )


# ---------------------------------------------------------------------------
# §4.2.1 — Zero axe violations on three representative pages
# ---------------------------------------------------------------------------

@pytest.mark.browser
def test_axe_dashboard(logged_in_page):
    """Dashboard must have zero serious/critical axe violations."""
    _assert_zero(logged_in_page, "dashboard")


@pytest.mark.browser
def test_axe_run_editor(logged_in_page, base_url, seeded_ids):
    """Run editor (draft run with samples) must have zero serious/critical axe violations."""
    page = logged_in_page
    page.goto(base_url + f"/runs/{seeded_ids['screenshot_draft_run_id']}")
    _assert_zero(page, "run-editor")


@pytest.mark.browser
def test_axe_validation(logged_in_page, base_url, seeded_ids):
    """Validation page (collision run) must have zero serious/critical axe violations."""
    page = logged_in_page
    page.goto(base_url + f"/runs/{seeded_ids['collision_run_id']}/validation")
    _assert_zero(page, "validation")


# ---------------------------------------------------------------------------
# §4.2.2 — Contrast matrix (pure-Python, no browser needed)
# ---------------------------------------------------------------------------

def _srgb_to_linear(c: float) -> float:
    c /= 255.0
    if c <= 0.04045:
        return c / 12.92
    return ((c + 0.055) / 1.055) ** 2.4


def _luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return (
        0.2126 * _srgb_to_linear(r)
        + 0.7152 * _srgb_to_linear(g)
        + 0.0722 * _srgb_to_linear(b)
    )


def _contrast(fg: str, bg: str) -> float:
    l1, l2 = _luminance(fg), _luminance(bg)
    if l1 < l2:
        l1, l2 = l2, l1
    return (l1 + 0.05) / (l2 + 0.05)


# §4.4 contrast matrix — each tuple is (fg, bg, min_ratio, description)
# Source: docs/superpowers/specs/2026-06-10-gui-design-system-refresh-design.md §4.4
_CONTRAST_PAIRS = [
    # body / headings — well above 4.5:1
    ("#0f172a", "#f8fafc", 4.5, "text on bg"),
    ("#0f172a", "#ffffff", 4.5, "text on surface"),
    ("#0f172a", "#f1f5f9", 4.5, "text on surface-sunken"),
    # secondary labels
    ("#475569", "#f8fafc", 4.5, "text-muted on bg"),
    ("#475569", "#ffffff", 4.5, "text-muted on surface"),
    ("#475569", "#f1f5f9", 4.5, "text-muted on surface-sunken"),
    # primary as link/active text (large/non-text threshold ≥3:1)
    ("#0e7490", "#ffffff", 3.0, "primary on surface (link/large)"),
    # primary button label
    ("#ffffff", "#0e7490", 4.5, "primary-fg on primary (button)"),
    # semantic status pairs
    ("#166534", "#dcfce7", 4.5, "success-fg on success-bg"),
    ("#92400e", "#fef3c7", 4.5, "warning-fg on warning-bg"),
    ("#991b1b", "#fef2f2", 4.5, "danger-fg on danger-bg"),
    ("#155e75", "#cff5fb", 4.5, "info-fg on info-bg"),
]


def test_contrast_matrix():
    """All §4.4 token pairs must meet their WCAG 2.1 AA contrast target."""
    failures = []
    for fg, bg, minimum, description in _CONTRAST_PAIRS:
        ratio = _contrast(fg, bg)
        if ratio < minimum:
            failures.append(
                f"  FAIL {description}: {fg} on {bg} = {ratio:.2f} (need ≥{minimum})"
            )
    assert not failures, "Contrast matrix violations:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# §4.2.3 — Focus-ring presence on button, input, and index chip
# ---------------------------------------------------------------------------

@pytest.mark.browser
def test_focus_ring_button(logged_in_page):
    """A .btn-primary button must have a non-empty box-shadow on :focus-visible."""
    page = logged_in_page
    # Dashboard has a "+ New Run" submit button in the empty state, but the
    # seeded session has runs so the dashboard shows the run list.  Navigate to
    # the run editor where export buttons exist.
    page.wait_for_load_state("networkidle")
    # Find first focusable button on the page.
    btn = page.locator("button").first
    btn.focus()
    shadow = page.evaluate(
        "() => getComputedStyle(document.activeElement).boxShadow"
    )
    assert shadow and shadow != "none", (
        f"Button has no box-shadow on focus (got {shadow!r}); "
        "check --focus-ring is applied via :focus-visible"
    )


@pytest.mark.browser
def test_focus_ring_input(logged_in_page, base_url, seeded_ids):
    """A form input must have a non-empty box-shadow on :focus-visible."""
    page = logged_in_page
    page.goto(base_url + f"/runs/{seeded_ids['screenshot_draft_run_id']}")
    page.wait_for_load_state("networkidle")
    inp = page.locator("input[type='text'], input:not([type])").first
    inp.focus()
    shadow = page.evaluate(
        "() => getComputedStyle(document.activeElement).boxShadow"
    )
    assert shadow and shadow != "none", (
        f"Input has no box-shadow on focus (got {shadow!r}); "
        "check --focus-ring is applied via :focus-visible"
    )


@pytest.mark.browser
def test_focus_ring_index_chip(logged_in_page, base_url, seeded_ids):
    """An index chip (.draggable-index-compact) must have a non-empty box-shadow when focused."""
    page = logged_in_page
    page.goto(base_url + f"/runs/{seeded_ids['screenshot_draft_run_id']}")
    page.wait_for_load_state("networkidle")
    chip = page.locator(".draggable-index-compact").first
    chip.focus()
    shadow = page.evaluate(
        "() => getComputedStyle(document.activeElement).boxShadow"
    )
    assert shadow and shadow != "none", (
        f"Index chip has no box-shadow on focus (got {shadow!r}); "
        "check --focus-ring is applied via :focus-visible"
    )


# ---------------------------------------------------------------------------
# §4.2.4 — Keyboard-operable index assignment (kept from Task 3.3)
# ---------------------------------------------------------------------------

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
