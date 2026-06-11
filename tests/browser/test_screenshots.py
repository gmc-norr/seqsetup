"""Screenshot regression oracle.

Captures full-page PNGs of representative pages into
``tests/browser/screenshots/current/``.  Compare against the committed
baseline with ``python tools/screenshot_diff.py``.

Navigation-based pages use direct ``page.goto()``.  Dashboard status tabs and
validation content tabs are HTMX fragments / Alpine x-show toggles — both must
be captured by *clicking* the tab buttons, not by URL navigation.
"""

import re
import shutil
import pytest
from pathlib import Path

OUT = Path(__file__).parent / "screenshots" / "current"


@pytest.fixture(scope="session", autouse=True)
def _clear_current():
    # Wipe stale PNGs so a removed/renamed page can't leave a ghost behind.
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True, exist_ok=True)


# Plain full-page navigations (real, confirmed routes).
NAV_PAGES = [
    ("dashboard",         "/"),
    ("run-editor",        "/runs/{screenshot_draft_run_id}"),
    ("validation-issues", "/runs/{collision_run_id}/validation"),  # default tab = issues
    ("indexes-list",      "/indexes"),
    ("admin-users",       "/admin/users"),
    ("admin-auth",        "/admin/authentication"),
    ("admin-instruments", "/admin/instruments"),
]


def _shoot(page, name):
    OUT.mkdir(parents=True, exist_ok=True)
    page.wait_for_load_state("networkidle")
    # Let Alpine x-show toggles and any CSS transition settle so we never
    # capture a tab mid-expand (deterministic oracle). animations="disabled"
    # freezes CSS animations/transitions to their finished state at capture.
    page.wait_for_timeout(350)
    page.screenshot(path=str(OUT / f"{name}.png"), full_page=True, animations="disabled")


@pytest.mark.browser
@pytest.mark.parametrize("name,path", NAV_PAGES, ids=[p[0] for p in NAV_PAGES])
def test_capture_nav(logged_in_page, base_url, seeded_ids, name, path):
    page = logged_in_page
    page.goto(base_url + path.format(**seeded_ids))
    _shoot(page, name)


@pytest.mark.browser
def test_capture_dashboard_tabs(logged_in_page, base_url):
    page = logged_in_page
    page.goto(base_url + "/")
    for label in ("Ready", "Archived"):
        page.get_by_role("button", name=re.compile(rf"^{re.escape(label)}")).first.click()
        page.wait_for_load_state("networkidle")
        _shoot(page, f"dashboard-{label.lower()}")


@pytest.mark.browser
def test_capture_validation_tabs(logged_in_page, base_url, seeded_ids):
    page = logged_in_page
    page.goto(base_url + f"/runs/{seeded_ids['collision_run_id']}/validation")
    for label, name in [
        ("Heatmaps", "validation-heatmaps"),
        ("Color Balance", "validation-colorbalance"),
        ("Dark Cycles", "validation-darkcycles"),
    ]:
        page.get_by_text(label, exact=False).first.click()
        page.wait_for_load_state("networkidle")
        _shoot(page, name)
