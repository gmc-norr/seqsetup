"""Documentation screenshots: drive the real app in a made-up demo world and
save outlined crops into docs/_static/screenshots/.

Skipped unless SEQSETUP_DOCS_SCREENSHOTS=1 (`pixi run docs-screenshots`).
Tests run in file order; later tests may rely on what earlier ones did.
The browser-test database is snapshotted before and restored after, so
other browser tests never see the demo world.
"""

import os
from pathlib import Path

import pytest

from seqsetup.services import database

from .docs_shots import shoot
from .docs_world import DEMO_ADMIN, clear, reset_caches, restore, seed_demo, snapshot

SHOTS = Path(__file__).resolve().parents[2] / "docs" / "_static" / "screenshots"

pytestmark = [
    pytest.mark.browser,
    pytest.mark.skipif(
        os.environ.get("SEQSETUP_DOCS_SCREENSHOTS") != "1",
        reason="documentation screenshots: run `pixi run docs-screenshots`",
    ),
]


@pytest.fixture(scope="module")
def demo(app_ctx):
    db = database.get_db()
    saved = snapshot(db)
    clear(db)
    reset_caches()
    try:
        ids = seed_demo(app_ctx)
        yield ids
    finally:
        restore(db, saved)
        reset_caches()


@pytest.fixture
def demo_page(page, base_url, demo):
    page.set_viewport_size({"width": 1280, "height": 800})
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', DEMO_ADMIN["username"])
    page.fill('input[name="password"]', DEMO_ADMIN["password"])
    page.click('button[type="submit"]')
    page.wait_for_url(f"{base_url}/", timeout=5000)
    return page


def snap(page, name: str, target, region=None, pad: int = 16) -> Path:
    return shoot(page, SHOTS / f"{name}.png", target, region=region, pad=pad)


def test_login_form(page, base_url, demo):
    page.set_viewport_size({"width": 1280, "height": 800})
    page.goto(f"{base_url}/login")
    form = page.locator("form").filter(has=page.locator('input[name="username"]'))
    snap(page, "login/login-form", form, pad=24)
