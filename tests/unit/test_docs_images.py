"""Every screenshot a docs page points at exists, and every screenshot on
disk is used by some page."""

import re
from pathlib import Path

DOCS = Path(__file__).resolve().parents[2] / "docs"
SHOTS = DOCS / "_static" / "screenshots"
_REF = re.compile(r"/_static/screenshots/([\w./-]+\.png)")


def _referenced() -> set[str]:
    refs = set()
    for rst in DOCS.rglob("*.rst"):
        refs |= set(_REF.findall(rst.read_text(encoding="utf-8")))
    return refs


def test_every_referenced_screenshot_exists():
    missing = sorted(r for r in _referenced() if not (SHOTS / r).is_file())
    assert missing == []


def test_every_screenshot_is_referenced():
    on_disk = {p.relative_to(SHOTS).as_posix() for p in SHOTS.rglob("*.png")} if SHOTS.exists() else set()
    assert sorted(on_disk - _referenced()) == []


def test_screenshots_stay_under_15_mb():
    total = sum(p.stat().st_size for p in SHOTS.rglob("*.png")) if SHOTS.exists() else 0
    assert total <= 15 * 1024 * 1024
