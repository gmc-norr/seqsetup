# SeqSetup Guides with Screenshots Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite the SeqSetup user guide and admin guide to match today's app, with script-made screenshots that show what each step says, and make the docs build clean.

**Architecture:** A gated pytest module drives the real app (the existing browser-test harness: uvicorn in a thread, mongomock) inside a temporary made-up demo world and saves outlined, cropped PNGs into `docs/_static/screenshots/`. The Sphinx `.rst` pages reference those PNGs with `.. figure::`. Checks: every referenced PNG exists and none is orphaned; `sphinx-build -W` passes.

**Tech Stack:** Python 3.14, pytest + pytest-playwright (Chromium), Pillow, mongomock, Sphinx 9 + furo, Pixi.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-26-docs-screenshots-design.md` (copied in Task 0). It wins over this plan where they differ — record the difference.
- No change under `src/`. The app is not changed. Oddities go to `PLAN-DEFECTS.md` / `FINDINGS-DOCS.md`, not into code.
- No change under `tests/browser/screenshots/`, to `tests/browser/conftest.py`, or to any existing test's assertions.
- `pixi.lock` unchanged. `pixi.toml` changes ONLY in `[tasks]`: add `docs-screenshots`, and `docs` gains `-W --keep-going`.
- Pictures show made-up demo data only: never "browser-admin", "Browser Admin", "Screenshot…", "Screenshot-TestKit", "…seed run", never a real-looking patient identifier, never a password.
- UI labels in the text are written **exactly** as the app renders them, in bold (`**Mark Ready**`).
- Every `.. figure::` has `:alt:` text and a caption saying what the red outline marks.
- All PNGs under `docs/_static/screenshots/` together ≤ 15 MB.
- Plain language for the user guide: short sentences, numbered steps, one task per section.
- A behavioral claim ("Mark Ready refuses when…", "only admins can…") is written only after reading the code that does it or seeing it in the screenshot run.
- The worktree has no Pixi env. Always run with `PY=/home/parlar_ai/dev/seqsetup/.pixi/envs/default/bin/python` and `PYTHONPATH=src`, and `SPHINX=/home/parlar_ai/dev/seqsetup/.pixi/envs/default/bin/sphinx-build`. Never `pixi run` / `pixi install` in the worktree.
- Commit trailer, last line exactly: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`

Commands used throughout (from the worktree root `/home/parlar_ai/dev/seqsetup/.worktrees/docs-guide`):

- Screenshots: `SEQSETUP_DOCS_SCREENSHOTS=1 PYTHONPATH=src $PY -m pytest tests/browser/test_docs_screenshots.py -q -p no:cacheprovider`
- Docs build: `$SPHINX -W --keep-going -q -b html docs /tmp/seqsetup-docs-build` → must print nothing and exit 0.
- Server suite: `PYTHONPATH=src $PY -m pytest tests/unit tests/integration -q -p no:cacheprovider`
- Browser suite: `PYTHONPATH=src $PY -m pytest tests/browser -q -p no:cacheprovider`

---

### Task 0: Spec and plan into the branch

**Files:**
- Create: `docs/superpowers/specs/2026-09-26-docs-screenshots-design.md` (copy of `/home/parlar_ai/seqsetup-docs-run/spec.md`)
- Create: `docs/superpowers/plans/2026-09-26-docs-screenshots.md` (copy of `/home/parlar_ai/seqsetup-docs-run/plan.md`)

- [ ] **Step 1: Copy both files**

```bash
W=/home/parlar_ai/dev/seqsetup/.worktrees/docs-guide
cp /home/parlar_ai/seqsetup-docs-run/spec.md $W/docs/superpowers/specs/2026-09-26-docs-screenshots-design.md
cp /home/parlar_ai/seqsetup-docs-run/plan.md $W/docs/superpowers/plans/2026-09-26-docs-screenshots.md
```

- [ ] **Step 2: Commit**

```bash
git -C $W add docs/superpowers && git -C $W commit -m "docs: spec and plan for the guides with screenshots"
```
(with the trailer line)

---

### Task 1: The screenshot helper

**Files:**
- Create: `tests/browser/docs_shots.py`
- Test: `tests/browser/test_docs_harness.py`

**Interfaces:**
- Produces: `shoot(page: Page, path: Path, target: Locator, region: Locator | None = None, pad: int = 16) -> Path` in `tests.browser.docs_shots`. Outlines `target` (3 px `#e11d48`), saves a PNG clipped to `region` (default `target`) plus `pad` px, removes the outline, optimises the PNG, returns `path`. Raises `AssertionError` (Playwright `expect`) if `target` or `region` is not visible — and then writes no file.

- [ ] **Step 1: Write the failing tests**

```python
"""The documentation screenshot helper: one call outlines the control the
text talks about, saves a padded crop around it, and cleans up."""

import pytest
from PIL import Image

from .docs_shots import shoot

_BOX = ('<div id="box" style="margin:100px;width:200px;height:50px">'
        '<button id="go">Go</button></div>')


@pytest.mark.browser
def test_shoot_saves_a_padded_crop_of_the_region(page, tmp_path):
    page.set_viewport_size({"width": 800, "height": 600})
    page.set_content(_BOX)

    out = shoot(page, tmp_path / "a" / "b.png", page.locator("#go"),
                region=page.locator("#box"), pad=10)

    assert out == tmp_path / "a" / "b.png" and out.exists()
    assert Image.open(out).size == (220, 70)


@pytest.mark.browser
def test_shoot_removes_the_outline_afterwards(page, tmp_path):
    page.set_content(_BOX)

    shoot(page, tmp_path / "c.png", page.locator("#go"))

    assert page.locator("#go").evaluate("el => el.style.outline") == ""


@pytest.mark.browser
def test_shoot_fails_and_writes_nothing_when_the_target_is_missing(page, tmp_path):
    page.set_content("<p>nothing here</p>")

    with pytest.raises(AssertionError):
        shoot(page, tmp_path / "x.png", page.locator("#missing"))

    assert not (tmp_path / "x.png").exists()
```

- [ ] **Step 2: Run them to see them fail**

Run: `PYTHONPATH=src $PY -m pytest tests/browser/test_docs_harness.py -q -p no:cacheprovider`
Expected: collection ERROR `ModuleNotFoundError ... docs_shots` (the helper does not exist yet).

- [ ] **Step 3: Write the helper**

```python
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
```

- [ ] **Step 4: Run them to see them pass**

Run: `PYTHONPATH=src $PY -m pytest tests/browser/test_docs_harness.py -q -p no:cacheprovider`
Expected: `3 passed`. If the size assertion is off by a pixel, measure the real box (print it) and fix the helper's arithmetic, not the expected number.

- [ ] **Step 5: Commit** `tests/browser/docs_shots.py tests/browser/test_docs_harness.py` — `test(docs): a screenshot helper that outlines and crops`

---

### Task 2: The demo world

**Files:**
- Create: `tests/browser/docs_world.py`
- Test: `tests/unit/test_docs_world.py`, `tests/integration/test_docs_world_seed.py`

**Interfaces:**
- Produces, in `tests.browser.docs_world`:
  - `snapshot(db) -> dict[str, list[dict]]`, `clear(db) -> None`, `restore(db, snap: dict) -> None`
  - `reset_caches() -> None` — clears the validation cache and the synced-instrument cache
  - `DEMO_ADMIN: dict` (`username`, `password`, `display_name`), `DEMO_STAFF: dict` (same keys)
  - `DEMO_KIT_NAME = "Demo UDI Set A"`, `DEMO_KIT_VERSION = "1.0"`
  - `seed_demo(ctx) -> dict[str, str]` — returns run ids by key: `"draft"`, `"problem"`, `"ready"`, `"archived"`, `"fill"`

- [ ] **Step 1: Write the failing tests**

`tests/unit/test_docs_world.py`:
```python
"""The docs screenshot run borrows the browser-test database: it saves what
is there, empties it, and must put back exactly what it found."""

import mongomock

from tests.browser.docs_world import clear, restore, snapshot


def test_snapshot_clear_restore_round_trip():
    db = mongomock.MongoClient()["docs_world_test"]
    db["runs"].insert_many([{"_id": "a", "n": 1}, {"_id": "b", "n": 2}])
    db["users"].insert_one({"_id": "u"})

    saved = snapshot(db)
    clear(db)
    assert db["runs"].count_documents({}) == 0
    assert db["users"].count_documents({}) == 0

    db["runs"].insert_one({"_id": "demo"})
    restore(db, saved)

    assert sorted(d["_id"] for d in db["runs"].find()) == ["a", "b"]
    assert [d["_id"] for d in db["users"].find()] == ["u"]
```

`tests/integration/test_docs_world_seed.py`:
```python
"""The made-up demo world the documentation pictures are taken in."""

from seqsetup.models.sequencing_run import RunStatus
from tests.browser.docs_world import DEMO_ADMIN, DEMO_KIT_NAME, DEMO_STAFF, seed_demo

FIXTURE_WORDS = ("browser", "screenshot", "seed", "test")


def test_seed_demo_builds_runs_in_every_state(fresh_app):
    _app, ctx, _db = fresh_app

    ids = seed_demo(ctx)

    status = {key: ctx.run_repo.get_by_id(run_id).status for key, run_id in ids.items()}
    assert status == {
        "draft": RunStatus.DRAFT, "problem": RunStatus.DRAFT, "fill": RunStatus.DRAFT,
        "ready": RunStatus.READY, "archived": RunStatus.ARCHIVED,
    }


def test_seed_demo_users_and_kit(fresh_app):
    _app, ctx, _db = fresh_app

    seed_demo(ctx)

    assert ctx.local_user_repo.get_by_username(DEMO_ADMIN["username"]) is not None
    assert ctx.local_user_repo.get_by_username(DEMO_STAFF["username"]) is not None
    assert ctx.index_kit_repo.get_by_name_and_version(DEMO_KIT_NAME, "1.0") is not None


def test_seed_demo_uses_no_fixture_looking_names(fresh_app):
    _app, ctx, _db = fresh_app

    ids = seed_demo(ctx)

    for run_id in ids.values():
        run = ctx.run_repo.get_by_id(run_id)
        names = [run.run_name] + [s.sample_id for s in run.samples]
        assert not any(w in n.lower() for n in names for w in FIXTURE_WORDS), names
```

- [ ] **Step 2: Run them to see them fail**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_docs_world.py tests/integration/test_docs_world_seed.py -q -p no:cacheprovider`
Expected: collection ERROR `ModuleNotFoundError ... docs_world`.

- [ ] **Step 3: Write `tests/browser/docs_world.py`**

```python
"""A clean, made-up demo world for the documentation screenshots.

The docs module borrows the browser-test database: snapshot() what is
there, clear() it, seed_demo(), take the pictures, restore() it. Nothing
here is real: names, users and index sequences are invented.
"""

from datetime import datetime

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.local_user import LocalUser
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.test_profile import TestProfile
from seqsetup.models.user import UserRole

DEMO_ADMIN = {"username": "dana.demo", "password": "Demo-Docs-2026!", "display_name": "Dana Demo"}
DEMO_STAFF = {"username": "sam.staff", "password": "Demo-Staff-2026!", "display_name": "Sam Staff"}
DEMO_KIT_NAME = "Demo UDI Set A"
DEMO_KIT_VERSION = "1.0"
_T = datetime(2026, 3, 2, 9, 0, 0)
_WELLS = [f"{row}{col:02d}" for col in (1, 2, 3) for row in "ABCDEFGH"]


def snapshot(db) -> dict[str, list[dict]]:
    return {name: list(db[name].find()) for name in db.list_collection_names()}


def clear(db) -> None:
    for name in db.list_collection_names():
        db[name].delete_many({})


def restore(db, snap: dict[str, list[dict]]) -> None:
    clear(db)
    for name, docs in snap.items():
        if docs:
            db[name].insert_many(docs)


def reset_caches() -> None:
    from seqsetup.data import instruments
    from seqsetup.services.validation import clear_validation_cache

    clear_validation_cache()
    instruments._synced_instruments_cache = None


def _seq(n: int, salt: int) -> str:
    """A made-up 8-bp index: distinct for distinct n (7919 is odd, so
    n -> n * 7919 mod 4**8 is one-to-one)."""
    v = (n * 7919 + salt * 104729) % (4 ** 8)
    return "".join("ACGT"[(v >> (2 * k)) & 3] for k in range(8))


def _pair(n: int) -> IndexPair:
    name = f"UDI{n:04d}"
    return IndexPair(
        id=f"{DEMO_KIT_NAME}_{name}", name=name, well_position=_WELLS[n - 1],
        index1=Index(name=name, sequence=_seq(n, 1), index_type=IndexType.I7),
        index2=Index(name=name, sequence=_seq(n, 2), index_type=IndexType.I5),
    )


def _run(run_id, name, status=RunStatus.DRAFT, samples=()) -> SequencingRun:
    run = SequencingRun(
        id=run_id, run_name=name,
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
        created_by=DEMO_ADMIN["username"], updated_by=DEMO_ADMIN["username"],
        created_at=_T, updated_at=_T,
    )
    for s in samples:
        run.add_sample(s)
    return run


def _sample(run_id, n, pair=None, lanes=(1,), test_id="WGS") -> Sample:
    return Sample(
        id=f"{run_id}-s{n:02d}", sample_id=f"SAMPLE-A{n:02d}", sample_name=f"Sample A{n:02d}",
        project="DEMO-PROJECT", test_id=test_id, lanes=list(lanes),
        index_pair=pair, index_kit_name=DEMO_KIT_NAME if pair else None,
    )


def seed_demo(ctx) -> dict[str, str]:
    for spec, role in ((DEMO_ADMIN, UserRole.ADMIN), (DEMO_STAFF, UserRole.STANDARD)):
        user = LocalUser(username=spec["username"], display_name=spec["display_name"],
                         email=f"{spec['username']}@example.org", role=role,
                         created_at=_T, updated_at=_T)
        user.set_password(spec["password"])
        user.updated_at = _T
        ctx.local_user_repo.save(user)

    ctx.index_kit_repo.save(IndexKit(
        name=DEMO_KIT_NAME, version=DEMO_KIT_VERSION, index_mode=IndexMode.UNIQUE_DUAL,
        description="Made-up unique dual index set for the documentation",
        index_pairs=[_pair(n) for n in range(1, 25)], created_by=DEMO_ADMIN["username"],
    ))
    ctx.test_profile_repo.save(TestProfile(
        id="demo-wgs", test_type="WGS", test_name="Whole Genome Sequencing",
        description="Demo test profile", version="1.0.0", synced_at=_T,
    ))

    ids = {"draft": "demo-run-01", "problem": "demo-run-02", "fill": "demo-run-05",
           "ready": "demo-run-03", "archived": "demo-run-04"}
    ctx.run_repo.save(_run(ids["draft"], "DEMO-RUN-01", samples=[
        _sample(ids["draft"], n, _pair(n) if n <= 4 else None) for n in range(1, 9)]))
    ctx.run_repo.save(_run(ids["problem"], "DEMO-RUN-02", samples=[
        _sample(ids["problem"], 1, _pair(1)), _sample(ids["problem"], 2, _pair(1)),
        _sample(ids["problem"], 3, None, test_id="")]))
    ctx.run_repo.save(_run(ids["fill"], "DEMO-RUN-05", samples=[
        _sample(ids["fill"], n) for n in range(1, 7)]))
    ctx.run_repo.save(_run(ids["ready"], "DEMO-RUN-03", RunStatus.READY, samples=[
        _sample(ids["ready"], n, _pair(n)) for n in range(1, 5)]))
    ctx.run_repo.save(_run(ids["archived"], "DEMO-RUN-04", RunStatus.ARCHIVED, samples=[
        _sample(ids["archived"], n, _pair(n)) for n in range(5, 9)]))
    return ids
```
If a constructor argument does not exist on the real model (check `src/seqsetup/models/`), use the real one and write the change in STATUS.md. Do not change the models.

- [ ] **Step 4: Run them to see them pass**

Run: same command as Step 2. Expected: `4 passed`.

- [ ] **Step 5: Commit** — `test(docs): a made-up demo world the pictures are taken in`

---

### Task 3: The gated docs module, the pixi task, the image-reference check, and the login picture

**Files:**
- Create: `tests/browser/test_docs_screenshots.py`
- Create: `tests/unit/test_docs_images.py`
- Modify: `pixi.toml` (`[tasks]` only)
- Modify: `docs/user-guide/authentication.rst` (first real picture)

**Interfaces:**
- Consumes: `shoot` (Task 1); `snapshot/clear/restore/reset_caches/seed_demo/DEMO_ADMIN` (Task 2); `app_ctx`, `base_url`, `page` fixtures from `tests/browser/conftest.py` and pytest-playwright.
- Produces, in `tests/browser/test_docs_screenshots.py`: module fixture `demo -> dict[str, str]` (run ids), fixture `demo_page` (a 1280×800 page logged in as `DEMO_ADMIN`), helper `snap(page, name: str, target, region=None, pad=16)` that saves to `docs/_static/screenshots/<name>.png` (`name` is `"<page>/<shot>"`).

- [ ] **Step 1: Write the failing image-reference test** — `tests/unit/test_docs_images.py`

```python
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
```

Then add one reference to `docs/user-guide/authentication.rst` so the test has something to fail on:

```rst
.. figure:: /_static/screenshots/login/login-form.png
   :alt: The SeqSetup login page with the username and password fields outlined in red.

   The login form (outlined).
```

- [ ] **Step 2: Run it to see it fail**

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_docs_images.py -q -p no:cacheprovider`
Expected: `test_every_referenced_screenshot_exists` FAILS listing `login/login-form.png`.

- [ ] **Step 3: Write the gated module**

```python
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
    ids = seed_demo(app_ctx)
    yield ids
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
```

- [ ] **Step 4: Add the pixi task** — in `pixi.toml` `[tasks]`, after `smoke-browser`:

```toml
docs-screenshots = { cmd = "SEQSETUP_DOCS_SCREENSHOTS=1 PYTHONPATH=src pytest tests/browser/test_docs_screenshots.py -q", depends-on = ["css"] }
```

- [ ] **Step 5: Run the screenshots, then the checks**

Run: the Screenshots command (Global Constraints) → `1 passed`. Open `docs/_static/screenshots/login/login-form.png` with the Read tool and confirm it shows the login form with a red outline and empty fields.
Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_docs_images.py -q -p no:cacheprovider` → `3 passed`.
Run: `PYTHONPATH=src $PY -m pytest tests/browser/test_docs_screenshots.py -q -p no:cacheprovider` (no env var) → `1 skipped`.

- [ ] **Step 6: Commit** — `docs: gated screenshot module, pixi task, image-reference check, login picture`

---

### Task 4: A clean docs build

**Files:**
- Modify: `docs/api-reference/runs.rst`, `docs/api-reference/export.rst`, `docs/admin-guide/sample-api.rst` (the 13 `.. http:get::` blocks)
- Modify: `pixi.toml` (`docs` task only)

- [ ] **Step 1: See it fail**

Run: `$SPHINX -W --keep-going -q -b html docs /tmp/seqsetup-docs-build`
Expected: non-zero exit; 13 × `Unknown directive type "http:get"`.

- [ ] **Step 2: Rewrite each `http:get` block as plain reStructuredText**, keeping its content, in this shape:

```rst
Get the validation PDF
^^^^^^^^^^^^^^^^^^^^^^

``GET /api/runs/{run_id}/validation-pdf``

Get the pre-generated validation report as a PDF document.

:``run_id``: Run UUID.

====== ============================================================
Status Meaning
====== ============================================================
200    Returns the validation report PDF.
401    Missing or invalid Bearer token.
403    Run is a draft.
404    Run not found or validation PDF not yet generated.
429    Rate limit exceeded.
====== ============================================================
```

Check every path, parameter and status code against `src/seqsetup/api/app.py` (and `deps.py`). Where the docs disagree with the code, the code wins; note each correction in STATUS.md.

- [ ] **Step 3: Make the build strict** — in `pixi.toml`: `docs = "sphinx-build -W --keep-going -b html docs docs/_build/html"`

- [ ] **Step 4: See it pass** — the Docs build command prints nothing and exits 0.

- [ ] **Step 5: Commit** — `docs: plain reStructuredText for the API routes; the docs build fails on warnings`

---

### Tasks 5–12: Guide pages (same shape each)

Each of these tasks follows the same steps. Only the **Pages / Pictures / Read first** list differs.

- [ ] **Step 1: Read first** — the templates and routes listed, and `/home/parlar_ai/seqsetup-audit-run/ROUTES.md` for the route inventory. Write down (STATUS.md) every behavior the page will claim, each with the file:line that does it.
- [ ] **Step 2: Add a failing reference** — write the `.rst` skeleton with its `.. figure::` lines (names from the Pictures list). Run `tests/unit/test_docs_images.py` → FAILS listing the missing PNGs.
- [ ] **Step 3: Add one test function per picture** to `tests/browser/test_docs_screenshots.py`, in the order the reader meets the screens. Pattern:

```python
def test_samples_paste_preview(demo_page, base_url, demo):
    page = demo_page
    page.goto(f"{base_url}/runs/{demo['draft']}")
    # ... the exact clicks a user makes, with selectors read from the templates ...
    preview = page.locator("#paste-preview")          # selector from the template
    snap(page, "samples/paste-preview", preview.get_by_role("button", name="Add"),
         region=preview)
```
Selectors come from the templates — never guessed. A step the user takes is a step the test takes.
- [ ] **Step 4: Run the Screenshots command** → all pass. **Open every new PNG with the Read tool** and check: the red outline is on the control the caption names; no fixture data, no password; readable at the crop size. A picture nobody looked at is not done.
- [ ] **Step 5: Write the page text** — plain words, numbered steps, UI labels exactly as rendered, a figure where the screen changes, a `.. note::` or `.. warning::` for anything with clinical weight (e.g. two samples in one lane must not share an index).
- [ ] **Step 6: Run** `tests/unit/test_docs_images.py` → 3 passed, and the Docs build → 0 warnings.
- [ ] **Step 7: Commit** the `.rst`, the PNGs and the test changes — `docs(<area>): ...`

**Task 5 — Getting around** · Pages: `user-guide/authentication.rst` (finish), `user-guide/dashboard.rst`, `user-guide/run-setup.rst` · Pictures: `login/login-form` (exists), `dashboard/tabs`, `dashboard/search`, `dashboard/new-run-button`, `new-run/*` (one per wizard step, incl. the template choice and the red "too many cycles" message) · Read first: `templates/_app_shell.html`, `templates/dashboard*`, `templates/wizard/`, `routes/dashboard.py`, `routes/wizard.py`, `routes/runs.py`.

**Task 6 — Samples** · Page: `user-guide/samples.rst` · Pictures: `samples/add-button`, `samples/paste-form`, `samples/paste-preview` (including the lines-read vs samples-read count), `samples/sample-table`, `samples/row-edit`, and — only if the import controls render without a live LIMS — `samples/worklist-import`; otherwise describe the LIMS import in text from the code and say in STATUS.md why there is no picture · Read first: `templates/runs/_sample_section.html`, `_paste_form.html`, `_paste_preview.html`, `routes/samples.py`, `services/paste_preview.py`, `services/sample_parser.py`.

**Task 7 — Indexes** · Page: `user-guide/index-assignment.rst` · Pictures: `indexes/kit-picker`, `indexes/drag-drop` (chip and drop zone), `indexes/several-in-order` (shift-click selection), `indexes/ticked-rows` (confirm dialog text quoted, not pictured), `indexes/fill-preview`, `indexes/fill-assigned` · Use run `demo['fill']` for "fill in order" · Read first: `templates/wizard/_index_kit_dropdown.html`, `_index_kit_panel*.html`, `templates/runs/_index_fill_preview.html`, `static/js/app.js` (drag/drop, keyboard, ticked rows), `services/index_fill.py`, `routes/samples.py`.

**Task 8 — Lanes and override cycles** · Pages: `user-guide/lane-assignment.rst`, `user-guide/override-cycles.rst` · Pictures: `lanes/bulk-panel`, `lanes/row-lanes`, `override-cycles/cell`, `override-cycles/bulk` · Read first: `templates/wizard/_sample_table.html`, the bulk panel templates, `services/cycle_calculator.py`, `routes/samples.py`.

**Task 9 — Check, Ready, downloads, archive** · Pages: `user-guide/validation.rst`, `user-guide/export.rst` · Pictures: `check/panel`, `check/validation-issues` (run `demo['problem']`), `check/heatmaps`, `check/color-balance`, `ready/mark-ready-refused`, `ready/mark-ready` (promote a clean run), `ready/back-to-draft`, `export/panel-ready`, `export/panel-archived`, `archive/archive-button` · Read first: `templates/runs/_export_panel.html`, `templates/validation/`, `routes/runs.py` (status changes), `routes/export.py`, `services/validation.py`.

**Task 10 — Templates and change history** · New pages: `user-guide/templates.rst`, `user-guide/change-history.rst`; add both to `user-guide/index.rst` · Pictures: `templates/save-as-template`, `templates/new-run-from-template`, `templates/manage`, `history/change-history` · Read first: `routes/run_templates.py`, the change-history template and route.

**Task 11 — Admin: people and access** · Pages: `admin-guide/local-users.rst`, `admin-guide/authentication.rst`, `admin-guide/api-tokens.rst`, new `admin-guide/logs.rst` (add to `admin-guide/index.rst`) · Pictures: `admin/users-list`, `admin/user-edit`, `admin/auth-settings`, `admin/api-tokens`, `admin/api-token-created` (blank out nothing — the demo token is made up and shown once; do not reuse it anywhere), `admin/logs` · Read first: `routes/admin/*.py`, `routes/local_users.py`, `routes/api_tokens.py`, `templates/admin/`.

**Task 12 — Admin: kits, instruments, profiles, LIMS** · Pages: `admin-guide/index-kits.rst`, `admin-guide/instruments.rst`, `admin-guide/profiles.rst`, `admin-guide/sample-api.rst` · Pictures: `admin/index-kits-list`, `admin/index-kit-upload`, `admin/index-kit-detail`, `admin/instruments`, `admin/config-sync`, `admin/lims-settings` · Read first: `routes/indexes.py`, `routes/admin/instruments.py`, `routes/admin/config_sync.py`, `routes/admin/sample_api.py`, `routes/profiles.py`, `templates/admin/`, `templates/indexes/`.

---

### Task 13: Fix wrong facts elsewhere

**Files:** `docs/getting-started/*.rst`, `docs/architecture/*.rst`, `docs/development/*.rst`, `docs/index.rst`

- [ ] **Step 1:** In `getting-started/installation.rst`, remove the published `admin` / `admin123` login. Read how the first admin is really created today (`src/seqsetup/startup.py`, `services/auth*`, `config/users.yaml`, `routes/local_users.py`) and describe exactly that — with a strong-password instruction and no example password.
- [ ] **Step 2:** Read each remaining page in these folders against the code. Fix only statements that are false today (routes, file paths, feature names, commands, the feature list on `index.rst`). Record each fix with the file:line that proves it in STATUS.md. Do not restructure pages.
- [ ] **Step 3:** Docs build → 0 warnings; `tests/unit/test_docs_images.py` → 3 passed.
- [ ] **Step 4: Commit** — `docs: correct statements that no longer match the app`

---

### Final: regenerate everything and verify

- [ ] Delete `docs/_static/screenshots/` and run the Screenshots command → all pass; `git status` shows no deleted PNGs (every picture came back).
- [ ] `tests/unit/test_docs_images.py` → 3 passed; Docs build → 0 warnings, exit 0.
- [ ] Server suite → **1550 + the new unit/integration tests**, 0 error. Browser suite → **87 + 3 harness tests passed, the docs tests skipped**, 0 error. Name the term if a number differs.
- [ ] Open every PNG once more with the Read tool; list any that show fixture data, a password, or an outline on the wrong control, and fix them.
- [ ] Identity checks (see the run prompt) — paste real output into STATUS.md.
