# GUI Design-System Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace SeqSetup's ad-hoc styling with one consistent, token-driven design system (Deep Teal Clinical palette), reconcile the `components.css`-vs-inline-Tailwind split, and fix the verified GUI bugs — all behavior-preserving except an enumerated set of accessibility additions.

**Architecture:** Tokens-first. Add a semantic design-token layer to `components.css` `:root`, repoint every component rule and raw hex onto it, fix the bugs, then bridge Tailwind to the same tokens and migrate the inline-Tailwind pages. The brand stays **blue** through every structural phase so each screenshot matches the baseline except intended deltas; the blue→teal flip lands as **one isolated, fully-reviewed commit at the very end** (Phase 4). `components.css` is compiled into `app.css` (the only stylesheet the browser loads), so **every CSS change requires `pixi run css`**.

**Tech Stack:** Tailwind v4 (CLI build → `app.css`), hand-written `components.css`, Jinja2 templates, Alpine.js + HTMX (untouched hooks), Playwright (browser gate), pytest, Pixi.

**Spec:** `docs/superpowers/specs/2026-06-10-gui-design-system-refresh-design.md` (read it first).

---

## Conventions used by every task

**The CSS gate** (referenced as "run the CSS gate" below) — run after any CSS/template/JS change:

```bash
pixi run css            # rebuild app.css from input.css (+ components.css)
pixi run test           # unit + integration (must stay green)
pixi run smoke-browser  # 3 wiring checks + (after Task 0.3) screenshot + a11y checks
```

**Screenshot diff** — after Task 0.3 exists: run `pytest tests/browser/test_screenshots.py -v`, then `python tools/screenshot_diff.py` to compare `tests/browser/screenshots/current/` against `tests/browser/screenshots/baseline/`. "Zero unintended diff" means the only changed pixels are the deltas the task intends.

**Never touch:** any class/id used as an HTMX target (`#sample-section`, `#form-errors`, `#error-banner`, `#toast-stack`, `#ldap-config-form`, `#dashboard`, `#run-config-panel`, `#cycle-config`, `#export-panel`, `#index-list-container`, …), any Alpine binding (`x-data`/`x-show`/`x-for`, `toastStack`), or any `on*`/`hx-*`/`draggable` attribute. Before deleting any selector, grep it as both `class=` and `id=` across `src/seqsetup/templates/`, `src/seqsetup/static/js/`, and `src/seqsetup/routes/`.

**Commit cadence:** one commit per task (or per step where noted). Branch: `gui-design-system-refresh` (already checked out).

---

## File structure (what each touched file is responsible for)

| File | Role in this work |
|---|---|
| `src/seqsetup/static/css/components.css` | **Primary.** The `:root` token block + all component rules. Phases 1a/1b/1c edit this. |
| `src/seqsetup/static/css/input.css` | Tailwind entry; gains the `@theme` bridge (Phase 2). |
| `src/seqsetup/static/js/app.js` | Gains `handleIndexKeydown` helper (Phase 3). |
| `src/seqsetup/templates/_base.html` | Toast markup → `.toast` classes + `aria-live` (Phase 3). |
| `src/seqsetup/templates/_app_shell.html` | Skip-link, SVG chevron, `aria-current`, brand utilities (Phase 3). |
| `src/seqsetup/templates/dashboard.html`, `login.html`, `admin/*.html`, `indexes/*.html`, `validation/*.html` | Brand `blue-*` → semantic classes; table scroll wrappers; admin fieldset boxing (Phase 3). |
| `src/seqsetup/templates/wizard/_draggable_index*.html` | `tabindex`/`onkeydown`/`aria-label` for keyboard assign (Phase 3). |
| `tests/browser/conftest.py` | Representative seed data for screenshots (Phase 0). |
| `tests/browser/test_screenshots.py` | **New.** Screenshot capture across pages (Phase 0). |
| `tests/browser/test_a11y.py` | **New.** focus-visible + keyboard-assign + axe checks (Phase 0/3). |
| `tools/screenshot_diff.py` | **New.** Baseline-vs-current PNG diff (Phase 0). |
| `pixi.toml` | `smoke-browser` depends-on `css` (Phase 0). |

---

## Phase 0 — Baseline + verification harness

No visual change. Builds the regression oracle the later phases depend on.

### Task 0.1: Make the browser gate rebuild CSS first

**Files:** Modify `pixi.toml` (the `smoke-browser` task).

- [ ] **Step 1: Edit the task** so it depends on `css`:

```toml
smoke-browser = { cmd = "PYTHONPATH=src pytest tests/browser -v", depends-on = ["css"] }
```

- [ ] **Step 2: Verify** `pixi run smoke-browser` rebuilds `app.css` then runs the suite (watch for the tailwindcss build line, then pytest).

```bash
pixi run smoke-browser
```
Expected: CSS builds, then the existing 3 browser tests PASS.

- [ ] **Step 3: Commit**

```bash
git add pixi.toml && git commit -m "build: smoke-browser depends on css build"
```

### Task 0.2: Seed representative data for screenshots

The current `app_server` fixture seeds one minimal draft run. Screenshots of the heatmap, index assignment, and status states need richer, deterministic data.

**Files:** Modify `tests/browser/conftest.py` (the `app_server` seeding block, ~lines 110-120).

- [ ] **Step 1: Read** `tests/browser/conftest.py` fully to learn the existing seed pattern (`SequencingRun(...)`, `ctx.run_repo.save(...)`, how the admin user + ctx are built).

- [ ] **Step 2: Add** a deterministic seed helper after the existing seed run. Build (using the same model imports already in the file — `SequencingRun`, `Sample`, `RunStatus`, and the index-kit/profile repos the app exposes on `ctx`):
  - a **draft run** "Screenshot draft" with ~6 samples, some indexed (so `.sample-row.has-index` + drop zones render) and some not;
  - a run with **index collisions** (two samples sharing an i7+i5) promoted/validated so the validation heatmap + issues render with `dist-0` cells;
  - a **ready** run and an **archived** run (so dashboard tabs are non-empty);
  - at least one **index kit** and one **test profile** so the wizard/index panels populate.

  Use fixed IDs/names/timestamps (no `datetime.now()` — pass fixed datetimes) so screenshots are stable. Keep all values inside model length bounds.

- [ ] **Step 3: Verify** the app still boots and the existing smoke passes against the richer seed:

```bash
pixi run smoke-browser
```
Expected: PASS (no fixture errors; seed data committed to mongomock at session start).

- [ ] **Step 4: Commit**

```bash
git add tests/browser/conftest.py && git commit -m "test: seed representative runs/kits for screenshot harness"
```

### Task 0.3: Screenshot capture module + diff tool (the regression oracle)

**Files:** Create `tests/browser/test_screenshots.py`, create `tools/screenshot_diff.py`.

- [ ] **Step 1: Write** `tests/browser/test_screenshots.py`. Validation tabs are Alpine `x-show` (no URL param) and the dashboard status tabs are HTMX fragments — both must be captured by **clicking**, not by navigating. Use two tests: simple navigations, and interaction-based captures.

```python
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
    ("dashboard",        "/"),
    ("run-editor",       "/runs/{draft_run_id}"),
    ("validation-issues","/runs/{collision_run_id}/validation"),  # default tab = issues
    ("indexes-list",     "/indexes"),
    ("admin-users",      "/admin/users"),
    ("admin-auth",       "/admin/authentication"),
    ("admin-instruments","/admin/instruments"),
]

def _shoot(page, name):
    OUT.mkdir(parents=True, exist_ok=True)
    page.wait_for_load_state("networkidle")
    page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)

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
        _shoot(page, f"dashboard-{label.lower()}")

@pytest.mark.browser
def test_capture_validation_tabs(logged_in_page, base_url, seeded_ids):
    page = logged_in_page
    page.goto(base_url + f"/runs/{seeded_ids['collision_run_id']}/validation")
    for label, name in [("Heatmaps","validation-heatmaps"),
                        ("Color Balance","validation-colorbalance"),
                        ("Dark Cycles","validation-darkcycles")]:
        page.get_by_text(label, exact=False).first.click()
        _shoot(page, name)
```

  (Add a `seeded_ids` fixture in `conftest.py` returning the fixed run IDs from Task 0.2. Confirm the exact tab-button text/selectors against `validation/page.html` and `dashboard.html` before relying on `get_by_role`/`get_by_text`; adjust to the real markup — do not invent selectors. The wizard page is intentionally omitted because `/runs/new` is a POST that creates a draft; capture the wizard later by following that POST if a static GET wizard page is confirmed.)

- [ ] **Step 2: Write** `tools/screenshot_diff.py` — compares `baseline/` vs `current/` PNGs with Pillow, prints per-image changed-pixel counts, exits non-zero if any non-baselined image exists:

```python
import sys
from pathlib import Path
from PIL import Image, ImageChops

root = Path("tests/browser/screenshots")
base, cur = root / "baseline", root / "current"
fail = False
base_names = {p.name for p in base.glob("*.png")}
cur_names = {p.name for p in cur.glob("*.png")}

for name in sorted(base_names - cur_names):          # baseline image not re-captured
    print(f"MISSING from current/: {name}"); fail = True
for name in sorted(cur_names - base_names):          # new image with no baseline
    print(f"NEW (no baseline): {name}"); fail = True

for name in sorted(base_names & cur_names):
    a = Image.open(base / name).convert("RGB")
    c = Image.open(cur / name).convert("RGB")
    if a.size != c.size:
        print(f"SIZE CHANGED: {name} {a.size} -> {c.size}"); fail = True; continue
    bbox = ImageChops.difference(a, c).getbbox()
    if bbox is None:
        print(f"{name}: 0 changed px"); continue
    n = sum(1 for px in ImageChops.difference(a, c).getdata() if px != (0, 0, 0))
    print(f"{name}: {n} changed px  bbox={bbox}"); fail = True

print("FAIL — visual diff detected" if fail else "PASS — no visual diff")
sys.exit(1 if fail else 0)   # non-zero so CI / the gate actually catches regressions
```

  (Add `pillow` as a dev dep: `pixi add --feature dev pillow`.) "Zero unintended diff" for a task = run this, and for every image that legitimately changed, **review it**, then re-copy that one PNG from `current/` into `baseline/` so the next task starts from a clean `PASS`.

- [ ] **Step 3: Capture the baseline.** Run the screenshot test, then promote `current/` → `baseline/`:

```bash
pixi run smoke-browser   # builds css + runs screenshots into current/
cp -r tests/browser/screenshots/current tests/browser/screenshots/baseline
```
Expected: ~13 PNGs in `baseline/`.

- [ ] **Step 4: Commit** the harness + baseline:

```bash
git add tests/browser/test_screenshots.py tools/screenshot_diff.py tests/browser/screenshots/baseline pixi.toml pixi.lock
git commit -m "test: screenshot regression oracle with committed baseline"
```

### Task 0.4: Accessibility helper (axe-core) + focus reachability check

**Files:** Create `tests/browser/test_a11y.py`.

- [ ] **Step 1: Vendor axe-core locally.** The app's CSP is `script-src 'self' 'unsafe-eval'`, so a CDN `<script>` (`add_script_tag(url=…)`) is **blocked**. Download axe-core ~4.9 to `src/seqsetup/static/js/vendor/axe.min.js` (it is injected via `page.evaluate`, which runs through CDP and is not subject to page CSP; `'unsafe-eval'` covers it regardless). If the box is offline, copy it from a machine that has it; do not rely on the CDN.

- [ ] **Step 2: Write** a real *no-new-violations* gate (subset-of-committed-baseline, not a no-op assert):

```python
import json, pytest
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
```

- [ ] **Step 3: Run twice** — first run records & commits `a11y_baseline.json` (skips), second run enforces it:

```bash
pixi run smoke-browser   # run 1: records baseline (test skips)
pixi run smoke-browser   # run 2: PASS (no new violations)
```

- [ ] **Step 4: Commit**

```bash
git add tests/browser/test_a11y.py tests/browser/a11y_baseline.json src/seqsetup/static/js/vendor/axe.min.js
git commit -m "test: axe-core no-new-a11y-violations gate (vendored, CSP-safe)"
```

---

## Phase 1a — Token layer (additive, zero visual change)

### Task 1a.1: Add the design-token block to `:root`

Brand stays blue; AA value bumps deferred to 1c; teal flip deferred to Phase 4. So this is genuinely zero-diff.

**Files:** Modify `src/seqsetup/static/css/components.css` (replace the `:root{…}` at lines 17-29).

- [ ] **Step 1: Replace** the `:root` block with:

```css
:root {
    /* ===== Surfaces & structure ===== */
    --bg: #f8fafc;
    --surface: #ffffff;
    --surface-sunken: #f1f5f9;
    --border: #e2e8f0;
    --border-strong: #cbd5e1;

    /* ===== Text (AA bumps applied in Phase 1c) ===== */
    --text: #1e293b;
    --text-muted: #64748b;
    --text-subtle: #64748b;

    /* ===== Brand — blue now; flips to teal in Phase 4 ===== */
    --primary: #2563eb;
    --primary-hover: #1d4ed8;
    --primary-fg: #ffffff;

    /* ===== Semantic states (fill / soft-bg / on-bg text) ===== */
    --success: #16a34a; --success-bg: #dcfce7; --success-fg: #166534;
    --warning: #ca8a04; --warning-bg: #fef3c7; --warning-fg: #92400e;
    --danger:  #dc2626; --danger-bg:  #fef2f2; --danger-fg:  #991b1b;
    --info:    #2563eb; --info-bg:    #dbeafe; --info-fg:    #1e40af;

    /* ===== Index coding — unchanged for the entire refresh ===== */
    --accent-i7: #2563eb; --accent-i5: #ea580c; --accent-pair: #8b5cf6;

    /* ===== Sidebar ===== */
    --sidebar-bg: #1e293b; --sidebar-fg: #e2e8f0; --sidebar-muted: #94a3b8;
    --sidebar-hover: #334155; --sidebar-accent: #2dd4bf;

    /* ===== Focus (opaque double ring; tracks --primary) ===== */
    --focus-ring: 0 0 0 2px var(--surface), 0 0 0 4px var(--primary);

    /* ===== Type ===== */
    --fs-2xs: .75rem; --fs-xs: .8125rem; --fs-sm: .875rem; --fs-base: 1rem;
    --fs-lg: 1.125rem; --fs-xl: 1.25rem; --fs-2xl: 1.5rem;
    --lh-tight: 1.3; --lh-base: 1.5;
    --fw-normal: 400; --fw-medium: 500; --fw-semibold: 600; --fw-bold: 700;
    --font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;

    /* ===== Spacing / radius / elevation ===== */
    --space-1: .25rem; --space-2: .5rem; --space-3: .75rem; --space-4: 1rem;
    --space-5: 1.5rem; --space-6: 2rem; --space-8: 3rem;
    --radius-sm: 4px; --radius-md: 8px; --radius-pill: 999px; --radius-circle: 50%;
    --shadow-xs: 0 1px 2px rgba(15,23,42,.06);
    --shadow-sm: 0 1px 3px rgba(15,23,42,.08), 0 1px 2px rgba(15,23,42,.06);
    --shadow-md: 0 4px 12px rgba(15,23,42,.10);
    --shadow-lg: 0 10px 30px rgba(15,23,42,.16);

    /* ===== Back-compat aliases (old names still referenced by rules) ===== */
    --card-bg: var(--surface);
    --secondary: var(--text-subtle);
}
```

- [ ] **Step 2: Run the CSS gate.** Expected: build OK, `pixi run test` green, screenshots **zero unintended diff** (every old `var(--…)` resolves to its prior value; `--secondary` #64748b == `--text-subtle`).

```bash
pixi run css && python tools/screenshot_diff.py
```
Expected: `worst=0`, every image "0 changed px".

- [ ] **Step 3: Commit**

```bash
git add src/seqsetup/static/css/components.css && git commit -m "style(tokens): add semantic design-token layer (zero visual change)"
```

---

## Phase 1b — Repoint component rules onto tokens (structural; small intended deltas)

The hex/size sprawl moves onto token names while keeping current values, so screenshots stay identical **except** the deliberate additions called out per task (button hovers/focus rings/shadows). Hex inventory to repoint (counts from `components.css`):

| Literal | → token | Notes |
|---|---|---|
| `#2563eb` (×10) | `var(--primary)` **or** `var(--accent-i7)` | brand usages → `--primary`; i7 index usages (`.i7-index`, `.index-seq.i7`, `.index-i7-name-compact`, `.drop-zone.i7-drop`) → `--accent-i7` |
| `#1d4ed8` (×2) | `var(--primary-hover)` | |
| `#ea580c` (×7) | `var(--accent-i5)` | i5 index coding |
| `#8b5cf6` (×2) | `var(--accent-pair)` | paired index |
| `#dc2626` (×13) | `var(--danger)` | |
| `#16a34a` (×2) | `var(--success)` | (keep heatmap `.dist-7` literal — see 1c) |
| `#64748b` (×5) | `var(--text-muted)` / `var(--text-subtle)` | per usage |
| `#e2e8f0` (×4) | `var(--border)` | |
| `#1e293b` (×3) | `var(--text)` or `var(--sidebar-bg)` | sidebar bg → `--sidebar-bg` |
| `#334155` (×3) | `var(--sidebar-hover)` | sidebar |
| `#94a3b8` (×2) | `var(--sidebar-muted)` | sidebar |
| `#fbbf24` (×2) | keep or `--warning` family | admin summary accent (decide in 1b, screenshot-verify) |
| status-badge hex (`#fef3c7/#92400e`, `#dbeafe/#1e40af`, `#e5e7eb/#374151`) | `.badge--*` token pairs (Task 1b.2) | |

Pale one-off tints (`#fee2e2`, `#fef3c7`, `#dcfce7`, `#fffbeb`, `#f0f9ff`, …) → the matching `--*-bg` token. Heatmap ramp, login gradient (`#667eea/#764ba2`), and dead-block hex are handled in 1c (or deleted).

### Task 1b.1: Buttons → tokens + hover-all-variants + focus ring

**Files:** Modify `components.css` `.btn`/variants (lines ~357-447, 1995-2013).

- [ ] **Step 1: Repoint + extend.** Replace the button rules so all variants use tokens, every solid variant gains a hover, radius uses `--radius-sm`, and a shared focus ring is added:

```css
.btn, button {
    padding: var(--space-2) var(--space-4);
    border-radius: var(--radius-sm);
    font-size: var(--fs-sm);
    cursor: pointer; border: none;
    transition: background .15s, box-shadow .15s;
}
.btn-primary   { background: var(--primary);   color: var(--primary-fg); }
.btn-primary:hover   { background: var(--primary-hover); box-shadow: var(--shadow-sm); }
.btn-secondary { background: var(--secondary); color: #fff; }
.btn-secondary:hover { background: var(--text-muted); box-shadow: var(--shadow-sm); }
.btn-danger    { background: var(--danger);    color: #fff; }
.btn-danger:hover    { background: #b91c1c; box-shadow: var(--shadow-sm); }
.btn-warning   { background: var(--warning);   color: #fff; }
.btn-warning:hover   { background: #a16207; box-shadow: var(--shadow-sm); }
.btn:focus-visible, button:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.btn.disabled, .btn:disabled { opacity: .5; pointer-events: none; cursor: not-allowed; }
```

- [ ] **Step 2: CSS gate + screenshot diff.** Expected deltas only: solid buttons now darken on hover (not visible in static screenshots) and show a focus ring on keyboard focus. Static full-page screenshots should be ~0 changed px (hover/focus aren't captured at rest).

- [ ] **Step 3: Commit** `style(buttons): token-driven fills, hover on all variants, focus-visible ring`.

### Task 1b.2: Status badge primitive

**Files:** Modify `components.css` (`.status-draft/ready/archived` ~1536-1550, `.run-status-badge` ~1643, `.validate-status-badges` ~271-309).

- [ ] **Step 1: Add** a `.badge` primitive + modifiers, and make the existing status classes compose it (keep the existing selectors so template hooks are unchanged):

```css
.badge, .status-draft, .status-ready, .status-archived, .run-status-badge {
    display: inline-flex; align-items: center; gap: .35rem;
    padding: .15rem .55rem; border-radius: var(--radius-pill);
    font-size: var(--fs-2xs); font-weight: var(--fw-semibold); line-height: 1.4;
}
.status-draft    { background: var(--warning-bg); color: var(--warning-fg); }
.status-ready    { background: var(--info-bg);    color: var(--info-fg); }
.status-archived { background: var(--surface-sunken); color: var(--text-muted); }
.badge--success { background: var(--success-bg); color: var(--success-fg); }
.badge--warning { background: var(--warning-bg); color: var(--warning-fg); }
.badge--danger  { background: var(--danger-bg);  color: var(--danger-fg); }
.badge--info    { background: var(--info-bg);    color: var(--info-fg); }
.badge--neutral { background: var(--surface-sunken); color: var(--text-muted); }
```

- [ ] **Step 2: CSS gate + screenshot diff.** Expected delta: status pills become fully-rounded and slightly recolored to the AA token pairs on the dashboard/run pages. Update the baseline for these images **only if** the change matches intent (re-copy those specific PNGs into `baseline/` after visual review).

- [ ] **Step 3: Commit** `style(badges): single pill primitive composed by status classes`.

### Task 1b.3: Index accents, drop zones, sample-table type scale

**Files:** Modify `components.css` (`.i7-index`/`.i5-index`/`.draggable-pair`/`.index-seq.i7|i5` ~1891-1969; `.drop-zone*`; `.sample-table` cells ~454-578; `.index-seqs`/`.index-seq-compact` ~878-1044).

- [ ] **Step 1: Repoint** all i7/i5/pair literals to `--accent-i7/i5/pair`; raise the smallest fonts: index/sequence/well text from `0.6–0.7rem` to `var(--fs-xs)` (sequences) / `var(--fs-2xs)` (names/wells), add `font-variant-numeric: tabular-nums` to `.index-cell`/`.lanes-display`/sequence cells; give sample-table cells `var(--fs-2xs)`; add row hover:

```css
.sample-row:hover { background: var(--surface-sunken); }
.index-seqs, .index-seqs-inline, .index-seq-compact { font-size: var(--fs-xs); }
.index-cell, .lanes-display { font-variant-numeric: tabular-nums; }
/* Sticky header so column meaning stays visible on long sample lists.
   Sticks within the table's scroll region; the existing `#sample-section
   { overflow-x: auto }` makes that region a scroll container — verify the
   header stays pinned and bump top/z-index if it detaches. */
.sample-table th { position: sticky; top: 0; z-index: 2; background: var(--surface-sunken); }
```

- [ ] **Step 2: CSS gate + screenshot diff.** Expected delta: index sequences render larger (≥13px), tables gain row-hover, and the header pins on scroll. Manually scroll a long sample table to confirm the header stays put and nothing overlaps. Review run-editor + validation screenshots; re-baseline the intended ones.

- [ ] **Step 3: Commit** `style(table,index): tabular nums, raised sequence font floor, row hover, sticky header`.

---

## Phase 1c — Bug-fix CSS + AA bumps + dead-CSS deletion

### Task 1c.1: Define `.config-panel` (fixes 6 run-editor fieldsets)

**Files:** Modify `components.css` (add near the other `.config-*` rules).

- [ ] **Step 1: Add:**

```css
.config-panel {
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-xs);
    background: var(--surface);
    padding: var(--space-4);
    margin: 0 0 var(--space-4);
}
.config-panel > legend {
    font-size: var(--fs-2xs); font-weight: var(--fw-semibold);
    text-transform: uppercase; letter-spacing: .03em;
    color: var(--text-muted); padding: 0 var(--space-2);
}
```

- [ ] **Step 2: CSS gate + screenshot diff.** Expected delta: the 6 fieldsets (instrument/cycle/samples/validate/details/export) lose the browser groove border and gain the clean card look on the run editor. Re-baseline `run-editor.png`.

- [ ] **Step 3: Commit** `fix(run-editor): define .config-panel so fieldsets stop using groove border`.

### Task 1c.2: Fix the broken index-panel layout (palette beside table)

**Files:** Modify `components.css` (add rules for `.run-page-with-index-panel` / `.run-page-sample-panel`, mirroring `.wizard-step3-layout`).

- [ ] **Step 1: Add:**

```css
.run-page-with-index-panel {
    display: grid;
    grid-template-columns: 320px 1fr;
    gap: var(--space-4);
    align-items: start;
}
.run-page-sample-panel { min-width: 0; overflow-x: auto; }
@media (max-width: 1000px) {
    .run-page-with-index-panel { grid-template-columns: 1fr; }
}
```

- [ ] **Step 2: CSS gate.** Manually open a draft run with un-indexed samples and confirm the "Available Indexes" palette sits **left of** the table and drag-drop still assigns. Re-baseline `run-editor.png`.

- [ ] **Step 3: Commit** `fix(run-editor): grid so index palette sits beside the sample table`.

### Task 1c.3: Reconcile paste-section, message classes, ldap selector, AA bumps

**Files:** Modify `components.css`.

- [ ] **Step 1: Add aliases** so the run-editor paste box (`.paste-section*`) gets the existing styled `.paste-details*` treatment, define the missing message classes, repoint the dead ldap class selector, and apply the AA value bumps:

```css
/* Paste section name reconcile (template uses .paste-section*, CSS had .paste-details*) */
.paste-section { border: 1px solid var(--border); border-radius: var(--radius-sm); margin-bottom: var(--space-4); }
.paste-section-summary { padding: var(--space-3) var(--space-4); cursor: pointer; background: var(--surface-sunken); font-weight: var(--fw-medium); font-size: var(--fs-sm); }
.paste-section[open] .paste-section-summary { border-bottom: 1px solid var(--border); }
.paste-section-content { padding: var(--space-4); }

/* Missing inline-message classes (mirror .error-message) */
.success-message { color: var(--success-fg); background: var(--success-bg); padding: var(--space-2); border-radius: var(--radius-sm); margin-top: var(--space-2); }
.warning-message { color: var(--warning-fg); background: var(--warning-bg); padding: var(--space-2); border-radius: var(--radius-sm); margin-top: var(--space-2); }
```

- [ ] **Step 2: Repoint** the LDAP card: change the `.ldap-config-form` selector(s) (~lines 2226-2256) to `#ldap-config-form` (the live element uses `id=`, not `class=`).

- [ ] **Step 3: Apply AA bumps** in `:root`: `--text: #0f172a;` `--text-muted: #475569;` `--warning: #b45309;`.

- [ ] **Step 4: CSS gate + screenshot diff.** Expected deltas: slightly darker muted text app-wide (AA), styled paste box on the run editor, boxed LDAP card on `/admin/authentication`. Review + re-baseline affected images (most pages change subtly via `--text-muted`).

- [ ] **Step 5: Commit** `fix(css): paste-section, success/warning-message, #ldap-config-form, AA text/warning`.

### Task 1c.4: Focus-visible on inputs + links + chips; `.is-invalid`

**Files:** Modify `components.css` (`.form-group input/select/textarea` ~328-355; add global focus rules).

- [ ] **Step 1: Replace** the faint input focus ring with the token ring and add a validity state + link focus:

```css
.form-group input:focus-visible, .form-group select:focus-visible, .form-group textarea:focus-visible,
.settings-input:focus-visible, .index-filter-input:focus-visible,
.mismatch-input:focus-visible, .override-cycles-input:focus-visible,
.paste-textarea:focus-visible, a:focus-visible {
    outline: none; box-shadow: var(--focus-ring); border-color: var(--primary);
}
.form-group input.is-invalid, .settings-input.is-invalid,
.form-group input:user-invalid { border-color: var(--danger); background: var(--danger-bg); }
```

- [ ] **Step 2: CSS gate.** Confirm via the run editor that tabbing shows a clear ring on inputs and the bulk-action inputs. Static screenshots ~unchanged.

- [ ] **Step 3: Commit** `a11y(forms): perceptible focus-visible ring + .is-invalid/:user-invalid`.

### Task 1c.5: Sidebar tokens + active state; header; chevron prep

**Files:** Modify `components.css` (`.sidebar*` ~1400-1520, `.admin-section summary` ~2415, `.app-header` ~47-79).

- [ ] **Step 1: Repoint** sidebar hex to `--sidebar-*`, give the active nav item a left-border accent distinct from hover, drop the dead `.app-header h1`, replace literal `bold`, add header shadow:

```css
.sidebar { background: var(--sidebar-bg); color: var(--sidebar-fg); }
.sidebar .nav-item { color: var(--sidebar-muted); }
.sidebar .nav-item:hover { background: var(--sidebar-hover); color: #fff; }
.sidebar .nav-item.active {
    background: var(--sidebar-hover); color: #fff;
    border-left: 3px solid var(--sidebar-accent); font-weight: var(--fw-semibold);
    padding-left: calc(1rem - 3px);
}
.app-header { box-shadow: var(--shadow-xs); }
.app-brand-text { font-weight: var(--fw-bold); }
```
  (Delete the `.app-header h1` block at ~56-59.) The `▶` → SVG chevron is a markup change, done in Phase 3 (Task 3.5).

- [ ] **Step 2: CSS gate + screenshot diff.** Expected delta: active sidebar item now has a teal-ish left accent; header gains a hairline shadow. Re-baseline shell-bearing pages.

- [ ] **Step 3: Commit** `style(sidebar,header): tokenize chrome, distinct active state, header shadow`.

### Task 1c.6: Heatmap legend fix + perceptual ramp + non-color danger cue

**Files:** Modify `components.css` (`.heatmap-cell.dist-*` 2584-2594, `.legend-item.dist-*` 2616-2620); modify `templates/validation/_heatmaps_tab.html` (legend markup) and `_color_balance_tab.html` (channel-demo classes).

- [ ] **Step 1: Replace** the diverging jet ramp with a **genuinely single-hue (red) sequential** scale — only lightness varies, so it is colour-blind-safe — darker = closer indices = higher collision risk, and **make the legend chips equal the cell colours**. Add a **real** non-colour glyph rule (not just a comment):

```css
/* Single-hue red sequential ramp; numeric distance stays in every cell as the
   load-bearing datum, colour is risk magnitude (dark = riskiest). */
.heatmap-cell.dist-0,.legend-item.dist-0 { background-color:#7f1d1d; color:#fff; }
.heatmap-cell.dist-1,.legend-item.dist-1 { background-color:#991b1b; color:#fff; }
.heatmap-cell.dist-2,.legend-item.dist-2 { background-color:#b91c1c; color:#fff; }
.heatmap-cell.dist-3,.legend-item.dist-3 { background-color:#dc2626; color:#fff; }
.heatmap-cell.dist-4,.legend-item.dist-4 { background-color:#ef4444; color:#fff; }
.heatmap-cell.dist-5,.legend-item.dist-5 { background-color:#f87171; color:#450a0a; }
.heatmap-cell.dist-6,.legend-item.dist-6 { background-color:#fca5a5; color:#450a0a; }
.heatmap-cell.dist-7,.legend-item.dist-7 { background-color:#fecaca; color:#450a0a; }
.heatmap-cell.dist-8 { background-color:#fee2e2; color:#450a0a; }
.heatmap-cell.dist-9 { background-color:#fef2f2; color:#450a0a; }
.heatmap-cell.dist-10 { background-color:#fff5f5; color:#450a0a; }
/* Non-colour danger cue: ⚠ glyph + heavy ring on the closest (riskiest) cells. */
.heatmap-cell.dist-0::after,
.heatmap-cell.dist-1::after,
.heatmap-cell.dist-2::after { content:" ⚠"; font-size:.7em; }
.heatmap-cell.dist-0,.heatmap-cell.dist-1,.heatmap-cell.dist-2 { outline:2px solid #450a0a; outline-offset:-2px; }
```

- [ ] **Step 2: Fix the legend markup** in `_heatmaps_tab.html` so it renders `.legend-item.dist-N` chips for the full bucketed range (0,1,2,3,4,5,6,7+) matching the CSS above (the old markup stopped at dist-4), and add a `⚠` glyph + `sr-only` "collision risk" to the dist-0/1/2 legend entries. Also add a **`title`** to every heatmap cell naming **both** samples and the distance — read `_heatmaps_tab.html` for the actual row/col loop vars and add `title="{{ row_label }} × {{ col_label }}: distance {{ dist }}"`. **Rename** the color-balance CSS `.channel-green-demo`/`.channel-red-demo` (2789/2794) to `.channel-1-demo`/`.channel-2-demo` to match `_color_balance_tab.html:48-49`.

- [ ] **Step 3: CSS gate + screenshot diff.** Review `validation-heatmaps.png` and `validation-colorbalance.png`: legend chips now match cells, danger cells have a ring/glyph, color-balance legend swatches render. Re-baseline.

- [ ] **Step 4: Commit** `fix(validation): correct heatmap legend, perceptual ramp, non-color danger cue, channel legend classes`.

### Task 1c.7: Delete dead CSS

**Files:** Modify `components.css`.

- [ ] **Step 1: Re-verify zero references** (class **and** id) for each block, then delete:

```bash
# Every token below is a selector the deletion step removes — grep them all.
for c in wizard-progress wizard-step wizard-nav \
         login-container login-card login-header login-subtitle login-form btn-login \
         run-list run-list-row run-list-header-row run-list-item run-list-empty rl-link rl-actions \
         settings-tabs tab-buttons tab-btn tab-content; do
  echo "== $c =="; grep -rn "$c" src/seqsetup/templates src/seqsetup/static/js src/seqsetup/routes;
done
```
Expected: zero hits outside `components.css`. **If any token shows an external hit, drop it from the deletion list and keep its block.** (`.wizard-nav` and `.tab-buttons` are included defensively — verify before deleting.)

- [ ] **Step 2: Delete** only the blocks whose selectors Step 1 proved unreferenced: `.wizard-progress`/`.wizard-step*` (~1683-1739), the `.login-container`/`.login-card`/`.login-header`/`.login-subtitle`/`.login-form*`/`.btn-login` block (~1324-1377), the `.run-list*`/`.rl-*` block, and `.settings-tabs`/`.tab-buttons`/`.tab-btn`/`.tab-content` (~2189-2223). The deletion set must equal the grep set from Step 1.

- [ ] **Step 3: CSS gate + screenshot diff.** Expected: **zero** visual change (the blocks were unused). `worst=0`.

- [ ] **Step 4: Commit** `chore(css): delete verified-dead style blocks`.

---

## Phase 2 — Tailwind `@theme` bridge

### Task 2.1: Mirror neutrals + define semantic theme tokens

**Files:** Modify `src/seqsetup/static/css/input.css`.

- [ ] **Step 1: Add** an `@theme` block mapping Tailwind's `slate` scale to the **exact** current hex (zero change — the inline pages already use these values) and defining semantic colors for later use:

```css
@theme {
  --color-slate-50:  #f8fafc; --color-slate-100: #f1f5f9; --color-slate-200: #e2e8f0;
  --color-slate-300: #cbd5e1; --color-slate-400: #94a3b8; --color-slate-500: #64748b;
  --color-slate-600: #475569; --color-slate-700: #334155; --color-slate-800: #1e293b;
  --color-slate-900: #0f172a;
  /* Semantic, used by Phase-3 markup (bg-primary, text-info-fg, …). The full
     fill/soft-bg/on-bg triad must exist so the brand-utility migration maps
     1:1 — e.g. status-ready's soft bg-blue-100/text-blue-800 → bg-info-bg/
     text-info-fg, and bg-blue-600 hover → hover:bg-primary-hover. */
  --color-primary:       #2563eb;  /* flips to #0e7490 in Phase 4 */
  --color-primary-hover: #1d4ed8;  /* flips to #155e75 in Phase 4 */
  --color-primary-fg:    #ffffff;
  --color-surface:        #ffffff;
  --color-surface-sunken: #f1f5f9;
  --color-success: #16a34a; --color-success-bg: #dcfce7; --color-success-fg: #166534;
  --color-warning: #b45309; --color-warning-bg: #fef3c7; --color-warning-fg: #92400e;
  --color-danger:  #dc2626; --color-danger-bg:  #fef2f2; --color-danger-fg:  #991b1b;
  --color-info:    #2563eb; --color-info-bg:    #dbeafe; --color-info-fg:    #1e40af;  /* info trio flips to teal in Phase 4 */
}
```

- [ ] **Step 2: CSS gate + screenshot diff.** Expected: **zero** change (slate mapped to identical hex; brand utilities still `blue-*`). `worst=0`.

- [ ] **Step 3: Commit** `style(tailwind): @theme bridge mirroring neutrals + semantic tokens`.

---

## Phase 3 — Per-page markup reconciliation (each sub-task independently shippable)

### Task 3.1: Migrate brand `blue-*` utilities → semantic classes

**Files:** Modify `dashboard.html`, `login.html`, `admin/*.html`, `indexes/*.html`, `validation/page.html` (wherever `blue-*` brand utilities appear).

- [ ] **Step 1: Find** every brand blue utility:

```bash
grep -rn 'blue-\(50\|100\|300\|600\|700\|800\)' src/seqsetup/templates/
```

- [ ] **Step 2: Replace** per this map (every right-hand utility is defined by the Task 2.1 `@theme` triad, so each maps 1:1 with no value change today):
  - `bg-blue-600` → `bg-primary`; the paired hover `bg-blue-700` → `hover:bg-primary-hover`
  - `text-blue-700`/`text-blue-600` → `text-primary`
  - `border-blue-300`/`border-blue-600` → `border-primary`
  - `ring-blue-300` → `ring-primary`
  - status-ready soft chip `bg-blue-100` → `bg-info-bg`, `text-blue-800` → `text-info-fg`
  - `bg-blue-50` (subtle info wells) → `bg-info-bg`

  Do **one page at a time**, screenshot after each.

- [ ] **Step 3: Tokenize the login card** (`login.html`). Keep the centered-card layout and all form hooks; on the card div add `shadow-lg rounded-md`, migrate the submit button's `bg-blue-600`/`hover:bg-blue-700` per the map, and ensure the inputs' focus uses the ring (they pick it up from the Task 1c.4 `a:focus-visible`/input rules once the page's inputs are plain `border` — add `focus-visible:ring` utilities if needed). Re-skin the error placeholder via the danger tokens.

- [ ] **Step 4: Tab count badges.** In `dashboard.html`, the status tabs render the count as inline `({{ counts[key] }})` text — wrap it in `<span class="badge badge--neutral">{{ counts[key] }}</span>` (the primitive from Task 1b.2). Do the same for any count shown on the validation tab buttons.

- [ ] **Step 5: CSS gate + screenshot diff** per page. Expected: badge pills replace `(N)` text and the login card gains elevation; brand colors stay blue (flip is Phase 4). Review + re-baseline the intended deltas.

- [ ] **Step 6: Commit** per page, e.g. `refactor(dashboard): brand utilities → semantic classes + count badges` / `style(login): tokenized card`.

### Task 3.2: Toasts → component classes + `aria-live`

**Files:** Modify `_base.html` (toast template ~37-53); add `.toast*` to `components.css`.

- [ ] **Step 1: Add** `.toast` classes built from tokens:

```css
.toast { border:1px solid var(--border); border-radius:var(--radius-sm); padding:var(--space-2) var(--space-4); box-shadow:var(--shadow-md); max-width:24rem; }
.toast--success { background:var(--success-bg); border-color:var(--success); color:var(--success-fg); }
.toast--error   { background:var(--danger-bg);  border-color:var(--danger);  color:var(--danger-fg); }
.toast--warning { background:var(--warning-bg); border-color:var(--warning); color:var(--warning-fg); }
.toast--info    { background:var(--info-bg);    border-color:var(--info);    color:var(--info-fg); }
```

- [ ] **Step 2: Edit** `_base.html`: keep the `x-data="toastStack()"`, `@toast.window`, `x-for`, `:key`, `x-text`, `#toast-stack` id; add `role="status" aria-live="polite"` to the container; swap the per-kind Tailwind utility `:class` map for `:class="'toast toast--' + toast.kind"`. **No dismiss button.**

- [ ] **Step 3: CSS gate.** Run `pixi run smoke-browser` — the toast reactivity test must still pass (it asserts the toast renders text). Trigger a real toast manually to confirm color + `aria-live`.

- [ ] **Step 4: Commit** `refactor(toasts): token-driven .toast classes + aria-live`.

### Task 3.3: Keyboard-operable index **assignment** (chip selects + drop zone assigns)

Assignment is drag-only today: the chip `onclick`/`handleIndexClick` merely *selects* (highlights); the assign happens in `handleIndexDrop` on the **drop zone**. So keyboard parity needs BOTH: chips focusable + Enter→select, and **drop zones focusable + Enter→assign the selected index**. `handleIndexDrop` is left untouched; a parallel single-assign function hits the same endpoint. Multi-index assignment stays drag-/bulk-only.

**Files:** Modify `app.js` (add 3 helpers, no edits to `handleIndexDrop`); modify `wizard/_draggable_index*.html` (chips) and the drop-zone markup in `wizard/_sample_table.html` / `_sample_row.html` (read them first to find the `.drop-zone` elements and their `ondrop="handleIndexDrop(event,'<sample>','<run>','<type>')"` args). **Prereq:** Task 0.2 seed includes a standard **pair** index kit so the first chip's type matches the first drop zone.

- [ ] **Step 1: Write the failing test** in `tests/browser/test_a11y.py` — assert a real **assignment**, not just selection:

```python
@pytest.mark.browser
def test_index_keyboard_assign(logged_in_page, base_url, seeded_ids):
    page = logged_in_page
    page.goto(base_url + f"/runs/{seeded_ids['draft_run_id']}")
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
```

- [ ] **Step 2: Run it** — Expected: FAIL (chips/zones not focusable; Enter does nothing).

- [ ] **Step 3: Add** the three helpers to `app.js` (do NOT modify `handleIndexDrop`):

```javascript
function handleIndexKeydown(event) {                 // chip: Enter/Space = select
    if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        event.currentTarget.click();                 // → handleIndexClick (highlight)
    }
}

function assignSelectedIndexToSample(sampleId, runId, dropZoneType, dropZoneEl) {
    if (selectedIndexes.length === 0) return false;  // nothing selected → no-op
    const idx = selectedIndexes[0];                  // keyboard path = single assign
    if ((idx.type === 'i7' || idx.type === 'i5') && dropZoneType && dropZoneType !== idx.type) return false;
    const context = dropZoneEl && dropZoneEl.dataset ? (dropZoneEl.dataset.context || '') : '';
    const sampleTable = document.getElementById('sample-table');
    const existingIds = sampleTable ? (sampleTable.dataset.existingIds || '') : '';
    const values = { context: context, existing_ids: existingIds };
    if (idx.type === 'pair') { values.index_pair_id = idx.id; }
    else { values.index_id = idx.id; values.index_type = idx.type; }
    htmx.ajax('POST', `/runs/${runId}/samples/${sampleId}/assign-index`, {
        target: `#sample-row-${sampleId}`, swap: 'outerHTML', values: values
    });
    clearIndexSelection();
    return true;
}

function handleIndexAssignKeydown(event, sampleId, runId, dropZoneType) {  // drop zone: Enter/Space = assign
    if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        assignSelectedIndexToSample(sampleId, runId, dropZoneType, event.currentTarget);
    }
}
```

- [ ] **Step 4: Edit the chip partials** (`_draggable_index_compact.html`, `_draggable_index.html`, `_draggable_index_pair*.html`): add `tabindex="0"`, `role="button"`, `onkeydown="handleIndexKeydown(event)"`, `aria-label="{{ index.name }} {{ index_type }} sequence {{ index.sequence }}"`, and an **i7/i5 text pill** `<span class="index-type-pill {{ index_type|e }}">{{ index_type|e }}</span>`. Keep `draggable`, `onclick`, `ondragstart`, `title`, all `data-*`.

- [ ] **Step 5: Edit the drop-zone markup**: on each `.drop-zone` add `tabindex="0"`, `role="button"`, `aria-label="Assign selected index to {{ sample.sample_id }}"`, `onkeydown="handleIndexAssignKeydown(event, '{{ sample.id }}', '{{ run.id }}', '{{ drop_zone_type }}')"` (match the exact args the element's existing `ondrop` passes), and a small target glyph (e.g. `<span aria-hidden="true">⌖</span>`). Keep `ondrop`, `ondragover`, `data-context`.

- [ ] **Step 6: Add focus + pill CSS** to `components.css`:

```css
.draggable-index:focus-visible, .draggable-index-compact:focus-visible,
.drop-zone:focus-visible { outline: none; box-shadow: var(--focus-ring); }
.index-type-pill { font-size: var(--fs-2xs); font-weight: var(--fw-semibold); padding: 0 .3rem; border-radius: var(--radius-sm); color: #fff; }
.index-type-pill.i7 { background: var(--accent-i7); }
.index-type-pill.i5 { background: var(--accent-i5); }
.index-type-pill.pair { background: var(--accent-pair); }
.drop-zone { border-radius: var(--radius-sm); }
.drop-zone.drag-over { box-shadow: var(--shadow-md); }
```

- [ ] **Step 7: Run the test** — Expected: PASS. Then `pixi run smoke-browser` green and a manual drag-drop still assigns (regression check on the untouched `handleIndexDrop`).

- [ ] **Step 8: Commit** `a11y(index): keyboard-operable assignment (chip select + drop-zone assign), type pills, focus rings`.

### Task 3.4: Wide-table scroll wrappers + sample-table cell titles

**Files:** Modify `indexes/detail.html`, `admin/logs.html`, validation table partials, `wizard/_sample_row.html`.

- [ ] **Step 1: Wrap** each wide table (`indexes/detail.html`, `admin/logs.html`, the validation heatmap/color-balance/dark-cycle tables) in `<div class="table-scroll">…</div>` and add to `components.css`: `.table-scroll { overflow-x: auto; }`. Add `title="{{ value }}"` to the truncated `.sample-table` cells (Sample-ID, Test-ID, Worksheet, kit) in `_sample_row.html`.

- [ ] **Step 2: Add `scope`** to every data-table header cell: `scope="col"` on column headers, `scope="row"` on the heatmap/dark-cycle row-label `th`s (screen-reader association). For the heatmap, make the **first column sticky** so row labels stay visible while scrolling horizontally — add to `components.css`:

```css
.heatmap-table .heatmap-row-header { position: sticky; left: 0; z-index: 1; background: var(--surface-sunken); }
```

- [ ] **Step 3: CSS gate + screenshot diff.** Expected: no resting-state change at desktop width; horizontal scroll + sticky first column appear when narrow. Confirm titles via hover and `scope` in the DOM.

- [ ] **Step 4: Commit** `a11y(tables): scroll wrappers, scope on headers, sticky heatmap first column, cell titles`.

### Task 3.5: Shell polish — skip-link, SVG chevron, aria-current, admin fieldset boxing

**Files:** Modify `_app_shell.html`; `admin/authentication.html` (and other admin pages with bare `<fieldset>`).

- [ ] **Step 1: Markup** (`_app_shell.html`): add `<a href="#main" class="skip-link">Skip to main content</a>` as the first child inside `<main class="app-container">`; add `id="main"` to the `.main-content` div; inside each settings/admin `<summary>` add an inline SVG chevron `<svg class="nav-chevron" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path d="M7 5l6 5-6 5z"/></svg>`; add `aria-current="page"` to the active `.nav-item` (the `{% if active_route == ... %}` branch).

- [ ] **Step 2: CSS** (`components.css`) — **remove the old CSS triangle so it doesn't double** with the SVG, rotate the SVG on open, and style the skip-link:

```css
.settings-section summary::before { content: none; }   /* kill the old ▶ (\25B6) so only the SVG renders */
.nav-chevron { width: .7rem; height: .7rem; margin-right: .5rem; transition: transform .2s; vertical-align: middle; }
.settings-section[open] > summary .nav-chevron { transform: rotate(90deg); }
.skip-link { position: absolute; left: -9999px; top: 0; z-index: 100;
    background: var(--surface); color: var(--primary);
    padding: var(--space-2) var(--space-3); border-radius: var(--radius-sm); }
.skip-link:focus { left: var(--space-2); box-shadow: var(--focus-ring); }
```

- [ ] **Step 3: Box admin fieldsets.** Add `class="config-panel"` to the bare `<fieldset>`s in `admin/authentication.html` and any other admin page rendering unboxed fieldsets.

- [ ] **Step 4: CSS gate + screenshot diff.** Expected: a single SVG chevron (not two markers), Tab-from-top reveals the skip-link, boxed admin fieldsets. Re-baseline admin + shell pages.

- [ ] **Step 5: Commit** `a11y(shell): skip-link, SVG chevron (old triangle removed), aria-current, boxed admin fieldsets`.

---

## Phase 4 — Palette flip (blue → Deep Teal) + a11y certification

### Task 4.1: Flip the brand to teal (one isolated, fully-reviewed commit)

**Files:** Modify `components.css` `:root` (brand + info) and `input.css` `@theme` (`--color-primary`/`--color-info`).

- [ ] **Step 1: Change** exactly these values:

```css
/* components.css :root */
--primary: #0e7490; --primary-hover: #155e75;
--info: #0e7490; --info-bg: #cff5fb; --info-fg: #155e75;
```
```css
/* input.css @theme */
--color-primary: #0e7490; --color-primary-hover: #155e75;
--color-info: #0e7490; --color-info-bg: #cff5fb; --color-info-fg: #155e75;
```
  Leave `--accent-i7: #2563eb` untouched (index blue stays blue — the whole point). Grep `input.css`/`components.css` after editing to confirm no stray `#2563eb`/`#1d4ed8` brand literal was missed.

- [ ] **Step 2: CSS gate + full screenshot diff.** Every primary button/link/active-tab/active-nav/focus-ring becomes teal; i7 index coding stays blue; the "ready" badge moves to the teal info family. **Review every screenshot**; re-baseline the whole set after confirming each delta is intended.

- [ ] **Step 3: Commit** `style(palette): flip brand to Deep Teal Clinical (#0e7490)`.

### Task 4.2: Accessibility certification

**Files:** Modify `tests/browser/test_a11y.py`.

- [ ] **Step 1: Tighten** the axe assertion to `serious/critical == 0` on dashboard + run editor + a validation page; fix any remaining violations surfaced.

- [ ] **Step 2: Add** a contrast assertion over the §4.4 matrix pairs (compute ratios in-test from the token hex, assert each ≥ its target). Add a focus-ring presence check on a button, an input, and an index chip.

- [ ] **Step 3: Run** `pixi run smoke-browser`. Expected: all PASS.

- [ ] **Step 4: Commit** `test(a11y): certify AA contrast, focus-visible, keyboard assign`.

### Task 4.3: Finalize

- [ ] **Step 1:** Run the full gate one last time: `pixi run css && pixi run test && pixi run smoke-browser`, then `python tools/screenshot_diff.py` against the final baseline (expect `worst=0`).
- [ ] **Step 2:** Use `superpowers:requesting-code-review`, then `superpowers:finishing-a-development-branch` to open the PR.

---

## Self-review notes

- **Spec coverage:** buttons 1b.1; badges + count-pills 1b.2/3.1; cards/.config-panel 1c.1; sample table type/sticky-header 1b.3, cell titles/scope 3.4; forms/focus/`:user-invalid` 1c.4; sidebar/header 1c.5, chevron/skip-link/aria-current 3.5; tabs — native `<button>`s + focus ring 1c.4, count badges 3.1; wizard stepper delete 1c.7; heatmap legend/ramp/glyph/titles/sticky-first-col 1c.6+3.4; drag-drop + i7/i5 pills + focus rings + **keyboard assignment** 3.3; toasts 3.2; login card tokenization 3.1 Step 3 + dead-CSS delete 1c.7. §6 phases map 1:1.
- **Round-2 review fixes applied:** screenshot diff now `sys.exit`s non-zero + checks both directions + clears `current/` (0.3); axe is vendored + `evaluate`-injected (CSP-safe) with a real subset-of-baseline gate (0.4); Phase 2 `@theme` defines the full `*-bg`/`*-fg`/`primary-hover` triad so 3.1 maps 1:1; **keyboard work assigns via drop zones, not just selects** (3.3, with a test asserting a real assignment); heatmap ramp is genuinely single-hue + has a real `::after` glyph (1c.6); chevron removes the old `summary::before` (3.5); skip-link has hidden/focus CSS (3.5); dead-CSS grep covers every deleted selector incl. `.login-container`/`.login-form` (1c.7).
- **Sequencing invariant:** brand is blue until Task 4.1; all earlier "zero-diff" gates assume that. Do not change `--primary`/`--color-primary` before Phase 4.
- **Re-verify-before-delete:** Task 1c.7 Step 1 must show zero external refs before any deletion; the audit's "dead" list is re-checked, not trusted.
- **Routes/URLs (verified):** validation page is `GET /runs/{run_id}/validation`; its four tabs and the dashboard status tabs are client-toggled (Alpine `x-show` / HTMX fragments), so Task 0.3 captures them by clicking, not by URL. Pixi tasks live in `pixi.toml` (Tasks 0.1, 2.1). Confirm exact tab-button selectors against the templates before running 0.3.
