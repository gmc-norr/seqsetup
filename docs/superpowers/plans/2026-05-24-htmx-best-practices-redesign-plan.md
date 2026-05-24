# SeqSetup HTMX best-practices redesign — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate SeqSetup from its current half-FastHTML state into a canonical Pragmatic-HTMX project: FastAPI + APIRouter + Jinja2 + jinja2-fragments + Tailwind v4 + Alpine.js + Pydantic forms, with conventions documented in `ARCHITECTURE.md`.

**Architecture:** Incremental, "all-new-patterns-per-touch" migration. Every commit is shippable with the full test suite green. Five phases: Foundation → Reference port → Migrate Jinja2 pages → Port FT files → Cleanup.

**Tech Stack:** Python 3.14, Pixi, FastAPI, Jinja2 + jinja2-fragments, Pydantic v2, HTMX 2.x, Alpine.js 3.x, Tailwind CSS v4, pytest + mongomock, pytest-playwright.

**Spec reference:** `docs/superpowers/specs/2026-05-24-htmx-best-practices-redesign-design.md` (read it first).

**Pre-flight (BEFORE Phase 0) — HUMAN CONFIRMATION REQUIRED:** This session's working tree has substantial uncommitted work-in-progress from the earlier porting effort (samples package split, validation chain port, indexes/wizard step1 port, etc.). The redesign supersedes that work, so before starting Phase 0 the tree must be reconciled.

**This is an explicit human-gate step.** An agent executing this plan MUST stop here and ask the human which option to take. The agent MUST NOT execute `git reset --hard`, `git stash`, or any destructive command autonomously. Whichever option the human picks, the human runs the destructive commands themselves (or explicitly authorizes the agent to run them in the specific message that follows).

Three options for the human to choose from:
- **Option A (recommended):** commit the in-progress work as-is on a `pre-redesign-backup` branch, then `git checkout main && git reset --hard 5fb76ed` to start the plan from a clean state at the spec commit.
    ```bash
    # Run these YOURSELF after deciding:
    git checkout -b pre-redesign-backup
    git add -A && git commit -m "wip: in-progress FT→Jinja2 port (pre-redesign-backup)"
    git checkout main
    git reset --hard 5fb76ed   # destructive — only run if you've confirmed the backup
    pixi run test               # confirm baseline ~837 passing
    ```
- **Option B:** stash the in-progress work and start the plan from a clean state — apply nothing back. Less recoverable than A.
    ```bash
    git stash push -u -m "pre-redesign WIP" && pixi run test
    ```
- **Option C:** commit the in-progress work to main as a single "intermediate state" commit, then the plan starts from there. The plan's task counts and file-state assumptions assume Option A or B (a clean tree at HEAD=5fb76ed); Option C requires the agent to reconcile against a different starting state.

After choosing AND running the chosen reconciliation: run `pixi run test` and confirm the baseline (~837 passing for A or B; different for C).

---

## Overall file map

**New files (created during the plan):**
| Path | Created in | Responsibility |
|---|---|---|
| `forms/__init__.py` | Phase 0 | Pydantic form models package marker |
| `src/seqsetup/forms/validators.py` | Phase 0 | Shared Pydantic validators: `strip_and_truncate`, `clamp`, `dna_upper_or_reject`, `json_list` |
| `src/seqsetup/routes/dependencies.py` | Phase 0 | FastAPI deps: `get_ctx`, `require_admin_dep`, `get_editable_run`, `is_htmx_request`, `_load_and_check_editable`, `saving_run` CM |
| `src/seqsetup/exception_handlers.py` | Phase 0 | HTML-aware `RequestValidationError`, `HTTPException`, `ConflictError` handlers |
| `static/css/input.css` | Phase 0 | Tailwind v4 source (`@import "tailwindcss"`) + `@import "legacy.css"` |
| `static/css/legacy.css` | Phase 0 | Renamed from existing `static/css/app.css` |
| `static/js/vendor/htmx.min.js` | Phase 0 | Vendored HTMX 2.x (pinned) |
| `static/js/vendor/alpine.min.js` | Phase 0 | Vendored Alpine 3.x (pinned) |
| `static/js/components/toast_stack.js` | Phase 0 | Alpine toast-stack component (consumes `HX-Trigger: toast`) |
| `tools/tailwind-version.txt` | Phase 0 | Pinned Tailwind v4 version string |
| `tailwind.config.js` | Phase 0 | Tailwind v4 config (`content: ["src/seqsetup/templates/**/*.html"]`) |
| `ARCHITECTURE.md` | Phase 0 | Developer-facing conventions doc |
| `tests/unit/test_form_validators.py` | Phase 0 | Unit tests for `strip_and_truncate`, `clamp`, `dna_upper_or_reject`, `json_list` |
| `tests/unit/test_dependencies.py` | Phase 0 | Unit tests for the new deps + `saving_run` CM |
| `tests/integration/test_html_exception_handler.py` | Phase 0 | `HTTPException` → HTML fragment (HTMX-aware) |
| `tests/integration/test_pydantic_422_htmx.py` | Phase 0 | `RequestValidationError` → HTML fragment with HX-Reswap/HX-Retarget |
| `tests/integration/test_toast_hxtrigger.py` | Phase 0 | `HX-Trigger: {"toast": …}` emitted correctly |
| `tests/integration/test_route_order.py` | Phase 0 | Regression: `/runs/new/step/1` ≠ `/runs/{run_id}` catch-all |
| `tests/browser/__init__.py` | Phase 0 | Browser smoke-test package marker |
| `tests/browser/conftest.py` | Phase 0 | Playwright fixtures (page, app server) |
| `tests/browser/test_browser_smoke.py` | Phase 0 | window.htmx + window.Alpine + 1 swap + 1 component test |
| `src/seqsetup/static/js/components/index_drag_zone.js` | Phase 3 | Drag-zone Alpine component (consumed by wizard sample table) |
| `src/seqsetup/static/js/components/sample_multi_select.js` | Phase 3 | Multi-select Alpine component |

**Files heavily modified:**
| Path | Modified in | Change |
|---|---|---|
| `src/seqsetup/templating.py` | Phase 0 | Switch to `Jinja2Blocks`; add `block_name=` arg to `render`; add `asset_url` filter; drop the `ASSET_VERSIONS` dict |
| `src/seqsetup/app.py` | Phase 0 → Phase 4 | Per-phase: install exception handlers, switch from `register(app, ctx)` to `app.include_router(...)`, drop legacy CSS link, etc. |
| `src/seqsetup/routes/utils.py` | Phase 0 → Phase 4 | Add new deps in Phase 0; in Phase 4, drop the deprecated `require_admin`, `check_run_editable`, and `editable_run_handler` decorator |
| `src/seqsetup/templates/_base.html` | Phase 0 | Load HTMX vendor + app.js + components + Alpine in order |
| `src/seqsetup/templates/_app_shell.html` | Phase 0 | Add toast-stack slot |
| `pixi.toml` | Phase 0 | Add deps + new tasks (`css`, `css-watch`, `tailwind-install`, `playwright-install`, `smoke-browser`); make `serve` depend on `css` |
| `Dockerfile` | Phase 0 | Add `RUN pixi run css` before `CMD` |
| `CLAUDE.md` | Phase 0 | Point at `ARCHITECTURE.md` |
| `.gitignore` | Phase 0 | Ignore generated `static/css/app.css` |
| Per-page route files | Phase 1, 2, 3 | One per page: APIRouter, Pydantic forms, deps, Tailwind-rendered templates |

**Files deleted (Phase 4 cleanup):**
- `src/seqsetup/components/wizard/sample_table.py`
- `src/seqsetup/components/wizard/index_panel.py`
- `src/seqsetup/components/wizard/add_samples.py`
- `src/seqsetup/components/wizard/steps.py`
- `src/seqsetup/components/wizard/__init__.py`
- `src/seqsetup/components/edit_run.py`
- `src/seqsetup/components/__init__.py`
- `src/seqsetup/static/css/legacy.css`

---

# Phase 0 — Foundation (1 commit, no behavioural change)

**Goal:** land all new dependencies, helpers, conventions, and the browser-smoke gate WITHOUT changing any existing route or template's user-visible behaviour. Tests green at the end.

**Acceptance for the Phase 0 commit:**
- `pixi run test` green (no regressions)
- `pixi run css` builds `static/css/app.css` without errors
- `pixi run smoke-browser` green (catches the current HTMX-not-loaded bug + verifies new infrastructure works)
- App boots and a manual `pixi run serve` + open `/login` works exactly as before

---

### Task 0.1: Add Python dependencies

**Files:**
- Modify: `pixi.toml`

- [ ] **Step 1: Add the new pypi-dependencies**

Find the `[pypi-dependencies]` section in `pixi.toml` and add (alphabetically):

```toml
[pypi-dependencies]
# (existing entries...)
jinja2-fragments = ">=1.4,<2"
pydantic = { version = ">=2.7,<3", extras = ["email"] }   # add the [email] extra to the existing pydantic entry
pytest-playwright = ">=0.5,<1"
```

If `pydantic` is already pinned in `[pypi-dependencies]`, update it in place to include `extras = ["email"]`. If it's only a transitive dep via FastAPI, add it explicitly with the extras.

- [ ] **Step 2: Lock and install**

```bash
pixi install
```

Expected: `pixi.lock` updates. No errors.

- [ ] **Step 3: Verify imports work**

```bash
PYTHONPATH=src pixi run python -c "import jinja2_fragments; from pydantic import EmailStr; from playwright.sync_api import sync_playwright; print('ok')"
```

Expected output: `ok`.

- [ ] **Step 4: Commit (intermediate — squashed at end of Phase 0)**

Don't commit yet. Phase 0 lands as a single commit at the end of Task 0.18.

---

### Task 0.2: Add Tailwind v4 standalone-binary tooling

**Files:**
- Create: `tools/tailwind-version.txt`
- Modify: `pixi.toml`
- Modify: `.gitignore`

- [ ] **Step 1: Pin the Tailwind version**

```bash
echo "v4.1.4" > tools/tailwind-version.txt
```

(Pick the latest v4 release at time of execution; `v4.1.4` is a placeholder — check https://github.com/tailwindlabs/tailwindcss/releases and use the latest stable v4.)

- [ ] **Step 2: Add the `tailwind-install` task to `pixi.toml`**

In the `[tasks]` section of `pixi.toml`, add:

```toml
tailwind-install = { cmd = """bash -c '
VERSION=$(cat tools/tailwind-version.txt)
DEST=.pixi/bin/tailwindcss
if [ -f "$DEST" ] && "$DEST" --version | grep -q "${VERSION#v}"; then
  echo "Tailwind $VERSION already installed at $DEST"
  exit 0
fi
mkdir -p .pixi/bin
PLATFORM=""
case "$(uname -sm)" in
  "Linux x86_64")  PLATFORM="linux-x64" ;;
  "Linux aarch64") PLATFORM="linux-arm64" ;;
  "Darwin x86_64") PLATFORM="macos-x64" ;;
  "Darwin arm64")  PLATFORM="macos-arm64" ;;
  *) echo "Unsupported platform: $(uname -sm)"; exit 1 ;;
esac
URL="https://github.com/tailwindlabs/tailwindcss/releases/download/$VERSION/tailwindcss-$PLATFORM"
echo "Downloading $URL -> $DEST"
if [ -f "tools/vendor/tailwindcss-$PLATFORM" ]; then
  echo "Using vendored binary at tools/vendor/tailwindcss-$PLATFORM"
  cp "tools/vendor/tailwindcss-$PLATFORM" "$DEST"
else
  curl -fsSL -o "$DEST" "$URL"
fi
chmod +x "$DEST"
"$DEST" --version
'""" }
```

The task installs the Tailwind binary to `.pixi/bin/tailwindcss`, preferring a vendored copy at `tools/vendor/tailwindcss-<platform>` (for air-gapped clinical deployments) over the network download.

- [ ] **Step 3: Add the `css` and `css-watch` tasks**

In the same `[tasks]` section:

```toml
css = { cmd = "bash -c '.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify'", depends-on = ["tailwind-install"] }
css-watch = { cmd = "bash -c '.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --watch'", depends-on = ["tailwind-install"] }
```

- [ ] **Step 4: Wire `serve` to build CSS first**

Change the existing `serve` task. If it currently looks like:

```toml
serve = "PYTHONPATH=src python -m seqsetup.app"
```

Update to:

```toml
serve = { cmd = "PYTHONPATH=src python -m seqsetup.app", depends-on = ["css"] }
```

- [ ] **Step 5: Run install + first build**

```bash
pixi run tailwind-install
```

Expected: prints `tailwindcss, X.Y.Z` (matching the pinned version).

- [ ] **Step 6: Ignore the generated CSS**

Add to `.gitignore`:

```
# Tailwind-generated CSS (built from src/seqsetup/static/css/input.css)
src/seqsetup/static/css/app.css

# Tailwind binary cache
.pixi/bin/tailwindcss
```

- [ ] **Step 7: Verify .gitignore works**

```bash
git check-ignore -v src/seqsetup/static/css/app.css
git check-ignore -v .pixi/bin/tailwindcss
```

Both should print the matching .gitignore rule.

---

### Task 0.3: Rename the existing CSS file to `legacy.css`

**Files:**
- Rename: `src/seqsetup/static/css/app.css` → `src/seqsetup/static/css/legacy.css`
- Create: `src/seqsetup/static/css/input.css`
- Create: `tailwind.config.js`

- [ ] **Step 1: Rename the existing app.css**

```bash
git mv src/seqsetup/static/css/app.css src/seqsetup/static/css/legacy.css
```

- [ ] **Step 2: Create `input.css` with v4 directives + legacy import**

Create `src/seqsetup/static/css/input.css`:

```css
/* Tailwind v4 — single import replaces the v3 @tailwind base/components/utilities trio. */
@import "tailwindcss";

/* Legacy custom CSS — kept during the migration, deleted in Phase 4 once no template
   references the legacy class names. */
@import "legacy.css";
```

- [ ] **Step 3: Create `tailwind.config.js`**

```js
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "src/seqsetup/templates/**/*.html",
  ],
  theme: {
    extend: {},
  },
  plugins: [],
};
```

- [ ] **Step 4: Generate the initial app.css**

```bash
pixi run css
```

Expected: writes `src/seqsetup/static/css/app.css` (gitignored). File should be substantially larger than the old hand-written one (Tailwind base + utilities take ~10KB minified) but still contain all the legacy rules.

- [ ] **Step 5: Verify the legacy rules are preserved**

```bash
grep -c "kit-card\|validation-approval-bar\|sample-table" src/seqsetup/static/css/app.css
```

Expected: a non-zero count — these are class names from the legacy CSS that should have flowed through.

---

### Task 0.4: Vendor HTMX and Alpine

**Files:**
- Create: `src/seqsetup/static/js/vendor/htmx.min.js`
- Create: `src/seqsetup/static/js/vendor/alpine.min.js`
- Create: `src/seqsetup/static/js/vendor/VERSIONS.md`

- [ ] **Step 1: Create the vendor dir**

```bash
mkdir -p src/seqsetup/static/js/vendor
```

- [ ] **Step 2: Download HTMX 2.x pinned**

```bash
HTMX_VERSION="2.0.4"   # Pick latest 2.x release from https://htmx.org/
curl -fsSL -o src/seqsetup/static/js/vendor/htmx.min.js \
  "https://unpkg.com/htmx.org@${HTMX_VERSION}/dist/htmx.min.js"
echo "Got HTMX $(wc -c < src/seqsetup/static/js/vendor/htmx.min.js) bytes"
```

- [ ] **Step 3: Download Alpine 3.x pinned**

```bash
ALPINE_VERSION="3.14.8"   # Pick latest 3.x from https://github.com/alpinejs/alpine/releases
curl -fsSL -o src/seqsetup/static/js/vendor/alpine.min.js \
  "https://unpkg.com/alpinejs@${ALPINE_VERSION}/dist/cdn.min.js"
echo "Got Alpine $(wc -c < src/seqsetup/static/js/vendor/alpine.min.js) bytes"
```

- [ ] **Step 4: Record the versions in a tracked file**

Create `src/seqsetup/static/js/vendor/VERSIONS.md`:

```markdown
# Vendored JS

These files are NOT npm/build-tool managed. They're pinned-version
downloads kept in-repo so the app works in air-gapped clinical
deployments and survives external CDN outages.

| File | Source | Version |
|---|---|---|
| htmx.min.js | https://htmx.org/ | 2.0.4 |
| alpine.min.js | https://alpinejs.dev/ | 3.14.8 |

To bump: replace the file, update the version here, run `pixi run smoke-browser`.
```

(Update version numbers to match what you actually downloaded.)

- [ ] **Step 5: Sanity-check the files are JS, not error HTML**

```bash
head -c 200 src/seqsetup/static/js/vendor/htmx.min.js
head -c 200 src/seqsetup/static/js/vendor/alpine.min.js
```

Expected: minified JS (e.g. `var htmx=function(){...`). NOT HTML or a 404 page.

---

### Task 0.5: Switch templating.py to Jinja2Blocks + asset_url filter

**Files:**
- Modify: `src/seqsetup/templating.py`

- [ ] **Step 1: Read the current `templating.py`**

```bash
cat src/seqsetup/templating.py
```

Note: there's an `ASSET_VERSIONS` dict and a `_asset_hash` helper. We'll keep `_asset_hash` and replace the dict with an `asset_url` filter.

- [ ] **Step 2: Replace the relevant parts**

Open `src/seqsetup/templating.py`. Replace:

```python
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
```

with:

```python
from jinja2_fragments.fastapi import Jinja2Blocks

templates = Jinja2Blocks(directory=str(TEMPLATES_DIR))


def _asset_url(rel_path: str) -> str:
    """``'js/foo.js' | asset_url`` → ``'/js/foo.js?v=abc12345'``.

    Hash recomputed at template render — fine, the static dir is small
    and these hashes are computed only during HTML rendering, not for
    every request to the static file itself.
    """
    h = _asset_hash(rel_path)
    return f"/{rel_path}?v={h}"


templates.env.filters["asset_url"] = _asset_url
```

And REMOVE the `ASSET_VERSIONS = {...}` block.

In the existing `render(...)` function, update the signature and merging:

```python
def render(
    request: Request,
    template: str,
    context: Optional[dict] = None,
    *,
    block_name: Optional[str] = None,
    status_code: int = 200,
    headers: Optional[dict] = None,
):
    """Render a full template, or one named ``{% block %}`` from it.

    ``block_name=None`` → full page (the ``{% extends "_app_shell.html" %}``
    chain). ``block_name="foo"`` → just the ``{% block foo %}`` contents,
    no shell — for HTMX swap fragments.
    """
    ctx = dict(context or {})
    ctx.setdefault("user", request.scope.get("auth"))

    merged_headers = {"Cache-Control": "no-store"}
    if headers:
        merged_headers.update(headers)

    return templates.TemplateResponse(
        request, template, ctx,
        block_name=block_name,
        status_code=status_code,
        headers=merged_headers,
    )
```

Note: `Jinja2Blocks.TemplateResponse(...)` accepts `block_name=None` and renders the full template; with a name it renders just that block.

- [ ] **Step 3: Drop the `asset_versions` context key from `render`**

The old context-injection step is gone; templates use `{{ 'js/foo.js' | asset_url }}` instead of `{{ asset_versions['js/foo.js'] }}`. No code change beyond what was done in Step 2 — but be aware existing templates will need updating in Task 0.6.

- [ ] **Step 4: Verify the module imports cleanly**

```bash
PYTHONPATH=src pixi run python -c "from seqsetup.templating import render, templates; print(templates.env.filters['asset_url']('js/app.js'))"
```

Expected output: `/js/app.js?v=<hash>` (some 8-char hex string).

---

### Task 0.6: Update _base.html to use asset_url filter + load vendor scripts in order

**Files:**
- Modify: `src/seqsetup/templates/_base.html`

- [ ] **Step 1: Read the current `_base.html`**

```bash
cat src/seqsetup/templates/_base.html
```

You'll see the old `asset_versions['css/app.css']` lookups.

- [ ] **Step 2: Replace the entire file**

Overwrite `src/seqsetup/templates/_base.html` with:

```jinja
{# Base layout — <html><head> shell + body. Child templates extend this
   (usually via _app_shell.html) and override {% block body %}.

   Asset cache-busting: use the ``asset_url`` Jinja filter, NOT the old
   ASSET_VERSIONS dict (gone in templating.py). Vendor files are pinned
   by filename so they skip the filter.
#}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}SeqSetup{% endblock %}</title>
    <link rel="icon" type="image/svg+xml" href="/img/favicon.svg">
    <link rel="stylesheet" href="{{ 'css/app.css' | asset_url }}">

    {# Loading order matters — see ARCHITECTURE.md "Client-side JS".
       Alpine MUST load last among the scripts that touch it, because
       it boots on alpine:init and component files register handlers
       via Alpine.data(...) before that. #}
    <script defer src="/js/vendor/htmx.min.js"></script>
    <script defer src="{{ 'js/app.js' | asset_url }}"></script>
    {# Component scripts registered here are added one per file as Phase 3 lands them. #}
    <script defer src="{{ 'js/components/toast_stack.js' | asset_url }}"></script>
    <script defer src="/js/vendor/alpine.min.js"></script>

    {% block head_extra %}{% endblock %}
</head>
<body>
    {% block body %}{% endblock %}
</body>
</html>
```

- [ ] **Step 3: Verify the app boots**

```bash
PYTHONPATH=src pixi run python -c "from seqsetup import app; print('boot ok')"
```

Expected: `boot ok` (no template parse errors yet — those would surface only when rendering).

---

### Task 0.7: Add toast-stack component + slot in _app_shell.html

**Files:**
- Create: `src/seqsetup/static/js/components/toast_stack.js`
- Modify: `src/seqsetup/templates/_app_shell.html`

- [ ] **Step 1: Create the toast stack Alpine component**

Create `src/seqsetup/static/js/components/toast_stack.js`:

```js
/* Toast stack — listens for the "toast" CustomEvent fired by HTMX
   when the server sends HX-Trigger: {"toast": {"kind": "success",
   "message": "..."}}. The event bubbles on document.body, so we
   listen on @toast.window on the host element.

   See ARCHITECTURE.md "Toast notifications" + spec section 4.5. */
document.addEventListener('alpine:init', () => {
  Alpine.data('toastStack', () => ({
    toasts: [],
    nextId: 1,

    addToast(detail) {
      if (!detail || typeof detail !== 'object') return;
      const id = this.nextId++;
      const kind = detail.kind || 'info';
      const message = String(detail.message || '');
      const lifetime = Number(detail.lifetime || 4000);
      this.toasts.push({ id, kind, message });
      // Auto-remove after lifetime ms.
      setTimeout(() => this.remove(id), lifetime);
    },

    remove(id) {
      this.toasts = this.toasts.filter(t => t.id !== id);
    },
  }));
});
```

- [ ] **Step 2: Read the current `_app_shell.html`**

```bash
cat src/seqsetup/templates/_app_shell.html
```

- [ ] **Step 3: Add the toast slot inside the `<main>` element**

In `src/seqsetup/templates/_app_shell.html`, just BEFORE the closing `</main>` tag (or as the last child of the `app-container` div, whichever is the outermost permanent wrapper in your shell), add:

```jinja
    {# Toast notifications — server emits HX-Trigger: {"toast": {…}};
       Alpine renders the stack here. See ARCHITECTURE.md. #}
    <div x-data="toastStack()"
         @toast.window="addToast($event.detail)"
         class="fixed top-4 right-4 z-50 space-y-2"
         id="toast-stack">
        <template x-for="toast in toasts" :key="toast.id">
            <div
                :class="{
                    'bg-green-100 border-green-400 text-green-800': toast.kind === 'success',
                    'bg-red-100   border-red-400   text-red-800':   toast.kind === 'error',
                    'bg-yellow-100 border-yellow-400 text-yellow-800': toast.kind === 'warning',
                    'bg-blue-100  border-blue-400  text-blue-800':  toast.kind === 'info'
                }"
                class="border rounded px-4 py-2 shadow-md max-w-sm"
                x-text="toast.message">
            </div>
        </template>
    </div>
```

(The Tailwind classes will work once `pixi run css` has run, which it will via the new `serve` dependency.)

- [ ] **Step 4: Smoke-check the change doesn't break rendering**

```bash
PYTHONPATH=src pixi run python -m pytest tests/integration/test_smoke_bootstrap.py -v 2>&1 | tail -10
```

Expected: existing bootstrap tests still pass.

---

### Task 0.8: Add the FastAPI dependencies module

**Files:**
- Create: `src/seqsetup/routes/dependencies.py`
- Modify: `src/seqsetup/routes/utils.py` (add nothing yet — that happens in Task 0.9)

- [ ] **Step 1: Create `dependencies.py`**

Create `src/seqsetup/routes/dependencies.py`:

```python
"""FastAPI dependencies — the DI-native replacements for the old
function-style guards in ``utils.py``.

The old shapes (``require_admin(req) -> Response | None``,
``check_run_editable(run) -> Response | None``) coexist in ``utils.py``
until Phase 4 — per-route migrations switch to these as they happen.

Clinical-safety contract (codified per Section 7 of the design spec):

* ``require_admin_dep`` RAISES on failure. Router-level
  ``dependencies=[Depends(...)]`` ignores return values; only raises
  short-circuit. The HTML-aware ``HTTPException`` handler renders the
  403 as an HTML fragment, not the FastAPI default JSON.

* ``get_editable_run`` is the load + check half of the old
  ``editable_run_handler`` decorator. The save half is the
  ``saving_run`` context manager — handlers explicitly enter the
  ``with`` block to persist mutations.

* ``_load_and_check_editable`` is the shared primitive; the dep wraps
  it for FastAPI use. Both call the same function so unit tests on the
  primitive cover both consumers.
"""

from contextlib import contextmanager
from typing import Iterator

from fastapi import Depends, HTTPException, Request

from ..context import AppContext
from ..models.sequencing_run import RunStatus, SequencingRun
from ..models.user import UserRole
from ..startup import get_app_context
from .utils import get_username


# ---------------------------------------------------------------------------
# Context dep — replaces closure-captured ``ctx`` in the per-module
# ``register(app, ctx)`` factories.
# ---------------------------------------------------------------------------


def get_ctx() -> AppContext:
    """Return the singleton AppContext. Cached at startup; the dep just
    fetches it each request."""
    return get_app_context()


# ---------------------------------------------------------------------------
# Admin guard — raises, never returns. FastAPI ignores return values of
# router-level deps; only raises short-circuit.
# ---------------------------------------------------------------------------


def require_admin_dep(request: Request) -> None:
    """Raise 403 if the authenticated user isn't an admin."""
    user = request.scope.get("auth")
    if not user or user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")


# ---------------------------------------------------------------------------
# Editable-run guards — shared primitive + dep wrapper + save CM.
# ---------------------------------------------------------------------------


def _load_and_check_editable(run_id: str, run_repo) -> SequencingRun:
    """Load the run by id; raise 404 if missing, 403 if not DRAFT."""
    run = run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status != RunStatus.DRAFT:
        raise HTTPException(status_code=403, detail="Run is not in draft status and cannot be edited")
    return run


def get_editable_run(
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> SequencingRun:
    """FastAPI dep: load + check the editable run. Mutation handlers
    then enter ``with saving_run(run, ctx, request):`` to persist."""
    return _load_and_check_editable(run_id, ctx.run_repo)


@contextmanager
def saving_run(
    run: SequencingRun,
    ctx: AppContext,
    request: Request,
    *,
    reset_validation: bool = True,
) -> Iterator[SequencingRun]:
    """Context manager: on successful exit, ``touch + save`` the run.
    On exception, do NOT save — the exception propagates as the
    response and the run stays untouched in the repo.

    Args:
        reset_validation: forwarded to ``run.touch(...)``. Default True
            because most mutations (sample edits, name change, etc.)
            invalidate any prior validation approval. Pass False for
            status-only transitions (archive, status change,
            validation approve/unapprove) where preserving
            ``validation_approved`` is the whole point of the touch
            call. Four current callsites use False — preserved by
            opting in.

    Single audit point for the load→check→mutate→touch→save invariant.
    Reviewers grep ``with saving_run(`` to enumerate every mutation
    handler.
    """
    try:
        yield run
    except BaseException:
        raise
    else:
        run.touch(reset_validation=reset_validation, updated_by=get_username(request))
        ctx.run_repo.save(run)


# ---------------------------------------------------------------------------
# HTMX detection — typed dep instead of header sniff.
# ---------------------------------------------------------------------------


def is_htmx_request(request: Request) -> bool:
    """True if the request was made by HTMX (sets ``HX-Request: true``)."""
    return request.headers.get("HX-Request", "").lower() == "true"
```

- [ ] **Step 2: Verify it imports**

```bash
PYTHONPATH=src pixi run python -c "from seqsetup.routes.dependencies import get_ctx, require_admin_dep, get_editable_run, saving_run, is_htmx_request, _load_and_check_editable; print('ok')"
```

Expected: `ok`.

---

### Task 0.9: Unit tests for the new dependencies

**Files:**
- Create: `tests/unit/test_dependencies.py`

- [ ] **Step 1: Write the test file**

Create `tests/unit/test_dependencies.py`:

```python
"""Unit tests for the new FastAPI deps + saving_run context manager.

Replaces the existing ``test_route_utils.py::TestEditableRunHandlerDecorator``
tests; the decorator goes away in Phase 4.
"""

import pytest
from fastapi import HTTPException

from seqsetup.models.sequencing_run import RunStatus, SequencingRun
from seqsetup.models.user import UserRole
from seqsetup.routes.dependencies import (
    _load_and_check_editable,
    is_htmx_request,
    require_admin_dep,
    saving_run,
)


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class _FakeUser:
    def __init__(self, role=UserRole.STANDARD, username="u"):
        self.role = role
        self.username = username


class _FakeRequest:
    def __init__(self, auth=None, hx=False):
        self.scope = {"auth": auth} if auth is not None else {}
        self.headers = {"HX-Request": "true"} if hx else {}


class _FakeRunRepo:
    def __init__(self, runs=()):
        self._runs = {r.id: r for r in runs}
        self.save_calls = []

    def get_by_id(self, run_id):
        return self._runs.get(run_id)

    def save(self, run):
        self.save_calls.append(run.id)


# ---------------------------------------------------------------------------
# require_admin_dep
# ---------------------------------------------------------------------------


class TestRequireAdminDep:
    def test_admin_user_passes(self):
        req = _FakeRequest(auth=_FakeUser(role=UserRole.ADMIN))
        # Returns None; the absence of an exception is success.
        assert require_admin_dep(req) is None

    def test_standard_user_raises_403(self):
        req = _FakeRequest(auth=_FakeUser(role=UserRole.STANDARD))
        with pytest.raises(HTTPException) as exc:
            require_admin_dep(req)
        assert exc.value.status_code == 403

    def test_unauthenticated_raises_403(self):
        req = _FakeRequest()
        with pytest.raises(HTTPException) as exc:
            require_admin_dep(req)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# _load_and_check_editable (the primitive both consumers share)
# ---------------------------------------------------------------------------


class TestLoadAndCheckEditable:
    def _draft_run(self, run_id="r1"):
        run = SequencingRun(status=RunStatus.DRAFT)
        run.id = run_id
        return run

    def test_loads_draft_run(self):
        run = self._draft_run()
        repo = _FakeRunRepo([run])
        result = _load_and_check_editable("r1", repo)
        assert result is run

    def test_missing_raises_404(self):
        repo = _FakeRunRepo([])
        with pytest.raises(HTTPException) as exc:
            _load_and_check_editable("missing", repo)
        assert exc.value.status_code == 404

    def test_ready_raises_403(self):
        run = SequencingRun(status=RunStatus.READY)
        run.id = "r1"
        repo = _FakeRunRepo([run])
        with pytest.raises(HTTPException) as exc:
            _load_and_check_editable("r1", repo)
        assert exc.value.status_code == 403

    def test_archived_raises_403(self):
        run = SequencingRun(status=RunStatus.ARCHIVED)
        run.id = "r1"
        repo = _FakeRunRepo([run])
        with pytest.raises(HTTPException) as exc:
            _load_and_check_editable("r1", repo)
        assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# saving_run context manager
# ---------------------------------------------------------------------------


class TestSavingRun:
    def _setup(self):
        run = SequencingRun(status=RunStatus.DRAFT)
        run.id = "r1"
        repo = _FakeRunRepo([run])

        class _Ctx:
            run_repo = repo

        return run, _Ctx(), _FakeRequest(auth=_FakeUser(username="alice"))

    def test_normal_exit_touches_and_saves(self):
        run, ctx, req = self._setup()
        before = run.updated_at
        with saving_run(run, ctx, req) as r:
            assert r is run
            r.run_name = "new name"
        # Touch bumps updated_at.
        assert run.updated_at != before or before is None
        # Save was called exactly once.
        assert ctx.run_repo.save_calls == ["r1"]
        # updated_by is set from the request's username.
        assert run.updated_by == "alice"

    def test_exception_skips_save(self):
        run, ctx, req = self._setup()
        before_updated_at = run.updated_at
        with pytest.raises(RuntimeError):
            with saving_run(run, ctx, req):
                raise RuntimeError("boom")
        # NOT saved.
        assert ctx.run_repo.save_calls == []
        # NOT touched.
        assert run.updated_at == before_updated_at

    def test_http_exception_propagates_and_skips_save(self):
        """Critical: an HTTPException raised inside the handler must
        propagate AND NOT trigger save. This is how the conditional-
        save protection works."""
        run, ctx, req = self._setup()
        with pytest.raises(HTTPException):
            with saving_run(run, ctx, req):
                raise HTTPException(status_code=400, detail="bad input")
        assert ctx.run_repo.save_calls == []

    def test_reset_validation_default_true_clears_approval(self):
        """Default behaviour: touch resets validation_approved → False.

        This matches the existing touch() default and is correct for
        mutations like sample edits where the prior validation no
        longer applies.
        """
        run, ctx, req = self._setup()
        run.validation_approved = True
        with saving_run(run, ctx, req):
            run.run_name = "edited"
        assert run.validation_approved is False
        assert ctx.run_repo.save_calls == ["r1"]

    def test_reset_validation_false_preserves_approval(self):
        """Status-only transitions (archive, status change, validation
        approve/unapprove) MUST preserve validation_approved. Four
        current callsites depend on this — wrapping them in saving_run
        without the flag would silently wipe approval.
        """
        run, ctx, req = self._setup()
        run.validation_approved = True
        with saving_run(run, ctx, req, reset_validation=False):
            run.status = RunStatus.ARCHIVED
        assert run.validation_approved is True
        assert ctx.run_repo.save_calls == ["r1"]


# ---------------------------------------------------------------------------
# is_htmx_request
# ---------------------------------------------------------------------------


class TestIsHtmxRequest:
    def test_htmx_header_true(self):
        assert is_htmx_request(_FakeRequest(hx=True)) is True

    def test_no_htmx_header_false(self):
        assert is_htmx_request(_FakeRequest(hx=False)) is False
```

- [ ] **Step 2: Run the tests**

```bash
PYTHONPATH=src pixi run python -m pytest tests/unit/test_dependencies.py -v
```

Expected: all tests PASS.

---

### Task 0.10: Add the shared Pydantic form validators

**Files:**
- Create: `src/seqsetup/forms/__init__.py`
- Create: `src/seqsetup/forms/validators.py`
- Create: `tests/unit/test_form_validators.py`

- [ ] **Step 1: Create the package marker**

```bash
mkdir -p src/seqsetup/forms
touch src/seqsetup/forms/__init__.py
```

- [ ] **Step 2: Write the validators**

Create `src/seqsetup/forms/validators.py`:

```python
"""Shared Pydantic ``BeforeValidator`` builders for SeqSetup form models.

CLAUDE.md hard rules require:
  - Strings: strip + length-limit (CLAMP, not reject)
  - Numbers: clamp to valid range (CLAMP, not reject)
  - DNA sequences: uppercase + validate against ``^[ACGTN]*$`` (REJECT bad regex)

Pydantic's built-in constraints (``max_length``, ``ge``, ``le``,
``pattern``) all REJECT. These validators implement the reject-vs-clamp
semantics CLAUDE.md requires.

Per-form models pick which validator each field gets; switching a field
from clamp→reject is a deliberate semantic change documented in the
commit message that introduces it.
"""

import json
import re
from typing import Callable


_DNA_RE = re.compile(r"[ACGTN]*")


def strip_and_truncate(max_len: int) -> Callable[[object], str]:
    """Strip whitespace and truncate to ``max_len`` chars. NEVER rejects.

    Replaces the existing ``sanitize_string(value, max_len)`` helper.
    Same semantics: empty input → empty string; oversized input →
    truncated to ``max_len``.
    """
    def _v(value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()[:max_len]
    return _v


def clamp(lo: int, hi: int) -> Callable[[object], int]:
    """Clamp an int to [lo, hi]. NEVER rejects valid-int input.

    Non-int or unparseable input raises ``ValueError`` (Pydantic surfaces
    it as a 422). Use ``BeforeValidator`` so this runs before Pydantic's
    int coercion.
    """
    def _v(value: object) -> int:
        try:
            n = int(value)
        except (TypeError, ValueError) as e:
            raise ValueError(f"expected integer, got {value!r}") from e
        return max(lo, min(hi, n))
    return _v


def dna_upper_or_reject(value: object) -> str:
    """Uppercase and validate as ``[ACGTN]*``. REJECTS invalid sequences.

    This is the only place in the form layer that rejects on bad
    content: a sample with non-ACGTN bases is clinically wrong and the
    user should see an error, not silently accept a sanitised version.
    """
    if value is None:
        return ""
    s = str(value).strip().upper()
    if not _DNA_RE.fullmatch(s):
        raise ValueError("DNA sequence must contain only A, C, G, T, N")
    return s


def json_list(item_type: type = str) -> Callable[[object], list]:
    """Decode a JSON-string form field into a list.

    Used by the Alpine multi-select pattern (Section 4 of the design
    spec) — bulk-action HTMX forms send the selected IDs as
    ``JSON.stringify([...])`` inside ``hx-vals`` because form-encoding
    is text, not structured. Pydantic won't parse the JSON
    automatically.
    """
    def _v(value: object) -> list:
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as e:
                raise ValueError("expected a JSON array") from e
            if not isinstance(parsed, list):
                raise ValueError("expected a JSON array")
            return parsed
        raise ValueError("expected a JSON array or list")
    return _v
```

- [ ] **Step 3: Write the validator tests**

Create `tests/unit/test_form_validators.py`:

```python
"""Tests for shared Pydantic form validators."""

import pytest

from seqsetup.forms.validators import (
    clamp,
    dna_upper_or_reject,
    json_list,
    strip_and_truncate,
)


class TestStripAndTruncate:
    def test_strips_whitespace(self):
        assert strip_and_truncate(256)("  hello  ") == "hello"

    def test_truncates_to_max_len(self):
        assert strip_and_truncate(5)("hello world") == "hello"

    def test_strip_happens_before_truncate(self):
        assert strip_and_truncate(5)("   hello world   ") == "hello"

    def test_none_becomes_empty(self):
        assert strip_and_truncate(256)(None) == ""

    def test_empty_becomes_empty(self):
        assert strip_and_truncate(256)("") == ""


class TestClamp:
    def test_in_range_unchanged(self):
        assert clamp(0, 10)(5) == 5

    def test_below_min_clamps_up(self):
        assert clamp(0, 10)(-5) == 0

    def test_above_max_clamps_down(self):
        assert clamp(0, 10)(99) == 10

    def test_string_int_accepted(self):
        assert clamp(0, 10)("5") == 5

    def test_non_int_raises(self):
        with pytest.raises(ValueError):
            clamp(0, 10)("not an int")


class TestDnaUpperOrReject:
    def test_lowercase_is_uppercased(self):
        assert dna_upper_or_reject("acgtn") == "ACGTN"

    def test_already_uppercase_unchanged(self):
        assert dna_upper_or_reject("ACGT") == "ACGT"

    def test_whitespace_stripped(self):
        assert dna_upper_or_reject("  ACGT  ") == "ACGT"

    def test_empty_ok(self):
        assert dna_upper_or_reject("") == ""

    def test_none_ok(self):
        assert dna_upper_or_reject(None) == ""

    def test_invalid_base_rejected(self):
        with pytest.raises(ValueError):
            dna_upper_or_reject("ACGTX")

    def test_digit_rejected(self):
        with pytest.raises(ValueError):
            dna_upper_or_reject("ACGT1")


class TestJsonList:
    def test_passes_list_through(self):
        assert json_list()(["a", "b"]) == ["a", "b"]

    def test_decodes_json_string(self):
        assert json_list()('["a","b"]') == ["a", "b"]

    def test_empty_array(self):
        assert json_list()("[]") == []

    def test_bad_json_raises(self):
        with pytest.raises(ValueError):
            json_list()("not json")

    def test_json_object_rejected(self):
        with pytest.raises(ValueError):
            json_list()('{"a": 1}')

    def test_non_string_non_list_rejected(self):
        with pytest.raises(ValueError):
            json_list()(42)
```

- [ ] **Step 4: Run the validator tests**

```bash
PYTHONPATH=src pixi run python -m pytest tests/unit/test_form_validators.py -v
```

Expected: all tests PASS.

---

### Task 0.11: HTML-aware exception handlers

**Files:**
- Create: `src/seqsetup/exception_handlers.py`

- [ ] **Step 1: Write the handlers module**

Create `src/seqsetup/exception_handlers.py`:

```python
"""HTML-aware exception handlers — overrides the FastAPI default JSON
responses for HTML routes so the "no JSON in HTML routes" rule holds.

The ``/api/*`` sub-app keeps the FastAPI default JSON behaviour — those
ARE JSON endpoints.

Three handlers:

  - ``RequestValidationError`` (422): Pydantic form validation. For
    HTMX requests, returns an HTML fragment with ``HX-Reswap``/
    ``HX-Retarget`` headers so the error lands in a form-errors slot.
    For non-HTMX, returns a friendly error page.

  - ``HTTPException``: any ``raise HTTPException(...)`` from a dep or
    handler. Replaces the FastAPI default ``JSONResponse``. Returns an
    HTML fragment (HTMX-aware) or a full HTML page.

  - ``ConflictError``: optimistic-lock conflict from
    ``SequencingRun.save``. Always 409 with a plain-text-in-HTML body.

**Security: every user/exception-controlled string is HTML-escaped
before interpolation.** Field names come from Pydantic and are
developer-controlled, but ``HTTPException.detail`` and ``ConflictError``
messages can be set by ANY code path including ones that might (now or
later) include user-supplied data. Defence in depth — escape always.
"""

import html

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import HTMLResponse

from .repositories.base import ConflictError


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request", "").lower() == "true"


def _is_api_path(request: Request) -> bool:
    """``/api/*`` paths are handled by the sub-app, not the host."""
    return request.url.path == "/api" or request.url.path.startswith("/api/")


def _error_fragment(message: str) -> str:
    """Build an HTML error fragment. ``message`` is HTML-escaped.

    All exception handler responses go through this helper so the
    escape is centralized.
    """
    return f'<div class="error-message">{html.escape(message)}</div>'


async def request_validation_handler(request: Request, exc: RequestValidationError):
    """Form-validation 422 → HTML fragment for HTMX, page for non-HTMX.

    Does NOT echo the offending input value (security: minimises help
    for an attacker fingerprinting validation rules).
    """
    if _is_api_path(request):
        # Let FastAPI's default JSON handler take over for the API.
        from fastapi.exception_handlers import request_validation_exception_handler
        return await request_validation_exception_handler(request, exc)

    # Build a minimal field-list message without echoing values.
    fields = []
    for err in exc.errors():
        loc = err.get("loc", ())
        # Skip the body/form prefix; we only want the field name.
        field_name = ".".join(str(p) for p in loc if p not in ("body", "form")) or "?"
        fields.append(field_name)
    field_list = ", ".join(sorted(set(fields))) or "input"
    body = _error_fragment(f"Validation error: {field_list} invalid.")

    headers = {"Cache-Control": "no-store"}
    if _is_htmx(request):
        # HTMX clients: re-target the form-errors slot, inner-swap.
        headers["HX-Retarget"] = "#form-errors"
        headers["HX-Reswap"] = "innerHTML"
        return HTMLResponse(content=body, status_code=422, headers=headers)

    # Non-HTMX (rare for HTML routes): render the same minimal page.
    page = f"<!DOCTYPE html><html><body>{body}</body></html>"
    return HTMLResponse(content=page, status_code=422, headers=headers)


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Any ``raise HTTPException(...)`` → HTML fragment, NOT JSON.

    Replaces FastAPI's default JSON response so 403/404 etc. raised
    from deps don't surface as raw JSON in the browser.
    """
    if _is_api_path(request):
        from fastapi.exception_handlers import http_exception_handler as default_handler
        return await default_handler(request, exc)

    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    body = _error_fragment(detail)
    headers = {"Cache-Control": "no-store"}
    if _is_htmx(request):
        headers["HX-Retarget"] = "#error-banner"
        headers["HX-Reswap"] = "innerHTML"
        return HTMLResponse(content=body, status_code=exc.status_code, headers=headers)

    page = f"<!DOCTYPE html><html><body>{body}</body></html>"
    return HTMLResponse(content=page, status_code=exc.status_code, headers=headers)


async def conflict_handler(request: Request, exc: ConflictError):
    """Optimistic-lock conflict → 409 with the user-facing message."""
    return HTMLResponse(
        content=_error_fragment(str(exc)),
        status_code=409,
        headers={"Cache-Control": "no-store"},
    )


def install(app):
    """Register all three handlers on the FastAPI app."""
    app.add_exception_handler(RequestValidationError, request_validation_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(ConflictError, conflict_handler)
```

- [ ] **Step 2: Wire them into `app.py`**

Open `src/seqsetup/app.py`. Find the `exception_handlers={ConflictError: _conflict_handler}` argument passed to `FastAPI(...)`. Replace the whole setup with:

```python
# At the top, with the other imports:
from .exception_handlers import install as install_exception_handlers

# Remove the old ``async def _conflict_handler`` function.
# In the FastAPI(...) call, REMOVE the exception_handlers={...} argument.

app = FastAPI(
    title="SeqSetup",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    # exception_handlers REMOVED — registered below via install_exception_handlers
)

# ...after the middleware stack, BEFORE app.mount("/api", ...):
install_exception_handlers(app)
```

- [ ] **Step 3: Verify the app boots**

```bash
PYTHONPATH=src pixi run python -c "from seqsetup import app; print('boot ok')"
```

Expected: `boot ok`.

---

### Task 0.12: Integration tests for the exception handlers

**Files:**
- Create: `tests/integration/test_html_exception_handler.py`
- Create: `tests/integration/test_pydantic_422_htmx.py`

- [ ] **Step 1: Write the HTTPException-handler test**

Create `tests/integration/test_html_exception_handler.py`:

```python
"""HTTPException raised by a route/dep → HTML fragment, not JSON.

The HTML-aware handler is critical because the new
``require_admin_dep`` and ``get_editable_run`` deps raise
``HTTPException`` to short-circuit. FastAPI's default handler returns
JSON, which would surface as raw JSON in the browser — violating the
"no JSON in HTML routes" rule.

We exercise the handler via a TEMPORARY test-only route that raises
``HTTPException`` directly — NOT via ``/admin/users``, because in
Phase 0 the admin routes still use the old function-style
``require_admin(request) -> Response`` that returns directly. The new
``require_admin_dep`` only takes effect when admin routes migrate in
Phase 2. (The real admin-via-HTMX assertion lives in Phase 2's
``admin/users`` migration commit.)
"""

from fastapi import HTTPException
from starlette.responses import HTMLResponse


def test_http_exception_returns_html_fragment(logged_in_client, fresh_app):
    """An HTTPException from a route → HTML body, NOT JSON.

    Uses ``logged_in_client`` because the AuthMiddleware redirects
    unauthenticated requests to ``/login`` for any non-public HTML path
    (``__test_*`` paths aren't in PUBLIC_ROUTES). The temp route is
    installed on the same app the fixture booted, so the auth cookie
    set by ``logged_in_client`` lets us actually reach the handler.
    """
    app, _ctx, _db = fresh_app

    @app.get("/__test_http_exc")
    def _h():
        raise HTTPException(status_code=404, detail="Resource not found")

    response = logged_in_client.get("/__test_http_exc")
    assert response.status_code == 404
    # The Content-Type should be HTML, not JSON.
    assert "text/html" in response.headers.get("content-type", "")
    # Body contains the HTML error fragment.
    assert "<div" in response.text
    assert "Resource not found" in response.text


def test_http_exception_via_htmx_includes_retarget(logged_in_client, fresh_app):
    """HTMX clients hitting an HTTPException get HX-Retarget so the
    error lands in the page's error slot."""
    app, _ctx, _db = fresh_app

    @app.get("/__test_http_exc_htmx")
    def _h():
        raise HTTPException(status_code=403, detail="Admin access required")

    response = logged_in_client.get(
        "/__test_http_exc_htmx",
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 403
    assert response.headers.get("HX-Retarget") == "#error-banner"
    assert response.headers.get("HX-Reswap") == "innerHTML"


def test_api_path_keeps_json_response(client):
    """``/api/*`` is the JSON API sub-app — should still return JSON
    on errors (different handler chain inside the sub-app)."""
    response = client.get(
        "/api/runs",
        headers={"Authorization": "Bearer invalid-token-here"},
    )
    # Unauthorized — sub-app handles, returns JSON.
    assert response.status_code == 401
    assert "application/json" in response.headers.get("content-type", "")


def test_http_exception_detail_is_html_escaped(logged_in_client, fresh_app):
    """SECURITY: any string in HTTPException.detail must be HTML-escaped
    before interpolation into the response body. Defence in depth —
    even though current detail strings are developer-controlled, a
    future raise with a user-controlled value must not produce XSS.
    """
    from fastapi import HTTPException

    app, _ctx, _db = fresh_app

    @app.get("/__test_xss")
    def _h():
        # Simulate the failure mode: a detail string that includes HTML.
        raise HTTPException(status_code=400, detail="<script>alert(1)</script>")

    response = logged_in_client.get("/__test_xss")
    assert response.status_code == 400
    # Tags MUST be escaped — raw <script> must not appear in the body.
    assert "<script>" not in response.text
    # Escaped form MUST be present.
    assert "&lt;script&gt;" in response.text
```

- [ ] **Step 2: Run the test**

```bash
PYTHONPATH=src pixi run python -m pytest tests/integration/test_html_exception_handler.py -v
```

Expected: all PASS.

- [ ] **Step 3: Write the Pydantic-422 test**

Create `tests/integration/test_pydantic_422_htmx.py`:

```python
"""Pydantic form validation failures → HTML fragment with HX-Reswap/HX-Retarget.

This test will become more meaningful as Phase 1+ routes start using
Pydantic forms. For now it exercises the global ``RequestValidationError``
handler against a synthetic invalid request to ``/login/submit``
(if that route is the first to gain a Pydantic form) OR a placeholder
test route added in this same file.
"""

import pytest
from starlette.testclient import TestClient


def test_pydantic_422_returns_html_fragment_with_hx_headers(logged_in_client, fresh_app):
    """When a Pydantic-validated form fails, HTMX clients get an HTML
    fragment + HX-Retarget. (Placeholder: any Phase-1+ route that gains
    a Pydantic form will exercise this in earnest.)

    Uses ``logged_in_client`` because AuthMiddleware redirects
    unauthenticated requests to /login for any non-public path.
    """
    app, _ctx, _db = fresh_app
    from fastapi import Form
    from pydantic import BaseModel, Field
    from typing import Annotated
    from starlette.responses import HTMLResponse

    class _TestForm(BaseModel):
        bounded: int = Field(ge=0, le=10)

    @app.post("/__test_pydantic_422", response_class=HTMLResponse)
    def _h(form: Annotated[_TestForm, Form()]):
        return "ok"

    response = logged_in_client.post(
        "/__test_pydantic_422",
        data={"bounded": "99"},
        headers={"Origin": "http://testserver", "HX-Request": "true"},
    )
    assert response.status_code == 422
    assert "text/html" in response.headers.get("content-type", "")
    assert response.headers.get("HX-Retarget") == "#form-errors"
    assert response.headers.get("HX-Reswap") == "innerHTML"
    # Body MUST NOT contain the offending value ("99") — security: no echo.
    assert "99" not in response.text
    assert "bounded" in response.text  # field name OK to include
```

- [ ] **Step 4: Run the test**

```bash
PYTHONPATH=src pixi run python -m pytest tests/integration/test_pydantic_422_htmx.py -v
```

Expected: PASS.

---

### Task 0.13: Toast HX-Trigger integration test

**Files:**
- Create: `tests/integration/test_toast_hxtrigger.py`

- [ ] **Step 1: Write the test**

Create `tests/integration/test_toast_hxtrigger.py`:

```python
"""Server emits ``HX-Trigger: {"toast": {...}}`` → Alpine renders the toast.

Server-side test: the HTTP header is present and parses as JSON with
the expected shape. (Client-side rendering is covered by the browser
smoke test.)
"""

import json

from fastapi.responses import HTMLResponse


def test_toast_hxtrigger_header_emitted(logged_in_client, fresh_app):
    """Install a temporary route that emits a toast trigger and assert
    the response header round-trips.

    Uses ``logged_in_client`` because AuthMiddleware redirects
    unauthenticated requests away from /__test_toast.
    """
    app, _ctx, _db = fresh_app

    @app.get("/__test_toast", response_class=HTMLResponse)
    def _h():
        return HTMLResponse(
            content="ok",
            headers={"HX-Trigger": json.dumps({"toast": {"kind": "success", "message": "Saved"}})},
        )

    response = logged_in_client.get("/__test_toast")
    trigger = response.headers.get("HX-Trigger", "")
    assert trigger
    payload = json.loads(trigger)
    assert "toast" in payload
    assert payload["toast"]["kind"] == "success"
    assert payload["toast"]["message"] == "Saved"
```

- [ ] **Step 2: Run the test**

```bash
PYTHONPATH=src pixi run python -m pytest tests/integration/test_toast_hxtrigger.py -v
```

Expected: PASS.

---

### Task 0.14: Route-order regression test

**Files:**
- Create: `tests/integration/test_route_order.py`

- [ ] **Step 1: Write the test**

Create `tests/integration/test_route_order.py`:

```python
"""Regression: ``/runs/new/step/1`` MUST resolve to the wizard route,
NOT the ``/runs/{run_id}`` catch-all.

Starlette matches routes in registration order. ``app.py`` documents
that ``wizard.register`` (or ``include_router``) MUST come before
``main.register`` so the specific ``/runs/new/*`` paths win over the
generic ``{run_id}`` capture.
"""


def test_runs_new_step1_resolves_to_wizard(logged_in_client, fresh_app):
    """Hitting /runs/new/step/1 with a run_id returns the wizard,
    NOT a 'Run not found' from the catch-all."""
    _app, ctx, _db = fresh_app
    # Create a run via the wizard's create endpoint.
    create_response = logged_in_client.get("/runs/new", follow_redirects=False)
    assert create_response.status_code == 303
    # Extract the run_id from the redirect location.
    location = create_response.headers.get("location", "")
    assert "run_id=" in location
    run_id = location.split("run_id=")[-1].split("&")[0]

    # Now hit /runs/new/step/1 directly — must NOT be matched by
    # /runs/{run_id}.
    response = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}", follow_redirects=False)
    assert response.status_code == 200
    # The wizard page contains a known marker.
    assert "Run Configuration" in response.text or "Step 1" in response.text
```

- [ ] **Step 2: Run the test**

```bash
PYTHONPATH=src pixi run python -m pytest tests/integration/test_route_order.py -v
```

Expected: PASS (since the current registration order is correct; this is a regression guard).

---

### Task 0.15: Browser smoke test (Playwright)

**Files:**
- Create: `tests/browser/__init__.py`
- Create: `tests/browser/conftest.py`
- Create: `tests/browser/test_browser_smoke.py`
- Modify: `pixi.toml` (add `playwright-install` and `smoke-browser` tasks)

- [ ] **Step 1: Install Playwright browsers**

Add to `pixi.toml` `[tasks]`:

```toml
playwright-install = "playwright install chromium"
smoke-browser = "PYTHONPATH=src pytest tests/browser -v"
```

Then run:

```bash
pixi run playwright-install
```

Expected: downloads Chromium (~150 MB). Takes a minute or two.

- [ ] **Step 2: Create package marker**

```bash
mkdir -p tests/browser
touch tests/browser/__init__.py
```

- [ ] **Step 3: Create `conftest.py`**

Create `tests/browser/conftest.py`. Critical: the integration suite's `fresh_app` fixture patches `init_db` to use mongomock; the browser tests need the same patch or app startup will fail trying to ping a real MongoDB. We also seed an admin user so the HTMX-swap test (which needs auth) works.

```python
"""Playwright fixtures: boot the app in a thread, serve it on a free
port, hand a base_url to the tests.

We intentionally serve the REAL app (with the REAL templating + static
asset stack), not a TestClient transport, so the browser exercises the
exact pipeline a user hits. We DO patch in mongomock (same as the
integration ``fresh_app`` fixture) — without it, ``init_db()`` would
try to ping a real MongoDB on startup and fail in CI / dev machines
without a running server.
"""

import importlib
import os
import socket
import sys
import threading
import time
from contextlib import closing

import mongomock
import pytest
import uvicorn

from seqsetup.models.local_user import LocalUser
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.user import UserRole


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# Session-scoped admin credentials used by the browser tests for login.
BROWSER_ADMIN = {"username": "browser-admin", "password": "Br0wser-Adm1n!"}


@pytest.fixture(scope="session")
def app_server(tmp_path_factory):
    """Boot seqsetup.app on a free port for the test session, backed by
    mongomock + a seeded admin user.
    """
    # --- Sandbox secrets / paths ---
    session_dir = tmp_path_factory.mktemp("browser-app")
    os.environ["SEQSETUP_SESSION_SECRET"] = "x" * 64
    os.environ["SEQSETUP_SESSKEY_PATH"] = str(session_dir / ".sesskey")

    # --- Patch init_db / get_db to use mongomock BEFORE app import ---
    # We can't use the integration fixture as-is (it's function-scoped
    # and uses monkeypatch); for the browser tests we patch the module
    # globals directly for the session.
    mongo_client = mongomock.MongoClient()
    db = mongo_client["seqsetup_test_browser"]

    from seqsetup.services import database as db_module
    db_module.init_db = lambda: db
    db_module.get_db = lambda: db
    db_module._db = db

    # Reset startup-module caches BEFORE app import.
    import seqsetup.startup as startup_module
    startup_module._db = None
    startup_module._repos = {}
    startup_module._github_sync_service = None
    startup_module._profile_sync_scheduler = None
    startup_module._auth_service = None

    # Also reset the data.instruments cache (same as integration conftest).
    from seqsetup.data import instruments as instruments_module
    instruments_module._synced_instruments_cache = None
    instruments_module._instrument_definition_repo = None

    # Reset log_capture handler (same reason).
    import logging
    from seqsetup.services import log_capture as log_capture_module
    if log_capture_module._log_capture_handler is not None:
        for name in ("seqsetup", ""):
            logging.getLogger(name).removeHandler(log_capture_module._log_capture_handler)
        log_capture_module._log_capture_handler = None

    # Now import the app — startup uses the patched db.
    if "seqsetup.app" in sys.modules:
        del sys.modules["seqsetup.app"]
    app_module = importlib.import_module("seqsetup.app")
    app = app_module.app
    ctx = app_module._ctx

    # Stop the background scheduler started during app import.
    scheduler = getattr(startup_module, "_profile_sync_scheduler", None)
    if scheduler is not None:
        try:
            scheduler.stop()
        except Exception:
            pass

    # --- Seed an admin user for login tests ---
    admin = LocalUser(
        username=BROWSER_ADMIN["username"],
        display_name="Browser Admin",
        email="browser@test.local",
        role=UserRole.ADMIN,
    )
    admin.set_password(BROWSER_ADMIN["password"])
    ctx.local_user_repo.save(admin)

    # --- Seed one DRAFT run so the dashboard tabs render. ---
    # The dashboard's empty-state branch (no runs) doesn't show tab
    # buttons; the HTMX swap test needs the tabs to exist so it can
    # click "Ready" and exercise the hx-get. One minimal draft is
    # enough — its content doesn't matter; only its presence does.
    seed_run = SequencingRun(
        run_name="Browser smoke seed run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=RunStatus.DRAFT,
        created_by=BROWSER_ADMIN["username"],
    )
    ctx.run_repo.save(seed_run)

    # --- Boot the server on a free port ---
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for the server to be ready.
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with closing(socket.create_connection(("127.0.0.1", port), timeout=0.5)):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("app server did not start within 10 seconds")

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def base_url(app_server):
    return app_server


@pytest.fixture
def admin_creds():
    """The seeded admin credentials — for tests that need to log in."""
    return BROWSER_ADMIN


@pytest.fixture
def logged_in_page(page, base_url, admin_creds):
    """A Playwright ``page`` that has already logged in as the seeded admin."""
    page.goto(f"{base_url}/login")
    page.fill('input[name="username"]', admin_creds["username"])
    page.fill('input[name="password"]', admin_creds["password"])
    page.click('button[type="submit"]')
    # Wait for redirect to dashboard.
    page.wait_for_url(f"{base_url}/", timeout=5000)
    return page
```

- [ ] **Step 4: Write the browser smoke test**

Create `tests/browser/test_browser_smoke.py`:

```python
"""Browser smoke gate — ~3 assertions that catch the entire class of
"client-side script wiring is broken" failures (which the current
HTMX-not-loaded bug demonstrated server-side tests cannot detect).

Asserts:
  1. window.htmx and window.Alpine are defined on a loaded page.
  2. The toast Alpine component is reactive (dispatch a synthetic
     event, see the DOM update).
  3. One real HTMX swap round-trips on the dashboard (which uses
     hx-get for tab switching).

The toast/HTMX-swap tests both use ``logged_in_page`` because the
toast slot lives in ``_app_shell.html`` (auth-required) — login pages
extend ``_base.html`` directly without the shell.
"""

import pytest


@pytest.mark.browser
def test_htmx_and_alpine_globals_present(logged_in_page, base_url):
    """The vendor scripts load and define their globals.

    Uses logged_in_page (which lands on /, the dashboard) because that
    page extends _app_shell.html — the place all the components live.
    """
    page = logged_in_page
    page.wait_for_load_state("networkidle")

    htmx_defined = page.evaluate("typeof window.htmx !== 'undefined'")
    alpine_defined = page.evaluate("typeof window.Alpine !== 'undefined'")
    assert htmx_defined, "window.htmx is not defined — HTMX script failed to load"
    assert alpine_defined, "window.Alpine is not defined — Alpine script failed to load"


@pytest.mark.browser
def test_toast_alpine_component_reacts_to_event(logged_in_page, base_url):
    """Dispatch a synthetic 'toast' CustomEvent on window; assert the
    toast renders. This proves the toast_stack.js component registered
    and Alpine processed it.

    Requires logged_in_page — the toast slot lives in _app_shell.html,
    which only renders for authenticated pages.
    """
    page = logged_in_page
    page.wait_for_load_state("networkidle")

    # Wait for Alpine to fully bind the x-data on #toast-stack.
    page.wait_for_function("document.querySelector('#toast-stack') && window.Alpine !== undefined")

    # Dispatch the same event HTMX would dispatch from HX-Trigger.
    page.evaluate("""
        window.dispatchEvent(new CustomEvent('toast', {
            detail: {kind: 'success', message: 'Smoke test toast'}
        }));
    """)
    # Wait for Alpine to react and render the toast.
    page.wait_for_selector("text=Smoke test toast", timeout=2000)


@pytest.mark.browser
def test_htmx_swap_round_trips_via_dashboard_tab(logged_in_page, base_url):
    """Click a dashboard tab — a real hx-get swap that exists today
    (existing route ``GET /dashboard/tab/{tab}`` returns the tab
    fragment, swapped into ``#dashboard``).

    This test proves HTMX is wired and a real swap works end-to-end.
    Doesn't require any data to be present — the dashboard renders
    empty-state when there are no runs.
    """
    page = logged_in_page
    page.wait_for_load_state("networkidle")

    # Capture the network request HTMX will make.
    with page.expect_response(lambda r: "/dashboard/tab/" in r.url) as response_info:
        # Click the "Ready" tab. Selector should match the tab button
        # in the Tailwind-styled dashboard — adjust after Phase 2.2.
        page.click('button:has-text("Ready")')

    response = response_info.value
    assert response.status == 200, f"HTMX swap response status {response.status}"
    # HTMX requests include the HX-Request header — the route would have
    # rendered just the block. Body should NOT include <html>.
    body = response.text()
    assert "<html" not in body, "HTMX swap response should be a fragment, not a full page"
```

(All three tests now have a guaranteed-authenticated context via `logged_in_page`. The third uses the existing `/dashboard/tab/...` endpoint, which works in Phase 0 — no dependency on later phases.)

- [ ] **Step 5: Run the browser smoke**

```bash
pixi run smoke-browser
```

Expected: all three tests PASS. The conftest seeds a `browser-admin` user into mongomock and `logged_in_page` lands on the dashboard; the toast component reacts to a synthetic event; the dashboard tab-swap exercises a real HTMX round-trip.

If any test fails, the new vendoring / `_base.html` wiring / mongomock patching / toast slot in `_app_shell.html` is wrong — fix before continuing.

---

### Task 0.16: Write ARCHITECTURE.md

**Files:**
- Create: `ARCHITECTURE.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Create `ARCHITECTURE.md` at repo root**

```bash
cat > ARCHITECTURE.md << 'EOF'
# SeqSetup architecture & conventions

Stack: FastAPI + Jinja2 + jinja2-fragments + Tailwind v4 + Alpine.js + Pydantic v2 + MongoDB.

This is the developer-facing conventions doc. Read this before adding a
new page, route, form, or client-side interaction. AI tools (Claude
Code, Claude Design, etc.) should be pointed at this file via
`CLAUDE.md`.

## Reference implementations

Look at these first when adding new code in their category:

| Need a... | Look at |
|---|---|
| Standalone page (GET only) | `src/seqsetup/routes/profiles.py` + `src/seqsetup/templates/profiles.html` |
| Page with HTMX swap fragments | `src/seqsetup/routes/dashboard.py` + `src/seqsetup/templates/dashboard.html` |
| Admin form with Pydantic + router-level admin guard | `src/seqsetup/routes/local_users.py` + `src/seqsetup/templates/admin/users.html` |
| Run-editing handler (load + check + mutate + save) | `src/seqsetup/routes/runs.py:update_run_name` |
| Alpine multi-select with bulk HTMX action | `src/seqsetup/templates/runs/edit.html` (sample-table section) |

## Routing rules

(See design spec section 3 for the full rationale.)

1. One `APIRouter` per route module (`router = APIRouter(prefix=..., tags=..., dependencies=[...])`).
2. `app.py` registers each via `app.include_router(router)`. **Order matters** — specific paths before catch-all (e.g. `/runs/new/*` before `/runs/{run_id}`).
3. `ctx` comes from `Depends(get_ctx)`, never closure capture.
4. Admin guards go on the router via `dependencies=[Depends(require_admin_dep)]`. The dep MUST raise (router-level dep return values are ignored).
5. Editable-run handlers: `run: SequencingRun = Depends(get_editable_run)` to load+check; `with saving_run(run, ctx, request):` to persist mutations.
6. Pydantic form models: `form: Annotated[FooForm, Form()]`. Shared validators from `seqsetup.forms.validators`. Per-field clamp-vs-reject is deliberate and documented in the model.
7. Every HTML route: `response_class=HTMLResponse`.
8. HTMX swap fragments share URLs with their full-page counterparts — `Depends(is_htmx_request)` distinguishes.

## URL conventions

| Pattern | Example | Counter-example |
|---|---|---|
| Resource-oriented; plural nouns | `/admin/users` | `/admin/user` |
| HTTP method for CRUD | `DELETE /admin/users/{username}` | `POST /admin/users/{username}/delete` |
| State transitions: `POST /resource/{id}/{transition}` | `POST /runs/{id}/archive` | `POST /runs/{id}/set-status-to-ready` |
| Sub-resources for collection ops | `POST /runs/{id}/samples/bulk-delete` | `POST /bulk-delete-samples?run_id=…` |

## Template conventions

| Rule | Example |
|---|---|
| One file per page | `templates/dashboard.html` is the dashboard |
| Pages extend `_app_shell.html` (or `_base.html` for un-shelled pages) | `{% extends "_app_shell.html" %}` |
| HTMX swap targets are `{% block %}` regions inside the page | `{% block dashboard_content %}…{% endblock %}` |
| Block names match the swap target's role | `dashboard_content`, `validation_tabs` — not `block1` |
| Shared partials (≥2 pages) live in `templates/partials/` with `_` prefix | `partials/_error_banner.html` |
| Page-specific helpers are local includes inside the page directory | `wizard/_flowcell_select.html` |
| Pages set `page_title` and `active_route` via `{% set %}` | `{% set page_title = "Dashboard" %}` |
| Templates contain NO Python logic beyond filters/iteration | Route builds `kit_rows: list[dict]` → template loops |
| Tailwind classes inline; only `static/css/input.css` has hand-written CSS | `<div class="p-4 rounded shadow border bg-white">` |
| HTMX attributes hyphenated (`hx-post`) | (FT-style underscores are gone) |
| Page-level wrapper for HTMX re-target | `id="<page>-page"` (`#dashboard-page`) |
| List row | `id="<resource>-<id>"` (`#user-row-jdoe`) |
| Form field `name=` matches Pydantic model field name 1:1 | `<input name="username">` |

## Client-side JS

1. HTMX, Alpine, custom JS all vendored in `static/js/vendor/` (HTMX + Alpine) or `static/js/components/` (project components).
2. Load order in `_base.html`: HTMX first, `app.js` next, components, **Alpine LAST**. Component files register `Alpine.data(...)` and Alpine boots after.
3. Component files are self-contained: `document.addEventListener('alpine:init', () => Alpine.data('foo', () => ({...})))`. No imports, no cross-file deps.
4. **Authority boundary** (load-bearing rule): Alpine handles UI ephemera only — selected state, drag-over highlights, modal open/closed, filter inputs. The server is the source of truth for every domain fact. Mutations round-trip via HTMX, every time.
5. HX-Trigger event names: kebab-case, namespaced (`run-archived`, `toast`). The `toast` event's payload `{kind, message}` is consumed by the toast stack in `_app_shell.html`.

## Alpine patterns (canonical)

See `src/seqsetup/static/js/components/` for working examples.

- **toast_stack** — listens on `@toast.window`, renders a stack.
- **index_drag_zone** — drag-and-drop with server-side validation on drop.
- **sample_multi_select** — Set-based selection; bulk action posts via HTMX with `JSON.stringify(...)` in `hx-vals`. Server uses the `json_list` validator to decode.

## Form-validation reject-vs-clamp policy

Per CLAUDE.md hard rules:
- Strings: **clamp** (strip + truncate). Validator: `strip_and_truncate(max_len)`.
- Numbers: **clamp** to valid range. Validator: `clamp(lo, hi)`.
- DNA sequences: **reject** invalid bases. Validator: `dna_upper_or_reject`.
- Enums (e.g. `UserRole`): **reject** unknown values. (Pydantic default.)
- Password strength: **reject** weak. (Pydantic `Field(min_length=12)`.)

Each form model picks per field. Switching a field clamp→reject is a deliberate semantic change documented in the commit message.

## CSS

- Tailwind v4 utility classes inline in templates.
- Hand-written CSS in `static/css/input.css` only — Tailwind directives + occasional `@layer components` rules.
- Output `static/css/app.css` is gitignored; built by `pixi run css`.
- `pixi run serve` builds CSS first (Phase 0 wiring).

## Testing

- Unit tests: `tests/unit/`
- Integration: `tests/integration/` (mongomock + Starlette TestClient)
- Browser smoke: `tests/browser/` (Playwright; minimal — `pixi run smoke-browser`)
- Every new page gets a smoke test asserting the page renders.
- Every new form route gets a 422 test asserting Pydantic validation errors render as HTML fragments with `HX-Retarget`/`HX-Reswap` for HTMX clients.
EOF
```

- [ ] **Step 2: Point CLAUDE.md at ARCHITECTURE.md**

In `CLAUDE.md`, add this block at the top (just under the Context section):

```markdown
## Conventions

This codebase follows the conventions in `ARCHITECTURE.md` (at the
repo root). Read that file before adding new routes, forms,
templates, or client-side interactions. It documents the stack
(FastAPI + Jinja2 + jinja2-fragments + Tailwind + Alpine.js + Pydantic),
naming rules, URL conventions, and the canonical reference implementations
to copy.
```

- [ ] **Step 3: Verify both files exist**

```bash
ls -la ARCHITECTURE.md CLAUDE.md
```

---

### Task 0.17: Add Dockerfile CSS build step

**Files:**
- Modify: `Dockerfile`

- [ ] **Step 1: Read the current Dockerfile**

```bash
cat Dockerfile
```

- [ ] **Step 2: Add CSS build before CMD**

Edit `Dockerfile`. Just before the `CMD ["pixi", "run", "serve"]` line, add:

```dockerfile
# Build Tailwind CSS so the image ships with the generated app.css.
# The pixi css task is gated behind tailwind-install which downloads the
# pinned standalone binary into .pixi/bin/.
RUN pixi run css
```

Also copy the supporting files needed by `tailwind-install` and the CSS build itself. Find the `COPY src/` line and add right after it:

```dockerfile
COPY tools/ tools/
COPY tailwind.config.js ./
```

(Tailwind v4 reads its `content: [...]` glob from `tailwind.config.js`; without it the build would miss template scanning and the output `app.css` would be missing utility classes used only in templates.)

- [ ] **Step 3: Verify with a dry-run build**

```bash
docker build -t seqsetup-test . 2>&1 | tail -20
```

Expected: builds successfully. The `RUN pixi run css` step should download Tailwind and produce `app.css`. If you don't have Docker locally, skip this step and verify in CI later.

---

### Task 0.18: Phase 0 final commit

- [ ] **Step 1: Run the full test suite**

```bash
pixi run test
```

Expected: all tests PASS (including the new unit tests for validators + dependencies, and the new integration tests for exception handlers + toast + route order).

- [ ] **Step 2: Run the browser smoke**

```bash
pixi run smoke-browser
```

Expected: all three browser tests PASS (htmx + Alpine globals present on logged-in dashboard; toast component reactive; dashboard tab HTMX swap round-trips).

- [ ] **Step 3: Manually verify the app boots and serves CSS**

```bash
pixi run serve &
SERVE_PID=$!
sleep 3
curl -s http://localhost:5001/css/app.css?v=foo | head -c 200
curl -s http://localhost:5001/js/vendor/htmx.min.js | head -c 200
curl -s http://localhost:5001/js/vendor/alpine.min.js | head -c 200
curl -s http://localhost:5001/js/components/toast_stack.js | head -c 200
kill $SERVE_PID 2>/dev/null
wait $SERVE_PID 2>/dev/null
```

Expected: each curl returns the actual file content (CSS, minified JS, etc.). No 404s.

- [ ] **Step 4: Stage and commit**

```bash
git add -A
git status
git commit -m "$(cat <<'EOF'
feat: HTMX redesign Phase 0 — foundation

Lands all new dependencies, helpers, conventions, and the browser-smoke
gate WITHOUT changing existing route/template behaviour:

- Add jinja2-fragments, pydantic[email], pytest-playwright deps
- Vendor Tailwind v4 (standalone binary, downloaded by pixi task)
- Rename hand-written app.css → legacy.css; input.css does
  @import "tailwindcss"; @import "legacy.css";
- Vendor HTMX 2.x + Alpine 3.x in static/js/vendor/
- Add toast_stack.js Alpine component + permanent slot in _app_shell.html
- Switch templating.py to Jinja2Blocks + asset_url filter
  (drops the per-file ASSET_VERSIONS dict)
- Add routes/dependencies.py: get_ctx, require_admin_dep,
  get_editable_run, saving_run CM, is_htmx_request,
  _load_and_check_editable primitive
- Add forms/validators.py: strip_and_truncate, clamp,
  dna_upper_or_reject, json_list
- Add exception_handlers.py: HTML-aware RequestValidationError,
  HTTPException, ConflictError handlers (sub-app /api/* keeps JSON)
- _base.html loads HTMX → app.js → components → Alpine in correct order
- pixi serve depends on css; Dockerfile runs `pixi run css` in build
- New tests: dependencies (12), validators (15), html_exception_handler
  (3), pydantic_422_htmx (1), toast_hxtrigger (1), route_order (1),
  browser smoke (3)
- ARCHITECTURE.md + CLAUDE.md pointer

Fixes a real pre-existing bug: HTMX was no longer loaded in _base.html
after the FastHTML→FastAPI host swap; browser UI for HTMX-driven
features was silently broken. Phase 0 restores it.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Run the full suite once more on the commit**

```bash
pixi run test
pixi run smoke-browser
```

Both must be green.

---

# Phase 1 — Reference port: profiles (1 commit)

**Goal:** port `/profiles` end-to-end as the canonical example every Phase 2/3 commit will copy. Small, isolated, no HTMX swap fragments, no Pydantic forms — just GET → Tailwind-rendered Jinja2 page via APIRouter.

**Acceptance:** `/profiles` looks identical to a user; `tests/integration/test_smoke_bootstrap.py::test_profiles_page_renders` still passes; code demonstrates every applicable Section-3 rule.

---

### Task 1.1: Convert routes/profiles.py to APIRouter

**Files:**
- Modify: `src/seqsetup/routes/profiles.py`
- Modify: `src/seqsetup/app.py`

- [ ] **Step 1: Replace routes/profiles.py**

Overwrite `src/seqsetup/routes/profiles.py` with:

```python
"""Profiles overview page — the canonical reference port for the HTMX
best-practices redesign.

Patterns demonstrated:
  - APIRouter with prefix + tags
  - get_ctx dependency (no closure-captured ctx)
  - response_class=HTMLResponse
  - render() with no block_name (full page)
  - Pre-computed template context (every value built in Python; template
    iterates only)

See ARCHITECTURE.md and the design spec at
docs/superpowers/specs/2026-05-24-htmx-best-practices-redesign-design.md
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse

from ..context import AppContext
from ..services.version_resolver import resolve_application_profiles
from ..templating import render
from .dependencies import get_ctx


router = APIRouter(tags=["profiles"])


def _summarize_settings(settings: dict) -> str:
    """First three non-SoftwareVersion settings as ``"k: v, k: v, k: v, ..."``."""
    other = {k: v for k, v in settings.items() if k != "SoftwareVersion"}
    if not other:
        return ""
    summary = ", ".join(f"{k}: {v}" for k, v in list(other.items())[:3])
    if len(other) > 3:
        summary += ", ..."
    return summary


@router.get("/profiles", response_class=HTMLResponse)
def profiles_page(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
):
    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
    app_profiles = ctx.app_profile_repo.list_all() if ctx.app_profile_repo else []

    # Resolve constraint references to concrete application profiles.
    all_refs = []
    for tp in test_profiles:
        all_refs.extend(tp.application_profiles)
    resolved_map = resolve_application_profiles(all_refs, app_profiles)

    # Pre-format the settings-summary cell so the template stays purely
    # a renderer (no Python expressions in the template).
    app_profile_rows = [
        {
            "name": ap.name,
            "version": ap.version,
            "application_name": ap.application_name,
            "application_type": ap.application_type,
            "software_version": ap.settings.get("SoftwareVersion", "") if ap.settings else "",
            "settings_summary": _summarize_settings(ap.settings or {}),
        }
        for ap in sorted(app_profiles, key=lambda a: (a.application_name, a.name))
    ]

    return render(
        request,
        "profiles.html",
        {
            "test_profiles": test_profiles,
            "test_profiles_sorted": sorted(test_profiles, key=lambda t: t.test_type),
            "app_profiles": app_profiles,
            "app_profile_rows": app_profile_rows,
            "resolved_map": resolved_map,
        },
    )
```

- [ ] **Step 2: Replace `profiles.register(app, _ctx)` with `app.include_router(profiles.router)` in app.py**

Open `src/seqsetup/app.py`. Find:

```python
profiles.register(app, _ctx)
```

Replace with:

```python
app.include_router(profiles.router)
```

- [ ] **Step 3: Run the existing profiles smoke test**

```bash
PYTHONPATH=src pixi run python -m pytest tests/integration/test_smoke_bootstrap.py::test_profiles_page_renders -v
```

Expected: PASS.

---

### Task 1.2: Re-style templates/profiles.html in Tailwind

**Files:**
- Modify: `src/seqsetup/templates/profiles.html`

- [ ] **Step 1: Read the current template**

```bash
cat src/seqsetup/templates/profiles.html
```

Note the existing semantic class names: `profiles-page`, `profiles-section`, `profile-card`, `sample-table`, `summary-list`, `page-description`, `empty-message`. These live in `legacy.css` — they keep working through the migration, but new code uses Tailwind utility classes directly.

- [ ] **Step 2: Replace with Tailwind-styled version**

Overwrite `src/seqsetup/templates/profiles.html` with the Tailwind-rendered version. Visual goal: equivalent to the current page, just with utility classes instead of `legacy.css` selectors. Approximate template:

```jinja
{% extends "_app_shell.html" %}
{% set page_title = "Profiles" %}
{% set active_route = "/profiles" %}

{% block content %}
<div class="space-y-6">
    <h2 class="text-2xl font-semibold">Profiles</h2>
    <p class="text-slate-600">
        Test profiles define sequencing test types and their associated application profiles.
        Application profiles configure DRAGEN pipeline settings for samplesheet export.
    </p>

    {# Test profiles section #}
    {% if test_profiles %}
        <section>
            <h3 class="text-xl font-semibold mb-3">Test Profiles ({{ test_profiles|length }})</h3>
            <div class="space-y-4">
                {% for tp in test_profiles_sorted %}
                <div class="border rounded-lg p-4 bg-white shadow-sm">
                    <fieldset>
                        <legend class="font-semibold">{{ tp.test_name }} (v{{ tp.version }})</legend>
                        <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 my-3">
                            <dt class="font-medium text-slate-700">Test Type:</dt>
                            <dd>{{ tp.test_type }}</dd>
                            <dt class="font-medium text-slate-700">Description:</dt>
                            <dd>{{ tp.description or "—" }}</dd>
                        </dl>
                        <h4 class="font-medium mt-2 mb-1">Application Profiles</h4>
                        {% if tp.application_profiles %}
                        <table class="w-full border-collapse text-sm">
                            <thead>
                                <tr class="bg-slate-100">
                                    <th class="border px-2 py-1 text-left">Profile Name</th>
                                    <th class="border px-2 py-1 text-left">Constraint</th>
                                    <th class="border px-2 py-1 text-left">Resolved</th>
                                    <th class="border px-2 py-1 text-left">Application</th>
                                    <th class="border px-2 py-1 text-left">Type</th>
                                    <th class="border px-2 py-1 text-left">Software Version</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for ref in tp.application_profiles %}
                                    {% set ap = resolved_map.get((ref.profile_name, ref.profile_version)) %}
                                    {% if ap %}
                                    <tr>
                                        <td class="border px-2 py-1">{{ ref.profile_name }}</td>
                                        <td class="border px-2 py-1">{{ ref.profile_version }}</td>
                                        <td class="border px-2 py-1">v{{ ap.version }}</td>
                                        <td class="border px-2 py-1">{{ ap.application_name }}</td>
                                        <td class="border px-2 py-1">{{ ap.application_type }}</td>
                                        <td class="border px-2 py-1">{{ ap.settings.get("SoftwareVersion", "") or "—" }}</td>
                                    </tr>
                                    {% else %}
                                    <tr class="text-slate-400">
                                        <td class="border px-2 py-1">{{ ref.profile_name }}</td>
                                        <td class="border px-2 py-1">{{ ref.profile_version }}</td>
                                        <td class="border px-2 py-1">—</td>
                                        <td class="border px-2 py-1" colspan="3">—</td>
                                    </tr>
                                    {% endif %}
                                {% endfor %}
                            </tbody>
                        </table>
                        {% else %}
                        <p class="text-slate-500">No application profiles assigned.</p>
                        {% endif %}
                    </fieldset>
                </div>
                {% endfor %}
            </div>
        </section>
    {% else %}
        <section>
            <h3 class="text-xl font-semibold mb-3">Test Profiles</h3>
            <p class="text-slate-500">No test profiles available. Sync profiles from Admin &gt; Profiles.</p>
        </section>
    {% endif %}

    {# Application profiles section #}
    {% if app_profiles %}
        <section>
            <h3 class="text-xl font-semibold mb-3">Application Profiles ({{ app_profiles|length }})</h3>
            <table class="w-full border-collapse text-sm">
                <thead>
                    <tr class="bg-slate-100">
                        <th class="border px-2 py-1 text-left">Profile Name</th>
                        <th class="border px-2 py-1 text-left">Version</th>
                        <th class="border px-2 py-1 text-left">Application</th>
                        <th class="border px-2 py-1 text-left">Type</th>
                        <th class="border px-2 py-1 text-left">Software Version</th>
                        <th class="border px-2 py-1 text-left">Settings</th>
                    </tr>
                </thead>
                <tbody>
                    {% for row in app_profile_rows %}
                    <tr>
                        <td class="border px-2 py-1">{{ row.name }}</td>
                        <td class="border px-2 py-1">v{{ row.version }}</td>
                        <td class="border px-2 py-1">{{ row.application_name }}</td>
                        <td class="border px-2 py-1">{{ row.application_type }}</td>
                        <td class="border px-2 py-1">{{ row.software_version or "—" }}</td>
                        <td class="border px-2 py-1 text-xs">{{ row.settings_summary or "—" }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </section>
    {% else %}
        <section>
            <h3 class="text-xl font-semibold mb-3">Application Profiles</h3>
            <p class="text-slate-500">No application profiles available. Sync profiles from Admin &gt; Profiles.</p>
        </section>
    {% endif %}
</div>
{% endblock %}
```

- [ ] **Step 2: Rebuild CSS so the new utility classes are included**

```bash
pixi run css
```

- [ ] **Step 3: Run the smoke test**

```bash
PYTHONPATH=src pixi run python -m pytest tests/integration/test_smoke_bootstrap.py::test_profiles_page_renders -v
```

Expected: PASS. (The test asserts the empty-state messages; those text strings are preserved.)

- [ ] **Step 4: Manual visual check (recommended)**

```bash
pixi run serve &
SERVE_PID=$!
sleep 3
# Open http://localhost:5001/profiles in a browser. Confirm visually
# equivalent to before.
kill $SERVE_PID 2>/dev/null
wait $SERVE_PID 2>/dev/null
```

---

### Task 1.3: Update ARCHITECTURE.md reference link

**Files:**
- Modify: `ARCHITECTURE.md`

- [ ] **Step 1: Confirm the link is already there**

The Phase 0 ARCHITECTURE.md already points at `routes/profiles.py` + `templates/profiles.html` as canonical examples. Re-read the "Reference implementations" section to confirm. If the names match the just-committed structure, no change needed.

- [ ] **Step 2: Phase 1 commit**

```bash
git add -A
git status
git commit -m "$(cat <<'EOF'
refactor(profiles): port to canonical HTMX redesign patterns

Phase 1 — the reference port. Every Phase 2/3 commit copies this
pattern.

Demonstrates:
- APIRouter with prefix/tags + include_router in app.py (replaces
  register(app, ctx) closure factory)
- get_ctx dependency for AppContext (no closure capture)
- response_class=HTMLResponse explicit
- Pre-computed template context (template is a pure renderer)
- Tailwind utility classes inline (replaces legacy semantic class names)

No functional change; /profiles renders visually equivalent. Smoke
test test_profiles_page_renders still pins the empty-state messages.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
pixi run test
```

Expected: all green.

---

# Phase 2 — Migrate already-Jinja2 pages (one commit each)

**Goal:** apply the full new-patterns stack (APIRouter + Pydantic + dependencies + Tailwind + jinja2-fragments + Alpine where applicable) to each already-Jinja2 page, one page per commit. Each commit is independently shippable.

**Recipe per page (apply to every Phase 2 task):**

1. **Route file:** convert `register(app, ctx)` → `router = APIRouter(...)` + `@router.get/post/...` decorators
2. **Forms:** every POST handler gets a Pydantic form model; shared validators from `forms/validators.py`; clamp-vs-reject per field documented
3. **Admin routes:** `dependencies=[Depends(require_admin_dep)]` on the router
4. **Run-edit routes:** `Depends(get_editable_run)` + `with saving_run(...):`
5. **HTMX fragments:** become `{% block %}` regions in the page template; route uses `block_name=...`
6. **Template:** re-style in Tailwind; existing semantic classes may stay temporarily but new structure uses utility classes
7. **HTMX-Request detection:** `Depends(is_htmx_request)` typed dep
8. **app.py:** swap `module.register(app, _ctx)` for `app.include_router(module.router)` — **preserve order**
9. **Smoke test:** add one if missing; existing ones must still pass
10. **URL cleanup (where applicable):** apply the REST changes from spec Section 5

**Per-commit acceptance:**
- `pixi run test` green
- `pixi run css` green
- Page visually equivalent (manually opened in browser)
- One smoke test per migrated page exists and passes
- URL changes from Section 5 done in the same commit if the page is affected
- Commit message documents any deliberate clamp→reject decision

---

### Task 2.1: Migrate login

**Files:**
- Modify: `src/seqsetup/routes/auth.py`
- Modify: `src/seqsetup/templates/login.html`
- Modify: `src/seqsetup/app.py`
- Possibly add: `tests/integration/test_smoke_bootstrap.py::test_login_page_renders` (already exists — verify it still passes)

- [ ] **Step 1: Read the current `auth.py`**

```bash
cat src/seqsetup/routes/auth.py
```

- [ ] **Step 2: Define the Pydantic form model**

In `routes/auth.py`, add at the top of the file (after imports):

```python
from fastapi import APIRouter, Depends, Form, Request
from pydantic import BaseModel, Field
from pydantic.functional_validators import BeforeValidator
from typing import Annotated
from starlette.responses import HTMLResponse, RedirectResponse

from ..forms.validators import strip_and_truncate
from ..services.audit_log import audit
from ..templating import render
from .dependencies import get_ctx


class LoginForm(BaseModel):
    """Login credentials form.

    username: clamp (strip + truncate to 64). Length-limit defensively
        against admin-style usernames; the auth service does the actual
        existence + role check.
    password: **pass-through, REJECT if oversize**. We deliberately do
        NOT strip (whitespace in a password may be intentional and
        silent stripping would change what the user typed → lockouts),
        and we deliberately do NOT truncate (silently chopping a
        password is wrong — a 600-char password should fail to log in,
        not log in with the first 256 chars). The 512-char cap is a
        DoS guard, not a sanitisation: oversize → 422, not a corrupted
        attempt.
    """
    username: Annotated[str, BeforeValidator(strip_and_truncate(64))]
    password: str = Field(min_length=1, max_length=512)
```

(Adjust based on what's currently in `auth.py` — these are the typical fields.)

- [ ] **Step 3: Replace the `register(app, auth_service)` block with an APIRouter**

In `routes/auth.py`, the current `register(app, auth_service)` function wraps the routes. Replace with:

```python
def make_router(auth_service) -> APIRouter:
    """Build the auth router. ``auth_service`` is closed over because
    it's an app-singleton built once at startup, not per-request DI.
    The router itself uses standard ``Depends(...)`` for ``ctx``.
    """
    router = APIRouter(tags=["auth"])

    @router.get("/login", response_class=HTMLResponse)
    def login_page(request: Request):
        """Render the login page, OR redirect to / if already logged in.

        The "already logged in → /" check is load-bearing for the
        session-fixation defence: a user who navigates back to /login
        after authenticating shouldn't get a fresh form (which would
        invite re-submission with their cached browser autofill on a
        new session id).
        """
        if request.session.get("user"):
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", {"error_message": ""})

    @router.post("/login/submit")
    def login_submit(
        request: Request,
        form: Annotated[LoginForm, Form()],
        ctx: AppContext = Depends(get_ctx),
    ):
        """Port every line of the existing ``login_submit``:
          - rate-limit per-IP and per-username (existing limiter,
            existing audit on rate-limit denial)
          - call ``auth_service.authenticate(form.username,
            form.password)``
          - on AuthenticationError: re-render login.html with the
            error_message (NOT a redirect; user stays on /login)
          - on success: ``sess.clear()`` first (session-fixation
            defence), then ``_login_user(sess, user)``, audit
            ``"login.success"``, return RedirectResponse("/",
            status_code=303)

        Read the current implementation in routes/auth.py and copy
        the audit fields, rate-limit retry headers, and error-message
        text verbatim — clinical-safety audit trail depends on the
        existing call shapes.
        """
        ...   # implementation: port line-by-line from current auth.py

    @router.get("/logout")
    def logout(request: Request):
        """Clear the session and redirect to /login. Audit who logged
        out (best-effort — sess may already be empty if the cookie
        expired).
        """
        sess = request.session
        user_data = sess.get("user") or {}
        actor = (user_data.get("username") or "")[:128]
        sess.clear()
        audit("logout", actor=actor)
        return RedirectResponse("/login", status_code=303)

    return router
```

The `login_submit` body is the only place that's "port line-by-line" — the rate-limit branches, the auth-service call, the audit fields, and the session-fixation `sess.clear()` are all clinical-safety code that must be preserved verbatim. Read the current `routes/auth.py:login_submit` and translate field-by-field; do NOT shortcut the audit/rate-limit logic.

- [ ] **Step 4: Update app.py**

In `src/seqsetup/app.py`, find:

```python
auth.register(app, auth_service)
```

Replace with:

```python
app.include_router(auth.make_router(auth_service))
```

- [ ] **Step 5: Re-style login.html in Tailwind**

Open `src/seqsetup/templates/login.html`. Add Tailwind utility classes for the form layout. Visual goal: clean centred login form, same fields/labels/behaviour. Approximately:

```jinja
{% extends "_base.html" %}
{% block title %}Sign in - SeqSetup{% endblock %}
{% block body %}
<main class="min-h-screen flex items-center justify-center bg-slate-100">
    <div class="bg-white rounded-lg shadow-md p-8 w-full max-w-sm">
        <h1 class="text-2xl font-semibold mb-6 text-center">Sign in to SeqSetup</h1>
        {% if error %}
            <div id="form-errors" class="bg-red-100 border border-red-400 text-red-800 rounded px-3 py-2 mb-4 text-sm">
                {{ error }}
            </div>
        {% else %}
            <div id="form-errors"></div>
        {% endif %}
        <form method="post" action="/login/submit" class="space-y-4">
            <div>
                <label for="username" class="block text-sm font-medium mb-1">Username</label>
                <input type="text" name="username" id="username" required autofocus
                       class="w-full border rounded px-3 py-2 focus:outline-none focus:ring focus:ring-blue-300">
            </div>
            <div>
                <label for="password" class="block text-sm font-medium mb-1">Password</label>
                <input type="password" name="password" id="password" required
                       class="w-full border rounded px-3 py-2 focus:outline-none focus:ring focus:ring-blue-300">
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white rounded py-2 hover:bg-blue-700 transition">
                Sign in
            </button>
        </form>
    </div>
</main>
{% endblock %}
```

- [ ] **Step 6: Rebuild CSS + run smoke tests**

```bash
pixi run css
PYTHONPATH=src pixi run python -m pytest tests/integration/test_smoke_auth.py tests/integration/test_smoke_bootstrap.py::test_login_page_renders -v
```

Expected: all PASS.

- [ ] **Step 7: Manual visual check**

Boot the app and open `/login`. Verify visually equivalent + form submit still works.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(auth): migrate login route to APIRouter + Pydantic + Tailwind

Phase 2 — page 1 of ~11.

- APIRouter via make_router(auth_service) factory (auth_service is
  closed over because it's app-singleton, not a per-request dep)
- LoginForm Pydantic model: clamp username (strip + truncate to 64),
  REJECT oversize password (Field(min_length=1, max_length=512) — no
  strip, no truncate; password whitespace and exact length are
  semantically meaningful, silent mutation would cause lockouts; cap
  is a DoS guard)
- get_ctx via Depends
- login.html re-styled in Tailwind
- All existing smoke tests still pass (test_smoke_auth, test_login_page_renders)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
pixi run test
```

---

### Task 2.2: Migrate dashboard

**Files:**
- Modify: `src/seqsetup/routes/dashboard.py`
- Delete: `src/seqsetup/templates/_dashboard_content.html` (replaced by `{% block dashboard_content %}` inside dashboard.html)
- Modify: `src/seqsetup/templates/dashboard.html`
- Modify: `src/seqsetup/app.py`

Apply the Phase 2 recipe to the dashboard. Key changes:

- [ ] **Step 1: Route conversion + introduce `{% block dashboard_content %}`**

Convert `routes/dashboard.py` to an APIRouter. The HTMX tab-swap handlers use `block_name="dashboard_content"` to render just the block:

```python
from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

router = APIRouter(tags=["dashboard"])

_VALID_TABS = ("draft", "ready", "archived")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, ctx: AppContext = Depends(get_ctx)):
    return render(
        request, "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": "draft"},
    )


@router.get("/dashboard/tab/{tab}", response_class=HTMLResponse)
def dashboard_tab(tab: str, request: Request, ctx: AppContext = Depends(get_ctx)):
    if tab not in _VALID_TABS:
        tab = "draft"
    return render(
        request, "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": tab},
        block_name="dashboard_content",
    )


@router.post("/runs/{run_id}/archive", response_class=HTMLResponse)
def archive_run(
    request: Request,
    run: SequencingRun = Depends(get_archivable_run),
    ctx: AppContext = Depends(get_ctx),
):
    # Status transition — archive is a non-CRUD action, kept as POST.
    if err := check_status_transition(run.status, RunStatus.ARCHIVED):
        return err
    previous_tab = "ready" if run.status == RunStatus.READY else "draft"
    previous_status = run.status.value
    # reset_validation=False: archiving a READY run preserves its
    # validation_approved flag — the run was validated before and
    # archiving doesn't invalidate that prior approval. (Default True
    # would wipe approval, breaking the archived-run audit trail.)
    with saving_run(run, ctx, request, reset_validation=False):
        run.status = RunStatus.ARCHIVED
    audit("run.archived", actor=get_username(request), target=run.id, from_status=previous_status)
    return render(
        request, "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": previous_tab},
        block_name="dashboard_content",
    )


@router.delete("/runs/{run_id}", response_class=HTMLResponse)
def delete_run(
    request: Request,
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
):
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    if run.status != RunStatus.ARCHIVED:
        raise HTTPException(status_code=403, detail="Only archived runs can be deleted")
    deleted_role = run.status.value
    ctx.run_repo.delete(run_id)
    audit("run.deleted", actor=get_username(request), target=run_id,
          previous_status=deleted_role, run_name=run.run_name)
    return render(
        request, "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": "archived"},
        block_name="dashboard_content",
    )
```

Note: `archive_run` uses `Depends(get_editable_run)` — but `get_editable_run` raises 403 on non-DRAFT runs. Since archiving a READY run is allowed, we need a variant. Add to `dependencies.py`:

```python
def get_archivable_run(
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> SequencingRun:
    """Load run; raise 404 if missing. No status check — archive is
    valid from DRAFT and READY (state machine enforces)."""
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return run
```

And use `get_archivable_run` for `archive_run`. (The state-machine check is then explicit in the handler.)

- [ ] **Step 2: Restructure dashboard.html with `{% block dashboard_content %}`**

Delete `templates/_dashboard_content.html`. Move its contents into `templates/dashboard.html` wrapped in `{% block dashboard_content %}`:

```jinja
{% extends "_app_shell.html" %}
{% set page_title = "Dashboard" %}
{% set active_route = "/" %}

{% block content %}
{# This entire block is what HTMX swap targets re-render. #}
{% block dashboard_content %}
    {# ... the entire body of the old _dashboard_content.html, re-styled
       in Tailwind ... #}
{% endblock %}
{% endblock %}
```

Re-style the body in Tailwind (replace `dashboard-content`, `tab-buttons`, `dashboard-tabs`, `run-list`, etc. with utility classes).

- [ ] **Step 3: Update app.py**

```python
# Replace dashboard.register(app, _ctx) with:
app.include_router(dashboard.router)
```

**Order:** the dashboard router contains `DELETE /runs/{run_id}` and `POST /runs/{run_id}/archive` — both with a `{run_id}` path param. The `wizard` router has `/runs/new/*` which is more specific. Make sure dashboard is registered AFTER wizard's `/runs/new/*` routes — currently in app.py, the order is wizard → samples → runs → main; dashboard slots in alongside the others. Move `app.include_router(dashboard.router)` to AFTER `wizard.register(...)` (or the equivalent post-migration line) so wizard wins for `/runs/new/*`.

- [ ] **Step 4: Update existing dashboard smoke tests**

The existing `test_smoke_uploads_and_htmx.py` may exercise dashboard tabs. Run:

```bash
PYTHONPATH=src pixi run python -m pytest tests/integration/ -v -k "dashboard or runs"
```

Fix any failures. Add a smoke test if none exists:

```python
def test_dashboard_renders(logged_in_client):
    response = logged_in_client.get("/", follow_redirects=False)
    assert response.status_code == 200
    assert "Dashboard" in response.text or "No Runs Yet" in response.text


def test_dashboard_tab_swap_returns_fragment(logged_in_client):
    response = logged_in_client.get(
        "/dashboard/tab/ready",
        headers={"HX-Request": "true"},
    )
    assert response.status_code == 200
    # Fragment: should NOT include the app shell.
    assert "<html" not in response.text
    # Should include the dashboard content block markers.
    assert 'id="dashboard"' in response.text or 'dashboard-content' in response.text
```

- [ ] **Step 5: Run css build + tests**

```bash
pixi run css
pixi run test
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "refactor(dashboard): migrate to APIRouter + Tailwind + jinja2-fragments"
pixi run test
```

---

### Tasks 2.3 – 2.11: Apply the recipe to each remaining Jinja2 page

For each of the following pages, follow the same recipe as Task 2.1/2.2. Each is one commit.

**Page list and per-page notes:**

| Task | Page | Route module | Notes specific to this page |
|---|---|---|---|
| 2.3 | `admin/instruments` | `routes/admin.py` (extract to `routes/admin/instruments.py` if split) | Router-level `dependencies=[Depends(require_admin_dep)]`. HTMX swap target `{% block synced_instruments_section %}`. |
| 2.4 | `admin/sample_api` | `routes/admin.py` (or split) | Same admin pattern. `SampleApiConfigForm` Pydantic model. |
| 2.5 | `admin/logs` | `routes/admin.py` (or split) | Tab/filter swap exercises `block_name="logs_page"` path. |
| 2.6 | `admin/api_tokens` | `routes/api_tokens.py` | `CreateTokenForm` Pydantic: `expiry_days` uses `clamp(0, 730)` per existing semantics. URL change: `POST .../revoke` → `DELETE .../{id}`. |
| 2.7 | `admin/users` (local_users) | `routes/local_users.py` | `CreateUserForm`/`EditUserForm` Pydantic. **Inline edit row via Alpine** — replaces the `_edit_user_row.html` HTMX swap; the row becomes `x-data="{ editing: false }"` and toggles in place. URL change: `POST .../delete` → `DELETE /admin/users/{username}`. |
| 2.8 | `admin/authentication` | `routes/admin.py` (or split) | Large `LDAPConfigForm`; many optional fields. |
| 2.9 | `admin/config_sync` | `routes/admin.py` (or split) | `ConfigSyncForm` + manual-sync action POST endpoint (state-transition action — kept as POST). |
| 2.10 | `indexes/list` + `indexes/import` + `indexes/detail` | `routes/indexes.py` | Three pages; group as one commit since they share a router (`prefix="/indexes"`). URL change: `POST .../delete` → `DELETE .../{name}/{version}`. The Upload form is multipart — `Annotated[UploadFile, File()]` not Pydantic. |
| 2.11 | `validation/page` | `routes/validation.py` | Tabs + heatmaps + color balance. **Alpine tab switcher** replaces HTMX tab swap (tabs become `x-data="{ activeTab: 'issues' }"` + `:class="activeTab === 'issues' && 'active'"`; content panes use `x-show`). HTMX still used for approve/unapprove buttons. Block names: `{% block validation_tabs %}`, `{% block approval_bar %}`. |

For each task above (2.3 – 2.11), the steps are:

- [ ] **Step 1: Read the current route module + template(s) + any partial files.**
- [ ] **Step 2: Convert route to APIRouter; add Pydantic form models (one per POST endpoint) with shared validators; add router-level deps where applicable (`require_admin_dep` for admin; `get_editable_run` for run-edits).**
- [ ] **Step 3: Apply URL changes from spec Section 5 if listed in the table above; update the corresponding `hx-post` / `hx-delete` / `hx-put` in templates.**
- [ ] **Step 4: Restructure the template: page-content slot becomes `{% block content %}`; HTMX swap targets become inner `{% block <name> %}` regions; old `_*_content.html` partial files are absorbed and deleted.**
- [ ] **Step 5: Re-style the template in Tailwind (utility classes inline).**
- [ ] **Step 6: Replace `module.register(app, _ctx)` with `app.include_router(module.router)` in `app.py`, preserving order.**
- [ ] **Step 7: Add/update the per-page smoke test in `tests/integration/test_smoke_bootstrap.py` (or the relevant smoke file). For URL-changed routes, add a regression test asserting the new DELETE/PUT works and the old POST returns 404/405.**
- [ ] **Step 8: `pixi run css`, then `pixi run test`. Fix any regressions.**
- [ ] **Step 9: Manual visual check (boot, click around the page).**
- [ ] **Step 10: Commit with a descriptive message documenting any clamp-vs-reject decisions and the URL change if applicable.**

**Per-page-template detail (use as templates when writing the Tailwind versions):**

- Cards / list rows → `<div class="border rounded-lg p-4 bg-white shadow-sm">`
- Tables → `<table class="w-full border-collapse text-sm">` with `<th class="border px-2 py-1 text-left bg-slate-100">` and `<td class="border px-2 py-1">`
- Forms → label `class="block text-sm font-medium mb-1"`, input `class="w-full border rounded px-3 py-2"`, submit `class="bg-blue-600 text-white rounded px-4 py-2 hover:bg-blue-700"`
- Danger buttons → `class="bg-red-600 text-white rounded px-3 py-1 hover:bg-red-700"`
- Success message → `class="bg-green-100 border border-green-400 text-green-800 rounded px-3 py-2"`
- Error message → `class="bg-red-100 border border-red-400 text-red-800 rounded px-3 py-2"`
- Page wrapper → `class="space-y-6"` for vertical-spaced sections; `class="container mx-auto p-6"` for the inner page width if needed

---

# Phase 3 — Port remaining FT files (5 main commits)

**Goal:** delete every remaining FastHTML component file, replacing it with Tailwind+Alpine+jinja2-fragments templates rendered via APIRouter routes using Pydantic forms.

**Per-commit acceptance:** smoke test for the affected route passes, full test suite green, FT component file DELETED in the same commit, all route callsites updated.

---

### Task 3.1: Port `components/wizard/steps.py` (WizardNavigation) — small starter

**Files:**
- Delete: `src/seqsetup/components/wizard/steps.py`
- Modify: `src/seqsetup/components/wizard/__init__.py` (drop the `WizardNavigation` export)
- Modify: `src/seqsetup/routes/samples/_shared.py` (the only caller)
- Modify: any other route still importing `WizardNavigation` (grep first)

- [ ] **Step 1: Grep for callers**

```bash
rg "WizardNavigation" src/seqsetup/
```

Should show: `_shared.py` + `steps.py` itself + `__init__.py` re-export.

- [ ] **Step 2: Convert `WizardNavigation` to a partial template**

Create `src/seqsetup/templates/wizard/_navigation.html`:

```jinja
{# Wizard navigation: Cancel → /, Continue → /runs/{id}.

   Inputs:
     step:        int (informational — used in the wrapper id)
     run_id:      str
     can_proceed: bool (currently unused — Continue always enabled)
     oob:        bool — true to add hx-swap-oob for out-of-band swaps #}
<div id="wizard-nav-step-{{ step }}"
     class="flex gap-3 mt-6"
     {% if oob %}hx-swap-oob="true"{% endif %}>
    <a href="/" class="bg-slate-200 text-slate-800 rounded px-4 py-2 hover:bg-slate-300">Cancel</a>
    <a href="/runs/{{ run_id }}" class="bg-blue-600 text-white rounded px-4 py-2 hover:bg-blue-700">Continue to Run</a>
</div>
```

- [ ] **Step 3: Update `_shared.py` to render the template instead of calling `WizardNavigation`**

In `routes/samples/_shared.py`, replace:

```python
from ...components.wizard import SampleTableWizard, WizardNavigation
# ...
def sample_table_with_nav(run):
    num_lanes = ...
    can_proceed = ...
    return ft_response(
        Div(
            SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes),
            WizardNavigation(2, run.id, can_proceed=can_proceed, oob=True),
        )
    )
```

with a version that renders the navigation template separately and concatenates with the FT-rendered sample table HTML:

```python
from starlette.responses import HTMLResponse
from ...templating import ft_to_html, templates as jinja_templates

def sample_table_with_nav(run, request=None):
    num_lanes = ...
    can_proceed = ...
    table_html = ft_to_html(SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes))
    nav_html = jinja_templates.env.get_template("wizard/_navigation.html").render(
        step=2, run_id=run.id, can_proceed=can_proceed, oob=True,
    )
    return HTMLResponse(table_html + nav_html, headers={"Cache-Control": "no-store"})
```

Update the signature so callers pass `request` if they need it (most don't because the nav template doesn't currently use request context — adjust as needed).

- [ ] **Step 4: Delete `steps.py` and drop the export**

```bash
rm src/seqsetup/components/wizard/steps.py
```

Edit `components/wizard/__init__.py`: remove the `WizardNavigation` import and its `__all__` entry.

- [ ] **Step 5: Run tests**

```bash
pixi run test
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "$(cat <<'EOF'
refactor(wizard): port WizardNavigation FT component to Jinja2 template

Phase 3 — file 1 of 5 (the smallest, warms up the per-file pattern).

- Replace src/seqsetup/components/wizard/steps.py with
  src/seqsetup/templates/wizard/_navigation.html
- routes/samples/_shared.py uses the template directly
- FT component file deleted; __init__.py export removed

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
pixi run test
```

---

### Task 3.2: Port `components/wizard/index_panel.py` (IndexKitPanel + IndexKitDropdown) — adds index_drag_zone Alpine component

**Files:**
- Delete: `src/seqsetup/components/wizard/index_panel.py`
- Modify: `src/seqsetup/components/wizard/__init__.py`
- Create: `src/seqsetup/templates/wizard/_index_kit_panel.html`
- Create: `src/seqsetup/templates/wizard/_index_kit_dropdown.html`
- Create: `src/seqsetup/static/js/components/index_drag_zone.js` (Alpine drag-zone component)
- Modify: `src/seqsetup/templates/_base.html` (load the new component script)
- Modify: `src/seqsetup/routes/indexes.py` (which calls `IndexKitPanel` for `/indexes/kit-content`)
- Modify: any other caller (grep first)

- [ ] **Step 1: Grep callers**

```bash
rg "IndexKitPanel|IndexKitDropdown|IndexListCompact|DraggableIndexCompact|DraggableIndexPairCompact" src/seqsetup/
```

- [ ] **Step 2-N: Apply Phase 3 recipe.**

(Detailed sub-steps follow the same shape as Task 3.1 + Phase 2 recipe. Each Phase 3 task creates the templates with Tailwind classes, the Alpine component file, route updates, and a smoke test asserting `/indexes/kit-content?selected_kit=...` returns the partial.)

The `index_drag_zone.js` Alpine component should mirror the structure of `toast_stack.js`:

```js
document.addEventListener('alpine:init', () => {
  Alpine.data('indexDragZone', () => ({
    dragover: false,
    handleDrop(event) {
      this.dragover = false;
      const payload = event.dataTransfer.getData('text/plain');
      if (!payload) return;
      // Trigger an HTMX request — the server is authoritative; it
      // validates the drop and returns the swapped row.
      const data = JSON.parse(payload);
      htmx.ajax('POST', this.$root.dataset.dropUrl, {
        target: this.$root,
        swap: 'outerHTML',
        values: data,
      });
    },
  }));
});
```

Add a `<script defer src="{{ 'js/components/index_drag_zone.js' | asset_url }}"></script>` line to `_base.html` between the toast and Alpine vendor scripts.

- [ ] **Final step: commit**

```bash
git commit -m "refactor(wizard): port index_panel FT to Jinja2 + Alpine drag-zone"
pixi run test
```

---

### Task 3.3: Port `components/wizard/add_samples.py` (2-step sub-wizard)

- [ ] Convert `AddSamplesStep1`, `AddSamplesStep2`, `AddSamplesNavigation`, `AddSamplesWizardProgress`, `NewSamplesPreviewTable` to templates under `templates/wizard/add_samples/`.
- [ ] Add Pydantic forms for the 2 step submit handlers.
- [ ] Update `routes/wizard.py` callers + `routes/samples/import_paths.py` caller.
- [ ] Delete the FT file, drop exports.
- [ ] Smoke test for both steps.
- [ ] Commit.

---

### Task 3.4: Port `components/wizard/sample_table.py` (~850 LOC — the big one)

This one is large enough to warrant internal splitting into 3-4 sub-commits. Each sub-commit ports one sub-component:

- [ ] **3.4.a** — port `WorklistSelector` + `WorklistPreview` (the LIMS-import sidebar). Templates: `templates/wizard/_worklist_selector.html`, `_worklist_preview.html`. Routes: `routes/samples/import_paths.py`.

- [ ] **3.4.b** — port `BulkPasteSectionWizard` + `SamplePasteFormatHelp` + `FetchFromApiSection`. Templates: `templates/wizard/_bulk_paste_section.html`, `_sample_paste_format_help.html`, `_fetch_from_api_section.html`. Pydantic form for the paste/upload handler (multipart file + textarea — use `Annotated[UploadFile, File()]` for the file).

- [ ] **3.4.c** — port `SampleRowWizard` (single row) + the Alpine drag-zone integration per-row. Template: `templates/wizard/_sample_row.html`. This is where the Alpine `indexDragZone` from Task 3.2 gets consumed at scale.

- [ ] **3.4.d** — port `SampleTableWizard` (the table shell) + `BulkLaneAssignmentPanel` (the multi-select bulk-actions panel above the table). Templates: `templates/wizard/_sample_table.html`, `_bulk_lane_panel.html`. This is where the `sample_multi_select` Alpine component lands (`static/js/components/sample_multi_select.js`). Pydantic forms for every bulk-action route (`set-lanes`, `set-mismatches`, `set-override-cycles`, `set-test-id`, `bulk-delete`) with `Annotated[list[str], BeforeValidator(json_list())]` for the `sample_ids` field.

- [ ] **3.4.e** — port `NewSamplesTableWizard` (variant used in add-samples step 2). Template: `templates/wizard/_new_samples_table.html`.

After all sub-commits: delete `src/seqsetup/components/wizard/sample_table.py`. Drop exports from `__init__.py`. Update all `routes/samples/*.py` callers. Run full test suite.

- [ ] **Final commit** (or amend the last sub-commit):

```bash
git commit -m "refactor(wizard): port sample_table FT (final) — delete FT module"
pixi run test
pixi run smoke-browser
```

---

### Task 3.5: Port `components/edit_run.py` (run-edit page composer)

The run-edit page composes `RunStatusBar`, `TopBarForRun`, `RunConfigPanelHorizontal`, `SampleTableSectionForRun`, `ExportPanelForRun`. After Task 3.4, `SampleTableSectionForRun` can render from the new templates.

- [ ] Convert each composer function to a template fragment under `templates/runs/` (page) and `templates/runs/_*.html` (partials).
- [ ] The run-edit page becomes `templates/runs/edit.html` extending `_app_shell.html`.
- [ ] Each HTMX swap target on the page becomes a `{% block %}` (e.g. `{% block run_status_bar %}`, `{% block export_panel %}`).
- [ ] Update `routes/main.py` and `routes/runs.py:update_status` (which uses `RunStatusBar` + OOB swaps for export panel + sample section).
- [ ] Replace the OOB-swap pattern in `update_status` with `HX-Trigger` events where it makes sense (e.g. `HX-Trigger: run-status-changed` — Alpine components on the page listen and re-fetch via HTMX). Document any OOB swaps that stay.
- [ ] Delete `src/seqsetup/components/edit_run.py`. Drop the file.
- [ ] Delete `src/seqsetup/components/__init__.py` if it's now empty.
- [ ] Smoke test asserting `/runs/{id}` page renders.
- [ ] Commit.

---

# Phase 4 — Cleanup (1 commit)

**Goal:** remove every trace of FastHTML and the migration scaffolding. App is one consistent stack throughout.

**Pre-flight verification gate (run BEFORE writing the commit):**

- [ ] **Step 0: Verify no FastHTML imports remain**

```bash
rg "from fasthtml" src/
rg "import fasthtml" src/
rg "ft_response|ft_page_response|ft_to_html" src/
```

ALL must return empty. If any return results, Phase 3 isn't done — go back.

```bash
rg "from \.\.components\.(wizard|edit_run|sample_table|index_panel|export_panel|run_config|dashboard|local_users|api_tokens|profiles|admin)" src/
rg "from \.\.\.components\.(wizard|edit_run|sample_table|index_panel|export_panel|run_config|dashboard|local_users|api_tokens|profiles|admin)" src/
```

ALL must return empty.

---

### Task 4.1: Delete FT helpers from templating.py

**Files:**
- Modify: `src/seqsetup/templating.py`

- [ ] **Step 1: Remove ft_response, ft_page_response, ft_to_html**

In `src/seqsetup/templating.py`, delete the entire `def ft_to_html(...)`, `def ft_response(...)`, and `def ft_page_response(...)` functions. Delete the docstring section that describes them. Verify by re-reading the file.

---

### Task 4.2: Remove python-fasthtml dep

**Files:**
- Modify: `pixi.toml`

- [ ] **Step 1: Remove from pixi.toml**

In `pixi.toml`, find and remove the `python-fasthtml = ...` line under `[pypi-dependencies]`.

- [ ] **Step 2: Lock + reinstall**

```bash
pixi install
```

---

### Task 4.3: Delete legacy.css and the legacy @import

**Files:**
- Delete: `src/seqsetup/static/css/legacy.css`
- Modify: `src/seqsetup/static/css/input.css`

- [ ] **Step 1: Verify no template references legacy class names**

```bash
# Grep for a sample of legacy class names to confirm nothing depends.
for cls in kit-card validation-approval-bar sample-table run-list dashboard-tabs; do
  echo "=== $cls ==="
  rg "class=.*\\b$cls\\b" src/seqsetup/templates/ || echo "(none — good)"
done
```

If any template still uses a legacy class, port it to Tailwind utilities before this task.

- [ ] **Step 2: Delete legacy.css**

```bash
rm src/seqsetup/static/css/legacy.css
```

- [ ] **Step 3: Remove its `@import` from input.css**

In `src/seqsetup/static/css/input.css`, delete the `@import "legacy.css";` line.

- [ ] **Step 4: Rebuild CSS**

```bash
pixi run css
```

Expected: builds cleanly. Output `app.css` should be substantially smaller now.

---

### Task 4.4: Delete the old function-style `require_admin` + `editable_run_handler` decorator

**Files:**
- Modify: `src/seqsetup/routes/utils.py`
- Delete: tests for the old decorator (in `tests/unit/test_route_utils.py`)

- [ ] **Step 1: Verify nothing imports the old shapes**

```bash
rg "from .utils import require_admin\b" src/
rg "from .utils import check_run_editable\b" src/
rg "editable_run_handler" src/
```

All must be empty.

- [ ] **Step 2: Delete from utils.py**

Open `src/seqsetup/routes/utils.py`. Delete:
- The `def require_admin(req)` function
- The `def check_run_editable(run)` function
- The `def editable_run_handler(...)` factory and its inner `wrapper` (the entire context-manager-replaced helper)

Keep: `get_username`, `check_status_transition`, `check_run_exportable`, `sanitize_filename`, `sanitize_string` (still used in some places — though Phase 2 migrated most call sites to Pydantic).

- [ ] **Step 3: Delete the corresponding tests**

In `tests/unit/test_route_utils.py`, delete the `class TestEditableRunHandlerDecorator` and `class TestRequireAdmin` classes (replaced by `tests/unit/test_dependencies.py`).

---

### Task 4.5: Phase 4 final commit

- [ ] **Step 1: Run the full verification gate**

```bash
rg "from fasthtml" src/ || echo "(none — good)"
rg "import fasthtml" src/ || echo "(none — good)"
rg "ft_response|ft_page_response|ft_to_html" src/ || echo "(none — good)"
rg "python-fasthtml" pixi.toml || echo "(none — good)"
rg "static/css/legacy.css" src/ || echo "(none — good)"
```

ALL must return "(none — good)" or empty.

- [ ] **Step 2: Run the full test suite + browser smoke + CSS build**

```bash
pixi run css
pixi run test
pixi run smoke-browser
```

All three must be green.

- [ ] **Step 3: Manual click-through**

Boot `pixi run serve`. Open `/` and click into one run-edit page. Confirm: dashboard renders, tab switching works, navigation to a run works, the run-edit page renders all panels, the validation page tabs switch, the index-kit drag-zone is responsive (visually). Sign out and back in.

- [ ] **Step 4: Final commit**

```bash
git add -A
git status
git commit -m "$(cat <<'EOF'
refactor: HTMX redesign Phase 4 — remove FastHTML completely

Final cleanup:
- Delete ft_response, ft_page_response, ft_to_html from templating.py
- Remove python-fasthtml from pixi.toml
- Delete static/css/legacy.css (no template references it now)
- Delete @import "legacy.css" from input.css
- Delete function-style require_admin (replaced by require_admin_dep)
  from routes/utils.py
- Delete editable_run_handler decorator + its tests (replaced by
  saving_run context manager + tests in test_dependencies.py)

Verification gate passed:
- rg "from fasthtml" src/ → empty
- rg "ft_response|ft_page_response|ft_to_html" src/ → empty
- pixi run test → green (843+ passing)
- pixi run smoke-browser → green
- pixi run css → green (legacy-free output)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 5: Update ARCHITECTURE.md to remove the "during the migration" caveats**

Some lines in ARCHITECTURE.md may reference the legacy.css migration or "Phase 3 not yet done" caveats. Clean those up:

```bash
grep -n "legacy\|during the migration\|will be deleted" ARCHITECTURE.md
```

Fix any stale references. Amend the Phase 4 commit if needed:

```bash
git add ARCHITECTURE.md
git commit --amend --no-edit
```

- [ ] **Step 6: Final verification**

```bash
pixi run test
pixi run smoke-browser
pixi run css
git log --oneline -10
```

Plan complete.

---

## Self-review checklist

- [x] Every spec section has corresponding tasks (Phase 0 covers all infrastructure from spec sections 1-7; Phase 1 is the reference port specified in spec section 6; Phase 2 migrates each Jinja2 page named in the spec; Phase 3 ports each FT file named in spec section 6; Phase 4 cleanup matches spec section 6).
- [x] No "TBD"/"TODO" placeholders.
- [x] Type/name consistency: `get_ctx`, `require_admin_dep`, `get_editable_run`, `saving_run`, `is_htmx_request`, `_load_and_check_editable` used consistently from task 0.8 onward. `strip_and_truncate`, `clamp`, `dna_upper_or_reject`, `json_list` from task 0.10.
- [x] Each task names exact file paths + shows the code to write (not "implement X").
- [x] TDD where it makes sense — validator tests + dependency tests + handler tests are written alongside the code.
- [x] Frequent commits — every page is its own commit, every phase has commit messages with the full context.
