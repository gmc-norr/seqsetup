# SeqSetup HTMX best-practices redesign — design spec

**Date:** 2026-05-24
**Status:** Approved (brainstorming complete; ready for implementation planning)
**Scope:** Convert SeqSetup from its current half-migrated state (FastAPI + Jinja2 + HTMX + 5 leftover FastHTML component files + ~9 route modules importing FT helpers + transitional `ft_response` / `ft_page_response` in `templating.py` + custom CSS + manual form parsing + silently-broken HTMX loading) into a canonical Pragmatic-HTMX project: one consistent stack, conventions documented, ready for ongoing development by humans and AI (notably Claude Design).

---

## Decisions summary

| # | Decision point | Choice |
|---|---|---|
| 1 | Redesign scope | **Significant rework** — whatever it takes to land on a canonical HTMX project |
| 2 | HTMX philosophy | **Pragmatic HTMX** — HTMX for server interactions, Alpine.js for client ephemera, Tailwind for styling |
| 3 | Client-side state library | **Alpine.js** (vendored, no bundler) |
| 4 | CSS approach | **Tailwind CSS** (utility-first, built via Tailwind CLI) |
| 5 | Build pipeline | **Tailwind CLI only** — no Vite/esbuild |
| 6 | Form parsing | **Pydantic form models** (`Annotated[FooForm, Form()]`) |
| 7 | Templating fragments | **jinja2-fragments** — one file per page, HTMX swap targets are `{% block %}` regions |
| 8 | Route registration | **FastAPI `APIRouter` + decorators** |
| 9 | URL conventions | **REST cleanup** — proper HTTP methods for CRUD, action endpoints only for non-CRUD; template reorganization to match jinja2-fragments |
| 10 | Migration strategy | **Incremental, all-new-patterns-per-touch** — each commit applies every new pattern to one feature; never double-touch |

---

## 1. Overview & end-state

**Goal.** Convert SeqSetup from its current half-migrated state into a canonical Pragmatic-HTMX project: one consistent stack, conventions documented, ready for ongoing development by humans and AI.

**Final stack:**

| Concern | Choice |
|---|---|
| Web framework | FastAPI |
| Routing | FastAPI `APIRouter` + decorators |
| Templating | Jinja2 + jinja2-fragments |
| CSS | Tailwind CSS (built via Tailwind CLI) |
| Client-side state | Alpine.js (loaded via `<script>` tag, no bundler) |
| Form parsing | Pydantic models (`Annotated[FooForm, Form()]`) |
| Client JS bundler | None — Alpine via `<script>` tag, custom JS as plain `.js` files under `static/js/` |
| CSS build tool | Tailwind CLI in watch mode during dev; one-shot in prod build |
| HTML routes | Return HTML via templates; no JSON in HTML routes |
| JSON API | Separate at `/api/*` — FastAPI-native, Pydantic models, OpenAPI |
| Auth | Unchanged (session middleware + Bearer for `/api/*`) |
| Clinical-safety patterns | Unchanged (`check_run_editable`, `audit()`, optimistic locking, state machine) |

**What's removed:**
- `python-fasthtml` runtime dep (after the 5 FT files port out — see Phase 3 list)
- `ft_response` / `ft_page_response` / `ft_to_html` helpers in `templating.py`
- All `_foo_content.html` mirror files (replaced by `{% block foo_content %}` inside the page)
- The hand-written `static/css/app.css` (renamed to `legacy.css` in Phase 0, then deleted in Phase 4 once no template references the legacy class names)
- Inline `onclick="..."` attributes in templates (replaced by `x-on:click` Alpine handlers)
- The function-style `require_admin(request) -> Response | None` (replaced by `require_admin_dep` that raises HTTPException)

**What's documented:**
- New `ARCHITECTURE.md` at the repo root (alongside `CLAUDE.md` and `README.md`) covering: stack, routing conventions, template structure, form-handling pattern, Alpine usage, where to put JS/CSS, naming rules. Repo-root markdown (not under `docs/`) because the existing Sphinx setup at `docs/` uses `.rst` only — no MyST parser, no markdown extension. `ARCHITECTURE.md` is developer-facing (humans + AI working on the codebase), not user-facing — it does not need to be in the published docs site. If/when the user-facing docs site needs a redesign overview, it can be authored separately as `.rst` and reference `ARCHITECTURE.md`.
- Updated `CLAUDE.md` so future AI work follows the same patterns; CLAUDE.md links to `ARCHITECTURE.md` for the detailed rules.

---

## 2. Templating model

**Library:** `jinja2-fragments` (small wrapper over Jinja2 that can render an individual `{% block %}` from a template).

### Mechanics

```python
# templating.py
from jinja2_fragments.fastapi import Jinja2Blocks
templates = Jinja2Blocks(directory=str(TEMPLATES_DIR))

def render(request, template, context=None, *, block_name=None, status_code=200):
    """Render a full template, or one named block from it.

    block_name=None → full page (the {% extends "_app_shell.html" %} chain)
    block_name="foo" → just the {% block foo %} contents, no shell
    """
    ctx = _with_globals(request, context or {})
    if block_name:
        return templates.TemplateResponse(
            request, template, ctx, block_name=block_name, status_code=status_code,
            headers={"Cache-Control": "no-store"},
        )
    return templates.TemplateResponse(
        request, template, ctx, status_code=status_code,
        headers={"Cache-Control": "no-store"},
    )
```

The transitional `ft_response` / `ft_page_response` / `ft_to_html` helpers are deleted once no FT components remain.

### File organization

```
templates/
├── _base.html                ← <html><head>…</head><body>{% block body %}{% endblock %}</body></html>
├── _app_shell.html           ← header + sidebar; extends _base
├── partials/                 ← shared snippets used across multiple pages
│   ├── _error_banner.html
│   └── _confirm_dialog.html
├── dashboard.html            ← one file per page; HTMX swap targets are blocks inside
├── login.html
├── profiles.html
├── admin/
│   ├── users.html
│   ├── instruments.html
│   ├── api_tokens.html
│   ├── authentication.html
│   ├── config_sync.html
│   ├── sample_api.html
│   └── logs.html
├── indexes/
│   ├── list.html
│   ├── import.html
│   └── detail.html
├── wizard/
│   ├── step1.html
│   └── add_samples/
│       ├── step1.html
│       └── step2.html
├── runs/
│   └── edit.html             ← run-edit page (the big composer)
└── validation/
    └── page.html
```

### Block-naming inside pages

```jinja
{# dashboard.html #}
{% extends "_app_shell.html" %}
{% set page_title = "Dashboard" %}
{% set active_route = "/" %}
{% block content %}
    <h2>Dashboard</h2>
    {% block dashboard_content %}        {# ← HTMX swap target #}
        {% for run in runs %}
            <div id="run-{{ run.id }}">
                {% block run_row scoped %}{% endblock %}   {# ← per-row swap #}
            </div>
        {% endfor %}
    {% endblock %}
{% endblock %}
```

Block names match the swap target's purpose: `dashboard_content`, `run_row`, `validation_tabs`, `sample_row`. The route renders by name:
```python
return render(request, "dashboard.html", ctx, block_name="dashboard_content")
```

### Conventions

- One file per page. No `_page_content.html` mirror files.
- A `{% block %}` exists for every HTMX swap target on the page.
- Shared partials (used across ≥2 pages) live in `templates/partials/` with an `_` prefix.
- All pages extend `_app_shell.html` (or `_base.html` for un-shelled pages like login).
- Templates are pure renderers — no business logic, no service calls. Routes pre-compute everything.
- Tailwind classes go in the template, not in a separate CSS file. The only hand-written CSS is in `static/css/input.css` (Tailwind directives + the small handful of `@layer components` rules for repeated patterns).

---

## 3. Route layer

### Module shape

Every route file exports an `APIRouter`. `app.py` does `app.include_router(router, ...)` once per module.

```python
# routes/local_users.py
from fastapi import APIRouter, Depends, Form, Request
from typing import Annotated

router = APIRouter(
    prefix="/admin/users",
    tags=["admin-users"],
    dependencies=[Depends(require_admin_dep)],   # ← applied to every route in this module
)


class CreateUserForm(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._\-]+$")
    display_name: str = Field(min_length=1, max_length=256)
    email: EmailStr | Literal[""] = ""
    role: UserRole = UserRole.STANDARD
    password: SecretStr = Field(min_length=12, max_length=256)


@router.get("", response_class=HTMLResponse)
def admin_users(request: Request, ctx: AppContext = Depends(get_ctx)):
    return render(request, "admin/users.html", {"users": ctx.local_user_repo.list_all()})


@router.post("/create", response_class=HTMLResponse)
def create_user(
    request: Request,
    form: Annotated[CreateUserForm, Form()],
    ctx: AppContext = Depends(get_ctx),
):
    repo = ctx.local_user_repo
    if repo.exists(form.username):
        return render(
            request, "admin/users.html",
            {"users": repo.list_all(), "error": f"User '{form.username}' already exists."},
            block_name="local_users_page",
        )
    # ... create user, audit, return fragment ...
```

### Patterns

1. **`APIRouter` per route module.** Each `routes/*.py` defines `router = APIRouter(prefix=..., tags=..., dependencies=[...])` and a series of decorated handlers. `app.py` calls `app.include_router(router)` for each one. The current per-module `register(app, ctx)` factory pattern goes away.

2. **`ctx` via dependency injection** rather than closure-capture. A small `get_ctx() -> AppContext` dep returns the singleton from `startup.py`. Handlers declare `ctx: AppContext = Depends(get_ctx)` when they need it. Removes the wrapping `register()` closure entirely.

3. **`require_admin` as a router-level dep — raises, never returns.** Applied via `dependencies=[Depends(require_admin_dep)]` on admin routers. **FastAPI ignores the return value of a router-level dep; the dep MUST raise to short-circuit** (different from the current `require_admin(request) -> Response | None` shape — porting that as-is would silently let admin handlers through). The dep raises `HTTPException(status_code=403, detail="Admin access required")`. Paired with the HTML-aware `HTTPException` handler in pattern 8.

    ```python
    # routes/utils.py
    def require_admin_dep(request: Request) -> None:
        user = request.scope.get("auth")
        if not user or user.role != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Admin access required")

    # routes/admin/users.py
    router = APIRouter(prefix="/admin/users", dependencies=[Depends(require_admin_dep)])
    ```

4. **Editable-run guard: `Depends(get_editable_run)` for loading + a `saving_run` context manager for the save half.** The existing `@editable_run_handler(...)` decorator is the single audit point for the load→check→mutate→touch→save invariant (pinned by 7 unit tests in `tests/unit/test_route_utils.py`). It does NOT survive the move to FastAPI APIRouter handlers: FastAPI's dependency-injection works by introspecting the endpoint signature, and wrapping a handler with `functools.wraps` to preserve the inner signature works for trivial cases but breaks subtly when the handler has Pydantic `Form()` models, path params, and `Depends(...)` — exactly the shape this redesign uses. Decorator order is load-bearing in FastAPI and silently dropping form binding is a real failure mode.

    The redesign replaces the decorator with a two-piece pattern that is structurally visible at every callsite:

    ```python
    # routes/utils.py — shared primitive
    def _load_and_check_editable(run_id: str, run_repo) -> SequencingRun:
        run = run_repo.get_by_id(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="Run not found")
        if run.status != RunStatus.DRAFT:
            raise HTTPException(status_code=403, detail="Run is not in draft status")
        return run

    def get_editable_run(run_id: str, ctx: AppContext = Depends(get_ctx)) -> SequencingRun:
        return _load_and_check_editable(run_id, ctx.run_repo)

    from contextlib import contextmanager

    @contextmanager
    def saving_run(run: SequencingRun, ctx: AppContext, request: Request):
        """Context manager: on successful exit, touch + save the run.
        On exception (HTTPException, validation, etc.), do NOT save —
        the exception propagates as the response, and the run stays
        untouched in the repo.
        """
        try:
            yield run
        except BaseException:
            raise
        else:
            run.touch(updated_by=get_username(request))
            ctx.run_repo.save(run)
    ```

    Handlers explicitly enter the `with` block:

    ```python
    @router.post("/runs/{run_id}/name", response_class=HTMLResponse)
    def update_run_name(
        request: Request,
        form: Annotated[NameForm, Form()],
        run: SequencingRun = Depends(get_editable_run),
        ctx: AppContext = Depends(get_ctx),
    ):
        with saving_run(run, ctx, request):
            run.run_name = form.run_name
        return render(request, "runs/edit.html", {"run": run}, block_name="run_name_display")
    ```

    | Use case | Pattern |
    |---|---|
    | Unconditional save on success (most run-edit handlers) | `with saving_run(run, ctx, request):` around the mutation |
    | Conditional save (paste-with-zero-new-samples; sample-not-found returns empty) | NO `saving_run` block — the handler decides whether to call `run.touch(...) + ctx.run_repo.save(run)` explicitly. Comment in the handler MUST document why save is conditional. |
    | Read-only on an editable run (rare) | `Depends(get_editable_run)` + no save call |

    **Audit point.** The `saving_run` context manager is the single tested mutation-persistence path. Reviewers grep for `with saving_run(`. Forgetting it means the mutation isn't persisted — visible in any smoke test that asserts the persisted-side state. Conditional-save handlers are an enumerated small set (`add_bulk_samples`, `import_worklist_samples`, `update_sample`, `clear_index`); their handler-side `touch + save` calls are reviewed line-by-line.

    **Tests.** The existing 7 decorator tests port to two test classes:
    - `Test_saving_run_ContextManager`: yields run on entry; calls `touch + save` on normal exit; does NOT call them on exception; propagates the exception.
    - `Test_get_editable_run_Dependency`: 404 on missing run, 403 on non-draft, yields run otherwise.

    Plus per-route integration tests for every mutation handler that hit the real route via `TestClient` and assert the persisted run reflects the change (this is what we already do — those existing smoke tests continue to be the higher-level safety net).

5. **Pydantic form models for parsing + shared validators for SeqSetup's reject-vs-clamp semantics.** Validation lives on the model — patterns, lengths, enums. **Important:** Pydantic's default constraints (`max_length`, `ge`, `le`, `pattern`) all REJECT invalid input. The CLAUDE.md hard rules require *stripping and length-limiting* string inputs (not rejecting them), *clamping* numeric inputs to valid ranges (not rejecting them), and *uppercasing + validating* DNA sequences (rejecting only the regex failure). To preserve those semantics we add a shared validators module:

    ```python
    # forms/validators.py — reusable Pydantic field_validators
    def strip_and_truncate(max_len: int):
        def _v(v: str | None) -> str:
            return (v or "").strip()[:max_len]
        return _v

    def clamp(lo: int, hi: int):
        def _v(v: int) -> int:
            return max(lo, min(hi, v))
        return _v

    def dna_upper_or_reject(v: str) -> str:
        v = v.strip().upper()
        if not re.fullmatch(r"[ACGTN]*", v):
            raise ValueError("DNA sequence must be [ACGTN]")
        return v

    def json_list(item_type: type = str):
        """Decode a JSON-string form field into a list. Used by the Alpine
        multi-select pattern in Section 4, which sends a Set serialized
        via JSON.stringify([...]) in hx-vals (form data is text, not
        structured — Pydantic won't parse it for us automatically).
        """
        def _v(v):
            if isinstance(v, list):
                return v
            if isinstance(v, str):
                try:
                    parsed = json.loads(v)
                except json.JSONDecodeError:
                    raise ValueError("expected JSON array")
                if not isinstance(parsed, list):
                    raise ValueError("expected JSON array")
                return parsed
            raise ValueError("expected JSON array or list")
        return _v
    ```

    Each form model declares **per-field, deliberate, documented** reject-vs-clamp:

    ```python
    class CreateUserForm(BaseModel):
        username: Annotated[str, BeforeValidator(strip_and_truncate(64))]  # clamp
        password: SecretStr = Field(min_length=12, max_length=256)         # reject (weak-password policy)
        email: Annotated[str, BeforeValidator(strip_and_truncate(256))]    # clamp
        role: UserRole = UserRole.STANDARD                                 # reject unknown (enum)
    ```

    **Bulk-action forms (the Alpine multi-select pattern in Section 4) send list-typed fields as JSON strings inside `hx-vals`.** FastAPI/Pydantic does NOT auto-parse a JSON string into `list[str]`. The `json_list(...)` shared validator decodes it explicitly:

    ```python
    class BulkDeleteSamplesForm(BaseModel):
        sample_ids: Annotated[list[str], BeforeValidator(json_list())]
    ```

    Alternative: switch the client to repeated form keys (`name="sample_ids[]"` with multiple inputs). The Alpine Set-based pattern is harder to express that way; we keep the `JSON.stringify` + `json_list` approach for symmetry with the existing JS.

    The decision per field — *clamp silently* (existing behaviour, user gets sanitised value back) or *reject loudly* (user must fix input) — is part of the migration's per-form work. Default: match current behaviour (clamp where CLAUDE.md says clamp, reject where it says validate-and-reject). Any deliberate change from clamp→reject is called out in the per-form commit message.

    FastAPI auto-rejects bad input with 422. We install a global `RequestValidationError` handler that returns a small HTML error fragment (with `HX-Reswap: innerHTML` and `HX-Retarget: #form-errors`) for HTMX clients, and a friendly error page for non-HTMX.

6. **HX-Request detection — typed dep, not header sniff.** A `hx_request: bool = Depends(is_htmx_request)` dep makes the "is this a fragment swap?" question explicit at the handler signature.
    ```python
    @router.get("/admin/logs")
    def admin_logs(request: Request, hx: bool = Depends(is_htmx_request), ...):
        return render(request, "admin/logs.html", ctx_data, block_name="logs_page" if hx else None)
    ```

7. **OOB swaps via `HX-Trigger`** where it fits — emit a custom event from the server (`HX-Trigger: refresh-export-panel`) instead of always returning an out-of-band swap fragment. Reduces coupling between handlers and unrelated DOM regions. (We keep OOB swaps where they're genuinely needed — e.g. updating the wizard nav alongside the sample table.)

8. **Exception handlers — three of them, all HTML-aware:**
    - `ConflictError → 409` (existing) — translates optimistic-lock conflicts.
    - `RequestValidationError → 422` (new) — renders the form-error fragment for HTMX or a friendly error page otherwise.
    - `HTTPException → status-matched` (new) — **critical:** the FastAPI default `HTTPException` handler returns JSON, which violates the "no JSON in HTML routes" rule and would surface as raw JSON in the browser for any 403/404/etc. raised from the `require_admin_dep` / `get_editable_run` deps. The HTML-aware handler renders a small HTML error fragment (HTMX-aware: with `HX-Retarget`/`HX-Reswap`) for HTMX requests, or a full error page otherwise. Skipped for `/api/*` (the FastAPI sub-app keeps the JSON default — that's a JSON API).

9. **Response classes are explicit.** `response_class=HTMLResponse` on every HTML route so FastAPI doesn't try to JSON-serialise.

10. **`include_router` order preserves URL-match priority.** Starlette routes match in registration order. Current ordering (`wizard.register` before `main.register` so `/runs/new/step/1` matches before the `/runs/{run_id}` catch-all) must be preserved. The `app.py` `include_router` block is annotated with the load-bearing constraints, and the smoke-test suite includes a regression test asserting `/runs/new/step/1` resolves to the wizard route (not "Run not found" from the catch-all).

### What this fixes

- The boilerplate `if err := require_admin(request): return err` repeated 17+ times → one router-level dep (that raises HTTPException, not returns a Response)
- Manual form parsing → typed Pydantic with shared validators, field-level constraints visible at the top of each route file, per-field clamp-vs-reject documented in form models
- The `register(app, ctx)` closure pattern → standard FastAPI `include_router`, more familiar to anyone reading the code
- The decorator-based `editable_run_handler` audit point (built earlier) is replaced by the `saving_run` context manager + `Depends(get_editable_run)` pair — both share one tested `_load_and_check_editable` primitive. The CM is a structural marker (`with saving_run(...)`) visible at every callsite; reviewers grep for it.

---

## 4. Client-side (Alpine.js + JS organization)

### Loading

HTMX, Alpine, custom JS — all served from the project's `static/js/` (vendored, not CDN — avoids a runtime dependency on a third party and works in air-gapped clinical networks). The full `<script>` ordering for `_base.html` is documented under "JS file organization" below; it matters because Alpine boots on `DOMContentLoaded` and components must have registered themselves first.

### Authority boundary (load-bearing rule)

> **Alpine handles UI ephemera. The server is the source of truth for every domain fact.**

Alpine is allowed to manage:
- Which row is being edited (open/closed)
- Which samples are selected for a bulk action
- Drag-over highlight state
- Filter input text + which elements are hidden
- Open/closed state of disclosure panels
- Confirmation dialogs
- Toast notifications

Alpine is NOT allowed to manage:
- Run status, sample data, index assignments — those round-trip through HTMX every mutation
- "Pending" form values that haven't been saved — every form submit goes to the server
- Cached lookups — repos own those

In code, the rule is: any state that survives a page reload lives on the server. Anything that doesn't is fine in Alpine.

### Pattern catalogue

Five canonical patterns; new UI work copies one of them.

1. **Multi-select with bulk action** (replaces the current `selectedSampleIds` global):
    ```jinja
    <div x-data="{ selected: new Set() }" class="sample-table">
        {% for sample in samples %}
            <div class="sample-row" :class="selected.has('{{ sample.id }}') && 'bg-blue-50'">
                <input type="checkbox"
                       value="{{ sample.id }}"
                       :checked="selected.has('{{ sample.id }}')"
                       @change="$event.target.checked ? selected.add('{{ sample.id }}') : selected.delete('{{ sample.id }}'); selected = new Set(selected)">
            </div>
        {% endfor %}
        <button x-show="selected.size > 0"
                hx-post="/runs/{{ run.id }}/samples/bulk-delete"
                :hx-vals='JSON.stringify({sample_ids: JSON.stringify([...selected])})'
                class="btn-danger">
            Delete <span x-text="selected.size"></span> samples
        </button>
    </div>
    ```

2. **Drag-and-drop** (replaces the current global `handleDragStart` / `handleIndexClick`):
    ```jinja
    <div x-data="indexDragZone()"
         @dragover.prevent="dragover = true"
         @dragleave="dragover = false"
         @drop.prevent="drop($event)"
         :class="dragover && 'ring-2 ring-blue-500'">
        ...
    </div>
    ```
    With the `indexDragZone()` Alpine component defined in `static/js/app.js` via `Alpine.data('indexDragZone', () => ({...}))`. Server-side validation always re-checks the drop (server is authoritative).

3. **Inline edit row** (replaces the current `EditUserRow` partial render):
    ```jinja
    <tr x-data="{ editing: false }">
        <td x-show="!editing">{{ user.display_name }}</td>
        <td x-show="editing"><input name="display_name" value="{{ user.display_name }}"></td>
        <td>
            <button x-show="!editing" @click="editing = true">Edit</button>
            <button x-show="editing" hx-post="/admin/users/{{ user.username }}" hx-target="closest tr">Save</button>
            <button x-show="editing" @click="editing = false">Cancel</button>
        </td>
    </tr>
    ```
    Replaces swapping between `_user_row.html` and `_edit_user_row.html` via HTMX — much less server chatter, same audit trail (the save still goes through HTMX).

4. **Filter input** (replaces the current `filterIndexes` / `filterIndexesWizard` globals):
    ```jinja
    <div x-data="{ q: '' }">
        <input x-model="q" placeholder="Filter…">
        <template x-for="item in items.filter(i => i.name.toLowerCase().includes(q.toLowerCase()))">
            ...
        </template>
    </div>
    ```

5. **Toast notifications** (new pattern, replaces ad-hoc per-page success banners):
    ```html
    <div x-data="toastStack()"
         @toast.window="addToast($event.detail)"
         class="fixed top-4 right-4 space-y-2">
        <template x-for="toast in toasts" :key="toast.id">
            <div :class="toast.kind" x-text="toast.message"
                 x-init="setTimeout(() => remove(toast.id), 4000)"></div>
        </template>
    </div>
    ```
    Server emits `HX-Trigger: {"toast": {"kind": "success", "message": "User created"}}`. HTMX dispatches a `toast` `CustomEvent` (bubbling, on the body) with the JSON payload as `event.detail`. Alpine's `@toast.window` listens for it directly — no need to parse `htmx:after-on-load` response details.

### JS file organization

```
static/js/
├── vendor/
│   ├── htmx.min.js              ← vendored, pinned version (HTMX 2.x)
│   └── alpine.min.js            ← vendored, pinned version (Alpine 3.x)
├── app.js                       ← global setup; runs first, defines window-level helpers if any
└── components/
    ├── index_drag_zone.js       ← each calls Alpine.data('indexDragZone', () => ({...}))
    ├── sample_multi_select.js
    └── toast_stack.js
```

**Loading order** (matters — each component calls `Alpine.data(...)` which must run before Alpine boots):

```html
<!-- _base.html <head> -->
<script defer src="/js/vendor/htmx.min.js"></script>
<script defer src="{{ 'js/app.js' | asset_url }}"></script>
<script defer src="{{ 'js/components/toast_stack.js' | asset_url }}"></script>
<script defer src="{{ 'js/components/index_drag_zone.js' | asset_url }}"></script>
<script defer src="{{ 'js/components/sample_multi_select.js' | asset_url }}"></script>
<script defer src="/js/vendor/alpine.min.js"></script>
```

All `defer`, vendor and components are **classic scripts** (no `type="module"`, no `import`/`export`). Each component file is a self-contained `document.addEventListener('alpine:init', () => { Alpine.data('foo', () => ({...})) })` block — no cross-file dependencies, no bundler needed.

Alpine vendor loads LAST among scripts that touch it so that `alpine:init` fires after every `Alpine.data` registration is in place. `app.js` carries any pure-vanilla helpers and bootstraps shared state.

**Asset cache-busting.** The current `ASSET_VERSIONS` dict in `templating.py` only carries `css/app.css` and `js/app.js`. Phase 0 replaces it with an `asset_url` Jinja2 filter that computes the cache-busting query string on demand from the asset path — that way new asset files (per-component JS, additional CSS partials) don't need a touchpoint in `templating.py`:

```python
# templating.py
def _asset_url(rel_path: str) -> str:
    """`'js/foo.js' | asset_url` → '/js/foo.js?v=abc12345'"""
    h = _asset_hash(rel_path)
    return f"/{rel_path}?v={h}"

templates.env.filters["asset_url"] = _asset_url
```

Vendored files (`/js/vendor/htmx.min.js`, `/js/vendor/alpine.min.js`) bypass the filter because they're pinned-version files; the filename or path is the cache key.

### What goes away

- Every `onclick="..."` attribute in templates → `@click="…"` on the wrapping `x-data` scope
- The global `selectedSampleIds` array → component-scoped `selected` Set
- Global `handleIndexClick`, `handleDragStart`, `filterIndexes` functions → Alpine `x-data` components
- ~150 LOC of hand-rolled state management → ~50 LOC of Alpine components

### What stays vanilla

- File-upload handling (`<input type="file">` validation, drag-files-to-drop-zone)
- Page-load setup (focus first input, initial scroll position)

---

## 5. URL + template conventions

These rules go into `ARCHITECTURE.md` (repo root) as a published contract so every future addition (by a human or by Claude) lands consistently.

### URL rules

| Rule | Example | Counter-example |
|---|---|---|
| Resource-oriented; plural nouns | `/admin/users`, `/runs`, `/indexes/kits` | `/admin/user`, `/run` |
| HTTP method for CRUD | `DELETE /admin/users/{username}` | `POST /admin/users/{username}/delete` |
| State transitions: `POST /resource/{id}/{transition}` | `POST /runs/{id}/archive`, `POST /runs/{id}/status/{status}` | `POST /runs/{id}/set-status-to-ready` |
| Sub-resources for collection ops | `POST /runs/{id}/samples/bulk-delete` | `POST /bulk-delete-samples?run_id=…` |
| Query params for filtering, never action verbs | `GET /admin/logs?level=ERROR&search=foo` | `GET /admin/logs/filter-by-level/ERROR` |
| HTMX fragment endpoints share URLs with their full-page counterparts; server distinguishes via `HX-Request` header | `GET /admin/logs` returns full page OR `{% block logs_page %}` depending on `HX-Request` | Separate URLs like `/admin/logs/fragment` |

### URL changes for this redesign

```
POST /admin/api-tokens/{id}/revoke              → DELETE /admin/api-tokens/{id}
POST /admin/users/{name}/delete                  → DELETE /admin/users/{name}
POST /indexes/kits/{name}/{version}/delete       → DELETE /indexes/kits/{name}/{version}
POST /admin/instruments/synced/toggle            → PUT  /admin/instruments/synced/{id}  (body: enabled=true/false)
```

The `enable-all` / `disable-all` instrument endpoints stay as `POST` (action endpoints — state transition, not CRUD).

### Template rules

| Rule | Example |
|---|---|
| One file per page | `templates/dashboard.html` is the dashboard |
| Pages extend `_app_shell.html` (or `_base.html` for un-shelled pages) | `{% extends "_app_shell.html" %}` |
| HTMX swap targets are `{% block %}` regions inside the page | `{% block dashboard_content %}…{% endblock %}` |
| Block names match the swap target's semantic role | `dashboard_content`, `validation_tabs`, `sample_row` — not `block1` |
| Shared partials (used by ≥2 pages) live in `templates/partials/` with `_` prefix | `partials/_error_banner.html` |
| Page-specific helpers are local includes inside the page directory | `wizard/_flowcell_select.html` (used only by `wizard/step1.html`) |
| Pages set `page_title` and `active_route` via `{% set %}` | `{% set page_title = "Dashboard" %}` |
| Templates contain NO Python expressions beyond filters/iteration; all computation in the route | Route builds `kit_rows: list[dict]` → template loops with no logic |
| Tailwind classes go inline; only `static/css/input.css` has hand-written CSS | `<div class="p-4 rounded shadow border bg-white">` |
| HTMX attributes use the hyphenated form (`hx-post`, not `hx_post`) | (FT-style underscores are gone with FT) |

### Naming conventions inside a page

- Page-level `<div>` that wraps everything HTMX might re-target: `id="<page>-page"` (`#dashboard-page`, `#logs-page`)
- A row in a list: `id="<resource>-<id>"` (`#user-row-jdoe`, `#sample-row-abc123`)
- Form elements: `name="..."` matching the Pydantic model field name 1:1

### HX-Trigger naming (server-emitted client events)

- `kebab-case`, namespaced by resource: `run-archived`, `user-created`, `index-kit-deleted`, `toast`
- The `toast` event is special — its payload `{kind, message}` is consumed by the toast component

---

## 6. Migration plan

Each phase is a self-contained, shippable commit with `pixi run test` green at the end. The full test suite runs after every phase — no "broken in the middle" branches.

### Phase 0 — Foundation (one commit)

Land all the new dependencies and infrastructure with NO behavioural change yet.

- Add deps: `jinja2-fragments`, `pydantic[email]` (for `EmailStr`)
- **Install Tailwind v4** (pinned major) as a **standalone single-file binary**, downloaded by a Pixi task — no Node ecosystem in the repo, which keeps the toolchain Pixi-only. The Tailwind project publishes platform-specific standalone binaries at `https://github.com/tailwindlabs/tailwindcss/releases` (e.g. `tailwindcss-linux-x64`, `tailwindcss-macos-arm64`); a `pixi run tailwind-install` task downloads the pinned version to `.pixi/bin/tailwindcss`. For air-gapped clinical deployments, the binary can also be vendored manually into `tools/vendor/tailwindcss-<platform>` — `pixi run css` checks both locations. The pinned Tailwind version is recorded in `tools/tailwind-version.txt`. (Alternative considered: add Node + npm via Pixi conda-forge and use `@tailwindcss/cli`. Rejected because it pulls the entire Node ecosystem into a Python-only repo for one tool.)
- **Tailwind CSS-side syntax pinned to v4:** `static/css/input.css` uses `@import "tailwindcss";` (NOT the v3-era `@tailwind base/components/utilities`). Create `tailwind.config.js` configured for v4 with `content: ["src/seqsetup/templates/**/*.html"]`. The Tailwind output goes to `static/css/app.css` (gitignored — generated). The existing hand-written `static/css/app.css` is renamed to `static/css/legacy.css` in this commit, and `input.css` does `@import "legacy.css";` so the old custom CSS keeps applying during the migration. Legacy shrinks as Phase 2 commits port templates to Tailwind utility classes; Phase 4 deletes whatever's left.
- **CSS build wired into every entry point.** Add `pixi run css` (one-shot build) and `pixi run css-watch` (watch mode for dev). Make `pixi run serve` depend on `pixi run css` so a fresh clone runs the build before serving. Add a build step to `Dockerfile` (`RUN pixi run css` before `CMD`) so containers ship with the generated `app.css`. The generated file is gitignored but produced deterministically — both the dev box and the prod image build it the same way.
- **Vendor `htmx.min.js` (HTMX 2.x, pinned) and `alpine.min.js` (Alpine 3.x, pinned) into `static/js/vendor/`.** Note: HTMX is not currently loaded by `_base.html` — `fast_app(...)` used to inject it automatically, and that auto-inclusion was silently lost when we moved off FastHTML. The browser UI is broken for HTMX-dependent interactions today; integration smoke tests don't catch it because they assert server responses, not client behaviour. Phase 0 fixes this as a side-effect.
- Update `_base.html` to load the vendor + component scripts in the order documented in Section 4 (HTMX, `app.js`, components, Alpine last so `alpine:init` fires after registrations are in place).
- Refactor `templating.py`:
    - `render()` gains optional `block_name=` arg; underlying `Jinja2Blocks` swap
    - Replace the per-file `ASSET_VERSIONS` dict with an `asset_url` Jinja2 filter (see Section 4) so per-component JS files don't each need a touchpoint in templating.py
- Add `static/js/components/toast_stack.js` + permanent toast slot in `_app_shell.html` (listening on `@toast.window` per Section 4)
- Add new dependency functions to `routes/utils.py`: `get_ctx()`, `require_admin_dep()` (raises HTTPException), `get_editable_run()`, `is_htmx_request()`, plus the shared `_load_and_check_editable()` primitive. Old function-style versions kept temporarily for routes that haven't migrated yet.
- Add shared validators module `forms/validators.py` (`strip_and_truncate`, `clamp`, `dna_upper_or_reject`) per Section 3 pattern 5.
- Add **three** global exception handlers in `app.py`: `ConflictError → 409` (existing, kept), `RequestValidationError → 422 HTML fragment` (new, HTMX-aware), `HTTPException → status-matched HTML fragment` (new, HTMX-aware, skipped for `/api/*`).
- **Add minimal browser smoke test (Playwright).**
    - Pixi dep: `pytest-playwright` (which pulls in `playwright`).
    - Browser install: `pixi run playwright install chromium` task (one-shot, run during dev setup; in CI it runs once per cache).
    - Pixi run task: `pixi run smoke-browser` runs the pytest browser-smoke tests against a TestClient-served app.
    - Tests (in `tests/browser/`, separate from the existing pytest tree so the unit/integration suite stays fast):
        1. Boot, navigate to logged-in dashboard, assert `window.htmx` and `window.Alpine` are defined.
        2. Click a dashboard tab button (`hx-get="/dashboard/tab/ready"`), assert the `#dashboard` region's content changes — this is a real HTMX swap. (NOT the login form submit, which is a normal HTML POST/redirect, not HTMX.)
        3. Assert the toast-stack Alpine component is reactive: dispatch a synthetic `toast` CustomEvent on `window`, then read the resulting DOM and confirm the toast rendered.
    - ~50 LOC total. Runs in CI alongside pytest. Catches the exact class of failure the current HTMX-not-loaded bug demonstrated.
- Write `ARCHITECTURE.md` at the repo root (URL + template + Alpine + Pydantic rules from this spec)
- Update `CLAUDE.md` to point new contributors at `ARCHITECTURE.md`

**Acceptance:** full test suite green, app renders identically, no Tailwind classes in templates yet.

### Phase 1 — Reference port (one commit)

Pick **profiles** as the reference. It's small, already Jinja2, no HTMX swap fragments.

- `routes/profiles.py`: convert to `APIRouter`, decorator-style, `get_ctx` via DI, return via `render`
- `templates/profiles.html`: re-style entirely in Tailwind
- `app.py`: replace `profiles.register(app, _ctx)` with `app.include_router(profiles.router)`
- `ARCHITECTURE.md`: link to `routes/profiles.py` and `templates/profiles.html` as canonical examples

**Acceptance:** tests green, `/profiles` looks the same to the user, code demonstrates every Section-3 + Section-5 rule.

### Phase 2 — Migrate Jinja2 pages (~10 commits)

Each commit takes one already-Jinja2 page and applies the full new-pattern stack. Order:

1. `login` — establishes the form-error-fragment pattern
2. `dashboard` — establishes the page-with-blocks pattern + Alpine for tab state
3. `admin/instruments`
4. `admin/sample_api`
5. `admin/logs` — exercises `block_name` path
6. `admin/api_tokens` — Pydantic form with custom validation
7. `admin/users` (local_users) — inline edit row pattern using Alpine (replaces the `_edit_user_row.html` HTMX swap)
8. `admin/authentication` — large form, optional fields
9. `admin/config_sync` — large form + manual-sync action endpoint
10. `indexes/list` + `indexes/import` + `indexes/detail`
11. `validation/page` — tabs + heatmaps + color balance; Alpine for tab switcher

**Per-commit acceptance:** tests green; page renders visually equivalent; all new patterns from Sections 3–5 applied; URL changes from Section 5 done in the same commit.

### Phase 3 — Port remaining FT files (5 commits, ordered by leaf → composer)

Actual current FT inventory (verified by `rg "from fasthtml"` at the time of spec writing):

```
components/wizard/steps.py        (small — 1 function, WizardNavigation)
components/wizard/index_panel.py  (~150 LOC — IndexKitPanel + IndexKitDropdown)
components/wizard/add_samples.py  (~250 LOC — 2-step sub-wizard composer)
components/wizard/sample_table.py (~850 LOC — sample table + bulk-action panel)
components/edit_run.py            (~340 LOC — run-edit page composer)
```

Ported in this order (each commit deletes its FT file + updates all importing route callsites):

1. `wizard/steps.py` — port `WizardNavigation` to a partial template; routes/samples/_shared.py updated. Smallest, lowest risk; warms up the per-commit pattern.
2. `wizard/index_panel.py` — `IndexKitPanel` + `IndexKitDropdown` to templates. The Alpine `indexDragZone` component lands here.
3. `wizard/add_samples.py` — 2-step sub-wizard; Pydantic forms for both steps.
4. `wizard/sample_table.py` (~850 LOC) — `SampleTableWizard` + `SampleRowWizard` + `NewSamplesTableWizard` + `WorklistSelector` + `WorklistPreview` + `BulkPasteSectionWizard`. Alpine multi-select + drag-zone consumed here. Likely split into ~3-4 internal commits (table shell, row, bulk-actions panel, worklist).
5. `edit_run.py` — run-edit page composer. Depends on 3.4.

**Per-commit acceptance:** smoke test for the affected route, full test suite green, FT component file deleted in the same commit, all route callsites updated.

### Phase 4 — Cleanup (one commit)

**Verification gate before this commit is written:** run these checks; ALL must return empty:

```bash
rg "from fasthtml" src/
rg "import fasthtml" src/
rg "ft_response|ft_page_response|ft_to_html" src/
rg "from \.\.components\.(wizard|edit_run|sample_table|index_panel|export_panel|run_config|dashboard|local_users|api_tokens|profiles|admin)" src/
rg "from \.\.\.components\.(wizard|edit_run|sample_table|index_panel|export_panel|run_config|dashboard|local_users|api_tokens|profiles|admin)" src/
```

If any return results, Phase 3 isn't actually done — go back. Only when all return empty:

- Delete `ft_response`, `ft_page_response`, `ft_to_html` from `templating.py`
- Remove `python-fasthtml` from `pixi.toml` runtime deps
- Delete `static/css/legacy.css` and its `@import` from `input.css` — no template should rely on legacy class names by now
- Delete the function-style `require_admin` (replaced by `require_admin_dep`) and the `editable_run_handler` decorator + its 7 unit tests (replaced by `Depends(get_editable_run)` + `saving_run` CM + their respective tests, per Section 3 pattern 4)
- Delete the old-style `register(app, ctx)` shim functions in any remaining route modules
- Final architecture doc pass: every rule in `ARCHITECTURE.md` has a code reference

**Acceptance:** all `rg` checks above return empty. `pixi run test` green. `pixi run css` green. Browser smoke test green. App boots and a manual click-through of the dashboard + one run-edit page works.

### Effort estimate

| Phase | Files touched | Effort | Risk |
|---|---|---|---|
| 0 Foundation | ~8 (docs, config, helpers) | ~1 day | Low |
| 1 Reference port | 2 (profiles route + template) | ~½ day | Low |
| 2 Migrate Jinja2 | ~15 | ~5-7 days | Medium |
| 3 Port remaining FT | 5 main commits / 5 files (sample_table.py likely split into ~3-4 internal commits) | ~3-5 days | Medium-High |
| 4 Cleanup | ~10 files | ~½ day | Low |

**Total: ~10-14 focused days.** Each commit is independently mergeable. If priorities shift, the work can pause at any phase boundary.

**Rollout safety:** the app is not yet in production. No feature-flagging needed.

---

## 7. Clinical safety + testing

The CLAUDE.md Hard Rules are inviolate through this redesign. The new patterns reinforce — and in some cases strengthen — those rules.

### How the new patterns reinforce clinical safety

| Hard rule | Old enforcement | New enforcement |
|---|---|---|
| Input sanitization | Manual `sanitize_string` calls in every handler | Codified as Pydantic form models + shared validators (`strip_and_truncate`, `clamp`, `dna_upper_or_reject` — see Section 3 pattern 5). **Reject-vs-clamp semantics are preserved per-field** (CLAUDE.md says strings strip-and-truncate, numbers clamp, DNA reject-on-bad-regex — the shared validators implement exactly that). Per-form models explicitly call out any deliberate clamp→reject changes. |
| Admin-only routes | `if err := require_admin(request): return err` at the top of each handler | Router-level `dependencies=[Depends(require_admin_dep)]`. Forgetting it requires deleting the dep from the router — single visible point. |
| Run editability | `@editable_run_handler(...)` decorator | `Depends(get_editable_run)` for load+check. Decorator dropped because FastAPI's signature-introspecting DI doesn't survive a wrapped endpoint reliably (see Section 3 pattern 4 — verified the wraps trick is fragile with Pydantic form models + Depends). |
| Optimistic locking (`run.touch()` before `save`) | Manual in 17+ places, audited by the `editable_run_handler` decorator | Auditable via the `saving_run` context manager (`with saving_run(run, ctx, request): ...`) — the CM is a visible structural marker at every callsite. Reviewers grep for `with saving_run(`. The four documented conditional-save handlers don't use the CM and instead document WHY in a comment + call `run.touch + ctx.run_repo.save` explicitly. See Section 3 pattern 4. |
| Pre-generated exports on DRAFT→READY | Unchanged | Unchanged. |
| State machine (`check_status_transition`) | Unchanged | Unchanged. |
| Audit logging on every mutation | Manual `audit(...)` calls in handlers | Manual. Kept explicit for audit reviewer clarity. |
| No JSON in HTML routes | Convention | Convention, codified by `response_class=HTMLResponse` + separate `/api/*` sub-app. |

### One new safety-relevant rule (Alpine authority boundary)

> Alpine state is for ephemera only. Any state that survives a page reload lives on the server. Mutations always round-trip via HTMX. Alpine is allowed to UI-validate (e.g. disable Save button when empty) but the server re-validates.

Codified in `ARCHITECTURE.md`. Reviewers flag any Alpine `x-data` that holds run/sample/index data without an HTMX swap path.

### Pydantic error handling — security note

The `RequestValidationError` handler returns user-friendly messages but does NOT leak the raw Pydantic error structure (which can include the offending input value, useful to an attacker fingerprinting validation rules). The handler renders a clean fragment with "Field X is invalid" — no echo of the bad value.

### Testing approach

The existing test pattern (`pixi run test` — 843 unit + 55 integration smoke tests via mongomock + Starlette TestClient) extends without major change.

**New tests added during the migration:**

1. **One server-side smoke test per migrated page.** Phase 2 fills any gaps (login, admin/authentication, admin/config_sync, indexes/import, validation/page subsections, wizard/step1). Each test asserts: page renders, key form elements present, HX-Request mode renders the block.

2. **Pydantic-422-via-HTMX test.** Submit a deliberately-invalid form, assert 422 status, assert response body is an HTML fragment (not JSON), assert `HX-Retarget` / `HX-Reswap` headers set correctly.

3. **HTMLException-via-HTMX test.** Hit an admin route as a non-admin (triggers the `require_admin_dep` raise) and assert the 403 response body is HTML (not JSON), with HTMX-aware headers when the client sent `HX-Request: true`. Proves the new HTML-aware `HTTPException` handler is wired.

4. **Router-level admin gate test.** For one or two admin routers, hit a route as a non-admin user, assert 403 — proves the `dependencies=[Depends(require_admin_dep)]` wraps every handler in the router.

5. **`_load_and_check_editable` primitive + `get_editable_run` dep + `saving_run` CM tests** — three small test classes around the same primitive. The primitive's tests pin 404-on-missing / 403-on-non-draft / yields-otherwise. The dep wraps it for FastAPI use. The `saving_run` CM tests pin: yields run on entry; calls `touch + save` on normal exit; does NOT call on exception; propagates the exception. The existing 7 `editable_run_handler` decorator tests don't port — they're replaced by the CM tests + per-route integration tests asserting the persisted state.

6. **Per-validator tests for `strip_and_truncate`, `clamp`, `dna_upper_or_reject`** — unit tests for the shared form validators. Tiny but they pin the reject-vs-clamp semantics CLAUDE.md requires.

7. **Toast HX-Trigger smoke test.** Server emits `HX-Trigger: {"toast": {...}}`; assert the response header is present and the JSON parses.

8. **Include-router order regression test.** Assert `GET /runs/new/step/1?run_id=X` returns the wizard page (not "Run not found" from the `/runs/{run_id}` catch-all). Pins the load-bearing route ordering in `app.py`.

9. **Browser smoke test (new — minimal Playwright).** A single test that boots the app, opens `/login` headless, asserts:
    - `window.htmx` is defined
    - `window.Alpine` is defined
    - One HTMX swap round-trips (e.g. submit login form, see dashboard load)
    - One Alpine component is reactive (toast stack `x-data` exists)

    ~30 LOC. Runs in CI alongside pytest. Catches the exact class of failure the current HTMX-not-loaded bug demonstrates (silently broken client wiring that server-side smoke tests can't detect).

### What we deliberately don't add

- Full visual regression tests (Percy / pixel diffs). The minimal browser smoke catches wiring breakage; pixel-perfect visual regression is overkill for now.
- Alpine unit tests. Implicit in the browser smoke test + route-level server tests.
- Lint rules enforcing "no business logic in templates". Aspirational; relies on code review.

### Pre-merge gate for every commit

```
pixi run test          # unit + integration green
pixi run css           # Tailwind build succeeds
manually open the page touched in this commit and click around
```

---

## Open questions / future work

These are deliberately out of scope but worth flagging for future consideration:

- **Visual regression testing** (Playwright + Percy or similar) — would catch the medium-risk visual drift in Phase 2.
- **Hidden singletons in `startup.py`** — module-level `_db` / `_repos` work but aren't explicit. Refactoring to an `AppState` class would be cleaner but is risk-without-feature-benefit and is intentionally out of scope.
- **Linting / template validation** — automated checks for "no Python expressions in templates" or "every HX-target has a matching `{% block %}`" — aspirational, can wait until pain demands it.
- **i18n** — not currently a requirement; if it becomes one, Jinja2 has standard i18n support and Tailwind doesn't interfere.

---

*This spec is the output of a structured brainstorming session. The next step is to invoke the `writing-plans` skill to translate this design into a phase-by-phase implementation plan.*
