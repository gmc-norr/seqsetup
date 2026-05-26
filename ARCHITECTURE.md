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
| Admin form with Pydantic + router-level admin guard | `src/seqsetup/routes/local_users.py` + `src/seqsetup/templates/admin/local_users.html` |
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
| Shared partials (≥2 pages) belong under a `templates/partials/` directory with `_` prefix | (none currently — all partials are page-local; add `partials/` if a true cross-page partial appears) |
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
- `static/css/components.css` contains shared component-level styles
  (`.btn` family, `.sample-table`, `.config-panel`, etc.). Used by
  templates that need consistent component appearance across pages.
- `static/css/input.css` is the Tailwind entry point — imports
  `tailwindcss` and `components.css`.
- Output `static/css/app.css` is gitignored; built by `pixi run css`.
- `pixi run serve` builds CSS first (Phase 0 wiring).

## Testing

- Unit tests: `tests/unit/`
- Integration: `tests/integration/` (mongomock + Starlette TestClient)
- Browser smoke: `tests/browser/` (Playwright; minimal — `pixi run smoke-browser`)
- Every new page gets a smoke test asserting the page renders.
- Every new form route gets a 422 test asserting Pydantic validation errors render as HTML fragments with `HX-Retarget`/`HX-Reswap` for HTMX clients.

## Migration history

The HTMX best-practices redesign (2026-05-24 plan, ~30 commits, May 2026)
moved this codebase from a half-FastHTML legacy state to FastAPI +
APIRouter + Jinja2 + jinja2-fragments + Tailwind v4 + Alpine.js +
Pydantic v2. The `python-fasthtml` dependency was removed in roadmap
step 8.

The project uses Tailwind v4 utility classes inline for layout and
ad-hoc styling, alongside a hand-written component stylesheet at
`static/css/components.css` for shared visual components (buttons,
tables, form rows, heatmap cells, status badges, the app shell, etc.).
The two layers are imported together in `static/css/input.css`. This
is a standard Tailwind+CSS pattern, not a migration carry-over.

## Known follow-ups

These items were noted during reviews and are NOT regressions from
the migration, but represent real gaps in the codebase that warrant
tracking:

1. ~~**`routes/samples.py` mutation audit logging gap.** Per CLAUDE.md
   "Audit logging" hard rule, every state-changing route should emit
   an audit record. `samples.py` has ~17 mutation handlers
   (add_sample, add_bulk_samples, assign_index, clear_index,
   update_sample, delete_sample, bulk-delete, set_lanes_bulk,
   set_mismatches_bulk, set_override_cycles_bulk, set_test_id_bulk,
   import_worklist_samples, ...) and currently emits ZERO audit
   events. This pre-dates the redesign but became more visible after
   the migration. Adding audit calls is a follow-up: each mutation
   should emit `sample.added` / `sample.deleted` / `sample.index.assigned`
   / `sample.index.cleared` / etc., with `actor`, `target` (run_id +
   sample_id), and `outcome` where applicable.~~
   **CLOSED** — All 15 mutation handlers now emit audit events
   (sample.added, sample.updated, sample.deleted, sample.index.assigned,
   sample.index.cleared, sample.settings.updated, sample.bulk_added,
   sample.worklist_imported, sample.bulk_index_assigned,
   sample.bulk_index_assigned_selected, sample.bulk_lanes_set,
   sample.bulk_mismatches_set, sample.bulk_override_cycles_set,
   sample.bulk_test_id_set, sample.bulk_deleted).

2. ~~**APIRouter pattern not yet adopted by `routes/samples.py`,
   `routes/wizard.py`, `routes/runs.py`, `routes/export.py`.**
   These four modules still use the legacy `register(app, ctx)`
   pattern with closure-captured `ctx` and manual `run.touch() +
   ctx.run_repo.save()` calls instead of `Depends(get_ctx)` +
   `with saving_run(run, ctx, request):`.~~
   **PARTIALLY CLOSED** — All four migrated to APIRouter and `saving_run`:
   - `routes/export.py` → `Depends(get_exportable_run)` + APIRouter
   - `routes/wizard.py` → APIRouter + `Depends(get_ctx)` (GET-only)
   - `routes/runs.py` → `Depends(get_editable_run)` /
     `Depends(get_archivable_run)` + `with saving_run(...)`
   - `routes/samples.py` → `Depends(get_editable_run)` +
     `with saving_run(...)` for every mutation; the 15 audit events
     from follow-up #1 are preserved verbatim
   ZERO `register(app, ctx)` closures remain in `src/seqsetup/routes/`.

   **Remaining gap:** `routes/samples.py` and parts of `routes/runs.py`
   still parse form data manually (`form = await request.form()`)
   instead of declaring `Annotated[FooForm, Form()]` per rule 6 of the
   routing conventions. The manual pattern is deliberate for
   per-field HTMX endpoints such as `update_sample_settings` and
   `update_sample`, which need to detect which keys are present in
   the submission (partial-update semantics). For the simpler bulk
   handlers (`set_test_id_bulk`, `set_lanes_bulk`, etc.) migration to
   Pydantic Form models would be a consistency-only change with no
   security or correctness impact — the load-bearing input bounds
   live in the Sample/SequencingRun model `__setattr__`s.
