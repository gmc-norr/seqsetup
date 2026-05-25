# CLAUDE.md

## Context

SeqSetup is a **clinical-use** application for configuring Illumina DNA sequencing runs.
It generates Sample Sheets that directly control sequencer behavior. Errors in sample
identity, index assignment, or export output can lead to incorrect clinical results.

**Correctness and safety are non-negotiable. When in doubt, do less, not more.**

Technology: Python, FastAPI, Jinja2 (with jinja2-fragments), Tailwind v4,
Alpine.js, Pydantic v2, MongoDB, HTMX. Environment managed with Pixi.

## Architecture reference

This codebase follows the conventions in `ARCHITECTURE.md` (at the
repo root). Read that file before adding new routes, forms,
templates, or client-side interactions. It documents the stack
(FastAPI + Jinja2 + jinja2-fragments + Tailwind + Alpine.js + Pydantic),
naming rules, URL conventions, and the canonical reference implementations
to copy.

## What Claude Should and Should Not Do

### DO:
- Refactor for clarity
- Suggest improvements to robustness and readability
- Point out potential clinical pitfalls
- Ask clarifying questions if assumptions are unclear

### DO NOT:
- Assume clinical validity without evidence
- Introduce silent behavior changes

## Hard Rules

These rules must NEVER be violated. Each rule states the invariant and the
mechanism that enforces it; if you find yourself relying on "remembering"
to call something at every ingest point, prefer pushing the check down to
a model or service layer where it cannot be forgotten.

### Input sanitization
- **Bound every string at the model boundary.** Model fields (e.g. `Sample.sample_id`, `Run.run_name`) own their length and character constraints, validated both on construction (`__post_init__`) AND on later attribute assignment (`__setattr__` or property setter). Route handlers may use `sanitize_string(value, N)` (typically `N=256` for identifiers, `4096` for descriptions) as a fast clamp at the edge, but they MUST NOT be the only line of defense.
- **Bound every string at every ingest point.** Bulk-paste, LIMS import, and any other parser that strips cells must also clamp them — see `_MAX_CELL_LEN` / `_MAX_FIELD_LEN` in `services/sample_parser.py` and `services/sample_api.py`.
- Clamp all numeric inputs to valid ranges: `max(low, min(high, value))`. Apply at the model layer so re-assignment can't bypass it.
- Validate DNA sequences against `^[ACGTN]*$` after uppercasing — at the model layer.
- Use `escape_js_string()` and `escape_html_attr()` from `utils/html.py` when embedding values in HTML or JavaScript. For JS string literals in Alpine/HTMX attributes, the project's canonical pattern is `{{ value | tojson }}` inside a single-quoted attribute (see `templates/admin/instruments.html`).
- Use `sanitize_filename()` from `routes/utils.py` for Content-Disposition headers.
- Use `_escape_csv()` for all user-supplied values in SampleSheet output (BCLConvert, DRAGEN, and Cloud sections).

### Run state integrity
- Never allow mutations to a run unless `check_run_editable(run)` passes (returns None).
- Never expose draft runs via the API — only `ready` and `archived`.
- Always call `run.touch(updated_by=get_username(req))` before saving after mutations. The `saving_run(...)` context manager does this for you — prefer it over manual save calls so reviewers can grep `with saving_run(` to enumerate every mutation handler.
- Pre-generate all exports (samplesheet v2, v1, JSON, validation) when transitioning to Ready — the API serves pre-generated content, not live exports. The UI export routes share this guarantee; they fall back to live generation only for runs created before pre-generation existed, and any new code path that mutates a Ready/Archived run must re-pre-generate.
- Enforce state machine transitions via `check_status_transition()`: DRAFT→READY, READY→DRAFT, READY→ARCHIVED. ARCHIVED is terminal.
- Exports are only available for READY and ARCHIVED runs — enforce via `check_run_exportable()`.
- Transition to READY runs validation in real time via `ValidationService.validate_run()` and refuses if `error_count > 0`.

### Authentication and authorization
- All non-public routes require authentication — never add unprotected routes.
- Admin routes must use `require_admin_dep` (from `routes/dependencies.py`) as a router-level dependency — it raises HTTP 403 for non-admin users.
- Index kit upload requires admin — standard users cannot upload index kits.
- API routes require Bearer token auth — tokens stored as bcrypt hashes, never log or expose plaintext.
- Access the authenticated user via `req.scope.get("auth")`, API token via `req.scope.get("api_token")`.

### Data integrity
- Validation services are **read-only** — they must never mutate run state.
- Repositories contain **no business logic** — they are thin data access layers.
- Models are **self-validating on every assignment, not just construction**, for any non-trivial invariant they declare. `Sample.__setattr__` enforces `barcode_mismatches_*` (clamp 0–3), `index*_cycles` (clamp >=1), `lanes` (filter positive ints), and `override_cycles` (regex). When adding a model field whose validity is anything more than "any string of any length", enforce it in `__setattr__` (or a property setter) so the rule survives direct attribute writes from route handlers — `__post_init__` alone is insufficient. String length and character-set sanitization for free-form fields lives at the ingest layer (route forms via `sanitize_string`, parsers via `[:N]`), since silently clamping in the model would surprise readers more than it would protect them.
- **Validation cache coherence:** `ValidationService` memoizes results by `(run.id, run.updated_at, repo identity)`. Any mutation that changes validation *inputs* without bumping `run.updated_at` (GitHub config sync, index-kit save/delete, instrument enable/disable, etc.) MUST call `clear_validation_cache()`. See `services/validation.py` and existing call sites in `services/github_sync.py`, `routes/indexes.py`, `routes/admin/instruments.py`.
- **Partial updates update only what was submitted.** Handlers serving per-field HTMX inputs (e.g. `update_sample_settings`) MUST check `field in form` before writing — defaulting missing fields to empty and writing them back silently destroys sibling values.
- Never silently discard data. If input is invalid, reject it (raise `HTTPException(400)` or let model `ValueError` propagate) or clamp it visibly.

### External API safety
- The LIMS API client (`services/sample_api.py`) uses SSL certificate verification via `ssl.create_default_context()`.
- **URLs are validated before fetching.** Hostnames are DNS-resolved and any resolved IP that is loopback, link-local, RFC1918 private, multicast, reserved, or unspecified is refused — this blocks SSRF pivots into the host's own networks. Operators whose LIMS lives on a private corporate network must explicitly opt in via `SEQSETUP_LIMS_ALLOW_PRIVATE_NETS=1`; this is a deliberate, audited decision per deployment, not a default. Plain HTTP is similarly gated by `SEQSETUP_LIMS_ALLOW_HTTP=1`; production uses HTTPS exclusively so the api-key is not sent in clear.
- API responses are size-limited (10 MB) to prevent memory exhaustion.

## Conventions

### Route handler pattern (follow this order)

See `ARCHITECTURE.md` for the canonical patterns. Quick reference for
run-editing handlers:

```python
from typing import Annotated
from fastapi import Depends, Form
from .dependencies import get_editable_run, saving_run
from ..models.sequencing_run import SequencingRun

@router.post("/runs/{run_id}/samples", response_class=HTMLResponse)
def add_sample(
    request: Request,
    form: Annotated[AddSampleForm, Form()],
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
):
    # 1. Pydantic Form() already validated + sanitized the inputs
    # 2. get_editable_run loaded the run AND raised 403 if not editable
    # 3. Mutate the model, then touch+save inside the CM:
    with saving_run(run, ctx, request):
        run.add_sample(form.to_sample())
    # 4. Return the rendered fragment (block_name="..." for HTMX swap):
    return render(request, "runs/edit.html", {...}, block_name="sample_table")
```

For admin-only routes, attach the dep at router level:
`router = APIRouter(dependencies=[Depends(require_admin_dep)])`.


### Models
- Python `@dataclass` with `to_dict()` / `from_dict()` for MongoDB serialization
- Validation and normalization in `__post_init__`
- Use `field(default_factory=...)` for mutable defaults (lists, datetimes)

### Tests
- Run with `pixi run test`
- Group by feature using test classes with docstrings
- Descriptive names: `test_verb_expected_behavior`
- Always test both valid and invalid inputs
- Test edge cases around security boundaries (draft vs ready, admin vs user)

## Working Style

- **Do not add features, refactoring, or "improvements" beyond what is asked.** This is clinical software — unnecessary changes increase risk.
- **Do not add comments, docstrings, or type annotations to code you didn't change.**
- **Read code before modifying it.** Understand the existing pattern before touching it.
- **Run tests after changes.** Do not assume correctness — verify it.
- **Ask before making architectural changes.** The existing patterns exist for reasons.

## Project Structure

```
src/seqsetup/
├── app.py              # FastAPI app creation, route registration
├── startup.py          # Repo initialization, service factories, DI setup
├── middleware.py        # AuthMiddleware (Starlette BaseHTTPMiddleware) — session + redirect on unauthenticated
├── context.py          # AppContext dataclass (dependency injection)
├── openapi.py          # OpenAPI spec for the JSON API
├── templates/         # Jinja2 templates
│   ├── admin/         # Admin pages (auth, config-sync, instruments, logs, sample-api, users, api-tokens)
│   ├── runs/          # Edit-run page + per-section partials
│   ├── validation/    # Validation page + tab content partials
│   ├── wizard/        # New-run wizard + add-samples wizard partials
│   ├── indexes/       # Index kits list/import/detail
│   └── _app_shell.html, _base.html, _messages.html, etc.
├── models/             # Dataclasses — self-validating, with to_dict/from_dict
├── repositories/       # MongoDB access — thin, no business logic
│   └── base.py         # BaseRepository[T], SingletonConfigRepository[C]
├── routes/             # Request handlers — follow the pattern above
│   ├── utils.py        # Guards: check_run_editable, check_status_transition,
│   │                   #   check_run_exportable, get_username, sanitize_*
│   └── api.py          # JSON API (ready/archived runs only)
├── services/           # Business logic — validation, export, LDAP, LIMS API
│   ├── validation.py   # Read-only validation orchestrator
│   ├── sample_api.py   # External LIMS API client (SSL verified, SSRF protected)
│   └── database.py     # MongoDB connection (timeout + health check on init)
├── data/
│   └── instruments.py  # Instrument definitions (YAML + synced DB)
├── utils/
│   └── html.py         # escape_js_string, escape_html_attr
└── static/             # CSS, JS, images
```

## Key Files

| File | Purpose |
|------|---------|
| `routes/utils.py` | `check_run_editable()`, `check_status_transition()`, `check_run_exportable()`, `get_username()`, `sanitize_string()`, `sanitize_filename()` |
| `routes/dependencies.py` | `get_ctx`, `get_editable_run`, `get_archivable_run`, `require_admin_dep`, `saving_run`, `is_htmx_request` |
| `utils/html.py` | `escape_js_string()`, `escape_html_attr()` — use these for all user data in HTML/JS |
| `models/sequencing_run.py` | `SequencingRun`, `RunStatus`, `RunCycles` — central data model |
| `models/sample.py` | `Sample` — DNA sequences validated here |
| `services/validation.py` | Index collision, color balance, application profile validation |
| `services/samplesheet_v2_exporter.py` | Sample Sheet v2 generation with `_escape_csv()` for all user data |
| `services/sample_api.py` | LIMS API client with SSL, SSRF protection, size limits |
| `services/database.py` | MongoDB connection with timeout and health check |
| `startup.py` | Application initialization, repository registry, `get_app_context()` |
| `context.py` | `AppContext` — all repos and service factories in one dataclass |
| `repositories/base.py` | `BaseRepository[T]` and `SingletonConfigRepository[C]` base classes |

## Commands

```bash
pixi install          # Install dependencies
pixi run serve        # Run the application (localhost:5001)
pixi run test         # Run tests (~920 unit + integration tests; pytest)
pixi run smoke-browser  # 3 Playwright browser smoke tests
pixi run mock-api     # Start mock LIMS API server (localhost:8100)
pixi add <pkg>        # Add dependency
pixi add --feature dev <pkg>  # Add dev dependency
```

To point the app at the mock LIMS in dev, set both opt-ins (production must
not set either):

```bash
export SEQSETUP_LIMS_ALLOW_HTTP=1            # mock LIMS speaks plain HTTP
export SEQSETUP_LIMS_ALLOW_PRIVATE_NETS=1    # mock LIMS lives on localhost
```

## Run Status State Machine

```
Draft ──→ Ready ──→ Archived (terminal)
            │
            └──→ Draft (back to editing)
```

- **Draft**: Editable. Validation not required.
- **Ready**: Locked. All exports pre-generated. Accessible via API.
- **Archived**: Read-only historical record. Accessible via API. No transitions out.

Transition to Ready runs `ValidationService.validate_run()` inline and refuses if any errors are present. Export generation follows on success. Transition is enforced by `check_status_transition()` in `routes/utils.py`.
