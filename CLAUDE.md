# CLAUDE.md

## Context

SeqSetup is a **clinical-use** application for configuring Illumina DNA sequencing runs.
It generates Sample Sheets that directly control sequencer behavior. Errors in sample
identity, index assignment, or export output can lead to incorrect clinical results.

**Correctness and safety are non-negotiable. When in doubt, do less, not more.**

Technology: Python, FastHTML, MongoDB, HTMX. Environment managed with Pixi.

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

These rules must NEVER be violated.

### Input sanitization
- Strip and length-limit all string inputs: `.strip()[:N]` (typically 256 for short fields, 4096 for descriptions)
- Clamp all numeric inputs to valid ranges: `max(low, min(high, value))`
- Validate DNA sequences against `^[ACGTN]*$` after uppercasing
- Use `escape_js_string()` and `escape_html_attr()` from `utils/html.py` when embedding user data in HTML or JavaScript — never raw f-strings
- Use `sanitize_filename()` from `routes/utils.py` for Content-Disposition headers
- Use `_escape_csv()` for all user-supplied values in SampleSheet output (BCLConvert, DRAGEN, and Cloud sections)

### Run state integrity
- Never allow mutations to a run unless `check_run_editable(run)` passes (returns None)
- Never expose draft runs via the API — only `ready` and `archived`
- Always call `run.touch(updated_by=get_username(req))` before saving after mutations
- Pre-generate all exports (samplesheet v2, v1, JSON, validation) when transitioning to Ready — the API serves pre-generated content, not live exports
- Modifying samples or indexes must reset `validation_approved` (the model handles this via `add_sample`/`remove_sample`, but verify if bypassing those methods)
- Enforce state machine transitions via `check_status_transition()`: DRAFT→READY, READY→DRAFT, READY→ARCHIVED. ARCHIVED is terminal.
- Exports are only available for READY and ARCHIVED runs — enforce via `check_run_exportable()`
- Validation approval is only allowed on DRAFT runs; unapproval is blocked on ARCHIVED runs

### Authentication and authorization
- All non-public routes require authentication — never add unprotected routes
- Admin routes must check `require_admin(req)` and return the error response if non-None
- Index kit upload requires admin — standard users cannot upload index kits
- API routes require Bearer token auth — tokens stored as bcrypt hashes, never log or expose plaintext
- Access the authenticated user via `req.scope.get("auth")`, API token via `req.scope.get("api_token")`

### Data integrity
- Validation services are **read-only** — they must never mutate run state
- Repositories contain **no business logic** — they are thin data access layers
- Models are **self-validating** — invariants enforced in `__post_init__`
- Never silently discard data. If input is invalid, reject it or clamp it visibly.

### External API safety
- The LIMS API client (`services/sample_api.py`) uses SSL certificate verification via `ssl.create_default_context()`
- URLs are validated before fetching — localhost and loopback addresses are blocked to prevent SSRF
- API responses are size-limited (10 MB) to prevent memory exhaustion

## Conventions

### Route handler pattern (follow this order)
```python
def handler(req, run_id: str, ...):
    # 1. Validate and sanitize inputs
    value = value.strip()[:256]
    # 2. Load data from repository
    run = ctx.run_repo.get_by_id(run_id)
    if not run: return Response("Not found", status_code=404)
    # 3. Check permissions and editable state
    if err := check_run_editable(run): return err
    # 4. Mutate model
    run.add_sample(sample)
    # 5. Touch and save
    run.touch(updated_by=get_username(req))
    ctx.run_repo.save(run)
    # 6. Return FastHTML component
    return SomeComponent(...)
```

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
├── app.py              # FastHTML app creation, route registration
├── startup.py          # Repo initialization, service factories, DI setup
├── middleware.py        # Auth beforeware (session + Bearer token)
├── context.py          # AppContext dataclass (dependency injection)
├── openapi.py          # OpenAPI spec for the JSON API
├── components/         # UI components (FastHTML/HTMX)
│   ├── wizard/         # Run creation wizard (steps, sample table, indexes)
│   ├── admin/          # Admin pages (auth, instruments, sync, API config)
│   └── validation/     # Validation page (issues, heatmaps, color balance)
├── models/             # Dataclasses — self-validating, with to_dict/from_dict
├── repositories/       # MongoDB access — thin, no business logic
│   └── base.py         # BaseRepository[T], SingletonConfigRepository[C]
├── routes/             # Request handlers — follow the pattern above
│   ├── utils.py        # Guards: check_run_editable, check_status_transition,
│   │                   #   check_run_exportable, require_admin, get_username, sanitize_*
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
| `routes/utils.py` | `check_run_editable()`, `check_status_transition()`, `check_run_exportable()`, `require_admin()`, `get_username()`, `sanitize_*()` |
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
pixi run test         # Run tests (607 unit tests)
pixi run mock-api     # Start mock LIMS API server (localhost:8100)
pixi add <pkg>        # Add dependency
pixi add --feature dev <pkg>  # Add dev dependency
```

## Run Status State Machine

```
Draft ──→ Ready ──→ Archived (terminal)
            │
            └──→ Draft (back to editing)
```

- **Draft**: Editable. Validation not required.
- **Ready**: Locked. Validation must be approved. All exports pre-generated. Accessible via API.
- **Archived**: Read-only historical record. Accessible via API. No transitions out.

Transition to Ready requires `validation_approved == True` and triggers export generation.
Transition is enforced by `check_status_transition()` in `routes/utils.py`.
