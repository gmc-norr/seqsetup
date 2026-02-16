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
- Save all changes in a changes.txt file in the root

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

### Run state integrity
- Never allow mutations to a run unless `check_run_editable(run)` passes (returns None)
- Never expose draft runs via the API — only `ready` and `archived`
- Always call `run.touch(updated_by=get_username(req))` before saving after mutations
- Pre-generate all exports (samplesheet v2, v1, JSON, validation) when transitioning to Ready — the API serves pre-generated content, not live exports
- Modifying samples or indexes must reset `validation_approved` (the model handles this via `add_sample`/`remove_sample`, but verify if bypassing those methods)

### Authentication and authorization
- All non-public routes require authentication — never add unprotected routes
- Admin routes must check `require_admin(req)` and return the error response if non-None
- API routes require Bearer token auth — tokens stored as bcrypt hashes, never log or expose plaintext
- Access the authenticated user via `req.scope.get("auth")`, API token via `req.scope.get("api_token")`

### Data integrity
- Validation services are **read-only** — they must never mutate run state
- Repositories contain **no business logic** — they are thin data access layers
- Models are **self-validating** — invariants enforced in `__post_init__`
- Never silently discard data. If input is invalid, reject it or clamp it visibly.

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
├── app.py              # FastHTML app, auth middleware
├── context.py          # AppContext (dependency injection)
├── components/         # UI components (FastHTML/HTMX)
├── models/             # Dataclasses — self-validating, with to_dict/from_dict
├── repositories/       # MongoDB access — thin, no business logic
├── routes/             # Request handlers — follow the pattern above
│   ├── utils.py        # check_run_editable, require_admin, get_username, sanitize_filename
│   └── api.py          # JSON API (ready/archived runs only)
├── services/           # Business logic — validation, export, LDAP
│   └── validation.py   # Read-only validation, never mutates state
├── utils/
│   └── html.py         # escape_js_string, escape_html_attr
└── static/             # CSS, JS, images
```

## Key Files

| File | Purpose |
|------|---------|
| `routes/utils.py` | `check_run_editable()`, `require_admin()`, `get_username()`, `sanitize_filename()` |
| `utils/html.py` | `escape_js_string()`, `escape_html_attr()` — use these for all user data in HTML/JS |
| `models/sequencing_run.py` | `SequencingRun`, `RunStatus`, `RunCycles` — central data model |
| `models/sample.py` | `Sample` — DNA sequences validated here |
| `services/validation.py` | Index collision, color balance, application profile validation |

## Commands

```bash
pixi install          # Install dependencies
pixi run dev          # Run the application
pixi run test         # Run tests
pixi add <pkg>        # Add dependency
pixi add --feature dev <pkg>  # Add dev dependency
```

## Run Status State Machine

**Draft** → **Ready** → **Archived**

- **Draft**: Editable. Validation not required.
- **Ready**: Locked. Validation must be approved. All exports pre-generated. Accessible via API.
- **Archived**: Read-only historical record. Accessible via API.

Transition to Ready requires `validation_approved == True` and triggers export generation.
