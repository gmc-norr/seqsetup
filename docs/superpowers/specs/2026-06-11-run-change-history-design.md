# Per-Run Change History — Design

**Date:** 2026-06-11
**Status:** Approved design, pending implementation plan
**Feature area:** Clinical traceability / run auditing

## Problem

SeqSetup records `created_by/at` and `updated_by/at` on a run, and emits
coarse `audit()` events to a write-only logger (`seqsetup.audit`) — but the
application has **no queryable, in-UI trail of who changed what on a run and
when**. For clinical traceability a reviewer must be able to reconstruct a
run's edit history after the fact: when an index or lane was reassigned, who
promoted it to Ready, what a sample's i7 was before it changed. Today that
information is unrecoverable from the app.

## Scope

In scope:
- An **append-only, queryable** per-run change history with **automatic
  field-level diffs** captured at the single run-mutation chokepoint.
- **Deep, per-field sample changes** (added / removed / modified-with-fields),
  paired by stable sample uuid so a `sample_id` rename reads as a modification,
  not a delete+add.
- **Creation entries** with provenance (blank / cloned-from / from-template).
- A **read-only History panel** on the run page, lazy-loaded via HTMX, visible
  to any authenticated user for a run in any status.
- **Cascade-delete** of a run's history when the (archived) run is deleted.

Out of scope (YAGNI / deliberate):
- Admin cross-run audit viewer / retaining history after run deletion.
- Rollback or restore to a prior version.
- Tracking template/admin/config actions (those already `audit()` to the
  logger).
- Migrating the app's timestamps from local time to UTC (pre-existing concern,
  see Open Questions).

## Architecture

### Chosen approach: capture in `saving_run`

`saving_run(run, ctx, request)` (`routes/dependencies.py`) is the single
context manager through which **every mutation of an existing run** is
persisted (27 call sites; `touch()` + `run_repo.save()` on success, nothing on
exception). It already has `ctx` (→ repos) and `request` (→ actor). Capturing
here means edit-history can never be forgotten for an edit path.

Rejected alternatives:
- **`RunRepository.save()`** — repositories must contain no business logic
  (hard rule), and `.save()` has no actor/request context.
- **Derive from existing `audit()` events** — they are coarse and not
  field-level; they cannot satisfy the "deep per-field" requirement.

Run **creation** does not pass through `saving_run` (it saves directly): the
three creation sites — `RunRepository.create_run` (blank), `duplicate_run`
(clone), `new_run_from_template` — each record an explicit `created` entry.

### Components

**`models/run_history.py` — `RunHistoryEntry` dataclass** (self-validating,
`to_dict`/`from_dict`):

- `id: str` (uuid)
- `run_id: str` — the run this entry belongs to
- `timestamp: datetime` — **the run's `updated_at` for that save** (reused, not
  a fresh clock read) so the history timeline is consistent with the run's own
  metadata. For a `created` entry, the run's `created_at`.
- `actor: str` — username (`get_username(request)`); for creation, the
  creating user.
- `kind: str` — `"created"` or `"updated"`.
- `provenance: Optional[dict]` — for `created` only:
  `{"source": "blank" | "clone" | "template", "ref": <id or None>}`.
- `field_changes: list[dict]` — `{"field": str, "before": Any, "after": Any}`
  for run-level config fields.
- `sample_changes: list[dict]` — `{"sample_id": str, "kind":
  "added"|"removed"|"modified", "fields": [{"name", "before", "after"}]}`.

**`repositories/run_history_repo.py` — `RunHistoryRepository`**, collection
`run_history`. **Application-level append-only** — enforced by the API it
exposes, not merely by caller convention:
- It does **not** inherit `BaseRepository.save()` (a `replace_one` upsert that
  could silently overwrite an existing entry). It exposes a dedicated
  `append(entry) -> None` using `insert_one`, which raises `DuplicateKeyError`
  on a colliding `_id`. There is **no update method**.
- `list_by_run(run_id, *, limit, before=None) -> list[RunHistoryEntry]` —
  **bounded and pageable**, newest-first, ordered by `(timestamp, _id)`
  descending for deterministic tie-breaking (two saves could in principle share
  a `timestamp`). `before` is a cursor (timestamp/`_id`) for "load older".
- `delete_by_run(run_id) -> int` for the cascade.
- On init, ensures a compound index `{run_id: 1, timestamp: -1}` so per-run
  queries are indexed.

> **Scope of the guarantee:** this is *application-level* append-only (no update
> path, insert-only). It is **not** cryptographic tamper-evidence — a DB admin
> can still alter the collection directly. True tamper-evidence (externally
> anchored hash-chaining) is explicitly out of scope.

Registered in `startup.py` (`_REPO_REGISTRY` + getter) and exposed on
`AppContext` as `run_history_repo`. (It may still subclass `BaseRepository` for
collection wiring, but must override/omit `save` so no upsert/update path is
reachable.)

**`services/run_diff.py` — the diff engine** (pure, unit-testable):
- `RUN_DIFF_IGNORED_KEYS = {"updated_at", "updated_by", "_loaded_updated_at",
  "wizard_step", "generated_samplesheet_v2", "generated_samplesheet_v1",
  "generated_json", "generated_validation_json", "generated_validation_pdf",
  "samples", "_id", "id"}` — `samples` handled separately; the rest are volatile
  outputs / metadata that would be noise. (Mirrors the existing
  `_FINGERPRINT_IGNORED_KEYS` in `routes/runs.py`.)
- `diff_run(before: dict, after: dict) -> tuple[list[field_changes],
  list[sample_changes]]` operating on `SequencingRun.to_dict()` outputs:
  - **Config fields:** every top-level key not in the ignore set whose value
    differs → a `field_change`. Scalars (`run_name`, `flowcell_type`,
    `reagent_cycles`, `status`, `no_lane_splitting`, `barcode_mismatches_*`,
    `adapter_behavior`, …) compare directly. The two nested values —
    `run_cycles` and `analyses` — are compared as **whole values** in v1
    (before/after carry the full sub-dict / list); per-cycle and per-analysis
    deep diffing is deferred (samples are the one structure that gets deep
    per-field treatment, because that's where the clinical risk concentrates).
  - **Samples:** paired by the stable uuid `id` (NOT `sample_id`, which is
    editable). Present-after-only → `added`; present-before-only → `removed`;
    present-in-both with any differing tracked field → `modified` with per-field
    before/after. The reported `sample_id` is the after-value (or before-value
    for a removal).
    - **Track every persisted sample field except an explicit ignore set**
      (a *denylist*, not an allowlist — an allowlist silently drops fields the
      way audit-event drift does, which is exactly the failure mode this feature
      exists to prevent). The ignore set is just `{"id"}` (the pairing key, not a
      change). Everything else in `Sample.to_dict()` is tracked, including the
      easily-forgotten ones mutated during index assignment:
      `sample_id`, `sample_name`, `project`, `test_id`, `worksheet_id`, `lanes`,
      `index_pair` / `index1` / `index2`, `index_kit_name`, `override_cycles`,
      `index1_cycles`, `index2_cycles`, `index1_override_pattern`,
      `index2_override_pattern`, `barcode_mismatches_index1`,
      `barcode_mismatches_index2`.
    - **Store structured before/after values** (the raw dict values from
      `Sample.to_dict()` — e.g. the full index sub-dict with name, sequence,
      well), not lossy display strings. The UI formats them compactly
      (`"D701 ATTACTCG"`); the stored record keeps the structured identity.
    - `added` and `removed` entries carry a **snapshot of all tracked fields**
      of the sample (so the trail shows what a sample was when it appeared or
      vanished, not merely that it did).
- `is_empty(field_changes, sample_changes) -> bool` — true when nothing
  tracked changed.

### Capture flow (edits)

`saving_run` is extended:
1. On entry, snapshot `before = run.to_dict()` (the loaded, pre-mutation
   state).
2. `yield run` (handler mutates in place).
3. On **successful** exit: `run.touch(updated_by=actor)`, then
   `ctx.run_repo.save(run)` (optimistic-locked — may raise `ConflictError`).
4. **Only after a successful save**, run the **entire** post-save history block
   — `after = run.to_dict()`, `diff_run(before, after)`, and, if not empty,
   `run_history_repo.append(...)` (`kind="updated"`, `timestamp=run.updated_at`,
   `actor`) — inside one `try/except`. A bug in diffing or an `append` failure
   must **never** turn into a 500 on a clinical edit that already persisted.
5. On exception anywhere in the handler body or in `run_repo.save`, **no** entry
   is recorded — so a rolled-back `ConflictError` never leaves a phantom entry,
   and a failed handler records nothing.

Recording **after** a persisted save is the load-bearing ordering: the run is
the source of truth; history reflects only what actually persisted.

### Durability of the trail (dual-write reality)

The run save and the history `append` are **two separate writes**. The
deployment runs a **standalone MongoDB** (`docker-compose.yml` — no replica
set), so multi-document **transactions are not available**; we cannot make the
two writes atomic. This bounds the guarantee honestly:

- **"Automatic" means no developer omission, not crash-proof durability.** The
  diff is captured at the one chokepoint, so no one adding a future edit handler
  can *forget* to record history. That is the property "can't be forgotten"
  refers to — it is distinct from durability under a mid-operation failure.
- **The history write is application-level best-effort.** If `run_repo.save`
  succeeds but the subsequent `append` fails (or the process crashes between the
  two), that one diff is lost. The window is narrow — both writes hit the *same*
  MongoDB, so a total DB outage fails the run save first (no "edit persisted,
  history lost" in that case) — but it is real.
- **Failures are loud and reconcilable, never silent.** The `except` logs at
  ERROR **and** emits `audit("run.history.record_failed", actor=…,
  target=run.id, outcome="failure", reason=…)` so an operator can monitor for
  and reconcile gaps. A run's `updated_at` advancing without a corresponding
  history entry is the detectable signal.
- **Optional hardening (deployment choice, not required by this feature):** on a
  replica-set MongoDB, wrap the run save + history append in a single
  transaction for true atomicity. The code is structured so this can be added
  later without changing the capture sites.

The same dual-write caveat applies to **creation** entries (run insert +
history append) and **cascade deletion** (run delete + `delete_by_run`); both
guard the history write the same way and log/audit on failure. A failed cascade
delete leaves orphaned history rows, which are harmless (keyed by a now-absent
`run_id`) and removable by a reconciliation sweep.

### Creation flow

A small helper `record_run_created(ctx, run, actor, source, ref=None)` inserts
a `created` entry. Called from:
- `RunRepository.create_run` — `source="blank"`. (The repo is thin; to keep
  business logic out of it, the *caller* — the wizard route `wizard_new` —
  records creation after `create_run` returns, with the actor from the
  request. `create_run` itself stays unchanged.)
- `duplicate_run` — `source="clone"`, `ref=<source run id>`.
- `new_run_from_template` — `source="template"`, `ref=<template id>`.

### Surfacing

- **Route:** `GET /runs/{run_id}/history` — loads the run (any status; 404 if
  missing — a read loader, not `get_editable_run`), calls `list_by_run` with a
  bounded page size (default e.g. 50) and an optional `before` cursor query
  param, renders a partial. Read-only; standard auth; no admin gate. A "load
  older" control issues the same route with the next cursor.
- **Panel:** a "History" section on `templates/runs/edit.html`, lazy-loaded via
  HTMX (`hx-get="/runs/{id}/history"`, e.g. `hx-trigger="revealed"` or a
  toggle) so a long history isn't built on every page render.
- **Rendering:** newest-first list; each entry shows timestamp · actor · a
  summary line. `created` entries show provenance ("Created from template X").
  `updated` entries render `field_changes` ("Flowcell 10B → 25B") and
  `sample_changes` ("S3: i7 D701 → D702", "+S1", "−S2"). CSP-compliant (no
  inline handlers; values auto-escaped by Jinja).
- **Baseline marker (rollout for existing runs):** there is **no backfill
  migration**. A run created before this feature shipped has no `created` entry,
  so its panel must not imply a complete trail. Whenever a run's oldest history
  entry is **not** a `created` entry (i.e. the run predates the feature, or the
  creation entry's write was lost), the panel renders a baseline note at the
  bottom of the timeline: *"Change history began when this feature was deployed;
  edits before that point were not recorded."* Diffs still work for these runs —
  the first post-deploy edit diffs against the run's then-current state captured
  at `saving_run` entry — so only the pre-feature tail is missing, and it is
  labeled as such. (An operator who wants a real anchor for legacy runs may run
  a one-off baseline-snapshot script, but that is not part of this feature.)

### Cascade delete

`delete_run` (`routes/dashboard.py`, archived-only) calls
`ctx.run_history_repo.delete_by_run(run.id)` after deleting the run. The
existing `run.deleted` audit event still fires.

## Clinical-safety summary

- **No developer omission** — capture lives at the one edit chokepoint, so a
  future handler can't forget to record history; creation is explicit at the
  only three creation sites. (Durability under mid-operation failure is a
  separate, best-effort property — see *Durability of the trail*.)
- **Application-level append-only** — `RunHistoryRepository` exposes only
  `append` (insert-only) and has no update path; an entry can't be rewritten
  through the app. This is not cryptographic tamper-evidence (a DB admin can
  still edit the collection directly) — that's out of scope.
- **Recorded only after a persisted save** — a `ConflictError` (concurrent
  edit) or a raising handler leaves **no** entry; no phantom history. The whole
  post-save diff+append is exception-guarded so it can never 500 a persisted
  clinical edit.
- **Volatile-noise excluded** — `generated_*`, `updated_at/by`,
  `_loaded_updated_at`, `wizard_step` are not diffed, so a DRAFT→READY
  promotion records `status: draft → ready`, not a wall of export blobs.
- **Samples paired by stable uuid** — a `sample_id` rename reads as a
  modification, not delete+add, preserving an accurate identity trail.
- **No new data exposure** — entries hold the same clinical identifiers the run
  already holds, in the same MongoDB (same encryption-at-rest posture the run
  model documents).
- **Honest about coverage start** — runs that predate this feature show a clear
  baseline marker rather than implying a complete trail (see *Surfacing →
  baseline marker*).

## Testing

- **Config diff:** a `run_name` / flowcell / cycles / `status` change yields an
  entry with the right `field_changes`, `actor`, and `timestamp == run.updated_at`.
- **No-op:** a save that changes only volatile fields (e.g. a `touch` with no
  field change) records **no** entry.
- **READY promotion:** DRAFT→READY records only `status: draft → ready` (no
  `generated_*` noise) despite the export blobs being populated in the same save.
- **Samples, deep:** add a sample → `added` (entry carries a tracked-field
  **snapshot**); remove → `removed` (snapshot); reassign i7 on an existing
  sample → `modified` with `i7` before/after; change lanes → `modified` with
  `lanes`; rename a sample's `sample_id` (same uuid) → `modified` with
  `sample_id` before/after (NOT delete+add).
- **Easily-forgotten sample fields tracked:** a change to `index1_cycles` /
  `index2_cycles` / `index1_override_pattern` / `index2_override_pattern` /
  `override_cycles` (mutated during index assignment) is recorded — the denylist
  approach must not drop them. Structured index values are stored, not lossy
  display strings.
- **Creation:** blank/clone/template each produce a `created` entry with the
  correct `provenance.source` and `ref`.
- **Append-only repo:** `append` inserts; appending an entry whose `_id` already
  exists raises `DuplicateKeyError`; there is no update method on the repo.
- **Ordering & pagination:** N successive edits → N entries, newest-first;
  `list_by_run(..., limit=k)` returns at most `k`, and the `before` cursor pages
  to older entries; ordering is deterministic by `(timestamp, _id)` desc even
  when two entries share a `timestamp`.
- **No phantom on conflict:** when `run_repo.save` raises `ConflictError`, no
  history entry is inserted.
- **No entry on handler exception:** a handler that raises inside `saving_run`
  records nothing.
- **History-write failure is non-fatal + observable:** if `append` raises after
  a successful run save, the request still succeeds (the edit persisted), the
  failure is logged at ERROR, and `run.history.record_failed` is audited.
- **Cascade:** deleting an archived run removes its history; `list_by_run`
  returns empty.
- **Baseline marker:** a run with no `created` entry (predating the feature)
  renders the baseline note; a run created through the app does not.
- **Surfacing:** `GET /runs/{id}/history` renders newest-first, is read-only,
  and works for draft / ready / archived runs; 404 for a missing run.
- **Diff engine units:** `diff_run` covers config-only, sample-only, mixed,
  empty, sample-pairing-by-uuid, denylist coverage (a non-ignored field always
  surfaces), and ignored-key exclusion — as pure functions without a DB.

## Open questions

None blocking.

- **Timestamp timezone (documented, not fixed here):** the app records
  `created_at`/`updated_at` via local `datetime.now()` while the API schema
  documents them as UTC. History reuses the run's own timestamp for
  consistency, so it inherits this discrepancy rather than introducing a second
  convention. Converting the app to UTC is a separate, broader migration and is
  intentionally out of this feature's scope.

- **Latent before-snapshot aliasing for `Sample.metadata` / `Sample.analyses`
  (documented, not fixed here):** `Sample.to_dict()` returns those two fields by
  reference, not as copies, so the `before = run.to_dict()` snapshot aliases
  them. No current route handler mutates a sample's `metadata` or `analyses`
  *in place* (they are reassigned via `__setattr__`, which the snapshot does not
  alias), so the diff is correct today. If a future handler ever does
  `sample.metadata[...] = ...` in place, that change would be invisible to the
  history diff. The robust fix lives in `Sample.to_dict()` (copy those fields)
  rather than in this feature; deep-copying the whole snapshot here was rejected
  to avoid introducing diff-type noise. Tracked as a follow-up.
