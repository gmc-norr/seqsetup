# Run Templates & Clone-Run — Design

**Date:** 2026-06-11
**Status:** Approved design, pending implementation plan
**Feature area:** Run setup / reuse of configuration

## Problem

Clinical labs run the same assay configuration repeatedly (same instrument,
flowcell, cycles, BCLConvert settings, and often the same fixed control
samples). Today every run is rebuilt from the new-run wizard, and a failed
run cannot be re-submitted without re-entering all its samples and index
assignments. This is repetitive and is itself a configuration-error vector.

Two distinct reuse needs:

1. **Clone a run** — start from an existing run, either:
   - *config only* (new batch of the same assay), or
   - *full duplicate including samples + index assignments* (re-run a failed run).
2. **Named templates** — a user-managed, org-wide library of reusable run
   configurations, optionally carrying scaffold samples (e.g. fixed controls),
   that new runs are started from.

## Scope

In scope:
- Clone (duplicate) action on an existing run, with a choice at clone time of
  whether to include samples.
- A `RunTemplate` entity: org-wide, any authenticated user may create / edit /
  delete (no admin gate).
- Template creation **only** via "Save as template" from an existing run
  (no from-scratch blank-template builder).
- Templates capture run config **and** an optional set of scaffold samples.
- "Start from template" entry point in the new-run flow.

Out of scope (YAGNI for this spec):
- Blank/from-scratch template builder.
- Template versioning / history (editing a template just updates it; runs
  already created from it are independent and unaffected).
- Admin governance tier / personal-vs-shared visibility (all templates are
  org-wide and user-managed).
- Smart index assignment, plate-map entry (separate specs).

## Architecture

### Chosen approach: separate model, shared instantiation path

A `RunTemplate` is its own typed entity, **fully outside the run state
machine**. This is the load-bearing safety decision: templates can never leak
into the dashboard, the JSON API (which exposes only `ready`/`archived`), the
export pipeline, validation, or the `get_editable_run` guard, because they are
not `SequencingRun` documents at all. The alternative — a `RunStatus.TEMPLATE`
value — would thread a new "remember to exclude TEMPLATE here" obligation
through every run query and the state machine, exactly the kind of forgettable
invariant CLAUDE.md warns against. Rejected.

Clone and template-instantiation share **one** construction helper so the
"build a fresh DRAFT from a config + samples" logic exists in a single place.

### Components

**`models/run_template.py` — `RunTemplate` dataclass** (mirrors the existing
self-validating dataclass pattern: `to_dict`/`from_dict`, invariants in
`__setattr__`):

- `id: str` (uuid default)
- `name: str` — required, 256-char cap, CR/LF stripped (same rule as
  `run_name`)
- `description: str` — 4096-char cap
- `created_by / updated_by: str`
- `created_at / updated_at: datetime`
- Run configuration (mirrors `SequencingRun` config fields, **excluding**
  identity/status/export/lock fields):
  - `instrument_platform: InstrumentPlatform`
  - `flowcell_type: str`
  - `reagent_cycles: int`
  - `run_cycles: Optional[RunCycles]`
  - `barcode_mismatches_index1 / barcode_mismatches_index2: int`
  - `adapter_behavior: str`
  - `create_fastq_for_index_reads: bool`
  - `no_lane_splitting: bool`
  - `analyses: list[Analysis]`
- `scaffold_samples: list[Sample]` — optional; rebuilt via `Sample.from_dict`
  on load so model validation applies.

> Note: there is **no** run-level "index kit" field in `SequencingRun` — the
> index kit is implied per-sample via `Sample.index_kit_name`. Templates
> therefore do not store a separate kit selection; the index-kit panel default
> in a new run is derived from scaffold samples (if any), exactly as it is for
> any run today.

**`repositories/run_template_repo.py` — `RunTemplateRepository(BaseRepository[RunTemplate])`**:
thin, no business logic; `COLLECTION = "run_templates"`. Standard CRUD from the
base class. Registered in `startup.py` and exposed on `AppContext` alongside
the other repos.

**Shared instantiation helper** — a single function that produces a fresh DRAFT
`SequencingRun` from a config source plus a sample list:

```
build_draft_run(*, config_source, samples, created_by) -> SequencingRun
```

Guarantees, regardless of caller (clone or template):
- New run `id` (fresh uuid); `_loaded_updated_at = None` (insert, no false
  optimistic-lock conflict).
- `status = RunStatus.DRAFT` always — never inherits READY/ARCHIVED.
- All `generated_*` export blobs are `None` — never copies pre-generated
  exports.
- `created_by = updated_by = current user`; `created_at = updated_at = now`.
- `samples` are deep-copied through `Sample.to_dict` → `Sample.from_dict`, so
  every sample re-validates on construction. **Each sample's `id` (and its
  clinical `sample_id`) is preserved**, not regenerated: the round-trip already
  yields independent objects, and uuids need not be unique across separate run
  documents. Preserving identity keeps any `Analysis.sample_ids` references
  valid (see next point) and avoids a class of dangling-reference bugs.
- **Sample-count cap is enforced.** The helper refuses if the included sample
  count exceeds `MAX_SAMPLES_PER_RUN`, replicating the backstop that
  `SequencingRun.add_sample` provides (direct list construction would otherwise
  bypass it — sequencing_run.py:236). Historical runs may exceed the cap by
  having predated it; a *fresh* instantiation must not.
- **Analyses are filtered to included samples, never copied verbatim.**
  `Analysis.sample_ids` is emitted directly into the DRAGEN
  `[Dragen*_Data]` sections with no referential validation
  (samplesheet_v2_exporter.py:269). The helper therefore rewrites each copied
  analysis's `sample_ids` to the intersection with the included samples'
  identifiers and **drops any analysis left with no samples**. Consequence: a
  **config-only clone copies no analyses** (all reference excluded samples); an
  include-samples clone keeps analyses intact; a scaffolded template keeps only
  the analyses whose samples are among the scaffold.
- Remaining config fields copied verbatim (instrument, flowcell, reagent
  cycles, run cycles, BCLConvert settings).

`config_source` is either an existing `SequencingRun` (clone) or a
`RunTemplate` (template instantiation); the helper reads the shared config
field set from either.

### Reference-integrity check at instantiation

Before returning the draft, the helper validates against the **current enabled
instrument configuration** that:
- the referenced **instrument definition** still exists (config sync can remove
  or rename it),
- `flowcell_type` is still among that instrument's offered flowcells, **and**
- the `reagent_cycles` value is still among the reagent-kit cycles that
  instrument offers for that flowcell (a flowcell can survive while a specific
  reagent kit is withdrawn; ordinary validation only checks cycle *totals*
  against capacity, not whether the kit is currently offered).

If any of the three is no longer available, instantiation **refuses with a
clear HTTP 400-level message** rather than producing a silently-misconfigured
run.

A missing **index kit** is, by contrast, **non-fatal**. Copied/scaffold samples
carry their **embedded index sequences** (`index_pair`/`index1`/`index2`),
which are authoritative for export; `index_kit_name` is descriptive metadata
only and kit membership is never validated. A withdrawn kit therefore does not
compromise a fully-indexed run — the only visible effect is that the index-kit
panel may be empty when assigning *additional* indexes. A scaffold sample that
genuinely has *no* embedded index is still caught by the existing
`prerequisite_missing_indexes` validation. No kit-membership check is added.

## User-facing flows & routes

All routes require authentication; none require admin. Mutations of a *run*
continue to go through `saving_run(...)`; template mutations save through the
new repo directly (templates are not state-machine guarded).

### Clone

- **Dashboard "Duplicate" action** on any run (draft/ready/archived) opens a
  small confirm with an `include_samples` checkbox.
- `POST /runs/{run_id}/duplicate` (form: `include_samples: bool`,
  optional `run_name`):
  1. Load the source run (read-only; no editable guard — we only read it).
  2. `build_draft_run(config_source=source, samples=source.samples if
     include_samples else [], created_by=current_user)`.
  3. New `run_name`: provided value, else source name + " (copy)" (subject to
     the model's 256-cap/CR-LF rule).
  4. Save the new draft; `audit("run.cloned", actor=…, target=new_id,
     source=source_id, included_samples=…)`.
  5. Redirect to the new run's edit page.

### Templates

- **List:** `GET /templates` — org-wide list (name, description, instrument,
  sample count, updated_by/at) with edit/delete actions.
- **Create (save as template):** `POST /runs/{run_id}/save-as-template`
  (form: `name`, `description`, sample-inclusion selection). **Create-only** —
  always mints a new template with a fresh `id`; it never replaces an existing
  one. Captures the run's current config; the selected current samples become
  `scaffold_samples` (deep-copied via `Sample` round-trip, with the same
  cap/analyses-filtering rules the instantiation helper uses). Template **names
  are not required to be unique** (templates are identified by `id`); a
  duplicate name is allowed. `audit("template.created", …)`.
- **Replacing a template's config/scaffold:** there is **no** update-config
  route. To change a template's configuration or scaffold samples, create a new
  template from the corrected run and delete the old one. This is the explicit,
  deliberate consequence of create-only + the "no from-scratch builder" cut —
  the template editor is not a second run editor.
- **Edit:** `GET /templates/{id}` + `POST /templates/{id}` — update **name and
  description only**. On save, set `updated_by = current user` and
  `updated_at = now`, and `audit("template.updated", actor=…, target=id)`
  (every state-changing route audits, per ARCHITECTURE.md).
- **Delete:** `DELETE /templates/{id}`. `audit("template.deleted", …)`.
- **Start from template:** the new-run flow gains a "Start from template"
  choice alongside "Blank." `POST /runs/new/from-template/{template_id}`:
  1. Load template.
  2. `build_draft_run(config_source=template, samples=template.scaffold_samples,
     created_by=current_user)` (reference-integrity check applies; refuse if
     instrument, flowcell, or reagent-kit cycles are no longer offered).
  3. Save draft; `audit("run.created_from_template", actor=…, target=new_id,
     template=template_id)`.
  4. Redirect to the new run's **edit page** (same target as clone). Config is
     already complete, so — unlike a blank new run — there is no reason to drop
     the user back at wizard step 1.

## Clinical-safety summary

- Instantiated runs are **always DRAFT with no exports** — never inherit Ready/
  Archived state or pre-generated blobs.
- Scaffold and cloned samples pass through `Sample` construction → DNA-regex,
  length-cap, and numeric clamps apply; a bad index baked into a template
  **cannot** bypass model validation.
- **Stale scaffold control indexes** are a real risk (a control's index in a
  template can drift from reality). The resulting run's normal validation —
  index collision, index-length consistency, dark-cycle, color-balance — is the
  backstop, and re-saving a template from a corrected run keeps it current. This
  risk is documented, not silently accepted.
- **No dangling sample references in exports.** Copied analyses are filtered to
  the included samples and empty analyses dropped, so the DRAGEN
  `[Dragen*_Data]` sections never list a `Sample_ID` that isn't in the run
  (a config-only clone carries no analyses at all). Sample identity is
  preserved on copy so surviving references stay valid.
- **Fresh-run sample cap is enforced** even though the copy path bypasses
  `add_sample` — the helper refuses an included-sample count over
  `MAX_SAMPLES_PER_RUN`.
- Reference-integrity refusal prevents a template/source that points at a
  removed/renamed instrument, a withdrawn flowcell, **or a withdrawn reagent
  kit** from silently producing a misconfigured run.
- Templates are structurally outside the run state machine, the run dashboard,
  the JSON API, and the export pipeline.

## Testing

Following the project convention (valid + invalid, security boundaries):

- **Clone:**
  - config-only clone copies config, **no** samples, **and no analyses**;
  - include-samples clone copies samples with their **ids preserved** and
    re-runs `Sample` validation;
  - cloned run is DRAFT, has fresh `id`, `created_by`/`updated_by` = actor, and
    **all `generated_*` are None**;
  - cloning a READY/ARCHIVED run does not mutate the source.
- **Analyses filtering:**
  - a config-only clone of a run that had analyses produces a run with **zero**
    analyses;
  - an include-samples clone keeps analyses, and each analysis's `sample_ids`
    contains only included samples;
  - a scaffolded template whose analysis referenced a non-scaffold sample drops
    that reference (and drops the analysis if it becomes empty);
  - regression: the exported `[Dragen*_Data]` section never lists a `Sample_ID`
    absent from the run.
- **Sample-count cap:** instantiation with included samples exceeding
  `MAX_SAMPLES_PER_RUN` is refused (even though it bypasses `add_sample`); a
  historical source run already over the cap can still be the *source* of a
  config-only clone.
- **Templates:**
  - save-as-template captures config and selected scaffold samples;
  - new-from-template pre-populates scaffold samples and config;
  - save-as-template is create-only: two saves with the same name yield two
    distinct templates;
  - template name/description edit updates `updated_by`/`updated_at`;
  - `RunTemplate.to_dict`/`from_dict` round-trip; `__setattr__` invariants
    (name cap/CR-LF, description cap) enforced on direct assignment.
- **Reference integrity:** instantiation is refused with a clear error when the
  source/template's **instrument, flowcell, or reagent-kit cycles** are no
  longer offered by the current enabled instrument config. A missing **index
  kit** is non-fatal: a fully-indexed copied sample still validates (embedded
  sequences are authoritative); a scaffold sample with no embedded index is
  caught by `prerequisite_missing_indexes`.
- **Safety boundaries:**
  - a template never appears in `run_repo.list_all()` / the run dashboard /
    the JSON API;
  - model validation cannot be bypassed via a malicious scaffold sample (e.g.
    over-length sample_id or non-ACGTN index in the stored template dict).
- **Audit:** clone, template create / **update** / delete, and
  create-from-template each emit their audit event.

## Open questions

None blocking. (Changing a template's config or scaffold is deliberately
delete-and-recreate: save a new template from a corrected run and delete the
old one — there is no update-config route.)
