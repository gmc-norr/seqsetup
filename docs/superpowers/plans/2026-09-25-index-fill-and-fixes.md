# Fill indexes in order + leftover fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix four small leftover defects, then add "Fill empty samples in order": a previewed, all-or-nothing fill of samples that have no index, from one kit, in table order.

**Architecture:** Part A are local fixes in existing routes/templates. Part B adds a pure planning service (`services/index_fill.py`), two routes in `routes/samples.py` (preview, apply), one preview template, a button in the sample section, a click action and styles. Apply rebuilds the plan and saves only if it matches the preview's signature.

**Tech Stack:** FastAPI, Jinja2 + jinja2-fragments, HTMX 2, Alpine.js (UI state only), plain CSS in `components.css`, MongoDB (mongomock in tests), pytest + Playwright.

**Spec:** `docs/superpowers/specs/2026-09-25-index-fill-design.md` (copied in Task 0). Read it before Task 5.

## Global Constraints

- Read `CLAUDE.md` and `ARCHITECTURE.md` at the repo root first; they bind every task. Clinical software: "when in doubt, do less"; no silent behavior changes; no extra refactors, comments or docstrings on code you did not change.
- Test first: write the failing test, run it and see it fail for the right reason, then implement.
- Do NOT change anything under `src/seqsetup/models/`, the exporters (`services/samplesheet_v2_exporter.py`, `services/samplesheet_v1_exporter.py`, `services/json_exporter.py`), or the validators (`services/validation.py`, `services/index_collision_validator.py`, `services/color_analysis_validator.py`). No new dependency (`pixi.toml`, `pixi.lock` unchanged).
- Run-mutating routes: `run: SequencingRun = Depends(get_editable_run)` and `with saving_run(run, ctx, request):`.
- HTMX 2 inherits `hx-target`/`hx-select`/`hx-swap` from ancestors: every new hx element sets its own. 4xx response text is shown in `#error-banner` by `static/js/app.js`.
- The CSP forbids inline handlers (`onclick=` etc.). Client actions go in `_CLICK_ACTIONS` in `static/js/app.js` via `data-action="..."`.
- `POST /runs/{run_id}/samples/{sample_id}` is a catch-all. New run routes must not live under `/runs/{run_id}/samples/` unless declared before it.
- UI copy: short plain sentences, like the existing app text.
- Commit per task on the worktree branch, conventional style (`fix(...)`, `feat(...)`, `chore:`, `test(...)`), a body explaining why, last line exactly:
  `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
- Commands, from the worktree root (there is no pixi env in the worktree; never run `pixi install` or `pixi run`):
  - `PY=/home/parlar_ai/dev/seqsetup/.pixi/envs/default/bin/python`
  - one file: `PYTHONPATH=src $PY -m pytest <file> -q`
  - server suite: `PYTHONPATH=src $PY -m pytest tests/unit tests/integration -q` (baseline **1428 passed**)
  - CSS (app.css is untracked; build before browser tests and after CSS edits; never commit it): `/home/parlar_ai/dev/seqsetup/.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify`
  - browser suite: `PYTHONPATH=src $PY -m pytest tests/browser -q` (baseline **67 passed**)
- Test fixtures: integration `fresh_app` → `(app, ctx, db)`, `logged_in_client`; POSTs need `headers={"Origin": "http://testserver"}`. Browser: `logged_in_page`, `base_url`, `app_ctx`, `mutable_run_id`; `SCREENSHOT_KIT_NAME` ("Screenshot-TestKit", 4 unique-dual pairs UDP0001–UDP0004) in `tests/browser/conftest.py`.

---

### Task 0: Put the spec and plan in the branch

**Files:**
- Create: `docs/superpowers/specs/2026-09-25-index-fill-design.md` (copy of `/home/parlar_ai/seqsetup-fill-run/spec.md`)
- Create: `docs/superpowers/plans/2026-09-25-index-fill-and-fixes.md` (copy of `/home/parlar_ai/seqsetup-fill-run/plan.md`)

- [ ] Copy both files, commit `docs: plan for fill indexes in order and leftover fixes`.

---

### Task 1 (A1): Changing the instrument keeps a kit the new flowcell offers

**Files:**
- Modify: `src/seqsetup/routes/runs.py` (`update_instrument`)
- Modify: `src/seqsetup/templates/wizard/_flowcell_select.html` and/or `wizard/_reagent_kit_select.html` (an out-of-band variant of the kit select)
- Test: `tests/integration/test_instrument_change_kit.py`, `tests/browser/test_instrument_change_kit.py`

Today `update_instrument` sets `run.flowcell_type` to the new instrument's first flowcell, never checks `run.reagent_cycles`, and only swaps `#flowcell-select`; `#reagent-kit-select` keeps the old instrument's kit list. `update_flowcell` (same file) already has the rule to copy: `if reagent_kits and run.reagent_cycles not in reagent_kits: run.reagent_cycles = reagent_kits[0]`. Run cycles are NOT reset (update_flowcell does not reset them either).

- [ ] **Step 1: failing integration test.** Find, in the fallback `config/instruments.yaml`, an instrument whose first flowcell does not offer the new run's default kit (a new run is NovaSeq X Series, 10B, 300 cycles; e.g. MiSeq's first flowcell or another — read the file and pick one; record your choice in STATUS.md). Post `/runs/{id}/instrument` with it and assert: the saved `reagent_cycles` is in that flowcell's kits; the response contains `id="reagent-kit-select"` with `hx-swap-oob="true"` listing exactly that flowcell's kits with the saved one `selected`; the response still contains the cycle total line (`id="cycle-total"`, out of band) showing the saved kit. A second test: switching to an instrument whose first flowcell DOES offer 300 keeps 300.
- [ ] **Step 2: run, see it fail.**
- [ ] **Step 3: implement.** Apply the rule inside the existing `saving_run` in `update_instrument`, then return the kit select out of band alongside the flowcell select (and the existing `_cycle_total_oob(run)` context, computed after the change). Reuse `_reagent_kit_select.html` with a flag (e.g. `kit_select_oob`) that adds `hx-swap-oob="true"`; when the template is included normally (step-1 page, `update_flowcell`) nothing changes.
- [ ] **Step 4: browser test.** Open a new run's setup page (`page.click("button.sidebar-btn")`, wait for `**/runs/new/step/1?new=1&run_id=*`), `select_option("#instrument_platform", <that instrument>)`, wait for the `/instrument` response, assert `#reagent-kit-select` options are the new flowcell's kits and its value equals the stored `reagent_cycles`; delete the run in `finally`.
- [ ] **Step 5: both tests pass; run `tests/integration/test_kit_cycle_limit_page.py` and `tests/browser/test_run_setup.py` too. Commit** `fix(ui): changing the instrument keeps a reagent kit the new flowcell offers`.

---

### Task 2 (A2): Bulk sample routes refuse a sample_ids value that is not a list of IDs

**Files:**
- Modify: `src/seqsetup/routes/samples.py` (`set_test_id_bulk` and any sibling with the same flaw)
- Test: `tests/integration/test_bulk_sample_ids_input.py`

`POST /runs/{run_id}/samples/set-test-id` returns 500 (TypeError) when `sample_ids` is JSON `null`. Read every handler in `routes/samples.py` that parses `sample_ids` (`assign_index_to_selected`, `set_lanes_bulk`, `set_mismatches_bulk`, `set_override_cycles_bulk`, `set_test_id_bulk`, `delete_samples_bulk`) and list in STATUS.md which ones crash on `null`, `{}` and `[1]`.

- [ ] **Step 1: failing tests**, parametrized over each affected route and over `"null"`, `"{}"`, `"[1]"`, `"\"S1\""`: status 400 (not 500), and the stored run is unchanged (compare `ctx.run_repo.get_by_id(run_id).to_dict()` before/after, ignoring nothing). Give each route the other fields it needs so only `sample_ids` is wrong (read the handler).
- [ ] **Step 2: run, see them fail (500 or TypeError).**
- [ ] **Step 3: implement** one small module-level helper in `routes/samples.py`, e.g. `_parse_sample_ids(raw) -> Optional[list[str]]` returning None unless the JSON is a list of strings, and use it in each affected handler: on None return `Response("sample_ids must be a list of sample IDs", status_code=400)` before any change. Keep each handler's existing messages for a missing field.
- [ ] **Step 4: tests pass; run the existing tests that cover these routes (`grep -rln "set-test-id\|set-lanes\|assign-index-to-selected\|samples/delete" tests`). Commit** `fix(samples): bulk routes answer 400, not 500, when sample_ids is not a list`.

---

### Task 3 (A3): Bulk lane panel — prove, then fix only if real

**Files:**
- Find: the bulk lane panel template (`grep -rn "_bulk_lane_panel" src/seqsetup/templates`) and its route (`set_lanes_bulk`)
- Test: `tests/browser/test_bulk_lane_panel_swap.py`

Its forms (or the JS in `static/js/app.js` that posts them, e.g. `applyBulkLanesForm`) target `#sample-table` while the route returns the whole `#sample-section`.

- [ ] **Step 1: browser test** on a draft with ≥2 samples (fixture creating and deleting its own run, like `empty_rows_run_id` in `tests/browser/test_multi_index_drop.py`): tick two samples, apply a lane change through the bulk lane panel as a user would, wait for the response, then assert `page.locator("#sample-section")` has count 1, `#sample-table #sample-section` has count 0, `#sample-table` has count 1, and the stored lanes changed.
- [ ] **Step 2: run it.** If it PASSES on the unchanged code, the issue is not real: keep the test (it guards the behavior), record the evidence in STATUS.md, commit `test(ui): bulk lane change leaves one sample section`, and go to Task 4. Do not change source.
- [ ] **Step 3 (only if it failed):** make the request target/select match the response the way other sample-section updates do (e.g. target `#sample-section`, `hx-select="#sample-section"`, swap `outerHTML`, or `htmx.ajax` with the same target/select). Check the other bulk actions in the same panel/JS for the same mismatch and cover each you fix with the same assertion.
- [ ] **Step 4: tests pass. Commit** `fix(ui): bulk lane change no longer nests the sample section`.

---

### Task 4 (A4): Delete the unused template

**Files:**
- Delete: `src/seqsetup/templates/wizard/_bulk_paste_section.html`

- [ ] **Step 1:** `grep -rn "_bulk_paste_section" /abs/worktree --include=*.py --include=*.html --include=*.js --include=*.md --include=*.rst` (exclude `.git`). Also check for string-built template names (`grep -rn "bulk_paste" src tests`). If anything other than docs history references it, leave the file, record in STATUS.md, skip this task.
- [ ] **Step 2:** delete it; run the server suite's `tests/integration/test_smoke_*` files (they render every page). **Commit** `chore: delete unused wizard/_bulk_paste_section.html`.

---

### Task 5 (B): The fill plan — pure service

**Files:**
- Create: `src/seqsetup/services/index_fill.py`
- Test: `tests/unit/test_index_fill.py`

**Interfaces produced (Tasks 6–7 rely on these exact names):**
- `build_fill_plan(run: SequencingRun, kit: IndexKit, start_id: str = "") -> FillPlan` (raises `ValueError` for a `start_id` not in the kit)
- `FillPlan` fields: `kit`, `mode` (`"pair"`, `"i7"` or `""`), `entries: list[KitEntry]`, `needed: int`, `start: Optional[KitEntry]`, `rows: list[FillRow]`, `skipped: list[str]`, `problem: str`; property `can_apply`; method `signature() -> str`
- `KitEntry` fields: `id, name, i7, i5, well, index`; `FillRow` fields: `sample_id, sample_label, entry`
- `COMBINATORIAL_REFUSAL` (str)

- [ ] **Step 1: write the failing tests** (`tests/unit/test_index_fill.py`):

```python
"""Planning "Fill empty samples in order": samples with no index get the
next unused indexes of one kit, in table order, or nothing at all."""

import json

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.index_fill import COMBINATORIAL_REFUSAL, build_fill_plan

I7 = ["AAAAAAAA", "CCCCCCCC", "GGGGGGGG", "TTTTTTTT", "ACACACAC"]
I5 = ["AGAGAGAG", "CTCTCTCT", "GAGAGAGA", "TCTCTCTC", "CACACACA"]


def _pair(k, i7=None, i5=None):
    return IndexPair(
        id=f"p{k}", name=f"UDP{k:04d}",
        index1=Index(name=f"i7-{k}", sequence=i7 or I7[k], index_type=IndexType.I7),
        index2=Index(name=f"i5-{k}", sequence=i5 or I5[k], index_type=IndexType.I5),
    )


def _dual_kit(n=5, pairs=None):
    return IndexKit(name="Kit", version="1", index_mode=IndexMode.UNIQUE_DUAL,
                    index_pairs=pairs if pairs is not None else [_pair(k) for k in range(n)])


def _single_kit(n=4):
    return IndexKit(name="Single", version="1", index_mode=IndexMode.SINGLE,
                    i7_indexes=[Index(name=f"S{k}", sequence=I7[k], index_type=IndexType.I7)
                                for k in range(n)])


def _run(n_samples=3):
    run = SequencingRun(run_name="R", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8))
    for k in range(1, n_samples + 1):
        run.add_sample(Sample(id=f"s{k}", sample_id=f"S{k}", lanes=[1]))
    return run


def _mapping(plan):
    return [(r.sample_label, r.entry.name) for r in plan.rows]


class TestFillOrder:
    """Samples in table order get the kit's indexes in kit order."""

    def test_fills_every_empty_sample_from_the_first_index(self):
        plan = build_fill_plan(_run(), _dual_kit())
        assert plan.can_apply and plan.problem == ""
        assert _mapping(plan) == [("S1", "UDP0000"), ("S2", "UDP0001"), ("S3", "UDP0002")]
        assert plan.start.name == "UDP0000" and plan.skipped == []

    def test_start_picks_where_to_begin(self):
        plan = build_fill_plan(_run(2), _dual_kit(), start_id="p2")
        assert _mapping(plan) == [("S1", "UDP0002"), ("S2", "UDP0003")]

    def test_never_wraps_to_the_beginning(self):
        plan = build_fill_plan(_run(2), _dual_kit(), start_id="p4")
        assert not plan.can_apply and plan.rows == []
        assert plan.problem == ("Not enough unused indexes: 2 needed, 1 left in Kit from "
                                "UDP0004. Pick an earlier start or another kit.")

    def test_unknown_start_raises(self):
        with pytest.raises(ValueError):
            build_fill_plan(_run(), _dual_kit(), start_id="nope")


class TestOnlyEmptySamples:
    """A sample with any index is never a target and is never changed."""

    def test_indexed_and_partial_samples_are_left_alone(self):
        run = _run(4)
        run.samples[1].assign_index(_pair(4))                       # S2: full pair
        run.samples[2].assign_index2(Index(name="x", sequence="GTGTGTGT",
                                           index_type=IndexType.I5))  # S3: i5 only
        plan = build_fill_plan(run, _dual_kit())
        assert [r.sample_label for r in plan.rows] == ["S1", "S4"]
        assert plan.needed == 2

    def test_nothing_to_do(self):
        run = _run(1)
        run.samples[0].assign_index(_pair(0))
        plan = build_fill_plan(run, _dual_kit())
        assert plan.problem == "Every sample already has an index." and not plan.can_apply


class TestSkipUsed:
    """An index whose i7 or i5 is already used in the run is skipped."""

    def test_default_start_is_first_unused(self):
        run = _run(3)
        run.samples[0].assign_index(_pair(0))
        plan = build_fill_plan(run, _dual_kit())
        assert plan.start.name == "UDP0001"
        assert _mapping(plan) == [("S2", "UDP0001"), ("S3", "UDP0002")]

    def test_used_index_after_the_start_is_skipped_and_named(self):
        run = _run(3)
        run.samples[0].assign_index(_pair(1))
        plan = build_fill_plan(run, _dual_kit(), start_id="p0")
        assert _mapping(plan) == [("S2", "UDP0000"), ("S3", "UDP0002")]
        assert plan.skipped == ["UDP0001"]

    def test_shared_i5_alone_counts_as_used(self):
        run = _run(2)
        other = _pair(4, i5=I5[0])            # another kit's pair sharing UDP0000's i5
        run.samples[0].assign_index(other)
        plan = build_fill_plan(run, _dual_kit(4))
        assert _mapping(plan) == [("S2", "UDP0001")]

    def test_a_kit_repeating_a_sequence_cannot_give_it_twice(self):
        pairs = [_pair(0), _pair(1, i7=I7[0]), _pair(2)]   # p1 repeats p0's i7
        plan = build_fill_plan(_run(2), _dual_kit(pairs=pairs))
        assert _mapping(plan) == [("S1", "UDP0000"), ("S2", "UDP0002")]
        assert plan.skipped == ["UDP0001"]

    def test_all_used(self):
        run = _run(3)
        run.samples[0].assign_index(_pair(0))
        plan = build_fill_plan(run, _dual_kit(1))
        assert plan.problem == "Every index in Kit is already used in this run."


class TestKitModes:

    def test_single_kit_fills_i7(self):
        plan = build_fill_plan(_run(2), _single_kit())
        assert plan.mode == "i7"
        assert [r.entry.id for r in plan.rows] == ["Single_i7_S0", "Single_i7_S1"]
        assert all(r.entry.i5 is None for r in plan.rows)

    def test_combinatorial_kit_refused(self):
        kit = IndexKit(name="Combo", version="1", index_mode=IndexMode.COMBINATORIAL,
                       i7_indexes=[Index(name="a", sequence=I7[0], index_type=IndexType.I7)],
                       i5_indexes=[Index(name="b", sequence=I5[0], index_type=IndexType.I5)])
        plan = build_fill_plan(_run(), kit)
        assert plan.problem == COMBINATORIAL_REFUSAL and not plan.can_apply

    def test_empty_kit(self):
        plan = build_fill_plan(_run(), _dual_kit(0))
        assert plan.problem == "Kit has no indexes."


class TestSignature:

    def test_signature_is_what_will_be_saved(self):
        plan = build_fill_plan(_run(2), _dual_kit())
        assert json.loads(plan.signature()) == [["s1", "p0"], ["s2", "p1"]]

    def test_signature_changes_when_the_run_changes(self):
        run = _run(2)
        before = build_fill_plan(run, _dual_kit(), start_id="p0").signature()
        run.add_sample(Sample(id="s3", sample_id="S3", lanes=[1]))
        assert build_fill_plan(run, _dual_kit(), start_id="p0").signature() != before


def test_planning_changes_nothing():
    run = _run(3)
    before = run.to_dict()
    build_fill_plan(run, _dual_kit())
    assert run.to_dict() == before
```

(Check first that `Sample.assign_index2` exists with that name; if the i5-only setter is named differently, use the real one and note it.)

- [ ] **Step 2: run, see ImportError.**
- [ ] **Step 3: implement `src/seqsetup/services/index_fill.py`:**

```python
"""Plan "Fill empty samples in order": give each sample that has no index the
next unused index of one kit, in table order.

Pure: reads a run and a kit, returns a plan, changes nothing. The preview
shows a plan; the apply route rebuilds it and saves only when its signature
matches the one the preview showed.
"""

import json
from dataclasses import dataclass, field
from typing import Optional, Union

from ..models.index import Index, IndexKit, IndexPair
from ..models.sequencing_run import SequencingRun

COMBINATORIAL_REFUSAL = (
    "Fill in order works with unique dual and single-index kits. "
    "Assign combinatorial indexes by hand."
)


@dataclass
class KitEntry:
    """One index of a kit, in kit order: a pair (unique dual) or an i7 (single)."""

    id: str  # IndexPair.id, or "<kit name>_i7_<index name>" as the index panel uses
    name: str
    i7: str
    i5: Optional[str]
    well: Optional[str]
    index: Union[IndexPair, Index]


@dataclass
class FillRow:
    sample_id: str  # Sample.id
    sample_label: str  # Sample.sample_id, as the table shows it
    entry: KitEntry


@dataclass
class FillPlan:
    kit: IndexKit
    mode: str  # "pair", "i7", or "" when the kit cannot be filled in order
    entries: list[KitEntry]
    needed: int  # samples with no index at all
    start: Optional[KitEntry] = None
    rows: list[FillRow] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    problem: str = ""

    @property
    def can_apply(self) -> bool:
        return not self.problem and bool(self.rows)

    def signature(self) -> str:
        """What Assign will save, for the apply route to compare."""
        return json.dumps([[row.sample_id, row.entry.id] for row in self.rows])


def kit_entries(kit: IndexKit) -> list[KitEntry]:
    """The kit's indexes in kit order; empty for a combinatorial kit."""
    if kit.is_unique_dual():
        return [
            KitEntry(p.id, p.name, p.index1_sequence, p.index2_sequence, p.well_position, p)
            for p in kit.index_pairs
        ]
    if kit.is_single():
        return [
            KitEntry(f"{kit.name}_i7_{i.name}", i.name, i.sequence, None, i.well_position, i)
            for i in kit.i7_indexes
        ]
    return []


def needs_index(sample) -> bool:
    """Only a sample with no index at all; a partial one is left alone."""
    return sample.index_pair is None and sample.index1 is None and sample.index2 is None


def build_fill_plan(run: SequencingRun, kit: IndexKit, start_id: str = "") -> FillPlan:
    """Plan giving each sample with no index the next unused index of ``kit``.

    An index is skipped when its i7 is already an i7 in the run or its i5 is
    already an i5 in the run; indexes chosen for this fill count as used.
    From the start it goes forward only. If there are not enough, the plan
    has a problem and no rows: nothing is partly filled.

    Raises ValueError when ``start_id`` is given but is not an index of ``kit``.
    """
    mode = "pair" if kit.is_unique_dual() else "i7" if kit.is_single() else ""
    entries = kit_entries(kit)
    targets = [s for s in run.samples if needs_index(s)]
    plan = FillPlan(kit=kit, mode=mode, entries=entries, needed=len(targets))

    if not mode:
        plan.problem = COMBINATORIAL_REFUSAL
        return plan
    if not entries:
        plan.problem = f"{kit.name} has no indexes."
        return plan

    used_i7 = {s.index1_sequence for s in run.samples if s.index1_sequence}
    used_i5 = {s.index2_sequence for s in run.samples if s.index2_sequence}

    def used(entry: KitEntry) -> bool:
        return entry.i7 in used_i7 or (entry.i5 is not None and entry.i5 in used_i5)

    if start_id:
        pos = next((i for i, e in enumerate(entries) if e.id == start_id), None)
        if pos is None:
            raise ValueError(f"{start_id!r} is not an index of {kit.name}")
    else:
        pos = next((i for i, e in enumerate(entries) if not used(e)), None)
    if pos is not None:
        plan.start = entries[pos]

    if not targets:
        plan.problem = "Every sample already has an index."
        return plan
    if pos is None:
        plan.problem = f"Every index in {kit.name} is already used in this run."
        return plan

    chosen: list[KitEntry] = []
    skipped: list[str] = []
    for entry in entries[pos:]:
        if len(chosen) == len(targets):
            break
        if used(entry):
            skipped.append(entry.name)
            continue
        chosen.append(entry)
        used_i7.add(entry.i7)
        if entry.i5 is not None:
            used_i5.add(entry.i5)

    if len(chosen) < len(targets):
        plan.problem = (
            f"Not enough unused indexes: {len(targets)} needed, {len(chosen)} left in "
            f"{kit.name} from {plan.start.name}. Pick an earlier start or another kit."
        )
        return plan

    plan.skipped = skipped
    plan.rows = [FillRow(s.id, s.sample_id, e) for s, e in zip(targets, chosen)]
    return plan
```

- [ ] **Step 4: tests pass** (if a test and this code disagree, the SPEC decides; record the disagreement in PLAN-DEFECTS.md). **Commit** `feat(indexes): plan filling empty samples in order from one kit`.

---

### Task 6 (B): Preview and apply routes, preview template, button

**Files:**
- Modify: `src/seqsetup/routes/samples.py` (two routes + one helper, placed right after `assign_indexes_bulk`; import `build_fill_plan`)
- Create: `src/seqsetup/templates/runs/_index_fill_preview.html`
- Modify: `src/seqsetup/templates/runs/_sample_section.html`
- Modify: `src/seqsetup/static/js/app.js` (`cancel-index-fill` in `_CLICK_ACTIONS`)
- Test: `tests/integration/test_index_fill_routes.py`

- [ ] **Step 1: failing integration tests.** Seed a kit with `ctx.index_kit_repo.save(IndexKit(...))` (5 unique-dual pairs, sequences as in Task 5) and a DRAFT run saved with `ctx.run_repo.save(...)` holding samples `S1..S3` with no index. Cover, each as its own test:
  1. Preview (`POST /runs/{id}/index-fill/preview`, data `selected_kit=<kit.kit_id>`) → 200; the page shows S1/S2/S3 with the first three pair names and their i7/i5 sequences, "Assign 3 indexes", a `name="plan"` hidden input whose value equals `str(markupsafe.escape(build_fill_plan(run, kit).signature()))` in the HTML; the stored run is unchanged.
  2. Preview with `start_id=<3rd pair id>` starts there.
  3. A sample already using the 1st pair, preview with `start_id=<1st pair id>` → "Skipped, already used in this run: <1st pair name>".
  4. Combinatorial kit → the refusal text and no "Assign".
  5. A 2-pair kit for 3 samples → the "Not enough unused indexes" text and no `name="plan"` input.
  6. Unknown kit → 400 "Pick an index kit first."; unknown `start_id` → 400.
  7. Apply (`POST /runs/{id}/index-fill`, data `selected_kit`, `start_id` = plan.start.id, `plan` = signature) → 200; stored S1..S3 have the three pairs' i7/i5 (`sample.index1_sequence`, `index2_sequence`), `index_kit_name == kit.name`; the response contains "Gave indexes to 3 samples from <kit name>, starting at <first pair name>."
  8. Stale preview: take the signature, then give S1 an index by hand and save; apply with the old signature → 409 "The run or kit changed since the preview. Preview again."; stored run equals the state before the apply call.
  9. A sample that already had an index keeps exactly that index after apply.
  10. A READY run → preview 403 and apply 403.
- [ ] **Step 2: run, see them fail (404 routes).**
- [ ] **Step 3: routes** (after `assign_indexes_bulk` in `routes/samples.py`):

```python
def _index_fill_plan(form, run: SequencingRun, ctx: AppContext):
    """(plan, "") or (None, message for a 400)."""
    kit_id = sanitize_string(form.get("selected_kit", ""), 512)
    start_id = sanitize_string(form.get("start_id", ""), 512)
    kit = ctx.index_kit_repo.get_by_kit_id(kit_id) if kit_id else None
    if kit is None:
        return None, "Pick an index kit first."
    try:
        return build_fill_plan(run, kit, start_id), ""
    except ValueError:
        return None, "That start index is not in this kit."


@router.post("/runs/{run_id}/index-fill/preview", response_class=HTMLResponse)
async def preview_index_fill(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/index-fill/preview — what "Fill in order" would
    assign. Nothing is saved."""
    plan, error = _index_fill_plan(await request.form(), run, ctx)
    if error:
        return Response(error, status_code=400)
    return render(request, "runs/_index_fill_preview.html", {"run": run, "plan": plan})


@router.post("/runs/{run_id}/index-fill", response_class=HTMLResponse)
async def apply_index_fill(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/index-fill — assign the previewed plan. Refused
    (409) unless the plan rebuilt now is the one the preview showed."""
    form = await request.form()
    plan, error = _index_fill_plan(form, run, ctx)
    if error:
        return Response(error, status_code=400)
    if not plan.can_apply:
        return Response(plan.problem or "Nothing to fill.", status_code=400)
    if plan.signature() != form.get("plan", ""):
        return Response(
            "The run or kit changed since the preview. Preview again.", status_code=409
        )

    with saving_run(run, ctx, request):
        for row in plan.rows:
            if plan.mode == "pair":
                run.assign_index_pair_to_sample(row.sample_id, row.entry.index)
            else:
                run.assign_index1_to_sample(row.sample_id, row.entry.index)
            sample = run.get_sample(row.sample_id)
            sample.index_kit_name = plan.kit.name
            _apply_kit_defaults(sample, plan.kit)
            _update_override_cycles(sample, run)

    audit(
        "sample.index_filled_in_order",
        actor=get_username(request),
        target=run.id,
        kit_name=plan.kit.name,
        kit_version=plan.kit.version,
        start=plan.start.name,
        sample_count=len(plan.rows),
    )
    return _render_sample_section(run, request, ctx, messages=[{
        "text": (
            f"Gave indexes to {len(plan.rows)} samples from {plan.kit.name}, "
            f"starting at {plan.start.name}."
        ),
        "kind": "success",
    }])
```

- [ ] **Step 4: preview template** `src/seqsetup/templates/runs/_index_fill_preview.html`:

```html
{#
   "Fill empty samples in order" preview. Nothing is saved until Assign;
   Assign sends the plan's signature and the server refuses a changed plan.

   Inputs:
     run:   SequencingRun
     plan:  FillPlan (services/index_fill.py)
#}
<div id="index-fill-preview" class="index-fill-preview">
    <h3 class="index-fill-title">Fill samples without an index, in order</h3>
    {% if plan.entries %}
    <form class="index-fill-options"
          hx-post="/runs/{{ run.id }}/index-fill/preview"
          hx-trigger="change"
          hx-target="#index-fill-area"
          hx-select="#index-fill-preview"
          hx-swap="innerHTML">
        <input type="hidden" name="selected_kit" value="{{ plan.kit.kit_id }}">
        <label for="index-fill-start">Start at</label>
        <select id="index-fill-start" name="start_id" class="paste-select">
            {% for e in plan.entries %}
            <option value="{{ e.id }}" {% if plan.start and e.id == plan.start.id %}selected{% endif %}>{{ e.name }}{% if e.well %} ({{ e.well }}){% endif %}</option>
            {% endfor %}
        </select>
    </form>
    {% endif %}

    {% if plan.problem %}
    <p class="index-fill-problem">{{ plan.problem }}</p>
    {% else %}
    <p class="index-fill-summary">{{ plan.rows | length }} sample(s) without an index get indexes
        from {{ plan.kit.name }}, in table order, starting at {{ plan.start.name }}.
        Samples that already have an index are not changed.</p>
    {% if plan.skipped %}
    <p class="index-fill-note">Skipped, already used in this run: {{ plan.skipped | join(', ') }}.</p>
    {% endif %}
    <table class="index-fill-table">
        <thead><tr><th>Sample</th><th>Index</th><th>i7</th><th>i5</th></tr></thead>
        <tbody>
            {% for row in plan.rows %}
            <tr>
                <td>{{ row.sample_label }}</td>
                <td>{{ row.entry.name }}</td>
                <td><code>{{ row.entry.i7 }}</code></td>
                <td><code>{{ row.entry.i5 or '' }}</code></td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% endif %}

    <div class="index-fill-actions">
        {% if plan.can_apply %}
        <form hx-post="/runs/{{ run.id }}/index-fill"
              hx-target="#sample-section"
              hx-swap="outerHTML"
              hx-disabled-elt="find button">
            <input type="hidden" name="selected_kit" value="{{ plan.kit.kit_id }}">
            <input type="hidden" name="start_id" value="{{ plan.start.id }}">
            <input type="hidden" name="plan" value="{{ plan.signature() }}">
            <button type="submit" class="btn btn-primary btn-small">Assign {{ plan.rows | length }} indexes</button>
        </form>
        {% endif %}
        <button type="button" class="paste-link" data-action="cancel-index-fill">Cancel</button>
    </div>
</div>
```

(The Assign form copies the paste preview's Add form, `templates/runs/_paste_preview.html`, which swaps `#sample-section` the same way. If an ancestor of `#sample-section` turns out to set `hx-select`, add `hx-select="#sample-section"` and note it.)

- [ ] **Step 5: button and area** in `templates/runs/_sample_section.html`, inside `{% if has_unindexed %}`: put `<div id="index-fill-area"></div>` directly before `<div class="run-page-with-index-panel">`, and in the aside, right after the `_index_kit_dropdown.html` include:

```html
{% if index_kits %}
<form class="index-fill-start"
      hx-post="/runs/{{ run.id }}/index-fill/preview"
      hx-include="#index-kit-dropdown"
      hx-target="#index-fill-area"
      hx-select="#index-fill-preview"
      hx-swap="innerHTML">
    <button type="submit" class="btn btn-secondary btn-small">Fill empty samples in order…</button>
</form>
{% endif %}
```

Also update the template's header comment (Inputs unchanged; mention the fill area in the DRAFT bullet list).

- [ ] **Step 6: Cancel** — in `static/js/app.js`, add to `_CLICK_ACTIONS`: `'cancel-index-fill': () => { const a = document.getElementById('index-fill-area'); if (a) a.innerHTML = ''; },`
- [ ] **Step 7: tests pass; run `tests/integration/test_smoke_*.py` too. Commit** `feat(indexes): fill empty samples in order, with a preview`.

---

### Task 7 (B): Styles and browser test

**Files:**
- Modify: `src/seqsetup/static/css/components.css` (`.index-fill-*`)
- Test: `tests/browser/test_index_fill.py`

- [ ] **Step 1: failing browser test** with a fixture creating a DRAFT run with three samples and no indexes (copy `empty_rows_run_id` from `tests/browser/test_multi_index_drop.py`, new run id, delete in teardown):
  1. Open `/runs/{id}`, `select_option("#index-kit-dropdown", f"{SCREENSHOT_KIT_NAME}:1.0")` (wait for the `/indexes/kit-content` response), click "Fill empty samples in order…", expect `#index-fill-preview` to contain `UDP0001`, `UDP0002`, `UDP0003` and 3 table body rows; the stored run still has no indexes.
  2. Change `#index-fill-start` to `UDP0002`'s id (read the option value) and expect the preview's first row to show `UDP0002`.
  3. Click "Assign 3 indexes", wait for the `/index-fill` response (200); the stored samples now carry UDP0002, UDP0003, UDP0004 sequences in order; `#index-fill-preview` is gone.
  4. A separate test: open the preview, click Cancel, `#index-fill-area` is empty and nothing was stored.
- [ ] **Step 2: styles** in `components.css`, next to the `.paste-*` block, using existing tokens (`--space-*`, `--fs-sm`, `--danger`, `--danger-fg`, `--danger-bg`, `--text-muted`, borders like `.paste-*` use): `.index-fill-start` (margin under the dropdown), `.index-fill-preview` (bordered panel with padding and bottom margin, like the paste preview), `.index-fill-options` (flex, gap, wrap), `.index-fill-problem` (danger colors), `.index-fill-note` (muted), `.index-fill-table` (full width, small font, cells padded), `.index-fill-actions` (flex, gap, align center). Must work at 375 px width: the table may scroll inside the panel (`overflow-x: auto` on a wrapper), the page must not.
- [ ] **Step 3: rebuild CSS, run the test, then the whole browser suite. Take one screenshot of the preview (full page, 1280 wide) into `/home/parlar_ai/seqsetup-fill-run/shots/` and look at it; record what you saw in STATUS.md. Commit** `feat(ui): style the fill-in-order preview`.

---

### Final

- [ ] Full server suite and full browser suite on the final tree; exact counts into STATUS.md (expected: 1428 + your new server tests; 67 + your new browser tests; zero failed, zero errors).
- [ ] Identity checks (see the run prompt) with their real output into STATUS.md.
- [ ] Final whole-branch review, then the closing summary.
