# Run checks (group 1b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mark Ready asks before promoting a run with color-balance errors, its own messages get a slot nothing clears by mistake, Override Cycles that do not fit the run are refused at save, and the cycle total says when it is not checked.

**Architecture:** One rule for "does this Override Cycles value fit the run" in `CycleCalculator`, used by Mark Ready and both save routes. Mark Ready's refusal and its new color-balance question go into a new `#ready-message` slot under the status bar, emptied out of band on every successful status change. The color-balance answer is tied to the run's `updated_at` and the lanes shown.

**Tech Stack:** FastAPI, Jinja2, HTMX 2.0.10, Tailwind v4 (`components.css`), pytest (mongomock), Playwright.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-09-27-run-checks-1b-design.md` (commits ace33b3, c00597b).
- Worktree `/home/parlar_ai/dev/seqsetup/.worktrees/run-checks`, branch `fix/run-checks`, base `101a326`.
- `PY=/home/parlar_ai/dev/seqsetup/.pixi/envs/default/bin/python`. Tests: `cd <worktree> && PYTHONPATH=src $PY -m pytest <paths> -q -p no:cacheprovider`. Never `pixi run` in a worktree; no `-n`.
- CSS for browser tests (app.css is gitignored): `/home/parlar_ai/dev/seqsetup/.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify`.
- Docs: `$PY -m sphinx -W --keep-going -q -b html docs <scratch dir>`.
- Clinical: tests first and seen failing; no silent behaviour change; do not touch the main checkout's uncommitted files; never `git stash`/`checkout --`/`reset --hard`/`clean`.
- UI spelling is "color" (as in the app). Messages in banners are escaped (Jinja autoescape; `exception_handlers._error_fragment`).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`.

---

### Task 1: One rule for "does this Override Cycles value fit the run"

**Files:**
- Modify: `src/seqsetup/services/cycle_calculator.py` (new classmethod after `is_valid_override_segment`, ~line 212)
- Modify: `src/seqsetup/services/validation.py` `_validate_override_cycles_match_run` (~381-485)
- Test: `tests/unit/test_cycle_calculator.py` (append a class)

**Interfaces:**
- Produces: `CycleCalculator.override_cycles_problem(override_cycles: str, run_cycles: RunCycles) -> Optional[str]` — `None` | `"invalid"` | `"mismatch"`.

- [ ] **Step 1: Write the failing test** (append to `tests/unit/test_cycle_calculator.py`; add `import pytest` / `RunCycles` imports if the file lacks them)

```python
class TestOverrideCyclesProblem:
    """One rule, used by Mark Ready and the save routes: does a sample's
    OverrideCycles fit the run's reads (spec 2026-09-27 run checks 1b, F11)?"""

    RC = RunCycles(151, 151, 10, 10)

    @pytest.mark.parametrize("value", [
        "Y151;I10;I10;Y151", "Y151;I8N2;I8N2;Y151", "U8Y143;I10;I10;Y151",
        "y151;i10;i10;y151", "Y151,I10,I10,Y151",
    ])
    def test_value_that_fits_has_no_problem(self, value):
        assert CycleCalculator.override_cycles_problem(value, self.RC) is None

    @pytest.mark.parametrize("value", ["151;I10;I10;Y151", "Y151N;I10;I10;Y151", "Y151;;I10;I10;Y151"])
    def test_malformed_value_is_invalid(self, value):
        assert CycleCalculator.override_cycles_problem(value, self.RC) == "invalid"

    @pytest.mark.parametrize("value", [
        pytest.param("Y151;I10;Y151", id="too-few-parts"),
        pytest.param("Y100;I10;I10;Y151", id="wrong-sum"),
        pytest.param("Y100;I8N2;I8N2;Y151", id="kit-pattern-Y100"),
        pytest.param("Y*;I10;I10;Y151", id="leftover-wildcard"),
    ])
    def test_value_that_does_not_fit_is_a_mismatch(self, value):
        assert CycleCalculator.override_cycles_problem(value, self.RC) == "mismatch"

    def test_zero_cycle_read_has_no_part(self):
        rc = RunCycles(151, 0, 10, 10)
        assert CycleCalculator.override_cycles_problem("Y151;I10;I10", rc) is None
        assert CycleCalculator.override_cycles_problem("Y151;I10;I10;Y0", rc) == "mismatch"
```

- [ ] **Step 2: Run it; expect FAIL** — `AttributeError: ... has no attribute 'override_cycles_problem'`.

Run: `PYTHONPATH=src $PY -m pytest tests/unit/test_cycle_calculator.py -q -p no:cacheprovider -k OverrideCyclesProblem`

- [ ] **Step 3: Implement** (in `CycleCalculator`, after `is_valid_override_segment`)

```python
    @classmethod
    def override_cycles_problem(
        cls, override_cycles: str, run_cycles: RunCycles
    ) -> Optional[str]:
        """Whether a sample's OverrideCycles fits the run. ``None`` if it
        does; ``"invalid"`` if a segment is malformed (a digit sum can match
        while BCL Convert rejects the value: '151' has no letter, 'Y151N' a
        dangling one); ``"mismatch"`` if a '*' is left in it — internal
        shorthand, never valid in a sheet — or its segments do not match the
        run's reads: one per read of more than 0 cycles, each summing to that
        read's cycles. Mark Ready and the save routes use this one rule."""
        if "*" in override_cycles:
            return "mismatch"
        segments = re.split(r"[;,]", override_cycles)
        if not all(cls.is_valid_override_segment(seg.upper()) for seg in segments):
            return "invalid"
        sums = [sum(int(n) for n in re.findall(r"\d+", seg)) for seg in segments if seg]
        expected = [cycles for _, _, cycles in cls.read_structure(run_cycles)]
        return "mismatch" if sums != expected else None
```

In `validation.py` `_validate_override_cycles_match_run`, delete the `expected = ...` line and its comment block (the comment moves into the docstring above), and replace everything from `if "*" in oc:` down to `bad.append(...)` after the sums comparison with:

```python
            problem = CycleCalculator.override_cycles_problem(oc, rc)
            if problem == "invalid":
                invalid.append(sample.sample_id or sample.id)
            elif problem == "mismatch":
                bad.append(sample.sample_id or sample.id)
```

The read-override-pattern part above it and both error messages below stay as they are.

- [ ] **Step 4: Run** the new tests and every existing Override Cycles validation test: `PYTHONPATH=src $PY -m pytest tests/unit/test_cycle_calculator.py tests/unit/test_validation.py tests/unit/test_override_cycles*.py -q -p no:cacheprovider` (drop a glob that matches nothing). Expected: all pass.

- [ ] **Step 5: Commit** — `refactor(cycles): one rule for Override Cycles that fit the run (F11)`.

---

### Task 2: Both save routes check every final value (F11)

**Files:**
- Modify: `src/seqsetup/routes/samples.py` — `set_override_cycles_bulk` (~1058-1113), `update_sample_settings` (~1380-1463), new helper `_override_cycles_refusal` near `_update_override_cycles` (~129)
- Modify: `docs/user-guide/override-cycles.rst` (warning at ~125-136)
- Modify: spec line for "typed, invalid" (already refused today by `expand_override_cycles`, message unchanged)
- Test: new `tests/integration/test_run_checks_1b.py`

**Interfaces:**
- Consumes: `CycleCalculator.override_cycles_problem` (Task 1).
- Produces: `_override_cycles_refusal(value: str, run_cycles: RunCycles, calculated_for: str | None = None, more: int = 0) -> str`.

- [ ] **Step 1: Write the failing tests** (`tests/integration/test_run_checks_1b.py`)

```python
"""Run checks, group 1b, through the real routes (spec 2026-09-27)."""

import re

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}


def _pair(i7: str, i5: str, name: str = "p1") -> IndexPair:
    return IndexPair(
        id=name, name=name,
        index1=Index(name=f"{name}-i7", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"{name}-i5", sequence=i5, index_type=IndexType.I5),
    )


# No blocking error and no color-balance error: i7 CCCCCCCC lights both
# channels; NovaSeq X reads i5 as its reverse complement, so i5 GGGGGGGG is
# read as CCCCCCCC (i5 CCCCCCCC would be read GGGGGGGG: a dark-cycle error).
CLEAN_PAIR = ("CCCCCCCC", "GGGGGGGG")


def _seed(ctx, run_id: str, pairs=(("ATTACTCG", "TATAGCCT"),), platform=InstrumentPlatform.NOVASEQ_X,
          flowcell="10B", read1_pattern: str | None = None, lanes=(1,)) -> str:
    """A DRAFT run with one indexed sample per pair, in lane 1 only (a sample
    without lanes is in every lane: 8 on a 10B flowcell); 151/10/10/151 cycles."""
    run = SequencingRun(
        id=run_id, run_name="Checks", instrument_platform=platform, flowcell_type=flowcell,
        run_cycles=RunCycles(151, 151, 10, 10),
    )
    for n, (i7, i5) in enumerate(pairs, start=1):
        sample = Sample(sample_id=f"S{n}", index_pair=_pair(i7, i5, f"p{n}"), lanes=list(lanes))
        if read1_pattern:
            sample.read1_override_pattern = read1_pattern
        run.add_sample(sample)
    ctx.run_repo.save(run)
    return run.id


class TestOverrideCyclesRefusedAtSave:
    """A value that does not fit the run is refused when saved, typed or
    calculated ("Auto"); nothing is saved (F11)."""

    def test_typed_value_that_does_not_fit_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-typed")
        run = ctx.run_repo.get_by_id(run_id)
        sample = run.samples[0]
        before = (sample.override_cycles, run.updated_at)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample.id}/settings",
            data={"override_cycles": "Y151;I10;Y151"}, headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert "does not fit this run" in resp.text
        after = ctx.run_repo.get_by_id(run_id)
        assert (after.samples[0].override_cycles, after.updated_at) == before

    def test_typed_value_that_fits_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-typed-ok")
        sample_id = ctx.run_repo.get_by_id(run_id).samples[0].id

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample_id}/settings",
            data={"override_cycles": "Y151;I8N2;I8N2;Y151"}, headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run_id).samples[0].override_cycles == "Y151;I8N2;I8N2;Y151"

    def test_calculated_value_that_does_not_fit_is_refused(self, logged_in_client, fresh_app):
        """A kit whose default read override is Y100 calculates
        Y100;I8N2;I8N2;Y151 on a 151-cycle run (Astra's review)."""
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-auto", read1_pattern="Y100")
        run = ctx.run_repo.get_by_id(run_id)
        sample = run.samples[0]
        before = (sample.override_cycles, run.updated_at)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/{sample.id}/settings",
            data={"override_cycles": ""}, headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert "calculated for S1" in resp.text
        assert "Y100;I8N2;I8N2;Y151" in resp.text
        after = ctx.run_repo.get_by_id(run_id)
        assert (after.samples[0].override_cycles, after.updated_at) == before

    def test_bulk_typed_value_that_does_not_fit_changes_no_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-bulk", pairs=(("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")))
        run = ctx.run_repo.get_by_id(run_id)
        before = ([s.override_cycles for s in run.samples], run.updated_at)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}", "{run.samples[1].id}"]',
                  "override_cycles": "Y151;I10;Y151"},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        after = ctx.run_repo.get_by_id(run_id)
        assert ([s.override_cycles for s in after.samples], after.updated_at) == before

    def test_bulk_auto_with_one_failing_sample_changes_no_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-bulk-auto", pairs=(("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")))
        run = ctx.run_repo.get_by_id(run_id)
        run.samples[1].read1_override_pattern = "Y100"
        ctx.run_repo.save(run)
        run = ctx.run_repo.get_by_id(run_id)
        before = ([s.override_cycles for s in run.samples], run.updated_at)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}", "{run.samples[1].id}"]',
                  "override_cycles": ""},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert "calculated for S2" in resp.text
        after = ctx.run_repo.get_by_id(run_id)
        assert ([s.override_cycles for s in after.samples], after.updated_at) == before

    def test_bulk_value_that_fits_is_saved_for_every_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "oc-bulk-ok", pairs=(("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")))
        run = ctx.run_repo.get_by_id(run_id)

        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/set-override-cycles",
            data={"sample_ids": f'["{run.samples[0].id}", "{run.samples[1].id}"]',
                  "override_cycles": "Y151;I8N2;I8N2;Y151"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert [s.override_cycles for s in ctx.run_repo.get_by_id(run_id).samples] == [
            "Y151;I8N2;I8N2;Y151"] * 2
```

Before running, confirm the two route paths with `grep -n '@router.post' src/seqsetup/routes/samples.py | grep -n 'settings\|set-override'` and fix the URLs above if they differ.

- [ ] **Step 2: Run; expect FAIL** — the "does not fit" cases get 200 (value saved); the "fits" cases pass already (controls).

- [ ] **Step 3: Implement.** Helper (near `_update_override_cycles`):

```python
def _override_cycles_refusal(
    value: str, run_cycles: RunCycles, calculated_for: Optional[str] = None, more: int = 0
) -> str:
    """The 400 message for an Override Cycles value that does not fit the
    run (spec 2026-09-27 run checks 1b, F11). Escaped by the error banner."""
    cycles = (
        f"Read1 {run_cycles.read1_cycles} / Index1 {run_cycles.index1_cycles} / "
        f"Index2 {run_cycles.index2_cycles} / Read2 {run_cycles.read2_cycles}"
    )
    if calculated_for is None:
        return (
            f"Override Cycles {value!r} does not fit this run's cycles ({cycles}): each "
            f"part must add up to its read's cycles, one part per read of more than 0 "
            f"cycles. Nothing was saved. Leave the field empty to calculate it from the "
            f"run's cycles."
        )
    others = f" (and {more} more sample(s))" if more else ""
    return (
        f"The Override Cycles calculated for {calculated_for}{others} ({value!r}) do not "
        f"fit this run's cycles ({cycles}). They come from the index kit's default read "
        f"override, which an admin must correct. Nothing was saved."
    )
```

`update_sample_settings`: inside the existing `try:`, after the expansion and before `with saving_run(...)`, work out the final value; inside the block assign it:

```python
        final_override = None
        if has_override:
            calculated = False
            if override_cycles:
                final_override = override_cycles
            elif run.run_cycles and sample.has_index:
                final_override = CycleCalculator.calculate_override_cycles(sample, run.run_cycles)
                calculated = True
            if final_override and run.run_cycles and CycleCalculator.override_cycles_problem(
                final_override, run.run_cycles
            ):
                raise HTTPException(status_code=400, detail=_override_cycles_refusal(
                    final_override, run.run_cycles,
                    calculated_for=(sample.sample_id or sample.id) if calculated else None,
                ))
        with saving_run(run, ctx, request):
            if has_override:
                sample.override_cycles = final_override
            if has_bmi1:
                sample.barcode_mismatches_index1 = bmi1
            if has_bmi2:
                sample.barcode_mismatches_index2 = bmi2
```

`set_override_cycles_bulk`: inside the existing `try:`, after the expansion, replace the loop with a compute-then-save pair:

```python
        finals: dict[str, Optional[str]] = {}
        failing: list[tuple[str, str]] = []
        for sample in run.samples:
            if sample.id not in sample_ids:
                continue
            if override_cycles:
                finals[sample.id] = override_cycles
            elif run.run_cycles and sample.has_index:
                value = CycleCalculator.calculate_override_cycles(sample, run.run_cycles)
                finals[sample.id] = value
                if CycleCalculator.override_cycles_problem(value, run.run_cycles):
                    failing.append((sample.sample_id or sample.id, value))
            else:
                finals[sample.id] = None
        if override_cycles and run.run_cycles and finals and CycleCalculator.override_cycles_problem(
            override_cycles, run.run_cycles
        ):
            raise HTTPException(status_code=400, detail=_override_cycles_refusal(
                override_cycles, run.run_cycles))
        if failing:
            name, value = failing[0]
            raise HTTPException(status_code=400, detail=_override_cycles_refusal(
                value, run.run_cycles, calculated_for=name, more=len(failing) - 1))
        with saving_run(run, ctx, request):
            for sample in run.samples:
                if sample.id in finals:
                    sample.override_cycles = finals[sample.id]
```

`HTTPException` is not a `ValueError`, so the existing `except ValueError` does not swallow it. Import `RunCycles` for the helper's annotation if `samples.py` lacks it.

- [ ] **Step 4: Run** `tests/integration/test_run_checks_1b.py`, `tests/integration/test_smoke_wizard.py`, `tests/integration/test_index_fill_routes.py`, `tests/browser/test_htmx_errors.py` is browser-only (skip here). Expected: pass. If an existing test saved a mismatching value on purpose to test Mark Ready, give it a fitting one or seed the bad value through the repo instead, and say which in the commit message.

- [ ] **Step 5: Docs.** In `docs/user-guide/override-cycles.rst` replace the `.. warning::` block that begins "That immediate check does **not** confirm the value actually matches this run" with:

```rst
The same save also checks that the value fits this run: one segment per
read of more than 0 cycles, each adding up to that read's cycles. A value
that does not fit is refused the same way, and so is a value calculated
when you leave the field empty -- that one comes from the index kit's
default read override, which an admin must correct. The **Check** panel
and Mark Ready check again, because the run's cycles can change after a
value was saved.
```

In the spec, change the "typed, invalid" bullet to: "typed, malformed: already refused today by `expand_override_cycles` with its own message (unchanged)."

- [ ] **Step 6: Commit** — `fix(samples): refuse Override Cycles that do not fit the run when saved (F11)`.

---

### Task 3: Mark Ready's messages get their own slot

**Files:**
- Create: `src/seqsetup/templates/runs/_ready_message.html`
- Modify: `src/seqsetup/templates/runs/edit.html` (after the `.run-header-top` div, ~line 15)
- Modify: `src/seqsetup/templates/runs/_ready_refused.html` (header comment only)
- Modify: `src/seqsetup/routes/runs.py` `update_status` (refusal headers ~441-450; success response ~545-553)
- Modify tests: `tests/integration/test_mark_ready_sample_text_line_breaks.py` (73, 90, 108), `test_ready_refusal_and_row_errors.py` (66), `test_smoke_validation.py` (95, if it is the refusal), `test_sheet_safety.py` (61, 81), `tests/browser/test_row_errors.py` (`test_refusal_is_a_list`), `tests/browser/test_docs_screenshots.py` (`test_ready_mark_ready_refused`)
- Test: `tests/integration/test_run_checks_1b.py` (new class), new `tests/browser/test_ready_message.py`
- Docs: `docs/user-guide/export.rst`

- [ ] **Step 1: Write the failing tests.** Integration (append):

```python
class TestReadyMessageSlot:
    """Mark Ready's refusal goes to #ready-message, and a successful status
    change empties it; #error-banner is left to save failures."""

    def test_refusal_targets_the_ready_slot(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = SequencingRun(id="slot-refused", run_name="R", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                            flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
        ctx.run_repo.save(run)  # no samples: a real refusal

        resp = logged_in_client.post("/runs/slot-refused/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert resp.headers.get("HX-Reswap") == "innerHTML"
        assert "Cannot mark ready" in resp.text

    def test_success_empties_the_ready_slot(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run_id = _seed(ctx, "slot-ok", pairs=(CLEAN_PAIR,))

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert ctx.run_repo.get_by_id(run_id).status.value == "ready", resp.text[:400]
        assert re.search(r'<div id="ready-message" class="empty:hidden" hx-swap-oob="true"></div>', resp.text)

    def test_edit_page_has_the_ready_slot(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "slot-page")

        page = logged_in_client.get(f"/runs/{run_id}").text

        assert '<div id="ready-message" class="empty:hidden"></div>' in page
```

(`CLEAN_PAIR` has no blocking error and no color-balance error, so this run is not asked the Task 4 question — Astra checked the pair.)

Browser (`tests/browser/test_ready_message.py`) — seeds its own runs through `app_ctx`, like `mutable_run_id`:

```python
"""Mark Ready's messages live in #ready-message; save failures stay in
#error-banner (spec 2026-09-27 run checks 1b, Astra's review points 1 and 3)."""

from datetime import datetime

import pytest
from playwright.sync_api import expect

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun


# See CLEAN_PAIR in tests/integration/test_run_checks_1b.py: i5 GGGGGGGG is
# read as CCCCCCCC on NovaSeq X, so this pair has no error of any kind.
CLEAN = ("CCCCCCCC", "GGGGGGGG")


def _seed(app_ctx, run_id, i7, i5, test_id="WGS", indexed=True):
    t = datetime(2026, 1, 10, 9, 0, 0)
    run = SequencingRun(id=run_id, run_name=run_id, instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
                        created_at=t, updated_at=t)
    pair = IndexPair(id=f"{run_id}-p", name="p",
                     index1=Index(name="i7", sequence=i7, index_type=IndexType.I7),
                     index2=Index(name="i5", sequence=i5, index_type=IndexType.I5)) if indexed else None
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="RM-01", test_id=test_id, index_pair=pair,
                          lanes=[1]))
    app_ctx.run_repo.save(run)
    return run_id


@pytest.fixture
def cleanup(app_ctx):
    ids = []
    yield ids
    for run_id in ids:
        app_ctx.run_repo.delete(run_id)


@pytest.mark.browser
def test_save_failure_survives_mark_ready(logged_in_page, base_url, app_ctx, cleanup):
    """A refused edit leaves the old value stored; Mark Ready can succeed
    on it, and the failure message must still be on screen afterwards."""
    run_id = _seed(app_ctx, "ready-msg-survive", *CLEAN)
    cleanup.append(run_id)
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    box = page.locator('td.override-cell input[name="override_cycles"]').first
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == 400):
        box.fill("Y*Q;I8;I8;Y*")
        box.dispatch_event("change")
    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")

    page.get_by_role("button", name="Mark Ready").click()
    expect(page.locator("#run-status-bar .status-ready")).to_be_visible()

    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")


@pytest.mark.browser
def test_refusal_does_not_replace_a_save_failure(logged_in_page, base_url, app_ctx, cleanup):
    run_id = _seed(app_ctx, "ready-msg-refused", *CLEAN, test_id="")
    cleanup.append(run_id)
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    box = page.locator('td.override-cell input[name="override_cycles"]').first
    with page.expect_response(lambda r: r.url.endswith("/settings") and r.status == 400):
        box.fill("Y*Q;I8;I8;Y*")
        box.dispatch_event("change")

    page.get_by_role("button", name="Mark Ready").click()

    expect(page.locator("#ready-message .ready-refused")).to_contain_text("Cannot mark ready")
    expect(page.locator("#error-banner")).to_contain_text("not valid OverrideCycles")
```

If `app_ctx.run_repo` has no `delete`, use the method `mutable_run_id`'s teardown uses. In setup, confirm the first run passes validation (`ValidationService.validate_run(...).error_count == 0` with the app's repos) so a failure points at the setup, not the feature; the browser server seeds test profile `WGS`.

- [ ] **Step 2: Run; expect FAIL** — the integration tests see `#error-banner` / no slot; the browser tests (CSS built first) fail on `#error-banner` being emptied or replaced, or on the missing slot.

- [ ] **Step 3: Implement.** `runs/_ready_message.html` (keep the div empty: `empty:hidden` needs `:empty`):

```html
{#
   Slot for Mark Ready's own messages — the refusal and the color-balance
   question — under the run status bar. update_status aims them here with
   HX-Retarget, and every successful status change sends the slot back
   empty (oob=True). Kept apart from #error-banner, which static/js/app.js
   empties when an element whose request failed later succeeds, and which
   holds save failures that must outlive a status change.

   Inputs:
     oob: bool — swap in out of band
#}
<div id="ready-message" class="empty:hidden"{% if oob %} hx-swap-oob="true"{% endif %}></div>
```

`edit.html`, right after the closing `</div>` of `.run-header-top`:

```html
        {% with oob=False %}
        {% include "runs/_ready_message.html" %}
        {% endwith %}
```

`update_status`: in the refusal's headers, `"HX-Retarget": "#ready-message"` (keep `HX-Reswap: innerHTML`); in the success response:

```python
    ready_html = templates.env.get_template("runs/_ready_message.html").render(oob=True)
    return HTMLResponse(status_html + export_html + section_html + ready_html, headers={"Cache-Control": "no-store"})
```

`_ready_refused.html` header comment: "swapped into #ready-message (HX-Retarget)".

- [ ] **Step 4: Update the existing assertions** listed under Files from `"#error-banner"` to `"#ready-message"` (only the Mark Ready refusals; `test_session_revocation.py` and `test_html_exception_handler.py` are HTTP errors and stay). `test_row_errors.py::test_refusal_is_a_list`: `banner = page.locator("#ready-message")`. `test_docs_screenshots.py::test_ready_mark_ready_refused`: wait on `#ready-message .ready-refused` and `region=page.locator("#ready-message")`.

- [ ] **Step 5: Run** the integration files touched, then the browser files (`tests/browser/test_ready_message.py tests/browser/test_row_errors.py tests/browser/test_htmx_errors.py`) with the CSS built. Expected: pass.

- [ ] **Step 6: Docs** (`export.rst`): "lists every one of them in a banner at the top of the page" → "lists every one of them right under the status bar"; figure alt/caption "The Mark Ready refusal, under the status bar, outlined." Add after the "Once every error is fixed" figure:

```rst
A message Mark Ready shows stays under the status bar until the run's
status changes; an error from a save that was refused stays in the red
banner at the top of the page, even after the run becomes Ready -- read
it before you rely on the value you typed.
```

- [ ] **Step 7: Commit** — `fix(runs): Mark Ready's messages get their own slot under the status bar`.

---

### Task 4: Mark Ready asks about color-balance errors (F13)

**Files:**
- Modify: `src/seqsetup/models/validation.py` (`LaneColorBalance.has_errors` after `has_issues` ~148; `ValidationResult.color_balance_error_lanes` after `color_balance_issue_count` ~315)
- Create: `src/seqsetup/templates/runs/_ready_color_balance.html`
- Modify: `src/seqsetup/routes/runs.py` `update_status`
- Modify: `src/seqsetup/templates/runs/_validate_panel.html` (badge ~68-70)
- Modify: `src/seqsetup/static/css/components.css` (after `.ready-refused li + li`, ~1841)
- Modify: `tests/integration/conftest.py` (new helper `mark_ready`), existing tests that now meet the question
- Test: new `tests/unit/test_color_balance_question.py`; `tests/integration/test_run_checks_1b.py` (new class); `tests/browser/test_ready_message.py` (retry test)
- Docs: `docs/user-guide/validation.rst`, `docs/user-guide/export.rst`, `tests/browser/test_docs_screenshots.py::test_ready_mark_ready`

**Interfaces:**
- Produces: `LaneColorBalance.has_errors -> bool`; `ValidationResult.color_balance_error_lanes -> list[int]`; form fields `color_balance_confirmed_at`, `color_balance_lanes`; audit details `color_balance_lanes` (denied) and `color_balance_accepted_lanes` (changed); test helper `mark_ready(client, run_id, headers) -> Response`.

- [ ] **Step 1: Write the failing unit tests** (`tests/unit/test_color_balance_question.py`)

```python
"""Which lanes make Mark Ready ask about color balance (F13): lanes with at
least one Error position; warnings do not count."""

from seqsetup.models.validation import (
    IndexColorBalance, LaneColorBalance, PositionColorBalance, ValidationResult,
)


def _lane(lane, *positions):
    return LaneColorBalance(lane=lane, sample_count=1,
                            i7_balance=IndexColorBalance(index_type="i7", positions=list(positions)))


OK = PositionColorBalance(position=1, c_count=1)                 # C: both channels
WARNING = PositionColorBalance(position=1, a_count=4, c_count=1)  # channel 2 at 20 %
ERROR = PositionColorBalance(position=1, a_count=1)              # A: channel 2 at 0 %


def _result(color_balance):
    return ValidationResult(duplicate_sample_ids=[], index_collisions=[], distance_matrices={},
                            color_balance=color_balance)


def test_error_position_makes_a_lane_have_errors():
    assert _lane(1, ERROR).has_errors
    assert not _lane(1, WARNING).has_errors
    assert not _lane(1, OK).has_errors


def test_i5_errors_count_too():
    lane = LaneColorBalance(lane=2, sample_count=1,
                            i5_balance=IndexColorBalance(index_type="i5", positions=[ERROR]))
    assert lane.has_errors


def test_error_lanes_are_sorted_and_skip_warning_lanes():
    result = _result({3: _lane(3, ERROR), 1: _lane(1, ERROR), 2: _lane(2, WARNING)})
    assert result.color_balance_error_lanes == [1, 3]


def test_no_color_balance_means_no_error_lanes():
    assert _result({}).color_balance_error_lanes == []
```

Run: expect `AttributeError` on `has_errors`.

- [ ] **Step 2: Implement the model properties**

```python
    @property
    def has_errors(self) -> bool:
        """At least one Error position (a channel with no signal) in i7 or i5."""
        return any(
            balance.error_count > 0 for balance in (self.i7_balance, self.i5_balance) if balance
        )
```

```python
    @property
    def color_balance_error_lanes(self) -> list[int]:
        """Lanes with a color-balance Error — Mark Ready asks before going on
        (warnings do not count). Empty when color balance is not analysed."""
        return sorted(lane for lane, lb in self.color_balance.items() if lb.has_errors)
```

Run the unit file: pass.

- [ ] **Step 3: Write the failing integration tests** (append to `test_run_checks_1b.py`)

```python
def _question_fields(html: str) -> dict:
    return dict(re.findall(r'name="(color_balance_[a-z_]+)" value="([^"]*)"', html))


def _events(ctx, prefix):
    return ctx.audit_event_repo.search(limit=50, event_prefix=prefix)


class TestColorBalanceQuestion:
    """Mark Ready asks before promoting a run with color-balance errors; the
    answer counts only for the run and lanes that were shown (F13). `_seed`
    puts samples in lane 1 only, so the error lanes are [1]."""

    def _setup(self, fresh_app, run_id, pairs=(("ATTACTCG", "TATAGCCT"),)):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        return ctx, _seed(ctx, run_id, pairs=pairs)

    def test_error_lanes_ask_and_stay_draft(self, logged_in_client, fresh_app):
        ctx, run_id = self._setup(fresh_app, "cb-ask")

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.status_code == 200
        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert "Color balance errors" in resp.text and "Mark Ready anyway" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status.value == "draft" and run.generated_samplesheet_v2 is None
        (event,) = _events(ctx, "run.status.denied")
        assert event.details["reason"] == "color_balance_unconfirmed"
        assert event.details["color_balance_lanes"] == [1]

    def test_answer_makes_it_ready_and_is_recorded(self, logged_in_client, fresh_app):
        ctx, run_id = self._setup(fresh_app, "cb-yes")
        question = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready",
                                     data=_question_fields(question.text), headers=ORIGIN)

        assert "HX-Retarget" not in resp.headers, resp.text[:400]
        assert ctx.run_repo.get_by_id(run_id).status.value == "ready"
        (event,) = _events(ctx, "run.status.changed")
        assert event.details["color_balance_accepted_lanes"] == [1]

    def test_answer_for_an_older_version_asks_again(self, logged_in_client, fresh_app):
        ctx, run_id = self._setup(fresh_app, "cb-stale")
        fields = _question_fields(logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN).text)
        assert logged_in_client.post(f"/runs/{run_id}/name", data={"run_name": "Edited"},
                                     headers=ORIGIN).status_code == 200

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", data=fields, headers=ORIGIN)

        assert "Mark Ready anyway" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status.value == "draft"

    def test_answer_for_other_lanes_asks_again(self, logged_in_client, fresh_app):
        ctx, run_id = self._setup(fresh_app, "cb-lanes")
        fields = _question_fields(logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN).text)
        fields["color_balance_lanes"] = "2"

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", data=fields, headers=ORIGIN)

        assert "Mark Ready anyway" in resp.text
        assert ctx.run_repo.get_by_id(run_id).status.value == "draft"

    def test_no_error_lanes_do_not_ask(self, logged_in_client, fresh_app):
        ctx, run_id = self._setup(fresh_app, "cb-none", pairs=(CLEAN_PAIR,))

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert "Mark Ready anyway" not in resp.text
        assert ctx.run_repo.get_by_id(run_id).status.value == "ready"

    def test_real_errors_are_refused_before_asking(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "cb-refused")  # profile repos on, no test_id: a real error

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert "Cannot mark ready" in resp.text and "Mark Ready anyway" not in resp.text
```

Add to `ValidationService` unit coverage (same unit file):

```python
def test_four_color_instrument_has_no_error_lanes():
    from seqsetup.models.index import Index, IndexPair, IndexType
    from seqsetup.models.sample import Sample
    from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
    from seqsetup.services.validation import ValidationService, clear_validation_cache

    clear_validation_cache()
    run = SequencingRun(id="cb-4color", instrument_platform=InstrumentPlatform.HISEQ_4000,
                        run_cycles=RunCycles(151, 151, 8, 8))
    run.add_sample(Sample(sample_id="S1", index_pair=IndexPair(id="p", name="p",
        index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5))))
    assert ValidationService.validate_run(run).color_balance_error_lanes == []
```

(Use the platform enum member for a 4-color instrument that exists — check `InstrumentPlatform`; HiSeq 4000 is 4-color in `config/instruments.yaml`. Pass `flowcell_type` if the enum's instrument needs one.)

Run: the integration tests fail (Ready without a question, no audit details); the 4-color test passes already (control).

- [ ] **Step 4: Implement the route.** In `update_status`, declare `color_balance_lanes: list[int] = []` before `if new_status == RunStatus.READY:`; after the `error_count > 0` refusal block, inside the same `if`:

```python
        color_balance_lanes = validation_result.color_balance_error_lanes
        if color_balance_lanes:
            # Poor color balance costs read quality in a lane but does not
            # mix up patients, and one-sample lanes almost always show it —
            # so ask, and record the answer (spec 2026-09-27, F13). The
            # answer counts only for the run version and lanes shown.
            form = await request.form()
            shown = ",".join(str(lane) for lane in color_balance_lanes)
            confirmed = (
                form.get("color_balance_confirmed_at") == run.updated_at.isoformat()
                and form.get("color_balance_lanes") == shown
            )
            if not confirmed:
                audit(
                    "run.status.denied",
                    actor=get_username(request),
                    target=run.id,
                    outcome="denied",
                    reason="color_balance_unconfirmed",
                    attempted_status=new_status.value,
                    color_balance_lanes=color_balance_lanes,
                )
                return HTMLResponse(
                    templates.env.get_template("runs/_ready_color_balance.html").render(
                        run=run, lanes=color_balance_lanes, lanes_value=shown,
                    ),
                    headers={
                        "Cache-Control": "no-store",
                        "HX-Retarget": "#ready-message",
                        "HX-Reswap": "innerHTML",
                    },
                )
```

And the success audit:

```python
    audit(
        "run.status.changed",
        actor=get_username(request),
        target=run.id,
        from_status=previous_status,
        to_status=new_status.value,
        **({"color_balance_accepted_lanes": color_balance_lanes} if color_balance_lanes else {}),
    )
```

`runs/_ready_color_balance.html`:

```html
{#
   Mark-Ready question when color balance has errors, swapped into
   #ready-message (HX-Retarget). The run stays Draft until the operator
   answers; routes/runs.py update_status accepts the answer only while the
   run's updated_at and its error lanes are what was shown here.

   Inputs:
     run:          SequencingRun
     lanes:        list[int] — lanes with color balance errors
     lanes_value:  str — the same lanes, "1,2", sent back with the answer
#}
<div class="warning-message ready-confirm">
    <p><strong>Color balance errors</strong></p>
    <p>{{ "Lane" if lanes | length == 1 else "Lanes" }} {{ lanes | join(", ") }}
       {{ "has" if lanes | length == 1 else "have" }} color balance errors: at some index
       position, one color channel gets no signal from any sample in the lane. Reads from
       that lane may fail to be assigned to their samples. Check the Color Balance tab of
       the <a href="/runs/{{ run.id }}/validation">validation page</a> before going on.</p>
    <form hx-post="/runs/{{ run.id }}/status/ready"
          hx-target="#run-status-bar"
          hx-swap="outerHTML"
          hx-disabled-elt="find button">
        <input type="hidden" name="color_balance_confirmed_at" value="{{ run.updated_at.isoformat() }}">
        <input type="hidden" name="color_balance_lanes" value="{{ lanes_value }}">
        <button type="submit" class="btn btn-secondary btn-small">Mark Ready anyway</button>
    </form>
</div>
```

CSS (`components.css`, after `.ready-refused li + li`):

```css
/* Mark Ready's color-balance question (runs/_ready_color_balance.html). */
.ready-confirm p + p { margin-top: var(--space-1); }
.ready-confirm form { margin-top: var(--space-2); }
```

Check panel badge (`_validate_panel.html`): after the `color_balance_issues` set line add
`{% set color_balance_asks = validation_result.color_balance_error_lanes | length > 0 %}` and make the badge
`<span class="status-warning">Color balance: {{ color_balance_issues }} lane(s){% if color_balance_asks %} · Mark Ready will ask{% endif %}</span>`.
Add a test in `test_run_checks_1b.py` that `GET /runs/{id}/validate-panel` for the `cb-ask` setup contains `Mark Ready will ask`, and for the `CLEAN_PAIR` setup does not.

- [ ] **Step 5: Run** the unit file and `test_run_checks_1b.py`: pass.

- [ ] **Step 6: Existing tests.** Add to `tests/integration/conftest.py`:

```python
def mark_ready(client, run_id: str, headers: dict):
    """POST Mark Ready; if the color-balance question comes back, answer it
    the way its form does. Returns the last response. For tests about
    something else that happen to use a one-sample two-color run."""
    resp = client.post(f"/runs/{run_id}/status/ready", headers=headers)
    if "Mark Ready anyway" not in resp.text:
        return resp
    fields = dict(re.findall(r'name="(color_balance_[a-z_]+)" value="([^"]*)"', resp.text))
    return client.post(f"/runs/{run_id}/status/ready", data=fields, headers=headers)
```

(add `import re` there). Run the nine files that post Mark Ready (`grep -rln "status/ready" tests/integration`). For every test that expected Ready and now sees the question, replace its `logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)` with `mark_ready(logged_in_client, run_id, ORIGIN)` (import from `.conftest`). Do not use the helper in a test whose point is the refusal. List the changed tests in the commit message.

- [ ] **Step 7: Browser retry test** (append to `tests/browser/test_ready_message.py`)

```python
@pytest.mark.browser
def test_question_survives_a_retry_after_a_failure(logged_in_page, base_url, app_ctx, cleanup):
    """Astra's point 1: after Mark Ready failed (here a 500), the retry's
    question must stay on screen and its button must work."""
    run_id = _seed(app_ctx, "ready-msg-retry", "ATTACTCG", "TATAGCCT")
    cleanup.append(run_id)
    page = logged_in_page
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")
    page.route(f"**/runs/{run_id}/status/ready",
               lambda route: route.fulfill(status=500, body="Failed to generate exports",
                                           content_type="text/plain"),
               times=1)
    page.get_by_role("button", name="Mark Ready").click()
    expect(page.locator("#error-banner")).to_contain_text("Failed to generate exports")

    with page.expect_response(lambda r: r.url.endswith("/status/ready") and r.status == 200):
        page.get_by_role("button", name="Mark Ready").click()
    page.wait_for_load_state("networkidle")

    question = page.locator("#ready-message .ready-confirm")
    expect(question).to_be_visible()
    question.get_by_role("button", name="Mark Ready anyway").click()
    expect(page.locator("#run-status-bar .status-ready")).to_be_visible()
    expect(page.locator("#ready-message")).to_be_empty()
```

Also run `tests/browser/test_mark_ready_quiet.py`; if its clean run now meets the question, answer it there the same way.

- [ ] **Step 8: Docs.** `validation.rst` Check panel paragraph: after "an amber **Color balance: N lane(s)** badge appears too" add "-- with "· Mark Ready will ask" when a lane has a color balance *error*". Replace the color-balance `.. warning::` (starts "An **Error** here -- 0% signal in a channel") with:

```rst
.. note::
   An **Error** here -- no signal in a channel from any sample in the
   lane -- does not block **Mark Ready** on its own, because a lane with
   one or two samples almost always has one. Instead, Mark Ready stops
   and asks: it names the lanes and offers **Mark Ready anyway** (see
   :doc:`export`). Your answer is kept in the audit trail. If the run
   changes before you answer, it asks again. Read this tab before you
   answer; a **Warning** does not make it ask.
```

`export.rst`, after the refusal figure:

```rst
If the run has no errors but a lane has a color balance error (see
:doc:`validation`), **Mark Ready** does not go ahead yet. It asks, under
the status bar, and names the lanes:

.. figure:: /_static/screenshots/ready/mark-ready-color-balance.png
   :alt: The "Color balance errors" question under the status bar, naming lane 1, with a "Mark Ready anyway" button.

   The color balance question, outlined.

Select **Mark Ready anyway** to promote the run; your answer, and the
lanes it covered, are recorded in the audit trail. If the run changes
before you answer, the question comes back for the new state.
```

`test_docs_screenshots.py::test_ready_mark_ready`: after `page.get_by_role("button", name="Mark Ready").click()`, before waiting for the Ready badge:

```python
    # DEMO-RUN-06's four pairs leave color-balance errors (i7 positions 4
    # and 6, in every lane the samples are in), so Mark Ready asks first
    # (spec 2026-09-27, F13).
    question = page.locator("#ready-message .ready-confirm")
    expect(question).to_be_visible()
    snap(page, "ready/mark-ready-color-balance", question, region=page.locator("#ready-message"))
    question.get_by_role("button", name="Mark Ready anyway").click()
```

and update that test's long comment about `color_balance_issue_count` "never added into error_count" to say the check makes Mark Ready ask.

- [ ] **Step 9: Run** unit + `test_run_checks_1b.py` + the nine Mark Ready files + `tests/browser/test_ready_message.py tests/browser/test_row_errors.py tests/browser/test_mark_ready_quiet.py`. Expected: pass.

- [ ] **Step 10: Commit** — `feat(runs): Mark Ready asks before promoting a run with color-balance errors (F13)`.

---

### Task 5: The cycle total says when it is not checked (F1/F2)

**Files:**
- Modify: `src/seqsetup/templates/wizard/_cycle_total.html`
- Modify: `src/seqsetup/static/css/components.css` (after `.cycle-total-over`, ~1151)
- Modify: `docs/user-guide/run-setup.rst` (~63-96)
- Test: `tests/integration/test_run_checks_1b.py` (new class)

- [ ] **Step 1: Failing test**

```python
class TestCycleTotalLine:
    """With no cycle limit for the kit, the total says it is not checked
    (F1/F2); with a limit, it is unchanged."""

    def test_kit_without_a_limit_says_not_checked(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _seed(ctx, "total-unchecked")
        run = ctx.run_repo.get_by_id(run_id)
        run.reagent_cycles = 300
        ctx.run_repo.save(run)

        page = logged_in_client.get(f"/runs/new/step/1?run_id={run_id}").text

        assert "Total: 322 cycles (300-cycle kit)" in page
        assert "Not checked: no cycle limit is set for this kit." in page
        assert "322 / 300" not in page
```

Check the wizard step URL with `grep -n "step/1" src/seqsetup/routes/wizard.py` and the page that renders `_cycle_total.html`; `tests/integration/test_kit_cycle_limit_page.py` already renders it with and without a limit — copy its request if it differs, and keep its with-limit tests as the control. Run: FAIL.

- [ ] **Step 2: Implement** (`_cycle_total.html`, the `{% else %}` branch; update the header comment: "None: the total is shown as not checked")

```html
    {% else %}
    <span>Total: {{ cycles.total_cycles }} cycles ({{ run.reagent_cycles }}-cycle kit)</span>
    <span class="cycle-total-unchecked">Not checked: no cycle limit is set for this kit. Kits hold a few extra cycles, so a total a little over the kit's label is normal.</span>
    {% endif %}
```

CSS: `.cycle-total-unchecked { display: block; margin-top: 0.25rem; }`

- [ ] **Step 3: Run** the new class and `tests/integration/test_kit_cycle_limit_page.py`, `tests/unit/test_kit_cycle_limit.py`: pass. If an existing test asserted the old "Total: N / K cycles" text, update it and name it in the commit.

- [ ] **Step 4: Docs** (`run-setup.rst`): replace the paragraph "The total shown here is often higher…" with

```rst
The line below the fields adds up Read 1, Index 1, Index 2 and Read 2.
When no cycle limit is recorded for the reagent kit -- which is how
SeqSetup ships -- it says so: **Not checked: no cycle limit is set for
this kit.** A 300-cycle kit's defaults already add up to 322 cycles (151
+ 151 + 10 + 10), because the kit label understates its real capacity, so
a total a little over the label is normal.
```

and shorten the "As shipped, no instrument's configuration records a cycle limit…" warning to: "Until an administrator adds a cycle limit for your instrument's kit through **Admin > Config Sync**, nothing checks the total -- not the line above, and not **Mark Ready** -- and the line says so." Delete the sentence "The line below the four fields totals them against the reagent kit." if it repeats.

- [ ] **Step 5: Commit** — `fix(wizard): the cycle total says when no kit limit checks it (F1/F2)`.

---

### Task 6: Pictures

- [ ] **Step 1:** Build the CSS (Global Constraints). Run only the picture tests this change affects, in file order:
  `SEQSETUP_DOCS_SCREENSHOTS=1 PYTHONPATH=src $PY -m pytest tests/browser/test_docs_screenshots.py -q -p no:cacheprovider -k "cycle or mark_ready or check_panel or color_balance"`.
  If a selected test depends on an earlier one (fails at setup), add that test to `-k` and run again.
- [ ] **Step 2:** `git status --short docs/_static/screenshots`. Look at every changed picture (Read the PNG). Expected: `new-run/cycle-config.png` (new line), `ready/mark-ready-refused.png` (under the status bar), `ready/mark-ready-color-balance.png` (new), `ready/mark-ready.png`, and `check/panel.png` if it shows the color-balance badge. Stage only pictures whose change comes from this branch. Report any other changed picture to the user instead of discarding it.
- [ ] **Step 3:** Docs build clean (`-W`). Commit — `docs: pictures for the color balance question, the Mark Ready slot and the cycle total`.

---

### Task 7: Verify independently

- [ ] **Step 1:** Full server suite: `PYTHONPATH=src $PY -m pytest tests --ignore=tests/browser -q -p no:cacheprovider` (≈12 min, background). Expected: 0 failed; count = 2048 + the new tests.
- [ ] **Step 2:** Browser suite with CSS built: `PYTHONPATH=src $PY -m pytest tests/browser -q -p no:cacheprovider`. Expected: 0 failed (was 92 passed, 52 skipped, plus the new ones).
- [ ] **Step 3:** Docs build clean.
- [ ] **Step 4:** Break tests — undo each guard in turn and confirm a test fails: (a) `override_cycles_problem` returns `None` always; (b) the single route skips the check for calculated values; (c) the bulk route saves before checking; (d) the question ignores `color_balance_confirmed_at`; (e) the question ignores `color_balance_lanes`; (f) `has_errors` counts warnings; (g) the refusal goes back to `#error-banner`; (h) the success response drops the empty `#ready-message`; (i) the cycle line loses "Not checked".
- [ ] **Step 5:** Independent review of `101a326..HEAD` against the spec (general-purpose reviewer, read-only). Fix Critical/Important with a failing test first.
- [ ] **Step 6:** Report to the user; merge only on "merge".
