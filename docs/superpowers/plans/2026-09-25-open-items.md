# Open items — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Working downloads for archived runs, a kit picker that keeps the user's kit, an honest fill message for i5-only samples, edge-case tests for the fill, and two tidy-ups.

**Architecture:** Template-only change for the Export panel; one request header (set in `app.js`, read by a helper in `routes/utils.py`) that lets server renders of the sample section keep the chosen kit; a small addition to the pure fill planner; tests; two one-line tidy-ups.

**Tech Stack:** FastAPI, Jinja2 + jinja2-fragments, HTMX 2, plain CSS, MongoDB (mongomock in tests), pytest + Playwright.

**Spec:** `docs/superpowers/specs/2026-09-25-open-items-design.md` (copied in Task 0). Read it before Task 1.

## Global Constraints

- Read `CLAUDE.md` and `ARCHITECTURE.md` first; they bind every task. Clinical software: "when in doubt, do less"; no silent behavior changes; no refactors, comments or docstrings on code you did not change.
- Test first: write the failing test, run it, see it fail for the right reason, then implement.
- Do NOT change `src/seqsetup/models/`, the exporters (`services/samplesheet_v2_exporter.py`, `services/samplesheet_v1_exporter.py`, `services/json_exporter.py`, `services/validation_report.py`), the validators (`services/validation.py`, `services/index_collision_validator.py`, `services/color_analysis_validator.py`), `routes/export.py`, `routes/dependencies.py`, or dependencies (`pixi.toml`, `pixi.lock`).
- HTMX 2 inherits `hx-target`/`hx-select`/`hx-swap`; every new hx element sets its own. The CSP forbids inline handlers; client code goes in `static/js/app.js` by delegation.
- UI copy: short plain sentences, like the existing app text.
- One commit per task on the worktree branch, conventional style, a body explaining why, last line exactly:
  `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`
- Commands, from the worktree root (no env in the worktree; never `pixi install` / `pixi run`):
  - `PY=/home/parlar_ai/dev/seqsetup/.pixi/envs/default/bin/python`
  - one file: `PYTHONPATH=src $PY -m pytest <file> -q`
  - server suite: `PYTHONPATH=src $PY -m pytest tests/unit tests/integration -q` (baseline **1489 passed**)
  - CSS (app.css is untracked; build before browser tests and after CSS edits; never commit it): `/home/parlar_ai/dev/seqsetup/.pixi/bin/tailwindcss -i src/seqsetup/static/css/input.css -o src/seqsetup/static/css/app.css --minify`
  - browser suite: `PYTHONPATH=src $PY -m pytest tests/browser -q` (baseline **80 passed, 0 warnings**)
- Fixtures: integration `fresh_app` → `(app, ctx, db)`, `logged_in_client`, POSTs need `headers={"Origin": "http://testserver"}`; `_make_ready_eligible_run(ctx)` in `tests/integration/test_smoke_validation.py` builds a run that can be marked Ready. Browser: `logged_in_page`, `base_url`, `app_ctx`, `mutable_run_id`; `SCREENSHOT_KIT_NAME`, `ARCHIVED_RUN_ID` in `tests/browser/conftest.py`; `tests/browser/test_bulk_lane_panel_swap.py` shows how to tick samples and apply a bulk lane change; `tests/browser/test_index_fill.py` has a `second_kit_id` fixture creating and deleting a second kit.
- Status transitions in tests go through the real routes: `POST /runs/{id}/status/ready`, then `POST /runs/{id}/status/archived` (this pre-generates and keeps the exports).

---

### Task 0: Put the spec and plan in the branch

- [ ] Copy `/home/parlar_ai/seqsetup-open-run/spec.md` to `docs/superpowers/specs/2026-09-25-open-items-design.md` and `/home/parlar_ai/seqsetup-open-run/plan.md` to `docs/superpowers/plans/2026-09-25-open-items.md`. Commit `docs: plan for the open items`.

---

### Task 1: Archived runs can download from the Export panel

**Files:**
- Modify: `src/seqsetup/templates/runs/_export_panel.html`
- Test: `tests/integration/test_archived_export_panel.py`, `tests/browser/test_archived_export.py`

- [ ] **Step 1: failing integration tests.**
  1. Make an eligible run (`_make_ready_eligible_run`), mark it Ready then Archived through the routes. `GET /runs/{id}` → the export panel contains `href="/runs/{id}/export/samplesheet-v2"`, `…/export/json`, `…/export/validation-report`, `…/export/validation-pdf` (and `…/samplesheet-v1` when `SampleSheetV1Exporter.supports(run.instrument_platform)`), no `aria-disabled="true"` inside `#export-panel`, and no "Run must be marked as ready".
  2. For the same archived run, `GET` each of those links → 200, and the body equals the stored pre-generated value (`run.generated_samplesheet_v2`, `generated_samplesheet_v1` if supported, `generated_json`, `generated_validation_json`, `generated_validation_pdf`) read back from `ctx.run_repo` — this proves the archived download serves the bytes frozen at Ready, not a live re-export. (This part may already pass; that is expected — it pins the behavior the panel now exposes.)
  3. A READY run's panel is unchanged (links present, same as before); a DRAFT run still shows "Downloads open when the run is Ready." and no links.
- [ ] **Step 2: run, see 1 fail.**
- [ ] **Step 3: implement** in `_export_panel.html`: `{% set is_exportable = run.status.value in ('ready', 'archived') %}` and use it wherever `is_ready` enabled a button; delete the `{% if not is_ready %}…Run must be marked as ready…{% endif %}` paragraph (inside the non-draft branch it could only ever show for archived runs, which is exactly the wrong message). Update the header comment if it mentions Ready-only.
- [ ] **Step 4: browser test** on `ARCHIVED_RUN_ID`: open `/runs/{ARCHIVED_RUN_ID}`, `with page.expect_download() as d: page.click("text=Download Sample Sheet v2")`, assert the suggested filename ends with `.csv`. (If the seeded archived run has no indexed samples, so the Sample Sheet button is legitimately disabled, use "Download JSON" and `.json` instead, and record why.)
- [ ] **Step 5: tests pass; run `tests/integration/test_smoke_*.py` and `tests/browser/test_screenshots.py`. Commit** `fix(ui): archived runs can download their exports from the Export panel`.

---

### Task 2: The kit picker keeps the chosen kit across sample-section re-renders

**Files:**
- Modify: `src/seqsetup/static/js/app.js`, `src/seqsetup/routes/utils.py`, `src/seqsetup/routes/samples.py` (`_render_sample_section`), `src/seqsetup/routes/runs.py` (the status-change render of `runs/_sample_section.html`), `src/seqsetup/templates/runs/_sample_section.html`
- Test: `tests/unit/test_selected_kit_header.py` (or add to an existing utils test file), `tests/integration/test_kit_choice_kept.py`, `tests/browser/test_kit_choice_kept.py`

- [ ] **Step 1: failing tests.**
  - Unit: `selected_kit_id(request)` returns `""` without the header; decodes `quote("Kit — ü:1.0")` back to `"Kit — ü:1.0"`; caps at 512 characters. (Build a request with `starlette.requests.Request({"type": "http", "headers": [(b"x-selected-kit", value.encode("latin-1"))]})`.)
  - Integration (two kits A then B in `ctx.index_kit_repo`, a draft with two unindexed samples): `POST /runs/{id}/samples/set-lanes` with valid `sample_ids`/`lanes` and header `X-Selected-Kit: quote(B.kit_id)` → the returned section's `#index-kit-dropdown` has B's option `selected`, and the panel lists B's pair names, not A's. Same request without the header → A selected (today's behavior). With `X-Selected-Kit: quote("no-such-kit:1")` → A selected. A kit whose name has non-ASCII characters is selected when its id is sent encoded.
  - Browser: with a second kit (copy `second_kit_id` from `tests/browser/test_index_fill.py`), open a draft with unindexed samples, select the second kit in `#index-kit-dropdown` (wait for `/indexes/kit-content`), then do a bulk lane change as `tests/browser/test_bulk_lane_panel_swap.py` does; after the swap `#index-kit-dropdown` still has the second kit's value and the panel shows its index name (`SK0001`).
- [ ] **Step 2: run, see them fail.**
- [ ] **Step 3: implement.**

`routes/utils.py`:

```python
def selected_kit_id(request) -> str:
    """The kit the page's index-kit dropdown shows, sent by app.js on every
    HTMX request as the X-Selected-Kit header (URI-encoded), so a re-rendered
    sample section keeps it. Only ever compared with existing kit ids."""
    return unquote(request.headers.get("X-Selected-Kit", ""))[:512]
```
(`from urllib.parse import unquote`.)

`static/js/app.js` (next to the other `document.body.addEventListener` blocks):

```js
// Every HTMX request says which kit the kit dropdown shows, so a re-rendered
// sample section keeps it instead of falling back to the first kit. A header,
// not a form field: the fill's Assign form sends its own selected_kit, which
// must not be overwritten. URI-encoded because header values must be Latin-1.
document.body.addEventListener('htmx:configRequest', function(event) {
    const d = document.getElementById('index-kit-dropdown');
    if (d && d.value) event.detail.headers['X-Selected-Kit'] = encodeURIComponent(d.value);
});
```

`runs/_sample_section.html` — new input `chosen_kit_id` (document it in the header comment; may be undefined on a full page load):

```jinja
{% set chosen_kits = index_kits | selectattr('kit_id', 'equalto', chosen_kit_id) | list if chosen_kit_id else [] %}
{% set default_kit = chosen_kits[0] if chosen_kits else (index_kits[0] if index_kits else None) %}
```
(replacing the current `{% set default_kit = index_kits[0] if index_kits else None %}`; the dropdown and compact panel already use `default_kit`).

Pass `chosen_kit_id=selected_kit_id(request)` in `_render_sample_section` (`routes/samples.py`) and in the status-change render in `routes/runs.py`.
- [ ] **Step 4: tests pass; run `tests/browser/test_index_fill.py`, `tests/browser/test_multi_index_drop.py`, `tests/browser/test_bulk_lane_panel_swap.py`, `tests/integration/test_index_fill_routes.py` — the fill's Assign must still apply the previewed kit. Commit** `fix(ui): the index kit picker keeps the chosen kit after edits`.

---

### Task 3: Fill in order explains samples that have only an i5 index

**Files:**
- Modify: `src/seqsetup/services/index_fill.py`, `src/seqsetup/templates/runs/_index_fill_preview.html`
- Test: `tests/unit/test_index_fill.py`, `tests/integration/test_index_fill_routes.py`

**Interfaces:** `FillPlan.partial: list[str]` (sample labels, run order), default empty. Everything else in `FillPlan` unchanged; `signature()` unchanged.

- [ ] **Step 1: failing tests** (unit; use the file's `_run`, `_dual_kit`, and give a sample an i5 only with `sample.assign_index2(Index(name="x", sequence="GTGTGTGT", index_type=IndexType.I5))`):
  1. Run S1 (i5 only), S2 (full pair): `plan.partial == ["S1"]`, `not plan.can_apply`, `plan.problem == "Fill in order only fills samples with no index at all. 1 sample(s) have only an i5 index; give them an i7 by hand: S1."`
  2. Run S1 (no index), S2 (i5 only), S3 (no index): rows are S1 and S3 only; `plan.partial == ["S2"]`; `plan.problem == ""`.
  3. Twelve i5-only samples P01..P12 and nothing else: the problem lists P01..P10 then `", and 2 more."` — exact text: `"Fill in order only fills samples with no index at all. 12 sample(s) have only an i5 index; give them an i7 by hand: P01, P02, P03, P04, P05, P06, P07, P08, P09, P10, and 2 more."`
  4. A run where every sample has a full index still gives `"Every sample already has an index."` and `partial == []`.
  Integration: for case 2, the preview HTML contains `Left alone, they have only an i5 index: S2.` and still offers "Assign 2 indexes"; after Assign, S2's stored indexes are unchanged.
- [ ] **Step 2: run, see them fail.**
- [ ] **Step 3: implement** in `build_fill_plan`: compute `partial = [s.sample_id for s in run.samples if not needs_index(s) and s.index_pair is None and s.index1 is None]` and set it on the plan before any early return that follows the mode/entries checks; where the code now sets `"Every sample already has an index."`, use the partial message instead when `partial` is non-empty (names: first 10 joined by ", ", then `f", and {n - 10} more"` when longer, then "."). In the preview template, under the skipped note and only when there is no problem: `<p class="index-fill-note">Left alone, they have only an i5 index: {{ plan.partial | join(', ') }}.</p>` when `plan.partial`.
- [ ] **Step 4: tests pass; run the fill browser tests. Commit** `fix(indexes): fill in order says why it leaves i5-only samples alone`.

---

### Task 4: Edge-case tests for the fill planner

**Files:**
- Test: `tests/unit/test_index_fill.py`

Characterisation tests; they describe today's behavior. Write each, run it, and if it fails, decide: a real defect → fix inside `services/index_fill.py` only when the fix is obvious and safe (record in PLAN-DEFECTS.md), otherwise ESCALATE and mark the test with the expectation you believe is right plus `pytest.mark.xfail(strict=True, reason=...)` — this is the ONLY xfail allowed in this run.

- [ ] Two pairs sharing the id `p0` with different sequences: `start_id="p0"` starts at the first; the plan's rows carry both distinct sequences; the two rows' signatures differ from a kit where the second pair has another sequence (the signature holds sequences, so a shared id cannot hide a sequence change).
- [ ] A unique-dual pair with `index2=None`: it is filled; the row's `entry.i5 is None`; another pair whose i5 equals nothing in the run is not affected by the None.
- [ ] More samples than the whole kit, from its first index: problem `"Not enough unused indexes: {n} needed, {k} left in Kit from UDP0000. Pick an earlier start or another kit."` with the real counts, no rows.
- [ ] A sample whose `sample_id` is `""` (if the model allows it; if the model rejects it, write a test that says so instead): it is a target in run order and its row label is `""`.
- [ ] Commit `test(indexes): pin fill-in-order edge cases`.

---

### Task 5: Tidy-ups

**Files:**
- Modify: `src/seqsetup/static/css/components.css`, `src/seqsetup/routes/samples.py` (`set_lanes_bulk`)
- Test: add one case to `tests/integration/test_bulk_sample_ids_input.py` or the nearest lanes test

- [ ] `grep -rn "bulk-paste-section" src tests` (ignore the untracked `app.css`): if only `components.css` matches, delete that rule block (and nothing else). Rebuild CSS.
- [ ] Test first: `POST /runs/{id}/samples/set-lanes` with valid `sample_ids` and `lanes="not json"` → 400 with text `"Invalid lanes JSON"`; stored run unchanged. Then change the message in `set_lanes_bulk` from `"Invalid sample_ids or lanes JSON"` to `"Invalid lanes JSON"`.
- [ ] Commit `chore: drop an orphaned style; name the bad field in the lanes error`.

---

### Final

- [ ] Full server suite and full browser suite on the final tree; exact counts into STATUS.md (server 1489 + new; browser 80 + new; zero failed, zero errors, and zero `PytestUnknownMarkWarning`).
- [ ] Run `PYTHONPATH=src $PY tools/screenshot_diff.py` (read its `--help` first) and list which baseline screenshots differ and why; do NOT update baselines.
- [ ] Identity checks (run prompt) with real output into STATUS.md.
- [ ] Final whole-branch review, then the closing summary.
