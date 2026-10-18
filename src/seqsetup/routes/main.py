"""Edit run page route.

The composed edit-run page is a Jinja2 template at templates/runs/edit.html.

Must be registered LAST among /runs/... routes because {run_id} is a
path catch-all.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..context import AppContext
from ..data.instruments import (
    get_flowcells_for_instrument,
    get_lanes_for_flowcell,
    i5_workflow_names,
)
from ..models.sequencing_run import RunCycles, RunStatus
from ..services import edit_locks
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.versioned_tests import offered_tests
from ..services.validation_summary import error_messages, errors_by_sample, waiting_for_samples
from ..templating import render
from .dependencies import get_ctx
from .utils import get_username, setup_panel_context


router = APIRouter(tags=["main"])


def _validate_for_panel(run, ctx: AppContext):
    # Pass the same repos as the Mark-Ready gate so the panel reflects the
    # full validation (incl. application-profile / test_id checks) and primes
    # the same cache entry the gate reads — never an under-counted
    # repos-less result.
    return ValidationService.validate_run(
        run,
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
    )


def _edit_lock(run, ctx: AppContext, request: Request):
    """The run's edit lock as its viewer sees it (services/edit_locks.py);
    None off a Draft, which nobody edits."""
    if run.status != RunStatus.DRAFT:
        return None
    return edit_locks.state(ctx.edit_lock_repo, run.id, get_username(request))


def _samples_without_test(run, editing: bool) -> list[str]:
    """Internal ids of a draft's samples with no test, for Check's
    "Set test" picker. Empty unless the viewer is editing the run."""
    if not editing:
        return []
    return [s.id for s in run.samples if not s.test_id]


def _samples_without_version(run, editing: bool) -> list[tuple[str, list[str]]]:
    """(test, internal ids) of a draft's samples that have a test but no
    version, one entry per test in the order first seen, for Check's version
    boxes (spec 2026-10-07 group A4, §2). Empty unless the viewer is editing
    the run."""
    if not editing:
        return []
    by_test: dict[str, list[str]] = {}
    for s in run.samples:
        if s.test_id and not s.test_version:
            by_test.setdefault(s.test_id, []).append(s.id)
    return list(by_test.items())


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _run_steps(run, result) -> list[dict]:
    """The step bar's steps, in work order, for runs/_step_bar.html.

    Each step's ``state`` is "done", "todo", or "error" (Check with
    errors); on a draft, the first step that is not done is ``current``.
    Display only: Mark Ready runs its own validation and refuses on any
    error.
    """
    locked = run.status in (RunStatus.READY, RunStatus.ARCHIVED)
    named = bool((run.run_name or "").strip())
    n = len(run.samples)
    indexed = sum(1 for s in run.samples if s.has_index)
    errors = result.error_count

    if waiting_for_samples(run, result):
        check_state, check_detail = "todo", "After samples"
    elif errors:
        check_state, check_detail = "error", _plural(errors, "error")
    else:
        check_state, check_detail = "done", "No errors"

    # The Setup step was keyed on the run name alone, so it said "done" for a
    # run with no cycle counts, or with Read 1 = 0, which the Check refuses
    # (review of 9fac120, P2-2).
    has_cycles = bool(run.run_cycles) and run.run_cycles.read1_cycles >= 1
    setup_done = named and has_cycles
    steps = [
        {"key": "setup", "label": "Setup", "href": "#run-config-panel",
         "state": "done" if setup_done else "todo",
         "detail": (f"{run.instrument_platform.value} · {run.flowcell_type}" if setup_done
                    else "Needs a name" if not named else "Needs cycle counts")},
        {"key": "samples", "label": "Samples", "href": "#samples",
         "state": "done" if n else "todo",
         "detail": _plural(n, "sample") if n else "None yet"},
        {"key": "indexes", "label": "Indexes", "href": "#samples",
         "state": "done" if n and indexed == n else "todo",
         "detail": f"{indexed} of {n} assigned" if n else "After samples"},
        {"key": "check", "label": "Check", "href": "#validate-panel",
         "state": check_state, "detail": check_detail},
        {"key": "ready", "label": "Ready", "href": "#run-status-bar",
         "state": "done" if locked else "todo",
         "detail": run.status.value.capitalize() if locked else "Locks the run"},
        # A draft's Export box is a hidden placeholder; Mark Ready comes first.
        {"key": "export", "label": "Export", "href": "#export-panel" if locked else "#run-status-bar",
         "state": "done" if locked else "todo",
         "detail": {"ready": "Available", "archived": "Archived"}.get(run.status.value, "After Ready")},
    ]
    # A locked run has no next step; a live error on it still shows red.
    current = None if locked else next((s for s in steps if s["state"] != "done"), None)
    for number, step in enumerate(steps, 1):
        step["number"] = number
        step["current"] = step is current
    return steps


@router.get("/runs/{run_id}/step-bar", response_class=HTMLResponse)
def step_bar(
    request: Request,
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/step-bar — the step bar, recomputed.

    Read-only. The bar on the edit page fetches this after each successful
    change, like the Validate box.
    """
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return render(request, "runs/_step_bar.html", {
        "run": run,
        "steps": _run_steps(run, _validate_for_panel(run, ctx)),
    })


@router.get("/runs/{run_id}/validate-panel", response_class=HTMLResponse)
def validate_panel(
    request: Request,
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/validate-panel — the Validate box, recomputed.

    Read-only. The box on the edit page fetches this after each successful
    change so its counts never go stale.
    """
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    validation_result = _validate_for_panel(run, ctx)
    lock = _edit_lock(run, ctx, request)
    editing = bool(lock and lock.mine)
    return render(request, "runs/_validate_panel.html", {
        "run": run,
        "validation_result": validation_result,
        "sample_errors": errors_by_sample(run, validation_result),
        "error_lines": error_messages(validation_result),
        "waiting": waiting_for_samples(run, validation_result),
        "fix_test_ids": _samples_without_test(run, editing),
        "fix_versions": _samples_without_version(run, editing),
        "test_profiles": offered_tests(ctx.test_profile_repo.list_all()) if ctx.test_profile_repo else [],
    })


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def edit_run(
    request: Request,
    run_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id} — full edit-run page."""
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return RedirectResponse("/", status_code=303)

    test_profiles = offered_tests(ctx.test_profile_repo.list_all()) if ctx.test_profile_repo else []
    index_kits = ctx.index_kit_repo.list_all() if ctx.index_kit_repo else []
    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    # Only the person holding the Draft's edit lock gets the edit controls.
    lock = _edit_lock(run, ctx, request)
    is_editable = bool(lock and lock.mine)
    sample_api_cfg = ctx.sample_api_config
    sample_api_enabled = bool(sample_api_cfg and sample_api_cfg.enabled and sample_api_cfg.base_url)

    # Pre-compute validation result for the validate panel.
    validation_result = _validate_for_panel(run, ctx)
    has_v1 = SampleSheetV1Exporter.supports(run.instrument_platform)

    return render(request, "runs/edit.html", {
        "run": run,
        "index_kits": index_kits,
        "test_profiles": test_profiles,
        "num_lanes": num_lanes,
        "is_editable": is_editable,
        "edit_lock": lock,
        "sample_api_enabled": sample_api_enabled,
        "validation_result": validation_result,
        "sample_errors": errors_by_sample(run, validation_result),
        "error_lines": error_messages(validation_result),
        "waiting": waiting_for_samples(run, validation_result),
        "fix_test_ids": _samples_without_test(run, is_editable),
        "fix_versions": _samples_without_version(run, is_editable),
        "steps": _run_steps(run, validation_result),
        "has_v1": has_v1,
        # The setup panel's own context, from the one builder the status
        # answer uses too (routes/runs.py: update_status), so the panel the
        # page draws and the panel that answer sends cannot drift. "cycles"
        # has no default: a run with no counts showed 150/10/10/150, and
        # pressing Continue would have saved those unseen (review F2).
        **setup_panel_context(run, is_editable=is_editable),
    })
