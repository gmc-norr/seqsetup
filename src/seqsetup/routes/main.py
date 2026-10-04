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
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_summary import error_messages, errors_by_sample, waiting_for_samples
from ..templating import render
from .dependencies import get_ctx


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


def _samples_without_test(run) -> list[str]:
    """Internal ids of a draft's samples with no test, for Check's
    "Set test" picker. Empty on a locked run (nothing can be changed)."""
    if run.status != RunStatus.DRAFT:
        return []
    return [s.id for s in run.samples if not s.test_id]


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

    steps = [
        {"key": "setup", "label": "Setup", "href": "#run-config-panel",
         "state": "done" if named else "todo",
         "detail": f"{run.instrument_platform.value} · {run.flowcell_type}" if named else "Needs a name"},
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
        {"key": "export", "label": "Export", "href": "#export-panel",
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
    return render(request, "runs/_validate_panel.html", {
        "run": run,
        "validation_result": validation_result,
        "sample_errors": errors_by_sample(run, validation_result),
        "error_lines": error_messages(validation_result),
        "waiting": waiting_for_samples(run, validation_result),
        "fix_test_ids": _samples_without_test(run),
        "test_profiles": ctx.test_profile_repo.list_all() if ctx.test_profile_repo else [],
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

    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
    index_kits = ctx.index_kit_repo.list_all() if ctx.index_kit_repo else []
    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    is_editable = run.status == RunStatus.DRAFT
    sample_api_cfg = ctx.sample_api_config
    sample_api_enabled = bool(sample_api_cfg and sample_api_cfg.enabled and sample_api_cfg.base_url)

    # Pre-compute validation result for the validate panel.
    validation_result = _validate_for_panel(run, ctx)
    has_v1 = SampleSheetV1Exporter.supports(run.instrument_platform)

    # Resolve flowcell description for the Jinja2 template.
    flowcells = get_flowcells_for_instrument(run.instrument_platform)
    flowcell_info = flowcells.get(run.flowcell_type, {})
    flowcell_desc = flowcell_info.get("description", run.flowcell_type)

    cycles = run.run_cycles or RunCycles(150, 150, 10, 10)

    return render(request, "runs/edit.html", {
        "run": run,
        "index_kits": index_kits,
        "test_profiles": test_profiles,
        "num_lanes": num_lanes,
        "is_editable": is_editable,
        "sample_api_enabled": sample_api_enabled,
        "validation_result": validation_result,
        "sample_errors": errors_by_sample(run, validation_result),
        "error_lines": error_messages(validation_result),
        "waiting": waiting_for_samples(run, validation_result),
        "fix_test_ids": _samples_without_test(run),
        "steps": _run_steps(run, validation_result),
        "has_v1": has_v1,
        "flowcell_desc": flowcell_desc,
        "cycles": cycles,
        "i5_workflows": i5_workflow_names(run.instrument_platform.value),
    })
