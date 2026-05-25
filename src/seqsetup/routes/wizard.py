"""Wizard routes for creating new runs and adding samples.

APIRouter-style; all handlers render Jinja2 templates under
``templates/wizard/`` and ``templates/tests.html``.
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import RedirectResponse, Response

from ..context import AppContext
from ..data.instruments import (
    get_enabled_instruments,
    get_flowcells_for_instrument,
    get_index_cycle_options,
    get_reagent_kits_for_flowcell,
)
from ..models.sequencing_run import RunCycles
from ..startup import get_instrument_config_repo
from ..templating import render
from .dependencies import get_ctx


router = APIRouter(tags=["wizard"])


def _sample_api_enabled(ctx: AppContext) -> bool:
    cfg = ctx.sample_api_config
    return bool(cfg and cfg.enabled and cfg.base_url)


@router.get("/runs/new")
def wizard_new(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/new — create the run row and redirect to step 1."""
    user = request.scope.get("auth")
    run = ctx.run_repo.create_run(user.username if user else "")
    return RedirectResponse(f"/runs/new/step/1?run_id={run.id}", status_code=303)


@router.get("/runs/new/step/1")
def wizard_step1(
    request: Request,
    run_id: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/new/step/1 — wizard step 1: run configuration."""
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return RedirectResponse("/", status_code=303)

    instrument_config = get_instrument_config_repo().get()
    instruments = get_enabled_instruments(instrument_config)
    current_flowcells = get_flowcells_for_instrument(run.instrument_platform)
    current_reagent_kits = get_reagent_kits_for_flowcell(
        run.instrument_platform, run.flowcell_type
    )
    cycles = run.run_cycles or RunCycles(150, 150, 10, 10)
    index_cycle_options = get_index_cycle_options()

    return render(request, "wizard/new_run_step1.html", {
        "run": run,
        "instruments": instruments,
        "current_flowcells": current_flowcells,
        "current_reagent_kits": current_reagent_kits,
        "cycles": cycles,
        "index_cycle_options": index_cycle_options,
        "steps": [
            {"number": "1", "label": "Run Configuration",
             "href": f"/runs/new/step/1?run_id={run.id}",
             "is_active": True, "is_completed": False},
        ],
    })


@router.get("/runs/{run_id}/samples/add/step/1")
def add_samples_step1(
    request: Request,
    run_id: str,
    existing: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/samples/add/step/1 — enter sample/test info."""
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return RedirectResponse("/", status_code=303)

    existing_sample_ids = (
        [sid.strip() for sid in existing.split(",") if sid.strip()]
        if existing else [s.id for s in run.samples]
    )
    existing_ids_param = ",".join(existing_sample_ids) if existing_sample_ids else ""

    steps_for_progress = [
        {"number": "1", "label": "Add Samples",
         "href": f"/runs/{run.id}/samples/add/step/1", "is_active": True, "is_completed": False},
        {"number": "2", "label": "Assign Indexes",
         "href": f"/runs/{run.id}/samples/add/step/2", "is_active": False, "is_completed": False},
    ]
    return render(request, "wizard/add_samples_step1.html", {
        "run": run,
        "existing_ids_param": existing_ids_param,
        "sample_api_enabled": _sample_api_enabled(ctx),
        "steps": steps_for_progress,
    })


@router.get("/runs/{run_id}/samples/add/step/2")
def add_samples_step2(
    request: Request,
    run_id: str,
    existing: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/samples/add/step/2 — assign indexes to samples."""
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return RedirectResponse("/", status_code=303)

    existing_sample_ids = (
        [sid.strip() for sid in existing.split(",") if sid.strip()]
        if existing else []
    )
    existing_ids_param = ",".join(existing_sample_ids)
    existing_ids_set = set(existing_sample_ids)
    new_samples = [s for s in run.samples if s.id not in existing_ids_set]
    samples_without_indexes = [s for s in new_samples if not s.has_index]
    all_have_indexes = len(samples_without_indexes) == 0

    index_kits = ctx.index_kit_repo.list_all()
    default_kit = index_kits[0] if index_kits else None

    steps_for_progress = [
        {"number": "1", "label": "Add Samples",
         "href": f"/runs/{run.id}/samples/add/step/1", "is_active": False, "is_completed": True},
        {"number": "2", "label": "Assign Indexes",
         "href": f"/runs/{run.id}/samples/add/step/2", "is_active": True, "is_completed": False},
    ]
    return render(request, "wizard/add_samples_step2.html", {
        "run": run,
        "existing_ids_param": existing_ids_param,
        "new_samples": new_samples,
        "all_have_indexes": all_have_indexes,
        "index_kits": index_kits,
        "default_kit": default_kit,
        "steps": steps_for_progress,
    })


@router.get("/tests")
def tests_page(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /tests — tests management page."""
    tests = ctx.test_repo.list_all()
    return render(request, "tests.html", {"tests": tests})
