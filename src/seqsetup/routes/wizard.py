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



@router.post("/runs/new")
def wizard_new(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/new — create the run row and redirect to step 1."""
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
    })


@router.get("/tests")
def tests_page(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /tests — tests management page."""
    tests = ctx.test_repo.list_all()
    return render(request, "tests.html", {"tests": tests})
