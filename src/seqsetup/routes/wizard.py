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
    get_reagent_kit_max_cycles,
    get_reagent_kits_for_flowcell,
    i5_workflow_names,
    is_instrument_enabled_by_name,
    standard_i5_workflow,
)
from ..models.sequencing_run import RunCycles, RunStatus
from ..startup import get_instrument_config_repo
from ..templating import render
from ..services.run_history import record_run_created_safe
from .dependencies import get_ctx


router = APIRouter(tags=["wizard"])



@router.post("/runs/new")
def wizard_new(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/new — create the run row and redirect to step 1."""
    user = request.scope.get("auth")
    actor = user.username if user else ""
    run = ctx.run_repo.create_run(
        actor, i5_workflow=standard_i5_workflow(ctx.run_repo.NEW_RUN_INSTRUMENT.value)
    )
    record_run_created_safe(ctx, run, actor, source="blank")
    # new=1: this page just made the run, so its Cancel deletes it.
    return RedirectResponse(f"/runs/new/step/1?new=1&run_id={run.id}", status_code=303)


@router.get("/runs/new/step/1")
def wizard_step1(
    request: Request,
    run_id: str = "",
    new: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/new/step/1 — run setup (name, instrument, cycles).

    Opened for a new run (``new=1``) and from a draft's "Edit setup" link.
    A Ready or Archived run cannot be changed, so it goes to its run page.
    """
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        return RedirectResponse("/", status_code=303)
    if run.status != RunStatus.DRAFT:
        return RedirectResponse(f"/runs/{run.id}", status_code=303)

    instrument_config = get_instrument_config_repo().get()
    instruments = get_enabled_instruments(instrument_config)
    if all(inst["platform"] != run.instrument_platform for inst in instruments):
        # Always show the run's own instrument, marked, so the select never
        # shows a different instrument than the run uses (F27).
        own = run.instrument_platform.value
        instruments = instruments + [{
            "name": own,
            "platform": run.instrument_platform,
            "unavailable": "disabled" if not is_instrument_enabled_by_name(own) else "not available",
        }]
    current_flowcells = get_flowcells_for_instrument(run.instrument_platform)
    current_reagent_kits = get_reagent_kits_for_flowcell(
        run.instrument_platform, run.flowcell_type
    )
    cycles = run.run_cycles or RunCycles(150, 150, 10, 10)
    index_cycle_options = get_index_cycle_options()
    # A new run may start from a template instead (see run_templates.py).
    templates = (
        sorted(ctx.run_template_repo.list_all(), key=lambda t: t.name.lower())
        if new == "1" else []
    )

    return render(request, "wizard/new_run_step1.html", {
        "run": run,
        "instruments": instruments,
        "current_flowcells": current_flowcells,
        "current_reagent_kits": current_reagent_kits,
        "cycles": cycles,
        "index_cycle_options": index_cycle_options,
        "kit_max_cycles": get_reagent_kit_max_cycles(run.instrument_platform, run.reagent_cycles),
        "i5_workflows": i5_workflow_names(run.instrument_platform.value),
        "is_new": new == "1",
        "templates": templates,
    })


@router.get("/tests")
def tests_page(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /tests — tests management page."""
    tests = ctx.test_repo.list_all()
    return render(request, "tests.html", {"tests": tests})
