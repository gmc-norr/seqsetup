"""Edit run page route.

The composed edit-run page is a Jinja2 template at templates/runs/edit.html.
RunConfigPanelHorizontal's three nested helpers (CycleConfigDisplay,
InstrumentConfigDisplay, RunNameDisplay) live in components/run_config.py
and are still FT-rendered — Phase 4 ports them. They're pre-rendered
to HTML strings here and embedded via |safe.

Must be registered LAST among /runs/... routes because {run_id} is a
path catch-all.
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..context import AppContext
from ..data.instruments import get_lanes_for_flowcell
from ..models.sequencing_run import RunStatus
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..templating import ft_to_html, render
from .dependencies import get_ctx


router = APIRouter(tags=["main"])


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

    # Pre-compute validation result for the validate panel.
    validation_result = ValidationService.validate_run(run)
    has_v1 = SampleSheetV1Exporter.supports(run.instrument_platform)

    # Pre-render the three run-config helpers (still FT — Phase 4 ports them).
    from ..components.run_config import (
        CycleConfigDisplay, InstrumentConfigDisplay, RunNameDisplay,
    )
    run_name_display_html = ft_to_html(RunNameDisplay(run))
    instrument_config_display_html = ft_to_html(InstrumentConfigDisplay(run))
    cycle_config_display_html = ft_to_html(CycleConfigDisplay(run))

    return render(request, "runs/edit.html", {
        "run": run,
        "index_kits": index_kits,
        "test_profiles": test_profiles,
        "num_lanes": num_lanes,
        "is_editable": is_editable,
        "validation_result": validation_result,
        "has_v1": has_v1,
        "run_name_display_html": run_name_display_html,
        "instrument_config_display_html": instrument_config_display_html,
        "cycle_config_display_html": cycle_config_display_html,
    })
