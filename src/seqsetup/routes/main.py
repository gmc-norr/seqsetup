"""Edit run page route.

The composed edit-run page is a Jinja2 template at templates/runs/edit.html.

Must be registered LAST among /runs/... routes because {run_id} is a
path catch-all.
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..context import AppContext
from ..data.instruments import get_flowcells_for_instrument, get_lanes_for_flowcell
from ..models.sequencing_run import RunCycles, RunStatus
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..templating import render
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
    sample_api_cfg = ctx.sample_api_config
    sample_api_enabled = bool(sample_api_cfg and sample_api_cfg.enabled and sample_api_cfg.base_url)

    # Pre-compute validation result for the validate panel. Pass the same repos
    # as the Mark-Ready gate so the panel reflects the full validation (incl.
    # application-profile / test_id checks) and primes the same cache entry the
    # gate reads — never an under-counted repos-less result.
    validation_result = ValidationService.validate_run(
        run,
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
    )
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
        "has_v1": has_v1,
        "flowcell_desc": flowcell_desc,
        "cycles": cycles,
    })
