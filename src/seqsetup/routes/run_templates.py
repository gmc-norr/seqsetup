"""Clone-run and run-template routes.

Clone and create-from-template both delegate to services.run_builder.
build_draft_run; templates are managed via a thin CRUD over
ctx.run_template_repo and live entirely outside the run state machine.
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..context import AppContext
from ..models.run_template import RunTemplate
from ..services.audit_log import audit
from ..services.run_builder import build_draft_run, RunInstantiationError
from ..templating import render
from .dependencies import get_archivable_run, get_ctx
from .utils import get_username, sanitize_string


router = APIRouter(tags=["run-templates"])


def _bool_field(form, key: str) -> bool:
    raw = form.get(key)
    if raw is None:
        return False
    return str(raw).lower() in ("1", "true", "on", "yes")


@router.post("/runs/{run_id}/duplicate")
async def duplicate_run(
    request: Request,
    run=Depends(get_archivable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/duplicate — clone a run into a fresh DRAFT.

    include_samples=true performs a full duplicate (re-run); false copies
    config only (new batch). The source is read, never mutated.
    """
    form = await request.form()
    include_samples = _bool_field(form, "include_samples")
    requested_name = sanitize_string(form.get("run_name", ""), 256)
    new_name = requested_name or f"{run.run_name} (copy)"

    samples = run.samples if include_samples else []
    try:
        new_run = build_draft_run(
            config_source=run,
            samples=samples,
            created_by=get_username(request),
            run_name=new_name,
            instrument_config=ctx.instrument_config,
            check_references=False,
        )
    except RunInstantiationError as exc:
        return Response(str(exc), status_code=400)

    ctx.run_repo.save(new_run)
    audit(
        "run.cloned",
        actor=get_username(request),
        target=new_run.id,
        source=run.id,
        included_samples=include_samples,
    )
    return RedirectResponse(f"/runs/{new_run.id}", status_code=303)
