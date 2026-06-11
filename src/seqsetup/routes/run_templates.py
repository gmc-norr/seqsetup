"""Clone-run and run-template routes.

Clone and create-from-template both delegate to services.run_builder.
build_draft_run; templates are managed via a thin CRUD over
ctx.run_template_repo and live entirely outside the run state machine.
"""

import json

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..context import AppContext
from ..models.run_template import RunTemplate
from ..models.sample import Sample
from ..models.sequencing_run import RunCycles
from ..services.audit_log import audit
from ..services.run_history import record_run_created_safe
from ..services.run_builder import build_draft_run, RunInstantiationError, _filter_analyses
from ..templating import render
from .dependencies import get_archivable_run, get_ctx
from .utils import get_username, sanitize_string


router = APIRouter(tags=["run-templates"])


def _bool_field(form, key: str) -> bool:
    raw = form.get(key)
    if raw is None:
        return False
    return str(raw).lower() in ("1", "true", "on", "yes")


@router.post("/runs/{run_id}/duplicate", response_class=Response)
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
    record_run_created_safe(ctx, new_run, get_username(request),
                            source="clone", ref=run.id)
    audit(
        "run.cloned",
        actor=get_username(request),
        target=new_run.id,
        source=run.id,
        included_samples=include_samples,
    )
    return RedirectResponse(f"/runs/{new_run.id}", status_code=303)


def _config_from_run(run, name: str, description: str, scaffold_samples) -> RunTemplate:
    """Build a RunTemplate capturing a run's config + chosen scaffold samples.

    Analyses are filtered to the scaffold samples (and emptied analyses dropped)
    so the stored template never references a sample that isn't in its scaffold —
    the same rule build_draft_run applies at instantiation.
    """
    scaffold_ids = {s.sample_id for s in scaffold_samples}
    return RunTemplate(
        name=name,
        description=description,
        run_description=run.run_description,
        instrument_platform=run.instrument_platform,
        flowcell_type=run.flowcell_type,
        reagent_cycles=run.reagent_cycles,
        run_cycles=RunCycles.from_dict(run.run_cycles.to_dict()) if run.run_cycles else None,
        barcode_mismatches_index1=run.barcode_mismatches_index1,
        barcode_mismatches_index2=run.barcode_mismatches_index2,
        adapter_behavior=run.adapter_behavior,
        create_fastq_for_index_reads=run.create_fastq_for_index_reads,
        no_lane_splitting=run.no_lane_splitting,
        analyses=_filter_analyses(run.analyses, scaffold_ids),
        scaffold_samples=[Sample.from_dict(s.to_dict()) for s in scaffold_samples],
    )


@router.post("/runs/{run_id}/save-as-template", response_class=Response)
async def save_as_template(
    request: Request,
    run=Depends(get_archivable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/save-as-template — snapshot a run's config (+ chosen
    scaffold samples) into a NEW template. Create-only; a run of any status may
    be templated and the scaffold is captured as a deep-copied snapshot."""
    form = await request.form()
    name = sanitize_string(form.get("name", ""), 256)
    if not name:
        return Response("Template name is required", status_code=400)
    description = sanitize_string(form.get("description", ""), 4096)

    try:
        wanted_ids = set(json.loads(form.get("scaffold_sample_ids", "[]")))
    except (ValueError, TypeError):
        return Response("Invalid scaffold_sample_ids", status_code=400)
    scaffold = [s for s in run.samples if s.id in wanted_ids]

    template = _config_from_run(run, name, description, scaffold)
    template.created_by = get_username(request)
    template.updated_by = get_username(request)
    ctx.run_template_repo.save(template)
    audit(
        "template.created",
        actor=get_username(request),
        target=template.id,
        source_run=run.id,
        scaffold_count=len(scaffold),
    )
    return RedirectResponse("/templates", status_code=303)


@router.get("/templates", response_class=HTMLResponse)
def list_templates(request: Request, ctx: AppContext = Depends(get_ctx)) -> Response:
    """GET /templates — org-wide template library."""
    templates = sorted(
        ctx.run_template_repo.list_all(),
        key=lambda t: t.updated_at, reverse=True,
    )
    return render(request, "run_templates/list.html", {"templates": templates})


@router.post("/templates/{template_id}", response_class=Response)
async def update_template(
    template_id: str, request: Request, ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /templates/{id} — overwrite a template's name and description.
    This is a whole-form overwrite, not a per-field HTMX patch; both fields
    are always written."""
    template = ctx.run_template_repo.get_by_id(template_id)
    if template is None:
        return Response("Template not found", status_code=404)
    form = await request.form()
    name = sanitize_string(form.get("name", ""), 256)
    if not name:
        return Response("Template name is required", status_code=400)
    template.name = name
    template.description = sanitize_string(form.get("description", ""), 4096)
    template.touch(updated_by=get_username(request))
    ctx.run_template_repo.save(template)
    audit("template.updated", actor=get_username(request), target=template.id)
    return RedirectResponse("/templates", status_code=303)


@router.delete("/templates/{template_id}", response_class=Response)
def delete_template(
    template_id: str, request: Request, ctx: AppContext = Depends(get_ctx),
) -> Response:
    """DELETE /templates/{id}."""
    if ctx.run_template_repo.get_by_id(template_id) is None:
        return Response("Template not found", status_code=404)
    ctx.run_template_repo.delete(template_id)
    audit("template.deleted", actor=get_username(request), target=template_id)
    return Response("", status_code=200)


@router.post("/runs/new/from-template/{template_id}", response_class=Response)
def new_run_from_template(
    template_id: str, request: Request, ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/new/from-template/{id} — instantiate a draft from a template."""
    template = ctx.run_template_repo.get_by_id(template_id)
    if template is None:
        return Response("Template not found", status_code=404)

    try:
        new_run = build_draft_run(
            config_source=template,
            samples=template.scaffold_samples,
            created_by=get_username(request),
            run_name=template.name,
            instrument_config=ctx.instrument_config,
            check_references=True,
        )
    except RunInstantiationError as exc:
        return Response(str(exc), status_code=400)

    ctx.run_repo.save(new_run)
    record_run_created_safe(ctx, new_run, get_username(request),
                            source="template", ref=template_id)
    audit(
        "run.created_from_template",
        actor=get_username(request),
        target=new_run.id,
        template=template_id,
    )
    return RedirectResponse(f"/runs/{new_run.id}", status_code=303)
