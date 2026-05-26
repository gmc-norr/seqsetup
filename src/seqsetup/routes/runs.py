"""Run configuration routes.

Uses APIRouter + Depends(get_editable_run) for the six simple
mutation handlers (DRAFT-only). update_status uses
Depends(get_archivable_run) because status transitions cross the
editable boundary (READY->DRAFT, ARCHIVED->DRAFT).

All persistence goes through `with saving_run(run, ctx, request):`
which calls run.touch(updated_by=...) before ctx.run_repo.save(run)
and skips touch+save if the body raises.
"""

import hashlib
import json
import logging

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..data.instruments import (
    get_default_cycles,
    get_flowcells_for_instrument,
    get_index_cycle_options,
    get_lanes_for_flowcell,
    get_reagent_kits_for_flowcell,
)
from ..models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from ..repositories.base import ConflictError
from ..services.audit_log import audit
from ..services.cycle_calculator import CycleCalculator
from ..services.json_exporter import JSONExporter
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF
from ..templating import render, templates
from .dependencies import get_archivable_run, get_ctx, get_editable_run, saving_run
from .utils import check_status_transition, get_username, sanitize_string


logger = logging.getLogger(__name__)


# Fields that are run *outputs* or per-touch metadata, not inputs to export
# generation. Excluded from the fingerprint below so a concurrent edit that
# only bumps ``updated_at`` (e.g. a different code path calling ``touch()``
# without changing any export-relevant field) doesn't cause a false refusal.
_FINGERPRINT_IGNORED_KEYS = (
    "updated_at",
    "updated_by",
    "_loaded_updated_at",
    "generated_samplesheet_v2",
    "generated_samplesheet_v1",
    "generated_json",
    "generated_validation_json",
    "generated_validation_pdf",
)


def _export_input_fingerprint(run: SequencingRun) -> str:
    """Stable hash of every run field that affects export output.

    DRAFT→READY pre-generates exports against the run state at the start of
    the request — that takes seconds (validation PDF). If a concurrent edit
    lands during that window we use this fingerprint to distinguish:

      * Trivial touch (only ``updated_at`` / ``updated_by`` changed) — the
        exports we just generated are still valid; apply them to the fresh
        instance and save against its own optimistic-lock token.
      * Material edit (a sample was added, run_cycles changed, …) — the
        exports are stale; refuse the transition with a clear message so the
        user can retry without an unexpected 409.

    Stripping the ``generated_*`` blobs is what keeps the fingerprint about
    *inputs* — those fields are output of the very transition we're trying
    to commit, so including them would always fingerprint-differ.
    """
    d = run.to_dict()
    for key in _FINGERPRINT_IGNORED_KEYS:
        d.pop(key, None)
    return hashlib.sha256(
        json.dumps(d, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


router = APIRouter(tags=["runs"])


def _int_field(form, key: str, default: int = 0) -> int:
    """Parse an integer from a Starlette FormData, returning ``default`` on failure."""
    raw = form.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


def _bool_field(form, key: str) -> bool:
    """Treat presence of an HTML checkbox value as True; HTML omits unchecked boxes."""
    raw = form.get(key)
    if raw is None:
        return False
    return str(raw).lower() in ("1", "true", "on", "yes")


# --- Simple mutation handlers (DRAFT-only via get_editable_run) ---

@router.post("/runs/{run_id}/name", response_class=HTMLResponse)
async def update_run_name(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/name — update run name and description."""
    form = await request.form()
    run_name = sanitize_string(form.get("run_name", ""), 256)
    run_description = sanitize_string(form.get("run_description", ""), 4096)

    with saving_run(run, ctx, request):
        run.run_name = run_name
        run.run_description = run_description
    return Response("")


@router.post("/runs/{run_id}/instrument", response_class=HTMLResponse)
async def update_instrument(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/instrument — change platform; return new flowcell options.

    Rejects unknown platform values rather than silently keeping the
    previous one — silent fallback would let a stale UI submit a
    mistyped enum and the change would not take.
    """
    form = await request.form()
    instrument_platform = form.get("instrument_platform", "")

    matched = None
    for platform in InstrumentPlatform:
        if platform.value == instrument_platform:
            matched = platform
            break
    if matched is None:
        return Response(
            f"Unknown instrument platform: {instrument_platform!r}",
            status_code=400,
        )

    flowcells = get_flowcells_for_instrument(matched)
    with saving_run(run, ctx, request):
        run.instrument_platform = matched
        if flowcells:
            run.flowcell_type = list(flowcells.keys())[0]
        else:
            run.flowcell_type = ""

    return render(request, "wizard/_flowcell_select.html", {
        "run_id": run.id,
        "current": run.flowcell_type,
        "flowcells": flowcells,
    })


@router.post("/runs/{run_id}/flowcell", response_class=HTMLResponse)
async def update_flowcell(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/flowcell — change flowcell; return new reagent kit options."""
    form = await request.form()
    flowcell_type = form.get("flowcell_type", "")

    reagent_kits = get_reagent_kits_for_flowcell(run.instrument_platform, flowcell_type)
    with saving_run(run, ctx, request):
        run.flowcell_type = flowcell_type
        if reagent_kits and run.reagent_cycles not in reagent_kits:
            run.reagent_cycles = reagent_kits[0]

    return render(request, "wizard/_reagent_kit_select.html", {
        "run_id": run.id,
        "current": run.reagent_cycles,
        "reagent_kits": reagent_kits,
    })


@router.post("/runs/{run_id}/reagent-kit", response_class=HTMLResponse)
async def update_reagent_kit(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/reagent-kit — change reagent kit; reset cycles to defaults."""
    form = await request.form()
    reagent_cycles = max(1, min(_int_field(form, "reagent_cycles", 1), 2000))

    defaults = get_default_cycles(reagent_cycles)
    with saving_run(run, ctx, request):
        run.reagent_cycles = reagent_cycles
        run.run_cycles = RunCycles(
            read1_cycles=defaults["read1"],
            read2_cycles=defaults["read2"],
            index1_cycles=defaults["index1"],
            index2_cycles=defaults["index2"],
        )
        CycleCalculator.update_all_sample_override_cycles(run)

    index_cycle_options = get_index_cycle_options()
    return render(request, "wizard/_cycle_config_form.html", {
        "run": run,
        "cycles": run.run_cycles,
        "index_cycle_options": index_cycle_options,
    })


@router.post("/runs/{run_id}/cycles", response_class=HTMLResponse)
async def update_cycles(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/cycles — update cycle configuration."""
    form = await request.form()
    read1_cycles = max(0, min(_int_field(form, "read1_cycles"), 600))
    read2_cycles = max(0, min(_int_field(form, "read2_cycles"), 600))
    index1_cycles = max(0, min(_int_field(form, "index1_cycles"), 600))
    index2_cycles = max(0, min(_int_field(form, "index2_cycles"), 600))

    with saving_run(run, ctx, request):
        run.run_cycles = RunCycles(
            read1_cycles=read1_cycles,
            read2_cycles=read2_cycles,
            index1_cycles=index1_cycles,
            index2_cycles=index2_cycles,
        )
        CycleCalculator.update_all_sample_override_cycles(run)

    return render(request, "wizard/_sample_table.html", {
        "run": run,
        "show_drop_zones": False,
        "index_kits": None,
        "num_lanes": 1,
        "show_bulk_actions": True,
        "context": "",
        "test_profiles": None,
        "editable": True,
    })


@router.post("/runs/{run_id}/bclconvert", response_class=HTMLResponse)
async def update_bclconvert(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/bclconvert — update BCLConvert settings."""
    form = await request.form()
    barcode_mismatches_index1 = max(0, min(_int_field(form, "barcode_mismatches_index1", 1), 3))
    barcode_mismatches_index2 = max(0, min(_int_field(form, "barcode_mismatches_index2", 1), 3))
    no_lane_splitting = _bool_field(form, "no_lane_splitting")

    with saving_run(run, ctx, request):
        run.barcode_mismatches_index1 = barcode_mismatches_index1
        run.barcode_mismatches_index2 = barcode_mismatches_index2
        run.no_lane_splitting = no_lane_splitting

    return Response("")


# --- update_status: cross-status transitions (uses get_archivable_run) ---

@router.post("/runs/{run_id}/status/{status}", response_class=HTMLResponse)
async def update_status(
    request: Request,
    status: str,
    run: SequencingRun = Depends(get_archivable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/status/{status} — transition run status.

    Pre-generates Sample Sheet v2/v1, JSON, validation JSON+PDF on
    DRAFT->READY transition BEFORE flipping the status — a failure
    leaves the run in its current state, no half-mutated READY run
    persists.

    For DRAFT->READY, validation is run in real time. If errors are
    present the transition is refused with an inline error message
    returned via HX-Retarget to #error-banner.
    """
    try:
        new_status = RunStatus(status)
    except ValueError:
        return Response(f"Invalid status: {status}", status_code=400)

    if err := check_status_transition(run.status, new_status):
        return err

    if new_status == RunStatus.READY:
        validation_result = ValidationService.validate_run(
            run,
            test_profile_repo=ctx.test_profile_repo,
            app_profile_repo=ctx.app_profile_repo,
            instrument_config=ctx.instrument_config,
        )
        if validation_result.error_count > 0:
            first_messages = []
            for err in validation_result.configuration_errors[:3]:
                if err.severity.value == "error":
                    first_messages.append(err.message)
            if not first_messages and validation_result.index_collisions:
                first_messages.append(
                    f"Index collisions in {len(validation_result.index_collisions)} lane(s)."
                )
            more = validation_result.error_count - len(first_messages)
            suffix = f" (+ {more} more)" if more > 0 else ""
            denial_message = (
                f"Cannot mark ready — {validation_result.error_count} validation "
                f"error(s):\n" + "\n".join(f"• {m}" for m in first_messages) + suffix
            )
            audit(
                "run.status.denied",
                actor=get_username(request),
                target=run.id,
                outcome="denied",
                reason="validation_failed",
                attempted_status=new_status.value,
                error_count=validation_result.error_count,
            )
            return HTMLResponse(
                templates.env.get_template("_messages.html").render(
                    messages=[{"text": denial_message, "kind": "error"}]
                ),
                headers={
                    "Cache-Control": "no-store",
                    "HX-Retarget": "#error-banner",
                    "HX-Reswap": "innerHTML",
                },
            )

    previous_status = run.status.value

    # Pre-compute exports BEFORE touching run.status so that a failure
    # leaves the run in its current state (no half-mutated READY run persisted).
    new_ss_v2 = None
    new_json = None
    new_ss_v1 = None
    new_val_json = None
    new_val_pdf = None
    if new_status == RunStatus.READY:
        try:
            new_ss_v2 = SampleSheetV2Exporter.export(
                run,
                test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo,
            )
            new_json = JSONExporter.export(run)

            if SampleSheetV1Exporter.supports(run.instrument_platform):
                new_ss_v1 = SampleSheetV1Exporter.export(run)

            result = ValidationService.validate_run(
                run,
                test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo,
                instrument_config=ctx.instrument_config,
            )
            new_val_json = ValidationReportJSON.export(run, result)
            new_val_pdf = ValidationReportPDF.export(run, result)
        except Exception:
            logger.error(f"Failed to generate exports for run {run.id}", exc_info=True)
            return Response("Failed to generate exports", status_code=500)

    # On DRAFT→READY, re-fetch the run right before save so the optimistic-
    # lock token reflects the freshest version. Export generation above
    # took multiple seconds; without this refresh, any unrelated touch
    # during that window (background sync, another tab) turns the user's
    # multi-second action into a 409. The fingerprint comparison ensures
    # we only carry forward exports onto fresh state if the fresh state
    # would have produced byte-identical exports — anything that affects
    # export output is refused with a specific message instead.
    if new_status == RunStatus.READY:
        fingerprint_initial = _export_input_fingerprint(run)
        fresh = ctx.run_repo.get_by_id(run.id)
        if fresh is None:
            raise ConflictError(
                f"Run {run.id} was deleted while its exports were being "
                "generated. The Mark Ready transition has been refused."
            )
        if _export_input_fingerprint(fresh) != fingerprint_initial:
            audit(
                "run.status.denied",
                actor=get_username(request),
                target=run.id,
                outcome="denied",
                reason="concurrent_edit_during_export",
                attempted_status=new_status.value,
            )
            raise ConflictError(
                "This run was edited by another user (or session) while its "
                "exports were being generated. The Mark Ready transition was "
                "refused so the saved snapshot would not reflect stale state. "
                "Refresh the page and try again."
            )
        # Same content, possibly newer token — adopt the fresh instance.
        run = fresh

    with saving_run(run, ctx, request):
        run.status = new_status
        if new_status == RunStatus.READY:
            run.generated_samplesheet_v2 = new_ss_v2
            run.generated_json = new_json
            if new_ss_v1 is not None:
                run.generated_samplesheet_v1 = new_ss_v1
            run.generated_validation_json = new_val_json
            run.generated_validation_pdf = new_val_pdf

    audit(
        "run.status.changed",
        actor=get_username(request),
        target=run.id,
        from_status=previous_status,
        to_status=new_status.value,
    )

    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
    index_kits = ctx.index_kit_repo.list_all() if ctx.index_kit_repo else []
    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    is_editable = run.status == RunStatus.DRAFT
    has_v1 = SampleSheetV1Exporter.supports(run.instrument_platform)
    sample_api_cfg = ctx.sample_api_config
    sample_api_enabled = bool(sample_api_cfg and sample_api_cfg.enabled and sample_api_cfg.base_url)

    # Out-of-band swaps update the export panel and sample table without a
    # full page reload. HTMX needs the hx-swap-oob attribute on the
    # response fragments themselves.
    status_html = templates.env.get_template("runs/_run_status_bar.html").render(run=run)
    export_html = templates.env.get_template("runs/_export_panel.html").render(run=run, has_v1=has_v1, oob=True)
    section_html = templates.env.get_template("runs/_sample_section.html").render(
        run=run, index_kits=index_kits, test_profiles=test_profiles,
        num_lanes=num_lanes, is_editable=is_editable,
        sample_api_enabled=sample_api_enabled, oob=True,
    )
    return HTMLResponse(status_html + export_html + section_html, headers={"Cache-Control": "no-store"})
