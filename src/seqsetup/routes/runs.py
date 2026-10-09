"""Run configuration routes.

Uses APIRouter + Depends(get_editable_run) for the simple
mutation handlers (DRAFT-only). update_status uses
Depends(get_archivable_run) because status transitions cross the
editable boundary (DRAFT->READY, READY->DRAFT, READY->ARCHIVED).
ARCHIVED is terminal — no transition out.

All persistence goes through `with saving_run(run, ctx, request):`
which calls run.touch(updated_by=...) before ctx.run_repo.save(run)
and skips touch+save if the body raises.
"""

import hashlib
import json
import logging
import re
from contextlib import contextmanager
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..data.instruments import (
    get_default_cycles,
    get_flowcells_for_instrument,
    get_index_cycle_options,
    get_lanes_for_flowcell,
    get_reagent_kit_max_cycles,
    get_reagent_kits_for_flowcell,
    i5_workflow_names,
    is_instrument_enabled_by_name,
    no_settings_reason,
    reading_synced_records,
    SyncedInstrumentsUnusable,
)
from ..models.instrument_definition import InstrumentRecordError
from ..models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from ..repositories.base import ConflictError
from ..services.audit_log import audit
from ..services.cycle_calculator import CycleCalculator
from ..services.json_exporter import JSONExporter
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.sheet_plan import SheetPlanChanged, SheetPlanProblem
from ..services.validation import ValidationService, clear_validation_cache
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF
from ..services.validation_summary import error_messages
from ..services.versioned_tests import offered_tests
from ..templating import render, templates
from .dependencies import get_archivable_run, get_ctx, get_editable_run, saving_run
from .utils import check_status_transition, get_username, sanitize_string, selected_kit_id


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
    "samplesheet_v1_withheld",
)


def _pregenerate_exports(
    run: SequencingRun, ctx: AppContext, plan_fingerprint: Optional[str] = None,
) -> tuple:
    """Generate all run exports against the current state snapshot.

    Returns ``(samplesheet_v2, samplesheet_v1, json_export, validation_json,
    validation_pdf)``. The v1 entry is ``None`` for platforms that don't
    support the legacy IEM format. Raises on any export failure so the
    caller can refuse the status transition without persisting half-mutated
    state — the responsibility for converting that to a 500 lives at the
    handler boundary, not here.

    ``plan_fingerprint`` is the fingerprint of the sheet plan Mark Ready's
    checks passed: the v2 writer and the validation report made here must
    come from a plan with the same one, or ``SheetPlanChanged`` is raised
    (spec 2026-10-05 group A3, §1).
    """
    ss_v2 = SampleSheetV2Exporter.export(
        run,
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
        plan_fingerprint=plan_fingerprint,
    )
    json_export = JSONExporter.export(run)

    ss_v1 = None
    if SampleSheetV1Exporter.supports(run.instrument_platform):
        ss_v1 = SampleSheetV1Exporter.export(run)

    result = ValidationService.validate_run(
        run,
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
    )
    if plan_fingerprint is not None and result.sheet_plan_fingerprint != plan_fingerprint:
        raise SheetPlanChanged()
    val_json = ValidationReportJSON.export(run, result)
    val_pdf = ValidationReportPDF.export(run, result)
    return ss_v2, ss_v1, json_export, val_json, val_pdf


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
    # Write only the fields that were sent: a missing field must not be
    # saved as "" over its current value.
    has_name = "run_name" in form
    has_description = "run_description" in form
    if not (has_name or has_description):
        return Response("Nothing to save", status_code=400)

    with saving_run(run, ctx, request):
        if has_name:
            run.run_name = sanitize_string(form.get("run_name", ""), 256)
        if has_description:
            run.run_description = sanitize_string(form.get("run_description", ""), 4096)
    return Response("")


def _cycle_total_oob(run: SequencingRun) -> dict:
    """Context for sending the setup page's cycle total line out of band:
    an instrument or flowcell change can change the kit's cycle limit."""
    if not run.run_cycles:
        return {"cycle_total_oob": False}
    return {
        "cycle_total_oob": True,
        "run": run,
        "cycles": run.run_cycles,
        "kit_max_cycles": get_reagent_kit_max_cycles(run.instrument_platform, run.reagent_cycles),
    }


@router.post("/runs/{run_id}/instrument", response_class=HTMLResponse)
async def update_instrument(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/instrument — change platform; return new flowcell
    and reagent-kit options.

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

    if not is_instrument_enabled_by_name(matched.value):
        # Only a page opened before an admin switched it off still offers it
        # (F27). HTTPException: the error handler escapes the message.
        raise HTTPException(status_code=400, detail=(
            f"{matched.value} is disabled by an administrator. The run still uses "
            f"{run.instrument_platform.value}. Reload the page to see the instruments "
            f"you can pick."
        ))

    workflows = i5_workflow_names(matched.value)
    if workflows is None:
        # Not among the synced instruments (spec 2026-10-04 group A2, §5).
        raise HTTPException(status_code=400, detail=(
            f"{no_settings_reason(matched.value)}. The run still uses "
            f"{run.instrument_platform.value}. Reload the page to see the instruments "
            f"you can pick."
        ))

    flowcells = get_flowcells_for_instrument(matched)
    with saving_run(run, ctx, request):
        run.instrument_platform = matched
        # The new instrument's standard i5 workflow (spec 2026-10-04 group A2, §3).
        run.i5_workflow = workflows[0] if workflows else ""
        if flowcells:
            run.flowcell_type = list(flowcells.keys())[0]
        else:
            run.flowcell_type = ""
        reagent_kits = get_reagent_kits_for_flowcell(matched, run.flowcell_type)
        if reagent_kits and run.reagent_cycles not in reagent_kits:
            run.reagent_cycles = reagent_kits[0]

    return render(request, "wizard/_flowcell_select.html", {
        "run_id": run.id,
        "current": run.flowcell_type,
        "flowcells": flowcells,
        "kit_select_oob": True,
        "reagent_kits": reagent_kits,
        "reagent_cycles": run.reagent_cycles,
        "i5_select_oob": True,
        "i5_workflows": workflows,
        "i5_workflow": run.i5_workflow,
        **_cycle_total_oob(run),
    })


@router.post("/runs/{run_id}/i5-workflow", response_class=HTMLResponse)
async def update_i5_workflow(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/i5-workflow — pick the run's i5 workflow (spec
    2026-10-04 group A2, §3). Only a name the instrument lists is saved, as
    sent; anything else is refused and nothing is written."""
    form = await request.form()
    value = form.get("i5_workflow")
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail="No i5 workflow was sent. Nothing was saved.")
    instrument = run.instrument_platform.value
    workflows = i5_workflow_names(instrument) or []
    if value not in workflows:
        raise HTTPException(status_code=400, detail=(
            f"{value[:64]!r} is not an i5 workflow of {instrument} "
            f"(it has: {', '.join(workflows) or 'none'}). Nothing was saved."
        ))
    with saving_run(run, ctx, request):
        run.i5_workflow = value
    return render(request, "wizard/_i5_workflow_select.html", {
        "run_id": run.id,
        "i5_workflows": workflows,
        "i5_workflow": run.i5_workflow,
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
        **_cycle_total_oob(run),
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
        "kit_max_cycles": get_reagent_kit_max_cycles(run.instrument_platform, run.reagent_cycles),
    })


_CYCLE_FIELDS = (
    ("read1_cycles", "Read 1"),
    ("read2_cycles", "Read 2"),
    ("index1_cycles", "Index 1"),
    ("index2_cycles", "Index 2"),
)
_MAX_CYCLES = 600


def _parse_run_cycles(form) -> RunCycles:
    """Read all four cycle counts, or raise ValueError naming the first one
    that is missing or not a whole number 0-600. Nothing is clamped or
    defaulted: a count the user did not see must never be saved."""
    values = {}
    for key, label in _CYCLE_FIELDS:
        raw = form.get(key)
        raw = raw.strip() if isinstance(raw, str) else ""
        if not re.fullmatch(r"[0-9]{1,4}", raw) or int(raw) > _MAX_CYCLES:
            raise ValueError(f"{label} cycles must be a whole number from 0 to {_MAX_CYCLES}.")
        values[key] = int(raw)
    return RunCycles(**values)


def _set_run_cycles(run: SequencingRun, run_cycles: RunCycles) -> None:
    """Apply cycle counts. Every sample's OverrideCycles is recomputed only
    when the counts change: re-saving the same counts must not wipe
    overrides the user set by hand."""
    if run.run_cycles == run_cycles:
        return
    run.run_cycles = run_cycles
    CycleCalculator.update_all_sample_override_cycles(run)


@router.post("/runs/{run_id}/cycles", response_class=HTMLResponse)
async def update_cycles(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/cycles — update cycle configuration.

    All four counts are required; a missing or invalid one is a 400 and
    nothing is saved. Returns the re-rendered cycle form (new total).
    """
    form = await request.form()
    try:
        run_cycles = _parse_run_cycles(form)
    except ValueError as exc:
        return Response(str(exc), status_code=400)

    with saving_run(run, ctx, request):
        _set_run_cycles(run, run_cycles)

    return render(request, "wizard/_cycle_config_form.html", {
        "run": run,
        "cycles": run.run_cycles,
        "index_cycle_options": get_index_cycle_options(),
        "kit_max_cycles": get_reagent_kit_max_cycles(run.instrument_platform, run.reagent_cycles),
    })


@router.post("/runs/{run_id}/setup", response_class=HTMLResponse)
async def update_setup(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/setup — save the setup page's name, description
    and cycles together (its Continue / Back button), so a value typed just
    before leaving is never lost. All or nothing: any missing or invalid
    field is a 400 and nothing is saved.
    """
    form = await request.form()
    missing = [key for key in ("run_name", "run_description") if key not in form]
    if missing:
        return Response(f"Missing field(s): {', '.join(missing)}", status_code=400)
    try:
        run_cycles = _parse_run_cycles(form)
    except ValueError as exc:
        return Response(str(exc), status_code=400)
    run_name = sanitize_string(form.get("run_name", ""), 256)
    run_description = sanitize_string(form.get("run_description", ""), 4096)

    with saving_run(run, ctx, request):
        run.run_name = run_name
        run.run_description = run_description
        _set_run_cycles(run, run_cycles)
    return Response("")


@router.post("/runs/{run_id}/bclconvert", response_class=HTMLResponse)
async def update_bclconvert(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/bclconvert — update BCLConvert settings."""
    form = await request.form()
    barcode_mismatches_index1 = max(0, min(_int_field(form, "barcode_mismatches_index1", 1), 2))
    barcode_mismatches_index2 = max(0, min(_int_field(form, "barcode_mismatches_index2", 1), 2))
    no_lane_splitting = _bool_field(form, "no_lane_splitting")

    with saving_run(run, ctx, request):
        run.barcode_mismatches_index1 = barcode_mismatches_index1
        run.barcode_mismatches_index2 = barcode_mismatches_index2
        run.no_lane_splitting = no_lane_splitting

    return Response("")


# --- update_status: cross-status transitions (uses get_archivable_run) ---

@contextmanager
def _denied_if_instruments_unusable(request: Request, run: SequencingRun, new_status: RunStatus):
    """Mark Ready stops when the synced instrument records cannot be used:
    audit the refusal, then let the error reach its handler (spec 2026-10-04
    group A2, §5). Nothing has been saved at these points."""
    try:
        yield
    except (InstrumentRecordError, SyncedInstrumentsUnusable):
        audit(
            "run.status.denied",
            actor=get_username(request),
            target=run.id,
            outcome="denied",
            reason="synced_instruments_unusable",
            attempted_status=new_status.value,
        )
        raise


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
    returned via HX-Retarget to #ready-message.
    """
    try:
        new_status = RunStatus(status)
    except ValueError:
        return Response(f"Invalid status: {status}", status_code=400)

    if err := check_status_transition(run.status, new_status):
        return err

    color_balance_lanes: list[int] = []
    if new_status == RunStatus.READY:
        with _denied_if_instruments_unusable(request, run, new_status):
            validation_result = ValidationService.validate_run(
                run,
                test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo,
                instrument_config=ctx.instrument_config,
            )
        if validation_result.error_count > 0:
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
                templates.env.get_template("runs/_ready_refused.html").render(
                    run=run, messages=error_messages(validation_result),
                ),
                headers={
                    "Cache-Control": "no-store",
                    "HX-Retarget": "#ready-message",
                    "HX-Reswap": "innerHTML",
                },
            )

        color_balance_lanes = validation_result.color_balance_error_lanes
        if color_balance_lanes:
            # Poor color balance costs read quality in a lane but does not
            # mix up patients, and one-sample lanes almost always show it —
            # so ask, and record the answer (spec 2026-09-27, F13). The
            # answer counts only for the run version and lanes shown.
            form = await request.form()
            shown = ",".join(str(lane) for lane in color_balance_lanes)
            confirmed = (
                form.get("color_balance_confirmed_at") == run.updated_at.isoformat()
                and form.get("color_balance_lanes") == shown
            )
            if not confirmed:
                audit(
                    "run.status.denied",
                    actor=get_username(request),
                    target=run.id,
                    outcome="denied",
                    reason="color_balance_unconfirmed",
                    attempted_status=new_status.value,
                    color_balance_lanes=color_balance_lanes,
                )
                return HTMLResponse(
                    templates.env.get_template("runs/_ready_color_balance.html").render(
                        run=run, lanes=color_balance_lanes, lanes_value=shown,
                    ),
                    headers={
                        "Cache-Control": "no-store",
                        "HX-Retarget": "#ready-message",
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
            with _denied_if_instruments_unusable(request, run, new_status):
                new_ss_v2, new_ss_v1, new_json, new_val_json, new_val_pdf = (
                    _pregenerate_exports(
                        run, ctx,
                        plan_fingerprint=validation_result.sheet_plan_fingerprint or None,
                    )
                )
        except (InstrumentRecordError, SyncedInstrumentsUnusable):
            raise
        except SheetPlanChanged as e:
            # A sync changed a profile between the checks and the writing
            # (spec 2026-10-05 group A3, §1): nothing is stored. The cache is
            # cleared so the next Mark Ready checks the profiles stored now,
            # even when the sync stopped before it cleared the cache.
            clear_validation_cache()
            audit(
                "run.status.denied",
                actor=get_username(request),
                target=run.id,
                outcome="denied",
                reason="profiles_changed_during_export",
                attempted_status=new_status.value,
            )
            raise ConflictError(str(e))
        except SheetPlanProblem as e:
            logger.error(f"Failed to generate exports for run {run.id}: {e}")
            audit(
                "run.status.denied",
                actor=get_username(request),
                target=run.id,
                outcome="denied",
                reason="sheet_plan_problem",
                attempted_status=new_status.value,
            )
            return Response("Failed to generate exports", status_code=500)
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

        # The instrument may have been switched off while the exports were
        # being generated. Read the switch from the database, not the
        # in-process cache (spec 2026-09-28 group 1c, F27, review P2).
        with _denied_if_instruments_unusable(request, run, new_status), reading_synced_records():
            definition = (
                ctx.instrument_definition_repo.get_by_name(run.instrument_platform.value)
                if ctx.instrument_definition_repo is not None else None
            )
        if definition is not None and not definition.enabled:
            audit(
                "run.status.denied",
                actor=get_username(request),
                target=run.id,
                outcome="denied",
                reason="instrument_disabled_during_export",
                attempted_status=new_status.value,
            )
            raise ConflictError(
                f"{run.instrument_platform.value} was disabled by an administrator "
                "while the exports were being generated. The run is still a Draft. "
                "Pick another instrument in Run Setup."
            )

    with saving_run(run, ctx, request):
        run.status = new_status
        if new_status == RunStatus.READY:
            run.generated_samplesheet_v2 = new_ss_v2
            run.generated_json = new_json
            # No v1 sheet when the checks that let the run through say it
            # cannot carry their settings (spec 2026-10-05 group A3, §3).
            run.samplesheet_v1_withheld = validation_result.v1_sheet_withheld
            if new_ss_v1 is not None and not validation_result.v1_sheet_withheld:
                run.generated_samplesheet_v1 = new_ss_v1
            run.generated_validation_json = new_val_json
            run.generated_validation_pdf = new_val_pdf
        elif new_status == RunStatus.DRAFT:
            # READY→DRAFT puts the run back into the editable pool. Clear
            # pre-generated exports so a subsequent re-promotion never
            # adopts blobs from before the edit cycle that brought the
            # run back to DRAFT. READY→ARCHIVED retains the exports —
            # archived runs are read-only snapshots whose exports must
            # remain accessible via the API surface.
            run.generated_samplesheet_v2 = None
            run.generated_samplesheet_v1 = None
            run.samplesheet_v1_withheld = ""
            run.generated_json = None
            run.generated_validation_json = None
            run.generated_validation_pdf = None

    audit(
        "run.status.changed",
        actor=get_username(request),
        target=run.id,
        from_status=previous_status,
        to_status=new_status.value,
        **({"color_balance_accepted_lanes": color_balance_lanes} if color_balance_lanes else {}),
    )

    test_profiles = offered_tests(ctx.test_profile_repo.list_all()) if ctx.test_profile_repo else []
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
        chosen_kit_id=selected_kit_id(request),
    )
    ready_html = templates.env.get_template("runs/_ready_message.html").render(oob=True)
    return HTMLResponse(status_html + export_html + section_html + ready_html, headers={"Cache-Control": "no-store"})


_HISTORY_PAGE = 50


@router.get("/runs/{run_id}/history", response_class=HTMLResponse)
def run_history(
    request: Request,
    run_id: str,
    before_ts: str = "",
    before_id: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/history — read-only change-history panel (any status)."""
    run = ctx.run_repo.get_by_id(run_id)
    if run is None:
        return Response("Run not found", status_code=404)

    # A keyset cursor is both-or-neither. A half cursor is malformed input —
    # reject it rather than silently re-serving page 1 (clinical default: never
    # silently discard a paging request and hand back the wrong page).
    if bool(before_ts) != bool(before_id):
        return Response("Invalid pagination cursor", status_code=400)

    # Read path mirrors the recording helpers' None-guard: history is an
    # Optional dependency, so degrade to an empty panel rather than 500 if it
    # isn't configured.
    if ctx.run_history_repo is None:
        entries = []
    else:
        entries = ctx.run_history_repo.list_by_run(
            run_id,
            limit=_HISTORY_PAGE + 1,
            before_ts=before_ts or None,
            before_id=before_id or None,
        )
    has_more = len(entries) > _HISTORY_PAGE
    entries = entries[:_HISTORY_PAGE]

    next_ts = next_id = None
    if has_more and entries:
        next_ts, next_id = entries[-1].cursor()

    show_baseline = (not has_more) and (
        not entries or entries[-1].kind != "created"
    )

    return render(request, "runs/_history_list.html", {
        "run": run,
        "entries": entries,
        "next_ts": next_ts,
        "next_id": next_id,
        "show_baseline": show_baseline,
    })
