"""Run configuration routes.

Migrated to Starlette ``Route(...)`` registration. The wizard FT
components are still returned via ``ft_response`` while the templates
are progressively ported.
"""

import logging

from starlette.requests import Request
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route

from ..components.wizard import (
    CycleConfigFormWizard,
    FlowcellSelectWizard,
    ReagentKitSelectWizard,
)
from ..context import AppContext
from ..data.instruments import (
    get_default_cycles,
    get_flowcells_for_instrument,
    get_lanes_for_flowcell,
    get_reagent_kits_for_flowcell,
)
from ..models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus
from ..services.audit_log import audit
from ..services.cycle_calculator import CycleCalculator
from ..services.json_exporter import JSONExporter
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF
from ..templating import ft_response, render, templates
from .utils import check_run_editable, check_status_transition, get_username, sanitize_string

logger = logging.getLogger(__name__)


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


def register(app, ctx: AppContext) -> None:
    """Register run configuration routes on the parent Starlette app."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"runs.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    async def update_run_name(request: Request) -> Response:
        """POST /runs/{run_id}/name — update run name and description."""
        run_id = request.path_params["run_id"]
        form = await request.form()
        run_name = sanitize_string(form.get("run_name", ""), 256)
        run_description = sanitize_string(form.get("run_description", ""), 4096)

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.run_name = run_name
        run.run_description = run_description
        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)
        return Response("")

    async def update_instrument(request: Request) -> Response:
        """POST /runs/{run_id}/instrument — change platform; return new flowcell options."""
        run_id = request.path_params["run_id"]
        form = await request.form()
        instrument_platform = form.get("instrument_platform", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        # Parse platform — reject unknown values rather than silently keeping
        # the previous one. Silent fallback would let a stale UI submit a
        # mis-typed enum value and the user would never know the change
        # didn't take.
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
        run.instrument_platform = matched

        flowcells = get_flowcells_for_instrument(run.instrument_platform)
        if flowcells:
            run.flowcell_type = list(flowcells.keys())[0]
        else:
            run.flowcell_type = ""

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)
        return ft_response(FlowcellSelectWizard(run_id, run.flowcell_type, flowcells))

    async def update_flowcell(request: Request) -> Response:
        """POST /runs/{run_id}/flowcell — change flowcell; return new reagent kit options."""
        run_id = request.path_params["run_id"]
        form = await request.form()
        flowcell_type = form.get("flowcell_type", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.flowcell_type = flowcell_type

        reagent_kits = get_reagent_kits_for_flowcell(
            run.instrument_platform, flowcell_type
        )

        if reagent_kits and run.reagent_cycles not in reagent_kits:
            run.reagent_cycles = reagent_kits[0]

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)
        return ft_response(ReagentKitSelectWizard(run_id, run.reagent_cycles, reagent_kits))

    async def update_reagent_kit(request: Request) -> Response:
        """POST /runs/{run_id}/reagent-kit — change reagent kit; reset cycles to defaults."""
        run_id = request.path_params["run_id"]
        form = await request.form()
        reagent_cycles = max(1, min(_int_field(form, "reagent_cycles", 1), 2000))

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.reagent_cycles = reagent_cycles

        defaults = get_default_cycles(reagent_cycles)
        run.run_cycles = RunCycles(
            read1_cycles=defaults["read1"],
            read2_cycles=defaults["read2"],
            index1_cycles=defaults["index1"],
            index2_cycles=defaults["index2"],
        )

        CycleCalculator.update_all_sample_override_cycles(run)

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)
        return ft_response(CycleConfigFormWizard(run))

    async def update_cycles(request: Request) -> Response:
        """POST /runs/{run_id}/cycles — update cycle configuration."""
        run_id = request.path_params["run_id"]
        form = await request.form()
        read1_cycles = max(0, min(_int_field(form, "read1_cycles"), 600))
        read2_cycles = max(0, min(_int_field(form, "read2_cycles"), 600))
        index1_cycles = max(0, min(_int_field(form, "index1_cycles"), 600))
        index2_cycles = max(0, min(_int_field(form, "index2_cycles"), 600))

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.run_cycles = RunCycles(
            read1_cycles=read1_cycles,
            read2_cycles=read2_cycles,
            index1_cycles=index1_cycles,
            index2_cycles=index2_cycles,
        )

        CycleCalculator.update_all_sample_override_cycles(run)

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)
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

    async def update_bclconvert(request: Request) -> Response:
        """POST /runs/{run_id}/bclconvert — update BCLConvert settings."""
        run_id = request.path_params["run_id"]
        form = await request.form()
        barcode_mismatches_index1 = max(0, min(_int_field(form, "barcode_mismatches_index1", 1), 3))
        barcode_mismatches_index2 = max(0, min(_int_field(form, "barcode_mismatches_index2", 1), 3))
        no_lane_splitting = _bool_field(form, "no_lane_splitting")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.barcode_mismatches_index1 = barcode_mismatches_index1
        run.barcode_mismatches_index2 = barcode_mismatches_index2
        run.no_lane_splitting = no_lane_splitting

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)
        return Response("")

    async def update_status(request: Request) -> Response:
        """POST /runs/{run_id}/status/{status} — transition run status."""
        run_id = request.path_params["run_id"]
        status = request.path_params["status"]

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        try:
            new_status = RunStatus(status)
        except ValueError:
            return Response(f"Invalid status: {status}", status_code=400)

        if err := check_status_transition(run.status, new_status):
            return err

        if new_status == RunStatus.READY and not run.validation_approved:
            audit(
                "run.status.denied",
                actor=get_username(request),
                target=run_id,
                outcome="denied",
                reason="validation_not_approved",
                attempted_status=new_status.value,
            )
            status_html = templates.env.get_template("runs/_run_status_bar.html").render(run=run)
            return HTMLResponse(status_html, headers={"Cache-Control": "no-store"})

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

                # Generate validation JSON + PDF reports. Pre-generating the PDF
                # here (rather than lazy on first download) keeps READY/ARCHIVED
                # runs immutable — the export routes must not write back.
                # See CLAUDE.md: "API serves pre-generated content, not live exports".
                result = ValidationService.validate_run(
                    run,
                    test_profile_repo=ctx.test_profile_repo,
                    app_profile_repo=ctx.app_profile_repo,
                    instrument_config=ctx.instrument_config,
                )
                new_val_json = ValidationReportJSON.export(run, result)
                new_val_pdf = ValidationReportPDF.export(run, result)
            except Exception:
                logger.error(f"Failed to generate exports for run {run_id}", exc_info=True)
                return Response("Failed to generate exports", status_code=500)

        # All exports succeeded (or transition doesn't need them). Apply now.
        run.status = new_status
        if new_status == RunStatus.READY:
            run.generated_samplesheet_v2 = new_ss_v2
            run.generated_json = new_json
            if new_ss_v1 is not None:
                run.generated_samplesheet_v1 = new_ss_v1
            run.generated_validation_json = new_val_json
            run.generated_validation_pdf = new_val_pdf

        run.touch(reset_validation=False, updated_by=get_username(request))
        ctx.run_repo.save(run)

        audit(
            "run.status.changed",
            actor=get_username(request),
            target=run_id,
            from_status=previous_status,
            to_status=new_status.value,
        )

        test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
        index_kits = ctx.index_kit_repo.list_all() if ctx.index_kit_repo else []
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        is_editable = run.status == RunStatus.DRAFT
        has_v1 = SampleSheetV1Exporter.supports(run.instrument_platform)

        # Out-of-band swaps update the export panel and sample table without a
        # full page reload. HTMX needs the hx-swap-oob attribute on the
        # response fragments themselves.
        status_html = templates.env.get_template("runs/_run_status_bar.html").render(run=run)
        export_html = templates.env.get_template("runs/_export_panel.html").render(run=run, has_v1=has_v1, oob=True)
        section_html = templates.env.get_template("runs/_sample_section.html").render(
            run=run, index_kits=index_kits, test_profiles=test_profiles,
            num_lanes=num_lanes, is_editable=is_editable, oob=True,
        )
        return HTMLResponse(status_html + export_html + section_html, headers={"Cache-Control": "no-store"})

    app.routes.append(Route("/runs/{run_id}/name", update_run_name, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/instrument", update_instrument, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/flowcell", update_flowcell, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/reagent-kit", update_reagent_kit, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/cycles", update_cycles, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/bclconvert", update_bclconvert, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/status/{status}", update_status, methods=["POST"]))
