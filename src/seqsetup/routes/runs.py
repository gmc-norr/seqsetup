"""Run configuration routes."""

from fasthtml.common import *
from starlette.responses import Response

from ..components.wizard import (
    CycleConfigFormWizard,
    FlowcellSelectWizard,
    ReagentKitSelectWizard,
    SampleTableWizard,
)
from ..context import AppContext
from ..data.instruments import (
    get_default_cycles,
    get_flowcells_for_instrument,
    get_reagent_kits_for_flowcell,
)
from ..models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus
from ..services.cycle_calculator import CycleCalculator
from ..services.json_exporter import JSONExporter
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF


def _get_username(req) -> str:
    """Extract username from request auth scope."""
    user = req.scope.get("auth")
    return user.username if user else ""


def register(app, rt, ctx: AppContext):
    """Register run configuration routes."""

    @app.post("/runs/{run_id}/name")
    def update_run_name(req, run_id: str, run_name: str = "", run_description: str = ""):
        """Update run name and description."""
        run_name = run_name.strip()[:256]
        run_description = run_description.strip()[:4096]

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        run.run_name = run_name
        run.run_description = run_description
        run.touch(updated_by=_get_username(req))
        ctx.run_repo.save(run)
        return ""

    @app.post("/runs/{run_id}/instrument")
    def update_instrument(req, run_id: str, instrument_platform: str):
        """Update instrument platform and return updated flowcell options."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        # Parse platform
        for platform in InstrumentPlatform:
            if platform.value == instrument_platform:
                run.instrument_platform = platform
                break

        # Get flowcells for new platform
        flowcells = get_flowcells_for_instrument(run.instrument_platform)

        # Reset flowcell selection
        if flowcells:
            run.flowcell_type = list(flowcells.keys())[0]
        else:
            run.flowcell_type = ""

        run.touch(updated_by=_get_username(req))
        ctx.run_repo.save(run)
        return FlowcellSelectWizard(run_id, run.flowcell_type, flowcells)

    @app.post("/runs/{run_id}/flowcell")
    def update_flowcell(req, run_id: str, flowcell_type: str):
        """Update flowcell type and return updated reagent kit options."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        run.flowcell_type = flowcell_type

        # Get reagent kits for new flowcell
        reagent_kits = get_reagent_kits_for_flowcell(
            run.instrument_platform, flowcell_type
        )

        # Reset reagent kit if current not available
        if reagent_kits and run.reagent_cycles not in reagent_kits:
            run.reagent_cycles = reagent_kits[0]

        run.touch(updated_by=_get_username(req))
        ctx.run_repo.save(run)
        return ReagentKitSelectWizard(run_id, run.reagent_cycles, reagent_kits)

    @app.post("/runs/{run_id}/reagent-kit")
    def update_reagent_kit(req, run_id: str, reagent_cycles: int):
        """Update reagent kit and return updated cycle configuration."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        run.reagent_cycles = reagent_cycles

        # Update run cycles with defaults for new reagent kit
        defaults = get_default_cycles(reagent_cycles)
        run.run_cycles = RunCycles(
            read1_cycles=defaults["read1"],
            read2_cycles=defaults["read2"],
            index1_cycles=defaults["index1"],
            index2_cycles=defaults["index2"],
        )

        # Update all sample override cycles
        CycleCalculator.update_all_sample_override_cycles(run)

        run.touch(updated_by=_get_username(req))
        ctx.run_repo.save(run)
        return CycleConfigFormWizard(run)

    @app.post("/runs/{run_id}/cycles")
    def update_cycles(
        req,
        run_id: str,
        read1_cycles: int,
        read2_cycles: int,
        index1_cycles: int,
        index2_cycles: int,
    ):
        """Update cycle configuration."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        run.run_cycles = RunCycles(
            read1_cycles=read1_cycles,
            read2_cycles=read2_cycles,
            index1_cycles=index1_cycles,
            index2_cycles=index2_cycles,
        )

        # Update all sample override cycles
        CycleCalculator.update_all_sample_override_cycles(run)

        run.touch(updated_by=_get_username(req))
        ctx.run_repo.save(run)
        return SampleTableWizard(run, show_drop_zones=False)

    @app.post("/runs/{run_id}/bclconvert")
    def update_bclconvert(
        req,
        run_id: str,
        barcode_mismatches_index1: int = 1,
        barcode_mismatches_index2: int = 1,
        no_lane_splitting: bool = False,
    ):
        """Update BCLConvert settings."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        run.barcode_mismatches_index1 = barcode_mismatches_index1
        run.barcode_mismatches_index2 = barcode_mismatches_index2
        run.no_lane_splitting = no_lane_splitting

        run.touch(updated_by=_get_username(req))
        ctx.run_repo.save(run)
        return ""

    @app.post("/runs/{run_id}/status/{status}")
    def update_status(req, run_id: str, status: str):
        """Update run status."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        try:
            new_status = RunStatus(status)
        except ValueError:
            return Response(f"Invalid status: {status}", status_code=400)

        # Block transition to "ready" unless validation is approved
        if new_status == RunStatus.READY and not run.validation_approved:
            from .main import RunStatusBar
            return RunStatusBar(run)

        run.status = new_status

        # Pre-generate exports when transitioning to READY
        if new_status == RunStatus.READY:
            run.generated_samplesheet_v2 = SampleSheetV2Exporter.export(
                run,
                test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo,
            )
            run.generated_json = JSONExporter.export(run)

            # Generate v1 samplesheet if instrument supports it
            if SampleSheetV1Exporter.supports(run.instrument_platform):
                run.generated_samplesheet_v1 = SampleSheetV1Exporter.export(run)

            # Generate validation reports
            result = ValidationService.validate_run(
                run,
                test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo,
                instrument_config=ctx.instrument_config,
            )
            run.generated_validation_json = ValidationReportJSON.export(run, result)
            run.generated_validation_pdf = ValidationReportPDF.export(run, result)

        run.touch(reset_validation=False, updated_by=_get_username(req))
        ctx.run_repo.save(run)

        from .main import RunStatusBar
        return RunStatusBar(run)
