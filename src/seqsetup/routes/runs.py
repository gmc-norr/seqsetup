"""Run configuration routes."""

import logging

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
from ..services.validation_report import ValidationReportJSON
from .utils import check_run_editable, check_status_transition, get_username, sanitize_string

logger = logging.getLogger(__name__)


def register(app, rt, ctx: AppContext):
    """Register run configuration routes."""

    @app.post("/runs/{run_id}/name")
    def update_run_name(req, run_id: str, run_name: str = "", run_description: str = ""):
        """Update run name and description."""
        run_name = sanitize_string(run_name, 256)
        run_description = sanitize_string(run_description, 4096)

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.run_name = run_name
        run.run_description = run_description
        run.touch(updated_by=get_username(req))
        ctx.run_repo.save(run)
        return ""

    @app.post("/runs/{run_id}/instrument")
    def update_instrument(req, run_id: str, instrument_platform: str):
        """Update instrument platform and return updated flowcell options."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

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

        run.touch(updated_by=get_username(req))
        ctx.run_repo.save(run)
        return FlowcellSelectWizard(run_id, run.flowcell_type, flowcells)

    @app.post("/runs/{run_id}/flowcell")
    def update_flowcell(req, run_id: str, flowcell_type: str):
        """Update flowcell type and return updated reagent kit options."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.flowcell_type = flowcell_type

        # Get reagent kits for new flowcell
        reagent_kits = get_reagent_kits_for_flowcell(
            run.instrument_platform, flowcell_type
        )

        # Reset reagent kit if current not available
        if reagent_kits and run.reagent_cycles not in reagent_kits:
            run.reagent_cycles = reagent_kits[0]

        run.touch(updated_by=get_username(req))
        ctx.run_repo.save(run)
        return ReagentKitSelectWizard(run_id, run.reagent_cycles, reagent_kits)

    @app.post("/runs/{run_id}/reagent-kit")
    def update_reagent_kit(req, run_id: str, reagent_cycles: int):
        """Update reagent kit and return updated cycle configuration."""
        reagent_cycles = max(1, min(reagent_cycles, 2000))

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

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

        run.touch(updated_by=get_username(req))
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
        read1_cycles = max(0, min(read1_cycles, 600))
        read2_cycles = max(0, min(read2_cycles, 600))
        index1_cycles = max(0, min(index1_cycles, 600))
        index2_cycles = max(0, min(index2_cycles, 600))

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

        # Update all sample override cycles
        CycleCalculator.update_all_sample_override_cycles(run)

        run.touch(updated_by=get_username(req))
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
        barcode_mismatches_index1 = max(0, min(barcode_mismatches_index1, 3))
        barcode_mismatches_index2 = max(0, min(barcode_mismatches_index2, 3))

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.barcode_mismatches_index1 = barcode_mismatches_index1
        run.barcode_mismatches_index2 = barcode_mismatches_index2
        run.no_lane_splitting = no_lane_splitting

        run.touch(updated_by=get_username(req))
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

        # Enforce state machine transitions
        if err := check_status_transition(run.status, new_status):
            return err

        # Block transition to "ready" unless validation is approved
        if new_status == RunStatus.READY and not run.validation_approved:
            from ..components.edit_run import RunStatusBar
            return RunStatusBar(run)

        run.status = new_status

        # Pre-generate exports when transitioning to READY
        if new_status == RunStatus.READY:
            try:
                run.generated_samplesheet_v2 = SampleSheetV2Exporter.export(
                    run,
                    test_profile_repo=ctx.test_profile_repo,
                    app_profile_repo=ctx.app_profile_repo,
                )
                run.generated_json = JSONExporter.export(run)

                # Generate v1 samplesheet if instrument supports it
                if SampleSheetV1Exporter.supports(run.instrument_platform):
                    run.generated_samplesheet_v1 = SampleSheetV1Exporter.export(run)

                # Generate validation JSON report (fast)
                # PDF is generated lazily on first download to keep Mark Ready fast
                result = ValidationService.validate_run(
                    run,
                    test_profile_repo=ctx.test_profile_repo,
                    app_profile_repo=ctx.app_profile_repo,
                    instrument_config=ctx.instrument_config,
                )
                run.generated_validation_json = ValidationReportJSON.export(run, result)
                run.generated_validation_pdf = None  # Generated on-demand when downloaded
            except Exception:
                logger.error(f"Failed to generate exports for run {run_id}", exc_info=True)
                return Response("Failed to generate exports", status_code=500)

        run.touch(reset_validation=False, updated_by=get_username(req))
        ctx.run_repo.save(run)

        from ..components.edit_run import RunStatusBar, SampleTableSectionForRun, ExportPanelForRun

        # Get test profiles for the sample table
        test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []

        # Return status bar as main response, plus export panel and sample section as out-of-band swaps
        export_panel = ExportPanelForRun(run)
        export_panel.attrs["hx-swap-oob"] = "true"

        sample_section = SampleTableSectionForRun(run, ctx.index_kit_repo.list_all(), test_profiles)
        sample_section.attrs["hx-swap-oob"] = "true"

        return Div(RunStatusBar(run), export_panel, sample_section)
