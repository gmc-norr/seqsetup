"""Export routes for SampleSheet and JSON."""

import logging

from fasthtml.common import *
from starlette.responses import Response as StarletteResponse

from ..context import AppContext
from ..services.json_exporter import JSONExporter
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF
from .utils import check_run_exportable, sanitize_filename

logger = logging.getLogger("seqsetup")


def register(app, rt, ctx: AppContext):
    """Register export routes."""

    def _run_validation(run):
        """Run full validation with all available repos."""
        return ValidationService.validate_run(
            run,
            test_profile_repo=ctx.test_profile_repo,
            app_profile_repo=ctx.app_profile_repo,
            instrument_config=ctx.instrument_config,
        )

    @rt("/runs/{run_id}/export/samplesheet-v2")
    def export_samplesheet_v2(run_id: str):
        """Download SampleSheet v2 CSV for a specific run."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(
                content="Run not found",
                status_code=404,
            )

        if err := check_run_exportable(run):
            return err

        try:
            # Use cached content if available, otherwise generate fresh
            if run.generated_samplesheet_v2:
                content = run.generated_samplesheet_v2
            else:
                content = SampleSheetV2Exporter.export(
                    run,
                    test_profile_repo=ctx.test_profile_repo,
                    app_profile_repo=ctx.app_profile_repo,
                )

            # Sanitize filename to prevent header injection
            safe_name = sanitize_filename(run.run_name, "SampleSheet_v2")
            filename = f"{safe_name}.csv"

            return StarletteResponse(
                content=content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception:
            logger.exception("Failed to generate SampleSheet v2")
            return StarletteResponse(
                content="Failed to generate SampleSheet v2. Please try again.",
                status_code=500,
            )

    @rt("/runs/{run_id}/export/samplesheet-v1")
    def export_samplesheet_v1(run_id: str):
        """Download SampleSheet v1 CSV for instruments that support it."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(content="Run not found", status_code=404)

        if err := check_run_exportable(run):
            return err

        if not SampleSheetV1Exporter.supports(run.instrument_platform):
            return StarletteResponse(
                content="SampleSheet v1 not supported for this instrument",
                status_code=400,
            )

        try:
            # Use cached content if available, otherwise generate fresh
            if run.generated_samplesheet_v1:
                content = run.generated_samplesheet_v1
            else:
                content = SampleSheetV1Exporter.export(run)

            safe_name = sanitize_filename(run.run_name, "SampleSheet")
            filename = f"{safe_name}.csv"

            return StarletteResponse(
                content=content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception:
            logger.exception("Failed to generate SampleSheet v1")
            return StarletteResponse(
                content="Failed to generate SampleSheet v1. Please try again.",
                status_code=500,
            )

    @rt("/runs/{run_id}/export/json")
    def export_json(run_id: str):
        """Download full JSON metadata for a specific run."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(
                content="Run not found",
                status_code=404,
            )

        if err := check_run_exportable(run):
            return err

        try:
            # Use cached content if available, otherwise generate fresh
            if run.generated_json:
                content = run.generated_json
            else:
                content = JSONExporter.export(run)

            # Sanitize filename to prevent header injection
            safe_name = sanitize_filename(run.run_name, "run_metadata")
            filename = f"{safe_name}.json"

            return StarletteResponse(
                content=content,
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception:
            logger.exception("Failed to generate JSON export")
            return StarletteResponse(
                content="Failed to generate JSON export. Please try again.",
                status_code=500,
            )

    @rt("/runs/{run_id}/export/validation-report")
    def export_validation_json(run_id: str):
        """Download validation report as JSON."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(content="Run not found", status_code=404)

        if err := check_run_exportable(run):
            return err

        try:
            # Use cached content if available, otherwise generate fresh
            if run.generated_validation_json:
                content = run.generated_validation_json
            else:
                result = _run_validation(run)
                content = ValidationReportJSON.export(run, result)

            safe_name = sanitize_filename(run.run_name, "validation_report")
            filename = f"{safe_name}_validation.json"

            return StarletteResponse(
                content=content,
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception:
            logger.exception("Failed to generate validation report")
            return StarletteResponse(
                content="Failed to generate validation report. Please try again.",
                status_code=500,
            )

    @rt("/runs/{run_id}/export/validation-pdf")
    def export_validation_pdf(run_id: str):
        """Download validation report as PDF."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(content="Run not found", status_code=404)

        if err := check_run_exportable(run):
            return err

        try:
            # Use cached content if available, otherwise generate and cache
            if run.generated_validation_pdf:
                pdf_bytes = run.generated_validation_pdf
            else:
                result = _run_validation(run)
                pdf_bytes = ValidationReportPDF.export(run, result)
                # Cache the generated PDF for future downloads
                run.generated_validation_pdf = pdf_bytes
                ctx.run_repo.save(run)

            safe_name = sanitize_filename(run.run_name, "validation_report")
            filename = f"{safe_name}_validation.pdf"

            return StarletteResponse(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception:
            logger.exception("Failed to generate validation PDF")
            return StarletteResponse(
                content="Failed to generate validation PDF. Please try again.",
                status_code=500,
            )
