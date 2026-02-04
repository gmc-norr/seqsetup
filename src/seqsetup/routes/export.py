"""Export routes for SampleSheet and JSON."""

import re

from fasthtml.common import *
from starlette.responses import Response as StarletteResponse

from ..context import AppContext
from ..services.json_exporter import JSONExporter
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF


def _sanitize_filename(name: str, default: str = "export") -> str:
    """
    Sanitize a filename for use in Content-Disposition headers.

    Removes or replaces characters that could be used for header injection
    or cause filesystem issues.

    Args:
        name: The filename to sanitize
        default: Default name if result would be empty

    Returns:
        Safe filename containing only alphanumeric, dash, underscore, and dot
    """
    if not name:
        return default
    # Remove any characters that aren't alphanumeric, dash, underscore, dot, or space
    sanitized = re.sub(r'[^\w\-. ]', '', name)
    # Replace spaces with underscores
    sanitized = sanitized.replace(' ', '_')
    # Remove leading/trailing dots and spaces
    sanitized = sanitized.strip('. ')
    # Limit length
    sanitized = sanitized[:100]
    return sanitized if sanitized else default


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

        try:
            content = SampleSheetV2Exporter.export(
                run,
                test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo,
            )
            # Sanitize filename to prevent header injection
            safe_name = _sanitize_filename(run.run_name, "SampleSheet_v2")
            filename = f"{safe_name}.csv"

            return StarletteResponse(
                content=content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception as e:
            return StarletteResponse(
                content=f"Error generating SampleSheet v2: {e}",
                status_code=500,
            )

    @rt("/runs/{run_id}/export/samplesheet-v1")
    def export_samplesheet_v1(run_id: str):
        """Download SampleSheet v1 CSV for instruments that support it."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(content="Run not found", status_code=404)

        if not SampleSheetV1Exporter.supports(run.instrument_platform):
            return StarletteResponse(
                content="SampleSheet v1 not supported for this instrument",
                status_code=400,
            )

        try:
            content = SampleSheetV1Exporter.export(run)
            safe_name = _sanitize_filename(run.run_name, "SampleSheet")
            filename = f"{safe_name}.csv"

            return StarletteResponse(
                content=content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception as e:
            return StarletteResponse(
                content=f"Error generating SampleSheet v1: {e}",
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

        try:
            content = JSONExporter.export(run)
            # Sanitize filename to prevent header injection
            safe_name = _sanitize_filename(run.run_name, "run_metadata")
            filename = f"{safe_name}.json"

            return StarletteResponse(
                content=content,
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception as e:
            return StarletteResponse(
                content=f"Error generating JSON: {e}",
                status_code=500,
            )

    @rt("/runs/{run_id}/export/validation-report")
    def export_validation_json(run_id: str):
        """Download validation report as JSON."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(content="Run not found", status_code=404)

        try:
            result = _run_validation(run)
            content = ValidationReportJSON.export(run, result)
            safe_name = _sanitize_filename(run.run_name, "validation_report")
            filename = f"{safe_name}_validation.json"

            return StarletteResponse(
                content=content,
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception as e:
            return StarletteResponse(
                content=f"Error generating validation report: {e}",
                status_code=500,
            )

    @rt("/runs/{run_id}/export/validation-pdf")
    def export_validation_pdf(run_id: str):
        """Download validation report as PDF."""
        run = ctx.run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(content="Run not found", status_code=404)

        try:
            result = _run_validation(run)
            pdf_bytes = ValidationReportPDF.export(run, result)
            safe_name = _sanitize_filename(run.run_name, "validation_report")
            filename = f"{safe_name}_validation.pdf"

            return StarletteResponse(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"'
                },
            )
        except Exception as e:
            return StarletteResponse(
                content=f"Error generating validation PDF: {e}",
                status_code=500,
            )
