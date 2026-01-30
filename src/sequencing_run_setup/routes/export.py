"""Export routes for SampleSheet and JSON."""

import re

from fasthtml.common import *
from starlette.responses import Response as StarletteResponse

from ..services.json_exporter import JSONExporter
from ..services.samplesheet_exporter import SampleSheetV2Exporter


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


def register(
    app,
    rt,
    get_run_repo,
    get_index_kit_repo,
    get_test_profile_repo=None,
    get_app_profile_repo=None,
):
    """Register export routes."""

    @rt("/runs/{run_id}/export/samplesheet")
    def export_samplesheet(run_id: str):
        """Download SampleSheet v2 CSV for a specific run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

        if not run:
            return StarletteResponse(
                content="Run not found",
                status_code=404,
            )

        try:
            # Use profile-based export if repos are available
            test_profile_repo = get_test_profile_repo() if get_test_profile_repo else None
            app_profile_repo = get_app_profile_repo() if get_app_profile_repo else None

            content = SampleSheetV2Exporter.export(
                run,
                test_profile_repo=test_profile_repo,
                app_profile_repo=app_profile_repo,
            )
            # Sanitize filename to prevent header injection
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
                content=f"Error generating SampleSheet: {e}",
                status_code=500,
            )

    @rt("/runs/{run_id}/export/json")
    def export_json(run_id: str):
        """Download full JSON metadata for a specific run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)

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
