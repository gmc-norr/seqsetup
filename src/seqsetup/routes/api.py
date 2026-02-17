"""JSON API routes for external integrations."""

from starlette.responses import JSONResponse, Response

from ..context import AppContext
from ..models.sequencing_run import RunStatus


def register(app, rt, ctx: AppContext):
    """Register API routes."""

    # Only allow API access to runs in these statuses
    ALLOWED_API_STATUSES = {RunStatus.READY, RunStatus.ARCHIVED}

    def _check_run_access(run):
        """Check if run can be accessed via API. Returns error response or None."""
        if not run:
            return Response("Run not found", status_code=404)
        if run.status not in ALLOWED_API_STATUSES:
            return Response(
                "Run not available via API. Only ready or archived runs can be accessed.",
                status_code=403,
            )
        return None

    @rt("/api/runs")
    def api_list_runs(req, status: str = "ready"):
        """List runs filtered by status. Defaults to 'ready'.

        Only 'ready' and 'archived' statuses are allowed via API.
        """
        # Restrict status parameter to allowed values
        if status not in ("ready", "archived"):
            return Response(
                "Invalid status. Only 'ready' and 'archived' are allowed via API.",
                status_code=400,
            )

        runs = ctx.run_repo.list_by_status(status)
        return JSONResponse([run.to_dict() for run in runs])

    @rt("/api/runs/{run_id}/samplesheet-v2")
    def api_get_samplesheet_v2(req, run_id: str):
        """Get pre-generated SampleSheet v2 CSV for a ready run."""
        run = ctx.run_repo.get_by_id(run_id)

        error = _check_run_access(run)
        if error:
            return error

        if not run.generated_samplesheet_v2:
            return Response("SampleSheet v2 not yet generated", status_code=404)
        return Response(
            content=run.generated_samplesheet_v2,
            media_type="text/csv",
        )

    @rt("/api/runs/{run_id}/samplesheet-v1")
    def api_get_samplesheet_v1(req, run_id: str):
        """Get pre-generated SampleSheet v1 CSV for a ready run."""
        run = ctx.run_repo.get_by_id(run_id)

        error = _check_run_access(run)
        if error:
            return error

        if not run.generated_samplesheet_v1:
            return Response("SampleSheet v1 not available for this run", status_code=404)
        return Response(
            content=run.generated_samplesheet_v1,
            media_type="text/csv",
        )

    @rt("/api/runs/{run_id}/json")
    def api_get_json(req, run_id: str):
        """Get pre-generated JSON metadata for a ready run."""
        run = ctx.run_repo.get_by_id(run_id)

        error = _check_run_access(run)
        if error:
            return error

        if not run.generated_json:
            return Response("JSON metadata not yet generated", status_code=404)
        return Response(
            content=run.generated_json,
            media_type="application/json",
        )

    @rt("/api/runs/{run_id}/validation-report")
    def api_get_validation_json(req, run_id: str):
        """Get pre-generated validation report JSON for a ready run."""
        run = ctx.run_repo.get_by_id(run_id)

        error = _check_run_access(run)
        if error:
            return error

        if not run.generated_validation_json:
            return Response("Validation report not yet generated", status_code=404)
        return Response(
            content=run.generated_validation_json,
            media_type="application/json",
        )

    @rt("/api/runs/{run_id}/validation-pdf")
    def api_get_validation_pdf(req, run_id: str):
        """Get pre-generated validation report PDF for a ready run."""
        run = ctx.run_repo.get_by_id(run_id)

        error = _check_run_access(run)
        if error:
            return error

        if not run.generated_validation_pdf:
            return Response("Validation PDF not yet generated", status_code=404)
        return Response(
            content=run.generated_validation_pdf,
            media_type="application/pdf",
        )
