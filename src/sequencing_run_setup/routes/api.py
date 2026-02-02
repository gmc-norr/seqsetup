"""JSON API routes for external integrations."""

from starlette.responses import JSONResponse, Response


def register(app, rt, get_run_repo):
    """Register API routes."""

    @rt("/api/runs")
    def api_list_runs(req, status: str = "ready"):
        """List runs filtered by status. Defaults to 'ready'."""
        run_repo = get_run_repo()
        runs = run_repo.list_by_status(status)
        return JSONResponse([run.to_dict() for run in runs])

    @rt("/api/runs/{run_id}/samplesheet")
    def api_get_samplesheet(req, run_id: str):
        """Get pre-generated SampleSheet v2 CSV for a ready run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if not run.generated_samplesheet:
            return Response("SampleSheet not yet generated", status_code=404)
        return Response(
            content=run.generated_samplesheet,
            media_type="text/csv",
        )

    @rt("/api/runs/{run_id}/samplesheet-v1")
    def api_get_samplesheet_v1(req, run_id: str):
        """Get pre-generated SampleSheet v1 CSV for a ready run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if not run.generated_samplesheet_v1:
            return Response("SampleSheet v1 not available for this run", status_code=404)
        return Response(
            content=run.generated_samplesheet_v1,
            media_type="text/csv",
        )

    @rt("/api/runs/{run_id}/json")
    def api_get_json(req, run_id: str):
        """Get pre-generated JSON metadata for a ready run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if not run.generated_json:
            return Response("JSON metadata not yet generated", status_code=404)
        return Response(
            content=run.generated_json,
            media_type="application/json",
        )

    @rt("/api/runs/{run_id}/validation-report")
    def api_get_validation_json(req, run_id: str):
        """Get pre-generated validation report JSON for a ready run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if not run.generated_validation_json:
            return Response("Validation report not yet generated", status_code=404)
        return Response(
            content=run.generated_validation_json,
            media_type="application/json",
        )

    @rt("/api/runs/{run_id}/validation-pdf")
    def api_get_validation_pdf(req, run_id: str):
        """Get pre-generated validation report PDF for a ready run."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if not run.generated_validation_pdf:
            return Response("Validation PDF not yet generated", status_code=404)
        return Response(
            content=run.generated_validation_pdf,
            media_type="application/pdf",
        )
