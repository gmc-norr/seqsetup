"""JSON API routes for external integrations."""

from starlette.responses import JSONResponse


def register(app, rt, get_run_repo):
    """Register API routes."""

    @rt("/api/runs")
    def api_list_runs(req, status: str = "ready"):
        """List runs filtered by status. Defaults to 'ready'."""
        run_repo = get_run_repo()
        runs = run_repo.list_by_status(status)
        return JSONResponse([run.to_dict() for run in runs])
