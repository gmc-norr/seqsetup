"""Dashboard routes for the main landing page."""

from fasthtml.common import *

from starlette.responses import Response

from ..components.dashboard import DashboardContent
from ..components.layout import AppShell
from ..models.sequencing_run import RunStatus


def register(app, rt, get_run_repo):
    """Register dashboard routes."""

    @rt("/")
    def dashboard(req):
        """Render the dashboard showing all runs."""
        run_repo = get_run_repo()
        user = req.scope.get("auth")

        runs = run_repo.list_all()

        return AppShell(
            user=user,
            active_route="/",
            content=DashboardContent(runs),
            title="Dashboard",
        )

    @rt("/dashboard/tab/{tab}")
    def dashboard_tab(req, tab: str):
        """Return dashboard content for a specific tab."""
        run_repo = get_run_repo()
        runs = run_repo.list_all()
        if tab not in ("draft", "ready", "archived"):
            tab = "draft"
        return DashboardContent(runs, active_tab=tab)

    @app.delete("/runs/{run_id}")
    def delete_run(req, run_id: str):
        """Delete a run. Only archived runs can be deleted."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if run.status != RunStatus.ARCHIVED:
            return Response("Only archived runs can be deleted", status_code=403)

        run_repo.delete(run_id)

        # Return empty string to remove the item
        return ""
