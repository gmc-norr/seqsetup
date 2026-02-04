"""Dashboard routes for the main landing page."""

from fasthtml.common import *

from starlette.responses import Response

from ..components.dashboard import DashboardContent
from ..components.layout import AppShell
from ..context import AppContext
from ..models.sequencing_run import RunStatus


def register(app, rt, ctx: AppContext):
    """Register dashboard routes."""

    @rt("/")
    def dashboard(req):
        """Render the dashboard showing all runs."""
        user = req.scope.get("auth")

        runs = ctx.run_repo.list_all()

        return AppShell(
            user=user,
            active_route="/",
            content=DashboardContent(runs),
            title="Dashboard",
        )

    @rt("/dashboard/tab/{tab}")
    def dashboard_tab(req, tab: str):
        """Return dashboard content for a specific tab."""
        runs = ctx.run_repo.list_all()
        if tab not in ("draft", "ready", "archived"):
            tab = "draft"
        return DashboardContent(runs, active_tab=tab)

    @app.post("/runs/{run_id}/archive")
    def archive_run(req, run_id: str):
        """Archive a run directly from the dashboard."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if run.status == RunStatus.ARCHIVED:
            return Response("Run is already archived", status_code=403)

        # Remember which tab we came from
        previous_tab = "ready" if run.status == RunStatus.READY else "draft"

        run.status = RunStatus.ARCHIVED
        user = req.scope.get("auth")
        run.touch(reset_validation=False, updated_by=user.username if user else "")
        ctx.run_repo.save(run)

        # Return updated dashboard (stays on previous tab)
        runs = ctx.run_repo.list_all()
        return DashboardContent(runs, active_tab=previous_tab)

    @app.delete("/runs/{run_id}")
    def delete_run(req, run_id: str):
        """Delete a run. Only archived runs can be deleted."""
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if run.status != RunStatus.ARCHIVED:
            return Response("Only archived runs can be deleted", status_code=403)

        ctx.run_repo.delete(run_id)

        # Return updated dashboard (stays on archived tab) to update counts
        runs = ctx.run_repo.list_all()
        return DashboardContent(runs, active_tab="archived")
