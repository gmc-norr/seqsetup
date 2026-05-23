"""Dashboard routes for the main landing page.

Migrated off FastHTML to plain Starlette + Jinja2. The dashboard page
renders the full app shell; the tab/archive/delete handlers return the
``_dashboard_content.html`` fragment that HTMX swaps into ``#dashboard``.
"""

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..context import AppContext
from ..models.sequencing_run import RunStatus
from ..services.audit_log import audit
from ..templating import render
from .utils import check_status_transition, get_username


_VALID_TABS = ("draft", "ready", "archived")


def register(app, ctx: AppContext) -> None:
    """Register dashboard routes on the parent Starlette app.

    Requires ``app`` to have a mutable ``.routes`` list — Starlette /
    FastHTML do, anything else does not.
    """
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"dashboard.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def dashboard(request: Request) -> Response:
        """GET / — full dashboard page."""
        return render(
            request,
            "dashboard.html",
            {"runs": ctx.run_repo.list_all(), "active_tab": "draft"},
        )

    def dashboard_tab(request: Request) -> Response:
        """GET /dashboard/tab/{tab} — HTMX swap-out for tab selection."""
        tab = request.path_params["tab"]
        if tab not in _VALID_TABS:
            tab = "draft"
        return render(
            request,
            "_dashboard_content.html",
            {"runs": ctx.run_repo.list_all(), "active_tab": tab},
        )

    def archive_run(request: Request) -> Response:
        """POST /runs/{run_id}/archive — archive a run from the dashboard."""
        run_id = request.path_params["run_id"]
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if run.status == RunStatus.ARCHIVED:
            return Response("Run is already archived", status_code=403)
        # Same state machine the run-edit routes enforce.
        if err := check_status_transition(run.status, RunStatus.ARCHIVED):
            return err

        previous_status = run.status.value
        previous_tab = "ready" if run.status == RunStatus.READY else "draft"
        run.status = RunStatus.ARCHIVED
        run.touch(reset_validation=False, updated_by=get_username(request))
        ctx.run_repo.save(run)

        audit(
            "run.archived",
            actor=get_username(request),
            target=run_id,
            from_status=previous_status,
        )

        return render(
            request,
            "_dashboard_content.html",
            {"runs": ctx.run_repo.list_all(), "active_tab": previous_tab},
        )

    def delete_run(request: Request) -> Response:
        """DELETE /runs/{run_id} — delete an archived run."""
        run_id = request.path_params["run_id"]
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)
        if run.status != RunStatus.ARCHIVED:
            return Response("Only archived runs can be deleted", status_code=403)

        ctx.run_repo.delete(run_id)
        audit(
            "run.deleted",
            actor=get_username(request),
            target=run_id,
            previous_status=run.status.value,
            run_name=run.run_name,
        )
        return render(
            request,
            "_dashboard_content.html",
            {"runs": ctx.run_repo.list_all(), "active_tab": "archived"},
        )

    app.routes.append(Route("/", dashboard, methods=["GET"]))
    app.routes.append(Route("/dashboard/tab/{tab}", dashboard_tab, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/archive", archive_run, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}", delete_run, methods=["DELETE"]))
