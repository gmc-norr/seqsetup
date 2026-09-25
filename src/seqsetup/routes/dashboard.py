"""Dashboard routes — the main landing page (/), tab switching,
and run archive/delete actions.

Migrated to APIRouter. The page returns the full Jinja2 shell;
the HTMX swap targets (tab/archive/delete) re-render just the
{% block dashboard_content %} fragment via block_name="dashboard_content".
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..models.sequencing_run import RunStatus, SequencingRun
from ..models.user import UserRole
from ..services.audit_log import audit
from ..services.run_history import cascade_delete_history_safe
from ..templating import render
from .dependencies import get_archivable_run, get_ctx, saving_run
from .utils import check_status_transition, get_username


router = APIRouter(tags=["dashboard"])

_VALID_TABS = ("draft", "ready", "archived")


@router.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET / — full dashboard page (default tab: draft)."""
    return render(
        request,
        "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": "draft"},
    )


@router.get("/dashboard/tab/{tab}", response_class=HTMLResponse)
def dashboard_tab(
    tab: str,
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /dashboard/tab/{tab} — HTMX fragment swap for tab buttons."""
    if tab not in _VALID_TABS:
        tab = "draft"
    return render(
        request,
        "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": tab},
        block_name="dashboard_content",
    )


@router.post("/runs/{run_id}/archive", response_class=HTMLResponse)
def archive_run(
    request: Request,
    run: SequencingRun = Depends(get_archivable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/archive — archive from dashboard (HTMX).

    Returns the refreshed dashboard fragment on success, with the
    active_tab restored to the tab the user was on (draft/ready) —
    NOT switched to archived. State-machine enforced via
    check_status_transition.
    """
    if run.status == RunStatus.ARCHIVED:
        return Response("Run is already archived", status_code=403)
    if err := check_status_transition(run.status, RunStatus.ARCHIVED):
        return err

    previous_status = run.status.value
    previous_tab = "ready" if run.status == RunStatus.READY else "draft"

    with saving_run(run, ctx, request):
        run.status = RunStatus.ARCHIVED

    audit(
        "run.archived",
        actor=get_username(request),
        target=run.id,
        from_status=previous_status,
    )
    return render(
        request,
        "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": previous_tab},
        block_name="dashboard_content",
    )


@router.delete("/runs/{run_id}", response_class=HTMLResponse)
def delete_run(
    request: Request,
    run: SequencingRun = Depends(get_archivable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """DELETE /runs/{run_id} — delete a run (HTMX fragment).

    - An EMPTY draft (no samples) may be deleted by any user: it can never
      have been Ready, so no sheet from it can have been used.
    - A draft with samples may have been Ready and sent back: 403.
    - A Ready run: 403.
    - An ARCHIVED run is the clinical record: admins only, else 403.
    """
    user = request.scope.get("auth")
    is_admin = bool(user and user.role == UserRole.ADMIN)
    if run.status == RunStatus.DRAFT:
        if run.samples:
            return Response("A draft run with samples cannot be deleted.", status_code=403)
    elif run.status == RunStatus.ARCHIVED:
        if not is_admin:
            return Response("Only an admin can delete an archived run.", status_code=403)
    else:
        return Response("A Ready run cannot be deleted.", status_code=403)

    previous_status = run.status.value
    ctx.run_repo.delete(run.id)
    cascade_delete_history_safe(ctx, run.id, get_username(request))
    audit(
        "run.deleted",
        actor=get_username(request),
        target=run.id,
        previous_status=previous_status,
        run_name=run.run_name,
    )
    return render(
        request,
        "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": previous_status},
        block_name="dashboard_content",
    )
