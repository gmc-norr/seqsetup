"""Dashboard routes — the main landing page (/), tab switching,
and run archive/delete actions.

Migrated to APIRouter. The page returns the full Jinja2 shell;
the HTMX swap targets (tab/archive/delete) re-render just the
{% block dashboard_content %} fragment via block_name="dashboard_content".

archive_run is the canonical reference for state-machine mutations:
  - load via get_archivable_run (no DRAFT-only check)
  - check_status_transition before mutating
  - `with saving_run(run, ctx, request, reset_validation=False)`:
    archiving a READY run preserves its validation_approved flag
    so the archived record retains its prior approval. Default True
    would wipe approval, breaking the archived-run audit trail.
"""

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..models.sequencing_run import RunStatus, SequencingRun
from ..services.audit_log import audit
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

    # reset_validation=False: archiving a READY run preserves its
    # validation_approved flag — the run was validated before, and
    # archiving doesn't invalidate that prior approval. Default True
    # would wipe approval, breaking the archived-run audit trail.
    with saving_run(run, ctx, request, reset_validation=False):
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
    """DELETE /runs/{run_id} — delete an ARCHIVED run (HTMX fragment).

    Only archived runs may be deleted; draft/ready return 403.
    """
    if run.status != RunStatus.ARCHIVED:
        return Response("Only archived runs can be deleted", status_code=403)

    previous_status = run.status.value
    ctx.run_repo.delete(run.id)
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
        {"runs": ctx.run_repo.list_all(), "active_tab": "archived"},
        block_name="dashboard_content",
    )
