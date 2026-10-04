"""Dashboard routes — the main landing page (/), tab switching,
and run archive/delete actions.

Migrated to APIRouter. The page returns the full Jinja2 shell;
the HTMX swap targets (tab/archive/delete) re-render just the
{% block dashboard_content %} fragment via block_name="dashboard_content".
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..models.deleted_run import DeletedRun
from ..models.sequencing_run import RunStatus, SequencingRun
from ..models.user import UserRole
from ..repositories.base import ConflictError
from ..services.audit_log import audit
from ..templating import render
from .dependencies import get_archivable_run, get_ctx, saving_run
from .utils import check_status_transition, get_username, sanitize_string
from ..utils.clock import utcnow


logger = logging.getLogger(__name__)
router = APIRouter(tags=["dashboard"])

_VALID_TABS = ("draft", "ready", "archived")

# Delete messages (spec 2026-09-28 group 2a).
_ONCE_READY_REFUSAL = "This run was Ready once, so only an admin can delete it. Nothing was deleted."
_COPY_FAILED = "Could not keep a copy of this run, so it was not deleted. Nothing was changed."
_DELETE_FAILED = "Could not delete this run. Reload the page to see whether it is still there."
_RUN_CHANGED = (
    "Someone else changed or deleted this run at the same moment, so your delete did "
    "nothing. Reload the page to see where it stands."
)


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


def _search_runs(runs: list[SequencingRun], query: str) -> tuple[list[SequencingRun], dict[str, list[str]]]:
    """Runs whose name, or any sample ID, contains ``query`` (ignoring
    case), newest first, and for each run the sample IDs that matched."""
    q = query.lower()
    found: list[SequencingRun] = []
    matched: dict[str, list[str]] = {}
    for run in runs:
        samples = [s.sample_id for s in run.samples if q in (s.sample_id or "").lower()]
        if samples or q in (run.run_name or "").lower():
            found.append(run)
            matched[run.id] = samples
    found.sort(key=lambda r: r.updated_at, reverse=True)
    return found, matched


@router.get("/dashboard/search", response_class=HTMLResponse)
def dashboard_search(
    request: Request,
    q: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /dashboard/search?q= — runs whose name or a sample ID contains q,
    in every status. Read-only. An empty query gives back the tabs."""
    query = sanitize_string(q, 256)
    runs = ctx.run_repo.list_all()
    search = None
    if query:
        found, matched = _search_runs(runs, query)
        search = {"query": query, "runs": found, "matched": matched}
    return render(
        request,
        "dashboard.html",
        {"runs": runs, "active_tab": "draft", "search": search},
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

    - An EMPTY draft (no samples) that was never Ready may be deleted by any
      user: no sheet from it can have been used.
    - An empty draft that WAS Ready once (sent back and emptied): admins only.
    - A draft with samples: 403. A Ready run: 403.
    - An ARCHIVED run is the clinical record: admins only, else 403.

    A run that was ever Ready is copied to Admin → Deleted runs first, and
    only the exact version that was checked is deleted. Change history is
    never deleted (spec 2026-09-28 group 2a, F16 + review).
    """
    user = request.scope.get("auth")
    is_admin = bool(user and user.role == UserRole.ADMIN)
    if run.status == RunStatus.DRAFT:
        if run.samples:
            return Response("A draft run with samples cannot be deleted.", status_code=403)
        if run.was_ready and not is_admin:
            return Response(_ONCE_READY_REFUSAL, status_code=403)
    elif run.status == RunStatus.ARCHIVED:
        if not is_admin:
            return Response("Only an admin can delete an archived run.", status_code=403)
    else:
        return Response("A Ready run cannot be deleted.", status_code=403)

    actor = get_username(request)
    previous_status = run.status.value
    copy = _start_copy(ctx, run, actor) if run.was_ready else None
    copy_detail = {"copy_id": copy.copy_id} if copy is not None else {}

    try:
        deleted = ctx.run_repo.delete_if_unchanged(run)
    except Exception:
        # The copy stays pending: we cannot know whether the run went. The
        # Deleted runs page decides from whether the run still exists.
        logger.error("Deleting run %s failed", run.id, exc_info=True)
        audit("run.delete.failed", actor=actor, target=run.id, outcome="failure",
              reason="delete_error", **copy_detail)
        raise HTTPException(status_code=500, detail=_DELETE_FAILED)

    if not deleted:
        if copy is not None:
            try:
                ctx.deleted_run_repo.mark_abandoned(copy.copy_id, utcnow(), "run_changed")
            except Exception:
                # Left pending; the page does not list a pending copy while
                # its run still exists.
                logger.error("Could not mark copy %s abandoned", copy.copy_id, exc_info=True)
        audit("run.delete.failed", actor=actor, target=run.id, outcome="failure",
              reason="run_changed", **copy_detail)
        raise ConflictError(_RUN_CHANGED)

    if copy is not None:
        try:
            confirmed = ctx.deleted_run_repo.mark_completed(copy.copy_id, utcnow())
        except Exception:
            logger.error("Could not mark copy %s completed", copy.copy_id, exc_info=True)
            confirmed = False
        if not confirmed:
            audit("run.delete.copy_unconfirmed", actor=actor, target=run.id,
                  outcome="failure", copy_id=copy.copy_id)

    audit(
        "run.deleted",
        actor=actor,
        target=run.id,
        previous_status=previous_status,
        run_name=run.run_name,
        kept_copy=copy is not None,
        **copy_detail,
    )
    return render(
        request,
        "dashboard.html",
        {"runs": ctx.run_repo.list_all(), "active_tab": previous_status},
        block_name="dashboard_content",
    )


def _start_copy(ctx: AppContext, run: SequencingRun, actor: str) -> DeletedRun:
    """Write the pending copy of ``run`` before anything is deleted. If it
    cannot be written, refuse with 500: a run that was ever Ready is never
    deleted without its copy (spec 2026-09-28 group 2a, F16)."""
    reason = "no_copy_store"
    if ctx.deleted_run_repo is not None:
        copy = DeletedRun.of(run, actor, utcnow())
        try:
            ctx.deleted_run_repo.start(copy)
            return copy
        except Exception:
            logger.error("Could not keep a copy of run %s", run.id, exc_info=True)
            reason = "copy_failed"
    audit("run.delete.failed", actor=actor, target=run.id, outcome="failure", reason=reason)
    raise HTTPException(status_code=500, detail=_COPY_FAILED)
