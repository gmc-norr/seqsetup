"""Who edits a Draft run (the user's decision, 2026-10-13).

- POST   /runs/{id}/edit-lock           Edit run: take a run nobody is editing.
- DELETE /runs/{id}/edit-lock           Done editing: give it back.
- POST   /runs/{id}/edit-lock/take-over Take over editing, whoever holds it.
- POST   /runs/{id}/edit-lock/heartbeat The open page's "still here".

The rules live in services/edit_locks.py; every change to a Draft is checked
by ``get_editable_run``. The three buttons reload the run page; the
heartbeat answers JSON for the page's own script.
"""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from starlette.responses import Response

from ..context import AppContext
from ..models.sequencing_run import SequencingRun
from ..repositories.base import ConflictError
from ..services import edit_locks
from ..services.audit_log import audit
from ..services.edit_locks import EditLockRefused
from .dependencies import get_ctx, get_draft_run
from .utils import get_username

router = APIRouter(tags=["edit-lock"])


def _reload(run: SequencingRun) -> Response:
    return Response(status_code=200, headers={"HX-Redirect": f"/runs/{run.id}"})


@router.post("/runs/{run_id}/edit-lock")
def start_editing(
    request: Request,
    run: SequencingRun = Depends(get_draft_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """Edit run. 409, naming them, while someone else is editing."""
    try:
        edit_locks.start(ctx.edit_lock_repo, run.id, request.scope.get("auth"))
    except EditLockRefused as e:
        raise ConflictError(str(e))
    audit("run.edit.started", actor=get_username(request), target=run.id)
    return _reload(run)


@router.delete("/runs/{run_id}/edit-lock")
def stop_editing(
    request: Request,
    run: SequencingRun = Depends(get_draft_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """Done editing. Frees the run only when the user holds it."""
    actor = get_username(request)
    if edit_locks.end(ctx.edit_lock_repo, run.id, actor):
        audit("run.edit.ended", actor=actor, target=run.id)
    return _reload(run)


@router.post("/runs/{run_id}/edit-lock/take-over")
def take_over_editing(
    request: Request,
    run: SequencingRun = Depends(get_draft_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """Take over editing: anyone may, after the page's confirmation."""
    previous = edit_locks.take_over(ctx.edit_lock_repo, run.id, request.scope.get("auth"))
    audit("run.edit.taken_over", actor=get_username(request), target=run.id,
          from_user=previous.username if previous else "")
    return _reload(run)


@router.post("/runs/{run_id}/edit-lock/heartbeat")
def editing_heartbeat(
    request: Request,
    run: SequencingRun = Depends(get_draft_run),
    ctx: AppContext = Depends(get_ctx),
) -> JSONResponse:
    """The open edit page's "still here", once a minute. Not audited."""
    if edit_locks.beat(ctx.edit_lock_repo, run.id, get_username(request)):
        return JSONResponse({"editing": True})
    return JSONResponse({"editing": False, "message": edit_locks.why_not(ctx.edit_lock_repo, run.id)})
