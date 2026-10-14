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
from ..utils.clock import utcnow
from .dependencies import get_ctx, get_draft_run
from .utils import get_username

router = APIRouter(tags=["edit-lock"])


def _reload(run: SequencingRun) -> Response:
    return Response(status_code=200, headers={"HX-Redirect": f"/runs/{run.id}"})


def _new_editor(ctx: AppContext, run: SequencingRun, actor: str) -> None:
    """Someone who did not hold the run starts editing it: mark the run
    changed, after the lock row was written. A change of the user who held
    it before, already past its lock check, loaded the run before this, so
    its save is refused (outside review of 7f858e0, finding 3; the user's
    choice, 2026-10-14). Done editing marks nothing, so the editor's own
    last change on its way is kept (review of 999447b, P2)."""
    ctx.run_repo.mark_changed(run.id, utcnow(), actor)


@router.post("/runs/{run_id}/edit-lock")
def start_editing(
    request: Request,
    run: SequencingRun = Depends(get_draft_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """Edit run. 409, naming them, while someone else is editing. Taking a
    lock someone else left (not seen for three minutes) names them."""
    actor = get_username(request)
    previous = ctx.edit_lock_repo.get(run.id)
    try:
        edit_locks.start(ctx.edit_lock_repo, run.id, request.scope.get("auth"))
    except EditLockRefused as e:
        raise ConflictError(str(e))
    if not (previous and previous.username == actor):
        _new_editor(ctx, run, actor)
    audit("run.edit.started", actor=actor, target=run.id,
          from_user=previous.username if previous and previous.username != actor else "")
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
    actor = get_username(request)
    previous = edit_locks.take_over(ctx.edit_lock_repo, run.id, request.scope.get("auth"))
    if not (previous and previous.username == actor):
        _new_editor(ctx, run, actor)
    audit("run.edit.taken_over", actor=actor, target=run.id,
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
    return JSONResponse({"editing": False, "message": edit_locks.lost_message(ctx.edit_lock_repo, run.id)})
